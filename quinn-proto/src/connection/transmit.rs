use super::*;

impl Connection {
    /// Returns packets to transmit
    ///
    /// Connections should be polled for transmit after:
    /// - the application performed some I/O on the connection
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    ///
    /// `max_datagrams` specifies how many datagrams can be returned inside a
    /// single Transmit using GSO. This must be at least 1.
    #[must_use]
    pub fn poll_transmit(
        &mut self,
        now: Instant,
        max_datagrams: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        assert!(max_datagrams != 0);
        let max_datagrams = match self.config.enable_segmentation_offload {
            false => 1,
            true => max_datagrams,
        };

        let mut num_datagrams = 0;
        // Position in `buf` of the first byte of the current UDP datagram. When coalescing QUIC
        // packets, this can be earlier than the start of the current QUIC packet.
        let mut datagram_start = 0;
        let mut segment_size = usize::from(self.path.current_mtu());

        if let Some(challenge) = self.send_path_challenge(now, buf) {
            return Some(challenge);
        }

        // If we need to send a probe, make sure we have something to send.
        for space in SpaceId::iter() {
            if space != SpaceId::Data {
                self.spaces[space].maybe_queue_probe(false, false, &self.streams);
                continue;
            }

            let has_ack_eliciting_data = self.can_send_1rtt(
                Ord::min(segment_size, usize::from(INITIAL_MTU)).saturating_sub(
                    self.predict_1rtt_overhead(Some(
                        self.packet_number_filter.peek(&self.spaces[SpaceId::Data]),
                    )),
                ),
            );
            let request_immediate_ack = self.peer_supports_ack_frequency();

            self.spaces[space].maybe_queue_probe(
                request_immediate_ack,
                has_ack_eliciting_data,
                &self.streams,
            );
        }

        // Check whether we need to send a close message
        let close = match self.state {
            State::Drained => {
                self.app_limited = true;
                return None;
            }
            State::Draining | State::Closed(_) => {
                // self.close is only reset once the associated packet had been
                // encoded successfully
                if !self.close {
                    self.app_limited = true;
                    return None;
                }
                true
            }
            _ => false,
        };

        // Check whether we need to send an ACK_FREQUENCY frame
        if let Some(config) = &self.config.ack_frequency_config {
            self.spaces[SpaceId::Data].pending.ack_frequency = self
                .ack_frequency
                .should_send_ack_frequency(self.path.rtt.get(), config, &self.peer_params)
                && self.highest_space == SpaceId::Data
                && self.peer_supports_ack_frequency();
        }

        // Reserving capacity can provide more capacity than we asked for. However, we are not
        // allowed to write more than `segment_size`. Therefore the maximum capacity is tracked
        // separately.
        let mut buf_capacity = 0;

        let mut coalesce = true;
        let mut builder_storage: Option<PacketBuilder> = None;
        let mut sent_frames = None;
        let mut pad_datagram = false;
        let mut pad_datagram_to_mtu = false;
        let mut congestion_blocked = false;

        // Iterate over all spaces and find data to send
        let mut space_idx = 0;
        let spaces = [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data];
        // This loop will potentially spend multiple iterations in the same `SpaceId`,
        // so we cannot trivially rewrite it to take advantage of `SpaceId::iter()`.
        while space_idx < spaces.len() {
            let space_id = spaces[space_idx];
            // Number of bytes available for frames if this is a 1-RTT packet. We're guaranteed to
            // be able to send an individual frame at least this large in the next 1-RTT
            // packet. This could be generalized to support every space, but it's only needed to
            // handle large fixed-size frames, which only exist in 1-RTT (application datagrams). We
            // don't account for coalesced packets potentially occupying space because frames can
            // always spill into the next datagram.
            let pn = self.packet_number_filter.peek(&self.spaces[SpaceId::Data]);
            let frame_space_1rtt =
                segment_size.saturating_sub(self.predict_1rtt_overhead(Some(pn)));

            // Is there data or a close message to send in this space?
            let can_send = self.space_can_send(space_id, frame_space_1rtt);
            if can_send.is_empty() && (!close || self.spaces[space_id].crypto.is_none()) {
                space_idx += 1;
                continue;
            }

            let mut ack_eliciting = !self.spaces[space_id].pending.is_empty(&self.streams)
                || self.spaces[space_id].ping_pending
                || self.spaces[space_id].immediate_ack_pending;
            if space_id == SpaceId::Data {
                ack_eliciting |= self.can_send_1rtt(frame_space_1rtt);
            }

            pad_datagram_to_mtu |= space_id == SpaceId::Data && self.config.pad_to_mtu;

            // Can we append more data into the current buffer?
            // It is not safe to assume that `buf.len()` is the end of the data,
            // since the last packet might not have been finished.
            let buf_end = if let Some(builder) = &builder_storage {
                buf.len().max(builder.min_size) + builder.tag_len
            } else {
                buf.len()
            };

            let tag_len = if let Some(ref crypto) = self.spaces[space_id].crypto {
                crypto.packet.local.tag_len()
            } else if space_id == SpaceId::Data {
                self.zero_rtt_crypto.as_ref().expect(
                    "sending packets in the application data space requires known 0-RTT or 1-RTT keys",
                ).packet.tag_len()
            } else {
                unreachable!("tried to send {:?} packet without keys", space_id)
            };
            if !coalesce || buf_capacity - buf_end < MIN_PACKET_SPACE + tag_len {
                // We need to send 1 more datagram and extend the buffer for that.

                // Is 1 more datagram allowed?
                if num_datagrams >= max_datagrams {
                    // No more datagrams allowed
                    break;
                }

                // Anti-amplification is only based on `total_sent`, which gets
                // updated at the end of this method. Therefore we pass the amount
                // of bytes for datagrams that are already created, as well as 1 byte
                // for starting another datagram. If there is any anti-amplification
                // budget left, we always allow a full MTU to be sent
                // (see https://github.com/quinn-rs/quinn/issues/1082)
                if self
                    .path
                    .anti_amplification_blocked(segment_size as u64 * (num_datagrams as u64) + 1)
                {
                    trace!("blocked by anti-amplification");
                    break;
                }

                // Congestion control and pacing checks
                // Tail loss probes must not be blocked by congestion, or a deadlock could arise.
                // Close packets contain only ACKs and CONNECTION_CLOSE, neither of which is
                // congestion controlled, and must not be blocked either: `ack_eliciting` reflects
                // pending frames that will never be sent once closing, and a closed connection no
                // longer processes ACKs, so the window could never drain
                // (see https://github.com/quinn-rs/quinn/issues/2785)
                if ack_eliciting && self.spaces[space_id].loss_probes == 0 && !close {
                    // Assume the current packet will get padded to fill the segment
                    let untracked_bytes = if let Some(builder) = &builder_storage {
                        buf_capacity - builder.partial_encode.start
                    } else {
                        0
                    } as u64;
                    debug_assert!(untracked_bytes <= segment_size as u64);

                    let bytes_to_send = segment_size as u64 + untracked_bytes;
                    if self.path.in_flight.bytes + bytes_to_send > self.path.congestion.window() {
                        space_idx += 1;
                        congestion_blocked = true;
                        // We continue instead of breaking here in order to avoid
                        // blocking loss probes queued for higher spaces.
                        trace!("blocked by congestion control");
                        continue;
                    }

                    // Check whether the next datagram is blocked by pacing
                    let smoothed_rtt = self.path.rtt.get();
                    if let Some(delay) = self.path.pacing.delay(
                        smoothed_rtt,
                        bytes_to_send,
                        self.path.current_mtu(),
                        self.path.congestion.window(),
                        now,
                    ) {
                        self.timers.set(Timer::Pacing, delay);
                        congestion_blocked = true;
                        // Loss probes should be subject to pacing, even though
                        // they are not congestion controlled.
                        trace!("blocked by pacing");
                        break;
                    }
                }

                // Finish current packet
                if let Some(mut builder) = builder_storage.take() {
                    if pad_datagram {
                        builder.pad_to(MIN_INITIAL_SIZE);
                    }

                    if num_datagrams > 1 || pad_datagram_to_mtu {
                        // If too many padding bytes would be required to continue the GSO batch
                        // after this packet, end the GSO batch here. Ensures that fixed-size frames
                        // with heterogeneous sizes (e.g. application datagrams) won't inadvertently
                        // waste large amounts of bandwidth. The exact threshold is a bit arbitrary
                        // and might benefit from further tuning, though there's no universally
                        // optimal value.
                        //
                        // Additionally, if this datagram is a loss probe and `segment_size` is
                        // larger than `INITIAL_MTU`, then padding it to `segment_size` to continue
                        // the GSO batch would risk failure to recover from a reduction in path
                        // MTU. Loss probes are the only packets for which we might grow
                        // `buf_capacity` by less than `segment_size`.
                        const MAX_PADDING: usize = 16;
                        let packet_len_unpadded = cmp::max(builder.min_size, buf.len())
                            - datagram_start
                            + builder.tag_len;
                        if (packet_len_unpadded + MAX_PADDING < segment_size
                            && !pad_datagram_to_mtu)
                            || datagram_start + segment_size > buf_capacity
                        {
                            trace!(
                                "GSO truncated by demand for {} padding bytes or loss probe",
                                segment_size - packet_len_unpadded
                            );
                            builder_storage = Some(builder);
                            break;
                        }

                        // Pad the current datagram to GSO segment size so it can be included in the
                        // GSO batch.
                        builder.pad_to(segment_size as u16);
                    }

                    builder.finish_and_track(now, self, sent_frames.take(), buf);

                    if num_datagrams == 1 {
                        // Set the segment size for this GSO batch to the size of the first UDP
                        // datagram in the batch. Larger data that cannot be fragmented
                        // (e.g. application datagrams) will be included in a future batch. When
                        // sending large enough volumes of data for GSO to be useful, we expect
                        // packet sizes to usually be consistent, e.g. populated by max-size STREAM
                        // frames or uniformly sized datagrams.
                        segment_size = buf.len();
                        // Clip the unused capacity out of the buffer so future packets don't
                        // overrun
                        buf_capacity = buf.len();

                        // Check whether the data we planned to send will fit in the reduced segment
                        // size. If not, bail out and leave it for the next GSO batch so we don't
                        // end up trying to send an empty packet. We can't easily compute the right
                        // segment size before the original call to `space_can_send`, because at
                        // that time we haven't determined whether we're going to coalesce with the
                        // first datagram or potentially pad it to `MIN_INITIAL_SIZE`.
                        if space_id == SpaceId::Data {
                            let frame_space_1rtt =
                                segment_size.saturating_sub(self.predict_1rtt_overhead(Some(pn)));
                            if self.space_can_send(space_id, frame_space_1rtt).is_empty() {
                                break;
                            }
                        }
                    }
                }

                // Allocate space for another datagram
                let next_datagram_size_limit = match self.spaces[space_id].loss_probes {
                    0 => segment_size,
                    _ => {
                        self.spaces[space_id].loss_probes -= 1;
                        // Clamp the datagram to at most the minimum MTU to ensure that loss probes
                        // can get through and enable recovery even if the path MTU has shrank
                        // unexpectedly.
                        cmp::min(segment_size, usize::from(INITIAL_MTU))
                    }
                };
                buf_capacity += next_datagram_size_limit;
                if buf.capacity() < buf_capacity {
                    // We reserve the maximum space for sending `max_datagrams` upfront
                    // to avoid any reallocations if more datagrams have to be appended later on.
                    // Benchmarks have shown shown a 5-10% throughput improvement
                    // compared to continuously resizing the datagram buffer.
                    // While this will lead to over-allocation for small transmits
                    // (e.g. purely containing ACKs), modern memory allocators
                    // (e.g. mimalloc and jemalloc) will pool certain allocation sizes
                    // and therefore this is still rather efficient.
                    buf.reserve(max_datagrams * segment_size);
                }
                num_datagrams += 1;
                coalesce = true;
                pad_datagram = false;
                datagram_start = buf.len();

                debug_assert_eq!(
                    datagram_start % segment_size,
                    0,
                    "datagrams in a GSO batch must be aligned to the segment size"
                );
            } else {
                // We can append/coalesce the next packet into the current
                // datagram.
                // Finish current packet without adding extra padding
                if let Some(builder) = builder_storage.take() {
                    builder.finish_and_track(now, self, sent_frames.take(), buf);
                }
            }

            debug_assert!(buf_capacity - buf.len() >= MIN_PACKET_SPACE);

            //
            // From here on, we've determined that a packet will definitely be sent.
            //

            if self.spaces[SpaceId::Initial].crypto.is_some()
                && space_id == SpaceId::Handshake
                && self.side.is_client()
            {
                // A client stops both sending and processing Initial packets when it
                // sends its first Handshake packet.
                self.discard_space(now, SpaceId::Initial);
            }
            if let Some(ref mut prev) = self.prev_crypto {
                prev.update_unacked = false;
            }

            debug_assert!(
                builder_storage.is_none() && sent_frames.is_none(),
                "Previous packet must have been finished"
            );

            let builder = builder_storage.insert(PacketBuilder::new(
                now,
                space_id,
                self.rem_cids.active(),
                buf,
                buf_capacity,
                datagram_start,
                ack_eliciting,
                self,
            )?);
            coalesce = coalesce && !builder.short_header;

            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14.1
            pad_datagram |=
                space_id == SpaceId::Initial && (self.side.is_client() || ack_eliciting);

            if close {
                trace!("sending CONNECTION_CLOSE");
                // Encode ACKs before the ConnectionClose message, to give the receiver
                // a better approximate on what data has been processed. This is
                // especially important with ack delay, since the peer might not
                // have gotten any other ACK for the data earlier on.
                if !self.spaces[space_id].pending_acks.ranges().is_empty() {
                    Self::try_populate_acks(
                        now,
                        self.receiving_ecn,
                        &mut SentFrames::default(),
                        &mut self.spaces[space_id],
                        buf,
                        &mut self.stats,
                        buf_capacity,
                    );
                }

                // Since there only 64 ACK frames there will always be enough space
                // to encode the ConnectionClose frame too. However we still have the
                // check here to prevent crashes if something changes.
                debug_assert!(
                    buf.len() + frame::ConnectionClose::SIZE_BOUND < builder.max_size,
                    "ACKs should leave space for ConnectionClose"
                );
                if buf.len() + frame::ConnectionClose::SIZE_BOUND < builder.max_size {
                    let max_frame_size = builder.max_size - buf.len();
                    match self.state {
                        State::Closed(state::Closed { ref reason }) => {
                            if space_id == SpaceId::Data || reason.is_transport_layer() {
                                reason.encode(buf, max_frame_size)
                            } else {
                                frame::ConnectionClose {
                                    error_code: TransportErrorCode::APPLICATION_ERROR,
                                    frame_type: None,
                                    reason: Bytes::new(),
                                }
                                .encode(buf, max_frame_size)
                            }
                        }
                        State::Draining => frame::ConnectionClose {
                            error_code: TransportErrorCode::NO_ERROR,
                            frame_type: None,
                            reason: Bytes::new(),
                        }
                        .encode(buf, max_frame_size),
                        _ => unreachable!(
                            "tried to make a close packet when the connection wasn't closed"
                        ),
                    }
                }
                if space_id == self.highest_space {
                    // Don't send another close packet
                    self.close = false;
                    // `CONNECTION_CLOSE` is the final packet
                    break;
                } else {
                    // Send a close frame in every possible space for robustness, per RFC9000
                    // "Immediate Close during the Handshake". Don't bother trying to send anything
                    // else.
                    space_idx += 1;
                    continue;
                }
            }

            // Send an off-path PATH_RESPONSE. Prioritized over on-path data to ensure that path
            // validation can occur while the link is saturated.
            if space_id == SpaceId::Data && num_datagrams == 1 {
                if let Some((token, remote, local_ip)) = self
                    .path_responses
                    .pop_off_path(self.path.remote, self.local_ip)
                {
                    // `unwrap` guaranteed to succeed because `builder_storage` was populated just
                    // above.
                    let mut builder = builder_storage.take().unwrap();
                    trace!("PATH_RESPONSE {:08x} (off-path)", token);
                    buf.write(frame::FrameType::PATH_RESPONSE);
                    buf.write(token);
                    self.stats.frame_tx.path_response += 1;
                    builder.pad_to(MIN_INITIAL_SIZE);
                    builder.finish_and_track(
                        now,
                        self,
                        Some(SentFrames {
                            non_retransmits: true,
                            ..SentFrames::default()
                        }),
                        buf,
                    );
                    self.stats.udp_tx.on_sent(1, buf.len());
                    return Some(Transmit {
                        destination: remote,
                        size: buf.len(),
                        ecn: None,
                        segment_size: None,
                        src_ip: local_ip,
                    });
                }
            }

            let sent =
                self.populate_packet(now, space_id, buf, builder.max_size, builder.exact_number);

            // ACK-only packets should only be sent when explicitly allowed. If we write them due to
            // any other reason, there is a bug which leads to one component announcing write
            // readiness while not writing any data. This degrades performance. The condition is
            // only checked if the full MTU is available and when potentially large fixed-size
            // frames aren't queued, so that lack of space in the datagram isn't the reason for just
            // writing ACKs.
            debug_assert!(
                !(sent.is_ack_only(&self.streams)
                    && !can_send.acks
                    && can_send.other
                    && (buf_capacity - builder.datagram_start) == self.path.current_mtu() as usize
                    && self.datagrams.outgoing.is_empty()),
                "SendableFrames was {can_send:?}, but only ACKs have been written"
            );
            pad_datagram |= sent.requires_padding;

            if sent.largest_acked.is_some() {
                self.spaces[space_id].pending_acks.acks_sent();
                self.timers.stop(Timer::MaxAckDelay);
                self.next_bundled_ack_time = Some(now + self.next_bundled_ack_delay());
            }

            // Keep information about the packet around until it gets finalized
            sent_frames = Some(sent);

            // Don't increment space_idx.
            // We stay in the current space and check if there is more data to send.
        }

        // Finish the last packet
        if let Some(mut builder) = builder_storage {
            if pad_datagram {
                builder.pad_to(MIN_INITIAL_SIZE);
            }

            // If this datagram is a loss probe and `segment_size` is larger than `INITIAL_MTU`,
            // then padding it to `segment_size` would risk failure to recover from a reduction in
            // path MTU.
            // Loss probes are the only packets for which we might grow `buf_capacity`
            // by less than `segment_size`.
            if pad_datagram_to_mtu && buf_capacity >= datagram_start + segment_size {
                builder.pad_to(segment_size as u16);
            }

            let last_packet_number = builder.exact_number;
            builder.finish_and_track(now, self, sent_frames, buf);
            self.path
                .congestion
                .on_sent(now, buf.len() as u64, last_packet_number);

            self.config.qlog_sink.emit_recovery_metrics(
                self.pto_count,
                &mut self.path,
                now,
                self.orig_rem_cid,
            );
        }

        self.app_limited = buf.is_empty() && !congestion_blocked;

        // Send MTU probe if necessary
        if buf.is_empty() && self.state.is_established() {
            let space_id = SpaceId::Data;
            let probe_size = self
                .path
                .mtud
                .poll_transmit(now, self.packet_number_filter.peek(&self.spaces[space_id]))?;

            let buf_capacity = probe_size as usize;
            buf.reserve(buf_capacity);

            let mut builder = PacketBuilder::new(
                now,
                space_id,
                self.rem_cids.active(),
                buf,
                buf_capacity,
                0,
                true,
                self,
            )?;

            // We implement MTU probes as ping packets padded up to the probe size
            buf.write(frame::FrameType::PING);
            self.stats.frame_tx.ping += 1;

            // If supported by the peer, we want no delays to the probe's ACK
            if self.peer_supports_ack_frequency() {
                buf.write(frame::FrameType::IMMEDIATE_ACK);
                self.stats.frame_tx.immediate_ack += 1;
            }

            builder.pad_to(probe_size);
            let sent_frames = SentFrames {
                non_retransmits: true,
                ..Default::default()
            };
            builder.finish_and_track(now, self, Some(sent_frames), buf);

            self.stats.path.sent_plpmtud_probes += 1;
            num_datagrams = 1;

            trace!(?probe_size, "writing MTUD probe");
        }

        if buf.is_empty() {
            return None;
        }

        trace!("sending {} bytes in {} datagrams", buf.len(), num_datagrams);
        self.path.total_sent = self.path.total_sent.saturating_add(buf.len() as u64);

        self.stats.udp_tx.on_sent(num_datagrams as u64, buf.len());

        Some(Transmit {
            destination: self.path.remote,
            size: buf.len(),
            ecn: if self.path.sending_ecn {
                Some(EcnCodepoint::Ect0)
            } else {
                None
            },
            segment_size: match num_datagrams {
                1 => None,
                _ => Some(segment_size),
            },
            src_ip: self.local_ip,
        })
    }

    /// Send PATH_CHALLENGE for a previous path if necessary
    pub(super) fn send_path_challenge(
        &mut self,
        now: Instant,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        let (prev_cid, prev_path) = self.prev_path.as_mut()?;
        if !prev_path.challenge_pending {
            return None;
        }
        prev_path.challenge_pending = false;
        let token = prev_path
            .challenge
            .expect("previous path challenge pending without token");
        let destination = prev_path.remote;
        debug_assert_eq!(
            self.highest_space,
            SpaceId::Data,
            "PATH_CHALLENGE queued without 1-RTT keys"
        );
        buf.reserve(MIN_INITIAL_SIZE as usize);

        let buf_capacity = buf.capacity();

        // Use the previous CID to avoid linking the new path with the previous path. We
        // don't bother accounting for possible retirement of that prev_cid because this is
        // sent once, immediately after migration, when the CID is known to be valid. Even
        // if a post-migration packet caused the CID to be retired, it's fair to pretend
        // this is sent first.
        let mut builder = PacketBuilder::new(
            now,
            SpaceId::Data,
            *prev_cid,
            buf,
            buf_capacity,
            0,
            false,
            self,
        )?;
        trace!("validating previous path with PATH_CHALLENGE {:08x}", token);
        buf.write(frame::FrameType::PATH_CHALLENGE);
        buf.write(token);
        self.stats.frame_tx.path_challenge += 1;

        // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
        // to at least the smallest allowed maximum datagram size of 1200 bytes,
        // unless the anti-amplification limit for the path does not permit
        // sending a datagram of this size
        builder.pad_to(MIN_INITIAL_SIZE);

        builder.finish(self, now, buf);
        self.stats.udp_tx.on_sent(1, buf.len());

        Some(Transmit {
            destination,
            size: buf.len(),
            ecn: None,
            segment_size: None,
            src_ip: self.local_ip,
        })
    }

    /// Indicate what types of frames are ready to send for the given space
    pub(super) fn space_can_send(
        &self,
        space_id: SpaceId,
        frame_space_1rtt: usize,
    ) -> SendableFrames {
        if self.spaces[space_id].crypto.is_none()
            && (space_id != SpaceId::Data
                || self.zero_rtt_crypto.is_none()
                || self.side.is_server())
        {
            // No keys available for this space
            return SendableFrames::empty();
        }
        let mut can_send = self.spaces[space_id].can_send(&self.streams);
        if space_id == SpaceId::Data {
            can_send.other |= self.can_send_1rtt(frame_space_1rtt);
        }
        can_send
    }

    pub(super) fn populate_packet(
        &mut self,
        now: Instant,
        space_id: SpaceId,
        buf: &mut Vec<u8>,
        max_size: usize,
        pn: u64,
    ) -> SentFrames {
        let mut sent = SentFrames::default();
        let space = &mut self.spaces[space_id];
        let is_0rtt = space_id == SpaceId::Data && space.crypto.is_none();
        space.pending_acks.maybe_ack_non_eliciting();

        let pre_payload_len = buf.len();

        // HANDSHAKE_DONE
        if !is_0rtt && mem::replace(&mut space.pending.handshake_done, false) {
            buf.write(frame::FrameType::HANDSHAKE_DONE);
            sent.retransmits.get_or_create().handshake_done = true;
            // This is just a u8 counter and the frame is typically just sent once
            self.stats.frame_tx.handshake_done =
                self.stats.frame_tx.handshake_done.saturating_add(1);
        }

        // PING
        if mem::replace(&mut space.ping_pending, false) {
            trace!("PING");
            buf.write(frame::FrameType::PING);
            sent.non_retransmits = true;
            self.stats.frame_tx.ping += 1;
        }

        // IMMEDIATE_ACK
        if mem::replace(&mut space.immediate_ack_pending, false) {
            trace!("IMMEDIATE_ACK");
            buf.write(frame::FrameType::IMMEDIATE_ACK);
            sent.non_retransmits = true;
            self.stats.frame_tx.immediate_ack += 1;
        }

        // ACK
        if space.pending_acks.can_send() {
            Self::try_populate_acks(
                now,
                self.receiving_ecn,
                &mut sent,
                space,
                buf,
                &mut self.stats,
                max_size,
            );
        }

        // ACK_FREQUENCY
        if mem::replace(&mut space.pending.ack_frequency, false) {
            let sequence_number = self.ack_frequency.next_sequence_number();

            // Safe to unwrap because this is always provided when ACK frequency is enabled
            let config = self.config.ack_frequency_config.as_ref().unwrap();

            // Ensure the delay is within bounds to avoid a PROTOCOL_VIOLATION error
            let max_ack_delay = self.ack_frequency.candidate_max_ack_delay(
                self.path.rtt.get(),
                config,
                &self.peer_params,
            );

            trace!(?max_ack_delay, "ACK_FREQUENCY");

            frame::AckFrequency {
                sequence: sequence_number,
                ack_eliciting_threshold: config.ack_eliciting_threshold,
                request_max_ack_delay: max_ack_delay.as_micros().try_into().unwrap_or(VarInt::MAX),
                reordering_threshold: config.reordering_threshold,
            }
            .encode(buf);

            sent.retransmits.get_or_create().ack_frequency = true;

            self.ack_frequency.ack_frequency_sent(pn, max_ack_delay);
            self.stats.frame_tx.ack_frequency += 1;
        }

        // PATH_CHALLENGE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            // Transmit challenges with every outgoing frame on an unvalidated path
            if let Some(token) = self.path.challenge {
                // But only send a packet solely for that purpose at most once
                self.path.challenge_pending = false;
                sent.non_retransmits = true;
                sent.requires_padding = true;
                trace!("PATH_CHALLENGE {:08x}", token);
                buf.write(frame::FrameType::PATH_CHALLENGE);
                buf.write(token);
                self.stats.frame_tx.path_challenge += 1;
            }
        }

        // PATH_RESPONSE
        if buf.len() + 9 < max_size && space_id == SpaceId::Data {
            if let Some(token) = self
                .path_responses
                .pop_on_path(self.path.remote, self.local_ip)
            {
                sent.non_retransmits = true;
                sent.requires_padding = true;
                trace!("PATH_RESPONSE {:08x}", token);
                buf.write(frame::FrameType::PATH_RESPONSE);
                buf.write(token);
                self.stats.frame_tx.path_response += 1;
            }
        }

        // CRYPTO
        while buf.len() + frame::Crypto::SIZE_BOUND < max_size && !is_0rtt {
            let Some(mut frame) = space.pending.crypto.pop_front() else {
                break;
            };

            // Calculate the maximum amount of crypto data we can store in the buffer.
            // Since the offset is known, we can reserve the exact size required to encode it.
            // For length we reserve 2bytes which allows to encode up to 2^14,
            // which is more than what fits into normally sized QUIC frames.
            // SAFETY: CRYPTO stream offsets are encoded as QUIC variable-length integers and so are
            // always less than 2^62.
            let offset = unsafe { VarInt::from_u64_unchecked(frame.offset) };
            let max_crypto_data_size = max_size
                - buf.len()
                - 1 // Frame Type
                - VarInt::size(offset)
                - 2; // Maximum encoded length for frame size, given we send less than 2^14 bytes

            let len = frame
                .data
                .len()
                .min(2usize.pow(14) - 1)
                .min(max_crypto_data_size);

            let data = frame.data.split_to(len);
            let truncated = frame::Crypto {
                offset: frame.offset,
                data,
            };
            trace!(
                "CRYPTO: off {} len {}",
                truncated.offset,
                truncated.data.len()
            );
            truncated.encode(buf);
            self.stats.frame_tx.crypto += 1;
            sent.retransmits.get_or_create().crypto.push_back(truncated);
            if !frame.data.is_empty() {
                frame.offset += len as u64;
                space.pending.crypto.push_front(frame);
            }
        }

        if space_id == SpaceId::Data {
            self.streams.write_control_frames(
                buf,
                &mut space.pending,
                &mut sent.retransmits,
                &mut self.stats.frame_tx,
                max_size,
            );
        }

        // NEW_CONNECTION_ID
        while buf.len() + NewConnectionId::SIZE_BOUND < max_size {
            let Some(issued) = space.pending.new_cids.pop() else {
                break;
            };
            trace!(
                sequence = issued.sequence,
                id = %issued.id,
                "NEW_CONNECTION_ID"
            );
            NewConnectionId {
                sequence: issued.sequence,
                retire_prior_to: self.local_cid_state.retire_prior_to(),
                id: issued.id,
                reset_token: issued.reset_token,
            }
            .encode(buf);
            sent.retransmits.get_or_create().new_cids.push(issued);
            self.stats.frame_tx.new_connection_id += 1;
        }

        // RETIRE_CONNECTION_ID
        while buf.len() + frame::RETIRE_CONNECTION_ID_SIZE_BOUND < max_size {
            let Some(seq) = space.pending.retire_cids.pop() else {
                break;
            };
            trace!(sequence = seq, "RETIRE_CONNECTION_ID");
            buf.write(frame::FrameType::RETIRE_CONNECTION_ID);
            buf.write_var(seq);
            sent.retransmits.get_or_create().retire_cids.push(seq);
            self.stats.frame_tx.retire_connection_id += 1;
        }

        // DATAGRAM
        let mut sent_datagrams = false;
        while buf.len() + Datagram::SIZE_BOUND < max_size && space_id == SpaceId::Data {
            match self.datagrams.write(buf, max_size) {
                true => {
                    sent_datagrams = true;
                    sent.non_retransmits = true;
                    self.stats.frame_tx.datagram += 1;
                }
                false => break,
            }
        }
        if self.datagrams.send_blocked && sent_datagrams {
            self.events.push_back(Event::DatagramsUnblocked);
            self.datagrams.send_blocked = false;
        }

        // NEW_TOKEN
        while let Some(remote_addr) = space.pending.new_tokens.pop() {
            debug_assert_eq!(space_id, SpaceId::Data);
            let ConnectionSide::Server { server_config } = &self.side else {
                panic!("NEW_TOKEN frames should not be enqueued by clients");
            };

            if remote_addr != self.path.remote {
                // NEW_TOKEN frames contain tokens bound to a client's IP address, and are only
                // useful if used from the same IP address.  Thus, we abandon enqueued NEW_TOKEN
                // frames upon an path change. Instead, when the new path becomes validated,
                // NEW_TOKEN frames may be enqueued for the new path instead.
                continue;
            }

            let token = Token::new(
                TokenPayload::Validation {
                    ip: remote_addr.ip(),
                    issued: server_config.time_source.now(),
                },
                &mut self.rng,
            );
            let new_token = NewToken {
                token: token.encode(&*server_config.token_key).into(),
            };

            if buf.len() + new_token.size() >= max_size {
                space.pending.new_tokens.push(remote_addr);
                break;
            }

            new_token.encode(buf);
            sent.retransmits
                .get_or_create()
                .new_tokens
                .push(remote_addr);
            self.stats.frame_tx.new_token += 1;
        }

        // STREAM
        if space_id == SpaceId::Data {
            sent.stream_frames =
                self.streams
                    .write_stream_frames(buf, max_size, self.config.send_fairness);
            self.stats.frame_tx.stream += sent.stream_frames.len() as u64;
        }

        // Bundle ACK with other frames when there is room for them.
        // We want to reuse encryption and underlying protocol overhead,
        // but sending multiple ACKs for a single incoming packet is a waste of peer's resources,
        // so we have next_bundled_ack_time to control when to send ACKs.
        let any_frames_sent = buf.len() > pre_payload_len;
        if any_frames_sent
            && sent.largest_acked.is_none()
            && self.next_bundled_ack_time.is_some_and(|time| time <= now)
            && space.pending_acks.can_send_with_other_frames()
        {
            Self::try_populate_acks(
                now,
                self.receiving_ecn,
                &mut sent,
                space,
                buf,
                &mut self.stats,
                max_size,
            );
        }

        sent
    }

    /// The delay to wait after sending an ACK before bundling the next one.
    ///
    /// This delay prevents waste of peer's resources with processing bundled
    /// ACKs unnecessarily frequently.
    ///
    /// If we receive an ack-eliciting packet while this delay is still pending,
    /// `next_bundled_ack_time` is reset to `now`, which means this delay will be ignored.
    /// So this delay only matters when we keep sending but stop receiving ack-eliciting
    /// packets for a while.
    ///
    /// This should be at least `RTT + peer's max_ack_delay`: since a bundled ACK frame rides
    /// along with an ack-eliciting frame, the packet carrying it is itself ack-eliciting.
    /// We should give the peer enough time to acknowledge it.
    /// Otherwise, we risk bundling another ACK before the peer has even had a chance
    /// to acknowledge the previous one, which is a waste of remote peer's resources.
    fn next_bundled_ack_delay(&self) -> Duration {
        self.path.rtt.get() + self.ack_frequency.peer_max_ack_delay + TIMER_GRANULARITY
    }

    /// Tries to write pending ACKs into a buffer if there is enough space.
    ///
    /// If the ACK frame does not fit into the buffer, the ACK frame will not
    /// be sent at all.
    ///
    /// This method assumes ACKs are pending, and should only be called if
    /// `!PendingAcks::ranges().is_empty()` returns `true`.
    pub(super) fn try_populate_acks(
        now: Instant,
        receiving_ecn: bool,
        sent: &mut SentFrames,
        space: &mut PacketSpace,
        buf: &mut Vec<u8>,
        stats: &mut ConnectionStats,
        max_size: usize,
    ) {
        debug_assert!(!space.pending_acks.ranges().is_empty());

        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        debug_assert!(space.crypto.is_some(), "tried to send ACK in 0-RTT");
        let ecn = if receiving_ecn {
            Some(&space.ecn_counters)
        } else {
            None
        };

        let delay_micros = space.pending_acks.ack_delay(now).as_micros() as u64;

        // TODO: This should come from `TransportConfig` if that gets configurable.
        let ack_delay_exp = TransportParameters::default().ack_delay_exponent;
        let delay = delay_micros >> ack_delay_exp.into_inner();

        trace!(
            "ACK {:?}, Delay = {}us",
            space.pending_acks.ranges(),
            delay_micros
        );

        let no_acks_len = buf.len();
        frame::Ack::encode(delay as _, space.pending_acks.ranges(), ecn, buf);
        if buf.len() > max_size {
            // The ACK frame is too large. Remove it.
            buf.truncate(no_acks_len);
            return;
        }
        sent.largest_acked = space.pending_acks.ranges().max();
        stats.frame_tx.acks += 1;
    }
}
