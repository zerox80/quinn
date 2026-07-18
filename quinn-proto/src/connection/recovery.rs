use super::*;

impl Connection {

    pub(super) fn on_ack_received(
        &mut self,
        now: Instant,
        space: SpaceId,
        ack: frame::Ack,
    ) -> Result<(), TransportError> {
        if ack.largest >= self.spaces[space].next_packet_number {
            return Err(TransportError::PROTOCOL_VIOLATION("unsent packet acked"));
        }
        let active_path = self.path.generation();
        let mut new_largest_active_path = false;
        {
            let space = &mut self.spaces[space];
            if space.largest_acked_packet.is_none_or(|pn| ack.largest > pn) {
                space.largest_acked_packet = Some(ack.largest);
                if let Some(info) = space.sent_packets.get(&ack.largest) {
                    // This should always succeed, but a misbehaving peer might ACK a packet we
                    // haven't sent. At worst, that will result in us spuriously reducing the
                    // congestion window.
                    space.largest_acked_packet_sent = info.time_sent;
                    new_largest_active_path = info.path_generation == active_path;
                }
            }
        };

        if self.detect_spurious_loss(&ack, space, active_path) {
            self.stats.path.spurious_congestion_events += 1;
            self.path.congestion.on_spurious_congestion_event();
        }

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        let mut newly_acked = ArrayRangeSet::new();
        for range in ack.iter() {
            self.packet_number_filter.check_ack(space, range.clone())?;
            for (&pn, _) in self.spaces[space].sent_packets.range(range) {
                newly_acked.insert_one(pn);
            }
        }

        if newly_acked.is_empty() {
            return Ok(());
        }

        let mut active_ack_eliciting_acked = false;
        let mut active_newly_acked = 0;
        let mut active_congestion_acked = false;
        for packet in newly_acked.elts() {
            if let Some(info) = self.spaces[space].take(packet) {
                let active_path_packet = info.path_generation == active_path;
                if let Some(acked) = info.largest_acked {
                    // Assume ACKs for all packets below the largest acknowledged in `packet` have
                    // been received. This can cause the peer to spuriously retransmit if some of
                    // our earlier ACKs were lost, but allows for simpler state tracking. See
                    // discussion at
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-limiting-ranges-by-tracking
                    self.spaces[space].pending_acks.subtract_below(acked);
                }
                if active_path_packet {
                    active_ack_eliciting_acked |= info.ack_eliciting;
                    active_newly_acked += 1;

                    // Notify MTU discovery that a packet was acked, because it might be an MTU probe
                    let mtu_updated = self.path.mtud.on_acked(space, packet, info.size);
                    if mtu_updated {
                        self.path
                            .congestion
                            .on_mtu_update(self.path.mtud.current_mtu());
                    }
                }

                // Notify ack frequency that a packet was acked, because it might contain an ACK_FREQUENCY frame
                self.ack_frequency.on_acked(packet);

                active_congestion_acked |= self.on_packet_acked(now, info, active_path_packet);
            }
        }

        if active_congestion_acked {
            self.path.congestion.on_end_acks(
                now,
                self.path.in_flight.bytes,
                self.app_limited,
                self.spaces[space].largest_acked_packet,
            );
        }

        if new_largest_active_path && active_ack_eliciting_acked {
            let ack_delay = if space != SpaceId::Data {
                Duration::from_micros(0)
            } else {
                cmp::min(
                    self.ack_frequency.peer_max_ack_delay,
                    Duration::from_micros(ack.delay << self.peer_params.ack_delay_exponent.0),
                )
            };
            let rtt = now.saturating_duration_since(self.spaces[space].largest_acked_packet_sent);
            self.path.rtt.update(ack_delay, rtt);
            if self.path.first_packet_after_rtt_sample.is_none() {
                self.path.first_packet_after_rtt_sample =
                    Some((space, self.spaces[space].next_packet_number));
            }
        }

        // Must be called before crypto/pto_count are clobbered
        self.detect_lost_packets(now, space, true);

        if active_ack_eliciting_acked && self.peer_completed_address_validation() {
            self.pto_count = 0;
        }

        // Explicit congestion notification
        if self.path.sending_ecn {
            if let Some(ecn) = ack.ecn {
                // We only examine ECN counters from ACKs that we are certain we received in transmit
                // order, allowing us to compute an increase in ECN counts to compare against the number
                // of newly acked packets that remains well-defined in the presence of arbitrary packet
                // reordering.
                if new_largest_active_path {
                    let sent = self.spaces[space].largest_acked_packet_sent;
                    self.process_ecn(now, space, active_newly_acked, ecn, sent);
                }
            } else if active_newly_acked != 0 {
                // We always start out sending ECN, so any ack that doesn't acknowledge it disables it.
                debug!("ECN not acknowledged by peer");
                self.path.sending_ecn = false;
            }
        }

        self.set_loss_detection_timer(now);
        Ok(())
    }

    pub(super) fn detect_spurious_loss(&mut self, ack: &frame::Ack, space: SpaceId, active_path: u64) -> bool {
        let lost_packets = &mut self.spaces[space].lost_packets;

        if lost_packets.is_empty() {
            return false;
        }

        let had_active_loss = lost_packets
            .values()
            .any(|info| info.path_generation == active_path);
        let mut active_loss_acked = false;
        for range in ack.iter() {
            let spurious_losses: Vec<_> = lost_packets
                .range(range.clone())
                .map(|(&pn, info)| (pn, info.path_generation == active_path))
                .collect();

            for (pn, active_path_packet) in spurious_losses {
                active_loss_acked |= active_path_packet;
                lost_packets.remove(&pn);
            }
        }

        // If this ACK frame acknowledged all deemed lost packets,
        // then we have raised a spurious congestion event in the past.
        // We cannot conclude when there are remaining packets,
        // but future ACK frames might indicate a spurious loss detection.
        had_active_loss
            && active_loss_acked
            && !lost_packets
                .values()
                .any(|info| info.path_generation == active_path)
    }

    /// Drain lost packets that we reasonably think will never arrive
    ///
    /// The current criterion is copied from `msquic`:
    /// discard packets that were sent earlier than 2 probe timeouts ago.
    pub(super) fn drain_lost_packets(&mut self, now: Instant, space: SpaceId) {
        let two_pto = 2 * self.path.rtt.pto_base();

        let lost_packets = &mut self.spaces[space].lost_packets;
        lost_packets.retain(|_pn, info| now.saturating_duration_since(info.time_sent) <= two_pto);
    }

    /// Process a new ECN block from an in-order ACK
    pub(super) fn process_ecn(
        &mut self,
        now: Instant,
        space: SpaceId,
        newly_acked: u64,
        ecn: frame::EcnCounts,
        largest_sent_time: Instant,
    ) {
        match self.spaces[space].detect_ecn(newly_acked, ecn) {
            Err(e) => {
                debug!("halting ECN due to verification failure: {}", e);
                self.path.sending_ecn = false;
                // Wipe out the existing value because it might be garbage and could interfere with
                // future attempts to use ECN on new paths.
                self.spaces[space].ecn_feedback = frame::EcnCounts::ZERO;
            }
            Ok(false) => {}
            Ok(true) => {
                self.stats.path.congestion_events += 1;
                self.path
                    .congestion
                    .on_congestion_event(now, largest_sent_time, false, true, 0);
            }
        }
    }

    // Not timing-aware, so it's safe to call this for inferred acks, such as arise from
    // high-latency handshakes
    pub(super) fn on_packet_acked(
        &mut self,
        now: Instant,
        info: SentPacket,
        active_path_packet: bool,
    ) -> bool {
        self.remove_in_flight(&info);
        let update_congestion =
            active_path_packet && info.ack_eliciting && self.path.challenge.is_none();
        if update_congestion {
            // Only pass ACKs to the congestion controller if we are not validating the current
            // path, so as to ignore any ACKs from older paths still coming in.
            self.path.congestion.on_ack(
                now,
                info.time_sent,
                info.size.into(),
                self.app_limited,
                &self.path.rtt,
            );
        }

        // Update state for confirmed delivery of frames
        if let Some(retransmits) = info.retransmits.get() {
            for (id, _) in retransmits.reset_stream.iter() {
                self.streams.reset_acked(*id);
            }
        }

        for frame in info.stream_frames {
            self.streams.received_ack_of(frame);
        }

        update_congestion
    }

    pub(super) fn set_key_discard_timer(&mut self, now: Instant, space: SpaceId) {
        let start = if self.zero_rtt_crypto.is_some() {
            now
        } else {
            self.prev_crypto
                .as_ref()
                .expect("no previous keys")
                .end_packet
                .as_ref()
                .expect("update not acknowledged yet")
                .1
        };
        self.timers
            .set(Timer::KeyDiscard, start + self.pto(space) * 3);
    }

    pub(super) fn on_loss_detection_timeout(&mut self, now: Instant) {
        if let Some((_, pn_space)) = self.loss_time_and_space() {
            // Time threshold loss Detection
            self.detect_lost_packets(now, pn_space, false);
            self.set_loss_detection_timer(now);
            return;
        }

        let Some((_, space)) = self.pto_time_and_space(now) else {
            error!("PTO expired while unset");
            return;
        };
        trace!(
            in_flight = self.path.in_flight.bytes,
            count = self.pto_count,
            ?space,
            "PTO fired"
        );

        let count = match self.path.in_flight.ack_eliciting {
            // A PTO when we're not expecting any ACKs must be due to handshake anti-amplification
            // deadlock preventions
            0 => {
                debug_assert!(!self.peer_completed_address_validation());
                1
            }
            // Conventional loss probe
            _ => 2,
        };
        self.spaces[space].loss_probes = self.spaces[space].loss_probes.saturating_add(count);
        self.pto_count = self.pto_count.saturating_add(1);
        self.set_loss_detection_timer(now);
    }

    pub(super) fn detect_lost_packets(&mut self, now: Instant, pn_space: SpaceId, due_to_ack: bool) {
        let mut lost_packets = Vec::<u64>::new();
        let mut lost_mtu_probe = None;
        let active_path = self.path.generation();
        let in_flight_mtu_probe = self.path.mtud.in_flight_mtu_probe();
        let rtt = self.path.rtt.conservative();
        let loss_delay = cmp::max(rtt.mul_f32(self.config.time_threshold), TIMER_GRANULARITY);

        let largest_acked_packet = self.spaces[pn_space].largest_acked_packet.unwrap();
        let packet_threshold = self.config.packet_threshold as u64;
        let mut size_of_lost_packets = 0u64;
        let mut active_size_of_lost_packets = 0u64;

        // InPersistentCongestion: Determine if all packets in the time period before the newest
        // lost packet, including the edges, are marked lost. PTO computation must always
        // include max ACK delay, i.e. operate as if in Data space (see RFC9001 §7.6.1).
        let congestion_period = self
            .pto(SpaceId::Data)
            .saturating_mul(self.config.persistent_congestion_threshold);
        let mut persistent_congestion_start: Option<Instant> = None;
        let mut prev_packet = None;
        let mut in_persistent_congestion = false;
        let mut active_largest_lost_sent = None;

        let space = &mut self.spaces[pn_space];
        space.loss_time = None;

        for (&packet, info) in space.sent_packets.range(0..largest_acked_packet) {
            let active_path_packet = info.path_generation == active_path;
            if prev_packet != Some(packet.wrapping_sub(1)) {
                // An intervening packet was acknowledged
                persistent_congestion_start = None;
            }

            // Packets sent before now - loss_delay are deemed lost.
            // However, we avoid this subtraction as it can panic and there's no
            // saturating equivalent of this substraction operation with a Duration.
            let packet_too_old = now.saturating_duration_since(info.time_sent) >= loss_delay;
            if packet_too_old || largest_acked_packet >= packet + packet_threshold {
                if active_path_packet && Some(packet) == in_flight_mtu_probe {
                    // Lost MTU probes are not included in `lost_packets`, because they should not
                    // trigger a congestion control response
                    lost_mtu_probe = in_flight_mtu_probe;
                } else {
                    lost_packets.push(packet);
                    size_of_lost_packets += info.size as u64;
                    if active_path_packet {
                        active_size_of_lost_packets += info.size as u64;
                        active_largest_lost_sent = Some(info.time_sent);
                    }
                    if active_path_packet && info.ack_eliciting && due_to_ack {
                        match persistent_congestion_start {
                            // Two ACK-eliciting packets lost more than congestion_period apart, with no
                            // ACKed packets in between
                            Some(start) if info.time_sent - start > congestion_period => {
                                in_persistent_congestion = true;
                            }
                            // Persistent congestion must start after the first RTT sample
                            None if self
                                .path
                                .first_packet_after_rtt_sample
                                .is_some_and(|x| x < (pn_space, packet)) =>
                            {
                                persistent_congestion_start = Some(info.time_sent);
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                let next_loss_time = info.time_sent + loss_delay;
                space.loss_time = Some(
                    space
                        .loss_time
                        .map_or(next_loss_time, |x| cmp::min(x, next_loss_time)),
                );
                persistent_congestion_start = None;
            }

            prev_packet = Some(packet);
        }

        self.drain_lost_packets(now, pn_space);

        // OnPacketsLost
        if !lost_packets.is_empty() {
            let old_bytes_in_flight = self.path.in_flight.bytes;
            self.stats.path.lost_packets += lost_packets.len() as u64;
            self.stats.path.lost_bytes += size_of_lost_packets;
            trace!(
                "packets lost: {:?}, bytes lost: {}",
                lost_packets, size_of_lost_packets
            );

            let mut active_non_probe_lost = false;
            for &packet in &lost_packets {
                let info = self.spaces[pn_space].take(packet).unwrap(); // safe: lost_packets is populated just above
                let active_path_packet = info.path_generation == active_path;
                self.config.qlog_sink.emit_packet_lost(
                    packet,
                    &info,
                    loss_delay,
                    pn_space,
                    now,
                    self.orig_rem_cid,
                );

                self.remove_in_flight(&info);
                for frame in info.stream_frames {
                    self.streams.retransmit(frame);
                }
                self.spaces[pn_space].pending |= info.retransmits;
                if active_path_packet {
                    self.path.mtud.on_non_probe_lost(packet, info.size);
                    active_non_probe_lost = true;
                }

                self.spaces[pn_space].lost_packets.insert(
                    packet,
                    LostPacket {
                        path_generation: info.path_generation,
                        time_sent: info.time_sent,
                    },
                );
            }

            if active_non_probe_lost && self.path.mtud.black_hole_detected(now) {
                self.stats.path.black_holes_detected += 1;
                self.path
                    .congestion
                    .on_mtu_update(self.path.mtud.current_mtu());
                if let Some(max_datagram_size) = self.datagrams().max_size() {
                    if self.datagrams.drop_oversized(max_datagram_size)
                        && self.datagrams.send_blocked
                    {
                        self.datagrams.send_blocked = false;
                        self.events.push_back(Event::DatagramsUnblocked);
                    }
                }
            }

            // Don't apply a congestion penalty for lost ack-only packets. Only losses on the
            // *active* path change `self.path.in_flight.bytes` and populate
            // `active_largest_lost_sent` (see `remove_in_flight`), so a previous path's losses after
            // migration never reach the active path's congestion controller. The `if let` keeps this
            // robust against a panic should that invariant ever be weakened by a refactor.
            let lost_active_ack_eliciting = old_bytes_in_flight != self.path.in_flight.bytes;
            debug_assert!(
                !lost_active_ack_eliciting || active_largest_lost_sent.is_some(),
                "active-path in-flight bytes changed without recording an active-path loss",
            );

            if let (true, Some(active_largest_lost_sent)) =
                (lost_active_ack_eliciting, active_largest_lost_sent)
            {
                self.stats.path.congestion_events += 1;
                self.path.congestion.on_congestion_event(
                    now,
                    active_largest_lost_sent,
                    in_persistent_congestion,
                    false,
                    active_size_of_lost_packets,
                );
            }
        }

        // Handle a lost MTU probe
        if let Some(packet) = lost_mtu_probe {
            let info = self.spaces[SpaceId::Data].take(packet).unwrap(); // safe: lost_mtu_probe is omitted from lost_packets, and therefore must not have been removed yet
            self.remove_in_flight(&info);
            self.path.mtud.on_probe_lost();
            self.stats.path.lost_plpmtud_probes += 1;
        }

        // Acks and losses above may have drained the previous path; release it once it is empty.
        self.reap_prev_path();
    }

    pub(super) fn loss_time_and_space(&self) -> Option<(Instant, SpaceId)> {
        SpaceId::iter()
            .filter_map(|id| Some((self.spaces[id].loss_time?, id)))
            .min_by_key(|&(time, _)| time)
    }

    pub(super) fn pto_time_and_space(&self, now: Instant) -> Option<(Instant, SpaceId)> {
        let backoff = 2u32.pow(self.pto_count.min(MAX_BACKOFF_EXPONENT));
        let mut duration = self.path.rtt.pto_base() * backoff;

        if self.path.in_flight.ack_eliciting == 0 {
            debug_assert!(!self.peer_completed_address_validation());
            let space = match self.highest_space {
                SpaceId::Handshake => SpaceId::Handshake,
                _ => SpaceId::Initial,
            };
            return Some((now + duration, space));
        }

        let mut result = None;
        for space in SpaceId::iter() {
            if !self.spaces[space].has_in_flight() {
                continue;
            }
            if space == SpaceId::Data {
                // Skip ApplicationData until handshake completes.
                if self.is_handshaking() {
                    return result;
                }
                // Include max_ack_delay and backoff for ApplicationData.
                duration += self.ack_frequency.max_ack_delay_for_pto() * backoff;
            }
            let Some(last_ack_eliciting) = self.spaces[space].time_of_last_ack_eliciting_packet
            else {
                continue;
            };
            let pto = last_ack_eliciting + duration;
            if result.is_none_or(|(earliest_pto, _)| pto < earliest_pto) {
                result = Some((pto, space));
            }
        }
        result
    }

    pub(super) fn peer_completed_address_validation(&self) -> bool {
        if self.side.is_server() || self.state.is_closed() {
            return true;
        }
        // The server is guaranteed to have validated our address if any of our handshake or 1-RTT
        // packets are acknowledged or we've seen HANDSHAKE_DONE and discarded handshake keys.
        self.spaces[SpaceId::Handshake]
            .largest_acked_packet
            .is_some()
            || self.spaces[SpaceId::Data].largest_acked_packet.is_some()
            || (self.spaces[SpaceId::Data].crypto.is_some()
                && self.spaces[SpaceId::Handshake].crypto.is_none())
    }

    pub(super) fn set_loss_detection_timer(&mut self, now: Instant) {
        if self.state.is_closed() {
            // No loss detection takes place on closed connections, and `close_common` already
            // stopped time timer. Ensure we don't restart it inadvertently, e.g. in response to a
            // reordered packet being handled by state-insensitive code.
            return;
        }

        if let Some((loss_time, _)) = self.loss_time_and_space() {
            // Time threshold loss detection.
            self.timers.set(Timer::LossDetection, loss_time);
            return;
        }

        if self.path.anti_amplification_blocked(1) {
            // We wouldn't be able to send anything, so don't bother.
            self.timers.stop(Timer::LossDetection);
            return;
        }

        if self.path.in_flight.ack_eliciting == 0 && self.peer_completed_address_validation() {
            // There is nothing to detect lost, so no timer is set. However, the client needs to arm
            // the timer if the server might be blocked by the anti-amplification limit.
            self.timers.stop(Timer::LossDetection);
            return;
        }

        // Determine which PN space to arm PTO for.
        // Calculate PTO duration
        if let Some((timeout, _)) = self.pto_time_and_space(now) {
            self.timers.set(Timer::LossDetection, timeout);
        } else {
            self.timers.stop(Timer::LossDetection);
        }
    }

    /// Probe Timeout
    pub(super) fn pto(&self, space: SpaceId) -> Duration {
        let max_ack_delay = match space {
            SpaceId::Initial | SpaceId::Handshake => Duration::ZERO,
            SpaceId::Data => self.ack_frequency.max_ack_delay_for_pto(),
        };
        self.path.rtt.pto_base() + max_ack_delay
    }

}
