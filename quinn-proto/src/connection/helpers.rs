use super::*;

impl Connection {

    /// Whether we have 1-RTT data to send
    ///
    /// See also `self.space(SpaceId::Data).can_send()`
    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.streams.can_send_stream_data()
            || self.path.challenge_pending
            || self
                .prev_path
                .as_ref()
                .is_some_and(|(_, x)| x.challenge_pending)
            || !self.path_responses.is_empty()
            || self
                .datagrams
                .outgoing
                .front()
                .is_some_and(|x| x.size(true) <= max_size)
    }

    /// Update counters to account for a packet becoming acknowledged, lost, or abandoned
    pub(super) fn remove_in_flight(&mut self, packet: &SentPacket) {
        // Visit known paths from newest to oldest to find the one `packet` was sent on
        for path in [&mut self.path]
            .into_iter()
            .chain(self.prev_path.as_mut().map(|(_, data)| data))
        {
            if path.remove_in_flight(packet) {
                return;
            }
        }
    }

    /// Release `prev_path` once it has served its purpose, to avoid retaining a stale path
    ///
    /// After `path_changed` the active path is already validated, so the previous path is kept
    /// solely to keep accounting its still-in-flight packets against the correct congestion
    /// controller. Once those packets have all been acked or lost, the previous path carries no
    /// state worth retaining and can be dropped.
    ///
    /// During `migrate` the active path is *not* yet validated and the previous path is the
    /// fallback we restore on `Timer::PathValidation` failure (see the `PathValidation` arm in
    /// `handle_timeout`); the `self.path.challenge.is_none()` guard ensures we never reap it then.
    pub(super) fn reap_prev_path(&mut self) {
        if self.path.challenge.is_some() {
            // Active path still validating: keep the fallback.
            return;
        }
        if let Some((_, prev)) = &self.prev_path {
            if !prev.challenge_pending && prev.in_flight.bytes == 0 {
                self.prev_path = None;
            }
        }
    }

    /// Terminate the connection instantly, without sending a close packet
    pub(super) fn kill(&mut self, reason: ConnectionError) {
        self.close_common();
        self.error = Some(reason);
        self.state = State::Drained;
        self.endpoint_events.push_back(EndpointEventInner::Drained);
    }

    /// Storage size required for the largest packet known to be supported by the current path
    ///
    /// Buffers passed to [`Connection::poll_transmit`] should be at least this large.
    pub fn current_mtu(&self) -> u16 {
        self.path.current_mtu()
    }

    /// Size of non-frame data for a 1-RTT packet
    ///
    /// Quantifies space consumed by the QUIC header and AEAD tag. All other bytes in a packet are
    /// frames. Changes if the length of the remote connection ID changes, which is expected to be
    /// rare. If `pn` is specified, may additionally change unpredictably due to variations in
    /// latency and packet loss.
    pub(super) fn predict_1rtt_overhead(&self, pn: Option<u64>) -> usize {
        let pn_len = match pn {
            Some(pn) => PacketNumber::new(
                pn,
                self.spaces[SpaceId::Data].largest_acked_packet.unwrap_or(0),
            )
            .len(),
            // Upper bound
            None => 4,
        };

        // 1 byte for flags
        1 + self.rem_cids.active().len() + pn_len + self.tag_len_1rtt()
    }

    pub(super) fn tag_len_1rtt(&self) -> usize {
        let key = match self.spaces[SpaceId::Data].crypto.as_ref() {
            Some(crypto) => Some(&*crypto.packet.local),
            None => self.zero_rtt_crypto.as_ref().map(|x| &*x.packet),
        };
        // If neither Data nor 0-RTT keys are available, make a reasonable tag length guess. As of
        // this writing, all QUIC cipher suites use 16-byte tags. We could return `None` instead,
        // but that would needlessly prevent sending datagrams during 0-RTT.
        key.map_or(16, |x| x.tag_len())
    }

    /// Mark the path as validated, and enqueue NEW_TOKEN frames to be sent as appropriate
    pub(super) fn on_path_validated(&mut self) {
        self.path.validated = true;
        let ConnectionSide::Server { server_config } = &self.side else {
            return;
        };
        let new_tokens = &mut self.spaces[SpaceId::Data as usize].pending.new_tokens;
        new_tokens.clear();
        for _ in 0..server_config.validation_token.sent {
            new_tokens.push(self.path.remote);
        }
    }
}
