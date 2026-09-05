use super::*;

impl Connection {

    pub(super) fn peer_supports_ack_frequency(&self) -> bool {
        self.peer_params.min_ack_delay.is_some()
    }

    #[cfg(test)]
    pub(crate) fn disable_peer_ack_frequency(&mut self) {
        self.peer_params.min_ack_delay = None;
    }

    /// Send an IMMEDIATE_ACK frame to the remote endpoint
    ///
    /// According to the spec, this will result in an error if the remote endpoint does not support
    /// the Acknowledgement Frequency extension
    pub(crate) fn immediate_ack(&mut self) {
        self.spaces[self.highest_space].immediate_ack_pending = true;
    }

    /// Decodes a packet, returning its decrypted payload, so it can be inspected in tests
    #[cfg(test)]
    pub(crate) fn decode_packet(&self, event: &ConnectionEvent) -> Option<Vec<u8>> {
        let ConnectionEventInner::Datagram(DatagramConnectionEvent {
            first_decode,
            remaining,
            ..
        }) = &event.0
        else {
            return None;
        };

        if remaining.is_some() {
            panic!("Packets should never be coalesced in tests");
        }

        let decrypted_header = packet_crypto::unprotect_header(
            first_decode.clone(),
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.peer_params.stateless_reset_token,
        )?;

        let mut packet = decrypted_header.packet?;
        packet_crypto::decrypt_packet_body(
            &mut packet,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.key_phase,
            self.prev_crypto.as_ref(),
            self.next_crypto.as_ref(),
        )
        .ok()?;

        Some(packet.payload.to_vec())
    }

    /// The number of bytes of packets containing retransmittable frames that have not been
    /// acknowledged or declared lost.
    #[cfg(test)]
    pub(crate) fn bytes_in_flight(&self) -> u64 {
        self.path.in_flight.bytes
    }

    #[cfg(test)]
    pub(crate) fn previous_path_bytes_in_flight(&self) -> Option<u64> {
        self.prev_path
            .as_ref()
            .map(|(_, path)| path.in_flight.bytes)
    }

    #[cfg(test)]
    pub(crate) fn path_generation(&self) -> u64 {
        self.path.generation()
    }

    #[cfg(test)]
    pub(crate) fn pto_count(&self) -> u32 {
        self.pto_count
    }

    #[cfg(test)]
    pub(crate) fn set_pto_count_for_test(&mut self, pto_count: u32, now: Instant) {
        self.pto_count = pto_count;
        self.set_loss_detection_timer(now);
    }

    /// Number of bytes worth of non-ack-only packets that may be sent
    #[cfg(test)]
    pub(crate) fn congestion_window(&self) -> u64 {
        self.path
            .congestion
            .window()
            .saturating_sub(self.path.in_flight.bytes)
    }

    /// Whether no timers but keepalive, idle, rtt, pushnewcid, and key discard are running
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        Timer::VALUES
            .iter()
            .filter(|&&t| !matches!(t, Timer::KeepAlive | Timer::PushNewCid | Timer::KeyDiscard))
            .filter_map(|&t| Some((t, self.timers.get(t)?)))
            .min_by_key(|&(_, time)| time)
            .is_none_or(|(timer, _)| timer == Timer::Idle)
    }

    /// Whether explicit congestion notification is in use on outgoing packets.
    #[cfg(test)]
    pub(crate) fn using_ecn(&self) -> bool {
        self.path.sending_ecn
    }

    /// The number of received bytes in the current path
    #[cfg(test)]
    pub(crate) fn total_recvd(&self) -> u64 {
        self.path.total_recvd
    }

    #[cfg(test)]
    pub(crate) fn active_local_cid_seq(&self) -> (u64, u64) {
        self.local_cid_state.active_seq()
    }

    /// Instruct the peer to replace previously issued CIDs by sending a NEW_CONNECTION_ID frame
    /// with updated `retire_prior_to` field set to `v`
    #[cfg(test)]
    pub(crate) fn rotate_local_cid(&mut self, v: u64, now: Instant) {
        let n = self.local_cid_state.assign_retire_seq(v);
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(now, n));
    }

    /// Check the current active remote CID sequence
    #[cfg(test)]
    pub(crate) fn active_rem_cid_seq(&self) -> u64 {
        self.rem_cids.active_seq()
    }

    /// Returns the detected maximum udp payload size for the current path
    #[cfg(test)]
    pub(crate) fn path_mtu(&self) -> u16 {
        self.path.current_mtu()
    }

}
