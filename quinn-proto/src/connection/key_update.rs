use super::*;

impl Connection {

    pub(super) fn decrypt_packet(
        &mut self,
        now: Instant,
        packet: &mut Packet,
    ) -> Result<Option<u64>, Option<TransportError>> {
        let result = packet_crypto::decrypt_packet_body(
            packet,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.key_phase,
            self.prev_crypto.as_ref(),
            self.next_crypto.as_ref(),
        )?;

        let Some(result) = result else {
            return Ok(None);
        };

        if result.outgoing_key_update_acked {
            if let Some(prev) = self.prev_crypto.as_mut() {
                prev.end_packet = Some((result.number, now));
                self.set_key_discard_timer(now, packet.header.space());
            }
        }

        if result.incoming_key_update {
            trace!("key update authenticated");
            self.update_keys(Some((result.number, now)), true);
            self.set_key_discard_timer(now, packet.header.space());
        }

        Ok(Some(result.number))
    }

    pub(super) fn update_keys(&mut self, end_packet: Option<(u64, Instant)>, remote: bool) {
        trace!("executing key update");
        // Generate keys for the key phase after the one we're switching to, store them in
        // `next_crypto`, make the contents of `next_crypto` current, and move the current keys into
        // `prev_crypto`.
        let new = self
            .crypto
            .next_1rtt_keys()
            .expect("only called for `Data` packets");
        self.key_phase_size = new
            .local
            .confidentiality_limit()
            .saturating_sub(KEY_UPDATE_MARGIN);
        let old = mem::replace(
            &mut self.spaces[SpaceId::Data]
                .crypto
                .as_mut()
                .unwrap() // safe because update_keys() can only be triggered by short packets
                .packet,
            mem::replace(self.next_crypto.as_mut().unwrap(), new),
        );
        self.spaces[SpaceId::Data].sent_with_keys = 0;
        self.prev_crypto = Some(PrevCrypto {
            crypto: old,
            end_packet,
            update_unacked: remote,
        });
        self.key_phase = !self.key_phase;
    }

}
