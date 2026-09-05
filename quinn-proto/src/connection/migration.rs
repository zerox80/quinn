use super::*;

impl Connection {

    pub(super) fn migrate(&mut self, now: Instant, remote: SocketAddr) {
        trace!(%remote, "migration initiated");
        self.path_counter = self.path_counter.wrapping_add(1);
        // Reset rtt/congestion state for new path unless it looks like a NAT rebinding.
        // Note that the congestion window will not grow until validation terminates. Helps mitigate
        // amplification attacks performed by spoofing source addresses.
        let mut new_path = if remote.is_ipv4() && remote.ip() == self.path.remote.ip() {
            PathData::from_previous(remote, &self.path, self.path_counter, now)
        } else {
            let peer_max_udp_payload_size =
                u16::try_from(self.peer_params.max_udp_payload_size.into_inner())
                    .unwrap_or(u16::MAX);
            PathData::new(
                remote,
                self.allow_mtud,
                Some(peer_max_udp_payload_size),
                self.path_counter,
                now,
                &self.config,
            )
        };
        new_path.challenge = Some(self.rng.random());
        new_path.challenge_pending = true;
        let prev_pto = self.pto(SpaceId::Data);

        let mut prev = mem::replace(&mut self.path, new_path);
        self.events.push_back(Event::PathUpdated);

        // Don't clobber the original path if the previous one hasn't been validated yet
        if prev.challenge.is_none() {
            prev.challenge = Some(self.rng.random());
            prev.challenge_pending = true;
            // We haven't updated the remote CID yet, this captures the remote CID we were using on
            // the previous path.
            self.prev_path = Some((self.rem_cids.active(), prev));
        }

        self.timers.set(
            Timer::PathValidation,
            now + 3 * cmp::max(self.pto(SpaceId::Data), prev_pto),
        );
    }

    /// Handle a change in the local address, i.e. an active migration
    pub fn local_address_changed(&mut self) {
        self.update_rem_cid();
        self.ping();
    }

    /// Switch to a previously unused remote connection ID, if possible
    pub(super) fn update_rem_cid(&mut self) {
        let Some((reset_token, retired)) = self.rem_cids.next() else {
            return;
        };

        // Retire the current remote CID and any CIDs we had to skip.
        self.spaces[SpaceId::Data]
            .pending
            .retire_cids
            .extend(retired);
        self.set_reset_token(reset_token);
    }

    pub(super) fn set_reset_token(&mut self, reset_token: ResetToken) {
        self.endpoint_events
            .push_back(EndpointEventInner::ResetToken(
                self.path.remote,
                reset_token,
            ));
        self.peer_params.stateless_reset_token = Some(reset_token);
    }

    /// Issue an initial set of connection IDs to the peer upon connection
    pub(super) fn issue_first_cids(&mut self, now: Instant) {
        if self.local_cid_state.cid_len() == 0 {
            return;
        }

        // Subtract 1 to account for the CID we supplied while handshaking
        let mut n = self.peer_params.issue_cids_limit() - 1;
        if let ConnectionSide::Server { server_config } = &self.side {
            if server_config.has_preferred_address() {
                // We also sent a CID in the transport parameters
                n -= 1;
            }
        }
        self.endpoint_events
            .push_back(EndpointEventInner::NeedIdentifiers(now, n));
    }

}
