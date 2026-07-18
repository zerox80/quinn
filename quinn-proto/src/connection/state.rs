use bytes::Bytes;

use crate::frame::Close;

#[allow(unreachable_pub)] // fuzzing only
#[derive(Clone)]
pub enum State {
    Handshake(Handshake),
    Established,
    Closed(Closed),
    Draining,
    /// Waiting for application to call close so we can dispose of the resources
    Drained,
}

impl State {
    pub(super) fn closed<R: Into<Close>>(reason: R) -> Self {
        Self::Closed(Closed {
            reason: reason.into(),
        })
    }

    pub(super) fn is_handshake(&self) -> bool {
        matches!(*self, Self::Handshake(_))
    }

    pub(super) fn is_established(&self) -> bool {
        matches!(*self, Self::Established)
    }

    pub(super) fn is_closed(&self) -> bool {
        matches!(*self, Self::Closed(_) | Self::Draining | Self::Drained)
    }

    pub(super) fn is_drained(&self) -> bool {
        matches!(*self, Self::Drained)
    }
}

#[allow(unnameable_types, unreachable_pub)] // fuzzing only
#[derive(Clone)]
pub struct Handshake {
    /// Whether the remote CID has been set by the peer yet
    ///
    /// Always set for servers
    pub(super) rem_cid_set: bool,
    /// Stateless retry token received in the first Initial by a server.
    ///
    /// Must be present in every Initial. Always empty for clients.
    pub(super) expected_token: Bytes,
    /// First cryptographic message
    ///
    /// Only set for clients
    pub(super) client_hello: Option<Bytes>,
}

#[allow(unnameable_types, unreachable_pub)] // fuzzing only
#[derive(Clone)]
pub struct Closed {
    pub(super) reason: Close,
}
