use std::io;

use thiserror::Error;

use crate::{
    TransportError,
    frame::{self, Close},
};

/// Reasons why a connection might be lost
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The peer doesn't implement any supported version
    #[error("peer doesn't implement any supported version")]
    VersionMismatch,
    /// The peer violated the QUIC specification as understood by this implementation
    #[error(transparent)]
    TransportError(#[from] TransportError),
    /// The peer's QUIC stack aborted the connection automatically
    #[error("aborted by peer: {0}")]
    ConnectionClosed(frame::ConnectionClose),
    /// The peer closed the connection
    #[error("closed by peer: {0}")]
    ApplicationClosed(frame::ApplicationClose),
    /// The peer is unable to continue processing this connection, usually due to having restarted
    #[error("reset by peer")]
    Reset,
    /// Communication with the peer has lapsed for longer than the negotiated idle timeout
    ///
    /// If neither side is sending keep-alives, a connection will time out after a long enough idle
    /// period even if the peer is still reachable. See also [`crate::TransportConfig::max_idle_timeout()`]
    /// and [`crate::TransportConfig::keep_alive_interval()`].
    #[error("timed out")]
    TimedOut,
    /// The local application closed the connection
    #[error("closed")]
    LocallyClosed,
    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs.
    #[error("CIDs exhausted")]
    CidsExhausted,
}

impl From<Close> for ConnectionError {
    fn from(x: Close) -> Self {
        match x {
            Close::Connection(reason) => Self::ConnectionClosed(reason),
            Close::Application(reason) => Self::ApplicationClosed(reason),
        }
    }
}

// For compatibility with API consumers
impl From<ConnectionError> for io::Error {
    fn from(x: ConnectionError) -> Self {
        use ConnectionError::*;
        let kind = match x {
            TimedOut => io::ErrorKind::TimedOut,
            Reset => io::ErrorKind::ConnectionReset,
            ApplicationClosed(_) | ConnectionClosed(_) => io::ErrorKind::ConnectionAborted,
            TransportError(_) | VersionMismatch | LocallyClosed | CidsExhausted => {
                io::ErrorKind::Other
            }
        };
        Self::new(kind, x)
    }
}
