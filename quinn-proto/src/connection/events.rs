use super::{ConnectionError, StreamEvent};

/// Events of interest to the application
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// The connection's handshake data is ready
    HandshakeDataReady,
    /// The connection was successfully established
    Connected,
    /// The TLS handshake was confirmed
    HandshakeConfirmed,
    /// The connection was lost
    ///
    /// Emitted when the connection is closed due to an error, a timeout, or the peer closing it.
    /// This is **not** emitted when the local application closes the connection via
    /// [`Connection::close()`](crate::Connection::close). In that case, pending operations will
    /// fail with [`ConnectionError::LocallyClosed`].
    ConnectionLost {
        /// Reason that the connection was closed
        reason: ConnectionError,
    },
    /// Stream events
    Stream(StreamEvent),
    /// One or more application datagrams have been received
    DatagramReceived,
    /// One or more application datagrams have been sent after blocking
    DatagramsUnblocked,
    /// The currently active path was updated
    PathUpdated,
}
