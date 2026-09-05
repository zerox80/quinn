use std::{
    cmp,
    collections::VecDeque,
    convert::TryFrom,
    fmt, mem,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};
use frame::StreamMetaVec;

use rand::{RngExt, SeedableRng, rngs::StdRng};
use tracing::{debug, error, trace, trace_span, warn};

use crate::{
    Dir, Duration, EndpointConfig, Frame, INITIAL_MTU, Instant, MAX_CID_SIZE, MAX_STREAM_COUNT,
    MIN_INITIAL_SIZE, Side, StreamId, TIMER_GRANULARITY, TokenStore, Transmit, TransportError,
    TransportErrorCode, VarInt,
    cid_queue::CidQueue,
    coding::BufMutExt,
    config::{ServerConfig, TransportConfig},
    connection::spaces::LostPacket,
    crypto::{self, KeyPair, Keys, PacketKey},
    frame::{self, Close, Datagram, FrameStruct, NewConnectionId, NewToken},
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, InitialPacket, LongType, Packet,
        PacketNumber, PartialDecode, SpaceId,
    },
    range_set::ArrayRangeSet,
    shared::{
        ConnectionEvent, ConnectionEventInner, ConnectionId, DatagramConnectionEvent, EcnCodepoint,
        EndpointEvent, EndpointEventInner,
    },
    token::{ResetToken, Token, TokenPayload},
    transport_parameters::TransportParameters,
};

mod ack_frequency;
use ack_frequency::AckFrequencyState;

mod assembler;
pub use assembler::Chunk;

mod cid_state;
use cid_state::CidState;

mod datagrams;
use datagrams::DatagramState;
pub use datagrams::{Datagrams, SendDatagramError};

mod mtud;
mod pacing;

mod packet_builder;
use packet_builder::PacketBuilder;

mod packet_crypto;
use packet_crypto::{PrevCrypto, ZeroRttCrypto};

mod paths;
pub use paths::RttEstimator;
use paths::{PathData, PathResponses};

pub(crate) mod qlog;

mod send_buffer;

mod sent_packets;
mod spaces;
#[cfg(fuzzing)]
pub use spaces::Retransmits;
#[cfg(not(fuzzing))]
use spaces::Retransmits;
use spaces::{PacketNumberFilter, PacketSpace, SendableFrames, SentPacket, ThinRetransmits};

mod stats;
pub use stats::{ConnectionStats, FrameStats, PathStats, UdpStats};

mod streams;
#[cfg(fuzzing)]
pub use streams::StreamsState;
#[cfg(not(fuzzing))]
use streams::StreamsState;
pub use streams::{
    Chunks, ClosedStream, FinishError, ReadError, ReadableError, RecvStream, SendStream,
    ShouldTransmit, StreamEvent, Streams, WriteError, Written,
};

mod timer;
use crate::congestion::Controller;
use timer::{Timer, TimerTable};

mod error;
pub use error::ConnectionError;

mod events;
pub use events::Event;

mod side;
use side::ConnectionSide;
pub(crate) use side::SideArgs;

mod state;
pub use state::State;

mod helpers;
mod introspection;
mod key_update;
mod lifecycle;
mod migration;
mod receive;
mod recovery;
mod transmit;

/// Protocol state and logic for a single QUIC connection
///
/// Objects of this type receive [`ConnectionEvent`]s and emit [`EndpointEvent`]s and application
/// [`Event`]s to make progress. To handle timeouts, a `Connection` returns timer updates and
/// expects timeouts through various methods. A number of simple getter methods are exposed
/// to allow callers to inspect some of the connection state.
///
/// `Connection` has roughly 4 types of methods:
///
/// - A. Simple getters, taking `&self`
/// - B. Handlers for incoming events from the network or system, named `handle_*`.
/// - C. State machine mutators, for incoming commands from the application. For convenience we
///   refer to this as "performing I/O" below, however as per the design of this library none of the
///   functions actually perform system-level I/O. For example, [`read`](RecvStream::read) and
///   [`write`](SendStream::write), but also things like [`reset`](SendStream::reset).
/// - D. Polling functions for outgoing events or actions for the caller to
///   take, named `poll_*`.
///
/// The simplest way to use this API correctly is to call (B) and (C) whenever
/// appropriate, then after each of those calls, as soon as feasible call all
/// polling methods (D) and deal with their outputs appropriately, e.g. by
/// passing it to the application or by making a system-level I/O call. You
/// should call the polling functions in this order:
///
/// 1. [`poll_transmit`](Self::poll_transmit)
/// 2. [`poll_timeout`](Self::poll_timeout)
/// 3. [`poll_endpoint_events`](Self::poll_endpoint_events)
/// 4. [`poll`](Self::poll)
///
/// Currently the only actual dependency is from (2) to (1), however additional
/// dependencies may be added in future, so the above order is recommended.
///
/// (A) may be called whenever desired.
///
/// Care should be made to ensure that the input events represent monotonically
/// increasing time. Specifically, calling [`handle_timeout`](Self::handle_timeout)
/// with events of the same [`Instant`] may be interleaved in any order with a
/// call to [`handle_event`](Self::handle_event) at that same instant; however
/// events or timeouts with different instants must not be interleaved.
pub struct Connection {
    endpoint_config: Arc<EndpointConfig>,
    config: Arc<TransportConfig>,
    rng: StdRng,
    crypto: Box<dyn crypto::Session>,
    /// The CID we initially chose, for use during the handshake
    handshake_cid: ConnectionId,
    /// The CID the peer initially chose, for use during the handshake
    rem_handshake_cid: ConnectionId,
    /// The "real" local IP address which was was used to receive the initial packet.
    /// This is only populated for the server case, and if known
    local_ip: Option<IpAddr>,
    path: PathData,
    /// Incremented every time we see a new path
    ///
    /// Stored separately from `path.generation` to account for aborted migrations
    path_counter: u64,
    /// Whether MTU detection is supported in this environment
    allow_mtud: bool,
    prev_path: Option<(ConnectionId, PathData)>,
    state: State,
    side: ConnectionSide,
    /// Whether or not 0-RTT was enabled during the handshake. Does not imply acceptance.
    zero_rtt_enabled: bool,
    /// Set if 0-RTT is supported, then cleared when no longer needed.
    zero_rtt_crypto: Option<ZeroRttCrypto>,
    key_phase: bool,
    /// How many packets are in the current key phase. Used only for `Data` space.
    key_phase_size: u64,
    /// Transport parameters set by the peer
    peer_params: TransportParameters,
    /// Source ConnectionId of the first packet received from the peer
    orig_rem_cid: ConnectionId,
    /// Destination ConnectionId sent by the client on the first Initial
    initial_dst_cid: ConnectionId,
    /// The value that the server included in the Source Connection ID field of a Retry packet, if
    /// one was received
    retry_src_cid: Option<ConnectionId>,
    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    /// Whether the spin bit is in use for this connection
    spin_enabled: bool,
    /// Outgoing spin bit state
    spin: bool,
    /// Packet number spaces: initial, handshake, 1-RTT
    spaces: [PacketSpace; 3],
    /// Highest usable packet number space
    highest_space: SpaceId,
    /// 1-RTT keys used prior to a key update
    prev_crypto: Option<PrevCrypto>,
    /// 1-RTT keys to be used for the next key update
    ///
    /// These are generated in advance to prevent timing attacks and/or DoS by third-party attackers
    /// spoofing key updates.
    next_crypto: Option<KeyPair<Box<dyn PacketKey>>>,
    accepted_0rtt: bool,
    /// Whether the idle timer should be reset the next time an ack-eliciting packet is transmitted.
    permit_idle_reset: bool,
    /// Negotiated idle timeout
    idle_timeout: Option<Duration>,
    /// The time we send next bundled ACK
    ///
    /// The goal is to wait long enough for the peer to acknowledge our previous
    /// bundled ACK (see `next_bundled_ack_delay`).
    /// A packet-count threshold would over- or under-shoot this depending on how fast we happen
    /// to be sending, so a time threshold is used instead.
    next_bundled_ack_time: Option<Instant>,
    timers: TimerTable,
    /// Number of packets received which could not be authenticated
    authentication_failures: u64,
    /// Why the connection was lost, if it has been
    error: Option<ConnectionError>,
    /// Identifies Data-space packet numbers to skip. Not used in earlier spaces.
    packet_number_filter: PacketNumberFilter,

    //
    // Queued non-retransmittable 1-RTT data
    //
    /// Responses to PATH_CHALLENGE frames
    path_responses: PathResponses,
    close: bool,

    //
    // ACK frequency
    //
    ack_frequency: AckFrequencyState,

    //
    // Loss Detection
    //
    /// The number of times a PTO has been sent without receiving an ack.
    pto_count: u32,

    //
    // Congestion Control
    //
    /// Whether the most recently received packet had an ECN codepoint set
    receiving_ecn: bool,
    /// Number of packets authenticated
    total_authed_packets: u64,
    /// Whether the last `poll_transmit` call yielded no data because there was
    /// no outgoing application data.
    app_limited: bool,

    streams: StreamsState,
    /// Surplus remote CIDs for future use on new paths
    rem_cids: CidQueue,
    // Attributes of CIDs generated by local peer
    local_cid_state: CidState,
    /// State of the unreliable datagram extension
    datagrams: DatagramState,
    /// 1-RTT packets that arrived before the TLS handshake reached `Established`.
    buffered_handshake_1rtt: VecDeque<BufferedHandshakePacket>,
    /// Connection level statistics
    stats: ConnectionStats,
    /// QUIC version used for the connection.
    version: u32,
}

struct BufferedHandshakePacket {
    received_at: Instant,
    remote: SocketAddr,
    local_ip: Option<IpAddr>,
    number: u64,
    packet: Packet,
}

const MAX_BUFFERED_HANDSHAKE_1RTT_PACKETS: usize = 64;

impl Connection {
    pub(crate) fn new(
        endpoint_config: Arc<EndpointConfig>,
        config: Arc<TransportConfig>,
        init_cid: ConnectionId,
        loc_cid: ConnectionId,
        rem_cid: ConnectionId,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        crypto: Box<dyn crypto::Session>,
        local_cid_len: usize,
        local_cid_lifetime: Option<Duration>,
        now: Instant,
        version: u32,
        allow_mtud: bool,
        rng_seed: [u8; 32],
        side_args: SideArgs,
    ) -> Self {
        let pref_addr_cid = side_args.pref_addr_cid();
        let path_validated = side_args.path_validated();
        let connection_side = ConnectionSide::from(side_args);
        let side = connection_side.side();
        let initial_space = PacketSpace {
            crypto: Some(crypto.initial_keys(init_cid, side)),
            ..PacketSpace::new(now)
        };
        let state = State::Handshake(state::Handshake {
            rem_cid_set: side.is_server(),
            expected_token: Bytes::new(),
            client_hello: None,
        });
        let mut rng = StdRng::from_seed(rng_seed);
        let mut this = Self {
            endpoint_config,
            crypto,
            handshake_cid: loc_cid,
            rem_handshake_cid: rem_cid,
            local_cid_state: CidState::new(
                local_cid_len,
                local_cid_lifetime,
                now,
                if pref_addr_cid.is_some() { 2 } else { 1 },
            ),
            path: PathData::new(remote, allow_mtud, None, 0, now, &config),
            path_counter: 0,
            allow_mtud,
            local_ip,
            prev_path: None,
            state,
            side: connection_side,
            zero_rtt_enabled: false,
            zero_rtt_crypto: None,
            key_phase: false,
            // A small initial key phase size ensures peers that don't handle key updates correctly
            // fail sooner rather than later. It's okay for both peers to do this, as the first one
            // to perform an update will reset the other's key phase size in `update_keys`, and a
            // simultaneous key update by both is just like a regular key update with a really fast
            // response. Inspired by quic-go's similar behavior of performing the first key update
            // at the 100th short-header packet.
            key_phase_size: rng.random_range(10..1000),
            peer_params: TransportParameters::default(),
            orig_rem_cid: rem_cid,
            initial_dst_cid: init_cid,
            retry_src_cid: None,
            events: VecDeque::new(),
            endpoint_events: VecDeque::new(),
            spin_enabled: config.allow_spin && rng.random_ratio(7, 8),
            spin: false,
            spaces: [initial_space, PacketSpace::new(now), PacketSpace::new(now)],
            highest_space: SpaceId::Initial,
            prev_crypto: None,
            next_crypto: None,
            accepted_0rtt: false,
            permit_idle_reset: true,
            idle_timeout: match config.max_idle_timeout {
                None | Some(VarInt(0)) => None,
                Some(dur) => Some(Duration::from_millis(dur.0)),
            },
            timers: TimerTable::default(),
            authentication_failures: 0,
            error: None,
            #[cfg(test)]
            packet_number_filter: match config.deterministic_packet_numbers {
                false => PacketNumberFilter::new(&mut rng),
                true => PacketNumberFilter::disabled(),
            },
            #[cfg(not(test))]
            packet_number_filter: PacketNumberFilter::new(&mut rng),

            path_responses: PathResponses::default(),
            close: false,

            ack_frequency: AckFrequencyState::new(get_max_ack_delay(
                &TransportParameters::default(),
            )),
            next_bundled_ack_time: None,

            pto_count: 0,

            app_limited: false,
            receiving_ecn: false,
            total_authed_packets: 0,

            streams: StreamsState::new(
                side,
                config.max_concurrent_uni_streams,
                config.max_concurrent_bidi_streams,
                config.send_window,
                config.receive_window,
                config.stream_receive_window,
            ),
            datagrams: DatagramState::default(),
            buffered_handshake_1rtt: VecDeque::new(),
            config,
            rem_cids: CidQueue::new(rem_cid),
            rng,
            stats: ConnectionStats::default(),
            version,
        };
        if path_validated {
            this.on_path_validated();
        }
        if side.is_client() {
            // Kick off the connection
            this.write_crypto();
            this.init_0rtt();
        }
        this
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("handshake_cid", &self.handshake_cid)
            .finish()
    }
}

fn get_max_ack_delay(params: &TransportParameters) -> Duration {
    Duration::from_micros(params.max_ack_delay.0 * 1000)
}

// Prevents overflow and improves behavior in extreme circumstances
const MAX_BACKOFF_EXPONENT: u32 = 16;

/// Minimal remaining size to allow packet coalescing, excluding cryptographic tag
///
/// This must be at least as large as the header for a well-formed empty packet to be coalesced,
/// plus some space for frames. We only care about handshake headers because short header packets
/// necessarily have smaller headers, and initial packets are only ever the first packet in a
/// datagram (because we coalesce in ascending packet space order and the only reason to split a
/// packet is when packet space changes).
const MIN_PACKET_SPACE: usize = MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE + 32;

/// Largest amount of space that could be occupied by a Handshake or 0-RTT packet's header
///
/// Excludes packet-type-specific fields such as packet number or Initial token
// https://www.rfc-editor.org/rfc/rfc9000.html#name-0-rtt: flags + version + dcid len + dcid +
// scid len + scid + length + pn
const MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE: usize =
    1 + 4 + 1 + MAX_CID_SIZE + 1 + MAX_CID_SIZE + VarInt::from_u32(u16::MAX as u32).size() + 4;

/// Perform key updates this many packets before the AEAD confidentiality limit.
///
/// Chosen arbitrarily, intended to be large enough to prevent spurious connection loss.
const KEY_UPDATE_MARGIN: u64 = 10_000;

#[derive(Default)]
struct SentFrames {
    retransmits: ThinRetransmits,
    largest_acked: Option<u64>,
    stream_frames: StreamMetaVec,
    /// Whether the packet contains non-retransmittable frames (like datagrams)
    non_retransmits: bool,
    requires_padding: bool,
}

impl SentFrames {
    /// Returns whether the packet contains only ACKs
    fn is_ack_only(&self, streams: &StreamsState) -> bool {
        self.largest_acked.is_some()
            && !self.non_retransmits
            && self.stream_frames.is_empty()
            && self.retransmits.is_empty(streams)
    }
}

/// Compute the negotiated idle timeout based on local and remote max_idle_timeout transport parameters.
///
/// According to the definition of max_idle_timeout, a value of `0` means the timeout is disabled; see <https://www.rfc-editor.org/rfc/rfc9000#section-18.2-4.4.1.>
///
/// According to the negotiation procedure, either the minimum of the timeouts or one specified is used as the negotiated value; see <https://www.rfc-editor.org/rfc/rfc9000#section-10.1-2.>
///
/// Returns the negotiated idle timeout as a `Duration`, or `None` when both endpoints have opted out of idle timeout.
fn negotiate_max_idle_timeout(x: Option<VarInt>, y: Option<VarInt>) -> Option<Duration> {
    match (x, y) {
        (Some(VarInt(0)) | None, Some(VarInt(0)) | None) => None,
        (Some(VarInt(0)) | None, Some(y)) => Some(Duration::from_millis(y.0)),
        (Some(x), Some(VarInt(0)) | None) => Some(Duration::from_millis(x.0)),
        (Some(x), Some(y)) => Some(Duration::from_millis(cmp::min(x, y).0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_max_idle_timeout_commutative() {
        let test_params = [
            (None, None, None),
            (None, Some(VarInt(0)), None),
            (None, Some(VarInt(2)), Some(Duration::from_millis(2))),
            (Some(VarInt(0)), Some(VarInt(0)), None),
            (
                Some(VarInt(2)),
                Some(VarInt(0)),
                Some(Duration::from_millis(2)),
            ),
            (
                Some(VarInt(1)),
                Some(VarInt(4)),
                Some(Duration::from_millis(1)),
            ),
        ];

        for (left, right, result) in test_params {
            assert_eq!(negotiate_max_idle_timeout(left, right), result);
            assert_eq!(negotiate_max_idle_timeout(right, left), result);
        }
    }
}
