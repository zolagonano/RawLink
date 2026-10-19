//! Session — two cooperating threads, event-driven end to end.
//!
//! * **recv** (`rl-<sid>`): reads the carrier, decrypts, dispatches frames
//!   to per-stream event channels, and enforces the carrier-recv
//!   backpressure gate. It performs NO send-side work — which is what
//!   keeps a stalled peer from deadlocking the local receive path.
//! * **sender** (`rl-send-<sid>`): owns ALL outgoing work — stream commands,
//!   session commands, keepalive PINGs, dead-peer detection, packet
//!   building+encryption, and the carrier writes themselves. It sleeps on a
//!   condvar ([`SendWaker`]) and is woken the instant new work is enqueued.
use crate::carrier::Carrier;
use crate::config::{Config, HEADER_LEN};
use crate::crypto::{self, Direction, TrafficKeySet};
use crate::error::Error;
use crate::frame::*;
use crate::packet::PacketHeader;
use crate::stream::StreamId;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

mod replay;
use replay::ReplayWindow;

/// Protocol-level cap on frames decoded from a single packet. Mode-
/// independent: a receiver must accept whatever frame count the SENDER's
/// mode produced (Throughput packs up to 256 frames/packet).
pub const MAX_FRAMES_PER_PACKET: usize = 1024;

/// Per-DATA-frame payload cap applied by the packer. The frame is the
/// receiver's dispatch quantum (one StreamEvent + one socket write per
/// frame at the far bridge), so 16 KiB keeps dispatch granularity fine
/// under multi-stream load while keeping the big app-facing chunks.
/// Purely sender-side policy — receivers accept any frame size the
/// packet body fits, so this is wire-compatible with every peer.
pub const MAX_DATA_FRAME: usize = 16384;

/// How long `wait_for_open_tcp_response` blocks before giving up.
const OPEN_TCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Keepalive cadence: while the link is receive-silent, a Ping probe is
/// scheduled at a uniformly random interval inside [PING_MIN, PING_MAX]
/// (a fixed period would be an idle-time wire signature). Dead-peer
/// detection semantics: PONG_TIMEOUT of receive silence with at least one
/// unanswered probe kills the session (10 s worst case).
const PING_MIN: Duration = Duration::from_millis(1200);
const PING_MAX: Duration = Duration::from_millis(3600);

fn jittered_ping_interval() -> Duration {
    let lo = PING_MIN.as_millis() as u64;
    let hi = PING_MAX.as_millis() as u64;
    Duration::from_millis(lo + (rand::RngCore::next_u64(&mut rand::rng()) % (hi - lo + 1)))
}
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the sender re-evaluates when nothing wakes it. Covers the
/// obfs idle tick (dummy cover frames / coalesced tail flush, see
/// `Carrier::idle_tick`) and the keepalive scheduler (worst case a 2 s
/// probe leaves ~100 ms late — irrelevant next to its 10 s timeout).
/// Real work always arrives via the waker.
const SEND_IDLE_TICK: Duration = Duration::from_millis(100);

/// Hard bound on packets built+sent per sender pass. Keeps the sender
/// returning to the top of its loop (draining NEW session/stream commands
/// mid-download) every ~1-2 ms instead of monopolizing the thread behind
/// a bulk transfer. The loop immediately re-runs while data remains, so
/// throughput is unaffected — only worst-case command latency shrinks.
const MAX_PACKS_PER_WAKE: usize = 8;

/// Event-driven wakeup for the send thread. Any thread that enqueues
/// send-side work calls [`SendWaker::notify`]; the send thread sleeps on
/// the condvar instead of polling. `notify()` sets the flag THEN signals;
/// `wait()` clears the flag before the caller re-checks for work, so a
/// wakeup can never be missed.
pub struct SendWaker {
    flag: Mutex<bool>,
    cv: Condvar,
}
impl SendWaker {
    fn new() -> Self {
        Self {
            flag: Mutex::new(false),
            cv: Condvar::new(),
        }
    }
    pub fn notify(&self) {
        let mut f = self.flag.lock().unwrap();
        *f = true;
        self.cv.notify_one();
    }
    /// Block until notified or `timeout` elapses, then clear the flag.
    fn wait(&self, timeout: Duration) {
        let mut f = self.flag.lock().unwrap();
        if !*f {
            let (guard, _) = self.cv.wait_timeout(f, timeout).unwrap();
            f = guard;
        }
        *f = false;
    }
}

type UnclaimedStream = (
    mpsc::SyncSender<StreamCommand>,
    mpsc::Receiver<StreamEvent>,
    Arc<AtomicU64>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}
impl Role {
    fn send_dir(self) -> Direction {
        match self {
            Self::Client => Direction::ClientToServer,
            Self::Server => Direction::ServerToClient,
        }
    }
    fn recv_dir(self) -> Direction {
        self.send_dir().opposite()
    }
}

/// Why a session was shut down. Always logged on shutdown
/// so that the server can answer: "client saw EOF — why did
/// we close our side?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Peer sent CONNECTION_CLOSE frame (graceful).
    PeerShutdown,
    /// Peer's carrier returned EOF / reset (peer closed socket).
    PeerEof,
    /// Local carrier recv returned a fatal error.
    CarrierRecvError,
    /// Local carrier send returned a fatal error.
    CarrierSendError,
    /// Keepalive: no pong within timeout.
    KeepaliveTimeout,
    /// Application dropped the Session handle.
    ApplicationDrop,
    /// Internal error (e.g., build_outgoing_packet failure).
    InternalError,
    /// Not yet shut down.
    None,
}
impl ShutdownReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::PeerShutdown => "peer_shutdown",
            Self::PeerEof => "peer_eof",
            Self::CarrierRecvError => "carrier_error",
            Self::CarrierSendError => "carrier_send_error",
            Self::KeepaliveTimeout => "timeout",
            Self::ApplicationDrop => "shutdown",
            Self::InternalError => "internal_error",
            Self::None => "none",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 8]);
impl SessionId {
    pub fn generate() -> Self {
        let mut b = [0u8; 8];
        rand::rng().fill_bytes(&mut b);
        Self(b)
    }
    pub fn from_u64(v: u64) -> Self {
        Self(v.to_le_bytes())
    }
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}
pub struct Stream {
    pub stream_id: StreamId,
    tx_cmd: mpsc::SyncSender<StreamCommand>,
    rx_evt: Mutex<mpsc::Receiver<StreamEvent>>,
    closed: Mutex<bool>,
    /// Wakes the session's send thread — every send-side API call ends
    /// with a notify so the command is packed within microseconds, not
    /// on the next poll tick.
    waker: Arc<SendWaker>,
    /// Shared with DriverStream — incremented by producer, decremented
    /// by Stream::read. Used by metrics to detect saturation.
    rx_evt_depth: Arc<AtomicU64>,
    /// DATA events skipped by `wait_for_open_tcp_response` while it was
    /// waiting for the OPEN_TCP response. Returned by subsequent `read()`
    /// calls in order — the old code DISCARDED them (data loss whenever
    /// peer data raced ahead of the dial response).
    pending_data: Mutex<VecDeque<Vec<u8>>>,
}
#[derive(Debug)]
pub enum StreamCommand {
    Write(Vec<u8>),
    Close,
    Reset(u8),
    OpenTcp(u8, Vec<u8>, u16),
    SendOpenTcpResponse(u8, String),
    Drop,
}
#[derive(Debug, Clone)]
pub enum StreamEvent {
    Data(Vec<u8>),
    PeerFin,
    PeerReset(u8),
    OpenTcpResponse(OpenTcpResponseFrame),
    SessionClosed,
}
impl Stream {
    fn new(
        sid: StreamId,
        tx: mpsc::SyncSender<StreamCommand>,
        rx: mpsc::Receiver<StreamEvent>,
        rx_evt_depth: Arc<AtomicU64>,
        waker: Arc<SendWaker>,
    ) -> Self {
        Self {
            stream_id: sid,
            tx_cmd: tx,
            rx_evt: Mutex::new(rx),
            closed: Mutex::new(false),
            waker,
            rx_evt_depth,
            pending_data: Mutex::new(VecDeque::new()),
        }
    }
    pub fn write(&self, data: &[u8]) -> Result<usize, Error> {
        // We do NOT check the `closed` flag here: it is set by read() on
        // PeerFin — the PEER closed its write side — while our write side
        // may still have data to send (half-open). tx_cmd.send() errors
        // once the stream is actually cleaned up, which is the correct
        // signal. Zero-length writes are rejected: an empty DATA frame
        // would be indistinguishable from PeerFin on the receiving side.
        if data.is_empty() {
            return Ok(0);
        }
        self.tx_cmd
            .send(StreamCommand::Write(data.to_vec()))
            .map_err(|_| Error::Application("closed".into()))?;
        self.waker.notify();
        Ok(data.len())
    }
    pub fn read(&self) -> Result<Vec<u8>, Error> {
        // Data buffered by wait_for_open_tcp_response has delivery priority:
        // it arrived BEFORE whatever is currently in rx_evt.
        if let Some(d) = self.pending_data.lock().unwrap().pop_front() {
            return Ok(d);
        }
        let rx = self.rx_evt.lock().unwrap();
        loop {
            match rx.recv() {
                Ok(StreamEvent::Data(d)) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(d);
                }
                Ok(StreamEvent::PeerFin) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    *self.closed.lock().unwrap() = true;
                    return Ok(Vec::new());
                }
                Ok(StreamEvent::PeerReset(_)) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    *self.closed.lock().unwrap() = true;
                    return Err(Error::Application("reset".into()));
                }
                Ok(StreamEvent::OpenTcpResponse(_)) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }
                Ok(StreamEvent::SessionClosed) | Err(_) => {
                    // The channel is closed — depth is no longer meaningful.
                    *self.closed.lock().unwrap() = true;
                    return Err(Error::Application("session closed".into()));
                }
            }
        }
    }
    /// Block until the peer answers our OPEN_TCP, with a hard timeout so a
    /// hung peer cannot park this thread forever. DATA events that race
    /// ahead of the response are buffered (not discarded) and returned by
    /// later `read()` calls.
    pub fn wait_for_open_tcp_response(&self) -> Result<OpenTcpResponseFrame, Error> {
        let deadline = Instant::now() + OPEN_TCP_RESPONSE_TIMEOUT;
        let rx = self.rx_evt.lock().unwrap();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout("open_tcp response timed out".into()));
            }
            match rx.recv_timeout(remaining) {
                Ok(StreamEvent::OpenTcpResponse(r)) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(r);
                }
                Ok(StreamEvent::Data(d)) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    self.pending_data.lock().unwrap().push_back(d);
                }
                Ok(StreamEvent::PeerFin) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    // Peer closed before answering the dial.
                    *self.closed.lock().unwrap() = true;
                    return Err(Error::Application("closed".into()));
                }
                Ok(StreamEvent::PeerReset(_)) => {
                    self.rx_evt_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    *self.closed.lock().unwrap() = true;
                    return Err(Error::Application("reset".into()));
                }
                Ok(StreamEvent::SessionClosed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    *self.closed.lock().unwrap() = true;
                    return Err(Error::Application("session closed".into()));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(Error::Timeout("open_tcp response timed out".into()));
                }
            }
        }
    }
    pub fn close(&self) -> Result<(), Error> {
        self.tx_cmd
            .send(StreamCommand::Close)
            .map_err(|_| Error::Application("closed".into()))?;
        self.waker.notify();
        Ok(())
    }
    pub fn open_tcp(&self, atyp: u8, addr: Vec<u8>, port: u16) -> Result<(), Error> {
        self.tx_cmd
            .send(StreamCommand::OpenTcp(atyp, addr, port))
            .map_err(|_| Error::Application("closed".into()))?;
        self.waker.notify();
        Ok(())
    }
    pub fn send_open_tcp_response(
        &self,
        status: u8,
        reason: impl Into<String>,
    ) -> Result<(), Error> {
        self.tx_cmd
            .send(StreamCommand::SendOpenTcpResponse(status, reason.into()))
            .map_err(|_| Error::Application("closed".into()))?;
        self.waker.notify();
        Ok(())
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        // try_send: Drop must never block on a full command channel. If all
        // 4 slots hold queued Writes, the driver still learns about the drop
        // via channel disconnect when the last Stream handle goes away —
        // and a missed Drop command only delays cleanup, never loses data.
        let _ = self.tx_cmd.try_send(StreamCommand::Drop);
        self.waker.notify();
    }
}

struct DriverStream {
    tx_evt: mpsc::SyncSender<StreamEvent>,
    rx_cmd: mpsc::Receiver<StreamCommand>,
    send_buf: VecDeque<(u64, Vec<u8>)>,
    /// Running total of bytes in send_buf. Incremented when pushing,
    /// decremented when popping. Replaces the O(N) scan
    /// `ds.send_buf.iter().map(|(_, d)| d.len() as u64).sum()`
    /// that was called on EVERY try_recv iteration in
    /// drain_stream_commands — with 20 streams × 64 entries × 4
    /// commands, that was 5120 iterations per drain call.
    send_buf_bytes: u64,
    next_offset: u64,
    /// Set to true when the application calls Stream::close() (or
    /// the bridge thread does so after seeing Ok(0) on its TCP).
    /// Stays true until the stream is removed.
    fin_sent: bool,
    /// Set to true when a CloseStream frame has actually been
    /// written to the wire (in build_outgoing_packet). This is
    /// separate from fin_sent so that the scheduler can distinguish
    /// "close requested" from "close frame sent" — and the cleanup
    /// logic can wait until the frame has actually been emitted.
    close_stream_sent: bool,
    /// Set to true when peer's CloseStream frame has been received.
    fin_recv: bool,
    /// Shared counter for rx_evt in-flight events. Incremented by
    /// the producer (recv_loop in dispatch_frame) BEFORE the send so
    /// we can detect saturation even when the send itself blocks.
    /// Decremented by the consumer (Stream::read) after popping.
    rx_evt_depth: Arc<AtomicU64>,
    /// The StreamId of this stream — used for logging in Drop.
    sid_log: StreamId,
    /// Total DATA payload bytes dispatched to rx_evt (via try_send or
    /// pending_events). Used to detect data loss: if this != total
    /// bytes written by bridge s2, data was lost in delivery.
    data_bytes_dispatched: u64,
    /// Next byte offset expected in an incoming DATA frame for this
    /// stream. DATA frames whose offset does not match are dropped:
    /// on an ordered carrier any deviation is a duplicate/replay or an
    /// injection (the wire offset field was previously never validated).
    recv_next_offset: u64,
}

impl Drop for DriverStream {
    fn drop(&mut self) {
        log::debug!(
            "DriverStream dropped sid={:?} fin_sent={} fin_recv={} close_stream_sent={} send_buf_len={} data_bytes_dispatched={}",
            self.sid_log,
            self.fin_sent,
            self.fin_recv,
            self.close_stream_sent,
            self.send_buf.len(),
            self.data_bytes_dispatched
        );
    }
}
struct SessionInner {
    role: Role,
    session_id: SessionId,
    keys: TrafficKeySet,
    /// Anti-replay detector for the receive direction. A packet number is
    /// accepted only once; marks happen after successful authentication.
    recv_replay: ReplayWindow,
    config: Config,
    streams: HashMap<StreamId, DriverStream>,
    /// (tx_cmd, rx_evt, rx_evt_depth) for streams opened by the peer
    /// but not yet accepted by the local application.
    unclaimed: HashMap<StreamId, UnclaimedStream>,
    open_tcp_tx: mpsc::Sender<(StreamId, OpenTcpFrame)>,
    next_pn: u64,
    next_stream_num: u32,
    streams_total: u32,
    closing: bool,
    outgoing: VecDeque<Frame>,
    total_sent: u64,
    total_recv: u64,
    last_recv: Instant,
    last_send: Instant,
    last_ping_sent: Instant,
    last_pong: Instant,
    /// When the next keepalive probe is due (jittered, see PING_MIN/MAX).
    next_ping_at: Instant,
    /// Pings sent since the last received packet. Reset on every recv;
    /// drives dead-peer detection (see the keepalive block in recv_loop).
    pings_since_recv: u32,
    stats: SessionStats,
    shutdown_reason: ShutdownReason,
    /// Events that couldn't be delivered to a stream's rx_evt because
    /// the bounded channel was full. The recv_loop retries these via
    /// try_send BEFORE reading new packets from the carrier — this
    /// prevents the bilateral deadlock where:
    ///   * recv_loop blocks on tx.send(evt)
    ///   * can't call carrier.recv()
    ///   * kernel TCP recv buffer fills
    ///   * peer's writer blocks (kernel TCP send buffer full)
    ///   * peer's recv_loop also blocks on tx.send(evt)
    ///   * neither side can drain → 30s write timeout → carrier EOF
    ///
    /// When pending_events reaches cap, the recv_loop stops reading
    /// from the carrier (backpressure propagates to the peer).
    /// Events that couldn't be delivered to a stream's rx_evt because
    /// the bounded channel was full. The recv_loop retries these via
    /// try_send BEFORE reading new packets from the carrier.
    ///
    /// **IMPORTANT**: pending_events is UNBOUNDED. It must never drop
    /// events — dropping a DATA event causes permanent data loss.
    /// Backpressure comes from the carrier (not reading from the
    /// carrier when pending_events is large), NOT from capping
    /// pending_events and dropping frames.
    ///
    /// The `pending_events_soft_limit` is a threshold above which the
    /// recv_loop stops reading from the carrier (backpressure). But
    /// packets already read are ALWAYS fully processed.
    /// Per-stream overflow queues for events that didn't fit the stream's
    /// bounded rx_evt. One sub-queue per stream preserves STRICT per-stream
    /// FIFO (a stream's Fin can never overtake its own Data) while the
    /// round-robin drain in try_deliver_pending prevents head-of-line
    /// blocking (one slow stream must not stall delivery to others — the
    /// old shared VecDeque + first-full-channel break did exactly that).
    pending_events: HashMap<StreamId, VecDeque<(mpsc::SyncSender<StreamEvent>, StreamEvent, u64)>>,
    /// Total events across all per-stream pending queues (watermark gauge).
    pending_total: usize,
    /// Soft limit for pending_events. When exceeded, the recv_loop
    /// stops reading from the carrier (backpressure). But events from
    /// packets already being processed are NEVER dropped.
    pending_events_soft_limit: usize,
    /// Per-stream dispatch sequence for Data events. Powers the delivery-
    /// order canary: on an ordered carrier a stream's DATA must be handed
    /// to the application strictly in wire order; a decreasing sequence is
    /// a bug (or a hostile peer) and is logged loudly.
    data_seq: HashMap<StreamId, u64>,
    /// Last delivered Data sequence per stream (see `data_seq`).
    last_data_delivered: HashMap<StreamId, u64>,
    /// Set by the recv thread whenever dispatch queued a control frame
    /// onto `outgoing` (Pong for a Ping, ResetStream for a rejected open).
    /// The send thread clears it — this is the recv→send handoff signal
    /// that avoids waking the send thread on every received packet.
    outgoing_added: bool,
    /// The send thread's wakeup handle (shared with every Stream).
    waker: Arc<SendWaker>,
}
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub pings_sent: u64,
    pub pongs_recv: u64,
    pub streams_open: u32,
    pub streams_total: u32,
    pub session_uptime_ms: u64,
}
/// Richer metrics snapshot — for diagnosing where the session stalls.
/// Sampled atomically under the inner lock.
#[derive(Debug, Clone, Default)]
pub struct SessionMetrics {
    pub session_id: u64,
    pub role: &'static str,
    pub transport_mode: &'static str,
    pub uptime_ms: u64,
    pub alive: bool,
    pub shutdown_reason: &'static str,

    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub pings_sent: u64,
    pub pongs_recv: u64,

    pub streams_open: u32,
    pub streams_total: u32,

    /// Last time we received ANY packet from the peer (ms ago).
    pub last_recv_ago_ms: u64,
    /// Last time the writer sent a packet to the carrier (ms ago).
    pub last_send_ago_ms: u64,
    /// Last time we sent a PING (ms ago).
    pub last_ping_ago_ms: u64,
    /// Last time we received a PONG (ms ago).
    pub last_pong_ago_ms: u64,

    /// Outgoing frame queue depth (frames waiting to be packed).
    pub outgoing_depth: u64,
    /// Outgoing queue capacity (MAX_OUTGOING_DEPTH).
    pub outgoing_capacity: u64,

    /// Sum of all streams' send_buf bytes (data waiting to be packed).
    pub send_buf_total_bytes: u64,
    /// Sum of all streams' rx_evt depth (events waiting for app read).
    pub rx_evt_total_depth: u64,
    /// rx_evt capacity per stream (constant).
    pub rx_evt_capacity_per_stream: u64,
    /// Number of streams whose send_buf is at cap (4 MiB by default).
    pub streams_at_send_cap: u32,
    /// Number of streams whose rx_evt is at cap (16 by default).
    pub streams_at_rx_evt_cap: u32,
    /// Pending events waiting for rx_evt space (overflow from rx_evt).
    /// Non-zero = application is slow to read, backpressure is active.
    pub pending_events_depth: u64,
    /// Pending events capacity.
    pub pending_events_soft_limit: u64,
}
pub struct Session {
    inner: Arc<Mutex<SessionInner>>,
    tx_cmd: mpsc::Sender<SessionCommand>,
    open_tcp_rx: Mutex<mpsc::Receiver<(StreamId, OpenTcpFrame)>>,
    alive: Arc<std::sync::atomic::AtomicBool>,
    started_at: Instant,
}
enum SessionCommand {
    OpenStream {
        reply: mpsc::Sender<Result<Stream, Error>>,
    },
    CloseSession,
}
impl Session {
    pub fn connect_pre_shared<C: Carrier + 'static>(
        carrier: C,
        psk: [u8; 32],
        config: Config,
    ) -> Result<Self, Error> {
        let sid = SessionId::generate();
        let keys = crypto::derive_keys(sid.as_bytes(), &psk);
        Self::start(carrier, keys, Role::Client, sid, config, false)
    }
    /// Client variant with a caller-chosen session id — required when the
    /// carrier derives its v3 header mask from the id (TCP carrier dials).
    pub fn connect_pre_shared_with_sid<C: Carrier + 'static>(
        carrier: C,
        psk: [u8; 32],
        config: Config,
        sid: SessionId,
    ) -> Result<Self, Error> {
        let keys = crypto::derive_keys(sid.as_bytes(), &psk);
        Self::start(carrier, keys, Role::Client, sid, config, false)
    }
    /// Client variant for early-data handshakes: the session's FIRST packet
    /// (`pn=1`, the authenticated hello Ping) was already sent inside the
    /// carrier handshake (see [`build_first_packet`]). The session starts
    /// at `pn=2` and does not re-send the hello.
    pub fn connect_pre_shared_preamble<C: Carrier + 'static>(
        carrier: C,
        psk: [u8; 32],
        config: Config,
        sid: SessionId,
    ) -> Result<Self, Error> {
        let keys = crypto::derive_keys(sid.as_bytes(), &psk);
        Self::start(carrier, keys, Role::Client, sid, config, true)
    }
    pub fn accept_pre_shared<C: Carrier + 'static>(
        carrier: C,
        session_id: SessionId,
        psk: [u8; 32],
        config: Config,
    ) -> Result<Self, Error> {
        let keys = crypto::derive_keys(session_id.as_bytes(), &psk);
        Self::start(carrier, keys, Role::Server, session_id, config, false)
    }
    fn start<C: Carrier + 'static>(
        carrier: C,
        keys: TrafficKeySet,
        role: Role,
        sid: SessionId,
        config: Config,
        preamble: bool,
    ) -> Result<Self, Error> {
        config.validate()?;
        let (open_tcp_tx, open_tcp_rx) = mpsc::channel();
        let (tx_cmd, rx_cmd) = mpsc::channel();
        const PENDING_EVENTS_SOFT_LIMIT: usize = 256;
        let waker = Arc::new(SendWaker::new());
        let now = Instant::now();
        let inner = Arc::new(Mutex::new(SessionInner {
            role,
            session_id: sid.clone(),
            keys,
            recv_replay: ReplayWindow::new(),
            config,
            streams: HashMap::new(),
            unclaimed: HashMap::new(),
            open_tcp_tx,
            next_pn: if preamble && role == Role::Client {
                2
            } else {
                1
            },
            next_stream_num: 0,
            streams_total: 0,
            closing: false,
            outgoing: VecDeque::new(),
            total_sent: 0,
            total_recv: 0,
            last_recv: now,
            last_send: now,
            last_ping_sent: now,
            last_pong: now,
            next_ping_at: now + jittered_ping_interval(),
            pings_since_recv: 0,
            stats: SessionStats::default(),
            shutdown_reason: ShutdownReason::None,
            pending_events: HashMap::new(),
            pending_total: 0,
            pending_events_soft_limit: PENDING_EVENTS_SOFT_LIMIT,
            data_seq: HashMap::new(),
            last_data_delivered: HashMap::new(),
            outgoing_added: false,
            waker: Arc::clone(&waker),
        }));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        // CLIENT hello: enqueue an authenticated Ping IMMEDIATELY. The
        // server's admission phase waits (up to ADMISSION_TIMEOUT, 5 s) for
        // the client's first packet to verify the PSK — an idle client that
        // sends nothing would be rejected on a timer. The server's
        // admission read completes instantly and the frame is dispatched
        // normally (replayed via PreLoadedCarrier → answered with a Pong).
        if role == Role::Client && !preamble {
            inner
                .lock()
                .unwrap()
                .outgoing
                .push_back(Frame::Ping(PingFrame { echo: 0 }));
        }
        let carrier = Arc::new(carrier);
        let rc = Arc::clone(&carrier);
        let ri = Arc::clone(&inner);
        let ra = Arc::clone(&alive);
        let j = thread::Builder::new()
            .name(format!("rl-{}", sid.as_u64()))
            .spawn(move || recv_loop(rc, ri, ra))
            .map_err(|e| Error::Transport(format!("spawn recv: {e}")))?;
        drop(j); // detached recv thread; exits via the alive flag
        let sc = Arc::clone(&carrier);
        let si = Arc::clone(&inner);
        let sa = Arc::clone(&alive);
        let sw = Arc::clone(&waker);
        let j2 = thread::Builder::new()
            .name(format!("rl-send-{}", sid.as_u64()))
            .spawn(move || sender_loop(sc, si, rx_cmd, sa, sw))
            .map_err(|e| Error::Transport(format!("spawn sender: {e}")))?;
        drop(j2); // detached sender thread; exits via the alive flag
        waker.notify(); // the pre-queued hello Ping must leave immediately
        Ok(Self {
            inner,
            tx_cmd,
            open_tcp_rx: Mutex::new(open_tcp_rx),
            alive,
            started_at: now,
        })
    }
    pub fn open_stream(&self) -> Result<Stream, Error> {
        let (tx, rx) = mpsc::channel();
        self.tx_cmd
            .send(SessionCommand::OpenStream { reply: tx })
            .map_err(|_| Error::Application("closed".into()))?;
        // Wake the send thread so the OpenStream is processed (and its
        // OPEN_STREAM frame packed) within microseconds.
        self.inner.lock().unwrap().waker.notify();
        rx.recv().map_err(|_| Error::Application("closed".into()))?
    }
    pub fn accept_open_tcp(&self) -> Result<(Stream, OpenTcpFrame), Error> {
        loop {
            if !self.is_alive() {
                return Err(Error::Application("session closed".into()));
            }
            match self
                .open_tcp_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_millis(100))
            {
                Ok((sid, otc)) => {
                    let handle = {
                        let mut g = self.inner.lock().unwrap();
                        g.unclaimed.remove(&sid)
                    };
                    match handle {
                        Some((tx_cmd, rx_evt, rx_evt_depth)) => {
                            let waker = Arc::clone(&self.inner.lock().unwrap().waker);
                            return Ok((
                                Stream::new(sid, tx_cmd, rx_evt, rx_evt_depth, waker),
                                otc,
                            ));
                        }
                        None => {
                            // Duplicate OPEN_TCP for an already-accepted
                            // stream (dup carrier, replay, buggy peer) —
                            // must not kill the accept loop.
                            log::warn!(
                                "accept_open_tcp: no unclaimed handle for sid={sid:?} (duplicate OPEN_TCP?) — ignoring"
                            );
                            continue;
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Error::Application("closed".into()));
                }
            }
        }
    }
    pub fn session_id(&self) -> u64 {
        self.inner.lock().unwrap().session_id.as_u64()
    }
    pub fn role(&self) -> Role {
        self.inner.lock().unwrap().role
    }
    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn stats(&self) -> SessionStats {
        let g = self.inner.lock().unwrap();
        let mut s = g.stats.clone();
        s.streams_open = g.streams.len() as u32;
        s.streams_total = g.streams_total;
        s.session_uptime_ms = self.started_at.elapsed().as_millis() as u64;
        s
    }
    /// Richer metrics snapshot — see `SessionMetrics`.
    pub fn metrics(&self) -> SessionMetrics {
        let g = self.inner.lock().unwrap();
        let now = Instant::now();
        let send_cap = g.config.windows.stream_send_window;
        let rx_evt_cap_per_stream = 16u64;
        let mut send_buf_total_bytes: u64 = 0;
        let mut rx_evt_total_depth: u64 = 0;
        let mut streams_at_send_cap = 0u32;
        let mut streams_at_rx_evt_cap = 0u32;
        for ds in g.streams.values() {
            // O(1): send_buf_bytes is maintained incrementally.
            let bytes: u64 = ds.send_buf_bytes;
            send_buf_total_bytes += bytes;
            let depth = ds.rx_evt_depth.load(std::sync::atomic::Ordering::Relaxed);
            rx_evt_total_depth += depth;
            if bytes >= send_cap {
                streams_at_send_cap += 1;
            }
            if depth >= rx_evt_cap_per_stream {
                streams_at_rx_evt_cap += 1;
            }
        }
        let mode_str = match g.config.mode {
            crate::config::TransportMode::LowLatency => "low-latency",
            crate::config::TransportMode::Balanced => "balanced",
            crate::config::TransportMode::Throughput => "throughput",
        };
        let role_str = match g.role {
            Role::Client => "client",
            Role::Server => "server",
        };
        SessionMetrics {
            session_id: g.session_id.as_u64(),
            role: role_str,
            transport_mode: mode_str,
            uptime_ms: self.started_at.elapsed().as_millis() as u64,
            alive: self.alive.load(std::sync::atomic::Ordering::Relaxed),
            shutdown_reason: g.shutdown_reason.as_str(),
            packets_sent: g.stats.packets_sent,
            packets_recv: g.stats.packets_recv,
            bytes_sent: g.stats.bytes_sent,
            bytes_recv: g.stats.bytes_recv,
            pings_sent: g.stats.pings_sent,
            pongs_recv: g.stats.pongs_recv,
            streams_open: g.streams.len() as u32,
            streams_total: g.streams_total,
            last_recv_ago_ms: now.duration_since(g.last_recv).as_millis() as u64,
            last_send_ago_ms: now.duration_since(g.last_send).as_millis() as u64,
            last_ping_ago_ms: now.duration_since(g.last_ping_sent).as_millis() as u64,
            last_pong_ago_ms: now.duration_since(g.last_pong).as_millis() as u64,
            outgoing_depth: g.outgoing.len() as u64,
            outgoing_capacity: 512,
            send_buf_total_bytes,
            rx_evt_total_depth,
            rx_evt_capacity_per_stream: rx_evt_cap_per_stream,
            streams_at_send_cap,
            streams_at_rx_evt_cap,
            pending_events_depth: g.pending_total as u64,
            pending_events_soft_limit: g.pending_events_soft_limit as u64,
        }
    }
    pub fn shutdown_reason(&self) -> ShutdownReason {
        self.inner.lock().unwrap().shutdown_reason
    }
    /// Get a clone of the alive flag for passing to bridge threads.
    /// Bridge threads check this to know when their session has died.
    pub fn alive_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.alive)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.tx_cmd.send(SessionCommand::CloseSession);
    }
}

/// Signal that the session is shutting down. Drains all stream tx_evt
/// senders so bridge threads wake up from rx.recv(). Returns the
/// drained senders and events to deliver outside the lock.
fn signal_shutdown(
    inner: &Arc<Mutex<SessionInner>>,
    alive: &Arc<std::sync::atomic::AtomicBool>,
    reason: ShutdownReason,
) {
    alive.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut g = inner.lock().unwrap();
    g.closing = true;
    if g.shutdown_reason == ShutdownReason::None {
        g.shutdown_reason = reason;
    }
    log::warn!(
        "session={} closing reason={} role={} uptime_ms={} streams_open={} packets_sent={} packets_recv={} bytes_sent={} bytes_recv={}",
        g.session_id.as_u64(),
        g.shutdown_reason.as_str(),
        match g.role {
            Role::Client => "client",
            Role::Server => "server",
        },
        g.stats.session_uptime_ms,
        g.streams.len(),
        g.stats.packets_sent,
        g.stats.packets_recv,
        g.stats.bytes_sent,
        g.stats.bytes_recv,
    );
    // Drain all streams — dropping tx_evt senders causes bridge
    // threads' rx.recv() to return Disconnected, which Stream::read()
    // handles as SessionClosed. This wakes up bridge threads blocked
    // on stream.read() without needing to send through the (possibly
    // full) bounded channel.
    //
    // For bridge threads blocked on TCP read (socks_read.read() or
    // tcp_read.read()), the bridge thread will exit when
    // stream.write() returns Err (because tx_cmd is also dropped
    // when the DriverStream is dropped) or when the TCP socket gets
    // a read timeout (bridge threads set read timeouts).
    let drained: Vec<(StreamId, DriverStream)> = g.streams.drain().collect();
    g.unclaimed.clear();
    g.pending_events.clear();
    g.pending_total = 0;
    drop(g); // release lock before doing anything else
    // The DriverStreams are dropped here, which drops the tx_evt
    // and rx_cmd — waking up bridge threads.
    drop(drained);
}

fn recv_loop<C: Carrier>(
    carrier: Arc<C>,
    inner: Arc<Mutex<SessionInner>>,
    alive: Arc<std::sync::atomic::AtomicBool>,
) {
    // HIGH/LOW watermarks for the carrier-recv gate.
    //
    // **LOSS-TOLERANT, NOT ARTIFICIALLY LOSSLESS** (the regression fix):
    // when `pending_events` is at or above HIGH_WATERMARK, we STOP calling
    // `carrier.recv()` entirely. Data stays in the kernel socket buffer (TCP)
    // and TCP flow control backpressures the peer's sender. No accepted data
    // is ever dropped.
    //
    // Counts are calibrated to the 16 KiB DATA-frame cap (see
    // `MAX_DATA_FRAME`): 1024 × 16 KiB = 16 MiB of buffered events before
    // the gate closes, 4 MiB to reopen. Bigger values let the carrier
    // freeze for hundreds of milliseconds at a time (measured: RTO storms
    // and 10× throughput collapse with ≥ 6 concurrent streams).
    //
    // HIGH: stop reading from the carrier (backpressure).
    // LOW: resume reading from the carrier.
    const PENDING_HIGH_WATERMARK: usize = 1024;
    const PENDING_LOW_WATERMARK: usize = 256;
    loop {
        if !alive.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        // CRITICAL: drain pending events BEFORE reading from carrier.
        // If we don't, rx_evt can stay full → tx.send blocks in
        // handle_packet → we can't read from carrier → kernel TCP
        // recv buffer fills → peer's writer blocks → bilateral
        // deadlock → 30s write timeout → carrier EOF.
        let pending_drained = {
            let mut g = inner.lock().unwrap();
            try_deliver_pending(&mut g)
        };
        let pending_len = {
            let g = inner.lock().unwrap();
            g.pending_total
        };
        let should_read = if pending_len >= PENDING_HIGH_WATERMARK {
            false // Gate CLOSED — TRULY stop reading
        } else if pending_len <= PENDING_LOW_WATERMARK {
            true // Gate OPEN — full read
        } else {
            // Hysteresis: keep the current state to prevent oscillation.
            // If we just drained some events, the consumer is making
            // progress, so it's safe to read more. If not, keep the
            // gate closed.
            pending_drained
        };
        // Gate-driven max_reads:
        //   * Open: read up to 1000 packets per iteration (drains the kernel buffer).
        //   * Closed: read ZERO packets — let the kernel buffer fill,
        //     TCP flow control backpressures the peer. NO data loss.
        let max_reads = if should_read { 1000 } else { 0 };
        let mut read_count = 0u32;
        loop {
            if read_count >= max_reads {
                break;
            }
            read_count += 1;
            match carrier.recv() {
                Ok(Some((_, bytes))) => match handle_packet(&inner, &bytes) {
                    Ok(_) => {
                        let now_len = {
                            let g = inner.lock().unwrap();
                            g.pending_total
                        };
                        if now_len >= PENDING_HIGH_WATERMARK && should_read {
                            break;
                        }
                        continue;
                    }
                    Err(e) => {
                        log::warn!("handle_packet: {e}");
                        continue;
                    }
                },
                Ok(None) => break,
                Err(e) => {
                    log::warn!("carrier recv fatal: {e}");
                    signal_shutdown(&inner, &alive, ShutdownReason::CarrierRecvError);
                    return;
                }
            }
        }
        // Hand off control frames the recv path queued (Pong for a peer
        // Ping, ResetStream for a rejected open): wake the sender if it
        // has anything waiting in `outgoing`. A plain flag check under the
        // lock — no allocation, no per-packet cost.
        let wake_sender = {
            let mut g = inner.lock().unwrap();
            std::mem::take(&mut g.outgoing_added)
        };
        if wake_sender {
            let waker = {
                let g = inner.lock().unwrap();
                Arc::clone(&g.waker)
            };
            waker.notify();
        }
        // Sleep strategy: when the carrier-recv gate is CLOSED (pending
        // above LOW watermark), use a SHORT SLEEP to yield CPU while
        // waiting for the consumer to drain. thread::yield_now() is
        // NOT enough — it returns immediately when there are no other
        // runnable threads, causing a busy-loop that burns 100% CPU
        // when the gate stays closed for a long time.
        if !should_read {
            thread::sleep(Duration::from_millis(1));
        } else if read_count > 0 {
            // Busy reading — go straight back to recv(); the carrier's
            // read blocks in the syscall until data arrives or its
            // timeout expires, so no further yield is needed.
            thread::yield_now();
        } else {
            // Nothing arrived this pass (carrier returned None after its
            // internal timeout). Loop immediately — try_deliver_pending
            // above is the only work left and it is cheap. The carrier's
            // own read timeout (5 ms on TCP) paces this idle cadence;
            // for carriers whose recv() is non-blocking (sim), the small
            // sleep prevents a hot spin.
            thread::sleep(Duration::from_micros(200));
        }
    }
}

/// The sender thread — ALL outgoing work, woken on demand.
///
/// Runs one pass of: session commands (OpenStream/CloseSession) →
/// stream commands (Write/Close/…) → keepalive scheduling →
/// pack-and-write packets until there is nothing left → sleep on the
/// waker. The waker is notified by every send-side API ([`Stream::write`],
/// [`Stream::open_tcp`], …) and by the recv thread when dispatch queues a
/// control frame. This is what makes the outbound data path event-driven:
/// latency is a futex wake (~tens of µs), not a poll interval (was 5 ms),
/// and a built packet goes straight to the carrier write — no queue, no
/// extra thread hop.
///
/// `write_all` on a stalled peer simply blocks here; that is ordinary TCP
/// backpressure (apps block on Stream::write, the recv thread keeps
/// flowing) and the carrier's 30 s write timeout converts a dead peer
/// into a session shutdown.
fn sender_loop<C: Carrier>(
    carrier: Arc<C>,
    inner: Arc<Mutex<SessionInner>>,
    rx_cmd: mpsc::Receiver<SessionCommand>,
    alive: Arc<std::sync::atomic::AtomicBool>,
    waker: Arc<SendWaker>,
) {
    let carrier_mtu = carrier.mtu();
    let mode = {
        let g = inner.lock().unwrap();
        g.config.mode
    };
    loop {
        if !alive.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        // ---- 1) Session-level commands. ----
        match rx_cmd.try_recv() {
            Ok(SessionCommand::OpenStream { reply }) => {
                let _ = reply.send(handle_open_stream(&inner));
            }
            Ok(SessionCommand::CloseSession) => {
                pack_and_send_all(&carrier, &inner, &alive, carrier_mtu, mode);
                {
                    let mut g = inner.lock().unwrap();
                    g.outgoing
                        .push_back(Frame::ConnectionClose(ConnectionCloseFrame {
                            code: 0,
                            reason: "shutdown".into(),
                        }));
                }
                pack_and_send_all(&carrier, &inner, &alive, carrier_mtu, mode);
                // Grace period: the writes above have only reached the
                // kernel buffer; give the carrier a moment before the
                // session tears the socket down.
                thread::sleep(Duration::from_millis(50));
                signal_shutdown(&inner, &alive, ShutdownReason::ApplicationDrop);
                return;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                signal_shutdown(&inner, &alive, ShutdownReason::ApplicationDrop);
                return;
            }
        }
        // ---- 2) Stream commands → send_buf / control frames. ----
        drain_stream_commands(&inner);
        // ---- 3) Keepalive: probes and dead-peer detection (v3: jittered). ----
        {
            let mut g = inner.lock().unwrap();
            let now = Instant::now();
            let since_recv = now.duration_since(g.last_recv);
            if since_recv > PING_MIN && now >= g.next_ping_at {
                let echo: u64 = rand::random();
                // push_front: control frames must not queue behind bulk
                // data in `outgoing` — a delayed probe would delay death
                // detection by exactly the congestion duration.
                g.outgoing.push_front(Frame::Ping(PingFrame { echo }));
                g.last_ping_sent = now;
                g.stats.pings_sent += 1;
                g.pings_since_recv += 1;
                g.next_ping_at = now + jittered_ping_interval();
            }
            // Dead peer: no packet of ANY kind for PONG_TIMEOUT while at
            // least one probe went unanswered. On a healthy link ANY
            // traffic (data, pong) refreshes last_recv and resets the
            // counter, so a busy one-way session is never falsely killed.
            if since_recv > PONG_TIMEOUT && g.pings_since_recv > 0 {
                log::warn!(
                    "keepalive: dead peer (no traffic for {since_recv:?}, {} unanswered probe(s))",
                    g.pings_since_recv
                );
                drop(g);
                signal_shutdown(&inner, &alive, ShutdownReason::KeepaliveTimeout);
                return;
            }
        }
        // ---- 4) Pack + write until nothing is left to send. ----
        let sent = pack_and_send_all(&carrier, &inner, &alive, carrier_mtu, mode);
        if sent > 0 {
            // More data may remain (budget-limited pass) — go straight
            // back to the top so pending commands are drained first;
            // yielding once lets the recv thread and app pumps run.
            thread::yield_now();
            continue;
        }
        // Nothing to send — sender-idle tick: obfs dummy cover frames
        // and coalesced-write tail flushes happen HERE (blocking
        // carrier writes are fine on this thread), then sleep on the
        // waker until new work arrives.
        if let Err(e) = carrier.idle_tick() {
            log::warn!("sender: carrier idle tick fatal: {e}");
            signal_shutdown(&inner, &alive, ShutdownReason::CarrierSendError);
            return;
        }
        waker.wait(SEND_IDLE_TICK);
    }
}

/// Build and send packets until there is nothing left to pack or a
/// carrier write fails fatally. Returns how many packets were sent.
/// Runs ONLY on the sender thread (single builder — `next_pn` and the
/// outgoing queue have exactly one consumer here).
fn pack_and_send_all<C: Carrier>(
    carrier: &Arc<C>,
    inner: &Arc<Mutex<SessionInner>>,
    alive: &Arc<std::sync::atomic::AtomicBool>,
    carrier_mtu: usize,
    mode: crate::config::TransportMode,
) -> usize {
    let mut budget = MAX_PACKS_PER_WAKE;
    let mut sent = 0usize;
    while budget > 0 {
        match pack_one(inner, carrier_mtu, mode) {
            Ok(Some(packet)) => {
                budget -= 1;
                // carrier.send() (for TCP) combines the length prefix +
                // packet into ONE write_all call — 2 syscalls per packet
                // total instead of 3.
                match carrier.send(carrier.local_addr(), &packet) {
                    Ok(()) => {
                        sent += 1;
                        let mut g = inner.lock().unwrap();
                        g.last_send = Instant::now();
                        g.stats.packets_sent += 1;
                        g.stats.bytes_sent += packet.len() as u64;
                    }
                    Err(e) => {
                        log::warn!("sender: carrier send fatal: {e}");
                        signal_shutdown(inner, alive, ShutdownReason::CarrierSendError);
                        return sent;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                log::warn!("pack: {e}");
                break;
            }
        }
    }
    sent
}

/// Build ONE packet. One lock pass covers the outgoing-depth check and
/// the frame pops; encryption happens after the lock is released (up to
/// ~64 KiB of AES-GCM never stalls the recv thread or app threads).
///
/// Outgoing frame-queue cap note: `outgoing` only ever holds CONTROL
/// frames (Ping/Pong/Reset/ConnectionClose/OpenStream/OpenTcp/Response)
/// — bulk data is packed straight from the per-stream send buffers — so
/// MAX_OUTGOING_DEPTH (512) is deep headroom, not a throughput limiter.
const MAX_OUTGOING_DEPTH: usize = 512;

fn pack_one(
    inner: &Arc<Mutex<SessionInner>>,
    carrier_mtu: usize,
    mode: crate::config::TransportMode,
) -> Result<Option<Vec<u8>>, Error> {
    // Phase 1 (under lock): depth check + frame pops + body encode +
    // key/PN handoff. Phase 2 (lock released): AES-GCM encryption — up to
    // ~64 KiB of crypto must never stall the recv thread or app threads.
    let built = {
        let mut g = inner.lock().unwrap();
        if g.outgoing.len() >= MAX_OUTGOING_DEPTH {
            return Ok(None);
        }
        build_body_locked(&mut g, carrier_mtu, mode)?
    };
    let Some(b) = built else { return Ok(None) };
    // Hard invariant: the packed body must never exceed the carrier's
    // payload capacity — an oversized packet is rejected by the peer's
    // carrier (len > MTU) and would kill the session.
    debug_assert!(
        b.body.len() <= carrier_mtu.saturating_sub(HEADER_LEN + crate::config::AEAD_TAG_LEN),
        "packed body {} exceeds carrier payload capacity",
        b.body.len()
    );
    let header = PacketHeader::new(b.sid, b.pn, false);
    let aad = header.to_bytes();
    let ct = crypto::encrypt(&b.tk, b.pn, &b.body, &aad)?;
    let mut wire = Vec::with_capacity(HEADER_LEN + ct.len());
    wire.extend_from_slice(&aad);
    wire.extend_from_slice(&ct);
    Ok(Some(wire))
}

/// What [`build_body_locked`] hands its caller: the encoded packet body
/// plus everything needed to seal it (traffic key, session id, packet
/// number). The caller encrypts WITHOUT holding the session lock.
struct BuiltPacket {
    body: Vec<u8>,
    tk: crate::crypto::TrafficKey,
    sid: u64,
    pn: u64,
}

/// Pop frames and encode one packet BODY (see [`BuiltPacket`]).
fn build_body_locked(
    g: &mut SessionInner,
    carrier_mtu: usize,
    mode: crate::config::TransportMode,
) -> Result<Option<BuiltPacket>, Error> {
    // `body` is the single source of truth for packet fill: every frame is
    // encoded into it exactly once, so body.len() always equals the sum of
    // encoded frame sizes (the old code measured via a separate body_est
    // counter and encoded every frame twice; the intermediate version of
    // this refactor encoded ONLY outgoing-queue frames and silently dropped
    // DATA/CloseStream bytes — caught by wire-level divergence tests).
    let mut body: Vec<u8> = Vec::with_capacity(carrier_mtu);
    let mut frames: Vec<Frame> = Vec::new();
    {
        let max_frames = mode.max_frames_per_packet();
        let max_body = carrier_mtu.saturating_sub(HEADER_LEN + crate::config::AEAD_TAG_LEN);
        // Pop frames from outgoing. encoded_len() is pure arithmetic.
        loop {
            if frames.len() >= max_frames {
                break;
            }
            let Some(f) = g.outgoing.front() else { break };
            if body.len() + f.encoded_len() > max_body {
                break;
            }
            let f = g.outgoing.pop_front().unwrap();
            f.encode_into(&mut body);
            frames.push(f);
        }
        // NOTE: stream_send_window is a SEND-BUFFER cap, enforced by
        // drain_stream_commands (it stops adding data to send_buf when
        // stream_bytes >= cap). The packer must NOT re-check the cap here —
        // that would permanently stall a stream once it reaches the cap
        // (there is no ACK mechanism to "un-saturate" it). Buffered data
        // must always be packed and sent.
        //
        // DATA frames are capped at MAX_DATA_FRAME (16 KiB) even when the
        // app writes bigger chunks: the frame is the RECEIVER's dispatch
        // granularity. The exact-fit split below preserves per-stream byte
        // order: the remainder of a split chunk is pushed back to the
        // FRONT of that stream's send_buf.
        let mut total_sent_delta: u64 = 0;
        'pull: while frames.len() < max_frames {
            let mut progressed = false;
            for (sid, ds) in g.streams.iter_mut() {
                if frames.len() >= max_frames {
                    break;
                }
                // Recompute per stream: body.len() changes on every take in
                // this loop. (Computing `available` once per round served
                // MULTIPLE streams with a stale value — four 16KB chunks
                // packed into one packet and blew past the carrier MTU.)
                let available = max_body.saturating_sub(body.len() + 15).min(MAX_DATA_FRAME); // 15 = DATA frame overhead
                if available == 0 {
                    break 'pull;
                }
                let Some(&(offset, _)) = ds.send_buf.front() else {
                    continue;
                };
                let dlen = ds.send_buf.front().unwrap().1.len();
                if dlen <= available {
                    let (_, data) = ds.send_buf.pop_front().unwrap();
                    ds.send_buf_bytes -= dlen as u64;
                    total_sent_delta += dlen as u64;
                    let f = Frame::Data(DataFrame {
                        stream_id: sid.0,
                        offset,
                        payload: data,
                    });
                    f.encode_into(&mut body);
                    frames.push(f);
                    progressed = true;
                } else {
                    // Chunk larger than the remaining space: split it —
                    // emit what fits, keep the rest at the FRONT so this
                    // stream's byte order is preserved.
                    let (offset, data) = ds.send_buf.pop_front().unwrap();
                    ds.send_buf_bytes -= data.len() as u64;
                    let first = data[..available].to_vec();
                    let rest_offset = offset + available as u64;
                    let rest = data[available..].to_vec();
                    ds.send_buf_bytes += rest.len() as u64;
                    ds.send_buf.push_front((rest_offset, rest));
                    total_sent_delta += available as u64;
                    let f = Frame::Data(DataFrame {
                        stream_id: sid.0,
                        offset,
                        payload: first,
                    });
                    f.encode_into(&mut body);
                    frames.push(f);
                    break 'pull; // body is now exactly full
                }
            }
            if !progressed {
                break;
            }
        }
        g.total_sent += total_sent_delta;
        // CloseStream emission: only after the stream's data is fully
        // packed, and only if the 15-byte frame still fits.
        for (sid, ds) in g.streams.iter_mut() {
            if frames.len() >= max_frames {
                break;
            }
            if body.len() + 15 > max_body {
                break;
            }
            if ds.fin_sent && !ds.close_stream_sent && ds.send_buf.is_empty() {
                ds.close_stream_sent = true;
                let f = Frame::CloseStream(CloseStreamFrame {
                    stream_id: sid.0,
                    final_offset: ds.next_offset,
                });
                f.encode_into(&mut body);
                frames.push(f);
            }
        }
        if frames.is_empty() {
            return Ok(None);
        }
        let dir = g.role.send_dir();
        Ok(Some(BuiltPacket {
            body,
            tk: g.keys.for_dir(dir).clone(),
            sid: g.session_id.as_u64(),
            pn: {
                let pn = g.next_pn;
                g.next_pn += 1;
                pn
            },
        }))
    }
}

fn handle_open_stream(inner: &Arc<Mutex<SessionInner>>) -> Result<Stream, Error> {
    let mut g = inner.lock().unwrap();
    if g.closing {
        return Err(Error::Application("closed".into()));
    }
    // Enforce the stream cap for locally-opened streams too — handle_open_stream
    // previously grew `streams` without any bound (config field was never checked).
    if g.streams.len() >= g.config.max_streams_per_session as usize {
        return Err(Error::ResourceLimit(format!(
            "max streams per session ({}) reached",
            g.config.max_streams_per_session
        )));
    }
    let side = if g.role == Role::Client {
        0
    } else {
        1u32 << 31
    };
    // Guard the stream-number space: `num` must never reach the role bit.
    const STREAM_NUM_LIMIT: u32 = 1 << 31;
    if g.next_stream_num >= STREAM_NUM_LIMIT - 1 {
        return Err(Error::ResourceLimit("stream number space exhausted".into()));
    }
    let num = g.next_stream_num;
    g.next_stream_num += 1;
    let sid = StreamId(side | num);
    let (tx_cmd, rx_cmd) = mpsc::sync_channel(64);
    let (tx_evt, rx_evt) = mpsc::sync_channel(16);
    let rx_evt_depth = Arc::new(AtomicU64::new(0));
    g.streams.insert(
        sid,
        DriverStream {
            tx_evt,
            rx_cmd,
            send_buf: VecDeque::new(),
            send_buf_bytes: 0,
            next_offset: 0,
            fin_sent: false,
            close_stream_sent: false,
            fin_recv: false,
            sid_log: sid,
            data_bytes_dispatched: 0,
            rx_evt_depth: Arc::clone(&rx_evt_depth),
            recv_next_offset: 0,
        },
    );
    g.outgoing
        .push_back(Frame::OpenStream(OpenStreamFrame { stream_id: sid.0 }));
    let waker = Arc::clone(&g.waker);
    Ok(Stream::new(sid, tx_cmd, rx_evt, rx_evt_depth, waker))
}
fn drain_stream_commands(inner: &Arc<Mutex<SessionInner>>) {
    // ONE critical section for the whole drain pass. try_recv never blocks,
    // so holding the lock here is safe — the old code acquired the global
    // lock TWICE per command (cap check + try_recv), which under load meant
    // hundreds of acquisitions per tick.
    let mut all_cmds: Vec<(StreamId, StreamCommand)> = Vec::new();
    // Streams whose last Stream handle was DROPPED (rx_cmd disconnected
    // after the queued commands drained). This is the reliable drop signal:
    // Stream::Drop's try_send(Drop) hint can be lost when the command
    // channel is full of queued Writes, but the channel disconnect is
    // observable unconditionally once every queued command is drained.
    let mut handle_dropped: Vec<StreamId> = Vec::new();
    {
        let g = inner.lock().unwrap();
        for (sid, ds) in g.streams.iter() {
            loop {
                if ds.send_buf_bytes >= g.config.windows.stream_send_window {
                    break;
                }
                match ds.rx_cmd.try_recv() {
                    Ok(c) => all_cmds.push((*sid, c)),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        handle_dropped.push(*sid);
                        break;
                    }
                }
            }
        }
    }
    if all_cmds.is_empty() && handle_dropped.is_empty() {
        return;
    }
    let mut g = inner.lock().unwrap();
    for sid in handle_dropped {
        if let Some(ds) = g.streams.get_mut(&sid)
            && !ds.fin_sent {
                ds.fin_sent = true;
                log::debug!(
                    "fin_sent set sid={sid:?} (Stream handle dropped, rx_cmd disconnected)"
                );
            }
    }
    for (sid, cmd) in all_cmds {
        let Some(ds) = g.streams.get_mut(&sid) else {
            continue;
        };
        match cmd {
            StreamCommand::Write(data) => {
                let off = ds.next_offset;
                ds.next_offset += data.len() as u64;
                ds.send_buf_bytes += data.len() as u64;
                ds.send_buf.push_back((off, data));
            }
            StreamCommand::Close => {
                ds.fin_sent = true;
                log::debug!("fin_sent set sid={:?} (Close command drained)", sid);
            }
            StreamCommand::Reset(code) => {
                let fo = ds.next_offset;
                g.outgoing.push_back(Frame::ResetStream(ResetStreamFrame {
                    stream_id: sid.0,
                    code,
                    final_offset: fo,
                }));
            }
            StreamCommand::OpenTcp(atyp, addr, port) => {
                g.outgoing.push_back(Frame::OpenTcp(OpenTcpFrame {
                    stream_id: sid.0,
                    atyp,
                    addr,
                    port,
                }));
            }
            StreamCommand::SendOpenTcpResponse(status, reason) => {
                g.outgoing
                    .push_back(Frame::OpenTcpResponse(OpenTcpResponseFrame {
                        stream_id: sid.0,
                        status,
                        reason,
                    }));
            }
            StreamCommand::Drop => {
                // The application dropped its last Stream handle without an
                // explicit close() — e.g. the SOCKS5 handler bailing out on
                // a dial failure or a handshake timeout. Treating this as a
                // local close makes the stream dead-cleanup-eligible (and
                // emits our CloseStream so the PEER can reclaim its half
                // too). The old no-op leaked one DriverStream in the session
                // table per abandoned stream, forever.
                ds.fin_sent = true;
                log::debug!("fin_sent set sid={sid:?} (Stream dropped without close)");
            }
        }
    }
    // A stream is "dead" (safe to remove) only when ALL of:
    //   * fin_sent     — local app called close()
    //   * fin_recv     — peer sent CloseStream
    //   * close_stream_sent — we actually emitted our CloseStream frame
    //   * send_buf.is_empty() — no queued data left to pack
    // The close_stream_sent check is CRITICAL: previously, the cleanup
    // used only fin_sent && fin_recv && send_buf.is_empty(), which
    // raced with build_outgoing_packet. The stream could be removed
    // BEFORE the CloseStream frame was actually emitted, causing the
    // peer to never see PeerFin — leading to a hung SOCKS5 client and
    // the user-visible "carrier EOF" symptom on the next iteration.
    let dead: Vec<StreamId> = g
        .streams
        .iter()
        .filter(|(_, ds)| {
            ds.fin_sent && ds.fin_recv && ds.close_stream_sent && ds.send_buf.is_empty()
        })
        .map(|(sid, _)| *sid)
        .collect();
    for sid in &dead {
        g.streams.remove(sid);
        // Also drop any still-unclaimed channel halves for the same stream
        // (peer-opened stream that died before the app accepted it) — the
        // old code leaked these until session end.
        g.unclaimed.remove(sid);
        log::debug!("cleaned up dead stream {sid:?}");
    }
}
fn handle_packet(inner: &Arc<Mutex<SessionInner>>, bytes: &[u8]) -> Result<bool, Error> {
    let header = PacketHeader::parse(bytes)?;
    let pn = header.packet_number;
    let aad = &bytes[..HEADER_LEN];
    // Lock #1: identity check + replay pre-filter + key handle. Decrypt
    // runs OUTSIDE the lock — up to ~64KB of AES-GCM no longer stalls the
    // writer thread and app threads while it completes.
    let tk = {
        let mut g = inner.lock().unwrap();
        g.stats.packets_recv += 1;
        g.last_recv = Instant::now();
        g.pings_since_recv = 0;
        if g.session_id.as_u64() != header.session_id {
            return Err(Error::Auth("session_id mismatch".into()));
        }
        // Cheap pre-filter: reject replays BEFORE spending CPU on decrypt
        // (an attacker cannot burn decryption cycles with recorded traffic).
        if g.recv_replay.is_duplicate(pn) {
            return Err(Error::Replay(format!("replayed packet pn={pn}")));
        }
        g.keys.for_dir(g.role.recv_dir()).clone()
    };
    let plaintext = crypto::decrypt(&tk, pn, &bytes[HEADER_LEN..], aad)?;
    let (frames, _consumed) = Frame::parse_many(&plaintext, MAX_FRAMES_PER_PACKET)?;
    // Lock #2 — ONE critical section for the whole packet: mark the PN as
    // authenticated, update byte stats, flush pending events, then dispatch
    // every frame. All channel sends on this path are try_send (never
    // block), so holding the lock is deadlock-free. The old code took the
    // lock once per FRAME plus twice per EVENT (~200 acquisitions per
    // 64-frame packet).
    let mut g = inner.lock().unwrap();
    g.recv_replay.mark(pn);
    // bytes_recv tracks WIRE bytes received (encrypted + header).
    g.stats.bytes_recv += bytes.len() as u64;
    // Drain pending events BEFORE processing new frames — events queued
    // earlier get priority.
    try_deliver_pending(&mut g);
    // NOTE: We do NOT check pending_events depth here. ALL frames in
    // this packet MUST be processed — dropping frames causes permanent
    // data loss. Events that can't be delivered to rx_evt are queued
    // to the unbounded pending_events. The recv_loop's carrier-recv
    // gate (which checks pending_events depth BEFORE calling recv)
    // provides backpressure without losing data.
    let mut all_delivered = true;
    for frame in frames {
        dispatch_frame(&mut g, frame, &mut all_delivered)?;
    }
    Ok(all_delivered)
}

/// Try to deliver pending events to rx_evt channels. Called while already
/// holding the session lock (from recv_loop via handle_packet paths).
/// Returns true if any events were delivered.
///
/// Round-robin over the per-stream queues: for each stream, pop from the
/// FRONT while its rx_evt accepts events (strict per-stream FIFO); when the
/// channel is full, move on to the NEXT stream — never block on one slow
/// consumer. One full rotation per call keeps the cost bounded by the
/// number of streams with pending events (not by queue length).
fn try_deliver_pending(g: &mut SessionInner) -> bool {
    let mut delivered_any = false;
    let sids: Vec<StreamId> = g.pending_events.keys().copied().collect();
    for sid in sids {
        loop {
            // Pop with a short borrow, then act — the borrow must not span
            // check_order (which mutates other SessionInner fields).
            let front = g.pending_events.get_mut(&sid).and_then(|q| q.pop_front());
            let Some((tx, evt, seq)) = front else { break };
            match tx.try_send(evt) {
                Ok(()) => {
                    delivered_any = true;
                    g.pending_total -= 1;
                    if seq > 0 {
                        check_order(g, sid, seq);
                    }
                }
                Err(mpsc::TrySendError::Full(evt)) => {
                    // Channel full — put the event back at the FRONT of
                    // this stream's queue (strict FIFO) and move on.
                    if let Some(q) = g.pending_events.get_mut(&sid) {
                        q.push_front((tx, evt, seq));
                    }
                    break;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    // Stream handle gone — drop the event.
                    g.pending_total -= 1;
                }
            }
        }
    }
    // Drop empty queues so the map doesn't grow with dead streams.
    g.pending_events.retain(|_, q| !q.is_empty());
    delivered_any
}

/// Deliver one event to a stream's rx_evt, preserving per-stream ordering:
/// if the stream already has events queued in its pending sub-queue, the
/// new event MUST also go there (a later PeerFin must never overtake
/// queued DATA). Recovers the event from TrySendError::Full — no clones.
fn deliver_event(
    g: &mut SessionInner,
    sid: StreamId,
    tx: mpsc::SyncSender<StreamEvent>,
    evt: StreamEvent,
    all_delivered: &mut bool,
) {
    let seq = if matches!(evt, StreamEvent::Data(_)) {
        let e = g.data_seq.entry(sid).or_insert(0);
        *e += 1;
        *e
    } else {
        0
    };
    let queued = g
        .pending_events
        .get_mut(&sid)
        .map(|q| !q.is_empty())
        .unwrap_or(false);
    if queued {
        g.pending_events
            .get_mut(&sid)
            .unwrap()
            .push_back((tx, evt, seq));
        g.pending_total += 1;
        *all_delivered = false;
        return;
    }
    match tx.try_send(evt) {
        Ok(()) => {
            if seq > 0 {
                check_order(g, sid, seq);
            }
        }
        Err(mpsc::TrySendError::Full(evt)) => {
            // Queue to the stream's pending sub-queue (UNBOUNDED — never
            // drop; backpressure comes from the carrier-recv gate).
            g.pending_events
                .entry(sid)
                .or_default()
                .push_back((tx, evt, seq));
            g.pending_total += 1;
            *all_delivered = false;
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            // Stream handle dropped — nothing to deliver to.
        }
    }
}

/// Delivery-order canary: a stream's DATA events must reach the
/// application in strictly increasing dispatch order. A violation means
/// the delivery layer reordered frames — log loudly (never panic: the
/// release profile aborts the process and a proxy must keep its other
/// connections alive; the stream data is detectably bad either way).
fn check_order(g: &mut SessionInner, sid: StreamId, seq: u64) {
    let last = g.last_data_delivered.entry(sid).or_insert(0);
    if seq <= *last {
        log::error!(
            "DELIVERY ORDER VIOLATION: sid={sid:?} delivered seq={seq} but last={}",
            *last
        );
    }
    *last = seq;
}

/// Dispatch a frame while the session lock is held. Events are delivered
/// immediately via `deliver_event` (try_send never blocks, so this is
/// deadlock-free under the lock). Applies receive-side integrity checks:
/// stream caps, role-bit sanity, and DATA offset validation.
fn dispatch_frame(
    g: &mut SessionInner,
    frame: Frame,
    all_delivered: &mut bool,
) -> Result<(), Error> {
    match frame {
        Frame::Data(d) => {
            let sid = StreamId(d.stream_id);
            if let Some(ds) = g.streams.get_mut(&sid) {
                if d.payload.is_empty() {
                    // Crafted/empty DATA: an empty payload would be
                    // indistinguishable from PeerFin by Stream::read — drop it.
                    log::debug!("empty DATA dropped sid={sid:?}");
                } else if d.offset != ds.recv_next_offset {
                    // On an ordered carrier, any offset deviation is a
                    // duplicate/replay or an injection — never deliver it.
                    if d.offset < ds.recv_next_offset {
                        log::debug!(
                            "DATA duplicate/replay sid={sid:?} offset={} expected={}",
                            d.offset,
                            ds.recv_next_offset
                        );
                    } else {
                        log::warn!(
                            "DATA offset gap sid={sid:?} offset={} expected={} — frame dropped",
                            d.offset,
                            ds.recv_next_offset
                        );
                    }
                } else {
                    ds.recv_next_offset += d.payload.len() as u64;
                    g.total_recv += d.payload.len() as u64;
                    ds.rx_evt_depth
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    ds.data_bytes_dispatched += d.payload.len() as u64;
                    let tx = ds.tx_evt.clone();
                    deliver_event(g, sid, tx, StreamEvent::Data(d.payload), all_delivered);
                }
            } else {
                log::debug!("DATA on unknown stream {sid:?}");
            }
        }
        Frame::OpenStream(o) => {
            let sid = StreamId(o.stream_id);
            // Role-bit sanity: peer-opened streams must carry the PEER's role bit
            // (client opens 0x0…, server opens 0x8000_0000…). Prevents a malformed
            // or hostile peer from colliding with our own stream IDs.
            let peer_bit = match g.role {
                Role::Server => 0u32,
                Role::Client => 1u32 << 31,
            };
            if (sid.0 >> 31) != (peer_bit >> 31) {
                log::warn!("OPEN_STREAM with wrong role bit sid={sid:?} — ignoring");
            } else if g.streams.contains_key(&sid) {
                // Duplicate open — ignore (stream already exists).
            } else if g.streams.len() + g.unclaimed.len()
                >= g.config.max_streams_per_session as usize
            {
                // Enforce the (previously never checked) per-session stream cap.
                log::warn!(
                    "OPEN_STREAM rejected: max_streams_per_session ({}) reached",
                    g.config.max_streams_per_session
                );
                g.outgoing.push_back(Frame::ResetStream(ResetStreamFrame {
                    stream_id: sid.0,
                    code: 1,
                    final_offset: 0,
                }));
                g.outgoing_added = true;
            } else {
                let (tx_cmd, rx_cmd) = mpsc::sync_channel(64);
                let (tx_evt, rx_evt) = mpsc::sync_channel(16);
                let rx_evt_depth = Arc::new(AtomicU64::new(0));
                g.streams.insert(
                    sid,
                    DriverStream {
                        tx_evt,
                        rx_cmd,
                        send_buf: VecDeque::new(),
                        send_buf_bytes: 0,
                        next_offset: 0,
                        fin_sent: false,
                        close_stream_sent: false,
                        fin_recv: false,
                        sid_log: sid,
                        data_bytes_dispatched: 0,
                        rx_evt_depth: Arc::clone(&rx_evt_depth),
                        recv_next_offset: 0,
                    },
                );
                g.unclaimed.insert(sid, (tx_cmd, rx_evt, rx_evt_depth));
                g.stats.streams_total += 1;
            }
        }
        Frame::CloseStream(c) => {
            let sid = StreamId(c.stream_id);
            if let Some(ds) = g.streams.get_mut(&sid) {
                ds.fin_recv = true;
                ds.rx_evt_depth
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let tx = ds.tx_evt.clone();
                deliver_event(g, sid, tx, StreamEvent::PeerFin, all_delivered);
            }
        }
        Frame::ResetStream(r) => {
            let sid = StreamId(r.stream_id);
            if let Some(ds) = g.streams.get_mut(&sid) {
                // A reset terminates the stream in BOTH directions: mark
                // fin_recv so the dead-stream cleanup in
                // drain_stream_commands can reclaim it once the local
                // side closes too. Without this, a reset stream stayed in
                // `streams` forever (fin_recv was never set) — a slow
                // memory leak on every peer reset. Drop any buffered
                // outbound data as well: it would never be read by the
                // peer and would block cleanup until the window drained.
                ds.fin_recv = true;
                ds.send_buf.clear();
                ds.send_buf_bytes = 0;
                ds.rx_evt_depth
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let tx = ds.tx_evt.clone();
                deliver_event(g, sid, tx, StreamEvent::PeerReset(r.code), all_delivered);
            }
        }
        Frame::OpenTcp(o) => {
            let sid = StreamId(o.stream_id);
            if g.streams.contains_key(&sid) {
                let _ = g.open_tcp_tx.send((sid, o));
            }
        }
        Frame::OpenTcpResponse(r) => {
            let sid = StreamId(r.stream_id);
            if let Some(ds) = g.streams.get_mut(&sid) {
                ds.rx_evt_depth
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let tx = ds.tx_evt.clone();
                deliver_event(g, sid, tx, StreamEvent::OpenTcpResponse(r), all_delivered);
            }
        }
        Frame::Ping(p) => {
            g.outgoing
                .push_front(Frame::Pong(PongFrame { echo: p.echo }));
            g.outgoing_added = true;
        }
        Frame::Pong(_) => {
            g.last_pong = Instant::now();
            g.stats.pongs_recv += 1;
        }
        Frame::ConnectionClose(_) => {
            g.closing = true;
            if g.shutdown_reason == ShutdownReason::None {
                g.shutdown_reason = ShutdownReason::PeerShutdown;
            }
            // SessionClosed is sent to ALL streams. Use stream_id 0
            // as a placeholder — these events don't need per-stream
            // ordering (the session is shutting down anyway).
            let stream_dels: Vec<(StreamId, mpsc::SyncSender<StreamEvent>)> = g
                .streams
                .iter()
                .map(|(sid, ds)| (*sid, ds.tx_evt.clone()))
                .collect();
            for (sid, tx) in stream_dels {
                g.streams.get(&sid).map(|ds| {
                    ds.rx_evt_depth
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                });
                deliver_event(g, sid, tx, StreamEvent::SessionClosed, all_delivered);
            }
        }
    }
    Ok(())
}
/// Build the client's FIRST wire packet: an authenticated hello Ping
/// (packet number 1) — used by the SSH obfs carrier as post-NEWKEYS early
/// data so the RawLink session completes in the handshake round trips.
///
/// The packet is returned already first-flight-masked and its session id
/// must be passed to [`Session::connect_pre_shared_preamble`].
pub fn build_first_packet(psk: &[u8; 32]) -> Result<(SessionId, Vec<u8>), Error> {
    let sid = SessionId::generate();
    let keys = crypto::derive_keys(sid.as_bytes(), psk);
    let header = PacketHeader::new(sid.as_u64(), 1, false);
    let aad = header.to_bytes();
    let mut body = Vec::new();
    Frame::Ping(PingFrame {
        echo: rand::random(),
    })
    .encode_into(&mut body);
    let ct = crypto::encrypt(&keys.c2s, 1, &body, &aad)?;
    let mut wire = Vec::with_capacity(HEADER_LEN + ct.len());
    wire.extend_from_slice(&aad);
    wire.extend_from_slice(&ct);
    let mut m = crate::mask::HeaderMasker::first_flight(psk);
    m.apply(&mut wire[..HEADER_LEN]);
    Ok((sid, wire))
}

pub fn verify_psk(first_packet: &[u8], psk: [u8; 32]) -> Result<SessionId, Error> {
    // NOTE: with a TCP carrier the header mask has already been removed by
    // the carrier's recv path; the (test) sim carrier never masks.
    let header = PacketHeader::parse(first_packet)?;
    let session_id = SessionId::from_u64(header.session_id);
    let keys = crypto::derive_keys(session_id.as_bytes(), &psk);
    let aad = &first_packet[..HEADER_LEN];
    match crypto::decrypt(
        &keys.c2s,
        header.packet_number,
        &first_packet[HEADER_LEN..],
        aad,
    ) {
        Ok(_) => Ok(session_id),
        Err(_) => Err(Error::Auth("RawLink authentication failed".into())),
    }
}
