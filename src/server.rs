//! RawLink server: carrier accept → two-phase admission → session → remote
//! dial (OPEN_TCP) + bridge.
//!
//! Admission (YELLOWPAPER §13) bounds the server's exposure in two phases:
//! an unauthenticated connection holds only a socket (cap 512, 5 s window
//! to deliver an authenticatable first packet), and a real session is only
//! constructed after the PSK is proven (cap 256). The already-consumed first
//! packet is replayed into the session via the `PreLoadedCarrier` decorator.
//!
//! Serving: each `OPEN_TCP` request dials the destination in its own thread
//! (one slow `connect()` never blocks other streams), answers with a status
//! that maps 1:1 onto the SOCKS5 reply code, and bridges via [`bridge`].
use crate::bridge;
use crate::carrier::Carrier;
use crate::config::Config;
use crate::error::Error;
use crate::frame::OpenTcpFrame;
use crate::session::Session;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Unauthenticated connections held at once (Phase A cap).
pub const MAX_PENDING: u32 = 512;
/// Authenticated sessions held at once (Phase B cap).
pub const MAX_SESSIONS: u32 = 256;
/// How long an unauthenticated connection may take to deliver its first
/// packet. The client's session start sends an authenticated PING hello
/// immediately, so a genuine client completes this in one RTT.
pub const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Anti-oracle: the TIME at which a failed admission closes the connection
/// is drawn uniformly from [4.0, 5.0) s after ACCEPT — the same distribution
/// for EVERY failure class, and the admission deadline itself is randomized
/// inside the same window (see `recv_first_packet` callers), so "sent a
/// complete packet that failed auth" and "sent nothing" are
/// indistinguishable on the wire.
fn uniform_close_delay() -> Duration {
    let lo = 4000u64;
    let span = 1000u64;
    Duration::from_millis(lo + (rand::RngCore::next_u64(&mut rand::rng()) % span))
}
/// Hard cap on one outbound dial (bridge target). The OS default (~130 s)
/// would park a bridge thread and leave the client hanging.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Dial `host:port` with a hard timeout. Acceptes `ip:port` directly and
/// resolves `name:port` (first working address wins). TCP_NODELAY is set
/// on the dialed socket — the bridge's writes to the destination must not
/// be Nagle-delayed (40 ms tail latency on small responses).
pub fn dial_with_timeout(dest: &str) -> std::io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let dial = |addr: SocketAddr| -> std::io::Result<TcpStream> {
        let s = TcpStream::connect_timeout(&addr, DIAL_TIMEOUT)?;
        s.set_nodelay(true).ok();
        Ok(s)
    };
    match dest.parse::<SocketAddr>() {
        Ok(addr) => dial(addr),
        Err(_) => {
            let addrs: Vec<SocketAddr> = dest.to_socket_addrs()?.collect();
            if addrs.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("resolution of {dest} produced no addresses"),
                ));
            }
            let mut last = None;
            for addr in addrs {
                match dial(addr) {
                    Ok(s) => return Ok(s),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap())
        }
    }
}

/// Map a dial failure's io kind onto the OPEN_TCP_RESPONSE status byte
/// (identical to the SOCKS5 reply code byte, passed through verbatim).
fn dial_status(kind: std::io::ErrorKind) -> u8 {
    match kind {
        std::io::ErrorKind::NetworkUnreachable => 0x03,
        std::io::ErrorKind::HostUnreachable => 0x04,
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionAborted => 0x05,
        std::io::ErrorKind::TimedOut => 0x06,
        _ => 0x01,
    }
}

/// Handle one accepted carrier connection: admission, session, serve.
/// Runs on a dedicated thread; returns when the session ends.
///
/// `pending_counter` / `active_counter` are the process-wide admission
/// caps' backing counters (see [`MAX_PENDING`] / [`MAX_SESSIONS`]) — the
/// accept loop creates them once and passes references in; RAII guards
/// prevent leaks on every early return.
pub fn handle_connection<C: Carrier + 'static>(
    carrier: C,
    peer: String,
    psk: [u8; 32],
    config: Config,
    pending_counter: &Arc<std::sync::atomic::AtomicU32>,
    active_counter: &Arc<std::sync::atomic::AtomicU32>,
) {
    struct Dec<'a>(&'a Arc<std::sync::atomic::AtomicU32>);
    impl Drop for Dec<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let _dec_p = Dec(pending_counter);
    pending_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let accepted_at = Instant::now();

    // ---- Phase A: unauthenticated — wait (bounded) for the first packet. ----
    // The deadline is randomized inside [4.0, 5.0) s (same window as the
    // failure close-time delay) so a silent prober and a rejected one are
    // closed on the same distribution.
    let admission_deadline = uniform_close_delay();
    let first = match recv_first_packet(&carrier, admission_deadline) {
        Ok(b) => b,
        Err(AdmissionError::Timeout) => {
            log::debug!("admission timeout from {peer}");
            return;
        }
        Err(AdmissionError::Carrier(e)) => {
            log::debug!("admission err from {peer}: {e}");
            return;
        }
    };
    if first.len() < crate::config::HEADER_LEN + crate::config::AEAD_TAG_LEN {
        log::debug!("admission: packet too short ({}) from {peer}", first.len());
        // Same close-time distribution as every other failure.
        let until = accepted_at + uniform_close_delay();
        if until > Instant::now() {
            thread::sleep(until - Instant::now());
        }
        return;
    }
    // PSK verification — the first packet IS the handshake (YELLOWPAPER §3.5).
    let session_id = match crate::session::verify_psk(&first, psk) {
        Ok(sid) => sid,
        Err(_) => {
            log::warn!("admission rejected: auth failed from {peer}");
            // Same close-time distribution as every other failure.
            let until = accepted_at + uniform_close_delay();
            if until > Instant::now() {
                thread::sleep(until - Instant::now());
            }
            return;
        }
    };

    // ---- Phase B: authenticated — session slot, then the real session. ----
    // fetch_add avoids the check-then-increment race that could overshoot
    // the cap when admissions run concurrently.
    let current = active_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if current >= MAX_SESSIONS {
        active_counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        log::warn!("session limit {MAX_SESSIONS} reached, rejecting {peer} after auth");
        return;
    }
    let _dec_a = Dec(active_counter);

    let session = match Session::accept_pre_shared(
        PreLoadedCarrier::new(carrier, first),
        session_id,
        psk,
        config,
    ) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("session creation from {peer}: {e}");
            return;
        }
    };
    log::info!(
        "session established: id={} from {peer}",
        session.session_id()
    );

    serve_session(&session);

    // One-line summary instead of periodic metrics spam: everything an
    // operator needs to answer "why did this session end?".
    let m = session.metrics();
    log::info!(
        "session closed: id={} from {peer} reason={} uptime={}s pkts={}/{} bytes={}/{} streams_total={}",
        m.session_id,
        m.shutdown_reason,
        m.uptime_ms / 1000,
        m.packets_sent,
        m.packets_recv,
        m.bytes_sent,
        m.bytes_recv,
        m.streams_total
    );
}

/// Serve an authenticated session: accept OPEN_TCP requests until the
/// session ends. Each dial + bridge pair runs on its own thread so one slow
/// destination never blocks the others.
pub fn serve_session(session: &Session) {
    let alive = session.alive_flag();
    loop {
        let (stream, open_tcp) = match session.accept_open_tcp() {
            Ok(x) => x,
            Err(Error::Application(msg)) if msg.contains("closed") => return,
            Err(e) => {
                log::warn!("accept_open_tcp: {e}");
                return;
            }
        };

        let dest = match format_dest(&open_tcp) {
            Some(d) => d,
            None => {
                let _ = stream.send_open_tcp_response(0x08, "bad address");
                continue;
            }
        };
        let stream_id = stream.stream_id.0;
        log::info!("OPEN_TCP stream={stream_id} dest={dest}");

        let stream = Arc::new(stream);
        // Spare handle for the spawn-failure path below (the closure moves
        // its own clone in).
        let stream_err = Arc::clone(&stream);
        let alive_clone = Arc::clone(&alive);
        // Builder::spawn (not thread::spawn): a bare spawn PANICS on
        // failure (e.g. EAGAIN under thread pressure) and would unwind this
        // loop — permanently ending stream acceptance for the whole session.
        if let Err(e) = thread::Builder::new()
            .name(format!("rl-dial-{stream_id}"))
            .spawn(move || {
                let tcp = match dial_with_timeout(&dest) {
                    Ok(s) => s,
                    Err(e) => {
                        let status = dial_status(e.kind());
                        log::warn!(
                            "dial stream={stream_id} dest={dest} failed: {e} (status={status})"
                        );
                        let _ = stream.send_open_tcp_response(status, format!("dial: {e}"));
                        // Close the stream so it becomes dead-cleanup-eligible
                        // on BOTH ends once the client drops its handle.
                        let _ = stream.close();
                        return;
                    }
                };
                log::info!("TCP connected stream={stream_id} dest={dest}");
                if let Err(e) = stream.send_open_tcp_response(0x00, "") {
                    log::warn!("send response stream={stream_id}: {e}");
                    let _ = stream.close();
                    return;
                }
                bridge::run(tcp, stream, alive_clone);
            })
        {
            log::error!("spawn dial thread for stream={stream_id}: {e}");
            let _ = stream_err.send_open_tcp_response(0x01, "internal error");
            let _ = stream_err.close();
        }
    }
}

/// Render an OPEN_TCP address into `host:port` for dialing. `None` on a
/// malformed address (the caller answers 0x08).
fn format_dest(open: &OpenTcpFrame) -> Option<String> {
    let port = open.port;
    match open.atyp {
        1 => {
            let a = &open.addr;
            if a.len() != 4 {
                return None;
            }
            Some(format!("{}.{}.{}.{}:{port}", a[0], a[1], a[2], a[3]))
        }
        4 => {
            if open.addr.len() != 16 {
                return None;
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&open.addr);
            Some(format!("[{}]:{port}", std::net::Ipv6Addr::from(b)))
        }
        3 => {
            let a = &open.addr;
            if a.is_empty() {
                return None;
            }
            let len = a[0] as usize;
            if a.len() < 1 + len {
                return None;
            }
            let s = std::str::from_utf8(&a[1..1 + len]).ok()?;
            Some(format!("{s}:{port}"))
        }
        _ => None,
    }
}

enum AdmissionError {
    Timeout,
    Carrier(Error),
}

/// Poll the carrier for the first packet until the deadline.
fn recv_first_packet<C: Carrier>(
    carrier: &C,
    timeout: Duration,
) -> Result<Vec<u8>, AdmissionError> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(AdmissionError::Timeout);
        }
        match carrier.recv() {
            Ok(Some((_, bytes))) => return Ok(bytes),
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(AdmissionError::Carrier(e)),
        }
    }
}

/// A `Carrier` decorator whose `recv()` returns the one stored packet
/// exactly once before delegating — making the admission-time first-packet
/// read invisible to the session layer above.
struct PreLoadedCarrier<C: Carrier> {
    inner: C,
    first: Mutex<Option<Vec<u8>>>,
    addr: C::Address,
}
impl<C: Carrier> PreLoadedCarrier<C> {
    fn new(inner: C, first_bytes: Vec<u8>) -> Self {
        let addr = inner.local_addr();
        Self {
            inner,
            first: Mutex::new(Some(first_bytes)),
            addr,
        }
    }
}
impl<C: Carrier> Carrier for PreLoadedCarrier<C> {
    type Address = C::Address;
    fn send(&self, dst: Self::Address, pkt: &[u8]) -> Result<(), Error> {
        self.inner.send(dst, pkt)
    }
    fn recv(&self) -> Result<Option<(Self::Address, Vec<u8>)>, Error> {
        let mut first = self.first.lock().unwrap();
        if let Some(bytes) = first.take() {
            return Ok(Some((self.addr.clone(), bytes)));
        }
        drop(first);
        self.inner.recv()
    }
    fn mtu(&self) -> usize {
        self.inner.mtu()
    }
    fn local_addr(&self) -> Self::Address {
        self.addr.clone()
    }
    // Forward the writer-idle tick — dummy (cover) frames and coalescing
    // tail flushes happen on the writer thread.
    fn idle_tick(&self) -> Result<(), Error> {
        self.inner.idle_tick()
    }
}
