//! TunnelManager — the client's outbound: a self-healing set of RawLink
//! tunnels to one server.
//!
//! Reliability contract (the sing-box shape):
//!
//! * There is always a tunnel: the manager (re)dials the server with bounded,
//!   jittered exponential backoff, forever. No operator action is needed.
//! * When a session breaks, it is detected (carrier error, EOF, or the keepalive
//!   watchdog for silent deaths) and replaced on the next attempt. A session
//!   that lived a while resets the backoff to minimum.
//! * Callers never touch the pool: [`TunnelManager::open_stream`] blocks up
//!   to its budget for a live tunnel and returns a stream on the
//!   least-loaded one.
//!
//! Why more than one tunnel: a single RawLink session multiplexes every
//! stream, so a browser burst can exhaust the per-session stream cap. When
//! every tunnel is near the cap the manager dials another (up to
//! `max_tunnels`; 1 disables scale-out), spreads new streams across the set
//! least-loaded-first, and retires extra tunnels that sit idle for 10 s —
//! always keeping at least one.
//!
//! Threading: one maintenance thread (`rl-tunnels`) owns the lifecycle; it
//! is the only writer of the tunnel list. Dials happen outside the state
//! lock (a connect can block up to 10 s). The manager stops when the last
//! `TunnelManager` handle is dropped.
use crate::carrier::tcp::TcpCarrier;
use crate::config::Config;
use crate::error::Error;
use crate::obfs::ObfsMode;
use crate::session::{Session, Stream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// How often the maintenance thread evaluates the tunnel set.
const TICK: Duration = Duration::from_millis(100);
/// Retry cadence for a failed scale-out dial (short: the primary reconnect
/// owns the long backoff; aux dials must not inherit it).
const SCALE_RETRY: Duration = Duration::from_secs(1);
/// An extra tunnel with zero streams for this long is retired.
const TUNNEL_IDLE_RETIRE: Duration = Duration::from_secs(10);
/// Stream-count headroom below the per-session cap that triggers scale-out.
/// Covers the burst that arrives while the extra tunnel is still dialing.
const SCALE_HEADROOM: u32 = 48;

/// Deterministic exponential backoff (unit-tested). Jitter is applied by the
/// manager loop so tests stay exact.
pub fn next_backoff(
    current: Duration,
    lived: Option<Duration>,
    min: Duration,
    max: Duration,
    reset_after: Duration,
) -> Duration {
    if let Some(l) = lived
        && l >= reset_after {
            return min;
        }
    if current.is_zero() {
        min
    } else {
        (current * 2).min(max)
    }
}

/// Jittered backoff: ±15% randomization prevents every client from
/// reconnecting in lockstep after a server restart (thundering herd).
fn jittered(d: Duration) -> Duration {
    if d.is_zero() {
        return d;
    }
    let pct = (rand::random::<f64>() - 0.5).clamp(-0.15, 0.15);
    let j = (d.as_secs_f64() * (1.0 + pct)).max(0.0);
    Duration::from_secs_f64(j)
}

/// Configuration for one client's tunnel set.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub server: SocketAddr,
    pub psk: [u8; 32],
    pub session: Config,
    /// When Some, the carrier speaks the obfuscated wire format (rand =
    /// high-entropy masking, ssh = OpenSSH mimicry with early data).
    /// MUST match the server's setting (a plain server rejects obfs
    /// handshakes and vice versa — both fail cleanly and re-enter the
    /// backoff loop).
    pub obfs: Option<ObfsMode>,
    /// Maximum parallel tunnels to the server. 1 disables scale-out entirely.
    pub max_tunnels: usize,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    /// A session that lived at least this long resets the backoff to minimum.
    pub backoff_reset_after: Duration,
}
impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:6123".parse().unwrap(),
            psk: [0u8; 32],
            session: Config::default(),
            min_backoff: Duration::from_secs(1),
            // 10 s (not 30 s): when a downed server comes back, the client
            // must reattach within one interval — worst-case blackout gap
            // after a long outage matters more than a cheap connect attempt
            // every 10 s while it is down.
            max_backoff: Duration::from_secs(10),
            backoff_reset_after: Duration::from_secs(30),
            obfs: None,
            max_tunnels: 4,
        }
    }
}

struct State {
    /// Live (or dying-but-not-yet-reaped) tunnels. Index 0 is not special.
    tunnels: Vec<Arc<Session>>,
    /// Current reconnect backoff (ZERO right after a successful dial).
    backoff: Duration,
    /// When the next (re)connect attempt is due.
    next_attempt: Instant,
    /// When a failed scale-out dial may be retried.
    scale_retry_at: Instant,
    /// session_id -> when its stream count hit zero (scale-in tracking).
    idle_since: HashMap<u64, Instant>,
}

/// The client-side tunnel set. Clone the Arc, share it, drop it — the
/// maintenance thread outlives the last handle only until its next tick.
pub struct TunnelManager {
    cfg: TunnelConfig,
    state: Mutex<State>,
    rr: AtomicUsize,
    /// Keeps the maintenance loop's channel open; dropping the last manager
    /// handle disconnects it and the loop tears the tunnel set down.
    _stop: mpsc::Sender<()>,
}

impl TunnelManager {
    /// Start the manager: spawns the maintenance thread and returns a shared
    /// handle. The first dial happens immediately.
    pub fn start(cfg: TunnelConfig) -> Arc<Self> {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let mgr = Arc::new(Self {
            cfg,
            state: Mutex::new(State {
                tunnels: Vec::new(),
                backoff: Duration::ZERO,
                next_attempt: Instant::now(),
                scale_retry_at: Instant::now(),
                idle_since: HashMap::new(),
            }),
            rr: AtomicUsize::new(0),
            _stop: stop_tx,
        });
        let m = Arc::clone(&mgr);
        thread::Builder::new()
            .name("rl-tunnels".into())
            .spawn(move || maintenance_loop(m, stop_rx))
            .expect("spawn tunnel manager");
        mgr
    }

    /// Open a stream on the least-loaded live tunnel, waiting up to `wait`
    /// for a tunnel to exist (reconnect window) and for stream capacity
    /// (scale-out window). This is the whole client-side API for callers.
    pub fn open_stream(&self, wait: Duration) -> Result<(Arc<Session>, Stream), Error> {
        let deadline = Instant::now() + wait;
        let mut warned = false;
        loop {
            if let Some(session) = self.least_loaded() {
                match session.open_stream() {
                    Ok(stream) => return Ok((session, stream)),
                    // Every tunnel is at the stream cap — the manager is
                    // dialing another one; ride it out within the budget.
                    Err(e @ Error::ResourceLimit(_)) => {
                        if !warned {
                            log::warn!(
                                "open_stream: {e} — waiting for scale-out (retrying ≤{:?})",
                                wait
                            );
                            warned = true;
                        }
                        if Instant::now() >= deadline {
                            return Err(e);
                        }
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(e) => return Err(e),
                }
            } else {
                // No live tunnel: the manager is (re)connecting. Requests
                // arriving inside a brief reconnect window stay invisible
                // to the application; only a genuinely unreachable server
                // fails the caller — at the budget deadline.
                if Instant::now() >= deadline {
                    return Err(Error::Application("no live tunnel to server".into()));
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
    }

    /// Snapshot of the live tunnels (metrics / diagnostics).
    pub fn snapshot(&self) -> Vec<Arc<Session>> {
        self.state.lock().unwrap().tunnels.clone()
    }

    /// The least-loaded live tunnel (load = open stream count). Ties break
    /// round-robin so equal tunnels share traffic. `None` while reconnecting.
    pub fn least_loaded(&self) -> Option<Arc<Session>> {
        let state = self.state.lock().unwrap();
        let mut best: Option<(Arc<Session>, u32)> = None;
        for s in state.tunnels.iter() {
            if !s.is_alive() {
                continue;
            }
            let load = s.stats().streams_open;
            best = match best {
                None => Some((Arc::clone(s), load)),
                Some((_, l)) if load < l => Some((Arc::clone(s), load)),
                Some((_, l)) if load == l => {
                    // round-robin tie-break
                    if self.rr.fetch_add(1, Ordering::Relaxed) & 1 == 1 {
                        Some((Arc::clone(s), load))
                    } else {
                        best
                    }
                }
                _ => best,
            };
        }
        best.map(|(s, _)| s)
    }
}
impl Drop for TunnelManager {
    fn drop(&mut self) {
        // The maintenance loop sees the disconnect on its next tick (≤100 ms)
        // and tears the tunnel set down. Session drops send CONNECTION_CLOSE.
    }
}

/// Single maintenance loop: keep ≥1 tunnel, scale out under pressure, reap
/// the dead, retire the idle. One function, in the order the state changes.
fn maintenance_loop(mgr: Arc<TunnelManager>, stop_rx: mpsc::Receiver<()>) {
    let cfg = mgr.cfg.clone();
    let max_tunnels = cfg.max_tunnels.max(1);
    let cap = cfg.session.max_streams_per_session;
    let threshold = cap.saturating_sub(SCALE_HEADROOM).max(1);

    loop {
        // Stop on an explicit signal OR when the last manager handle was
        // dropped (sender disconnected).
        match stop_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                mgr.state.lock().unwrap().tunnels.clear();
                return;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let now = Instant::now();

        // ---- 1) Reap dead tunnels; schedule the reconnect. ----
        {
            let state = &mut *mgr.state.lock().unwrap();
            let now_dead: Vec<Arc<Session>> = state
                .tunnels
                .iter()
                .filter(|s| !s.is_alive())
                .cloned()
                .collect();
            if !now_dead.is_empty() {
                state.tunnels.retain(|s| s.is_alive());
                state.idle_since.clear();
                // One backoff step per death-wave (tunnels usually die
                // together — one server). The longest-lived session decides
                // the reset rule, mirroring the single-tunnel semantics.
                let longest_lived = now_dead
                    .iter()
                    .map(|s| Duration::from_millis(s.stats().session_uptime_ms))
                    .max()
                    .unwrap_or(Duration::ZERO);
                state.backoff = jittered(next_backoff(
                    state.backoff,
                    Some(longest_lived),
                    cfg.min_backoff,
                    cfg.max_backoff,
                    cfg.backoff_reset_after,
                ));
                state.next_attempt = now + state.backoff;
                for s in &now_dead {
                    log::warn!(
                        "tunnel id={} lost after {:?} (reason={:?})",
                        s.session_id(),
                        Duration::from_millis(s.stats().session_uptime_ms),
                        s.shutdown_reason()
                    );
                }
                log::warn!(
                    "{} tunnel(s) lost — reconnecting in {:?}",
                    now_dead.len(),
                    state.backoff
                );
            }
        }

        // ---- 2) Ensure at least one live tunnel. ----
        let need_primary = {
            let state = mgr.state.lock().unwrap();
            !state.tunnels.iter().any(|s| s.is_alive())
        };
        if need_primary {
            let due = {
                let state = mgr.state.lock().unwrap();
                now >= state.next_attempt
            };
            if due {
                match dial(&cfg) {
                    Ok(session) => {
                        let session = Arc::new(session);
                        log::info!(
                            "tunnel established: id={} ({}/{})",
                            session.session_id(),
                            mgr.state.lock().unwrap().tunnels.len() + 1,
                            max_tunnels
                        );
                        let mut state = mgr.state.lock().unwrap();
                        state.tunnels.push(session);
                        state.backoff = Duration::ZERO;
                    }
                    Err(e) => {
                        let mut state = mgr.state.lock().unwrap();
                        state.backoff = jittered(next_backoff(
                            state.backoff,
                            None,
                            cfg.min_backoff,
                            cfg.max_backoff,
                            cfg.backoff_reset_after,
                        ));
                        state.next_attempt = now + state.backoff;
                        log::warn!("connect: {e} — retrying in {:?}", state.backoff);
                    }
                }
            }
        }

        // ---- 3) Scale out when every tunnel is near the stream cap. ----
        let want_scale_out = {
            let state = mgr.state.lock().unwrap();
            state.tunnels.len() < max_tunnels
                && now >= state.scale_retry_at
                && state.tunnels.iter().all(|s| s.is_alive())
                && state
                    .tunnels
                    .iter()
                    .any(|s| s.stats().streams_open >= threshold)
        };
        if want_scale_out {
            let load = mgr
                .state
                .lock()
                .unwrap()
                .tunnels
                .iter()
                .map(|s| s.stats().streams_open)
                .max()
                .unwrap_or(0);
            log::info!(
                "tunnels at {load}/{cap} streams — scaling out ({}/{})",
                mgr.state.lock().unwrap().tunnels.len() + 1,
                max_tunnels
            );
            match dial(&cfg) {
                Ok(session) => {
                    let session = Arc::new(session);
                    log::info!(
                        "tunnel established: id={} ({}/{})",
                        session.session_id(),
                        mgr.state.lock().unwrap().tunnels.len() + 1,
                        max_tunnels
                    );
                    mgr.state.lock().unwrap().tunnels.push(session);
                }
                Err(e) => {
                    log::warn!("scale-out dial failed: {e} — retrying in {SCALE_RETRY:?}");
                    mgr.state.lock().unwrap().scale_retry_at = now + SCALE_RETRY;
                }
            }
        }

        // ---- 4) Retire idle extra tunnels (keep at least one). ----
        {
            let state = &mut *mgr.state.lock().unwrap();
            if state.tunnels.len() > 1 {
                let mut retire: Vec<u64> = Vec::new();
                for s in state.tunnels.iter() {
                    if !s.is_alive() {
                        continue;
                    } // reaped above next tick
                    let sid = s.session_id();
                    if s.stats().streams_open == 0 {
                        let since = state.idle_since.entry(sid).or_insert(now);
                        if since.elapsed() >= TUNNEL_IDLE_RETIRE {
                            retire.push(sid);
                        }
                    } else {
                        state.idle_since.remove(&sid);
                    }
                }
                // Never retire below one tunnel.
                for sid in retire {
                    if state.tunnels.len() <= 1 {
                        break;
                    }
                    if let Some(pos) = state.tunnels.iter().position(|s| s.session_id() == sid) {
                        let s = state.tunnels.remove(pos);
                        state.idle_since.remove(&sid);
                        log::info!(
                            "tunnel id={} idle {:?} — scaled in",
                            sid,
                            TUNNEL_IDLE_RETIRE
                        );
                        drop(s); // Arc drop → clean close when unreferenced
                    }
                }
            }
        }

        thread::sleep(TICK);
    }
}

/// Stream-count threshold at/above which the manager dials another tunnel
/// (headroom `SCALE_HEADROOM` below the per-session cap, floored at 1).
pub fn scale_threshold(cap: u32) -> u32 {
    cap.saturating_sub(SCALE_HEADROOM).max(1)
}

/// Dial one tunnel: TCP connect (+ obfs handshake if configured) and session
/// start. `TcpCarrier::connect` enforces a 10 s connect timeout internally,
/// so a black-holed server cannot park the manager.
/// The session id is generated BEFORE the carrier connects — the header
/// mask keys derive from it (see `mask.rs`).
pub fn dial(cfg: &TunnelConfig) -> Result<Session, Error> {
    match &cfg.obfs {
        None => {
            let sid = crate::session::SessionId::generate();
            let carrier = TcpCarrier::connect(cfg.server, &cfg.psk, sid.as_bytes())?;
            Session::connect_pre_shared_with_sid(carrier, cfg.psk, cfg.session.clone(), sid)
        }
        Some(ObfsMode::Rand(_)) => {
            let sid = crate::session::SessionId::generate();
            let carrier = TcpCarrier::connect_obfs(
                cfg.server,
                &cfg.psk,
                sid.as_bytes(),
                cfg.obfs.as_ref().unwrap(),
            )?;
            Session::connect_pre_shared_with_sid(carrier, cfg.psk, cfg.session.clone(), sid)
        }
        // SSH mimicry: the RawLink hello packet rides the post-NEWKEYS
        // flight — the earliest point a real SSH client could send data
        // (one RTT after the emulated curve25519 exchange).
        Some(ObfsMode::Ssh(scfg)) => {
            let (sid, early) = crate::session::build_first_packet(&cfg.psk)?;
            let carrier = TcpCarrier::connect_obfs_ssh_early(
                cfg.server,
                &cfg.psk,
                scfg,
                &early,
                sid.as_bytes(),
            )?;
            Session::connect_pre_shared_preamble(carrier, cfg.psk, cfg.session.clone(), sid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_up_threshold_leaves_burst_headroom() {
        assert_eq!(scale_threshold(256), 208);
        assert_eq!(scale_threshold(48), 1);
        assert_eq!(scale_threshold(16), 1);
        assert_eq!(scale_threshold(1), 1);
    }

    #[test]
    fn backoff_semantics_unchanged() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(30);
        let reset = Duration::from_secs(30);
        assert_eq!(next_backoff(Duration::ZERO, None, min, max, reset), min);
        assert_eq!(next_backoff(min, None, min, max, reset), min * 2);
        assert_eq!(next_backoff(max, None, min, max, reset), max);
        // long-lived session resets to min
        assert_eq!(next_backoff(max, Some(reset), min, max, reset), min);
        // short-lived session keeps growing
        assert_eq!(
            next_backoff(min, Some(Duration::from_secs(1)), min, max, reset),
            min * 2
        );
    }
}
