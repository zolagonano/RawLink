//! TunnelManager integration tests: scale-out/in under stream pressure,
//! least-loaded routing, and the reconnect contract (server off → on, the
//! client re-attaches on its own).
//!
//! Scale-out regression: "open_stream: max streams per session (256)
//! reached — it should scale when more connections come in".

use rawlink::carrier::{Carrier, TcpListenerCarrier};
use rawlink::client::{TunnelConfig, TunnelManager};
use rawlink::config::Config;
use rawlink::obfs::ObfsConfig;
use rawlink::session::{Session, SessionId};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const PSK: [u8; 32] = [0x7C; 32];

static LOG_INIT: std::sync::Once = std::sync::Once::new();
fn init_log() {
    LOG_INIT.call_once(|| {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .format_timestamp_millis().try_init();
    });
}

/// Carrier that replays one pre-read packet before delegating (mirrors the
/// server's admission flow without depending on server internals). When the
/// shared kill flag is set, `recv` returns a fatal error — the same signal a
/// real server's socket death produces.
struct PreLoaded {
    inner: rawlink::carrier::TcpCarrier,
    first: std::sync::Mutex<Option<Vec<u8>>>,
    addr: rawlink::carrier::TcpAddr,
    kill: Arc<std::sync::atomic::AtomicBool>,
}
impl Carrier for PreLoaded {
    type Address = rawlink::carrier::TcpAddr;
    fn send(&self, dst: Self::Address, pkt: &[u8]) -> Result<(), rawlink::Error> {
        self.inner.send(dst, pkt)
    }
    fn recv(&self) -> Result<Option<(Self::Address, Vec<u8>)>, rawlink::Error> {
        if self.kill.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(rawlink::Error::Carrier(rawlink::error::CarrierError::new(
                "test", "recv", "server killed")));
        }
        let mut f = self.first.lock().unwrap();
        if let Some(b) = f.take() { return Ok(Some((self.addr, b))); }
        drop(f);
        self.inner.recv()
    }
    fn mtu(&self) -> usize { self.inner.mtu() }
    fn local_addr(&self) -> Self::Address { self.inner.local_addr() }
}

/// An echo server over RawLink: every admitted session gets every OPEN_TCP
/// answered and echoed back. Reports each admitted session id on `sid_tx`.
/// Setting `stop` makes every worker return (sessions drop → the client's
/// tunnels die) and the accept loop exit (listener drops → port freed) —
/// the "server off" event.
fn serve_echo(addr: SocketAddr, obfs: bool, sid_tx: mpsc::Sender<u64>, stop: Arc<std::sync::atomic::AtomicBool>) {
    let listener = if obfs {
        TcpListenerCarrier::bind_obfs(addr, &PSK, &rawlink::ObfsMode::Rand(obfs_cfg())).unwrap()
    } else {
        TcpListenerCarrier::bind(addr, &PSK).unwrap()
    };
    'outer: loop {
        if stop.load(std::sync::atomic::Ordering::SeqCst) { return; }
        match listener.accept() {
            Ok(carrier) => {
                let first = loop {
                    match carrier.recv() {
                        Ok(Some((_, b))) => break b,
                        Ok(None) => {
                            thread::sleep(Duration::from_millis(2));
                            if stop.load(std::sync::atomic::Ordering::SeqCst) { return; }
                        }
                        Err(_) => continue 'outer,
                    }
                };
                let sid = match rawlink::session::verify_psk(&first, PSK) {
                    Ok(sid) => sid,
                    Err(_) => continue,
                };
                let carrier = PreLoaded {
                    addr: carrier.local_addr(),
                    inner: carrier,
                    first: std::sync::Mutex::new(Some(first)),
                    kill: Arc::clone(&stop),
                };
                let session = Session::accept_pre_shared(carrier, sid, PSK, Config::default()).unwrap();
                let _ = sid_tx.send(session.session_id());
                thread::spawn(move || {
                    // Accept + echo until the session dies ("server off" makes
                    // the wrapped carrier return a fatal error → the session
                    // shuts down → this loop's accept returns Err → the
                    // socket drops → the client sees EOF).
                    loop {
                        match session.accept_open_tcp() {
                            Ok((stream, _)) => {
                                let _ = stream.send_open_tcp_response(0x00, "");
                                thread::spawn(move || loop {
                                    match stream.read() {
                                        Ok(b) if b.is_empty() => break,
                                        Ok(b) => { if stream.write(&b).is_err() { break; } }
                                        Err(_) => break,
                                    }
                                });
                            }
                            Err(_) => return,
                        }
                    }
                });
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// Stop an echo server: set the flag, then unblock its accept loop with a
/// throwaway connection so it observes the flag and exits.
fn stop_echo_server(stop: &Arc<std::sync::atomic::AtomicBool>, addr: SocketAddr) {
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500));
}

fn obfs_cfg() -> ObfsConfig {
    ObfsConfig { padding_max: 24, dummy_min_ms: 80, dummy_max_ms: 160, dummy_size_max: 256 }
}

#[test]
fn tunnels_scale_out_under_stream_pressure_and_back_in() {
    init_log();
    let addr = free_port();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (sid_tx, sid_rx) = mpsc::channel::<u64>();
    {
        let stop = Arc::clone(&stop);
        thread::spawn(move || serve_echo(addr, true, sid_tx, stop));
    }

    // Small per-tunnel cap so the scale-out threshold is 1 stream: every
    // loaded tunnel immediately justifies another dial (up to max_tunnels).
    let mgr = TunnelManager::start(TunnelConfig {
        server: addr,
        psk: PSK,
        session: Config { max_streams_per_session: 8, ..Default::default() },
        obfs: Some(rawlink::ObfsMode::Rand(obfs_cfg())),
        max_tunnels: 3,
        min_backoff: Duration::from_millis(200),
        ..Default::default()
    });
    let t0 = Instant::now();

    // 1) The first tunnel comes up (obfs enabled).
    while mgr.least_loaded().is_none() {
        assert!(t0.elapsed() < Duration::from_secs(10), "first tunnel never came up");
        thread::sleep(Duration::from_millis(20));
    }

    // 2) One live stream pushes it to the threshold → scale-out.
    let s0 = mgr.least_loaded().unwrap();
    let st0 = s0.open_stream().unwrap();
    st0.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    assert_eq!(st0.wait_for_open_tcp_response().unwrap().status, 0x00,
        "stream on the first tunnel must dial");
    wait_for_len(&mgr, 2, Duration::from_secs(10), "after 1 loaded stream");

    // 3) More streams → the set keeps scaling until max_tunnels is hit, and
    //    streams ROUTE to the lightest tunnel (loads stay balanced).
    let mut streams: Vec<Arc<rawlink::session::Stream>> = vec![Arc::new(st0)];
    for _ in 0..6 {
        let s = mgr.least_loaded().expect("set must keep at least one live tunnel");
        let st = Arc::new(s.open_stream().unwrap());
        st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
        let resp = st.wait_for_open_tcp_response().unwrap();
        assert_eq!(resp.status, 0x00, "stream must dial on whichever tunnel it lands on");
        streams.push(Arc::clone(&st));
        wait_for_len(&mgr, 3, Duration::from_secs(10), "while loading the set");
    }
    assert!(mgr.snapshot().len() <= 3, "set must never exceed max_tunnels");
    // All three tunnels carry streams (least-loaded routing).
    for s in mgr.snapshot() {
        let load = s.stats().streams_open;
        assert!(load >= 1, "every tunnel should hold streams, tunnel {} has {load}",
            s.session_id());
    }
    // The server saw 3 distinct sessions.
    let mut server_sessions = std::collections::HashSet::new();
    while let Ok(id) = sid_rx.try_recv() { server_sessions.insert(id); }
    assert!(server_sessions.len() >= 3,
        "server must see 3 separate tunnel sessions, saw {server_sessions:?}");

    // 4) Concurrent bulk echo through every stream — integrity across all
    //    tunnels with obfs + scale-out combined.
    let mut handles = Vec::new();
    for (i, st) in streams.iter().enumerate() {
        let st = Arc::clone(st);
        handles.push(thread::spawn(move || {
            let payload: Vec<u8> = (0..128 * 1024).map(|j| (j % 251) as u8 ^ i as u8).collect();
            st.write(&payload).unwrap();
            let mut got = Vec::with_capacity(payload.len());
            let deadline = Instant::now() + Duration::from_secs(30);
            while got.len() < payload.len() {
                assert!(Instant::now() < deadline, "echo timeout on stream {i}");
                match st.read() {
                    Ok(b) if b.is_empty() => panic!("unexpected FIN on stream {i}"),
                    Ok(b) => got.extend_from_slice(&b),
                    Err(e) => panic!("read on stream {i}: {e}"),
                }
            }
            assert_eq!(got, payload, "echo mismatch on stream {i}");
        }));
    }
    for h in handles { h.join().unwrap(); }

    // 5) SCALE-IN: drop every stream; extra tunnels retire after their idle
    //    window; exactly one remains.
    streams.clear();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if mgr.snapshot().len() == 1 { break; }
        assert!(Instant::now() < deadline,
            "extra tunnels never scaled back in (live: {})", mgr.snapshot().len());
        thread::sleep(Duration::from_millis(100));
    }
    log::info!("tunnel scale-in verified ({} elapsed)", t0.elapsed().as_secs_f32());

    // 6) The remaining tunnel still works after the whole exercise.
    let s = mgr.least_loaded().unwrap();
    let st = s.open_stream().unwrap();
    st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    assert_eq!(st.wait_for_open_tcp_response().unwrap().status, 0x00);

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    stop_echo_server(&stop, addr);
}

/// The reconnect contract: the server goes off (its sockets vanish — the
/// client's session dies) and comes back on a new listener; the manager
/// re-attaches on its own and `open_stream` works again. No external
/// action, no restart — the sing-box-style liveness the client promises.
#[test]
fn manager_reconnects_after_server_restart() {
    init_log();
    let addr = free_port();

    // Server instance #1.
    let stop1 = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (sid_tx, _sid_rx) = mpsc::channel::<u64>();
    {
        let stop = Arc::clone(&stop1);
        thread::spawn(move || serve_echo(addr, false, sid_tx, stop));
    }

    let mgr = TunnelManager::start(TunnelConfig {
        server: addr,
        psk: PSK,
        session: Config::default(),
        obfs: None,
        max_tunnels: 1,
        min_backoff: Duration::from_millis(200),
        max_backoff: Duration::from_millis(800),
        backoff_reset_after: Duration::from_millis(500),
    });

    // (a) First tunnel works.
    let (s, st) = mgr.open_stream(Duration::from_secs(5)).expect("first tunnel");
    st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    assert_eq!(st.wait_for_open_tcp_response().unwrap().status, 0x00);
    drop(st); drop(s);

    // (b) Let the session outlive backoff_reset_after so the reconnect is
    //     immediate, then KILL server #1 (listener + sessions all drop).
    thread::sleep(Duration::from_millis(700));
    stop_echo_server(&stop1, addr);

    // (c) The client notices the dead session.
    let deadline = Instant::now() + Duration::from_secs(10);
    while mgr.least_loaded().is_some() {
        assert!(Instant::now() < deadline, "client never noticed the dead tunnel");
        thread::sleep(Duration::from_millis(20));
    }

    // (d) Server goes back ON (a fresh instance on the same port).
    thread::sleep(Duration::from_millis(200));
    let (sid_tx2, _sid_rx2) = mpsc::channel::<u64>();
    {
        let stop2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2_keep = Arc::clone(&stop2);
        std::mem::forget(stop2_keep); // keep this server running until the test ends
        thread::spawn(move || serve_echo(addr, false, sid_tx2, stop2));
    }
    // The real contract under test: open_stream must ride the reconnect
    // window and succeed without any external action.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (_s, st) = loop {
        match mgr.open_stream(Duration::from_millis(300)) {
            Ok(x) => break x,
            Err(e) => {
                assert!(Instant::now() < deadline, "manager never reconnected: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    };

    // (e) Post-restart dial + echo round-trip succeeds.
    st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    assert_eq!(st.wait_for_open_tcp_response().unwrap().status, 0x00,
        "post-restart dial must succeed");
    let payload: Vec<u8> = (0..64 * 1024).map(|j| (j % 251) as u8).collect();
    st.write(&payload).unwrap();
    let mut got = Vec::with_capacity(payload.len());
    let echo_deadline = Instant::now() + Duration::from_secs(10);
    while got.len() < payload.len() {
        assert!(Instant::now() < echo_deadline, "post-restart echo timeout");
        match st.read() {
            Ok(b) if b.is_empty() => panic!("unexpected FIN after restart"),
            Ok(b) => got.extend_from_slice(&b),
            Err(e) => panic!("read after restart: {e}"),
        }
    }
    assert_eq!(got, payload);
    log::info!("manager reconnect verified");
}

fn free_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

fn wait_for_len(mgr: &TunnelManager, want: usize, timeout: Duration, ctx: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if mgr.snapshot().len() >= want { return; }
        assert!(Instant::now() < deadline,
            "tunnel set never reached {want} tunnels {ctx} (len={})", mgr.snapshot().len());
        thread::sleep(Duration::from_millis(20));
    }
}

/// Sanity: SessionId helper used above (guards against API drift).
#[test]
fn session_id_roundtrip() {
    let sid = SessionId::from_u64(0x1234_5678_9abc_def0);
    assert_eq!(sid.as_u64(), 0x1234_5678_9abc_def0);
}
