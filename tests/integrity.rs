//! Session-level integrity tests: replay/duplicate rejection, duplicate
//! OPEN_TCP survival, stream caps, empty-write FIN confusion, and the
//! frame-count receive limit.
//!
//! Uses an in-memory crossbar carrier so tests can inject raw packets
//! (replays, oversized frame counts) that would be impossible over TCP.

use rawlink::carrier::{Carrier, CarrierAddress};
use rawlink::config::{Config, HEADER_LEN};
use rawlink::crypto;
use rawlink::error::Error;
use rawlink::packet::PacketHeader;
use rawlink::session::{Session, SessionId};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Crossbar test carrier: end A (client) <-> end B (server)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TestAddr(u8);
impl CarrierAddress for TestAddr {}

#[derive(Default)]
struct Shared {
    /// B -> A queue (popped by A's recv).
    in_a: VecDeque<Vec<u8>>,
    /// A -> B queue (popped by B's recv).
    in_b: VecDeque<Vec<u8>>,
}

#[derive(Clone)]
struct TestCarrier {
    shared: Arc<Mutex<Shared>>,
    is_a: bool,
    /// Deliver every packet twice (second copy = replay attack simulation).
    duplicate_every: bool,
}

impl TestCarrier {
    fn pair(duplicate_every: bool) -> (TestCarrier, TestCarrier) {
        let shared = Arc::new(Mutex::new(Shared::default()));
        (
            TestCarrier {
                shared: Arc::clone(&shared),
                is_a: true,
                duplicate_every,
            },
            TestCarrier {
                shared,
                is_a: false,
                duplicate_every,
            },
        )
    }
}

impl Carrier for TestCarrier {
    type Address = TestAddr;
    fn send(&self, _dst: TestAddr, pkt: &[u8]) -> Result<(), Error> {
        let mut g = self.shared.lock().unwrap();
        let q = if self.is_a { &mut g.in_b } else { &mut g.in_a };
        q.push_back(pkt.to_vec());
        if self.duplicate_every {
            q.push_back(pkt.to_vec());
        }
        Ok(())
    }
    fn recv(&self) -> Result<Option<(TestAddr, Vec<u8>)>, Error> {
        let mut g = self.shared.lock().unwrap();

        let q = if self.is_a { &mut g.in_a } else { &mut g.in_b };
        Ok(q.pop_front()
            .map(|b| (TestAddr(if self.is_a { 1 } else { 0 }), b)))
    }
    fn mtu(&self) -> usize {
        65535
    }
    fn local_addr(&self) -> TestAddr {
        TestAddr(if self.is_a { 0 } else { 1 })
    }
}

const PSK: [u8; 32] = [0x42u8; 32];

static LOG_INIT: std::sync::Once = std::sync::Once::new();
fn init_log() {
    LOG_INIT.call_once(|| {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .format_timestamp_millis()
                .try_init();
    });
}

/// Build a raw, correctly-encrypted packet carrying `body`, as if sent by
/// the client (c2s key, client session id, packet number `pn`).
fn craft_packet(sid_u64: u64, pn: u64, body: &[u8]) -> Vec<u8> {
    let keys = crypto::derive_keys(&sid_u64.to_le_bytes(), &PSK);
    let header = PacketHeader::new(sid_u64, pn, false);
    let aad = header.to_bytes();
    let ct = crypto::encrypt(&keys.c2s, pn, body, &aad).unwrap();
    let mut wire = Vec::with_capacity(HEADER_LEN + ct.len());
    wire.extend_from_slice(&aad);
    wire.extend_from_slice(&ct);
    wire
}

fn ping_body(range: std::ops::Range<u64>, base: u64) -> Vec<u8> {
    let mut body = Vec::new();
    for i in range {
        body.extend_from_slice(
            &rawlink::frame::Frame::Ping(rawlink::frame::PingFrame { echo: base + i }).encode(),
        );
    }
    body
}

fn wait_until<F: Fn() -> bool>(deadline_ms: u64, f: F) -> bool {
    let start = Instant::now();
    while start.elapsed().as_millis() < deadline_ms as u128 {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    f()
}

/// Server-side accept + read worker. Collects each payload as a String and
/// reports the exact sequence received — a duplicated DATA frame would show
/// up as an extra entry.
fn server_reader(server: Arc<Session>, n_streams: usize, tx: mpsc::Sender<Vec<String>>) {
    let mut received = Vec::new();
    for _ in 0..n_streams {
        let (stream, _otc) = match server.accept_open_tcp() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("server accept_open_tcp failed: {e}");
                let _ = tx.send(received);
                return;
            }
        };
        match stream.read() {
            Ok(b) if !b.is_empty() => received.push(String::from_utf8_lossy(&b).into_owned()),
            other => {
                eprintln!("server stream read unexpected: {other:?}");
                let _ = tx.send(received);
                return;
            }
        }
    }
    let _ = tx.send(received);
}

#[test]
fn duplicates_and_replays_do_not_corrupt_or_kill_session() {
    init_log();
    let (ca, cb) = TestCarrier::pair(true /* duplicate_every */);
    let client = Arc::new(Session::connect_pre_shared(ca, PSK, Config::default()).unwrap());
    let sid = SessionId::from_u64(client.session_id());
    let server = Arc::new(Session::accept_pre_shared(cb, sid, PSK, Config::default()).unwrap());
    thread::sleep(Duration::from_millis(50));

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || server_reader(server, 2, tx));

    // Stream 1: open + dial + write.
    let s1 = client.open_stream().unwrap();
    s1.open_tcp(1, vec![127, 0, 0, 1], 8080).unwrap();
    s1.write(b"payload-one").unwrap();

    // Stream 2 on the SAME session — exercises the duplicate-OPEN_TCP
    // regression: the duplicated OPEN_TCP for stream 1 must NOT kill the
    // accept loop, otherwise this second accept never completes.
    let s2 = client.open_stream().unwrap();
    s2.open_tcp(1, vec![127, 0, 0, 1], 8081).unwrap();
    s2.write(b"payload-two").unwrap();

    let got = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("server reader did not finish in time");
    assert_eq!(
        got,
        vec!["payload-one".to_string(), "payload-two".to_string()],
        "duplicated packets corrupted the stream data or killed the accept loop"
    );
    assert!(client.is_alive());
}

#[test]
fn replayed_authenticated_packet_is_processed_exactly_once() {
    init_log();
    let (ca, cb) = TestCarrier::pair(false);
    // Clone BEFORE the carrier moves into the session — the clone's send()
    // reaches the server end, acting as an on-path injector.
    let injector = ca.clone();
    let client = Arc::new(Session::connect_pre_shared(ca, PSK, Config::default()).unwrap());
    let sid_u64 = client.session_id();
    let server = Arc::new(
        Session::accept_pre_shared(cb, SessionId::from_u64(sid_u64), PSK, Config::default())
            .unwrap(),
    );
    thread::sleep(Duration::from_millis(50));

    // NOTE on packet numbers: the client session now sends an authenticated
    // hello Ping at start (so the server CLI's admission phase completes
    // without application traffic). That hello occupies client pn=1 and is
    // answered with a Pong — pongs_recv therefore starts at 1, and crafted
    // client-direction packets must use pn >= 2 to stay clear of the
    // server's replay window.

    // Packet pn=2 with 100 PINGs.
    let body = ping_body(0..100, 0xfeed_0000);
    let wire = craft_packet(sid_u64, 2, &body);
    injector.send(injector.local_addr(), &wire).unwrap();
    assert!(
        wait_until(5000, || client.stats().pongs_recv >= 101),
        "first delivery failed (pongs_recv={})",
        client.stats().pongs_recv
    );

    // REPLAY the exact same authenticated bytes. The replay window must
    // reject it: the server must NOT answer with another 100 pongs.
    injector.send(injector.local_addr(), &wire).unwrap();
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        client.stats().pongs_recv,
        101,
        "replayed packet was processed a second time — replay protection missing"
    );

    // A NEW packet (pn=3) must still flow: rejection isn't a session kill.
    let body2 = ping_body(0..100, 0xbeef_0000);
    let wire2 = craft_packet(sid_u64, 3, &body2);
    injector.send(injector.local_addr(), &wire2).unwrap();
    assert!(
        wait_until(5000, || client.stats().pongs_recv == 201),
        "session broken after replay rejection (pongs_recv={})",
        client.stats().pongs_recv
    );
    assert!(server.is_alive() && client.is_alive());
}

#[test]
fn empty_write_does_not_look_like_fin() {
    init_log();
    let (ca, cb) = TestCarrier::pair(false);
    let client = Arc::new(Session::connect_pre_shared(ca, PSK, Config::default()).unwrap());
    let sid = SessionId::from_u64(client.session_id());
    let server = Arc::new(Session::accept_pre_shared(cb, sid, PSK, Config::default()).unwrap());
    thread::sleep(Duration::from_millis(50));

    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let (stream, _otc) = match server.accept_open_tcp() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("accept failed: {e}");
                let _ = tx.send("<accept-err>".into());
                return;
            }
        };
        // First read must return the REAL payload — an empty DATA frame
        // previously read as PeerFin-equivalent and closed the bridge.
        match stream.read() {
            Ok(b) => {
                let _ = tx.send(String::from_utf8_lossy(&b).into_owned());
            }
            Err(e) => {
                eprintln!("read err: {e}");
                let _ = tx.send("<err>".into());
            }
        }
    });

    let s = client.open_stream().unwrap();
    s.open_tcp(1, vec![127, 0, 0, 1], 9090).unwrap();
    let n = s.write(b"").expect("empty write should be Ok(0)");
    assert_eq!(n, 0, "empty write must be a no-op, not a sent frame");
    s.write(b"real-payload").unwrap();

    let got = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server read timeout");
    assert_eq!(
        got, "real-payload",
        "empty DATA frame was delivered and looked like FIN"
    );
}

#[test]
fn max_streams_per_session_is_enforced() {
    init_log();
    let (ca, cb) = TestCarrier::pair(false);
    let cfg = Config {
        max_streams_per_session: 2,
        ..Default::default()
    };
    let client = Session::connect_pre_shared(ca, PSK, cfg.clone()).unwrap();
    let sid = SessionId::from_u64(client.session_id());
    let _server = Session::accept_pre_shared(cb, sid, PSK, cfg).unwrap();

    let s1 = client.open_stream().unwrap();
    let s2 = client.open_stream().unwrap();
    let _ = (s1, s2);
    let err = client
        .open_stream()
        .err()
        .expect("third open_stream must fail");
    assert!(
        matches!(err, Error::ResourceLimit(_)),
        "expected ResourceLimit, got {err:?}"
    );
    // The session must remain alive and usable after the rejection.
    assert!(client.is_alive());
}

#[test]
fn receiver_accepts_throughput_frame_counts_and_rejects_over_limit() {
    // Throughput mode packs up to 256 frames/packet; the receiver previously
    // hard-coded a 64-frame parse limit and silently DROPPED such packets.
    init_log();
    let (ca, cb) = TestCarrier::pair(false);
    let injector = ca.clone();
    let client = Arc::new(Session::connect_pre_shared(ca, PSK, Config::default()).unwrap());
    let sid = SessionId::from_u64(client.session_id());
    let server = Arc::new(Session::accept_pre_shared(cb, sid, PSK, Config::default()).unwrap());
    thread::sleep(Duration::from_millis(50));

    // 100 PING frames in one packet (> old limit of 64) must be accepted.
    // (Client pn=1 is the session hello Ping — see the replay test above.)
    let sid_u64 = client.session_id();
    let wire = craft_packet(sid_u64, 2, &ping_body(0..100, 0xfeed_0000));
    injector.send(injector.local_addr(), &wire).unwrap();
    assert!(
        wait_until(5000, || client.stats().pongs_recv >= 101),
        "server rejected the 100-frame packet (pongs_recv={})",
        client.stats().pongs_recv
    );

    // Over the protocol cap: 2000 ping frames must be REJECTED as a unit
    // (no pongs from that packet), and the session must stay alive.
    let wire2 = craft_packet(sid_u64, 3, &ping_body(0..2000, 0xbeef_0000));
    injector.send(injector.local_addr(), &wire2).unwrap();

    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        client.stats().pongs_recv,
        101,
        "over-limit packet must be rejected as a whole"
    );
    assert!(
        server.is_alive() && client.is_alive(),
        "session must survive an over-limit packet"
    );
}
