//! Basic integration tests for TCP carrier round-trip + crypto + framing.
use rawlink::carrier::{Carrier, SimCarrier, SimAddr, SimConfig, LossPattern, DelayPattern};
use rawlink::config::Config;
use rawlink::session::Session;
use std::thread;
use std::time::Duration;

#[test]
fn sim_carrier_round_trip() {
    let c = SimCarrier::clean();
    c.send(SimAddr::Server, b"hello").unwrap();
    thread::sleep(Duration::from_millis(5));
    let (_, d) = c.recv().unwrap().unwrap();
    assert_eq!(d, b"hello");
}

#[test]
fn sim_carrier_loss_10pct() {
    let c = SimCarrier::new(SimConfig { loss: LossPattern::EveryNth(10), ..Default::default() });
    for i in 0..100u32 { c.send(SimAddr::Server, format!("p{i}").as_bytes()).unwrap(); }
    thread::sleep(Duration::from_millis(10));
    let mut got = Vec::new();
    while let Some((_, d)) = c.recv().unwrap() { got.push(d); }
    assert!(got.len() >= 90, "expected >= 90 delivered, got {}", got.len());
}

#[test]
fn sim_carrier_duplicates() {
    let c = SimCarrier::new(SimConfig { duplicate: true, ..Default::default() });
    c.send(SimAddr::Server, b"dup").unwrap();
    thread::sleep(Duration::from_millis(5));
    let mut got = Vec::new();
    while let Some((_, d)) = c.recv().unwrap() { got.push(d); }
    assert!(!got.is_empty());
    for d in &got { assert_eq!(d, b"dup"); }
}

#[test]
fn sim_carrier_reorder() {
    let c = SimCarrier::new(SimConfig {
        delay: DelayPattern::Variable { base: Duration::from_millis(0),
            step: Duration::from_millis(1), modulus: 10 },
        ..Default::default()
    });
    for i in 0..10u32 { c.send(SimAddr::Server, format!("p{i}").as_bytes()).unwrap(); }
    thread::sleep(Duration::from_millis(20));
    let mut got: Vec<String> = Vec::new();
    while let Some((_, d)) = c.recv().unwrap() { got.push(String::from_utf8(d).unwrap()); }
    assert_eq!(got.len(), 10);
    let mut sorted = got.clone(); sorted.sort();
    let expected: Vec<String> = (0..10).map(|i| format!("p{i}")).collect();
    assert_eq!(sorted, expected);
}

#[test]
fn frame_round_trip() {
    use rawlink::frame::*;
    let f = Frame::Data(DataFrame { stream_id: 42, offset: 100, payload: b"hello".to_vec() });
    let bytes = f.encode();
    let (p, n) = Frame::parse(&bytes).unwrap();
    assert_eq!(n, bytes.len());
    assert_eq!(p, f);
}

#[test]
fn crypto_round_trip() {
    use rawlink::crypto;
    let psk = [0x55u8; 32];
    let sid = [1, 2, 3, 4, 5, 6, 7, 8];
    let keys = crypto::derive_keys(&sid, &psk);
    let aad = b"header";
    let ct = crypto::encrypt(&keys.c2s, 1, b"hello", aad).unwrap();
    let pt = crypto::decrypt(&keys.c2s, 1, &ct, aad).unwrap();
    assert_eq!(pt, b"hello");
}

#[test]
fn config_validation() {
    use rawlink::config::Config;
    let mut c = Config::default();
    assert!(c.validate().is_ok());
    c.mss = 0;
    assert!(c.validate().is_err(), "mss=0 must be rejected");
    c.mss = rawlink::config::DEFAULT_MTU;
    assert!(c.validate().is_err(), "mss larger than payload capacity must be rejected");
    c.mss = 1200;
    c.max_streams_per_session = 0;
    assert!(c.validate().is_err(), "zero stream cap must be rejected");
}

#[test]
fn session_alive_check() {
    let psk = [0x55u8; 32];
    let carrier = SimCarrier::clean();
    let session = Session::connect_pre_shared(carrier, psk, Config::default()).unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(session.is_alive());
    drop(session);
}

#[test]
fn backoff_doubles_until_cap() {
    use rawlink::client::next_backoff;
    let min = Duration::from_secs(1);
    let max = Duration::from_secs(30);
    let reset = Duration::from_secs(30);
    let want = [1u64, 2, 4, 8, 16, 30, 30, 30];
    let mut b = Duration::ZERO;
    for w in want {
        b = next_backoff(b, None, min, max, reset);
        assert_eq!(b, Duration::from_secs(w), "expected {w}s got {:?}", b);
    }
}

#[test]
fn backoff_resets_after_long_session() {
    use rawlink::client::next_backoff;
    let b = next_backoff(Duration::from_secs(30), Some(Duration::from_secs(60)),
        Duration::from_secs(1), Duration::from_secs(30), Duration::from_secs(30));
    assert_eq!(b, Duration::from_secs(1));
}
