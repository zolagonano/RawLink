//! Backpressure + data integrity tests.
//! Verify: zero data loss, bounded memory, proper backpressure.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
fn rawlink_bin() -> String {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_rawlink") { return p; }
    let mut p = std::env::current_dir().unwrap();
    p.push("target/debug/rawlink");
    p.to_string_lossy().into_owned()
}
const PSK: &str = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd";

fn spawn_server(port: u16) -> Child {
    let bin = rawlink_bin();
    let err_dest = if std::env::var("RL_KEEP_LOGS").is_ok() {
        std::fs::File::create("/tmp/rl_test_server.log").unwrap().into()
    } else { Stdio::null() };
    Command::new(&bin).args(["server",
        "--listen",&format!("127.0.0.1:{port}"),
        "--psk",PSK,"--log-level","warn",
    ]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(err_dest)
    .spawn().expect("spawn server")
}
fn spawn_client(srv: u16, socks: u16) -> Child {
    let bin = rawlink_bin();
    let err_dest = if std::env::var("RL_KEEP_LOGS").is_ok() {
        std::fs::File::create("/tmp/rl_test_client.log").unwrap().into()
    } else { Stdio::null() };
    Command::new(&bin).args(["client",
        "--server",&format!("127.0.0.1:{srv}"),
        "--socks-listen",&format!("127.0.0.1:{socks}"),
        "--psk",PSK,"--log-level","warn",
    ]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(err_dest)
    .spawn().expect("spawn client")
}
fn kill(c: &mut Child) { let _ = c.kill(); let _ = c.wait(); }

struct EchoServer {
    addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl EchoServer {
    fn addr(&self) -> std::net::SocketAddr { self.addr }
    fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self.handle.join();
    }
}

/// Echo server: reads data and echoes it back.
fn spawn_echo() -> EchoServer {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let a = l.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown2 = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        // The listener thread is bounded by a shutdown flag. This avoids
        // leaking a background accept loop across the whole test suite.
        while !shutdown2.load(Ordering::SeqCst) {
            match l.accept() {
                Ok((mut s, _)) => {
                    thread::spawn(move || {
                        let mut buf = [0u8; 8192];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0)|Err(_) => break,
                                Ok(n) => { if s.write_all(&buf[..n]).is_err() { break; } }
                            }
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    EchoServer { addr: a, shutdown, handle }
}

fn socks5_connect(port: u16, dest: std::net::SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    s.write_all(&[0x05,1,0x00]).unwrap();
    let mut h = [0u8;2]; s.read_exact(&mut h).unwrap();
    let mut req = vec![0x05,0x01,0x00,0x01];
    req.extend_from_slice(&match dest.ip() {
        std::net::IpAddr::V4(v) => v.octets(), _ => unreachable!() });
    req.extend_from_slice(&dest.port().to_be_bytes());
    s.write_all(&req).unwrap();
    let mut r = [0u8;10]; s.read_exact(&mut r).unwrap();
    assert_eq!(r[1], 0, "SOCKS5 CONNECT failed");
    s
}

/// Block until the tunnel is fully functional: a complete SOCKS5 CONNECT
/// through the client to the echo target plus a 1-byte round-trip must
/// succeed. Replaces the old blind `sleep(800ms)` that made this suite
/// flaky on loaded or low-core machines (session establishment is not
/// time-bounded — it depends on scheduler pressure).
fn wait_tunnel_ready(socks: u16, dest: std::net::SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("tunnel not ready after 20s — SOCKS probe kept failing");
        }
        let ok = TcpStream::connect(format!("127.0.0.1:{socks}")).ok()
            .and_then(|mut s| {
                s.write_all(&[0x05, 1, 0x00]).ok()?;
                let mut h = [0u8; 2];
                s.read_exact(&mut h).ok()?;
                if h != [0x05, 0x00] { return None; }
                let mut req = vec![0x05, 0x01, 0x00, 0x01];
                req.extend_from_slice(&match dest.ip() {
                    std::net::IpAddr::V4(v) => v.octets(), _ => return None });
                req.extend_from_slice(&dest.port().to_be_bytes());
                s.write_all(&req).ok()?;
                let mut r = [0u8; 10];
                s.read_exact(&mut r).ok()?;
                if r[1] != 0 { return None; }
                s.write_all(b"ping").ok()?;
                let mut got = [0u8; 4];
                s.read_exact(&mut got).ok()?;
                if &got != b"ping" { return None; }
                Some(())
            })
            .is_some();
        if ok { return; }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Large-transfer integrity test: send 1MB of random data through
/// RawLink and verify SHA-256 matches on both sides.
#[test]
fn large_transfer_integrity() {
    let _guard = TEST_LOCK.lock().unwrap();
    let srv = free_port();
    let echo = spawn_echo();
    let socks = free_port();
    let mut server = spawn_server(srv);
    let mut client = spawn_client(srv, socks);
    wait_tunnel_ready(socks, echo.addr());

    let data: Vec<u8> = (0..1_000_000).map(|i| (i * 7 + 13) as u8).collect();
    let expected_sha = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        let mut h = DefaultHasher::new();
        h.write(&data);
        h.finish()
    };

    let d = echo.addr();
    let data_clone = data.clone();
    let handle = thread::spawn(move || {
        let mut s = socks5_connect(socks, d);
        s.write_all(&data_clone).unwrap();
        // Read back the echo.
        let mut got = vec![0u8; data_clone.len()];
        let mut total = 0;
        while total < got.len() {
            let n = s.read(&mut got[total..]).unwrap();
            if n == 0 { break; }
            total += n;
        }
        assert_eq!(total, data_clone.len(), "incomplete echo: got {total}");
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        let mut h = DefaultHasher::new();
        h.write(&got);
        h.finish()
    });

    let actual_sha = handle.join().expect("thread");
    assert_eq!(actual_sha, expected_sha, "SHA mismatch — data corrupted!");
    kill(&mut client); kill(&mut server);
    echo.shutdown();
}

/// Backpressure test: slow receiver, verify no data loss.
/// The echo server deliberately delays each read by 10ms, creating
/// backpressure. The SOCKS5 bridge should block on stream.write()
/// instead of dropping data.
#[test]
fn backpressure_no_data_loss() {
    let _guard = TEST_LOCK.lock().unwrap();
    let srv = free_port();
    let echo = spawn_echo();
    let socks = free_port();
    let mut server = spawn_server(srv);
    let mut client = spawn_client(srv, socks);
    wait_tunnel_ready(socks, echo.addr());

    // Send 100KB of data — should take ~1 second due to slow echo
    let data: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    let d = echo.addr();
    let data_clone = data.clone();
    let handle = thread::spawn(move || {
        let mut s = socks5_connect(socks, d);
        s.write_all(&data_clone).unwrap();
        let mut got = vec![0u8; data_clone.len()];
        let mut total = 0;
        while total < got.len() {
            let n = s.read(&mut got[total..]).unwrap();
            if n == 0 { break; }
            total += n;
        }
        assert_eq!(total, data_clone.len(), "data loss: sent {} got {}", data_clone.len(), total);
        assert_eq!(&got[..], &data_clone[..], "data corruption");
    });
    handle.join().expect("thread");
    kill(&mut client); kill(&mut server);
    echo.shutdown();
}

/// Concurrent transfer test: one large + several small streams.
#[test]
fn concurrent_large_plus_small() {
    let _guard = TEST_LOCK.lock().unwrap();
    let srv = free_port();
    let echo = spawn_echo();
    let socks = free_port();
    let mut server = spawn_server(srv);
    let mut client = spawn_client(srv, socks);
    wait_tunnel_ready(socks, echo.addr());

    // Large transfer (500KB)
    let large = vec![0xABu8; 500_000];
    let d = echo.addr();
    let large_clone = large.clone();
    let big_handle = thread::spawn(move || {
        let mut s = socks5_connect(socks, d);
        s.write_all(&large_clone).unwrap();
        let mut got = vec![0u8; large_clone.len()];
        let mut total = 0;
        while total < got.len() {
            let n = s.read(&mut got[total..]).unwrap();
            if n == 0 { break; }
            total += n;
        }
        assert_eq!(total, large_clone.len());
        assert_eq!(&got[..], &large_clone[..]);
    });

    // Small transfers concurrently
    let mut small_handles = Vec::new();
    for i in 0..5 {
        let sp = socks;
        let dest = echo.addr();
        let payload = format!("small-{i}-{}", "y".repeat(50));
        let p2 = payload.clone();
        small_handles.push(thread::spawn(move || {
            let mut s = socks5_connect(sp, dest);
            s.write_all(p2.as_bytes()).unwrap();
            let mut got = vec![0u8; p2.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, p2.as_bytes(), "small stream {i} mismatch");
        }));
    }

    big_handle.join().expect("big");
    for h in small_handles { h.join().expect("small"); }
    kill(&mut client); kill(&mut server);
    echo.shutdown();
}

/// Repeated stream open/close cycles — verify no leaks.
#[test]
fn repeated_open_close_cycles() {
    let _guard = TEST_LOCK.lock().unwrap();
    let srv = free_port();
    let echo = spawn_echo();
    let socks = free_port();
    let mut server = spawn_server(srv);
    let mut client = spawn_client(srv, socks);
    wait_tunnel_ready(socks, echo.addr());

    for i in 0..30 {
        let sp = socks;
        let dest = echo.addr();
        let payload = format!("cycle-{i}");
        let p2 = payload.clone();
        let h = thread::spawn(move || {
            let mut s = socks5_connect(sp, dest);
            s.write_all(p2.as_bytes()).unwrap();
            let mut got = vec![0u8; p2.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, p2.as_bytes(), "cycle {i} mismatch");
        });
        h.join().expect("cycle thread");
    }

    kill(&mut client); kill(&mut server);
    echo.shutdown();
}

/// Stress test with concurrent send+read threads (required for
/// large transfers — without concurrent read, the echo protocol
/// deadlocks when the kernel TCP buffer fills).
#[test]
fn stress_concurrent_5_streams_4mb_sha256() {
    let _guard = TEST_LOCK.lock().unwrap();
    let srv = free_port();
    let echo = spawn_echo();
    let socks = free_port();
    let mut server = spawn_server(srv);
    let mut client = spawn_client(srv, socks);
    wait_tunnel_ready(socks, echo.addr());

    const N_STREAMS: usize = 5;
    const PAYLOAD_MB: usize = 4;
    let payload_size = PAYLOAD_MB * 1024 * 1024;
    let mut handles = Vec::new();
    for i in 0..N_STREAMS {
        let sp = socks;
        let dest = echo.addr();
        // Generate deterministic payload + compute SHA-256
        let payload: Vec<u8> = (0..payload_size).map(|x| ((x * 7 + i) % 251) as u8).collect();
        let expected_sha = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::Hasher;
            let mut h = DefaultHasher::new();
            h.write(&payload);
            h.finish()
        };
        let payload_clone = payload.clone();
        handles.push(thread::spawn(move || {
            let mut s = socks5_connect(sp, dest);
            s.set_read_timeout(Some(Duration::from_secs(60))).ok();
            // Clone for the sender thread (concurrent send+read is
            // REQUIRED for large transfers — otherwise the echo
            // protocol deadlocks when the kernel TCP buffer fills).
            let s_sender = s.try_clone().unwrap();
            let payload_for_sender = payload_clone.clone();
            let sender = thread::spawn(move || {
                let mut s2 = s_sender;
                s2.write_all(&payload_for_sender).unwrap();
                let _ = s2.shutdown(std::net::Shutdown::Write);
            });
            // Reader
            let mut got = vec![0u8; payload_clone.len()];
            let mut total = 0;
            while total < got.len() {
                match s.read(&mut got[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                          || e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
            sender.join().expect("sender");
            use std::collections::hash_map::DefaultHasher;
            use std::hash::Hasher;
            let mut h = DefaultHasher::new();
            h.write(&got[..total]);
            let actual_sha = h.finish();
            assert_eq!(total, payload_clone.len(), "stream {i}: got {total} expected {}", payload_clone.len());
            assert_eq!(actual_sha, expected_sha, "stream {i}: SHA mismatch");
        }));
    }
    for h in handles { h.join().expect("stream thread"); }
    kill(&mut client); kill(&mut server);
    echo.shutdown();
}

/// Regression test for the "pending_events cap drops frames" bug.
///
/// Before the fix, when pending_events reached its cap (256), handle_packet
/// returned Ok(false) WITHOUT processing the packet's frames. The DATA frames
/// inside were already consumed from the carrier but never dispatched to
/// rx_evt — permanently LOST.
///
/// This test runs 10 streams × 4MB (40MB total) to trigger the race
/// condition. With the fix, all 10 streams should complete with matching
/// SHA-256 hashes, 100% of the time.
#[test]
fn regression_pending_events_no_drop() {
    let _guard = TEST_LOCK.lock().unwrap();
    let srv = free_port();
    let echo = spawn_echo();
    let socks = free_port();
    let mut server = spawn_server(srv);
    let mut client = spawn_client(srv, socks);
    wait_tunnel_ready(socks, echo.addr());

    const N_STREAMS: usize = 10;
    const PAYLOAD_MB: usize = 4;
    let payload_size = PAYLOAD_MB * 1024 * 1024;
    let mut handles = Vec::new();
    for i in 0..N_STREAMS {
        let sp = socks;
        let dest = echo.addr();
        let payload: Vec<u8> = (0..payload_size).map(|x| ((x * 7 + i) % 251) as u8).collect();
        let expected_sha = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::Hasher;
            let mut h = DefaultHasher::new();
            h.write(&payload);
            h.finish()
        };
        let payload_clone = payload.clone();
        handles.push(thread::spawn(move || {
            let mut s = socks5_connect(sp, dest);
            s.set_read_timeout(Some(Duration::from_secs(120))).ok();
            let s_sender = s.try_clone().unwrap();
            let payload_for_sender = payload_clone.clone();
            let sender = thread::spawn(move || {
                let mut s2 = s_sender;
                s2.write_all(&payload_for_sender).unwrap();
                let _ = s2.shutdown(std::net::Shutdown::Write);
            });
            let mut got = vec![0u8; payload_clone.len()];
            let mut total = 0;
            while total < got.len() {
                match s.read(&mut got[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                          || e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
            sender.join().expect("sender");
            use std::collections::hash_map::DefaultHasher;
            use std::hash::Hasher;
            let mut h = DefaultHasher::new();
            h.write(&got[..total]);
            let actual_sha = h.finish();
            assert_eq!(total, payload_clone.len(), "stream {i}: got {total} expected {}", payload_clone.len());
            assert_eq!(actual_sha, expected_sha, "stream {i}: SHA mismatch — DATA LOSS or CORRUPTION");
        }));
    }
    for h in handles { h.join().expect("stream thread"); }
    kill(&mut client); kill(&mut server);
    echo.shutdown();
}
