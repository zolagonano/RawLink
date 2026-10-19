//! End-to-end obfuscation tests: a real RawLink session (client + server)
//! over loopback TCP with the obfuscation layer enabled, plus mode-mismatch
//! checks. Plain-mode behavior is covered by the pre-existing suites; this
//! file proves obfs is transparent to the session AND fails cleanly when
//! the two ends disagree.

use rawlink::carrier::{Carrier, TcpCarrier, TcpListenerCarrier};
use rawlink::config::Config;
use rawlink::obfs::ObfsConfig;
use rawlink::session::{Session, SessionId};
use std::io::Write as _;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const PSK: [u8; 32] = [0x5A; 32];

static LOG_INIT: std::sync::Once = std::sync::Once::new();
fn init_log() {
    LOG_INIT.call_once(|| {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .format_timestamp_millis()
                .try_init();
    });
}

fn obfs_cfg() -> ObfsConfig {
    ObfsConfig {
        padding_max: 48,
        dummy_min_ms: 60,
        dummy_max_ms: 120,
        dummy_size_max: 512,
    }
}

fn spawn_echoer(stream: rawlink::session::Stream) {
    // Echo everything back until FIN/reset/session death.
    thread::spawn(move || {
        loop {
            match stream.read() {
                Ok(b) if b.is_empty() => break, // peer FIN
                Ok(b) => {
                    if stream.write(&b).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

/// Server-side worker: accept one session (obfs or plain carrier), echo its
/// streams. The listener is pre-bound by the test thread (no bind race).
fn server_echo_worker(listener: TcpListenerCarrier, sid_rx: mpsc::Receiver<SessionId>) {
    let carrier = listener.accept().unwrap();
    let sid = sid_rx.recv().unwrap();
    let session = Session::accept_pre_shared(carrier, sid, PSK, Config::default()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        match session.accept_open_tcp() {
            Ok((stream, _open)) => {
                // Mirror the real server: answer the dial, then echo.
                let _ = stream.send_open_tcp_response(0x00, "");
                spawn_echoer(stream);
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("closed") {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn bind(use_obfs: bool) -> (TcpListenerCarrier, std::net::SocketAddr) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let listener = if use_obfs {
        TcpListenerCarrier::bind_obfs(addr, &PSK, &rawlink::ObfsMode::Rand(obfs_cfg())).unwrap()
    } else {
        TcpListenerCarrier::bind(addr, &PSK).unwrap()
    };
    (listener, addr)
}

#[test]
fn obfs_session_e2e_echo_4mb() {
    init_log();
    let (listener, addr) = bind(true);
    let (sid_tx, sid_rx) = mpsc::channel();
    let server = thread::spawn(move || server_echo_worker(listener, sid_rx));

    let sid = SessionId::generate();
    let carrier = TcpCarrier::connect_obfs(
        addr,
        &PSK,
        sid.as_bytes(),
        &rawlink::ObfsMode::Rand(obfs_cfg()),
    )
    .unwrap();
    let session =
        Session::connect_pre_shared_with_sid(carrier, PSK, Config::default(), sid).unwrap();
    sid_tx
        .send(SessionId::from_u64(session.session_id()))
        .unwrap();

    let st = session.open_stream().unwrap();
    st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    let resp = st.wait_for_open_tcp_response().unwrap();
    assert_eq!(resp.status, 0x00, "OPEN_TCP must succeed");

    // Ping-pong 16 x 256 KiB = 4 MiB, byte-exact.
    let chunk: Vec<u8> = (0..256 * 1024).map(|i| (i % 253) as u8).collect();
    for round in 0..16u32 {
        let mut seq = chunk.clone();
        seq[0] = round as u8;
        st.write(&seq).unwrap();
        let mut got = Vec::with_capacity(seq.len());
        let deadline = Instant::now() + Duration::from_secs(30);
        while got.len() < seq.len() {
            if Instant::now() > deadline {
                panic!("echo timeout round {round}: got {}", got.len());
            }
            match st.read() {
                Ok(b) if b.is_empty() => panic!("unexpected FIN round {round}"),
                Ok(b) => got.extend_from_slice(&b),
                Err(e) => panic!("read round {round}: {e}"),
            }
        }
        assert_eq!(got, seq, "echoed bytes must match (integrity through obfs)");
    }

    // Idle-cover check: no user traffic beyond a few dummy intervals —
    // the session must stay alive and aligned.
    thread::sleep(Duration::from_millis(500));
    assert!(
        session.is_alive(),
        "session must survive idle period with dummy traffic"
    );

    // Drop client-side handles FIRST so the server sees the session die
    // (a join before drop would deadlock until the server's 60s deadline).
    drop(st);
    drop(session);
    let _ = server.join();
}

#[test]
fn obfs_session_survives_idle_with_dummies() {
    let (listener, addr) = bind(true);
    let (sid_tx, sid_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let carrier = listener.accept().unwrap();
        let sid = sid_rx.recv().unwrap();
        let session = Session::accept_pre_shared(carrier, sid, PSK, Config::default()).unwrap();
        // 2s idle — dummies + session machinery only.
        thread::sleep(Duration::from_secs(2));
        session.is_alive()
    });
    let sid = SessionId::generate();
    let carrier = TcpCarrier::connect_obfs(
        addr,
        &PSK,
        sid.as_bytes(),
        &rawlink::ObfsMode::Rand(obfs_cfg()),
    )
    .unwrap();
    let session =
        Session::connect_pre_shared_with_sid(carrier, PSK, Config::default(), sid).unwrap();
    sid_tx
        .send(SessionId::from_u64(session.session_id()))
        .unwrap();
    thread::sleep(Duration::from_secs(2));
    assert!(
        session.is_alive(),
        "client session must survive 2s idle with dummies"
    );
    assert!(
        server.join().unwrap(),
        "server session must survive 2s idle with dummies"
    );
    drop(session);
}

#[test]
fn obfs_client_to_plain_server_fails_fast() {
    let (listener, addr) = bind(false);
    // Plain server: admission loop like the CLI (5s deadline), no obfs.
    let server = thread::spawn(move || {
        let carrier = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if Instant::now() >= deadline {
                return "admission-timeout";
            }
            match carrier.recv() {
                Ok(Some(b)) => match rawlink::session::verify_psk(&b.1, PSK) {
                    Ok(_) => return "authenticated (BAD: obfs leaked?)",
                    Err(_) => return "rejected-garbage",
                },
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(_) => return "carrier-error",
            }
        }
    });
    // Obfs client: the plain server never answers the obfs handshake
    // correctly → handshake must fail (bounded by its 10s deadline; in
    // practice it fails as soon as the server gives up or resets).
    let started = Instant::now();
    let sid2 = SessionId::generate();
    let outcome = TcpCarrier::connect_obfs(
        addr,
        &PSK,
        sid2.as_bytes(),
        &rawlink::ObfsMode::Rand(obfs_cfg()),
    );
    match outcome {
        Err(_) => { /* handshake-level rejection — expected */ }
        Ok(_carrier) => {
            // Only reachable if the plain server somehow answered with a
            // valid ServerHello — impossible without the key.
            panic!("obfs handshake must not succeed against a plain server");
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "failure must be bounded"
    );
    let verdict = server.join().unwrap();
    assert_ne!(verdict, "authenticated (BAD: obfs leaked?)");
}

#[test]
fn plain_client_to_obfs_server_gets_probe_response() {
    let (listener, addr) = bind(true);
    let server = thread::spawn(move || {
        // Accept must FAIL: the plain client cannot produce a valid hello.
        listener.accept().is_err()
    });
    // Plain client: sends a rawlink session handshake immediately.
    let sid = SessionId::generate();
    let carrier = TcpCarrier::connect(addr, &PSK, sid.as_bytes()).unwrap();
    let session = Session::connect_pre_shared_with_sid(carrier, PSK, Config::default(), sid);
    // Either the connect itself errors, or the session dies quickly when
    // the server closes after the failed obfs handshake.
    match session {
        Err(_) => {}
        Ok(s) => {
            let deadline = Instant::now() + Duration::from_secs(10);
            while s.is_alive() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                !s.is_alive(),
                "plain client must not establish against obfs server"
            );
        }
    }
    assert!(
        server.join().unwrap(),
        "obfs server must reject the plain client"
    );
}

#[test]
fn plain_session_still_works_regression() {
    // Proves the carrier refactor left the plain path fully functional.
    let (listener, addr) = bind(false);
    let (sid_tx, sid_rx) = mpsc::channel();
    let server = thread::spawn(move || server_echo_worker(listener, sid_rx));
    let sid = SessionId::generate();
    let carrier = TcpCarrier::connect(addr, &PSK, sid.as_bytes()).unwrap();
    let session =
        Session::connect_pre_shared_with_sid(carrier, PSK, Config::default(), sid).unwrap();
    sid_tx
        .send(SessionId::from_u64(session.session_id()))
        .unwrap();

    let st = session.open_stream().unwrap();
    st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    let resp = st.wait_for_open_tcp_response().unwrap();
    assert_eq!(resp.status, 0x00);
    st.write(b"plain-mode regression").unwrap();
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while got.len() < 21 {
        if Instant::now() > deadline {
            panic!("plain echo timeout");
        }
        match st.read() {
            Ok(b) if b.is_empty() => panic!("unexpected FIN"),
            Ok(b) => got.extend_from_slice(&b),
            Err(e) => panic!("read: {e}"),
        }
    }
    assert_eq!(got, b"plain-mode regression".to_vec());
    // Drop client-side handles first (see note in the 4MB test).
    drop(st);
    drop(session);
    let _ = server.join();
}

// ---------------------------------------------------------------------------
// SSH mimicry end-to-end (real TCP, real session, post-NEWKEYS early data)
// ---------------------------------------------------------------------------

fn ssh_cfg() -> rawlink::obfs_ssh::SshObfsConfig {
    rawlink::obfs_ssh::SshObfsConfig::default()
}

#[test]
fn ssh_mimicry_session_e2e_echo() {
    init_log();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let listener =
        TcpListenerCarrier::bind_obfs(addr, &PSK, &rawlink::ObfsMode::Ssh(ssh_cfg())).unwrap();
    let (sid_tx, sid_rx) = mpsc::channel();
    let _server = thread::spawn(move || server_echo_worker(listener, sid_rx));

    // SSH client with post-NEWKEYS early data: the RawLink hello is the
    // first "encrypted" packet after the emulated KEX.
    let (sid, early) = rawlink::session::build_first_packet(&PSK).unwrap();
    let carrier =
        TcpCarrier::connect_obfs_ssh_early(addr, &PSK, &ssh_cfg(), &early, sid.as_bytes()).unwrap();
    let session =
        Session::connect_pre_shared_preamble(carrier, PSK, Config::default(), sid).unwrap();
    sid_tx
        .send(SessionId::from_u64(session.session_id()))
        .unwrap();

    let st = session.open_stream().unwrap();
    st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    let resp = st.wait_for_open_tcp_response().unwrap();
    assert_eq!(
        resp.status, 0x00,
        "OPEN_TCP must succeed through the SSH layer"
    );

    // Echo 2 MiB through the emulated-SSH data phase, byte-exact.
    let chunk: Vec<u8> = (0..256 * 1024).map(|i| (i % 249) as u8).collect();
    for round in 0..8u32 {
        let mut seq = chunk.clone();
        seq[0] = round as u8;
        st.write(&seq).unwrap();
        let mut got = Vec::with_capacity(seq.len());
        let deadline = Instant::now() + Duration::from_secs(30);
        while got.len() < seq.len() {
            if Instant::now() > deadline {
                panic!("timeout at round {round}");
            }
            match st.read() {
                Ok(mut b) => {
                    got.append(&mut b);
                }
                Err(_) => thread::sleep(Duration::from_millis(2)),
            }
        }
        assert_eq!(got, seq, "round {round} echo mismatch through SSH layer");
    }
    assert!(session.is_alive());
    drop(st);
    drop(session);
}

/// Pull one SSH binary packet off `buf`; validates the framing invariants
/// a DPI (or a real sshd) would check.
fn ssh_next_packet(buf: &mut &[u8]) -> (u8, Vec<u8>) {
    let plen = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    assert!(
        (5..=35000).contains(&plen),
        "packet_length {plen} out of range"
    );
    assert_eq!((4 + plen) % 8, 0, "8-byte block alignment");
    let padlen = buf[4] as usize;
    assert!(padlen >= 4, "padding >= 4");
    assert!(padlen < plen, "padding fits in packet");
    let payload = buf[5..4 + plen - padlen].to_vec();
    let msg = payload[0];
    *buf = &buf[4 + plen..];
    (msg, payload)
}

fn shannon_entropy(b: &[u8]) -> f64 {
    let mut freq = [0usize; 256];
    for &x in b {
        freq[x as usize] += 1;
    }
    let n = b.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[test]
fn ssh_mimicry_wire_looks_like_ssh() {
    // Passive wire check with a tee: every pre-NEWKEYS byte in BOTH
    // directions must parse as a structurally valid OpenSSH handshake
    // (banner, KEXINIT, curve25519 DH, NEWKEYS with OpenSSH packet
    // sizes), and everything after NEWKEYS must be indistinguishable
    // from encrypted SSH (uniform random).
    init_log();
    use std::io::Read as _;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let listener =
        TcpListenerCarrier::bind_obfs(addr, &PSK, &rawlink::ObfsMode::Ssh(ssh_cfg())).unwrap();
    let (sid_tx, sid_rx) = mpsc::channel();
    let _server = thread::spawn(move || server_echo_worker(listener, sid_rx));

    // Tee proxy capturing both directions.
    let front = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let front_addr = front.local_addr().unwrap();
    let c2s: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
    let s2c: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
    let tee = {
        let c2s = c2s.clone();
        let s2c = s2c.clone();
        thread::spawn(move || {
            let (c, _) = front.accept().unwrap();
            let srv = std::net::TcpStream::connect(addr).unwrap();
            let (mut cr, mut cw) = (c.try_clone().unwrap(), c);
            let (mut sr, mut sw) = (srv.try_clone().unwrap(), srv);
            let h1 = {
                let c2s = c2s.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 16384];
                    loop {
                        match cr.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                c2s.lock().unwrap().extend_from_slice(&buf[..n]);
                                if sw.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                })
            };
            let h2 = {
                let s2c = s2c.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 16384];
                    loop {
                        match sr.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                s2c.lock().unwrap().extend_from_slice(&buf[..n]);
                                if cw.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                })
            };
            let _ = h1.join();
            let _ = h2.join();
        })
    };

    // Run a real session through the tee (with early data + bulk echo).
    let (sid, early) = rawlink::session::build_first_packet(&PSK).unwrap();
    let carrier =
        TcpCarrier::connect_obfs_ssh_early(front_addr, &PSK, &ssh_cfg(), &early, sid.as_bytes())
            .unwrap();
    let session =
        Session::connect_pre_shared_preamble(carrier, PSK, Config::default(), sid).unwrap();
    sid_tx
        .send(SessionId::from_u64(session.session_id()))
        .unwrap();
    let st = session.open_stream().unwrap();
    st.open_tcp(1, vec![127, 0, 0, 1], 80).unwrap();
    let _ = st.wait_for_open_tcp_response().unwrap();
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    for _ in 0..4 {
        st.write(&payload).unwrap();
        let mut got = 0;
        let deadline = Instant::now() + Duration::from_secs(30);
        while got < payload.len() {
            if Instant::now() > deadline {
                panic!("echo timeout");
            }
            match st.read() {
                Ok(b) => got += b.len(),
                Err(_) => thread::sleep(Duration::from_millis(2)),
            }
        }
    }
    drop(st);
    drop(session);
    let _ = tee.join();

    // ---- Dissect the captured client->server stream. ----
    let c2s = c2s.lock().unwrap().clone();
    let nl = c2s
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("banner CRLF");
    let banner = std::str::from_utf8(&c2s[..nl]).unwrap();
    assert!(
        banner.starts_with("SSH-2.0-OpenSSH"),
        "client banner: {banner}"
    );
    let mut buf = &c2s[nl + 2..];
    // KEXINIT
    let (msg, payload) = ssh_next_packet(&mut buf);
    assert_eq!(msg, 20, "client KEXINIT");
    {
        let mut p = &payload[1..];
        let _cookie = &p[..16];
        p = &p[16..];
        let mut lists = Vec::new();
        for i in 0..10 {
            let l = u32::from_be_bytes(p[..4].try_into().unwrap()) as usize;
            p = &p[4..];
            let list = std::str::from_utf8(&p[..l]).unwrap();
            p = &p[l..];
            if i < 6 {
                assert!(!list.is_empty(), "name-list {i} must be non-empty");
            }
            lists.push(list.to_string());
        }
        assert!(
            lists[0].contains("curve25519-sha256"),
            "kex list: {}",
            lists[0]
        );
        assert_eq!(p[0], 0, "first_kex_packet_follows = false");
        assert_eq!(&p[1..5], &[0, 0, 0, 0], "reserved = 0");
    }
    // DH_INIT: exactly 48 bytes on the wire, string of 32.
    let before = buf.len();
    let (msg, payload) = ssh_next_packet(&mut buf);
    assert_eq!(msg, 30, "DH_INIT");
    assert_eq!(before - buf.len(), 48, "OpenSSH DH_INIT wire size");
    assert_eq!(payload.len(), 37);
    assert_eq!(u32::from_be_bytes(payload[1..5].try_into().unwrap()), 32);
    // NEWKEYS: 16 bytes on the wire.
    let before = buf.len();
    let (msg, payload) = ssh_next_packet(&mut buf);
    assert_eq!(msg, 21, "NEWKEYS");
    assert_eq!(before - buf.len(), 16, "OpenSSH NEWKEYS wire size");
    assert_eq!(payload.len(), 1);
    // Post-NEWKEYS: encrypted SSH = uniform random. (The rand-mode codec
    // emits masked frames — XChaCha20 keystream over everything.)
    assert!(
        buf.len() > 32 * 1024,
        "need bulk bytes for entropy, got {}",
        buf.len()
    );
    for i in (0..buf.len() - 512).step_by(4096) {
        assert!(
            shannon_entropy(&buf[i..i + 512]) > 7.0,
            "post-NEWKEYS window at {i} must look encrypted"
        );
    }

    // ---- Dissect the captured server->client stream. ----
    let s2c = s2c.lock().unwrap().clone();
    let nl = s2c
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("banner CRLF");
    let banner = std::str::from_utf8(&s2c[..nl]).unwrap();
    assert!(
        banner.starts_with("SSH-2.0-OpenSSH"),
        "server banner: {banner}"
    );
    let mut buf = &s2c[nl + 2..];
    let (msg, payload) = ssh_next_packet(&mut buf);
    assert_eq!(msg, 20, "server KEXINIT");
    assert!(
        payload.len() > 400 && payload.len() < 1100,
        "server kexinit size class"
    );
    // DH_REPLY: parse K_S / f / sig strings.
    let before = buf.len();
    let (msg, payload) = ssh_next_packet(&mut buf);
    assert_eq!(msg, 31, "DH_REPLY");
    assert_eq!(
        before - buf.len(),
        192,
        "OpenSSH DH_REPLY wire size (ed25519 hostkey)"
    );
    let mut p = &payload[1..];
    let take_str = |p: &mut &[u8]| -> Vec<u8> {
        let l = u32::from_be_bytes(p[..4].try_into().unwrap()) as usize;
        let s = p[4..4 + l].to_vec();
        *p = &p[4 + l..];
        s
    };
    let k_s = take_str(&mut p);
    assert_eq!(k_s.len(), 51, "ssh-ed25519 hostkey blob size");
    assert_eq!(
        &k_s[..15],
        b"\x00\x00\x00\x0bssh-ed25519",
        "hostkey algorithm"
    );
    let f = take_str(&mut p);
    assert_eq!(f.len(), 32, "server f");
    let sig = take_str(&mut p);
    assert_eq!(sig.len(), 83, "ed25519 signature blob size");
    assert!(p.is_empty(), "no trailing bytes");
    // NEWKEYS from server.
    let (msg, payload) = ssh_next_packet(&mut buf);
    assert_eq!(msg, 21, "server NEWKEYS");
    assert_eq!(payload.len(), 1);
    // Post-NEWKEYS: encrypted.
    assert!(
        buf.len() > 32 * 1024,
        "need bulk s2c bytes, got {}",
        buf.len()
    );
    for i in (0..buf.len() - 512).step_by(4096) {
        assert!(
            shannon_entropy(&buf[i..i + 512]) > 7.0,
            "s2c post-NEWKEYS window at {i} must look encrypted"
        );
    }
}

#[test]
fn ssh_probe_garbage_gets_sshd_like_response() {
    // A scanner that connects and sends garbage must see, FIRST, an
    // ordinary sshd: banner + KEXINIT arrive before the server has read
    // anything; the connection is then closed quietly (sshd's bad-
    // identification path). No protocol-specific bytes are leaked.
    init_log();
    use std::io::Read as _;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let listener =
        TcpListenerCarrier::bind_obfs(addr, &PSK, &rawlink::ObfsMode::Ssh(ssh_cfg())).unwrap();
    let server = thread::spawn(move || listener.accept().is_err());

    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 4096];
    let mut got = 0usize;
    while got < 256 {
        let n = s
            .read(&mut buf[got..])
            .expect("banner+kexinit must precede any read");
        assert!(n > 0, "server must keep sending banner+KEXINIT");
        got += n;
    }
    assert!(got > 256, "banner + KEXINIT, got {got} bytes");
    let nl = buf[..got]
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("banner CRLF");
    assert!(
        std::str::from_utf8(&buf[..nl])
            .unwrap()
            .starts_with("SSH-2.0-OpenSSH")
    );
    let plen = u32::from_be_bytes(buf[nl + 2..nl + 6].try_into().unwrap()) as usize;
    assert_eq!(buf[nl + 7], 20, "KEXINIT message type"); // after u32 len + u8 padlen
    let _ = plen;
    // Now send garbage identification and close.
    let _ = s.write_all(&[0xA7; 64]);
    let _ = s.shutdown(std::net::Shutdown::Write);
    assert!(
        server.join().expect("server thread"),
        "ssh server must reject garbage"
    );
}

#[test]
fn ssh_client_to_rand_server_fails_fast() {
    let (listener, addr) = bind(true); // rand-mode listener
    let server = thread::spawn(move || listener.accept().is_err());
    let started = Instant::now();
    let (sid, early) = rawlink::session::build_first_packet(&PSK).unwrap();
    let out = TcpCarrier::connect_obfs_ssh_early(addr, &PSK, &ssh_cfg(), &early, sid.as_bytes());
    assert!(
        out.is_err(),
        "ssh client must not establish against a rand server"
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "failure must be bounded"
    );
    assert!(
        server.join().unwrap(),
        "rand server must reject the ssh client"
    );
}
