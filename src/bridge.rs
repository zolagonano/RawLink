//! Bidirectional byte pump between a local TCP socket and a RawLink stream.
//!
//! One implementation shared by both proxy edges (the SOCKS5 client side and
//! the remote-dial server side) — the pump logic is symmetric:
//!
//! * **app → stream** (`s1`): read up to 16 KiB from the local socket,
//!   `Stream::write` it. `Stream::write` blocks when the stream's send
//!   buffer is full — this is the outermost backpressure edge of the
//!   whole system.
//! * **stream → app** (`s2`): blocking `Stream::read`; an empty `Vec` is the
//!   peer's FIN → half-close the local socket's write side (the local app
//!   may keep sending). `Err` = reset or session death → full stop.
//!
//! Half-close rule (protocol-critical): after `s2` sees the peer's FIN we do
//! NOT close the stream — the peer's FIN only closed its *send* side; the
//! local app may still have data to send (YELLOWPAPER §12.4, invariant I11).
//! The stream is closed on every other exit path so the session can reap it.
//!
//! Both pumps watch the session's shared `alive` flag with a 1 s socket read
//! timeout, so a dead session unblocks them within a second.
use crate::session::Stream;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Socket read timeout on the local socket — lets the app→stream pump
/// observe session death (alive flag) instead of blocking forever.
const READ_TIMEOUT: Duration = Duration::from_secs(1);
/// Read chunk for the app→stream pump. 64 KiB: big enough that one chunk
/// fills a max-size carrier packet on its own (fewer channel hops, fewer
/// frames, fewer splits than the old 16 KiB) while still giving the pump
/// fine-grained backpressure granularity against a fast app.
const CHUNK: usize = 65536;

/// Bridge `local` ↔ `stream` until either side closes (or the session dies).
///
/// Spawns the app→stream pump on its own thread and runs the stream→app
/// pump on the calling thread; returns when the stream→app pump exits (the
/// spawned pump exits on its own within ≤1 s afterwards).
pub fn run(local: TcpStream, stream: Arc<Stream>, alive: Arc<AtomicBool>) {
    // Nagle off on the app-facing edge: small writes (a SOCKS5 reply, the
    // tail of a response) must not wait for a delayed ACK against an
    // unacked small segment — that added up to 40 ms of tail latency per
    // connection on the proxy edge sockets.
    local.set_nodelay(true).ok();
    let mut local_read = local;
    let mut local_write = match local_read.try_clone() {
        Ok(w) => w,
        Err(_) => {
            let _ = stream.close();
            return;
        }
    };
    local_read.set_read_timeout(Some(READ_TIMEOUT)).ok();

    // app → stream pump (own thread).
    let pump_stream = Arc::clone(&stream);
    let pump_alive = Arc::clone(&alive);
    let spawned = thread::Builder::new()
        .name("rl-pump-app".into())
        .spawn(move || {
            let mut buf = [0u8; CHUNK];
            loop {
                if !pump_alive.load(Ordering::Relaxed) {
                    break;
                }
                match local_read.read(&mut buf) {
                    Ok(0) => break, // app closed its write side → our FIN
                    Ok(n) => {
                        if pump_stream.write(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let _ = pump_stream.close();
        });

    if let Err(e) = &spawned {
        // Could not start the app→stream pump — the bridge cannot work.
        log::debug!("bridge: spawn app pump failed: {e}");
        let _ = stream.close();
        return;
    }

    // stream → app pump (this thread).
    let mut wrote_all: u64 = 0;
    let mut peer_fin = false;
    loop {
        if !alive.load(Ordering::Relaxed) {
            break;
        }
        match stream.read() {
            Ok(b) if b.is_empty() => {
                peer_fin = true;
                break;
            }
            Ok(b) => {
                wrote_all += b.len() as u64;
                if local_write.write_all(&b).is_err() {
                    break;
                }
                let _ = local_write.flush();
            }
            Err(_) => break, // reset or session closed
        }
    }
    let _ = local_write.shutdown(Shutdown::Write);
    log::debug!("bridge done: peer_fin={} wrote={}B", peer_fin, wrote_all);
    if !peer_fin {
        // Local failure path (dead session, peer reset, app gone): close the
        // stream so the session can reclaim it. On peer_fin we keep it —
        // the local app may still be sending (half-close).
        let _ = stream.close();
    }
}
