//! SOCKS5 front-end for a RawLink tunnel set (client side).
//!
//! Implements the RFC 1928 subset RawLink ships with: method `0x00`
//! (NO-AUTH) only, command `0x01` CONNECT only, and the three address forms
//! (IPv4 / IPv6 / domain), which map 1:1 onto the protocol's `OPEN_TCP`
//! address sub-format (YELLOWPAPER §12). Each SOCKS5 connection becomes
//! exactly one RawLink stream: `open_stream()` → `OPEN_TCP` → await
//! `OPEN_TCP_RESPONSE` → reply → [`bridge::run`].
use crate::bridge;
use crate::client::TunnelManager;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// Timeout for the SOCKS5 greeting/request exchange. A connection that
/// connects but never completes the handshake (port scanner, health probe,
/// half-open TCP) must not park a thread and its two fds forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Write timeout for the client-facing socket (a dead client that stopped
/// reading must not park the bridge).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a request waits for a live tunnel (covers the reconnect window:
/// brief outages are invisible to applications; only a genuinely unreachable
/// server fails the caller).
const TUNNEL_WAIT: Duration = Duration::from_secs(5);

/// A parsed SOCKS5 CONNECT request, in OPEN_TCP wire form.
pub struct Socks5Request {
    pub atyp: u8,
    pub addr: Vec<u8>,
    pub port: u16,
}

/// Send a SOCKS5 reply with the given status byte. BND.ADDR is all-zero —
/// legal per RFC 1928 when the server does not bind a local address.
pub fn reply(out: &mut TcpStream, status: u8) -> std::io::Result<()> {
    out.write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

/// Read the SOCKS5 greeting + CONNECT request from `io`. Sends the proper
/// error reply bytes on protocol violations and returns `Err` only on
/// transport-level failures; a served error reply yields `Ok(None)` —
/// the connection is finished, do not bridge.
fn handshake(io: &mut TcpStream) -> std::io::Result<Option<Socks5Request>> {
    io.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    io.set_write_timeout(Some(WRITE_TIMEOUT))?;
    // A clone for replies: reads and writes may interleave during parsing.
    let mut out = io.try_clone()?;

    // Greeting: VER NMETHODS METHODS…
    let mut hdr = [0u8; 2];
    io.read_exact(&mut hdr)?;
    if hdr[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    io.read_exact(&mut methods)?;
    if !methods.contains(&0x00) {
        out.write_all(&[0x05, 0xFF])?;
        return Ok(None);
    }
    out.write_all(&[0x05, 0x00])?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    io.read_exact(&mut req)?;
    if req[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    if req[1] != 0x01 {
        // only CONNECT
        reply(&mut out, 0x07)?;
        return Ok(None);
    }
    let atyp = req[3];
    let addr = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            io.read_exact(&mut a)?;
            a.to_vec()
        }
        0x04 => {
            let mut a = [0u8; 16];
            io.read_exact(&mut a)?;
            a.to_vec()
        }
        0x03 => {
            let mut l = [0u8; 1];
            io.read_exact(&mut l)?;
            let mut buf = vec![0u8; l[0] as usize];
            io.read_exact(&mut buf)?;
            let mut a = vec![l[0]];
            a.extend_from_slice(&buf);
            a
        }
        _ => {
            reply(&mut out, 0x08)?;
            return Ok(None);
        }
    };
    let mut pb = [0u8; 2];
    io.read_exact(&mut pb)?;
    let port = u16::from_be_bytes(pb);
    Ok(Some(Socks5Request { atyp, addr, port }))
}

/// Serve one accepted SOCKS5 connection end-to-end against the tunnel set:
/// handshake → open a stream on the least-loaded tunnel → remote-dial RPC →
/// SOCKS5 reply → bridge. Blocks until the connection is done.
pub fn serve_connection(mut io: TcpStream, manager: &TunnelManager) {
    // Nagle off from the first byte we write on this socket (the SOCKS5
    // CONNECT reply is 10 bytes — exactly the kind of small write that
    // otherwise waits on a delayed ACK and adds ~40 ms to every
    // connection setup).
    io.set_nodelay(true).ok();
    let req = match handshake(&mut io) {
        Ok(Some(r)) => r,
        Ok(None) => return, // handshake served an error reply
        Err(e) => {
            log::debug!("socks5 handshake: {e}");
            return;
        }
    };
    log::info!("SOCKS5 CONNECT (atyp={}, port={})", req.atyp, req.port);

    let (session, stream) = match manager.open_stream(TUNNEL_WAIT) {
        Ok(x) => x,
        Err(e) => {
            log::warn!("socks5: no tunnel available: {e}");
            let mut out = io.try_clone().ok();
            if let Some(o) = out.as_mut() {
                let _ = reply(o, 0x01);
            }
            return;
        }
    };
    let stream = Arc::new(stream);

    // Remote-dial RPC (OPEN_TCP → OPEN_TCP_RESPONSE, 30 s hard timeout
    // inside the session library). The server's status byte maps 1:1 onto
    // the SOCKS5 reply code.
    if let Err(e) = stream.open_tcp(req.atyp, req.addr.clone(), req.port) {
        log::warn!("socks5: open_tcp: {e}");
        let _ = stream.close();
        let mut out = io.try_clone().ok();
        if let Some(o) = out.as_mut() {
            let _ = reply(o, 0x01);
        }
        return;
    }
    match stream.wait_for_open_tcp_response() {
        Ok(resp) if resp.status == 0 => {}
        Ok(resp) => {
            log::warn!(
                "socks5: dial failed: status={} reason={}",
                resp.status,
                resp.reason
            );
            let _ = stream.close();
            let mut out = io.try_clone().ok();
            if let Some(o) = out.as_mut() {
                let _ = reply(o, resp.status);
            }
            return;
        }
        Err(e) => {
            log::warn!("socks5: dial response: {e}");
            let _ = stream.close();
            let mut out = io.try_clone().ok();
            if let Some(o) = out.as_mut() {
                let _ = reply(o, 0x01);
            }
            return;
        }
    }

    let mut out = io.try_clone().ok();
    let ok = out
        .as_mut()
        .map(|o| reply(o, 0x00).is_ok())
        .unwrap_or(false);
    if !ok {
        let _ = stream.close();
        return;
    }

    bridge::run(io, stream, session.alive_flag());
}
