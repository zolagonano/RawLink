//! SSH transport-mimicry obfuscation layer.
//!
//! Makes a RawLink tunnel look, byte for byte, like an ordinary OpenSSH
//! session.
//!
//! What a censor sees on the wire:
//!
//! ```text
//! C→S: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"   (banner)
//! S→C: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"   (sent on accept,
//!       KEXINIT binary packet                                 sshd-style)
//! C→S: KEXINIT binary packet
//! C→S: SSH_MSG_KEX_DH_INIT (48 B — curve25519 public key)
//! S→C: SSH_MSG_KEX_DH_REPLY (~192 B — host key, f, signature)
//!       SSH_MSG_NEWKEYS (16 B)
//! C→S: SSH_MSG_NEWKEYS (16 B)
//!   ... everything past NEWKEYS is encrypted SSH: uniform random bytes ...
//! ```
//!
//! The emulation is faithful down to the padding rules (8-byte block
//! alignment, >=4 random padding bytes, 16-byte minimum packets), so a
//! DPI running a full RFC 4251/4253 state machine parses every pre-NEWKEYS
//! byte. After NEWKEYS the real SSH record layer encrypts the length
//! field itself, so a censor cannot parse the remainder of ANY SSH
//! session — and our data phase is the same masked + AEAD stream the
//! `rand` mode produces, i.e. uniform random bytes. Encrypted SSH and our
//! tunnel are indistinguishable from each other by construction.
//!
//! Crypto / anti-replay:
//! * The SSH-layer handshake carries NO credential (banners, algorithm
//!   lists and host-key bytes are PSK-independent or PSK-derived public
//!   material — a replayed handshake byte-stream re-derives the same
//!   stream keys only if the SERVER replays its `f`, which it never does:
//!   `f` is fresh random per connection, so a captured ClientHello/DH_INIT
//!   replay produces different inner keys and the inner RawLink AEAD fails
//!   in admission, exactly like the rand mode).
//! * The client's RawLink hello packet rides the post-NEWKEYS flight
//!   ("early data"): the session completes in the SSH round trips, one
//!   RTT after the KEX — the earliest point a real SSH client could send
//!   its first data packet.
//! * Authentication is the RawLink AEAD itself (`server::` admission +
//!   the uniform [4,5)s failure close) — identical behavior to the rand
//!   mode, no new timing surface.
//!
//! Probe behavior (a probe is any connection whose SSH-layer structure
//! does not validate):
//! * The server writes its banner + KEXINIT IMMEDIATELY on accept, before
//!   reading anything — exactly what sshd does. A scanner that connects
//!   and reads sees an OpenSSH server.
//! * A garbage identification line gets a silent close (sshd's "bad
//!   protocol version identification" path); a structurally valid
//!   handshake whose inner key material is wrong completes the SSH
//!   theater and is closed by the uniform admission delay.

use crate::error::Error;
use crate::obfs::{self, DirectionKeys, ObfsConfig, ObfReadHalf, ObfWriteHalf};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The obfs handshakes run with their own deadline, independent of the
/// session's carrier poll cadence (mirrors `obfs::HANDSHAKE_TIMEOUT`).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// RFC 4253 §4.2: identification string is at most 255 bytes incl. CRLF.
const MAX_BANNER_BYTES: usize = 255;
/// Largest binary packet we accept pre-NEWKEYS. Real KEXINIT is ~1.5 KiB;
/// OpenSSH's own limit is 256 KiB but every handshake packet is far below
/// this bound — anything larger is a probe.
const MAX_PACKET_BYTES: usize = 35000;
/// Unencrypted-phase cipher block size (RFC 4253 §6): packets are padded
/// so that `(4 + packet_length) % 8 == 0`.
const SSH_BLOCK: usize = 8;
/// Minimum random padding per binary packet (RFC 4253 §6).
const MIN_PAD: usize = 4;

const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_DH_INIT: u8 = 30;
const MSG_KEX_DH_REPLY: u8 = 31;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tunables for the SSH mimicry layer.
#[derive(Debug, Clone)]
pub struct SshObfsConfig {
    /// The SSH identification string BOTH ends present (without CRLF).
    /// Must look like an ordinary deployment — the default matches the
    /// most common Ubuntu 24.04 sshd build in the wild. Operators may
    /// override per endpoint (the two ends do not need to agree).
    pub banner: String,
    /// Max random padding appended to every inner masked frame (0..=127),
    /// identical to the rand mode's `padding_max`.
    pub padding_max: u8,
}

impl Default for SshObfsConfig {
    fn default() -> Self {
        Self {
            banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5".into(),
            padding_max: 64,
        }
    }
}

impl SshObfsConfig {
    pub fn validate(&self) -> Result<(), Error> {
        let b = self.banner.as_bytes();
        if b.len() < 8 + 1 || b.len() + 2 > MAX_BANNER_BYTES {
            return Err(Error::Malformed("obfs-ssh: banner length out of range".into()));
        }
        if !self.banner.starts_with("SSH-2.0-") {
            return Err(Error::Malformed("obfs-ssh: banner must start with 'SSH-2.0-'".into()));
        }
        if !b.iter().all(|&c| (0x21..=0x7e).contains(&c) || c == b' ') {
            return Err(Error::Malformed("obfs-ssh: banner must be printable ASCII".into()));
        }
        if self.padding_max as usize > 127 {
            return Err(Error::Malformed("obfs-ssh: padding_max > 127".into()));
        }
        Ok(())
    }
}

/// The inner codec config (rand-mode machinery) for the data phase.
/// Dummies are intentionally OFF for SSH: a real idle SSH session is
/// near-silent, and RawLink's own jittered PING/PONG keepalives already
/// provide liveness with ordinary small-encrypted-packet shapes.
fn inner_cfg(cfg: &SshObfsConfig) -> ObfsConfig {
    ObfsConfig {
        padding_max: cfg.padding_max,
        dummy_min_ms: 700,
        dummy_max_ms: 700,
        dummy_size_max: 0, // disabled — see doc comment
    }
}

// ---------------------------------------------------------------------------
// Key derivation (domain-separated from the rand mode)
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

fn ssh_prk(psk: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk).expect("hmac");
    mac.update(b"rawlink-obfs-ssh-v1/salt");
    let out = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&out);
    prk
}

fn expand(prk: &[u8; 32], label: &[u8], len: usize) -> Vec<u8> {
    let h = Hkdf::<Sha256>::from_prk(prk).expect("hkdf");
    let mut okm = vec![0u8; len];
    h.expand(label, &mut okm).expect("expand");
    okm
}

/// Stream keys for the data phase, bound to BOTH handshake randoms. `q_c`
/// is the client's DH_INIT public-key field and `f` the server's DH_REPLY
/// public-key field — both fresh per connection, so a replayed handshake
/// (same `q_c`) still derives different keys because the server's `f` is
/// never replayed.
fn derive_stream_keys(prk: &[u8; 32], q_c: &[u8; 32], f: &[u8; 32])
    -> (DirectionKeys, DirectionKeys)
{
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("hmac");
    mac.update(b"rawlink-obfs-ssh-v1/ks");
    mac.update(q_c);
    mac.update(f);
    let mut kp = [0u8; 32];
    kp.copy_from_slice(&mac.finalize().into_bytes());
    let mut ck = [0u8; 32]; ck.copy_from_slice(&expand(&kp, b"rawlink-obfs-ssh-v1 c2s key", 32));
    let mut cn = [0u8; 24]; cn.copy_from_slice(&expand(&kp, b"rawlink-obfs-ssh-v1 c2s nonce", 24));
    let mut sk = [0u8; 32]; sk.copy_from_slice(&expand(&kp, b"rawlink-obfs-ssh-v1 s2c key", 32));
    let mut sn = [0u8; 24]; sn.copy_from_slice(&expand(&kp, b"rawlink-obfs-ssh-v1 s2c nonce", 24));
    (DirectionKeys { key: ck, nonce: cn }, DirectionKeys { key: sk, nonce: sn })
}

/// The "host key" the server presents in DH_REPLY: 32 bytes derived
/// deterministically from the PSK so it is STABLE across connections and
/// restarts (a censor correlating host keys across sessions sees one
/// long-lived key, like a real sshd). Shaped as an ssh-ed25519 public key
/// (RFC 8652 field sizes) but not a curve point — see the limitations
/// note in OBFUSCATION.md.
fn hostkey_bytes(prk: &[u8; 32]) -> [u8; 32] {
    let k = expand(prk, b"rawlink-obfs-ssh-v1 hostkey", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&k);
    out
}

/// A "signature" for DH_REPLY: 64 bytes keyed by the handshake randoms —
/// deterministic for the pair (so both ends of a connection agree on the
/// bytes they emit/parse), random-looking to anyone without the PSK.
/// No one can verify an SSH signature without the DH secret, so the
/// value only needs the right shape.
fn signature_bytes(prk: &[u8; 32], q_c: &[u8; 32], f: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("hmac");
    mac.update(b"rawlink-obfs-ssh-v1/sig");
    mac.update(q_c);
    mac.update(f);
    out[..32].copy_from_slice(&mac.finalize().into_bytes());
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("hmac");
    mac.update(b"rawlink-obfs-ssh-v1/sig2");
    mac.update(q_c);
    mac.update(f);
    out[32..].copy_from_slice(&mac.finalize().into_bytes());
    out
}

// ---------------------------------------------------------------------------
// SSH binary packet + message builders
// ---------------------------------------------------------------------------

/// OpenSSH 9.6 (Ubuntu) default CLIENT proposal. `ext-info-c` is the
/// RFC 8308 extension-negotiation marker and `kex-strict-c-v00@openssh.com`
/// the Terrapin strict-KEX marker — every OpenSSH >= 9.6 client appends
/// both to its kex list.
const KEX_C: &str = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com";
const HOSTKEY_C: &str = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256";
/// sshd's shorter server-side proposal (Ubuntu defaults) with the
/// Terrapin strict-KEX marker every >= 9.6 server appends.
const KEX_S: &str = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com";
const HOSTKEY_S: &str = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519";
const CIPHERS: &str = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com";
const MACS_C: &str = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1";
const MACS_S: &str = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1";
const COMPRESS_C: &str = "none,zlib@openssh.com,zlib";
const COMPRESS_S: &str = "none,zlib@openssh.com";

fn push_name_list(out: &mut Vec<u8>, names: &str) {
    out.extend_from_slice(&(names.len() as u32).to_be_bytes());
    out.extend_from_slice(names.as_bytes());
}

/// Build a KEXINIT payload (RFC 4253 §7.1). `is_client` selects the
/// client/server proposal shape (clients offer the long compat lists,
/// servers the short set they actually support).
fn kexinit_payload(is_client: bool) -> Vec<u8> {
    let (kex, hostkey, macs, compress) = if is_client {
        (KEX_C, HOSTKEY_C, MACS_C, COMPRESS_C)
    } else {
        (KEX_S, HOSTKEY_S, MACS_S, COMPRESS_S)
    };
    let mut p = Vec::with_capacity(1 + 16 + 10 * (4 + 80));
    p.push(MSG_KEXINIT);
    let mut cookie = [0u8; 16];
    rand::rng().fill_bytes(&mut cookie);
    p.extend_from_slice(&cookie);
    push_name_list(&mut p, kex);
    push_name_list(&mut p, hostkey);
    push_name_list(&mut p, CIPHERS);
    push_name_list(&mut p, CIPHERS);
    push_name_list(&mut p, macs);
    push_name_list(&mut p, macs);
    push_name_list(&mut p, compress);
    push_name_list(&mut p, compress);
    push_name_list(&mut p, ""); // languages c2s
    push_name_list(&mut p, ""); // languages s2c
    p.push(0);                  // first_kex_packet_follows = false
    p.extend_from_slice(&0u32.to_be_bytes()); // reserved
    p
}

/// Frame `payload` into an unencrypted SSH binary packet (RFC 4253 §6):
/// `[u32 BE packet_length][u8 padding_length][payload][random padding]`
/// with `(4 + packet_length) % 8 == 0`, padding >= 4, total >= 16.
fn wrap_packet(payload: &[u8]) -> Vec<u8> {
    let body = 1 + payload.len();
    let mut pad = SSH_BLOCK - ((4 + body) % SSH_BLOCK);
    if pad < MIN_PAD { pad += SSH_BLOCK; }
    while 4 + body + pad < 16 { pad += SSH_BLOCK; }
    debug_assert!((MIN_PAD..=255).contains(&pad));
    let plen = (body + pad) as u32;
    let mut out = Vec::with_capacity(4 + body + pad);
    out.extend_from_slice(&plen.to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    let at = out.len();
    out.resize(at + pad, 0);
    rand::rng().fill_bytes(&mut out[at..]);
    out
}

fn banner_line(cfg: &SshObfsConfig) -> Vec<u8> {
    let mut v = Vec::with_capacity(cfg.banner.len() + 2);
    v.extend_from_slice(cfg.banner.as_bytes());
    v.extend_from_slice(b"\r\n");
    v
}

/// SSH_MSG_KEX_DH_INIT for curve25519-sha256 (RFC 8731 §4): `byte 30,
/// string q_c` where q_c is the 32-byte "public key". Ours is the
/// client's fresh handshake random.
fn dh_init_payload(q_c: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + 4 + 32);
    p.push(MSG_KEX_DH_INIT);
    p.extend_from_slice(&32u32.to_be_bytes());
    p.extend_from_slice(q_c);
    p
}

/// SSH_MSG_KEX_DH_REPLY: `byte 31, string K_S, string f, string sig`.
/// K_S is an ssh-ed25519-shaped blob around the PSK-stable hostkey bytes;
/// `f` is the server's fresh random; `sig` is an ssh-ed25519-shaped
/// signature blob (algorithm name + 64 keyed-random bytes).
fn dh_reply_payload(prk: &[u8; 32], q_c: &[u8; 32], f: &[u8; 32]) -> Vec<u8> {
    let hk = hostkey_bytes(prk);
    let sig = signature_bytes(prk, q_c, f);
    let mut k_s = Vec::with_capacity(4 + 11 + 4 + 32);
    push_name_list(&mut k_s, "ssh-ed25519");
    k_s.extend_from_slice(&32u32.to_be_bytes());
    k_s.extend_from_slice(&hk);
    let mut sig_blob = Vec::with_capacity(4 + 11 + 4 + 64);
    push_name_list(&mut sig_blob, "ssh-ed25519");
    sig_blob.extend_from_slice(&64u32.to_be_bytes());
    sig_blob.extend_from_slice(&sig);
    let mut p = Vec::with_capacity(1 + (4 + 51) + (4 + 32) + (4 + 83));
    p.push(MSG_KEX_DH_REPLY);
    p.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
    p.extend_from_slice(&k_s);
    p.extend_from_slice(&32u32.to_be_bytes());
    p.extend_from_slice(f);
    p.extend_from_slice(&(sig_blob.len() as u32).to_be_bytes());
    p.extend_from_slice(&sig_blob);
    p
}

fn newkeys_packet() -> Vec<u8> {
    wrap_packet(&[MSG_NEWKEYS])
}

// ---------------------------------------------------------------------------
// SSH parsers (strict — they double as probe triage)
// ---------------------------------------------------------------------------

fn io_err(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Carrier(crate::error::CarrierError::new("obfs-ssh", op, format!("{e}")))
}

/// Read one identification line. Accepts SSH-2.0- and SSH-1.99- prefixed
/// lines (what sshd accepts); anything else is an error. Reads
/// byte-by-byte until LF (banners are one line, ~40 bytes).
fn read_banner(stream: &mut TcpStream) -> Result<(), Error> {
    let mut line = Vec::with_capacity(64);
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).map_err(io_err("read banner"))?;
        if b[0] == b'\n' {
            let t = line.strip_suffix(b"\r").unwrap_or(&line);
            let ok = (t.starts_with(b"SSH-2.0-") || t.starts_with(b"SSH-1.99-"))
                && !t.is_empty();
            if !ok {
                return Err(Error::Auth("obfs-ssh: bad peer identification string".into()));
            }
            return Ok(());
        }
        line.push(b[0]);
        if line.len() >= MAX_BANNER_BYTES {
            return Err(Error::Auth("obfs-ssh: peer banner overlong".into()));
        }
    }
}

/// Read one unencrypted binary packet, return its payload (padding
/// stripped). Enforces the bounds a real sshd would (max packet, sane
/// padding, positive length).
fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let mut lhdr = [0u8; 4];
    stream.read_exact(&mut lhdr).map_err(io_err("read pkt len"))?;
    let plen = u32::from_be_bytes(lhdr) as usize;
    if !(1 + MIN_PAD..=MAX_PACKET_BYTES).contains(&plen) {
        return Err(Error::Malformed("obfs-ssh: bad packet length".into()));
    }
    let mut body = vec![0u8; plen];
    stream.read_exact(&mut body).map_err(io_err("read pkt body"))?;
    let padlen = body[0] as usize;
    if padlen < MIN_PAD || 1 + padlen > plen {
        return Err(Error::Malformed("obfs-ssh: bad padding length".into()));
    }
    let payload = body[1..plen - padlen].to_vec();
    if payload.is_empty() {
        return Err(Error::Malformed("obfs-ssh: empty payload".into()));
    }
    Ok(payload)
}

fn expect_msg_type(payload: &[u8], want: u8, what: &'static str) -> Result<(), Error> {
    if payload[0] != want {
        return Err(Error::Malformed(format!(
            "obfs-ssh: expected msg type {want} ({what}), got {}", payload[0])));
    }
    Ok(())
}

/// Extract the 32-byte q_c from a structurally valid DH_INIT payload.
fn parse_dh_init(p: &[u8]) -> Result<[u8; 32], Error> {
    expect_msg_type(p, MSG_KEX_DH_INIT, "DH_INIT")?;
    if p.len() != 1 + 4 + 32 {
        return Err(Error::Malformed("obfs-ssh: DH_INIT size mismatch".into()));
    }
    let ql = u32::from_be_bytes(p[1..5].try_into().unwrap()) as usize;
    if ql != 32 {
        return Err(Error::Malformed("obfs-ssh: DH_INIT q_c length != 32".into()));
    }
    Ok(p[5..37].try_into().unwrap())
}

/// Validate a DH_REPLY's string structure and return the 32-byte `f`.
fn parse_dh_reply(p: &[u8]) -> Result<[u8; 32], Error> {
    expect_msg_type(p, MSG_KEX_DH_REPLY, "DH_REPLY")?;
    let take_str = |off: usize, p: &[u8]| -> Result<(usize, Vec<u8>), Error> {
        if off + 4 > p.len() {
            return Err(Error::Malformed("obfs-ssh: DH_REPLY truncated".into()));
        }
        let l = u32::from_be_bytes(p[off..off + 4].try_into().unwrap()) as usize;
        if l == 0 || off + 4 + l > p.len() {
            return Err(Error::Malformed("obfs-ssh: DH_REPLY bad string length".into()));
        }
        Ok((off + 4 + l, p[off + 4..off + 4 + l].to_vec()))
    };
    let (off, _k_s) = take_str(1, p)?;
    let (off, f) = take_str(off, p)?;
    let (_off, _sig) = take_str(off, p)?;
    if f.len() != 32 {
        return Err(Error::Malformed("obfs-ssh: DH_REPLY f length != 32".into()));
    }
    Ok(f.try_into().unwrap())
}

/// sshd-style quiet close: shutdown the write side and drain briefly so
/// the kernel does not answer unread peer data with an RST.
fn close_quietly(stream: &mut TcpStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut sink = [0u8; 4096];
    let mut budget = 8;
    while budget > 0 {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => budget -= 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Handshakes
// ---------------------------------------------------------------------------

/// Client side of the SSH emulation.
///
/// Sequence (byte-identical to OpenSSH's own): banner, peer banner,
/// KEXINIT, peer KEXINIT, DH_INIT(q_c), peer DH_REPLY(f) — then NEWKEYS
/// and, when `early` is given, the RawLink hello packet as the first
/// post-NEWKEYS "encrypted" frame. Returns the rand-mode codec halves
/// keyed by the handshake randoms.
pub fn client_handshake(mut stream: TcpStream, psk: &[u8; 32], cfg: &SshObfsConfig,
                        early: Option<&[u8]>)
    -> Result<(ObfReadHalf, ObfWriteHalf), Error>
{
    cfg.validate()?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs rtimeout"))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs wtimeout"))?;

    // Flight 1: identification string (immediately on connect).
    stream.write_all(&banner_line(cfg)).map_err(io_err("send banner"))?;
    read_banner(&mut stream)?;

    // Flight 2: KEXINIT.
    stream.write_all(&wrap_packet(&kexinit_payload(true))).map_err(io_err("send kexinit"))?;
    let p = read_packet(&mut stream)?;
    expect_msg_type(&p, MSG_KEXINIT, "KEXINIT")?;

    // Flight 3: curve25519 DH_INIT with our fresh random.
    let mut q_c = [0u8; 32];
    rand::rng().fill_bytes(&mut q_c);
    stream.write_all(&wrap_packet(&dh_init_payload(&q_c))).map_err(io_err("send dh_init"))?;

    // Flight 4: DH_REPLY carries the server's fresh random.
    let p = read_packet(&mut stream)?;
    let f = parse_dh_reply(&p)?;
    // (server NEWKEYS follows immediately — read after we commit our side)
    let p = read_packet(&mut stream)?;
    expect_msg_type(&p, MSG_NEWKEYS, "NEWKEYS")?;

    // Commit: NEWKEYS + (optionally) the RawLink hello as the first
    // "encrypted" frame, riding the same flight.
    let prk = ssh_prk(psk);
    let (c2s, s2c) = derive_stream_keys(&prk, &q_c, &f);
    stream.write_all(&newkeys_packet()).map_err(io_err("send newkeys"))?;
    let (read, mut write) = obfs::build_halves(stream, &inner_cfg(cfg), c2s, s2c, true)?;
    if let Some(e) = early {
        if e.len() >= crate::config::HEADER_LEN {
            write.write_frame2(&e[..crate::config::HEADER_LEN],
                               &e[crate::config::HEADER_LEN..])
                .map_err(|e| Error::Carrier(crate::error::CarrierError::new(
                    "obfs-ssh", "early data", format!("{e}"))))?;
        }
    }
    Ok((read, write))
}

/// Server side of the SSH emulation. Sends banner + KEXINIT immediately
/// on accept (sshd does the same), validates the client's messages
/// structurally, answers the DH exchange, exchanges NEWKEYS, and hands
/// the connection to the data-phase codec. Early data (the RawLink
/// hello) is NOT consumed here — it flows through the codec into the
/// carrier read path.
pub fn server_handshake(mut stream: TcpStream, psk: &[u8; 32], cfg: &SshObfsConfig)
    -> Result<(ObfReadHalf, ObfWriteHalf), Error>
{
    cfg.validate()?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs rtimeout"))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs wtimeout"))?;

    // sshd-style: our identification + KEXINIT go out before ANY client
    // bytes are read, coalesced in one write (a scanner that connects and
    // only listens sees an ordinary OpenSSH server).
    let mut flight = banner_line(cfg);
    flight.extend_from_slice(&wrap_packet(&kexinit_payload(false)));
    stream.write_all(&flight).map_err(io_err("send banner+kexinit"))?;

    // Identification line; garbage gets sshd's quiet close.
    if let Err(e) = read_banner(&mut stream) {
        close_quietly(&mut stream);
        return Err(e);
    }
    let p = match read_packet(&mut stream) {
        Ok(p) => p,
        Err(e) => { close_quietly(&mut stream); return Err(e); }
    };
    if let Err(e) = expect_msg_type(&p, MSG_KEXINIT, "KEXINIT") {
        close_quietly(&mut stream);
        return Err(e);
    }

    // DH_INIT: the client's fresh random.
    let p = match read_packet(&mut stream) {
        Ok(p) => p,
        Err(e) => { close_quietly(&mut stream); return Err(e); }
    };
    let q_c = match parse_dh_init(&p) {
        Ok(q) => q,
        Err(e) => { close_quietly(&mut stream); return Err(e); }
    };

    // DH_REPLY + NEWKEYS leave together (typical sshd coalescing).
    let mut f = [0u8; 32];
    rand::rng().fill_bytes(&mut f);
    let prk = ssh_prk(psk);
    let (c2s, s2c) = derive_stream_keys(&prk, &q_c, &f);
    let mut flight = Vec::with_capacity(192 + 16);
    flight.extend_from_slice(&wrap_packet(&dh_reply_payload(&prk, &q_c, &f)));
    flight.extend_from_slice(&newkeys_packet());
    stream.write_all(&flight).map_err(io_err("send dh_reply+newkeys"))?;

    // Client NEWKEYS — after this, everything is the encrypted data phase.
    let p = read_packet(&mut stream)?;
    expect_msg_type(&p, MSG_NEWKEYS, "NEWKEYS")?;

    obfs::build_halves(stream, &inner_cfg(cfg), c2s, s2c, false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_packet_framing_invariants() {
        for payload_len in [1usize, 2, 15, 37, 179, 460, 1400] {
            let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
            let pkt = wrap_packet(&payload);
            assert!(pkt.len() >= 16, "min total 16");
            assert_eq!((pkt.len()) % 8, 0, "8-byte alignment, got {}", pkt.len());
            let plen = u32::from_be_bytes(pkt[..4].try_into().unwrap()) as usize;
            assert_eq!(4 + plen, pkt.len(), "packet_length covers body+padding");
            let padlen = pkt[4] as usize;
            assert!(padlen >= 4, "padding >= 4");
            assert_eq!(pkt[5..5 + payload_len], payload, "payload intact");
        }
    }

    #[test]
    fn known_packet_sizes_match_openssh() {
        // Real OpenSSH curve25519 KEX on the wire:
        //   DH_INIT  = 4+1+37+6  = 48 B
        //   NEWKEYS  = 4+1+1+10  = 16 B
        //   DH_REPLY (ed25519 hostkey) = 4+1+179+8 = 192 B
        assert_eq!(wrap_packet(&dh_init_payload(&[7u8; 32])).len(), 48);
        assert_eq!(newkeys_packet().len(), 16);
        let prk = ssh_prk(&[9u8; 32]);
        assert_eq!(wrap_packet(&dh_reply_payload(&prk, &[1u8; 32], &[2u8; 32])).len(), 192);
        // KEXINIT lands in the real size class (~1.3-1.6 KiB).
        let k = wrap_packet(&kexinit_payload(true));
        assert!(k.len() > 1100 && k.len() < 1700, "kexinit size {}", k.len());
        let ks = wrap_packet(&kexinit_payload(false));
        assert!(ks.len() > 600 && ks.len() < 1100, "server kexinit size {}", ks.len());
    }

    #[test]
    fn hostkey_is_stable_across_calls_and_psks() {
        let a = hostkey_bytes(&ssh_prk(&[1u8; 32]));
        let b = hostkey_bytes(&ssh_prk(&[1u8; 32]));
        let c = hostkey_bytes(&ssh_prk(&[2u8; 32]));
        assert_eq!(a, b, "same PSK => same host key (server identity stable)");
        assert_ne!(a, c, "different PSK => different host key");
    }

    #[test]
    fn dh_messages_round_trip_through_parsers() {
        let q_c = [0xABu8; 32];
        let p = dh_init_payload(&q_c);
        assert_eq!(parse_dh_init(&p).unwrap(), q_c);
        let prk = ssh_prk(&[3u8; 32]);
        let f = [0xCDu8; 32];
        let r = dh_reply_payload(&prk, &q_c, &f);
        assert_eq!(parse_dh_reply(&r).unwrap(), f);
        // Structural corruption is rejected.
        let mut bad = r.clone();
        bad[1] = 0xFF; // K_S length broken
        assert!(parse_dh_reply(&bad).is_err());
    }

    #[test]
    fn stream_keys_bind_both_randoms() {
        let prk = ssh_prk(&[5u8; 32]);
        let (a_c2s, _) = derive_stream_keys(&prk, &[1u8; 32], &[2u8; 32]);
        let (b_c2s, _) = derive_stream_keys(&prk, &[1u8; 32], &[3u8; 32]);
        let (c_c2s, _) = derive_stream_keys(&prk, &[9u8; 32], &[2u8; 32]);
        assert_ne!(a_c2s.key, b_c2s.key, "server random must change keys (replay defense)");
        assert_ne!(a_c2s.key, c_c2s.key, "client random must change keys");
    }
}
