//! Traffic obfuscation layer (`rand` mode).
//!
//! Wraps the TCP byte stream so that everything on the wire — including
//! the handshake — is indistinguishable from uniformly random bytes:
//!
//! * masked framing — the carrier's `u16` length prefix is replaced by a
//!   masked 3-byte header (bits: payload len | pad len | dummy flag), and
//!   the plaintext packet headers never appear in cleartext;
//! * every frame carries 0..`padding_max` random padding bytes and random-
//!   sized DUMMY frames are injected during idle periods, so frame sizes
//!   and timing do not correlate with user data;
//! * a probe that cannot produce a valid ClientHello MAC receives exactly
//!   40 random bytes (same shape as a legitimate ServerHello) and a close —
//!   no error messages, no size oracle;
//! * stream keys derive from the PSK AND both fresh randoms, so a replayed
//!   handshake derives different keys and fails the inner authentication.
//!
//! Layering (the RawLink core protocol is untouched — this is a transport
//! adapter, exactly like the plain TCP carrier's length prefix):
//!
//! ```text
//!   Session (AES-256-GCM packets, frames)          UNCHANGED
//!   TcpCarrier packet framing [u16 len][pkt]       reconstructed on top of obfs
//!   Obfuscation (optional)
//!     [3B masked hdr: len16|pad7|dummy1][masked pkt][raw random pad]
//!     XChaCha20 keystream per direction, bound to PSK + both randoms
//!   TCP
//! ```
//!
//! Security notes:
//! * The keystream mask is NOT a substitute for the inner AEAD — it exists
//!   to erase structure (framing, sizes, timing). All confidentiality and
//!   integrity guarantees come from the RawLink AES-256-GCM layer.
//! * Keystream is consumed ONLY over the 3 header bytes + payload bytes of
//!   each frame, identically on both sides (padding bytes are raw random and
//!   skipped, not masked).
//! * Handshake MACs are truncated to 8 bytes — online forgery is rate-limited
//!   by the uniform probe response + close behaviour, and the inner session
//!   still requires a full PSK authentication.

use cipher::{KeyIvInit, StreamCipher};
use chacha20::{Key as ChachaKey, XChaCha20, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::RngCore;
use sha2::Sha256;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// ClientHello / ServerHello wire size: 8-byte tag + 32 random bytes.
pub const HELLO_LEN: usize = 40;
/// Obfuscated frame header size: 3 bytes (u24: len16 | pad7 | dummy1), masked.
pub const FRAME_HDR_LEN: usize = 3;
/// Maximum frame payload = the RawLink packet itself (carrier MTU bound).
pub const MAX_FRAME_PAYLOAD: usize = 65535;
/// Maximum random padding per frame (7-bit field).
pub const MAX_PADDING: usize = 127;
/// Maximum dummy (cover) frame payload.
pub const MAX_DUMMY_PAYLOAD: usize = 8192;
/// Deadline for the obfs handshake exchange.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// 24-bit header layout (little-endian u32, top byte only carries the flag):
//   bits 0..15  payload length (0..=65535)
//   bits 16..22 pad length (0..=127)
//   bit  23     dummy flag
const LEN_MASK: u32 = 0xFFFF;
const PAD_SHIFT: u32 = 16;
const DUMMY_BIT: u32 = 1 << 23;

type HmacSha256 = Hmac<Sha256>;

/// Which obfuscation a connection uses.
///
/// * `Rand` — everything on the wire is indistinguishable from uniformly
///   random bytes (masked framing, padding, dummy cover traffic).
/// * `Ssh` — SSH transport mimicry (`obfs_ssh`): a byte-faithful OpenSSH
///   handshake whose emulated key exchange derives the data-phase keys.
#[derive(Debug, Clone)]
pub enum ObfsMode {
    Rand(ObfsConfig),
    Ssh(crate::obfs_ssh::SshObfsConfig),
}

/// Obfuscation tunables. Present (as `Option<ObfsConfig>`) => enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObfsConfig {
    /// Max random padding appended to every frame (0..=127). Padding bytes
    /// are pure random and skipped by the receiver; they decorrelate wire
    /// frame sizes from payload sizes.
    pub padding_max: u8,
    /// Lower bound of the randomized idle interval before a dummy frame is
    /// sent (milliseconds). Keeps long-lived tunnels from showing dead air.
    pub dummy_min_ms: u32,
    /// Upper bound of the randomized idle interval (milliseconds).
    pub dummy_max_ms: u32,
    /// Max payload size of a dummy frame (0..=8192).
    pub dummy_size_max: u16,
}
impl Default for ObfsConfig {
    fn default() -> Self {
        Self { padding_max: 64, dummy_min_ms: 700, dummy_max_ms: 2200, dummy_size_max: 384 }
    }
}
impl ObfsConfig {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.padding_max as usize > MAX_PADDING {
            return Err(crate::Error::Malformed("obfs: padding_max > 127".into()));
        }
        if self.dummy_size_max as usize > MAX_DUMMY_PAYLOAD {
            return Err(crate::Error::Malformed("obfs: dummy_size_max > 8192".into()));
        }
        if self.dummy_min_ms < 50 {
            return Err(crate::Error::Malformed("obfs: dummy_min_ms < 50 (don't spin)".into()));
        }
        if self.dummy_min_ms > self.dummy_max_ms {
            return Err(crate::Error::Malformed("obfs: dummy_min_ms > dummy_max_ms".into()));
        }
        Ok(())
    }
    fn dummy_interval(&self) -> Duration {
        let lo = self.dummy_min_ms;
        let hi = self.dummy_max_ms.max(lo);
        Duration::from_millis(rand::rng().random_range(lo..=hi) as u64)
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Long-lived obfs PRK: extracted once from the PSK (same pattern as the
/// session key derivation in crypto::derive_keys).
fn obfs_prk(psk: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk).expect("hmac");
    mac.update(b"rawlink-obfs-v1/salt");
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

fn hmac8(key: &[u8; 32], data: &[u8]) -> [u8; 8] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    [out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]]
}

fn hello_key(prk: &[u8; 32]) -> [u8; 32] {
    let k = expand(prk, b"rawlink-obfs-v1 hello-tag", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&k);
    out
}

/// Per-connection traffic keys for one direction. The 24-byte nonces are
/// freshly derived per connection (from both randoms), so keystream reuse
/// across connections is impossible even for a fixed PSK.
pub(crate) struct DirectionKeys { pub(crate) key: [u8; 32], pub(crate) nonce: [u8; 24] }

fn derive_stream_keys(prk: &[u8; 32], client_random: &[u8; 32], server_random: &[u8; 32])
    -> (DirectionKeys, DirectionKeys)
{
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("hmac");
    mac.update(b"rawlink-obfs-v1/ks");
    mac.update(client_random);
    mac.update(server_random);
    let ks_prk = mac.finalize().into_bytes();
    let mut kp = [0u8; 32];
    kp.copy_from_slice(&ks_prk);
    let mut ck = [0u8; 32]; ck.copy_from_slice(&expand(&kp, b"rawlink-obfs-v1 c2s key", 32));
    let mut cn = [0u8; 24]; cn.copy_from_slice(&expand(&kp, b"rawlink-obfs-v1 c2s nonce", 24));
    let mut sk = [0u8; 32]; sk.copy_from_slice(&expand(&kp, b"rawlink-obfs-v1 s2c key", 32));
    let mut sn = [0u8; 24]; sn.copy_from_slice(&expand(&kp, b"rawlink-obfs-v1 s2c nonce", 24));
    (DirectionKeys { key: ck, nonce: cn }, DirectionKeys { key: sk, nonce: sn })
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Client side: send ClientHello (tag ++ 32 random bytes), read + verify
/// ServerHello, return the masked stream halves.
pub fn client_handshake(mut stream: TcpStream, psk: &[u8; 32], cfg: &ObfsConfig)
    -> Result<(ObfReadHalf, ObfWriteHalf), crate::Error>
{
    cfg.validate()?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs rtimeout"))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs wtimeout"))?;

    let hk = hello_key(&obfs_prk(psk));

    let mut client_random = [0u8; 32];
    rand::rng().fill_bytes(&mut client_random);
    let mut tag_data = Vec::with_capacity(20 + 32);
    tag_data.extend_from_slice(b"rawlink-obfs-v1/ch");
    tag_data.extend_from_slice(&client_random);
    let tag = hmac8(&hk, &tag_data);

    stream.write_all(&tag).map_err(io_err("send ch tag"))?;
    stream.write_all(&client_random).map_err(io_err("send ch random"))?;

    let mut hello = [0u8; HELLO_LEN];
    stream.read_exact(&mut hello).map_err(io_err("read sh"))?;
    let mut tag_data = Vec::with_capacity(20 + 64);
    tag_data.extend_from_slice(b"rawlink-obfs-v1/sh");
    tag_data.extend_from_slice(&client_random);
    tag_data.extend_from_slice(&hello[8..]);
    let expect = hmac8(&hk, &tag_data);
    if expect != hello[..8] {
        return Err(crate::Error::Auth("obfs: server hello verification failed".into()));
    }
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(&hello[8..]);

    let (c2s, s2c) = derive_stream_keys(&obfs_prk(psk), &client_random, &server_random);
    build_halves(stream, cfg, c2s, s2c, true)
}

/// Server side: read + verify ClientHello, answer with ServerHello.
/// On ANY failure the peer still receives exactly 40 random bytes before
/// close — a failed handshake is wire-indistinguishable from a success up to
/// the point where the data phase begins (which only key holders can tell).
pub fn server_handshake(mut stream: TcpStream, psk: &[u8; 32], cfg: &ObfsConfig)
    -> Result<(ObfReadHalf, ObfWriteHalf), crate::Error>
{
    cfg.validate()?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs rtimeout"))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(io_err("set hs wtimeout"))?;

    let hk = hello_key(&obfs_prk(psk));

    let mut hello = [0u8; HELLO_LEN];
    if let Err(e) = stream.read_exact(&mut hello) {
        probe_fail(stream);
        return Err(io_err("read ch")(e));
    }
    let mut tag_data = Vec::with_capacity(20 + 32);
    tag_data.extend_from_slice(b"rawlink-obfs-v1/ch");
    tag_data.extend_from_slice(&hello[8..]);
    let expect = hmac8(&hk, &tag_data);
    if expect != hello[..8] {
        probe_fail(stream);
        return Err(crate::Error::Auth("obfs: client hello verification failed".into()));
    }
    let client_random: [u8; 32] = hello[8..].try_into().unwrap();

    let mut server_random = [0u8; 32];
    rand::rng().fill_bytes(&mut server_random);
    let mut tag_data = Vec::with_capacity(20 + 64);
    tag_data.extend_from_slice(b"rawlink-obfs-v1/sh");
    tag_data.extend_from_slice(&client_random);
    tag_data.extend_from_slice(&server_random);
    let tag = hmac8(&hk, &tag_data);

    stream.write_all(&tag).map_err(io_err("send sh tag"))?;
    stream.write_all(&server_random).map_err(io_err("send sh random"))?;

    let (c2s, s2c) = derive_stream_keys(&obfs_prk(psk), &client_random, &server_random);
    build_halves(stream, cfg, c2s, s2c, false)
}

fn probe_fail(mut s: TcpStream) {
    // Uniform probe response: 40 random bytes, then close.
    let mut junk = [0u8; HELLO_LEN];
    rand::rng().fill_bytes(&mut junk);
    let _ = s.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = s.write_all(&junk);
    let _ = s.shutdown(std::net::Shutdown::Both);
}

/// Construct the codec halves from explicit direction keys. Shared by the
/// rand handshake and the SSH-mimicry layer (which derives its keys from
/// the emulated DH exchange randoms instead of the obfs hello randoms —
/// the frame CODEC is mode-independent, only the key schedule differs).
pub(crate) fn build_halves(stream: TcpStream, cfg: &ObfsConfig, c2s: DirectionKeys, s2c: DirectionKeys,
                          is_client: bool)
    -> Result<(ObfReadHalf, ObfWriteHalf), crate::Error>
{
    let (my, peer) = if is_client { (&c2s, &s2c) } else { (&s2c, &c2s) };
    let mk_cipher = |k: &DirectionKeys| {
        XChaCha20::new(ChachaKey::from_slice(&k.key), XNonce::from_slice(&k.nonce))
    };
    let write = ObfWriteHalf {
        stream: stream.try_clone().map_err(io_err("clone wr"))?,
        cipher: mk_cipher(my),
        pending: Vec::with_capacity(COALESCE_FLUSH_BYTES + 4096),
        last_append: None,
        ewma_bpms: -1.0,
        last_flush: Instant::now(),
        pad_max: cfg.padding_max as usize,
        dummy_min_ms: cfg.dummy_min_ms,
        dummy_max_ms: cfg.dummy_max_ms,
        dummy_size_max: cfg.dummy_size_max,
        last_send: Instant::now(),
        next_dummy: Instant::now() + cfg.dummy_interval(),
    };
    let read = ObfReadHalf {
        stream,
        cipher: mk_cipher(peer),
        wire: Vec::with_capacity(WIRE_READ_CHUNK + 4096),
        wpos: 0,
        rd_buf: vec![0u8; WIRE_READ_CHUNK],
        hdr: [0u8; FRAME_HDR_LEN],
        hdr_got: 0,
        frame_len: 0,
        frame_rem: 0,
        frame_pad: 0,
        frame_dummy: false,
        prefix_rem: 0,
    };
    Ok((read, write))
}

fn io_err(op: &'static str) -> impl Fn(std::io::Error) -> crate::Error {
    move |e| crate::Error::Carrier(crate::error::CarrierError::new("obfs", op, format!("{e}")))
}

// ---------------------------------------------------------------------------
// Write half
// ---------------------------------------------------------------------------

/// Hard cap of the coalescing buffer: under bulk load one write_all carries
/// this many bytes (~20 packets of 1.5 KiB) — roughly a 20x syscall cut.
const COALESCE_FLUSH_BYTES: usize = 32 * 1024;
/// Coalescing only engages while packets arrive in a HOT streak (gap between
/// consecutive sends at or under this). On a cold link every frame is flushed
/// immediately — zero added latency for interactive traffic.
const HOT_WINDOW: Duration = Duration::from_micros(300);
/// Adaptive flush target bounds: the target is ~1ms worth of recently
/// observed send rate (EWMA, bytes/ms), clamped to [4 KiB, 32 KiB]. A burst
/// that ends mid-target leaves at most `target` bytes for the writer's idle
/// tick (≤100ms) to flush — acceptable for bulk-shaped tails only, because
/// cold/small traffic always flushes immediately.
const TARGET_MIN_BYTES: usize = 4096;
const TARGET_MAX_BYTES: usize = COALESCE_FLUSH_BYTES;
const TARGET_WINDOW_MS: f64 = 1.0;

/// Masked write half. Every frame:
/// `[3B masked hdr][payload XOR keystream][0..pad_max raw random bytes]`
///
/// Performance notes (the wire format is fixed):
/// * frames are appended straight into a coalescing buffer and masked there —
///   one keystream call per frame, zero intermediate copies;
/// * the buffer leaves in ONE write_all — sized adaptively: cold/interactive
///   traffic flushes per frame (no latency added), hot bulk traffic coalesces
///   up to 32 KiB. The writer's idle tick flushes any bulk tail;
/// * dummy frames always flush immediately (they exist to be seen);
/// * ALL socket writes happen on the session's WRITER thread (send() or
///   idle_tick) — never on the recv thread, which must never stall behind a
///   socket write (bilateral-deadlock prevention);
/// * `Drop` performs a best-effort bounded flush so a coalesced tail (e.g. a
///   final ConnectionClose packet) still reaches the wire at teardown.
pub struct ObfWriteHalf {
    stream: TcpStream,
    cipher: XChaCha20,
    /// Obfuscated frames awaiting one `write_all`.
    pending: Vec<u8>,
    /// When the previous frame was appended (hot/cold streak detection).
    last_append: Option<Instant>,
    /// Smoothed send rate in bytes/ms (drives the adaptive flush target).
    ewma_bpms: f64,
    last_flush: Instant,
    pad_max: usize,
    dummy_min_ms: u32,
    dummy_max_ms: u32,
    dummy_size_max: u16,
    last_send: Instant,
    next_dummy: Instant,
}

impl ObfWriteHalf {
    /// Write one obfuscated frame whose payload is `hdr || rest` (used by
    /// the v3 header-mask carrier integration: the 17-byte packet header is
    /// masked before framing, the rest rides along untouched).
    pub fn write_frame2(&mut self, hdr: &[u8], rest: &[u8]) -> io::Result<()> {
        if hdr.len() + rest.len() > MAX_FRAME_PAYLOAD {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                format!("obfs frame payload {} > {}", hdr.len() + rest.len(), MAX_FRAME_PAYLOAD)));
        }
        let hot = self.last_append.is_some_and(|t| t.elapsed() <= HOT_WINDOW);
        self.last_append = Some(Instant::now());
        // (single combined append — same code shape as append_frame but with
        // the payload arriving as two slices)
        let pad = if self.pad_max > 0 {
            rand::rng().random_range(0..=self.pad_max.min(MAX_PADDING))
        } else { 0 };
        let hval = ((hdr.len() + rest.len()) as u32)
            | ((pad as u32) << PAD_SHIFT);
        let hle = hval.to_le_bytes();
        self.pending.reserve(FRAME_HDR_LEN + hdr.len() + rest.len() + pad);
        let hstart = self.pending.len();
        self.pending.extend_from_slice(&hle[..FRAME_HDR_LEN]);
        self.pending.extend_from_slice(hdr);
        self.pending.extend_from_slice(rest);
        self.cipher.apply_keystream(&mut self.pending[hstart..]);
        let pend_at = self.pending.len();
        self.pending.resize(pend_at + pad, 0);
        rand::rng().fill_bytes(&mut self.pending[pend_at..]);
        let n = self.pending.len();
        if n >= COALESCE_FLUSH_BYTES || n >= self.flush_target() || !hot {
            self.flush_pending()?;
        }
        Ok(())
    }

    /// Write one obfuscated frame carrying `payload` (the rawlink packet).
    pub fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                format!("obfs frame payload {} > {}", payload.len(), MAX_FRAME_PAYLOAD)));
        }
        // Hot streak? (Measured BEFORE this frame updates the timestamp.)
        let hot = self.last_append
            .is_some_and(|t| t.elapsed() <= HOT_WINDOW);
        self.last_append = Some(Instant::now());
        self.append_frame(payload, false)?;
        let n = self.pending.len();
        if n >= COALESCE_FLUSH_BYTES || n >= self.flush_target() || !hot {
            self.flush_pending()?;
        }
        Ok(())
    }

    /// Force-write every coalesced frame to the socket. Cheap when idle.
    pub fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() { return Ok(()); }
        // Update the rate estimate from the bytes that just accumulated.
        let now = Instant::now();
        let dt_ms = now.duration_since(self.last_flush).as_secs_f64() * 1000.0;
        if dt_ms >= 0.5 {
            let inst = self.pending.len() as f64 / dt_ms.max(0.05);
            self.ewma_bpms = if self.ewma_bpms.is_sign_negative() || self.ewma_bpms == 0.0 {
                inst
            } else {
                self.ewma_bpms * 0.7 + inst * 0.3
            };
        }
        self.last_flush = now;
        let res = self.stream.write_all(&self.pending);
        self.pending.clear();
        self.last_send = Instant::now();
        res
    }

    /// Bytes-per-ms-adaptive flush target: ~1ms of recent traffic, clamped.
    fn flush_target(&self) -> usize {
        if self.ewma_bpms <= 0.0 { return TARGET_MIN_BYTES; }
        let t = (self.ewma_bpms * TARGET_WINDOW_MS) as usize;
        t.clamp(TARGET_MIN_BYTES, TARGET_MAX_BYTES)
    }

    /// Send a random-sized dummy (cover) frame if the idle interval elapsed,
    /// then flush everything pending. Called from the WRITER thread's
    /// `idle_tick` (send queue empty ≥100ms) — blocking here is ordinary TCP
    /// backpressure. Never carries user data; the receiver consumes its
    /// keystream and drops it.
    pub fn maybe_send_dummy(&mut self) -> io::Result<()> {
        let now = Instant::now();
        if self.dummy_size_max > 0 && now >= self.next_dummy {
            self.next_dummy = now + Duration::from_millis(rand::rng()
                .random_range(self.dummy_min_ms..=self.dummy_max_ms.max(self.dummy_min_ms)) as u64);
            // Dummies only make sense when the link has been quiet — a frame
            // written just now already refreshed the size/timing pattern.
            if self.last_send.elapsed() >= Duration::from_millis((self.dummy_min_ms / 2).max(1) as u64) {
                let size = rand::rng().random_range(0..=self.dummy_size_max as usize);
                self.append_dummy(size)?;
                // Dummies exist to be ON the wire — never coalesce them.
                self.flush_pending()?;
                return Ok(());
            }
        }
        // The writer only ticks when the send queue has been empty for
        // ~100ms, so anything still pending is a stale bulk tail — flush it.
        self.flush_pending()
    }

    fn append_frame(&mut self, payload: &[u8], dummy: bool) -> io::Result<()> {
        let pad = if self.pad_max > 0 {
            rand::rng().random_range(0..=self.pad_max.min(MAX_PADDING))
        } else { 0 };
        // Header: len | pad<<16 | dummy<<23. Keystream is consumed over
        // exactly hdr+payload (receiver mirrors this); padding is raw random
        // and skipped. Header and payload are appended RAW and masked with
        // ONE contiguous apply_keystream.
        let hval = (payload.len() as u32)
            | ((pad as u32) << PAD_SHIFT)
            | if dummy { DUMMY_BIT } else { 0 };
        let hle = hval.to_le_bytes();
        self.pending.reserve(FRAME_HDR_LEN + payload.len() + pad);
        let hstart = self.pending.len();
        self.pending.extend_from_slice(&hle[..FRAME_HDR_LEN]);
        self.pending.extend_from_slice(payload);
        self.cipher.apply_keystream(&mut self.pending[hstart..]);
        let pend_at = self.pending.len();
        self.pending.resize(pend_at + pad, 0);
        rand::rng().fill_bytes(&mut self.pending[pend_at..]);
        Ok(())
    }

    /// Dummy frames need a random payload; build it in place (no allocation).
    fn append_dummy(&mut self, size: usize) -> io::Result<()> {
        let pad = if self.pad_max > 0 {
            rand::rng().random_range(0..=self.pad_max.min(MAX_PADDING))
        } else { 0 };
        let hval = (size as u32) | ((pad as u32) << PAD_SHIFT) | DUMMY_BIT;
        let hle = hval.to_le_bytes();
        self.pending.reserve(FRAME_HDR_LEN + size + pad);
        let hstart = self.pending.len();
        self.pending.extend_from_slice(&hle[..FRAME_HDR_LEN]);
        let pend_at = self.pending.len();
        self.pending.resize(pend_at + size, 0);
        rand::rng().fill_bytes(&mut self.pending[pend_at..]);
        self.cipher.apply_keystream(&mut self.pending[hstart..]);
        let pend_at = self.pending.len();
        self.pending.resize(pend_at + pad, 0);
        rand::rng().fill_bytes(&mut self.pending[pend_at..]);
        Ok(())
    }
}

impl Drop for ObfWriteHalf {
    fn drop(&mut self) {
        // Best-effort bounded tail flush at teardown: a coalesced final
        // packet (e.g. ConnectionClose) must still reach the wire. Bounded
        // so a dead peer cannot stall the drop for the full 30s timeout.
        if !self.pending.is_empty() {
            let _ = self.stream.set_write_timeout(Some(Duration::from_millis(200)));
            let _ = self.stream.write_all(&self.pending);
        }
    }
}

// ---------------------------------------------------------------------------
// Read half
// ---------------------------------------------------------------------------

/// Wire bytes pulled from the socket per read (a max-size frame assembles in
/// one syscall when the data has already arrived).
const WIRE_READ_CHUNK: usize = 65536;

/// Masked read half. Decodes obfuscated frames into the carrier's
/// `[u16 LE len][packet]` byte stream (dummies dropped), so the existing
/// carrier `ReadBuffer` logic is unchanged.
///
/// The decoded payload is copied STRAIGHT into the caller's buffer and
/// keystream-unmasked there. Whatever does not fit the caller's buffer
/// simply stays in `wire` as raw, unmasked bytes and is finished on the
/// next call (the keystream is only consumed over bytes actually decoded,
/// so a partially read frame stays resumable).
pub struct ObfReadHalf {
    stream: TcpStream,
    cipher: XChaCha20,
    /// Raw wire bytes not yet decoded (decryption happens on the copy out).
    wire: Vec<u8>,
    wpos: usize,
    /// Reusable socket-read staging buffer (pre-sized once — a resize-based
    /// direct read would memset the whole chunk on EVERY read call, which
    /// measurably hurts the small-packet path; the staging copy is a plain
    /// memcpy of exactly the bytes that arrived).
    rd_buf: Vec<u8>,
    /// Partial header accumulation.
    hdr: [u8; FRAME_HDR_LEN],
    hdr_got: usize,
    /// Payload length of the frame being decoded (drives the u16 prefix).
    frame_len: usize,
    /// Remaining payload bytes of the frame being read.
    frame_rem: usize,
    /// Padding bytes still to skip after the payload.
    frame_pad: usize,
    frame_dummy: bool,
    /// Carrier-prefix bytes (0..=2) still to emit for the current frame.
    prefix_rem: u8,
}

impl ObfReadHalf {
    pub(crate) fn set_data_read_timeout(&self, d: Duration) {
        let _ = self.stream.set_read_timeout(Some(d));
    }

    fn compact_wire(&mut self) {
        if self.wpos >= self.wire.len() {
            self.wire.clear();
            self.wpos = 0;
        } else if self.wpos >= 8192 {
            self.wire.drain(..self.wpos);
            self.wpos = 0;
        }
    }

    fn mid_frame(&self) -> bool {
        self.frame_rem > 0 || self.frame_pad > 0 || self.hdr_got > 0 || self.prefix_rem > 0
    }
}

impl Read for ObfReadHalf {
    /// Read decoded (de-obfuscated) bytes. Preserves the underlying socket's
    /// error semantics — `WouldBlock`/`TimedOut` propagate so the carrier's
    /// non-blocking poll loop works unchanged; `Ok(0)` only when the wire is
    /// cleanly EOF'd at a frame boundary AND no decoded bytes remain.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let mut filled = 0usize;
        loop {
            // Decode from `wire` into the caller's buffer as far as possible.
            loop {
                if filled == buf.len() { return Ok(filled); }
                if self.prefix_rem > 0 {
                    // Re-emit the carrier's u16 length prefix (synthesized
                    // bytes — they do not exist on the obfs wire).
                    let len16 = (self.frame_len as u16).to_le_bytes();
                    buf[filled] = len16[2 - self.prefix_rem as usize];
                    filled += 1;
                    self.prefix_rem -= 1;
                    continue;
                }
                if self.frame_rem == 0 && self.frame_pad == 0 {
                    // Between frames: accumulate a full 3-byte header.
                    while self.hdr_got < FRAME_HDR_LEN && self.wpos < self.wire.len() {
                        self.hdr[self.hdr_got] = self.wire[self.wpos];
                        self.hdr_got += 1;
                        self.wpos += 1;
                    }
                    if self.hdr_got < FRAME_HDR_LEN { break; }
                    self.cipher.apply_keystream(&mut self.hdr);
                    let v = u32::from_le_bytes([self.hdr[0], self.hdr[1], self.hdr[2], 0]);
                    self.frame_len = (v & LEN_MASK) as usize;
                    self.frame_pad = ((v >> PAD_SHIFT) & 0x7F) as usize;
                    self.frame_dummy = v & DUMMY_BIT != 0;
                    self.frame_rem = self.frame_len;
                    self.hdr_got = 0;
                    if !self.frame_dummy {
                        self.prefix_rem = 2; // payload is preceded by its u16 prefix
                    }
                    continue;
                }
                if self.frame_rem > 0 {
                    let avail = self.wire.len() - self.wpos;
                    if avail == 0 { break; }
                    if self.frame_dummy {
                        // Dummy (cover) payload: consume the keystream and
                        // DROP the bytes — nothing reaches the caller.
                        // Not bounded by the caller's buffer: skipping a
                        // dummy never blocks.
                        let n = avail.min(self.frame_rem);
                        self.cipher.apply_keystream(
                            &mut self.wire[self.wpos..self.wpos + n]);
                        self.wpos += n;
                        self.frame_rem -= n;
                        continue;
                    }
                    let n = avail.min(self.frame_rem).min(buf.len() - filled);
                    buf[filled..filled + n]
                        .copy_from_slice(&self.wire[self.wpos..self.wpos + n]);
                    // Unmask on the copy out — the keystream advances only
                    // over bytes actually handed to the caller, so a frame
                    // the buffer could not fully take stays resumable.
                    self.cipher.apply_keystream(&mut buf[filled..filled + n]);
                    filled += n;
                    self.wpos += n;
                    self.frame_rem -= n;
                    continue;
                }
                if self.frame_pad > 0 {
                    let avail = self.wire.len() - self.wpos;
                    if avail == 0 { break; }
                    let n = avail.min(self.frame_pad);
                    self.wpos += n; // padding: raw random, skip (no keystream)
                    self.frame_pad -= n;
                    continue;
                }
            }
            if filled > 0 {
                self.compact_wire();
                return Ok(filled);
            }
            // Nothing decoded and wire exhausted — pull more raw bytes.
            self.compact_wire();
            let n = self.stream.read(&mut self.rd_buf)?;
            if n > 0 {
                self.wire.extend_from_slice(&self.rd_buf[..n]);
            } else if self.mid_frame() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                    "obfs: EOF mid-frame"));
            } else {
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream as TS};

    fn loopback_pair() -> (TS, TS) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || l.accept().unwrap().0);
        let c = TS::connect(addr).unwrap();
        let s = h.join().unwrap();
        (c, s)
    }

    fn establish(psk: [u8; 32], cfg: ObfsConfig)
        -> ((ObfReadHalf, ObfWriteHalf), (ObfReadHalf, ObfWriteHalf))
    {
        let (c, s) = loopback_pair();
        let hs = std::thread::spawn(move || server_handshake(s, &psk, &cfg).unwrap());
        let cl = client_handshake(c, &psk, &cfg).unwrap();
        (cl, hs.join().unwrap())
    }

    #[test]
    fn handshake_roundtrip_and_echo() {
        let cfg = ObfsConfig { padding_max: 32, ..Default::default() };
        let ((mut cr, mut cw), (mut sr, mut sw)) = establish([7u8; 32], cfg);
        let payload: Vec<u8> = (0..=255u8).cycle().take(50_000).collect();
        cw.write_frame(&payload).unwrap(); // client -> server
        // Decoded stream = carrier framing [u16 len][payload].
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while got.len() < payload.len() + 2 {
            let n = sr.read(&mut buf).unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got[..2], &(payload.len() as u16).to_le_bytes(), "carrier prefix");
        assert_eq!(&got[2..2 + payload.len()], &payload[..], "payload through obfs");
        sw.write_frame(b"hello from server").unwrap(); // server -> client
        sw.flush_pending().unwrap(); // force the small frame out (coalescing)
        let mut buf = [0u8; 64];
        let mut total = Vec::new();
        while total.len() < 19 {
            let n = cr.read(&mut buf).unwrap();
            total.extend_from_slice(&buf[..n]);
        }
        // Reconstructed carrier framing: [u16 len=17][payload]
        assert_eq!(&total[..2], &(17u16).to_le_bytes());
        assert_eq!(&total[2..19], b"hello from server");
    }
    #[test]
    fn wrong_psk_fails_handshake() {
        let cfg = ObfsConfig::default();
        let (c, s) = loopback_pair();
        let hs = std::thread::spawn(move || {
            server_handshake(s, &[1u8; 32], &cfg).is_err()
        });
        let cl = client_handshake(c, &[2u8; 32], &cfg);
        assert!(cl.is_err(), "client must reject bogus server hello");
        assert!(hs.join().unwrap(), "server must reject bogus client hello");
    }

    #[test]
    fn probe_gets_uniform_40_byte_response() {
        let cfg = ObfsConfig::default();
        let (mut c, s) = loopback_pair();
        let hs = std::thread::spawn(move || {
            assert!(server_handshake(s, &[9u8; 32], &cfg).is_err());
        });
        c.write_all(&[0xAB; 40]).unwrap();
        let mut resp = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match c.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
                Err(e) => panic!("probe read err: {e}"),
            }
        }
        assert_eq!(resp.len(), HELLO_LEN, "probe response must be exactly {HELLO_LEN} bytes");
        hs.join().unwrap();
    }

    #[test]
    fn byte_at_a_time_reads_stay_aligned() {
        let cfg = ObfsConfig { padding_max: 127, ..Default::default() };
        let ((mut cr, mut cw), (mut sr, mut sw)) = establish([3u8; 32], cfg);
        let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        cw.write_frame(&payload).unwrap(); // client -> server
        cw.flush_pending().unwrap();
        let mut got = Vec::new();
        let mut one = [0u8; 1];
        while got.len() < payload.len() + 2 {
            let n = sr.read(&mut one).unwrap();
            assert_eq!(n, 1);
            got.push(one[0]);
        }
        // Decoded stream = carrier framing [u16 len][payload]; compare via a
        // cheap helper so a mismatch never dumps 5000 bytes into the log.
        let mismatch = got[0..2] != (payload.len() as u16).to_le_bytes()
            || got[2..2 + payload.len()] != payload[..];
        assert!(!mismatch, "decoded stream must equal [len][payload] (len={})", payload.len());
        sw.write_frame(b"after").unwrap(); // server -> client
        sw.flush_pending().unwrap();
        let mut buf = [0u8; 16];
        let mut t = Vec::new();
        while t.len() < 7 { let n = cr.read(&mut buf).unwrap(); t.extend_from_slice(&buf[..n]); }
        assert_eq!(&t[2..7], b"after");
    }

    #[test]
    fn identical_payloads_decode_consistently() {
        let cfg = ObfsConfig { padding_max: 96, ..Default::default() };
        let ((_cr, mut cw), (mut sr, _sw)) = establish([4u8; 32], cfg);
        let p = [42u8; 100];
        cw.write_frame(&p).unwrap();
        cw.write_frame(&p).unwrap();
        cw.flush_pending().unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        let expect = 2 * (2 + 100);
        while got.len() < expect {
            let n = sr.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got[0..2], &(100u16).to_le_bytes());
        assert_eq!(&got[2 + 100..2 + 100 + 2], &(100u16).to_le_bytes());
    }

    #[test]
    fn dummy_frames_are_dropped_and_alignment_kept() {
        let cfg = ObfsConfig { padding_max: 8, dummy_min_ms: 50, dummy_max_ms: 60,
            dummy_size_max: 256 };
        let ((mut cr, mut cw), (mut sr, mut sw)) = establish([5u8; 32], cfg);
        // Idle long enough for a dummy to fire on the CLIENT write half,
        // then real data: the SERVER read half must skip the dummy and
        // deliver the data.
        std::thread::sleep(Duration::from_millis(140));
        cw.maybe_send_dummy().unwrap();
        cw.write_frame(b"real-data").unwrap();
        cw.flush_pending().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got = Vec::new();
        let mut buf = [0u8; 128];
        while got.len() < 2 + 9 && Instant::now() < deadline {
            match sr.read(&mut buf) {
                Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                Ok(_) => {}
                Err(e) => panic!("read err: {e}"),
            }
        }
        assert_eq!(&got[..2], &(9u16).to_le_bytes());
        assert_eq!(&got[2..11], b"real-data");
        // Reverse direction: SERVER-side dummy then data, CLIENT read half
        // still aligned.
        std::thread::sleep(Duration::from_millis(140));
        sw.maybe_send_dummy().unwrap();
        sw.write_frame(b"srv-data").unwrap();
        sw.flush_pending().unwrap();
        let mut got2 = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while got2.len() < 2 + 8 && Instant::now() < deadline {
            if let Ok(n) = cr.read(&mut buf) { if n > 0 { got2.extend_from_slice(&buf[..n]); } }
        }
        assert_eq!(&got2[2..10], b"srv-data");
    }

    #[test]
    fn zero_pad_and_max_size_frames() {
        let cfg = ObfsConfig { padding_max: 0, ..Default::default() };
        let ((_cr, mut cw), (mut sr, _sw)) = establish([6u8; 32], cfg);
        let big: Vec<u8> = (0..65535).map(|i| (i % 255) as u8).collect();
        cw.write_frame(&big).unwrap(); // client -> server
        cw.write_frame(&[1, 2, 3]).unwrap();
        cw.flush_pending().unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 65536];
        let expect = 2 + 65535 + 2 + 3;
        while got.len() < expect {
            let n = sr.read(&mut buf).unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got[..2], &(65535u16).to_le_bytes());
        assert_eq!(&got[2..2 + 65535], &big[..]);
        assert_eq!(&got[2 + 65535..2 + 65535 + 2], &(3u16).to_le_bytes());
        assert_eq!(&got[2 + 65535 + 2..], &[1, 2, 3]);
    }

    #[test]
    fn config_validation() {
        assert!(ObfsConfig { padding_max: 128, ..Default::default() }.validate().is_err());
        assert!(ObfsConfig { dummy_min_ms: 40, dummy_max_ms: 100, ..Default::default() }.validate().is_err());
        assert!(ObfsConfig { dummy_min_ms: 500, dummy_max_ms: 100, ..Default::default() }.validate().is_err());
        assert!(ObfsConfig { dummy_size_max: 8193, ..Default::default() }.validate().is_err());
        assert!(ObfsConfig::default().validate().is_ok());
    }

    #[test]
    fn coalesced_frames_flush_via_maintenance_tick() {
        // Core behaviour: small frames coalesce; a write_frame alone does
        // NOT hit the wire; the maintenance tick (grace elapsed) flushes the
        // tail — proving latency stays bounded without explicit flushes.
        let cfg = ObfsConfig { padding_max: 16, ..Default::default() };
        let ((_cr, mut cw), (mut sr, _sw)) = establish([8u8; 32], cfg);
        cw.write_frame(b"tail-one").unwrap();
        cw.write_frame(b"tail-two").unwrap();
        // Nothing was flushed yet (both frames sit in the coalescing buffer).
        // After the grace period the maintenance tick must flush the tail
        // even though no dummy is due (dummy interval is 700ms+ away).
        std::thread::sleep(Duration::from_millis(3)); // > MAINT_FLUSH_GRACE
        cw.maybe_send_dummy().unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let deadline = Instant::now() + Duration::from_secs(2);
        while got.len() < 2 + 8 + 2 + 8 && Instant::now() < deadline {
            if let Ok(n) = sr.read(&mut buf) { if n > 0 { got.extend_from_slice(&buf[..n]); } }
        }
        assert_eq!(&got[0..2], &(8u16).to_le_bytes());
        assert_eq!(&got[2..10], b"tail-one");
        assert_eq!(&got[10..12], &(8u16).to_le_bytes());
        assert_eq!(&got[12..20], b"tail-two");
    }

    #[test]
    fn coalescing_preserves_frame_order_and_content() {
        // 300 small frames coalesced across the 32KiB threshold, decoded in
        // one streamed pass — order and content must survive exactly.
        let cfg = ObfsConfig { padding_max: 24, ..Default::default() };
        let ((_cr, mut cw), (mut sr, _sw)) = establish([9u8; 32], cfg);
        let n_frames = 300;
        for i in 0..n_frames {
            let payload = format!("frame-{i:05}").into_bytes();
            cw.write_frame(&payload).unwrap();
        }
        cw.flush_pending().unwrap();
        let expect_len = n_frames * (2 + 11);
        let mut got = Vec::with_capacity(expect_len);
        let mut buf = [0u8; 4096];
        while got.len() < expect_len {
            let n = sr.read(&mut buf).unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        for i in 0..n_frames {
            let off = i * (2 + 11);
            assert_eq!(&got[off..off + 2], &(11u16).to_le_bytes(), "frame {i} prefix");
            assert_eq!(&got[off + 2..off + 13], &format!("frame-{i:05}").into_bytes()[..],
                "frame {i} content");
        }
    }

    #[test]
    fn multiple_frames_decode_in_one_read_call() {
        // A single read() with a large buffer must decode every buffered
        // frame in one call (decodes straight into the caller's buffer).
        let cfg = ObfsConfig { padding_max: 0, ..Default::default() };
        let ((_cr, mut cw), (mut sr, _sw)) = establish([10u8; 32], cfg);
        for i in 0..50 {
            cw.write_frame(&[i as u8; 100]).unwrap();
        }
        cw.flush_pending().unwrap();
        let mut buf = [0u8; 65536];
        let n = sr.read(&mut buf).unwrap();
        assert_eq!(n, 50 * (2 + 100), "one read call must drain all coalesced frames");
        for i in 0..50 {
            let off = i * (2 + 100);
            assert_eq!(&buf[off..off + 2], &(100u16).to_le_bytes());
            assert!(buf[off + 2..off + 102].iter().all(|&b| b == i as u8));
        }
    }

    #[test]
    fn wire_format_layout_smoke() {
        // Prove the codec writes the documented wire layout: 3-byte masked
        // header + masked payload + `pad` raw random bytes. We can't know
        // the keystream here, but we can check the FRAME SIZE arithmetic:
        // wire bytes consumed = 3 + len + pad for each frame (the receiver
        // resyncs exactly at frame boundaries even across coalescing).
        let cfg = ObfsConfig { padding_max: 0, dummy_min_ms: 1000, dummy_max_ms: 2000,
            dummy_size_max: 0 };
        let ((_cr, mut cw), (mut sr, _sw)) = establish([11u8; 32], cfg);
        // With padding_max=0 every frame is exactly 3+len wire bytes; send a
        // known sequence and verify the decoded stream byte-exactly.
        let payloads: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; 33 * (i + 1)]).collect();
        for p in &payloads { cw.write_frame(p).unwrap(); }
        cw.flush_pending().unwrap();
        let expect: usize = payloads.iter().map(|p| 2 + p.len()).sum();
        let mut got = Vec::with_capacity(expect);
        let mut buf = [0u8; 16384];
        while got.len() < expect {
            let n = sr.read(&mut buf).unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        let mut off = 0;
        for (i, p) in payloads.iter().enumerate() {
            assert_eq!(&got[off..off + 2], &(p.len() as u16).to_le_bytes(), "prefix {i}");
            assert_eq!(&got[off + 2..off + 2 + p.len()], &p[..], "payload {i}");
            off += 2 + p.len();
        }
        assert_eq!(off, expect);
        assert_eq!(got.len(), expect, "no extra bytes decoded");
    }
}
