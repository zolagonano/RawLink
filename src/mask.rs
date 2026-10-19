//! Packet-header masking for the TCP carrier.
//!
//! Every packet's 17-byte header — `[version|flags][8-byte session id]
//! [8-byte packet counter]` — is XOR-masked with an XChaCha20 keystream
//! before it hits the wire. The AEAD body was already indistinguishable
//! from random; after this the ENTIRE packet is, byte for byte, uniform
//! random to anyone without the PSK. The mask hides STRUCTURE only —
//! integrity still comes from the inner AES-256-GCM (the header is the
//! AAD, so any middleman bit flip breaks the tag).
//!
//! Key schedule (two phases, to break the chicken-and-egg of the server
//! needing the session id before it can parse the first packet):
//!
//! * **First-flight phase** — the client's very FIRST packet is masked with
//!   keys derived from the PSK alone. The server unmasks it without
//!   knowing the session id, reads the id from the plaintext header, and
//!   derives the session-phase maskers.
//! * **Session phase** — every other packet (both directions) is masked with
//!   keys derived from PSK + session id + direction, so each connection and
//!   direction has an independent keystream. (Without the session id in
//!   the key, the packet-number field is a known plaintext by position —
//!   PN of the k-th packet is k — and a censor could strip the mask and
//!   read the counter pattern again.)
//!
//! Keystream alignment: TCP (and the obfs framing above it) is a reliable
//! ordered byte stream, and each packet carries exactly one 17-byte header.
//! Both sides consume 17 keystream bytes per packet in send/receive order —
//! no length field, no resync. (This guarantee is why the mask lives in the
//! TCP carrier and not in the carrier-agnostic session layer: the simulated
//! test carrier CAN duplicate packets, which no byte-stream transport can.)
//!
//! Threading: the send masker is only used by the session's sender thread
//! (under the carrier's write mutex) and the recv masker only by the recv
//! thread (under the read mutex).

use crate::crypto::Direction;
use chacha20::{Key as ChachaKey, XChaCha20, XNonce};
use cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;

/// Masked header length == `config::HEADER_LEN`.
pub const MASKED_HEADER_LEN: usize = 17;

fn derive(psk: &[u8; 32], sid: Option<&[u8; 8]>, dir: Direction) -> XChaCha20 {
    let mut ikm = Vec::with_capacity(32 + 8);
    ikm.extend_from_slice(psk);
    if let Some(s) = sid { ikm.extend_from_slice(s); }
    let (key_label, nonce_label, salt): (&[u8], &[u8], &[u8]) = match (sid, dir) {
        (None, _) => (
            b"rawlink-v6 first-hdr key",
            b"rawlink-v6 first-hdr nonce",
            b"rawlink-v6/first",
        ),
        (Some(_), Direction::ClientToServer) => (
            b"rawlink-v6 hdr c2s key",
            b"rawlink-v6 hdr c2s nonce",
            b"rawlink-v6/session",
        ),
        (Some(_), Direction::ServerToClient) => (
            b"rawlink-v6 hdr s2c key",
            b"rawlink-v6 hdr s2c nonce",
            b"rawlink-v6/session",
        ),
    };
    let h = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    h.expand(key_label, &mut key).expect("hkdf expand key");
    h.expand(nonce_label, &mut nonce).expect("hkdf expand nonce");
    XChaCha20::new(ChachaKey::from_slice(&key), XNonce::from_slice(&nonce))
}

/// Positionally-consumed XChaCha20 keystream over successive 17-byte headers.
pub struct HeaderMasker {
    cipher: XChaCha20,
    scratch: [u8; MASKED_HEADER_LEN],
}

impl HeaderMasker {
    /// Masker for the client's very first packet (PSK-only derivation).
    pub fn first_flight(psk: &[u8; 32]) -> Self {
        Self { cipher: derive(psk, None, Direction::ClientToServer), scratch: [0u8; MASKED_HEADER_LEN] }
    }
    /// Masker for session-phase packets (PSK + session id + direction).
    pub fn session(psk: &[u8; 32], sid: &[u8; 8], dir: Direction) -> Self {
        Self { cipher: derive(psk, Some(sid), dir), scratch: [0u8; MASKED_HEADER_LEN] }
    }
    /// XOR the next 17 header bytes with the keystream (mask == unmask).
    pub fn apply(&mut self, header: &mut [u8]) {
        assert_eq!(header.len(), MASKED_HEADER_LEN, "header mask length");
        self.scratch.copy_from_slice(&[0u8; MASKED_HEADER_LEN]);
        self.cipher.apply_keystream(&mut self.scratch);
        for (b, k) in header.iter_mut().zip(self.scratch.iter()) {
            *b ^= *k;
        }
    }
}

/// CLIENT send-side masking: packet #1 uses the first-flight mask, every
/// later packet the session c2s mask.
pub struct ClientSendMasker {
    first: Option<HeaderMasker>,
    normal: HeaderMasker,
}

impl ClientSendMasker {
    pub fn new(psk: &[u8; 32], sid: &[u8; 8]) -> Self {
        Self {
            first: Some(HeaderMasker::first_flight(psk)),
            normal: HeaderMasker::session(psk, sid, Direction::ClientToServer),
        }
    }
    /// A client whose packet #1 already went out as handshake early data
    /// (see `session::build_first_packet`): the first-flight phase is
    /// consumed, everything from pn=2 uses the session mask.
    pub fn new_preamble(psk: &[u8; 32], sid: &[u8; 8]) -> Self {
        Self {
            first: None,
            normal: HeaderMasker::session(psk, sid, Direction::ClientToServer),
        }
    }
    pub fn apply(&mut self, header: &mut [u8]) {
        match self.first.take() {
            Some(mut m) => m.apply(header),
            None => self.normal.apply(header),
        }
    }
}

/// CLIENT recv-side masking: the server never uses the first-flight mask,
/// so every received packet uses the session s2c mask.
pub struct ClientRecvMasker {
    normal: HeaderMasker,
}

impl ClientRecvMasker {
    pub fn new(psk: &[u8; 32], sid: &[u8; 8]) -> Self {
        Self { normal: HeaderMasker::session(psk, sid, Direction::ServerToClient) }
    }
    pub fn apply(&mut self, header: &mut [u8]) {
        self.normal.apply(header);
    }
}

/// SERVER recv-side masking: packet #1 arrives under the PSK-only
/// first-flight mask; unmasking it reveals the session id, from which the
/// session-phase c2s mask is derived (and shared with the send side via
/// `sid_cell`).
pub struct ServerRecvMasker {
    first: Option<HeaderMasker>,
    psk: [u8; 32],
    sid_cell: std::sync::Arc<std::sync::Mutex<Option<[u8; 8]>>>,
    normal: Option<HeaderMasker>,
}

impl ServerRecvMasker {
    pub fn new(psk: &[u8; 32], sid_cell: std::sync::Arc<std::sync::Mutex<Option<[u8; 8]>>>) -> Self {
        Self { first: Some(HeaderMasker::first_flight(psk)), psk: *psk, sid_cell, normal: None }
    }
    pub fn apply(&mut self, header: &mut [u8]) {
        if let Some(mut f) = self.first.take() {
            f.apply(header);
            let mut sid = [0u8; 8];
            sid.copy_from_slice(&header[1..9]);
            *self.sid_cell.lock().unwrap() = Some(sid);
            self.normal = Some(HeaderMasker::session(&self.psk, &sid, Direction::ClientToServer));
            return;
        }
        self.normal.as_mut().expect("session mask initialized after first packet").apply(header);
    }
}

/// SERVER send-side masking: the s2c session mask, derived lazily from the
/// session id learned off the first received packet. Sending before any
/// packet was received is a flow violation (admission always reads first)
/// and fails loudly.
pub struct ServerSendMasker {
    psk: [u8; 32],
    sid_cell: std::sync::Arc<std::sync::Mutex<Option<[u8; 8]>>>,
    normal: Option<HeaderMasker>,
}

impl ServerSendMasker {
    pub fn new(psk: &[u8; 32], sid_cell: std::sync::Arc<std::sync::Mutex<Option<[u8; 8]>>>) -> Self {
        Self { psk: *psk, sid_cell, normal: None }
    }
    pub fn apply(&mut self, header: &mut [u8]) -> Result<(), crate::Error> {
        if self.normal.is_none() {
            let sid = self.sid_cell.lock().unwrap()
                .ok_or_else(|| crate::Error::Carrier(crate::error::CarrierError::new(
                    "tcp", "mask", "server sent before the session id was learned")))?
                ;
            self.normal = Some(HeaderMasker::session(&self.psk, &sid, Direction::ServerToClient));
        }
        self.normal.as_mut().unwrap().apply(header);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_roundtrip_both_phases() {
        let psk = [9u8; 32];
        let sid = [7u8; 8];
        let hdr: [u8; 17] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));

        // First flight: mask with one instance, unmask with a fresh one
        // (same PSK => same keystream at position 0).
        let mut a = hdr;
        HeaderMasker::first_flight(&psk).apply(&mut a);
        assert_ne!(a, hdr, "mask must change bytes");
        HeaderMasker::first_flight(&psk).apply(&mut a);
        assert_eq!(a, hdr, "unmask restores header");

        // Session phase, both directions, positions advance
        let mut c = HeaderMasker::session(&psk, &sid, Direction::ClientToServer);
        let mut d = HeaderMasker::session(&psk, &sid, Direction::ClientToServer);
        let mut e = HeaderMasker::session(&psk, &sid, Direction::ServerToClient);
        for i in 0..5 {
            let mut m1 = hdr; m1[0] = 0x30 + i as u8;
            let orig = m1;
            c.apply(&mut m1);
            let masked = m1;
            assert_ne!(masked, orig, "mask must change bytes");
            d.apply(&mut m1);
            assert_eq!(m1, orig, "recv side restores");
            let mut m2 = orig;
            e.apply(&mut m2);
            assert_ne!(m2, masked, "directions must not share keystreams");
        }
    }

    #[test]
    fn different_sessions_different_keystreams() {
        let psk = [1u8; 32];
        let s1 = [1u8; 8]; let s2 = [2u8; 8];
        let hdr = [0x33u8; 17];
        let mut m1 = HeaderMasker::session(&psk, &s1, Direction::ClientToServer);
        let mut m2 = HeaderMasker::session(&psk, &s2, Direction::ClientToServer);
        let mut a = hdr; let mut b = hdr;
        m1.apply(&mut a); m2.apply(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn server_masker_learns_sid_from_first_packet() {
        use std::sync::{Arc, Mutex};
        let psk = [4u8; 32];
        let sid = [0xABu8; 8];
        let cell = Arc::new(Mutex::new(None));
        let mut hdr = [0x30u8; 17];
        hdr[1..9].copy_from_slice(&sid);
        // The client masks its first packet with the first-flight mask.
        let mut sender = HeaderMasker::first_flight(&psk);
        sender.apply(&mut hdr);
        // The server's recv masker unmasks it and adopts the sid.
        let mut recv = ServerRecvMasker::new(&psk, Arc::clone(&cell));
        recv.apply(&mut hdr);
        assert_eq!(&hdr[1..9], &sid, "sid recovered");
        assert_eq!(*cell.lock().unwrap(), Some(sid), "sid shared with send side");
        // Subsequent packets use the session mask and round-trip.
        let mut client = ClientSendMasker::new(&psk, &sid);
        let mut recv2 = ServerRecvMasker::new(&psk, Arc::new(Mutex::new(None)));
        // The first packet's header carries the sid in bytes 1..9 (as on
        // the real wire — the server learns the sid from it).
        let mut p2 = [0x30u8; 17];
        p2[1..9].copy_from_slice(&sid);
        client.apply(&mut p2);       // first-flight
        recv2.apply(&mut p2);        // server unmasks, learns sid
        let orig = [0x31u8; 17];
        let mut p3 = orig;
        client.apply(&mut p3);       // session-phase
        recv2.apply(&mut p3);        // session-phase
        assert_eq!(p3, orig, "session-phase roundtrip");
    }
}
