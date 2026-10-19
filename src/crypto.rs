//! AES-256-GCM AEAD + HKDF-SHA256 key derivation.
//!
//! `TrafficKey` caches the constructed `Aes256Gcm` cipher so the AES key
//! schedule is expanded ONCE per key instead of once per packet.
use crate::config::{AEAD_KEY_LEN, AEAD_NONCE_LEN};
use crate::error::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, ZeroizeOnDrop)]
pub struct Nonce(pub [u8; AEAD_NONCE_LEN]);
impl Nonce {
    pub fn from_salt_and_pn(salt: &[u8; AEAD_NONCE_LEN], pn: u64) -> Self {
        let mut buf = [0u8; AEAD_NONCE_LEN]; buf.copy_from_slice(salt);
        let pn_bytes = pn.to_le_bytes();
        for i in 0..8 { buf[i] ^= pn_bytes[i]; }
        Self(buf)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction { ClientToServer, ServerToClient }
impl Direction {
    pub fn opposite(self) -> Self {
        match self { Self::ClientToServer => Self::ServerToClient, Self::ServerToClient => Self::ClientToServer }
    }
}
/// A direction's traffic key: raw key + nonce salt + the cached AEAD
/// cipher (key schedule expanded once at construction).
pub struct TrafficKey { key: [u8; AEAD_KEY_LEN], salt: [u8; AEAD_NONCE_LEN], cipher: Aes256Gcm }
impl TrafficKey {
    pub fn from_bytes(key: [u8; AEAD_KEY_LEN], salt: [u8; AEAD_NONCE_LEN]) -> Self {
        let cipher = Aes256Gcm::new((&key).into());
        Self { key, salt, cipher }
    }
    pub fn key(&self) -> &[u8; AEAD_KEY_LEN] { &self.key }
    pub fn salt(&self) -> &[u8; AEAD_NONCE_LEN] { &self.salt }
    pub fn cipher(&self) -> &Aes256Gcm { &self.cipher }
}
impl Clone for TrafficKey {
    fn clone(&self) -> Self { Self::from_bytes(self.key, self.salt) }
}
impl Drop for TrafficKey {
    fn drop(&mut self) { self.key.zeroize(); self.salt.zeroize(); }
}
impl std::fmt::Debug for TrafficKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficKey").field("key", &"[redacted]").field("salt", &"[redacted]").finish()
    }
}
#[derive(Clone)]
pub struct TrafficKeySet { pub c2s: TrafficKey, pub s2c: TrafficKey }
impl TrafficKeySet {
    pub fn for_dir(&self, dir: Direction) -> &TrafficKey {
        match dir { Direction::ClientToServer => &self.c2s, Direction::ServerToClient => &self.s2c }
    }
}
impl std::fmt::Debug for TrafficKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficKeySet").field("c2s", &"<redacted>").field("s2c", &"<redacted>").finish()
    }
}

pub fn derive_keys(session_id: &[u8; 8], psk: &[u8; 32]) -> TrafficKeySet {
    let mut transcript = Vec::with_capacity(24);
    transcript.extend_from_slice(b"rawlink-v05"); transcript.extend_from_slice(session_id);
    let prk = hmac_sha256(b"rawlink-hs-salt", psk);
    let mut prk_arr = [0u8; 32]; prk_arr.copy_from_slice(&prk);
    let c2s_key = expand_label(&prk_arr, "c2s_key_0", &transcript, AEAD_KEY_LEN);
    let c2s_salt = expand_label(&prk_arr, "c2s_nonce_0", &transcript, AEAD_NONCE_LEN);
    let s2c_key = expand_label(&prk_arr, "s2c_key_0", &transcript, AEAD_KEY_LEN);
    let s2c_salt = expand_label(&prk_arr, "s2c_nonce_0", &transcript, AEAD_NONCE_LEN);
    let mut ck = [0u8; AEAD_KEY_LEN]; ck.copy_from_slice(&c2s_key);
    let mut cs = [0u8; AEAD_NONCE_LEN]; cs.copy_from_slice(&c2s_salt);
    let mut sk = [0u8; AEAD_KEY_LEN]; sk.copy_from_slice(&s2c_key);
    let mut ss = [0u8; AEAD_NONCE_LEN]; ss.copy_from_slice(&s2c_salt);
    TrafficKeySet { c2s: TrafficKey::from_bytes(ck, cs), s2c: TrafficKey::from_bytes(sk, ss) }
}
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac}; type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("hmac");
    mac.update(data); mac.finalize().into_bytes().to_vec()
}
fn expand_label(prk: &[u8; 32], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"rl-05"); full_label.extend_from_slice(label.as_bytes());
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8); info.extend_from_slice(&full_label);
    info.push(context.len() as u8); info.extend_from_slice(context);
    let h = Hkdf::<Sha256>::from_prk(prk).expect("hkdf");
    let mut okm = vec![0u8; length];
    h.expand(&info, &mut okm).expect("expand"); okm
}
/// Encrypt with a direction's cached cipher. `aad` is authenticated but
/// not encrypted (the 17-byte packet header).
pub fn encrypt(tk: &TrafficKey, pn: u64, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = Nonce::from_salt_and_pn(tk.salt(), pn);
    tk.cipher().encrypt((&nonce.0).into(), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("AES-256-GCM encrypt failed".into()))
}
/// Decrypt with a direction's cached cipher. Caller is responsible for
/// replay filtering (see `session::replay`).
pub fn decrypt(tk: &TrafficKey, pn: u64, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = Nonce::from_salt_and_pn(tk.salt(), pn);
    tk.cipher().decrypt((&nonce.0).into(), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Crypto("AES-256-GCM authentication failed".into()))
}
