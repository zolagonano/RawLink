/// Protocol version nibble carried in the first header byte (0x3).
///
/// The censorship-hardening revision (breaking, clean cut): every packet header
/// is XOR-masked on the wire (see `mask.rs`); PING/PONG frames carry random
/// padding and the probe interval is jittered; server admission failure
/// timing is uniform across input classes. A v3 speaker rejects a v2 peer
/// at the version check and vice versa — old deployments must upgrade both
/// ends together.
pub const PROTOCOL_VERSION: u8 = 0x3;
pub const HEADER_LEN: usize = 17;
pub const AEAD_TAG_LEN: usize = 16;
pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const DEFAULT_MSS: usize = 1200;
pub const DEFAULT_MTU: usize = 1500;
pub const MIN_MTU: usize = 1280;
pub const SESSION_ID_LEN: usize = 8;
pub const FRAME_HEADER_LEN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    #[default]
    Balanced,
    LowLatency,
    Throughput,
}
impl TransportMode {
    /// Max data/control frames packed into one carrier packet. Receive
    /// side always accepts up to MAX_FRAMES_PER_PACKET regardless of the
    /// local mode (see session::MAX_FRAMES_PER_PACKET).
    pub fn max_frames_per_packet(self) -> usize {
        match self {
            Self::LowLatency => 8,
            Self::Balanced => 64,
            Self::Throughput => 256,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WindowConfig {
    /// Per-stream SEND-BUFFER cap (bytes of queued-but-unpacked data).
    /// When a stream's send_buf reaches this, drain_stream_commands stops
    /// taking Write commands and the app blocks on Stream::write — this is
    /// the library's app-facing backpressure. Sized for high-BDP paths:
    /// 4 MiB covers a 100 Mbps × 300 ms link entirely inside one stream.
    pub stream_send_window: u64,
}
impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            stream_send_window: 4 << 20,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mtu: usize,
    pub mss: usize,
    pub max_streams_per_session: u32,
    pub mode: TransportMode,
    pub windows: WindowConfig,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            mss: DEFAULT_MSS,
            max_streams_per_session: 256,
            mode: TransportMode::default(),
            windows: WindowConfig::default(),
        }
    }
}
impl Config {
    pub fn payload_capacity(&self) -> usize {
        self.mtu - HEADER_LEN - AEAD_TAG_LEN
    }
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.mtu < MIN_MTU {
            return Err(crate::Error::Malformed("mtu too small".into()));
        }
        // The packet builder sizes DATA chunks against the carrier MTU, but
        // `mss` is used as a per-frame sizing hint; a nonsensical mss (0, or
        // larger than what fits in one packet) would produce packets the
        // carrier refuses to send.
        if self.mss == 0 {
            return Err(crate::Error::Malformed("mss must be > 0".into()));
        }
        if self.mss > self.mtu.saturating_sub(HEADER_LEN + AEAD_TAG_LEN) {
            return Err(crate::Error::Malformed(
                "mss larger than packet payload capacity".into(),
            ));
        }
        if self.max_streams_per_session == 0 {
            return Err(crate::Error::Malformed(
                "max_streams_per_session must be > 0".into(),
            ));
        }
        Ok(())
    }
}
