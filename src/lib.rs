//! RawLink v0.5 — a reliable, encrypted, multiplexed transport with a
//! pluggable carrier, plus the SOCKS5/TCP-bridge proxy edges.
//!
//! Layer map (WHITEPAPER §4):
//!
//! ```text
//! L4   application edge      socks (client) / server (dial+bridge)
//! L3   session               session — multiplexing, backpressure, keepalive
//! L2.5 codec primitives      packet, frame, crypto, session::replay
//! L2   carrier              carrier — the "dumb pipe" (tcp, sim)
//!      client               TunnelManager — reconnect + scale-out policy
//!      bridge               shared socket ↔ stream pump
//! ```
pub mod bridge;
pub mod carrier;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod mask;
pub mod obfs;
pub mod obfs_ssh;
pub mod packet;
pub mod server;
pub mod session;
pub mod socks;
pub mod stream;

pub use config::Config;
pub use error::Error;
pub use obfs::{ObfsConfig, ObfsMode};
pub use obfs_ssh::SshObfsConfig;
pub use session::{Session, Stream};
