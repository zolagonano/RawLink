use crate::carrier::{Carrier, CarrierAddress};
use crate::error::{CarrierError, Error};
use crate::mask::{ClientRecvMasker, ClientSendMasker, ServerRecvMasker, ServerSendMasker};
use crate::obfs::{self, ObfsMode};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

pub const TCP_MTU: usize = 65535;
/// Outbound TCP connect timeout — without it a black-holed address parks
/// the calling thread for the OS default (~130s) and stalls the client
/// reconnection manager or a server-side dial.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Stack buffer for the length-prefixed single write. A max-size packet
/// is 2 + 65535 bytes; writing prefix and payload as ONE syscall avoids
/// a stray 2-byte segment per packet (extra skb + delayed-ACK interaction
/// with TCP_NODELAY).
const WRITE_BUF: usize = 65537;

/// Read chunk for the receive path. 16KB meant 4+ syscalls to assemble one
/// 64KB packet; 64KB assembles a max-size packet in one read when the data
/// has already arrived.
const RECV_CHUNK: usize = 65536;

fn tune_socket(s: &TcpStream) {
    // SOCKET BUFFERS: deliberately NOT set. Explicit SO_RCVBUF/SO_SNDBUF is
    // silently clamped to net.core.rmem_max/wmem_max on stock kernels AND
    // locks the buffer, disabling TCP autotuning — a clamped receive window
    // collapses multi-stream throughput. The kernel's autotuning adapts to
    // the real path and is strictly better. TCP_NODELAY (set by the caller)
    // plus autotuning is the correct combination for a tunnel like this.
    let _ = s;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpAddr(pub SocketAddr);
impl CarrierAddress for TcpAddr {}

/// Cursor-based receive buffer: compaction happens only when the consumed
/// prefix passes 8KB, so the amortized cost per packet is ~zero.
struct ReadBuffer {
    buf: Vec<u8>,
    pos: usize,
}
impl ReadBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(16384),
            pos: 0,
        }
    }
    fn available(&self) -> usize {
        self.buf.len() - self.pos
    }
    /// Extract the next length-prefixed packet if fully buffered.
    fn take_packet(&mut self, mtu: usize) -> Result<Option<Vec<u8>>, Error> {
        if self.available() < 2 {
            return Ok(None);
        }
        let len = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]) as usize;
        if len > mtu {
            return Err(Error::Carrier(CarrierError::new(
                "tcp",
                "recv",
                format!("declared len {len} > MTU"),
            )));
        }
        if self.available() < 2 + len {
            return Ok(None);
        }
        let pkt = self.buf[self.pos + 2..self.pos + 2 + len].to_vec();
        self.pos += 2 + len;
        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos >= 8192 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        Ok(Some(pkt))
    }
}

/// Packet-header masks (see `mask.rs`): every packet's 17-byte header is
/// XOR-masked before it goes on the wire, keyed by PSK + session id +
/// direction. The SERVER side learns the session id lazily off the first
/// received packet (shared cell), the CLIENT side knows it from dial().
pub(crate) enum SendMask {
    Client(ClientSendMasker),
    Server(ServerSendMasker),
}
impl SendMask {
    fn apply(&mut self, header: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::Client(m) => {
                m.apply(header);
                Ok(())
            }
            Self::Server(m) => m.apply(header),
        }
    }
}
pub(crate) enum RecvMask {
    Client(ClientRecvMasker),
    Server(ServerRecvMasker),
}
impl RecvMask {
    fn apply(&mut self, header: &mut [u8]) {
        match self {
            Self::Client(m) => m.apply(header),
            Self::Server(m) => m.apply(header),
        }
    }
}

/// Read half of the underlying byte stream. `Plain` is the historical
/// path (unchanged semantics); `Obfs` decodes masked frames and
/// yields the SAME `[u16 len][packet]` byte stream to the ReadBuffer, so
/// everything above this layer is identical in all modes.
pub(crate) enum StreamReadHalf {
    Plain(TcpStream, RecvMask),
    Obfs(Box<obfs::ObfReadHalf>, RecvMask),
}
impl StreamReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s, _) => s.read(buf),
            Self::Obfs(o, _) => o.read(buf),
        }
    }
    /// Unmask one extracted packet header.
    fn unmask(&mut self, header: &mut [u8]) {
        match self {
            Self::Plain(_, m) | Self::Obfs(_, m) => m.apply(header),
        }
    }
}

/// Write half. `Plain` writes the historical `[u16 len][pkt]` framing;
/// `Obfs` replaces it on the wire with masked framing and re-adds the
/// prefix on the receive side.
pub(crate) enum StreamWriteHalf {
    Plain(TcpStream, SendMask),
    Obfs(Box<obfs::ObfWriteHalf>, SendMask),
}
impl StreamWriteHalf {
    fn write_frame(&mut self, pkt: &[u8]) -> std::io::Result<()> {
        // The packet header is masked first (in a scratch copy — the
        // caller's packet is immutable). Plain mode folds this into its
        // single stack-copy write; obfs modes use the two-slice frame API.
        debug_assert!(pkt.len() >= crate::config::HEADER_LEN);
        match self {
            Self::Plain(s, mask) => {
                // ONE write syscall for any packet size: prefix + payload
                // leave together, so no stray 2-byte segment rides in front
                // of every packet (an extra skb per packet and a delayed-ACK
                // interaction under TCP_NODELAY).
                debug_assert!(pkt.len() + 2 <= WRITE_BUF);
                let mut buf = [0u8; WRITE_BUF];
                buf[..2].copy_from_slice(&(pkt.len() as u16).to_le_bytes());
                buf[2..2 + pkt.len()].copy_from_slice(pkt);
                if let Err(e) = mask.apply(&mut buf[2..2 + crate::config::HEADER_LEN]) {
                    return Err(io_error(e));
                }
                s.write_all(&buf[..2 + pkt.len()])
            }
            Self::Obfs(o, mask) => {
                let mut hdr = [0u8; crate::config::HEADER_LEN];
                hdr.copy_from_slice(&pkt[..crate::config::HEADER_LEN]);
                if let Err(e) = mask.apply(&mut hdr) {
                    return Err(io_error(e));
                }
                o.write_frame2(&hdr, &pkt[crate::config::HEADER_LEN..])
            }
        }
    }
    fn maybe_send_dummy(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(..) => Ok(()),
            Self::Obfs(o, _) => o.maybe_send_dummy(),
        }
    }
}

/// Map a library error into an io error with the right flavor.
fn io_error(e: Error) -> std::io::Error {
    std::io::Error::other(format!("{e}"))
}

pub struct TcpCarrier {
    /// Separate mutexes for read and write halves: with a single
    /// `Mutex<TcpStream>`, the writer's write_all() can block (up to the 30s
    /// SO_SNDTIMEO) holding the lock, preventing the recv_loop from calling
    /// read() — a bilateral deadlock under heavy traffic. try_clone() gives
    /// two independent handles to the same full-duplex socket.
    read_stream: Mutex<StreamReadHalf>,
    write_stream: Mutex<StreamWriteHalf>,
    local: TcpAddr,
    remote: TcpAddr,
    mtu: usize,
    read_buf: Mutex<ReadBuffer>,
    eof: std::sync::atomic::AtomicBool,
}

impl TcpCarrier {
    /// Plain connect with header masking. `sid` is the session id the
    /// session above WILL use (the mask keys depend on it — the client
    /// generates the id before dialing; see `client::dial`).
    pub fn connect(remote: SocketAddr, psk: &[u8; 32], sid: &[u8; 8]) -> Result<Self, Error> {
        let s = TcpStream::connect_timeout(&remote, CONNECT_TIMEOUT).map_err(|e| {
            Error::Carrier(CarrierError::new(
                "tcp",
                "connect",
                format!("TCP connect to {remote} failed: {e}"),
            ))
        })?;
        self_from_connected(s, remote, *psk, None, Some(*sid), None)
    }
    /// Connect with the obfuscation layer enabled (client role).
    pub fn connect_obfs(
        remote: SocketAddr,
        psk: &[u8; 32],
        sid: &[u8; 8],
        mode: &ObfsMode,
    ) -> Result<Self, Error> {
        let s = TcpStream::connect_timeout(&remote, CONNECT_TIMEOUT).map_err(|e| {
            Error::Carrier(CarrierError::new(
                "tcp",
                "connect",
                format!("TCP connect to {remote} failed: {e}"),
            ))
        })?;
        self_from_connected(s, remote, *psk, Some(mode.clone()), Some(*sid), None)
    }
    /// Connect with the SSH-mimicry layer and post-NEWKEYS early data:
    /// `early` is the first-flight-masked RawLink hello that rides the
    /// client's NEWKEYS flight (one RTT after the emulated DH exchange —
    /// the earliest point a real SSH client could send data).
    pub fn connect_obfs_ssh_early(
        remote: SocketAddr,
        psk: &[u8; 32],
        cfg: &crate::obfs_ssh::SshObfsConfig,
        early: &[u8],
        sid: &[u8; 8],
    ) -> Result<Self, Error> {
        let s = TcpStream::connect_timeout(&remote, CONNECT_TIMEOUT).map_err(|e| {
            Error::Carrier(CarrierError::new(
                "tcp",
                "connect",
                format!("TCP connect to {remote} failed: {e}"),
            ))
        })?;
        self_from_connected(
            s,
            remote,
            *psk,
            Some(ObfsMode::Ssh(cfg.clone())),
            Some(*sid),
            Some(early.to_vec()),
        )
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote.0
    }
    fn mark_eof(&self) {
        self.eof.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Shared constructor body for every connect/accept path. `client_ctx`
/// (PSK + session id) is present for CLIENT dials — the server side learns
/// the session id lazily off the first received packet (see `mask.rs`).
fn self_from_connected(
    s: TcpStream,
    remote: SocketAddr,
    psk: [u8; 32],
    obfs: Option<ObfsMode>,
    client_sid: Option<[u8; 8]>,
    early: Option<Vec<u8>>,
) -> Result<TcpCarrier, Error> {
    let local = s
        .local_addr()
        .map_err(|e| Error::Carrier(CarrierError::new("tcp", "local_addr", format!("{e}"))))?;
    s.set_nodelay(true).ok();
    // Deep kernel buffers FIRST — the whole pipeline's throughput
    // depends on how much data can be in flight while the receiver's
    // event loop is between polls.
    tune_socket(&s);
    // WRITE TIMEOUT: prevents the writer thread from blocking
    // forever in write_all() when the peer stops reading. Without
    // this, a slow/dead peer causes the writer to block, which
    // fills the send_queue, which blocks the recv_loop, which
    // prevents carrier.recv() from draining, which eventually
    // kills the session via carrier timeout.
    s.set_write_timeout(Some(Duration::from_secs(30))).ok();
    // ---- header masks ----
    let (send_mask, recv_mask) = match client_sid {
        Some(sid) => (
            if early.is_some() {
                SendMask::Client(ClientSendMasker::new_preamble(&psk, &sid))
            } else {
                SendMask::Client(ClientSendMasker::new(&psk, &sid))
            },
            RecvMask::Client(ClientRecvMasker::new(&psk, &sid)),
        ),
        None => {
            let sid_cell: std::sync::Arc<std::sync::Mutex<Option<[u8; 8]>>> =
                std::sync::Arc::new(std::sync::Mutex::new(None));
            (
                SendMask::Server(ServerSendMasker::new(&psk, sid_cell.clone())),
                RecvMask::Server(ServerRecvMasker::new(&psk, sid_cell)),
            )
        }
    };
    let (read_half, write_half) = match obfs {
        None => {
            s.set_read_timeout(Some(Duration::from_millis(5))).ok();
            let write_stream = s
                .try_clone()
                .map_err(|e| Error::Carrier(CarrierError::new("tcp", "clone", format!("{e}"))))?;
            (
                StreamReadHalf::Plain(s, recv_mask),
                StreamWriteHalf::Plain(write_stream, send_mask),
            )
        }
        Some(mode) => {
            // The obfs handshake runs with its own 10s deadlines (set
            // inside the handshake functions); the data-phase 5ms poll
            // timeout is restored afterwards on the read half.
            match mode {
                ObfsMode::Rand(cfg) => {
                    let (rh, wh) = if client_sid.is_some() {
                        obfs::client_handshake(s, &psk, &cfg)?
                    } else {
                        obfs::server_handshake(s, &psk, &cfg)?
                    };
                    rh.set_data_read_timeout(Duration::from_millis(5));
                    (
                        StreamReadHalf::Obfs(Box::new(rh), recv_mask),
                        StreamWriteHalf::Obfs(Box::new(wh), send_mask),
                    )
                }
                // The SSH mode's data phase IS the rand codec (masked
                // framing) with keys derived from the emulated DH exchange —
                // on the wire: uniform random bytes, i.e. encrypted SSH.
                ObfsMode::Ssh(cfg) => {
                    let (rh, wh) = if client_sid.is_some() {
                        crate::obfs_ssh::client_handshake(s, &psk, &cfg, early.as_deref())?
                    } else {
                        crate::obfs_ssh::server_handshake(s, &psk, &cfg)?
                    };
                    rh.set_data_read_timeout(Duration::from_millis(5));
                    (
                        StreamReadHalf::Obfs(Box::new(rh), recv_mask),
                        StreamWriteHalf::Obfs(Box::new(wh), send_mask),
                    )
                }
            }
        }
    };
    Ok(TcpCarrier {
        read_stream: Mutex::new(read_half),
        write_stream: Mutex::new(write_half),
        local: TcpAddr(local),
        remote: TcpAddr(remote),
        mtu: TCP_MTU,
        read_buf: Mutex::new(ReadBuffer::new()),
        eof: std::sync::atomic::AtomicBool::new(false),
    })
}

impl Carrier for TcpCarrier {
    type Address = TcpAddr;

    fn send(&self, _dst: TcpAddr, pkt: &[u8]) -> Result<(), Error> {
        if self.eof.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Carrier(CarrierError::new(
                "tcp",
                "send",
                "EOF: peer closed connection",
            )));
        }
        if pkt.len() > self.mtu {
            return Err(Error::Carrier(CarrierError::new(
                "tcp",
                "send",
                format!("pkt too large: {}", pkt.len()),
            )));
        }
        // Use write_stream (separate from read_stream) so the recv_loop
        // can read concurrently even when we're blocked on write_all.
        let write_res = self.write_stream.lock().unwrap().write_frame(pkt);
        match write_res {
            Ok(_) => Ok(()),
            Err(e) => {
                use std::io::ErrorKind as K;
                match e.kind() {
                    K::BrokenPipe | K::ConnectionReset | K::ConnectionAborted | K::NotConnected => {
                        self.mark_eof();
                        Err(Error::Carrier(CarrierError::new(
                            "tcp",
                            "write",
                            format!("{e}"),
                        )))
                    }
                    K::TimedOut | K::WouldBlock => {
                        log::warn!("tcp: write timeout after 30s (peer not draining), marking EOF");
                        self.mark_eof();
                        Err(Error::Carrier(CarrierError::new(
                            "tcp",
                            "write",
                            format!("{e}"),
                        )))
                    }
                    _ => Err(Error::Carrier(CarrierError::new(
                        "tcp",
                        "write",
                        format!("{e}"),
                    ))),
                }
            }
        }
    }
    fn recv(&self) -> Result<Option<(TcpAddr, Vec<u8>)>, Error> {
        if self.eof.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Carrier(CarrierError::new(
                "tcp",
                "read",
                "EOF: peer closed connection",
            )));
        }
        let mut rb = self.read_buf.lock().unwrap();
        loop {
            if let Some(mut pkt) = rb.take_packet(self.mtu)? {
                // Unmask the packet header (position-based, see mask.rs).
                if pkt.len() >= crate::config::HEADER_LEN {
                    self.read_stream
                        .lock()
                        .unwrap()
                        .unmask(&mut pkt[..crate::config::HEADER_LEN]);
                }
                return Ok(Some((self.remote, pkt)));
            }
            let mut tmp = [0u8; RECV_CHUNK];
            // Use read_stream (separate from write_stream) so the
            // writer's write_all doesn't block us.
            let read_res = self.read_stream.lock().unwrap().read(&mut tmp);
            match read_res {
                Ok(0) => {
                    self.mark_eof();
                    return Err(Error::Carrier(CarrierError::new(
                        "tcp",
                        "read",
                        "EOF: peer closed connection",
                    )));
                }
                Ok(n) => rb.buf.extend_from_slice(&tmp[..n]),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        return Ok(None);
                    }
                    std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected => {
                        return Err(Error::Carrier(CarrierError::new(
                            "tcp",
                            "read",
                            format!("{e}"),
                        )));
                    }
                    _ => {
                        return Err(Error::Carrier(CarrierError::new(
                            "tcp",
                            "read",
                            format!("{e}"),
                        )));
                    }
                },
            }
        }
    }
    fn mtu(&self) -> usize {
        self.mtu
    }
    fn local_addr(&self) -> TcpAddr {
        self.local
    }

    /// Writer-idle tick (~every 100ms with an empty send queue): dummy cover
    /// frames + coalescing tail flush, on the WRITER thread where blocking
    /// is safe. Runs under the full write lock — the only competitors are
    /// send() on this same thread, so the lock is uncontended.
    ///
    /// (The recv thread performs NO socket writes, by design: a blocked
    /// recv thread stops reading, which under bidirectional backpressure
    /// deadlocks both peers — the class the separate read/write mutexes
    /// exist to prevent. A writer blocking on write_all is ordinary TCP
    /// backpressure and is safe.)
    fn idle_tick(&self) -> Result<(), Error> {
        let res = self.write_stream.lock().unwrap().maybe_send_dummy();
        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                use std::io::ErrorKind as K;
                match e.kind() {
                    K::BrokenPipe
                    | K::ConnectionReset
                    | K::ConnectionAborted
                    | K::NotConnected
                    | K::TimedOut
                    | K::WouldBlock => self.mark_eof(),
                    _ => {}
                }
                Err(Error::Carrier(CarrierError::new(
                    "tcp",
                    "idle_tick",
                    format!("{e}"),
                )))
            }
        }
    }
}

pub struct TcpListenerCarrier {
    listener: TcpListener,
    local: TcpAddr,
    /// PSK used for the header masks on every accepted connection (and
    /// by the obfs handshake when enabled).
    psk: [u8; 32],
    /// When set, every accepted connection must complete the obfs
    /// handshake (server role) before becoming a carrier. Mismatched
    /// peers (plain clients, scanners, probes) get the mode's uniform
    /// probe response (rand: 40 random bytes; ssh: an sshd-style
    /// banner+KEXINIT then close) and are dropped.
    obfs: Option<ObfsMode>,
}
impl TcpListenerCarrier {
    /// Plain bind with header masking (the PSK feeds the mask keys).
    pub fn bind(addr: SocketAddr, psk: &[u8; 32]) -> Result<Self, Error> {
        Self::bind_inner(addr, (*psk, None))
    }
    /// Bind with the obfuscation layer required for all incoming
    /// connections. `psk` is the same pre-shared key the session uses;
    /// the obfs handshake keys are derived from it (domain-separated
    /// labels, see obfs::obfs_prk / obfs_ssh::ssh_prk).
    pub fn bind_obfs(addr: SocketAddr, psk: &[u8; 32], mode: &ObfsMode) -> Result<Self, Error> {
        match mode {
            ObfsMode::Rand(cfg) => cfg.validate()?,
            ObfsMode::Ssh(cfg) => cfg.validate()?,
        }
        Self::bind_inner(addr, (*psk, Some(mode.clone())))
    }
    fn bind_inner(addr: SocketAddr, args: ([u8; 32], Option<ObfsMode>)) -> Result<Self, Error> {
        let l = TcpListener::bind(addr).map_err(|e| {
            Error::Carrier(CarrierError::new(
                "tcp",
                "bind",
                format!("bind to {addr} failed: {e}"),
            ))
        })?;
        let local = l.local_addr().map_err(|e| {
            Error::Carrier(CarrierError::new("tcp", "bind", format!("local_addr: {e}")))
        })?;
        let (psk, obfs) = args;
        Ok(Self {
            listener: l,
            local: TcpAddr(local),
            psk,
            obfs,
        })
    }
    pub fn accept(&self) -> Result<TcpCarrier, Error> {
        let (s, _peer) = self
            .listener
            .accept()
            .map_err(|e| Error::Carrier(CarrierError::new("tcp", "accept", format!("{e}"))))?;
        let remote = s
            .peer_addr()
            .map_err(|e| Error::Carrier(CarrierError::new("tcp", "peer_addr", format!("{e}"))))?;
        let obfs = self.obfs.clone();
        self_from_connected(s, remote, self.psk, obfs, None, None)
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local.0
    }
}
