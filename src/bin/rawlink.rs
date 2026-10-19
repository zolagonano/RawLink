//! rawlink CLI — a SOCKS5 front-end (client) and a TCP-bridge back-end
//! (server) around the RawLink protocol.
//!
//!   client:  SOCKS5 listener → TunnelManager (auto-reconnect, auto-scale)
//!            → [optional obfs] → server
//!   server:  carrier listener → admission → session → dial + bridge
//!
//! All actual proxy logic lives in the library (`rawlink::socks`,
//! `rawlink::server`, `rawlink::client`); this file is wiring only.
use clap::{Parser, Subcommand};
use rawlink::carrier::TcpListenerCarrier;
use rawlink::client::{TunnelConfig, TunnelManager};
use rawlink::config::Config;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "rawlink",
    version,
    about = "RawLink encrypted transport + SOCKS5 proxy"
)]
struct Cli {
    #[arg(long, default_value = "info", global = true)]
    log_level: String,
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    Client(ClientArgs),
    Server(ServerArgs),
}

#[derive(clap::Args)]
struct ClientArgs {
    /// Local SOCKS5 listen address (what applications point at).
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks_listen: String,
    /// RawLink server address (the tunnel's other end).
    #[arg(long)]
    server: String,
    /// 32-byte pre-shared key, 64 hex chars.
    #[arg(long)]
    psk: Option<String>,
    #[arg(long, default_value = "balanced")]
    mode: String,
    /// Maximum concurrent SOCKS5 connections. Each holds 2 file descriptors
    /// for its lifetime; the default stays under the common 1024 ulimit.
    #[arg(long, default_value_t = 256)]
    max_conn: u32,
    /// Per-tunnel stream cap. When every tunnel approaches this limit the
    /// client AUTOMATICALLY dials more tunnels (up to --max-tunnels) and
    /// spreads new connections across them, instead of rejecting streams.
    #[arg(long, default_value_t = 256)]
    max_streams: u32,
    /// Maximum parallel tunnels to the server (auto scale-out cap).
    /// 1 = single tunnel.
    #[arg(long, default_value_t = 4)]
    max_tunnels: usize,
    /// Obfuscation layer (MUST match the server). Values:
    ///   rand — high-entropy masking (wire looks like uniform random)
    ///   ssh  — OpenSSH mimicry (looks like an ordinary ssh session)
    ///   off  — plain mode (same as omitting the flag)
    #[arg(long, num_args = 0..=1, default_missing_value = "rand")]
    obfs: Option<String>,
    /// SSH identification string both ends present in obfs ssh mode
    /// (without CRLF). Match an ordinary deployment on your network.
    #[arg(long, default_value = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")]
    ssh_banner: String,
    /// Max random padding per frame in bytes (0-127, default 64).
    #[arg(long, default_value_t = 64)]
    obfs_padding: u8,
    /// Idle interval before a dummy (cover) frame is sent, "min-max" in ms.
    /// Use "off" to disable dummy traffic.
    #[arg(long, default_value = "700-2200")]
    obfs_dummy: String,
    /// Max dummy frame payload in bytes (0-8192, default 384).
    #[arg(long, default_value_t = 384)]
    obfs_dummy_size: u16,
}

#[derive(clap::Args)]
struct ServerArgs {
    /// Listen address for RawLink carrier connections.
    #[arg(long, default_value = "127.0.0.1:6123")]
    listen: String,
    /// 32-byte pre-shared key, 64 hex chars.
    #[arg(long)]
    psk: Option<String>,
    #[arg(long, default_value = "balanced")]
    mode: String,
    /// Per-tunnel (per-session) stream cap. Clients auto-scale out to more
    /// tunnels before hitting this.
    #[arg(long, default_value_t = 256)]
    max_streams: u32,
    /// Obfuscation layer (MUST match the client). Values:
    ///   rand | ssh | off (plain). Connections that fail the obfs
    ///   handshake get the mode's probe response (rand: 40 random bytes;
    ///   ssh: an sshd-style banner+KEXINIT then close) and are closed.
    #[arg(long, num_args = 0..=1, default_missing_value = "rand")]
    obfs: Option<String>,
    /// SSH identification string both ends present in obfs ssh mode
    /// (without CRLF). The server sends it + KEXINIT immediately on
    /// accept, exactly like sshd.
    #[arg(long, default_value = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")]
    ssh_banner: String,
    /// Max random padding per frame in bytes (0-127, default 64).
    #[arg(long, default_value_t = 64)]
    obfs_padding: u8,
    /// Idle interval before a dummy (cover) frame is sent, "min-max" in ms.
    /// Use "off" to disable dummy traffic.
    #[arg(long, default_value = "700-2200")]
    obfs_dummy: String,
    /// Max dummy frame payload in bytes (0-8192, default 384).
    #[arg(long, default_value_t = 384)]
    obfs_dummy_size: u16,
}

const DEV_PSK: [u8; 32] = *b"RawLink dev-psk do not use in!!!";

fn main() {
    let cli = Cli::parse();
    let _ = env_logger::Builder::new()
        .filter_level(match cli.log_level.as_str() {
            "error" => log::LevelFilter::Error,
            "warn" => log::LevelFilter::Warn,
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            _ => log::LevelFilter::Info,
        })
        .format_timestamp_millis()
        .try_init();
    match cli.cmd {
        Cmd::Client(a) => std::process::exit(run_client(a)),
        Cmd::Server(a) => std::process::exit(run_server(a)),
    }
}

// ---------------------------------------------------------------------------
// Shared argument helpers
// ---------------------------------------------------------------------------

fn parse_psk(hex_str: &Option<String>) -> [u8; 32] {
    if let Some(h) = hex_str {
        let mut out = [0u8; 32];
        if h.len() != 64 {
            eprintln!("--psk must be 64 hex chars");
            std::process::exit(2);
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
                eprintln!("bad hex");
                std::process::exit(2)
            });
        }
        out
    } else {
        log::warn!("using dev PSK — DO NOT USE IN PRODUCTION");
        DEV_PSK
    }
}

fn parse_mode(s: &str) -> rawlink::config::TransportMode {
    match s.to_ascii_lowercase().as_str() {
        "low-latency" | "lowlatency" => rawlink::config::TransportMode::LowLatency,
        "throughput" => rawlink::config::TransportMode::Throughput,
        _ => rawlink::config::TransportMode::Balanced,
    }
}

fn build_config(mode: &str, max_streams: u32) -> Config {
    if max_streams == 0 {
        eprintln!("--max-streams must be > 0");
        std::process::exit(2);
    }
    Config {
        mode: parse_mode(mode),
        max_streams_per_session: max_streams,
        ..Default::default()
    }
}

/// Parse `--obfs-dummy "min-max"` (ms) or "off".
fn build_obfs_mode(
    obfs: &Option<String>,
    padding: u8,
    dummy: &str,
    dummy_size: u16,
    ssh_banner: &str,
) -> Result<Option<rawlink::ObfsMode>, String> {
    let Some(obfs) = obfs else { return Ok(None) };
    let mode = obfs.to_ascii_lowercase();
    if mode.is_empty() || mode == "off" || mode == "none" {
        return Ok(None);
    }
    if mode == "ssh" {
        let cfg = rawlink::obfs_ssh::SshObfsConfig {
            banner: ssh_banner.to_string(),
            padding_max: padding,
        };
        cfg.validate()
            .map_err(|e| format!("invalid obfs-ssh config: {e}"))?;
        return Ok(Some(rawlink::ObfsMode::Ssh(cfg)));
    }
    if mode != "rand" {
        return Err(format!(
            "unknown --obfs mode '{obfs}' (expected rand|ssh|off)"
        ));
    }
    let off = dummy.trim().eq_ignore_ascii_case("off");
    let (dmin, dmax) = if off {
        (Ok(700u32), Ok(700u32)) // size 0 below disables dummies
    } else {
        match dummy.split_once('-') {
            Some((a, b)) => (a.trim().parse::<u32>(), b.trim().parse::<u32>()),
            None => {
                let v = dummy
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| "bad --obfs-dummy".to_string())?;
                (Ok(v), Ok(v))
            }
        }
    };
    let dmin = dmin.map_err(|_| "bad --obfs-dummy min".to_string())?;
    let dmax = dmax.map_err(|_| "bad --obfs-dummy max".to_string())?;
    let cfg = rawlink::ObfsConfig {
        padding_max: padding,
        dummy_min_ms: dmin.max(50),
        dummy_max_ms: dmax.max(dmin.max(50)),
        dummy_size_max: if off { 0 } else { dummy_size },
    };
    cfg.validate()
        .map_err(|e| format!("invalid obfs config: {e}"))?;
    Ok(Some(rawlink::ObfsMode::Rand(cfg)))
}

fn parse_addr(s: &str, what: &str) -> SocketAddr {
    match s.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("bad {what}: {s}");
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

fn run_server(args: ServerArgs) -> i32 {
    let psk = parse_psk(&args.psk);
    let config = build_config(&args.mode, args.max_streams);
    let obfs = match build_obfs_mode(
        &args.obfs,
        args.obfs_padding,
        &args.obfs_dummy,
        args.obfs_dummy_size,
        &args.ssh_banner,
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let listen_addr = parse_addr(&args.listen, "--listen");

    let listener = match &obfs {
        Some(m) => TcpListenerCarrier::bind_obfs(listen_addr, &psk, m),
        None => TcpListenerCarrier::bind(listen_addr, &psk),
    };
    let listener = match listener {
        Ok(l) => l,
        Err(e) => {
            log::error!("carrier init failed: {e}");
            return 4;
        }
    };
    match &obfs {
        Some(rawlink::ObfsMode::Ssh(_)) => log::info!(
            "RawLink server listening on {} (tcp carrier, obfs=ssh '{}')",
            listener.local_addr(),
            args.ssh_banner
        ),
        Some(_) => log::info!(
            "RawLink server listening on {} (tcp carrier, obfuscation ON)",
            listener.local_addr()
        ),
        None => log::info!(
            "RawLink server listening on {} (tcp carrier)",
            listener.local_addr()
        ),
    }

    let pending = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let active = Arc::new(std::sync::atomic::AtomicU32::new(0));

    loop {
        let carrier = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("accept: {e}");
                // Backoff: a persistent accept error (EMFILE, hiccup) must
                // not become a hot loop.
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let peer = carrier.remote_addr().to_string();
        if pending.load(std::sync::atomic::Ordering::Relaxed) >= rawlink::server::MAX_PENDING {
            log::warn!(
                "pending limit {} reached, rejecting {}",
                rawlink::server::MAX_PENDING,
                peer
            );
            continue;
        }
        let psk_copy = psk;
        let config_clone = config.clone();
        let p = Arc::clone(&pending);
        let a = Arc::clone(&active);
        if let Err(e) = thread::Builder::new()
            .name(format!("rl-srv-{peer}"))
            .spawn(move || {
                rawlink::server::handle_connection(carrier, peer, psk_copy, config_clone, &p, &a)
            })
        {
            log::error!("spawn session thread: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

fn run_client(args: ClientArgs) -> i32 {
    let psk = parse_psk(&args.psk);
    let config = build_config(&args.mode, args.max_streams);
    let obfs = match build_obfs_mode(
        &args.obfs,
        args.obfs_padding,
        &args.obfs_dummy,
        args.obfs_dummy_size,
        &args.ssh_banner,
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let server_addr = parse_addr(&args.server, "--server");
    let socks_addr = parse_addr(&args.socks_listen, "--socks-listen");

    let listener = match TcpListener::bind(socks_addr) {
        Ok(l) => l,
        Err(e) => {
            log::error!("SOCKS5 bind {socks_addr}: {e}");
            return 3;
        }
    };
    log::info!("SOCKS5 listening on {socks_addr}");

    // The tunnel set: auto-reconnect with backoff, auto scale-out/in.
    let manager = TunnelManager::start(TunnelConfig {
        server: server_addr,
        psk,
        session: config,
        obfs,
        max_tunnels: args.max_tunnels.max(1),
        ..Default::default()
    });
    log::info!(
        "tunnel set: max {} tunnel(s) x {} streams each (auto scale-out)",
        args.max_tunnels.max(1),
        args.max_streams
    );

    // Load shed: each SOCKS5 connection holds 2 fds for its whole lifetime.
    // Without a cap, the fd table fills under load and accept() starts
    // failing with EMFILE — every new connection rejected by the OS.
    let max_conn = args.max_conn;
    let active_conns = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let last_shed_warn = Arc::new(std::sync::Mutex::new(
        Instant::now() - Duration::from_secs(10),
    ));

    for stream in listener.incoming() {
        match stream {
            Ok(io) => {
                // fetch_add admission: overshoot under concurrency is
                // impossible because the increment is atomic.
                let current = active_conns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if current >= max_conn {
                    active_conns.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    // Rate-limited so a connect flood cannot become a log
                    // flood (EMFILE hot-loop lesson).
                    let mut last = last_shed_warn.lock().unwrap();
                    if last.elapsed() > Duration::from_secs(1) {
                        *last = Instant::now();
                        log::warn!(
                            "connection limit {max_conn} reached — shedding new SOCKS5 connections (consider raising --max-conn and ulimit -n)"
                        );
                    }
                    drop(io); // close immediately; peer sees EOF
                    continue;
                }
                let mgr = Arc::clone(&manager);
                let ac = Arc::clone(&active_conns);
                let spawned = thread::Builder::new().name("socks5".into()).spawn(move || {
                    struct DecConn(Arc<std::sync::atomic::AtomicU32>);
                    impl Drop for DecConn {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    let _dec = DecConn(ac);
                    rawlink::socks::serve_connection(io, &mgr);
                });
                if let Err(e) = spawned {
                    active_conns.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    log::error!("spawn socks5 thread: {e}");
                }
            }
            Err(e) => {
                log::warn!("accept: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    0
}
