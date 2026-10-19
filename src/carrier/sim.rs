use crate::carrier::{Carrier, CarrierAddress};
use crate::error::Error;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimAddr {
    Client,
    Server,
}
impl CarrierAddress for SimAddr {}

#[derive(Debug, Clone)]
pub enum LossPattern {
    None,
    EveryNth(u32),
    PseudoRandom { seed: u64, mask: u64 },
}
#[derive(Debug, Clone)]
pub enum DelayPattern {
    None,
    Fixed(Duration),
    Variable {
        base: Duration,
        step: Duration,
        modulus: u32,
    },
}
#[derive(Debug, Clone)]
pub struct SimConfig {
    pub mtu: usize,
    pub loss: LossPattern,
    pub delay: DelayPattern,
    pub duplicate: bool,
}
impl Default for SimConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            loss: LossPattern::None,
            delay: DelayPattern::None,
            duplicate: false,
        }
    }
}

struct QueuedPkt {
    from: SimAddr,
    bytes: Vec<u8>,
    deliver_at: Instant,
}
#[derive(Clone)]
pub struct SimCarrier {
    inner: Arc<Mutex<SimInner>>,
}
struct SimInner {
    cfg: SimConfig,
    inbox_c: VecDeque<QueuedPkt>,
    inbox_s: VecDeque<QueuedPkt>,
    sent_c: u64,
    sent_s: u64,
}
impl SimCarrier {
    pub fn new(cfg: SimConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimInner {
                cfg,
                inbox_c: VecDeque::new(),
                inbox_s: VecDeque::new(),
                sent_c: 0,
                sent_s: 0,
            })),
        }
    }
    pub fn clean() -> Self {
        Self::new(SimConfig::default())
    }
    fn should_drop(p: &LossPattern, idx: u64) -> bool {
        match p {
            LossPattern::None => false,
            LossPattern::EveryNth(n) => {
                let n = *n as u64;
                n > 0 && (idx + 1) % n == 0
            }
            LossPattern::PseudoRandom { seed, mask } => {
                let mut h = *seed;
                h = h.wrapping_add(idx);
                h ^= h >> 33;
                h = h.wrapping_mul(0xff51afd7ed55aacb);
                h ^= h >> 33;
                (h & mask) != 0
            }
        }
    }
    fn delay_for(p: &DelayPattern, idx: u64) -> Duration {
        match p {
            DelayPattern::None => Duration::ZERO,
            DelayPattern::Fixed(d) => *d,
            DelayPattern::Variable {
                base,
                step,
                modulus,
            } => {
                let m = (*modulus as u64).max(1);
                *base + (*step * (idx % m) as u32)
            }
        }
    }
}
impl Carrier for SimCarrier {
    type Address = SimAddr;

    fn send(&self, dst: SimAddr, pkt: &[u8]) -> Result<(), Error> {
        let mut g = self.inner.lock().unwrap();
        let from = match dst {
            SimAddr::Client => SimAddr::Server,
            SimAddr::Server => SimAddr::Client,
        };
        let is_c2s = from == SimAddr::Client;
        let idx = if is_c2s { g.sent_c } else { g.sent_s };
        if is_c2s {
            g.sent_c += 1;
        } else {
            g.sent_s += 1;
        }
        if Self::should_drop(&g.cfg.loss, idx) {
            return Ok(());
        }
        let at = Instant::now() + Self::delay_for(&g.cfg.delay, idx);
        let p = QueuedPkt {
            from,
            bytes: pkt.to_vec(),
            deliver_at: at,
        };
        match dst {
            SimAddr::Client => g.inbox_c.push_back(p),
            SimAddr::Server => g.inbox_s.push_back(p),
        }
        if g.cfg.duplicate && idx % 2 == 0 {
            let d = QueuedPkt {
                from,
                bytes: pkt.to_vec(),
                deliver_at: at,
            };
            match dst {
                SimAddr::Client => g.inbox_c.push_back(d),
                SimAddr::Server => g.inbox_s.push_back(d),
            }
        }
        Ok(())
    }
    fn recv(&self) -> Result<Option<(SimAddr, Vec<u8>)>, Error> {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        if let Some(idx) = g.inbox_s.iter().position(|p| p.deliver_at <= now) {
            let p = g.inbox_s.remove(idx).unwrap();
            return Ok(Some((p.from, p.bytes)));
        }
        if let Some(idx) = g.inbox_c.iter().position(|p| p.deliver_at <= now) {
            let p = g.inbox_c.remove(idx).unwrap();
            return Ok(Some((p.from, p.bytes)));
        }
        Ok(None)
    }
    fn mtu(&self) -> usize {
        self.inner.lock().unwrap().cfg.mtu
    }
    fn local_addr(&self) -> SimAddr {
        SimAddr::Server
    }
}
