//! Carrier abstraction — sim, tcp. NO UDP fallback, NO custom-IP.
use crate::error::Error;
pub mod sim;
pub mod tcp;
pub use sim::{SimCarrier, SimAddr, SimConfig, LossPattern, DelayPattern};
pub use tcp::{TcpCarrier, TcpAddr, TcpListenerCarrier};

pub trait CarrierAddress: Clone + Send + Sync + 'static {}

pub type CarrierPacket<A> = (A, Vec<u8>);

pub trait Carrier: Send + Sync {
    type Address: CarrierAddress;

    fn send(&self, dst: Self::Address, packet: &[u8]) -> Result<(), Error>;
    fn recv(&self) -> Result<Option<CarrierPacket<Self::Address>>, Error>;
    fn mtu(&self) -> usize;
    fn local_addr(&self) -> Self::Address;

    /// Writer-idle tick: called by the session's WRITER thread whenever the
    /// send queue has been empty for ~100ms (and only then — never during a
    /// burst). This is the ONE place where a carrier may perform
    /// potentially-blocking write work outside `send()`: the writer thread
    /// blocking on a socket write is ordinary TCP backpressure, while the
    /// recv thread blocking would stall packet draining (deadlock class).
    /// Used for dummy (cover) frames and coalesced-write tail flushes.
    ///
    /// (Historical note: a `maintenance()` hook on the recv thread existed
    /// for carriers with internal timers; every implementation ended up a
    /// no-op after write work moved here, so it was removed.)
    fn idle_tick(&self) -> Result<(), Error> {
        Ok(())
    }
}
