//! Stream ID — 32-bit, top 2 bits encode direction/type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u32);
impl StreamId {
    pub fn from_u32(v: u32) -> Self {
        Self(v)
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}
