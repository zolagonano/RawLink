use crate::config::{HEADER_LEN, PROTOCOL_VERSION};
use crate::error::Error;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader { pub key_phase: bool, pub session_id: u64, pub packet_number: u64 }
impl PacketHeader {
    pub fn new(session_id: u64, pn: u64, kp: bool) -> Self { Self { key_phase: kp, session_id, packet_number: pn } }
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = (PROTOCOL_VERSION << 4) | ((self.key_phase as u8) << 3);
        b[1..9].copy_from_slice(&self.session_id.to_le_bytes());
        b[9..17].copy_from_slice(&self.packet_number.to_le_bytes()); b
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN { return Err(Error::Malformed("header too short".into())); }
        let f = bytes[0];
        if (f >> 4) & 0xF != PROTOCOL_VERSION { return Err(Error::Malformed("bad version".into())); }
        if f & 0x07 != 0 { return Err(Error::Malformed("reserved bits".into())); }
        Ok(Self { key_phase: (f & 0x08) != 0,
            session_id: u64::from_le_bytes(bytes[1..9].try_into().unwrap()),
            packet_number: u64::from_le_bytes(bytes[9..17].try_into().unwrap()) })
    }
}
