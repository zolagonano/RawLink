use crate::error::Error;
use crate::config::FRAME_HEADER_LEN;

/// Draw the next PING/PONG random padding length (0..=48).
fn next_ping_pad() -> usize {
    (rand::RngCore::next_u32(&mut rand::rng()) as usize) % (PING_PAD_MAX + 1)
}

/// Append `n` uniformly random bytes to `out`.
fn push_random(out: &mut Vec<u8>, n: usize) {
    let start = out.len();
    out.resize(start + n, 0);
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut out[start..]);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data(DataFrame), OpenStream(OpenStreamFrame), CloseStream(CloseStreamFrame),
    ResetStream(ResetStreamFrame), OpenTcp(OpenTcpFrame), OpenTcpResponse(OpenTcpResponseFrame),
    ConnectionClose(ConnectionCloseFrame), Ping(PingFrame), Pong(PongFrame),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame { pub stream_id: u32, pub offset: u64, pub payload: Vec<u8> }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenStreamFrame { pub stream_id: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseStreamFrame { pub stream_id: u32, pub final_offset: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamFrame { pub stream_id: u32, pub code: u8, pub final_offset: u64 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTcpFrame { pub stream_id: u32, pub atyp: u8, pub addr: Vec<u8>, pub port: u16 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTcpResponseFrame { pub stream_id: u32, pub status: u8, pub reason: String }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCloseFrame { pub code: u8, pub reason: String }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingFrame { pub echo: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongFrame { pub echo: u64 }

/// Max random padding appended to PING/PONG frames (8..=56-byte body).
/// Breaks the fixed-size heartbeat signature: a keepalive is no longer
/// always exactly 11 wire bytes on the carrier.
pub const PING_PAD_MAX: usize = 48;

impl Frame {
    /// Exact encoded wire length (3-byte header + body). Pure arithmetic —
    /// lets the packet builder do fit checks without allocating/encoding.
    ///
    /// PING/PONG return the WORST-CASE length (8 + PING_PAD_MAX) so the
    /// packer's fit check reserves room for the random padding — the
    /// actual encoded size varies per frame by design.
    pub fn encoded_len(&self) -> usize {
        let body = match self {
            Self::Data(f) => 12 + f.payload.len(),
            Self::OpenStream(_) => 4,
            Self::CloseStream(_) => 12,
            Self::ResetStream(_) => 13,
            Self::OpenTcp(f) => 7 + f.addr.len(),
            Self::OpenTcpResponse(f) => 9 + f.reason.len().min(1024),
            Self::ConnectionClose(f) => 5 + f.reason.len().min(1024),
            Self::Ping(_) | Self::Pong(_) => 8 + PING_PAD_MAX,
        };
        FRAME_HEADER_LEN + body
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }
    /// Append the encoded frame to `out` without intermediate allocations.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let start = out.len();
        match self {
            Self::Data(f) => {
                out.push(0x03);
                out.extend_from_slice(&((12 + f.payload.len()) as u16).to_le_bytes());
                out.extend_from_slice(&f.stream_id.to_le_bytes());
                out.extend_from_slice(&f.offset.to_le_bytes());
                out.extend_from_slice(&f.payload);
            }
            Self::OpenStream(f) => {
                out.push(0x04);
                out.extend_from_slice(&4u16.to_le_bytes());
                out.extend_from_slice(&f.stream_id.to_le_bytes());
            }
            Self::CloseStream(f) => {
                out.push(0x05);
                out.extend_from_slice(&12u16.to_le_bytes());
                out.extend_from_slice(&f.stream_id.to_le_bytes());
                out.extend_from_slice(&f.final_offset.to_le_bytes());
            }
            Self::ResetStream(f) => {
                out.push(0x06);
                out.extend_from_slice(&13u16.to_le_bytes());
                out.extend_from_slice(&f.stream_id.to_le_bytes());
                out.push(f.code);
                out.extend_from_slice(&f.final_offset.to_le_bytes());
            }
            Self::OpenTcp(f) => {
                out.push(0x07);
                out.extend_from_slice(&((5 + f.addr.len() + 2) as u16).to_le_bytes());
                out.extend_from_slice(&f.stream_id.to_le_bytes());
                out.push(f.atyp);
                out.extend_from_slice(&f.addr);
                out.extend_from_slice(&f.port.to_be_bytes());
            }
            Self::OpenTcpResponse(f) => {
                let r = f.reason.as_bytes();
                let rlen = r.len().min(1024);
                out.push(0x08);
                out.extend_from_slice(&((9 + rlen) as u16).to_le_bytes());
                out.extend_from_slice(&f.stream_id.to_le_bytes());
                out.push(f.status);
                out.extend_from_slice(&(rlen as u32).to_le_bytes());
                out.extend_from_slice(&r[..rlen]);
            }
            Self::ConnectionClose(f) => {
                let r = f.reason.as_bytes();
                let rlen = r.len().min(1024);
                out.push(0x09);
                out.extend_from_slice(&((5 + rlen) as u16).to_le_bytes());
                out.push(f.code);
                out.extend_from_slice(&(rlen as u32).to_le_bytes());
                out.extend_from_slice(&r[..rlen]);
            }
            Self::Ping(f) => {
                out.push(0x00);
                let pad = next_ping_pad();
                out.extend_from_slice(&((8 + pad) as u16).to_le_bytes());
                out.extend_from_slice(&f.echo.to_le_bytes());
                // v3: random tail padding (0..=48 B). Receivers must accept
                // any body >= 8 bytes; the first 8 are the echo value.
                push_random(out, pad);
            }
            Self::Pong(f) => {
                out.push(0x01);
                let pad = next_ping_pad();
                out.extend_from_slice(&((8 + pad) as u16).to_le_bytes());
                out.extend_from_slice(&f.echo.to_le_bytes());
                push_random(out, pad);
            }
        }
        // Wire-safety guard: the frame length field is u16 and covers the
        // BODY only. The packet builder caps bodies far below this, so
        // exceeding it is a programming error — fail loudly instead of
        // silently corrupting the byte stream.
        let body_len = out.len() - start - FRAME_HEADER_LEN;
        assert!(body_len <= u16::MAX as usize, "frame body {} exceeds u16 length field", body_len);
    }
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < FRAME_HEADER_LEN { return Err(Error::Malformed("frame header too short".into())); }
        let ty = bytes[0]; let len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
        let total = FRAME_HEADER_LEN.checked_add(len).ok_or(Error::Malformed("frame len overflow".into()))?;
        if bytes.len() < total { return Err(Error::Malformed("frame body too short".into())); }
        let body = &bytes[FRAME_HEADER_LEN..total];
        let frame = match ty {
            0x00 => { if body.len() < 8 { return Err(Error::Malformed("ping".into())); }
                Self::Ping(PingFrame { echo: u64::from_le_bytes(body[..8].try_into().unwrap()) }) }
            0x01 => { if body.len() < 8 { return Err(Error::Malformed("pong".into())); }
                Self::Pong(PongFrame { echo: u64::from_le_bytes(body[..8].try_into().unwrap()) }) },
            0x03 => { if body.len() < 12 { return Err(Error::Malformed("data frame".into())); }
                Self::Data(DataFrame { stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
                    offset: u64::from_le_bytes(body[4..12].try_into().unwrap()), payload: body[12..].to_vec() }) }
            0x04 => { if body.len() != 4 { return Err(Error::Malformed("open_stream".into())); }
                Self::OpenStream(OpenStreamFrame { stream_id: u32::from_le_bytes(body.try_into().unwrap()) }) }
            0x05 => { if body.len() != 12 { return Err(Error::Malformed("close_stream".into())); }
                Self::CloseStream(CloseStreamFrame { stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
                    final_offset: u64::from_le_bytes(body[4..12].try_into().unwrap()) }) }
            0x06 => { if body.len() != 13 { return Err(Error::Malformed("reset_stream".into())); }
                Self::ResetStream(ResetStreamFrame { stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
                    code: body[4], final_offset: u64::from_le_bytes(body[5..13].try_into().unwrap()) }) }
            0x07 => { if body.len() < 7 { return Err(Error::Malformed("open_tcp".into())); }
                let sid = u32::from_le_bytes(body[0..4].try_into().unwrap()); let atyp = body[4];
                let (addr, consumed) = parse_addr(atyp, &body[5..])?;
                let port_offset = 5 + consumed;
                if body.len() < port_offset + 2 { return Err(Error::Malformed("open_tcp port".into())); }
                let port = u16::from_be_bytes([body[port_offset], body[port_offset+1]]);
                Self::OpenTcp(OpenTcpFrame { stream_id: sid, atyp, addr, port }) }
            0x08 => { if body.len() < 9 { return Err(Error::Malformed("open_tcp_resp".into())); }
                let sid = u32::from_le_bytes(body[0..4].try_into().unwrap()); let status = body[4];
                let rlen = u32::from_le_bytes(body[5..9].try_into().unwrap()) as usize;
                if rlen > 1024 { return Err(Error::Malformed("reason too long".into())); }
                if body.len() < 9 + rlen { return Err(Error::Malformed("resp body".into())); }
                Self::OpenTcpResponse(OpenTcpResponseFrame { stream_id: sid, status,
                    reason: String::from_utf8(body[9..9+rlen].to_vec()).map_err(|_| Error::Malformed("utf8".into()))? }) }
            0x09 => { if body.len() < 5 { return Err(Error::Malformed("conn_close".into())); }
                let code = body[0]; let rlen = u32::from_le_bytes(body[1..5].try_into().unwrap()) as usize;
                if rlen > 1024 { return Err(Error::Malformed("reason too long".into())); }
                if body.len() < 5 + rlen { return Err(Error::Malformed("conn_close body".into())); }
                Self::ConnectionClose(ConnectionCloseFrame { code,
                    reason: String::from_utf8(body[5..5+rlen].to_vec()).map_err(|_| Error::Malformed("utf8".into()))? }) }
            _ => return Err(Error::Malformed(format!("unknown frame 0x{ty:02x}"))),
        };
        Ok((frame, total))
    }
    pub fn parse_many(bytes: &[u8], max: usize) -> Result<(Vec<Self>, usize), Error> {
        let mut frames = Vec::new(); let mut consumed = 0;
        while consumed < bytes.len() {
            if frames.len() >= max { return Err(Error::ResourceLimit("too many frames".into())); }
            let (f, n) = Self::parse(&bytes[consumed..])?; frames.push(f); consumed += n;
        }
        Ok((frames, consumed))
    }
}
fn parse_addr(atyp: u8, body: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    match atyp {
        1 => { if body.len() < 4 { return Err(Error::Malformed("ipv4".into())); } Ok((body[0..4].to_vec(), 4)) }
        4 => { if body.len() < 16 { return Err(Error::Malformed("ipv6".into())); } Ok((body[0..16].to_vec(), 16)) }
        3 => { if body.is_empty() { return Err(Error::Malformed("domain".into())); }
            let len = body[0] as usize; if len > 255 || body.len() < 1+len { return Err(Error::Malformed("domain body".into())); }
            Ok((body[0..1+len].to_vec(), 1+len)) }
        _ => Err(Error::Malformed(format!("unknown atyp {atyp}"))),
    }
}
