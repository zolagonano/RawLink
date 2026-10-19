use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    Protocol(String), Crypto(String), Auth(String), Replay(String),
    FlowControl(String), Transport(String), Carrier(CarrierError),
    Timeout(String), ResourceLimit(String), Application(String), Malformed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CarrierError {
    pub carrier: &'static str,
    pub op: &'static str,
    pub interface: Option<String>,
    pub address: Option<String>,
    pub cause: String,
}

impl CarrierError {
    pub fn new(carrier: &'static str, op: &'static str, cause: impl Into<String>) -> Self {
        Self { carrier, op, interface: None, address: None, cause: cause.into() }
    }
    pub fn with_interface(mut self, iface: impl Into<String>) -> Self { self.interface = Some(iface.into()); self }
    pub fn with_address(mut self, addr: impl Into<String>) -> Self { self.address = Some(addr.into()); self }
}

impl fmt::Display for CarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.carrier, self.op)?;
        if let Some(ref i) = self.interface { write!(f, " interface {i}")?; }
        if let Some(ref a) = self.address { write!(f, " {a}")?; }
        write!(f, ": {}", self.cause)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::Crypto(m) => write!(f, "crypto: {m}"),
            Self::Auth(m) => write!(f, "auth: {m}"),
            Self::Replay(m) => write!(f, "replay: {m}"),
            Self::FlowControl(m) => write!(f, "flow: {m}"),
            Self::Transport(m) => write!(f, "transport: {m}"),
            Self::Carrier(c) => write!(f, "{c}"),
            Self::Timeout(m) => write!(f, "timeout: {m}"),
            Self::ResourceLimit(m) => write!(f, "resource: {m}"),
            Self::Application(m) => write!(f, "app: {m}"),
            Self::Malformed(m) => write!(f, "malformed: {m}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self { Self::Carrier(CarrierError::new("?", "io", format!("{e}"))) }
}
impl From<CarrierError> for Error { fn from(c: CarrierError) -> Self { Self::Carrier(c) } }
