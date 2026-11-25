//! APDU transport abstraction.
//!
//! A [`Transport`] moves one command APDU to the card and returns the response with the status
//! word still attached. Everything above (native command wrapping, secure messaging, chaining)
//! lives in [`crate::card`]. Implementations:
//!
//! * `PcscTransport` (cargo feature `pcsc`) - a real reader through the OS smart card service,
//! * [`MockTransport`] - scripted replies for tests.
//!
//! Every transport owns a [`Tracer`]; the UI installs a hook with [`Transport::set_trace`] to
//! see each APDU in both directions (for a log pane). The hook sees the raw bytes on the wire,
//! which for authenticated commands are ciphertext and MACs - key material never passes
//! through here.

mod mock;
#[cfg(feature = "pcsc")]
mod pcsc_impl;

pub use mock::MockTransport;
#[cfg(feature = "pcsc")]
pub use pcsc_impl::{list_readers, PcscProtocol, PcscTransport};

/// Direction of a traced APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDir {
    /// Command APDU, reader to card.
    Tx,
    /// Response APDU including SW1 SW2, card to reader.
    Rx,
}

/// Callback receiving every APDU.
pub type TraceHook = Box<dyn FnMut(TraceDir, &[u8]) + Send>;

/// Holder for the optional trace hook; embed one in every transport.
#[derive(Default)]
pub struct Tracer {
    hook: Option<TraceHook>,
}

impl Tracer {
    pub fn set(&mut self, hook: Option<TraceHook>) {
        self.hook = hook;
    }
    pub fn emit(&mut self, dir: TraceDir, bytes: &[u8]) {
        if let Some(h) = self.hook.as_mut() {
            h(dir, bytes);
        }
    }
}

impl std::fmt::Debug for Tracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tracer({})", if self.hook.is_some() { "set" } else { "unset" })
    }
}

/// Transport level failures.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("not connected")]
    NotConnected,
    #[error("cannot connect to card: {0}")]
    Connect(String),
    #[error("reader not found: {0}")]
    ReaderNotFound(String),
    #[error("PC/SC service unavailable: {0}")]
    Service(String),
    #[error("transmit failed: {message}{hint}")]
    Transmit { message: String, hint: String },
    #[error("response shorter than a status word")]
    ShortResponse,
    #[error("mock transport: {0}")]
    Script(String),
}

/// Synchronous APDU channel to one card.
pub trait Transport {
    /// Human readable name (reader name).
    fn name(&self) -> String;
    /// Power the card / open the connection. Returns the ATR.
    fn connect(&mut self) -> Result<Vec<u8>, TransportError>;
    fn disconnect(&mut self);
    /// Send one APDU and return the complete response (data followed by SW1 SW2).
    /// Implementations do not trace; [`Transport::transmit`] does.
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn tracer(&mut self) -> &mut Tracer;

    /// Install (or remove) the APDU trace hook.
    fn set_trace(&mut self, hook: Option<TraceHook>) {
        self.tracer().set(hook);
    }

    /// Send an APDU, tracing both directions, and split off the status word.
    fn transmit(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        self.tracer().emit(TraceDir::Tx, apdu);
        let resp = self.transmit_raw(apdu)?;
        self.tracer().emit(TraceDir::Rx, &resp);
        if resp.len() < 2 {
            return Err(TransportError::ShortResponse);
        }
        let n = resp.len();
        let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
        Ok((resp[..n - 2].to_vec(), sw))
    }
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn name(&self) -> String {
        (**self).name()
    }
    fn connect(&mut self) -> Result<Vec<u8>, TransportError> {
        (**self).connect()
    }
    fn disconnect(&mut self) {
        (**self).disconnect()
    }
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        (**self).transmit_raw(apdu)
    }
    fn tracer(&mut self) -> &mut Tracer {
        (**self).tracer()
    }
    fn set_trace(&mut self, hook: Option<TraceHook>) {
        (**self).set_trace(hook)
    }
    fn transmit(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        (**self).transmit(apdu)
    }
}

/// True if the APDU uses extended length (Lc/Le coding with a leading zero byte).
pub fn is_extended_apdu(apdu: &[u8]) -> bool {
    apdu.len() > 261 || (apdu.len() > 7 && apdu[4] == 0)
}
