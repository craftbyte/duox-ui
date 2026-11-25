//! PC/SC transport (cargo feature `pcsc`).
//!
//! Connects in shared mode so other applications keep access to the reader. The protocol can be
//! forced to T=0 or T=1; the default accepts either (Windows drivers such as the OMNIKEY CCID
//! driver pick T=1 for ISO 14443-4 cards). Extended-length APDUs are passed through untouched
//! with a receive buffer large enough for a 64 KiB response; when one fails, the error carries a
//! hint because short-APDU-only readers/drivers are the usual cause.

use super::{is_extended_apdu, Tracer, Transport, TransportError};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

/// Which T= protocol to negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PcscProtocol {
    /// T=0 or T=1, whatever the driver offers.
    #[default]
    Any,
    T0,
    T1,
}

impl PcscProtocol {
    fn flags(self) -> Protocols {
        match self {
            PcscProtocol::Any => Protocols::T0 | Protocols::T1,
            PcscProtocol::T0 => Protocols::T0,
            PcscProtocol::T1 => Protocols::T1,
        }
    }
}

fn service_err(e: pcsc::Error) -> TransportError {
    TransportError::Service(e.to_string())
}

/// Names of the PC/SC readers currently known to the service.
pub fn list_readers() -> Result<Vec<String>, TransportError> {
    let ctx = Context::establish(Scope::User).map_err(service_err)?;
    let readers = ctx.list_readers_owned().map_err(service_err)?;
    Ok(readers.into_iter().map(|r| r.to_string_lossy().into_owned()).collect())
}

/// A card in a PC/SC reader.
pub struct PcscTransport {
    reader: String,
    protocol: PcscProtocol,
    ctx: Option<Context>,
    card: Option<Card>,
    tracer: Tracer,
}

impl PcscTransport {
    pub fn new(reader_name: impl Into<String>) -> Self {
        PcscTransport {
            reader: reader_name.into(),
            protocol: PcscProtocol::Any,
            ctx: None,
            card: None,
            tracer: Tracer::default(),
        }
    }

    pub fn with_protocol(mut self, protocol: PcscProtocol) -> Self {
        self.protocol = protocol;
        self
    }
}

impl Transport for PcscTransport {
    fn name(&self) -> String {
        self.reader.clone()
    }

    fn connect(&mut self) -> Result<Vec<u8>, TransportError> {
        self.disconnect();
        let ctx = Context::establish(Scope::User).map_err(service_err)?;
        let names = ctx.list_readers_owned().map_err(service_err)?;
        let name = names
            .iter()
            .find(|n| n.to_string_lossy() == self.reader)
            .ok_or_else(|| TransportError::ReaderNotFound(self.reader.clone()))?;
        let card = ctx
            .connect(name, ShareMode::Shared, self.protocol.flags())
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let atr = card
            .status2_owned()
            .map(|s| s.atr().to_vec())
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        self.ctx = Some(ctx);
        self.card = Some(card);
        Ok(atr)
    }

    fn disconnect(&mut self) {
        // Reset on disconnect: a DUOX card keeps its authenticated session across PC/SC handles otherwise.
        if let Some(card) = self.card.take() {
            let _ = card.disconnect(pcsc::Disposition::ResetCard);
        }
        self.ctx = None;
    }

    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        let card = self.card.as_ref().ok_or(TransportError::NotConnected)?;
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        match card.transmit(apdu, &mut buf) {
            Ok(r) => Ok(r.to_vec()),
            Err(e) => {
                let hint = if is_extended_apdu(apdu) {
                    " - this APDU uses extended length; the reader and its driver must support it \
                     (needed for certificate-based ECC authentication) and the connection should use T=1"
                } else {
                    ""
                };
                Err(TransportError::Transmit { message: e.to_string(), hint: hint.into() })
            }
        }
    }

    fn tracer(&mut self) -> &mut Tracer {
        &mut self.tracer
    }
}
