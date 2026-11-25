//! Scripted transport for tests.

use super::{Tracer, Transport, TransportError};
use std::collections::VecDeque;

type Handler = Box<dyn FnMut(&[u8]) -> Vec<u8>>;

enum Step {
    Exact { apdu: Vec<u8>, response: Vec<u8> },
    Any { response: Vec<u8> },
    Fail(String),
}

/// A transport that replays a script or delegates to a closure acting as a card.
///
/// Script mode: queue steps with [`expect`](Self::expect) / [`reply`](Self::reply); each
/// transmitted APDU consumes one step (an `expect` step fails the call when the APDU differs).
/// Handler mode: [`with_handler`](Self::with_handler) computes every response, which lets a
/// test play the card side of a stateful protocol such as EV2 authentication.
/// Every transmitted APDU is recorded in [`sent`](Self::sent).
pub struct MockTransport {
    atr: Vec<u8>,
    steps: VecDeque<Step>,
    handler: Option<Handler>,
    sent: Vec<Vec<u8>>,
    connected: bool,
    tracer: Tracer,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    pub fn new() -> Self {
        MockTransport {
            atr: vec![0x3B, 0x81, 0x80, 0x01, 0x80, 0x80],
            steps: VecDeque::new(),
            handler: None,
            sent: Vec::new(),
            connected: false,
            tracer: Tracer::default(),
        }
    }

    /// Handler mode: `f` receives each command APDU and returns the full response (data + SW).
    pub fn with_handler(f: impl FnMut(&[u8]) -> Vec<u8> + 'static) -> Self {
        let mut m = Self::new();
        m.handler = Some(Box::new(f));
        m
    }

    pub fn with_atr(mut self, atr: &[u8]) -> Self {
        self.atr = atr.to_vec();
        self
    }

    /// Expect exactly `apdu` next and answer with `response` (data + SW).
    pub fn expect(&mut self, apdu: &[u8], response: &[u8]) -> &mut Self {
        self.steps.push_back(Step::Exact { apdu: apdu.to_vec(), response: response.to_vec() });
        self
    }

    /// Same as [`expect`](Self::expect) with hex strings (spaces allowed). Panics on bad hex.
    pub fn expect_hex(&mut self, apdu: &str, response: &str) -> &mut Self {
        let a = hex_bytes(apdu);
        let r = hex_bytes(response);
        self.expect(&a, &r)
    }

    /// Answer the next APDU, whatever it is.
    pub fn reply(&mut self, response: &[u8]) -> &mut Self {
        self.steps.push_back(Step::Any { response: response.to_vec() });
        self
    }

    /// Make the next transmit fail at transport level.
    pub fn fail_next(&mut self, message: &str) -> &mut Self {
        self.steps.push_back(Step::Fail(message.into()));
        self
    }

    /// All APDUs transmitted so far.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// Scripted steps not consumed yet.
    pub fn remaining(&self) -> usize {
        self.steps.len()
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(clean).expect("valid hex in test script")
}

impl Transport for MockTransport {
    fn name(&self) -> String {
        "Mock transport".into()
    }
    fn connect(&mut self) -> Result<Vec<u8>, TransportError> {
        self.connected = true;
        Ok(self.atr.clone())
    }
    fn disconnect(&mut self) {
        self.connected = false;
    }
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.sent.push(apdu.to_vec());
        if let Some(h) = self.handler.as_mut() {
            return Ok(h(apdu));
        }
        match self.steps.pop_front() {
            None => Err(TransportError::Script(format!("unexpected APDU {}", hex::encode_upper(apdu)))),
            Some(Step::Any { response }) => Ok(response),
            Some(Step::Fail(m)) => Err(TransportError::Transmit { message: m, hint: String::new() }),
            Some(Step::Exact { apdu: want, response }) => {
                if want == apdu {
                    Ok(response)
                } else {
                    Err(TransportError::Script(format!(
                        "expected {} but got {}",
                        hex::encode_upper(&want),
                        hex::encode_upper(apdu)
                    )))
                }
            }
        }
    }
    fn tracer(&mut self) -> &mut Tracer {
        &mut self.tracer
    }
}
