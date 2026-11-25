//! A transport wrapper that runs [`Guard::check_wire`] on every command APDU before it reaches the
//! reader. It is the backstop for code that talks to the card without going through the guarded
//! helpers of [`crate::ctx::Ctx`] (the card is reachable through `Deref`).
//!
//! It follows native SelectApplication to know whether the PICC or a suite application is selected;
//! an ISO selection makes the selection unknown.

use crate::guard::{is_suite_aid, Guard, Selection};
use duox::card::Aid;
use duox::transport::{Tracer, Transport, TransportError};

pub struct GuardedTransport<T: Transport> {
    inner: T,
    guard: Guard,
    selected: Selection,
    pending_select: Option<Aid>,
}

impl<T: Transport> GuardedTransport<T> {
    pub fn new(inner: T, guard: Guard) -> Self {
        GuardedTransport { inner, guard, selected: Selection::Picc, pending_select: None }
    }
}

impl<T: Transport> Transport for GuardedTransport<T> {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn connect(&mut self) -> Result<Vec<u8>, TransportError> {
        self.selected = Selection::Picc;
        self.pending_select = None;
        self.inner.connect()
    }

    fn disconnect(&mut self) {
        self.selected = Selection::Picc;
        self.inner.disconnect()
    }

    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        if let Err(v) = self.guard.check_wire(self.selected, apdu) {
            return Err(TransportError::Transmit { message: v.to_string(), hint: String::new() });
        }
        self.pending_select = None;
        let is_native_select = apdu.len() >= 8 && apdu[0] == 0x90 && apdu[1] == 0x5A;
        let is_iso_select = apdu.len() >= 4 && apdu[0] == 0x00 && apdu[1] == 0xA4;
        if is_native_select {
            self.pending_select = Some(Aid::from_bytes(&apdu[5..8]));
        }
        let resp = self.inner.transmit_raw(apdu)?;
        let sw = resp.len().checked_sub(2).map(|n| u16::from_be_bytes([resp[n], resp[n + 1]]));
        if is_native_select {
            // OPERATION_OK or OPERATION_OK_LIM; a failed selection leaves the PICC selected.
            self.selected = match (sw, self.pending_select) {
                (Some(0x9100 | 0x9101), Some(aid)) if is_suite_aid(aid) => Selection::App,
                _ => Selection::Picc,
            };
        } else if is_iso_select {
            self.selected = Selection::Unknown;
        }
        Ok(resp)
    }

    fn tracer(&mut self) -> &mut Tracer {
        self.inner.tracer()
    }
}
