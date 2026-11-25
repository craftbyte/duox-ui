//! Transactions (7.14): CommitTransaction, AbortTransaction, CommitReaderID and bookkeeping of
//! the Transaction MAC Input (TMI) that the data commands feed into the [`Tmi`] recorder of the
//! `txmac` module. Computing the Transaction MAC / Signature value from a recorded TMI is also
//! the job of `txmac`; pass [`CommitResult::tmi`] to it.

use super::types::*;
use crate::txmac::Tmi;
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Outcome of CommitTransaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitResult {
    /// 0x00, or 0x0C (NO_CHANGES) when there was nothing to commit.
    pub status: u8,
    /// The Transaction MAC Input this reader recorded for the transaction.
    pub tmi: Vec<u8>,
    /// Transaction MAC Counter returned by the card (when requested and a TransactionMAC file exists).
    pub tmc: Option<u32>,
    /// Transaction MAC value (8 bytes) returned by the card.
    pub tmv: Option<Vec<u8>>,
    /// Transaction Signature (64 bytes) returned by the card.
    pub tsv: Option<Vec<u8>>,
}

impl<T: Transport> Card<T> {
    /// Start recording a fresh TMI; `excl_map` replaces the exclusion map when given.
    pub fn new_transaction(&mut self, excl_map: Option<u32>) {
        let m = excl_map.unwrap_or(self.tmi.excl_map);
        self.tmi = Tmi::new(m);
    }

    /// The Transaction MAC Input recorded so far.
    pub fn transaction_input(&self) -> &[u8] {
        self.tmi.as_bytes()
    }

    /// Tell the recorder whether the application holding the TransactionMAC file is the
    /// secondary one of two selected applications.
    pub fn set_tm_secondary(&mut self, secondary: bool) {
        self.tm_secondary = secondary;
    }

    /// The recorder, if `file_no` lives in the application whose transaction is being recorded.
    pub(crate) fn tm_for(&mut self, file_no: u8) -> Option<&mut Tmi> {
        if (file_no & SECOND_APP_BIT != 0) == self.tm_secondary {
            Some(&mut self.tmi)
        } else {
            None
        }
    }

    /// CommitTransaction. With `want_tm` the card also returns TMC and TMV / TSV. The response is
    /// protected in CommMode.MAC whatever the CommMode of the TransactionMAC file is (observed on
    /// silicon with a Full mode file: TMC || TMV || MAC, not encrypted); `tm_mode` is accepted for
    /// API stability and ignored.
    pub fn commit_transaction(&mut self, want_tm: bool, tm_mode: CommMode) -> Result<CommitResult> {
        let _ = tm_mode;
        let mode = CommMode::Mac;
        let opt: &[u8] = if want_tm { &[0x01] } else { &[] };
        let r = self.run(cmd::COMMIT_TRANSACTION, opt, &[], mode, &[0x00, 0x0C])?;
        let d = r.data();
        let mut out = CommitResult {
            status: r.status,
            tmi: self.tmi.as_bytes().to_vec(),
            tmc: None,
            tmv: None,
            tsv: None,
        };
        if d.len() >= 12 {
            out.tmc = Some(le_u32(&d[..4]));
            if d.len() >= 68 {
                out.tsv = Some(d[4..].to_vec());
            } else {
                out.tmv = Some(d[4..].to_vec());
            }
        }
        self.new_transaction(None);
        Ok(out)
    }

    /// AbortTransaction. Returns the native status (0x00 or 0x0C).
    pub fn abort_transaction(&mut self) -> Result<u8> {
        let r = self.run(cmd::ABORT_TRANSACTION, &[], &[], CommMode::Mac, &[0x00, 0x0C])?;
        self.new_transaction(None);
        Ok(r.status)
    }

    /// CommitReaderID. Returns EncTMRI (the previous ReaderID, encrypted) when authenticated.
    pub fn commit_reader_id(&mut self, tmri: &[u8]) -> Result<Vec<u8>> {
        if tmri.len() != 16 {
            return Err(Error::arg("a ReaderID is 16 bytes"));
        }
        let enc = self.command(cmd::COMMIT_READER_ID, &[], tmri, CommMode::Mac)?;
        self.tmi.commit_reader_id(tmri, &enc);
        Ok(enc)
    }
}
