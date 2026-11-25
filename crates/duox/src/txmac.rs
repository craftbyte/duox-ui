//! Transaction MAC and Transaction Signature (data sheet 7.14.3, 7.14.4).
//!
//! * [`session_keys`]: K_SesTMMAC / K_SesTMENC for one transaction,
//! * [`Tmi`]: recorder for the Transaction MAC Input,
//! * [`tmv`], [`verify_tmv`], [`tsv_message`], [`sign_tsv`], [`verify_tsv`]: the final values,
//! * [`decrypt_reader_id`]: TMRIPrev from the EncTMRI returned by CommitReaderID.

use crate::crypto::{self, CryptoError, PrivKey, PubKey};
use thiserror::Error;

/// Errors of the Transaction MAC module.
#[derive(Debug, Error)]
pub enum TxMacError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("Transaction MAC key must be 16 or 32 bytes, got {0}")]
    KeyLength(usize),
}

type Result<T> = std::result::Result<T, TxMacError>;

/// Session keys of one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmSessionKeys {
    /// K_SesTMMAC, used for the Transaction MAC Value.
    pub mac: Vec<u8>,
    /// K_SesTMENC, used for the reader ID encryption.
    pub enc: Vec<u8>,
}

/// Derive `K_SesTMMAC` and `K_SesTMENC` for the transaction that gets counter value `tmc_next`
/// (TMC + 1) on the card with the given `uid` (7.14.3).
pub fn session_keys(tm_key: &[u8], tmc_next: u32, uid: &[u8]) -> Result<TmSessionKeys> {
    let mut ctx = tmc_next.to_le_bytes().to_vec();
    ctx.extend_from_slice(uid);
    let sv = |label: u8, i: u8, len: [u8; 2]| {
        let mut v = vec![label, 0, i, len[0], len[1]];
        v.extend_from_slice(&ctx);
        while v.len() % 16 != 0 {
            v.push(0);
        }
        v
    };
    match tm_key.len() {
        16 => Ok(TmSessionKeys {
            mac: crypto::aes_cmac(tm_key, &sv(0x5A, 1, [0x00, 0x80]))?,
            enc: crypto::aes_cmac(tm_key, &sv(0xA5, 1, [0x00, 0x80]))?,
        }),
        32 => {
            let (mut mac, mut enc) = (Vec::new(), Vec::new());
            for i in [1u8, 2] {
                mac.extend(crypto::aes_cmac(tm_key, &sv(0x5A, i, [0x01, 0x00]))?);
                enc.extend(crypto::aes_cmac(tm_key, &sv(0xA5, i, [0x01, 0x00]))?);
            }
            Ok(TmSessionKeys { mac, enc })
        }
        n => Err(TxMacError::KeyLength(n)),
    }
}

/// Transaction MAC Value: truncated CMAC of the TMI with K_SesTMMAC (8 bytes).
pub fn tmv(tm_key: &[u8], tmc_next: u32, uid: &[u8], tmi: &[u8]) -> Result<Vec<u8>> {
    Ok(crypto::mact(&session_keys(tm_key, tmc_next, uid)?.mac, tmi)?)
}

/// Check a Transaction MAC Value returned by the card.
pub fn verify_tmv(tm_key: &[u8], tmc_next: u32, uid: &[u8], tmi: &[u8], value: &[u8]) -> Result<bool> {
    Ok(tmv(tm_key, tmc_next, uid, tmi)? == value)
}

/// Message signed for a Transaction Signature Value: `TMI || (TMC + 1)` (4 bytes LSB first).
pub fn tsv_message(tmi: &[u8], tmc_next: u32) -> Vec<u8> {
    let mut m = tmi.to_vec();
    m.extend_from_slice(&tmc_next.to_le_bytes());
    m
}

/// Produce a Transaction Signature Value (r || s) as the card does.
pub fn sign_tsv(key: &PrivKey, tmi: &[u8], tmc_next: u32) -> Result<Vec<u8>> {
    Ok(key.sign_raw(&tsv_message(tmi, tmc_next))?)
}

/// Verify a Transaction Signature Value (r || s) with the card's signing public key.
pub fn verify_tsv(pubkey: &PubKey, signature: &[u8], tmi: &[u8], tmc_next: u32) -> bool {
    pubkey.verify_raw(signature, &tsv_message(tmi, tmc_next))
}

/// Decrypt TMRIPrev from the EncTMRI returned by CommitReaderID in the transaction with counter
/// value `tmc_next` (AES-CBC, zero IV, K_SesTMENC).
pub fn decrypt_reader_id(tm_key: &[u8], tmc_next: u32, uid: &[u8], enc_tmri: &[u8]) -> Result<Vec<u8>> {
    let k = session_keys(tm_key, tmc_next, uid)?;
    Ok(crypto::aes_cbc_dec(&k.enc, enc_tmri, &crypto::ZERO_IV)?)
}

fn le3(v: u32) -> [u8; 3] {
    let b = v.to_le_bytes();
    [b[0], b[1], b[2]]
}

/// Transaction MAC Input accumulator (7.14.3). File numbers are given as sent on the wire
/// (including the second-application bit); the exclusion map uses the low five bits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tmi {
    buf: Vec<u8>,
    /// TMIExclFileMap: bit n set excludes file n from the TMI.
    pub excl_map: u32,
}

impl Tmi {
    pub fn new(excl_map: u32) -> Self {
        Tmi { buf: Vec::new(), excl_map }
    }

    /// The recorded input.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    /// Restart recording (new transaction).
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    fn pad(&mut self) {
        while self.buf.len() % 16 != 0 {
            self.buf.push(0);
        }
    }
    fn skip(&self, file_no: u8) -> bool {
        self.excl_map >> (file_no & 0x1F) & 1 == 1
    }
    fn data_op(&mut self, head: &[u8], file_no: u8, data: &[u8]) {
        if self.skip(file_no) {
            return;
        }
        self.buf.extend_from_slice(head);
        self.pad();
        self.buf.extend_from_slice(data);
        self.pad();
    }

    /// ReadData / WriteData: `cmd | file | offset | length`, padded, then the data, padded.
    pub fn data(&mut self, cmd: u8, file_no: u8, offset: u32, data: &[u8]) {
        let mut h = vec![cmd, file_no];
        h.extend_from_slice(&le3(offset));
        h.extend_from_slice(&le3(data.len() as u32));
        self.data_op(&h, file_no, data);
    }

    /// ReadRecords: `cmd | file | first record | count`, padded, then the data, padded.
    pub fn read_records(&mut self, cmd: u8, file_no: u8, rec_no: u32, count: u32, data: &[u8]) {
        let mut h = vec![cmd, file_no];
        h.extend_from_slice(&le3(rec_no));
        h.extend_from_slice(&le3(count));
        self.data_op(&h, file_no, data);
    }

    /// WriteRecord is recorded like ReadData / WriteData (offset within the record).
    pub fn write_record(&mut self, cmd: u8, file_no: u8, offset: u32, data: &[u8]) {
        self.data(cmd, file_no, offset, data);
    }

    /// UpdateRecord: `cmd | file | record | offset | length`, padded, then the data, padded.
    pub fn update_record(&mut self, cmd: u8, file_no: u8, rec_no: u32, offset: u32, data: &[u8]) {
        let mut h = vec![cmd, file_no];
        h.extend_from_slice(&le3(rec_no));
        h.extend_from_slice(&le3(offset));
        h.extend_from_slice(&le3(data.len() as u32));
        self.data_op(&h, file_no, data);
    }

    /// Credit / Debit / LimitedCredit: `cmd | file | value (i32 LSB first)`, padded.
    pub fn value(&mut self, cmd: u8, file_no: u8, value: i32) {
        if self.skip(file_no) {
            return;
        }
        self.buf.push(cmd);
        self.buf.push(file_no);
        self.buf.extend_from_slice(&value.to_le_bytes());
        self.pad();
    }

    /// ClearRecordFile: `cmd | file`, padded.
    pub fn clear_records(&mut self, cmd: u8, file_no: u8) {
        if self.skip(file_no) {
            return;
        }
        self.buf.push(cmd);
        self.buf.push(file_no);
        self.pad();
    }

    /// CommitReaderID (0xC8): `0xC8 | TMRI | EncTMRI`, padded. `enc_tmri` is empty on the reader
    /// side before the card's response is known.
    pub fn commit_reader_id(&mut self, tmri: &[u8], enc_tmri: &[u8]) {
        self.buf.push(0xC8);
        self.buf.extend_from_slice(tmri);
        self.buf.extend_from_slice(enc_tmri);
        self.pad();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: [u8; 7] = [0x04, 0x95, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];

    #[test]
    fn session_keys_layout_and_lengths() {
        let k = session_keys(&[1u8; 16], 3, &UID).unwrap();
        assert_eq!((k.mac.len(), k.enc.len()), (16, 16));
        assert_ne!(k.mac, k.enc);
        // independent re-derivation of the 16-byte vector: 5A 00 01 00 80 || TMC || UID, zero padded
        let mut sv = vec![0x5A, 0, 1, 0, 0x80, 3, 0, 0, 0];
        sv.extend_from_slice(&UID);
        sv.resize(16, 0);
        assert_eq!(k.mac, crypto::aes_cmac(&[1u8; 16], &sv).unwrap());
        let k = session_keys(&[1u8; 32], 3, &UID).unwrap();
        assert_eq!((k.mac.len(), k.enc.len()), (32, 32));
        assert!(matches!(session_keys(&[1u8; 24], 3, &UID), Err(TxMacError::KeyLength(24))));
    }

    #[test]
    fn tmi_layout() {
        let mut t = Tmi::new(0);
        t.data(0xBD, 1, 0, b"hello");
        // header 8 bytes padded to 16, data 5 bytes padded to 16
        assert_eq!(t.len(), 32);
        assert_eq!(&t.as_bytes()[..8], &[0xBD, 1, 0, 0, 0, 5, 0, 0]);
        assert_eq!(&t.as_bytes()[16..21], b"hello");
        t.value(0xDC, 2, -2);
        assert_eq!(&t.as_bytes()[32..38], &[0xDC, 2, 0xFE, 0xFF, 0xFF, 0xFF]);
        assert_eq!(t.len(), 48);
        let mut ex = Tmi::new(1 << 1);
        ex.data(0xBD, 1, 0, b"hello");
        ex.value(0xDC, 1, 5);
        ex.clear_records(0xEB, 0x81);
        assert!(ex.is_empty());
        ex.commit_reader_id(&[1; 16], &[2; 16]);
        assert_eq!(ex.len(), 48);
    }

    #[test]
    fn tmv_tsv_and_reader_id_roundtrip() {
        let key = [9u8; 16];
        let mut t = Tmi::new(0);
        t.data(0x8D, 3, 0, &[1, 2, 3]);
        let v = tmv(&key, 7, &UID, t.as_bytes()).unwrap();
        assert_eq!(v.len(), 8);
        assert!(verify_tmv(&key, 7, &UID, t.as_bytes(), &v).unwrap());
        assert!(!verify_tmv(&key, 8, &UID, t.as_bytes(), &v).unwrap());

        let sk = crypto::gen_key(crypto::CURVE_P256).unwrap();
        let sig = sign_tsv(&sk, t.as_bytes(), 7).unwrap();
        assert!(verify_tsv(&sk.public(), &sig, t.as_bytes(), 7));
        assert!(!verify_tsv(&sk.public(), &sig, t.as_bytes(), 8));

        let ks = session_keys(&key, 7, &UID).unwrap();
        let tmri = [0x5Au8; 16];
        let enc = crypto::aes_cbc_enc(&ks.enc, &tmri, &crypto::ZERO_IV).unwrap();
        assert_eq!(decrypt_reader_id(&key, 7, &UID, &enc).unwrap(), tmri);
    }
}
