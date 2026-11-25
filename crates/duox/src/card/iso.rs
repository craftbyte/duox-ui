//! ISO/IEC 7816-4 commands (7.17): ISOSelectFile, ISOReadBinary, ISOUpdateBinary, ISOReadRecord,
//! ISOAppendRecord, ISOGetChallenge and fast confidential UID retrieval from the FCI.
//!
//! These commands are plain, only valid while no authentication is active, and are rejected in an
//! application that holds a TransactionMAC file. Any non-success status ends the tracked session.

use super::secure_messaging::Le;
use super::types::*;
use super::Card;
use crate::crypto::{self};
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Target of ISOSelectFile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoSelect<'a> {
    /// The master file / PICC level (P1 = 00 without data).
    Mf,
    /// Select by file identifier (P1 = 00): MF 3F00, a DF or an EF of the selected application.
    FileId(u16),
    /// An EF below the current DF by its file identifier (P1 = 02).
    EfUnderCurrent(u16),
    /// Application by DF name (P1 = 04).
    DfName(&'a [u8]),
    /// Explicit parameters.
    Raw { p1: u8, p2: u8, data: &'a [u8] },
}

impl IsoSelect<'_> {
    fn parts(&self) -> (u8, u8, Vec<u8>) {
        match *self {
            IsoSelect::Mf => (0x00, 0x00, vec![]),
            IsoSelect::FileId(f) => (0x00, 0x00, f.to_be_bytes().to_vec()),
            IsoSelect::EfUnderCurrent(f) => (0x02, 0x00, f.to_be_bytes().to_vec()),
            IsoSelect::DfName(n) => (0x04, 0x00, n.to_vec()),
            IsoSelect::Raw { p1, p2, data } => (p1, p2, data.to_vec()),
        }
    }
}

/// Result of fast confidential UID retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastUid {
    /// First byte of the decrypted VCData.
    pub info: u8,
    /// Virtual card type identifier (low 6 bits of `info`).
    pub vctid: u8,
    pub pd_cap1: [u8; 2],
    pub uid: Vec<u8>,
}

impl<T: Transport> Card<T> {
    /// ISOSelectFile. Returns `(FCI, SW)` where SW is 9000 or 6283 (limited functionality).
    /// Selecting an MF / DF ends any authentication and transaction.
    pub fn iso_select(&mut self, target: &IsoSelect<'_>) -> Result<(Vec<u8>, u16)> {
        let (p1, p2, data) = target.parts();
        self.log_line(&format!("-- ISOSelectFile P1={p1:02X} {}", hex::encode_upper(&data)));
        let le = if p2 == 0x0C { Le::None } else { Le::Short(0) };
        let (fci, sw) = self.iso_apdu(0x00, 0xA4, p1, p2, &data, le, false)?;
        if sw != 0x9000 && sw != 0x6283 {
            self.drop_session();
            return Err(Error::Iso { command: "ISOSelectFile".into(), sw });
        }
        if p1 != 0x02 {
            self.drop_session();
            self.tmi = Default::default();
            self.selection.secondary = None;
            let picc = matches!(p1, 0x00 | 0x03) && (data.is_empty() || data == [0x3F, 0x00]);
            self.selection.primary = if picc { Some(Aid::PICC) } else { None };
        }
        Ok((fci, sw))
    }

    fn sfi_p1p2(offset: u32, sfi: Option<u8>) -> Result<(u8, u8)> {
        match sfi {
            Some(s) => {
                if offset > 255 {
                    return Err(Error::arg("with a short file ID the offset is limited to 255"));
                }
                Ok((0x80 | (s & 0x1F), offset as u8))
            }
            None => {
                if offset > 0x7FFF {
                    return Err(Error::arg("offset is limited to 32767"));
                }
                Ok(((offset >> 8) as u8, offset as u8))
            }
        }
    }

    pub fn iso_read_binary(&mut self, offset: u32, length: u8, sfi: Option<u8>) -> Result<Vec<u8>> {
        let (p1, p2) = Self::sfi_p1p2(offset, sfi)?;
        self.iso_checked("ISOReadBinary", 0x00, 0xB0, p1, p2, &[], Le::Short(length))
    }

    pub fn iso_update_binary(&mut self, data: &[u8], offset: u32, sfi: Option<u8>) -> Result<()> {
        let (p1, p2) = Self::sfi_p1p2(offset, sfi)?;
        self.iso_checked("ISOUpdateBinary", 0x00, 0xD6, p1, p2, data, Le::None).map(|_| ())
    }

    /// ISOReadRecord. `rec_no` 0 means the current (last written) record; ISO record numbering
    /// differs from the native one (7.17.3.7). `all_from` reads from record `rec_no` up to the *newest*
    /// record (measured: chronological order, oldest first). For a cyclic file ISO record 1 is the
    /// newest, so `rec_no` 1 returns one record and `rec_no` = the record count returns all of them.
    pub fn iso_read_record(&mut self, rec_no: u8, all_from: bool, sfi: u8, length: u8) -> Result<Vec<u8>> {
        let p2 = ((sfi & 0x1F) << 3) | if all_from { 5 } else { 4 };
        self.iso_checked("ISOReadRecord", 0x00, 0xB2, rec_no, p2, &[], Le::Short(length))
    }

    pub fn iso_append_record(&mut self, data: &[u8], sfi: u8) -> Result<()> {
        self.iso_checked("ISOAppendRecord", 0x00, 0xE2, 0x00, (sfi & 0x1F) << 3, data, Le::None).map(|_| ())
    }

    pub fn iso_get_challenge(&mut self, length: u8) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(Error::arg("challenge length must be 1..255"));
        }
        self.iso_checked("ISOGetChallenge", 0x00, 0x84, 0, 0, &[], Le::Short(length))
    }

    /// Decrypt the FCI of an application configured for fast confidential UID retrieval
    /// (7.7.1.3) with AppUIDENCKey. `Ok(None)` if the FCI carries no such data object. Also
    /// remembers the UID for [`Card::uid`].
    pub fn fci_fast_uid(&mut self, fci: &[u8], uid_enc_key: &[u8]) -> Result<Option<FastUid>> {
        let Some(i) = fci.windows(2).position(|w| w == [0x85, 0x20]) else { return Ok(None) };
        let Some(blob) = fci.get(i + 2..i + 34) else { return Ok(None) };
        let (iv, payload) = blob.split_at(16);
        let vc = crypto::aes_cbc_dec(uid_enc_key, payload, iv)?;
        let ulen = match vc[0] >> 6 {
            0 => 7,
            1 => 10,
            2 => 4,
            _ => return Err(Error::protocol("VCData does not decrypt to a plausible value - wrong AppUIDENCKey?")),
        };
        if vc[3 + ulen..].iter().any(|&b| b != 0) {
            return Err(Error::protocol("VCData does not decrypt to a plausible value - wrong AppUIDENCKey?"));
        }
        let uid = vc[3..3 + ulen].to_vec();
        self.uid = uid.clone();
        Ok(Some(FastUid { info: vc[0], vctid: vc[0] & 0x3F, pd_cap1: [vc[1], vc[2]], uid }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn select_wire_and_state() {
        let mut t = MockTransport::new();
        t.expect_hex("00A4040007 D2760000850101 00", "6F00 9000");
        t.expect_hex("00A4000002 3F00 00", "9000");
        t.expect_hex("00A4020002 E101 00", "6283");
        t.expect_hex("00A4000002 1234 00", "6A82");
        let mut card = Card::new(t);
        let (fci, sw) = card.iso_select(&IsoSelect::DfName(&hex::decode("D2760000850101").unwrap())).unwrap();
        assert_eq!((fci, sw), (vec![0x6F, 0x00], 0x9000));
        assert_eq!(card.selection().primary, None);
        card.iso_select(&IsoSelect::FileId(0x3F00)).unwrap();
        assert_eq!(card.selection().primary, Some(Aid::PICC));
        let (_, sw) = card.iso_select(&IsoSelect::EfUnderCurrent(0xE101)).unwrap();
        assert_eq!(sw, 0x6283);
        let e = card.iso_select(&IsoSelect::FileId(0x1234)).unwrap_err();
        assert_eq!(e.iso_sw(), Some(0x6A82));
    }

    #[test]
    fn binary_and_record_commands() {
        let mut t = MockTransport::new();
        t.expect_hex("00B0850510", "AABB9000");
        t.expect_hex("00B0012C00", "9000");
        t.expect_hex("00D6000003 010203", "9000");
        t.expect_hex("00B2010D00", "11 9000");
        t.expect_hex("00E2000802 0A0B", "9000");
        t.expect_hex("00840000 10", "000102030405060708090A0B0C0D0E0F9000");
        let mut card = Card::new(t);
        assert_eq!(card.iso_read_binary(5, 0x10, Some(5)).unwrap(), vec![0xAA, 0xBB]);
        card.iso_read_binary(0x12C, 0, None).unwrap();
        card.iso_update_binary(&[1, 2, 3], 0, None).unwrap();
        assert_eq!(card.iso_read_record(1, true, 1, 0).unwrap(), vec![0x11]);
        card.iso_append_record(&[0x0A, 0x0B], 1).unwrap();
        assert_eq!(card.iso_get_challenge(16).unwrap().len(), 16);
        assert!(card.iso_read_binary(300, 1, Some(1)).is_err());
        assert!(card.iso_get_challenge(0).is_err());
    }

    #[test]
    fn fast_uid_decrypt() {
        let key = [3u8; 16];
        let iv = [9u8; 16];
        let mut vc = vec![0x00 | 0x05, 0xAA, 0xBB];
        vc.extend([1, 2, 3, 4, 5, 6, 7]);
        vc.resize(16, 0);
        let enc = crypto::aes_cbc_enc(&key, &vc, &iv).unwrap();
        let mut fci = vec![0x6F, 0x24, 0x85, 0x20];
        fci.extend(iv);
        fci.extend(enc);
        let mut card = Card::new(MockTransport::new());
        let f = card.fci_fast_uid(&fci, &key).unwrap().unwrap();
        assert_eq!((f.vctid, f.pd_cap1, f.uid.clone()), (5, [0xAA, 0xBB], vec![1, 2, 3, 4, 5, 6, 7]));
        assert_eq!(card.uid(), &f.uid[..]);
        assert!(card.fci_fast_uid(&fci, &[4u8; 16]).is_err());
        assert!(card.fci_fast_uid(&[0x6F, 0x00], &key).unwrap().is_none());
    }
}
