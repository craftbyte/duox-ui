//! Data commands (7.13): ReadData, WriteData, value operations, record operations and the
//! certificate file helpers. Every command comes with its CommMode chosen from the file settings
//! unless the caller says otherwise ([`ModeSel`]); Transaction MAC Input is recorded for each.

use super::files::FileSettings;
use super::types::*;
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// How the communication mode of a data command is determined.
#[derive(Debug, Clone, Copy)]
pub enum ModeSel<'a> {
    /// Fetch the file settings first (one extra GetFileSettings).
    Auto,
    /// Derive the mode from cached file settings.
    File(&'a FileSettings),
    /// Use this mode.
    Explicit(CommMode),
}

impl From<CommMode> for ModeSel<'_> {
    fn from(m: CommMode) -> Self {
        ModeSel::Explicit(m)
    }
}
impl<'a> From<&'a FileSettings> for ModeSel<'a> {
    fn from(f: &'a FileSettings) -> Self {
        ModeSel::File(f)
    }
}

fn is_tmac(fs: &Option<FileSettings>) -> bool {
    matches!(fs, Some(f) if f.file_type == FileType::TransactionMac)
}

impl<T: Transport> Card<T> {
    /// Resolve the CommMode, returning the file settings if they were consulted.
    fn resolve_mode(&mut self, file_no: u8, sel: ModeSel<'_>, write: bool) -> Result<(CommMode, Option<FileSettings>)> {
        Ok(match sel {
            ModeSel::Explicit(m) => (m, None),
            ModeSel::File(f) => (self.file_comm_mode(f, write), Some(f.clone())),
            ModeSel::Auto => {
                let f = self.get_file_settings(file_no)?;
                (self.file_comm_mode(&f, write), Some(f))
            }
        })
    }

    // ------------------------------------------------------------- data files
    /// ReadData with the mode derived from the file settings. `length` 0 reads to the end.
    pub fn read_data(&mut self, file_no: u8, offset: u32, length: u32) -> Result<Vec<u8>> {
        self.read_data_with(file_no, offset, length, ModeSel::Auto)
    }

    pub fn read_data_with(&mut self, file_no: u8, offset: u32, length: u32, sel: ModeSel<'_>) -> Result<Vec<u8>> {
        check_range("offset", offset, 24)?;
        check_range("length", length, 24)?;
        let (mode, fs) = self.resolve_mode(file_no, sel, false)?;
        let mut h = vec![file_no];
        h.extend(le_bytes(offset, 3));
        h.extend(le_bytes(length, 3));
        let data = self.command(cmd::READ_DATA, &h, &[], mode)?;
        if !is_tmac(&fs) {
            if let Some(t) = self.tm_for(file_no) {
                t.data(cmd::READ_DATA, file_no, offset, &data);
            }
        }
        Ok(data)
    }

    /// ReadData through the ISO-wrapped variant (command code 0xAD), in chunks of at most 240 bytes.
    ///
    /// Use this, not [`Card::read_data`], to read a file that mirrors an SDMSIG: on silicon the
    /// native 0xBD variant cannot deliver any byte of the signature (it answers every additional
    /// frame request with an empty frame), while 0xAD, like ISOReadBinary, returns it. `length`
    /// must be given (0 = "to the end" is not available in this variant).
    pub fn read_data_iso_with(&mut self, file_no: u8, offset: u32, length: u32, sel: ModeSel<'_>) -> Result<Vec<u8>> {
        check_range("offset", offset, 24)?;
        check_range("length", length, 24)?;
        if length == 0 {
            return Err(Error::arg("read_data_iso needs an explicit length"));
        }
        let (mode, _) = self.resolve_mode(file_no, sel, false)?;
        let mut out = Vec::with_capacity(length as usize);
        while (out.len() as u32) < length {
            let n = (length - out.len() as u32).min(240);
            let mut h = vec![file_no];
            h.extend(le_bytes(offset + out.len() as u32, 3));
            h.extend(le_bytes(n, 3));
            out.extend(self.command(cmd::READ_DATA_ISO, &h, &[], mode)?);
        }
        Ok(out)
    }

    /// CRLVersion of a CRLFile (ReadData with offset 0xFFFFFF, 7.10.2.3.4).
    pub fn read_crl_version(&mut self, file_no: u8, sel: ModeSel<'_>) -> Result<u32> {
        let (mode, _) = self.resolve_mode(file_no, sel, false)?;
        let mut h = vec![file_no, 0xFF, 0xFF, 0xFF];
        h.extend([0, 0, 0]);
        Ok(le_u32(&self.command(cmd::READ_DATA, &h, &[], mode)?))
    }

    pub fn write_data(&mut self, file_no: u8, offset: u32, data: &[u8]) -> Result<()> {
        self.write_data_with(file_no, offset, data, ModeSel::Auto)
    }

    pub fn write_data_with(&mut self, file_no: u8, offset: u32, data: &[u8], sel: ModeSel<'_>) -> Result<()> {
        check_range("offset", offset, 24)?;
        check_range("length", data.len() as u32, 24)?;
        let (mode, _) = self.resolve_mode(file_no, sel, true)?;
        let mut h = vec![file_no];
        h.extend(le_bytes(offset, 3));
        h.extend(le_bytes(data.len() as u32, 3));
        self.command(cmd::WRITE_DATA, &h, data, mode)?;
        if let Some(t) = self.tm_for(file_no) {
            t.data(cmd::WRITE_DATA, file_no, offset, data);
        }
        Ok(())
    }

    /// WriteData to a CRLFile: one unchained frame (command 0x8D) carrying the CRLVersion; the
    /// optional `signature` (CRLSignature over the update, computed by the caller with the CA
    /// key) follows the data.
    pub fn write_crl(
        &mut self,
        file_no: u8,
        version: u16,
        offset: u32,
        data: &[u8],
        signature: &[u8],
        sel: ModeSel<'_>,
    ) -> Result<()> {
        check_range("offset", offset, 24)?;
        check_range("length", data.len() as u32, 24)?;
        let (mode, _) = self.resolve_mode(file_no, sel, true)?;
        let mut h = vec![file_no];
        h.extend(version.to_le_bytes());
        h.extend(le_bytes(offset, 3));
        h.extend(le_bytes(data.len() as u32, 3));
        let body = [data, signature].concat();
        self.command(cmd::WRITE_DATA_CRL, &h, &body, mode)?;
        if let Some(t) = self.tm_for(file_no) {
            t.data(cmd::WRITE_DATA_CRL, file_no, offset, data);
        }
        Ok(())
    }

    // ---------------------------------------------------------------- values
    pub fn get_value(&mut self, file_no: u8) -> Result<i32> {
        self.get_value_with(file_no, ModeSel::Auto)
    }

    pub fn get_value_with(&mut self, file_no: u8, sel: ModeSel<'_>) -> Result<i32> {
        let (mode, _) = self.resolve_mode(file_no, sel, false)?;
        let d = self.command(cmd::GET_VALUE, &[file_no], &[], mode)?;
        if d.len() < 4 {
            self.drop_session();
            return Err(Error::protocol("GetValue: response shorter than 4 bytes"));
        }
        let v = le_u32(&d) as i32;
        if let Some(t) = self.tm_for(file_no) {
            t.value(cmd::GET_VALUE, file_no, v);
        }
        Ok(v)
    }

    fn value_op(&mut self, c: u8, file_no: u8, amount: i32, sel: ModeSel<'_>) -> Result<()> {
        let (mode, _) = self.resolve_mode(file_no, sel, true)?;
        self.command(c, &[file_no], &amount.to_le_bytes(), mode)?;
        if let Some(t) = self.tm_for(file_no) {
            t.value(c, file_no, amount);
        }
        Ok(())
    }

    pub fn credit(&mut self, file_no: u8, amount: i32) -> Result<()> {
        self.value_op(cmd::CREDIT, file_no, amount, ModeSel::Auto)
    }
    pub fn debit(&mut self, file_no: u8, amount: i32) -> Result<()> {
        self.value_op(cmd::DEBIT, file_no, amount, ModeSel::Auto)
    }
    pub fn limited_credit(&mut self, file_no: u8, amount: i32) -> Result<()> {
        self.value_op(cmd::LIMITED_CREDIT, file_no, amount, ModeSel::Auto)
    }
    pub fn credit_with(&mut self, file_no: u8, amount: i32, sel: ModeSel<'_>) -> Result<()> {
        self.value_op(cmd::CREDIT, file_no, amount, sel)
    }
    pub fn debit_with(&mut self, file_no: u8, amount: i32, sel: ModeSel<'_>) -> Result<()> {
        self.value_op(cmd::DEBIT, file_no, amount, sel)
    }
    pub fn limited_credit_with(&mut self, file_no: u8, amount: i32, sel: ModeSel<'_>) -> Result<()> {
        self.value_op(cmd::LIMITED_CREDIT, file_no, amount, sel)
    }

    // --------------------------------------------------------------- records
    /// ReadRecords: `count` 0 reads all records from `rec_no`.
    pub fn read_records(&mut self, file_no: u8, rec_no: u32, count: u32) -> Result<Vec<u8>> {
        self.read_records_with(file_no, rec_no, count, ModeSel::Auto)
    }

    pub fn read_records_with(&mut self, file_no: u8, rec_no: u32, count: u32, sel: ModeSel<'_>) -> Result<Vec<u8>> {
        check_range("record number", rec_no, 24)?;
        check_range("record count", count, 24)?;
        let (mode, mut fs) = self.resolve_mode(file_no, sel, false)?;
        // The TMI records the number of records read; when "all" was asked the record size is needed.
        if fs.is_none() && count == 0 && self.tm_for(file_no).is_some() {
            fs = Some(self.get_file_settings(file_no)?);
        }
        let mut h = vec![file_no];
        h.extend(le_bytes(rec_no, 3));
        h.extend(le_bytes(count, 3));
        let data = self.command(cmd::READ_RECORDS, &h, &[], mode)?;
        let n = if count != 0 {
            count
        } else {
            match fs.as_ref().and_then(|f| f.record.as_ref()) {
                Some(r) if r.record_size > 0 => (data.len() as u32) / r.record_size,
                _ => 0,
            }
        };
        if let Some(t) = self.tm_for(file_no) {
            t.read_records(cmd::READ_RECORDS, file_no, rec_no, n, &data);
        }
        Ok(data)
    }

    /// WriteRecord: append `data` (at `offset` within the new record).
    pub fn write_record(&mut self, file_no: u8, offset: u32, data: &[u8]) -> Result<()> {
        self.write_record_with(file_no, offset, data, ModeSel::Auto)
    }

    pub fn write_record_with(&mut self, file_no: u8, offset: u32, data: &[u8], sel: ModeSel<'_>) -> Result<()> {
        check_range("offset", offset, 24)?;
        check_range("length", data.len() as u32, 24)?;
        let (mode, _) = self.resolve_mode(file_no, sel, true)?;
        let mut h = vec![file_no];
        h.extend(le_bytes(offset, 3));
        h.extend(le_bytes(data.len() as u32, 3));
        self.command(cmd::WRITE_RECORD, &h, data, mode)?;
        if let Some(t) = self.tm_for(file_no) {
            t.write_record(cmd::WRITE_RECORD, file_no, offset, data);
        }
        Ok(())
    }

    pub fn update_record(&mut self, file_no: u8, rec_no: u32, offset: u32, data: &[u8]) -> Result<()> {
        self.update_record_with(file_no, rec_no, offset, data, ModeSel::Auto)
    }

    pub fn update_record_with(&mut self, file_no: u8, rec_no: u32, offset: u32, data: &[u8], sel: ModeSel<'_>) -> Result<()> {
        check_range("record number", rec_no, 24)?;
        check_range("offset", offset, 24)?;
        check_range("length", data.len() as u32, 24)?;
        let (mode, _) = self.resolve_mode(file_no, sel, true)?;
        let mut h = vec![file_no];
        h.extend(le_bytes(rec_no, 3));
        h.extend(le_bytes(offset, 3));
        h.extend(le_bytes(data.len() as u32, 3));
        self.command(cmd::UPDATE_RECORD, &h, data, mode)?;
        if let Some(t) = self.tm_for(file_no) {
            t.update_record(cmd::UPDATE_RECORD, file_no, rec_no, offset, data);
        }
        Ok(())
    }

    pub fn clear_record_file(&mut self, file_no: u8) -> Result<()> {
        self.command(cmd::CLEAR_RECORD_FILE, &[file_no], &[], CommMode::Mac)?;
        if let Some(t) = self.tm_for(file_no) {
            t.clear_records(cmd::CLEAR_RECORD_FILE, file_no);
        }
        Ok(())
    }

    // ---------------------------------------------------- certificate files
    /// Read a certificate file formatted as `CLEN(3, LSB first) || certificate || padding` (7.10.1.1).
    /// A file that starts with a DER SEQUENCE and has no plausible length prefix is read as a bare DER certificate.
    pub fn read_cert_file(&mut self, file_no: u8) -> Result<Vec<u8>> {
        let fs = self.get_file_settings(file_no)?;
        let sel = ModeSel::File(&fs);
        let head = self.read_data_with(file_no, 0, 3, sel)?;
        let clen = le_u32(&head);
        let size = fs.size.unwrap_or(0);
        if (clen == 0 || clen > size.saturating_sub(3)) && head.first() == Some(&0x30) {
            // The trust-provisioned originality certificate (file 01) of the cards seen so far holds the DER
            // certificate from offset 0, without the length prefix: take its length from the DER header.
            let h = self.read_data_with(file_no, 0, 4, sel)?;
            let total = match h.as_slice() {
                [_, l, ..] if *l < 0x80 => 2 + *l as u32,
                [_, 0x81, l, ..] => 3 + *l as u32,
                [_, 0x82, a, b] => 4 + u16::from_be_bytes([*a, *b]) as u32,
                _ => 0,
            };
            if total > 0 && total <= size {
                return self.read_data_with(file_no, 0, total, sel);
            }
        }
        if clen == 0 || clen > size.saturating_sub(3) {
            self.drop_session();
            return Err(Error::protocol(format!("file {file_no:02X} holds no certificate (CertificateLength {clen})")));
        }
        self.read_data_with(file_no, 3, clen, sel)
    }

    pub fn write_cert_file(&mut self, file_no: u8, cert: &[u8]) -> Result<()> {
        let fs = self.get_file_settings(file_no)?;
        if cert.len() as u32 + 3 > fs.size.unwrap_or(0) {
            return Err(Error::arg(format!(
                "certificate ({} bytes) does not fit file {file_no:02X} ({} bytes)",
                cert.len(),
                fs.size.unwrap_or(0)
            )));
        }
        let mut body = le_bytes(cert.len() as u32, 3);
        body.extend_from_slice(cert);
        self.write_data_with(file_no, 0, &body, ModeSel::File(&fs))
    }
}
