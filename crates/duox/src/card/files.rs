//! File management (7.12): FileSettings parsing / serialising, creating, deleting and changing
//! files, listing file IDs and counters.

use super::types::*;
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

// ----------------------------------------------------------------- settings
/// CRL file parameters (data file with CRL layout, Table 237).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlSettings {
    pub options: u8,
    pub csn_size: u8,
    pub sig_key: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueSettings {
    pub lower: i32,
    pub upper: i32,
    pub limited_credit: i32,
    /// bit 0 LimitedCredit enabled, bit 1 free GetValue.
    pub flags: u8,
}

impl ValueSettings {
    pub fn limited_credit_enabled(&self) -> bool {
        self.flags & 1 != 0
    }
    pub fn free_get_value(&self) -> bool {
        self.flags & 2 != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSettings {
    pub record_size: u32,
    pub max_records: u32,
    pub current_records: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmacSettings {
    /// bit 7: Transaction Signature, bits 1..0: key type (0 none, 2 AES-128, 3 AES-256).
    pub key_option: u8,
    pub key_version: Option<u8>,
    pub tsig_key: Option<u8>,
    /// TMIExclFileMap as a 32-bit value (byte 0 sent first, bit n = file n).
    pub excl_map: Option<u32>,
    pub tmc_limit: Option<u32>,
}

impl TmacSettings {
    pub fn is_signature(&self) -> bool {
        self.key_option & 0x80 != 0
    }
}

/// Parsed GetFileSettings response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettings {
    /// File number as addressed (bit 7 = secondary application).
    pub file_no: u8,
    pub file_type: FileType,
    pub option: u8,
    pub access: AccessRights,
    /// Additional access right sets (only the Read/Write/ReadWrite nibbles are defined).
    pub additional: Vec<AccessRights>,
    pub size: Option<u32>,
    /// Raw SDM settings block of a StandardData file (parse with the `sdm` module).
    pub sdm: Option<Vec<u8>>,
    pub crl: Option<CrlSettings>,
    pub value: Option<ValueSettings>,
    pub record: Option<RecordSettings>,
    pub tmac: Option<TmacSettings>,
    /// The response as received (empty for hand-built settings).
    pub raw: Vec<u8>,
}

fn slice(d: &[u8], from: usize, to: usize) -> Result<&[u8]> {
    d.get(from..to).ok_or_else(|| Error::protocol("GetFileSettings response too short"))
}

fn le(d: &[u8], from: usize, n: usize) -> Result<u32> {
    Ok(super::types::le_u32(slice(d, from, from + n)?))
}

impl FileSettings {
    pub fn comm_mode(&self) -> CommMode {
        CommMode::from_bits(self.option)
    }

    /// Access conditions relevant for reading (`write == false`) or writing: the Read / Write
    /// condition and ReadWrite of every set.
    pub fn access_conditions(&self, write: bool) -> Vec<AccessRight> {
        let mut out = vec![if write { self.access.write } else { self.access.read }, self.access.read_write];
        for a in &self.additional {
            out.push(if write { a.write } else { a.read });
            out.push(a.read_write);
        }
        out
    }

    pub fn is_secondary_app(&self) -> bool {
        self.file_no & SECOND_APP_BIT != 0
    }

    pub fn type_label(&self) -> String {
        let mut n = self.file_type.name().to_string();
        if self.crl.is_some() {
            n.push_str(" (CRL)");
        } else if self.option & 0x40 != 0 && self.file_type == FileType::StandardData {
            n.push_str(" (SDM)");
        }
        n
    }

    /// Parse a GetFileSettings response (without status byte).
    pub fn parse(file_no: u8, d: &[u8]) -> Result<FileSettings> {
        let head = slice(d, 0, 4)?;
        let file_type = FileType::try_from(head[0])?;
        let option = head[1];
        let mut fs = FileSettings {
            file_no,
            file_type,
            option,
            access: AccessRights::from_u16(u16::from_le_bytes([head[2], head[3]])),
            additional: vec![],
            size: None,
            sdm: None,
            crl: None,
            value: None,
            record: None,
            tmac: None,
            raw: d.to_vec(),
        };
        let add = |pos: usize, fs: &mut FileSettings| -> Result<usize> {
            if option & 0x80 != 0 && pos < d.len() {
                let n = d[pos] as usize;
                let b = slice(d, pos + 1, pos + 1 + 2 * n)?;
                fs.additional =
                    b.chunks(2).map(|c| AccessRights::from_u16(u16::from_le_bytes([c[0], c[1]]))).collect();
                return Ok(pos + 1 + 2 * n);
            }
            Ok(pos)
        };
        match file_type {
            FileType::StandardData | FileType::BackupData => {
                fs.size = Some(le(d, 4, 3)?);
                let pos = add(7, &mut fs)?;
                let rest = &d[pos..];
                if option & 0x40 != 0 && file_type == FileType::StandardData && !rest.is_empty() {
                    fs.sdm = Some(rest.to_vec());
                } else if rest.len() >= 2 {
                    fs.crl = Some(CrlSettings { options: rest[0], csn_size: rest[1], sig_key: rest.get(2).copied() });
                } else if option & 0x10 != 0 {
                    fs.crl = Some(CrlSettings { options: 0, csn_size: 0, sig_key: None });
                }
            }
            FileType::Value => {
                fs.value = Some(ValueSettings {
                    lower: le(d, 4, 4)? as i32,
                    upper: le(d, 8, 4)? as i32,
                    limited_credit: le(d, 12, 4)? as i32,
                    flags: *slice(d, 16, 17)?.first().unwrap_or(&0),
                });
                add(17, &mut fs)?;
            }
            FileType::LinearRecord | FileType::CyclicRecord => {
                fs.record = Some(RecordSettings {
                    record_size: le(d, 4, 3)?,
                    max_records: le(d, 7, 3)?,
                    current_records: le(d, 10, 3)?,
                });
                add(13, &mut fs)?;
            }
            FileType::TransactionMac => {
                let key_option = slice(d, 4, 5)?[0];
                let mut t = TmacSettings { key_option, key_version: None, tsig_key: None, excl_map: None, tmc_limit: None };
                let mut pos = 5;
                if key_option & 3 != 0 && pos < d.len() {
                    t.key_version = Some(d[pos]);
                    pos += 1;
                }
                if key_option & 0x80 != 0 && pos < d.len() {
                    t.tsig_key = Some(d[pos]);
                    pos += 1;
                }
                if option & 0x40 != 0 && pos + 4 <= d.len() {
                    t.excl_map = Some(le(d, pos, 4)?);
                    pos += 4;
                }
                if option & 0x20 != 0 && pos + 4 <= d.len() {
                    t.tmc_limit = Some(le(d, pos, 4)?);
                }
                fs.tmac = Some(t);
            }
        }
        Ok(fs)
    }

    /// Serialise in the GetFileSettings response layout (inverse of [`FileSettings::parse`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![self.file_type.code(), self.option];
        v.extend(self.access.to_bytes());
        let add = |v: &mut Vec<u8>| {
            if self.option & 0x80 != 0 {
                v.push(self.additional.len() as u8);
                for a in &self.additional {
                    v.extend(a.to_bytes());
                }
            }
        };
        match self.file_type {
            FileType::StandardData | FileType::BackupData => {
                v.extend(le_bytes(self.size.unwrap_or(0), 3));
                add(&mut v);
                if let Some(sdm) = &self.sdm {
                    v.extend(sdm);
                } else if let Some(c) = &self.crl {
                    v.extend([c.options, c.csn_size]);
                    v.extend(c.sig_key);
                }
            }
            FileType::Value => {
                let s = self.value.clone().unwrap_or(ValueSettings { lower: 0, upper: 0, limited_credit: 0, flags: 0 });
                v.extend(s.lower.to_le_bytes());
                v.extend(s.upper.to_le_bytes());
                v.extend(s.limited_credit.to_le_bytes());
                v.push(s.flags);
                add(&mut v);
            }
            FileType::LinearRecord | FileType::CyclicRecord => {
                let r = self.record.clone().unwrap_or(RecordSettings { record_size: 0, max_records: 0, current_records: 0 });
                v.extend(le_bytes(r.record_size, 3));
                v.extend(le_bytes(r.max_records, 3));
                v.extend(le_bytes(r.current_records, 3));
                add(&mut v);
            }
            FileType::TransactionMac => {
                if let Some(t) = &self.tmac {
                    v.push(t.key_option);
                    v.extend(t.key_version);
                    v.extend(t.tsig_key);
                    if self.option & 0x40 != 0 {
                        v.extend(t.excl_map.unwrap_or(0).to_le_bytes());
                    }
                    if self.option & 0x20 != 0 {
                        v.extend(t.tmc_limit.unwrap_or(0).to_le_bytes());
                    }
                }
            }
        }
        v
    }

    /// Multi-line human readable description.
    pub fn describe(&self) -> Vec<String> {
        let mut l = vec![
            format!("File {:02X}: {}", self.file_no, self.type_label()),
            format!("FileOption   0x{:02X}   CommMode.{}", self.option, self.comm_mode()),
            format!("AccessRights 0x{:04X}  {}", self.access.to_u16(), self.access),
        ];
        for (i, a) in self.additional.iter().enumerate() {
            l.push(format!("  set {}: Read={} Write={} ReadWrite={}", i + 2, a.read, a.write, a.read_write));
        }
        if let Some(s) = self.size {
            l.push(format!("FileSize     {s} bytes"));
        }
        if self.sdm.is_some() {
            l.push("Secure Dynamic Messaging enabled".into());
        }
        if let Some(c) = &self.crl {
            l.push(format!(
                "CRLOptions   0x{:02X}  signature+monotonic version: {}, increment by one: {}",
                c.options,
                if c.options & 1 != 0 { "yes" } else { "no" },
                if c.options & 2 != 0 { "yes" } else { "no" }
            ));
            l.push(format!("CSNSize      {}{}", c.csn_size, if c.csn_size == 0 { "  (revocation disabled)" } else { "" }));
            if let Some(k) = c.sig_key {
                l.push(format!("CRLSigKey    CARootKey {k}"));
            }
        }
        if let Some(v) = &self.value {
            l.push(format!("Limits       {} .. {}   LimitedCredit value {}", v.lower, v.upper, v.limited_credit));
            l.push(format!(
                "LimitedCredit {}, free GetValue {}",
                if v.limited_credit_enabled() { "enabled" } else { "disabled" },
                if v.free_get_value() { "yes" } else { "no" }
            ));
        }
        if let Some(r) = &self.record {
            l.push(format!("Records      size {}, max {}, current {}", r.record_size, r.max_records, r.current_records));
        }
        if let Some(t) = &self.tmac {
            let kt = match t.key_option & 3 {
                0 => "no TMAC key",
                2 => "AES-128",
                3 => "AES-256",
                _ => "?",
            };
            l.push(format!(
                "TMKeyOption  0x{:02X}  {}, {}",
                t.key_option,
                if t.is_signature() { "Transaction Signature" } else { "Transaction MAC" },
                kt
            ));
            if let Some(x) = t.key_version {
                l.push(format!("TMKeyVer     {x}"));
            }
            if let Some(x) = t.tsig_key {
                l.push(format!("TSIGKeyNo    {x}"));
            }
            if let Some(x) = t.excl_map {
                l.push(format!("TMIExclFileMap {x:08X}"));
            }
            if let Some(x) = t.tmc_limit {
                l.push(format!("TMCLimit     {x}"));
            }
        }
        l.push(format!("raw: {}", hex::encode_upper(&self.raw)));
        l
    }
}

// -------------------------------------------------------------- creation specs
/// StandardData / BackupData file (optionally flagged as SDM or CRL file).
#[derive(Debug, Clone)]
pub struct DataFileSpec {
    pub file_no: u8,
    pub size: u32,
    pub access: AccessRights,
    pub comm_mode: CommMode,
    pub backup: bool,
    pub iso_fid: Option<u16>,
    pub sdm: bool,
    pub crl: bool,
    pub additional_access: bool,
}

impl DataFileSpec {
    pub fn new(file_no: u8, size: u32, access: AccessRights) -> Self {
        DataFileSpec {
            file_no,
            size,
            access,
            comm_mode: CommMode::Plain,
            backup: false,
            iso_fid: None,
            sdm: false,
            crl: false,
            additional_access: false,
        }
    }
    pub fn comm_mode(mut self, m: CommMode) -> Self {
        self.comm_mode = m;
        self
    }
    pub fn backup(mut self) -> Self {
        self.backup = true;
        self
    }
    pub fn iso_fid(mut self, fid: u16) -> Self {
        self.iso_fid = Some(fid);
        self
    }
    pub fn sdm(mut self) -> Self {
        self.sdm = true;
        self
    }
    pub fn crl(mut self) -> Self {
        self.crl = true;
        self
    }
    pub fn additional_access(mut self) -> Self {
        self.additional_access = true;
        self
    }
}

#[derive(Debug, Clone)]
pub struct ValueFileSpec {
    pub file_no: u8,
    pub access: AccessRights,
    pub lower: i32,
    pub upper: i32,
    pub initial: i32,
    /// bit 0 LimitedCredit enabled, bit 1 free GetValue.
    pub flags: u8,
    pub comm_mode: CommMode,
}

impl ValueFileSpec {
    pub fn new(file_no: u8, access: AccessRights, lower: i32, upper: i32, initial: i32) -> Self {
        ValueFileSpec { file_no, access, lower, upper, initial, flags: 0, comm_mode: CommMode::Plain }
    }
    pub fn flags(mut self, f: u8) -> Self {
        self.flags = f;
        self
    }
    pub fn comm_mode(mut self, m: CommMode) -> Self {
        self.comm_mode = m;
        self
    }
}

#[derive(Debug, Clone)]
pub struct RecordFileSpec {
    pub file_no: u8,
    pub access: AccessRights,
    pub record_size: u32,
    pub max_records: u32,
    pub cyclic: bool,
    pub comm_mode: CommMode,
    pub iso_fid: Option<u16>,
}

impl RecordFileSpec {
    pub fn new(file_no: u8, access: AccessRights, record_size: u32, max_records: u32) -> Self {
        RecordFileSpec { file_no, access, record_size, max_records, cyclic: false, comm_mode: CommMode::Plain, iso_fid: None }
    }
    pub fn cyclic(mut self) -> Self {
        self.cyclic = true;
        self
    }
    pub fn comm_mode(mut self, m: CommMode) -> Self {
        self.comm_mode = m;
        self
    }
    pub fn iso_fid(mut self, fid: u16) -> Self {
        self.iso_fid = Some(fid);
        self
    }
}

#[derive(Debug, Clone)]
pub struct TmacFileSpec {
    pub file_no: u8,
    pub access: AccessRights,
    pub comm_mode: CommMode,
    /// 16 or 32 bytes AES key for Transaction MAC; empty for none.
    pub tm_key: Vec<u8>,
    pub tm_key_version: u8,
    /// Switches to Transaction Signature with this ECC private key number.
    pub tsig_key_no: Option<u8>,
    pub excl_map: Option<u32>,
}

impl TmacFileSpec {
    pub fn new(file_no: u8, access: AccessRights) -> Self {
        TmacFileSpec {
            file_no,
            access,
            comm_mode: CommMode::Plain,
            tm_key: vec![],
            tm_key_version: 0,
            tsig_key_no: None,
            excl_map: None,
        }
    }
    pub fn comm_mode(mut self, m: CommMode) -> Self {
        self.comm_mode = m;
        self
    }
    pub fn key(mut self, key: &[u8], version: u8) -> Self {
        self.tm_key = key.to_vec();
        self.tm_key_version = version;
        self
    }
    pub fn signature_key(mut self, key_no: u8) -> Self {
        self.tsig_key_no = Some(key_no);
        self
    }
    pub fn excl_map(mut self, m: u32) -> Self {
        self.excl_map = Some(m);
        self
    }
}

// ----------------------------------------------------------- change settings
/// CRL part of ChangeFileSettings.
#[derive(Debug, Clone)]
pub struct CrlChange {
    pub options: u8,
    pub csn_size: u8,
    pub sig_key: Option<u8>,
}

/// New settings for ChangeFileSettings. Which optional parts are sent is derived from `option`
/// bits (bit 7 additional access rights, bit 6 SDM / TMI exclusion map, bit 5 TMC limit) and
/// from the parts that are present.
#[derive(Debug, Clone)]
pub struct FileSettingsChange {
    pub option: u8,
    pub access: AccessRights,
    pub additional: Vec<AccessRights>,
    /// Encoded SDM settings (as produced by the `sdm` module), sent when `option` bit 6 is set.
    pub sdm: Vec<u8>,
    /// TransactionMAC file: TMIExclFileMap (sent if present).
    pub tmac_excl_map: Option<u32>,
    /// TransactionMAC file: TMCLimit (sent if present).
    pub tmc_limit: Option<u32>,
    pub crl: Option<CrlChange>,
    /// Override the CommMode; default derives it from `current_change_access`.
    pub mode: Option<CommMode>,
    /// The Change access condition currently set on the file. When it is "free" and the session
    /// does not satisfy it, the command is sent plain.
    pub current_change_access: AccessRight,
}

impl FileSettingsChange {
    pub fn new(option: u8, access: AccessRights) -> Self {
        FileSettingsChange {
            option,
            access,
            additional: vec![],
            sdm: vec![],
            tmac_excl_map: None,
            tmc_limit: None,
            crl: None,
            mode: None,
            current_change_access: AccessRight::key(0),
        }
    }
    fn encode_data(&self) -> Vec<u8> {
        let mut data = vec![self.option];
        data.extend(self.access.to_bytes());
        if self.option & 0x80 != 0 {
            data.push(self.additional.len() as u8);
            for a in &self.additional {
                data.extend(a.to_bytes());
            }
        }
        if self.option & 0x40 != 0 {
            data.extend(&self.sdm);
        }
        if let Some(x) = self.tmac_excl_map {
            data.extend(x.to_le_bytes());
        }
        if let Some(x) = self.tmc_limit {
            data.extend(x.to_le_bytes());
        }
        if let Some(c) = &self.crl {
            data.extend([c.options, c.csn_size]);
            if c.options & 1 != 0 {
                data.extend(c.sig_key);
            }
        }
        data
    }
}

impl<T: Transport> Card<T> {
    pub fn get_file_ids(&mut self) -> Result<Vec<u8>> {
        self.command(cmd::GET_FILE_IDS, &[], &[], CommMode::Mac)
    }

    pub fn get_iso_file_ids(&mut self) -> Result<Vec<u16>> {
        let d = self.command(cmd::GET_ISO_FILE_IDS, &[], &[], CommMode::Mac)?;
        Ok(d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect())
    }

    pub fn get_file_settings(&mut self, file_no: u8) -> Result<FileSettings> {
        let d = self.command(cmd::GET_FILE_SETTINGS, &[file_no], &[], CommMode::Mac)?;
        match FileSettings::parse(file_no, &d) {
            Ok(fs) => Ok(fs),
            Err(e) => {
                self.drop_session();
                Err(e)
            }
        }
    }

    /// SDMReadCtr of a file (GetFileCounters).
    pub fn get_file_counters(&mut self, file_no: u8) -> Result<u32> {
        let d = self.command(cmd::GET_FILE_COUNTERS, &[file_no], &[], CommMode::Full)?;
        Ok(le_u32(&d[..d.len().min(3)]))
    }

    fn file_header(file_no: u8, iso_fid: Option<u16>, option: u8, access: AccessRights) -> Vec<u8> {
        let mut h = vec![file_no];
        if let Some(f) = iso_fid {
            h.extend(f.to_le_bytes());
        }
        h.push(option);
        h.extend(access.to_bytes());
        h
    }

    pub fn create_data_file(&mut self, spec: &DataFileSpec) -> Result<()> {
        check_range("file size", spec.size, 24)?;
        let opt = spec.comm_mode.bits()
            | if spec.sdm { 0x40 } else { 0 }
            | if spec.crl { 0x10 } else { 0 }
            | if spec.additional_access { 0x80 } else { 0 };
        let mut h = Self::file_header(spec.file_no, spec.iso_fid, opt, spec.access);
        h.extend(le_bytes(spec.size, 3));
        let c = if spec.backup { cmd::CREATE_BACKUP_DATA_FILE } else { cmd::CREATE_STD_DATA_FILE };
        self.command(c, &h, &[], CommMode::Mac).map(|_| ())
    }

    pub fn create_value_file(&mut self, spec: &ValueFileSpec) -> Result<()> {
        let mut h = Self::file_header(spec.file_no, None, spec.comm_mode.bits(), spec.access);
        h.extend(spec.lower.to_le_bytes());
        h.extend(spec.upper.to_le_bytes());
        h.extend(spec.initial.to_le_bytes());
        h.push(spec.flags);
        self.command(cmd::CREATE_VALUE_FILE, &h, &[], CommMode::Mac).map(|_| ())
    }

    pub fn create_record_file(&mut self, spec: &RecordFileSpec) -> Result<()> {
        check_range("record size", spec.record_size, 24)?;
        check_range("record count", spec.max_records, 24)?;
        let mut h = Self::file_header(spec.file_no, spec.iso_fid, spec.comm_mode.bits(), spec.access);
        h.extend(le_bytes(spec.record_size, 3));
        h.extend(le_bytes(spec.max_records, 3));
        let c = if spec.cyclic { cmd::CREATE_CYCLIC_RECORD_FILE } else { cmd::CREATE_LINEAR_RECORD_FILE };
        self.command(c, &h, &[], CommMode::Mac).map(|_| ())
    }

    /// CreateTransactionMACFile; the key material travels in the encrypted data field.
    pub fn create_tmac_file(&mut self, spec: &TmacFileSpec) -> Result<()> {
        let key_type = match spec.tm_key.len() {
            0 => 0,
            16 => 2,
            32 => 3,
            n => return Err(Error::arg(format!("Transaction MAC key must be 16 or 32 bytes, got {n}"))),
        };
        let kopt = key_type | if spec.tsig_key_no.is_some() { 0x80 } else { 0 };
        let opt = spec.comm_mode.bits() | if spec.excl_map.is_some() { 0x40 } else { 0 };
        let mut header = vec![spec.file_no, opt];
        header.extend(spec.access.to_bytes());
        if let Some(m) = spec.excl_map {
            header.extend(m.to_le_bytes());
        }
        header.push(kopt);
        let mut data = vec![];
        if !spec.tm_key.is_empty() {
            data.extend(&spec.tm_key);
            data.push(spec.tm_key_version);
        }
        data.extend(spec.tsig_key_no);
        self.command(cmd::CREATE_TRANSACTION_MAC_FILE, &header, &data, CommMode::Full).map(|_| ())
    }

    pub fn delete_file(&mut self, file_no: u8) -> Result<()> {
        self.command(cmd::DELETE_FILE, &[file_no], &[], CommMode::Mac).map(|_| ())
    }

    pub fn change_file_settings(&mut self, file_no: u8, change: &FileSettingsChange) -> Result<()> {
        let data = change.encode_data();
        let mode = change.mode.unwrap_or_else(|| {
            if change.current_change_access.is_free() && !self.has_access_condition(change.current_change_access, false) {
                CommMode::Plain
            } else {
                CommMode::Full
            }
        });
        self.command(cmd::CHANGE_FILE_SETTINGS, &[file_no], &data, mode).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    #[test]
    fn parse_standard_file_with_additional_sets() {
        // type 0, option 0x81 (Full? bits 01 = MAC) + addARs, AR 0xE0EE.. size 0x20
        let d = hx("00 81 EE E0 20 00 00 01 21 43");
        let fs = FileSettings::parse(3, &d).unwrap();
        assert_eq!(fs.file_type, FileType::StandardData);
        assert_eq!(fs.comm_mode(), CommMode::Mac);
        assert_eq!(fs.access.read, AccessRight::FREE);
        assert_eq!(fs.access.write, AccessRight::key(0));
        assert_eq!(fs.size, Some(0x20));
        assert_eq!(fs.additional, vec![AccessRights::from_u16(0x4321)]);
        assert_eq!(fs.encode(), d);
        assert_eq!(fs.access_conditions(true), vec![AccessRight::key(0), AccessRight::key(14 & 0xE), AccessRight::key(3), AccessRight::key(2)]);
    }

    #[test]
    fn parse_value_record_tmac_roundtrip() {
        let v = hx("02 03 11 22 0A000000 E8030000 00000000 03");
        let fs = FileSettings::parse(1, &v).unwrap();
        let val = fs.value.clone().unwrap();
        assert_eq!((val.lower, val.upper), (10, 1000));
        assert!(val.limited_credit_enabled() && val.free_get_value());
        assert_eq!(fs.encode(), v);

        let r = hx("04 01 11 22 100000 050000 020000");
        let fs = FileSettings::parse(2, &r).unwrap();
        assert_eq!(fs.record.clone().unwrap().record_size, 16);
        assert_eq!(fs.file_type, FileType::CyclicRecord);
        assert_eq!(fs.encode(), r);

        let t = hx("05 61 EE EE 02 07 05000000 0A000000");
        let fs = FileSettings::parse(0x0F, &t).unwrap();
        let tm = fs.tmac.clone().unwrap();
        assert_eq!(tm.key_version, Some(7));
        assert_eq!(tm.excl_map, Some(5));
        assert_eq!(tm.tmc_limit, Some(10));
        assert!(!tm.is_signature());
        assert_eq!(fs.encode(), t);

        let sig = hx("05 00 EE EE 82 01 02");
        let tm = FileSettings::parse(0x0F, &sig).unwrap().tmac.unwrap();
        assert!(tm.is_signature());
        assert_eq!((tm.key_version, tm.tsig_key), (Some(1), Some(2)));
    }

    #[test]
    fn parse_crl_and_sdm_and_truncation() {
        let crl = hx("00 00 11 22 000100 03 00 01");
        let fs = FileSettings::parse(5, &crl).unwrap();
        assert_eq!(fs.crl.clone().unwrap(), CrlSettings { options: 3, csn_size: 0, sig_key: Some(1) });
        assert_eq!(fs.type_label(), "StandardData (CRL)");
        assert_eq!(fs.encode(), crl);
        let sdm = hx("00 40 11 22 000100 C1 FF 01");
        let fs = FileSettings::parse(5, &sdm).unwrap();
        assert_eq!(fs.sdm.clone().unwrap(), hx("C1FF01"));
        assert!(FileSettings::parse(5, &hx("00 00 11")).is_err());
        assert!(FileSettings::parse(5, &hx("09 00 11 22")).is_err());
        assert!(FileSettings::parse(5, &hx("02 00 11 22 00")).is_err());
    }

    #[test]
    fn create_file_wire_format() {
        let mut t = MockTransport::new();
        t.expect_hex("90CD000009 05 1000 01 E0EE 200000 00", "9100");
        t.expect_hex("90CC000011 02 00 1122 0A000000 E8030000 14000000 01 00", "9100");
        t.expect_hex("90C100000A 03 00 1122 100000 0A0000 00", "9100");
        t.expect_hex("90C000000A 04 01 1122 100000 0A0000 00", "9100");
        let mut card = Card::new(t);
        let spec = DataFileSpec::new(5, 0x20, AccessRights::from_u16(0xEEE0)).iso_fid(0x0010).comm_mode(CommMode::Mac);
        card.create_data_file(&spec).unwrap();
        card.create_value_file(&ValueFileSpec::new(2, AccessRights::from_u16(0x2211), 10, 1000, 20).flags(1)).unwrap();
        card.create_record_file(&RecordFileSpec::new(3, AccessRights::from_u16(0x2211), 16, 10)).unwrap();
        card.create_record_file(&RecordFileSpec::new(4, AccessRights::from_u16(0x2211), 16, 10).cyclic().comm_mode(CommMode::Mac)).unwrap();
        assert_eq!(card.transport().remaining(), 0);
    }

    #[test]
    fn create_file_rejects_oversize() {
        let mut card = Card::new(MockTransport::new());
        let spec = DataFileSpec::new(5, 0x0100_0000, AccessRights::all(AccessRight::FREE));
        assert!(matches!(card.create_data_file(&spec), Err(Error::InvalidArgument(_))));
        assert!(card.transport().sent().is_empty());
    }
}
