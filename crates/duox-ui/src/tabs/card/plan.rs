//! Turning what the user entered into library command specifications, with every precondition
//! checked before anything is sent to the card. Pure functions: no card, no forms.

use super::model::{app_key_count, PICC_KEYS};
use crate::ui::hex;
use duox::card::{
    AccessRight, AccessRights, AppSpec, Aid, AuthKind, AuthSummary, CaRootKeySpec, ChangeKeySpec, CommMode,
    CrlChange, DataFileSpec, EccKeyInfo, FileSettings, FileSettingsChange, FileType, KeyPairOp, KeyPairSpec,
    KeySetConfig, KeySettings, RecordFileSpec, TmacFileSpec, ValueFileSpec,
};
use duox::crypto::{priv_from_bytes, PubKey};
use duox::pki::{certfile, AcMap, Certificate, TrustAnchor};

/// Highest AES key number in an application with the maximum key count.
const MAX_APP_KEYS: u8 = 14;
/// ISO file identifiers reserved by ISO/IEC 7816-4.
const RESERVED_ISO_FIDS: [u16; 4] = [0x0000, 0x3F00, 0x3FFF, 0xFFFF];
/// A card certificate (public key, two names, validity, signature) never fits a file smaller than this.
pub const MIN_CARD_CERT_FILE: u32 = 200;

// ------------------------------------------------------------- access checks

/// Why the active authentication cannot use `fs` for reading or writing, if it cannot. `has`
/// tells whether the authentication satisfies an access condition (second application: `true`).
pub fn access_problem(fs: &FileSettings, write: bool, has: impl Fn(AccessRight, bool) -> bool) -> Option<String> {
    let secondary = fs.is_secondary_app();
    let acs = fs.access_conditions(write);
    if acs.iter().any(|a| a.is_free() || has(*a, secondary)) {
        return None;
    }
    let mut keys: Vec<AccessRight> = acs.into_iter().filter(|a| a.is_key()).collect();
    keys.sort_by_key(|a| a.0);
    keys.dedup();
    let what = if write { "writing" } else { "reading" };
    let name = format!("File {:02X}", fs.file_no & 0x7F);
    if keys.is_empty() {
        return Some(format!("{name} cannot be used for {what}: its access rights are set to \"never\"."));
    }
    let list: Vec<String> = keys.iter().map(|k| format!("{k}")).collect();
    Some(format!(
        "{name} needs an authentication that satisfies {} for {what}, and the active one does not. \
         Authenticate on the Authenticate tab first.",
        list.join(" or ")
    ))
}

/// Why a single access condition (for example Change) is not satisfied, if it is not.
pub fn condition_problem(
    what: &str,
    ac: AccessRight,
    secondary: bool,
    has: impl Fn(AccessRight, bool) -> bool,
) -> Option<String> {
    if ac.is_free() || has(ac, secondary) {
        None
    } else if ac.is_never() {
        Some(format!("{what} is not possible: the access right is set to \"never\"."))
    } else {
        Some(format!("{what} needs an authentication that satisfies {ac}, and the active one does not. Authenticate on the Authenticate tab first."))
    }
}

/// Why the master key (access condition 0) is required but missing, if it is.
pub fn master_key_problem(what: &str, needed: bool, has: impl Fn(AccessRight, bool) -> bool) -> Option<String> {
    if needed && !has(AccessRight::key(0), false) {
        Some(format!("{what} needs an authentication with the master key (key 00); the active authentication is not."))
    } else {
        None
    }
}

// ------------------------------------------------------------ certificates

/// Bytes to write to a certificate file: PEM is converted to DER, then the 3 byte length prefix
/// is added.
pub fn certificate_file_payload(raw: &[u8]) -> Result<Vec<u8>, String> {
    let der: Vec<u8> = if raw.trim_ascii_start().starts_with(b"-----BEGIN") {
        let certs = Certificate::load_all(raw).map_err(|e| format!("The PEM data holds no usable certificate: {e}"))?;
        if certs.is_empty() {
            return Err("The PEM data holds no certificate.".into());
        }
        certs.iter().flat_map(|c| c.to_der().to_vec()).collect()
    } else {
        raw.to_vec()
    };
    certfile::build_image(&der, None).map_err(|e| e.to_string())
}

// --------------------------------------------------------------------- data

pub fn is_data_file(fs: &FileSettings) -> bool {
    matches!(fs.file_type, FileType::StandardData | FileType::BackupData)
}

pub fn plan_write(fs: &FileSettings, offset: u32, data: &[u8]) -> Result<(), String> {
    let no = fs.file_no & 0x7F;
    if !is_data_file(fs) {
        return Err(format!("File {no:02X} is not a data file. Use Value... or Records... for the other file types."));
    }
    if fs.crl.is_some() {
        return Err(format!("File {no:02X} is a CRL file. Update it on the CRL tab so the version and signature are handled."));
    }
    if data.is_empty() {
        return Err("There is nothing to write: enter data or choose a file.".into());
    }
    let size = fs.size.unwrap_or(0) as u64;
    if offset as u64 + data.len() as u64 > size {
        return Err(format!(
            "Writing {} bytes at offset {offset} would end after the {size} bytes of file {no:02X}.",
            data.len()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueOp {
    Credit,
    Debit,
    LimitedCredit,
}

impl ValueOp {
    pub const ALL: [(&'static str, ValueOp); 3] =
        [("Credit", ValueOp::Credit), ("Debit", ValueOp::Debit), ("LimitedCredit", ValueOp::LimitedCredit)];
}

pub fn plan_value(fs: &FileSettings, op: ValueOp, amount: i64) -> Result<i32, String> {
    let no = fs.file_no & 0x7F;
    let Some(v) = &fs.value else {
        return Err(format!("File {no:02X} is not a value file."));
    };
    if amount <= 0 || amount > i32::MAX as i64 {
        return Err("The amount must be a positive number that fits 31 bits.".into());
    }
    if op == ValueOp::LimitedCredit && !v.limited_credit_enabled() {
        return Err(format!("File {no:02X} was created without LimitedCredit; use Credit instead."));
    }
    Ok(amount as i32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOp {
    Write,
    Update,
    Clear,
}

impl RecordOp {
    pub const ALL: [(&'static str, RecordOp); 3] =
        [("WriteRecord", RecordOp::Write), ("UpdateRecord", RecordOp::Update), ("ClearRecordFile", RecordOp::Clear)];
}

pub fn plan_record(fs: &FileSettings, op: RecordOp, rec_no: u32, offset: u32, data: &[u8]) -> Result<(), String> {
    let no = fs.file_no & 0x7F;
    let Some(r) = &fs.record else {
        return Err(format!("File {no:02X} is not a record file."));
    };
    if op == RecordOp::Clear {
        return Ok(());
    }
    if data.is_empty() {
        return Err("There is nothing to write: enter the record data in hex.".into());
    }
    if offset as u64 + data.len() as u64 > r.record_size as u64 {
        return Err(format!(
            "{} bytes at offset {offset} do not fit a record of {} bytes.",
            data.len(),
            r.record_size
        ));
    }
    // The record count in the cached settings does not include uncommitted changes, so the
    // number of the record to update and the "full" state are left to the card.
    let _ = rec_no;
    Ok(())
}

// -------------------------------------------------------------- applications

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySetsInput {
    pub count: u8,
    pub max_aes256: bool,
    pub roll_key: u8,
    pub aks_version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInput {
    pub aid: u32,
    pub keys: u8,
    pub aes256: bool,
    pub key_sett1: u8,
    pub iso_file_ids: bool,
    pub iso_fid: Option<u16>,
    pub df_name: Vec<u8>,
    pub key_sets: Option<KeySetsInput>,
}

fn check_iso_fid(fid: u16) -> Result<(), String> {
    if RESERVED_ISO_FIDS.contains(&fid) {
        return Err(format!("ISO file ID {fid:04X} is reserved by ISO/IEC 7816-4; choose another one."));
    }
    Ok(())
}

pub fn plan_app(i: &AppInput, existing: &[Aid]) -> Result<AppSpec, String> {
    if i.aid == 0 || i.aid > 0xFF_FFFF {
        return Err("The application ID must be between 000001 and FFFFFF (000000 is the PICC level).".into());
    }
    if existing.contains(&Aid(i.aid)) {
        return Err(format!("Application {:06X} already exists on the card.", i.aid));
    }
    if i.keys > MAX_APP_KEYS {
        return Err(format!("An application has at most {MAX_APP_KEYS} keys."));
    }
    if !i.df_name.is_empty() && i.iso_fid.is_none() {
        return Err("A DF name needs an ISO file ID as well.".into());
    }
    if i.df_name.len() > 16 {
        return Err("A DF name is 1 to 16 bytes long.".into());
    }
    if let Some(f) = i.iso_fid {
        check_iso_fid(f)?;
    }
    let mut spec = AppSpec::new(Aid(i.aid)).key_settings(i.key_sett1).keys(i.keys);
    if i.aes256 {
        spec = spec.aes256();
    }
    if i.iso_file_ids {
        spec = spec.iso_file_ids();
    }
    if let Some(f) = i.iso_fid {
        spec = spec.iso_name(f, &i.df_name);
    }
    if let Some(k) = &i.key_sets {
        if !(2..=16).contains(&k.count) {
            return Err("An application with key sets needs 2 to 16 of them.".into());
        }
        if k.roll_key > 0x0D {
            return Err("The key allowed to roll key sets is a key number from 0 to 13.".into());
        }
        let size = if k.max_aes256 || i.aes256 { 0x20 } else { 0x10 };
        spec = spec.key_sett3(0x01).key_sets(KeySetConfig {
            aks_version: k.aks_version,
            no_key_sets: k.count,
            max_key_size: size,
            app_key_set_settings: k.roll_key & 0x0F,
        });
    }
    Ok(spec)
}

// --------------------------------------------------------------------- files

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewFileKind {
    Data { backup: bool, size: u32, sdm: bool, crl: bool },
    Value { lower: i32, upper: i32, initial: i32, limited_credit: bool, free_get_value: bool },
    Record { cyclic: bool, record_size: u32, max_records: u32 },
    Tmac { key: Vec<u8>, key_version: u8, signature_key: Option<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInput {
    pub number: u8,
    pub second_app: bool,
    pub iso_fid: Option<u16>,
    pub mode: CommMode,
    pub access: AccessRights,
    pub additional_access: bool,
    pub kind: NewFileKind,
}

#[derive(Debug, Clone)]
pub enum FileSpec {
    Data(DataFileSpec),
    Value(ValueFileSpec),
    Record(RecordFileSpec),
    Tmac(TmacFileSpec),
}

/// `existing`: files known in the application (file number as addressed, type).
pub fn plan_new_file(i: &FileInput, existing: &[(u8, FileType)], at_picc: bool) -> Result<FileSpec, String> {
    if i.number > 0x1F {
        return Err("File numbers go from 00 to 1F.".into());
    }
    if i.second_app && at_picc {
        return Err("The PICC level has no second application.".into());
    }
    let addressed = i.number | if i.second_app { 0x80 } else { 0 };
    if existing.iter().any(|(n, _)| *n == addressed) {
        return Err(format!("File {:02X} already exists in this application.", i.number));
    }
    if let Some(f) = i.iso_fid {
        check_iso_fid(f)?;
    }
    if at_picc {
        match &i.kind {
            NewFileKind::Data { backup: false, sdm: false, .. } if !i.additional_access => {}
            NewFileKind::Data { .. } => {
                return Err("At PICC level only plain standard data files are possible (no backup, SDM or additional access rights).".into())
            }
            _ => return Err("The PICC level can only hold standard data files.".into()),
        }
        if i.iso_fid.is_none() {
            return Err("Files at PICC level need an ISO file ID.".into());
        }
    }
    Ok(match &i.kind {
        NewFileKind::Data { backup, size, sdm, crl } => {
            if *size == 0 || *size > 0xFF_FFFF {
                return Err("A data file holds 1 to 16777215 bytes.".into());
            }
            if *sdm && *backup {
                return Err("Secure Dynamic Messaging is only available for standard data files, not backup files.".into());
            }
            if *sdm && *crl {
                return Err("A file cannot be both an SDM file and a CRL file.".into());
            }
            let mut s = DataFileSpec::new(addressed, *size, i.access).comm_mode(i.mode);
            if *backup {
                s = s.backup();
            }
            if let Some(f) = i.iso_fid {
                s = s.iso_fid(f);
            }
            if *sdm {
                s = s.sdm();
            }
            if *crl {
                s = s.crl();
            }
            if i.additional_access {
                s = s.additional_access();
            }
            FileSpec::Data(s)
        }
        NewFileKind::Value { lower, upper, initial, limited_credit, free_get_value } => {
            if lower > upper {
                return Err("The lower limit of a value file must not exceed the upper limit.".into());
            }
            if initial < lower || initial > upper {
                return Err("The initial value must lie between the lower and upper limit.".into());
            }
            if i.iso_fid.is_some() {
                return Err("Value files have no ISO file ID.".into());
            }
            let flags = u8::from(*limited_credit) | (u8::from(*free_get_value) << 1);
            FileSpec::Value(ValueFileSpec::new(addressed, i.access, *lower, *upper, *initial).flags(flags).comm_mode(i.mode))
        }
        NewFileKind::Record { cyclic, record_size, max_records } => {
            if *record_size == 0 || *record_size > 0xFF_FFFF {
                return Err("A record holds 1 to 16777215 bytes.".into());
            }
            let min = if *cyclic { 2 } else { 1 };
            if *max_records < min || *max_records > 0xFF_FFFF {
                return Err(if *cyclic {
                    "A cyclic record file needs room for at least 2 records (one is consumed by the backup mechanism).".into()
                } else {
                    "A record file holds 1 to 16777215 records.".into()
                });
            }
            let mut s = RecordFileSpec::new(addressed, i.access, *record_size, *max_records).comm_mode(i.mode);
            if *cyclic {
                s = s.cyclic();
            }
            if let Some(f) = i.iso_fid {
                s = s.iso_fid(f);
            }
            FileSpec::Record(s)
        }
        NewFileKind::Tmac { key, key_version, signature_key } => {
            if !matches!(key.len(), 0 | 16 | 32) {
                return Err(format!("The Transaction MAC key must be 16 or 32 bytes (or empty for none), not {}.", key.len()));
            }
            if existing.iter().any(|(n, t)| *t == FileType::TransactionMac && (n & 0x80 != 0) == i.second_app) {
                return Err("This application already has a TransactionMAC file; an application can hold only one.".into());
            }
            if i.iso_fid.is_some() {
                return Err("The TransactionMAC file has no ISO file ID.".into());
            }
            let mut s = TmacFileSpec::new(addressed, i.access).comm_mode(i.mode);
            if !key.is_empty() {
                s = s.key(key, *key_version);
            }
            if let Some(k) = signature_key {
                s = s.signature_key(*k);
            }
            FileSpec::Tmac(s)
        }
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlInput {
    pub require_signature: bool,
    pub increment_by_one: bool,
    pub active: bool,
    pub sig_key: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeInput {
    pub mode: CommMode,
    pub access: AccessRights,
    /// Present when the file has additional access right sets.
    pub additional: Option<Vec<AccessRights>>,
    pub crl: Option<CrlInput>,
}

/// Parse "1234, 5678" into additional access right sets.
pub fn parse_additional_sets(text: &str) -> Result<Vec<AccessRights>, String> {
    let mut out = Vec::new();
    for part in text.split([',', ' ', ';']).filter(|p| !p.is_empty()) {
        let p = part.trim_start_matches("0x");
        let v = u16::from_str_radix(p, 16).map_err(|_| format!("'{part}' is not a 4-digit hex access rights value."))?;
        out.push(AccessRights::from_u16(v));
    }
    if out.len() > 8 {
        return Err("Too many additional access right sets.".into());
    }
    Ok(out)
}

pub fn plan_file_change(fs: &FileSettings, i: &ChangeInput) -> Result<FileSettingsChange, String> {
    let no = fs.file_no & 0x7F;
    if fs.access.change.is_never() {
        return Err(format!("File {no:02X} has Change set to \"never\": its settings can no longer be changed."));
    }
    let mut option = i.mode.bits();
    if i.additional.is_some() {
        option |= 0x80;
    }
    let mut change = FileSettingsChange::new(option, i.access);
    change.current_change_access = fs.access.change;
    if let Some(a) = &i.additional {
        change.additional = a.clone();
    }
    if let Some(t) = &fs.tmac {
        // keep the exclusion map and the TMC limit of a TransactionMAC file
        if let Some(m) = t.excl_map {
            change.option |= 0x40;
            change.tmac_excl_map = Some(m);
        }
        if let Some(l) = t.tmc_limit {
            change.option |= 0x20;
            change.tmc_limit = Some(l);
        }
    }
    if let Some(c) = &i.crl {
        if fs.crl.is_none() {
            return Err(format!("File {no:02X} is not a CRL file."));
        }
        if c.increment_by_one && !c.require_signature {
            return Err("\"Version must increase by exactly 1\" needs the signature requirement as well.".into());
        }
        if c.sig_key > 4 {
            return Err("CA root key numbers go from 0 to 4.".into());
        }
        let options = u8::from(c.require_signature) | (u8::from(c.increment_by_one) << 1);
        change.crl = Some(CrlChange {
            options,
            csn_size: if c.active { 4 } else { 0 },
            sig_key: c.require_signature.then_some(c.sig_key),
        });
    }
    Ok(change)
}

// ---------------------------------------------------------------------- keys

/// What the planner needs to know about the current key situation.
#[derive(Debug, Clone)]
pub struct KeyEnv<'a> {
    pub picc: bool,
    pub auth: Option<&'a AuthSummary>,
    pub keys: Option<&'a KeySettings>,
    pub second_selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeKeyInput {
    pub key_no: u8,
    pub second_app: bool,
    pub new_key: Vec<u8>,
    pub old_key: Option<Vec<u8>>,
    pub version: u8,
    pub key_set: Option<u8>,
}

pub fn plan_change_key(i: &ChangeKeyInput, env: &KeyEnv<'_>) -> Result<ChangeKeySpec, String> {
    let Some(auth) = env.auth else {
        return Err("ChangeKey needs an authentication that may change this key. Authenticate first.".into());
    };
    if !matches!(i.new_key.len(), 16 | 32) {
        return Err(format!("An AES key has 16 or 32 bytes; the new key has {}.", i.new_key.len()));
    }
    if i.second_app && !env.second_selected {
        return Err("No second application is selected.".into());
    }
    if i.second_app && env.picc {
        return Err("The PICC level has no second application.".into());
    }
    let mut key_no = i.key_no;
    if env.picc {
        if i.key_set.is_some() {
            return Err("The PICC level has no key sets.".into());
        }
        if !PICC_KEYS.contains(&key_no) {
            return Err(format!("{key_no:02X} is not a PICC level key (00, 10-12, 18-1A, 20, 21)."));
        }
        // the key type travels in the key number for these keys
        if matches!(key_no, 0x00 | 0x20 | 0x21) {
            key_no |= if i.new_key.len() == 32 { 0xC0 } else { 0x80 };
        }
    } else {
        if key_no > 0x3F {
            return Err("Key numbers go up to 3F.".into());
        }
        if let Some(k) = env.keys {
            let (n, tmp) = app_key_count(k, false);
            if key_no >= n {
                return Err(if tmp {
                    "Only key 00 exists while the AppMasterTmpKey is active.".to_string()
                } else {
                    format!("The application has {n} key(s), numbered from 00; key {key_no:02X} does not exist.")
                });
            }
            let want = match k.key_type {
                2 => Some(16),
                3 => Some(32),
                _ => None,
            };
            if want.is_some_and(|w| w != i.new_key.len()) {
                return Err(format!(
                    "The application's keys are {}; the new key must have {} bytes.",
                    super::model::aes_type_name(k.key_type),
                    want.unwrap_or(0)
                ));
            }
            if i.key_set.is_some() && k.key_sets.is_none() {
                return Err("This application has no key sets.".into());
            }
        }
        if let Some(ks) = i.key_set {
            if ks > 15 {
                return Err("Key set numbers go from 0 to 15.".into());
            }
        }
        if i.second_app {
            key_no |= 0x80;
        }
    }
    let same = auth.kind == AuthKind::Aes
        && auth.key_no == Some(key_no & 0x3F)
        && auth.secondary == i.second_app
        && i.key_set.unwrap_or(0) == 0;
    let mut spec = ChangeKeySpec::new(key_no, &i.new_key, i.version);
    if !same {
        match &i.old_key {
            Some(o) if o.len() == i.new_key.len() => spec = spec.old_key(o),
            Some(o) => {
                return Err(format!(
                    "The current key has {} bytes but the new one {}; they must be of the same type.",
                    o.len(),
                    i.new_key.len()
                ))
            }
            None => {
                return Err("Changing a key other than the one you are authenticated with needs the current value of that key.".into())
            }
        }
    }
    if let Some(ks) = i.key_set {
        spec = spec.key_set(ks);
    }
    Ok(spec)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySettingsInput {
    pub master_changeable: bool,
    pub listing_free: bool,
    pub create_delete_free: bool,
    pub settings_changeable: bool,
    /// Upper nibble: ChangeKey access condition (application) or bit 4 (PICC level).
    pub upper: u8,
}

pub fn plan_key_settings(i: &KeySettingsInput, env: &KeyEnv<'_>) -> Result<u8, String> {
    if let Some(k) = env.keys {
        if k.settings & 0x08 == 0 {
            return Err("The key settings of this level are frozen and cannot be changed any more.".into());
        }
    }
    if env.auth.is_none() {
        return Err("ChangeKeySettings needs an authentication with the master key. Authenticate first.".into());
    }
    let upper = if env.picc { i.upper & 1 } else { i.upper & 0x0F };
    Ok(u8::from(i.master_changeable)
        | u8::from(i.listing_free) << 1
        | u8::from(i.create_delete_free) << 2
        | u8::from(i.settings_changeable) << 3
        | upper << 4)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairAction {
    Generate,
    Import,
    UpdateMetaData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPairInput {
    pub key_no: u8,
    pub action: PairAction,
    pub curve: u8,
    pub policy: u16,
    pub write_mode: CommMode,
    pub write_ac: u8,
    pub limit: u32,
    /// Raw private key to import (32 bytes), already taken from the store or typed in.
    pub import_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct KeyPairPlan {
    pub spec: KeyPairSpec,
    pub op: KeyPairOp,
    pub mode: CommMode,
    /// The slot exists already; generating or importing replaces its key.
    pub replaces: bool,
}

/// CommMode for a command on an asymmetric key entry, from cached knowledge only.
fn asym_mode(authenticated: bool, existing_access: Option<u8>) -> CommMode {
    match (authenticated, existing_access) {
        (false, _) => CommMode::Plain,
        (true, Some(a)) => CommMode::from_bits(a >> 4),
        (true, None) => CommMode::Full,
    }
}

pub fn plan_key_pair(i: &KeyPairInput, picc: bool, authenticated: bool, existing: &[EccKeyInfo]) -> Result<KeyPairPlan, String> {
    let max = if picc { 1 } else { 4 };
    if i.key_no > max {
        return Err(format!(
            "{} ECC private keys are numbered 0 to {max}.",
            if picc { "PICC level" } else { "Application" }
        ));
    }
    if i.write_ac > 0x0F {
        return Err("The update access condition is a single hex digit (0 to F).".into());
    }
    let cur = existing.iter().find(|k| k.key_no == i.key_no);
    if i.action == PairAction::UpdateMetaData && cur.is_none() {
        return Err(format!("There is no ECC private key {} whose meta-data could be updated.", i.key_no));
    }
    let op = match i.action {
        PairAction::Generate => KeyPairOp::Generate,
        PairAction::UpdateMetaData => KeyPairOp::UpdateMetadata,
        PairAction::Import => {
            if i.import_key.len() != 32 {
                return Err("Choose a card identity from the store or enter a 32-byte private key.".into());
            }
            priv_from_bytes(i.curve, &i.import_key).map_err(|e| format!("The private key cannot be used on this curve: {e}"))?;
            KeyPairOp::Import(i.import_key.clone())
        }
    };
    let wa = (i.write_mode.bits() << 4) | i.write_ac;
    let spec = KeyPairSpec::new(i.key_no, i.curve, i.policy, wa).kuc_limit(i.limit);
    Ok(KeyPairPlan {
        spec,
        op,
        mode: asym_mode(authenticated, cur.map(|k| k.write_access)),
        replaces: cur.is_some() && i.action != PairAction::UpdateMetaData,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaKeyInput {
    pub key_no: u8,
    pub curve: u8,
    pub public_key: Vec<u8>,
    /// DER of the trusted issuer name, empty for none.
    pub issuer: Vec<u8>,
    pub acmap: AcMap,
    pub write_mode: CommMode,
    pub write_ac: u8,
    pub read_mode: CommMode,
    pub read_ac: u8,
    /// (CRL file number, AID holding it) when revocation is enabled.
    pub crl: Option<(u8, Aid)>,
}

#[derive(Debug, Clone)]
pub struct CaKeyPlan {
    pub spec: CaRootKeySpec,
    pub mode: CommMode,
    pub replaces: bool,
}

pub fn plan_ca_key(
    i: &CaKeyInput,
    picc: bool,
    authenticated: bool,
    existing: &[duox::card::CaRootKeyInfo],
) -> Result<CaKeyPlan, String> {
    let max = if picc { 1 } else { 4 };
    if i.key_no > max {
        return Err(format!("{} have CA root key numbers 0 to {max}.", if picc { "The PICC level" } else { "An application" }));
    }
    if i.write_ac > 0x0F || i.read_ac > 0x0F {
        return Err("Access conditions are a single hex digit (0 to F).".into());
    }
    PubKey::from_bytes(i.curve, &i.public_key).map_err(|e| format!("The public key is not valid on this curve: {e}"))?;
    if i.issuer.len() > 255 {
        return Err("The issuer name is longer than 255 bytes.".into());
    }
    if let Some((f, _)) = i.crl {
        if f > 0x1F {
            return Err("CRL file numbers go from 00 to 1F.".into());
        }
    }
    let cur = existing.iter().find(|k| k.key_no == i.key_no);
    let mut spec = CaRootKeySpec::new(i.key_no, i.curve, i.public_key.clone());
    spec.access_rights = i.acmap.bits();
    spec.write_access = (i.write_mode.bits() << 4) | i.write_ac;
    spec.read_access = (i.read_mode.bits() << 4) | i.read_ac;
    spec.issuer = i.issuer.clone();
    if let Some((f, aid)) = i.crl {
        spec.crl_file = 0x80 | f;
        spec.crl_aid = aid;
    }
    Ok(CaKeyPlan {
        spec,
        mode: asym_mode(authenticated, cur.map(|k| k.write_access)),
        replaces: cur.is_some(),
    })
}

/// Mode for ExportKey from the cached read access of the key.
pub fn export_mode(authenticated: bool, k: &duox::card::CaRootKeyInfo) -> CommMode {
    asym_mode(authenticated, Some(k.read_access))
}

// ------------------------------------------------------------------- outputs

/// The certificate bytes of a certificate file read from the card: `CLEN || certificate ||
/// padding`, or raw DER.
pub fn certificate_blob(data: &[u8]) -> &[u8] {
    if data.len() > 3 {
        let clen = u32::from_le_bytes([data[0], data[1], data[2], 0]) as usize;
        if clen > 0 && clen <= data.len() - 3 && data[3] == 0x30 {
            return &data[3..3 + clen];
        }
    }
    data
}

/// Describe the certificates in a certificate file and check them against the trust anchors.
pub fn decode_certificates(data: &[u8], anchors: &[TrustAnchor]) -> Result<Vec<String>, String> {
    let blob = certificate_blob(data);
    let ders = duox::pki::der::split_sequences(blob);
    if ders.is_empty() {
        return Err("No DER certificate found. Expected CertificateLength || certificate || padding, or raw DER.".into());
    }
    let mut out = vec![format!("{} certificate(s), {} bytes", ders.len(), ders.iter().map(|d| d.len()).sum::<usize>()), String::new()];
    for der in &ders {
        out.extend(duox::pki::describe_der(der));
        out.push(String::new());
    }
    match duox::pki::verify_card_chain(blob, anchors) {
        Ok(c) => {
            out.push(format!("Chain: {}", c.path.join(" <- ")));
            out.push(match &c.anchor {
                Some(a) if c.trusted => format!("Trust: anchored at '{a}'"),
                _ => format!("Trust: NOT anchored in the local store (issuer {})", c.issuer),
            });
        }
        Err(e) => out.push(format!("Chain: cannot be checked ({e})")),
    }
    Ok(out)
}

/// Records of a read, oldest first, each as a dump.
pub fn records_text(data: &[u8], record_size: u32) -> String {
    if record_size == 0 {
        return String::new();
    }
    let mut out = String::new();
    for (i, rec) in data.chunks(record_size as usize).enumerate() {
        out.push_str(&format!("record {i} (oldest first)\n{}\n", hex::dump(rec)));
    }
    out
}

/// Reading a TransactionMAC file returns TMC (4 bytes) and TMV (8 bytes) or TSV (64 bytes).
pub fn tmac_read_text(data: &[u8]) -> Vec<String> {
    if data.len() < 4 {
        return vec![format!("Unexpected content: {}", hex::spaced(data))];
    }
    let tmc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    vec![
        format!("TMC {tmc}"),
        format!("{} {}", if data.len() > 12 { "TSV" } else { "TMV" }, hex::spaced(&data[4..])),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use duox::card::{CaRootKeyInfo, KeySetInfo};

    fn file(bytes: &[u8]) -> FileSettings {
        FileSettings::parse(1, bytes).unwrap()
    }
    /// StandardData, option, access 0x1234-style, size
    fn data_file(option: u8, ar: u16, size: u32) -> FileSettings {
        let mut d = vec![0x00, option];
        d.extend(ar.to_le_bytes());
        d.extend(&size.to_le_bytes()[..3]);
        file(&d)
    }

    fn app_input() -> AppInput {
        AppInput {
            aid: 0x112233,
            keys: 3,
            aes256: false,
            key_sett1: 0x0F,
            iso_file_ids: false,
            iso_fid: None,
            df_name: vec![],
            key_sets: None,
        }
    }

    #[test]
    fn access_problem_reports_keys_and_never() {
        // Read=E Write=1 ReadWrite=2 Change=0: reading is free, writing needs key 1 or 2
        let fs = data_file(0x03, 0xE120, 16);
        assert!(access_problem(&fs, false, |_, _| false).is_none());
        let msg = access_problem(&fs, true, |_, _| false).unwrap();
        assert!(msg.contains("key 1 or key 2") && msg.contains("writing"), "{msg}");
        assert!(access_problem(&fs, true, |a, _| a == AccessRight::key(2)).is_none());
        // Read=F Write=F ReadWrite=F
        let never = data_file(0x03, 0xFFFF, 16);
        assert!(access_problem(&never, false, |_, _| false).unwrap().contains("never"));
    }

    #[test]
    fn write_checks_type_bounds_and_crl() {
        let fs = data_file(0x03, 0xEEEE, 16);
        assert!(plan_write(&fs, 0, &[1; 16]).is_ok());
        assert!(plan_write(&fs, 8, &[1; 9]).unwrap_err().contains("would end after"));
        assert!(plan_write(&fs, 0, &[]).is_err());
        let crl = file(&[0x00, 0x00, 0xEE, 0xEE, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01]);
        assert!(plan_write(&crl, 0, &[1]).unwrap_err().contains("CRL"));
        let value = file(&[0x02, 0x03, 0xEE, 0xEE, 0, 0, 0, 0, 0xE8, 3, 0, 0, 0, 0, 0, 0, 0]);
        assert!(plan_write(&value, 0, &[1]).unwrap_err().contains("not a data file"));
    }

    #[test]
    fn value_and_record_rules() {
        let value = file(&[0x02, 0x03, 0xEE, 0xEE, 0, 0, 0, 0, 0xE8, 3, 0, 0, 0, 0, 0, 0, 0x00]);
        assert_eq!(plan_value(&value, ValueOp::Credit, 5), Ok(5));
        assert!(plan_value(&value, ValueOp::Credit, 0).is_err());
        assert!(plan_value(&value, ValueOp::Credit, 1 << 31).is_err());
        assert!(plan_value(&value, ValueOp::LimitedCredit, 5).unwrap_err().contains("LimitedCredit"));
        let limited = file(&[0x02, 0x03, 0xEE, 0xEE, 0, 0, 0, 0, 0xE8, 3, 0, 0, 0, 0, 0, 0, 0x01]);
        assert!(plan_value(&limited, ValueOp::LimitedCredit, 5).is_ok());

        // linear record file: size 16, max 2, current 2
        let rec = file(&[0x03, 0x03, 0xEE, 0xEE, 16, 0, 0, 2, 0, 0, 2, 0, 0]);
        assert!(plan_record(&rec, RecordOp::Write, 0, 0, &[1]).is_ok());
        assert!(plan_record(&rec, RecordOp::Update, 1, 0, &[1; 16]).is_ok());
        assert!(plan_record(&rec, RecordOp::Update, 0, 0, &[]).is_err());
        assert!(plan_record(&rec, RecordOp::Update, 0, 10, &[1; 7]).unwrap_err().contains("do not fit"));
        assert!(plan_record(&rec, RecordOp::Clear, 0, 0, &[]).is_ok());
        assert!(plan_record(&value, RecordOp::Clear, 0, 0, &[]).is_err());
    }

    #[test]
    fn application_planning() {
        assert!(plan_app(&app_input(), &[]).is_ok());
        assert!(plan_app(&app_input(), &[Aid(0x112233)]).unwrap_err().contains("already exists"));
        assert!(plan_app(&AppInput { aid: 0, ..app_input() }, &[]).is_err());
        assert!(plan_app(&AppInput { keys: 15, ..app_input() }, &[]).is_err());
        assert!(plan_app(&AppInput { df_name: vec![1], ..app_input() }, &[]).unwrap_err().contains("ISO file ID"));
        assert!(plan_app(&AppInput { iso_fid: Some(0x3F00), ..app_input() }, &[]).unwrap_err().contains("reserved"));
        let ks = KeySetsInput { count: 2, max_aes256: false, roll_key: 0, aks_version: 0 };
        assert!(plan_app(&AppInput { key_sets: Some(ks.clone()), ..app_input() }, &[]).is_ok());
        let bad = KeySetsInput { count: 17, ..ks };
        assert!(plan_app(&AppInput { key_sets: Some(bad), ..app_input() }, &[]).is_err());
    }

    fn file_input(kind: NewFileKind) -> FileInput {
        FileInput {
            number: 5,
            second_app: false,
            iso_fid: None,
            mode: CommMode::Full,
            access: AccessRights::all(AccessRight::key(0)),
            additional_access: false,
            kind,
        }
    }

    #[test]
    fn new_file_planning() {
        let data = NewFileKind::Data { backup: false, size: 32, sdm: false, crl: false };
        assert!(matches!(plan_new_file(&file_input(data.clone()), &[], false), Ok(FileSpec::Data(_))));
        assert!(plan_new_file(&file_input(data.clone()), &[(5, FileType::StandardData)], false).unwrap_err().contains("already exists"));
        // the same number in the second application is a different file
        let mut second = file_input(data.clone());
        second.second_app = true;
        match plan_new_file(&second, &[(5, FileType::StandardData)], false).unwrap() {
            FileSpec::Data(s) => assert_eq!(s.file_no, 0x85),
            _ => panic!("data spec expected"),
        }
        let sdm_backup = NewFileKind::Data { backup: true, size: 32, sdm: true, crl: false };
        assert!(plan_new_file(&file_input(sdm_backup), &[], false).is_err());
        let value = NewFileKind::Value { lower: 0, upper: 100, initial: 200, limited_credit: false, free_get_value: false };
        assert!(plan_new_file(&file_input(value), &[], false).unwrap_err().contains("initial value"));
        let cyc = NewFileKind::Record { cyclic: true, record_size: 8, max_records: 1 };
        assert!(plan_new_file(&file_input(cyc), &[], false).unwrap_err().contains("at least 2"));
        let tm = NewFileKind::Tmac { key: vec![0; 10], key_version: 0, signature_key: None };
        assert!(plan_new_file(&file_input(tm), &[], false).unwrap_err().contains("16 or 32"));
        let tm = NewFileKind::Tmac { key: vec![0; 16], key_version: 0, signature_key: None };
        assert!(plan_new_file(&file_input(tm.clone()), &[(2, FileType::TransactionMac)], false).unwrap_err().contains("only one"));
        assert!(plan_new_file(&file_input(tm), &[], false).is_ok());
        // PICC level: standard data with ISO id only
        assert!(plan_new_file(&file_input(data.clone()), &[], true).unwrap_err().contains("ISO file ID"));
        let mut picc = file_input(data);
        picc.iso_fid = Some(0xE001);
        assert!(plan_new_file(&picc, &[], true).is_ok());
        let rec = NewFileKind::Record { cyclic: false, record_size: 8, max_records: 4 };
        assert!(plan_new_file(&file_input(rec), &[], true).is_err());
    }

    #[test]
    fn file_change_planning() {
        let fs = data_file(0x83, 0xE120, 16);
        let i = ChangeInput {
            mode: CommMode::Mac,
            access: AccessRights::from_u16(0x1111),
            additional: Some(vec![AccessRights::from_u16(0x2220)]),
            crl: None,
        };
        let c = plan_file_change(&fs, &i).unwrap();
        assert_eq!(c.option, 0x81);
        assert_eq!(c.additional.len(), 1);
        assert_eq!(c.current_change_access, AccessRight::key(0));
        let frozen = data_file(0x03, 0xE12F, 16);
        assert!(plan_file_change(&frozen, &i).unwrap_err().contains("never"));
        assert!(plan_file_change(&fs, &ChangeInput { crl: Some(CrlInput { require_signature: false, increment_by_one: true, active: true, sig_key: 0 }), ..i.clone() }).is_err());
        assert_eq!(parse_additional_sets("1234, 0xABCD").unwrap().len(), 2);
        assert!(parse_additional_sets("12G4").is_err());
    }

    #[test]
    fn crl_change_sends_signature_key_only_when_required() {
        let crl = file(&[0x00, 0x00, 0xEE, 0xE0, 0x10, 0x00, 0x00, 0x03, 0x04, 0x01]);
        let mk = |sig| ChangeInput {
            mode: CommMode::Plain,
            access: AccessRights::from_u16(0xEEE0),
            additional: None,
            crl: Some(CrlInput { require_signature: sig, increment_by_one: sig, active: true, sig_key: 2 }),
        };
        let c = plan_file_change(&crl, &mk(true)).unwrap().crl.unwrap();
        assert_eq!((c.options, c.csn_size, c.sig_key), (3, 4, Some(2)));
        let c = plan_file_change(&crl, &mk(false)).unwrap().crl.unwrap();
        assert_eq!((c.options, c.csn_size, c.sig_key), (0, 4, None));
    }

    fn summary(key_no: u8) -> AuthSummary {
        AuthSummary {
            kind: AuthKind::Aes,
            key_no: Some(key_no),
            secondary: false,
            key_bits: 128,
            acmap: 0,
            acmap2: 0,
            cmd_ctr: 0,
            ti: [0; 4],
        }
    }

    fn app_keys(max_keys: u8, key_type: u8, sets: bool) -> KeySettings {
        KeySettings {
            settings: 0x0F,
            max_keys,
            key_type,
            key_sets: sets.then(|| KeySetInfo { aks_version: 0, key_sets: 2, max_key_size: 0x10, key_set_settings: 0 }),
            raw: vec![],
        }
    }

    #[test]
    fn change_key_planning() {
        let auth = summary(0);
        let keys = app_keys(3, 2, false);
        let env = KeyEnv { picc: false, auth: Some(&auth), keys: Some(&keys), second_selected: false };
        let i = ChangeKeyInput { key_no: 0, second_app: false, new_key: vec![1; 16], old_key: None, version: 1, key_set: None };
        // the authenticated key needs no old key
        let spec = plan_change_key(&i, &env).unwrap();
        assert_eq!((spec.key_no, spec.old_key.is_none()), (0, true));
        // another key does
        let other = ChangeKeyInput { key_no: 1, ..i.clone() };
        assert!(plan_change_key(&other, &env).unwrap_err().contains("current value"));
        let with_old = ChangeKeyInput { old_key: Some(vec![0; 16]), ..other.clone() };
        assert!(plan_change_key(&with_old, &env).is_ok());
        let wrong_len = ChangeKeyInput { old_key: Some(vec![0; 32]), ..other.clone() };
        assert!(plan_change_key(&wrong_len, &env).is_err());
        // key out of range, wrong type, no auth, no key sets
        assert!(plan_change_key(&ChangeKeyInput { key_no: 3, ..i.clone() }, &env).unwrap_err().contains("does not exist"));
        assert!(plan_change_key(&ChangeKeyInput { new_key: vec![1; 32], ..i.clone() }, &env).unwrap_err().contains("AES-128"));
        let noauth = KeyEnv { auth: None, ..env.clone() };
        assert!(plan_change_key(&i, &noauth).unwrap_err().contains("Authenticate first"));
        assert!(plan_change_key(&ChangeKeyInput { key_set: Some(1), ..i.clone() }, &env).unwrap_err().contains("no key sets"));
        let sets = app_keys(3, 2, true);
        let env2 = KeyEnv { keys: Some(&sets), ..env.clone() };
        let spec = plan_change_key(&ChangeKeyInput { key_set: Some(1), key_no: 1, old_key: Some(vec![0; 16]), ..i.clone() }, &env2).unwrap();
        assert_eq!(spec.key_set, Some(1));
        // second application
        assert!(plan_change_key(&ChangeKeyInput { second_app: true, ..i.clone() }, &env).unwrap_err().contains("second application"));
    }

    #[test]
    fn change_key_at_picc_level_adds_key_type() {
        let auth = summary(0);
        let env = KeyEnv { picc: true, auth: Some(&auth), keys: None, second_selected: false };
        let i = ChangeKeyInput { key_no: 0, second_app: false, new_key: vec![1; 32], old_key: None, version: 0, key_set: None };
        assert_eq!(plan_change_key(&i, &env).unwrap().key_no, 0xC0);
        let i16 = ChangeKeyInput { new_key: vec![1; 16], ..i.clone() };
        assert_eq!(plan_change_key(&i16, &env).unwrap().key_no, 0x80);
        assert!(plan_change_key(&ChangeKeyInput { key_no: 5, ..i16.clone() }, &env).unwrap_err().contains("not a PICC level key"));
        // a PICC key other than the authenticated one keeps its number and needs the old key
        let dam = ChangeKeyInput { key_no: 0x11, old_key: Some(vec![0; 16]), ..i16 };
        assert_eq!(plan_change_key(&dam, &env).unwrap().key_no, 0x11);
    }

    #[test]
    fn key_settings_byte() {
        let auth = summary(0);
        let keys = app_keys(3, 2, false);
        let env = KeyEnv { picc: false, auth: Some(&auth), keys: Some(&keys), second_selected: false };
        let i = KeySettingsInput { master_changeable: true, listing_free: false, create_delete_free: true, settings_changeable: true, upper: 0xE };
        assert_eq!(plan_key_settings(&i, &env), Ok(0xED));
        let picc = KeyEnv { picc: true, ..env.clone() };
        assert_eq!(plan_key_settings(&KeySettingsInput { upper: 0xE, ..i.clone() }, &picc), Ok(0x0D));
        let frozen = KeySettings { settings: 0x07, ..keys.clone() };
        let env3 = KeyEnv { keys: Some(&frozen), ..env.clone() };
        assert!(plan_key_settings(&i, &env3).unwrap_err().contains("frozen"));
        assert!(plan_key_settings(&i, &KeyEnv { auth: None, ..env }).is_err());
    }

    fn ecc_key(no: u8, write_access: u8) -> EccKeyInfo {
        EccKeyInfo { key_no: no, curve: 0x0C, policy: 0x80, write_access, kuc_limit: 0, kuc: 0 }
    }

    fn pair_input(action: PairAction) -> KeyPairInput {
        KeyPairInput {
            key_no: 1,
            action,
            curve: 0x0C,
            policy: 0x0080,
            write_mode: CommMode::Full,
            write_ac: 0,
            limit: 0,
            import_key: vec![],
        }
    }

    #[test]
    fn key_pair_planning() {
        let existing = [ecc_key(1, 0x10)];
        let p = plan_key_pair(&pair_input(PairAction::Generate), false, true, &existing).unwrap();
        assert!(p.replaces);
        assert_eq!(p.mode, CommMode::Mac); // the slot's own write access says MAC
        assert_eq!(p.spec.write_access, 0x30);
        let fresh = plan_key_pair(&KeyPairInput { key_no: 2, ..pair_input(PairAction::Generate) }, false, true, &existing).unwrap();
        assert!(!fresh.replaces);
        assert_eq!(fresh.mode, CommMode::Full);
        let plain = plan_key_pair(&KeyPairInput { key_no: 2, ..pair_input(PairAction::Generate) }, false, false, &existing).unwrap();
        assert_eq!(plain.mode, CommMode::Plain);
        assert!(plan_key_pair(&KeyPairInput { key_no: 5, ..pair_input(PairAction::Generate) }, false, true, &[]).is_err());
        assert!(plan_key_pair(&KeyPairInput { key_no: 2, ..pair_input(PairAction::Generate) }, true, true, &[]).is_err());
        assert!(plan_key_pair(&KeyPairInput { key_no: 2, ..pair_input(PairAction::UpdateMetaData) }, false, true, &existing).is_err());
        assert!(plan_key_pair(&pair_input(PairAction::Import), false, true, &existing).unwrap_err().contains("32-byte"));
        let imp = KeyPairInput { import_key: vec![0; 32], ..pair_input(PairAction::Import) };
        assert!(plan_key_pair(&imp, false, true, &existing).unwrap_err().contains("cannot be used"));
        let imp = KeyPairInput { import_key: vec![7; 32], ..pair_input(PairAction::Import) };
        assert!(matches!(plan_key_pair(&imp, false, true, &existing).unwrap().op, KeyPairOp::Import(_)));
    }

    #[test]
    fn ca_key_planning() {
        let key = duox::crypto::gen_key(0x0C).unwrap().public().to_bytes();
        let i = CaKeyInput {
            key_no: 0,
            curve: 0x0C,
            public_key: key.clone(),
            issuer: vec![],
            acmap: AcMap::ALL,
            write_mode: CommMode::Full,
            write_ac: 0,
            read_mode: CommMode::Mac,
            read_ac: 0xE,
            crl: Some((3, Aid(0x42))),
        };
        let existing = [CaRootKeyInfo { key_no: 0, curve: 0x0C, access_rights: 1, write_access: 0x30, read_access: 0x1E, crl_file: 0, crl_aid: Aid(0) }];
        let p = plan_ca_key(&i, false, true, &existing).unwrap();
        assert!(p.replaces);
        assert_eq!(p.mode, CommMode::Full);
        assert_eq!((p.spec.access_rights, p.spec.write_access, p.spec.read_access), (0x3FFF, 0x30, 0x1E));
        assert_eq!((p.spec.crl_file, p.spec.crl_aid), (0x83, Aid(0x42)));
        let bad_pub = CaKeyInput { public_key: vec![4; 65], ..i.clone() };
        assert!(plan_ca_key(&bad_pub, false, true, &[]).unwrap_err().contains("not valid"));
        assert!(plan_ca_key(&CaKeyInput { key_no: 2, ..i.clone() }, true, true, &[]).is_err());
        assert!(plan_ca_key(&CaKeyInput { crl: Some((0x20, Aid(0))), ..i }, false, true, &[]).is_err());
        assert_eq!(export_mode(true, &existing[0]), CommMode::Mac);
        assert_eq!(export_mode(false, &existing[0]), CommMode::Plain);
    }

    #[test]
    fn certificate_payload_wraps_der_and_pem() {
        let der = vec![0x30, 0x03, 1, 2, 3];
        assert_eq!(certificate_file_payload(&der).unwrap(), [5, 0, 0, 0x30, 0x03, 1, 2, 3]);
        assert!(certificate_file_payload(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err());
    }

    #[test]
    fn decoding_a_certificate_file_checks_trust() {
        use duox::crypto::gen_key;
        use duox::pki::{CertificateBuilder, Name};
        let ca_key = gen_key(0x0C).unwrap();
        let card_key = gen_key(0x0C).unwrap();
        let ca_name = Name::with_common_name("Test CA", "Test");
        let ca = CertificateBuilder::new(ca_name.clone(), ca_name.clone(), ca_key.public()).ca(true).sign(&ca_key).unwrap();
        let card = CertificateBuilder::new(Name::with_common_name("Card", "Test"), ca_name, card_key.public())
            .sign(&ca_key)
            .unwrap();
        let image = certfile::build_image(card.to_der(), Some(card.to_der().len() + 20)).unwrap();
        assert_eq!(certificate_blob(&image), card.to_der());
        let text = decode_certificates(&image, &[TrustAnchor::Certificate(ca)]).unwrap().join("\n");
        assert!(text.contains("1 certificate(s)") && text.contains("Trust: anchored at"), "{text}");
        let text = decode_certificates(&image, &[]).unwrap().join("\n");
        assert!(text.contains("NOT anchored"), "{text}");
        // raw DER and garbage
        assert!(decode_certificates(card.to_der(), &[]).is_ok());
        assert!(decode_certificates(&[1, 2, 3, 4, 5], &[]).is_err());
    }

    #[test]
    fn single_conditions() {
        assert!(condition_problem("Change", AccessRight::FREE, false, |_, _| false).is_none());
        assert!(condition_problem("Change", AccessRight::key(2), false, |a, _| a.0 == 2).is_none());
        assert!(condition_problem("Change", AccessRight::key(2), false, |_, _| false).unwrap().contains("key 2"));
        assert!(condition_problem("Change", AccessRight::NEVER, false, |_, _| false).unwrap().contains("never"));
        assert!(master_key_problem("Deleting", true, |_, _| false).is_some());
        assert!(master_key_problem("Deleting", false, |_, _| false).is_none());
    }

    #[test]
    fn read_outputs() {
        let t = tmac_read_text(&[5, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(t[0], "TMC 5");
        assert!(t[1].starts_with("TMV 01 02"));
        assert!(tmac_read_text(&[1]).len() == 1);
        let r = records_text(&[1, 2, 3, 4], 2);
        assert!(r.contains("record 0") && r.contains("record 1"));
        assert_eq!(records_text(&[1], 0), "");
    }
}
