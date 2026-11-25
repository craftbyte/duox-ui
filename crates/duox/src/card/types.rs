//! Typed vocabulary of the DUOX command set: communication modes, file types, access rights,
//! status codes, command codes and small helpers shared by all command groups.

use crate::error::{Error, Result};
use std::fmt;

// ------------------------------------------------------------------ CommMode
/// Communication mode (wire bits of FileOption / key access fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CommMode {
    #[default]
    Plain,
    Mac,
    Full,
}

impl CommMode {
    /// The two FileOption bits.
    pub fn bits(self) -> u8 {
        match self {
            CommMode::Plain => 0,
            CommMode::Mac => 1,
            CommMode::Full => 3,
        }
    }
    /// Decode the low two bits (value 2 is reserved and treated as Plain, as the card does not use it).
    pub fn from_bits(b: u8) -> Self {
        match b & 3 {
            1 => CommMode::Mac,
            3 => CommMode::Full,
            _ => CommMode::Plain,
        }
    }
}

impl fmt::Display for CommMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CommMode::Plain => "Plain",
            CommMode::Mac => "MAC",
            CommMode::Full => "Full",
        })
    }
}

// ------------------------------------------------------------------ FileType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    StandardData = 0,
    BackupData = 1,
    Value = 2,
    LinearRecord = 3,
    CyclicRecord = 4,
    TransactionMac = 5,
}

impl FileType {
    pub fn code(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            FileType::StandardData => "StandardData",
            FileType::BackupData => "BackupData",
            FileType::Value => "Value",
            FileType::LinearRecord => "LinearRecord",
            FileType::CyclicRecord => "CyclicRecord",
            FileType::TransactionMac => "TransactionMAC",
        }
    }
}

impl TryFrom<u8> for FileType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0 => FileType::StandardData,
            1 => FileType::BackupData,
            2 => FileType::Value,
            3 => FileType::LinearRecord,
            4 => FileType::CyclicRecord,
            5 => FileType::TransactionMac,
            _ => return Err(Error::protocol(format!("unknown file type {v}"))),
        })
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// --------------------------------------------------------------- AccessRight
/// One access condition: a key number 0..=0xD, [`FREE`](Self::FREE) (0xE) or [`NEVER`](Self::NEVER) (0xF).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessRight(pub u8);

impl AccessRight {
    pub const FREE: AccessRight = AccessRight(0xE);
    pub const NEVER: AccessRight = AccessRight(0xF);

    pub fn key(n: u8) -> Self {
        AccessRight(n & 0x0F)
    }
    pub fn is_key(self) -> bool {
        self.0 <= 0xD
    }
    pub fn is_free(self) -> bool {
        self == Self::FREE
    }
    pub fn is_never(self) -> bool {
        self == Self::NEVER
    }
}

impl fmt::Display for AccessRight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0xE => f.write_str("free"),
            0xF => f.write_str("never"),
            n => write!(f, "key {n:X}"),
        }
    }
}

/// The four access right nibbles of a file (transmitted as a little-endian u16
/// `Read<<12 | Write<<8 | ReadWrite<<4 | Change`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessRights {
    pub read: AccessRight,
    pub write: AccessRight,
    pub read_write: AccessRight,
    pub change: AccessRight,
}

impl AccessRights {
    pub fn new(read: AccessRight, write: AccessRight, read_write: AccessRight, change: AccessRight) -> Self {
        AccessRights { read, write, read_write, change }
    }
    /// All four rights set to the same condition.
    pub fn all(ar: AccessRight) -> Self {
        Self::new(ar, ar, ar, ar)
    }
    pub fn from_u16(v: u16) -> Self {
        AccessRights {
            read: AccessRight((v >> 12) as u8 & 0xF),
            write: AccessRight((v >> 8) as u8 & 0xF),
            read_write: AccessRight((v >> 4) as u8 & 0xF),
            change: AccessRight(v as u8 & 0xF),
        }
    }
    pub fn to_u16(self) -> u16 {
        (self.read.0 as u16) << 12 | (self.write.0 as u16) << 8 | (self.read_write.0 as u16) << 4 | self.change.0 as u16
    }
    /// Two wire bytes (little endian).
    pub fn to_bytes(self) -> [u8; 2] {
        self.to_u16().to_le_bytes()
    }
}

impl From<u16> for AccessRights {
    fn from(v: u16) -> Self {
        Self::from_u16(v)
    }
}

impl fmt::Display for AccessRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Read={} Write={} ReadWrite={} Change={}",
            self.read, self.write, self.read_write, self.change
        )
    }
}

// ---------------------------------------------------------------------- Aid
/// Application identifier (3 bytes, transmitted least significant byte first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Aid(pub u32);

impl Aid {
    /// The PICC level "application".
    pub const PICC: Aid = Aid(0);
    pub fn to_bytes(self) -> [u8; 3] {
        let b = self.0.to_le_bytes();
        [b[0], b[1], b[2]]
    }
    pub fn from_bytes(b: &[u8]) -> Aid {
        let mut v = [0u8; 4];
        let n = b.len().min(3);
        v[..n].copy_from_slice(&b[..n]);
        Aid(u32::from_le_bytes(v))
    }
}

impl From<u32> for Aid {
    fn from(v: u32) -> Self {
        Aid(v)
    }
}

impl fmt::Display for Aid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06X}", self.0)
    }
}

// --------------------------------------------------------------------- Status
/// Native response status (the second status byte of a `91xx` response).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    OperationOk,
    OperationOkLim,
    NoChanges,
    OutOfMemory,
    IllegalCommandCode,
    IntegrityError,
    WeakField,
    NoSuchKey,
    LengthError,
    PermissionDenied,
    ParameterError,
    ApplicationNotFound,
    AuthenticationError,
    AdditionalFrame,
    BoundaryError,
    CommandAborted,
    CertError,
    DuplicateError,
    FileNotFound,
    PadVoltageUnreliable,
    /// Not in the table of the data sheet.
    Other(u8),
}

impl Status {
    pub fn code(self) -> u8 {
        match self {
            Status::OperationOk => 0x00,
            Status::OperationOkLim => 0x01,
            Status::NoChanges => 0x0C,
            Status::OutOfMemory => 0x0E,
            Status::IllegalCommandCode => 0x1C,
            Status::IntegrityError => 0x1E,
            Status::WeakField => 0x1F,
            Status::NoSuchKey => 0x40,
            Status::LengthError => 0x7E,
            Status::PermissionDenied => 0x9D,
            Status::ParameterError => 0x9E,
            Status::ApplicationNotFound => 0xA0,
            Status::AuthenticationError => 0xAE,
            Status::AdditionalFrame => 0xAF,
            Status::BoundaryError => 0xBE,
            Status::CommandAborted => 0xCA,
            Status::CertError => 0xCE,
            Status::DuplicateError => 0xDE,
            Status::FileNotFound => 0xF0,
            Status::PadVoltageUnreliable => 0x2F,
            Status::Other(c) => c,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Status::OperationOk => "OPERATION_OK",
            Status::OperationOkLim => "OPERATION_OK_LIM",
            Status::NoChanges => "NO_CHANGES",
            Status::OutOfMemory => "OUT_OF_MEMORY_ERROR",
            Status::IllegalCommandCode => "ILLEGAL_COMMAND_CODE",
            Status::IntegrityError => "INTEGRITY_ERROR",
            Status::WeakField => "WEAK_FIELD",
            Status::NoSuchKey => "NO_SUCH_KEY",
            Status::LengthError => "LENGTH_ERROR",
            Status::PermissionDenied => "PERMISSION_DENIED",
            Status::ParameterError => "PARAMETER_ERROR",
            Status::ApplicationNotFound => "APPLICATION_NOT_FOUND",
            Status::AuthenticationError => "AUTHENTICATION_ERROR",
            Status::AdditionalFrame => "ADDITIONAL_FRAME",
            Status::BoundaryError => "BOUNDARY_ERROR",
            Status::CommandAborted => "COMMAND_ABORTED",
            Status::CertError => "CERT_ERROR",
            Status::DuplicateError => "DUPLICATE_ERROR",
            Status::FileNotFound => "FILE_NOT_FOUND",
            Status::PadVoltageUnreliable => "PAD_VOLTAGE_UNRELIABLE",
            Status::Other(_) => "unknown status",
        }
    }

    pub fn is_ok(self) -> bool {
        matches!(self, Status::OperationOk | Status::OperationOkLim)
    }
}

impl From<u8> for Status {
    fn from(c: u8) -> Self {
        match c {
            0x00 => Status::OperationOk,
            0x01 => Status::OperationOkLim,
            0x0C => Status::NoChanges,
            0x0E => Status::OutOfMemory,
            0x1C => Status::IllegalCommandCode,
            0x1E => Status::IntegrityError,
            0x1F => Status::WeakField,
            0x2F => Status::PadVoltageUnreliable,
            0x40 => Status::NoSuchKey,
            0x7E => Status::LengthError,
            0x9D => Status::PermissionDenied,
            0x9E => Status::ParameterError,
            0xA0 => Status::ApplicationNotFound,
            0xAE => Status::AuthenticationError,
            0xAF => Status::AdditionalFrame,
            0xBE => Status::BoundaryError,
            0xCA => Status::CommandAborted,
            0xCE => Status::CertError,
            0xDE => Status::DuplicateError,
            0xF0 => Status::FileNotFound,
            c => Status::Other(c),
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Status byte of the proximity-check command family (PreparePC / ProximityCheck / VerifyPC).
pub fn pc_status_name(code: u8) -> &'static str {
    match code {
        0x90 => "OK",
        0x06 => "ErrAuth",
        0x07 => "ErrCmdOverflow",
        0x09 => "ErrBNr",
        0x0B => "ErrCmdInvalid",
        0x0C => "ErrFormat",
        0x0F => "ErrGenFailure",
        0xCA => "COMMAND_ABORTED",
        _ => Status::from(code).name(),
    }
}

/// Description of an ISO/IEC 7816-4 status word.
pub fn iso_sw_description(sw: u16) -> &'static str {
    match sw {
        0x9000 => "OK",
        0x6283 => "selected with limited functionality",
        0x6581 => "memory failure",
        0x6700 => "wrong length",
        0x6982 => "security status not satisfied",
        0x6984 => "reference data not usable",
        0x6985 => "conditions of use not satisfied",
        0x6987 => "expected data object missing",
        0x6988 => "unexpected data object",
        0x6A80 => "incorrect parameters in data field",
        0x6A82 => "file or application not found",
        0x6A86 => "incorrect P1-P2",
        0x6A87 => "Lc inconsistent with P1-P2",
        0x6A88 => "referenced key or data not found",
        0x6C00 => "wrong Le",
        0x6D00 => "instruction not supported",
        _ => "unexpected",
    }
}

// ----------------------------------------------------------------- Commands
/// Native command codes.
pub mod cmd {
    pub const AUTH_EV2_FIRST: u8 = 0x71;
    pub const AUTH_EV2_NON_FIRST: u8 = 0x77;
    pub const ADDITIONAL_FRAME: u8 = 0xAF;
    pub const FREE_MEM: u8 = 0x6E;
    pub const FORMAT: u8 = 0xFC;
    pub const SET_CONFIGURATION: u8 = 0x5C;
    pub const GET_CONFIGURATION: u8 = 0x65;
    pub const GET_VERSION: u8 = 0x60;
    pub const GET_CARD_UID: u8 = 0x51;
    pub const CHANGE_KEY: u8 = 0xC4;
    pub const CHANGE_KEY_EV2: u8 = 0xC6;
    pub const INITIALIZE_KEY_SET: u8 = 0x56;
    pub const FINALIZE_KEY_SET: u8 = 0x57;
    pub const ROLL_KEY_SET: u8 = 0x55;
    pub const GET_KEY_SETTINGS: u8 = 0x45;
    pub const CHANGE_KEY_SETTINGS: u8 = 0x54;
    pub const GET_KEY_VERSION: u8 = 0x64;
    pub const MANAGE_KEY_PAIR: u8 = 0x46;
    pub const MANAGE_CA_ROOT_KEY: u8 = 0x48;
    pub const EXPORT_KEY: u8 = 0x47;
    pub const CREATE_APPLICATION: u8 = 0xCA;
    pub const DELETE_APPLICATION: u8 = 0xDA;
    pub const CREATE_DELEGATED_APPLICATION: u8 = 0xC9;
    pub const SELECT_APPLICATION: u8 = 0x5A;
    pub const GET_APPLICATION_IDS: u8 = 0x6A;
    pub const GET_DF_NAMES: u8 = 0x6D;
    pub const GET_DELEGATED_INFO: u8 = 0x69;
    pub const CREATE_STD_DATA_FILE: u8 = 0xCD;
    pub const CREATE_BACKUP_DATA_FILE: u8 = 0xCB;
    pub const CREATE_VALUE_FILE: u8 = 0xCC;
    pub const CREATE_LINEAR_RECORD_FILE: u8 = 0xC1;
    pub const CREATE_CYCLIC_RECORD_FILE: u8 = 0xC0;
    pub const CREATE_TRANSACTION_MAC_FILE: u8 = 0xCE;
    pub const DELETE_FILE: u8 = 0xDF;
    pub const GET_FILE_IDS: u8 = 0x6F;
    pub const GET_ISO_FILE_IDS: u8 = 0x61;
    pub const GET_FILE_SETTINGS: u8 = 0xF5;
    pub const GET_FILE_COUNTERS: u8 = 0xF6;
    pub const CHANGE_FILE_SETTINGS: u8 = 0x5F;
    pub const READ_DATA: u8 = 0xBD;
    pub const READ_DATA_ISO: u8 = 0xAD;
    pub const WRITE_DATA: u8 = 0x3D;
    pub const WRITE_DATA_CRL: u8 = 0x8D;
    pub const GET_VALUE: u8 = 0x6C;
    pub const CREDIT: u8 = 0x0C;
    pub const DEBIT: u8 = 0xDC;
    pub const LIMITED_CREDIT: u8 = 0x1C;
    pub const READ_RECORDS: u8 = 0xBB;
    pub const READ_RECORDS_ISO: u8 = 0xAB;
    pub const WRITE_RECORD: u8 = 0x3B;
    pub const WRITE_RECORD_ISO: u8 = 0x8B;
    pub const UPDATE_RECORD: u8 = 0xDB;
    pub const UPDATE_RECORD_ISO: u8 = 0xBA;
    pub const CLEAR_RECORD_FILE: u8 = 0xEB;
    pub const COMMIT_TRANSACTION: u8 = 0xC7;
    pub const ABORT_TRANSACTION: u8 = 0xA7;
    pub const COMMIT_READER_ID: u8 = 0xC8;
    pub const CRYPTO_REQUEST: u8 = 0x4C;
    pub const MANAGE_GPIO: u8 = 0x42;
    pub const READ_GPIO: u8 = 0x43;
    pub const PREPARE_PC: u8 = 0xF0;
    pub const PROXIMITY_CHECK: u8 = 0xF2;
    pub const VERIFY_PC: u8 = 0xFD;
}

/// Name of a native command code, for logs and error messages.
pub fn command_name(code: u8) -> &'static str {
    use cmd::*;
    match code {
        AUTH_EV2_FIRST => "AuthenticateEV2First",
        AUTH_EV2_NON_FIRST => "AuthenticateEV2NonFirst",
        ADDITIONAL_FRAME => "AdditionalFrame",
        FREE_MEM => "FreeMem",
        FORMAT => "Format",
        SET_CONFIGURATION => "SetConfiguration",
        GET_CONFIGURATION => "GetConfiguration",
        GET_VERSION => "GetVersion",
        GET_CARD_UID => "GetCardUID",
        CHANGE_KEY => "ChangeKey",
        CHANGE_KEY_EV2 => "ChangeKeyEV2",
        INITIALIZE_KEY_SET => "InitializeKeySet",
        FINALIZE_KEY_SET => "FinalizeKeySet",
        ROLL_KEY_SET => "RollKeySet",
        GET_KEY_SETTINGS => "GetKeySettings",
        CHANGE_KEY_SETTINGS => "ChangeKeySettings",
        GET_KEY_VERSION => "GetKeyVersion",
        MANAGE_KEY_PAIR => "ManageKeyPair",
        MANAGE_CA_ROOT_KEY => "ManageCARootKey",
        EXPORT_KEY => "ExportKey",
        CREATE_APPLICATION => "CreateApplication",
        DELETE_APPLICATION => "DeleteApplication",
        CREATE_DELEGATED_APPLICATION => "CreateDelegatedApplication",
        SELECT_APPLICATION => "SelectApplication",
        GET_APPLICATION_IDS => "GetApplicationIDs",
        GET_DF_NAMES => "GetDFNames",
        GET_DELEGATED_INFO => "GetDelegatedInfo",
        CREATE_STD_DATA_FILE => "CreateStdDataFile",
        CREATE_BACKUP_DATA_FILE => "CreateBackupDataFile",
        CREATE_VALUE_FILE => "CreateValueFile",
        CREATE_LINEAR_RECORD_FILE => "CreateLinearRecordFile",
        CREATE_CYCLIC_RECORD_FILE => "CreateCyclicRecordFile",
        CREATE_TRANSACTION_MAC_FILE => "CreateTransactionMACFile",
        DELETE_FILE => "DeleteFile",
        GET_FILE_IDS => "GetFileIDs",
        GET_ISO_FILE_IDS => "GetISOFileIDs",
        GET_FILE_SETTINGS => "GetFileSettings",
        GET_FILE_COUNTERS => "GetFileCounters",
        CHANGE_FILE_SETTINGS => "ChangeFileSettings",
        READ_DATA | READ_DATA_ISO => "ReadData",
        WRITE_DATA | WRITE_DATA_CRL => "WriteData",
        GET_VALUE => "GetValue",
        CREDIT => "Credit",
        DEBIT => "Debit",
        LIMITED_CREDIT => "LimitedCredit",
        READ_RECORDS | READ_RECORDS_ISO => "ReadRecords",
        WRITE_RECORD | WRITE_RECORD_ISO => "WriteRecord",
        UPDATE_RECORD | UPDATE_RECORD_ISO => "UpdateRecord",
        CLEAR_RECORD_FILE => "ClearRecordFile",
        COMMIT_TRANSACTION => "CommitTransaction",
        ABORT_TRANSACTION => "AbortTransaction",
        COMMIT_READER_ID => "CommitReaderID",
        CRYPTO_REQUEST => "CryptoRequest",
        MANAGE_GPIO => "ManageGPIO",
        READ_GPIO => "ReadGPIO",
        PREPARE_PC => "PreparePC",
        PROXIMITY_CHECK => "ProximityCheck",
        VERIFY_PC => "VerifyPC",
        _ => "unknown command",
    }
}

/// Names of the PICC level keys.
pub fn picc_key_name(key_no: u8) -> &'static str {
    match key_no {
        0x00 => "PICCMasterKey",
        0x10 => "PICCDAMAuthKey",
        0x11 => "PICCDAMMACKey",
        0x12 => "PICCDAMENCKey",
        0x18 => "NXPDAMAuthKey",
        0x19 => "NXPDAMMACKey",
        0x1A => "NXPDAMENCKey",
        0x20 => "VCConfigurationKey",
        0x21 => "VCProximityKey",
        _ => "unknown key",
    }
}

/// Bit 7 of key and file numbers: the object lives in the secondary of two selected applications.
pub const SECOND_APP_BIT: u8 = 0x80;

// -------------------------------------------------------------------- helpers
pub(crate) fn le_bytes(v: u32, n: usize) -> Vec<u8> {
    v.to_le_bytes()[..n].to_vec()
}

pub(crate) fn le_u32(b: &[u8]) -> u32 {
    let mut v = [0u8; 4];
    let n = b.len().min(4);
    v[..n].copy_from_slice(&b[..n]);
    u32::from_le_bytes(v)
}

/// Check that a value fits `bits` and return a helpful error if not.
pub(crate) fn check_range(name: &str, v: u32, bits: u32) -> Result<()> {
    if bits < 32 && v >> bits != 0 {
        return Err(Error::arg(format!("{name} {v} does not fit {bits} bits")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_rights_roundtrip() {
        let ar = AccessRights::new(AccessRight::FREE, AccessRight::key(1), AccessRight::key(2), AccessRight::NEVER);
        assert_eq!(ar.to_u16(), 0xE12F);
        assert_eq!(AccessRights::from_u16(0xE12F), ar);
        assert_eq!(ar.to_bytes(), [0x2F, 0xE1]);
    }

    #[test]
    fn aid_is_little_endian() {
        assert_eq!(Aid(0x123456).to_bytes(), [0x56, 0x34, 0x12]);
        assert_eq!(Aid::from_bytes(&[0x56, 0x34, 0x12]), Aid(0x123456));
    }

    #[test]
    fn status_roundtrip() {
        for c in 0..=255u8 {
            assert_eq!(Status::from(c).code(), c);
        }
        assert_eq!(Status::from(0x9D), Status::PermissionDenied);
        assert_eq!(command_name(cmd::GET_VERSION), "GetVersion");
    }

    #[test]
    fn comm_mode_bits() {
        assert_eq!(CommMode::from_bits(0x43), CommMode::Full);
        assert_eq!(CommMode::Mac.bits(), 1);
    }
}
