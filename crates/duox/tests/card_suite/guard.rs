//! Safety guard of the card suite.
//!
//! Format at PICC level only releases applications and files. It does not reset PICC keys, key
//! settings or configuration, so anything the suite changes there has to be restored by the suite
//! itself, and some changes are irreversible and must never be sent at all. [`Guard`] encodes that
//! policy. It is used twice:
//!
//! * [`Guard::check`] judges a typed [`Op`]; every card-modifying helper of [`crate::ctx::Ctx`]
//!   calls it before anything is sent.
//! * [`Guard::check_wire`] is a tripwire on the raw APDUs (see `wire.rs`). It cannot see encrypted
//!   payloads, only command codes and plain header bytes, so it blocks what is identifiable from
//!   those (wrong option numbers at PICC level, ManageKeyPair, key numbers, deleting a foreign
//!   application, writing PICC level files).
//!
//! Levels: [`Level::Picc`] is everything that is not a throwaway application of the suite.
//! [`Level::App`] is an application inside the reserved AID range
//! [`SUITE_AID_FIRST`]`..=`[`SUITE_AID_LAST`]; such applications are deleted by the suite, so
//! irreversible settings are acceptable there.

use duox::card::types::cmd;
use duox::card::Aid;
use std::fmt;

/// First AID the suite may create, change or delete.
pub const SUITE_AID_FIRST: u32 = 0xD0_0000;
/// Last AID of the reserved range.
pub const SUITE_AID_LAST: u32 = 0xD0_FFFF;

pub fn is_suite_aid(aid: Aid) -> bool {
    (SUITE_AID_FIRST..=SUITE_AID_LAST).contains(&aid.0)
}

/// Where a command acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The PICC itself (anything that is not a suite application).
    Picc,
    /// A throwaway application of the suite.
    App,
}

/// A refused operation, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation(pub String);

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "card-suite guard: {}", self.0)
    }
}
impl std::error::Error for Violation {}

fn deny<T>(msg: impl Into<String>) -> Result<T, Violation> {
    Err(Violation(msg.into()))
}

/// A card-modifying (or raw) operation to be judged.
#[derive(Debug, Clone)]
pub enum Op<'a> {
    SetConfiguration { level: Level, option: u8, data: &'a [u8] },
    /// `current` is the value read from the card just before.
    ChangeKeySettings { level: Level, current: u8, new: u8 },
    /// `key_no` is the byte sent on the wire (key type bits included at PICC level).
    ChangeKey { level: Level, key_no: u8, key_set: Option<u8> },
    ManageKeyPair { level: Level, policy: u16, write_access: u8 },
    ManageCaRootKey { level: Level },
    CreateApplication { aid: Aid },
    DeleteApplication { aid: Aid },
    Format { level: Level },
    /// Create / delete / change / write files or records.
    FileModify { level: Level, cmd: u8 },
    RawNative { level: Level, cmd: u8 },
    RawApdu { level: Level, apdu: &'a [u8] },
}

/// The policy. Stateless apart from the tier switch.
#[derive(Debug, Clone, Copy, Default)]
pub struct Guard {
    /// Allow SetConfiguration option 0x11 (GPIO) at PICC level. Off in the default tiers; the
    /// section that enables it must restore the value it read first.
    pub allow_gpio: bool,
}

/// Native commands that cannot change anything on the card (raw escape hatch at PICC level).
const READ_ONLY_NATIVE: &[u8] = &[
    cmd::GET_VERSION,
    cmd::GET_CARD_UID,
    cmd::FREE_MEM,
    cmd::GET_APPLICATION_IDS,
    cmd::GET_DF_NAMES,
    cmd::GET_DELEGATED_INFO,
    cmd::GET_KEY_SETTINGS,
    cmd::GET_KEY_VERSION,
    cmd::GET_CONFIGURATION,
    cmd::SELECT_APPLICATION,
    cmd::GET_FILE_IDS,
    cmd::GET_ISO_FILE_IDS,
    cmd::GET_FILE_SETTINGS,
    cmd::READ_DATA,
    cmd::READ_RECORDS,
    cmd::ADDITIONAL_FRAME,
    cmd::AUTH_EV2_FIRST,
    cmd::AUTH_EV2_NON_FIRST,
];

/// ISO 7816-4 instructions that only read or select.
const READ_ONLY_ISO: &[u8] = &[0xA4, 0xB0, 0xB2, 0xCA];

/// Commands that create, delete, change or write files.
const FILE_MODIFY: &[u8] = &[
    cmd::CREATE_STD_DATA_FILE,
    cmd::CREATE_BACKUP_DATA_FILE,
    cmd::CREATE_VALUE_FILE,
    cmd::CREATE_LINEAR_RECORD_FILE,
    cmd::CREATE_CYCLIC_RECORD_FILE,
    cmd::CREATE_TRANSACTION_MAC_FILE,
    cmd::DELETE_FILE,
    cmd::CHANGE_FILE_SETTINGS,
    cmd::WRITE_DATA,
    cmd::WRITE_DATA_CRL,
    cmd::WRITE_RECORD,
    cmd::WRITE_RECORD_ISO,
    cmd::UPDATE_RECORD,
    cmd::UPDATE_RECORD_ISO,
    cmd::CLEAR_RECORD_FILE,
    cmd::CREDIT,
    cmd::DEBIT,
    cmd::LIMITED_CREDIT,
];

/// ISO 7816-4 write instructions (UPDATE BINARY x2, UPDATE RECORD, APPEND RECORD, ERASE ...).
const ISO_WRITE: &[u8] = &[0xD6, 0xD7, 0xDC, 0xDD, 0xE0, 0xE4, 0x0E, 0x0F];

impl Guard {
    pub fn new(allow_gpio: bool) -> Self {
        Guard { allow_gpio }
    }

    /// Level for a selected application (`None` = unknown / failed selection, treated as PICC).
    pub fn level_of(selected: Option<Aid>) -> Level {
        match selected {
            Some(a) if is_suite_aid(a) => Level::App,
            _ => Level::Picc,
        }
    }

    /// Judge an operation.
    pub fn check(&self, op: &Op<'_>) -> Result<(), Violation> {
        match *op {
            Op::SetConfiguration { level, option, data } => self.check_set_configuration(level, option, data),
            Op::ChangeKeySettings { level, current, new } => match level {
                Level::App => Ok(()),
                Level::Picc => {
                    if current & 0x08 == 0 {
                        return deny("PICCKeySettings are frozen (bit 3 is clear); nothing can be changed any more");
                    }
                    if new & 0x01 == 0 {
                        return deny("PICCKeySettings bit 0 must stay set (clearing it freezes the PICC master key)");
                    }
                    if new & 0x08 == 0 {
                        return deny("PICCKeySettings bit 3 must stay set (clearing it freezes the settings forever)");
                    }
                    if new & 0x10 != 0 {
                        return deny("PICCKeySettings bit 4 (NXPDAMKeys) must never be set");
                    }
                    if (new ^ current) & 0xE0 != 0 {
                        return deny("RFU bits of PICCKeySettings must not change");
                    }
                    Ok(())
                }
            },
            Op::ChangeKey { level, key_no, key_set } => match level {
                Level::App => Ok(()),
                Level::Picc => Self::check_picc_key(key_no, key_set),
            },
            Op::ManageKeyPair { level, policy, write_access } => match level {
                Level::Picc => deny(
                    "ManageKeyPair at PICC level is never allowed: the preprovisioned ECC keys cannot be regenerated \
                     (and policy / write access could freeze them)",
                ),
                Level::App => {
                    let _ = (policy, write_access); // frozen flags are fine inside a throwaway application
                    Ok(())
                }
            },
            Op::ManageCaRootKey { level } => match level {
                Level::Picc => deny("ManageCARootKey at PICC level is never allowed"),
                Level::App => Ok(()),
            },
            Op::CreateApplication { aid } => {
                if is_suite_aid(aid) {
                    Ok(())
                } else {
                    deny(format!("AID {aid} is outside the suite range {SUITE_AID_FIRST:06X}..{SUITE_AID_LAST:06X}"))
                }
            }
            Op::DeleteApplication { aid } => {
                if is_suite_aid(aid) {
                    Ok(())
                } else {
                    deny(format!("refusing to delete AID {aid}: not a suite application"))
                }
            }
            Op::Format { .. } => Ok(()),
            Op::FileModify { level, cmd } => match level {
                Level::App => Ok(()),
                Level::Picc => deny(format!(
                    "{} at PICC level is not allowed (PICC level files hold the card's certificates and settings)",
                    duox::card::types::command_name(cmd)
                )),
            },
            Op::RawNative { level, cmd: c } => match level {
                Level::Picc if READ_ONLY_NATIVE.contains(&c) => Ok(()),
                Level::Picc => deny(format!(
                    "raw {} (0x{c:02X}) at PICC level: only read-only commands may be sent raw",
                    duox::card::types::command_name(c)
                )),
                Level::App if c == cmd::FORMAT => deny("raw Format is not allowed; use ctx.format()"),
                Level::App => Ok(()),
            },
            Op::RawApdu { level, apdu } => self.check_raw_apdu(level, apdu),
        }
    }

    fn check_raw_apdu(&self, level: Level, apdu: &[u8]) -> Result<(), Violation> {
        if apdu.len() < 4 {
            return deny("APDU shorter than a header");
        }
        let (cla, ins) = (apdu[0], apdu[1]);
        match cla {
            0x90 => self.check(&Op::RawNative { level, cmd: ins }),
            0x00 | 0x0C => {
                if ins == 0x88 {
                    deny("raw ISOInternalAuthenticate is not allowed; use the library (it may consume key usage counters)")
                } else if READ_ONLY_ISO.contains(&ins) || level == Level::App {
                    Ok(())
                } else {
                    deny(format!("raw ISO instruction 0x{ins:02X} at PICC level: only select / read are allowed"))
                }
            }
            _ => deny(format!("raw APDU with CLA 0x{cla:02X}")),
        }
    }

    fn check_picc_key(key_no: u8, key_set: Option<u8>) -> Result<(), Violation> {
        if key_set.is_some_and(|s| s != 0) {
            return deny("there are no key sets at PICC level");
        }
        let (num, ty) = (key_no & 0x3F, key_no >> 6);
        match num {
            0x18..=0x1A => deny("NXPDAM keys 0x18..0x1A are never touched"),
            // key type travels in bits 7..6 for these: AES-128 only
            0x00 | 0x20 | 0x21 => {
                if ty == 0b10 {
                    Ok(())
                } else {
                    deny(format!("PICC key 0x{num:02X}: only AES-128 (type bits 10b, wire byte 0x{:02X}) is used", 0x80 | num))
                }
            }
            0x10..=0x12 => {
                if ty == 0 {
                    Ok(())
                } else {
                    deny("PICCDAM keys are addressed without type or secondary-application bits")
                }
            }
            _ => deny(format!("PICC key 0x{num:02X} is not one the suite may change")),
        }
    }

    /// Which options may be written at all at `level` (data independent part).
    pub fn option_allowed(&self, level: Level, option: u8) -> Result<(), Violation> {
        match level {
            Level::Picc => match option {
                0x01 | 0x06 => Ok(()),
                0x11 if self.allow_gpio => Ok(()),
                0x11 => deny("SetConfiguration 0x11 (GPIO) is off in the default tiers (set DUOX_SUITE_ALLOW_GPIO=1)"),
                0x00 => deny(
                    "PICC option 0x00 is never written: bit0 disables Format forever, bit1 enables Random ID forever",
                ),
                0x02 | 0x03 | 0x0C => deny(format!(
                    "PICC option 0x{option:02X} (ATS / SAK / ATQA) could make the card unreachable and is never written"
                )),
                0x0F | 0x10 => deny(format!(
                    "PICC option 0x{option:02X} (protocol options NFC / I2C) could make the card unusable and is never written"
                )),
                0x05 => deny("PICC option 0x05 (capability data) is never written"),
                0x04 => deny("PICC option 0x04 (SMConfig) is never written: bit 2 is irreversible and the rest is not usable at PICC level"),
                0x15 | 0x16 | 0x17 | 0xFF => deny(format!(
                    "PICC option 0x{option:02X} (crypto API / authentication counter limit / HALT / lock) is never written at PICC level"
                )),
                _ => deny(format!("unknown or RFU SetConfiguration option 0x{option:02X}")),
            },
            Level::App => match option {
                0x00 | 0x04 | 0x05 | 0x06 | 0x15 | 0x16 | 0x17 | 0xFF => Ok(()),
                0x01 | 0x02 | 0x03 | 0x0C | 0x0F | 0x10 | 0x11 => {
                    deny(format!("SetConfiguration option 0x{option:02X} is PICC level only"))
                }
                _ => deny(format!("unknown or RFU SetConfiguration option 0x{option:02X}")),
            },
        }
    }

    fn check_set_configuration(&self, level: Level, option: u8, data: &[u8]) -> Result<(), Violation> {
        self.option_allowed(level, option)?;
        match (level, option) {
            (Level::Picc, 0x01) if data.len() != 25 && data.len() != 33 => {
                deny("PICCAppDefaultKey data is 25 or 33 bytes (key || version)")
            }
            (Level::Picc, 0x06) if data.len() != 17 || !(1..=16).contains(&data[0]) => {
                deny("VCIID data is 17 bytes: length 1..=16 followed by 16 bytes")
            }
            (Level::Picc, 0x11) if data.len() != 33 => deny("GPIO configuration is 33 bytes"),
            (Level::App, 0x00) => match data {
                [b] if b & 0x01 == 0 => Ok(()),
                [_] => deny("AppConfig bit0 disables Format for the application forever"),
                _ => deny("option 0x00 carries exactly one byte"),
            },
            (Level::App, 0x04) => {
                if data.iter().take(2).any(|b| b & 0x04 != 0) {
                    deny("SMConfig bit 2 disables chained writes irreversibly")
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    /// Tripwire on a raw command APDU. `selected` is what the card currently has selected, as far as
    /// the transport could follow (`None` = unknown; treated like the PICC for keys and configuration,
    /// but file writes are not blocked because an ISO selected application cannot be named).
    pub fn check_wire(&self, selected: Selection, apdu: &[u8]) -> Result<(), Violation> {
        if apdu.len() < 4 {
            return Ok(());
        }
        let level = match selected {
            Selection::App => Level::App,
            Selection::Picc | Selection::Unknown => Level::Picc,
        };
        let (cla, ins) = (apdu[0], apdu[1]);
        if cla == 0x00 && ISO_WRITE.contains(&ins) && selected == Selection::Picc {
            return deny(format!("ISO write instruction 0x{ins:02X} at PICC level"));
        }
        if cla != 0x90 {
            return Ok(());
        }
        let data: &[u8] = if apdu.len() > 5 { &apdu[5..(5 + apdu[4] as usize).min(apdu.len())] } else { &[] };
        match ins {
            cmd::SET_CONFIGURATION => match data.first() {
                Some(&opt) => self.option_allowed(level, opt),
                None => Ok(()),
            },
            cmd::CHANGE_KEY => match data.first() {
                Some(&k) => self.check(&Op::ChangeKey { level, key_no: k, key_set: None }),
                None => Ok(()),
            },
            cmd::CHANGE_KEY_EV2 => match data {
                [set, k, ..] => self.check(&Op::ChangeKey { level, key_no: *k, key_set: Some(*set) }),
                _ => Ok(()),
            },
            cmd::MANAGE_KEY_PAIR => self.check(&Op::ManageKeyPair { level, policy: 0, write_access: 0 }),
            cmd::MANAGE_CA_ROOT_KEY => self.check(&Op::ManageCaRootKey { level }),
            cmd::DELETE_APPLICATION if data.len() >= 3 => {
                self.check(&Op::DeleteApplication { aid: Aid::from_bytes(&data[..3]) })
            }
            cmd::CREATE_APPLICATION | cmd::CREATE_DELEGATED_APPLICATION if data.len() >= 3 => {
                self.check(&Op::CreateApplication { aid: Aid::from_bytes(&data[..3]) })
            }
            c if FILE_MODIFY.contains(&c) && selected == Selection::Picc => self.check(&Op::FileModify { level, cmd: c }),
            _ => Ok(()),
        }
    }
}

/// What the transport believes is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    Picc,
    App,
    /// After an ISO selection.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(level: Level, option: u8, data: &[u8]) -> Result<(), Violation> {
        Guard::default().check(&Op::SetConfiguration { level, option, data })
    }

    #[test]
    fn set_configuration_table() {
        use Level::*;
        let key25 = [0u8; 25];
        let key33 = [0u8; 33];
        let mut vciid = [0u8; 17];
        vciid[0] = 4;
        let mut vciid_bad = [0u8; 17];
        vciid_bad[0] = 0;
        // (level, option, data, allowed)
        let table: Vec<(Level, u8, &[u8], bool)> = vec![
            // option 0x00
            (Picc, 0x00, &[0x00], false),
            (Picc, 0x00, &[0x01], false),
            (Picc, 0x00, &[0x02], false),
            (Picc, 0x00, &[0x23], false),
            (App, 0x00, &[0x00], true),
            (App, 0x00, &[0x01], false),
            (App, 0x00, &[0x00, 0x00], false),
            // PICCAppDefaultKey
            (Picc, 0x01, &key25, true),
            (Picc, 0x01, &key33, true),
            (Picc, 0x01, &[0u8; 16], false),
            (App, 0x01, &key25, false),
            // never at PICC
            (Picc, 0x02, &[0x05, 0x75, 0x77, 0x81, 0x02], false),
            (Picc, 0x03, &[0x20, 0x00], false),
            (Picc, 0x0C, &[0x44, 0x00], false),
            (Picc, 0x0F, &[0x00, 0x00, 0x00], false),
            (Picc, 0x10, &[0x00, 0x20, 0x00, 0x00], false),
            (Picc, 0x05, &[0u8; 10], false),
            (Picc, 0x04, &[0x00, 0x00], false),
            (Picc, 0x04, &[0x04, 0x00], false),
            (Picc, 0x11, &key33, false),
            (Picc, 0x15, &[0x02, 0x00], false),
            (Picc, 0x16, &[0, 0, 1, 0, 0, 0], false),
            (Picc, 0x17, &[0u8; 4], false),
            (Picc, 0xFF, &[0xFF, 0xFF, 0xFF], false),
            (Picc, 0x07, &[0], false),
            (Picc, 0x12, &[0], false),
            // VCIID
            (Picc, 0x06, &vciid, true),
            (Picc, 0x06, &vciid_bad, false),
            (Picc, 0x06, &[4, 1, 2], false),
            // application level
            (App, 0x04, &[0x00, 0x00], true),
            (App, 0x04, &[0x00, 0x08], true),
            (App, 0x04, &[0x00, 0x04], false),
            (App, 0x04, &[0x04, 0x00], false),
            (App, 0x04, &[0x00, 0x0C, 0x0C], false),
            (App, 0x05, &[0u8; 10], true),
            (App, 0x06, &vciid, true),
            (App, 0x15, &[0x02, 0x00], true),
            (App, 0x16, &[0, 0, 1, 0, 0, 0], true),
            (App, 0xFF, &[0, 0, 0], true),
            (App, 0x02, &[1], false),
            (App, 0x03, &[1, 2], false),
            (App, 0x0C, &[1, 2], false),
            (App, 0x0F, &[0, 0, 0], false),
            (App, 0x10, &[0, 0, 0, 0], false),
            (App, 0x11, &key33, false),
        ];
        for (level, option, data, allowed) in table {
            let r = set(level, option, data);
            assert_eq!(r.is_ok(), allowed, "{level:?} option 0x{option:02X} data {data:02X?}: {r:?}");
        }
    }

    #[test]
    fn gpio_only_in_the_gpio_tier() {
        let data = [0u8; 33];
        let op = Op::SetConfiguration { level: Level::Picc, option: 0x11, data: &data };
        assert!(Guard::new(false).check(&op).is_err());
        assert!(Guard::new(true).check(&op).is_ok());
        // the other PICC options stay forbidden in the GPIO tier
        let op = Op::SetConfiguration { level: Level::Picc, option: 0x0F, data: &[0, 0, 0] };
        assert!(Guard::new(true).check(&op).is_err());
    }

    #[test]
    fn picc_key_settings_table() {
        let g = Guard::default();
        // (current, new, allowed)
        let table = [
            (0x0F, 0x0F, true),
            (0x0F, 0x0D, true),  // bit 1 cleared
            (0x0F, 0x0B, true),  // bit 2 cleared
            (0x0F, 0x09, true),  // bits 1 and 2 cleared
            (0x0F, 0x0E, false), // bit 0 cleared
            (0x0F, 0x07, false), // bit 3 cleared
            (0x0F, 0x06, false),
            (0x0F, 0x00, false),
            (0x0F, 0x1F, false), // NXPDAMKeys
            (0x0F, 0x2F, false), // RFU bit
            (0x07, 0x0F, false), // already frozen
        ];
        for (current, new, allowed) in table {
            let r = g.check(&Op::ChangeKeySettings { level: Level::Picc, current, new });
            assert_eq!(r.is_ok(), allowed, "{current:02X} -> {new:02X}: {r:?}");
        }
        // inside a throwaway application anything goes
        assert!(g.check(&Op::ChangeKeySettings { level: Level::App, current: 0x0F, new: 0x00 }).is_ok());
    }

    #[test]
    fn key_changes() {
        let g = Guard::default();
        let ck = |level, key_no, key_set| g.check(&Op::ChangeKey { level, key_no, key_set }).is_ok();
        assert!(ck(Level::Picc, 0x80, None)); // PICC master key, AES-128
        assert!(ck(Level::Picc, 0x80, Some(0)));
        assert!(!ck(Level::Picc, 0x00, None)); // type bits missing
        assert!(!ck(Level::Picc, 0xC0, None)); // AES-256 master key
        assert!(!ck(Level::Picc, 0x80, Some(1)));
        assert!(ck(Level::Picc, 0x10, None));
        assert!(ck(Level::Picc, 0x11, None));
        assert!(ck(Level::Picc, 0x12, None));
        assert!(!ck(Level::Picc, 0x90, None));
        assert!(ck(Level::Picc, 0xA0, None)); // VC configuration key
        assert!(ck(Level::Picc, 0xA1, None)); // VC proximity key
        for k in [0x18u8, 0x19, 0x1A, 0x98, 0x99, 0x9A, 0xD8] {
            assert!(!ck(Level::Picc, k, None), "NXPDAM key {k:02X}");
        }
        assert!(!ck(Level::Picc, 0x05, None));
        assert!(!ck(Level::Picc, 0x22, None));
        assert!(ck(Level::App, 0x01, None));
        assert!(ck(Level::App, 0x03, Some(2)));
    }

    #[test]
    fn asymmetric_keys_never_at_picc() {
        let g = Guard::default();
        for (policy, wa) in [(0u16, 0u8), (0x8000, 0x0F), (0x0100, 0x30)] {
            assert!(g.check(&Op::ManageKeyPair { level: Level::Picc, policy, write_access: wa }).is_err());
            assert!(g.check(&Op::ManageKeyPair { level: Level::App, policy, write_access: wa }).is_ok());
        }
        assert!(g.check(&Op::ManageCaRootKey { level: Level::Picc }).is_err());
        assert!(g.check(&Op::ManageCaRootKey { level: Level::App }).is_ok());
    }

    #[test]
    fn application_range() {
        let g = Guard::default();
        assert!(g.check(&Op::CreateApplication { aid: Aid(0xD00000) }).is_ok());
        assert!(g.check(&Op::CreateApplication { aid: Aid(0xD0FFFF) }).is_ok());
        assert!(g.check(&Op::CreateApplication { aid: Aid(0xD10000) }).is_err());
        assert!(g.check(&Op::CreateApplication { aid: Aid(0x000001) }).is_err());
        assert!(g.check(&Op::DeleteApplication { aid: Aid(0xD00005) }).is_ok());
        assert!(g.check(&Op::DeleteApplication { aid: Aid(0x123456) }).is_err());
        assert!(g.check(&Op::DeleteApplication { aid: Aid::PICC }).is_err());
        assert!(g.check(&Op::Format { level: Level::Picc }).is_ok());
    }

    #[test]
    fn file_changes_not_at_picc() {
        let g = Guard::default();
        assert!(g.check(&Op::FileModify { level: Level::Picc, cmd: cmd::WRITE_DATA }).is_err());
        assert!(g.check(&Op::FileModify { level: Level::Picc, cmd: cmd::CREATE_STD_DATA_FILE }).is_err());
        assert!(g.check(&Op::FileModify { level: Level::App, cmd: cmd::WRITE_DATA }).is_ok());
    }

    #[test]
    fn raw_escape_hatches() {
        let g = Guard::default();
        let raw = |level, c| g.check(&Op::RawNative { level, cmd: c }).is_ok();
        assert!(raw(Level::Picc, cmd::GET_VERSION));
        assert!(raw(Level::Picc, cmd::FREE_MEM));
        assert!(!raw(Level::Picc, cmd::FORMAT));
        assert!(!raw(Level::Picc, cmd::SET_CONFIGURATION));
        assert!(!raw(Level::Picc, cmd::CHANGE_KEY));
        assert!(!raw(Level::Picc, cmd::MANAGE_KEY_PAIR));
        assert!(!raw(Level::Picc, cmd::DELETE_APPLICATION));
        assert!(!raw(Level::App, cmd::FORMAT));
        assert!(raw(Level::App, cmd::WRITE_DATA));
        let apdu = |level, a: &[u8]| g.check(&Op::RawApdu { level, apdu: a }).is_ok();
        assert!(apdu(Level::Picc, &[0x90, 0x60, 0, 0, 0]));
        assert!(!apdu(Level::Picc, &[0x90, 0xFC, 0, 0, 0]));
        assert!(apdu(Level::Picc, &[0x00, 0xA4, 0x04, 0x00, 0x00]));
        assert!(!apdu(Level::Picc, &[0x00, 0xD6, 0x00, 0x00, 0x01, 0x00]));
        assert!(!apdu(Level::Picc, &[0x00, 0x88, 0x00, 0x01, 0x00]));
        assert!(!apdu(Level::Picc, &[0x80, 0x60, 0, 0]));
        assert!(!apdu(Level::Picc, &[0x90]));
    }

    fn apdu(ins: u8, data: &[u8]) -> Vec<u8> {
        let mut a = vec![0x90, ins, 0, 0, data.len() as u8];
        a.extend(data);
        a.push(0);
        a
    }

    #[test]
    fn wire_tripwire() {
        let g = Guard::default();
        let w = |sel, a: Vec<u8>| g.check_wire(sel, &a).is_ok();
        // SetConfiguration options by plain header byte
        assert!(w(Selection::Picc, apdu(cmd::SET_CONFIGURATION, &[0x01, 0xAA])));
        assert!(w(Selection::Picc, apdu(cmd::SET_CONFIGURATION, &[0x06, 0xAA])));
        for opt in [0x00u8, 0x02, 0x03, 0x04, 0x05, 0x0C, 0x0F, 0x10, 0x11, 0x16, 0xFF] {
            assert!(!w(Selection::Picc, apdu(cmd::SET_CONFIGURATION, &[opt, 0xAA])), "option {opt:02X}");
            assert!(!w(Selection::Unknown, apdu(cmd::SET_CONFIGURATION, &[opt, 0xAA])), "option {opt:02X}");
        }
        assert!(w(Selection::App, apdu(cmd::SET_CONFIGURATION, &[0x16, 0xAA])));
        assert!(!w(Selection::App, apdu(cmd::SET_CONFIGURATION, &[0x10, 0xAA])));
        // keys
        assert!(w(Selection::Picc, apdu(cmd::CHANGE_KEY, &[0x80, 1, 2])));
        assert!(!w(Selection::Picc, apdu(cmd::CHANGE_KEY, &[0x18, 1, 2])));
        assert!(!w(Selection::Picc, apdu(cmd::CHANGE_KEY_EV2, &[0x01, 0x80, 1])));
        assert!(w(Selection::Picc, apdu(cmd::CHANGE_KEY_EV2, &[0x00, 0x80, 1])));
        assert!(!w(Selection::Picc, apdu(cmd::MANAGE_KEY_PAIR, &[1, 0, 0x0C])));
        assert!(!w(Selection::Unknown, apdu(cmd::MANAGE_CA_ROOT_KEY, &[1, 0x0C])));
        assert!(w(Selection::App, apdu(cmd::MANAGE_KEY_PAIR, &[1, 0, 0x0C])));
        // applications: AID little endian on the wire
        assert!(w(Selection::Picc, apdu(cmd::DELETE_APPLICATION, &[0x00, 0x00, 0xD0])));
        assert!(!w(Selection::Picc, apdu(cmd::DELETE_APPLICATION, &[0x56, 0x34, 0x12])));
        assert!(!w(Selection::Picc, apdu(cmd::CREATE_APPLICATION, &[0x56, 0x34, 0x12, 0x0F, 0x81])));
        // files
        assert!(!w(Selection::Picc, apdu(cmd::WRITE_DATA, &[0, 0, 0, 0, 0, 0, 1])));
        assert!(w(Selection::App, apdu(cmd::WRITE_DATA, &[0, 0, 0, 0, 0, 0, 1])));
        assert!(w(Selection::Unknown, apdu(cmd::WRITE_DATA, &[0, 0, 0, 0, 0, 0, 1])));
        assert!(w(Selection::Picc, apdu(cmd::GET_VERSION, &[])));
        assert!(w(Selection::Picc, apdu(cmd::FORMAT, &[])));
        assert!(!w(Selection::Picc, vec![0x00, 0xD6, 0, 0, 1, 0]));
        assert!(w(Selection::Unknown, vec![0x00, 0xD6, 0, 0, 1, 0]));
    }

    #[test]
    fn level_of_selection() {
        assert_eq!(Guard::level_of(Some(Aid::PICC)), Level::Picc);
        assert_eq!(Guard::level_of(None), Level::Picc);
        assert_eq!(Guard::level_of(Some(Aid(0x123456))), Level::Picc);
        assert_eq!(Guard::level_of(Some(Aid(0xD00001))), Level::App);
    }
}
