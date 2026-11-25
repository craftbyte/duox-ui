//! Pure helpers of the tools tab: configuration options, decoding and text reports.

use crate::ui::hex;
use duox::card::types::iso_sw_description;
use duox::card::{CommMode, Status, VersionInfo};

/// Options of Get/SetConfiguration with their names.
pub const CONFIG_OPTIONS: [(u8, &str); 15] = [
    (0x00, "PICC / application configuration"),
    (0x01, "Default application key (write only)"),
    (0x02, "ATS"),
    (0x03, "SAK"),
    (0x04, "Secure messaging configuration"),
    (0x05, "Capability data"),
    (0x06, "VCIID / DF name"),
    (0x0C, "ATQA"),
    (0x0F, "NFC management (protocols)"),
    (0x10, "I2C management"),
    (0x11, "GPIO management"),
    (0x15, "Crypto API management"),
    (0x16, "Authentication counter and limit"),
    (0x17, "HALT and wake-up"),
    (0xFF, "Lock configurations"),
];

/// Index of an option in [`CONFIG_OPTIONS`].
pub fn option_index(opt: u8) -> usize {
    CONFIG_OPTIONS.iter().position(|(o, _)| *o == opt).unwrap_or(0)
}

/// `04  Secure messaging configuration`, the text shown in the option selector.
pub fn option_label(index: usize) -> String {
    let (o, n) = CONFIG_OPTIONS[index.min(CONFIG_OPTIONS.len() - 1)];
    format!("{o:02X}  {n}")
}

pub fn option_labels() -> Vec<String> {
    (0..CONFIG_OPTIONS.len()).map(option_label).collect()
}

/// Which option a selector text names.
pub fn option_from_label(label: &str) -> Option<u8> {
    label.get(..2).and_then(|h| u8::from_str_radix(h, 16).ok()).filter(|o| CONFIG_OPTIONS.iter().any(|(c, _)| c == o))
}

pub fn option_name(opt: u8) -> &'static str {
    CONFIG_OPTIONS.iter().find(|(o, _)| *o == opt).map_or("unknown option", |(_, n)| n)
}

/// Layout hint of an option's data.
pub fn config_help(opt: u8) -> &'static str {
    match opt {
        0x00 => "1 byte. PICC: bit 0 disable Format (permanent), bit 1 enable Random ID (permanent), bit 5 legacy random ID. Delegated application: bit 0 disable Format.",
        0x01 => "PICCAppDefaultKey: 24 or 32 key bytes followed by 1 version byte.",
        0x02 => "User ATS, 1 to 20 bytes starting with TL.",
        0x03 => "SAK1 || SAK2.",
        0x04 => "SMConfigA || SMConfigB [|| CurveID] [|| AppUIDENCKey]. SMConfigB: bit 2 disable chained WriteData under secure messaging, bit 3 ISOSelectFile-integrated ECC authentication (then CurveID 0C / 0D follows), bit 4 EV charging, bit 5 free access over I2C, bit 6 fast UID retrieval (then the key number follows).",
        0x05 => "10 bytes of capability data: VCTID override, PDCap1.2, PDCap2.2 (transaction timer), PDCap2.5, PDCap2.6.",
        0x06 => "Length (1) || VCIID or DF name padded to 16 bytes [|| DAMMAC (8) for delegated applications].",
        0x0C => "ATQA, LSB first.",
        0x0F => "ProtocolOptionsA || ProtocolOptionsB || RFU. A: bit 0 AES authentication, bit 1 ECC mutual / reader-unilateral, bit 2 ECC card-unilateral, bit 3 ECDSA sign.",
        0x10 => "I2C address || ProtocolOptions (2) || RFU.",
        0x11 => "33 bytes. The GPIO configuration form on the ISO / GPIO / EV tab is easier to use.",
        0x15 => "Support (0x02 = ECDSA sign) || access: bits 5-4 CommMode, bits 3-0 access condition.",
        0x16 => "AuthCtrOption (bit 0 count AuthenticateEV2First) || AuthCtrLimit (4 bytes, LSB first) || RFU. GetConfiguration additionally returns the current counter.",
        0x17 => "WakeUpA || WakeUpB || RDACSetting || HALTOption.",
        0xFF => "3-byte bitmap, LSB first: bit n locks option n permanently.",
        _ => "",
    }
}

fn yes(v: u8, bit: u8) -> &'static str {
    if v >> bit & 1 == 1 {
        "yes"
    } else {
        "no"
    }
}

/// Human readable decoding of the options whose layout is known.
pub fn describe_config(opt: u8, d: &[u8]) -> Vec<String> {
    match (opt, d) {
        (0x00, [b, ..]) => vec![
            format!("Format disabled: {}", yes(*b, 0)),
            format!("Random ID: {}", yes(*b, 1)),
            format!("legacy random ID: {}", yes(*b, 5)),
        ],
        (0x02, d) if !d.is_empty() => vec![format!("ATS of {} bytes, TL = {:02X}", d.len(), d[0])],
        (0x03, [a, b, ..]) => vec![format!("SAK1 {a:02X}, SAK2 {b:02X}")],
        (0x04, [_, b, rest @ ..]) => {
            let mut l = vec![
                format!("chained WriteData disabled under secure messaging: {}", yes(*b, 2)),
                format!("ISOSelectFile-integrated ECC authentication: {}", yes(*b, 3)),
                format!("EV charging: {}", yes(*b, 4)),
                format!("free access over I2C: {}", yes(*b, 5)),
                format!("fast UID retrieval: {}", yes(*b, 6)),
            ];
            if let Some(x) = rest.first() {
                l.push(format!("extra byte (CurveID / AppUIDENCKey number): {x:02X}"));
            }
            l
        }
        (0x06, [n, rest @ ..]) if rest.len() >= *n as usize => {
            vec![format!("name ({n} bytes): {}", hex::spaced(&rest[..*n as usize]))]
        }
        (0x0C, [a, b, ..]) => vec![format!("ATQA {b:02X}{a:02X}")],
        (0x0F, [a, ..]) => vec![
            format!("AES authentication: {}", yes(*a, 0)),
            format!("ECC mutual / reader-unilateral: {}", yes(*a, 1)),
            format!("ECC card-unilateral: {}", yes(*a, 2)),
            format!("ECDSA sign: {}", yes(*a, 3)),
        ],
        (0x15, [support, access, ..]) => vec![
            format!("support: {support:02X}"),
            format!("CryptoRequest: CommMode.{}, access condition {:X}", crypto_mode_bits(*access), access & 0xF),
        ],
        (0x16, [o, l @ ..]) if l.len() >= 4 => {
            let limit = u32::from_le_bytes([l[0], l[1], l[2], l[3]]);
            let mut v = vec![
                format!("count AuthenticateEV2First: {}", yes(*o, 0)),
                format!("limit: {}", if limit == 0 { "disabled".to_string() } else { limit.to_string() }),
            ];
            if d.len() >= 10 {
                let c = &d[d.len() - 4..];
                v.push(format!("current AuthCtr: {}", u32::from_le_bytes([c[0], c[1], c[2], c[3]])));
            }
            v
        }
        (0xFF, [a, b, c, ..]) => {
            let m = u32::from_le_bytes([*a, *b, *c, 0]);
            let locked: Vec<String> = (0..24).filter(|i| m >> i & 1 == 1).map(|i| format!("{i:02X}")).collect();
            vec![format!("locked options: {}", if locked.is_empty() { "none".into() } else { locked.join(", ") })]
        }
        _ => vec![],
    }
}

fn crypto_mode_bits(access: u8) -> CommMode {
    match (access >> 4) & 3 {
        1 => CommMode::Mac,
        3 => CommMode::Full,
        _ => CommMode::Plain,
    }
}

/// CommMode of CryptoRequest from the data of option 0x15.
pub fn crypto_mode_from_config(d: &[u8]) -> Option<CommMode> {
    d.get(1).map(|&a| crypto_mode_bits(a))
}

/// Check the data of SetConfiguration before it is sent; returns the bytes to send.
pub fn check_config_data(opt: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    let name = option_name(opt);
    let bad = |want: &str| Err(format!("Option {opt:02X} ({name}) needs {want}, but {} bytes were given.", data.len()));
    match opt {
        _ if data.is_empty() => Err("Enter the configuration data as hex.".into()),
        0x00 if data.len() != 1 => bad("1 byte"),
        0x01 if !matches!(data.len(), 25 | 33) => bad("24 or 32 key bytes plus a version byte (25 or 33 bytes)"),
        0x02 if data.len() > 20 => bad("1 to 20 bytes"),
        0x03 | 0x0C if data.len() != 2 => bad("2 bytes"),
        0x05 if data.len() != 10 => bad("10 bytes"),
        0x11 if data.len() != 33 => bad("33 bytes"),
        0x15 if data.len() != 2 => bad("2 bytes"),
        0xFF if data.len() != 3 => bad("3 bytes"),
        // GetConfiguration appends the current counter, which is not part of what is written.
        0x16 if data.len() < 5 => bad("at least 5 bytes"),
        0x16 => Ok(data[..data.len().min(6)].to_vec()),
        _ => Ok(data.to_vec()),
    }
}

pub const KEY_SET_HELP: &str = "\
Rolling an application to new keys (the application must have been created with key sets)
  1. Initialize the next set (1 = the one after the active set) with its key type.
  2. Load its keys: Card tab, Change AES key with the key set number filled in (ChangeKeyEV2).
  3. Finalize it with a version higher than the active set's.
  4. Roll: the set becomes active, the old keys stop working and the authentication ends.
Initialize and Finalize need the key that may change keys, Roll the key named at creation.
A version of 00 marks a set that is not finalised.";

/// Number of CryptoRequest commands a signature over `len` raw bytes takes.
pub fn sign_frames(len: usize) -> usize {
    const CHUNK: usize = 0xE0;
    if len <= CHUNK {
        1
    } else {
        // initialize + updates + finalize
        2 + (len - CHUNK - 1) / CHUNK
    }
}

pub fn format_version(v: &VersionInfo) -> String {
    let mut rows = vec![
        ("Vendor".to_string(), format!("{:02X}", v.vendor)),
        (
            "Hardware".into(),
            format!(
                "type {:02X}  subtype {:02X}  version {}.{}  storage {}  protocol {:02X}",
                v.hw_type, v.hw_subtype, v.hw_version.0, v.hw_version.1, v.hw_storage, v.hw_protocol
            ),
        ),
        (
            "Software".into(),
            format!(
                "type {:02X}  subtype {:02X}  version {}.{}  storage {}  protocol {:02X}",
                v.sw_type, v.sw_subtype, v.sw_version.0, v.sw_version.1, v.sw_storage, v.sw_protocol
            ),
        ),
        ("UID".into(), hex::spaced(&v.uid)),
        ("Batch".into(), hex::spaced(&v.batch)),
        ("Type id".into(), hex::spaced(&v.type_id)),
    ];
    if let Some((week, year)) = v.production {
        rows.push(("Production".into(), format!("calendar week {week:02X} of 20{year:02X}")));
    }
    rows.push(("Raw".into(), hex::spaced(&v.raw)));
    rows.iter().map(|(k, x)| format!("{k:<12} {x}")).collect::<Vec<_>>().join("\n")
}

/// Result of a raw native command.
pub fn format_native(rc: u8, frames: &[Vec<u8>]) -> String {
    let data = frames.concat();
    let mut s = format!("Status {rc:02X}  {}\n{} response bytes", Status::from(rc).name(), data.len());
    if frames.len() > 1 {
        s.push_str(&format!(" in {} frames", frames.len()));
    }
    if !data.is_empty() {
        s.push_str(&format!("\n{}\n\n{}", hex::spaced(&data), hex::dump(&data)));
    }
    s
}

/// Result of a raw APDU.
pub fn format_apdu(sw: u16, data: &[u8]) -> String {
    let name = if sw >> 8 == 0x91 { Status::from(sw as u8).name() } else { iso_sw_description(sw) };
    let mut s = format!("SW {sw:04X}  {name}\n{} response bytes", data.len());
    if !data.is_empty() {
        s.push_str(&format!("\n{}\n\n{}", hex::spaced(data), hex::dump(data)));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_selector_roundtrip() {
        for i in 0..CONFIG_OPTIONS.len() {
            let l = option_label(i);
            assert_eq!(option_from_label(&l), Some(CONFIG_OPTIONS[i].0));
            assert_eq!(option_index(CONFIG_OPTIONS[i].0), i);
        }
        assert_eq!(option_from_label("zz nonsense"), None);
        assert_eq!(option_from_label("07  not an option"), None);
    }

    #[test]
    fn every_option_has_help() {
        for (o, _) in CONFIG_OPTIONS {
            assert!(!config_help(o).is_empty(), "{o:02X}");
        }
    }

    #[test]
    fn decoding() {
        assert_eq!(describe_config(0x00, &[0x03])[0], "Format disabled: yes");
        assert_eq!(describe_config(0x00, &[0x03])[1], "Random ID: yes");
        let sm = describe_config(0x04, &[0, 0x50, 0x0C]);
        assert!(sm[2].ends_with("yes") && sm[4].ends_with("yes") && sm[0].ends_with("no"));
        assert!(sm[5].contains("0C"));
        let c = describe_config(0x15, &[0x02, 0x30]);
        assert!(c[1].contains("CommMode.Full") && c[1].contains("condition 0"));
        let a = describe_config(0x16, &[1, 5, 0, 0, 0, 0, 0, 9, 0, 0, 0]);
        assert_eq!(a[1], "limit: 5");
        assert_eq!(a[2], "current AuthCtr: 9");
        assert_eq!(describe_config(0x16, &[0, 0, 0, 0, 0, 0])[1], "limit: disabled");
        assert_eq!(describe_config(0xFF, &[0x05, 0, 0x80])[0], "locked options: 00, 02, 17");
        assert_eq!(describe_config(0xFF, &[0, 0, 0])[0], "locked options: none");
        assert_eq!(describe_config(0x0C, &[0x44, 0x03])[0], "ATQA 0344");
        let n = describe_config(0x06, &[2, 0xAA, 0xBB, 0, 0]);
        assert_eq!(n[0], "name (2 bytes): AA BB");
        assert!(describe_config(0x04, &[]).is_empty());
        assert!(describe_config(0x99, &[1, 2]).is_empty());
    }

    #[test]
    fn crypto_mode() {
        assert_eq!(crypto_mode_from_config(&[2, 0x10]), Some(CommMode::Mac));
        assert_eq!(crypto_mode_from_config(&[2, 0x30]), Some(CommMode::Full));
        assert_eq!(crypto_mode_from_config(&[2, 0x00]), Some(CommMode::Plain));
        assert_eq!(crypto_mode_from_config(&[2]), None);
    }

    #[test]
    fn config_data_checks() {
        assert!(check_config_data(0x00, &[]).is_err());
        assert!(check_config_data(0x00, &[1, 2]).is_err());
        assert_eq!(check_config_data(0x00, &[1]).unwrap(), vec![1]);
        assert!(check_config_data(0x01, &[0; 24]).is_err());
        assert!(check_config_data(0x01, &[0; 25]).is_ok());
        assert!(check_config_data(0x01, &[0; 33]).is_ok());
        assert!(check_config_data(0x02, &[0; 21]).is_err());
        assert!(check_config_data(0x05, &[0; 10]).is_ok());
        assert_eq!(check_config_data(0x16, &[1, 2, 0, 0, 0, 0, 7, 0, 0, 0]).unwrap(), vec![1, 2, 0, 0, 0, 0]);
        assert!(check_config_data(0x16, &[1, 2, 3]).is_err());
        // options with free layout are not second-guessed
        assert!(check_config_data(0x04, &[1, 2, 3, 4]).is_ok());
        let e = check_config_data(0xFF, &[1]).unwrap_err();
        assert!(e.contains("Lock configurations") && e.contains("3 bytes"));
    }

    #[test]
    fn signature_frame_count() {
        assert_eq!(sign_frames(1), 1);
        assert_eq!(sign_frames(0xE0), 1);
        assert_eq!(sign_frames(0xE1), 2);
        assert_eq!(sign_frames(0x1C0), 2);
        assert_eq!(sign_frames(0x1C1), 3);
        assert_eq!(sign_frames(300), 2);
    }

    #[test]
    fn response_formatting() {
        let n = format_native(0x00, &[vec![1, 2], vec![3]]);
        assert!(n.starts_with("Status 00  OPERATION_OK") && n.contains("3 response bytes in 2 frames"));
        assert!(n.contains("01 02 03"));
        assert!(format_native(0x9D, &[]).contains("PERMISSION_DENIED"));
        let a = format_apdu(0x9000, &[0xAA]);
        assert!(a.starts_with("SW 9000  OK") && a.contains("AA"));
        assert!(format_apdu(0x919D, &[]).contains("PERMISSION_DENIED"));
    }
}
