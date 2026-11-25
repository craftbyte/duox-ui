//! Pure helpers of the SDM tab: labels, number handling and the text reports.

use crate::ui::hex;
use duox::crypto::{PubKey, CURVE_BP256, CURVE_P256};
use duox::sdm::{self, SdmField, SdmResult, SdmSettings};

/// Labels of the access nibbles; the index of a label is the nibble value.
pub const AC_LABELS: [&str; 16] = [
    "Key 0", "Key 1", "Key 2", "Key 3", "Key 4", "Key 5", "Key 6", "Key 7", "Key 8", "Key 9", "Key A", "Key B",
    "Key C", "Key D", "E  free / plain", "F  off",
];

/// Offset fields of the settings form: the field and the key it has in the form.
pub const OFFSET_FIELDS: [(SdmField, &str); 9] = [
    (SdmField::UidOffset, "uid_off"),
    (SdmField::CtrOffset, "ctr_off"),
    (SdmField::PiccOffset, "picc_off"),
    (SdmField::GpioOffset, "gpio_off"),
    (SdmField::MacInputOffset, "macin_off"),
    (SdmField::EncOffset, "enc_off"),
    (SdmField::EncLength, "enc_len"),
    (SdmField::MacOffset, "mac_off"),
    (SdmField::CtrLimit, "ctr_limit"),
];

/// The file number as typed: hex, `00..=1F`, or `80..=9F` for the second application.
pub fn parse_file_no(text: &str) -> Result<u8, String> {
    let t = text.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() {
        return Err("Enter the file number (hex), for example 02.".into());
    }
    let v = u8::from_str_radix(t, 16).map_err(|_| format!("'{text}' is not a valid file number (two hex digits)."))?;
    if v & 0x7F > 0x1F {
        return Err(format!(
            "File number {v:02X} is out of range: files are numbered 00 to 1F (80 to 9F in the second application)."
        ));
    }
    Ok(v)
}

/// A form value below zero means "field not used".
pub fn offset_from_form(v: i64) -> Option<u32> {
    u32::try_from(v).ok()
}

pub fn offset_to_form(v: Option<u32>) -> i64 {
    v.map_or(-1, i64::from)
}

/// When SDMReadCtr is enabled with plain access but not mirrored, the card expects the "no mirror"
/// marker as its offset.
pub fn normalize(cfg: &mut SdmSettings) {
    if cfg.options & sdm::OPT_CTR != 0 && cfg.meta_read == sdm::AC_FREE && cfg.ctr_offset.is_none() {
        cfg.ctr_offset = Some(sdm::NO_MIRROR);
    }
}

/// Printable ASCII, everything else as `.`.
pub fn printable(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }).collect()
}

/// `name  first .. last` lines of the mirrored regions.
pub fn region_lines(cfg: &SdmSettings, uid_len: usize) -> Vec<String> {
    cfg.regions(uid_len)
        .iter()
        .map(|r| format!("  {:<16}{:>5} .. {}", r.kind.name(), r.offset, r.offset + r.len.max(1) - 1))
        .collect()
}

/// The outcome of the settings check as text.
pub fn validation_report(cfg: &SdmSettings, size: usize, size_note: &str, uid_len: usize) -> String {
    let problems = cfg.validate(size, uid_len);
    let mut s = cfg.describe().join("\n");
    s.push_str(&format!("\n\nChecked against a file of {size} bytes ({size_note}), UID length {uid_len}:\n"));
    if problems.is_empty() {
        s.push_str("  no problems found\n");
        if let Ok(b) = cfg.encode() {
            s.push_str(&format!("\nChangeFileSettings SDM bytes: {}", hex::spaced(&b)));
        }
    } else {
        for p in &problems {
            s.push_str(&format!("  - {p}\n"));
        }
    }
    s
}

fn check_word(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "VALID",
        Some(false) => "INVALID",
        None => "not checked",
    }
}

/// Everything a back end learns from dynamic file data.
pub fn verify_report(r: &SdmResult, cfg: &SdmSettings, dynamic: &[u8]) -> String {
    let mut l = Vec::new();
    match sdm::url_from_ndef_file(dynamic) {
        Ok(u) => l.push(format!("URL          {u}")),
        Err(_) => {
            let n = match dynamic {
                [a, b, ..] => (2 + usize::from(u16::from_be_bytes([*a, *b]))).min(dynamic.len()),
                _ => dynamic.len(),
            };
            l.push(format!("As text      {}", printable(&dynamic[..n])));
        }
    }
    l.push(String::new());
    l.push(format!("VCUID        {}", r.uid.as_deref().map_or("-".to_string(), hex::spaced)));
    l.push(format!("SDMReadCtr   {}", r.ctr.map_or("-".to_string(), |c| c.to_string())));
    if let Some(t) = r.picc_tag {
        l.push(format!("PICCDataTag  0x{t:02X}"));
    }
    if let Some(p) = &r.enc_plain {
        l.push(format!("Decrypted    {}   \"{}\"", hex::spaced(p), printable(p)));
    }
    if let Some(g) = &r.gpio {
        l.push(format!("GPIOStatus   {}", hex::spaced(g)));
    }
    if cfg.uses_sig() {
        l.push(format!("SDMSIG       {}", check_word(r.sig_ok)));
    } else if cfg.file_read != sdm::AC_NONE {
        l.push(format!("SDMMAC       {}", check_word(r.mac_ok)));
    } else {
        l.push("No SDMMAC / SDMSIG configured: the mirrored values are not authenticated.".into());
    }
    if let Some(f) = r.ctr_fresh {
        let what = if f { "newer than the last accepted value" } else { "NOT newer than the last accepted value" };
        l.push(format!("Counter      {what}"));
    }
    if r.ctr_within_limit == Some(false) {
        l.push("Counter      above SDMReadCtrLimit: the card should not mirror this value".into());
    }
    for n in &r.notes {
        l.push(format!("note: {n}"));
    }
    if r.mac_ok == Some(false) || r.sig_ok == Some(false) {
        l.push(String::new());
        l.push(
            "Check the keys, that the offsets match the card's settings, and that the data was read \
             unauthenticated."
                .into(),
        );
    }
    if r.mac_ok.is_some() || r.sig_ok.is_some() {
        l.push(String::new());
        l.push(format!("Verdict      {}", if r.ok() { "authentic" } else { "NOT authentic (or counter rejected)" }));
    }
    l.join("\n")
}

/// A 65 byte uncompressed point on P-256 or brainpoolP256r1.
pub fn parse_sig_pub(raw: &[u8]) -> Result<PubKey, String> {
    if raw.len() != 65 {
        return Err(format!("The SDMSIG public key is 65 bytes (04 || x || y), {} given.", raw.len()));
    }
    [CURVE_P256, CURVE_BP256]
        .into_iter()
        .find_map(|c| PubKey::from_bytes(c, raw).ok())
        .ok_or_else(|| "The SDMSIG public key is not a valid P-256 / brainpoolP256r1 point.".to_string())
}

/// Is a Type 4 NDEF file (NLEN + message) read completely?
pub fn ndef_complete(data: &[u8]) -> bool {
    data.len() >= 2 && data.len() >= usize::from(u16::from_be_bytes([data[0], data[1]])) + 2
}

/// A UID to render with when no card is present.
pub fn placeholder_uid(len: usize) -> Vec<u8> {
    let mut u = vec![0x11; len.max(1)];
    u[0] = 0x04;
    u
}

#[cfg(test)]
mod tests {
    use super::*;
    use duox::sdm::{build_ndef_template, render, verify, RenderKeys, TemplateOptions, VerifyParams};

    #[test]
    fn file_numbers() {
        assert_eq!(parse_file_no("02"), Ok(2));
        assert_eq!(parse_file_no(" 0x1f "), Ok(0x1F));
        assert_eq!(parse_file_no("81"), Ok(0x81));
        assert!(parse_file_no("").is_err());
        assert!(parse_file_no("20").is_err());
        assert!(parse_file_no("zz").is_err());
        assert!(parse_file_no("A0").is_err());
    }

    #[test]
    fn offsets_roundtrip() {
        assert_eq!(offset_from_form(-1), None);
        assert_eq!(offset_from_form(0), Some(0));
        assert_eq!(offset_from_form(0xFF_FFFF), Some(sdm::NO_MIRROR));
        assert_eq!(offset_to_form(None), -1);
        assert_eq!(offset_to_form(Some(77)), 77);
    }

    #[test]
    fn counter_marker_is_added_only_when_needed() {
        let mut c =
            SdmSettings { options: sdm::OPT_ASCII | sdm::OPT_CTR, meta_read: sdm::AC_FREE, ..Default::default() };
        normalize(&mut c);
        assert_eq!(c.ctr_offset, Some(sdm::NO_MIRROR));
        let mut c = SdmSettings { options: sdm::OPT_ASCII | sdm::OPT_CTR, meta_read: 0, ..Default::default() };
        normalize(&mut c);
        assert_eq!(c.ctr_offset, None);
    }

    #[test]
    fn ndef_completeness() {
        assert!(!ndef_complete(&[]));
        assert!(!ndef_complete(&[0, 5, 1, 2]));
        assert!(ndef_complete(&[0, 2, 1, 2]));
        assert!(ndef_complete(&[0, 2, 1, 2, 9]));
    }

    #[test]
    fn signature_key_parsing() {
        assert!(parse_sig_pub(&[4; 10]).is_err());
        assert!(parse_sig_pub(&[4; 65]).is_err());
        let k = duox::crypto::gen_key(CURVE_P256).unwrap().public().to_bytes();
        assert!(parse_sig_pub(&k).is_ok());
    }

    #[test]
    fn report_of_a_full_read_out() {
        let (mk, fk) = ([0x11u8; 16], [0x22u8; 16]);
        let uid = hex::parse("04958CAA5C5E80").unwrap();
        let t = build_ndef_template(
            "https://example.org/t?p={picc}&e={enc:16}&m={mac}",
            &TemplateOptions { meta_read: 1, file_read: 2, enc_fill: b"hello".to_vec(), ..Default::default() },
        )
        .unwrap();
        let mut file = t.file_data.clone();
        file.resize(256, 0);
        let keys = RenderKeys { meta_key: Some(&mk), file_key: Some(&fk), sig_key: None };
        let dynamic = render(&file, &t.settings, &uid, 9, &keys, b"000", false).unwrap();
        let p = VerifyParams { meta_key: Some(&mk), file_key: Some(&fk), ..Default::default() };
        let r = verify(&dynamic, &t.settings, &p).unwrap();
        let text = verify_report(&r, &t.settings, &dynamic);
        assert!(text.contains("SDMMAC       VALID"), "{text}");
        assert!(text.contains("04 95 8C AA 5C 5E 80"));
        assert!(text.contains("SDMReadCtr   9"));
        assert!(text.contains("\"hello"));
        assert!(text.contains("URL          https://example.org/t?p="));
        assert!(text.contains("authentic"));

        let wrong = VerifyParams { file_key: Some(&[0u8; 16]), ..p };
        let r = verify(&dynamic, &t.settings, &wrong).unwrap();
        let text = verify_report(&r, &t.settings, &dynamic);
        assert!(text.contains("SDMMAC       INVALID") && text.contains("NOT authentic"), "{text}");
    }

    #[test]
    fn region_and_validation_text() {
        let t = build_ndef_template("https://e.org/?u={uid}&c={ctr}", &TemplateOptions::default()).unwrap();
        let lines = region_lines(&t.settings, 7);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("VCUID"));
        let ok = validation_report(&t.settings, 256, "test", 7);
        assert!(ok.contains("no problems found") && ok.contains("ChangeFileSettings SDM bytes"));
        let bad = validation_report(&t.settings, 10, "test", 7);
        assert!(bad.contains("exceeds the file size"), "{bad}");
    }

    #[test]
    fn placeholder_uid_has_the_right_shape() {
        assert_eq!(placeholder_uid(7).len(), 7);
        assert_eq!(placeholder_uid(10)[0], 0x04);
    }
}
