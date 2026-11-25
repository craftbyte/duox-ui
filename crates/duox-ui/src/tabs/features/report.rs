//! Text shown in the result view. Pure formatting, unit tested.

use crate::ui::hex;
use duox::card::{GpioLevel, ProximityResult};
use duox::evcert::{Date, EvCertificate};

/// Does the FCI carry the encrypted UID of fast confidential UID retrieval (tag 85, 32 bytes)?
pub fn has_encrypted_uid(fci: &[u8]) -> bool {
    fci.windows(2).position(|w| w == [0x85, 0x20]).is_some_and(|i| fci.len() >= i + 34)
}

/// Result of an ISOSelectFile.
pub fn select_report(sw: u16, fci: &[u8], has_ephemeral_key: bool, ends_authentication: bool) -> String {
    let mut l = vec![format!(
        "ISOSelectFile: {sw:04X}{}",
        if sw == 0x6283 { "  (selected with limited functionality)" } else { "" }
    )];
    if !fci.is_empty() {
        l.push(format!("FCI ({} bytes)", fci.len()));
        l.push(hex::dump(fci).trim_end().to_string());
        if has_ephemeral_key {
            l.push(
                "The FCI carries an ephemeral public key: this application expects ISOGeneralAuthenticateFinal \
                 (Authenticate tab, start with ISOSelectFile)."
                    .into(),
            );
        } else if has_encrypted_uid(fci) {
            l.push(
                "The FCI carries the encrypted UID (fast confidential UID retrieval): use 'Fast UID...' with the \
                 AppUIDENCKey."
                    .into(),
            );
        }
    }
    if ends_authentication {
        l.push("Any authentication has ended.".into());
    }
    l.join("\n")
}

pub fn fast_uid_report(fci: &[u8], uid: &[u8], vctid: u8, pd_cap1: [u8; 2]) -> String {
    [
        format!("FCI      {}", hex::spaced(fci)),
        format!("UID      {}", hex::spaced(uid)),
        format!("VCTID    {vctid:02X}"),
        format!("PDCap1   {}", hex::spaced(&pd_cap1)),
        String::new(),
        "One ISOSelectFile and one AES decryption, no authentication round trip. The IV is fresh for every \
         selection, so the response cannot be used to track the card."
            .into(),
    ]
    .join("\n")
}

pub fn no_fast_uid_report(fci: &[u8]) -> String {
    format!(
        "FCI ({} bytes)\n{}\n\nThe FCI holds no encrypted UID: the application is not configured for fast UID \
         retrieval (SetConfiguration option 04, SMConfigB bit 6).",
        fci.len(),
        hex::dump(fci).trim_end()
    )
}

pub fn binary_report(name: &str, data: &[u8]) -> String {
    format!("{name}: {} bytes\n{}", data.len(), hex::dump(data).trim_end())
}

pub fn record_report(data: &[u8]) -> String {
    format!(
        "{}\n\nISO numbering: record 0 is the current (last written) one; in a linear file 1 is the oldest, in a \
         cyclic file 1 is the newest.",
        binary_report("ISOReadRecord", data)
    )
}

pub fn proximity_report(r: &ProximityResult) -> String {
    let times: Vec<String> = r.round_trip_us.iter().map(|t| format!("{t:.0}")).collect();
    let mut l = vec![
        if r.ok {
            "Proximity check PASSED: the card proved knowledge of the key over the exchange.".to_string()
        } else {
            "Proximity check FAILED: the card's MAC is wrong (key mismatch or relay).".to_string()
        },
        format!(
            "MAC key: {}",
            if r.authenticated_key { "session key of the active authentication" } else { "VCProximityKey" }
        ),
        format!(
            "Published response time {} \u{b5}s{}",
            r.announced_resp_time_us,
            r.pps1.map(|p| format!(", PPS1 {p:02X}")).unwrap_or_default()
        ),
        format!("Round trips measured here: {} \u{b5}s", times.join(", ")),
        String::new(),
    ];
    l.push(
        "The measured times include the reader, driver and USB latency, typically milliseconds. A PC/SC reader \
         cannot enforce the published response time, so this run proves the cryptographic part only; real relay \
         protection needs a reader that times the exchange itself."
            .into(),
    );
    l.join("\n")
}

fn level_text(l: GpioLevel) -> String {
    match l {
        GpioLevel::High => "HIGH (H)".into(),
        GpioLevel::Low => "LOW (L)".into(),
        GpioLevel::Invalid => "not an input or output, or not driven (I)".into(),
        GpioLevel::Unknown(b) => format!("unknown status {b:02X}"),
    }
}

pub fn gpio_read_report(raw: &[u8]) -> String {
    let mut l = vec![format!("ReadGPIO: {}  {:?}", hex::spaced(raw), String::from_utf8_lossy(raw))];
    if raw.len() >= 3 {
        l.push(format!("GPIO1  {}", level_text(raw[1].into())));
        l.push(format!("GPIO2  {}", level_text(raw[2].into())));
    }
    l.join("\n")
}

pub fn gpio_manage_report(gpio: &str, op: u8, response: &[u8]) -> String {
    let mut s = format!("ManageGPIO {gpio}, operation {op:02X}: OK");
    if !response.is_empty() {
        s.push_str(&format!("\nResponse data: {}", hex::spaced(response)));
    }
    s
}

/// How the certificate relates to the chosen issuer.
pub enum IssuerCheck<'a> {
    /// No issuer selected.
    NotChecked,
    /// Checked against `name`; `valid` is the signature result.
    Checked { name: &'a str, valid: bool },
}

pub fn certificate_report(
    cert: &EvCertificate,
    issuer: IssuerCheck<'_>,
    card_uid: &[u8],
    today: Date,
) -> Vec<String> {
    let mut l = cert.describe();
    l.push(String::new());
    match issuer {
        IssuerCheck::NotChecked => l.push("No issuer selected: the certificate signature was not checked.".into()),
        IssuerCheck::Checked { name, valid } => l.push(format!(
            "Certificate signature by '{name}': {}",
            if valid { "VALID" } else { "INVALID" }
        )),
    }
    if let Some(e) = cert.effective.filter(|&e| today < e) {
        l.push(format!("WARNING: the certificate is not valid before {e}."));
    }
    if let Some(e) = cert.expiry.filter(|&e| today > e) {
        l.push(format!("WARNING: the certificate expired on {e}."));
    }
    if !card_uid.is_empty() && cert.subject != card_uid {
        l.push(format!(
            "WARNING: the certificate is for {}, the card reports UID {}.",
            hex::spaced(&cert.subject),
            hex::spaced(card_uid)
        ));
    }
    l
}

pub fn challenge_report(challenge: &[u8], signature: &[u8], valid: bool) -> String {
    [
        format!("Challenge {}", hex::spaced(challenge)),
        format!("Signature {}", hex::spaced(signature)),
        String::new(),
        if valid {
            "VALID: the card holds the private key of its certificate.".to_string()
        } else {
            "INVALID: the card does NOT hold the private key of this certificate.".to_string()
        },
        "(Verify the certificate itself with 'Read + verify certificate'.)".to_string(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use duox::crypto;
    use duox::evcert;

    #[test]
    fn select_texts() {
        let mut fci = vec![0x6F, 0x22, 0x85, 0x20];
        fci.extend([0u8; 32]);
        assert!(has_encrypted_uid(&fci));
        assert!(!has_encrypted_uid(&fci[..20]));
        let s = select_report(0x6283, &fci, false, true);
        assert!(s.starts_with("ISOSelectFile: 6283  (selected with limited functionality)"));
        assert!(s.contains("fast confidential UID retrieval"));
        assert!(s.ends_with("Any authentication has ended."));
        let s = select_report(0x9000, &[], false, false);
        assert_eq!(s, "ISOSelectFile: 9000");
        assert!(select_report(0x9000, &[1], true, false).contains("ephemeral public key"));
    }

    #[test]
    fn gpio_texts() {
        let s = gpio_read_report(&[0x49, 0x48, 0x4C]);
        assert!(s.contains("GPIO1  HIGH (H)") && s.contains("GPIO2  LOW (L)"), "{s}");
        assert!(gpio_read_report(&[0x49]).lines().count() == 1);
        assert!(gpio_manage_report("GPIO1", 1, &[0xAB]).ends_with("Response data: AB"));
    }

    #[test]
    fn proximity_text() {
        let r = ProximityResult {
            ok: true,
            option: 1,
            announced_resp_time_us: 300,
            pps1: Some(0x11),
            round_trip_us: vec![1500.4, 2000.0],
            authenticated_key: false,
        };
        let s = proximity_report(&r);
        assert!(s.contains("PASSED") && s.contains("VCProximityKey") && s.contains("PPS1 11"));
        assert!(s.contains("1500, 2000 \u{b5}s"));
        assert!(proximity_report(&ProximityResult { ok: false, ..r }).contains("FAILED"));
    }

    #[test]
    fn certificate_warnings() {
        let ca = crypto::gen_key(crypto::CURVE_BP256).unwrap();
        let holder = crypto::gen_key(crypto::CURVE_BP256).unwrap();
        let uid = [4u8, 1, 2, 3, 4, 5, 6];
        let blob = evcert::build(
            &ca,
            "00000000000001",
            &uid,
            &holder.public().to_bytes(),
            crypto::CURVE_BP256,
            Date::new(2024, 1, 1).unwrap(),
            2,
        )
        .unwrap();
        let cert = EvCertificate::parse(&blob).unwrap();
        let today = Date::new(2025, 6, 1).unwrap();
        let ok = certificate_report(&cert, IssuerCheck::Checked { name: "CA", valid: true }, &uid, today);
        assert!(ok.iter().any(|l| l.contains("by 'CA': VALID")));
        assert!(!ok.iter().any(|l| l.starts_with("WARNING")));
        let bad = certificate_report(&cert, IssuerCheck::Checked { name: "CA", valid: false }, &[9, 9], today);
        assert!(bad.iter().any(|l| l.contains("INVALID")));
        assert!(bad.iter().any(|l| l.contains("the card reports UID 09 09")));
        let late = certificate_report(&cert, IssuerCheck::NotChecked, &[], Date::new(2030, 1, 1).unwrap());
        assert!(late.iter().any(|l| l.contains("expired on")));
        assert!(late.iter().any(|l| l.contains("not checked")));
        let early = certificate_report(&cert, IssuerCheck::NotChecked, &[], Date::new(2020, 1, 1).unwrap());
        assert!(early.iter().any(|l| l.contains("not valid before")));
    }

    #[test]
    fn challenge_text() {
        assert!(challenge_report(&[1], &[2], true).contains("VALID: the card holds"));
        assert!(challenge_report(&[1], &[2], false).contains("does NOT hold"));
        let s = fast_uid_report(&[1, 2], &[4, 5, 6, 7], 5, [0xAA, 0xBB]);
        assert!(s.contains("UID      04 05 06 07") && s.contains("VCTID    05") && s.contains("PDCap1   AA BB"));
        assert!(binary_report("ISOReadBinary", &[0x41]).starts_with("ISOReadBinary: 1 bytes\n0000  41"));
    }
}
