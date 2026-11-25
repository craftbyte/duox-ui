//! Installing a CA as a CA root key on the card (ManageCARootKey): the input form and the checks before
//! anything is sent. Used by this tab and by the CRL tab (linking a CRL file to the key).

use crate::shared::Shared;
use crate::ui::form::{FormSpec, FormValues};
use duox::card::{Aid, CaRootKeySpec, CommMode};
use duox::crypto::{curve_name, PubKey};
use duox::pki::{AcMap, CertKind, PkiStore};

/// First choice of the CA list: take the key from the text field instead.
pub const OWN_KEY: &str = "(use the public key below)";

const MODES: [&str; 3] = ["Plain", "MAC", "Full"];

/// What the form needs to know about the card selection (no command is sent to find out).
#[derive(Debug, Clone, Copy, Default)]
pub struct CardContext {
    /// The PICC level is selected: only key numbers 0 and 1 exist there.
    pub at_picc: bool,
    /// AID of the selected application (the default holder of a CRL file).
    pub aid: Option<u32>,
}

impl CardContext {
    pub fn of(shared: &Shared) -> Self {
        match shared.card.as_ref().map(|c| c.selection().primary) {
            Some(Some(a)) => CardContext { at_picc: a == Aid::PICC, aid: Some(a.0) },
            _ => CardContext::default(),
        }
    }
}

/// Parse an application id typed as hex; empty means "not given".
pub fn parse_aid(text: &str) -> Result<Option<u32>, String> {
    let t = text.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() {
        return Ok(None);
    }
    u32::from_str_radix(t, 16)
        .ok()
        .filter(|v| *v <= 0xFF_FFFF && t.len() <= 6)
        .map(Some)
        .ok_or_else(|| format!("'{t}' is not an application id (up to six hex digits)."))
}

fn mode_index(m: CommMode) -> usize {
    MODES.iter().position(|n| *n == m.to_string()).unwrap_or(0)
}

fn mode_at(i: usize) -> CommMode {
    match i {
        1 => CommMode::Mac,
        2 => CommMode::Full,
        _ => CommMode::Plain,
    }
}

/// CAs of the store that can be installed, as `(id, label)`.
pub fn ca_choices(store: &PkiStore) -> Vec<(String, String)> {
    store.by_kind(&[CertKind::Root, CertKind::Sub]).into_iter().map(|e| (e.id.clone(), store.label(e))).collect()
}

/// The ManageCARootKey form. `preset_ca` selects a store entry; `crl_file` turns revocation on for that file.
pub fn form(store: &PkiStore, ctx: CardContext, preset_ca: Option<&str>, crl_file: Option<u8>) -> FormSpec {
    let choices = ca_choices(store);
    let mut options: Vec<&str> = vec![OWN_KEY];
    options.extend(choices.iter().map(|c| c.1.as_str()));
    let default = preset_ca.and_then(|p| choices.iter().position(|c| c.0 == p)).map_or(0, |i| i + 1);
    let max_key = if ctx.at_picc { 1 } else { 4 };
    let curves = super::model::curve_labels();
    FormSpec::new("Install CA root key")
        .note(
            "Stores the public key readers must be certified by. Replaces the entry with this number; a new \
             entry needs the rights the card asks for (usually the master key).",
        )
        .ok_text("Install")
        .int_range("no", &format!("Key number (0-{max_key})"), 0, 0, max_key)
        .hint(if ctx.at_picc { "PICC level: keys 0 and 1." } else { "Application level: keys 0 to 4." })
        .combo("ca", "CA from the store", &options, default)
        .hex("pub", "... or public key", "")
        .hint("130 hex digits: 04 || x || y. Only used when the list above says so.")
        .combo("curve", "Curve (public key above)", &curves, 0)
        .text("ac", "Access conditions granted", "0-D")
        .hint("What readers certified by this key may do at most, e.g. 0,5 or 0-D.")
        .check("issuer", "Card checks the certificate issuer name", true)
        .hint("Untick if the card rejects valid certificates with 6A80.")
        .combo("wmode", "Update requires CommMode", &MODES, mode_index(CommMode::Full))
        .hex_int_range("wac", "Update access condition", 0, 1, 0, 0xF)
        .combo("rmode", "ExportKey CommMode", &MODES, mode_index(CommMode::Mac))
        .hex_int_range("rac", "ExportKey access condition", 0xE, 1, 0, 0xF)
        .check("crl", "Enable certificate revocation", crl_file.is_some())
        .hex_int_range("crlfile", "CRL file number", u64::from(crl_file.unwrap_or(0)), 2, 0, 0x1F)
        .text("crlaid", "AID holding the CRL file", "")
        .hint("Hex; empty = the selected application.")
}

/// The answers of [`form`] in typed form.
#[derive(Debug, Clone)]
pub struct Input {
    pub key_no: u8,
    /// Label of the chosen store entry, or [`OWN_KEY`].
    pub ca: String,
    pub public_key: Vec<u8>,
    pub curve_id: u8,
    pub acmap: String,
    pub check_issuer: bool,
    pub write_mode: CommMode,
    pub write_ac: u8,
    pub read_mode: CommMode,
    pub read_ac: u8,
    pub crl: bool,
    pub crl_file: u8,
    pub crl_aid: String,
}

impl Input {
    pub fn from_values(v: &FormValues) -> Result<Input, String> {
        Ok(Input {
            key_no: v.get_int("no")? as u8,
            ca: v.get_str("ca")?.to_string(),
            public_key: v.get_hex("pub")?,
            curve_id: super::model::curve_at(v.get_index("curve")?),
            acmap: v.get_str("ac")?.to_string(),
            check_issuer: v.get_bool("issuer")?,
            write_mode: mode_at(v.get_index("wmode")?),
            write_ac: v.get_uint("wac")? as u8,
            read_mode: mode_at(v.get_index("rmode")?),
            read_ac: v.get_uint("rac")? as u8,
            crl: v.get_bool("crl")?,
            crl_file: v.get_uint("crlfile")? as u8,
            crl_aid: v.get_str("crlaid")?.to_string(),
        })
    }
}

/// Validate everything locally and build the command parameters. The second value describes the result for the log.
pub fn build(store: &PkiStore, ctx: CardContext, i: &Input) -> Result<(CaRootKeySpec, String), String> {
    let max_key = if ctx.at_picc { 1 } else { 4 };
    if i.key_no > max_key {
        return Err(format!("Key number {} does not exist here; use 0 to {max_key}.", i.key_no));
    }
    let (public_key, curve_id, issuer, source) = if i.ca == OWN_KEY {
        let curve_name = curve_name(i.curve_id);
        let raw = i.public_key.clone();
        if raw.len() != 65 || raw[0] != 0x04 {
            return Err("Enter the CA public key as 65 bytes (130 hex digits starting with 04), or pick a CA from the list."
                .into());
        }
        PubKey::from_bytes(i.curve_id, &raw).map_err(|_| format!("The public key is not a valid point on {curve_name}."))?;
        (raw, i.curve_id, Vec::new(), "a public key".to_string())
    } else {
        let ca = store
            .by_kind(&[CertKind::Root, CertKind::Sub])
            .into_iter()
            .find(|e| store.label(e) == i.ca)
            .ok_or_else(|| "The chosen CA is no longer in the store.".to_string())?;
        let cert = ca.certificate().map_err(|e| e.to_string())?;
        let issuer = if i.check_issuer { cert.subject().to_der().to_vec() } else { Vec::new() };
        if issuer.len() > 255 {
            return Err(format!(
                "The subject name of '{}' is {} bytes; the card accepts at most 255. Untick the issuer name check.",
                ca.name,
                issuer.len()
            ));
        }
        (ca.public_bytes().map_err(|e| e.to_string())?, ca.curve, issuer, format!("'{}'", ca.name))
    };
    let acmap = AcMap::parse(&i.acmap).map_err(|e| format!("Access conditions: {e}. Write them like 0,5 or 0-D."))?;
    let (crl_file, crl_aid) = if i.crl {
        if i.crl_file > 0x1F {
            return Err("The CRL file number is 00 to 1F.".into());
        }
        let aid = match parse_aid(&i.crl_aid)? {
            Some(a) => a,
            None => ctx.aid.ok_or("Enter the AID of the application that holds the CRL file.")?,
        };
        (0x80 | i.crl_file, aid)
    } else {
        (0, 0)
    };
    let mut spec = CaRootKeySpec::new(i.key_no, curve_id, public_key);
    spec.access_rights = acmap.bits();
    spec.write_access = i.write_mode.bits() << 4 | (i.write_ac & 0xF);
    spec.read_access = i.read_mode.bits() << 4 | (i.read_ac & 0xF);
    spec.crl_file = crl_file;
    spec.crl_aid = Aid(crl_aid);
    spec.issuer = issuer;
    let crl = if i.crl { format!(", revocation file {:02X} of application {crl_aid:06X}", i.crl_file) } else { String::new() };
    let text = format!("CA root key {} set from {source} ({}, ACMap {:04X}{crl})", i.key_no, curve_name(curve_id), acmap.bits());
    Ok((spec, text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use duox::crypto::CURVE_P256;

    fn input(ca: &str) -> Input {
        Input {
            key_no: 0,
            ca: ca.into(),
            public_key: vec![],
            curve_id: CURVE_P256,
            acmap: "0-D".into(),
            check_issuer: true,
            write_mode: CommMode::Full,
            write_ac: 0,
            read_mode: CommMode::Mac,
            read_ac: 0xE,
            crl: false,
            crl_file: 0,
            crl_aid: String::new(),
        }
    }

    #[test]
    fn aid_text() {
        assert_eq!(parse_aid("").unwrap(), None);
        assert_eq!(parse_aid(" 0x1A2B3C ").unwrap(), Some(0x1A2B3C));
        assert!(parse_aid("1234567").is_err());
        assert!(parse_aid("xyz").is_err());
    }

    #[test]
    fn builds_from_store_entry() {
        let mut s = PkiStore::new();
        let root = s.new_root("Root", CURVE_P256, "", 1).unwrap();
        let label = s.label(&root);
        let ctx = CardContext { at_picc: false, aid: Some(0x123456) };
        let (spec, text) = build(&s, ctx, &input(&label)).unwrap();
        assert_eq!(spec.public_key, root.public_bytes().unwrap());
        assert_eq!(spec.issuer, root.certificate().unwrap().subject().to_der());
        assert_eq!((spec.write_access, spec.read_access, spec.access_rights), (0x30, 0x1E, 0x3FFF));
        assert_eq!((spec.crl_file, spec.crl_aid), (0, Aid(0)));
        assert!(text.contains("'Root'"));
        // revocation on: bit 7 of the file byte, default application from the selection
        let (spec, _) = build(&s, ctx, &Input { crl: true, crl_file: 4, ..input(&label) }).unwrap();
        assert_eq!((spec.crl_file, spec.crl_aid), (0x84, Aid(0x123456)));
        // no issuer check
        let (spec, _) = build(&s, ctx, &Input { check_issuer: false, ..input(&label) }).unwrap();
        assert!(spec.issuer.is_empty());
    }

    #[test]
    fn rejects_before_sending() {
        let mut s = PkiStore::new();
        let root = s.new_root("Root", CURVE_P256, "", 1).unwrap();
        let label = s.label(&root);
        let picc = CardContext { at_picc: true, aid: Some(0) };
        assert!(build(&s, picc, &Input { key_no: 3, ..input(&label) }).unwrap_err().contains("0 to 1"));
        assert!(build(&s, CardContext::default(), &Input { crl: true, ..input(&label) }).unwrap_err().contains("AID"));
        assert!(build(&s, picc, &Input { acmap: "Z".into(), ..input(&label) }).is_err());
        assert!(build(&s, picc, &input(OWN_KEY)).unwrap_err().contains("65 bytes"));
        assert!(build(&s, picc, &input("gone")).unwrap_err().contains("no longer"));
        let key = duox::crypto::gen_key(CURVE_P256).unwrap().public().to_bytes();
        let (spec, _) = build(&s, picc, &Input { public_key: key.clone(), ..input(OWN_KEY) }).unwrap();
        assert_eq!(spec.public_key, key);
        assert!(spec.issuer.is_empty());
    }
}
