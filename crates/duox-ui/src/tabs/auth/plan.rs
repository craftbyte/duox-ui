//! Preconditions and report texts of the Authenticate tab. Pure functions: everything is
//! checked here before the first byte goes to the card.

use crate::tabs::card::model::{app_key_count, PICC_KEYS};
use crate::tabs::card::Snapshot;
use crate::ui::hex;
use duox::card::{Aid, EccAuthResult, EccKeyInfo, InternalAuthResult, KeySettings};
use duox::crypto::{PubKey, CURVE_BP256, CURVE_P256};
use duox::pki::{AcMap, CardChain, CertKind, CsnOrder, PkiError, PkiStore, PreflightOptions};

// ----------------------------------------------------------------------- AES

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesInput {
    pub key_no: u8,
    pub second_app: bool,
    pub key: Vec<u8>,
    pub pcd_cap2: Vec<u8>,
}

/// What the AES planner needs to know about the card.
#[derive(Debug, Clone, Default)]
pub struct AesEnv<'a> {
    pub selected: Option<Aid>,
    pub second_selected: bool,
    pub keys: Option<&'a KeySettings>,
    /// An AES session is running (needed for AuthenticateEV2NonFirst).
    pub aes_session: bool,
}

/// Validate the input and return the key number as sent (bit 7 = second application).
pub fn plan_aes(i: &AesInput, env: &AesEnv<'_>, first: bool) -> Result<u8, String> {
    if !matches!(i.key.len(), 16 | 32) {
        return Err(format!("An AES key has 16 bytes (AES-128) or 32 bytes (AES-256); this one has {}.", i.key.len()));
    }
    if i.pcd_cap2.len() > 6 {
        return Err("PCDcap2 is at most 6 bytes.".into());
    }
    if i.key_no > 0x3F {
        return Err("Key numbers go up to 3F.".into());
    }
    if !first && !env.aes_session {
        return Err(
            "AuthenticateEV2NonFirst continues a running AES session. Run AuthenticateEV2First first (an ECC session \
             cannot be continued this way)."
                .into(),
        );
    }
    if i.second_app {
        if !env.second_selected {
            return Err("No second application is selected. Select two applications on the Card tab first.".into());
        }
        return Ok(i.key_no | 0x80);
    }
    match env.selected {
        Some(Aid::PICC) => {
            if !PICC_KEYS.contains(&i.key_no) {
                return Err(format!(
                    "{:02X} is not a key of the PICC level. Valid numbers: 00, 10-12, 18-1A, 20, 21.",
                    i.key_no
                ));
            }
        }
        Some(aid) => {
            if let Some(k) = env.keys {
                let (n, tmp) = app_key_count(k, false);
                if i.key_no >= n {
                    return Err(if tmp {
                        format!("Application {aid} has only key 00 while its AppMasterTmpKey is active.")
                    } else {
                        format!("Application {aid} has {n} AES key(s), numbered from 00; key {:02X} does not exist.", i.key_no)
                    });
                }
                let want = match k.key_type {
                    2 => Some(16),
                    3 => Some(32),
                    _ => None,
                };
                if want.is_some_and(|w| w != i.key.len()) {
                    return Err(format!(
                        "The keys of application {aid} are {}; the key given has {} bytes.",
                        crate::tabs::card::model::aes_type_name(k.key_type),
                        i.key.len()
                    ));
                }
            }
        }
        None => {}
    }
    Ok(i.key_no)
}

// ----------------------------------------------------------------------- ECC

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccInput {
    pub mutual: bool,
    pub ca_no: u8,
    pub ca2_no: u8,
    pub cert_file: u8,
    pub priv_no: u8,
    /// DF name when authentication starts with ISOSelectFile.
    pub select_df: Option<Vec<u8>>,
    pub check_issuer: bool,
}

/// The checked ECC request: the application the rights refer to and the CA key's rights.
#[derive(Debug, Clone)]
pub struct EccChecked {
    pub aid: Aid,
    pub df_name: Option<Vec<u8>>,
    pub root_acmap: AcMap,
}

pub fn plan_ecc(i: &EccInput, snap: &Snapshot, root_curve: u8) -> Result<EccChecked, String> {
    if i.ca_no > 4 || i.ca2_no > 4 {
        return Err("CA root key numbers go from 0 to 4.".into());
    }
    if i.mutual && (i.cert_file > 0x1F || i.priv_no > 4) {
        return Err("The card certificate file is 00 to 1F and the card private key 0 to 4.".into());
    }
    let (aid, df_name) = match &i.select_df {
        Some(df) => {
            if df.is_empty() || df.len() > 16 {
                return Err("Enter the DF name of the application (1 to 16 bytes) for the ISOSelectFile variant.".into());
            }
            let aid = snap.df_names.iter().find(|d| &d.name == df).map(|d| d.aid);
            if !snap.df_names.is_empty() && aid.is_none() {
                return Err("No application on the card has this DF name. Scan the card on the Card tab to see them.".into());
            }
            (aid.unwrap_or(Aid::PICC), Some(df.clone()))
        }
        None => {
            let aid = snap.selected.ok_or(
                "The selected application is not known. Select an application on the Card tab first, or use the ISOSelectFile variant.",
            )?;
            let df = snap.df_names.iter().find(|d| d.aid == aid).map(|d| d.name.clone()).filter(|n| !n.is_empty());
            (aid, df)
        }
    };
    let mut root_acmap = AcMap::ALL;
    // The key list is only known for the application the browser has loaded.
    let listed = i.select_df.is_none() && snap.ca_known;
    if listed {
        match snap.ca_keys.iter().find(|k| k.key_no == i.ca_no) {
            Some(k) => {
                if k.curve != root_curve {
                    return Err(format!(
                        "CA root key {} on the card uses {} but the chosen identity is on {}.",
                        i.ca_no,
                        crate::tabs::card::model::curve_label(k.curve),
                        crate::tabs::card::model::curve_label(root_curve)
                    ));
                }
                root_acmap = AcMap::new(k.access_rights);
            }
            None => {
                let have: Vec<String> = snap.ca_keys.iter().map(|k| k.key_no.to_string()).collect();
                return Err(if have.is_empty() {
                    "This application holds no CA root key. Install one with \"CA root key...\" on the Card tab.".to_string()
                } else {
                    format!("The card has no CA root key {} here; it holds key(s) {}.", i.ca_no, have.join(", "))
                });
            }
        }
    }
    if snap.second.is_none() && i.ca2_no != 0 {
        return Err("A CA key number for the second application is only used when two applications are selected.".into());
    }
    Ok(EccChecked { aid, df_name, root_acmap })
}

/// Outcome of validating Cert.A the way the card will.
#[derive(Debug, Clone, Default)]
pub struct LocalCheck {
    pub acmap: u16,
    pub acmap2: u16,
    pub report: Vec<String>,
    /// The card is expected to reject the certificate for this reason.
    pub failure: Option<String>,
}

pub fn local_check(
    store: &PkiStore,
    id: &str,
    checked: &EccChecked,
    second: Option<Aid>,
    uid: &[u8],
    check_issuer: bool,
) -> LocalCheck {
    let is_root = store.get(id).is_ok_and(|e| e.kind == CertKind::Root);
    let second_all = if second.is_some() { AcMap::ALL.bits() } else { 0 };
    if is_root {
        return LocalCheck {
            acmap: checked.root_acmap.bits(),
            acmap2: second_all,
            report: vec!["No certificate is sent: the card verifies the signature with the CA root key directly.".into()],
            failure: None,
        };
    }
    let opts = PreflightOptions {
        aid: checked.aid.0,
        aid2: second.map(|a| a.0),
        df_name: checked.df_name.clone(),
        uid: (!uid.is_empty()).then(|| uid.to_vec()),
        root_acmap: checked.root_acmap,
        check_issuer,
        csn_order: CsnOrder::default(),
    };
    match store.preflight(id, &opts) {
        Ok(r) => LocalCheck {
            acmap: r.acmap.bits(),
            acmap2: if second.is_some() { r.acmap2.map(AcMap::bits).unwrap_or(AcMap::ALL.bits()) } else { 0 },
            report: r.report,
            failure: None,
        },
        Err(PkiError::Chain(e)) => LocalCheck {
            acmap: checked.root_acmap.bits(),
            acmap2: 0,
            report: vec![format!("LOCAL CHECK FAILED: {}  (the card is expected to answer {:04X})", e.message, e.sw)],
            failure: Some(format!("{}  (the card would answer {:04X})", e.message, e.sw)),
        },
        Err(e) => LocalCheck {
            acmap: checked.root_acmap.bits(),
            acmap2: 0,
            report: vec![format!("LOCAL CHECK FAILED: {e}")],
            failure: Some(e.to_string()),
        },
    }
}

/// Lines describing how far a card certificate is trusted.
pub fn trust_lines(r: &Result<CardChain, PkiError>) -> Vec<String> {
    match r {
        Ok(c) => {
            let mut l = vec![format!("Certificate: {}", c.path.join(" <- "))];
            l.push(match &c.anchor {
                Some(a) if c.trusted => format!("Trust: anchored at '{a}'"),
                _ => format!("Trust: WARNING - issuer '{}' is not a CA in the local store", c.issuer),
            });
            l
        }
        Err(e) => vec![format!("Certificate: cannot be parsed ({e})")],
    }
}

pub fn ecc_report(
    mutual: bool,
    via_select: bool,
    state: &str,
    res: &EccAuthResult,
    local: &[String],
    trust: Option<Result<CardChain, PkiError>>,
) -> Vec<String> {
    let mut l = vec![
        format!(
            "ECC {} authentication OK{}",
            if mutual { "mutual" } else { "reader-unilateral" },
            if via_select { "  (ISOSelectFile + ISOGeneralAuthenticate)" } else { "" }
        ),
        state.to_string(),
        format!("PDCap2 {}", hex::spaced(&res.pd_cap2)),
        String::new(),
    ];
    l.extend(local.iter().cloned());
    l.push(String::new());
    if !mutual {
        l.push("Reader-unilateral: the card has NOT proven its identity.".into());
        return l;
    }
    match res.card_verified {
        Some(true) => {
            l.push(format!("Card signature valid ({:?}); Cert.B is {} bytes", res.order, res.card_cert.len()));
            if let Some(t) = &trust {
                l.extend(trust_lines(t).into_iter().map(|s| s.replacen("Certificate:", "Card certificate:", 1)));
                if matches!(t, Ok(c) if !c.trusted) {
                    l.push("The card proved possession of the key in Cert.B, but that certificate is not issued by a CA you trust.".into());
                }
            }
        }
        _ => {
            l.push(
                "WARNING: Cert.B is not an X.509 certificate this tool can read, so the card signature was NOT \
                 verified. Treat the card as unauthenticated."
                    .into(),
            );
            l.push(format!("Cert.B / Sig.B payload: {}", hex::spaced(&[res.card_cert.as_slice(), &res.card_sig].concat())));
        }
    }
    l
}

// ------------------------------------------------------ card-unilateral

/// Interpret a pasted public key on either supported curve.
pub fn parse_public_key(raw: &[u8]) -> Result<PubKey, String> {
    if raw.len() != 65 {
        return Err(format!("A public key is 65 bytes (04 || x || y); this one has {}.", raw.len()));
    }
    [CURVE_P256, CURVE_BP256]
        .into_iter()
        .find_map(|c| PubKey::from_bytes(c, raw).ok())
        .ok_or_else(|| "The public key is not a valid point on P-256 or brainpoolP256r1.".to_string())
}

/// Why the private key cannot be used for card-unilateral authentication, from cached key info.
pub fn unilateral_problem(key_no: u8, keys: &[EccKeyInfo]) -> Option<String> {
    if key_no > 4 {
        return Some("ECC private key numbers go from 0 to 4.".into());
    }
    let k = keys.iter().find(|k| k.key_no == key_no)?;
    (k.kuc_limit != 0 && k.kuc >= k.kuc_limit)
        .then(|| format!("ECC private key {key_no} has reached its usage limit ({}); the card will refuse it.", k.kuc_limit))
}

/// Remark when the cached policy does not list the use (the bit layout is the data sheet's table).
pub fn unilateral_policy_note(key_no: u8, keys: &[EccKeyInfo]) -> Option<String> {
    let k = keys.iter().find(|k| k.key_no == key_no)?;
    (k.policy & 0x0100 == 0).then(|| {
        format!("Note: KeyPolicy 0x{:04X} of key {key_no} does not list card-unilateral authentication.", k.policy)
    })
}

pub fn unilateral_report(
    r: &InternalAuthResult,
    source: &[String],
    trusted: Option<bool>,
    note: Option<String>,
) -> Vec<String> {
    let mut l: Vec<String> = source.to_vec();
    l.push(String::new());
    l.push(format!("RndA {}", hex::spaced(&r.rnd_a)));
    l.push(format!("RndB {}", hex::spaced(&r.rnd_b)));
    l.push(format!("Sig  {}", hex::spaced(&r.signature)));
    l.push(String::new());
    l.push(
        match r.valid {
            Some(true) => "Signature VALID - the card holds the private key.",
            Some(false) => "Signature INVALID - the card does NOT hold the private key for this public key.",
            None => "Signature not checked: no public key was available.",
        }
        .to_string(),
    );
    if r.valid == Some(true) && trusted == Some(false) {
        l.push("The key is genuine only if you trust the certificate's issuer (import its CA certificate on the CAs & certificates tab).".into());
    }
    l.extend(note);
    l
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tabs::card::Snapshot;
    use duox::card::{CaRootKeyInfo, DfName, KeySettings};
    use duox::crypto::gen_key;
    use duox::pki::{AccessRights as CertRights, IssueRequest};

    fn keys(max: u8, kt: u8) -> KeySettings {
        KeySettings { settings: 0x0F, max_keys: max, key_type: kt, key_sets: None, raw: vec![] }
    }

    fn aes(no: u8, len: usize) -> AesInput {
        AesInput { key_no: no, second_app: false, key: vec![0; len], pcd_cap2: vec![] }
    }

    #[test]
    fn aes_validation() {
        let k = keys(3, 2);
        let env = AesEnv { selected: Some(Aid(0x42)), keys: Some(&k), ..Default::default() };
        assert_eq!(plan_aes(&aes(2, 16), &env, true), Ok(2));
        assert!(plan_aes(&aes(3, 16), &env, true).unwrap_err().contains("does not exist"));
        assert!(plan_aes(&aes(0, 32), &env, true).unwrap_err().contains("AES-128"));
        assert!(plan_aes(&aes(0, 15), &env, true).unwrap_err().contains("16 bytes"));
        assert!(plan_aes(&aes(0, 16), &env, false).unwrap_err().contains("NonFirst"));
        let running = AesEnv { aes_session: true, ..env.clone() };
        assert_eq!(plan_aes(&aes(1, 16), &running, false), Ok(1));
        // PICC level
        let picc = AesEnv { selected: Some(Aid::PICC), ..Default::default() };
        assert_eq!(plan_aes(&aes(0x20, 16), &picc, true), Ok(0x20));
        assert!(plan_aes(&aes(0x05, 16), &picc, true).unwrap_err().contains("PICC level"));
        // second application
        let second = AesInput { second_app: true, ..aes(1, 16) };
        assert!(plan_aes(&second, &env, true).unwrap_err().contains("No second application"));
        let both = AesEnv { second_selected: true, ..env.clone() };
        assert_eq!(plan_aes(&second, &both, true), Ok(0x81));
        let tmp = keys(0x0F, 2);
        let env_tmp = AesEnv { selected: Some(Aid(1)), keys: Some(&tmp), ..Default::default() };
        assert!(plan_aes(&aes(1, 16), &env_tmp, true).unwrap_err().contains("AppMasterTmpKey"));
        let long_cap = AesInput { pcd_cap2: vec![0; 7], ..aes(0, 16) };
        assert!(plan_aes(&long_cap, &env, true).is_err());
    }

    fn snap() -> Snapshot {
        Snapshot {
            selected: Some(Aid(0x42)),
            second: None,
            apps: vec![Aid(0x42)],
            df_names: vec![DfName { aid: Aid(0x42), iso_fid: 0x1000, name: b"APP".to_vec() }],
            keys: None,
            ca_known: true,
            ca_keys: vec![CaRootKeyInfo {
                key_no: 1,
                curve: CURVE_P256,
                access_rights: 0x0021,
                write_access: 0x30,
                read_access: 0x1E,
                crl_file: 0,
                crl_aid: Aid(0),
            }],
            ecc_keys: vec![],
        }
    }

    fn ecc(ca: u8) -> EccInput {
        EccInput { mutual: true, ca_no: ca, ca2_no: 0, cert_file: 1, priv_no: 0, select_df: None, check_issuer: false }
    }

    #[test]
    fn ecc_planning_checks_the_cached_ca_keys() {
        let ok = plan_ecc(&ecc(1), &snap(), CURVE_P256).unwrap();
        assert_eq!(ok.aid, Aid(0x42));
        assert_eq!(ok.df_name.as_deref(), Some(&b"APP"[..]));
        assert_eq!(ok.root_acmap.bits(), 0x0021);
        assert!(plan_ecc(&ecc(0), &snap(), CURVE_P256).unwrap_err().contains("holds key(s) 1"));
        assert!(plan_ecc(&ecc(1), &snap(), CURVE_BP256).unwrap_err().contains("brainpool"));
        let none = Snapshot { ca_keys: vec![], ..snap() };
        assert!(plan_ecc(&ecc(0), &none, CURVE_P256).unwrap_err().contains("no CA root key"));
        // not known: no complaint
        let unknown = Snapshot { ca_known: false, ca_keys: vec![], ..snap() };
        assert!(plan_ecc(&ecc(3), &unknown, CURVE_P256).is_ok());
        assert!(plan_ecc(&ecc(5), &snap(), CURVE_P256).is_err());
        let nosel = Snapshot { selected: None, ..snap() };
        assert!(plan_ecc(&ecc(1), &nosel, CURVE_P256).unwrap_err().contains("not known"));
        assert!(plan_ecc(&EccInput { ca2_no: 2, ..ecc(1) }, &snap(), CURVE_P256).unwrap_err().contains("second application"));
    }

    #[test]
    fn ecc_select_variant_resolves_the_df_name() {
        let i = EccInput { select_df: Some(b"APP".to_vec()), ..ecc(1) };
        let ok = plan_ecc(&i, &snap(), CURVE_P256).unwrap();
        assert_eq!(ok.aid, Aid(0x42));
        let other = EccInput { select_df: Some(b"XYZ".to_vec()), ..ecc(1) };
        assert!(plan_ecc(&other, &snap(), CURVE_P256).unwrap_err().contains("DF name"));
        let empty = EccInput { select_df: Some(vec![]), ..ecc(1) };
        assert!(plan_ecc(&empty, &snap(), CURVE_P256).is_err());
    }

    #[test]
    fn local_check_uses_the_stores_rules() {
        let mut store = PkiStore::new();
        let root = store.new_root("Root", CURVE_P256, "Org", 5).unwrap();
        let rights = CertRights::for_aid(0x42, AcMap::parse("0,5").unwrap());
        let reader = store
            .issue(&root.id, IssueRequest::new(CertKind::Reader, "Reader").access_rights(rights))
            .unwrap();
        let checked = plan_ecc(&ecc(1), &snap(), CURVE_P256).unwrap();
        let ok = local_check(&store, &reader.id, &checked, None, &[], false);
        assert!(ok.failure.is_none(), "{:?}", ok.report);
        assert_eq!(ok.acmap, 0x0021); // within what the CA root key grants
        // other application: the certificate names AID 000042 only
        let elsewhere = EccChecked { aid: Aid(0x99), ..checked.clone() };
        let bad = local_check(&store, &reader.id, &elsewhere, None, &[], false);
        assert!(bad.failure.is_some());
        assert!(bad.report[0].contains("LOCAL CHECK FAILED") && bad.report[0].contains("6A80") || bad.report[0].contains("6982"));
        // the CA key itself: nothing to validate
        let by_root = local_check(&store, &root.id, &checked, Some(Aid(7)), &[], false);
        assert!(by_root.failure.is_none());
        assert_eq!((by_root.acmap, by_root.acmap2), (0x0021, 0x3FFF));
    }

    #[test]
    fn public_keys_on_either_curve_are_accepted() {
        let p = gen_key(CURVE_P256).unwrap().public().to_bytes();
        let b = gen_key(CURVE_BP256).unwrap().public().to_bytes();
        assert_eq!(parse_public_key(&p).unwrap().curve_id, CURVE_P256);
        assert_eq!(parse_public_key(&b).unwrap().curve_id, CURVE_BP256);
        assert!(parse_public_key(&p[..64]).unwrap_err().contains("65 bytes"));
        let mut bad = p.clone();
        bad[40] ^= 0xFF;
        assert!(parse_public_key(&bad).unwrap_err().contains("not a valid point"));
    }

    #[test]
    fn unilateral_checks() {
        let k = EccKeyInfo { key_no: 1, curve: CURVE_P256, policy: 0x0100, write_access: 0, kuc_limit: 5, kuc: 5 };
        assert!(unilateral_problem(1, &[k.clone()]).unwrap().contains("usage limit"));
        assert!(unilateral_problem(2, &[k.clone()]).is_none());
        assert!(unilateral_problem(9, &[]).is_some());
        assert!(unilateral_policy_note(1, &[k.clone()]).is_none());
        let off = EccKeyInfo { policy: 0x0080, kuc_limit: 0, ..k };
        assert!(unilateral_policy_note(1, &[off.clone()]).unwrap().contains("0080"));
        assert!(unilateral_problem(1, &[off]).is_none());
    }

    #[test]
    fn unilateral_report_wording() {
        let r = InternalAuthResult { rnd_a: vec![1], rnd_b: vec![2], signature: vec![3], message: vec![], valid: Some(true) };
        let t = unilateral_report(&r, &["src".into()], Some(false), None).join("\n");
        assert!(t.contains("Signature VALID") && t.contains("trust the certificate"), "{t}");
        let r = InternalAuthResult { valid: Some(false), ..r };
        assert!(unilateral_report(&r, &[], None, None).join("\n").contains("INVALID"));
        let r = InternalAuthResult { valid: None, ..r };
        assert!(unilateral_report(&r, &[], None, None).join("\n").contains("not checked"));
    }
}
