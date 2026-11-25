//! Certificate chain validation.
//!
//! [`validate_reader_chain`] applies the card's own rules for the reader certificate chain `Cert.A` (7.10.2.2);
//! [`verify_card_chain`] is what a reader does with a card's certificate (7.10.1) against trust anchors.

use super::access_rights::{AcMap, AccessRights, RightsScope};
use super::cert::Certificate;
use super::crl::{self, CsnOrder, CSN_SIZE};
use super::der;
use super::error::{CertError, PkiError, Result};
use super::profile::{check_reader_certificate, MAX_CHAIN_LEN};
use crate::crypto::PubKey;

/// What the card knows when it validates `Cert.A`.
#[derive(Debug, Clone)]
pub struct ChainParams<'a> {
    /// DER `Name` the CARootKey trusts as issuer (`currIssuer`); `None` or empty disables the check.
    pub issuer: Option<&'a [u8]>,
    /// Access conditions associated with the primary CARootKey.
    pub root_acmap: AcMap,
    /// Access conditions associated with the secondary application's CARootKey, when two are selected.
    pub root_acmap2: Option<AcMap>,
    /// Selected (primary) application; 0 is the PICC level.
    pub aid: u32,
    /// Selected secondary application.
    pub aid2: Option<u32>,
    /// DF name of the selected application, for ARType 2.
    pub df_name: Option<&'a [u8]>,
    /// UID (VCUID) of the card, for UID-bound delegated management rights.
    pub uid: Option<&'a [u8]>,
    /// Content of the CRLFile associated with the CARootKey, if revocation is active.
    pub crl: Option<&'a [u8]>,
    pub csn_order: CsnOrder,
}

impl Default for ChainParams<'_> {
    fn default() -> Self {
        ChainParams {
            issuer: None,
            root_acmap: AcMap::ALL,
            root_acmap2: None,
            aid: 0,
            aid2: None,
            df_name: None,
            uid: None,
            crl: None,
            csn_order: CsnOrder::default(),
        }
    }
}

/// Outcome of a successful validation.
#[derive(Debug, Clone)]
pub struct ChainResult {
    /// Public key of the leaf: the key the reader's `Sig.A` is verified with.
    pub leaf_pub: PubKey,
    /// Granted access conditions of the primary application (CertAccessRights).
    pub acmap: AcMap,
    /// Granted access conditions of the secondary application, if the rights name one.
    pub acmap2: Option<AcMap>,
    pub certs: Vec<Certificate>,
    /// One line per certificate, then the granted map.
    pub report: Vec<String>,
    /// The effective access-right extension: the leaf's, else the parent's.
    pub access_rights: Option<AccessRights>,
}

/// Validate `chain` (one or two concatenated DER certificates, parent first) against the CARootKey `root_pub`
/// the way the card does. The final `Sig.A` check against the leaf key is not part of this function.
pub fn validate_reader_chain(
    chain: &[u8],
    root_pub: &PubKey,
    params: &ChainParams<'_>,
) -> std::result::Result<ChainResult, CertError> {
    let parts = der::split_sequences(chain);
    if parts.is_empty() || parts.iter().map(|p| p.len()).sum::<usize>() != chain.len() {
        return Err(CertError::wrong_data("Cert.A is not a sequence of DER certificates"));
    }
    if parts.len() > MAX_CHAIN_LEN {
        return Err(CertError::wrong_data("chains of more than two certificates are not supported"));
    }
    let mut report = Vec::new();
    let mut cur_pub = root_pub.clone();
    let mut cur_issuer: Option<Vec<u8>> = params.issuer.filter(|i| !i.is_empty()).map(<[u8]>::to_vec);
    let mut acmap = params.root_acmap;
    let mut acmap2 = params.root_acmap2;
    let mut parent_ar: Option<AccessRights> = None;
    let mut certs = Vec::new();

    for (i, raw) in parts.iter().enumerate() {
        let role = match (parts.len(), i) {
            (1, _) => "certificate",
            (_, 0) => "parent",
            _ => "leaf",
        };
        let is_parent = parts.len() == 2 && i == 0;
        if raw.len() > super::profile::MAX_READER_CERT {
            return Err(CertError::wrong_data(format!(
                "{role}: {} bytes exceeds the {} byte limit",
                raw.len(),
                super::profile::MAX_READER_CERT
            )));
        }
        let cert = Certificate::from_der(raw)
            .map_err(|e| CertError::wrong_data(format!("{role}: not parseable ({e})")))?;
        check_reader_certificate(&cert, role, root_pub.curve_id)?;
        if !cert.verify_signature(&cur_pub) {
            return Err(CertError::security(format!("{role}: signature validation failed")));
        }
        if let Some(issuer) = &cur_issuer {
            if cert.issuer().to_der() != issuer.as_slice() {
                return Err(CertError::wrong_data(format!("{role}: issuer does not match the trusted issuer name")));
            }
        }
        let ar = cert.access_rights().map_err(|e| CertError::wrong_data(format!("{role}: {e}")))?;
        if let Some(ar) = &ar {
            check_rights_scope(ar, role, params, acmap)?;
            if is_parent && !ar.delegation {
                return Err(CertError::wrong_data("parent: CA delegation is not enabled in the access right extension"));
            }
            if let Some(p) = &parent_ar {
                check_against_parent(ar, p)?;
            }
            match ar.scope {
                RightsScope::Aid { .. } | RightsScope::DfName { .. } => {
                    if !ar.acmap().is_subset_of(acmap) {
                        return Err(CertError::wrong_data(format!(
                            "{role}: ACMap {:04X} exceeds the rights of its issuer ({:04X})",
                            ar.acmap().bits(),
                            acmap.bits()
                        )));
                    }
                    acmap = ar.acmap();
                    if let Some(m2) = ar.acmap2() {
                        if acmap2.is_some_and(|issuer2| !m2.is_subset_of(issuer2)) {
                            return Err(CertError::wrong_data(format!("{role}: ACMap2 exceeds the rights of its issuer")));
                        }
                        acmap2 = Some(m2);
                    }
                }
                RightsScope::DelegatedManagement(_) => acmap = AcMap::DAM,
            }
            parent_ar = Some(ar.clone());
        }
        if let (Some(image), Some(serial)) = (params.crl, cert.serial()) {
            if let Some(why) = crl::check_revoked(image, serial, CSN_SIZE, params.csn_order) {
                return Err(CertError::security(format!("{role}: revoked ({why})")));
            }
        }
        let rights_text = match &ar {
            Some(a) => format!(", {}", a.describe()),
            None => ", access rights inherited".to_string(),
        };
        report.push(format!(
            "{role}: {} serial {}, {} bytes - ok{rights_text}",
            cert.subject(),
            cert.serial().unwrap_or_default(),
            raw.len()
        ));
        cur_pub = cert.public_key().map_err(|e| CertError::wrong_data(format!("{role}: {e}")))?;
        cur_issuer = Some(cert.subject().to_der().to_vec());
        certs.push(cert);
    }
    report.push(format!("granted ACMap {:04X} [{acmap}]", acmap.bits()));
    Ok(ChainResult { leaf_pub: cur_pub, acmap, acmap2, certs, report, access_rights: parent_ar })
}

/// Rules 4d..4i of 7.10.2.2: the rights must name the application that is selected.
fn check_rights_scope(
    ar: &AccessRights,
    role: &str,
    p: &ChainParams<'_>,
    issuer_acmap: AcMap,
) -> std::result::Result<(), CertError> {
    let fail = |m: String| Err(CertError::wrong_data(format!("{role}: {m}")));
    match &ar.scope {
        RightsScope::Aid { aid, secondary, .. } => {
            if *aid != p.aid {
                return fail(format!("access rights are for AID {aid:06X}, not the selected application"));
            }
            if p.aid2.is_some() && secondary.is_none() {
                return fail("no AID2 access rights while two applications are selected".into());
            }
            if let Some((aid2, _)) = secondary {
                if Some(*aid2) != p.aid2 {
                    return fail("AID2 is not the selected secondary application".into());
                }
            }
        }
        RightsScope::DfName { name, .. } => {
            if p.df_name != Some(name.as_slice()) {
                return fail("DFName is not the selected application".into());
            }
        }
        RightsScope::DelegatedManagement(d) => {
            if p.aid != 0 {
                return fail("delegated application management rights need the PICC level".into());
            }
            if !d.uid.is_empty() && p.uid.is_some_and(|u| u != d.uid.as_slice()) {
                return fail("access rights are bound to another UID".into());
            }
            if !issuer_acmap.contains(2) {
                return fail("issuing CA does not hold access condition 2 (DAM)".into());
            }
        }
    }
    Ok(())
}

/// Rules 4k, 4n, 4o of 7.10.2.2: a leaf must be of the same type as its parent and not widen its DAM payload or UID.
fn check_against_parent(leaf: &AccessRights, parent: &AccessRights) -> std::result::Result<(), CertError> {
    if leaf.ar_type() != parent.ar_type() {
        return Err(CertError::wrong_data("leaf: access right type differs from the parent certificate"));
    }
    if let (RightsScope::DelegatedManagement(l), RightsScope::DelegatedManagement(p)) = (&leaf.scope, &parent.scope) {
        if l.payload != p.payload || l.operation != p.operation {
            return Err(CertError::wrong_data("leaf: DAM payload differs from the parent certificate"));
        }
        if !p.uid.is_empty() && l.uid != p.uid {
            return Err(CertError::wrong_data("leaf: UID differs from the parent certificate"));
        }
    }
    Ok(())
}

// ------------------------------------------------------- card certificate chains
/// A trust anchor for card certificates: a CA certificate or a bare public key.
#[derive(Debug, Clone)]
pub enum TrustAnchor {
    Certificate(Certificate),
    PublicKey(PubKey),
}

impl From<Certificate> for TrustAnchor {
    fn from(c: Certificate) -> Self {
        TrustAnchor::Certificate(c)
    }
}
impl From<PubKey> for TrustAnchor {
    fn from(k: PubKey) -> Self {
        TrustAnchor::PublicKey(k)
    }
}

impl TrustAnchor {
    fn key(&self) -> Option<PubKey> {
        match self {
            TrustAnchor::Certificate(c) => c.public_key().ok(),
            TrustAnchor::PublicKey(k) => Some(k.clone()),
        }
    }
    fn label(&self) -> String {
        match self {
            TrustAnchor::Certificate(c) => c.subject().to_string(),
            TrustAnchor::PublicKey(_) => "key".to_string(),
        }
    }
}

/// Result of [`verify_card_chain`].
#[derive(Debug, Clone)]
pub struct CardChain {
    pub leaf: Certificate,
    /// The card's public key (from the leaf certificate).
    pub public_key: PubKey,
    /// True when some certificate of the path is signed by an anchor.
    pub trusted: bool,
    /// Label of the anchor that vouched for the path (subject of the CA certificate, or `key`).
    pub anchor: Option<String>,
    /// Subjects from the leaf upwards to the last certificate examined.
    pub path: Vec<String>,
    /// Issuer of the last certificate examined.
    pub issuer: String,
}

/// Index of the certificate that is not an issuer of another one (the leaf).
fn leaf_index(certs: &[Certificate]) -> usize {
    for (i, c) in certs.iter().enumerate() {
        let is_issuer = certs.iter().any(|o| o.issuer() == c.subject());
        if !is_issuer || certs.len() == 1 {
            return i;
        }
    }
    certs.len() - 1
}

/// Public key of the leaf certificate of a PEM or DER certificate (chain).
pub fn leaf_public_key(blob: &[u8]) -> Result<PubKey> {
    let certs = Certificate::load_all(blob)?;
    if certs.is_empty() {
        return Err(PkiError::Certificate("no X.509 certificate found".into()));
    }
    certs[leaf_index(&certs)].public_key()
}

/// Validate a card certificate (chain) against trust anchors: walk from the leaf through issuers contained in
/// the blob until a certificate is signed by an anchor. The card is agnostic about its certificate format, so
/// only signatures and issuer names are used; validity periods are not examined.
pub fn verify_card_chain(blob: &[u8], anchors: &[TrustAnchor]) -> Result<CardChain> {
    let certs = Certificate::load_all(blob)?;
    if certs.is_empty() {
        return Err(PkiError::Certificate("no X.509 certificate found".into()));
    }
    let leaf = certs[leaf_index(&certs)].clone();
    let anchor_keys: Vec<(PubKey, String)> = anchors.iter().filter_map(|a| a.key().map(|k| (k, a.label()))).collect();
    let mut cur = leaf.clone();
    let mut path = Vec::new();
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut trusted_by = None;
    loop {
        path.push(cur.subject().to_string());
        if let Some((_, label)) = anchor_keys.iter().find(|(k, _)| cur.verify_signature(k)) {
            trusted_by = Some(label.clone());
            break;
        }
        seen.push(cur.to_der().to_vec());
        let next = certs.iter().find(|c| {
            !seen.iter().any(|s| s == c.to_der())
                && c.subject() == cur.issuer()
                && c.public_key().is_ok_and(|k| cur.verify_signature(&k))
        });
        match next {
            Some(n) => cur = n.clone(),
            None => break,
        }
    }
    Ok(CardChain {
        public_key: leaf.public_key()?,
        leaf,
        trusted: trusted_by.is_some(),
        anchor: trusted_by,
        path,
        issuer: cur.issuer().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::cert::CertificateBuilder;
    use super::super::crl::build_image;
    use super::super::name::Name;
    use super::*;
    use crate::crypto::{gen_key, PrivKey, CURVE_BP256, CURVE_P256};

    const AID: u32 = 0x112233;

    struct Pki {
        root_key: PrivKey,
        root_name: Name,
    }

    impl Pki {
        fn new(curve: u8) -> Pki {
            Pki { root_key: gen_key(curve).unwrap(), root_name: Name::with_common_name("Root", "Acme") }
        }
        fn issue(
            &self,
            signer: &PrivKey,
            issuer: &Name,
            cn: &str,
            serial: u64,
            ar: Option<AccessRights>,
        ) -> (PrivKey, Certificate) {
            let key = gen_key(self.root_key.curve_id).unwrap();
            let mut b = CertificateBuilder::new(Name::with_common_name(cn, "Acme"), issuer.clone(), key.public()).serial(serial);
            if let Some(a) = ar {
                b = b.access_rights(a, true);
            }
            (key, b.sign(signer).unwrap())
        }
        fn root_issue(&self, cn: &str, serial: u64, ar: Option<AccessRights>) -> (PrivKey, Certificate) {
            self.issue(&self.root_key, &self.root_name, cn, serial, ar)
        }
    }

    fn params() -> ChainParams<'static> {
        ChainParams { aid: AID, ..Default::default() }
    }

    #[test]
    fn single_certificate_inherits_rights() {
        for curve in [CURVE_P256, CURVE_BP256] {
            let pki = Pki::new(curve);
            let (_, c) = pki.root_issue("Reader", 5, None);
            let r = validate_reader_chain(c.to_der(), &pki.root_key.public(), &params()).unwrap();
            assert_eq!(r.acmap, AcMap::ALL);
            assert!(r.report[0].contains("access rights inherited"));
            assert_eq!(r.leaf_pub, c.public_key().unwrap());
            // wrong root key
            let other = gen_key(curve).unwrap().public();
            let e = validate_reader_chain(c.to_der(), &other, &params()).unwrap_err();
            assert_eq!(e.sw, 0x6982);
        }
    }

    #[test]
    fn delegated_chain_narrows_rights() {
        let pki = Pki::new(CURVE_P256);
        let sub_ar = AccessRights::for_aid(AID, AcMap::new(0x0023)).delegating();
        let (sub_key, sub) = pki.root_issue("Site CA", 1, Some(sub_ar));
        let door_ar = AccessRights::for_aid(AID, AcMap::new(0x0020));
        let (_, door) = pki.issue(&sub_key, sub.subject(), "Door", 2, Some(door_ar));
        let chain = [sub.to_der(), door.to_der()].concat();
        let issuer = pki.root_name.to_der().to_vec();
        let p = ChainParams { issuer: Some(&issuer), root_acmap: AcMap::new(0x0023), ..params() };
        let r = validate_reader_chain(&chain, &pki.root_key.public(), &p).unwrap();
        assert_eq!(r.acmap, AcMap::new(0x0020));
        assert_eq!(r.certs.len(), 2);

        // issuer name mismatch
        let wrong = Name::with_common_name("Other", "").to_der().to_vec();
        let e = validate_reader_chain(&chain, &pki.root_key.public(), &ChainParams { issuer: Some(&wrong), ..p.clone() })
            .unwrap_err();
        assert!(e.message.contains("issuer does not match"));

        // rights wider than the root key's
        let e = validate_reader_chain(&chain, &pki.root_key.public(), &ChainParams { root_acmap: AcMap::new(3), ..p.clone() })
            .unwrap_err();
        assert!(e.message.contains("exceeds the rights"), "{e}");

        // wrong application
        let e = validate_reader_chain(&chain, &pki.root_key.public(), &ChainParams { aid: 1, ..p.clone() }).unwrap_err();
        assert!(e.message.contains("not the selected application"));

        // the delegated CA is usable as a leaf and keeps its own rights
        let r = validate_reader_chain(sub.to_der(), &pki.root_key.public(), &p).unwrap();
        assert_eq!(r.acmap, AcMap::new(0x0023));
    }

    #[test]
    fn parent_without_delegation_is_refused() {
        let pki = Pki::new(CURVE_P256);
        let (k, parent) = pki.root_issue("P", 1, Some(AccessRights::for_aid(AID, AcMap::ALL)));
        let (_, leaf) = pki.issue(&k, parent.subject(), "L", 2, None);
        let chain = [parent.to_der(), leaf.to_der()].concat();
        let e = validate_reader_chain(&chain, &pki.root_key.public(), &params()).unwrap_err();
        assert!(e.message.contains("delegation is not enabled"));
        // a parent without any extension may delegate (rights inherited)
        let (k, parent) = pki.root_issue("P2", 3, None);
        let (_, leaf) = pki.issue(&k, parent.subject(), "L2", 4, Some(AccessRights::for_aid(AID, AcMap::new(1))));
        let chain = [parent.to_der(), leaf.to_der()].concat();
        let r = validate_reader_chain(&chain, &pki.root_key.public(), &params()).unwrap();
        assert_eq!(r.acmap, AcMap::new(1));
    }

    #[test]
    fn rejects_malformed_chains() {
        let pki = Pki::new(CURVE_P256);
        let (_, a) = pki.root_issue("A", 1, None);
        let rk = pki.root_key.public();
        assert!(validate_reader_chain(&[], &rk, &params()).is_err());
        let trailing = [a.to_der(), &[0u8, 0][..]].concat();
        assert!(validate_reader_chain(&trailing, &rk, &params()).is_err());
        let three = [a.to_der(), a.to_der(), a.to_der()].concat();
        assert!(validate_reader_chain(&three, &rk, &params()).unwrap_err().message.contains("more than two"));
        // curve mismatch
        let bp = Pki::new(CURVE_BP256);
        let (_, b) = bp.root_issue("B", 1, None);
        assert!(validate_reader_chain(b.to_der(), &rk, &params()).unwrap_err().message.contains("not on"));
        // serial too large
        let (_, big) = pki.root_issue("Big", 0x8000_0000, None);
        assert!(validate_reader_chain(big.to_der(), &rk, &params()).unwrap_err().message.contains("4-byte"));
        // critical unknown extension
        let key = gen_key(CURVE_P256).unwrap();
        let rights = AccessRights::for_aid(AID, AcMap::NONE);
        let _ = rights;
        let c = CertificateBuilder::new(Name::with_common_name("C", ""), pki.root_name.clone(), key.public())
            .ca(true)
            .sign(&pki.root_key)
            .unwrap();
        assert!(validate_reader_chain(c.to_der(), &rk, &params()).unwrap_err().message.contains("critical extension"));
    }

    #[test]
    fn revocation_is_applied_to_every_certificate() {
        let pki = Pki::new(CURVE_P256);
        let (k, parent) = pki.root_issue("P", 10, Some(AccessRights::for_aid(AID, AcMap::ALL).delegating()));
        let (_, leaf) = pki.issue(&k, parent.subject(), "L", 20, None);
        let chain = [parent.to_der(), leaf.to_der()].concat();
        let rk = pki.root_key.public();
        for (all_before, list, bad) in [(0u32, vec![20u32], "leaf"), (0, vec![10], "parent"), (10, vec![], "parent"), (20, vec![], "parent")] {
            let img = build_image(all_before, &list, Some(32), CsnOrder::MsbFirst).unwrap();
            let e = validate_reader_chain(&chain, &rk, &ChainParams { crl: Some(&img), ..params() }).unwrap_err();
            assert!(e.message.starts_with(bad) && e.message.contains("revoked"), "{e}");
            assert_eq!(e.sw, 0x6982);
        }
        let ok = build_image(9, &[11, 21], Some(32), CsnOrder::MsbFirst).unwrap();
        assert!(validate_reader_chain(&chain, &rk, &ChainParams { crl: Some(&ok), ..params() }).is_ok());
        // byte order switch
        let lsb = build_image(0, &[20], Some(32), CsnOrder::LsbFirst).unwrap();
        let p = ChainParams { crl: Some(&lsb), csn_order: CsnOrder::LsbFirst, ..params() };
        assert!(validate_reader_chain(&chain, &rk, &p).is_err());
        let p = ChainParams { crl: Some(&lsb), ..params() };
        assert!(validate_reader_chain(&chain, &rk, &p).is_ok());
    }

    #[test]
    fn dam_rights_rules() {
        use super::super::access_rights::DamOperation;
        let pki = Pki::new(CURVE_P256);
        let payload: Vec<u8> = (1..=10).collect();
        let uid = [0x04, 1, 2, 3, 4, 5, 6];
        let dam = AccessRights::for_dam(&uid, DamOperation::Create, &payload);
        let (_, c) = pki.root_issue("Dam", 1, Some(dam));
        let rk = pki.root_key.public();
        let p = ChainParams { aid: 0, root_acmap: AcMap::new(0x0004), uid: Some(&uid), ..Default::default() };
        let r = validate_reader_chain(c.to_der(), &rk, &p).unwrap();
        assert_eq!(r.acmap, AcMap::DAM);
        // CA without access condition 2
        let e = validate_reader_chain(c.to_der(), &rk, &ChainParams { root_acmap: AcMap::new(3), ..p.clone() }).unwrap_err();
        assert!(e.message.contains("access condition 2"));
        // other card
        let other = [0x04u8, 9, 9, 9, 9, 9, 9];
        let e = validate_reader_chain(c.to_der(), &rk, &ChainParams { uid: Some(&other), ..p.clone() }).unwrap_err();
        assert!(e.message.contains("another UID"));
        // not at PICC level
        let e = validate_reader_chain(c.to_der(), &rk, &ChainParams { aid: 5, ..p }).unwrap_err();
        assert!(e.message.contains("PICC level"));
    }

    #[test]
    fn card_chain_against_anchors() {
        let pki = Pki::new(CURVE_P256);
        let (ik, inter) = pki.root_issue("Intermediate", 1, None);
        let (_, card) = pki.issue(&ik, inter.subject(), "Card", 2, None);
        let chain = [card.to_der(), inter.to_der()].concat();
        // anchored by the root key
        let r = verify_card_chain(&chain, &[pki.root_key.public().into()]).unwrap();
        assert!(r.trusted);
        assert_eq!(r.anchor.as_deref(), Some("key"));
        assert_eq!(r.leaf, card);
        assert_eq!(r.public_key, card.public_key().unwrap());
        assert_eq!(r.path.len(), 2);
        // anchored by an intermediate certificate
        let r = verify_card_chain(card.to_der(), &[inter.clone().into()]).unwrap();
        assert!(r.trusted);
        assert_eq!(r.anchor.as_deref(), Some("CN=Intermediate,O=Acme"));
        // no anchor knows it
        let r = verify_card_chain(&chain, &[gen_key(CURVE_P256).unwrap().public().into()]).unwrap();
        assert!(!r.trusted && r.anchor.is_none());
        assert_eq!(r.issuer, "CN=Root,O=Acme");
        assert_eq!(leaf_public_key(&chain).unwrap(), card.public_key().unwrap());
        assert!(verify_card_chain(&[], &[]).is_err());
    }
}
