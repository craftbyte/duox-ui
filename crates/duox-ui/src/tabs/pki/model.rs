//! Pure logic of the CAs & certificates tab: tree contents, issuing requests, export formats and the
//! reader-certificate pre-check. Nothing here touches the card or the UI toolkit state.

use super::rootkey::parse_aid;
use crate::ui::hex;
use crate::ui::tree::Node;
use duox::crypto::{curve_name, PubKey, CURVE_BP256, CURVE_P256};
use duox::pki::{
    AcMap, AccessRights, CertKind, ChainResult, CsnOrder, Entry, PkiError, PkiStore, PreflightOptions,
};

/// Curves a CA can use, in the order the forms list them.
pub const CURVES: [(u8, &str); 2] = [(CURVE_P256, "NIST P-256"), (CURVE_BP256, "brainpoolP256r1")];

pub fn curve_labels() -> Vec<&'static str> {
    CURVES.iter().map(|c| c.1).collect()
}

pub fn curve_at(index: usize) -> u8 {
    CURVES.get(index).map(|c| c.0).unwrap_or(CURVE_P256)
}

// ------------------------------------------------------------------------- tree

/// Short description of the rights an entry carries or inherits.
pub fn rights_summary(e: &Entry) -> String {
    match e.access_rights() {
        Some(ar) => ar.describe(),
        None if matches!(e.kind, CertKind::Root | CertKind::Card) => "-".into(),
        None => "inherited from issuer".into(),
    }
}

/// One-line facts shown dimmed after the entry name.
pub fn entry_info(e: &Entry) -> String {
    let serial = e.serial().map(|s| format!("#{s}")).unwrap_or_else(|| "#?".into());
    format!(
        "{} | {serial} | {} | {} | key {} | {} | {} bytes",
        e.kind.label(),
        curve_name(e.curve),
        rights_summary(e),
        if e.has_key() { "yes" } else { "-" },
        if e.revoked { "REVOKED" } else { "ok" },
        e.cert.len()
    )
}

fn node_of(store: &PkiStore, e: &Entry, depth: usize) -> Node {
    let mut n = Node::new(e.id.clone(), e.name.clone()).info(entry_info(e));
    // The store only builds chains of two, but a damaged file must not recurse forever.
    if depth < 8 {
        n = n.children(store.children(Some(&e.id)).into_iter().map(|c| node_of(store, c, depth + 1)));
    }
    n
}

/// The issuer hierarchy: roots first, then entries whose issuer is not in the store.
pub fn tree_nodes(store: &PkiStore) -> Vec<Node> {
    let mut out: Vec<Node> = store.roots().into_iter().map(|e| node_of(store, e, 0)).collect();
    for e in store.entries() {
        let orphan = e.parent.as_deref().is_some_and(|p| store.get(p).is_err());
        if orphan {
            out.push(node_of(store, e, 0));
        }
    }
    out
}

/// Detail text of an entry: decoded certificate, CRL state of roots, chain size of readers.
pub fn describe_entry(store: &PkiStore, e: &Entry) -> String {
    let mut lines = vec![format!("{}: {}   (store id {})", e.kind.label(), e.name, e.id)];
    lines.extend(duox::pki::describe_der(&e.cert));
    if !e.note.is_empty() {
        lines.push(format!("Note         {}", e.note));
    }
    if e.kind == CertKind::Root {
        let listed = if e.crl.serials.is_empty() {
            "none".to_string()
        } else {
            e.crl.serials.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
        };
        lines.push(String::new());
        lines.push(format!("Next serial  {}", e.next_serial));
        lines.push(format!(
            "CRL          version {}, all serials up to {} revoked, listed: {listed}",
            e.crl.version, e.crl.all_before
        ));
    }
    if matches!(e.kind, CertKind::Reader | CertKind::Sub) {
        if let Ok(chain) = store.chain_bytes(&e.id) {
            let n = duox::pki::der::split_sequences(&chain).len();
            lines.push(String::new());
            lines.push(format!("Cert.A sent to the card: {n} certificate(s), {} bytes", chain.len()));
        }
    }
    lines.join("\n")
}

// ----------------------------------------------------------------------- issuing

/// The CA that issues for the selected entry: the nearest CA at or above it. A delegated CA can only be
/// issued by a root, so the root is returned for that kind.
pub fn issuer_for(store: &PkiStore, selected: Option<&str>, kind: CertKind) -> Result<String, String> {
    let Some(id) = selected else {
        return Err("Select the issuing CA (or any certificate below it) in the list first.".into());
    };
    let mut e = store.get(id).map_err(|e| e.to_string())?;
    let mut hops = 0;
    while !e.kind.is_ca() {
        hops += 1;
        e = match e.parent.as_deref().and_then(|p| store.get(p).ok()) {
            Some(p) if hops < 8 => p,
            _ => return Err(format!("'{}' has no issuing CA in the store; select a CA instead.", e.name)),
        };
    }
    if kind == CertKind::Sub && e.kind != CertKind::Root {
        e = store.root_of(&e.id).map_err(|e| e.to_string())?;
    }
    if !e.has_key() {
        return Err(format!("The CA '{}' has no private key in the store, so it cannot issue certificates.", e.name));
    }
    Ok(e.id.clone())
}

/// A public key to certify: empty (generate a pair), or an uncompressed point on the curve.
pub fn check_public_key(raw: &[u8], curve_id: u8) -> Result<Option<Vec<u8>>, String> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() != 65 || raw[0] != 0x04 {
        return Err(format!(
            "The public key must be an uncompressed point of 65 bytes (130 hex digits starting with 04); got {} bytes.",
            raw.len()
        ));
    }
    PubKey::from_bytes(curve_id, raw)
        .map_err(|_| format!("The public key is not a valid point on {}.", curve_name(curve_id)))?;
    Ok(Some(raw.to_vec()))
}

/// What the form says about the NXP access-right extension.
#[derive(Debug, Clone, Default)]
pub struct RightsInput {
    pub by_df_name: bool,
    pub aid: u32,
    pub df_name: Vec<u8>,
    pub acmap: String,
    pub secondary_aid: String,
    pub secondary_acmap: String,
    /// The certificate may act as a CA (delegated CAs).
    pub delegation: bool,
}

fn parse_acmap(label: &str, text: &str) -> Result<AcMap, String> {
    AcMap::parse(text).map_err(|e| format!("{label}: {e}. Write them like 0,5 or 0-D."))
}

pub fn build_rights(r: &RightsInput) -> Result<AccessRights, String> {
    let primary = parse_acmap("Access conditions", &r.acmap)?;
    let mut ar = if r.by_df_name {
        if r.df_name.is_empty() || r.df_name.len() > 16 {
            return Err(format!("The DF name must be 1 to 16 bytes, got {}.", r.df_name.len()));
        }
        AccessRights::for_df_name(&r.df_name, primary)
    } else {
        if r.aid > 0xFF_FFFF {
            return Err("The AID has at most six hex digits.".into());
        }
        AccessRights::for_aid(r.aid, primary)
    };
    if let Some(aid2) = parse_aid(&r.secondary_aid)? {
        if r.by_df_name {
            return Err("A secondary application can only be named together with an AID, not with a DF name.".into());
        }
        ar = ar.with_secondary(aid2, parse_acmap("Secondary access conditions", &r.secondary_acmap)?);
    }
    Ok(if r.delegation { ar.delegating() } else { ar })
}

// ------------------------------------------------------------------------ export

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Pem,
    Der,
    /// The DER chain a reader sends to the card (parent first for delegated CAs).
    CardChain,
}

impl ExportFormat {
    pub const LABELS: [&'static str; 3] = ["PEM", "DER", "DER chain as sent to the card (Cert.A)"];

    pub fn from_index(i: usize) -> Self {
        match i {
            1 => ExportFormat::Der,
            2 => ExportFormat::CardChain,
            _ => ExportFormat::Pem,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Pem => "pem",
            _ => "der",
        }
    }

    pub fn bytes(self, store: &PkiStore, e: &Entry) -> Result<Vec<u8>, String> {
        match self {
            ExportFormat::Pem => Ok(e.certificate().map_err(|e| e.to_string())?.to_pem().into_bytes()),
            ExportFormat::Der => Ok(e.cert.clone()),
            ExportFormat::CardChain => {
                if e.kind == CertKind::Root {
                    return Err("A root CA is not sent to the card as a chain; its public key is installed as a \
                                CA root key instead. Export it as PEM or DER."
                        .into());
                }
                store.chain_bytes(&e.id).map_err(|e| e.to_string())
            }
        }
    }
}

/// File name proposal: letters and digits of the entry name, other characters become `_`.
pub fn file_name(name: &str, suffix: &str, ext: &str) -> String {
    let stem: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
    let stem = if stem.trim_matches('_').is_empty() { "certificate".to_string() } else { stem };
    format!("{stem}{suffix}.{ext}")
}

// -------------------------------------------------------------------- passphrase

/// Two entries of a new passphrase: `None` means "store the keys unencrypted".
pub fn new_passphrase(first: &str, again: &str) -> Result<Option<String>, String> {
    if first != again {
        return Err("The two passphrases are not the same; nothing was changed.".into());
    }
    Ok((!first.is_empty()).then(|| first.to_string()))
}

// ---------------------------------------------------------------- card file image

/// Bytes written into a certificate file: the certificate, followed by the delegated CA that issued it when
/// requested.
pub fn card_file_payload(store: &PkiStore, e: &Entry, append_issuer: bool) -> Result<Vec<u8>, String> {
    let mut data = e.cert.clone();
    if append_issuer {
        match e.parent.as_deref().and_then(|p| store.get(p).ok()) {
            Some(p) if p.kind == CertKind::Sub => data.extend(&p.cert),
            _ => return Err(format!("'{}' was not issued by a delegated CA, so there is no issuer to append.", e.name)),
        }
    }
    Ok(data)
}

// ------------------------------------------------------------------- pre-check

/// Inputs of the reader chain check, as typed in the form.
#[derive(Debug, Clone)]
pub struct CheckInput {
    pub aid: u32,
    pub df_name: Vec<u8>,
    pub uid: Vec<u8>,
    pub root_acmap: String,
    pub check_issuer: bool,
    pub order: CsnOrder,
}

pub fn preflight_options(i: &CheckInput) -> Result<PreflightOptions, String> {
    if i.aid > 0xFF_FFFF {
        return Err("The AID has at most six hex digits.".into());
    }
    if !(i.uid.is_empty() || matches!(i.uid.len(), 4 | 7 | 10)) {
        return Err(format!("A card UID has 4, 7 or 10 bytes; got {}.", i.uid.len()));
    }
    if i.df_name.len() > 16 {
        return Err("The DF name has at most 16 bytes.".into());
    }
    Ok(PreflightOptions {
        aid: i.aid,
        aid2: None,
        df_name: (!i.df_name.is_empty()).then(|| i.df_name.clone()),
        uid: (!i.uid.is_empty()).then(|| i.uid.clone()),
        root_acmap: parse_acmap("CA root key access conditions", &i.root_acmap)?,
        check_issuer: i.check_issuer,
        csn_order: i.order,
    })
}

/// Text for the detail pane: the verdict, what the card would answer, and the per-certificate report.
pub fn format_check(outcome: Result<ChainResult, PkiError>, aid: u32) -> Result<String, String> {
    match outcome {
        Ok(r) => Ok(format!(
            "ACCEPTED for application {aid:06X} (as far as the CA root key's own access conditions allow)\n\n{}",
            r.report.join("\n")
        )),
        Err(PkiError::Chain(e)) => Ok(format!("REJECTED - the card would answer {:04X}\n\n{}", e.sw, e.message)),
        Err(other) => Err(other.to_string()),
    }
}

/// Hex text of a UID for form defaults.
pub fn uid_text(uid: &[u8]) -> String {
    hex::spaced(uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use duox::pki::{ImportOptions, IssueRequest};

    fn store_with_chain() -> (PkiStore, String, String, String) {
        let mut s = PkiStore::new();
        let root = s.new_root("Test Root", CURVE_P256, "", 5).unwrap();
        let ar = AccessRights::for_aid(0x123456, AcMap::new(0x0023));
        let reader = s.issue(&root.id, IssueRequest::new(CertKind::Reader, "Reader 1").access_rights(ar)).unwrap();
        let card = s.issue(&root.id, IssueRequest::new(CertKind::Card, "Card 1")).unwrap();
        (s, root.id, reader.id, card.id)
    }

    #[test]
    fn rights_text_inputs() {
        let base = RightsInput { aid: 0x123456, acmap: "0,5".into(), ..Default::default() };
        let ar = build_rights(&base).unwrap();
        assert_eq!(ar.acmap().bits(), 0x0021);
        assert!(!ar.delegation);
        let sub = build_rights(&RightsInput { delegation: true, ..base.clone() }).unwrap();
        assert!(sub.delegation);
        let two = build_rights(&RightsInput {
            secondary_aid: "ABCDEF".into(),
            secondary_acmap: "1".into(),
            ..base.clone()
        })
        .unwrap();
        assert_eq!(two.acmap2().unwrap().bits(), 2);
        let df = build_rights(&RightsInput {
            by_df_name: true,
            df_name: b"DUOX".to_vec(),
            acmap: "0".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(df.ar_type(), 2);
        assert!(build_rights(&RightsInput { acmap: "zz".into(), ..base.clone() }).unwrap_err().contains("Access conditions"));
        assert!(build_rights(&RightsInput { acmap: "E".into(), ..base.clone() }).is_err());
        assert!(build_rights(&RightsInput { by_df_name: true, acmap: "0".into(), ..Default::default() }).is_err());
        assert!(build_rights(&RightsInput { aid: 0x1_000000, acmap: "0".into(), ..Default::default() }).is_err());
        assert!(build_rights(&RightsInput { secondary_aid: "xyz".into(), ..base }).is_err());
    }

    #[test]
    fn public_key_input() {
        assert_eq!(check_public_key(&[], CURVE_P256).unwrap(), None);
        let key = duox::crypto::gen_key(CURVE_P256).unwrap().public().to_bytes();
        assert_eq!(check_public_key(&key, CURVE_P256).unwrap(), Some(key.clone()));
        assert!(check_public_key(&key[..64], CURVE_P256).unwrap_err().contains("65 bytes"));
        let mut off_curve = key;
        off_curve[64] ^= 1;
        assert!(check_public_key(&off_curve, CURVE_P256).unwrap_err().contains("valid point"));
    }

    #[test]
    fn issuer_selection() {
        let (s, root, reader, _) = store_with_chain();
        assert_eq!(issuer_for(&s, Some(&reader), CertKind::Reader).unwrap(), root);
        assert_eq!(issuer_for(&s, Some(&root), CertKind::Sub).unwrap(), root);
        assert!(issuer_for(&s, None, CertKind::Reader).unwrap_err().contains("Select"));
        // a CA known only by its certificate cannot issue
        let mut keyless = PkiStore::new();
        let imported = keyless.import(&s.get(&root).unwrap().cert.clone(), &ImportOptions::default()).unwrap();
        let err = issuer_for(&keyless, Some(&imported[0].id), CertKind::Reader).unwrap_err();
        assert!(err.contains("no private key"), "{err}");
    }

    #[test]
    fn tree_and_info() {
        let (s, root, reader, card) = store_with_chain();
        let nodes = tree_nodes(&s);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, root);
        let kids: Vec<&str> = nodes[0].children.iter().map(|n| n.id.as_str()).collect();
        assert!(kids.contains(&reader.as_str()) && kids.contains(&card.as_str()));
        let info = entry_info(s.get(&reader).unwrap());
        assert!(info.contains("Reader") && info.contains("AID 123456") && info.contains("ok"), "{info}");
        assert!(entry_info(s.get(&root).unwrap()).contains("key yes"));
        let text = describe_entry(&s, s.get(&root).unwrap());
        assert!(text.contains("Next serial") && text.contains("CRL"));
        assert!(describe_entry(&s, s.get(&reader).unwrap()).contains("Cert.A sent to the card: 1 certificate(s)"));
    }

    #[test]
    fn exports() {
        let (s, root, reader, _) = store_with_chain();
        let r = s.get(&reader).unwrap();
        let pem = String::from_utf8(ExportFormat::Pem.bytes(&s, r).unwrap()).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE"));
        assert_eq!(ExportFormat::Der.bytes(&s, r).unwrap(), r.cert);
        assert_eq!(ExportFormat::CardChain.bytes(&s, r).unwrap(), r.cert);
        assert!(ExportFormat::CardChain.bytes(&s, s.get(&root).unwrap()).is_err());
        assert_eq!(file_name("Reader 1/a", "", "pem"), "Reader_1_a.pem");
        assert_eq!(file_name("???", "-key", "pem"), "certificate-key.pem");
        assert_eq!(ExportFormat::from_index(2).extension(), "der");
    }

    #[test]
    fn passphrases() {
        assert_eq!(new_passphrase("a", "a").unwrap(), Some("a".into()));
        assert_eq!(new_passphrase("", "").unwrap(), None);
        assert!(new_passphrase("a", "b").is_err());
    }

    #[test]
    fn card_file_images() {
        let (mut s, root, reader, _) = store_with_chain();
        let r = s.get(&reader).unwrap().clone();
        assert_eq!(card_file_payload(&s, &r, false).unwrap(), r.cert);
        assert!(card_file_payload(&s, &r, true).is_err());
        let sub = s.issue(&root, IssueRequest::new(CertKind::Sub, "Site CA")).unwrap();
        let leaf = s.issue(&sub.id, IssueRequest::new(CertKind::Reader, "Leaf")).unwrap();
        let both = card_file_payload(&s, &leaf, true).unwrap();
        assert_eq!(both.len(), leaf.cert.len() + sub.cert.len());
    }

    #[test]
    fn precheck_accepts_and_rejects_like_the_card() {
        let (s, _, reader, _) = store_with_chain();
        let input = |aid| CheckInput {
            aid,
            df_name: vec![],
            uid: vec![],
            root_acmap: "0-D".into(),
            check_issuer: true,
            order: CsnOrder::MsbFirst,
        };
        let ok = format_check(s.preflight(&reader, &preflight_options(&input(0x123456)).unwrap()), 0x123456).unwrap();
        assert!(ok.starts_with("ACCEPTED for application 123456"), "{ok}");
        let bad = format_check(s.preflight(&reader, &preflight_options(&input(1)).unwrap()), 1).unwrap();
        assert!(bad.starts_with("REJECTED - the card would answer 6A80"), "{bad}");
        assert!(preflight_options(&CheckInput { uid: vec![1, 2, 3], ..input(1) }).is_err());
        assert!(preflight_options(&CheckInput { root_acmap: "x".into(), ..input(1) }).is_err());
    }

    #[test]
    fn precheck_sees_revocation() {
        let (mut s, _, reader, _) = store_with_chain();
        s.set_revoked(&reader, true).unwrap();
        let opts = PreflightOptions { aid: 0x123456, ..Default::default() };
        let text = format_check(s.preflight(&reader, &opts), 0x123456).unwrap();
        assert!(text.starts_with("REJECTED - the card would answer 6982"), "{text}");
    }
}
