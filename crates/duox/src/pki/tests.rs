//! Store behaviour, compatibility with existing store files and interoperability with the `openssl` command
//! line (those tests skip when `openssl` is not installed).

use super::*;
use crate::crypto::{self, CURVE_BP256, CURVE_P256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

const AID: u32 = 0x123456;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!("duox-pki-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn find<'a>(store: &'a PkiStore, name: &str) -> &'a Entry {
    store.entries().iter().find(|e| e.name == name).unwrap()
}

// ------------------------------------------------------- existing store files
const PLAIN: &str = include_str!("testdata/store_plain.json");
const LOCKED: &str = include_str!("testdata/store_locked.json");

fn load_fixture(dir: &TempDir, text: &str) -> PathBuf {
    let p = dir.file("store.json");
    std::fs::write(&p, text).unwrap();
    p
}

#[test]
fn existing_unprotected_store_loads_and_saves_back_identically() {
    let dir = TempDir::new();
    let path = load_fixture(&dir, PLAIN);
    let store = PkiStore::open(&path, None).unwrap();
    assert_eq!(store.entries().len(), 7);
    assert!(!store.is_encrypted() && !store.is_locked());
    assert_eq!(store.to_json().unwrap(), PLAIN);
    store.save().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), PLAIN);
    assert_eq!(store.aes_key("demo").unwrap(), hex::decode("00112233445566778899AABBCCDDEEFF").unwrap());
    assert_eq!(store.aes_key_names(), ["demo"]);
    let root = find(&store, "Root CA");
    assert_eq!(root.kind, CertKind::Root);
    assert_eq!(root.crl, CrlState { version: 3, all_before: 1, serials: vec![3] });
    assert_eq!(root.next_serial, 5);
    assert!(find(&store, "Gate").revoked);
    assert_eq!(find(&store, "BP Root").curve, CURVE_BP256);
}

#[test]
fn existing_store_chains_validate_with_the_card_rules() {
    let dir = TempDir::new();
    let mut store = PkiStore::open(load_fixture(&dir, &PLAIN.replace('\n', "\r\n")), None).unwrap();
    // the fixture revokes everything up to serial 1; keep only the listed Gate certificate revoked
    let root_id = find(&store, "Root CA").id.clone();
    store.set_crl(&root_id, CrlState { version: 3, all_before: 0, serials: vec![3] }).unwrap();
    let door = find(&store, "Door");
    let opts = PreflightOptions { aid: AID, root_acmap: AcMap::new(0x0023), ..Default::default() };
    let r = store.preflight(&door.id, &opts).unwrap();
    assert_eq!(r.acmap, AcMap::new(0x0020));
    assert_eq!(r.certs.len(), 2);
    assert_eq!(store.chain_bytes(&door.id).unwrap().len(), r.certs.iter().map(|c| c.to_der().len()).sum::<usize>());
    // the key stored for the leaf belongs to the certificate
    assert_eq!(store.key_of(&door.id).unwrap().public(), door.public_key().unwrap());
    // Gate is listed in the root's CRL
    let gate = find(&store, "Gate");
    let err = store.preflight(&gate.id, &PreflightOptions::default()).unwrap_err();
    assert!(err.to_string().contains("revoked"), "{err}");
    // brainpool reader without extension
    let bp = find(&store, "BP reader");
    assert_eq!(store.preflight(&bp.id, &PreflightOptions::default()).unwrap().acmap, AcMap::ALL);
    assert_eq!(store.root_of(&bp.id).unwrap().name, "BP Root");
    // root cert is a regular CA certificate
    assert!(store.get(&store.root_of(&door.id).unwrap().id).unwrap().certificate().unwrap().is_self_signed());
}

#[test]
fn existing_protected_store_needs_its_passphrase() {
    let dir = TempDir::new();
    let path = load_fixture(&dir, LOCKED);
    let mut store = PkiStore::open(&path, None).unwrap();
    assert!(store.is_encrypted() && store.is_locked());
    assert_eq!(store.to_json().unwrap(), LOCKED);
    let door = find(&store, "Door").id.clone();
    assert!(matches!(store.key_of(&door), Err(PkiError::StoreLocked(_))));
    assert!(matches!(store.unlock("wrong"), Err(PkiError::StoreLocked(m)) if m == "wrong passphrase"));
    assert!(store.is_locked());
    store.unlock("pass").unwrap();
    assert!(!store.is_locked());
    let key = store.key_of(&door).unwrap();
    assert_eq!(key.public(), store.get(&door).unwrap().public_key().unwrap());
    // opening with the passphrase works as well, and a wrong one is detected on use
    let ok = PkiStore::open(&path, Some("pass")).unwrap();
    assert!(ok.key_of(&door).is_ok());
    let bad = PkiStore::open(&path, Some("nope")).unwrap();
    assert!(matches!(bad.key_of(&door), Err(PkiError::StoreLocked(_))));
    // removing the protection leaves a store without encrypted keys
    store.set_passphrase(None).unwrap();
    let reopened = PkiStore::open(&path, None).unwrap();
    assert!(!reopened.is_encrypted());
    assert_eq!(reopened.key_of(&door).unwrap().to_bytes(), key.to_bytes());
}

// ------------------------------------------------------------- store workflow
#[test]
fn issue_validate_revoke_and_persist() {
    let dir = TempDir::new();
    let path = dir.file("store.json");
    let mut store = PkiStore::open(&path, None).unwrap();
    let root = store.new_root("Root", CURVE_P256, "Acme", 20).unwrap();
    let sub_ar = AccessRights::for_aid(AID, AcMap::new(0x0023)).delegating();
    let sub = store.issue(&root.id, IssueRequest::new(CertKind::Sub, "Site CA").access_rights(sub_ar)).unwrap();
    let r1 = store
        .issue(&sub.id, IssueRequest::new(CertKind::Reader, "R1").access_rights(AccessRights::for_aid(AID, AcMap::new(0x0020))))
        .unwrap();
    let r2 = store.issue(&root.id, IssueRequest::new(CertKind::Reader, "R2")).unwrap();
    assert_eq!(store.get(&root.id).unwrap().next_serial, 4);
    assert_eq!([sub.serial(), r1.serial(), r2.serial()], [Some(1), Some(2), Some(3)]);
    assert_eq!(store.chain_bytes(&root.id).unwrap(), Vec::<u8>::new());
    assert_eq!(store.chain_bytes(&r2.id).unwrap(), r2.cert);
    assert_eq!(store.chain_bytes(&r1.id).unwrap(), [sub.cert.clone(), r1.cert.clone()].concat());

    let opts = PreflightOptions { aid: AID, root_acmap: AcMap::new(0x0023), ..Default::default() };
    assert_eq!(store.preflight(&r1.id, &opts).unwrap().acmap, AcMap::new(0x0020));

    store.set_revoked(&r1.id, true).unwrap();
    assert!(store.preflight(&r1.id, &opts).unwrap_err().to_string().contains("revoked"));
    assert_eq!(store.get(&root.id).unwrap().crl.serials, [2]);
    let image = store.get(&root.id).unwrap().crl.image(Some(64), CsnOrder::MsbFirst).unwrap();
    assert_eq!(crl::parse_image(&image, CsnOrder::MsbFirst), (0, vec![2]));
    store.set_revoked(&r1.id, false).unwrap();
    assert!(store.preflight(&r1.id, &opts).is_ok());
    assert!(store.set_revoked(&root.id, true).is_err());

    // persisted and reloaded
    let again = PkiStore::open(&path, None).unwrap();
    assert_eq!(again.entries(), store.entries());
    assert_eq!(again.label(again.get(&r1.id).unwrap()), format!("R1  [Reader #2 {}]", r1.id));

    // deleting a CA removes what it issued
    store.delete(&sub.id).unwrap();
    assert!(store.get(&r1.id).is_err() && store.get(&sub.id).is_err());
    assert!(store.get(&r2.id).is_ok());
    assert!(matches!(store.delete("nope"), Err(PkiError::NoSuchEntry(_))));
}

#[test]
fn issue_rules_are_enforced() {
    let mut store = PkiStore::new();
    let root = store.new_root("Root", CURVE_P256, "", 5).unwrap();
    let sub = store
        .issue(&root.id, IssueRequest::new(CertKind::Sub, "Sub").access_rights(AccessRights::for_aid(AID, AcMap::new(3)).delegating()))
        .unwrap();
    let err = |r: Result<Entry>| r.unwrap_err().to_string();
    // delegated CA under a delegated CA: the card takes chains of two
    assert!(err(store.issue(&sub.id, IssueRequest::new(CertKind::Sub, "Sub2"))).contains("at most two"));
    // delegation bit required
    let no_bit = IssueRequest::new(CertKind::Sub, "X").access_rights(AccessRights::for_aid(AID, AcMap::new(1)));
    assert!(err(store.issue(&root.id, no_bit)).contains("delegation bit"));
    // rights wider than the issuer's
    let wide = IssueRequest::new(CertKind::Reader, "Wide").access_rights(AccessRights::for_aid(AID, AcMap::new(0x10)));
    assert!(err(store.issue(&sub.id, wide)).contains("exceeds the rights"));
    // wrong curve
    assert!(err(store.issue(&root.id, IssueRequest::new(CertKind::Reader, "BP").curve(CURVE_BP256))).contains("curve"));
    // serials
    assert!(err(store.issue(&root.id, IssueRequest::new(CertKind::Reader, "S").serial(0))).contains("serial"));
    assert!(err(store.issue(&root.id, IssueRequest::new(CertKind::Reader, "S").serial(0x8000_0000))).contains("serial"));
    // readers cannot issue
    let r = store.issue(&root.id, IssueRequest::new(CertKind::Reader, "R")).unwrap();
    assert!(err(store.issue(&r.id, IssueRequest::new(CertKind::Reader, "R2"))).contains("CA entry"));
    // size limit
    let long = "N".repeat(300);
    assert!(err(store.issue(&root.id, IssueRequest::new(CertKind::Reader, &long))).contains("440"));
    // explicit serial moves the counter
    let high = store.issue(&root.id, IssueRequest::new(CertKind::Reader, "High").serial(500)).unwrap();
    assert_eq!(high.serial(), Some(500));
    assert_eq!(store.get(&root.id).unwrap().next_serial, 501);
}

#[test]
fn card_certificates_for_supplied_keys_and_brainpool() {
    let mut store = PkiStore::new();
    let root = store.new_root("BP Root", CURVE_BP256, "", 5).unwrap();
    let card_key = crypto::gen_key(CURVE_BP256).unwrap();
    let card = store
        .issue(&root.id, IssueRequest::new(CertKind::Card, "CARD").public_key(&card_key.public().to_bytes()))
        .unwrap();
    assert!(!card.has_key());
    assert_eq!(card.public_key().unwrap(), card_key.public());
    assert_eq!(card.curve, CURVE_BP256);
    let chain = chain::verify_card_chain(&card.cert, &[TrustAnchor::Certificate(root.certificate().unwrap())]).unwrap();
    assert!(chain.trusted);
    let image = certfile::build_image(&card.cert, Some(512)).unwrap();
    assert_eq!(certfile::parse_image(&image).unwrap(), card.cert.as_slice());
}

#[test]
fn passphrase_protection_lifecycle() {
    let dir = TempDir::new();
    let path = dir.file("s.json");
    let mut store = PkiStore::open(&path, None).unwrap();
    let root = store.new_root("Root", CURVE_P256, "", 5).unwrap();
    let r = store.issue(&root.id, IssueRequest::new(CertKind::Reader, "R")).unwrap();
    let scalar = store.key_of(&r.id).unwrap().to_bytes();
    store.set_passphrase(Some("hunter2")).unwrap();
    assert!(store.is_encrypted());
    assert!(store.get(&root.id).unwrap().key_pem.contains("ENCRYPTED"));
    // keys created while a passphrase is held are protected too
    let r2 = store.issue(&root.id, IssueRequest::new(CertKind::Reader, "R2")).unwrap();
    assert!(store.get(&r2.id).unwrap().key_pem.contains("ENCRYPTED"));
    store.lock();
    assert!(matches!(store.key_of(&r.id), Err(PkiError::StoreLocked(_))));
    assert!(store.issue(&root.id, IssueRequest::new(CertKind::Reader, "R3")).is_err());
    assert!(store.set_passphrase(Some("x")).is_err());
    let mut reopened = PkiStore::open(&path, None).unwrap();
    assert!(reopened.is_locked());
    reopened.unlock("hunter2").unwrap();
    assert_eq!(reopened.key_of(&r.id).unwrap().to_bytes(), scalar);
    reopened.set_passphrase(Some("new")).unwrap();
    let third = PkiStore::open(&path, Some("new")).unwrap();
    assert_eq!(third.key_of(&r.id).unwrap().to_bytes(), scalar);
    assert!(PkiStore::open(&path, Some("hunter2")).unwrap().key_of(&r.id).is_err());
}

#[test]
fn import_export_roundtrip() {
    let mut a = PkiStore::new();
    let root = a.new_root("Root", CURVE_P256, "Acme", 5).unwrap();
    let r = a.issue(&root.id, IssueRequest::new(CertKind::Reader, "Reader")).unwrap();

    let mut b = PkiStore::new();
    let root_pem = a.cert_pem(&root.id).unwrap();
    let imported_root = b.import(root_pem.as_bytes(), &ImportOptions::default()).unwrap();
    assert_eq!(imported_root.len(), 1);
    assert_eq!(imported_root[0].kind, CertKind::Root);
    assert!(imported_root[0].parent.is_none() && !imported_root[0].has_key());
    assert_eq!(imported_root[0].name, "Root");

    // reader with its key: issuer found in the store, kind reader, key kept
    let key_pem = a.export_key_pem(&r.id).unwrap();
    let got = b.import(&r.cert, &ImportOptions { key_pem: Some(&key_pem), ..Default::default() }).unwrap();
    assert_eq!(got[0].kind, CertKind::Reader);
    assert_eq!(got[0].parent.as_deref(), Some(imported_root[0].id.as_str()));
    assert_eq!(b.key_of(&got[0].id).unwrap().to_bytes(), a.key_of(&r.id).unwrap().to_bytes());

    // key that does not match
    let other = keys::private_to_pem(&crypto::gen_key(CURVE_P256).unwrap(), PrivateKeyFormat::Sec1, None).unwrap();
    let err = b.import(&r.cert, &ImportOptions { key_pem: Some(&other), ..Default::default() }).unwrap_err();
    assert!(err.to_string().contains("does not match"));
    assert!(b.import(b"garbage", &ImportOptions::default()).is_err());
    assert_eq!(b.entries().len(), 2);

    // export formats
    let sec1 = a.export_key_pem_as(&r.id, PrivateKeyFormat::Sec1, None).unwrap();
    assert!(sec1.starts_with("-----BEGIN EC PRIVATE KEY-----"));
    let enc = a.export_key_pem_as(&r.id, PrivateKeyFormat::Pkcs8, Some("pw")).unwrap();
    assert_eq!(keys::private_from_pem(&enc, Some("pw")).unwrap().to_bytes(), a.key_of(&r.id).unwrap().to_bytes());
}

#[test]
fn named_aes_keys() {
    let dir = TempDir::new();
    let path = dir.file("s.json");
    let mut s = PkiStore::open(&path, None).unwrap();
    s.set_aes_key("  zeta ", &[1; 16]).unwrap();
    s.set_aes_key("alpha", &[2; 32]).unwrap();
    assert!(s.set_aes_key("bad", &[0; 5]).is_err());
    assert!(s.set_aes_key("  ", &[0; 16]).is_err());
    assert_eq!(s.aes_key_names(), ["alpha", "zeta"]);
    assert_eq!(s.resolve_aes_key("zeta").unwrap(), vec![1; 16]);
    assert_eq!(s.resolve_aes_key("00:11 22-33").unwrap(), vec![0, 0x11, 0x22, 0x33]);
    assert!(s.resolve_aes_key("abc").is_err());
    let again = PkiStore::open(&path, None).unwrap();
    assert_eq!(again.aes_key("alpha").unwrap(), vec![2; 32]);
    assert!(s.remove_aes_key("zeta").unwrap() && !s.remove_aes_key("zeta").unwrap());
    // insertion order is kept in the file
    let json = s.to_json().unwrap();
    assert!(json.contains("\"aes_keys\": {\n  \"alpha\": \"0202"), "{json}");
}

#[test]
fn file_layout_matches_the_established_format() {
    let mut s = PkiStore::new();
    s.set_aes_key("k", &[0xAB; 16]).unwrap();
    assert_eq!(
        s.to_json().unwrap(),
        "{\n \"format\": 1,\n \"entries\": [],\n \"aes_keys\": {\n  \"k\": \"ABABABABABABABABABABABABABABABAB\"\n }\n}"
    );
    let e = s.new_root("Ä root", CURVE_P256, "", 1).unwrap();
    s.set_note(&e.id, "caf\u{e9} \u{1F511}").unwrap();
    let json = s.to_json().unwrap();
    assert!(json.contains("\"name\": \"\\u00c4 root\""), "{json}");
    assert!(json.is_ascii());
    assert_eq!(PkiStore::from_json(&json).unwrap().entries()[0].name, "Ä root");
}

#[test]
fn unreadable_store_is_reported() {
    assert!(matches!(PkiStore::from_json("{not json"), Err(PkiError::Json(_))));
    let dir = TempDir::new();
    let p = dir.file("bad.json");
    std::fs::write(&p, r#"{"entries": [{"id": "1", "kind": "alien", "name": "x", "cert": "00"}]}"#).unwrap();
    assert!(PkiStore::open(&p, None).is_err());
}

// ------------------------------------------------------------------- openssl
fn openssl() -> Option<&'static str> {
    Command::new("openssl").arg("version").output().ok().filter(|o| o.status.success()).map(|_| "openssl")
}

fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new("openssl").args(args).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn openssl_reads_our_certificates() {
    if openssl().is_none() {
        eprintln!("openssl not found, skipping");
        return;
    }
    for (curve, curve_name) in [(CURVE_P256, "prime256v1"), (CURVE_BP256, "brainpoolP256r1")] {
        let dir = TempDir::new();
        let mut store = PkiStore::new();
        let root = store.new_root("Interop Root", curve, "Acme", 10).unwrap();
        let rights = AccessRights::for_aid(AID, AcMap::new(0x0021));
        let reader = store
            .issue(&root.id, IssueRequest::new(CertKind::Reader, "Interop Reader").access_rights(rights).critical(false))
            .unwrap();
        let strict = store
            .issue(
                &root.id,
                IssueRequest::new(CertKind::Reader, "Critical Reader").access_rights(AccessRights::for_aid(AID, AcMap::new(1))),
            )
            .unwrap();
        let (root_der, reader_der) = (dir.file("root.der"), dir.file("reader.der"));
        std::fs::write(&root_der, &root.cert).unwrap();
        std::fs::write(&reader_der, &reader.cert).unwrap();
        std::fs::write(dir.file("root.pem"), store.cert_pem(&root.id).unwrap()).unwrap();
        std::fs::write(dir.file("reader.pem"), store.cert_pem(&reader.id).unwrap()).unwrap();
        std::fs::write(dir.file("strict.pem"), store.cert_pem(&strict.id).unwrap()).unwrap();

        let (ok, text) = run(&["asn1parse", "-inform", "DER", "-in", p(&reader_der)]);
        assert!(ok, "{text}");
        assert!(text.contains("1.3.6.1.4.1.28137.64.1") || text.contains("28137"), "{text}");

        let (ok, text) = run(&["x509", "-inform", "DER", "-in", p(&reader_der), "-noout", "-text"]);
        assert!(ok, "{text}");
        assert!(text.contains("ecdsa-with-SHA256"), "{text}");
        assert!(text.contains("Version: 3 (0x2)"), "{text}");
        assert!(text.contains(curve_name) || text.contains("brainpoolP256r1"), "{text}");
        assert!(text.contains("CN = Interop Reader") || text.contains("CN=Interop Reader"), "{text}");
        assert!(text.contains("1.3.6.1.4.1.28137.64.1"), "{text}");

        // our signature verifies in openssl (non-critical private extension)
        let (ok, text) = run(&["verify", "-CAfile", p(&dir.file("root.pem")), p(&dir.file("reader.pem"))]);
        assert!(ok && text.contains("OK"), "{text}");
        // the critical private extension is something OpenSSL cannot process
        let (ok, text) = run(&["verify", "-CAfile", p(&dir.file("root.pem")), p(&dir.file("strict.pem"))]);
        assert!(!ok && text.to_lowercase().contains("critical"), "{text}");

        let (ok, text) = run(&["x509", "-inform", "DER", "-in", p(&root_der), "-noout", "-text"]);
        assert!(ok && text.contains("CA:TRUE"), "{text}");
    }
}

#[test]
fn openssl_keys_interoperate() {
    if openssl().is_none() {
        eprintln!("openssl not found, skipping");
        return;
    }
    for (curve, name) in [(CURVE_P256, "prime256v1"), (CURVE_BP256, "brainpoolP256r1")] {
        let dir = TempDir::new();
        let (sec1, enc, ours_plain, ours_enc, ours_sec1) = (
            dir.file("sec1.pem"),
            dir.file("enc.pem"),
            dir.file("ours.pem"),
            dir.file("ours_enc.pem"),
            dir.file("ours_sec1.pem"),
        );
        let (ok, t) = run(&["ecparam", "-name", name, "-genkey", "-noout", "-out", p(&sec1)]);
        assert!(ok, "{t}");
        let (ok, openssl_pub) = run(&["pkey", "-in", p(&sec1), "-pubout"]);
        assert!(ok, "{openssl_pub}");

        // their SEC1 file
        let key = keys::private_from_pem(&std::fs::read_to_string(&sec1).unwrap(), None).unwrap();
        assert_eq!(key.curve_id, curve);
        assert_eq!(keys::public_to_pem(&key.public()).unwrap(), openssl_pub.replace("\r\n", "\n"));

        // their PKCS#8, protected with PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC, and with AES-128 + SHA-1 PRF
        for extra in [&["-v2", "aes-256-cbc"][..], &["-v2", "aes-128-cbc", "-v2prf", "hmacWithSHA1"][..]] {
            let mut args = vec!["pkcs8", "-topk8", "-in", p(&sec1), "-out", p(&enc), "-passout", "pass:pw"];
            args.extend_from_slice(extra);
            let (ok, t) = run(&args);
            assert!(ok, "{t}");
            let k = keys::private_from_pem(&std::fs::read_to_string(&enc).unwrap(), Some("pw")).unwrap();
            assert_eq!(k.to_bytes(), key.to_bytes(), "{extra:?}");
        }

        // our files read by them
        std::fs::write(&ours_plain, keys::private_to_pem(&key, PrivateKeyFormat::Pkcs8, None).unwrap()).unwrap();
        std::fs::write(&ours_enc, keys::private_to_pem(&key, PrivateKeyFormat::Pkcs8, Some("s3cret")).unwrap()).unwrap();
        std::fs::write(&ours_sec1, keys::private_to_pem(&key, PrivateKeyFormat::Sec1, None).unwrap()).unwrap();
        for (file, extra) in [(&ours_plain, None), (&ours_enc, Some("pass:s3cret")), (&ours_sec1, None)] {
            let mut args = vec!["pkey", "-in", p(file), "-pubout"];
            if let Some(pw) = extra {
                args.extend(["-passin", pw]);
            }
            let (ok, got) = run(&args);
            assert!(ok, "{got}");
            assert_eq!(got.replace("\r\n", "\n"), openssl_pub.replace("\r\n", "\n"));
        }
        let (ok, t) = run(&["ec", "-in", p(&ours_sec1), "-noout", "-text"]);
        assert!(ok && t.contains(&format!("ASN1 OID: {name}")), "{t}");
    }
}

#[test]
fn openssl_signs_and_we_verify() {
    if openssl().is_none() {
        eprintln!("openssl not found, skipping");
        return;
    }
    let dir = TempDir::new();
    let (key, cert, der) = (dir.file("k.pem"), dir.file("c.pem"), dir.file("c.der"));
    let (ok, t) = run(&["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p(&key)]);
    assert!(ok, "{t}");
    let (ok, t) = run(&["req", "-new", "-x509", "-key", p(&key), "-sha256", "-subj", "/O=Ext/CN=External CA", "-days", "30", "-out", p(&cert)]);
    assert!(ok, "{t}");
    let (ok, t) = run(&["x509", "-in", p(&cert), "-outform", "DER", "-out", p(&der)]);
    assert!(ok, "{t}");
    let parsed = Certificate::from_der(&std::fs::read(&der).unwrap()).unwrap();
    assert!(parsed.is_self_signed());
    assert_eq!(parsed.subject().rfc4514(), "CN=External CA,O=Ext");
    assert_eq!(parsed.version(), 2);
    assert!(!parsed.extensions().is_empty()); // key identifiers, basic constraints
    assert_eq!(Certificate::from_pem(&std::fs::read_to_string(&cert).unwrap()).unwrap(), parsed);
    // such a certificate can anchor a card chain
    let anchor = TrustAnchor::Certificate(parsed);
    let mut store = PkiStore::new();
    let imported = store.import(&std::fs::read(&cert).unwrap(), &ImportOptions::default()).unwrap();
    assert_eq!(imported[0].kind, CertKind::Root);
    let _ = anchor;
}
