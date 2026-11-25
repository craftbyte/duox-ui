//! Section `pki_ecc_auth`: certificates from the library's PKI store, installed on a throwaway application, and
//! every ECC authentication flow against a real card.
//!
//! Per curve (NIST P-256 and brainpoolP256r1) one application holds an ECC key (mutual + card-unilateral
//! authentication), the card certificate file, a data file with distinct read / write / change rights, and
//! CA root keys. The PKI store (`ctx.store`, a temp dir) provides the root CA, a delegated CA, reader
//! certificates with access rights, and the card certificate.
//!
//! * mutual and reader-unilateral authentication with a chain of one certificate, two certificates, and the
//!   CA key directly (no certificate), through ISOGeneralAuthenticate and through ISOSelectFile (by DF name
//!   and by file identifier) + ISOGeneralAuthenticateFinal
//! * card-unilateral ISOInternalAuthenticate with the key usage counter
//! * access conditions after ECC authentication: granted versus CERT_ERROR
//! * CRL file creation, configuration, signed pushes, CRLVersion rules, revocation (a revoked reader is refused
//!   with 6982), CSNAllBefore, read-back (first curve only)
//! * negative cases: bad signature, wrong issuer, wrong key, parent without delegation, three certificates,
//!   wrong application, unknown key / file; an "expired" certificate is accepted because the card keeps no time
//!
//! Section numbers: 7.5.6, 7.5.7, 7.6.4, 7.10, 8.2. The data sheet does not state the byte order of the serial
//! numbers inside the CRL file; the step that revokes a reader finds out which order the card applies.

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use duox::card::types::cmd;
use duox::card::{
    Aid, AccessRights, AppSpec, AuthKind, CaRootKeySpec, CertSigOrder, CommMode, CrlChange, CrlSettings, DataFileSpec,
    EccAuthOptions, EccAuthResult, FileSettingsChange, IsoSelect, KeyPairOp, KeyPairSpec, ModeSel, Status,
};
use duox::crypto::{self, PrivKey, PubKey, CURVE_BP256, CURVE_P256};
use duox::pki::access_rights::{AcMap, AccessRights as CertRights};
use duox::pki::chain::{validate_reader_chain, verify_card_chain, ChainParams, ChainResult, TrustAnchor};
use duox::pki::crl::{build_image, check_revoked, CrlUpdate, CsnOrder};
use duox::pki::{CertError, Certificate, CertKind, CertificateBuilder, IssueRequest, Name, PkiStore, Time};

pub const NAME: &str = "pki_ecc_auth";
pub const DESCRIPTION: &str =
    "PKI store certificates and ECC authentication: mutual / reader-unilateral / card-unilateral, access rights, CRL revocation, negative cases.";

const P_SIGN: u16 = 0x0010;
const P_MUTUAL: u16 = 0x0080;
const P_INTERNAL: u16 = 0x0100;
/// Access conditions the CA root key grants: 0, 1 and 2.
const ROOT_MAP: u16 = 0x0007;

// ------------------------------------------------------------------ certificate fixture
/// A reader identity: its key, the Cert.A bytes (empty for the CA key itself) and what it is meant to be granted.
#[derive(Clone)]
struct Rd {
    name: &'static str,
    key: PrivKey,
    chain: Vec<u8>,
    acmap: u16,
    serial: u32,
}

struct Fixture {
    curve: u8,
    aid: u32,
    root_id: String,
    root_key: PrivKey,
    root_pub: PubKey,
    root_cert: Vec<u8>,
    issuer_der: Vec<u8>,
    /// Access conditions 0 and 1 (certificate with ACMap 3).
    a: Rd,
    /// Access condition 1 only.
    b: Rd,
    /// Access condition 2 only.
    c: Rd,
    /// Certificate without access-rights extension: inherits the CA key's rights.
    e: Rd,
    /// Delegated CA chain (parent + leaf), ACMap 3.
    d: Rd,
    sub_serial: u32,
    /// The CA key itself, no certificate.
    direct: Rd,
    /// Looks like a valid reader of the CA but is signed by an unrelated key.
    bad_sig: Rd,
    /// Certificate valid for another AID.
    wrong_aid: Rd,
    /// Parent certificate without the CA delegation bit.
    no_delegation: Rd,
    /// Three certificates.
    too_long: Rd,
    /// Validity period in the past.
    expired: Rd,
}

fn cert_name(cn: &str) -> Name {
    Name::with_common_name(cn, "")
}

impl Fixture {
    fn build(store: &mut PkiStore, curve: u8, aid: u32, tag: &str) -> duox::pki::Result<Fixture> {
        let rights = |m: u16| CertRights::for_aid(aid, AcMap::new(m));
        let root = store.new_root(&format!("Suite Root {tag}"), curve, "", 10)?;
        let root_key = store.key_of(&root.id)?;
        let root_pub = root_key.public();
        let root_cert = Certificate::from_der(&root.cert)?;
        let issuer_der = root_cert.subject().to_der().to_vec();
        let reader = |store: &mut PkiStore, parent: &str, name: &'static str, ar: Option<CertRights>, acmap: u16| {
            let mut req = IssueRequest::new(CertKind::Reader, name);
            if let Some(ar) = ar {
                req = req.access_rights(ar);
            }
            let e = store.issue(parent, req)?;
            Ok::<Rd, duox::pki::PkiError>(Rd {
                name,
                key: store.key_of(&e.id)?,
                chain: store.chain_bytes(&e.id)?,
                acmap,
                serial: e.serial().unwrap_or(0) as u32,
            })
        };
        // issue order = serial order: A has the lowest serial (used by the CSNAllBefore step)
        let a = reader(store, &root.id, "Suite Reader A", Some(rights(0x3)), 0x3)?;
        let b = reader(store, &root.id, "Suite Reader B", Some(rights(0x2)), 0x2)?;
        let c = reader(store, &root.id, "Suite Reader C", Some(rights(0x4)), 0x4)?;
        let e = reader(store, &root.id, "Suite Reader E", None, ROOT_MAP)?;
        let sub = store.issue(&root.id, IssueRequest::new(CertKind::Sub, "Suite Sub CA").access_rights(rights(ROOT_MAP).delegating()))?;
        let d = reader(store, &sub.id, "Suite Reader D", Some(rights(0x3)), 0x3)?;
        let wrong_aid = reader(store, &root.id, "Suite Reader W", Some(CertRights::for_aid(aid + 1000, AcMap::new(0x3))), 0x3)?;
        let sub_serial = sub.serial().unwrap_or(0) as u32;

        let direct = Rd { name: "CA key", key: root_key.clone(), chain: vec![], acmap: ROOT_MAP, serial: 0 };

        // unrelated signer, but the issuer name of our root
        let evil = crypto::gen_key(curve).map_err(|e| duox::pki::PkiError::Invalid(e.0))?;
        let leaf = crypto::gen_key(curve).map_err(|e| duox::pki::PkiError::Invalid(e.0))?;
        let bad = CertificateBuilder::new(cert_name("Suite Reader X"), root_cert.subject().clone(), leaf.public())
            .serial(777)
            .access_rights(rights(0x3), true)
            .sign(&evil)?;
        let bad_sig = Rd { name: "bad signature", key: leaf, chain: bad.to_der().to_vec(), acmap: 0x3, serial: 777 };

        // parent without delegation: reader A signs a leaf
        let a_cert = Certificate::from_der(&a.chain)?;
        let leaf2 = crypto::gen_key(curve).map_err(|e| duox::pki::PkiError::Invalid(e.0))?;
        let child = CertificateBuilder::new(cert_name("Suite Child"), a_cert.subject().clone(), leaf2.public())
            .serial(778)
            .sign(&a.key)?;
        let no_delegation =
            Rd { name: "parent without delegation", key: leaf2, chain: [a.chain.clone(), child.to_der().to_vec()].concat(), acmap: 0x3, serial: 778 };

        let too_long = Rd { name: "three certificates", key: d.key.clone(), chain: [d.chain.clone(), a.chain.clone()].concat(), acmap: 0x3, serial: 0 };

        // expired a year ago: the card has no notion of time
        let exp_key = crypto::gen_key(curve).map_err(|e| duox::pki::PkiError::Invalid(e.0))?;
        let now = Time::now();
        let exp = CertificateBuilder::new(cert_name("Suite Reader Old"), root_cert.subject().clone(), exp_key.public())
            .serial(779)
            .validity(now.plus_days(-800), now.plus_days(-400))
            .access_rights(rights(0x3), true)
            .sign(&root_key)?;
        let expired = Rd { name: "expired", key: exp_key, chain: exp.to_der().to_vec(), acmap: 0x3, serial: 779 };

        Ok(Fixture {
            curve,
            aid,
            root_id: root.id.clone(),
            root_key,
            root_pub,
            root_cert: root.cert.clone(),
            issuer_der,
            a,
            b,
            c,
            e,
            d,
            sub_serial,
            direct,
            bad_sig,
            wrong_aid,
            no_delegation,
            too_long,
            expired,
        })
    }

    /// The card's validation of `chain` as modelled by the library (7.10.2.2).
    fn local_check(&self, chain: &[u8]) -> Result<ChainResult, CertError> {
        let params = ChainParams { issuer: Some(&self.issuer_der), root_acmap: AcMap::new(ROOT_MAP), aid: self.aid, ..Default::default() };
        validate_reader_chain(chain, &self.root_pub, &params)
    }
}

// ------------------------------------------------------------------ run
pub fn run(ctx: &mut Ctx) {
    for (i, curve) in [CURVE_P256, CURVE_BP256].into_iter().enumerate() {
        curve_run(ctx, curve, i == 0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Via {
    General,
    SelectName,
    SelectFid,
}

struct Env {
    aid: Aid,
    curve: u8,
    df_name: Vec<u8>,
    fid: u16,
    card_pub: PubKey,
    card_cert: Vec<u8>,
}

struct Login<'a> {
    rd: &'a Rd,
    ca_key: u8,
    mutual: bool,
    via: Via,
    cert_file: u8,
    priv_key: u8,
    key_from_cert: bool,
}

impl<'a> Login<'a> {
    fn new(rd: &'a Rd, mutual: bool) -> Self {
        Login { rd, ca_key: 0, mutual, via: Via::General, cert_file: 0, priv_key: 0, key_from_cert: false }
    }
    fn via(mut self, v: Via) -> Self {
        self.via = v;
        self
    }
}

fn leaf_key(b: &[u8]) -> Option<PubKey> {
    duox::pki::leaf_public_key(b).ok()
}

fn login(c: &mut Ctx, env: &Env, l: &Login<'_>) -> duox::Result<EccAuthResult> {
    let epub = match l.via {
        Via::General => {
            c.select_application(env.aid, None)?;
            None
        }
        Via::SelectName => Some(c.select_for_ecc_auth(&IsoSelect::DfName(&env.df_name))?),
        Via::SelectFid => {
            c.select_application(Aid::PICC, None)?;
            Some(c.select_for_ecc_auth(&IsoSelect::FileId(env.fid))?)
        }
    };
    let mut o = EccAuthOptions::new(l.ca_key, env.curve, &l.rd.key).cert_chain(&l.rd.chain).access_map(l.rd.acmap, 0);
    if l.mutual {
        o = o.card_certificate(l.cert_file, l.priv_key);
        o = if l.key_from_cert { o.card_key_from_cert(&leaf_key) } else { o.card_public_key(&env.card_pub) };
    } else {
        o = o.reader_unilateral();
    }
    if let Some(e) = &epub {
        o = o.epub_b(e);
    }
    c.authenticate_ecc(&o)
}

/// Log in, require success and check the session.
fn login_ok(c: &mut Ctx, env: &Env, l: &Login<'_>) -> StepResult<EccAuthResult> {
    let r = login(c, env, l)?;
    let a = c.auth_summary().ok_or("no active session after the authentication")?;
    ensure_eq((a.kind, a.acmap, a.ti), (AuthKind::Ecc, l.rd.acmap, [0; 4]), "session (kind, ACMap, TI)")?;
    ensure_eq(r.mutual, l.mutual, "mutual flag")?;
    if l.mutual {
        ensure_eq(r.card_verified, Some(true), "card signature verified")?;
        ensure(matches!(r.order, CertSigOrder::CertThenSig | CertSigOrder::SigThenCert), format!("layout of Msg.B: {:?}", r.order))?;
        ensure(!r.card_cert.is_empty(), "no card certificate returned")?;
        c.detail(format!("Msg.B layout {:?}, PDCap2 {}", r.order, hex::encode_upper(&r.pd_cap2)));
    } else {
        ensure_eq(r.card_verified, None, "unilateral: no card verification")?;
        ensure(r.card_cert.is_empty() && r.card_sig.is_empty(), "unilateral: the card sent a certificate")?;
    }
    // the session keys are right when the card accepts a MAC protected command
    c.get_ecc_key_settings()?;
    Ok(r)
}

/// The authentication must fail; reports the status word. Leaves no session.
fn login_refused(c: &mut Ctx, env: &Env, l: &Login<'_>) -> StepResult<Option<u16>> {
    match login(c, env, l) {
        Ok(_) => Err(StepError::fail(format!("the card accepted a reader that must be refused ({})", l.rd.name))),
        Err(e) => {
            ensure(!c.is_authenticated(), "a session is active after a failed authentication")?;
            let sw = e.iso_sw();
            ensure(sw.is_some() || e.status().is_some(), format!("expected a card refusal, got: {e}"))?;
            c.detail(format!("{}: refused, {e}", l.rd.name));
            Ok(sw)
        }
    }
}

fn zero_auth(c: &mut Ctx, aid: Aid) -> StepResult {
    let z = c.zero_key;
    c.auth_app(aid, 0, &z)
}

fn cf<T>(r: Result<T, crypto::CryptoError>) -> StepResult<T> {
    r.map_err(|e| StepError::fail(format!("crypto: {}", e.0)))
}

fn der(name: &str, curve: u8) -> String {
    format!("{name} ({})", crypto::curve_name(curve))
}

// ------------------------------------------------------------------ per curve
fn curve_run(ctx: &mut Ctx, curve: u8, full: bool) {
    let aid = ctx.alloc_aid();
    let tag = crypto::curve_name(curve).to_string();
    let fx = ctx.step(&der("PKI store: root CA, delegated CA, reader certificates (rights ACMap 3 / 2 / 4, inherited, via delegated CA), card certificate base", curve), |c| {
        let fx = Fixture::build(&mut c.store, curve, aid.0, &tag)?;
        // the library's model of the card agrees with the intent
        for rd in [&fx.a, &fx.b, &fx.c, &fx.e, &fx.d, &fx.expired] {
            let r = fx.local_check(&rd.chain).map_err(|e| StepError::fail(format!("{}: {e}", rd.name)))?;
            ensure_eq(r.acmap.bits(), rd.acmap, &format!("{} granted map", rd.name))?;
        }
        for rd in [&fx.bad_sig, &fx.wrong_aid, &fx.no_delegation, &fx.too_long] {
            ensure(fx.local_check(&rd.chain).is_err(), format!("local model accepts {}", rd.name))?;
        }
        ensure(fx.b.serial > fx.a.serial && fx.e.serial > fx.a.serial && fx.d.serial > fx.a.serial, "serial order")?;
        c.detail(format!("serials: A {} B {} C {} E {} sub {} D {}", fx.a.serial, fx.b.serial, fx.c.serial, fx.e.serial, fx.sub_serial, fx.d.serial));
        Ok(fx)
    });
    let Some(fx) = fx else { return };
    let root_id = fx.root_id.clone();
    let df_name = format!("DUOXSUITE{:06X}", aid.0).into_bytes();
    let fid = 0xD100 | (aid.0 & 0xFF) as u16;
    let spec = AppSpec::new(aid).keys(2).iso_file_ids().iso_name(fid, &df_name);
    ctx.app_scope(spec, |c, aid| {
        if let Some(env) = provision(c, &fx, aid, fid, &df_name) {
            mutual_matrix(c, &fx, &env);
            card_unilateral(c, &fx, &env);
            access_rights(c, &fx, &env);
            negatives(c, &fx, &env);
            if full {
                crl(c, &fx, &env);
            }
            select_variants(c, &fx, &env);
        }
    });
    ctx.step(&der("PKI store: remove the suite root and everything it issued", curve), |c| {
        c.store.delete(&root_id)?;
        Ok(())
    });
}

fn provision(c: &mut Ctx, fx: &Fixture, aid: Aid, fid: u16, df_name: &[u8]) -> Option<Env> {
    let curve = fx.curve;
    c.step(&der("provision: ECC keys, card certificate file, data file, CA root keys 0 (issuer set) and 1 (other issuer)", curve), |c| {
        zero_auth(c, aid)?;
        // key 0: mutual + card-unilateral; key 1: sign only; key 2: card-unilateral with a usage limit of 1
        let raw = c.manage_key_pair(&KeyPairSpec::new(0, curve, P_MUTUAL | P_INTERNAL, 0x30), &KeyPairOp::Generate, None)?;
        c.manage_key_pair(&KeyPairSpec::new(1, curve, P_SIGN, 0x30), &KeyPairOp::Generate, None)?;
        c.manage_key_pair(&KeyPairSpec::new(2, curve, P_INTERNAL, 0x30).kuc_limit(1), &KeyPairOp::Generate, None)?;
        let card_pub = cf(PubKey::from_bytes(curve, &raw))?;
        // card certificate from the store, signed by the suite root
        let entry = c.store.issue(&fx.root_id, IssueRequest::new(CertKind::Card, "Suite Card").public_key(&raw).curve(curve))?;
        let card_cert = entry.cert.clone();
        let trust = verify_card_chain(&card_cert, &[TrustAnchor::Certificate(Certificate::from_der(&fx.root_cert)?)])?;
        ensure(trust.trusted && trust.public_key == card_pub, "store card certificate does not chain to the suite root / carries another key")?;

        let mut nos = c.file_nos();
        let cert_no = nos.next();
        let data_no = nos.next();
        ensure_eq((cert_no, data_no), (0, 1), "file numbers")?;
        let free_read = AccessRights::new(duox::card::AccessRight::FREE, duox::card::AccessRight::key(0), duox::card::AccessRight::key(0), duox::card::AccessRight::key(0));
        c.create_data_file(&DataFileSpec::new(cert_no, 512, free_read).comm_mode(CommMode::Plain).iso_fid(0xE100))?;
        c.write_cert_file(cert_no, &card_cert)?;
        ensure_eq(c.read_cert_file(cert_no)?, card_cert.clone(), "certificate file read-back")?;
        // read: AC 1, write: AC 2, no read/write, change: AC 0 (Full)
        let k = duox::card::AccessRight::key;
        let ar = AccessRights::new(k(1), k(2), duox::card::AccessRight::NEVER, k(0));
        c.create_data_file(&DataFileSpec::new(data_no, 32, ar).comm_mode(CommMode::Full).iso_fid(0xE101))?;

        for (slot, issuer) in [(0u8, fx.issuer_der.clone()), (1u8, cert_name("Some Other CA").to_der().to_vec())] {
            let mut s = CaRootKeySpec::new(slot, curve, fx.root_pub.to_bytes());
            s.access_rights = ROOT_MAP;
            s.write_access = 0x30;
            s.read_access = 0x30;
            s.issuer = issuer;
            c.manage_ca_root_key(&s, None)?;
        }
        let list = c.get_ca_root_key_settings()?;
        ensure_eq(list.iter().map(|e| (e.key_no, e.access_rights)).collect::<Vec<_>>(), vec![(0, ROOT_MAP), (1, ROOT_MAP)], "CA root key entries")?;
        c.detail(format!("card certificate {} bytes, serial {}", card_cert.len(), entry.serial().unwrap_or(0)));
        Ok(Env { aid, curve, df_name: df_name.to_vec(), fid, card_pub, card_cert })
    })
}

// ------------------------------------------------------------------ authentication matrix
fn mutual_matrix(c: &mut Ctx, fx: &Fixture, env: &Env) {
    let curve = env.curve;
    let who: [(&str, &Rd); 3] = [("chain of one certificate", &fx.a), ("chain of two certificates (delegated CA)", &fx.d), ("CA key directly, no certificate", &fx.direct)];
    for (what, rd) in who {
        c.step(&der(&format!("mutual authentication, {what}, ISOGeneralAuthenticate"), curve), |c| {
            let r = login_ok(c, env, &Login::new(rd, true))?;
            let tr = verify_card_chain(&r.card_cert, &[TrustAnchor::Certificate(Certificate::from_der(&fx.root_cert)?)])?;
            ensure(tr.trusted && tr.public_key == env.card_pub, "the card certificate the card sent does not chain to the suite root")?;
            ensure_eq(r.card_cert.clone(), env.card_cert.clone(), "card certificate bytes")
        });
        c.step(&der(&format!("reader-unilateral authentication, {what}, ISOGeneralAuthenticate"), curve), |c| {
            login_ok(c, env, &Login::new(rd, false))?;
            Ok(())
        });
    }
    c.step(&der("mutual authentication: card key taken from the returned Cert.B", curve), |c| {
        let mut l = Login::new(&fx.a, true);
        l.key_from_cert = true;
        login_ok(c, env, &l)?;
        Ok(())
    });
    c.step(&der("certificate without access-rights extension inherits the CA key's rights (ACMap 7)", curve), |c| {
        login_ok(c, env, &Login::new(&fx.e, true))?;
        Ok(())
    });
    c.step(&der("two sessions in a row: a new authentication replaces the old one", curve), |c| {
        login_ok(c, env, &Login::new(&fx.a, true))?;
        login_ok(c, env, &Login::new(&fx.e, false))?;
        let a = c.auth_summary().ok_or("no session")?;
        ensure_eq(a.acmap, ROOT_MAP, "ACMap of the second session")
    });
}

fn card_unilateral(c: &mut Ctx, fx: &Fixture, env: &Env) {
    let curve = env.curve;
    let _ = fx;
    c.step(&der("card-unilateral ISOInternalAuthenticate (key 0): signature verifies, message layout, no usage counting without a limit", curve), |c| {
        c.select_application(env.aid, None)?;
        let r = c.internal_authenticate(0, Some(&env.card_pub), None)?;
        ensure_eq(r.valid, Some(true), "signature check")?;
        ensure_eq((r.rnd_a.len(), r.rnd_b.len(), r.signature.len()), (16, 16, 64), "RndA / RndB / signature lengths")?;
        ensure_eq(&r.message[..2], &[0xF0u8, 0xF0][..], "message prefix")?;
        let r2 = c.internal_authenticate(0, Some(&env.card_pub), None)?;
        ensure(r2.rnd_b != r.rnd_b, "the card repeated its challenge")?;
        zero_auth(c, env.aid)?;
        let e = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
        ensure_eq((e.kuc_limit, e.kuc), (0, 0), "usage limit / counter of key 0")
    });
    c.step(&der("card-unilateral authentication with a wrong public key does not verify", curve), |c| {
        let other = cf(crypto::gen_key(curve))?.public();
        c.select_application(env.aid, None)?;
        let r = c.internal_authenticate(0, Some(&other), None)?;
        ensure_eq(r.valid, Some(false), "signature check against another key")
    });
    c.step(&der("ISOInternalAuthenticate counts key usage: limit 1 allows one run, the second is refused", curve), |c| {
        c.select_application(env.aid, None)?;
        let r = c.internal_authenticate(2, None, None)?;
        ensure_eq(r.signature.len(), 64, "signature length")?;
        zero_auth(c, env.aid)?;
        let e = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 2).ok_or("key 2 missing")?;
        ensure_eq((e.kuc_limit, e.kuc), (1, 1), "usage limit / counter of key 2")?;
        c.select_application(env.aid, None)?;
        let e = c.internal_authenticate(2, None, None).err().ok_or("second run accepted")?;
        ensure(e.iso_sw().is_some(), format!("expected an ISO status word, got {e}"))?;
        c.detail(format!("second run: {e}"));
        Ok(())
    });
    c.step(&der("ISOInternalAuthenticate with a key whose policy lacks it (key 1, sign only) is refused", curve), |c| {
        c.select_application(env.aid, None)?;
        let e = c.internal_authenticate(1, None, None).err().ok_or("accepted")?;
        ensure(e.iso_sw().is_some(), format!("expected an ISO status word, got {e}"))?;
        c.detail(format!("{e}"));
        Ok(())
    });
}

// ------------------------------------------------------------------ rights after ECC authentication
fn access_rights(c: &mut Ctx, fx: &Fixture, env: &Env) {
    let curve = env.curve;
    const DATA: [u8; 32] = *b"ECC rights test data 0123456789!";
    c.step(&der("reader C (ACMap 4, AC 2) may write the data file (write AC 2) but not read it (CERT_ERROR)", curve), |c| {
        login_ok(c, env, &Login::new(&fx.c, true))?;
        c.write_data_with(1, 0, &DATA, ModeSel::Explicit(CommMode::Full))?;
        login_ok(c, env, &Login::new(&fx.c, true))?;
        let r = c.read_data_with(1, 0, 32, ModeSel::Explicit(CommMode::Full));
        c.expect_err(Status::CertError, r)
    });
    c.step(&der("reader A (ACMap 3) reads what C wrote (read AC 1) but cannot write (CERT_ERROR)", curve), |c| {
        login_ok(c, env, &Login::new(&fx.a, true))?;
        ensure_eq(c.read_data_with(1, 0, 32, ModeSel::Explicit(CommMode::Full))?, DATA.to_vec(), "data read by reader A")?;
        login_ok(c, env, &Login::new(&fx.a, true))?;
        let r = c.write_data_with(1, 0, &[0u8; 16], ModeSel::Explicit(CommMode::Full));
        c.expect_err(Status::CertError, r)
    });
    c.step(&der("reader-unilateral reader A reads the file as well", curve), |c| {
        login_ok(c, env, &Login::new(&fx.a, false))?;
        ensure_eq(c.read_data_with(1, 0, 32, ModeSel::Explicit(CommMode::Full))?, DATA.to_vec(), "data read")
    });
    c.step(&der("reader B (ACMap 2, AC 1 only) cannot change file settings or create keys (CERT_ERROR)", curve), |c| {
        login_ok(c, env, &Login::new(&fx.b, true))?;
        let fs = c.get_file_settings(1)?;
        let ch = FileSettingsChange::new(fs.option & 0x03, fs.access);
        let r = c.change_file_settings(1, &ch);
        c.expect_err(Status::CertError, r)?;
        login_ok(c, env, &Login::new(&fx.b, true))?;
        let r = c.manage_key_pair(&KeyPairSpec::new(3, env.curve, P_SIGN, 0x30), &KeyPairOp::Generate, Some(CommMode::Full));
        c.expect_err(Status::CertError, r)
    });
    c.step(&der("reader A (ACMap 3, AC 0 = master) changes file settings and creates a key", curve), |c| {
        login_ok(c, env, &Login::new(&fx.a, true))?;
        let fs = c.get_file_settings(1)?;
        c.change_file_settings(1, &FileSettingsChange::new(fs.option & 0x03, fs.access))?;
        ensure_eq(c.get_file_settings(1)?.access, fs.access, "file access rights after ChangeFileSettings")?;
        let raw = c.manage_key_pair(&KeyPairSpec::new(3, env.curve, P_SIGN, 0x30), &KeyPairOp::Generate, Some(CommMode::Full))?;
        ensure_eq(raw.len(), 65, "generated public key")
    });
    c.step(&der("CA key directly (ACMap 7) reads and writes the data file", curve), |c| {
        login_ok(c, env, &Login::new(&fx.direct, true))?;
        c.write_data_with(1, 0, &DATA, ModeSel::Explicit(CommMode::Full))?;
        login_ok(c, env, &Login::new(&fx.direct, true))?;
        ensure_eq(c.read_data_with(1, 0, 32, ModeSel::Explicit(CommMode::Full))?, DATA.to_vec(), "data")
    });
}

// ------------------------------------------------------------------ negative authentication
fn negatives(c: &mut Ctx, fx: &Fixture, env: &Env) {
    let curve = env.curve;
    c.step(&der("bad signature: a certificate signed by an unrelated key is refused", curve), |c| {
        login_refused(c, env, &Login::new(&fx.bad_sig, true)).map(|_| ())
    });
    c.step(&der("bad Sig.A: valid certificate, but the message is signed with another reader's key", curve), |c| {
        let forged = Rd { key: fx.b.key.clone(), ..fx.a.clone() };
        login_refused(c, env, &Login::new(&forged, false)).map(|_| ())
    });
    c.step(&der("wrong issuer: CA root key 1 trusts another issuer name", curve), |c| {
        let mut l = Login::new(&fx.a, true);
        l.ca_key = 1;
        login_refused(c, env, &l).map(|_| ())
    });
    c.step(&der("CA root key number 3 does not exist", curve), |c| {
        let mut l = Login::new(&fx.a, false);
        l.ca_key = 3;
        login_refused(c, env, &l).map(|_| ())
    });
    c.step(&der("parent certificate without the CA delegation bit", curve), |c| {
        login_refused(c, env, &Login::new(&fx.no_delegation, false)).map(|_| ())
    });
    c.step(&der("chain of three certificates", curve), |c| {
        login_refused(c, env, &Login::new(&fx.too_long, false)).map(|_| ())
    });
    c.step(&der("certificate whose access rights name another application", curve), |c| {
        login_refused(c, env, &Login::new(&fx.wrong_aid, false)).map(|_| ())
    });
    c.step(&der("mutual authentication with a key whose policy lacks mutual authentication (key 1)", curve), |c| {
        let mut l = Login::new(&fx.a, true);
        l.priv_key = 1;
        login_refused(c, env, &l).map(|_| ())
    });
    c.step(&der("mutual authentication with a certificate file that does not exist (5)", curve), |c| {
        let mut l = Login::new(&fx.a, true);
        l.cert_file = 5;
        login_refused(c, env, &l).map(|_| ())
    });
    c.step(&der("mutual authentication with a private key number that does not exist (4)", curve), |c| {
        let mut l = Login::new(&fx.a, true);
        l.priv_key = 4;
        login_refused(c, env, &l).map(|_| ())
    });
    c.step(&der("an expired certificate is accepted: the card keeps no time (validity is not checked)", curve), |c| {
        login_ok(c, env, &Login::new(&fx.expired, false))?;
        Ok(())
    });
    c.step(&der("ISO commands are refused while an ECC session is active (6982)", curve), |c| {
        login_ok(c, env, &Login::new(&fx.a, false))?;
        let e = c.iso_get_challenge(8).err().ok_or("accepted")?;
        ensure_eq(e.iso_sw(), Some(0x6982), "status word")
    });
}

// ------------------------------------------------------------------ ISOSelectFile initiated authentication
fn select_variants(c: &mut Ctx, fx: &Fixture, env: &Env) {
    let curve = env.curve;
    c.step(&der("without the SMConfig bit the FCI of ISOSelectFile carries no ephemeral key", curve), |c| {
        c.select_application(Aid::PICC, None)?;
        let (fci, sw) = c.iso_select(&IsoSelect::DfName(&env.df_name))?;
        ensure_eq(sw, 0x9000, "status word")?;
        ensure(crate::ctx::SuiteCard::fci_ephemeral_key(&fci).is_none(), "an ephemeral key is offered")
    });
    let on = c.step(&der("SetConfiguration 0x04: enable ISOSelectFile integrated ECC authentication (bit 3) for this curve", curve), |c| {
        zero_auth(c, env.aid)?;
        c.set_configuration(0x04, &[0x00, 0x08, env.curve])
    });
    if on.is_none() {
        return;
    }
    c.step(&der("ISOSelectFile by DF name returns E.Pub.B (6F 43 85 41 + 65 bytes), a new one each time", curve), |c| {
        c.select_application(Aid::PICC, None)?;
        let (fci, sw) = c.iso_select(&IsoSelect::DfName(&env.df_name))?;
        ensure_eq(sw, 0x9000, "status word")?;
        ensure_eq(&fci[..4], &[0x6Fu8, 0x43, 0x85, 0x41][..], "FCI header")?;
        ensure_eq(fci.len(), 69, "FCI length")?;
        // The first select opens a multi-pass exchange: a second ISOSelectFile is answered with 6985
        // until another command ends it, so end it with a native SelectApplication.
        let r = c.iso_select(&IsoSelect::DfName(&env.df_name));
        ensure_eq(r.as_ref().err().and_then(|e| e.iso_sw()), Some(0x6985), "second ISOSelectFile while the exchange is pending")?;
        // a native command ends the pending exchange; the first one is answered with COMMAND_ABORTED
        let _ = c.select_application(Aid::PICC, None);
        let (fci2, _) = c.iso_select(&IsoSelect::DfName(&env.df_name))?;
        ensure(fci != fci2, "the ephemeral key repeated")?;
        let _ = c.select_application(Aid::PICC, None); // leave no multi-pass exchange pending
        Ok(())
    });
    for (what, rd, mutual) in [("mutual, one certificate", &fx.a, true), ("reader-unilateral, one certificate", &fx.a, false), ("mutual, delegated CA chain", &fx.d, true), ("mutual, CA key directly", &fx.direct, true)] {
        for via in [Via::SelectName, Via::SelectFid] {
            c.step(&der(&format!("ISOSelectFile ({via:?}) + ISOGeneralAuthenticateFinal: {what}"), curve), |c| {
                login_ok(c, env, &Login::new(rd, mutual).via(via))?;
                // data access works in the session (ISO selected: only reads here)
                ensure_eq(c.read_cert_file(0)?, env.card_cert.clone(), "certificate file read in the session")
            });
        }
    }
    c.step(&der("ISOSelectFile initiated authentication with a wrong CA key number is refused", curve), |c| {
        let mut l = Login::new(&fx.a, false).via(Via::SelectName);
        l.ca_key = 3;
        login_refused(c, env, &l).map(|_| ())
    });
    c.step(&der("ISOSelectFile initiated authentication with a bad signature is refused", curve), |c| {
        login_refused(c, env, &Login::new(&fx.bad_sig, false).via(Via::SelectName)).map(|_| ())
    });
    c.step(&der("ISOGeneralAuthenticate (two exchange variant) still works with the bit enabled", curve), |c| {
        login_ok(c, env, &Login::new(&fx.a, true))?;
        Ok(())
    });
}

// ------------------------------------------------------------------ CRL
const CRL_FILE: u8 = 2;
const CRL_FID: u16 = 0xE102;

/// Write a CRL image to the card with the AES master key. `signer` signs the whole native WriteData.
fn crl_push(c: &mut Ctx, env: &Env, version: u16, all_before: u32, serials: &[u32], order: CsnOrder, signer: Option<&PrivKey>) -> duox::Result<Vec<u8>> {
    let data = build_image(all_before, serials, None, order).map_err(|e| duox::Error::InvalidArgument(e.to_string()))?;
    let sig = match signer {
        Some(k) => CrlUpdate { cmd: cmd::WRITE_DATA_CRL, file_no: CRL_FILE, version, offset: 0, data: &data }
            .sign(k)
            .map_err(|e| duox::Error::InvalidArgument(e.to_string()))?,
        None => vec![],
    };
    let z = c.zero_key;
    c.select_application(env.aid, None)?;
    c.authenticate_ev2_first(0, &z, &[])?;
    let fs = c.get_file_settings(CRL_FILE)?;
    c.write_crl(CRL_FILE, version, 0, &data, &sig, ModeSel::File(&fs))?;
    Ok(data)
}

fn crl_readback(c: &mut Ctx, env: &Env, version: u16, data: &[u8]) -> StepResult {
    zero_auth(c, env.aid)?;
    ensure_eq(c.read_crl_version(CRL_FILE, ModeSel::Explicit(CommMode::Plain))? as u16, version, "CRLVersion")?;
    ensure_eq(c.read_data_with(CRL_FILE, 0, data.len() as u32, ModeSel::Explicit(CommMode::Plain))?, data.to_vec(), "CRL file content")
}

fn crl(c: &mut Ctx, fx: &Fixture, env: &Env) {
    let curve = env.curve;
    let ok = c.step(&der("CRL: create the CRL file (CRL flag) and link CA root key 0 to it", curve), |c| {
        zero_auth(c, env.aid)?;
        let k = duox::card::AccessRight::key;
        let ar = AccessRights::new(duox::card::AccessRight::FREE, k(0), k(0), k(0));
        c.create_data_file(&DataFileSpec::new(CRL_FILE, 64, ar).comm_mode(CommMode::Plain).crl().iso_fid(CRL_FID))?;
        let mut s = CaRootKeySpec::new(0, env.curve, fx.root_pub.to_bytes());
        s.access_rights = ROOT_MAP;
        s.write_access = 0x30;
        s.read_access = 0x30;
        s.issuer = fx.issuer_der.clone();
        s.crl_file = 0x80 | CRL_FILE;
        s.crl_aid = env.aid;
        c.manage_ca_root_key(&s, None)?;
        let e = c.get_ca_root_key_settings()?.into_iter().find(|e| e.key_no == 0).ok_or("slot 0 missing")?;
        ensure_eq((e.crl_file, e.crl_aid), (0x80 | CRL_FILE, env.aid), "CRL link")?;
        let fs = c.get_file_settings(CRL_FILE)?;
        c.detail(format!("CRL settings of the new file: {:?}", fs.crl));
        Ok(())
    });
    if ok.is_none() {
        return;
    }
    c.step(&der("CRL: CRLVersion of a new file is 0; an unsigned first update (version 1, empty list) is accepted and read back", curve), |c| {
        zero_auth(c, env.aid)?;
        ensure_eq(c.read_crl_version(CRL_FILE, ModeSel::Explicit(CommMode::Plain))?, 0, "initial CRLVersion")?;
        let data = crl_push(c, env, 1, 0, &[], CsnOrder::MsbFirst, None)?;
        crl_readback(c, env, 1, &data)
    });
    c.step(&der("CRL: ChangeFileSettings requires signature and exact +1 versions (CRLOptions 3, CSNSize 4, sig key 0)", curve), |c| {
        zero_auth(c, env.aid)?;
        let fs = c.get_file_settings(CRL_FILE)?;
        let mut ch = FileSettingsChange::new(fs.option & 0x03, fs.access);
        ch.crl = Some(CrlChange { options: 3, csn_size: 4, sig_key: Some(0) });
        c.change_file_settings(CRL_FILE, &ch)?;
        ensure_eq(c.get_file_settings(CRL_FILE)?.crl, Some(CrlSettings { options: 3, csn_size: 4, sig_key: Some(0) }), "CRL settings")
    });
    c.step(&der("CRL: unsigned, wrongly signed, stale and skipping updates are refused; the version stays 1", curve), |c| {
        let r = crl_push(c, env, 2, 0, &[], CsnOrder::MsbFirst, None);
        let st = c.expect_any_status(r)?;
        c.detail(format!("unsigned update: {st}"));
        let other = cf(crypto::gen_key(env.curve))?;
        let r = crl_push(c, env, 2, 0, &[], CsnOrder::MsbFirst, Some(&other));
        let st = c.expect_any_status(r)?;
        c.detail(format!("wrong signature: {st}"));
        let r = crl_push(c, env, 1, 0, &[], CsnOrder::MsbFirst, Some(&fx.root_key));
        let st = c.expect_any_status(r)?;
        c.detail(format!("same version: {st}"));
        let r = crl_push(c, env, 3, 0, &[], CsnOrder::MsbFirst, Some(&fx.root_key));
        let st = c.expect_any_status(r)?;
        c.detail(format!("version skipped: {st}"));
        zero_auth(c, env.aid)?;
        ensure_eq(c.read_crl_version(CRL_FILE, ModeSel::Explicit(CommMode::Plain))?, 1, "CRLVersion after the refused updates")
    });
    c.step(&der("CRL: signed update to version 2 (empty list); readers still authenticate", curve), |c| {
        let data = crl_push(c, env, 2, 0, &[], CsnOrder::MsbFirst, Some(&fx.root_key))?;
        crl_readback(c, env, 2, &data)?;
        login_ok(c, env, &Login::new(&fx.a, true))?;
        login_ok(c, env, &Login::new(&fx.b, false))?;
        Ok(())
    });
    // Revoking reader A: the byte order of the serials inside the file is found out here.
    let rev = c.step(&der("CRL: revoking reader A refuses its authentication with 6982 (also finds the CSN byte order)", curve), |c| {
        let data = crl_push(c, env, 3, 0, &[fx.a.serial], CsnOrder::MsbFirst, Some(&fx.root_key))?;
        crl_readback(c, env, 3, &data)?;
        match login(c, env, &Login::new(&fx.a, false)) {
            Err(e) => {
                ensure(!c.is_authenticated(), "a session is active after a failed authentication")?;
                ensure_eq(e.iso_sw(), Some(0x6982), "status word of the refusal")?;
                c.detail("serials are stored most significant byte first");
                Ok((CsnOrder::MsbFirst, 3u16))
            }
            Ok(_) => {
                // not revoked: the card reads the serials the other way round
                let data = crl_push(c, env, 4, 0, &[fx.a.serial], CsnOrder::LsbFirst, Some(&fx.root_key))?;
                crl_readback(c, env, 4, &data)?;
                let sw = login_refused(c, env, &Login::new(&fx.a, false))?;
                ensure_eq(sw, Some(0x6982), "status word of the refusal (least significant byte first image)")?;
                c.detail("serials are stored least significant byte first (a most significant first image did not revoke)");
                Ok((CsnOrder::LsbFirst, 4u16))
            }
        }
    });
    let Some((order, version)) = rev else { return };
    let mut version = version;
    c.step(&der("CRL: other readers are not affected by revoking A; the CA key itself needs no certificate", curve), |c| {
        login_ok(c, env, &Login::new(&fx.b, true))?;
        login_ok(c, env, &Login::new(&fx.d, false))?;
        login_ok(c, env, &Login::new(&fx.direct, true))?;
        Ok(())
    });
    c.step(&der("CRL: a later version replaces the list: A is admitted again, the delegated CA is revoked (chain D refused)", curve), |c| {
        version += 1;
        let data = crl_push(c, env, version, 0, &[fx.sub_serial], order, Some(&fx.root_key))?;
        crl_readback(c, env, version, &data)?;
        login_ok(c, env, &Login::new(&fx.a, true))?;
        let sw = login_refused(c, env, &Login::new(&fx.d, false))?;
        ensure_eq(sw, Some(0x6982), "status word of the refusal")
    });
    c.step(&der("CRL: CSNAllBefore = serial of A refuses A only (lower or equal serials), later certificates pass", curve), |c| {
        version += 1;
        let data = crl_push(c, env, version, fx.a.serial, &[], order, Some(&fx.root_key))?;
        crl_readback(c, env, version, &data)?;
        let sw = login_refused(c, env, &Login::new(&fx.a, true))?;
        ensure_eq(sw, Some(0x6982), "status word of the refusal")?;
        login_ok(c, env, &Login::new(&fx.b, true))?;
        login_ok(c, env, &Login::new(&fx.d, true))?;
        Ok(())
    });
    c.step(&der("CRL: an empty list again (version +1) admits everybody; the library's revocation check agrees with the file", curve), |c| {
        version += 1;
        let data = crl_push(c, env, version, 0, &[], order, Some(&fx.root_key))?;
        crl_readback(c, env, version, &data)?;
        ensure(check_revoked(&data, u64::from(fx.a.serial), 4, order).is_none(), "library model revokes with an empty list")?;
        login_ok(c, env, &Login::new(&fx.a, true))?;
        Ok(())
    });
    c.step(&der("CRL: ISOUpdateBinary on a CRL file is not supported", curve), |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(&env.df_name))?;
        c.iso_select(&IsoSelect::EfUnderCurrent(CRL_FID))?;
        let e = c.iso_update_binary(&[0, 0, 0, 0], 0, None).err().ok_or("ISOUpdateBinary on a CRL file succeeded")?;
        ensure(e.iso_sw().is_some(), format!("expected an ISO status word, got {e}"))?;
        c.detail(format!("{e}"));
        Ok(())
    });
}

// ------------------------------------------------------------------ offline tests
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(curve: u8) -> Fixture {
        let mut store = PkiStore::new();
        Fixture::build(&mut store, curve, 0xD00007, "test").unwrap()
    }

    #[test]
    fn fixture_models_the_card_on_both_curves() {
        for curve in [CURVE_P256, CURVE_BP256] {
            let fx = fixture(curve);
            for rd in [&fx.a, &fx.b, &fx.c, &fx.e, &fx.d, &fx.expired] {
                let r = fx.local_check(&rd.chain).unwrap_or_else(|e| panic!("{}: {e}", rd.name));
                assert_eq!(r.acmap.bits(), rd.acmap, "{}", rd.name);
                assert_eq!(r.leaf_pub, rd.key.public(), "{}", rd.name);
            }
            for rd in [&fx.bad_sig, &fx.wrong_aid, &fx.no_delegation, &fx.too_long] {
                assert!(fx.local_check(&rd.chain).is_err(), "{} must be refused", rd.name);
            }
            assert!(fx.local_check(&[]).is_err());
            assert!(fx.a.serial < fx.b.serial && fx.a.serial < fx.d.serial);
            assert!(fx.d.chain.len() > fx.a.chain.len());
            assert!(fx.direct.chain.is_empty());
            assert_eq!(fx.direct.key.public(), fx.root_pub);
        }
    }

    #[test]
    fn revocation_model_matches_the_planned_files() {
        let fx = fixture(CURVE_P256);
        for order in [CsnOrder::MsbFirst, CsnOrder::LsbFirst] {
            let img = build_image(0, &[fx.a.serial], None, order).unwrap();
            assert!(check_revoked(&img, u64::from(fx.a.serial), 4, order).is_some());
            assert!(check_revoked(&img, u64::from(fx.b.serial), 4, order).is_none());
            let img = build_image(fx.a.serial, &[], None, order).unwrap();
            assert!(check_revoked(&img, u64::from(fx.a.serial), 4, order).is_some());
            assert!(check_revoked(&img, u64::from(fx.b.serial), 4, order).is_none());
        }
        // an image written in the wrong order is not a revocation (the order probe relies on it)
        let msb = build_image(0, &[fx.a.serial], None, CsnOrder::MsbFirst).unwrap();
        assert!(check_revoked(&msb, u64::from(fx.a.serial), 4, CsnOrder::LsbFirst).is_none());
        // the 64 byte CRL file holds the largest list the steps write
        assert!(build_image(0, &[fx.sub_serial; 4], Some(64), CsnOrder::MsbFirst).is_ok());
    }

    #[test]
    fn crl_signature_message_covers_the_native_write() {
        let fx = fixture(CURVE_P256);
        let data = build_image(0, &[5], None, CsnOrder::MsbFirst).unwrap();
        let u = CrlUpdate { cmd: cmd::WRITE_DATA_CRL, file_no: CRL_FILE, version: 3, offset: 0, data: &data };
        let m = u.message();
        assert_eq!(&m[..4], &[0x8D, CRL_FILE, 3, 0]);
        let sig = u.sign(&fx.root_key).unwrap();
        assert!(fx.root_pub.verify_raw(&sig, &m));
    }

    #[test]
    fn store_is_cleaned_up() {
        let mut store = PkiStore::new();
        let fx = Fixture::build(&mut store, CURVE_P256, 0xD00001, "x").unwrap();
        assert!(!store.entries().is_empty());
        store.delete(&fx.root_id).unwrap();
        assert!(store.entries().is_empty());
    }
}
