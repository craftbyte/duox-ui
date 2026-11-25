//! Section `picc`: PICC level coverage.
//!
//! Read-only: GetVersion, GetCardUID, FreeMem, GetKeySettings (PICC, ECC, CA root), GetKeyVersion,
//! GetConfiguration (every readable option, decoded), directory lists on the empty card, the
//! originality check, authentication behaviour, raw escape hatches, negative tests.
//!
//! Modifying (each with proof of the restore value, read-back and a registered restore action):
//! PICCAppDefaultKey (0x01), VCIID (0x06), PICCKeySettings bits 1 and 2, the PICC master key via
//! ChangeKey and ChangeKeyEV2, PICCDAMAuthKey 0x10, and Format with an application present.
//!
//! Never done here (see `guard.rs`): PICCConfig, ATS / SAK / ATQA, protocol options, I2C, capability
//! data, GPIO, ManageKeyPair, ManageCARootKey, NXPDAM keys.

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use crate::keychange::KeyChange;
use crate::snapshot::{decode_config, option_name, CONFIG_OPTIONS, KEY_VERSION_KEYS};
use duox::card::types::cmd;
use duox::card::{Aid, AppSpec, AuthKind, CaRootKeySpec, ChangeKeySpec, KeyPairOp, KeyPairSpec, Status, VersionInfo};

pub const NAME: &str = "picc";
pub const DESCRIPTION: &str =
    "PICC level: version, UID, memory, key settings, configuration options, authentication, key changes with restore, raw escapes, originality, Format.";

pub fn run(ctx: &mut Ctx) {
    identification(ctx);
    read_only_info(ctx);
    configuration_reads(ctx);
    empty_card_lists(ctx);
    guard_refusals(ctx);
    negative_tests(ctx);
    authentication(ctx);
    raw_escapes(ctx);
    originality(ctx);
    app_default_key(ctx);
    vciid(ctx);
    key_settings_toggle(ctx);
    master_key(ctx);
    picc_dam_key(ctx);
    aes256(ctx);
    format_with_application(ctx);
}

/// Turn "the card refused" into a skip (the thing is not available on this card / at this level).
fn soft<T>(r: duox::Result<T>) -> StepResult<T> {
    match r {
        Ok(v) => Ok(v),
        Err(e) if e.status().is_some() => Err(StepError::skip(format!("card refused: {e}"))),
        Err(e) => Err(e.into()),
    }
}

fn initial_free_mem(c: &Ctx) -> Option<String> {
    c.initial.as_ref()?.get("FreeMem").map(|i| i.show.clone())
}

// ------------------------------------------------------------------ read only
fn identification(ctx: &mut Ctx) {
    ctx.step("GetVersion (not authenticated)", |c| {
        c.select_application(Aid::PICC, None)?;
        let v: VersionInfo = c.get_version()?;
        c.detail(format!(
            "vendor {:02X}, HW type {:02X}/{:02X} v{}.{} storage {} protocol {:02X}",
            v.vendor, v.hw_type, v.hw_subtype, v.hw_version.0, v.hw_version.1, v.hw_storage, v.hw_protocol
        ));
        c.detail(format!(
            "SW type {:02X}/{:02X} v{}.{} storage {} protocol {:02X}",
            v.sw_type, v.sw_subtype, v.sw_version.0, v.sw_version.1, v.sw_storage, v.sw_protocol
        ));
        c.detail(format!(
            "UID {} batch {} type {} production week/year {:02X?}",
            hex::encode_upper(&v.uid),
            hex::encode_upper(&v.batch),
            hex::encode_upper(&v.type_id),
            v.production
        ));
        ensure_eq(v.uid.clone(), c.uid.clone(), "UID")?;
        ensure(v.vendor == 0x04, format!("vendor ID {:02X} is not NXP (04)", v.vendor))
    });
    ctx.step_picc("GetCardUID", |c| {
        let u = c.get_card_uid()?;
        ensure_eq(u, c.uid.clone(), "GetCardUID vs GetVersion")
    });
    ctx.step_picc("FreeMem equals the initial value", |c| {
        let m = c.free_mem()?;
        c.detail(format!("{m} bytes free"));
        match initial_free_mem(c) {
            Some(i) => ensure_eq(format!("{m} bytes"), i, "FreeMem"),
            None => Ok(()),
        }
    });
}

fn read_only_info(ctx: &mut Ctx) {
    ctx.step_picc("GetKeySettings (PICC)", |c| {
        let k = c.get_key_settings()?;
        c.detail(format!(
            "PICCKeySettings {:02X}: master key changeable={} free directory={} free create/delete={} settings changeable={} NXPDAM keys={}; max keys {}, key type {}",
            k.settings,
            k.settings & 1,
            (k.settings >> 1) & 1,
            (k.settings >> 2) & 1,
            (k.settings >> 3) & 1,
            (k.settings >> 4) & 1,
            k.max_keys,
            k.key_type
        ));
        ensure(k.settings & 0x09 == 0x09, "bit 0 and bit 3 must be set on the factory card; the suite refuses to go on otherwise")
    });
    ctx.step_picc("GetKeySettings option 1: ECC key info (read only)", |c| {
        let list = c.get_ecc_key_settings()?;
        for k in &list {
            c.detail(format!(
                "ECC key {:02X}: curve {:02X} policy {:04X} write access {:02X} KUC limit {} used {}",
                k.key_no, k.curve, k.policy, k.write_access, k.kuc_limit, k.kuc
            ));
        }
        c.detail(format!("{} ECC key slot(s)", list.len()));
        Ok(())
    });
    ctx.step_picc("GetKeySettings option 2: CA root key info (read only)", |c| {
        let list = c.get_ca_root_key_settings()?;
        for k in &list {
            c.detail(format!("{k:?}"));
        }
        c.detail(format!("{} CA root key slot(s)", list.len()));
        Ok(())
    });
    for &k in KEY_VERSION_KEYS {
        ctx.step_picc(&format!("GetKeyVersion 0x{k:02X}"), |c| {
            let v = soft(c.get_key_version(k, None))?;
            c.detail(format!("version {}", hex::encode_upper(&v)));
            Ok(())
        });
    }
}

fn configuration_reads(ctx: &mut Ctx) {
    for &opt in CONFIG_OPTIONS {
        let name = match opt {
            None => "GetConfiguration without option (manufacturer data)".to_string(),
            Some(o) => format!("GetConfiguration 0x{o:02X} {}", option_name(opt)),
        };
        ctx.step_picc(&name, |c| {
            let d = soft(c.get_configuration(opt))?;
            c.detail(decode_config(opt, &d));
            Ok(())
        });
    }
    ctx.step_picc("authentication counter: GetConfiguration 0x16 before and after an authentication", |c| {
        let a = soft(c.get_configuration(Some(0x16)))?;
        c.auth_picc()?;
        let b = soft(c.get_configuration(Some(0x16)))?;
        c.detail(format!("before {}  after {}", hex::encode_upper(&a), hex::encode_upper(&b)));
        if a.len() < 10 || b.len() < 10 {
            return Err(StepError::skip("the response carries no counter field; not observable"));
        }
        let (ca, cb) = (u32::from_le_bytes([a[6], a[7], a[8], a[9]]), u32::from_le_bytes([b[6], b[7], b[8], b[9]]));
        if a[1] & 1 == 0 {
            return Err(StepError::skip(format!(
                "AES authentication counting is disabled (factory default, counter {ca} -> {cb}); the guard never enables it at PICC level"
            )));
        }
        ensure_eq(cb, ca + 1, "AuthCtr after one AuthenticateEV2First")
    });
}

fn empty_card_lists(ctx: &mut Ctx) {
    ctx.step_picc("GetApplicationIDs on the empty card", |c| {
        let a = c.get_application_ids()?;
        ensure(a.is_empty(), format!("expected no applications, found {a:?}"))
    });
    ctx.step_picc("GetDFNames on the empty card", |c| {
        let a = c.get_df_names()?;
        ensure(a.is_empty(), format!("expected no DF names, found {a:?}"))
    });
    ctx.step_picc("GetDelegatedInfo (slot 0) on the empty card", |c| {
        let i = soft(c.get_delegated_info(0))?;
        c.detail(format!("{i:?}"));
        Ok(())
    });
    ctx.step_picc("GetFileIDs at PICC level", |c| {
        let f = soft(c.get_file_ids())?;
        c.detail(format!("{f:02X?}"));
        Ok(())
    });
}

// ------------------------------------------------------------------ guard demonstration
fn guard_refusals(ctx: &mut Ctx) {
    ctx.step_picc("the guard refuses forbidden PICC operations (nothing is sent)", |c| {
        let forbidden: &[(u8, &[u8])] = &[
            (0x00, &[0x01]),
            (0x00, &[0x02]),
            (0x00, &[0x23]),
            (0x02, &[0x05, 0x75, 0x77, 0x81, 0x02]),
            (0x03, &[0x20, 0x00]),
            (0x0C, &[0x44, 0x00]),
            (0x0F, &[0x00, 0x00, 0x00]),
            (0x10, &[0x00, 0x20, 0x00, 0x00]),
            (0x05, &[0u8; 10]),
            (0x04, &[0x04, 0x00]),
            (0x11, &[0u8; 33]),
            (0xFF, &[0xFF, 0xFF, 0xFF]),
        ];
        for (opt, data) in forbidden {
            let r = c.set_configuration(*opt, data);
            c.expect_violation(r)?;
        }
        let r = c.manage_key_pair(&KeyPairSpec::new(1, 0x0C, 0, 0), &KeyPairOp::Generate, None);
        c.expect_violation(r)?;
        let r = c.manage_ca_root_key(&CaRootKeySpec::new(1, 0x0C, vec![0; 65]), None);
        c.expect_violation(r)?;
        let r = c.change_key(&ChangeKeySpec::new(0x80, &[1; 16], 1));
        c.expect_violation(r)?;
        let r = c.change_picc_key(KeyChange::other(0x18, &[0; 16], &[1; 16], 1));
        c.expect_violation(r)?;
        for bad in [0x0E_u8, 0x07, 0x1F] {
            let r = c.change_key_settings(bad);
            c.expect_violation(r)?;
        }
        let r = c.native_raw(cmd::FORMAT, &[]);
        c.expect_violation(r)?;
        // the session survived all of this (nothing reached the card)
        ensure(c.is_authenticated(), "the authentication was lost although nothing should have been sent")
    });
}

// ------------------------------------------------------------------ negative tests
fn negative_tests(ctx: &mut Ctx) {
    ctx.step("wrong PICC master key: AUTHENTICATION_ERROR and the session ends", |c| {
        c.select_application(Aid::PICC, None)?;
        let r = c.authenticate_ev2_first(0, &[0x55; 16], &[]);
        c.expect_err(Status::AuthenticationError, r)
    });
    ctx.step("authenticating a key number that does not exist is refused", |c| {
        c.select_application(Aid::PICC, None)?;
        let z = c.zero_key;
        let r = c.authenticate_ev2_first(0x07, &z, &[]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("the card answers {s} (0x{:02X})", s.code()));
        Ok(())
    });
    ctx.step("GetCardUID without authentication is refused", |c| {
        c.select_application(Aid::PICC, None)?;
        let r = c.get_card_uid();
        let s = c.expect_any_status(r)?;
        c.detail(format!("the card answers {s} (0x{:02X})", s.code()));
        Ok(())
    });
    ctx.step("SelectApplication of an unknown AID: APPLICATION_NOT_FOUND, PICC stays selected", |c| {
        let r = c.select_application(Aid(0xD0_FFFF), None);
        c.expect_err(Status::ApplicationNotFound, r)?;
        ensure_eq(c.selection().primary, Some(Aid::PICC), "selection after a failed select")
    });
    ctx.step("the card still authenticates after the failed attempts", |c| c.auth_picc());
}

// ------------------------------------------------------------------ authentication
fn authentication(ctx: &mut Ctx) {
    ctx.step("AES-128 EV2 authentication, PICC key 0: session state", |c| {
        c.auth_picc()?;
        let a = c.auth_summary().ok_or("no session")?;
        c.detail(c.state_text());
        c.detail(format!("TI {}", hex::encode_upper(a.ti)));
        if let Some(i) = c.aes_auth_info() {
            c.detail(format!("PDcap2 {} PCDcap2 {}", hex::encode_upper(&i.pd_cap2), hex::encode_upper(&i.pcd_cap2)));
        }
        ensure_eq((a.kind, a.key_no, a.cmd_ctr, a.key_bits), (AuthKind::Aes, Some(0), 0, 128), "session")
    });
    ctx.step("the command counter increases by one per command", |c| {
        c.auth_picc()?;
        c.free_mem()?;
        ensure_eq(c.auth_summary().ok_or("no session")?.cmd_ctr, 1, "CmdCtr after one command")?;
        c.get_card_uid()?;
        ensure_eq(c.auth_summary().ok_or("no session")?.cmd_ctr, 2, "CmdCtr after two commands")
    });
    ctx.step("two sessions get different transaction identifiers", |c| {
        c.auth_picc()?;
        let t1 = c.auth_summary().ok_or("no session")?.ti;
        c.auth_picc()?;
        let t2 = c.auth_summary().ok_or("no session")?.ti;
        ensure(t1 != t2, format!("TI repeated: {}", hex::encode_upper(t1)))
    });
    ctx.step("AuthenticateEV2NonFirst keeps TI and the command counter", |c| {
        c.auth_picc()?;
        c.free_mem()?;
        let before = c.auth_summary().ok_or("no session")?;
        let key = c.picc_key.clone();
        c.authenticate_ev2_non_first(0, &key)?;
        let after = c.auth_summary().ok_or("no session")?;
        ensure_eq((after.ti, after.cmd_ctr), (before.ti, before.cmd_ctr), "TI / CmdCtr")?;
        c.get_card_uid()?; // the new session keys work
        Ok(())
    });
    // AES-128 application with several keys: authentication with other keys and ChangeKey of a key
    // that is not the authenticated one (old key XOR new key plus CRC).
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(3), |ctx, aid| {
        ctx.step("AES-128 application: authenticate keys 0, 1 and 2 with the default zero keys", |c| {
            let z = c.zero_key;
            for k in 0..3 {
                c.auth_app(aid, k, &z)?;
                let a = c.auth_summary().ok_or("no session")?;
                ensure_eq((a.kind, a.key_no, a.key_bits), (AuthKind::Aes, Some(k), 128), "session")?;
            }
            Ok(())
        });
        ctx.step("AES-128 application: ChangeKey of key 1 from key 0 (old key XOR new key), verify, change back", |c| {
            let z = c.zero_key;
            let new: [u8; 16] = rand::random();
            c.auth_app(aid, 0, &z)?;
            c.change_key(&ChangeKeySpec::new(1, &new, 0x21).old_key(&z))?;
            c.auth_app(aid, 1, &new)?;
            let r = c.auth_app(aid, 1, &z);
            c.expect_err(Status::AuthenticationError, r)?;
            c.auth_app(aid, 0, &z)?;
            ensure_eq(c.get_key_version(1, None)?, vec![0x21], "key version")?;
            c.change_key(&ChangeKeySpec::new(1, &z, 0).old_key(&new))?;
            c.auth_app(aid, 1, &z)
        });
        ctx.step("AES-128 application: ChangeKey of the authenticated key 0 ends the session; the new key works", |c| {
            let z = c.zero_key;
            let new: [u8; 16] = rand::random();
            c.auth_app(aid, 0, &z)?;
            c.change_key(&ChangeKeySpec::new(0, &new, 0x07))?;
            ensure(!c.is_authenticated(), "the session should be gone after changing the authenticated key")?;
            c.auth_app(aid, 0, &new)?;
            c.change_key(&ChangeKeySpec::new(0, &z, 0))?;
            c.auth_app(aid, 0, &z)
        });
    });
}

// ------------------------------------------------------------------ raw escapes
fn raw_escapes(ctx: &mut Ctx) {
    ctx.step("raw native GetVersion drops the session and returns three frames", |c| {
        // the card keeps an authenticated session until it is ended: a plain command needs a fresh PICC selection
        c.auth_picc()?;
        c.select_application(Aid::PICC, None)?;
        let (rc, frames) = c.native_raw(cmd::GET_VERSION, &[])?;
        ensure_eq(rc, 0, "final status byte")?;
        ensure(!c.is_authenticated(), "raw commands must drop the tracked session")?;
        let v = VersionInfo::parse(&frames)?;
        ensure_eq(v.uid, c.uid.clone(), "UID from the raw frames")
    });
    ctx.step("raw APDU: GetVersion frame by frame", |c| {
        let (d, mut sw) = c.apdu_raw(&[0x90, 0x60, 0x00, 0x00, 0x00])?;
        ensure_eq((sw, d.len()), (0x91AF, 7), "first frame")?;
        let mut frames = 1;
        while sw == 0x91AF && frames < 5 {
            let (_, s) = c.apdu_raw(&[0x90, 0xAF, 0x00, 0x00, 0x00])?;
            sw = s;
            frames += 1;
        }
        ensure_eq((sw, frames), (0x9100, 3), "GetVersion must end after three frames with 9100")
    });
    ctx.step("raw ISO SELECT of the PICC level DF by name is answered", |c| {
        // read-only select; the status is reported, not judged
        let (d, sw) = c.apdu_raw(&[0x00, 0xA4, 0x04, 0x00, 0x00])?;
        c.detail(format!("SW {sw:04X} ({}), {} data bytes", duox::card::types::iso_sw_description(sw), d.len()));
        Ok(())
    });
}

// ------------------------------------------------------------------ originality
fn originality(ctx: &mut Ctx) {
    ctx.step_picc("originality check: card-unilateral ECC authentication with Priv.Orig (key 1), read-only", |c| {
        let ecc = c.get_ecc_key_settings()?;
        let Some(k1) = ecc.iter().find(|k| k.key_no == 1) else {
            return Err(StepError::skip("no ECC private key 1 on this card"));
        };
        if k1.kuc_limit != 0 {
            return Err(StepError::skip(format!(
                "ECC key 1 has a usage limit ({} of {} used); the suite does not spend usage counts",
                k1.kuc, k1.kuc_limit
            )));
        }
        // Cert.Orig is read under the PICC master key (its file is CommMode.Full); its leaf key verifies the signature.
        let cert = c.read_cert_file(0x01);
        let pub_orig = match &cert {
            Ok(bytes) => duox::pki::leaf_public_key(bytes).ok(),
            Err(e) => {
                c.detail(format!("Cert.Orig not readable under the master key: {e}"));
                None
            }
        };
        c.detail(format!(
            "Cert.Orig: {}",
            match &cert {
                Ok(b) => format!("{} bytes, public key {}", b.len(), if pub_orig.is_some() { "extracted" } else { "not extractable" }),
                Err(_) => "-".into(),
            }
        ));
        let leaf = |cert: &[u8]| duox::pki::leaf_public_key(cert).ok();
        let r = c.originality_check(pub_orig.as_ref(), Some(&leaf));
        let res = match r {
            Ok(r) => r,
            Err(e) if e.status().is_some() || e.iso_sw().is_some() => {
                return Err(StepError::skip(format!("the card refused: {e}")));
            }
            Err(e) => return Err(e.into()),
        };
        c.detail(format!(
            "certificate {}; signature {} bytes; key taken from the certificate: {}",
            match &res.certificate {
                Some(cert) => format!("{} bytes", cert.len()),
                None => "not readable".into(),
            },
            res.auth.signature.len(),
            res.key_from_certificate
        ));
        match res.auth.valid {
            Some(true) => Ok(()),
            Some(false) => Err(StepError::fail("the signature does not verify against the public key of Cert.Orig")),
            None => Err(StepError::skip("the card signed, but no public key was available to verify the signature")),
        }
    });
}

// ------------------------------------------------------------------ PICCAppDefaultKey
fn default_key_data(key: &[u8; 16], version: u8) -> Vec<u8> {
    let mut d = key.to_vec();
    d.extend([0u8; 8]);
    d.push(version);
    d
}

fn app_default_key(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let proven = ctx
        .app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
            ctx.step("PICCAppDefaultKey: a new application carries the all-zero key (proves the restore value)", |c| {
                let z = c.zero_key;
                c.auth_app(aid, 0, &z)?;
                let v = c.get_key_version(0, None)?;
                ensure_eq(v, vec![c.app_default_key_version], "default key version (measured in the preflight)")
            })
        })
        .flatten();
    if proven.is_none() {
        ctx.skip("PICCAppDefaultKey round trip", "the restore value could not be proven");
        return;
    }
    let (zero, version) = (ctx.zero_key, ctx.app_default_key_version);
    let restore = default_key_data(&zero, version);
    let r2 = restore.clone();
    let cid = ctx.push_cleanup("restore PICCAppDefaultKey to the all-zero key", move |c| {
        c.auth_picc()?;
        c.set_configuration(0x01, &r2)
    });
    let new_key: [u8; 16] = rand::random();
    ctx.step_picc("SetConfiguration 0x01: PICCAppDefaultKey to a new key", |c| {
        c.set_configuration(0x01, &default_key_data(&new_key, 0x5A))
    });
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        ctx.step("a new application takes the new default key, the zero key is refused", |c| {
            c.auth_app(aid, 0, &new_key)?;
            ensure_eq(c.get_key_version(0, None)?, vec![0x5A], "key version")?;
            let z = c.zero_key;
            let r = c.auth_app(aid, 0, &z);
            c.expect_err(Status::AuthenticationError, r)
        });
    });
    let ok = ctx.step_picc("SetConfiguration 0x01: restore the all-zero default key", |c| c.set_configuration(0x01, &restore));
    if ok.is_some() {
        ctx.cancel_cleanup(cid);
    }
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        ctx.step("after the restore a new application carries the all-zero key again", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "key version")
        });
    });
}

// ------------------------------------------------------------------ VCIID
fn vciid(ctx: &mut Ctx) {
    // Options 0x05 / 0x06 need the VCConfigurationKey (0x20). It is disabled at delivery and writing it
    // enables it for good, so it is only used when it already authenticates with the zero key.
    let orig = ctx.step("GetConfiguration 0x06 (VCIID): remember the exact value", |c| {
        let z = c.zero_key;
        if let Err(e) = c.auth_picc_key(0x20, &z) {
            return Err(StepError::skip(format!(
                "VCConfigurationKey 0x20 does not authenticate with the zero key ({e}): it is disabled at delivery and enabling it is irreversible, so VCIID is not exercised"
            )));
        }
        let d = c.get_configuration(Some(0x06))?;
        if d.len() != 17 || !(1..=16).contains(&d[0]) {
            return Err(StepError::skip(format!(
                "unexpected VCIID layout {} (expected length byte + 16 bytes); not modified",
                hex::encode_upper(&d)
            )));
        }
        c.detail(decode_config(Some(0x06), &d));
        Ok(d)
    });
    let Some(orig) = orig else {
        ctx.skip("VCIID round trip", "the original value could not be read in the expected layout");
        return;
    };
    let o2 = orig.clone();
    let cid = ctx.push_cleanup("restore VCIID to the exact value read first", move |c| {
        c.auth_picc_key(0x20, &[0u8; 16])?;
        c.set_configuration(0x06, &o2)
    });
    let mut new = vec![0u8; 17];
    new[0] = 4;
    new[1..5].copy_from_slice(b"DUOX");
    if new == orig {
        new[1] = b'Y';
    }
    ctx.step("SetConfiguration 0x06: new VCIID, read back", |c| {
        c.auth_picc_key(0x20, &[0u8; 16])?;
        c.set_configuration(0x06, &new)?;
        ensure_eq(c.get_configuration(Some(0x06))?, new.clone(), "VCIID read back")
    });
    let ok = ctx.step("SetConfiguration 0x06: restore the original VCIID, read back", |c| {
        c.auth_picc_key(0x20, &[0u8; 16])?;
        c.set_configuration(0x06, &orig)?;
        ensure_eq(c.get_configuration(Some(0x06))?, orig.clone(), "VCIID after the restore")
    });
    if ok.is_some() {
        ctx.cancel_cleanup(cid);
    }
}

// ------------------------------------------------------------------ PICCKeySettings
fn key_settings_toggle(ctx: &mut Ctx) {
    let cur = ctx.step_picc("PICCKeySettings: remember the value", |c| {
        let s = c.get_key_settings()?.settings;
        ensure(s & 0x09 == 0x09, format!("PICCKeySettings {s:02X}: bits 0 and 3 are not both set, not touching"))?;
        Ok(s)
    });
    let Some(cur) = cur else {
        ctx.skip("PICCKeySettings toggle", "bits 0 and 3 are not both set");
        return;
    };
    let cid = ctx.push_cleanup("restore PICCKeySettings", move |c| {
        c.auth_picc()?;
        if c.get_key_settings()?.settings != cur {
            c.change_key_settings(cur)?;
        }
        ensure_eq(c.get_key_settings()?.settings, cur, "PICCKeySettings after the restore")
    });

    // bit 1: free directory access
    let flipped = cur ^ 0x02;
    let toggled = ctx.step_picc("ChangeKeySettings: toggle bit 1 (directory access)", |c| {
        c.change_key_settings(flipped)?;
        ensure_eq(c.get_key_settings()?.settings, flipped, "PICCKeySettings read back")
    });
    if toggled.is_some() {
        ctx.step("directory commands follow bit 1", |c| {
            c.select_application(Aid::PICC, None)?;
            let r = c.get_application_ids();
            if flipped & 0x02 == 0 {
                let s = c.expect_any_status(r)?;
                c.detail(format!("unauthenticated GetApplicationIDs is refused: {s}"));
                Ok(())
            } else {
                r?;
                Ok(())
            }
        });
    } else {
        ctx.skip("directory commands follow bit 1", "bit 1 was not changed");
    }
    ctx.step_picc("ChangeKeySettings: restore bit 1", |c| {
        c.change_key_settings(cur)?;
        ensure_eq(c.get_key_settings()?.settings, cur, "PICCKeySettings read back")
    });

    // bit 2: free application creation
    let flipped = cur ^ 0x04;
    let toggled = ctx.step_picc("ChangeKeySettings: toggle bit 2 (application create / delete)", |c| {
        c.change_key_settings(flipped)?;
        ensure_eq(c.get_key_settings()?.settings, flipped, "PICCKeySettings read back")
    });
    if toggled.is_some() {
        let aid = ctx.alloc_aid();
        let dcid = ctx.push_cleanup(&format!("delete application {aid} if it exists"), move |c| c.delete_app_tolerant(aid));
        ctx.step("CreateApplication without authentication follows bit 2", |c| {
            c.select_application(Aid::PICC, None)?;
            let r = c.create_application(&AppSpec::new(aid).keys(1));
            if flipped & 0x04 == 0 {
                let s = c.expect_any_status(r)?;
                c.detail(format!("unauthenticated CreateApplication is refused: {s}"));
                Ok(())
            } else {
                r?;
                c.detail("unauthenticated CreateApplication succeeded (bit 2 set)");
                Ok(())
            }
        });
        let deleted = ctx.step("delete the probe application again", |c| c.delete_app_tolerant(aid));
        if deleted.is_some() {
            ctx.cancel_cleanup(dcid);
        }
    } else {
        ctx.skip("CreateApplication without authentication follows bit 2", "bit 2 was not changed");
    }
    let ok = ctx.step_picc("ChangeKeySettings: restore bit 2 and verify the original value", |c| {
        c.change_key_settings(cur)?;
        ensure_eq(c.get_key_settings()?.settings, cur, "PICCKeySettings read back")
    });
    if ok.is_some() {
        ctx.cancel_cleanup(cid);
    }
}

// ------------------------------------------------------------------ PICC master key
fn master_key(ctx: &mut Ctx) {
    for ev2 in [false, true] {
        let name = if ev2 { "ChangeKeyEV2" } else { "ChangeKey" };
        let new: [u8; 16] = rand::random();
        let handle = ctx.step(&format!("{name}: PICC master key to a new key (proof, recovery file, verification)"), |c| {
            let mut kc = KeyChange::master(&new, 0x42);
            if ev2 {
                kc = kc.ev2();
            }
            c.change_picc_key(kc)
        });
        let Some(handle) = handle else {
            ctx.skip(&format!("{name}: operate with the new key / restore"), "the key change did not happen");
            continue;
        };
        ctx.step(&format!("{name}: the new key works, the old zero key is refused"), |c| {
            c.ensure_picc()?;
            ensure_eq(c.get_card_uid()?, c.uid.clone(), "GetCardUID with the new key")?;
            c.select_application(Aid::PICC, None)?;
            let z = c.zero_key;
            let r = c.authenticate_ev2_first(0, &z, &[]);
            c.expect_err(Status::AuthenticationError, r)
        });
        ctx.step(&format!("{name}: restore the PICC master key and verify the zero key"), |c| {
            c.revert_key_change(handle)?;
            ensure_eq(c.picc_key.clone(), vec![0u8; 16], "ctx.picc_key after the restore")?;
            c.auth_picc()
        });
    }
}

// ------------------------------------------------------------------ PICCDAM key 0x10
fn picc_dam_key(ctx: &mut Ctx) {
    let proven = ctx.step("PICCDAMAuthKey 0x10: the all-zero key authenticates (proof of the restore value)", |c| {
        let z = c.zero_key;
        match c.auth_picc_key(0x10, &z) {
            Ok(()) => Ok(()),
            Err(e) => Err(StepError::skip(format!("key 0x10 does not authenticate with the zero key ({e}); not touched"))),
        }
    });
    if proven.is_none() {
        ctx.skip("ChangeKey of PICCDAMAuthKey 0x10", "the zero key does not authenticate");
        return;
    }
    let new: [u8; 16] = rand::random();
    let zero = ctx.zero_key;
    let handle = ctx.step("ChangeKey of PICCDAMAuthKey 0x10 to a new key (old key XOR new key)", |c| {
        c.change_picc_key(KeyChange::other(0x10, &zero, &new, 0x33))
    });
    let Some(handle) = handle else { return };
    ctx.step("PICCDAMAuthKey 0x10: the new key works, the zero key is refused", |c| {
        c.auth_picc_key(0x10, &new)?;
        let z = c.zero_key;
        let r = c.auth_picc_key(0x10, &z);
        c.expect_err(Status::AuthenticationError, r)
    });
    ctx.step("PICCDAMAuthKey 0x10: restore and verify the zero key", |c| {
        c.revert_key_change(handle)?;
        let z = c.zero_key;
        c.auth_picc_key(0x10, &z)?;
        c.auth_picc()
    });
}

// ------------------------------------------------------------------ AES-256
fn aes256_body(ctx: &mut Ctx, aid: Aid) {
    ctx.step("AES-256 application: authenticate key 0 with the 32-byte zero key", |c| {
        let z = c.zero_key32;
        c.auth_app(aid, 0, &z)?;
        let a = c.auth_summary().ok_or("no session")?;
        c.detail(c.state_text());
        ensure_eq((a.kind, a.key_bits), (AuthKind::Aes, 256), "session")
    });
    ctx.step("AES-256 application: GetKeySettings reports AES-256 keys", |c| {
        let z = c.zero_key32;
        c.auth_app(aid, 0, &z)?;
        let k = c.get_key_settings()?;
        c.detail(format!("{k:?}"));
        ensure_eq(k.key_type, 3, "key type bits (11b = AES-256)")
    });
    ctx.step("AES-256 application: ChangeKey of key 0, authenticate with it, change back", |c| {
        let z = c.zero_key32;
        let new: [u8; 32] = rand::random();
        c.auth_app(aid, 0, &z)?;
        c.change_key(&ChangeKeySpec::new(0, &new, 0x11))?;
        c.auth_app(aid, 0, &new)?;
        ensure_eq(c.get_key_version(0, None)?, vec![0x11], "key version")?;
        c.change_key(&ChangeKeySpec::new(0, &z, 0))?;
        c.auth_app(aid, 0, &z)?;
        c.authenticate_ev2_non_first(0, &z)?;
        c.get_key_settings()?;
        Ok(())
    });
}

/// Does the card create an AES-256 application with the factory default key? Err = could not tell.
fn probe_aes256_creation(c: &mut Ctx) -> StepResult<bool> {
    let aid = c.alloc_aid();
    let cid = c.push_cleanup(&format!("delete application {aid} if it exists"), move |c| c.delete_app_tolerant(aid));
    c.auth_picc()?;
    let r = c.create_application(&AppSpec::new(aid).keys(1).aes256());
    match r {
        Ok(()) => {
            c.delete_app_tolerant(aid)?;
            c.cancel_cleanup(cid);
            Ok(true)
        }
        Err(e) if e.status().is_some() => {
            c.cancel_cleanup(cid);
            c.detail(format!("creation refused: {e}"));
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

fn aes256(ctx: &mut Ctx) {
    let direct = ctx.step_picc("AES-256 application can be created with the factory default key", probe_aes256_creation);
    let Some(direct) = direct else {
        ctx.skip("AES-256 steps", "could not determine whether AES-256 applications can be created");
        return;
    };
    if direct {
        let aid = ctx.alloc_aid();
        ctx.app_scope(AppSpec::new(aid).keys(1).aes256(), |c, aid| aes256_body(c, aid));
        return;
    }
    // The data sheet ties AES-256 application creation to a 32-byte PICCAppDefaultKey: set it (all zero,
    // with the measured version), run the steps, write the 24 byte form back and probe again.
    let (zero, version) = (ctx.zero_key, ctx.app_default_key_version);
    let restore = default_key_data(&zero, version);
    let r2 = restore.clone();
    let cid = ctx.push_cleanup("restore PICCAppDefaultKey (24 byte form, all zero)", move |c| {
        c.auth_picc()?;
        c.set_configuration(0x01, &r2)
    });
    let mut wide = vec![0u8; 32];
    wide.push(version);
    let set = ctx.step_picc("SetConfiguration 0x01: 32-byte all-zero PICCAppDefaultKey (needed for AES-256 applications)", |c| {
        c.set_configuration(0x01, &wide)
    });
    if set.is_some() {
        let aid = ctx.alloc_aid();
        ctx.app_scope(AppSpec::new(aid).keys(1).aes256(), |c, aid| aes256_body(c, aid));
    } else {
        ctx.skip("AES-256 steps", "the 32-byte default key could not be set");
    }
    let ok = ctx.step_picc("SetConfiguration 0x01: write the 24-byte all-zero default key back", |c| c.set_configuration(0x01, &restore));
    if ok.is_some() {
        ctx.cancel_cleanup(cid);
        ctx.step_picc("after the restore AES-256 creation is refused again, as at the start", |c| {
            let now = probe_aes256_creation(c)?;
            ensure(!now, "AES-256 applications can now be created with the default key: the 32-byte state was NOT reverted")
        });
    }
}

// ------------------------------------------------------------------ Format
fn format_with_application(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, _aid| {
        ctx.step_picc("Format with an application present releases it and the memory", |c| {
            ensure(c.get_application_ids()?.len() == 1, "the probe application should be listed")?;
            c.format()?;
            c.ensure_picc()?;
            ensure(c.get_application_ids()?.is_empty(), "applications remain after Format")?;
            let m = c.free_mem()?;
            match initial_free_mem(c) {
                Some(i) => ensure_eq(format!("{m} bytes"), i, "FreeMem after Format"),
                None => Ok(()),
            }
        });
    });
}
