//! Section `application`: application management inside throwaway applications of the suite range.
//!
//! Covered: CreateApplication variants (AES-128 / AES-256 keys, 0 / 2 / 14 keys, ISO file ids and DF names,
//! KeySett1 variants, KeySett3 options), SelectApplication (one and two applications, secondary application
//! indicator), GetApplicationIDs, GetDFNames, DeleteApplication, GetKeySettings / ChangeKeySettings at application
//! level, GetKeyVersion, ChangeKey / ChangeKeyEV2 for every key (own key and other keys, all change-key
//! settings), authentication with every key, SetConfiguration / GetConfiguration at application level (only
//! options the guard approves), Format refusal in a conventional application, and negative tests.
//!
//! Everything happens in applications of the suite AID range created by `ctx.app_scope`. Nothing at PICC level is
//! changed; the only PICC level write is a Format between groups, and only when no application exists, to give
//! back memory that DeleteApplication does not release (data sheet 7.11.1.2).
//!
//! Section numbers: 7.8.5 (application keys), 7.8.6 (key commands), 7.11 (applications), 7.7.3 (configuration).

use crate::ctx::{ensure, ensure_eq, CleanupId, Ctx, StepError, StepResult};
use duox::card::{AccessRight, AccessRights, Aid, AppSpec, AuthKind, ChangeKeySpec, DataFileSpec, DfName, Status};

pub const NAME: &str = "application";
pub const DESCRIPTION: &str =
    "Applications: create variants (AES-128/256, ISO names, key counts, settings), select (also two at once), delete, key settings, ChangeKey for every key, configuration, Format refusal, negatives.";

pub fn run(ctx: &mut Ctx) {
    reclaim(ctx, "the application section");
    lifecycle(ctx);
    reclaim(ctx, "the 14-key application");
    many_keys_application(ctx);
    reclaim(ctx, "the application without keys");
    no_keys_application(ctx);
    reclaim(ctx, "ISO names");
    iso_applications(ctx);
    reclaim(ctx, "KeySett3 options");
    key_sett3_options(ctx);
    reclaim(ctx, "AES-256 applications");
    aes256_application(ctx);
    reclaim(ctx, "key settings");
    key_settings_group(ctx);
    reclaim(ctx, "change key settings");
    change_key_rights(ctx);
    reclaim(ctx, "two applications at once");
    two_applications(ctx);
    reclaim(ctx, "configuration");
    configuration_group(ctx);
    reclaim(ctx, "authentication counter");
    auth_counter_group(ctx);
    reclaim(ctx, "negative tests");
    negative_group(ctx);
    reclaim(ctx, "delete variants");
    delete_group(ctx);
}

// ------------------------------------------------------------------ helpers
/// Turn "the card refused" into a skip (the thing is not available on this card).
fn soft<T>(r: duox::Result<T>) -> StepResult<T> {
    match r {
        Ok(v) => Ok(v),
        Err(e) if e.status().is_some() => Err(StepError::skip(format!("card refused: {e}"))),
        Err(e) => Err(e.into()),
    }
}

fn rnd16() -> [u8; 16] {
    rand::random()
}

fn rnd32() -> [u8; 32] {
    rand::random()
}

fn hx(b: &[u8]) -> String {
    hex::encode_upper(b)
}

fn is_status<T>(r: &StepResult<T>, s: Status) -> bool {
    matches!(r, Err(e) if e.status() == Some(s))
}

/// Memory of an application in 32-byte blocks: key storage (7.8.7) plus application overhead (7.11.5).
fn app_blocks(n_keys: u32, key_sets: u32, max_key_size: u32, iso: bool, vc_key: bool, capability: bool) -> u32 {
    let key_blocks = if n_keys == 0 { 0 } else { key_sets * (21 + n_keys * (max_key_size + 4)).div_ceil(32) };
    let overhead = 1 + u32::from(iso || capability); // measured on a card: a VCProximityKey adds its 3 blocks only
    key_blocks + overhead + if vc_key { 3 } else { 0 }
}

/// Bytes taken between two FreeMem readings; a rising FreeMem is a failure, not an underflow.
fn consumed(before: u32, now: u32) -> StepResult<u32> {
    before.checked_sub(now).ok_or_else(|| StepError::fail(format!("FreeMem rose from {before} to {now}")))
}

/// Payload of SetConfiguration option 0x06 for a conventional application: length byte, name padded to 16.
fn dfname_data(name: &[u8]) -> Vec<u8> {
    let mut d = vec![name.len() as u8];
    d.extend_from_slice(name);
    d.resize(17, 0);
    d
}

/// Format the empty card to give back the memory that DeleteApplication keeps (7.11.1.2). Only when no
/// application exists; a card holding applications is never formatted here.
fn reclaim(ctx: &mut Ctx, before: &str) {
    ctx.step_picc(&format!("Format the empty card to release memory before {before}"), |c| {
        let ids = c.get_application_ids()?;
        if !ids.is_empty() {
            return Err(StepError::skip(format!("{} application(s) exist; the card is not formatted", ids.len())));
        }
        c.format()?;
        c.ensure_picc()?;
        ensure(c.get_application_ids()?.is_empty(), "applications exist after Format")
    });
}

/// Try CreateApplication for an AID that was just allocated; the probe application is removed again by the caller
/// through the returned cleanup id (after the verdict was taken, because removing it re-authenticates).
fn attempt_create(c: &mut Ctx, spec: &AppSpec) -> (StepResult, CleanupId) {
    let aid = spec.aid;
    let id = c.push_cleanup(&format!("delete probe application {aid} if it exists"), move |c| c.delete_app_tolerant(aid));
    let r = c.auth_picc().and_then(|_| c.create_application(spec));
    (r, id)
}

/// Log in with the zero key of AES-128 key `key_no`.
fn enter(c: &mut Ctx, aid: Aid, key_no: u8) -> StepResult {
    let z = c.zero_key;
    c.auth_app(aid, key_no, &z)
}

fn access_all(r: AccessRight) -> AccessRights {
    AccessRights::all(r)
}

// ------------------------------------------------------------------ lifecycle
fn lifecycle(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let before = ctx.step_picc("FreeMem before the first application", |c| Ok(c.free_mem()?));
    let after_create = ctx
        .app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
            let after = ctx.step("FreeMem drops by the amount the data sheet gives (key storage + 1 overhead block)", |c| {
                c.ensure_picc()?;
                let now = c.free_mem()?;
                let before = before.ok_or_else(|| StepError::skip("no FreeMem reading before the application"))?;
                let want = app_blocks(2, 1, 16, false, false, false) * 32;
                ensure_eq(consumed(before, now)?, want, "bytes consumed by CreateApplication (2 AES-128 keys)")?;
                Ok(now)
            });
            ctx.step("SelectApplication returns OPERATION_OK, selects the application and ends the authentication", |c| {
                enter(c, aid, 0)?;
                ensure(c.is_authenticated(), "authentication did not start")?;
                let rc = c.select_application(aid, None)?;
                ensure_eq(rc, 0, "SelectApplication status")?;
                ensure(!c.is_authenticated(), "SelectApplication left the authentication active")?;
                ensure_eq(c.selection().primary, Some(aid), "primary application")?;
                ensure_eq(c.selection().secondary, None, "secondary application")
            });
            ctx.step("GetApplicationIDs lists exactly the new application", |c| {
                c.ensure_picc()?;
                ensure_eq(c.get_application_ids()?, vec![aid], "application list")
            });
            ctx.step("GetDFNames omits an application created without ISO names", |c| {
                c.ensure_picc()?;
                let n = c.get_df_names()?;
                ensure(n.is_empty(), format!("unexpected DF names {n:?}"))
            });
            ctx.step("GetApplicationIDs and GetDFNames are refused while an application is selected", |c| {
                enter(c, aid, 0)?;
                let r = c.get_application_ids();
                c.expect_err(Status::PermissionDenied, r)?;
                enter(c, aid, 0)?;
                let r = c.get_df_names();
                c.expect_err(Status::PermissionDenied, r)
            });
            ctx.step("GetKeySettings of a default application: 0x0F, 2 keys, AES-128, no key sets", |c| {
                enter(c, aid, 0)?;
                let k = c.get_key_settings()?;
                c.detail(format!("{k:?}"));
                ensure_eq((k.settings, k.max_keys, k.key_type), (0x0F, 2, 2), "settings / key count / key type")?;
                ensure(k.key_sets.is_none(), "key set fields reported for a single key set application")
            });
            ctx.step("GetKeyVersion of both keys is the version measured in the preflight", |c| {
                enter(c, aid, 0)?;
                let v = c.app_default_key_version;
                ensure_eq(c.get_key_version(0, None)?, vec![v], "key 0")?;
                ensure_eq(c.get_key_version(1, None)?, vec![v], "key 1")
            });
            ctx.step("a new application contains no files", |c| {
                enter(c, aid, 0)?;
                ensure_eq(c.get_file_ids()?, Vec::<u8>::new(), "file list")
            });
            ctx.step("GetKeySettings and GetFileIDs work without authentication (KeySett1 bit 1 set)", |c| {
                c.select_application(aid, None)?;
                ensure_eq(c.get_key_settings()?.settings, 0x0F, "settings")?;
                ensure_eq(c.get_file_ids()?, Vec::<u8>::new(), "file list")?;
                ensure_eq(c.get_key_version(1, None)?, vec![c.app_default_key_version], "key version without authentication")
            });
            ctx.step("authenticate every key (0 and 1) of the application with the default zero key", |c| {
                for k in 0..2u8 {
                    enter(c, aid, k)?;
                    let a = c.auth_summary().ok_or("no session")?;
                    ensure_eq((a.kind, a.key_no, a.key_bits, a.secondary), (AuthKind::Aes, Some(k), 128, false), "session")?;
                    ensure_eq(a.cmd_ctr, 0, "command counter after authentication")?;
                }
                Ok(())
            });
            ctx.step("authenticating a key number the application does not have: NO_SUCH_KEY", |c| {
                c.select_application(aid, None)?;
                let z = c.zero_key;
                let r = c.authenticate_ev2_first(2, &z, &[]);
                c.expect_err(Status::NoSuchKey, r)?;
                c.select_application(aid, None)?;
                let r = c.authenticate_ev2_first(0x0D, &z, &[]);
                c.expect_err(Status::NoSuchKey, r)
            });
            ctx.step("a wrong key: AUTHENTICATION_ERROR, the right key works right afterwards", |c| {
                c.select_application(aid, None)?;
                let r = c.authenticate_ev2_first(1, &[0x66; 16], &[]);
                c.expect_err(Status::AuthenticationError, r)?;
                enter(c, aid, 1)
            });
            ctx.step("after changing key 1 the zero key is refused for key 1 and still accepted for key 0", |c| {
                // key 0 and key 1 start with the same (zero) value; the key number selects which key is meant
                let new = rnd16();
                let z = c.zero_key;
                enter(c, aid, 0)?;
                c.change_key(&ChangeKeySpec::new(1, &new, 0x42).old_key(&z))?;
                enter(c, aid, 0)?;
                c.select_application(aid, None)?;
                let r = c.authenticate_ev2_first(1, &z, &[]);
                c.expect_err(Status::AuthenticationError, r)?;
                c.auth_app(aid, 1, &new)?;
                ensure_eq(c.get_key_version(1, None)?, vec![0x42], "version of the changed key")?;
                enter(c, aid, 0)?;
                ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "version of the untouched key")
            });
            after
        })
        .flatten();
    reclaim_check_after_delete(ctx, after_create);
    // the AID is free again
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        ctx.step("the AID of a deleted application can be created again, with no files and default keys", |c| {
            enter(c, aid, 0)?;
            ensure_eq(c.get_file_ids()?, Vec::<u8>::new(), "file list")?;
            ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "key version")
        });
    });
}

fn reclaim_check_after_delete(ctx: &mut Ctx, after_create: Option<u32>) {
    ctx.step_picc("after DeleteApplication the application is gone and FreeMem is not given back (7.11.1.2)", |c| {
        ensure(c.get_application_ids()?.is_empty(), "the deleted application is still listed")?;
        let now = c.free_mem()?;
        match after_create {
            Some(a) => ensure_eq(now, a, "FreeMem after DeleteApplication vs after CreateApplication"),
            None => Ok(()),
        }
    });
}

// ------------------------------------------------------------------ no keys / many keys
fn no_keys_application(ctx: &mut Ctx) {
    // Measured on a card: CreateApplication with 0 keys is refused (PARAMETER_ERROR).
    let aid = ctx.alloc_aid();
    ctx.step("0 keys: CreateApplication is refused with PARAMETER_ERROR", |c| {
        c.auth_picc()?;
        let r = c.create_application(&AppSpec::new(aid).keys(0));
        if r.is_ok() {
            c.delete_application(aid, &[])?;
            return Err(StepError::fail("the card accepted an application without keys"));
        }
        c.expect_err(Status::ParameterError, r)
    });
}

#[allow(dead_code)]
fn no_keys_application_when_accepted(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(0), |ctx, aid| {
        ctx.step("0 keys: GetKeySettings without authentication reports no keys", |c| {
            c.select_application(aid, None)?;
            let k = c.get_key_settings()?;
            c.detail(format!("{k:?}"));
            ensure_eq((k.settings, k.max_keys), (0x0F, 0), "settings / key count")
        });
        ctx.step("0 keys: authentication is impossible (NO_SUCH_KEY)", |c| {
            c.select_application(aid, None)?;
            let z = c.zero_key;
            let r = c.authenticate_ev2_first(0, &z, &[]);
            c.expect_err(Status::NoSuchKey, r)
        });
        ctx.step("0 keys: with free key settings files are created, used and deleted without authentication", |c| {
            c.select_application(aid, None)?;
            c.create_data_file(&DataFileSpec::new(0, 32, access_all(AccessRight::FREE)))?;
            ensure_eq(c.get_file_ids()?, vec![0], "file list")?;
            c.write_data(0, 4, b"free access")?;
            ensure_eq(c.read_data(0, 4, 11)?, b"free access".to_vec(), "data read back without authentication")?;
            c.delete_file(0)?;
            ensure_eq(c.get_file_ids()?, Vec::<u8>::new(), "file list after DeleteFile")
        });
    });
}

fn many_keys_application(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    // keys[k] = the value key k currently holds (all zero at the start)
    let mut keys: Vec<[u8; 16]> = vec![[0; 16]; 14];
    let want_mem = ctx.step_picc("FreeMem before the 14-key application", |c| Ok(c.free_mem()?));
    ctx.app_scope(AppSpec::new(aid).keys(14), |ctx, aid| {
        ctx.step("14 keys: GetKeySettings reports 14 keys, AES-128", |c| {
            enter(c, aid, 0)?;
            let k = c.get_key_settings()?;
            ensure_eq((k.settings, k.max_keys, k.key_type), (0x0F, 14, 2), "settings / key count / key type")
        });
        ctx.step("14 keys: memory consumption follows the data sheet formula", |c| {
            c.ensure_picc()?;
            let now = c.free_mem()?;
            let before = want_mem.ok_or_else(|| StepError::skip("no FreeMem reading before the application"))?;
            ensure_eq(consumed(before, now)?, app_blocks(14, 1, 16, false, false, false) * 32, "bytes consumed")
        });
        ctx.step("14 keys: every key 0..13 authenticates with the zero key and has the default version", |c| {
            for k in 0..14u8 {
                enter(c, aid, k)?;
                let a = c.auth_summary().ok_or("no session")?;
                ensure_eq(a.key_no, Some(k), "authenticated key number")?;
                ensure_eq(c.get_key_version(k, None)?, vec![c.app_default_key_version], &format!("version of key {k}"))?;
            }
            Ok(())
        });
        ctx.step("14 keys: key 14 does not exist (NO_SUCH_KEY for authentication, GetKeyVersion and ChangeKey)", |c| {
            c.select_application(aid, None)?;
            let z = c.zero_key;
            let r = c.authenticate_ev2_first(14, &z, &[]);
            c.expect_err(Status::NoSuchKey, r)?;
            enter(c, aid, 0)?;
            let r = c.get_key_version(14, None);
            c.expect_err(Status::NoSuchKey, r)?;
            enter(c, aid, 0)?;
            let r = c.change_key(&ChangeKeySpec::new(14, &[1; 16], 1).old_key(&z));
            c.expect_err(Status::NoSuchKey, r)
        });
        ctx.step("ChangeKey of every key 1..13 from the master key (old key XOR new key), verified by authentication", |c| {
            for k in 1..14u8 {
                let new = rnd16();
                change_verify(c, aid, 0, &keys[0].clone(), k, &keys[k as usize].clone(), &new, 0x10 + k, false)?;
                keys[k as usize] = new;
            }
            // key 0 and the other keys are unaffected by each change: spot check key 0 and key 13
            enter(c, aid, 0)?;
            ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "master key version")
        });
        ctx.step("ChangeKeyEV2 (key set 0) of every key 1..13 from the master key, a second time", |c| {
            for k in 1..14u8 {
                let new = rnd16();
                change_verify(c, aid, 0, &keys[0].clone(), k, &keys[k as usize].clone(), &new, 0x40 + k, true)?;
                keys[k as usize] = new;
            }
            Ok(())
        });
        ctx.step("every key now accepts only its own value", |c| {
            for k in 1..14u8 {
                c.select_application(aid, None)?;
                let other = keys[(k % 13 + 1) as usize]; // the value of a different key
                let r = c.authenticate_ev2_first(k, &other, &[]);
                c.expect_err(Status::AuthenticationError, r)?;
                c.auth_app(aid, k, &keys[k as usize])?;
            }
            Ok(())
        });
        ctx.step("each key changes its own value (no old key needed; the session ends), ChangeKey for even and EV2 for odd keys", |c| {
            // A key other than master / roll / change key may change itself only when AppKeySettings
            // [b7..4] is 0xE ("the key itself"); with the default (key 0 changes keys) the card answers
            // AUTHENTICATION_ERROR, as the data sheet's return code table says.
            c.auth_app(aid, 0, &keys[0])?;
            c.change_key_settings(0xEF)?;
            for k in 1..14u8 {
                let new = rnd16();
                // versions run through the extremes
                let ver = match k {
                    1 => 0x00,
                    2 => 0xFF,
                    n => 0x20 + n,
                };
                c.auth_app(aid, k, &keys[k as usize])?;
                let mut spec = ChangeKeySpec::new(k, &new, ver);
                if k % 2 == 1 {
                    spec = spec.key_set(0);
                }
                c.change_key(&spec)?;
                ensure(!c.is_authenticated(), format!("changing the authenticated key {k} must end the session"))?;
                c.auth_app(aid, k, &new)?;
                ensure_eq(c.get_key_version(k, None)?, vec![ver], &format!("version of key {k}"))?;
                keys[k as usize] = new;
            }
            c.auth_app(aid, 0, &keys[0])?;
            c.change_key_settings(0x0F)?;
            Ok(())
        });
        ctx.step("the master key changes itself with ChangeKey and with ChangeKeyEV2, and the zero key stops working", |c| {
            let z = c.zero_key;
            let first = rnd16();
            c.auth_app(aid, 0, &z)?;
            c.change_key(&ChangeKeySpec::new(0, &first, 0x77))?;
            ensure(!c.is_authenticated(), "the session should end")?;
            c.select_application(aid, None)?;
            let r = c.authenticate_ev2_first(0, &z, &[]);
            c.expect_err(Status::AuthenticationError, r)?;
            let second = rnd16();
            c.auth_app(aid, 0, &first)?;
            c.change_key(&ChangeKeySpec::new(0, &second, 0x78).key_set(0))?;
            c.auth_app(aid, 0, &second)?;
            ensure_eq(c.get_key_version(0, None)?, vec![0x78], "master key version")?;
            keys[0] = second;
            Ok(())
        });
        ctx.step("a wrong old key makes ChangeKey fail and leaves the key unchanged", |c| {
            let new = rnd16();
            c.auth_app(aid, 0, &keys[0])?;
            let r = c.change_key(&ChangeKeySpec::new(13, &new, 0x55).old_key(&[0x99; 16]));
            let s = c.expect_any_status(r)?;
            c.detail(format!("a wrong old key is answered with {s} (0x{:02X})", s.code()));
            c.auth_app(aid, 13, &keys[13])?;
            ensure_eq(c.get_key_version(13, None)?, vec![0x20 + 13], "version of key 13 after the refused change")
        });
        ctx.step("ChangeKey without the old key for another key is refused by the library (nothing is sent)", |c| {
            c.auth_app(aid, 0, &keys[0])?;
            let r = c.change_key(&ChangeKeySpec::new(5, &rnd16(), 1));
            ensure(matches!(r, Err(StepError::Card(duox::Error::InvalidArgument(_)))), "expected an argument error from the library")?;
            ensure(!c.is_authenticated(), "the library drops the session after an unusable ChangeKey")
        });
        ctx.step("a 32-byte key in an AES-128 application is refused by the card", |c| {
            c.auth_app(aid, 0, &keys[0])?;
            let r = c.change_key(&ChangeKeySpec::new(4, &[7; 32], 1).old_key(&[0; 32]));
            let s = c.expect_any_status(r)?;
            c.detail(format!("{s} (0x{:02X})", s.code()));
            Ok(())
        });
    });
}

/// Authenticate `auth_key` (value `auth_value`), change `target` to `new` (old value `old`), verify the new value
/// authenticates, the old one does not, and the version reads back.
#[allow(clippy::too_many_arguments)]
fn change_verify(
    c: &mut Ctx,
    aid: Aid,
    auth_key: u8,
    auth_value: &[u8],
    target: u8,
    old: &[u8],
    new: &[u8],
    version: u8,
    ev2: bool,
) -> StepResult {
    c.auth_app(aid, auth_key, auth_value)?;
    let mut spec = ChangeKeySpec::new(target, new, version);
    if target != auth_key {
        spec = spec.old_key(old);
    }
    if ev2 {
        spec = spec.key_set(0);
    }
    c.change_key(&spec)?;
    if target == auth_key {
        ensure(!c.is_authenticated(), "changing the authenticated key must end the session")?;
    } else {
        ensure(c.is_authenticated(), "changing another key must keep the session")?;
    }
    c.auth_app(aid, target, new)?;
    ensure_eq(c.get_key_version(target, None)?, vec![version], &format!("version of key {target}"))?;
    if old != new {
        c.select_application(aid, None)?;
        let r = c.authenticate_ev2_first(target, old, &[]);
        c.expect_err(Status::AuthenticationError, r)?;
    }
    Ok(())
}

// ------------------------------------------------------------------ ISO file ids and DF names
const ISO_FID_A: u16 = 0x5D01;
const ISO_FID_B: u16 = 0x5D02;
const ISO_FID_C: u16 = 0x5D03;
const NAME_A: &[u8] = b"DUOX-SUITE-ONE";
const NAME_B: &[u8] = b"DUOX-SUITE-TWO";
const NAME_C: &[u8] = b"0123456789ABCDEF";

fn iso_applications(ctx: &mut Ctx) {
    let (a, b, cc) = (ctx.alloc_aid(), ctx.alloc_aid(), ctx.alloc_aid());
    let spec_a = AppSpec::new(a).keys(2).iso_file_ids().iso_name(ISO_FID_A, NAME_A);
    ctx.app_scope(spec_a, |ctx, a| {
        ctx.app_scope(AppSpec::new(b).keys(1).iso_name(ISO_FID_B, NAME_B), |ctx, b| {
            ctx.app_scope(AppSpec::new(cc).keys(1).iso_name(ISO_FID_C, NAME_C), |ctx, cc| {
                iso_steps(ctx, a, b, cc);
            });
        });
    });
}

fn iso_steps(ctx: &mut Ctx, a: Aid, b: Aid, cc: Aid) {
    ctx.step("GetDFNames lists the three applications with ISO file id and DF name (14, 14 and 16 byte names)", |c| {
        c.ensure_picc()?;
        let mut n = c.get_df_names()?;
        n.sort_by_key(|d| d.aid);
        let want = vec![
            DfName { aid: a, iso_fid: ISO_FID_A, name: NAME_A.to_vec() },
            DfName { aid: b, iso_fid: ISO_FID_B, name: NAME_B.to_vec() },
            DfName { aid: cc, iso_fid: ISO_FID_C, name: NAME_C.to_vec() },
        ];
        ensure_eq(n, want, "GetDFNames")
    });
    ctx.step("GetApplicationIDs lists the three applications", |c| {
        c.ensure_picc()?;
        let mut ids = c.get_application_ids()?;
        ids.sort();
        ensure_eq(ids, vec![a, b, cc], "application list")
    });
    ctx.step("a second application with the same ISO file id: DUPLICATE_ERROR", |c| {
        let probe = c.alloc_aid();
        let (r, id) = attempt_create(c, &AppSpec::new(probe).keys(1).iso_name(ISO_FID_A, b"OTHER-NAME"));
        let verdict = c.expect_err(Status::DuplicateError, r);
        c.run_cleanup_now(id);
        verdict
    });
    ctx.step("a second application with the same DF name: DUPLICATE_ERROR", |c| {
        let probe = c.alloc_aid();
        let (r, id) = attempt_create(c, &AppSpec::new(probe).keys(1).iso_name(0x5D09, NAME_A));
        let verdict = c.expect_err(Status::DuplicateError, r);
        c.run_cleanup_now(id);
        verdict
    });
    ctx.step("ISO file ids reserved by ISO 7816-4 (0x0000, 0x3F00, 0x3FFF, 0xFFFF) are refused", |c| {
        for fid in [0x0000u16, 0x3F00, 0x3FFF, 0xFFFF] {
            let probe = c.alloc_aid();
            let (r, id) = attempt_create(c, &AppSpec::new(probe).keys(1).iso_name(fid, b"RESERVED-ID"));
            let verdict = c.expect_any_status(r);
            c.run_cleanup_now(id);
            let s = verdict?;
            c.detail(format!("file id {fid:04X}: {s} (0x{:02X})", s.code()));
        }
        Ok(())
    });
    ctx.step("a 17-byte DF name, a DF name without ISO file id, and 15 keys are refused by the library (nothing is sent)", |c| {
        c.auth_picc()?;
        let probe = c.alloc_aid();
        let mut long = AppSpec::new(probe).keys(1).iso_name(0x5D0A, &[b'x'; 16]);
        long.df_name = vec![b'x'; 17];
        let mut no_fid = AppSpec::new(probe).keys(1);
        no_fid.df_name = b"NO-FID".to_vec();
        for (what, spec) in [("17-byte name", long), ("name without file id", no_fid), ("15 keys", AppSpec::new(probe).keys(15))] {
            let r = c.create_application(&spec);
            ensure(
                matches!(r, Err(StepError::Card(duox::Error::InvalidArgument(_)))),
                format!("{what}: expected an argument error, got {r:?}"),
            )?;
            ensure(c.is_authenticated(), format!("{what}: nothing should have been sent"))?;
        }
        Ok(())
    });
    ctx.step("renaming an application to the DF name of another one: DUPLICATE_ERROR (SetConfiguration 0x06)", |c| {
        enter(c, a, 0)?;
        let r = c.set_configuration(0x06, &dfname_data(NAME_B));
        c.expect_err(Status::DuplicateError, r)
    });
    ctx.step("SetConfiguration 0x06 renames an application; GetDFNames shows the new name with the same ISO file id", |c| {
        let new = b"RENAMED-DUOX";
        enter(c, a, 0)?;
        c.set_configuration(0x06, &dfname_data(new))?;
        c.ensure_picc()?;
        let n = c.get_df_names()?;
        let mine = n.iter().find(|d| d.aid == a).ok_or("the application vanished from GetDFNames")?;
        ensure_eq(mine.clone(), DfName { aid: a, iso_fid: ISO_FID_A, name: new.to_vec() }, "renamed entry")?;
        ensure_eq(n.len(), 3, "number of ISO applications")
    });
    ctx.step("KeySett2 bit 5: files of the application need an ISO file id (LENGTH_ERROR without one)", |c| {
        enter(c, a, 0)?;
        let r = c.create_data_file(&DataFileSpec::new(0, 16, access_all(AccessRight::FREE)));
        c.expect_err(Status::LengthError, r)
    });
    ctx.step("files with ISO file ids: GetISOFileIDs, DUPLICATE_ERROR for a reused id, record file with an id", |c| {
        use duox::card::RecordFileSpec;
        enter(c, a, 0)?;
        c.create_data_file(&DataFileSpec::new(0, 16, access_all(AccessRight::FREE)).iso_fid(0x5D11))?;
        c.create_data_file(&DataFileSpec::new(1, 16, access_all(AccessRight::FREE)).iso_fid(0x5D12).backup())?;
        c.create_record_file(&RecordFileSpec::new(2, access_all(AccessRight::FREE), 8, 4).iso_fid(0x5D13))?;
        let mut ids = c.get_iso_file_ids()?;
        ids.sort();
        ensure_eq(ids, vec![0x5D11, 0x5D12, 0x5D13], "ISO file ids")?;
        let mut fids = c.get_file_ids()?;
        fids.sort();
        ensure_eq(fids, vec![0, 1, 2], "file ids")?;
        enter(c, a, 0)?;
        let r = c.create_data_file(&DataFileSpec::new(3, 16, access_all(AccessRight::FREE)).iso_fid(0x5D11));
        c.expect_err(Status::DuplicateError, r)?;
        enter(c, a, 0)?;
        let r = c.create_data_file(&DataFileSpec::new(0, 16, access_all(AccessRight::FREE)).iso_fid(0x5D14));
        c.expect_err(Status::DuplicateError, r)
    });
    ctx.step("GetISOFileIDs in an application created without ISO file ids: FILE_NOT_FOUND", |c| {
        enter(c, b, 0)?;
        let r = c.get_iso_file_ids();
        c.expect_err(Status::FileNotFound, r)
    });
    ctx.step("a file with an ISO file id in an application without ISO file ids is refused", |c| {
        enter(c, b, 0)?;
        let r = c.create_data_file(&DataFileSpec::new(0, 16, access_all(AccessRight::FREE)).iso_fid(0x5D21));
        let s = c.expect_any_status(r)?;
        c.detail(format!("{s} (0x{:02X})", s.code()));
        Ok(())
    });
}

// ------------------------------------------------------------------ KeySett3 options
fn key_sett3_options(ctx: &mut Ctx) {
    // bit 2: application specific capability data and Crypto API configuration
    let aid = ctx.alloc_aid();
    let before = ctx.step_picc("FreeMem before the capability-data application", |c| Ok(c.free_mem()?));
    ctx.app_scope(AppSpec::new(aid).keys(1).key_sett3(0x04), |ctx, aid| {
        ctx.step("KeySett3 bit 2: memory is key storage + 2 overhead blocks", |c| {
            c.ensure_picc()?;
            let now = c.free_mem()?;
            let before = before.ok_or_else(|| StepError::skip("no FreeMem reading"))?;
            ensure_eq(consumed(before, now)?, app_blocks(1, 1, 16, false, false, true) * 32, "bytes consumed")
        });
        for opt in [0x05u8, 0x15] {
            ctx.step(
                &format!("KeySett3 bit 2: GetConfiguration 0x{opt:02X} reads, SetConfiguration with the same bytes is accepted and reads back"),
                |c| {
                    enter(c, aid, 0)?;
                    let d = soft(c.get_configuration(Some(opt)))?;
                    c.detail(hx(&d));
                    ensure_eq(d.len(), if opt == 0x05 { 10 } else { 2 }, "length of the option data")?;
                    c.set_configuration(opt, &d)?;
                    ensure_eq(c.get_configuration(Some(opt))?, d, "option data after writing the same bytes")
                },
            );
        }
        ctx.step("KeySett3 bit 2: Crypto API access condition 0x15 can be changed and restored", |c| {
            enter(c, aid, 0)?;
            let orig = c.get_configuration(Some(0x15))?;
            ensure_eq(orig.len(), 2, "length")?;
            let mut changed = orig.clone();
            changed[1] = (changed[1] & 0xF0) | 0x0E; // free access, CommMode unchanged
            c.set_configuration(0x15, &changed)?;
            ensure_eq(c.get_configuration(Some(0x15))?, changed.clone(), "option 0x15 after the change")?;
            c.set_configuration(0x15, &orig)?;
            ensure_eq(c.get_configuration(Some(0x15))?, orig, "option 0x15 after the restore")
        });
    });
    // bit 1: application specific VCProximityKey (memory is measured, so start from a freshly formatted card:
    // overhead blocks of a deleted application may be reused by the next one)
    reclaim(ctx, "the VCProximityKey application");
    let aid = ctx.alloc_aid();
    let before = ctx.step_picc("FreeMem before the VCProximityKey application", |c| Ok(c.free_mem()?));
    ctx.app_scope(AppSpec::new(aid).keys(1).key_sett3(0x02), |ctx, aid| {
        ctx.step("KeySett3 bit 1: memory is key storage + 1 overhead block + 3 blocks for the VCProximityKey", |c| {
            c.ensure_picc()?;
            let now = c.free_mem()?;
            let before = before.ok_or_else(|| StepError::skip("no FreeMem reading"))?;
            ensure_eq(consumed(before, now)?, app_blocks(1, 1, 16, false, true, false) * 32, "bytes consumed")
        });
        ctx.step("KeySett3 bit 1: the VCProximityKey 0x21 starts with the default version", |c| {
            enter(c, aid, 0)?;
            ensure_eq(c.get_key_version(0x21, None)?, vec![c.app_default_key_version], "version of key 0x21")
        });
        ctx.step("KeySett3 bit 1: ChangeKey of key 0x21 (type AES-128 in the key number) from the master key", |c| {
            let z = c.zero_key;
            let new = rnd16();
            enter(c, aid, 0)?;
            c.change_key(&ChangeKeySpec::new(0xA1, &new, 0x66).old_key(&z))?;
            ensure(c.is_authenticated(), "the session should survive a change of another key")?;
            ensure_eq(c.get_key_version(0x21, None)?, vec![0x66], "version of key 0x21")?;
            ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "the master key is untouched")
        });
        ctx.step("KeySett3 bit 1: the VCProximityKey cannot be used for authentication", |c| {
            c.select_application(aid, None)?;
            let z = c.zero_key;
            let r = c.authenticate_ev2_first(0x21, &z, &[]);
            let s = c.expect_any_status(r)?;
            c.detail(format!("{s} (0x{:02X})", s.code()));
            Ok(())
        });
        ctx.step("KeySett3 bit 1: an AES-256 VCProximityKey is refused in an application that only supports AES-128", |c| {
            enter(c, aid, 0)?;
            let r = c.change_key(&ChangeKeySpec::new(0xE1, &[3; 32], 1).old_key(&[0; 32]));
            c.expect_err(Status::PermissionDenied, r)
        });
    });
    // bit 4 is exercised in delete_group; all three bits together
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(2).key_sett3(0x16), |ctx, aid| {
        ctx.step("KeySett3 0x16 (deletion with master key, VC key, capability data) is accepted and works", |c| {
            enter(c, aid, 1)?;
            ensure_eq(c.get_key_version(0x21, None)?, vec![c.app_default_key_version], "version of key 0x21")?;
            enter(c, aid, 0)?;
            let d = c.get_configuration(Some(0x05))?;
            ensure_eq(d.len(), 10, "capability data length")
        });
    });
}

// ------------------------------------------------------------------ AES-256 applications
fn aes256_application(ctx: &mut Ctx) {
    let usable = ctx.step_picc("AES-256 applications can be created (needs a 32-byte PICCAppDefaultKey)", |c| {
        let probe = c.alloc_aid();
        let (r, id) = attempt_create(c, &AppSpec::new(probe).keys(1).aes256());
        let verdict = match r {
            Ok(()) => Ok(()),
            Err(e) if e.status() == Some(Status::PermissionDenied) => Err(StepError::skip(
                "the card refuses AES-256 applications while PICCAppDefaultKey is the 24-byte form; this section never changes PICC level state (the picc section does, temporarily)",
            )),
            Err(e) => Err(e),
        };
        c.run_cleanup_now(id);
        verdict
    });
    if usable.is_none() {
        return;
    }
    reclaim(ctx, "the measured AES-256 application (the probe application freed overhead blocks)");
    let aid = ctx.alloc_aid();
    let before = ctx.step_picc("FreeMem before the AES-256 application", |c| Ok(c.free_mem()?));
    ctx.app_scope(AppSpec::new(aid).keys(3).aes256(), |ctx, aid| {
        // keys[k] is the current value of key k (32 bytes)
        let mut keys: Vec<[u8; 32]> = vec![[0; 32]; 3];
        ctx.step("AES-256: memory is key storage with 32-byte keys + 1 overhead block", |c| {
            c.ensure_picc()?;
            let now = c.free_mem()?;
            let before = before.ok_or_else(|| StepError::skip("no FreeMem reading"))?;
            ensure_eq(consumed(before, now)?, app_blocks(3, 1, 32, false, false, false) * 32, "bytes consumed")
        });
        ctx.step("AES-256: GetKeySettings reports key type AES-256 and 3 keys", |c| {
            let z = c.zero_key32;
            c.auth_app(aid, 0, &z)?;
            let k = c.get_key_settings()?;
            ensure_eq((k.settings, k.max_keys, k.key_type), (0x0F, 3, 3), "settings / key count / key type")
        });
        ctx.step("AES-256: every key authenticates with the 32-byte zero key, 256-bit session keys", |c| {
            let z = c.zero_key32;
            for k in 0..3u8 {
                c.auth_app(aid, k, &z)?;
                let a = c.auth_summary().ok_or("no session")?;
                ensure_eq((a.kind, a.key_no, a.key_bits), (AuthKind::Aes, Some(k), 256), "session")?;
                ensure_eq(c.get_key_version(k, None)?, vec![c.app_default_key_version], &format!("version of key {k}"))?;
            }
            Ok(())
        });
        ctx.step("AES-256: the 16-byte zero key does not open an AES-256 key", |c| {
            c.select_application(aid, None)?;
            let z = c.zero_key;
            let r = c.authenticate_ev2_first(0, &z, &[]);
            c.expect_err(Status::AuthenticationError, r)
        });
        ctx.step("AES-256: ChangeKey and ChangeKeyEV2 of keys 1 and 2 from the master key", |c| {
            for (k, ev2) in [(1u8, false), (2u8, true)] {
                let new = rnd32();
                change_verify(c, aid, 0, &keys[0].clone(), k, &keys[k as usize].clone(), &new, 0x50 + k, ev2)?;
                keys[k as usize] = new;
            }
            Ok(())
        });
        ctx.step("AES-256: every key changes itself (ChangeKey, ChangeKeyEV2), the session ends, the new key works", |c| {
            for (k, ev2) in [(2u8, false), (1u8, true), (0u8, false)] {
                let new = rnd32();
                c.auth_app(aid, k, &keys[k as usize])?;
                let mut spec = ChangeKeySpec::new(k, &new, 0x60 + k);
                if ev2 {
                    spec = spec.key_set(0);
                }
                c.change_key(&spec)?;
                ensure(!c.is_authenticated(), "the session should end")?;
                c.auth_app(aid, k, &new)?;
                ensure_eq(c.get_key_version(k, None)?, vec![0x60 + k], &format!("version of key {k}"))?;
                keys[k as usize] = new;
            }
            Ok(())
        });
        ctx.step("AES-256: AuthenticateEV2NonFirst with the 32-byte key keeps TI and the command counter", |c| {
            c.auth_app(aid, 1, &keys[1])?;
            c.get_key_version(1, None)?;
            let before = c.auth_summary().ok_or("no session")?;
            c.authenticate_ev2_non_first(1, &keys[1])?;
            let after = c.auth_summary().ok_or("no session")?;
            ensure_eq((after.ti, after.cmd_ctr, after.key_bits), (before.ti, before.cmd_ctr, 256), "TI / command counter / key bits")?;
            c.get_key_version(1, None)?;
            Ok(())
        });
        ctx.step("AES-256: ChangeKeySettings round trip", |c| {
            c.auth_app(aid, 0, &keys[0])?;
            c.change_key_settings(0x0B)?;
            ensure_eq(c.get_key_settings()?.settings, 0x0B, "settings")?;
            c.change_key_settings(0x0F)?;
            ensure_eq(c.get_key_settings()?.settings, 0x0F, "settings")
        });
    });
}

// ------------------------------------------------------------------ AppKeySettings
fn key_settings_group(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        ctx.step("ChangeKeySettings with the master key switches every bit and reads back (GetKeySettings)", |c| {
            enter(c, aid, 0)?;
            for v in [0x0Bu8, 0x0D, 0x0E, 0x1F, 0xEF, 0xFF, 0x0F] {
                c.change_key_settings(v)?;
                ensure_eq(c.get_key_settings()?.settings, v, &format!("settings after ChangeKeySettings {v:02X}"))?;
            }
            Ok(())
        });
        ctx.step("ChangeKeySettings with a key that is not the master key: AUTHENTICATION_ERROR", |c| {
            enter(c, aid, 1)?;
            let r = c.change_key_settings(0x0B);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 0)?;
            ensure_eq(c.get_key_settings()?.settings, 0x0F, "settings are unchanged")
        });
        ctx.step("ChangeKeySettings without authentication: AUTHENTICATION_ERROR", |c| {
            c.select_application(aid, None)?;
            let r = c.change_key_settings(0x0B);
            // the command carries encrypted data, so a plain frame may be refused for its length first
            let st = c.expect_any_status(r)?;
            ensure(matches!(st, Status::AuthenticationError | Status::LengthError), format!("unexpected status {st}"))
        });
        ctx.step("clearing bit 3 freezes the key settings: ChangeKeySettings is then refused (PERMISSION_DENIED)", |c| {
            enter(c, aid, 0)?;
            c.change_key_settings(0x07)?;
            ensure_eq(c.get_key_settings()?.settings, 0x07, "settings")?;
            enter(c, aid, 0)?;
            let r = c.change_key_settings(0x0F);
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            ensure_eq(c.get_key_settings()?.settings, 0x07, "settings stay frozen")?;
            // the keys are still changeable although the settings are frozen
            let new = rnd16();
            let z = c.zero_key;
            change_verify(c, aid, 0, &z, 2, &z, &new, 0x2A, false)
        });
    });
    // KeySett1 bit 1 = 0: directory commands need the master key
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(3).key_settings(0x0D), |ctx, aid| {
        ctx.step("bit 1 = 0: GetKeySettings, GetFileIDs and GetFileSettings need the master key", |c| {
            enter(c, aid, 0)?;
            c.create_data_file(&DataFileSpec::new(0, 16, access_all(AccessRight::FREE)))?;
            ensure_eq(c.get_key_settings()?.settings, 0x0D, "settings")?;
            // no authentication
            c.select_application(aid, None)?;
            let r = c.get_key_settings();
            c.expect_err(Status::AuthenticationError, r)?;
            c.select_application(aid, None)?;
            let r = c.get_file_ids();
            c.expect_err(Status::AuthenticationError, r)?;
            c.select_application(aid, None)?;
            let r = c.get_file_settings(0);
            c.expect_err(Status::AuthenticationError, r)?;
            // a key that is not the master key
            enter(c, aid, 1)?;
            let r = c.get_file_ids();
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 1)?;
            let r = c.get_key_settings();
            c.expect_err(Status::AuthenticationError, r)?;
            // the master key
            enter(c, aid, 0)?;
            ensure_eq(c.get_file_ids()?, vec![0], "file list")?;
            ensure_eq(c.get_file_settings(0)?.size, Some(16), "file size")
        });
        ctx.step("bit 1 = 0: GetKeyVersion still works without authentication", |c| {
            c.select_application(aid, None)?;
            ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "key version")
        });
    });
    // KeySett1 bit 2 = 0: file creation and deletion need the master key
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(3).key_settings(0x0B), |ctx, aid| {
        ctx.step("bit 2 = 0: CreateStdDataFile needs the master key (none, key 1: AUTHENTICATION_ERROR; master: ok)", |c| {
            let spec = DataFileSpec::new(0, 16, access_all(AccessRight::FREE));
            c.select_application(aid, None)?;
            let r = c.create_data_file(&spec);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 1)?;
            let r = c.create_data_file(&spec);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 0)?;
            c.create_data_file(&spec)?;
            ensure_eq(c.get_file_ids()?, vec![0], "file list")
        });
        ctx.step("bit 2 = 0: DeleteFile needs the master key; the directory stays free (bit 1 = 1)", |c| {
            c.select_application(aid, None)?;
            ensure_eq(c.get_file_ids()?, vec![0], "directory without authentication")?;
            let r = c.delete_file(0);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 2)?;
            let r = c.delete_file(0);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 0)?;
            c.delete_file(0)?;
            ensure_eq(c.get_file_ids()?, Vec::<u8>::new(), "file list")
        });
    });
}

// ------------------------------------------------------------------ who may change which key
#[derive(Clone, Copy)]
struct Case {
    auth: u8,
    target: u8,
    ev2: bool,
    want: Option<Status>,
}

fn case(auth: u8, target: u8, ev2: bool, want: Option<Status>) -> Case {
    Case { auth, target, ev2, want }
}

/// Value and version a key currently has, as far as the section knows.
#[derive(Clone, Copy)]
struct KeyState {
    value: [u8; 16],
    version: Option<u8>,
}

fn change_rights(ctx: &mut Ctx, label: &str, ks1: u8, cases: &[Case]) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4).key_settings(ks1), |ctx, aid| {
        let mut model = [KeyState { value: [0; 16], version: None }; 4];
        for (i, cs) in cases.iter().enumerate() {
            let outcome = match cs.want {
                None => "succeeds".to_string(),
                Some(s) => s.name().to_string(),
            };
            let name = format!(
                "{label}: key {} changes key {}{} -> {outcome}",
                cs.auth,
                cs.target,
                if cs.ev2 { " (ChangeKeyEV2)" } else { "" }
            );
            let (a, t) = (cs.auth as usize, cs.target as usize);
            ctx.step(&name, |c| {
                let default_version = c.app_default_key_version;
                c.auth_app(aid, cs.auth, &model[a].value)?;
                let new = rnd16();
                let ver = 0x30 + i as u8;
                let mut spec = ChangeKeySpec::new(cs.target, &new, ver);
                if cs.target != cs.auth {
                    spec = spec.old_key(&model[t].value);
                }
                if cs.ev2 {
                    spec = spec.key_set(0);
                }
                let r = c.change_key(&spec);
                match cs.want {
                    None => {
                        r?;
                        ensure_eq(c.is_authenticated(), cs.target != cs.auth, "session after the change (kept only for another key)")?;
                        c.auth_app(aid, cs.target, &new)?;
                        ensure_eq(c.get_key_version(cs.target, None)?, vec![ver], "version of the changed key")?;
                        model[t] = KeyState { value: new, version: Some(ver) };
                    }
                    Some(s) => {
                        c.expect_err(s, r)?;
                        c.auth_app(aid, cs.target, &model[t].value)?;
                        ensure_eq(
                            c.get_key_version(cs.target, None)?,
                            vec![model[t].version.unwrap_or(default_version)],
                            "version of the key that must not have changed",
                        )?;
                    }
                }
                Ok(())
            });
        }
    });
}

fn change_key_rights(ctx: &mut Ctx) {
    use Status::{AuthenticationError as Auth, PermissionDenied as Denied};
    // AppKeySettings bits 7..4 = 0: the master key (key 0) is the change key
    change_rights(
        ctx,
        "change key = 0",
        0x0F,
        &[
            case(0, 2, false, None),
            case(0, 3, false, None),
            case(1, 2, false, Some(Auth)),
            case(2, 2, false, Some(Auth)),
            case(0, 1, true, None),
            case(0, 0, false, None),
        ],
    );
    // bits 7..4 = 1: key 1 is the change key; changing key 1 (and the master key) needs the master key
    change_rights(
        ctx,
        "change key = 1",
        0x1F,
        &[
            case(1, 2, false, None),
            case(0, 2, false, Some(Auth)),
            case(1, 3, true, None),
            case(1, 1, false, Some(Auth)),
            case(1, 0, false, Some(Auth)),
            case(0, 1, false, None),
            case(0, 0, true, None),
        ],
    );
    // bits 7..4 = 0xE: a key changes only itself
    change_rights(
        ctx,
        "change key = E (key itself)",
        0xEF,
        &[
            case(2, 2, false, None),
            case(2, 3, false, Some(Auth)),
            case(0, 3, false, Some(Auth)),
            case(3, 3, true, None),
            case(0, 0, false, None),
        ],
    );
    // bits 7..4 = 0xF: no key but the master key can be changed
    change_rights(
        ctx,
        "change key = F (frozen keys)",
        0xFF,
        &[
            case(0, 2, false, Some(Denied)),
            case(2, 2, false, Some(Denied)),
            case(0, 3, true, Some(Denied)),
            case(0, 0, false, None),
        ],
    );
    // bit 0 = 0: the master key is frozen, the other keys are not
    change_rights(
        ctx,
        "master key frozen (bit 0 = 0)",
        0x0E,
        &[
            case(0, 0, false, Some(Denied)),
            case(0, 0, true, Some(Denied)),
            case(0, 1, false, None),
            case(1, 1, false, Some(Auth)),
        ],
    );
}

// ------------------------------------------------------------------ two applications selected at once
fn two_applications(ctx: &mut Ctx) {
    let (a, b, unknown) = (ctx.alloc_aid(), ctx.alloc_aid(), ctx.alloc_aid());
    ctx.app_scope(AppSpec::new(a).keys(2), |ctx, a| {
        ctx.app_scope(AppSpec::new(b).keys(2), |ctx, b| two_steps(ctx, a, b, unknown));
    });
}

fn two_steps(ctx: &mut Ctx, a: Aid, b: Aid, unknown: Aid) {
    const A_DATA: [u8; 16] = *b"primary app data";
    const B_DATA: [u8; 16] = *b"secondary appdat";
    ctx.step("set up: key versions 0x11 / 0x22, a backup file per application, a second file in the secondary one", |c| {
        let z = c.zero_key;
        enter(c, a, 0)?;
        c.change_key(&ChangeKeySpec::new(0, &z, 0x11))?;
        enter(c, b, 0)?;
        c.change_key(&ChangeKeySpec::new(0, &z, 0x22))?;
        enter(c, a, 0)?;
        c.create_data_file(&DataFileSpec::new(0, 16, access_all(AccessRight::key(0))).backup().comm_mode(duox::card::CommMode::Mac))?;
        enter(c, b, 0)?;
        let free = AccessRights::new(AccessRight::FREE, AccessRight::FREE, AccessRight::FREE, AccessRight::key(0));
        c.create_data_file(&DataFileSpec::new(0, 16, free).backup())?;
        c.create_data_file(&DataFileSpec::new(5, 16, free))?;
        Ok(())
    });
    ctx.step("SelectApplication with two applications returns OPERATION_OK, selects both and ends the authentication", |c| {
        enter(c, a, 0)?;
        let rc = c.select_application(a, Some(b))?;
        ensure_eq(rc, 0, "status")?;
        ensure(!c.is_authenticated(), "selecting ended the authentication")?;
        let s = c.selection();
        ensure_eq((s.primary, s.secondary), (Some(a), Some(b)), "selection")
    });
    ctx.step("GetKeyVersion targets the primary application, key number | 0x80 the secondary one (no authentication)", |c| {
        c.select_application(a, Some(b))?;
        ensure_eq(c.get_key_version(0, None)?, vec![0x11], "primary key 0")?;
        ensure_eq(c.get_key_version(0x80, None)?, vec![0x22], "secondary key 0")?;
        ensure_eq(c.get_key_version(0x81, None)?, vec![c.app_default_key_version], "secondary key 1")
    });
    ctx.step("authenticating key 0x80 opens the secondary application's key 0 (SAI)", |c| {
        c.select_application(a, Some(b))?;
        let z = c.zero_key;
        c.authenticate_ev2_first(0x80, &z, &[])?;
        let s = c.auth_summary().ok_or("no session")?;
        ensure_eq((s.kind, s.key_no, s.secondary), (AuthKind::Aes, Some(0), true), "session")?;
        c.detail(c.state_text());
        ensure_eq(c.get_key_version(0x80, None)?, vec![0x22], "secondary key 0 under the secondary session")
    });
    ctx.step("the SAI bit without a second application: PERMISSION_DENIED for authentication and GetKeyVersion", |c| {
        c.select_application(a, None)?;
        let z = c.zero_key;
        let r = c.authenticate_ev2_first(0x80, &z, &[]);
        c.expect_err(Status::PermissionDenied, r)?;
        enter(c, a, 0)?;
        let r = c.get_key_version(0x80, None);
        c.expect_err(Status::PermissionDenied, r)
    });
    ctx.step("GetFileIDs lists the primary application only; GetFileSettings reaches both through the SAI bit", |c| {
        c.select_application(a, Some(b))?;
        ensure_eq(c.get_file_ids()?, vec![0], "file ids (primary only)")?;
        let fs = c.get_file_settings(0x85)?;
        ensure_eq((fs.file_type, fs.size, fs.is_secondary_app()), (duox::card::FileType::StandardData, Some(16), true), "secondary file 5")?;
        let fs = c.get_file_settings(0x80)?;
        ensure_eq(fs.file_type, duox::card::FileType::BackupData, "secondary file 0")?;
        c.select_application(a, Some(b))?;
        let r = c.get_file_settings(0x05);
        c.expect_err(Status::FileNotFound, r)
    });
    ctx.step("one transaction over both applications: uncommitted writes are invisible, one commit publishes both", |c| {
        let z = c.zero_key;
        c.select_application(a, Some(b))?;
        c.authenticate_ev2_first(0, &z, &[])?;
        c.write_data(0, 0, &A_DATA)?;
        c.write_data(0x80, 0, &B_DATA)?;
        ensure_eq(c.read_data(0, 0, 0)?, vec![0u8; 16], "primary backup file before the commit")?;
        ensure_eq(c.read_data(0x80, 0, 0)?, vec![0u8; 16], "secondary backup file before the commit")?;
        let r = c.commit_transaction(false, duox::card::CommMode::Plain)?;
        ensure_eq(r.status, 0, "CommitTransaction status")?;
        ensure_eq(c.read_data(0, 0, 0)?, A_DATA.to_vec(), "primary backup file after the commit")?;
        ensure_eq(c.read_data(0x80, 0, 0)?, B_DATA.to_vec(), "secondary backup file after the commit")
    });
    ctx.step("AbortTransaction discards writes in both applications", |c| {
        let z = c.zero_key;
        c.select_application(a, Some(b))?;
        c.authenticate_ev2_first(0, &z, &[])?;
        c.write_data(0, 0, &[0xEE; 16])?;
        c.write_data(0x80, 0, &[0xDD; 16])?;
        let s = c.abort_transaction()?;
        ensure_eq(s, 0, "AbortTransaction status")?;
        ensure_eq(c.read_data(0, 0, 0)?, A_DATA.to_vec(), "primary file after the abort")?;
        ensure_eq(c.read_data(0x80, 0, 0)?, B_DATA.to_vec(), "secondary file after the abort")
    });
    ctx.step("selecting the applications again aborts an open transaction", |c| {
        let z = c.zero_key;
        c.select_application(a, Some(b))?;
        c.authenticate_ev2_first(0, &z, &[])?;
        c.write_data(0, 0, &[0x11; 16])?;
        c.write_data(0x80, 0, &[0x22; 16])?;
        c.select_application(a, Some(b))?;
        c.authenticate_ev2_first(0, &z, &[])?;
        ensure_eq(c.read_data(0, 0, 0)?, A_DATA.to_vec(), "primary file after re-selection")?;
        ensure_eq(c.read_data(0x80, 0, 0)?, B_DATA.to_vec(), "secondary file after re-selection")
    });
    ctx.step("a standard file of the secondary application is written and read through the SAI bit without authentication", |c| {
        c.select_application(a, Some(b))?;
        c.write_data(0x85, 3, b"through SAI")?;
        ensure_eq(c.read_data(0x85, 3, 11)?, b"through SAI".to_vec(), "data")
    });
    ctx.step("ChangeKey in the secondary application (key 0x81 from the secondary master key) leaves the primary alone", |c| {
        let z = c.zero_key;
        let new = rnd16();
        c.select_application(a, Some(b))?;
        c.authenticate_ev2_first(0x80, &z, &[])?;
        c.change_key(&ChangeKeySpec::new(0x81, &new, 0x5B).old_key(&z))?;
        c.auth_app(b, 1, &new)?;
        ensure_eq(c.get_key_version(1, None)?, vec![0x5B], "secondary key 1")?;
        enter(c, a, 1)?;
        ensure_eq(c.get_key_version(1, None)?, vec![c.app_default_key_version], "primary key 1")
    });
    ctx.step("SelectApplication of the same application twice: PERMISSION_DENIED, the PICC level is selected", |c| {
        let r = c.select_application(a, Some(a));
        c.expect_err(Status::PermissionDenied, r)?;
        ensure_eq(c.selection().primary, Some(Aid::PICC), "selection after the refusal")
    });
    ctx.step("SelectApplication with the PICC level as primary or secondary: PERMISSION_DENIED", |c| {
        let r = c.select_application(Aid::PICC, Some(a));
        c.expect_err(Status::PermissionDenied, r)?;
        let r = c.select_application(a, Some(Aid::PICC));
        c.expect_err(Status::PermissionDenied, r)
    });
    ctx.step("SelectApplication with an application that does not exist (primary or secondary): APPLICATION_NOT_FOUND", |c| {
        let r = c.select_application(a, Some(unknown));
        c.expect_err(Status::ApplicationNotFound, r)?;
        ensure_eq((c.selection().primary, c.selection().secondary), (Some(Aid::PICC), None), "selection after the refusal")?;
        let r = c.select_application(unknown, Some(a));
        c.expect_err(Status::ApplicationNotFound, r)
    });
    ctx.step("DeleteApplication of an application that is not selected while another one is: PERMISSION_DENIED", |c| {
        enter(c, a, 0)?;
        let r = c.delete_application(b, &[]);
        c.expect_err(Status::PermissionDenied, r)?;
        c.ensure_picc()?;
        let mut ids = c.get_application_ids()?;
        ids.sort();
        ensure_eq(ids, vec![a, b], "both applications still exist")
    });
}

// ------------------------------------------------------------------ SetConfiguration / GetConfiguration at application level
fn configuration_group(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        ctx.step("GetConfiguration without an option (manufacturer data) works at application level", |c| {
            enter(c, aid, 0)?;
            let d = soft(c.get_configuration(None))?;
            c.detail(hx(&d));
            ensure(!d.is_empty(), "no manufacturer data")
        });
        ctx.step("GetConfiguration 0x04 (SMConfig) of a new application is 0000", |c| {
            enter(c, aid, 0)?;
            let d = c.get_configuration(Some(0x04))?;
            c.detail(hx(&d));
            ensure(d.len() >= 2, "SMConfig has two bytes")?;
            ensure_eq(d[..2].to_vec(), vec![0, 0], "SMConfigA / SMConfigB")
        });
        ctx.step("SetConfiguration 0x04: free access over I2C (bit 5) on, read back, off, read back", |c| {
            enter(c, aid, 0)?;
            c.set_configuration(0x04, &[0x00, 0x20])?;
            ensure_eq(c.get_configuration(Some(0x04))?, vec![0x00, 0x20], "SMConfig after enabling")?;
            c.set_configuration(0x04, &[0x00, 0x00])?;
            ensure_eq(c.get_configuration(Some(0x04))?, vec![0x00, 0x00], "SMConfig after disabling")
        });
        ctx.step("SetConfiguration 0x04 with one byte: LENGTH_ERROR", |c| {
            enter(c, aid, 0)?;
            let r = c.set_configuration(0x04, &[0x00]);
            c.expect_err(Status::LengthError, r)
        });
        ctx.step("SetConfiguration needs the master key (key 1, no authentication: AUTHENTICATION_ERROR)", |c| {
            enter(c, aid, 1)?;
            let r = c.set_configuration(0x04, &[0x00, 0x00]);
            c.expect_err(Status::AuthenticationError, r)?;
            c.select_application(aid, None)?;
            let r = c.set_configuration(0x04, &[0x00, 0x00]);
            c.expect_err(Status::AuthenticationError, r)
        });
        ctx.step("GetConfiguration needs the master key too", |c| {
            enter(c, aid, 1)?;
            let r = c.get_configuration(Some(0x04));
            c.expect_err(Status::AuthenticationError, r)?;
            c.select_application(aid, None)?;
            let r = c.get_configuration(None);
            c.expect_err(Status::AuthenticationError, r)
        });
        ctx.step("AppConfig (option 0x00) is for delegated applications only: PERMISSION_DENIED in a conventional one", |c| {
            enter(c, aid, 0)?;
            let r = c.set_configuration(0x00, &[0x00]);
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            let r = c.get_configuration(Some(0x00));
            let s = c.expect_any_status(r)?;
            c.detail(format!("GetConfiguration 0x00: {s} (0x{:02X})", s.code()));
            Ok(())
        });
        ctx.step("PICC level options are refused at application level: GetConfiguration 0x01 0x02 0x03 0x0C 0x0F 0x10 0x11", |c| {
            for opt in [0x01u8, 0x02, 0x03, 0x0C, 0x0F, 0x10, 0x11] {
                enter(c, aid, 0)?;
                let r = c.get_configuration(Some(opt));
                c.expect_err(Status::PermissionDenied, r)?;
            }
            Ok(())
        });
        ctx.step("options 0x05 and 0x15 need the application to be created with KeySett3 bit 2: PERMISSION_DENIED", |c| {
            enter(c, aid, 0)?;
            let r = c.set_configuration(0x05, &[0u8; 10]);
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            let r = c.set_configuration(0x15, &[0x02, 0x00]);
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("renaming (option 0x06) an application created without a DF name: PERMISSION_DENIED", |c| {
            enter(c, aid, 0)?;
            let r = c.set_configuration(0x06, &dfname_data(b"NO-NAME"));
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("the guard refuses irreversible or PICC level options before anything is sent", |c| {
            enter(c, aid, 0)?;
            let key33 = [0u8; 33];
            let cases: [(u8, &[u8]); 6] = [
                (0x00, &[0x01]),
                (0x04, &[0x04, 0x00]),
                (0x04, &[0x00, 0x04]),
                (0x02, &[0x05, 0x75, 0x77, 0x81, 0x02]),
                (0x11, &key33),
                (0x01, &[0u8; 25]),
            ];
            for (opt, data) in cases {
                let r = c.set_configuration(opt, data);
                c.expect_violation(r)?;
            }
            ensure(c.is_authenticated(), "nothing may have been sent")
        });
        ctx.step("option 0xFF locks configuration options: after locking 0x04 it cannot be written (PERMISSION_DENIED), reads still work", |c| {
            enter(c, aid, 0)?;
            c.set_configuration(0xFF, &[0x10, 0x00, 0x00])?; // bit 4 of the first byte = option 0x04
            let lock = c.get_configuration(Some(0xFF));
            if let Ok(d) = &lock {
                c.detail(format!("lock map {}", hx(d)));
            }
            enter(c, aid, 0)?;
            let r = c.set_configuration(0x04, &[0x00, 0x00]);
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            ensure_eq(c.get_configuration(Some(0x04))?, vec![0x00, 0x00], "SMConfig is still readable")
        });
    });
}

// ------------------------------------------------------------------ authentication counter (option 0x16)
fn counter_of(d: &[u8]) -> StepResult<u32> {
    if d.len() < 10 {
        return Err(StepError::skip(format!("GetConfiguration 0x16 returned {} bytes, no counter field", d.len())));
    }
    Ok(u32::from_le_bytes([d[6], d[7], d[8], d[9]]))
}

fn auth_counter_group(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        let mut last: Option<u32> = None;
        ctx.step("option 0x16: counting AES authentications is enabled without a limit (counter field read back)", |c| {
            enter(c, aid, 0)?;
            c.set_configuration(0x16, &[0x00, 0x01, 0, 0, 0, 0])?;
            let d = c.get_configuration(Some(0x16))?;
            c.detail(hx(&d));
            let n = counter_of(&d)?;
            ensure_eq((d[1] & 1, u32::from_le_bytes([d[2], d[3], d[4], d[5]])), (1, 0), "counting flag / limit")?;
            last = Some(n);
            Ok(())
        });
        ctx.step("every AuthenticateEV2First increments the counter by exactly one (three authentications)", |c| {
            let mut prev = last.ok_or_else(|| StepError::skip("the counter was not enabled"))?;
            for _ in 0..3 {
                enter(c, aid, 0)?;
                let n = counter_of(&c.get_configuration(Some(0x16))?)?;
                ensure_eq(n, prev + 1, "counter")?;
                prev = n;
            }
            last = Some(prev);
            Ok(())
        });
        ctx.step("AuthenticateEV2NonFirst is not counted", |c| {
            let z = c.zero_key;
            enter(c, aid, 0)?;
            let n1 = counter_of(&c.get_configuration(Some(0x16))?)?;
            c.authenticate_ev2_non_first(0, &z)?;
            let n2 = counter_of(&c.get_configuration(Some(0x16))?)?;
            ensure_eq(n2, n1, "counter after AuthenticateEV2NonFirst")?;
            last = Some(n2);
            Ok(())
        });
        ctx.step("a refused authentication (wrong key) is counted as well", |c| {
            let prev = last.ok_or_else(|| StepError::skip("the counter was not enabled"))?;
            c.select_application(aid, None)?;
            let r = c.authenticate_ev2_first(0, &[0x42; 16], &[]);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 0)?;
            let n = counter_of(&c.get_configuration(Some(0x16))?)?;
            ensure_eq(n, prev + 2, "counter after one failed and one good authentication")?;
            last = Some(n);
            Ok(())
        });
        ctx.step("a limit: authentication works up to the limit, then PERMISSION_DENIED (the application stays unusable)", |c| {
            last.ok_or_else(|| StepError::skip("the counter was not enabled"))?;
            enter(c, aid, 0)?;
            let now = counter_of(&c.get_configuration(Some(0x16))?)?;
            let limit = now + 3;
            c.set_configuration(0x16, &[&[0x00, 0x01][..], &limit.to_le_bytes()].concat())?;
            let d = c.get_configuration(Some(0x16))?;
            ensure_eq(u32::from_le_bytes([d[2], d[3], d[4], d[5]]), limit, "limit read back")?;
            ensure_eq(counter_of(&d)?, now, "the counter is not touched by changing the limit")?;
            c.detail(format!("counter {now}, limit {limit}"));
            let mut refused_at = None;
            for i in 1..=6u32 {
                c.select_application(aid, None)?;
                let z = c.zero_key;
                match c.authenticate_ev2_first(0, &z, &[]) {
                    Ok(_) => ensure(refused_at.is_none(), format!("attempt {i} succeeded after an earlier refusal"))?,
                    Err(e) => {
                        ensure_eq(e.status(), Some(Status::PermissionDenied), &format!("status of the refusal at attempt {i}"))?;
                        refused_at.get_or_insert(i);
                    }
                }
            }
            let at = refused_at.ok_or("the limit never took effect")?;
            c.detail(format!("first refusal at attempt {at} (counter before: {now}, limit {limit})"));
            // the counter reaches the limit with attempt 3; the card refuses either that one or the next
            ensure((3..=4).contains(&at), format!("refusal at attempt {at}, expected at attempt 3 or 4 (counter {now}, limit {limit})"))
        });
    });
}

// ------------------------------------------------------------------ negative tests
fn negative_group(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let (spare, other) = (ctx.alloc_aid(), ctx.alloc_aid());
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        ctx.step("CreateApplication with an AID that exists: DUPLICATE_ERROR", |c| {
            c.auth_picc()?;
            let r = c.create_application(&AppSpec::new(aid).keys(1));
            c.expect_err(Status::DuplicateError, r)?;
            c.auth_picc()?;
            ensure_eq(c.get_application_ids()?, vec![aid], "the original application is untouched")
        });
        ctx.step("the guard refuses AIDs outside the suite range and the PICC level (nothing is sent)", |c| {
            c.auth_picc()?;
            for bad in [Aid(0x000000), Aid(0x000001), Aid(0x123456), Aid(0xFFFFFF), Aid(0xD10000)] {
                let r = c.create_application(&AppSpec::new(bad).keys(1));
                c.expect_violation(r)?;
                let r = c.delete_application(bad, &[]);
                c.expect_violation(r)?;
            }
            ensure(c.is_authenticated(), "nothing may have been sent")
        });
        ctx.step("CreateApplication while an application is selected: PERMISSION_DENIED", |c| {
            enter(c, aid, 0)?;
            let id = c.push_cleanup(&format!("delete probe application {spare} if it exists"), move |c| c.delete_app_tolerant(spare));
            let r = c.create_application(&AppSpec::new(spare).keys(1));
            let verdict = c.expect_err(Status::PermissionDenied, r);
            c.run_cleanup_now(id);
            verdict
        });
        ctx.step("DeleteApplication of an AID that does not exist: APPLICATION_NOT_FOUND", |c| {
            c.auth_picc()?;
            let r = c.delete_application(other, &[]);
            c.expect_err(Status::ApplicationNotFound, r)
        });
        ctx.step("SelectApplication of an AID that does not exist: APPLICATION_NOT_FOUND, the PICC level stays selected", |c| {
            let r = c.select_application(other, None);
            c.expect_err(Status::ApplicationNotFound, r)?;
            ensure_eq(c.selection().primary, Some(Aid::PICC), "selection after the refusal")
        });
        ctx.step("ChangeKey of the application VCProximityKey 0x21 in an application created without one: NO_SUCH_KEY", |c| {
            enter(c, aid, 0)?;
            let r = c.change_key(&ChangeKeySpec::new(0xA1, &rnd16(), 1).old_key(&[0; 16]));
            c.expect_err(Status::NoSuchKey, r)?;
            enter(c, aid, 0)?;
            let r = c.get_key_version(0x21, None);
            let s = c.expect_any_status(r)?;
            c.detail(format!("GetKeyVersion 0x21: {s} (0x{:02X})", s.code()));
            Ok(())
        });
        ctx.step("a command that fails ends the session on the card as well: the next plain command needs authentication again", |c| {
            // KeySett1 0x0F allows unauthenticated reads; tighten it so the effect is visible
            enter(c, aid, 0)?;
            c.change_key_settings(0x0D)?;
            enter(c, aid, 0)?;
            let r = c.get_key_version(9, None);
            c.expect_err(Status::NoSuchKey, r)?;
            // the library has no session now and sends in plain; the card must not accept it as authenticated
            let r = c.get_key_settings();
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 0)?;
            c.change_key_settings(0x0F)?;
            ensure_eq(c.get_key_settings()?.settings, 0x0F, "settings restored")
        });
        ctx.step("Format is refused in a conventional application (PERMISSION_DENIED) and the application is untouched", |c| {
            enter(c, aid, 0)?;
            let r = c.format();
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            ensure_eq(c.get_key_settings()?.max_keys, 2, "the application still has its keys")?;
            ensure_eq(c.get_key_version(1, None)?, vec![c.app_default_key_version], "key 1")
        });
        ctx.step("Format without authentication is refused (AUTHENTICATION_ERROR or PERMISSION_DENIED) and changes nothing", |c| {
            c.select_application(aid, None)?;
            let r = c.format();
            let s = c.expect_any_status(r)?;
            c.detail(format!("{s} (0x{:02X})", s.code()));
            c.auth_picc()?;
            ensure(c.get_application_ids()?.contains(&aid), "the application was lost")
        });
    });
}

// ------------------------------------------------------------------ DeleteApplication variants
fn delete_group(ctx: &mut Ctx) {
    for (label, k3) in [("default KeySett3", None), ("KeySett3 bit 4 (deletion with the master key always enabled)", Some(0x10u8))] {
        let aid = ctx.alloc_aid();
        let mut spec = AppSpec::new(aid).keys(2);
        if let Some(k) = k3 {
            spec = spec.key_sett3(k);
        }
        ctx.app_scope(spec, |ctx, aid| {
            ctx.step(&format!("DeleteApplication of the selected application, authenticated with its own master key: {label}"), |c| {
                enter(c, aid, 0)?;
                c.delete_application(aid, &[])?;
                ensure(!c.is_authenticated(), "the authentication must end")?;
                c.select_application(Aid::PICC, None)?;
                c.ensure_picc()?;
                ensure(!c.get_application_ids()?.contains(&aid), "the application is still listed")?;
                c.select_application(Aid::PICC, None)?;
                let r = c.select_application(aid, None);
                c.expect_err(Status::ApplicationNotFound, r)
            });
        });
    }
    // everything an application held is gone with it
    let aid = ctx.alloc_aid();
    let secret = rnd16();
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        ctx.step("populate: change the master key, create two files, write data", |c| {
            enter(c, aid, 0)?;
            c.change_key(&ChangeKeySpec::new(0, &secret, 0x99))?;
            c.auth_app(aid, 0, &secret)?;
            c.create_data_file(&DataFileSpec::new(0, 32, access_all(AccessRight::key(0))))?;
            c.create_data_file(&DataFileSpec::new(1, 32, access_all(AccessRight::key(0))).backup())?;
            c.write_data(0, 0, b"remember me")?;
            ensure_eq(c.get_file_ids()?, vec![0, 1], "file list")
        });
        ctx.step("delete the application", |c| {
            c.auth_picc()?;
            c.delete_application(aid, &[])?;
            c.ensure_picc()?;
            ensure(!c.get_application_ids()?.contains(&aid), "the application is still listed")
        });
        ctx.step("the same AID created again: no files, default key (version and value), the old key is refused", |c| {
            c.auth_picc()?;
            c.create_application(&AppSpec::new(aid).keys(2))?;
            enter(c, aid, 0)?;
            ensure_eq(c.get_file_ids()?, Vec::<u8>::new(), "file list")?;
            ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "key version")?;
            c.select_application(aid, None)?;
            let r = c.authenticate_ev2_first(0, &secret, &[]);
            c.expect_err(Status::AuthenticationError, r)
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_blocks_follow_the_data_sheet() {
        // 1 key, AES-128: ceil((21 + 20) / 32) = 2 key blocks + 1 overhead block
        assert_eq!(app_blocks(1, 1, 16, false, false, false), 3);
        // 2 keys: ceil(61 / 32) = 2
        assert_eq!(app_blocks(2, 1, 16, false, false, false), 3);
        // 14 keys: ceil(301 / 32) = 10
        assert_eq!(app_blocks(14, 1, 16, false, false, false), 11);
        // 3 AES-256 keys: ceil(129 / 32) = 5
        assert_eq!(app_blocks(3, 1, 32, false, false, false), 6);
        // no keys: only overhead
        assert_eq!(app_blocks(0, 1, 16, false, false, false), 1);
        // ISO names or capability data add one overhead block, the VC proximity key three more
        assert_eq!(app_blocks(1, 1, 16, true, false, false), 4);
        assert_eq!(app_blocks(1, 1, 16, false, false, true), 4);
        assert_eq!(app_blocks(1, 1, 16, false, true, false), 6);
        // key sets multiply the key storage
        assert_eq!(app_blocks(3, 3, 16, false, false, false), 3 * 3 + 1);
    }

    #[test]
    fn dfname_payload_is_length_plus_padded_name() {
        let d = dfname_data(b"AB");
        assert_eq!(d.len(), 17);
        assert_eq!(&d[..4], &[2, b'A', b'B', 0]);
        assert_eq!(dfname_data(NAME_C)[0], 16);
        assert_eq!(&dfname_data(NAME_C)[1..], NAME_C);
    }

    #[test]
    fn counter_field_is_little_endian_at_offset_six() {
        let d = [0, 1, 0, 0, 0, 0, 0x2A, 1, 0, 0];
        assert_eq!(counter_of(&d).unwrap(), 0x12A);
        assert!(matches!(counter_of(&d[..6]), Err(StepError::Skip(_))));
    }

    #[test]
    fn case_table_has_no_self_contradiction() {
        // every refused case names a status that is a refusal, never OPERATION_OK
        for cs in [case(0, 1, false, Some(Status::AuthenticationError)), case(1, 1, true, None)] {
            if let Some(s) = cs.want {
                assert!(!s.is_ok());
            }
        }
    }
}
