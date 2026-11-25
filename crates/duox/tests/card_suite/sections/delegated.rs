//! Section `delegated`: delegated application management as far as it can be exercised without writing
//! PICC level state (data sheet 7.11.1.2, 7.11.2, 7.11.4.3, 7.11.5, 7.8.7).
//!
//! The PICCDAM keys (0x10..0x12) are disabled at delivery and become enabled for good once written, so
//! this section never writes them: everything that needs one of them is recorded as a skipped step with
//! the reason. What is exercised:
//!
//! * GetDelegatedInfo (directory access, refusal of an unknown slot),
//! * the card's refusal of CreateDelegatedApplication without PICCDAMAuthKey authentication,
//! * DeleteApplication paths that need no PICCDAM key (unknown AID, AID 0, a stray DAMMAC),
//! * memory consumption of conventional applications against the library's quota estimate
//!   (`AppHeader::overhead_blocks`),
//! * a pure offline self-test of the `dam` module against the library's own builders (headers, EncK,
//!   DAMMAC, delete MAC, tickets, JSON).

use crate::ctx::{ensure, ensure_eq, Ctx, StepError};
use duox::card::{Aid, AppSpec, DelegatedAppSpec, DelegatedKeys, Status};
use duox::crypto;
use duox::dam::{self, AppHeader, Ticket};

pub const NAME: &str = "delegated";
pub const DESCRIPTION: &str =
    "Delegated applications: GetDelegatedInfo, refusals without PICCDAM keys, quota estimates, offline DAM self-test; PICCDAM-key steps skipped.";

pub fn run(ctx: &mut Ctx) {
    offline_selftest(ctx);
    delegated_info(ctx);
    piccdam_state(ctx);
    refusals_without_keys(ctx);
    quota_estimates(ctx);
    skipped(ctx);
}

// ------------------------------------------------------------------ offline self-test (no card)
fn offline_selftest(ctx: &mut Ctx) {
    ctx.step("dam module self-test (offline): header layout, round trip, EncK, DAMMAC, delete MAC", |c| {
        let r = dam_header_and_macs();
        c.detail("AES-128 and AES-256 application headers, tickets, MACs and tamper detection checked against independent computations");
        r.map_err(StepError::Fail)
    });
    ctx.step("dam module self-test (offline): ticket JSON, tamper detection, DelegatedAppSpec lengths, quota formula", |_c| {
        dam_ticket_and_quota().map_err(StepError::Fail)
    });
}

fn chk(cond: bool, what: &str) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

fn chk_eq<T: PartialEq + std::fmt::Debug>(got: T, want: T, what: &str) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}: got {got:?}, expected {want:?}"))
    }
}

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

fn dam_header_and_macs() -> Result<(), String> {
    // layout: AID (3, LSB first) | slot (2) | slot version | quota (2) | KeySett1 | KeySett2 [...]
    let h = AppHeader::new(0xD1D2D3, 0x0102, 7, 0x0304);
    let raw = h.encode().map_err(e)?;
    chk_eq(raw.clone(), vec![0xD3, 0xD2, 0xD1, 0x02, 0x01, 7, 0x04, 0x03, 0x0F, 0x81], "AES-128 header bytes")?;
    chk_eq(AppHeader::parse(&raw).map_err(e)?, h.clone(), "header round trip")?;
    let h256 = AppHeader { aes256: true, n_keys: 2, ..h };
    let raw256 = h256.encode().map_err(e)?;
    chk_eq(raw256[9], 0xC2, "KeySett2 of an AES-256 application with two keys")?;
    chk_eq(AppHeader::parse(&raw256).map_err(e)?, h256.clone(), "AES-256 header round trip")?;
    chk(AppHeader::parse(&raw[..9]).is_err(), "a truncated header must be refused")?;

    let (mac_key, enc_key) = (crypto::rnd(16), crypto::rnd(16));
    // AES-128 application: 16 byte default key
    let key16 = crypto::rnd(16);
    let t = dam::issue_ticket(&mac_key, &enc_key, &raw, &key16, 0x42, true).map_err(e)?;
    chk_eq(t.enc_k.len(), 32, "EncK length (AES-128 application)")?;
    chk_eq(t.dam_mac.len(), 8, "DAMMAC length")?;
    let (k, ver) = dam::decrypt_enc_k(&enc_key, &t.enc_k, false).map_err(e)?;
    chk_eq(&k[..16], &key16[..], "decrypted AppDAMDefaultKey")?;
    chk(k[16..].iter().all(|&b| b == 0), "the key is zero padded to 24 bytes")?;
    chk_eq(ver, 0x42, "decrypted key version")?;
    // independent recomputation of the MACs
    let mut mi = vec![0xC9];
    mi.extend(&raw);
    mi.extend(&t.enc_k);
    chk_eq(t.dam_mac.clone(), crypto::mact(&mac_key, &mi).map_err(e)?, "DAMMAC over Cmd || header || EncK")?;
    chk_eq(t.delete_mac.clone(), crypto::mact(&mac_key, &[0xDA, 0xD3, 0xD2, 0xD1]).map_err(e)?, "delete MAC over Cmd || AID")?;
    chk_eq(t.delete_mac.clone(), dam::delete_mac(&mac_key, 0xD1D2D3).map_err(e)?, "delete_mac()")?;
    chk(t.verify(&mac_key).map_err(e)?, "ticket verifies with the issuer's MAC key")?;
    chk(!t.verify(&enc_key).map_err(e)?, "ticket must not verify with another key")?;
    // 24 byte key form
    let key24 = crypto::rnd(24);
    let t24 = dam::issue_ticket(&mac_key, &enc_key, &raw, &key24, 1, false).map_err(e)?;
    chk(t24.delete_mac.is_empty() && t24.verify(&mac_key).map_err(e)?, "ticket without delete MAC")?;
    let (k, _) = dam::decrypt_enc_k(&enc_key, &t24.enc_k, false).map_err(e)?;
    chk_eq(k, key24, "24 byte AppDAMDefaultKey")?;

    // AES-256 application: 32 byte key, EncK 48 bytes
    let key32 = crypto::rnd(32);
    let t = dam::issue_ticket(&mac_key, &enc_key, &raw256, &key32, 9, true).map_err(e)?;
    chk_eq(t.enc_k.len(), 48, "EncK length (AES-256 application)")?;
    let (k, ver) = dam::decrypt_enc_k(&enc_key, &t.enc_k, true).map_err(e)?;
    chk_eq((k, ver), (key32.clone(), 9), "AES-256 default key and version")?;
    chk(t.verify(&mac_key).map_err(e)?, "AES-256 ticket verifies")?;
    chk(dam::issue_ticket(&mac_key, &enc_key, &raw256, &key16, 0, false).is_err(), "a 16 byte key for an AES-256 application is refused")?;
    chk(dam::issue_ticket(&mac_key, &enc_key, &raw, &key32, 0, false).is_err(), "a 32 byte key for an AES-128 application is refused")?;
    // 32 byte DAM keys (AES-256 PICCDAM keys) work as well
    let (mk32, ek32) = (crypto::rnd(32), crypto::rnd(32));
    let t = dam::issue_ticket(&mk32, &ek32, &raw, &key16, 3, true).map_err(e)?;
    chk(t.verify(&mk32).map_err(e)?, "ticket under 32 byte PICCDAM keys")?;
    Ok(())
}

fn dam_ticket_and_quota() -> Result<(), String> {
    let (mac_key, enc_key) = (crypto::rnd(16), crypto::rnd(16));
    let h = AppHeader {
        n_keys: 3,
        iso_file_ids: true,
        key_sett3: Some(0x01),
        keyset_params: vec![1, 2, 0x10, 0],
        iso_fid: Some(0xE110),
        df_name: vec![0xD2, 0x76, 0x00],
        ..AppHeader::new(0xD0_0010, 4, 2, 100)
    };
    let raw = h.encode().map_err(e)?;
    chk_eq(AppHeader::parse(&raw).map_err(e)?, h, "full header round trip")?;
    let t = dam::issue_ticket(&mac_key, &enc_key, &raw, &crypto::rnd(16), 1, true).map_err(e)?;
    let back = Ticket::from_json(&t.to_json().map_err(e)?).map_err(e)?;
    chk_eq(back.clone(), t.clone(), "JSON round trip")?;
    chk(back.verify(&mac_key).map_err(e)?, "ticket verifies after the JSON round trip")?;
    chk(Ticket::from_json("{\"type\":\"other\"}").is_err(), "foreign JSON is refused")?;
    // tampering with any field is detected
    let mut bad = t.clone();
    bad.header[3] ^= 1; // slot number
    chk(!bad.verify(&mac_key).map_err(e)?, "tampered header")?;
    let mut bad = t.clone();
    bad.enc_k[0] ^= 1;
    chk(!bad.verify(&mac_key).map_err(e)?, "tampered EncK")?;
    let mut bad = t.clone();
    bad.dam_mac[7] ^= 1;
    chk(!bad.verify(&mac_key).map_err(e)?, "tampered DAMMAC")?;
    let mut bad = t.clone();
    bad.delete_mac[0] ^= 1;
    chk(!bad.verify(&mac_key).map_err(e)?, "tampered delete MAC")?;
    // the pieces fit the library's CreateDelegatedApplication argument checks
    let spec = DelegatedAppSpec { header: t.header.clone(), keys: DelegatedKeys::Aes { enc_k: t.enc_k.clone(), dam_mac: t.dam_mac.clone() } };
    match &spec.keys {
        DelegatedKeys::Aes { enc_k, dam_mac } => chk(matches!(enc_k.len(), 32 | 48) && dam_mac.len() == 8, "EncK / DAMMAC lengths")?,
        DelegatedKeys::Ecc { .. } => return Err("unexpected key kind".into()),
    }
    // quota formula against hand computed values
    chk_eq(AppHeader::new(1, 0, 0, 0).overhead_blocks(), 4, "one AES-128 key")?;
    chk_eq(AppHeader { n_keys: 3, ..AppHeader::new(1, 0, 0, 0) }.overhead_blocks(), 2 + (21u32 + 3 * 20).div_ceil(32), "three AES-128 keys")?;
    chk_eq(AppHeader { aes256: true, ..AppHeader::new(1, 0, 0, 0) }.overhead_blocks(), 2 + (21u32 + 36).div_ceil(32), "one AES-256 key")?;
    chk_eq(AppHeader { iso_fid: Some(1), ..AppHeader::new(1, 0, 0, 0) }.overhead_blocks(), 5, "ISO file ID adds a block")?;
    chk_eq(AppHeader { key_sett3: Some(2), ..AppHeader::new(1, 0, 0, 0) }.overhead_blocks(), 4 + 1 + 3, "VCProximityKey adds a block and three blocks of key storage")?;
    chk_eq(AppHeader { n_keys: 0x0F, ..AppHeader::new(1, 0, 0, 0) }.overhead_blocks(), 6, "transaction MAC key layout")?;
    Ok(())
}

// ------------------------------------------------------------------ GetDelegatedInfo
fn delegated_info(ctx: &mut Ctx) {
    ctx.step_picc("GetDelegatedInfo, PICC master key session: unknown slots are refused, an existing slot is consistent", |c| {
        let mut seen = 0;
        for slot in [0u16, 1, 0x00FF, 0xFFFF] {
            c.ensure_picc()?;
            match c.get_delegated_info(slot) {
                Ok(i) => {
                    seen += 1;
                    c.detail(format!("slot {slot}: {i:?}"));
                    ensure(i.free_blocks <= i.quota, format!("slot {slot}: FreeBlocks {} exceeds QuotaLimit {}", i.free_blocks, i.quota))?;
                    if i.aid == Aid::PICC {
                        ensure_eq(i.free_blocks, i.quota, "an unoccupied slot is completely free")?;
                    }
                }
                Err(err) => {
                    let s = c.expect_any_status(Err::<(), _>(err))?;
                    c.detail(format!("slot {slot}: refused with {s} (0x{:02X})", s.code()));
                    ensure_eq(s.is_ok(), false, "a refusal is an error status")?;
                }
            }
        }
        c.detail(format!("{seen} of 4 probed slots exist"));
        Ok(())
    });
    ctx.step("GetDelegatedInfo without authentication follows PICCKeySettings bit 1 (directory access)", |c| {
        c.ensure_picc()?;
        let free_dir = c.get_key_settings()?.settings & 0x02 != 0;
        c.select_application(Aid::PICC, None)?;
        match c.get_delegated_info(0) {
            Ok(i) => {
                c.detail(format!("answered: {i:?}"));
                ensure(free_dir, "answered without authentication although directory access requires it")
            }
            Err(err) => {
                let s = c.expect_any_status(Err::<(), _>(err))?;
                c.detail(format!("directory access free: {free_dir}; refused with {s} (0x{:02X})", s.code()));
                if free_dir {
                    // slot 0 does not exist on a card without delegated applications: the same refusal as when authenticated
                    ensure(s != Status::AuthenticationError, "with free directory access the refusal must not be an authentication error")
                } else {
                    ensure_eq(s, Status::AuthenticationError, "status when authentication is required")
                }
            }
        }
    });
}

// ------------------------------------------------------------------ state of the PICCDAM keys (read only)
fn piccdam_state(ctx: &mut Ctx) {
    ctx.step("PICCDAMAuthKey 0x10: report whether the zero key authenticates (observation only, nothing is written)", |c| {
        let z = c.zero_key;
        let r = c.auth_picc_key(0x10, &z);
        match r {
            Ok(()) => c.detail("the key authenticates with the zero key: it is ENABLED (the suite still does not touch it)"),
            Err(err) => {
                let s = c.expect_any_status(Err::<(), _>(err))?;
                c.detail(format!("refused with {s} (0x{:02X}): disabled at delivery, as expected", s.code()));
            }
        }
        c.auth_picc()
    });
}

// ------------------------------------------------------------------ refusals that need no PICCDAM key
fn refusals_without_keys(ctx: &mut Ctx) {
    ctx.step_picc("DeleteApplication of an AID that does not exist: APPLICATION_NOT_FOUND", |c| {
        let aid = c.alloc_aid();
        let r = c.delete_application(aid, &[]);
        c.expect_err(Status::ApplicationNotFound, r)
    });
    ctx.step_picc("the guard refuses DeleteApplication of AID 000000 and of a foreign AID (nothing is sent)", |c| {
        let r = c.delete_application(Aid::PICC, &[]);
        c.expect_violation(r)?;
        let r = c.delete_application(Aid(0x0000_0042), &[]);
        c.expect_violation(r)?;
        ensure(c.is_authenticated(), "the session was lost although nothing was sent")
    });
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        ctx.step("DeleteApplication of a conventional application with a stray 8 byte DAMMAC appended: refused, application kept", |c| {
            c.auth_picc()?;
            let r = c.delete_application(aid, &[0xAA; 8]);
            let s = c.expect_any_status(r)?;
            c.detail(format!("refused with {s} (0x{:02X})", s.code()));
            c.auth_picc()?;
            ensure(c.get_application_ids()?.contains(&aid), "the application disappeared")
        });
    });
    let aid = ctx.alloc_aid();
    let cid = ctx.push_cleanup(&format!("delete application {aid} if it was created"), move |c| c.delete_app_tolerant(aid));
    ctx.step_picc("CreateDelegatedApplication with the PICC master key session (no PICCDAMAuthKey): refused, nothing created", |c| {
        let hdr = AppHeader::new(aid.0, 0, 1, 8).encode().map_err(|x| StepError::fail(x.to_string()))?;
        let t = dam::issue_ticket(&crypto::rnd(16), &crypto::rnd(16), &hdr, &crypto::rnd(16), 0, false)
            .map_err(|x| StepError::fail(x.to_string()))?;
        let spec = DelegatedAppSpec { header: hdr, keys: DelegatedKeys::Aes { enc_k: t.enc_k, dam_mac: t.dam_mac } };
        let r = c.create_delegated_application(&spec);
        let s = c.expect_any_status(r)?;
        c.detail(format!("refused with {s} (0x{:02X})", s.code()));
        c.auth_picc()?;
        ensure(!c.get_application_ids()?.contains(&aid), "an application was created")
    });
    ctx.step_picc("CreateDelegatedApplication with an ECC-style key argument in an AES session is refused by the library (nothing sent)", |c| {
        let hdr = AppHeader::new(aid.0, 0, 1, 8).encode().map_err(|x| StepError::fail(x.to_string()))?;
        let spec = DelegatedAppSpec { header: hdr, keys: DelegatedKeys::Ecc { init_k: vec![0; 17] } };
        match c.create_delegated_application(&spec) {
            Err(duox::Error::InvalidArgument(_)) => Ok(()),
            other => Err(StepError::fail(format!("expected an argument error, got {other:?}"))),
        }
    });
    ctx.step_picc("the refused attempts left no application behind", |c| {
        c.cancel_cleanup(cid);
        ensure(!c.get_application_ids()?.contains(&aid), "an application exists")
    });
}

// ------------------------------------------------------------------ quota estimates
/// (name, spec, header the library would use for the same parameters)
fn quota_cases(aid: Aid) -> Vec<(&'static str, AppSpec, AppHeader)> {
    let hdr = |n: u8| AppHeader { n_keys: n, ..AppHeader::new(aid.0, 0, 1, 0) };
    vec![
        ("1 key", AppSpec::new(aid).keys(1), hdr(1)),
        ("3 keys", AppSpec::new(aid).keys(3), hdr(3)),
        (
            "1 key + ISO file ID",
            AppSpec::new(aid).keys(1).iso_name(0x0A01, &[]),
            AppHeader { iso_fid: Some(0x0A01), ..hdr(1) },
        ),
        (
            "1 key + application VCProximityKey",
            AppSpec::new(aid).keys(1).key_sett3(0x02),
            AppHeader { key_sett3: Some(0x02), ..hdr(1) },
        ),
    ]
}

/// Blocks of key storage that are never released (7.8.7).
fn key_blocks(h: &AppHeader) -> u32 {
    let keys = u32::from(h.n_keys);
    let max = if h.aes256 { 32 } else { 16 };
    let vc = if h.key_sett3.unwrap_or(0) & 2 != 0 { 3 } else { 0 };
    (21 + keys * (max + 4)).div_ceil(32) + vc
}

/// Expected blocks of a conventional application: the delegated estimate without the extra delegated block.
fn conventional_blocks(h: &AppHeader) -> u32 {
    h.overhead_blocks() - 1
}

fn quota_estimates(ctx: &mut Ctx) {
    for i in 0..4 {
        let probe = ctx.alloc_aid();
        let (name, spec, header) = quota_cases(probe).swap_remove(i);
        let before = ctx.step_picc(&format!("quota estimate [{name}]: FreeMem before creating a conventional application"), |c| Ok(c.free_mem()?));
        let Some(before) = before else { continue };
        let spec = AppSpec { aid: probe, ..spec };
        ctx.app_scope(spec, |ctx, _aid| {
            ctx.step_picc(&format!("quota estimate [{name}]: consumed memory is in whole blocks, within the library's estimate"), |c| {
                let after = c.free_mem()?;
                let used = before.saturating_sub(after);
                let est = conventional_blocks(&header);
                let lo = key_blocks(&header);
                c.detail(format!("consumed {used} bytes = {} blocks; estimate {est} blocks (overhead may be partly reused), keys alone {lo} blocks", used / 32));
                ensure_eq(used % 32, 0, "consumed bytes modulo block size")?;
                ensure(used / 32 <= est, format!("consumed {} blocks, more than the estimate {est}", used / 32))?;
                ensure(used / 32 >= lo, format!("consumed {} blocks, less than the key storage alone {lo}", used / 32))
            });
        });
    }
}

// ------------------------------------------------------------------ everything that needs a PICCDAM key
fn skipped(ctx: &mut Ctx) {
    const WHY: &str = "the PICCDAM keys 0x10..0x12 are disabled at delivery and become enabled for good once written; \
                       the suite must leave them untouched, so no PICCDAMAuthKey session exists";
    ctx.skip("ChangeKey of PICCDAMAuthKey / PICCDAMMACKey / PICCDAMENCKey", WHY);
    ctx.skip("CreateDelegatedApplication with a ticket (AES session, DAMMAC, EncK)", WHY);
    ctx.skip("GetDelegatedInfo on an occupied slot (QuotaLimit, FreeBlocks, DAMSlotVersion after creation)", WHY);
    ctx.skip("delegated application: files within the quota, OUT_OF_MEMORY beyond the QuotaLimit", WHY);
    ctx.skip("DeleteApplication of a delegated application with PICCDAMAuthKey and DAMMAC (delete MAC from the ticket)", WHY);
    ctx.skip("re-creating a delegated application in the same slot with a higher DAMSlotVersion", WHY);
    ctx.skip(
        "CreateDelegatedApplication / DeleteApplication with an ECC session (certificate with delegated-application rights)",
        "needs a CA root key at PICC level (ManageCARootKey is never done at PICC level by the suite) and a certificate carrying DAM rights",
    );
}

// ------------------------------------------------------------------ offline tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dam_selftest_passes() {
        dam_header_and_macs().unwrap();
        dam_ticket_and_quota().unwrap();
    }

    #[test]
    fn estimates_are_consistent() {
        for (name, _spec, h) in quota_cases(Aid(0xD00000)) {
            assert!(key_blocks(&h) <= conventional_blocks(&h), "{name}");
        }
        let h = AppHeader::new(1, 0, 0, 0);
        assert_eq!(conventional_blocks(&h), 3);
        assert_eq!(key_blocks(&h), 2);
        let vc = AppHeader { key_sett3: Some(2), ..h };
        assert_eq!(key_blocks(&vc), 5);
        assert_eq!(conventional_blocks(&vc), 7);
    }
}
