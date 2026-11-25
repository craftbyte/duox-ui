//! Section `iso_ev`: ISO/IEC 7816-4 commands (7.17), fast confidential UID retrieval (7.7.1.3) and EV charging
//! (7.19, VDE-AR-E 2532-100), always in throwaway applications.
//!
//! * ISOSelectFile (MF, PICC DF name, application by DF name and by file identifier, EF by identifier, P2 = 0C,
//!   FCI from file 0x1F, not found), ISOReadBinary / ISOUpdateBinary (current file and short file identifier,
//!   boundary), ISOReadRecord / ISOAppendRecord on a linear and a cyclic record file with the ISO numbering,
//!   ISOGetChallenge, the "no ISO command while authenticated" rule, rights of protected files.
//! * Fast confidential UID retrieval: application level SMConfig (bit 6) with an AppUIDENCKey, the encrypted UID in
//!   the FCI, refusals.
//! * EV charging provisioning per curve: application with the EV charging bit (SMConfig bit 4, guard approved inside a
//!   throwaway application), key 0, CryptoAPI access 0x0E, certificate file 0 (certificate from `evcert`) and data
//!   file 1; VDE_ReadData, VDE_WriteData, VDE lock, VDE_ECDSASign with signature verification, usage limit, access
//!   condition, refusals.

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use duox::card::{
    AccessRight, AccessRights, Aid, AppSpec, ChangeKeySpec, CommMode, DataFileSpec, IsoSelect, KeyPairOp, KeyPairSpec, ModeSel,
    RecordFileSpec,
};
use duox::crypto::{self, PubKey, CURVE_BP256, CURVE_P256};
use duox::evcert::{self, Date, EvCertificate};

pub const NAME: &str = "iso_ev";
pub const DESCRIPTION: &str =
    "ISO 7816-4 commands (select, binary, record, challenge), fast confidential UID, EV charging provisioning and VDE commands.";

const P_SIGN: u16 = 0x0010;
const FCI_DATA: &[u8; 12] = b"FCI-SUITE-OK";

pub fn run(ctx: &mut Ctx) {
    iso_basic(ctx);
    fast_uid(ctx);
    for curve in [CURVE_BP256, CURVE_P256] {
        ev(ctx, curve);
    }
}

// ------------------------------------------------------------------ helpers
fn cf<T>(r: Result<T, crypto::CryptoError>) -> StepResult<T> {
    r.map_err(|e| StepError::fail(format!("crypto: {}", e.0)))
}

fn zero_auth(c: &mut Ctx, aid: Aid) -> StepResult {
    let z = c.zero_key;
    c.auth_app(aid, 0, &z)
}

/// The command must fail with exactly this ISO status word.
fn expect_sw<T>(r: duox::Result<T>, sw: u16) -> StepResult {
    match r {
        Ok(_) => Err(StepError::fail(format!("accepted, expected status word {sw:04X}"))),
        Err(e) => ensure_eq(e.iso_sw(), Some(sw), &format!("status word ({e})")),
    }
}

/// The command must fail with some ISO status word; returns it.
fn expect_iso<T>(c: &mut Ctx, r: duox::Result<T>) -> StepResult<u16> {
    match r {
        Ok(_) => Err(StepError::fail("accepted, expected a refusal")),
        Err(e) => match e.iso_sw() {
            Some(sw) => {
                c.detail(format!("refused with {sw:04X}"));
                Ok(sw)
            }
            None => Err(StepError::fail(format!("expected an ISO status word, got: {e}"))),
        },
    }
}

fn names(aid: Aid) -> (Vec<u8>, u16) {
    (format!("DUOXSUITE{:06X}", aid.0).into_bytes(), 0xD300 | (aid.0 & 0xFF) as u16)
}

/// ISO select the application by DF name and then the EF.
fn enter_ef(c: &mut Ctx, name: &[u8], ef: u16) -> StepResult {
    c.select_application(Aid::PICC, None)?;
    c.iso_select(&IsoSelect::DfName(name))?;
    c.iso_select(&IsoSelect::EfUnderCurrent(ef))?;
    Ok(())
}

// ------------------------------------------------------------------ ISO commands
const F_BIN: u16 = 0xE101;
const F_LIN: u16 = 0xE102;
const F_CYC: u16 = 0xE103;
const F_PROT: u16 = 0xE106;

fn iso_basic(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let (name, fid) = names(aid);
    let spec = AppSpec::new(aid).keys(2).iso_file_ids().iso_name(fid, &name);
    ctx.app_scope(spec, |c, aid| {
        let provisioned = c.step("provision: binary file, linear and cyclic record files, protected file, FCI file 0x1F", |c| {
            zero_auth(c, aid)?;
            let (free, k0, k1) = (AccessRight::FREE, AccessRight::key(0), AccessRight::key(1));
            c.create_data_file(&DataFileSpec::new(0, 64, AccessRights::new(free, free, free, k0)).comm_mode(CommMode::Plain).iso_fid(F_BIN))?;
            c.create_record_file(&RecordFileSpec::new(1, AccessRights::new(free, free, free, k0), 16, 4).comm_mode(CommMode::Plain).iso_fid(F_LIN))?;
            c.create_record_file(&RecordFileSpec::new(2, AccessRights::new(free, free, free, k0), 16, 4).cyclic().comm_mode(CommMode::Plain).iso_fid(F_CYC))?;
            c.create_data_file(&DataFileSpec::new(3, 32, AccessRights::new(free, k1, AccessRight::NEVER, k0)).comm_mode(CommMode::Plain).iso_fid(F_PROT))?;
            c.create_data_file(&DataFileSpec::new(0x1F, 12, AccessRights::new(free, k0, AccessRight::NEVER, k0)).comm_mode(CommMode::Plain).iso_fid(0xE11F))?;
            c.write_data_with(0x1F, 0, FCI_DATA, ModeSel::Explicit(CommMode::Plain))?;
            ensure_eq(c.get_iso_file_ids()?, vec![F_BIN, F_LIN, F_CYC, F_PROT, 0xE11F], "ISO file identifiers")
        });
        if provisioned.is_none() {
            return;
        }
        select_variants(c, aid, &name, fid);
        binary_commands(c, aid, &name);
        record_commands(c, aid, &name);
        challenge_and_rules(c, aid, &name);
    });
}

fn select_variants(c: &mut Ctx, aid: Aid, name: &[u8], fid: u16) {
    c.step("ISOSelectFile: MF by empty data and by 3F00 selects the PICC level", |c| {
        let (fci, sw) = c.iso_select(&IsoSelect::Mf)?;
        ensure_eq((fci.len(), sw), (0, 0x9000), "FCI / status word of the MF selection")?;
        ensure_eq(c.selection().primary, Some(Aid::PICC), "selection after MF")?;
        let (_, sw) = c.iso_select(&IsoSelect::FileId(0x3F00))?;
        ensure_eq(sw, 0x9000, "status word of 3F00")?;
        ensure_eq(c.get_version()?.uid, c.uid.clone(), "GetVersion at the selected PICC level")
    });
    c.step("ISOSelectFile: the DESFire DF name D2760000850100 selects the PICC level", |c| {
        let (_, sw) = c.iso_select(&IsoSelect::DfName(&[0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00]))?;
        ensure_eq(sw, 0x9000, "status word")?;
        ensure_eq(c.get_version()?.uid, c.uid.clone(), "GetVersion at the selected PICC level")
    });
    c.step("ISOSelectFile: application by DF name returns the FCI from file 0x1F", |c| {
        c.select_application(Aid::PICC, None)?;
        let (fci, sw) = c.iso_select(&IsoSelect::DfName(name))?;
        ensure_eq(sw, 0x9000, "status word")?;
        ensure_eq(fci, FCI_DATA.to_vec(), "FCI")
    });
    c.step("ISOSelectFile: P2 = 0C selects without returning an FCI", |c| {
        c.select_application(Aid::PICC, None)?;
        let (fci, sw) = c.iso_select(&IsoSelect::Raw { p1: 0x04, p2: 0x0C, data: name })?;
        ensure_eq((fci.len(), sw), (0, 0x9000), "FCI / status word")
    });
    c.step("ISOSelectFile: application by file identifier (P1 = 00) and with P1 = 01 from the MF", |c| {
        c.select_application(Aid::PICC, None)?;
        let (fci, sw) = c.iso_select(&IsoSelect::FileId(fid))?;
        ensure_eq((fci, sw), (FCI_DATA.to_vec(), 0x9000), "FCI / status word by identifier")?;
        c.select_application(Aid::PICC, None)?;
        let (_, sw) = c.iso_select(&IsoSelect::Raw { p1: 0x01, p2: 0x00, data: &fid.to_be_bytes() })?;
        ensure_eq(sw, 0x9000, "status word of P1 = 01")
    });
    c.step("ISOSelectFile: P1 = 03 returns from an application to the MF", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let (_, sw) = c.iso_select(&IsoSelect::Raw { p1: 0x03, p2: 0x00, data: &[] })?;
        ensure_eq(sw, 0x9000, "status word")?;
        ensure_eq(c.selection().primary, Some(Aid::PICC), "selection")?;
        ensure_eq(c.get_version()?.uid, c.uid.clone(), "GetVersion at the PICC level")
    });
    c.step("ISOSelectFile: EF by identifier (P1 = 00) and under the current DF (P1 = 02)", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let (_, sw) = c.iso_select(&IsoSelect::FileId(F_BIN))?;
        ensure_eq(sw, 0x9000, "status word of the EF by identifier")?;
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let (_, sw) = c.iso_select(&IsoSelect::EfUnderCurrent(F_LIN))?;
        ensure_eq(sw, 0x9000, "status word of the EF under the current DF")
    });
    c.step("ISOSelectFile: unknown file identifier and unknown DF name give 6A82", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        expect_sw(c.iso_select(&IsoSelect::FileId(0x1234)), 0x6A82)?;
        c.select_application(Aid::PICC, None)?;
        expect_sw(c.iso_select(&IsoSelect::DfName(b"NO-SUCH-APP")), 0x6A82)
    });
    c.step("ISOSelectFile ends an authentication (the session is gone)", |c| {
        zero_auth(c, aid)?;
        ensure(c.is_authenticated(), "not authenticated")?;
        c.iso_select(&IsoSelect::DfName(name))?;
        ensure(!c.is_authenticated(), "still authenticated after ISOSelectFile")
    });
}

fn binary_commands(c: &mut Ctx, aid: Aid, name: &[u8]) {
    let pattern: Vec<u8> = (0..16u8).map(|i| 0xA0 + i).collect();
    c.step("ISOUpdateBinary / ISOReadBinary on the selected file: write 16 bytes, read back whole, partial, from an offset", |c| {
        enter_ef(c, name, F_BIN)?;
        c.iso_update_binary(&pattern, 0, None)?;
        ensure_eq(c.iso_read_binary(0, 16, None)?, pattern.clone(), "read of 16 bytes")?;
        ensure_eq(c.iso_read_binary(4, 8, None)?, pattern[4..12].to_vec(), "read at offset 4")?;
        let all = c.iso_read_binary(0, 0, None)?;
        ensure_eq(all.len(), 64, "Le = 0 returns the whole file")?;
        ensure_eq(&all[..16], &pattern[..], "start of the file")?;
        ensure(all[16..].iter().all(|&b| b == 0), "rest of the file is not zero")
    });
    c.step("ISOUpdateBinary / ISOReadBinary with a short file identifier and an offset", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let sfi = (F_BIN & 0x1F) as u8;
        let data = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        c.iso_update_binary(&data, 20, Some(sfi))?;
        ensure_eq(c.iso_read_binary(20, 5, Some(sfi))?, data.to_vec(), "read through the short identifier")?;
        ensure_eq(c.iso_read_binary(18, 9, Some(sfi))?, [&[0u8, 0][..], &data, &[0, 0]].concat(), "neighbouring bytes")
    });
    c.step("native ReadData sees what ISOUpdateBinary wrote (committed immediately)", |c| {
        c.select_application(aid, None)?;
        let d = c.read_data_with(0, 0, 64, ModeSel::Explicit(CommMode::Plain))?;
        ensure_eq(&d[..16], &pattern[..], "pattern")?;
        ensure_eq(&d[20..25], &[0x11u8, 0x22, 0x33, 0x44, 0x55][..], "short identifier write")
    });
    c.step("ISOUpdateBinary across the end of the file is refused", |c| {
        enter_ef(c, name, F_BIN)?;
        let r = c.iso_update_binary(&[0u8; 16], 56, None);
        expect_iso(c, r)?;
        Ok(())
    });
    // Only the read is tried at PICC level: the suite never sends ISO writes there.
    c.step("ISOReadBinary at PICC level is refused", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::Mf)?;
        let r = c.iso_read_binary(0, 4, None);
        expect_iso(c, r)?;
        Ok(())
    });
    c.step("a file whose write right needs key 1 refuses ISOUpdateBinary, reading stays free", |c| {
        enter_ef(c, name, F_PROT)?;
        let r = c.iso_update_binary(&[1, 2, 3], 0, None);
        expect_iso(c, r)?;
        enter_ef(c, name, F_PROT)?;
        ensure_eq(c.iso_read_binary(0, 4, None)?, vec![0u8; 4], "free read")
    });
}

fn records(tag: u8) -> Vec<Vec<u8>> {
    (1..=5u8).map(|n| (0..16u8).map(|i| tag.wrapping_add(n << 4).wrapping_add(i)).collect()).collect()
}

fn record_commands(c: &mut Ctx, aid: Aid, name: &[u8]) {
    let lin = records(0x10);
    let cyc = records(0x80);
    let lin_sfi = (F_LIN & 0x1F) as u8;
    let cyc_sfi = (F_CYC & 0x1F) as u8;
    c.step("linear record file: four ISOAppendRecord, then record 1 is the oldest, 0 is the current one", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        for r in &lin[..4] {
            c.iso_append_record(r, lin_sfi)?;
        }
        for (i, r) in lin[..4].iter().enumerate() {
            ensure_eq(c.iso_read_record(i as u8 + 1, false, lin_sfi, 0)?, r.clone(), &format!("record {}", i + 1))?;
        }
        ensure_eq(c.iso_read_record(0, false, lin_sfi, 0)?, lin[3].clone(), "current record (last written)")?;
        ensure_eq(c.iso_read_record(1, true, lin_sfi, 0)?, lin[..4].concat(), "records 1 to the end")?;
        ensure_eq(c.iso_read_record(3, true, lin_sfi, 0)?, lin[2..4].concat(), "records 3 to the end")
    });
    c.step("linear record file: native ReadRecords returns the same records in the same order", |c| {
        c.select_application(aid, None)?;
        let d = c.read_records_with(1, 0, 0, ModeSel::Explicit(CommMode::Plain))?;
        ensure_eq(d, lin[..4].concat(), "records read natively")
    });
    c.step("linear record file: a fifth record (file full), a missing record 5 and a 17 byte record are refused", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let r = c.iso_append_record(&lin[4], lin_sfi);
        expect_iso(c, r)?;
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let r = c.iso_read_record(5, false, lin_sfi, 0);
        expect_iso(c, r)?;
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let r = c.iso_append_record(&[0u8; 17], cyc_sfi);
        expect_iso(c, r)?;
        Ok(())
    });
    c.step("cyclic record file: record 1 is the most recent; the fourth append overwrites the oldest (holds 3)", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        for r in &cyc[..4] {
            c.iso_append_record(r, cyc_sfi)?;
        }
        ensure_eq(c.iso_read_record(1, false, cyc_sfi, 0)?, cyc[3].clone(), "record 1")?;
        ensure_eq(c.iso_read_record(2, false, cyc_sfi, 0)?, cyc[2].clone(), "record 2")?;
        ensure_eq(c.iso_read_record(3, false, cyc_sfi, 0)?, cyc[1].clone(), "record 3")?;
        ensure_eq(c.iso_read_record(0, false, cyc_sfi, 0)?, cyc[3].clone(), "current record")?;
        // measured: "all from P1" runs from record P1 up to the newest, oldest first
        ensure_eq(c.iso_read_record(3, true, cyc_sfi, 0)?, [cyc[1].clone(), cyc[2].clone(), cyc[3].clone()].concat(), "all records (from 3)")?;
        ensure_eq(c.iso_read_record(1, true, cyc_sfi, 0)?, cyc[3].clone(), "all from record 1 = the newest only")?;
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        let r = c.iso_read_record(4, false, cyc_sfi, 0);
        expect_iso(c, r)?;
        Ok(())
    });
    c.step("ISOReadRecord with a short Le returns the first bytes of the record", |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(name))?;
        ensure_eq(c.iso_read_record(1, false, lin_sfi, 5)?, lin[0][..5].to_vec(), "first 5 bytes")
    });
}

fn challenge_and_rules(c: &mut Ctx, aid: Aid, name: &[u8]) {
    c.step("ISOGetChallenge returns the requested length (1, 8, 16, 32) and fresh random bytes", |c| {
        c.select_application(Aid::PICC, None)?;
        for n in [1u8, 8, 16, 32] {
            ensure_eq(c.iso_get_challenge(n)?.len(), n as usize, &format!("length of a {n} byte challenge"))?;
        }
        let a = c.iso_get_challenge(16)?;
        let b = c.iso_get_challenge(16)?;
        ensure(a != b, "two challenges are identical")?;
        ensure(c.iso_get_challenge(0).is_err(), "length 0 accepted by the library")
    });
    c.step("ISOGetChallenge works with an application selected", |c| {
        c.select_application(aid, None)?;
        ensure_eq(c.iso_get_challenge(16)?.len(), 16, "challenge length")
    });
    c.step("ISO commands are refused while an AES session is active (6982)", |c| {
        zero_auth(c, aid)?;
        expect_sw(c.iso_get_challenge(8), 0x6982)?;
        zero_auth(c, aid)?;
        let r = c.iso_read_binary(0, 4, None);
        expect_iso(c, r)?;
        Ok(())
    });
    c.step("VDE commands are refused in an application without the EV charging option", |c| {
        c.select_application(aid, None)?;
        let r = c.vde_read_data(0);
        expect_iso(c, r)?;
        c.select_application(aid, None)?;
        let r = c.vde_ecdsa_sign(&[0u8; 32]);
        expect_iso(c, r)?;
        let _ = name;
        Ok(())
    });
}

// ------------------------------------------------------------------ fast confidential UID
fn fast_uid(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let (name, fid) = names(aid);
    let spec = AppSpec::new(aid).keys(3).iso_file_ids().iso_name(fid, &name);
    let uid = ctx.uid.clone();
    ctx.app_scope(spec, |c, aid| {
        let key = c.step("fast UID: change key 2 (AppUIDENCKey) and enable SMConfig bit 6 with key number 2", |c| {
            let k = crypto::rnd(16);
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            c.change_key(&ChangeKeySpec::new(2, &k, 2).old_key(&z))?;
            c.auth_app(aid, 0, &z)?;
            c.set_configuration(0x04, &[0x00, 0x40, 0x02])?;
            c.auth_app(aid, 0, &z)?;
            match c.get_configuration(Some(0x04)) {
                Ok(v) => c.detail(format!("GetConfiguration 0x04: {}", hex::encode_upper(v))),
                Err(e) => c.detail(format!("GetConfiguration 0x04 is not readable here: {e}")),
            }
            Ok(k)
        });
        let Some(key) = key else { return };
        c.step("fast UID: ISOSelectFile by DF name returns the encrypted VCData; decrypted with the AppUIDENCKey it is the UID", |c| {
            c.select_application(Aid::PICC, None)?;
            let (fci, sw) = c.iso_select(&IsoSelect::DfName(&name))?;
            ensure_eq(sw, 0x9000, "status word")?;
            ensure_eq(&fci[..4], &[0x6Fu8, 0x22, 0x85, 0x20][..], "FCI header")?;
            ensure_eq(fci.len(), 36, "FCI length")?;
            let f = c.fci_fast_uid(&fci, &key)?.ok_or("the FCI carries no encrypted UID")?;
            c.detail(format!("INFO {:02X} VCTID {:02X} PDCap1 {:02X?}", f.info, f.vctid, f.pd_cap1));
            ensure_eq(f.uid.clone(), uid.clone(), "decrypted UID")?;
            ensure_eq(c.uid().to_vec(), uid.clone(), "Card::uid after the retrieval")
        });
        c.step("fast UID: selection by file identifier works the same, and every selection uses a new IV", |c| {
            c.select_application(Aid::PICC, None)?;
            let (a, _) = c.iso_select(&IsoSelect::FileId(fid))?;
            c.select_application(Aid::PICC, None)?;
            let (b, _) = c.iso_select(&IsoSelect::FileId(fid))?;
            ensure(a != b, "the FCI repeated (IV not fresh)")?;
            for fci in [&a, &b] {
                let f = c.fci_fast_uid(fci, &key)?.ok_or("no encrypted UID")?;
                ensure_eq(f.uid, uid.clone(), "decrypted UID")?;
            }
            Ok(())
        });
        c.step("fast UID: a wrong AppUIDENCKey does not decrypt to a plausible UID", |c| {
            c.select_application(Aid::PICC, None)?;
            let (fci, _) = c.iso_select(&IsoSelect::DfName(&name))?;
            ensure(c.fci_fast_uid(&fci, &[0x5Au8; 16]).is_err(), "a wrong key decrypted to a plausible UID")
        });
        c.step("fast UID: native SelectApplication is unaffected (no FCI)", |c| {
            c.select_application(aid, None)?;
            let z = c.zero_key;
            c.authenticate_ev2_first(0, &z, &[])?;
            Ok(())
        });
    });
    // refusals need applications of their own
    let aid2 = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid2).keys(2), |c, aid| {
        c.step("fast UID needs an ISO file identifier and DF name: SetConfiguration 0x04 bit 6 is refused (PERMISSION_DENIED)", |c| {
            zero_auth(c, aid)?;
            let r = c.set_configuration(0x04, &[0x00, 0x40, 0x00]);
            c.expect_err(duox::card::Status::PermissionDenied, r)
        });
    });
    let aid3 = ctx.alloc_aid();
    let (name3, fid3) = names(aid3);
    ctx.app_scope(AppSpec::new(aid3).keys(2).iso_file_ids().iso_name(fid3, &name3), |c, aid| {
        c.step("fast UID together with ISOSelectFile integrated ECC authentication (bits 6 and 3) is refused (PERMISSION_DENIED)", |c| {
            zero_auth(c, aid)?;
            let r = c.set_configuration(0x04, &[0x00, 0x48, 0x00]);
            c.expect_err(duox::card::Status::PermissionDenied, r)
        });
    });
}

// ------------------------------------------------------------------ EV charging
struct Ev {
    aid: Aid,
    name: Vec<u8>,
    curve: u8,
    pubk: PubKey,
    ca_pub: PubKey,
    cert: Vec<u8>,
    limit: u32,
}

fn ev_cert_file_size(uid_len: usize) -> u32 {
    if uid_len == 10 {
        199
    } else {
        193
    }
}

fn ev(ctx: &mut Ctx, curve: u8) {
    let cname = crypto::curve_name(curve);
    let aid = ctx.alloc_aid();
    let (name, fid) = names(aid);
    let uid = ctx.uid.clone();
    // KeySett3 bit 2: application specific CryptoAPI configuration (SetConfiguration 0x15)
    let spec = AppSpec::new(aid).keys(2).iso_file_ids().iso_name(fid, &name).key_sett3(0x04);
    let limit = if curve == CURVE_BP256 { 6 } else { 0 };
    ctx.app_scope(spec, |c, aid| {
        let ev = c.step(&format!("EV {cname}: provision (SMConfig bit 4, key 0, CryptoAPI 0x0E, certificate file 0, data file 1, EvCert)"), |c| {
            zero_auth(c, aid)?;
            c.set_configuration(0x04, &[0x00, 0x10])?;
            c.auth_app(aid, 0, &[0u8; 16])?;
            c.set_configuration(0x15, &[0x02, 0x0E])?;
            c.auth_app(aid, 0, &[0u8; 16])?;
            let raw = c.manage_key_pair(&KeyPairSpec::new(0, curve, P_SIGN, 0x0F).kuc_limit(limit), &KeyPairOp::Generate, None)?;
            let pubk = cf(PubKey::from_bytes(curve, &raw))?;
            let (free, k0) = (AccessRight::FREE, AccessRight::key(0));
            let size = ev_cert_file_size(uid.len());
            c.create_data_file(&DataFileSpec::new(0, size, AccessRights::new(free, k0, k0, k0)).comm_mode(CommMode::Full).iso_fid(0x00EF))?;
            c.create_data_file(&DataFileSpec::new(1, 1024, AccessRights::all(free)).comm_mode(CommMode::Plain).iso_fid(0x01EF))?;
            let ca = cf(crypto::gen_key(curve))?;
            let cert = evcert::build(&ca, "99999999999999", &uid, &raw, curve, Date::today_utc(), 20).map_err(|e| StepError::fail(e.to_string()))?;
            ensure(cert.len() as u32 <= size, format!("certificate of {} bytes does not fit file 0 ({size} bytes)", cert.len()))?;
            c.write_data(0, 0, &cert)?;
            c.detail(format!("certificate {} bytes in a {size} byte file", cert.len()));
            Ok(Ev { aid, name: name.clone(), curve, pubk, ca_pub: ca.public(), cert, limit })
        });
        let Some(ev) = ev else { return };
        ev_steps(c, &ev, &uid);
    });
}

fn ev_steps(c: &mut Ctx, ev: &Ev, uid: &[u8]) {
    let cname = crypto::curve_name(ev.curve);
    let size = ev_cert_file_size(uid.len()) as usize;
    c.step(&format!("EV {cname}: key 0 reports sign policy, write access 0x0F and the configured limit"), |c| {
        zero_auth(c, ev.aid)?;
        let k = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
        ensure_eq((k.curve, k.policy, k.write_access, k.kuc_limit, k.kuc), (ev.curve, P_SIGN, 0x0F, ev.limit, 0), "key 0")
    });
    c.step(&format!("EV {cname}: VDE_ReadData file 0 (after ISOSelectFile by DF name) returns the certificate, which verifies"), |c| {
        c.select_application(Aid::PICC, None)?;
        c.iso_select(&IsoSelect::DfName(&ev.name))?;
        let d = c.vde_read_data(0)?;
        ensure_eq(d.len(), size, "bytes returned for file 0")?;
        ensure_eq(&d[..ev.cert.len()], &ev.cert[..], "certificate bytes")?;
        ensure(d[ev.cert.len()..].iter().all(|&b| b == 0), "padding behind the certificate is not zero")?;
        let p = EvCertificate::parse(&d).map_err(|e| StepError::fail(e.to_string()))?;
        ensure_eq(p.length, ev.cert.len(), "certificate length")?;
        ensure(p.verify(&ev.ca_pub), "certificate signature does not verify with the CA key")?;
        ensure_eq(p.holder_key().map_err(|e| StepError::fail(e.to_string()))?, ev.pubk.clone(), "holder key")?;
        ensure_eq((p.serial.clone(), p.subject.clone(), p.curve), (uid.to_vec(), uid.to_vec(), Some(ev.curve)), "serial / subject / curve")
    });
    c.step(&format!("EV {cname}: file 0 is also readable natively with the application key (Full mode)"), |c| {
        zero_auth(c, ev.aid)?;
        ensure_eq(c.read_data(0, 0, ev.cert.len() as u32)?, ev.cert.clone(), "certificate through ReadData")
    });
    c.step(&format!("EV {cname}: VDE_ReadData file 1 starts all zero; VDE_WriteData writes at the start of the file"), |c| {
        c.select_application(ev.aid, None)?;
        let d = c.vde_read_data(1)?;
        ensure_eq(d.len(), 256, "Le = 0 returns 256 bytes")?;
        ensure(d.iter().all(|&b| b == 0), "file 1 is not zero on creation")?;
        let data = crypto::rnd(100);
        c.select_application(ev.aid, None)?;
        c.vde_write_data(&data)?;
        c.select_application(ev.aid, None)?;
        let d = c.vde_read_data(1)?;
        ensure_eq(&d[..100], &data[..], "data written")?;
        ensure(d[100..].iter().all(|&b| b == 0), "bytes behind the written data changed")
    });
    let mut signs = 0u32;
    c.step(&format!("EV {cname}: VDE_ECDSASign signs a 32-byte challenge; the signature verifies with the certified key"), |c| {
        c.select_application(ev.aid, None)?;
        let ch = crypto::rnd(32);
        let sig = c.vde_ecdsa_sign(&ch)?;
        ensure_eq(sig.len(), 64, "signature length")?;
        ensure(ev.pubk.verify_raw(&sig, &ch), "signature does not verify over the challenge")?;
        ensure(ev.pubk.verify_hash(&sig, &crypto::sha256(&ch)), "signature does not verify over SHA-256(challenge)")?;
        c.select_application(ev.aid, None)?;
        let sig2 = c.vde_ecdsa_sign(&ch)?;
        ensure(sig2 != sig && ev.pubk.verify_raw(&sig2, &ch), "second signature")
    });
    signs += 2;
    c.step(&format!("EV {cname}: VDE commands refuse a challenge of the wrong length (library) and any command while authenticated"), |c| {
        c.select_application(ev.aid, None)?;
        ensure(matches!(c.vde_ecdsa_sign(&[0u8; 31]), Err(duox::Error::InvalidArgument(_))), "31 byte challenge accepted")?;
        zero_auth(c, ev.aid)?;
        let r = c.vde_read_data(0);
        expect_iso(c, r)?;
        zero_auth(c, ev.aid)?;
        let r = c.vde_ecdsa_sign(&[1u8; 32]);
        expect_iso(c, r)?;
        Ok(())
    });
    c.step(&format!("EV {cname}: CryptoAPI access 0x00 (key 0) refuses VDE_ECDSASign, 0x0E allows it again"), |c| {
        zero_auth(c, ev.aid)?;
        c.set_configuration(0x15, &[0x02, 0x00])?;
        c.select_application(ev.aid, None)?;
        let r = c.vde_ecdsa_sign(&[2u8; 32]);
        expect_iso(c, r)?;
        zero_auth(c, ev.aid)?;
        c.set_configuration(0x15, &[0x02, 0x0E])?;
        c.select_application(ev.aid, None)?;
        let ch = crypto::rnd(32);
        let sig = c.vde_ecdsa_sign(&ch)?;
        ensure(ev.pubk.verify_raw(&sig, &ch), "signature after restoring access 0x0E")
    });
    signs += 1;
    if ev.limit > 0 {
        c.step(&format!("EV {cname}: usage limit {}: signatures count, the one after the limit is refused", ev.limit), |c| {
            for _ in signs..ev.limit {
                c.select_application(ev.aid, None)?;
                let ch = crypto::rnd(32);
                let sig = c.vde_ecdsa_sign(&ch)?;
                ensure(ev.pubk.verify_raw(&sig, &ch), "signature")?;
            }
            zero_auth(c, ev.aid)?;
            let k = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
            ensure_eq((k.kuc_limit, k.kuc), (ev.limit, ev.limit), "usage counter at the limit")?;
            c.select_application(ev.aid, None)?;
            let r = c.vde_ecdsa_sign(&[3u8; 32]);
            expect_iso(c, r)?;
            Ok(())
        });
    } else {
        c.step(&format!("EV {cname}: without a usage limit nothing is counted"), |c| {
            c.select_application(ev.aid, None)?;
            c.vde_ecdsa_sign(&[4u8; 32])?;
            zero_auth(c, ev.aid)?;
            let k = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
            ensure_eq((k.kuc_limit, k.kuc), (0, 0), "limit / counter")
        });
    }
    c.step(&format!("EV {cname}: the key cannot be replaced (write access 0x0F): ManageKeyPair is refused (PERMISSION_DENIED)"), |c| {
        zero_auth(c, ev.aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(0, ev.curve, P_SIGN, 0x0F), &KeyPairOp::Generate, None);
        c.expect_err(duox::card::Status::PermissionDenied, r)
    });
    c.step(&format!("EV {cname}: VDE lock: further VDE_WriteData is refused, reading still works, rights become no access"), |c| {
        c.select_application(ev.aid, None)?;
        let before = c.vde_read_data(1)?;
        c.select_application(ev.aid, None)?;
        c.vde_lock()?;
        c.select_application(ev.aid, None)?;
        let r = c.vde_write_data(&[0xEE; 8]);
        expect_iso(c, r)?;
        c.select_application(ev.aid, None)?;
        ensure_eq(c.vde_read_data(1)?, before, "file 1 after the refused write")?;
        zero_auth(c, ev.aid)?;
        let fs = c.get_file_settings(1)?;
        ensure_eq(
            (fs.access.read, fs.access.write, fs.access.read_write, fs.access.change),
            (AccessRight::FREE, AccessRight::NEVER, AccessRight::NEVER, AccessRight::NEVER),
            "access rights of file 1 after the lock",
        )
    });
}

// ------------------------------------------------------------------ offline tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ev_certificate_fits_the_delivery_file_sizes_on_both_curves() {
        for curve in [CURVE_BP256, CURVE_P256] {
            for uid_len in [7usize, 10] {
                let ca = crypto::gen_key(curve).unwrap();
                let holder = crypto::gen_key(curve).unwrap();
                let uid = crypto::rnd(uid_len);
                let cert = evcert::build(&ca, "99999999999999", &uid, &holder.public().to_bytes(), curve, Date::today_utc(), 20).unwrap();
                assert!(cert.len() as u32 <= ev_cert_file_size(uid_len), "{} bytes", cert.len());
                let mut padded = cert.clone();
                padded.resize(ev_cert_file_size(uid_len) as usize, 0);
                let p = EvCertificate::parse(&padded).unwrap();
                assert_eq!(p.length, cert.len());
                assert!(p.verify(&ca.public()));
                assert_eq!((p.serial.clone(), p.subject.clone()), (uid.clone(), uid));
            }
        }
    }

    #[test]
    fn record_patterns_are_distinct_and_16_bytes() {
        for tag in [0x10u8, 0x80] {
            let r = records(tag);
            assert_eq!(r.len(), 5);
            assert!(r.iter().all(|x| x.len() == 16));
            for i in 0..5 {
                for j in i + 1..5 {
                    assert_ne!(r[i], r[j]);
                }
            }
        }
    }

    #[test]
    fn names_are_valid_iso_identifiers() {
        for n in [0xD00000u32, 0xD000FF, 0xD0FFFF] {
            let (name, fid) = names(Aid(n));
            assert!((1..=16).contains(&name.len()));
            assert!(![0x0000u16, 0x3F00, 0x3FFF, 0xFFFF].contains(&fid));
        }
    }

    #[test]
    fn iso_error_helpers() {
        let e: duox::Result<()> = Err(duox::Error::Iso { command: "x".into(), sw: 0x6A82 });
        assert!(expect_sw(e, 0x6A82).is_ok());
        let e: duox::Result<()> = Err(duox::Error::Iso { command: "x".into(), sw: 0x6A82 });
        assert!(expect_sw(e, 0x6982).is_err());
        assert!(expect_sw(Ok(()), 0x6982).is_err());
    }
}
