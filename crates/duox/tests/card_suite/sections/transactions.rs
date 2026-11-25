//! Section `transactions`: CommitTransaction / AbortTransaction / CommitReaderID, the TransactionMAC
//! file with Transaction MAC (AES-128 and AES-256 keys) and Transaction Signature (ECC key), exclusion
//! maps, TMCLimit, key usage limit of the signature key, and the Transaction MAC Input recorded by the
//! library (`Card::new_transaction`, `Tmi`) checked against the TMV / TSV the card computed
//! (verification with `duox::txmac`). Sections 7.12.1.5, 7.12.4.6, 7.14 of the data sheet.
//!
//! Everything happens inside throwaway applications created with `ctx.app_scope`; nothing at PICC level
//! is changed (the only PICC level commands are three refused ones in the negative tests).
//!
//! Per variant the section creates: a BackupData file, a Value file, a LinearRecord file, a second
//! BackupData file and the TransactionMAC file, and then runs transactions that touch all of them.

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use duox::card::types::cmd;
use duox::card::{
    Aid, AccessRight, AccessRights, AppSpec, CommMode, CommitResult, DataFileSpec, FileSettingsChange, FileType,
    KeyPairOp, KeyPairSpec, RecordFileSpec, Status, TmacFileSpec, ValueFileSpec,
};
use duox::crypto::{self, PubKey};
use duox::txmac::{self, Tmi};

pub const NAME: &str = "transactions";
pub const DESCRIPTION: &str =
    "Transactions: commit / abort, TransactionMAC file (AES-128 / AES-256 / ECC signature), exclusion map, TMCLimit, CommitReaderID, TMI vs card TMV / TSV.";

// file numbers inside every test application
const BAK: u8 = 0;
const VAL: u8 = 1;
const REC: u8 = 2;
const BAK2: u8 = 3;
const TM: u8 = 4;
/// Key version given to the Transaction MAC key.
const KVER: u8 = 0x5A;

pub fn run(ctx: &mut Ctx) {
    // AES-128 key, TMAC file in Full mode: the long battery (exclusion, TMCLimit, negatives, re-creation)
    variant(
        ctx,
        Cfg { label: "TMAC AES-128", mode: CommMode::Full, kind: Kind::Aes128, reader: false, extras: true },
    );
    // AES-256 key with authenticated CommitReaderID, TMAC file in Plain mode
    variant(
        ctx,
        Cfg { label: "TMAC AES-256", mode: CommMode::Plain, kind: Kind::Aes256, reader: true, extras: false },
    );
    // Transaction Signature, NIST P-256 key, TMAC file in MAC mode; exclusion and TMCLimit
    variant(
        ctx,
        Cfg { label: "TSIG P-256", mode: CommMode::Mac, kind: Kind::Sig(crypto::CURVE_P256), reader: false, extras: true },
    );
    // Transaction Signature, brainpoolP256r1 key plus an AES-128 key for CommitReaderID, Full mode
    variant(
        ctx,
        Cfg {
            label: "TSIG brainpoolP256r1 + ReaderID",
            mode: CommMode::Full,
            kind: Kind::Sig(crypto::CURVE_BP256),
            reader: true,
            extras: false,
        },
    );
    signature_config_errors(ctx);
    signature_key_usage_limit(ctx);
    no_tmac_application(ctx);
    ctx.skip(
        "TMAC in an AES-256 application",
        "creating an AES-256 application needs a 32-byte PICCAppDefaultKey (PICC level state, owned by the picc section); \
         the AES-256 Transaction MAC key itself is covered inside an AES-128 application",
    );
}

// ------------------------------------------------------------------ configuration and state
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Aes128,
    Aes256,
    /// Transaction Signature with an ECC key of this curve.
    Sig(u8),
}

#[derive(Clone)]
struct Cfg {
    label: &'static str,
    mode: CommMode,
    kind: Kind,
    /// FileAR.ReadWrite = key 1: CommitReaderID required (needs a symmetric TMAC key).
    reader: bool,
    /// exclusion map, TMCLimit, negative tests, deletion and re-creation of the TMAC file.
    extras: bool,
}

/// Facts about the application under test.
#[derive(Clone)]
struct Env {
    aid: Aid,
    auth_key: Vec<u8>,
    uid: Vec<u8>,
    tm_key: Vec<u8>,
    kver: u8,
    sig: Option<PubKey>,
    mode: CommMode,
    reader: bool,
}

impl Env {
    /// Access rights of the TransactionMAC file: read key 1, write RFU (0xF), ReadWrite as given, change key 0.
    fn tmac_ar(&self, rw: AccessRight) -> AccessRights {
        AccessRights::new(AccessRight::key(1), AccessRight::NEVER, rw, AccessRight::key(0))
    }
    fn key_option(&self) -> u8 {
        tm_key_option(self.tm_key.len(), self.sig.is_some())
    }
}

/// TMKeyOption: bit 7 signature, bits 1..0 key type (2 AES-128, 3 AES-256, 0 none).
fn tm_key_option(key_len: usize, signature: bool) -> u8 {
    let t = match key_len {
        16 => 2,
        32 => 3,
        _ => 0,
    };
    t | if signature { 0x80 } else { 0 }
}

/// What the suite expects the card to hold; updated after every successful commit.
#[derive(Clone)]
struct St {
    tmc: u32,
    /// TMRIPrev: the ReaderID of the latest successful authenticated transaction.
    prev_tmri: Vec<u8>,
    excl: u32,
    limit: Option<u32>,
    rw: AccessRight,
    bak: Vec<u8>,
    bak2: Vec<u8>,
    val: i32,
    rec_data: Vec<u8>,
}

impl St {
    fn new(env: &Env) -> St {
        St {
            tmc: 0,
            prev_tmri: vec![0; 16],
            excl: 0,
            limit: None,
            rw: if env.reader { AccessRight::key(1) } else { AccessRight::NEVER },
            bak: vec![0; 32],
            bak2: vec![0; 32],
            val: 100,
            rec_data: vec![],
        }
    }
    fn recs(&self) -> u32 {
        (self.rec_data.len() / 16) as u32
    }
}

fn fill(b: u8, n: usize) -> Vec<u8> {
    vec![b; n]
}

fn ar_data() -> AccessRights {
    AccessRights::new(AccessRight::key(1), AccessRight::key(1), AccessRight::key(1), AccessRight::key(0))
}

fn tx_err(e: txmac::TxMacError) -> StepError {
    StepError::fail(format!("txmac: {e}"))
}

fn cr_err(e: crypto::CryptoError) -> StepError {
    StepError::fail(format!("crypto: {e}"))
}

// ------------------------------------------------------------------ pure helpers (offline tested)
/// Split the content of a TransactionMAC file into (TMC, TMV or TSV).
fn parse_tm_file(d: &[u8], signature: bool) -> Result<(u32, Vec<u8>), String> {
    let want = if signature { 68 } else { 12 };
    if d.len() != want {
        return Err(format!("TransactionMAC file holds {} bytes, expected {want}", d.len()));
    }
    Ok((u32::from_le_bytes([d[0], d[1], d[2], d[3]]), d[4..].to_vec()))
}

/// Check a TMV / TSV against the recorded TMI.
fn verify_values(env: &Env, tmc: u32, value: &[u8], tmi: &[u8]) -> StepResult {
    let ok = match &env.sig {
        None => txmac::verify_tmv(&env.tm_key, tmc, &env.uid, tmi, value).map_err(tx_err)?,
        Some(p) => value.len() == 64 && txmac::verify_tsv(p, value, tmi, tmc),
    };
    ensure(
        ok,
        format!(
            "{} does not match the TMI recorded by the library (TMC {tmc}, TMI {} bytes: {})",
            if env.sig.is_some() { "TSV" } else { "TMV" },
            tmi.len(),
            hex::encode_upper(tmi)
        ),
    )
}

// ------------------------------------------------------------------ card helpers
fn enter(c: &mut Ctx, env: &Env, key_no: u8, st: &St) -> StepResult {
    c.auth_app(env.aid, key_no, &env.auth_key)?;
    c.new_transaction(Some(st.excl));
    Ok(())
}

fn read_tm(c: &mut Ctx, env: &Env) -> StepResult<(u32, Vec<u8>)> {
    let d = c.read_data(TM, 0, 0)?;
    parse_tm_file(&d, env.sig.is_some()).map_err(StepError::Fail)
}

/// The ReaderID step of a transaction (only when the file requires it). Returns the committed ReaderID.
fn reader_step(c: &mut Ctx, env: &Env, st: &St) -> StepResult<Option<Vec<u8>>> {
    if !env.reader {
        return Ok(None);
    }
    let tmri = crypto::rnd(16);
    let enc = c.commit_reader_id(&tmri)?;
    ensure_eq(enc.len(), 16, "EncTMRI length")?;
    let uid = c.uid.clone();
    let dec = txmac::decrypt_reader_id(&env.tm_key, st.tmc + 1, &uid, &enc).map_err(tx_err)?;
    ensure_eq(dec, st.prev_tmri.clone(), "ReaderID of the previous transaction, decrypted from EncTMRI")?;
    Ok(Some(tmri))
}

/// One complete transaction: enter with key 1, `ops`, optional CommitReaderID, CommitTransaction with TMC / TMV
/// (TSV) requested, check status / TMC / value against the library's TMI, check the TransactionMAC file.
fn run_txn(c: &mut Ctx, env: &Env, st: &mut St, ops: impl FnOnce(&mut Ctx) -> StepResult) -> StepResult<CommitResult> {
    enter(c, env, 1, st)?;
    let (t0, _) = read_tm(c, env)?;
    ensure_eq(t0, st.tmc, "TMC on the card before the transaction")?;
    ops(c)?;
    let tmri = reader_step(c, env, st)?;
    let r = c.commit_transaction(true, env.mode)?;
    finish_commit(c, env, st, &r, tmri)?;
    Ok(r)
}

/// Checks after a successful CommitTransaction that asked for TMC / TMV (TSV).
fn finish_commit(c: &mut Ctx, env: &Env, st: &mut St, r: &CommitResult, tmri: Option<Vec<u8>>) -> StepResult {
    ensure_eq(r.status, 0, "CommitTransaction status")?;
    let next = st.tmc + 1;
    ensure_eq(r.tmc, Some(next), "TMC in the CommitTransaction response")?;
    let value = if env.sig.is_some() { r.tsv.clone() } else { r.tmv.clone() };
    let value = value.ok_or_else(|| StepError::fail("the response carries no TMV / TSV"))?;
    ensure_eq(value.len(), if env.sig.is_some() { 64 } else { 8 }, "TMV / TSV length")?;
    verify_values(env, next, &value, &r.tmi)?;
    if let Some(t) = tmri {
        st.prev_tmri = t;
    }
    st.tmc = next;
    enter(c, env, 1, st)?;
    let (t1, v1) = read_tm(c, env)?;
    ensure_eq(t1, next, "TMC read from the TransactionMAC file")?;
    ensure_eq(v1, value, "TMV / TSV read from the TransactionMAC file")
}

/// The card holds the data the suite expects (TMC, files).
fn check_state(c: &mut Ctx, env: &Env, st: &St) -> StepResult {
    enter(c, env, 1, st)?;
    let (t, _) = read_tm(c, env)?;
    ensure_eq(t, st.tmc, "TMC")?;
    ensure_eq(c.read_data(BAK, 0, 0)?, st.bak.clone(), "BackupData file")?;
    ensure_eq(c.read_data(BAK2, 0, 0)?, st.bak2.clone(), "second BackupData file")?;
    ensure_eq(c.get_value(VAL)?, st.val, "Value file")?;
    let fs = c.get_file_settings(REC)?;
    ensure_eq(fs.record.as_ref().map(|r| r.current_records), Some(st.recs()), "number of records")?;
    if st.recs() > 0 {
        ensure_eq(c.read_records(REC, 0, 0)?, st.rec_data.clone(), "record file content")?;
    }
    Ok(())
}

fn check_settings(c: &mut Ctx, env: &Env, st: &St) -> StepResult {
    enter(c, env, 1, st)?;
    let fs = c.get_file_settings(TM)?;
    c.detail(format!("option {:02X}, access {:04X}", fs.option, fs.access.to_u16()));
    ensure_eq(fs.file_type, FileType::TransactionMac, "file type")?;
    ensure_eq(fs.comm_mode(), env.mode, "CommMode")?;
    ensure_eq(fs.access.to_u16(), env.tmac_ar(st.rw).to_u16(), "access rights")?;
    let t = fs.tmac.clone().ok_or_else(|| StepError::fail("no TransactionMAC settings in the response"))?;
    ensure_eq(t.key_option, env.key_option(), "TMKeyOption")?;
    ensure_eq(t.key_version, if env.tm_key.is_empty() { None } else { Some(env.kver) }, "TMKeyVer")?;
    ensure_eq(t.tsig_key, if env.sig.is_some() { Some(0) } else { None }, "TSIGKeyNo")?;
    ensure_eq(t.excl_map, if st.excl != 0 { Some(st.excl) } else { None }, "TMIExclFileMap")?;
    ensure_eq(t.tmc_limit, st.limit, "TMCLimit")
}

/// ChangeFileSettings of the TransactionMAC file to the state described by `st` (key 0 session).
fn change_tm(c: &mut Ctx, env: &Env, st: &St) -> StepResult {
    c.auth_app(env.aid, 0, &env.auth_key)?;
    let opt = env.mode.bits() | if st.excl != 0 { 0x40 } else { 0 } | if st.limit.is_some() { 0x20 } else { 0 };
    let mut ch = FileSettingsChange::new(opt, env.tmac_ar(st.rw));
    ch.tmac_excl_map = if st.excl != 0 { Some(st.excl) } else { None };
    ch.tmc_limit = st.limit;
    c.change_file_settings(TM, &ch)?;
    Ok(())
}

// ------------------------------------------------------------------ one variant
fn variant(ctx: &mut Ctx, cfg: Cfg) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        let Some(mut env) = setup(ctx, aid, &cfg, 0) else { return };
        let mut st = St::new(&env);
        let l = cfg.label;

        ctx.step(&format!("{l}: GetFileSettings of the TransactionMAC file and its initial content (TMC 0, value zero)"), |c| {
            check_settings(c, &env, &st)?;
            let (t, v) = read_tm(c, &env)?;
            ensure_eq(t, 0, "initial TMC")?;
            ensure(v.iter().all(|&b| b == 0), "the initial TMV / TSV is not all zero")
        });
        ctx.step(&format!("{l}: AbortTransaction without any change answers NO_CHANGES (0x0C)"), |c| {
            enter(c, &env, 1, &st)?;
            ensure_eq(c.abort_transaction()?, 0x0C, "AbortTransaction status")
        });
        if !cfg.reader {
            ctx.step(&format!("{l}: CommitTransaction with an empty TMI and no write answers NO_CHANGES, TMC stays 0"), |c| {
                enter(c, &env, 1, &st)?;
                let r = c.commit_transaction(false, env.mode)?;
                ensure_eq((r.status, r.tmc), (0x0C, None), "CommitTransaction")?;
                check_state(c, &env, &st)
            });
        }

        // transaction 1: one BackupData write
        ctx.step(&format!("{l}: transaction 1 (BackupData write): TMC 1, TMV / TSV equals the TMI the library recorded"), |c| {
            let d = fill(0xA1, 32);
            run_txn(c, &env, &mut st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
            st.bak = d;
            check_state(c, &env, &st)
        });
        // transaction 2: read before write, backup + value + record
        ctx.step(&format!("{l}: transaction 2 (reads, BackupData write, Credit, WriteRecord): TMC 2"), |c| {
            let (d, rec) = (fill(0xB2, 32), fill(0x21, 16));
            let old = st.bak.clone();
            let r = run_txn(c, &env, &mut st, |c| {
                ensure_eq(c.read_data(BAK, 0, 0)?, old, "BackupData before the write (uncommitted writes are not visible)")?;
                ensure_eq(c.get_value(VAL)?, 100, "value before Credit")?;
                c.write_data(BAK, 0, &d)?;
                c.credit(VAL, 50)?;
                c.write_record(REC, 0, &rec)?;
                Ok(())
            })?;
            ensure(r.tmi.len() >= 5 * 16, "the TMI recorded by the library is shorter than five commands")?;
            st.bak = d;
            st.val = 150;
            st.rec_data.extend(rec);
            ensure_eq(st.tmc, 2, "TMC progress")?;
            check_state(c, &env, &st)
        });
        // transaction 3: update + append record, debit, reads
        ctx.step(&format!("{l}: transaction 3 (UpdateRecord, WriteRecord, Debit, ReadRecords, ReadData): TMC 3"), |c| {
            let (r0, r1) = (fill(0x31, 16), fill(0x32, 16));
            let (before, bak) = (st.rec_data.clone(), st.bak.clone());
            run_txn(c, &env, &mut st, |c| {
                ensure_eq(c.read_records(REC, 0, 0)?, before, "records before the update")?;
                ensure_eq(c.read_data(BAK, 0, 0)?, bak, "BackupData")?;
                // UpdateRecord and WriteRecord on one file cannot share a transaction (PERMISSION_DENIED)
                c.update_record(REC, 0, 0, &r0)?;
                c.debit(VAL, 30)?;
                Ok(())
            })?;
            let _ = r1;
            st.rec_data = [r0, st.rec_data[16..].to_vec()].concat();
            st.val = 120;
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: transaction 4 (Debit 40): TMC 4"), |c| {
            run_txn(c, &env, &mut st, |c| Ok(c.debit(VAL, 40)?))?;
            st.val = 80;
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: transaction 5 (LimitedCredit 25 after the debit): TMC 5"), |c| {
            run_txn(c, &env, &mut st, |c| Ok(c.limited_credit(VAL, 25)?))?;
            st.val = 105;
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: transaction 6 (ClearRecordFile + BackupData write): TMC 6"), |c| {
            let d = fill(0xC6, 32);
            run_txn(c, &env, &mut st, |c| {
                c.clear_record_file(REC)?;
                c.write_data(BAK, 0, &d)?;
                Ok(())
            })?;
            st.bak = d;
            st.rec_data.clear();
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: read-only transaction (ReadData, GetValue): commits, TMC 7, values cover the reads"), |c| {
            let r = run_txn(c, &env, &mut st, |c| {
                c.read_data(BAK, 0, 0)?;
                c.get_value(VAL)?;
                Ok(())
            })?;
            ensure(!r.tmi.is_empty(), "the library recorded nothing for the reads")?;
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: AbortTransaction discards backup, value and record changes and the TMI; TMC unchanged"), |c| {
            enter(c, &env, 1, &st)?;
            c.write_data(BAK, 0, &fill(0xEE, 32))?;
            c.credit(VAL, 10)?;
            c.write_record(REC, 0, &fill(0xEE, 16))?;
            ensure_eq(c.abort_transaction()?, 0, "AbortTransaction status")?;
            ensure(c.transaction_input().is_empty(), "the library kept a TMI after AbortTransaction")?;
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: the transaction after an abort starts with a fresh TMI (TMC 8)"), |c| {
            let d = fill(0xC3, 32);
            let r = run_txn(c, &env, &mut st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
            let mut want = Tmi::new(0);
            want.data(cmd::WRITE_DATA, BAK, 0, &d);
            if env.reader {
                ensure(r.tmi.len() > want.len(), "TMI of the ReaderID transaction is not longer than a bare write")?;
            } else {
                ensure_eq(r.tmi.clone(), want.as_bytes().to_vec(), "TMI of a single WriteData")?;
            }
            st.bak = d;
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: CommitTransaction without the TMC / TMV option: status 0, no data; values read from the file match"), |c| {
            enter(c, &env, 1, &st)?;
            let d = fill(0xD4, 32);
            c.write_data(BAK, 0, &d)?;
            let tmri = reader_step(c, &env, &st)?;
            let r = c.commit_transaction(false, env.mode)?;
            ensure_eq((r.status, r.tmc, r.tmv.clone(), r.tsv.clone()), (0, None, None, None), "CommitTransaction without option")?;
            enter(c, &env, 1, &st)?;
            let (t, v) = read_tm(c, &env)?;
            ensure_eq(t, st.tmc + 1, "TMC read from the file")?;
            verify_values(&env, t, &v, &r.tmi)?;
            st.tmc = t;
            if let Some(x) = tmri {
                st.prev_tmri = x;
            }
            st.bak = d;
            check_state(c, &env, &st)
        });
        ctx.step(&format!("{l}: TMC keeps counting: three more transactions"), |c| {
            for i in 0..3u8 {
                let d = fill(0xE0 + i, 32);
                run_txn(c, &env, &mut st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
                st.bak = d;
            }
            Ok(())
        });

        if cfg.reader {
            reader_battery(ctx, &env, &mut st, l);
        }
        if cfg.extras {
            exclusion_battery(ctx, &env, &mut st, l);
            limit_battery(ctx, &env, &mut st, l);
            if matches!(cfg.kind, Kind::Aes128) {
                negatives_and_recreate(ctx, &mut env, &mut st, l);
            }
        }
    });
}

/// Create the files, the ECC key (signature variants) and the TransactionMAC file.
fn setup(ctx: &mut Ctx, aid: Aid, cfg: &Cfg, kuc: u32) -> Option<Env> {
    ctx.step(&format!("{}: create the data files and the TransactionMAC file", cfg.label), |c| {
        let z = c.zero_key.to_vec();
        c.auth_app(aid, 0, &z)?;
        c.create_data_file(&DataFileSpec::new(BAK, 32, ar_data()).backup().comm_mode(CommMode::Full))?;
        c.create_value_file(&ValueFileSpec::new(VAL, ar_data(), 0, 1000, 100).flags(1).comm_mode(CommMode::Mac))?;
        c.create_record_file(&RecordFileSpec::new(REC, ar_data(), 16, 4).comm_mode(CommMode::Plain))?;
        c.create_data_file(&DataFileSpec::new(BAK2, 32, ar_data()).backup().comm_mode(CommMode::Mac))?;
        let (tm_key, sig) = match cfg.kind {
            Kind::Aes128 => (crypto::rnd(16), None),
            Kind::Aes256 => (crypto::rnd(32), None),
            Kind::Sig(curve) => {
                let spec = KeyPairSpec::new(0, curve, 0x0040, 0x30).kuc_limit(kuc);
                let raw = c.manage_key_pair(&spec, &KeyPairOp::Generate, Some(CommMode::Full))?;
                ensure_eq(raw.len(), 65, "public key length")?;
                let p = PubKey::from_bytes(curve, &raw).map_err(cr_err)?;
                (if cfg.reader { crypto::rnd(16) } else { vec![] }, Some(p))
            }
        };
        let env = Env {
            aid,
            auth_key: z,
            uid: c.uid.clone(),
            tm_key,
            kver: KVER,
            sig,
            mode: cfg.mode,
            reader: cfg.reader,
        };
        let st = St::new(&env);
        let mut spec = TmacFileSpec::new(TM, env.tmac_ar(st.rw)).comm_mode(cfg.mode);
        if !env.tm_key.is_empty() {
            spec = spec.key(&env.tm_key, KVER);
        }
        if env.sig.is_some() {
            spec = spec.signature_key(0);
        }
        c.create_tmac_file(&spec)?;
        Ok(env)
    })
}

// ------------------------------------------------------------------ CommitReaderID
fn reader_battery(ctx: &mut Ctx, env: &Env, st: &mut St, l: &str) {
    ctx.step(&format!("{l}: CommitTransaction without a committed ReaderID: PERMISSION_DENIED"), |c| {
        enter(c, env, 1, st)?;
        c.write_data(BAK, 0, &fill(0x77, 32))?;
        let r = c.commit_transaction(false, env.mode);
        c.expect_err(Status::PermissionDenied, r)?;
        check_state(c, env, st)
    });
    ctx.step(&format!("{l}: a second CommitReaderID in one transaction: PERMISSION_DENIED"), |c| {
        enter(c, env, 1, st)?;
        c.commit_reader_id(&crypto::rnd(16))?;
        let r = c.commit_reader_id(&crypto::rnd(16));
        c.expect_err(Status::PermissionDenied, r)
    });
    ctx.step(&format!("{l}: CommitReaderID authenticated with the wrong key (0 instead of 1): AUTHENTICATION_ERROR"), |c| {
        enter(c, env, 0, st)?;
        let r = c.commit_reader_id(&crypto::rnd(16));
        c.expect_err(Status::AuthenticationError, r)
    });
    ctx.step(&format!("{l}: a ReaderID must be 16 bytes (rejected before anything is sent)"), |c| {
        enter(c, env, 1, st)?;
        match c.commit_reader_id(&[1u8; 15]) {
            Err(duox::Error::InvalidArgument(_)) => Ok(()),
            other => Err(StepError::fail(format!("expected an argument error, got {other:?}"))),
        }
    });
    ctx.step(&format!("{l}: ReaderIDs chain (each transaction returns the previous one): two more transactions"), |c| {
        for i in 0..2u8 {
            let d = fill(0x10 + i, 32);
            run_txn(c, env, st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
            st.bak = d;
        }
        Ok(())
    });
    ctx.step(&format!("{l}: FileAR.ReadWrite changed to free (0xE): settings read back"), |c| {
        st.rw = AccessRight::FREE;
        change_tm(c, env, st)?;
        check_settings(c, env, st)
    });
    ctx.step(&format!("{l}: unauthenticated CommitReaderID returns no data; the ReaderID only enters the TMI, TMRIPrev is not stored"), |c| {
        c.select_application(env.aid, None)?;
        c.new_transaction(Some(st.excl));
        let tmri = crypto::rnd(16);
        let enc = c.commit_reader_id(&tmri)?;
        ensure(enc.is_empty(), "an unauthenticated CommitReaderID returned data")?;
        let r = c.commit_transaction(true, env.mode)?;
        let mut want = Tmi::new(st.excl);
        want.commit_reader_id(&tmri, &[]);
        ensure_eq(r.tmi.clone(), want.as_bytes().to_vec(), "TMI of an unauthenticated CommitReaderID")?;
        finish_commit(c, env, st, &r, None)
    });
    ctx.step(&format!("{l}: an authenticated transaction after that still decrypts the old ReaderID (TMRIPrev was not overwritten)"), |c| {
        let d = fill(0x5C, 32);
        run_txn(c, env, st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
        st.bak = d;
        Ok(())
    });
}

// ------------------------------------------------------------------ exclusion map
fn exclusion_battery(ctx: &mut Ctx, env: &Env, st: &mut St, l: &str) {
    ctx.step(&format!("{l}: ChangeFileSettings enables a TMI exclusion map for the second BackupData file"), |c| {
        st.excl = 1 << BAK2;
        change_tm(c, env, st)?;
        check_settings(c, env, st)
    });
    ctx.step(&format!("{l}: an excluded file is left out of the TMI (and of the TMV / TSV)"), |c| {
        let (a, b) = (fill(0xD1, 32), fill(0xD2, 32));
        let r = run_txn(c, env, st, |c| {
            c.write_data(BAK, 0, &a)?;
            c.write_data(BAK2, 0, &b)?;
            Ok(())
        })?;
        if !env.reader {
            let mut want = Tmi::new(0);
            want.data(cmd::WRITE_DATA, BAK, 0, &a);
            ensure_eq(r.tmi.clone(), want.as_bytes().to_vec(), "TMI without the excluded file")?;
        }
        st.bak = a;
        st.bak2 = b;
        check_state(c, env, st)
    });
    ctx.step(&format!("{l}: a transaction that only writes the excluded file commits with an empty TMI"), |c| {
        let b = fill(0xD3, 32);
        let r = run_txn(c, env, st, |c| Ok(c.write_data(BAK2, 0, &b)?))?;
        if !env.reader {
            ensure(r.tmi.is_empty(), "the TMI is not empty")?;
        }
        st.bak2 = b;
        check_state(c, env, st)
    });
    ctx.step(&format!("{l}: exclusion map disabled again: both files are in the TMI"), |c| {
        st.excl = 0;
        change_tm(c, env, st)?;
        check_settings(c, env, st)?;
        let (a, b) = (fill(0xD5, 32), fill(0xD6, 32));
        let r = run_txn(c, env, st, |c| {
            c.write_data(BAK, 0, &a)?;
            c.write_data(BAK2, 0, &b)?;
            Ok(())
        })?;
        if !env.reader {
            let mut want = Tmi::new(0);
            want.data(cmd::WRITE_DATA, BAK, 0, &a);
            want.data(cmd::WRITE_DATA, BAK2, 0, &b);
            ensure_eq(r.tmi.clone(), want.as_bytes().to_vec(), "TMI with both files")?;
        }
        st.bak = a;
        st.bak2 = b;
        check_state(c, env, st)
    });
}

// ------------------------------------------------------------------ TMCLimit
fn limit_battery(ctx: &mut Ctx, env: &Env, st: &mut St, l: &str) {
    ctx.step(&format!("{l}: TMCLimit equal to the current TMC is rejected (PARAMETER_ERROR)"), |c| {
        let mut bad = st.clone();
        bad.limit = Some(st.tmc);
        let r = change_tm(c, env, &bad);
        c.expect_err(Status::ParameterError, r)
    });
    ctx.step(&format!("{l}: TMCLimit = TMC + 2 is accepted and read back"), |c| {
        st.limit = Some(st.tmc + 2);
        change_tm(c, env, st)?;
        check_settings(c, env, st)
    });
    for n in 1..=2u8 {
        ctx.step(&format!("{l}: transaction {n} of 2 below the limit commits"), |c| {
            let d = fill(0x40 + n, 32);
            run_txn(c, env, st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
            st.bak = d;
            Ok(())
        });
    }
    ctx.step(&format!("{l}: limit reached: SelectApplication gives OPERATION_OK_LIM, CommitTransaction is PERMISSION_DENIED, nothing changes"), |c| {
        let rc = c.select_application(env.aid, None)?;
        ensure_eq(rc, 1, "SelectApplication status at the limit")?;
        c.authenticate_ev2_first(1, &env.auth_key, &[])?;
        c.new_transaction(Some(st.excl));
        c.write_data(BAK, 0, &fill(0x99, 32))?;
        let r = c.commit_transaction(false, env.mode);
        c.expect_err(Status::PermissionDenied, r)?;
        check_state(c, env, st)?;
        ensure_eq(st.limit, Some(st.tmc), "the suite's own bookkeeping of the limit")
    });
    ctx.step(&format!("{l}: raising the limit makes the application fully usable again"), |c| {
        st.limit = Some(st.tmc + 5);
        change_tm(c, env, st)?;
        check_settings(c, env, st)?;
        let rc = c.select_application(env.aid, None)?;
        ensure_eq(rc, 0, "SelectApplication status after raising the limit")?;
        let d = fill(0x50, 32);
        run_txn(c, env, st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
        st.bak = d;
        Ok(())
    });
    ctx.step(&format!("{l}: TMCLimit disabled again: settings carry no limit"), |c| {
        st.limit = None;
        change_tm(c, env, st)?;
        check_settings(c, env, st)
    });
}

// ------------------------------------------------------------------ negative tests, deletion and re-creation
fn negatives_and_recreate(ctx: &mut Ctx, env: &mut Env, st: &mut St, l: &str) {
    ctx.step(&format!("{l}: a second TransactionMAC file in the application: PERMISSION_DENIED"), |c| {
        c.auth_app(env.aid, 0, &env.auth_key)?;
        let spec = TmacFileSpec::new(5, env.tmac_ar(AccessRight::NEVER)).key(&crypto::rnd(16), 1);
        let r = c.create_tmac_file(&spec);
        c.expect_err(Status::PermissionDenied, r)
    });
    ctx.step(&format!("{l}: a Transaction MAC key of 24 bytes is refused by the library before anything is sent"), |c| {
        c.auth_app(env.aid, 0, &env.auth_key)?;
        let spec = TmacFileSpec::new(6, env.tmac_ar(AccessRight::NEVER)).key(&[7u8; 24], 1);
        match c.create_tmac_file(&spec) {
            Err(duox::Error::InvalidArgument(_)) => ensure(c.is_authenticated(), "the session was lost although nothing was sent"),
            other => Err(StepError::fail(format!("expected an argument error, got {other:?}"))),
        }
    });
    let old_key = env.tm_key.clone();
    ctx.step(&format!("{l}: DeleteFile of the TransactionMAC file; the feature is gone (TMC / TMV request: PARAMETER_ERROR)"), |c| {
        c.auth_app(env.aid, 0, &env.auth_key)?;
        c.delete_file(TM)?;
        ensure(!c.get_file_ids()?.contains(&TM), "the file is still listed")?;
        enter(c, env, 1, st)?;
        c.write_data(BAK, 0, &fill(0x61, 32))?;
        let r = c.commit_transaction(true, env.mode);
        c.expect_err(Status::ParameterError, r)?;
        // the plain data check no longer has a TransactionMAC file to read
        enter(c, env, 1, st)?;
        ensure_eq(c.read_data(BAK, 0, 0)?, st.bak.clone(), "BackupData (the write was not committed)")
    });
    let new_env = ctx.step(&format!("{l}: re-create the TransactionMAC file with a new key, version and CommMode"), |c| {
        let mut e = env.clone();
        e.tm_key = crypto::rnd(16);
        e.kver = 0x22;
        e.mode = CommMode::Mac;
        c.auth_app(e.aid, 0, &e.auth_key)?;
        c.create_tmac_file(&TmacFileSpec::new(TM, e.tmac_ar(AccessRight::NEVER)).comm_mode(e.mode).key(&e.tm_key, e.kver))?;
        Ok(e)
    });
    let Some(e2) = new_env else { return };
    *env = e2;
    *st = St { bak: st.bak.clone(), bak2: st.bak2.clone(), val: st.val, rec_data: st.rec_data.clone(), ..St::new(env) };
    ctx.step(&format!("{l}: re-created file: TMC 0, new key version, first transaction verifies with the NEW key only"), |c| {
        enter(c, env, 1, st)?;
        let fs = c.get_file_settings(TM)?;
        ensure_eq(fs.tmac.as_ref().and_then(|t| t.key_version), Some(0x22), "TMKeyVer")?;
        let (t, _) = read_tm(c, env)?;
        ensure_eq(t, 0, "TMC after re-creation")?;
        let d = fill(0x62, 32);
        let r = run_txn(c, env, st, |c| Ok(c.write_data(BAK, 0, &d)?))?;
        st.bak = d;
        let (_, v) = read_tm(c, env)?;
        let uid = env.uid.clone();
        let with_old = txmac::verify_tmv(&old_key, 1, &uid, &r.tmi, &v).map_err(tx_err)?;
        ensure(!with_old, "the TMV verifies with the old key")
    });
}

// ------------------------------------------------------------------ Transaction Signature configuration errors
fn signature_config_errors(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        let ar = AccessRights::new(AccessRight::key(0), AccessRight::NEVER, AccessRight::NEVER, AccessRight::key(0));
        let ar_reader = AccessRights::new(AccessRight::key(0), AccessRight::NEVER, AccessRight::key(1), AccessRight::key(0));
        let ready = ctx.step("TSIG config: generate key 0 (policy: transaction signature) and key 1 (policy: mutual authentication only)", |c| {
            let z = c.zero_key.to_vec();
            c.auth_app(aid, 0, &z)?;
            let k0 = KeyPairSpec::new(0, crypto::CURVE_P256, 0x0040, 0x30);
            let k1 = KeyPairSpec::new(1, crypto::CURVE_P256, 0x0080, 0x30);
            ensure_eq(c.manage_key_pair(&k0, &KeyPairOp::Generate, Some(CommMode::Full))?.len(), 65, "public key 0")?;
            ensure_eq(c.manage_key_pair(&k1, &KeyPairOp::Generate, Some(CommMode::Full))?.len(), 65, "public key 1")?;
            let keys = c.get_ecc_key_settings()?;
            ensure_eq(keys.iter().find(|k| k.key_no == 0).map(|k| k.policy), Some(0x0040), "policy of key 0")?;
            ensure_eq(keys.iter().find(|k| k.key_no == 1).map(|k| k.policy), Some(0x0080), "policy of key 1")
        });
        if ready.is_none() {
            return;
        }
        ctx.step("TSIG config: signature key that does not exist: NO_SUCH_KEY", |c| {
            let z = c.zero_key.to_vec();
            c.auth_app(aid, 0, &z)?;
            let r = c.create_tmac_file(&TmacFileSpec::new(TM, ar).signature_key(3));
            c.expect_err(Status::NoSuchKey, r)
        });
        ctx.step("TSIG config: key without the Transaction Signature policy bit: PERMISSION_DENIED", |c| {
            let z = c.zero_key.to_vec();
            c.auth_app(aid, 0, &z)?;
            let r = c.create_tmac_file(&TmacFileSpec::new(TM, ar).signature_key(1));
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("TSIG config: CommitReaderID enabled without a symmetric key: PARAMETER_ERROR", |c| {
            let z = c.zero_key.to_vec();
            c.auth_app(aid, 0, &z)?;
            let r = c.create_tmac_file(&TmacFileSpec::new(TM, ar_reader).signature_key(0));
            c.expect_err(Status::ParameterError, r)
        });
        ctx.step("TSIG config: the valid configuration is accepted after the refusals; settings: signature, key 0, no TM key", |c| {
            let z = c.zero_key.to_vec();
            c.auth_app(aid, 0, &z)?;
            c.create_tmac_file(&TmacFileSpec::new(TM, ar).signature_key(0))?;
            let fs = c.get_file_settings(TM)?;
            let t = fs.tmac.clone().ok_or("no TransactionMAC settings")?;
            ensure_eq((t.key_option, t.key_version, t.tsig_key), (0x80, None, Some(0)), "TMKeyOption / TMKeyVer / TSIGKeyNo")?;
            ensure(t.is_signature(), "is_signature()")?;
            let (tmc, v) = parse_tm_file(&c.read_data(TM, 0, 0)?, true).map_err(StepError::Fail)?;
            ensure_eq(tmc, 0, "initial TMC")?;
            ensure(v.iter().all(|&b| b == 0), "initial TSV is not zero")
        });
    });
}

// ------------------------------------------------------------------ signature key usage limit
fn signature_key_usage_limit(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        const LIMIT: u32 = 3;
        let ar0 = AccessRights::all(AccessRight::key(0));
        let pubkey = ctx.step("TSIG key usage limit: key 0 with KUCLimit 3, backup file and signature TransactionMAC file", |c| {
            let z = c.zero_key.to_vec();
            c.auth_app(aid, 0, &z)?;
            c.create_data_file(&DataFileSpec::new(BAK, 32, ar0).backup().comm_mode(CommMode::Mac))?;
            let spec = KeyPairSpec::new(0, crypto::CURVE_P256, 0x0040, 0x30).kuc_limit(LIMIT);
            let raw = c.manage_key_pair(&spec, &KeyPairOp::Generate, Some(CommMode::Full))?;
            let p = PubKey::from_bytes(crypto::CURVE_P256, &raw).map_err(cr_err)?;
            c.create_tmac_file(&TmacFileSpec::new(TM, ar0).comm_mode(CommMode::Mac).signature_key(0))?;
            let k = c.get_ecc_key_settings()?;
            let k0 = k.iter().find(|k| k.key_no == 0).ok_or("key 0 is not listed")?;
            ensure_eq((k0.kuc_limit, k0.kuc), (LIMIT, 0), "KUCLimit / KUC after generation")?;
            Ok(p)
        });
        let Some(pubkey) = pubkey else { return };
        let z = ctx.zero_key.to_vec();
        let ok_count = ctx.step("TSIG key usage limit: every signature increments KUC by one; commits stop at the limit with PERMISSION_DENIED", |c| {
            let mut ok = 0u32;
            for i in 1..=LIMIT + 1 {
                c.auth_app(aid, 0, &z)?;
                c.new_transaction(Some(0));
                c.write_data(BAK, 0, &fill(i as u8, 32))?;
                match c.commit_transaction(true, CommMode::Mac) {
                    Ok(r) => {
                        ok += 1;
                        let tsv = r.tsv.clone().ok_or("no TSV")?;
                        let tmc = r.tmc.ok_or("no TMC")?;
                        ensure(txmac::verify_tsv(&pubkey, &tsv, &r.tmi, tmc), "TSV does not verify")?;
                        let k = c.get_ecc_key_settings()?;
                        ensure_eq(k.iter().find(|k| k.key_no == 0).map(|k| k.kuc), Some(ok), "KUC after the commit")?;
                    }
                    Err(e) => {
                        let s = c.expect_any_status(Err::<(), _>(e))?;
                        ensure_eq(s, Status::PermissionDenied, "status of the refused commit")?;
                        break;
                    }
                }
            }
            c.detail(format!("{ok} commits succeeded with KUCLimit {LIMIT}"));
            ensure(ok == LIMIT || ok == LIMIT - 1, format!("{ok} commits succeeded; expected {} or {LIMIT}", LIMIT - 1))?;
            Ok(ok)
        });
        if ok_count.is_none() {
            return;
        }
        ctx.step("TSIG key usage limit: at the limit SelectApplication answers OPERATION_OK_LIM and commits stay refused", |c| {
            let rc = c.select_application(aid, None)?;
            ensure_eq(rc, 1, "SelectApplication status")?;
            c.authenticate_ev2_first(0, &z, &[])?;
            c.write_data(BAK, 0, &fill(0x77, 32))?;
            let r = c.commit_transaction(false, CommMode::Mac);
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("TSIG key usage limit: ManageKeyPair metadata update raises the limit; KUC is kept; commits work again", |c| {
            c.auth_app(aid, 0, &z)?;
            let before = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
            let spec = KeyPairSpec::new(0, crypto::CURVE_P256, 0x0040, 0x30).kuc_limit(100);
            c.manage_key_pair(&spec, &KeyPairOp::UpdateMetadata, Some(CommMode::Full))?;
            let after = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
            ensure_eq((after.kuc_limit, after.kuc), (100, before.kuc), "KUCLimit / KUC after the metadata update")?;
            let rc = c.select_application(aid, None)?;
            ensure_eq(rc, 0, "SelectApplication status after raising the limit")?;
            c.authenticate_ev2_first(0, &z, &[])?;
            c.new_transaction(Some(0));
            c.write_data(BAK, 0, &fill(0x88, 32))?;
            let r = c.commit_transaction(true, CommMode::Mac)?;
            let (tsv, tmc) = (r.tsv.clone().ok_or("no TSV")?, r.tmc.ok_or("no TMC")?);
            ensure(txmac::verify_tsv(&pubkey, &tsv, &r.tmi, tmc), "TSV does not verify")
        });
    });
}

// ------------------------------------------------------------------ application without a TransactionMAC file
fn no_tmac_application(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        let ar0 = AccessRights::all(AccessRight::key(0));
        let z = ctx.zero_key.to_vec();
        let created = ctx.step("no TMAC: create a BackupData file and commit a first value", |c| {
            c.auth_app(aid, 0, &z)?;
            c.create_data_file(&DataFileSpec::new(BAK, 32, ar0).backup().comm_mode(CommMode::Mac))?;
            c.write_data(BAK, 0, &fill(0x11, 32))?;
            let r = c.commit_transaction(false, CommMode::Mac)?;
            ensure_eq((r.status, r.tmc, r.tmv, r.tsv), (0, None, None, None), "CommitTransaction without option")?;
            c.auth_app(aid, 0, &z)?;
            ensure_eq(c.read_data(BAK, 0, 0)?, fill(0x11, 32), "committed data")
        });
        if created.is_none() {
            return;
        }
        ctx.step("no TMAC: requesting TMC / TMV without a TransactionMAC file: PARAMETER_ERROR", |c| {
            c.auth_app(aid, 0, &z)?;
            c.write_data(BAK, 0, &fill(0x22, 32))?;
            let r = c.commit_transaction(true, CommMode::Mac);
            c.expect_err(Status::ParameterError, r)
        });
        ctx.step("no TMAC: AbortTransaction restores the committed data", |c| {
            c.auth_app(aid, 0, &z)?;
            c.write_data(BAK, 0, &fill(0x33, 32))?;
            ensure_eq(c.abort_transaction()?, 0, "AbortTransaction status")?;
            ensure_eq(c.read_data(BAK, 0, 0)?, fill(0x11, 32), "data after the abort")
        });
        ctx.step("no TMAC: AbortTransaction and CommitTransaction without changes answer NO_CHANGES", |c| {
            c.auth_app(aid, 0, &z)?;
            ensure_eq(c.abort_transaction()?, 0x0C, "AbortTransaction status")?;
            c.auth_app(aid, 0, &z)?;
            let r = c.commit_transaction(false, CommMode::Mac)?;
            ensure_eq(r.status, 0x0C, "CommitTransaction status")
        });
        ctx.step("no TMAC: SelectApplication aborts the ongoing transaction", |c| {
            c.auth_app(aid, 0, &z)?;
            c.write_data(BAK, 0, &fill(0x44, 32))?;
            c.auth_app(aid, 0, &z)?;
            ensure_eq(c.read_data(BAK, 0, 0)?, fill(0x11, 32), "data after re-selecting")
        });
        ctx.step("no TMAC: CommitReaderID: PERMISSION_DENIED", |c| {
            c.auth_app(aid, 0, &z)?;
            let r = c.commit_reader_id(&[0u8; 16]);
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("PICC level: CommitTransaction is PERMISSION_DENIED", |c| {
            c.auth_picc()?;
            let r = c.commit_transaction(false, CommMode::Mac);
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("PICC level: AbortTransaction is PERMISSION_DENIED", |c| {
            c.auth_picc()?;
            let r = c.abort_transaction();
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("PICC level: CommitReaderID is PERMISSION_DENIED", |c| {
            c.auth_picc()?;
            let r = c.commit_reader_id(&[0u8; 16]);
            c.expect_err(Status::PermissionDenied, r)
        });
    });
}

// ------------------------------------------------------------------ offline tests of the helpers
#[cfg(test)]
mod tests {
    use super::*;

    const UID: [u8; 7] = [0x04, 0x95, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];

    fn env(tm_key: Vec<u8>, sig: Option<PubKey>) -> Env {
        Env { aid: Aid(0xD00000), auth_key: vec![0; 16], uid: UID.to_vec(), tm_key, kver: KVER, sig, mode: CommMode::Full, reader: false }
    }

    #[test]
    fn key_options() {
        assert_eq!(tm_key_option(16, false), 0x02);
        assert_eq!(tm_key_option(32, false), 0x03);
        assert_eq!(tm_key_option(0, true), 0x80);
        assert_eq!(tm_key_option(16, true), 0x82);
        assert_eq!(tm_key_option(0, false), 0);
    }

    #[test]
    fn tm_file_parsing() {
        let mut d = vec![7, 0, 0, 0];
        d.extend([0xAA; 8]);
        assert_eq!(parse_tm_file(&d, false).unwrap(), (7, vec![0xAA; 8]));
        assert!(parse_tm_file(&d, true).is_err());
        let mut s = vec![1, 2, 0, 0];
        s.extend([1u8; 64]);
        assert_eq!(parse_tm_file(&s, true).unwrap().0, 0x0201);
        assert!(parse_tm_file(&s[..10], true).is_err());
    }

    #[test]
    fn mac_verification_accepts_the_right_value_only() {
        for key in [vec![5u8; 16], vec![6u8; 32]] {
            let e = env(key.clone(), None);
            let mut t = Tmi::new(0);
            t.data(cmd::WRITE_DATA, BAK, 0, &[1u8; 32]);
            t.value(cmd::CREDIT, VAL, 50);
            let v = txmac::tmv(&key, 4, &UID, t.as_bytes()).unwrap();
            verify_values(&e, 4, &v, t.as_bytes()).unwrap();
            assert!(verify_values(&e, 5, &v, t.as_bytes()).is_err());
            let mut other = Tmi::new(0);
            other.data(cmd::WRITE_DATA, BAK, 0, &[2u8; 32]);
            assert!(verify_values(&e, 4, &v, other.as_bytes()).is_err());
        }
    }

    #[test]
    fn signature_verification_both_curves() {
        for curve in [crypto::CURVE_P256, crypto::CURVE_BP256] {
            let sk = crypto::gen_key(curve).unwrap();
            let e = env(vec![], Some(sk.public()));
            let mut t = Tmi::new(0);
            t.data(cmd::WRITE_DATA, BAK, 0, &[9u8; 32]);
            let sig = txmac::sign_tsv(&sk, t.as_bytes(), 3).unwrap();
            assert_eq!(sig.len(), 64);
            verify_values(&e, 3, &sig, t.as_bytes()).unwrap();
            assert!(verify_values(&e, 4, &sig, t.as_bytes()).is_err());
            assert!(verify_values(&e, 3, &sig[..63], t.as_bytes()).is_err());
        }
    }

    #[test]
    fn exclusion_expectations() {
        // the expectation the suite builds for the exclusion tests: file BAK2 (bit 3) is dropped
        let mut with = Tmi::new(1 << BAK2);
        with.data(cmd::WRITE_DATA, BAK, 0, &[1u8; 32]);
        with.data(cmd::WRITE_DATA, BAK2, 0, &[2u8; 32]);
        let mut only = Tmi::new(0);
        only.data(cmd::WRITE_DATA, BAK, 0, &[1u8; 32]);
        assert_eq!(with.as_bytes(), only.as_bytes());
        let mut excluded_only = Tmi::new(1 << BAK2);
        excluded_only.data(cmd::WRITE_DATA, BAK2, 0, &[2u8; 32]);
        assert!(excluded_only.is_empty());
    }

    #[test]
    fn reader_id_roundtrip_matches_the_card_side_encryption() {
        let key = [3u8; 16];
        let ks = txmac::session_keys(&key, 9, &UID).unwrap();
        let tmri = crypto::rnd(16);
        let enc = crypto::aes_cbc_enc(&ks.enc, &tmri, &crypto::ZERO_IV).unwrap();
        assert_eq!(txmac::decrypt_reader_id(&key, 9, &UID, &enc).unwrap(), tmri);
        let mut t = Tmi::new(0);
        t.commit_reader_id(&tmri, &enc);
        assert_eq!(t.len(), 48);
        let mut u = Tmi::new(0);
        u.commit_reader_id(&tmri, &[]);
        assert_eq!(u.len(), 32);
    }

    #[test]
    fn state_bookkeeping() {
        let e = env(vec![1; 16], None);
        let mut st = St::new(&e);
        assert_eq!((st.tmc, st.recs(), st.rw), (0, 0, AccessRight::NEVER));
        st.rec_data = vec![0; 32];
        assert_eq!(st.recs(), 2);
        let r = Env { reader: true, ..e };
        assert_eq!(St::new(&r).rw, AccessRight::key(1));
        assert_eq!(r.tmac_ar(AccessRight::key(1)).to_u16(), 0x1F10);
    }
}
