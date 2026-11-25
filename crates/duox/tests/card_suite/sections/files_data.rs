//! Section `files_data`: files and data inside throwaway applications of the suite range.
//!
//! Every file type (StandardData, BackupData, Value, LinearRecord, CyclicRecord; TransactionMAC creation only) is
//! created, inspected (GetFileIDs, GetISOFileIDs, GetFileSettings, GetFileCounters), changed (ChangeFileSettings) and
//! deleted. Data commands run in all three communication modes with exact read-back: offsets, lengths around the AES
//! block and frame boundaries, several native frame sizes, commit and abort of backup files, value credit / debit /
//! limited credit with their limits, linear and cyclic records including the wrap of a cyclic file, access right
//! combinations (keys, free, never), and the negative cases (out of range, wrong mode, no access).
//!
//! Section numbers: 7.12 (files), 7.13 (data), 7.14 (transactions), 7.5.4 (communication modes).
//!
//! Memory: files are never given back by DeleteFile (7.12.6), so the groups format the empty card in between (only
//! when no application exists); group sizes are chosen to fit the smallest card (2 kB).

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use duox::card::{
    AccessRight, AccessRights, Aid, AppSpec, CommMode, DataFileSpec, FileSettingsChange, FileType, ModeSel, RecordFileSpec,
    RecordSettings, Status, TmacFileSpec, ValueFileSpec, ValueSettings,
};

pub const NAME: &str = "files_data";
pub const DESCRIPTION: &str =
    "Files and data: every file type, all comm modes, offsets / chunks, commit / abort, value limits and limited credit, records and cyclic wrap, access rights, settings changes, TransactionMAC creation.";

const MODES: [CommMode; 3] = [CommMode::Plain, CommMode::Mac, CommMode::Full];

pub fn run(ctx: &mut Ctx) {
    reclaim(ctx, "StandardData files");
    std_data_files(ctx);
    reclaim(ctx, "BackupData files");
    backup_files(ctx);
    reclaim(ctx, "Value files");
    value_files(ctx);
    reclaim(ctx, "linear record files");
    linear_record_files(ctx);
    reclaim(ctx, "cyclic record files");
    cyclic_record_files(ctx);
    reclaim(ctx, "access rights");
    access_rights(ctx);
    reclaim(ctx, "the file type sweep");
    file_type_sweep(ctx);
    reclaim(ctx, "the file count limit");
    file_count_limit(ctx);
    reclaim(ctx, "memory consumption");
    memory_consumption(ctx);
    reclaim(ctx, "TransactionMAC files");
    tmac_files(ctx);
}

// ------------------------------------------------------------------ helpers
fn k(n: u8) -> AccessRight {
    AccessRight::key(n)
}

/// Read = key 1, Write = key 2, ReadWrite = key 3, Change = key 0.
fn ladder() -> AccessRights {
    AccessRights::new(k(1), k(2), k(3), k(0))
}

fn login(c: &mut Ctx, aid: Aid, key: u8) -> StepResult {
    let z = c.zero_key;
    c.auth_app(aid, key, &z)
}

/// Format the empty card to give back memory that deleting applications and files does not release.
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

/// Skip unless the card has at least `bytes` free (read at PICC level, so only call at the start of a scope).
fn need_memory(c: &mut Ctx, bytes: u32) -> StepResult {
    c.ensure_picc()?;
    let free = c.free_mem()?;
    if free < bytes {
        return Err(StepError::skip(format!("needs {bytes} bytes of free memory, the card has {free}")));
    }
    Ok(())
}

fn bytes_taken(before: u32, now: u32) -> StepResult<u32> {
    before.checked_sub(now).ok_or_else(|| StepError::fail(format!("FreeMem rose from {before} to {now}")))
}

fn commit_ok(c: &mut Ctx) -> StepResult {
    let r = c.commit_transaction(false, CommMode::Plain)?;
    ensure_eq(r.status, 0, "CommitTransaction status")
}

fn abort_ok(c: &mut Ctx) -> StepResult {
    ensure_eq(c.abort_transaction()?, 0, "AbortTransaction status")
}

/// Deterministic test data: different seeds give different, non-constant bytes.
fn pat(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(12_345);
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect()
}

/// Memory of a file in 32-byte blocks (7.12.6), without the shared overhead block.
fn std_blocks(size: u32) -> u32 {
    size.div_ceil(32)
}
fn backup_blocks(size: u32) -> u32 {
    2 * size.div_ceil(32)
}
fn record_blocks(size: u32, max: u32) -> u32 {
    1 + (size * max).div_ceil(32)
}

/// A record file as the card must show it. `recs` is chronological, oldest first.
#[derive(Debug, Clone, PartialEq)]
struct RecordModel {
    size: usize,
    max: usize,
    cyclic: bool,
    recs: Vec<Vec<u8>>,
}

impl RecordModel {
    fn new(size: usize, max: usize, cyclic: bool) -> Self {
        RecordModel { size, max, cyclic, recs: vec![] }
    }
    /// Records the file can hold: a cyclic file keeps one record for its backup.
    fn capacity(&self) -> usize {
        if self.cyclic {
            self.max - 1
        } else {
            self.max
        }
    }
    fn is_full(&self) -> bool {
        self.recs.len() >= self.capacity()
    }
    /// WriteRecord(s) of one transaction: they build ONE new record (unwritten bytes are zero).
    /// Returns false when a linear file is full (the card must refuse).
    fn append(&mut self, writes: &[(usize, &[u8])]) -> bool {
        if self.is_full() && !self.cyclic {
            return false;
        }
        let mut rec = vec![0u8; self.size];
        for (off, data) in writes {
            rec[*off..*off + data.len()].copy_from_slice(data);
        }
        if self.is_full() {
            self.recs.remove(0);
        }
        self.recs.push(rec);
        true
    }
    /// UpdateRecord: `rec_no` counts from the newest record (0).
    fn update(&mut self, rec_no: usize, offset: usize, data: &[u8]) -> bool {
        let n = self.recs.len();
        if rec_no >= n || offset + data.len() > self.size {
            return false;
        }
        self.recs[n - 1 - rec_no][offset..offset + data.len()].copy_from_slice(data);
        true
    }
    fn clear(&mut self) {
        self.recs.clear();
    }
    /// ReadRecords(rec_no, count): `count` records starting at `rec_no` (counted from the newest), returned
    /// oldest first; count 0 = everything from the oldest up to and including `rec_no`.
    fn read(&self, rec_no: usize, count: usize) -> Option<Vec<u8>> {
        let n = self.recs.len();
        if rec_no >= n {
            return None;
        }
        let (lo, hi) = if count == 0 {
            (0, n - 1 - rec_no)
        } else {
            if rec_no + count > n {
                return None;
            }
            (n - rec_no - count, n - 1 - rec_no)
        };
        Some(self.recs[lo..=hi].concat())
    }
    fn all(&self) -> Option<Vec<u8>> {
        self.read(0, 0)
    }
}

// ------------------------------------------------------------------ StandardData
const STD_SIZE: usize = 200;
/// Write lengths: around the AES block (16), the frame payload (54 / 55 / 56) and a whole file.
const LENS: [usize; 22] = [1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 53, 54, 55, 56, 57, 63, 64, 65, 110, 150, 200];
const OFFSETS: [usize; 12] = [0, 1, 15, 16, 31, 32, 63, 64, 127, 128, 198, 199];

fn std_data_files(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        let mut nos = ctx.file_nos();
        for mode in MODES {
            let f = nos.next();
            std_mode(ctx, aid, f, mode);
        }
    });
}

fn std_mode(ctx: &mut Ctx, aid: Aid, f: u8, mode: CommMode) {
    let tag = format!("StandardData {mode}");
    let mut model = vec![0u8; STD_SIZE];
    ctx.step(&format!("{tag}: CreateStdDataFile; GetFileSettings reports type, mode, rights and size"), |c| {
        login(c, aid, 0)?;
        c.create_data_file(&DataFileSpec::new(f, STD_SIZE as u32, ladder()).comm_mode(mode))?;
        let fs = c.get_file_settings(f)?;
        c.detail(fs.describe().join("\n"));
        ensure_eq(
            (fs.file_type, fs.comm_mode(), fs.access, fs.size),
            (FileType::StandardData, mode, ladder(), Some(STD_SIZE as u32)),
            "settings",
        )?;
        ensure(fs.additional.is_empty() && fs.sdm.is_none() && fs.crl.is_none(), "unexpected optional settings")?;
        ensure(c.get_file_ids()?.contains(&f), "file missing from GetFileIDs")
    });
    ctx.step(&format!("{tag}: a new file reads as zeros (whole file, and the last byte)"), |c| {
        login(c, aid, 1)?;
        ensure_eq(c.read_data(f, 0, 0)?, vec![0u8; STD_SIZE], "whole file")?;
        ensure_eq(c.read_data(f, STD_SIZE as u32 - 1, 1)?, vec![0u8], "last byte")
    });
    ctx.step(&format!("{tag}: write with the write key (2), read with the read key (1)"), |c| {
        let d = pat(1, 10);
        login(c, aid, 2)?;
        c.write_data(f, 0, &d)?;
        model[..10].copy_from_slice(&d);
        login(c, aid, 1)?;
        ensure_eq(c.read_data(f, 0, 10)?, d, "the ten bytes")?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "the whole file")?;
        ensure_eq(c.read_data(f, 5, 0)?, model[5..].to_vec(), "from offset 5 to the end (length 0)")
    });
    ctx.step(&format!("{tag}: writes of 1..200 bytes around AES block and frame boundaries read back exactly"), |c| {
        login(c, aid, 3)?;
        for (i, &len) in LENS.iter().enumerate() {
            let off = (len * 7) % (STD_SIZE - len + 1);
            let data = pat(((mode.bits() as u32) << 8) | i as u32, len);
            c.write_data(f, off as u32, &data)?;
            model[off..off + len].copy_from_slice(&data);
            ensure_eq(c.read_data(f, off as u32, len as u32)?, data, &format!("{len} bytes at offset {off}"))?;
        }
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "the whole file")
    });
    ctx.step(&format!("{tag}: one byte at offsets 0, 1, 15, 16, 31, 32, 63, 64, 127, 128, 198, 199"), |c| {
        login(c, aid, 3)?;
        for (i, &off) in OFFSETS.iter().enumerate() {
            let b = 0x80 | i as u8;
            c.write_data(f, off as u32, &[b])?;
            model[off] = b;
            ensure_eq(c.read_data(f, off as u32, 1)?, vec![b], &format!("byte at offset {off}"))?;
        }
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "the whole file")
    });
    ctx.step(&format!("{tag}: reads of sub ranges and length 0 (to the end)"), |c| {
        login(c, aid, 1)?;
        for (off, len) in [(0usize, 1usize), (0, 200), (199, 1), (100, 100), (1, 198), (50, 0), (199, 0), (0, 0)] {
            let want = if len == 0 { model[off..].to_vec() } else { model[off..off + len].to_vec() };
            ensure_eq(c.read_data(f, off as u32, len as u32)?, want, &format!("read at offset {off}, length {len}"))?;
        }
        Ok(())
    });
    ctx.step(&format!("{tag}: native frame sizes 16, 24, 40 and 55 bytes for chained 150-byte writes and reads"), |c| {
        let old = c.max_native_frame();
        let r = (|| -> StepResult {
            login(c, aid, 3)?;
            for mf in [16usize, 24, 40, 55] {
                c.set_max_native_frame(mf);
                let off = 10 + mf % 7;
                let data = pat(mf as u32 + 1000, 150);
                c.write_data(f, off as u32, &data)?;
                model[off..off + 150].copy_from_slice(&data);
                ensure_eq(c.read_data(f, 0, 0)?, model.clone(), &format!("file after a write with frame size {mf}"))?;
            }
            Ok(())
        })();
        c.set_max_native_frame(old);
        r
    });
    ctx.step(&format!("{tag}: out of range: BOUNDARY_ERROR for reads and writes beyond the file; length 0 write refused"), |c| {
        let size = STD_SIZE as u32;
        login(c, aid, 3)?;
        let r = c.read_data(f, size, 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.read_data(f, size - 1, 2);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.read_data(f, 0, size + 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.write_data(f, size - 1, &[1, 2]);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.write_data(f, size, &[1]);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.write_data(f, 0, &[]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("a write of length 0 is answered with {s} (0x{:02X})", s.code()));
        login(c, aid, 1)?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "the file after the refused commands")
    });
    if mode != CommMode::Plain {
        ctx.step(&format!("{tag}: a plain command in an authenticated session on a {mode} file is refused and changes nothing"), |c| {
            login(c, aid, 1)?;
            let r = c.read_data_with(f, 0, 16, ModeSel::Explicit(CommMode::Plain));
            let s = c.expect_any_status(r)?;
            c.detail(format!("plain ReadData: {s} (0x{:02X})", s.code()));
            login(c, aid, 3)?;
            let r = c.write_data_with(f, 0, &[0xAA; 8], ModeSel::Explicit(CommMode::Plain));
            // The card may answer a write without a MAC with ADDITIONAL_FRAME (it waits for the missing
            // MAC bytes); the library then gives up after empty continuations and flushes the chain.
            match r {
                Err(duox::Error::Protocol(m)) if m.contains("additional frames") => {
                    c.detail("plain WriteData: the card waits for more command data (additional frame); abandoned")
                }
                other => {
                    let s = c.expect_any_status(other)?;
                    c.detail(format!("plain WriteData: {s} (0x{:02X})", s.code()));
                }
            }
            login(c, aid, 1)?;
            ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "the file")
        });
    } else {
        ctx.step(&format!("{tag}: a MAC protected command on a Plain file (observation)"), |c| {
            login(c, aid, 1)?;
            match c.read_data_with(f, 0, 16, ModeSel::Explicit(CommMode::Mac)) {
                Ok(d) => c.detail(format!("accepted, {} bytes", d.len())),
                Err(e) if e.status().is_some() => c.detail(format!("refused: {e}")),
                Err(e) => return Err(e.into()),
            }
            Ok(())
        });
    }
    if mode == CommMode::Mac {
        ctx.step(&format!("{tag}: StandardData is not transactional: data survives a re-selection; CommitTransaction reports NO_CHANGES"), |c| {
            login(c, aid, 3)?;
            let d = pat(77, 8);
            c.write_data(f, 20, &d)?;
            model[20..28].copy_from_slice(&d);
            login(c, aid, 3)?; // a new selection aborts any open transaction
            ensure_eq(c.read_data(f, 20, 8)?, d, "data written without CommitTransaction")?;
            let r = c.commit_transaction(false, CommMode::Plain)?;
            ensure_eq(r.status, 0x0C, "CommitTransaction without a backup file change")?;
            ensure_eq(c.abort_transaction()?, 0x0C, "AbortTransaction without a backup file change")
        });
        ctx.step(&format!("{tag}: GetFileCounters on a file without Secure Dynamic Messaging (status recorded)"), |c| {
            login(c, aid, 0)?;
            let r = c.get_file_counters(f);
            let s = c.expect_any_status(r)?;
            c.detail(format!("{s} (0x{:02X})", s.code()));
            Ok(())
        });
    }
}

// ------------------------------------------------------------------ BackupData
const BK_SIZE: usize = 100;

fn backup_files(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        let mut nos = ctx.file_nos();
        for mode in MODES {
            let f = nos.next();
            backup_mode(ctx, aid, f, mode);
        }
    });
}

fn backup_mode(ctx: &mut Ctx, aid: Aid, f: u8, mode: CommMode) {
    let tag = format!("BackupData {mode}");
    let mut model = vec![0u8; BK_SIZE];
    ctx.step(&format!("{tag}: CreateBackupDataFile; GetFileSettings reports the type"), |c| {
        login(c, aid, 0)?;
        c.create_data_file(&DataFileSpec::new(f, BK_SIZE as u32, ladder()).comm_mode(mode).backup())?;
        let fs = c.get_file_settings(f)?;
        ensure_eq((fs.file_type, fs.comm_mode(), fs.size), (FileType::BackupData, mode, Some(BK_SIZE as u32)), "settings")?;
        login(c, aid, 1)?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "a new file reads as zeros")
    });
    ctx.step(&format!("{tag}: a write is invisible until CommitTransaction, then visible in this and in a new session"), |c| {
        let d = pat(2, 20);
        login(c, aid, 3)?;
        c.write_data(f, 0, &d)?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file before the commit")?;
        commit_ok(c)?;
        model[..20].copy_from_slice(&d);
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after the commit")?;
        login(c, aid, 1)?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after the commit, new session")
    });
    ctx.step(&format!("{tag}: AbortTransaction discards the writes"), |c| {
        login(c, aid, 3)?;
        c.write_data(f, 10, &pat(3, 30))?;
        abort_ok(c)?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after the abort")?;
        // the abort leaves a clean transaction: a following write and commit work
        let d = pat(4, 5);
        c.write_data(f, 90, &d)?;
        commit_ok(c)?;
        model[90..95].copy_from_slice(&d);
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after the second transaction")
    });
    ctx.step(&format!("{tag}: overlapping writes of one transaction apply in order"), |c| {
        let (a, b) = (pat(5, 30), pat(6, 30));
        login(c, aid, 3)?;
        c.write_data(f, 0, &a)?;
        c.write_data(f, 20, &b)?;
        commit_ok(c)?;
        model[..30].copy_from_slice(&a);
        model[20..50].copy_from_slice(&b);
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after the commit")
    });
    ctx.step(&format!("{tag}: a chained 100-byte write is committed as a whole"), |c| {
        let d = pat(7, BK_SIZE);
        login(c, aid, 3)?;
        c.write_data(f, 0, &d)?;
        commit_ok(c)?;
        model.copy_from_slice(&d);
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after the commit")?;
        ensure_eq(c.read_data(f, 33, 40)?, model[33..73].to_vec(), "a range of it")
    });
    ctx.step(&format!("{tag}: a failed command aborts the pending writes"), |c| {
        login(c, aid, 3)?;
        c.write_data(f, 0, &[0xEE; 10])?;
        let r = c.write_data(f, BK_SIZE as u32 - 5, &[1; 10]);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 1)?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after the failed command")
    });
    ctx.step(&format!("{tag}: selecting the application again aborts the pending writes"), |c| {
        login(c, aid, 3)?;
        c.write_data(f, 0, &[0xDD; 10])?;
        login(c, aid, 1)?;
        ensure_eq(c.read_data(f, 0, 0)?, model.clone(), "file after re-selection")
    });
    ctx.step(&format!("{tag}: CommitTransaction and AbortTransaction without changes report NO_CHANGES (0x0C)"), |c| {
        login(c, aid, 3)?;
        let r = c.commit_transaction(false, CommMode::Plain)?;
        ensure_eq(r.status, 0x0C, "CommitTransaction")?;
        // measured: NO_CHANGES carries no MAC and ends the authentication on the card
        ensure(!c.is_authenticated(), "the session is expected to end after NO_CHANGES")?;
        login(c, aid, 3)?;
        ensure_eq(c.abort_transaction()?, 0x0C, "AbortTransaction")?;
        ensure(!c.is_authenticated(), "the session is expected to end after NO_CHANGES")
    });
    ctx.step(&format!("{tag}: out of range writes and reads: BOUNDARY_ERROR"), |c| {
        login(c, aid, 3)?;
        let r = c.write_data(f, BK_SIZE as u32, &[1]);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.read_data(f, BK_SIZE as u32 - 1, 2);
        c.expect_err(Status::BoundaryError, r)
    });
}

// ------------------------------------------------------------------ Value
fn value_files(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        let mut nos = ctx.file_nos();
        for mode in MODES {
            let f = nos.next();
            value_mode(ctx, aid, f, mode);
        }
        value_extremes(ctx, aid, nos.next());
        limited_credit(ctx, aid, nos.next(), nos.next());
        free_get_value(ctx, aid, [nos.next(), nos.next(), nos.next()]);
        value_creation_errors(ctx, aid, nos.next());
    });
}

fn value_mode(ctx: &mut Ctx, aid: Aid, f: u8, mode: CommMode) {
    let tag = format!("Value {mode}");
    ctx.step(&format!("{tag}: CreateValueFile (-100..1000, initial 50); GetFileSettings and GetValue"), |c| {
        login(c, aid, 0)?;
        c.create_value_file(&ValueFileSpec::new(f, ladder(), -100, 1000, 50).comm_mode(mode))?;
        let fs = c.get_file_settings(f)?;
        ensure_eq((fs.file_type, fs.comm_mode(), fs.access), (FileType::Value, mode, ladder()), "settings")?;
        ensure_eq(fs.value, Some(ValueSettings { lower: -100, upper: 1000, limited_credit: 0, flags: 0 }), "value settings")?;
        login(c, aid, 1)?;
        ensure_eq(c.get_value(f)?, 50, "initial value")
    });
    ctx.step(&format!("{tag}: Credit and Debit take effect at CommitTransaction only"), |c| {
        login(c, aid, 3)?;
        c.credit(f, 25)?;
        ensure_eq(c.get_value(f)?, 50, "value before the commit")?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 75, "value after Credit 25")?;
        c.debit(f, 30)?;
        ensure_eq(c.get_value(f)?, 75, "value before the second commit")?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 45, "value after Debit 30")?;
        login(c, aid, 1)?;
        ensure_eq(c.get_value(f)?, 45, "value in a new session")
    });
    ctx.step(&format!("{tag}: several operations of one transaction accumulate"), |c| {
        login(c, aid, 3)?;
        c.credit(f, 10)?;
        c.debit(f, 5)?;
        c.credit(f, 100)?;
        ensure_eq(c.get_value(f)?, 45, "value before the commit")?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 150, "value after 10 - 5 + 100")
    });
    ctx.step(&format!("{tag}: AbortTransaction discards value changes"), |c| {
        login(c, aid, 3)?;
        c.debit(f, 20)?;
        abort_ok(c)?;
        ensure_eq(c.get_value(f)?, 150, "value after the abort")
    });
    ctx.step(&format!("{tag}: the limits are exact: credit up to 1000 and debit down to -100 work, one more is BOUNDARY_ERROR"), |c| {
        login(c, aid, 3)?;
        c.credit(f, 850)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 1000, "value at the upper limit")?;
        let r = c.credit(f, 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        ensure_eq(c.get_value(f)?, 1000, "value after the refused credit")?;
        c.debit(f, 1100)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, -100, "value at the lower limit")?;
        let r = c.debit(f, 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        ensure_eq(c.get_value(f)?, -100, "value after the refused debit")?;
        c.credit(f, 150)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 50, "value restored to 50")
    });
    ctx.step(&format!("{tag}: a refused operation aborts the operations before it"), |c| {
        login(c, aid, 3)?;
        c.credit(f, 10)?;
        let r = c.debit(f, 5000);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 1)?;
        ensure_eq(c.get_value(f)?, 50, "value after the refused operation")
    });
    ctx.step(&format!("{tag}: negative amounts are refused"), |c| {
        login(c, aid, 3)?;
        let r = c.credit(f, -5);
        let s = c.expect_any_status(r)?;
        c.detail(format!("Credit -5: {s} (0x{:02X})", s.code()));
        login(c, aid, 3)?;
        let r = c.debit(f, -5);
        let s = c.expect_any_status(r)?;
        c.detail(format!("Debit -5: {s} (0x{:02X})", s.code()));
        login(c, aid, 3)?;
        let r = c.debit(f, i32::MIN);
        c.expect_any_status(r)?;
        login(c, aid, 1)?;
        ensure_eq(c.get_value(f)?, 50, "value after the refused amounts")
    });
}

fn value_extremes(ctx: &mut Ctx, aid: Aid, f: u8) {
    ctx.step("Value with limits i32::MIN..i32::MAX: no overflow or underflow, exact at both ends", |c| {
        login(c, aid, 0)?;
        c.create_value_file(&ValueFileSpec::new(f, ladder(), i32::MIN, i32::MAX, i32::MAX - 5).comm_mode(CommMode::Mac))?;
        login(c, aid, 3)?;
        c.credit(f, 5)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, i32::MAX, "value at i32::MAX")?;
        let r = c.credit(f, 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        c.debit(f, i32::MAX)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 0, "value after debiting i32::MAX")?;
        c.debit(f, i32::MAX)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, -i32::MAX, "value at -i32::MAX")?;
        c.debit(f, 1)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, i32::MIN, "value at i32::MIN")?;
        let r = c.debit(f, 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 1)?;
        ensure_eq(c.get_value(f)?, i32::MIN, "value after the refused debit")
    });
}

fn limited_credit(ctx: &mut Ctx, aid: Aid, f: u8, off: u8) {
    ctx.step("LimitedCredit file: settings report the feature and a limit of 0", |c| {
        login(c, aid, 0)?;
        c.create_value_file(&ValueFileSpec::new(f, ladder(), 0, 10_000, 500).flags(1).comm_mode(CommMode::Mac))?;
        let v = c.get_file_settings(f)?.value.ok_or("no value settings")?;
        ensure_eq((v.limited_credit_enabled(), v.free_get_value(), v.limited_credit), (true, false, 0), "settings")
    });
    ctx.step("LimitedCredit without a previous debit exceeds the limit: BOUNDARY_ERROR", |c| {
        login(c, aid, 3)?;
        let r = c.limited_credit(f, 10);
        c.expect_err(Status::BoundaryError, r)
    });
    ctx.step("after a committed Debit 100 the limit is 100: 101 is refused, 60 works, then the limit is 0", |c| {
        login(c, aid, 3)?;
        c.debit(f, 100)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 400, "value after Debit 100")?;
        ensure_eq(c.get_file_settings(f)?.value.map(|v| v.limited_credit), Some(100), "limit in GetFileSettings")?;
        let r = c.limited_credit(f, 101);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        ensure_eq(c.get_value(f)?, 400, "value after the refused LimitedCredit")?;
        c.limited_credit(f, 60)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 460, "value after LimitedCredit 60")?;
        ensure_eq(c.get_file_settings(f)?.value.map(|v| v.limited_credit), Some(0), "limit after the LimitedCredit")?;
        let r = c.limited_credit(f, 1);
        c.expect_err(Status::BoundaryError, r)
    });
    ctx.step("Credit does not change the limit; LimitedCredit uses exactly the debited amount", |c| {
        login(c, aid, 3)?;
        c.debit(f, 40)?;
        commit_ok(c)?;
        c.credit(f, 100)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 460 - 40 + 100, "value")?;
        ensure_eq(c.get_file_settings(f)?.value.map(|v| v.limited_credit), Some(40), "limit after Debit, Credit")?;
        c.limited_credit(f, 40)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 560, "value after LimitedCredit 40")
    });
    ctx.step("debits of one transaction accumulate into the limit", |c| {
        login(c, aid, 3)?;
        c.debit(f, 10)?;
        c.debit(f, 15)?;
        commit_ok(c)?;
        ensure_eq(c.get_file_settings(f)?.value.map(|v| v.limited_credit), Some(25), "limit after Debit 10, Debit 15")?;
        c.limited_credit(f, 25)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 560, "value back at 560")
    });
    ctx.step("Debit and LimitedCredit in one transaction: the pending debit counts", |c| {
        login(c, aid, 3)?;
        c.debit(f, 30)?;
        c.limited_credit(f, 30)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 560, "value after Debit 30, LimitedCredit 30")
    });
    ctx.step("an aborted LimitedCredit restores the limit", |c| {
        login(c, aid, 3)?;
        c.debit(f, 20)?;
        commit_ok(c)?;
        c.limited_credit(f, 20)?;
        abort_ok(c)?;
        ensure_eq(c.get_value(f)?, 540, "value after the abort")?;
        ensure_eq(c.get_file_settings(f)?.value.map(|v| v.limited_credit), Some(20), "limit after the abort")?;
        c.limited_credit(f, 20)?;
        commit_ok(c)?;
        ensure_eq(c.get_value(f)?, 560, "value")
    });
    ctx.step("LimitedCredit with the read key and with the write key (observation, not asserted)", |c| {
        login(c, aid, 3)?;
        c.debit(f, 8)?;
        commit_ok(c)?;
        for key in [1u8, 2] {
            login(c, aid, key)?;
            match c.limited_credit(f, 1) {
                Ok(()) => {
                    c.detail(format!("key {key}: LimitedCredit accepted"));
                    abort_ok(c)?;
                }
                Err(e) if e.status().is_some() => c.detail(format!("key {key}: {e}")),
                Err(e) => return Err(e.into()),
            }
        }
        login(c, aid, 3)?;
        ensure_eq(c.get_value(f)?, 552, "value is unchanged by the observation")
    });
    ctx.step("LimitedCredit on a file created without the feature is refused", |c| {
        login(c, aid, 0)?;
        c.create_value_file(&ValueFileSpec::new(off, ladder(), 0, 100, 50))?;
        login(c, aid, 3)?;
        c.debit(off, 10)?;
        commit_ok(c)?;
        let r = c.limited_credit(off, 5);
        let s = c.expect_any_status(r)?;
        c.detail(format!("{s} (0x{:02X})", s.code()));
        login(c, aid, 3)?;
        ensure_eq(c.get_value(off)?, 40, "value")
    });
}

fn free_get_value(ctx: &mut Ctx, aid: Aid, [on, off, locked]: [u8; 3]) {
    ctx.step("GetFreeValue (flag 2): GetValue works without authentication", |c| {
        login(c, aid, 0)?;
        let only_read = AccessRights::new(k(1), AccessRight::NEVER, AccessRight::NEVER, k(0));
        c.create_value_file(&ValueFileSpec::new(on, only_read, 0, 100, 42).flags(2).comm_mode(CommMode::Full))?;
        let v = c.get_file_settings(on)?.value.ok_or("no value settings")?;
        ensure_eq((v.limited_credit_enabled(), v.free_get_value()), (false, true), "flags")?;
        c.select_application(aid, None)?;
        ensure_eq(c.get_value(on)?, 42, "value without authentication")?;
        login(c, aid, 1)?;
        ensure_eq(c.get_value(on)?, 42, "value with the read key")
    });
    ctx.step("without the flag, GetValue needs the key: AUTHENTICATION_ERROR", |c| {
        login(c, aid, 0)?;
        let only_read = AccessRights::new(k(1), AccessRight::NEVER, AccessRight::NEVER, k(0));
        c.create_value_file(&ValueFileSpec::new(off, only_read, 0, 100, 42).comm_mode(CommMode::Full))?;
        c.select_application(aid, None)?;
        let r = c.get_value(off);
        c.expect_err(Status::AuthenticationError, r)?;
        login(c, aid, 1)?;
        ensure_eq(c.get_value(off)?, 42, "value with the read key")
    });
    ctx.step("GetFreeValue with every access right set to never (status recorded)", |c| {
        login(c, aid, 0)?;
        c.create_value_file(&ValueFileSpec::new(locked, AccessRights::new(AccessRight::NEVER, AccessRight::NEVER, AccessRight::NEVER, k(0)), 0, 100, 42).flags(2))?;
        c.select_application(aid, None)?;
        let r = c.get_value(locked);
        let s = c.expect_any_status(r)?;
        c.detail(format!("{s} (0x{:02X})", s.code()));
        Ok(())
    });
}

fn value_creation_errors(ctx: &mut Ctx, aid: Aid, f: u8) {
    ctx.step("CreateValueFile with lower limit above upper limit is refused", |c| {
        login(c, aid, 0)?;
        let r = c.create_value_file(&ValueFileSpec::new(f, ladder(), 10, 5, 7));
        let s = c.expect_any_status(r)?;
        c.detail(format!("{s} (0x{:02X})", s.code()));
        Ok(())
    });
    ctx.step("CreateValueFile with an initial value outside the limits is refused", |c| {
        login(c, aid, 0)?;
        let r = c.create_value_file(&ValueFileSpec::new(f, ladder(), 0, 10, 11));
        let s = c.expect_any_status(r)?;
        c.detail(format!("{s} (0x{:02X})", s.code()));
        login(c, aid, 0)?;
        let r = c.create_value_file(&ValueFileSpec::new(f, ladder(), 0, 10, -1));
        c.expect_any_status(r)?;
        Ok(())
    });
    ctx.step("a Value file with lower = upper = initial is valid and cannot change", |c| {
        login(c, aid, 0)?;
        c.create_value_file(&ValueFileSpec::new(f, ladder(), 5, 5, 5))?;
        login(c, aid, 3)?;
        ensure_eq(c.get_value(f)?, 5, "value")?;
        let r = c.credit(f, 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.debit(f, 1);
        c.expect_err(Status::BoundaryError, r)
    });
}

// ------------------------------------------------------------------ records
fn read_all(c: &mut Ctx, f: u8, m: &RecordModel) -> StepResult {
    let want = m.all().ok_or("internal: reading an empty model")?;
    ensure_eq(c.read_records(f, 0, 0)?, want, "all records")?;
    ensure_eq(c.get_file_settings(f)?.record.map(|r| r.current_records), Some(m.recs.len() as u32), "current record count")
}

fn linear_record_files(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        let mut nos = ctx.file_nos();
        for mode in MODES {
            let f = nos.next();
            linear_mode(ctx, aid, f, mode);
        }
    });
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        let f = ctx.file_nos().next();
        big_records(ctx, aid, f);
    });
}

fn linear_mode(ctx: &mut Ctx, aid: Aid, f: u8, mode: CommMode) {
    let tag = format!("LinearRecord {mode}");
    let mut m = RecordModel::new(16, 6, false);
    ctx.step(&format!("{tag}: CreateLinearRecordFile (16 bytes x 6); GetFileSettings reports an empty file"), |c| {
        login(c, aid, 0)?;
        c.create_record_file(&RecordFileSpec::new(f, ladder(), 16, 6).comm_mode(mode))?;
        let fs = c.get_file_settings(f)?;
        ensure_eq((fs.file_type, fs.comm_mode(), fs.access), (FileType::LinearRecord, mode, ladder()), "settings")?;
        ensure_eq(fs.record, Some(RecordSettings { record_size: 16, max_records: 6, current_records: 0 }), "record settings")
    });
    ctx.step(&format!("{tag}: ReadRecords of an empty file: BOUNDARY_ERROR"), |c| {
        login(c, aid, 1)?;
        let r = c.read_records(f, 0, 0);
        c.expect_err(Status::BoundaryError, r)
    });
    ctx.step(&format!("{tag}: WriteRecord is effective after CommitTransaction only"), |c| {
        let r0 = pat(10, 16);
        login(c, aid, 3)?;
        c.write_record(f, 0, &r0)?;
        ensure_eq(c.get_file_settings(f)?.record.map(|r| r.current_records), Some(0), "records before the commit")?;
        commit_ok(c)?;
        m.append(&[(0, &r0)]);
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: full and partial records (unwritten bytes are zero); ReadRecords returns the oldest first"), |c| {
        let r1 = pat(11, 16);
        let r2 = pat(12, 8);
        login(c, aid, 3)?;
        c.write_record(f, 0, &r1)?;
        commit_ok(c)?;
        m.append(&[(0, &r1)]);
        c.write_record(f, 4, &r2)?;
        commit_ok(c)?;
        m.append(&[(4, &r2)]);
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: ReadRecords ranges (record 0 is the newest)"), |c| {
        login(c, aid, 1)?;
        for (rn, cnt) in [(0usize, 1usize), (1, 1), (2, 1), (0, 2), (1, 2), (0, 3), (1, 0), (2, 0), (0, 0)] {
            let want = m.read(rn, cnt).ok_or("internal: range outside the model")?;
            ensure_eq(c.read_records(f, rn as u32, cnt as u32)?, want, &format!("ReadRecords({rn}, {cnt})"))?;
        }
        Ok(())
    });
    ctx.step(&format!("{tag}: two WriteRecord calls of one transaction build one record"), |c| {
        let (a, b) = (pat(13, 8), pat(14, 8));
        login(c, aid, 3)?;
        c.write_record(f, 0, &a)?;
        c.write_record(f, 8, &b)?;
        commit_ok(c)?;
        m.append(&[(0, &a), (8, &b)]);
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: UpdateRecord changes bytes of the chosen record"), |c| {
        let d = pat(15, 5);
        login(c, aid, 3)?;
        c.update_record(f, 1, 2, &d)?;
        commit_ok(c)?;
        ensure(m.update(1, 2, &d), "internal: model update")?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: one record updated twice in a transaction works; a second record in the same transaction is refused"), |c| {
        let (d1, d2) = (pat(16, 4), pat(17, 4));
        login(c, aid, 3)?;
        c.update_record(f, 0, 0, &d1)?;
        c.update_record(f, 0, 8, &d2)?;
        commit_ok(c)?;
        ensure(m.update(0, 0, &d1) && m.update(0, 8, &d2), "internal: model update")?;
        read_all(c, f, &m)?;
        login(c, aid, 3)?;
        c.update_record(f, 0, 0, &[0xAA])?;
        let r = c.update_record(f, 1, 0, &[0xBB]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("update of a second record: {s} (0x{:02X})", s.code()));
        login(c, aid, 1)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: WriteRecord after UpdateRecord in the same transaction is refused"), |c| {
        login(c, aid, 3)?;
        c.update_record(f, 0, 0, &[0xCC])?;
        let r = c.write_record(f, 0, &[1, 2, 3]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("{s} (0x{:02X})", s.code()));
        login(c, aid, 1)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: AbortTransaction discards a written record"), |c| {
        login(c, aid, 3)?;
        c.write_record(f, 0, &pat(18, 16))?;
        abort_ok(c)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: a failed command aborts the pending record"), |c| {
        login(c, aid, 3)?;
        c.write_record(f, 0, &pat(19, 16))?;
        let r = c.read_records(f, 0, 50);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 1)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: ReadRecords of more records than exist: BOUNDARY_ERROR; a record number beyond the end is refused"), |c| {
        login(c, aid, 1)?;
        let r = c.read_records(f, 0, m.recs.len() as u32 + 1);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 1)?;
        let r = c.read_records(f, 10, 1);
        let s = c.expect_any_status(r)?;
        c.detail(format!("record number 10: {s} (0x{:02X})", s.code()));
        Ok(())
    });
    ctx.step(&format!("{tag}: record boundaries: the last byte of a record works, offset 16 is BOUNDARY_ERROR, overrun refused"), |c| {
        login(c, aid, 3)?;
        c.write_record(f, 15, &[0xAB])?;
        commit_ok(c)?;
        m.append(&[(15, &[0xAB])]);
        read_all(c, f, &m)?;
        let r = c.write_record(f, 16, &[1]);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 3)?;
        let r = c.write_record(f, 10, &[1; 7]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("overrun: {s} (0x{:02X})", s.code()));
        login(c, aid, 1)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: ClearRecordFile is effective at the commit; the file is then empty"), |c| {
        login(c, aid, 3)?;
        c.clear_record_file(f)?;
        read_all(c, f, &m)?; // old content until the commit
        commit_ok(c)?;
        m.clear();
        ensure_eq(c.get_file_settings(f)?.record.map(|r| r.current_records), Some(0), "record count")?;
        let r = c.read_records(f, 0, 0);
        c.expect_err(Status::BoundaryError, r)
    });
    ctx.step(&format!("{tag}: WriteRecord after ClearRecordFile in the same transaction is refused"), |c| {
        let r0 = pat(20, 16);
        login(c, aid, 3)?;
        c.write_record(f, 0, &r0)?;
        commit_ok(c)?;
        m.append(&[(0, &r0)]);
        c.clear_record_file(f)?;
        let r = c.write_record(f, 0, &[1]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("{s} (0x{:02X})", s.code()));
        login(c, aid, 1)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: the file takes 6 records; the 7th WriteRecord and UpdateRecord on a full file are refused"), |c| {
        login(c, aid, 3)?;
        for i in 1..6 {
            let r = pat(30 + i, 16);
            c.write_record(f, 0, &r)?;
            commit_ok(c)?;
            m.append(&[(0, &r)]);
        }
        read_all(c, f, &m)?;
        ensure(!m.append(&[(0, &[1])]), "internal: the model must say full")?;
        let r = c.write_record(f, 0, &[1; 16]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("7th record: {s} (0x{:02X})", s.code()));
        login(c, aid, 3)?;
        let r = c.update_record(f, 0, 0, &[1]);
        let s = c.expect_any_status(r)?;
        c.detail(format!("update on a full file: {s} (0x{:02X})", s.code()));
        login(c, aid, 1)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: after ClearRecordFile the full file takes records again"), |c| {
        login(c, aid, 3)?;
        c.clear_record_file(f)?;
        commit_ok(c)?;
        m.clear();
        let r = pat(40, 16);
        c.write_record(f, 0, &r)?;
        commit_ok(c)?;
        m.append(&[(0, &r)]);
        read_all(c, f, &m)
    });
}

fn big_records(ctx: &mut Ctx, aid: Aid, f: u8) {
    let mut m = RecordModel::new(120, 3, false);
    ctx.step("LinearRecord Full, records of 120 bytes (several frames each way): write, commit, read", |c| {
        login(c, aid, 0)?;
        c.create_record_file(&RecordFileSpec::new(f, ladder(), 120, 3).comm_mode(CommMode::Full))?;
        login(c, aid, 3)?;
        for i in 0..2u32 {
            let r = pat(50 + i, 120);
            c.write_record(f, 0, &r)?;
            commit_ok(c)?;
            m.append(&[(0, &r)]);
        }
        read_all(c, f, &m)?;
        ensure_eq(c.read_records(f, 1, 1)?, m.read(1, 1).ok_or("model")?, "the older record alone")
    });
    ctx.step("LinearRecord Full: a 100-byte UpdateRecord inside a 120-byte record, and a partial write at an offset", |c| {
        let d = pat(60, 100);
        login(c, aid, 3)?;
        c.update_record(f, 0, 10, &d)?;
        commit_ok(c)?;
        ensure(m.update(0, 10, &d), "model")?;
        read_all(c, f, &m)?;
        let part = pat(61, 70);
        c.write_record(f, 50, &part)?;
        commit_ok(c)?;
        m.append(&[(50, &part)]);
        read_all(c, f, &m)
    });
}

fn cyclic_record_files(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        let mut nos = ctx.file_nos();
        for mode in MODES {
            let f = nos.next();
            cyclic_mode(ctx, aid, f, mode);
        }
        let f = nos.next();
        ctx.step("CreateCyclicRecordFile with a single record is refused (a cyclic file needs at least 2)", |c| {
            login(c, aid, 0)?;
            let r = c.create_record_file(&RecordFileSpec::new(f, ladder(), 8, 1).cyclic());
            let s = c.expect_any_status(r)?;
            c.detail(format!("{s} (0x{:02X})", s.code()));
            Ok(())
        });
    });
}

fn cyclic_mode(ctx: &mut Ctx, aid: Aid, f: u8, mode: CommMode) {
    let tag = format!("CyclicRecord {mode}");
    let mut m = RecordModel::new(8, 5, true);
    ctx.step(&format!("{tag}: CreateCyclicRecordFile (8 bytes x 5, holds 4); GetFileSettings"), |c| {
        login(c, aid, 0)?;
        c.create_record_file(&RecordFileSpec::new(f, ladder(), 8, 5).cyclic().comm_mode(mode))?;
        let fs = c.get_file_settings(f)?;
        ensure_eq((fs.file_type, fs.comm_mode(), fs.access), (FileType::CyclicRecord, mode, ladder()), "settings")?;
        ensure_eq(fs.record, Some(RecordSettings { record_size: 8, max_records: 5, current_records: 0 }), "record settings")
    });
    ctx.step(&format!("{tag}: 4 records fit; every further record replaces the oldest (7 commits, read back after each)"), |c| {
        login(c, aid, 3)?;
        for i in 0..7u32 {
            let r = pat(100 + i, 8);
            c.write_record(f, 0, &r)?;
            commit_ok(c)?;
            m.append(&[(0, &r)]);
            ensure_eq(m.recs.len(), (i as usize + 1).min(4), "model size")?;
            read_all(c, f, &m)?;
        }
        Ok(())
    });
    ctx.step(&format!("{tag}: ReadRecords ranges across the wrap"), |c| {
        login(c, aid, 1)?;
        for (rn, cnt) in [(0usize, 1usize), (3, 1), (0, 4), (1, 2), (2, 0), (3, 0)] {
            let want = m.read(rn, cnt).ok_or("internal: range outside the model")?;
            ensure_eq(c.read_records(f, rn as u32, cnt as u32)?, want, &format!("ReadRecords({rn}, {cnt})"))?;
        }
        let r = c.read_records(f, 0, 5);
        c.expect_err(Status::BoundaryError, r)
    });
    ctx.step(&format!("{tag}: UpdateRecord on the newest and on the oldest record of a wrapped file"), |c| {
        login(c, aid, 3)?;
        for (rn, d) in [(0usize, pat(110, 3)), (3, pat(111, 2))] {
            c.update_record(f, rn as u32, 1, &d)?;
            commit_ok(c)?;
            ensure(m.update(rn, 1, &d), "model")?;
            read_all(c, f, &m)?;
        }
        Ok(())
    });
    ctx.step(&format!("{tag}: AbortTransaction does not consume the oldest record"), |c| {
        login(c, aid, 3)?;
        c.write_record(f, 0, &pat(120, 8))?;
        abort_ok(c)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: a failed command aborts the pending record"), |c| {
        login(c, aid, 3)?;
        c.write_record(f, 0, &pat(121, 8))?;
        let r = c.write_record(f, 8, &[1]);
        c.expect_err(Status::BoundaryError, r)?;
        login(c, aid, 1)?;
        read_all(c, f, &m)
    });
    ctx.step(&format!("{tag}: ClearRecordFile, then the file fills and wraps again"), |c| {
        login(c, aid, 3)?;
        c.clear_record_file(f)?;
        commit_ok(c)?;
        m.clear();
        for i in 0..5u32 {
            let r = pat(130 + i, 8);
            c.write_record(f, 0, &r)?;
            commit_ok(c)?;
            m.append(&[(0, &r)]);
        }
        read_all(c, f, &m)
    });
}

// ------------------------------------------------------------------ access rights
type Want = Option<Status>;

fn enter_as(c: &mut Ctx, aid: Aid, who: Option<u8>) -> StepResult {
    match who {
        Some(key) => login(c, aid, key),
        None => {
            c.select_application(aid, None)?;
            Ok(())
        }
    }
}

fn who_name(who: Option<u8>) -> String {
    match who {
        Some(key) => format!("key {key}"),
        None => "no authentication".to_string(),
    }
}

fn outcome_name(w: Want) -> String {
    match w {
        None => "allowed".to_string(),
        Some(s) => s.name().to_string(),
    }
}

/// `want` None: the command must have succeeded; Some(status): the card must have refused with exactly that.
fn verdict<T>(c: &Ctx, r: duox::Result<T>, want: Want) -> StepResult {
    match want {
        None => r.map(|_| ()).map_err(StepError::from),
        Some(s) => c.expect_err(s, r),
    }
}

fn access_rights(ctx: &mut Ctx) {
    use Status::{AuthenticationError as A, PermissionDenied as D};
    let (fr, nev) = (AccessRight::FREE, AccessRight::NEVER);
    type Row = (Option<u8>, Want, Want);
    let specs: Vec<(&str, AccessRights, Vec<Row>)> = vec![
        (
            "R key 1, W key 2, RW key 3",
            AccessRights::new(k(1), k(2), k(3), k(0)),
            vec![
                (None, Some(A), Some(A)),
                (Some(0), Some(A), Some(A)),
                (Some(1), None, Some(A)),
                (Some(2), Some(A), None),
                (Some(3), None, None),
                (Some(4), Some(A), Some(A)),
            ],
        ),
        ("free read, write and read-write", AccessRights::new(fr, fr, fr, k(0)), vec![(None, None, None), (Some(0), None, None), (Some(3), None, None)]),
        (
            "R free, W key 2, RW never",
            AccessRights::new(fr, k(2), nev, k(0)),
            vec![(None, None, Some(A)), (Some(1), None, Some(A)), (Some(2), None, None), (Some(3), None, Some(A))],
        ),
        (
            "everything never",
            AccessRights::new(nev, nev, nev, k(0)),
            vec![(None, Some(D), Some(D)), (Some(0), Some(D), Some(D)), (Some(3), Some(D), Some(D))],
        ),
        (
            "R never, W key 2, RW never",
            AccessRights::new(nev, k(2), nev, k(0)),
            vec![(None, Some(D), Some(A)), (Some(1), Some(D), Some(A)), (Some(2), Some(D), None)],
        ),
        (
            "R key 1, W never, RW never",
            AccessRights::new(k(1), nev, nev, k(0)),
            vec![(None, Some(A), Some(D)), (Some(1), None, Some(D)), (Some(2), Some(A), Some(D))],
        ),
        (
            "R never, W never, RW key 3",
            AccessRights::new(nev, nev, k(3), k(0)),
            vec![(None, Some(A), Some(A)), (Some(1), Some(A), Some(A)), (Some(3), None, None)],
        ),
    ];
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(5), |ctx, aid| {
        let mut model: Vec<Vec<u8>> = vec![vec![0u8; 8]; specs.len()];
        ctx.step("create a StandardData file (32 bytes, MAC) for every access right combination", |c| {
            login(c, aid, 0)?;
            for (i, (_, rights, _)) in specs.iter().enumerate() {
                c.create_data_file(&DataFileSpec::new(i as u8, 32, *rights).comm_mode(CommMode::Mac))?;
                ensure_eq(c.get_file_settings(i as u8)?.access, *rights, "access rights as stored")?;
            }
            Ok(())
        });
        for (i, (label, _, rows)) in specs.iter().enumerate() {
            for (who, rwant, wwant) in rows {
                let name = format!(
                    "access {label}: {}: ReadData {}, WriteData {}",
                    who_name(*who),
                    outcome_name(*rwant),
                    outcome_name(*wwant)
                );
                ctx.step(&name, |c| {
                    let f = i as u8;
                    enter_as(c, aid, *who)?;
                    let r = c.read_data(f, 0, 8);
                    match rwant {
                        None => ensure_eq(r?, model[i].clone(), "data read")?,
                        Some(s) => c.expect_err(*s, r)?,
                    }
                    let data = pat(200 + i as u32 * 10 + who.unwrap_or(9) as u32, 8);
                    enter_as(c, aid, *who)?;
                    let w = c.write_data(f, 0, &data);
                    match wwant {
                        None => {
                            w?;
                            model[i] = data;
                        }
                        Some(s) => c.expect_err(*s, w)?,
                    }
                    Ok(())
                });
            }
        }
        ctx.step("the data the permitted writes left in the files reads back", |c| {
            // file 0: key 1; 1 and 2: free; 5: key 1; 6: key 3 (3 and 4 cannot be read)
            for (i, who) in [(0usize, Some(1u8)), (1, None), (2, None), (5, Some(1)), (6, Some(3))] {
                enter_as(c, aid, who)?;
                ensure_eq(c.read_data(i as u8, 0, 8)?, model[i].clone(), &format!("file {i}"))?;
            }
            Ok(())
        });
    });
    change_rights_group(ctx);
    value_and_record_access(ctx);
}

fn change_rights_group(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let (fr, nev) = (AccessRight::FREE, AccessRight::NEVER);
    ctx.app_scope(AppSpec::new(aid).keys(5), |ctx, aid| {
        ctx.step("set up: file 0 (Change key 0), file 1 (Change free), file 2 (Change never), file 3 (additional access rights enabled)", |c| {
            login(c, aid, 0)?;
            c.create_data_file(&DataFileSpec::new(0, 32, ladder()).comm_mode(CommMode::Mac))?;
            c.create_data_file(&DataFileSpec::new(1, 32, AccessRights::new(k(1), k(2), k(3), fr)).comm_mode(CommMode::Mac))?;
            c.create_data_file(&DataFileSpec::new(2, 32, AccessRights::new(k(1), k(2), k(3), nev)).comm_mode(CommMode::Mac))?;
            c.create_data_file(&DataFileSpec::new(3, 32, ladder()).comm_mode(CommMode::Mac).additional_access())?;
            let fs = c.get_file_settings(3)?;
            ensure(fs.option & 0x80 != 0, "the additional access rights flag is not reported")?;
            ensure_eq(fs.additional.len(), 0, "no additional sets yet")
        });
        ctx.step("Change = key 0: key 1 is refused (AUTHENTICATION_ERROR), key 0 changes mode and rights", |c| {
            let new = AccessRights::new(k(4), k(3), k(2), k(0));
            login(c, aid, 1)?;
            let r = c.change_file_settings(0, &FileSettingsChange::new(CommMode::Full.bits(), new));
            c.expect_err(Status::AuthenticationError, r)?;
            login(c, aid, 0)?;
            ensure_eq(c.get_file_settings(0)?.access, ladder(), "rights are unchanged after the refusal")?;
            c.change_file_settings(0, &FileSettingsChange::new(CommMode::Full.bits(), new))?;
            let fs = c.get_file_settings(0)?;
            ensure_eq((fs.comm_mode(), fs.access), (CommMode::Full, new), "settings after the change")?;
            // the new rights are in force
            login(c, aid, 4)?;
            ensure_eq(c.read_data(0, 0, 8)?, vec![0u8; 8], "read with the new read key 4")?;
            login(c, aid, 4)?;
            let r = c.write_data(0, 0, &[1]);
            c.expect_err(Status::AuthenticationError, r)?;
            login(c, aid, 3)?;
            c.write_data(0, 0, &[1, 2, 3])?;
            login(c, aid, 1)?;
            let r = c.read_data(0, 0, 3);
            c.expect_err(Status::AuthenticationError, r)
        });
        ctx.step("Change = free: ChangeFileSettings works without authentication (Plain) and with an unrelated key", |c| {
            let rights = AccessRights::new(k(1), k(2), k(3), fr);
            let mut to_plain = FileSettingsChange::new(CommMode::Plain.bits(), rights);
            to_plain.current_change_access = fr;
            c.select_application(aid, None)?;
            c.change_file_settings(1, &to_plain)?;
            ensure_eq(c.get_file_settings(1)?.comm_mode(), CommMode::Plain, "mode after the unauthenticated change")?;
            let mut to_mac = FileSettingsChange::new(CommMode::Mac.bits(), rights);
            to_mac.current_change_access = fr;
            login(c, aid, 3)?;
            c.change_file_settings(1, &to_mac)?;
            ensure_eq(c.get_file_settings(1)?.comm_mode(), CommMode::Mac, "mode after the change with key 3")
        });
        ctx.step("Change = never: ChangeFileSettings is refused (PERMISSION_DENIED) for every key", |c| {
            let rights = AccessRights::new(k(1), k(2), k(3), nev);
            for who in [Some(0u8), Some(3), None] {
                enter_as(c, aid, who)?;
                let mut ch = FileSettingsChange::new(CommMode::Plain.bits(), rights);
                ch.current_change_access = nev;
                let r = c.change_file_settings(2, &ch);
                c.expect_err(Status::PermissionDenied, r)?;
            }
            login(c, aid, 0)?;
            ensure_eq(c.get_file_settings(2)?.comm_mode(), CommMode::Mac, "mode is unchanged")
        });
        ctx.step("additional access rights: a second set grants key 4 read access; two sets grant key 4 write access", |c| {
            let set2 = AccessRights::new(k(4), nev, nev, nev);
            let mut ch = FileSettingsChange::new(CommMode::Mac.bits() | 0x80, ladder());
            ch.additional = vec![set2];
            login(c, aid, 0)?;
            c.change_file_settings(3, &ch)?;
            let fs = c.get_file_settings(3)?;
            ensure_eq(fs.additional.clone(), vec![set2], "additional sets")?;
            login(c, aid, 4)?;
            ensure_eq(c.read_data(3, 0, 8)?, vec![0u8; 8], "read with key 4 (second set)")?;
            login(c, aid, 4)?;
            let r = c.write_data(3, 0, &[9]);
            c.expect_err(Status::AuthenticationError, r)?;
            login(c, aid, 1)?;
            ensure_eq(c.read_data(3, 0, 8)?, vec![0u8; 8], "read with key 1 (first set) still works")?;
            let set3 = AccessRights::new(nev, k(4), nev, nev);
            let mut ch = FileSettingsChange::new(CommMode::Mac.bits() | 0x80, ladder());
            ch.additional = vec![set2, set3];
            login(c, aid, 0)?;
            c.change_file_settings(3, &ch)?;
            ensure_eq(c.get_file_settings(3)?.additional.len(), 2, "two additional sets")?;
            login(c, aid, 4)?;
            let d = pat(300, 8);
            c.write_data(3, 0, &d)?;
            ensure_eq(c.read_data(3, 0, 8)?, d, "write and read with key 4 through the two sets")?;
            login(c, aid, 0)?;
            let mut clear = FileSettingsChange::new(CommMode::Mac.bits() | 0x80, ladder());
            clear.additional = vec![];
            c.change_file_settings(3, &clear)?;
            ensure_eq(c.get_file_settings(3)?.additional.len(), 0, "additional sets after clearing them")?;
            login(c, aid, 4)?;
            let r = c.read_data(3, 0, 8);
            c.expect_err(Status::AuthenticationError, r)
        });
        ctx.step("additional access rights on a file created without them: PERMISSION_DENIED", |c| {
            let mut ch = FileSettingsChange::new(CommMode::Mac.bits() | 0x80, ladder());
            ch.additional = vec![AccessRights::new(k(4), nev, nev, nev)];
            login(c, aid, 0)?;
            let r = c.change_file_settings(0, &ch);
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("ChangeFileSettings of a file that does not exist: FILE_NOT_FOUND", |c| {
            login(c, aid, 0)?;
            let r = c.change_file_settings(17, &FileSettingsChange::new(CommMode::Mac.bits(), ladder()));
            c.expect_err(Status::FileNotFound, r)
        });
    });
}

fn value_and_record_access(ctx: &mut Ctx) {
    use Status::AuthenticationError as A;
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(5), |ctx, aid| {
        ctx.step("set up: a Value file and a LinearRecord file with R key 1, W key 2, RW key 3", |c| {
            login(c, aid, 0)?;
            c.create_value_file(&ValueFileSpec::new(0, ladder(), 0, 1000, 100).comm_mode(CommMode::Mac))?;
            c.create_record_file(&RecordFileSpec::new(1, ladder(), 16, 6).comm_mode(CommMode::Mac))?;
            login(c, aid, 3)?;
            c.write_record(1, 0, &pat(400, 16))?;
            commit_ok(c)
        });
        // (who, GetValue, Debit, Credit)
        let rows: [(Option<u8>, Want, Want, Want); 5] = [
            (None, Some(A), Some(A), Some(A)),
            (Some(0), Some(A), Some(A), Some(A)),
            (Some(1), None, None, Some(A)),
            (Some(2), None, None, Some(A)),
            (Some(3), None, None, None),
        ];
        for (who, get, debit, credit) in rows {
            ctx.step(
                &format!(
                    "Value access: {}: GetValue {}, Debit {}, Credit {}",
                    who_name(who),
                    outcome_name(get),
                    outcome_name(debit),
                    outcome_name(credit)
                ),
                |c| {
                    enter_as(c, aid, who)?;
                    let r = c.get_value(0);
                    match get {
                        None => ensure_eq(r?, 100, "value")?,
                        Some(s) => c.expect_err(s, r)?,
                    }
                    enter_as(c, aid, who)?;
                    let r = c.debit(0, 1);
                    verdict(c, r, debit)?;
                    if debit.is_none() {
                        abort_ok(c)?;
                    }
                    enter_as(c, aid, who)?;
                    let r = c.credit(0, 1);
                    verdict(c, r, credit)?;
                    if credit.is_none() {
                        abort_ok(c)?;
                    }
                    Ok(())
                },
            );
        }
        ctx.step("Value access: nothing above changed the value", |c| {
            login(c, aid, 1)?;
            ensure_eq(c.get_value(0)?, 100, "value")
        });
        // (who, ReadRecords, UpdateRecord, ClearRecordFile)
        let rows: [(Option<u8>, Want, Want, Want); 4] = [
            (None, Some(A), Some(A), Some(A)),
            (Some(1), None, Some(A), Some(A)),
            (Some(2), Some(A), Some(A), Some(A)),
            (Some(3), None, None, None),
        ];
        for (who, read, update, clear) in rows {
            ctx.step(
                &format!(
                    "Record access: {}: ReadRecords {}, UpdateRecord {}, ClearRecordFile {}",
                    who_name(who),
                    outcome_name(read),
                    outcome_name(update),
                    outcome_name(clear)
                ),
                |c| {
                    enter_as(c, aid, who)?;
                    let r = c.read_records(1, 0, 0);
                    match read {
                        None => ensure_eq(r?.len(), 16, "record length")?,
                        Some(s) => c.expect_err(s, r)?,
                    }
                    enter_as(c, aid, who)?;
                    let r = c.update_record(1, 0, 0, &[1]);
                    verdict(c, r, update)?;
                    if update.is_none() {
                        abort_ok(c)?;
                    }
                    enter_as(c, aid, who)?;
                    let r = c.clear_record_file(1);
                    verdict(c, r, clear)?;
                    if clear.is_none() {
                        abort_ok(c)?;
                    }
                    Ok(())
                },
            );
        }
        ctx.step("Record access: WriteRecord with the read key and with the write key (observation, not asserted)", |c| {
            for key in [1u8, 2] {
                login(c, aid, key)?;
                match c.write_record(1, 0, &[0x5A]) {
                    Ok(()) => {
                        c.detail(format!("key {key}: WriteRecord accepted"));
                        abort_ok(c)?;
                    }
                    Err(e) if e.status().is_some() => c.detail(format!("key {key}: {e}")),
                    Err(e) => return Err(e.into()),
                }
            }
            login(c, aid, 1)?;
            ensure_eq(c.read_records(1, 0, 0)?.len(), 16, "the file still holds one record")
        });
    });
}

// ------------------------------------------------------------------ every type: settings, change, counters, delete
fn type_op(c: &mut Ctx, f: u8, seed: u32) -> StepResult {
    let d = pat(500 + seed, 8);
    match f {
        0 => {
            let off = (seed * 8) % 56;
            c.write_data(f, off, &d)?;
            ensure_eq(c.read_data(f, off, 8)?, d, "StandardData read back")
        }
        1 => {
            c.write_data(f, 0, &d)?;
            commit_ok(c)?;
            ensure_eq(c.read_data(f, 0, 8)?, d, "BackupData read back")
        }
        2 => {
            let v = c.get_value(f)?;
            c.credit(f, 1)?;
            commit_ok(c)?;
            ensure_eq(c.get_value(f)?, v + 1, "Value after Credit 1")
        }
        _ => {
            let mut rec = d.clone();
            rec.extend(pat(600 + seed, 8));
            c.write_record(f, 0, &rec)?;
            commit_ok(c)?;
            ensure_eq(c.read_records(f, 0, 1)?, rec, "newest record")
        }
    }
}

fn file_type_sweep(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        ctx.step("create one file of every type; GetFileIDs lists them; GetFileSettings reports type, size, limits, record layout", |c| {
            let m = CommMode::Mac;
            login(c, aid, 0)?;
            c.create_data_file(&DataFileSpec::new(0, 64, ladder()).comm_mode(m))?;
            c.create_data_file(&DataFileSpec::new(1, 64, ladder()).comm_mode(m).backup())?;
            c.create_value_file(&ValueFileSpec::new(2, ladder(), -1000, 1000, 7).comm_mode(m))?;
            c.create_record_file(&RecordFileSpec::new(3, ladder(), 16, 4).comm_mode(m))?;
            c.create_record_file(&RecordFileSpec::new(4, ladder(), 16, 4).cyclic().comm_mode(m))?;
            let mut ids = c.get_file_ids()?;
            ids.sort();
            ensure_eq(ids, vec![0, 1, 2, 3, 4], "GetFileIDs")?;
            let types = [FileType::StandardData, FileType::BackupData, FileType::Value, FileType::LinearRecord, FileType::CyclicRecord];
            for (f, t) in types.iter().enumerate() {
                let fs = c.get_file_settings(f as u8)?;
                ensure_eq((fs.file_type, fs.comm_mode(), fs.access), (*t, m, ladder()), &format!("file {f}"))?;
            }
            ensure_eq(c.get_file_settings(0)?.size, Some(64), "StandardData size")?;
            ensure_eq(c.get_file_settings(1)?.size, Some(64), "BackupData size")?;
            ensure_eq(
                c.get_file_settings(2)?.value,
                Some(ValueSettings { lower: -1000, upper: 1000, limited_credit: 0, flags: 0 }),
                "Value settings",
            )?;
            ensure_eq(
                c.get_file_settings(3)?.record,
                Some(RecordSettings { record_size: 16, max_records: 4, current_records: 0 }),
                "LinearRecord settings",
            )?;
            ensure_eq(
                c.get_file_settings(4)?.record,
                Some(RecordSettings { record_size: 16, max_records: 4, current_records: 0 }),
                "CyclicRecord settings",
            )
        });
        ctx.step("GetISOFileIDs in an application without ISO file ids: FILE_NOT_FOUND", |c| {
            login(c, aid, 0)?;
            let r = c.get_iso_file_ids();
            c.expect_err(Status::FileNotFound, r)
        });
        ctx.step("ChangeFileSettings of every type: Full, Plain, Mac with new rights (R 2, W 3, RW 1); each change read back, the file still works", |c| {
            let new = AccessRights::new(k(2), k(3), k(1), k(0));
            let mut seed = 0;
            for mode in [CommMode::Full, CommMode::Plain, CommMode::Mac] {
                for f in 0..5u8 {
                    seed += 1;
                    login(c, aid, 0)?;
                    c.change_file_settings(f, &FileSettingsChange::new(mode.bits(), new))?;
                    let fs = c.get_file_settings(f)?;
                    ensure_eq((fs.comm_mode(), fs.access), (mode, new), &format!("file {f} settings after the change to {mode}"))?;
                    login(c, aid, 1)?;
                    type_op(c, f, seed).map_err(|e| StepError::fail(format!("file {f} in mode {mode}: {e}")))?;
                }
            }
            Ok(())
        });
        ctx.step("ChangeFileSettings with a key that is not the change key: AUTHENTICATION_ERROR, settings unchanged", |c| {
            for f in 0..5u8 {
                login(c, aid, 1)?;
                let r = c.change_file_settings(f, &FileSettingsChange::new(CommMode::Plain.bits(), ladder()));
                c.expect_err(Status::AuthenticationError, r)?;
                login(c, aid, 0)?;
                ensure_eq(c.get_file_settings(f)?.comm_mode(), CommMode::Mac, &format!("mode of file {f}"))?;
            }
            Ok(())
        });
        ctx.step("GetFileCounters on a file of every type (statuses recorded)", |c| {
            for f in 0..5u8 {
                login(c, aid, 0)?;
                match c.get_file_counters(f) {
                    Ok(v) => c.detail(format!("file {f}: counter {v}")),
                    Err(e) if e.status().is_some() => c.detail(format!("file {f}: {e}")),
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        });
        ctx.step("DeleteFile of every type: the id disappears, GetFileSettings and data commands say FILE_NOT_FOUND", |c| {
            for f in 0..5u8 {
                login(c, aid, 0)?;
                c.delete_file(f)?;
                ensure(!c.get_file_ids()?.contains(&f), format!("file {f} is still listed"))?;
                let r = c.get_file_settings(f);
                c.expect_err(Status::FileNotFound, r)?;
                login(c, aid, 1)?;
                let r = c.read_data(f, 0, 1);
                c.expect_err(Status::FileNotFound, r)?;
            }
            login(c, aid, 0)?;
            ensure_eq(c.get_file_ids()?, Vec::<u8>::new(), "file list")
        });
        ctx.step("a deleted file number can be used again; a number in use is DUPLICATE_ERROR", |c| {
            login(c, aid, 0)?;
            c.create_data_file(&DataFileSpec::new(0, 1, AccessRights::all(AccessRight::FREE)))?;
            c.write_data(0, 0, &[0x7E])?;
            ensure_eq(c.read_data(0, 0, 0)?, vec![0x7E], "a file of one byte")?;
            login(c, aid, 0)?;
            let r = c.create_data_file(&DataFileSpec::new(0, 8, AccessRights::all(AccessRight::FREE)));
            c.expect_err(Status::DuplicateError, r)?;
            login(c, aid, 0)?;
            let r = c.create_value_file(&ValueFileSpec::new(0, AccessRights::all(AccessRight::FREE), 0, 1, 0));
            c.expect_err(Status::DuplicateError, r)
        });
        ctx.step("files that do not exist: GetFileSettings, DeleteFile and ChangeFileSettings say FILE_NOT_FOUND", |c| {
            login(c, aid, 0)?;
            let r = c.get_file_settings(30);
            c.expect_err(Status::FileNotFound, r)?;
            login(c, aid, 0)?;
            let r = c.delete_file(30);
            c.expect_err(Status::FileNotFound, r)?;
            login(c, aid, 0)?;
            let r = c.get_value(30);
            c.expect_err(Status::FileNotFound, r)
        });
        ctx.step("invalid file creation: number 0x20, size 0 and a size no memory can hold", |c| {
            login(c, aid, 0)?;
            let r = c.create_data_file(&DataFileSpec::new(0x20, 8, AccessRights::all(AccessRight::FREE)));
            let s = c.expect_any_status(r)?;
            c.detail(format!("file number 0x20: {s} (0x{:02X})", s.code()));
            login(c, aid, 0)?;
            let r = c.create_data_file(&DataFileSpec::new(9, 0, AccessRights::all(AccessRight::FREE)));
            let s = c.expect_any_status(r)?;
            c.detail(format!("size 0: {s} (0x{:02X})", s.code()));
            login(c, aid, 0)?;
            let r = c.create_data_file(&DataFileSpec::new(9, 0xFF_FFFF, AccessRights::all(AccessRight::FREE)));
            c.expect_err(Status::OutOfMemory, r)?;
            login(c, aid, 0)?;
            let r = c.create_record_file(&RecordFileSpec::new(9, AccessRights::all(AccessRight::FREE), 0xFF_FFFF, 0xFF_FFFF));
            let s = c.expect_any_status(r)?;
            c.detail(format!("a record file of 16 MiB x 16 M records: {s} (0x{:02X})", s.code()));
            Ok(())
        });
        ctx.step("values the library cannot encode are refused before anything is sent", |c| {
            login(c, aid, 0)?;
            let r = c.create_data_file(&DataFileSpec::new(9, 0x0100_0000, AccessRights::all(AccessRight::FREE)));
            ensure(matches!(r, Err(duox::Error::InvalidArgument(_))), "a 25-bit file size must be refused by the library")?;
            let r = c.read_data(0, 0x0100_0000, 1);
            ensure(matches!(r, Err(duox::Error::InvalidArgument(_))), "a 25-bit offset must be refused by the library")?;
            ensure(c.is_authenticated(), "nothing may have been sent")
        });
    });
}

fn file_count_limit(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        ctx.step("32 files (numbers 0..=31): GetFileIDs lists all of them, number 0x20 is refused, a used number is DUPLICATE_ERROR", |c| {
            need_memory(c, 1800)?;
            login(c, aid, 0)?;
            let free = AccessRights::all(AccessRight::FREE);
            for f in 0..32u8 {
                c.create_value_file(&ValueFileSpec::new(f, free, 0, 100, f as i32))?;
            }
            let mut ids = c.get_file_ids()?;
            ids.sort();
            ensure_eq(ids, (0..32u8).collect::<Vec<_>>(), "GetFileIDs")?;
            login(c, aid, 0)?;
            let r = c.create_value_file(&ValueFileSpec::new(0x20, free, 0, 100, 0));
            let s = c.expect_any_status(r)?;
            c.detail(format!("file number 0x20: {s} (0x{:02X})", s.code()));
            login(c, aid, 0)?;
            let r = c.create_value_file(&ValueFileSpec::new(31, free, 0, 100, 0));
            c.expect_err(Status::DuplicateError, r)?;
            login(c, aid, 0)?;
            for f in [0u8, 7, 16, 31] {
                ensure_eq(c.get_value(f)?, f as i32, &format!("value of file {f}"))?;
            }
            Ok(())
        });
        ctx.step("delete one of 32 files: 31 are listed, the number is free again", |c| {
            login(c, aid, 0)?;
            if c.get_file_ids()?.len() != 32 {
                return Err(StepError::skip("the 32 files were not created"));
            }
            c.delete_file(12)?;
            ensure_eq(c.get_file_ids()?.len(), 31, "files after DeleteFile")?;
            c.create_value_file(&ValueFileSpec::new(12, AccessRights::all(AccessRight::FREE), 0, 100, 99))?;
            ensure_eq(c.get_file_ids()?.len(), 32, "files after creating it again")?;
            ensure_eq(c.get_value(12)?, 99, "value of the new file 12")
        });
    });
}

// ------------------------------------------------------------------ memory consumption of files
type CreateFile = fn(&mut Ctx, u8) -> StepResult;

fn memory_consumption(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let items: Vec<(&str, u32, CreateFile)> = vec![
        ("StandardData of 100 bytes", std_blocks(100), |c, f| Ok(c.create_data_file(&DataFileSpec::new(f, 100, ladder()))?)),
        ("BackupData of 50 bytes", backup_blocks(50), |c, f| Ok(c.create_data_file(&DataFileSpec::new(f, 50, ladder()).backup())?)),
        ("Value", 1, |c, f| Ok(c.create_value_file(&ValueFileSpec::new(f, ladder(), 0, 10, 0))?)),
        ("LinearRecord 5 x 20", record_blocks(20, 5), |c, f| Ok(c.create_record_file(&RecordFileSpec::new(f, ladder(), 20, 5))?)),
        ("CyclicRecord 4 x 30", record_blocks(30, 4), |c, f| Ok(c.create_record_file(&RecordFileSpec::new(f, ladder(), 30, 4).cyclic())?)),
        ("TransactionMAC with an AES-128 key", 3, |c, f| {
            let rights = AccessRights::new(k(1), AccessRight::NEVER, AccessRight::NEVER, k(0));
            Ok(c.create_tmac_file(&TmacFileSpec::new(f, rights).key(&[0x42; 16], 1))?)
        }),
    ];
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        let mut prev = ctx.step("FreeMem of the new application", |c| Ok(c.free_mem()?));
        for (i, (name, blocks, create)) in items.iter().enumerate() {
            let overhead = if i % 2 == 0 { 1 } else { 0 };
            ctx.step(&format!("memory of a {name}: {blocks} blocks + {overhead} overhead block (1 per 2 files, 7.12.6)"), |c| {
                login(c, aid, 0)?;
                create(c, i as u8)?;
                c.ensure_picc()?;
                let now = c.free_mem()?;
                let before = prev.ok_or_else(|| StepError::skip("no FreeMem reading before this file"))?;
                prev = Some(now);
                ensure_eq(bytes_taken(before, now)?, (blocks + overhead) * 32, "bytes consumed")
            });
        }
    });
}

// ------------------------------------------------------------------ TransactionMAC creation
fn tmac_files(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let rights = AccessRights::new(k(1), AccessRight::NEVER, AccessRight::NEVER, k(0));
    let (key16, key32) = (pat(900, 16), pat(901, 32));
    ctx.app_scope(AppSpec::new(aid).keys(4), |ctx, aid| {
        ctx.step("CommitReaderID without an AppTransactionMACKey is refused (PARAMETER_ERROR)", |c| {
            login(c, aid, 0)?;
            let with_reader = AccessRights::new(k(1), AccessRight::NEVER, k(2), k(0));
            let r = c.create_tmac_file(&TmacFileSpec::new(15, with_reader));
            c.expect_err(Status::ParameterError, r)
        });
        ctx.step("Transaction Signature with an ECC key that does not exist: NO_SUCH_KEY", |c| {
            login(c, aid, 0)?;
            let r = c.create_tmac_file(&TmacFileSpec::new(15, rights).signature_key(1));
            c.expect_err(Status::NoSuchKey, r)
        });
        for mode in MODES {
            let tag = format!("TransactionMAC {mode}");
            ctx.step(&format!("{tag}: CreateTransactionMACFile (AES-128 key, version 0x5A); GetFileSettings"), |c| {
                login(c, aid, 0)?;
                c.create_tmac_file(&TmacFileSpec::new(15, rights).comm_mode(mode).key(&key16, 0x5A))?;
                let fs = c.get_file_settings(15)?;
                c.detail(fs.describe().join("\n"));
                ensure_eq((fs.file_type, fs.comm_mode(), fs.access), (FileType::TransactionMac, mode, rights), "settings")?;
                let t = fs.tmac.ok_or("no TransactionMAC settings")?;
                ensure_eq((t.key_option & 0x83, t.is_signature(), t.key_version), (2, false, Some(0x5A)), "key option / key version")?;
                ensure_eq((t.excl_map, t.tmc_limit), (None, None), "exclusion map / TMC limit")
            });
            ctx.step(&format!("{tag}: ReadData gives TMC and TMV (12 zero bytes), nothing beyond; the file cannot be written"), |c| {
                login(c, aid, 1)?;
                ensure_eq(c.read_data(15, 0, 0)?, vec![0u8; 12], "TMC || TMV of a new file")?;
                ensure_eq(c.read_data(15, 4, 8)?, vec![0u8; 8], "TMV")?;
                let r = c.read_data(15, 0, 13);
                c.expect_err(Status::BoundaryError, r)?;
                login(c, aid, 1)?;
                let r = c.read_data(15, 12, 1);
                c.expect_err(Status::BoundaryError, r)?;
                login(c, aid, 0)?;
                let r = c.write_data(15, 0, &[1]);
                c.expect_err(Status::PermissionDenied, r)?;
                login(c, aid, 0)?;
                let r = c.read_data(15, 0, 12);
                c.expect_err(Status::AuthenticationError, r)
            });
            ctx.step(&format!("{tag}: DeleteFile removes it; the number is free again"), |c| {
                login(c, aid, 0)?;
                c.delete_file(15)?;
                let r = c.get_file_settings(15);
                c.expect_err(Status::FileNotFound, r)
            });
        }
        ctx.step("TransactionMAC with an AES-256 key and an exclusion map; GetFileSettings", |c| {
            login(c, aid, 0)?;
            let r = c.create_tmac_file(&TmacFileSpec::new(15, rights).key(&key32, 0x33).excl_map(0b110));
            match r {
                Ok(()) => {}
                Err(e) if e.status().is_some() => return Err(StepError::skip(format!("the card refuses an AES-256 TransactionMAC key: {e}"))),
                Err(e) => return Err(e.into()),
            }
            let t = c.get_file_settings(15)?.tmac.ok_or("no TransactionMAC settings")?;
            ensure_eq((t.key_option & 3, t.key_version, t.excl_map), (3, Some(0x33), Some(0b110)), "key type / version / exclusion map")?;
            login(c, aid, 0)?;
            c.delete_file(15)?;
            Ok(())
        });
        ctx.step("TransactionMAC with CommitReaderID enabled (ReadWrite = key 2) and a key; GetFileSettings", |c| {
            let with_reader = AccessRights::new(k(1), AccessRight::NEVER, k(2), k(0));
            login(c, aid, 0)?;
            c.create_tmac_file(&TmacFileSpec::new(15, with_reader).key(&key16, 0x01))?;
            ensure_eq(c.get_file_settings(15)?.access, with_reader, "access rights")?;
            login(c, aid, 0)?;
            c.delete_file(15)?;
            Ok(())
        });
        ctx.step("a second TransactionMAC file in the same application: PERMISSION_DENIED", |c| {
            login(c, aid, 0)?;
            c.create_tmac_file(&TmacFileSpec::new(15, rights).key(&key16, 0x5A))?;
            let r = c.create_tmac_file(&TmacFileSpec::new(14, rights).key(&key16, 0x5B));
            c.expect_err(Status::PermissionDenied, r)?;
            login(c, aid, 0)?;
            ensure_eq(c.get_file_ids()?, vec![15], "only the first TransactionMAC file exists")
        });
        ctx.step("ChangeFileSettings: TMIExclFileMap, then TMCLimit above the counter; a limit not above it is PARAMETER_ERROR", |c| {
            let mut ch = FileSettingsChange::new(0x40 | CommMode::Plain.bits(), rights);
            ch.tmac_excl_map = Some(0b101);
            login(c, aid, 0)?;
            c.change_file_settings(15, &ch)?;
            let t = c.get_file_settings(15)?.tmac.ok_or("no TransactionMAC settings")?;
            ensure_eq(t.excl_map, Some(0b101), "exclusion map")?;
            let mut ch = FileSettingsChange::new(0x60 | CommMode::Plain.bits(), rights);
            ch.tmac_excl_map = Some(0b101);
            ch.tmc_limit = Some(100);
            login(c, aid, 0)?;
            c.change_file_settings(15, &ch)?;
            let t = c.get_file_settings(15)?.tmac.ok_or("no TransactionMAC settings")?;
            ensure_eq((t.excl_map, t.tmc_limit), (Some(0b101), Some(100)), "exclusion map / TMC limit")?;
            ch.tmc_limit = Some(0);
            login(c, aid, 0)?;
            let r = c.change_file_settings(15, &ch);
            c.expect_err(Status::ParameterError, r)
        });
    });
    // memory: re-creating the TransactionMAC file takes no new memory
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        ctx.step("deleting and re-creating the TransactionMAC file takes no additional memory (7.12.1.5)", |c| {
            let spec = TmacFileSpec::new(15, rights).key(&key16, 0x5A);
            login(c, aid, 0)?;
            c.create_tmac_file(&spec)?;
            c.ensure_picc()?;
            let first = c.free_mem()?;
            login(c, aid, 0)?;
            c.delete_file(15)?;
            c.create_tmac_file(&spec)?;
            c.ensure_picc()?;
            ensure_eq(c.free_mem()?, first, "FreeMem after deleting and re-creating the file")
        });
    });
    // two applications that both hold a TransactionMAC file cannot be selected together
    let (a, b, plain) = (ctx.alloc_aid(), ctx.alloc_aid(), ctx.alloc_aid());
    ctx.app_scope(AppSpec::new(a).keys(1), |ctx, a| {
        ctx.app_scope(AppSpec::new(b).keys(1), |ctx, b| {
            ctx.app_scope(AppSpec::new(plain).keys(1), |ctx, plain| {
                ctx.step("TransactionMAC files in two applications: selecting both is PERMISSION_DENIED, one with a plain application works", |c| {
                    for x in [a, b] {
                        login(c, x, 0)?;
                        c.create_tmac_file(&TmacFileSpec::new(15, rights).key(&key16, 1))?;
                    }
                    let rc = c.select_application(a, Some(plain))?;
                    ensure_eq(rc, 0, "SelectApplication of an application with and one without TransactionMAC")?;
                    let r = c.select_application(a, Some(b));
                    c.expect_err(Status::PermissionDenied, r)?;
                    ensure_eq(c.selection().primary, Some(Aid::PICC), "selection after the refusal")
                });
            });
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_is_deterministic_and_seed_dependent() {
        assert_eq!(pat(1, 40), pat(1, 40));
        assert_ne!(pat(1, 40), pat(2, 40));
        assert_eq!(pat(7, 0), Vec::<u8>::new());
        assert_eq!(pat(7, 5), pat(7, 9)[..5].to_vec());
        let p = pat(3, 64);
        assert!(p.iter().any(|&b| b != p[0]), "not constant");
    }

    #[test]
    fn file_memory_follows_the_data_sheet_formulas() {
        assert_eq!(std_blocks(1), 1);
        assert_eq!(std_blocks(32), 1);
        assert_eq!(std_blocks(33), 2);
        assert_eq!(std_blocks(100), 4);
        assert_eq!(backup_blocks(50), 4);
        assert_eq!(record_blocks(20, 5), 1 + 4);
        assert_eq!(record_blocks(30, 4), 1 + 4);
        assert_eq!(record_blocks(120, 3), 13);
    }

    fn rec(b: u8) -> Vec<u8> {
        vec![b; 4]
    }

    #[test]
    fn linear_record_model_fills_and_refuses() {
        let mut m = RecordModel::new(4, 3, false);
        assert!(m.read(0, 0).is_none(), "an empty file cannot be read");
        for b in 1..=3 {
            assert!(m.append(&[(0, &rec(b))]));
        }
        assert!(m.is_full());
        assert!(!m.append(&[(0, &rec(9))]), "a full linear file refuses");
        assert_eq!(m.all().unwrap(), [rec(1), rec(2), rec(3)].concat());
    }

    #[test]
    fn cyclic_record_model_keeps_max_minus_one() {
        let mut m = RecordModel::new(4, 4, true);
        assert_eq!(m.capacity(), 3);
        for b in 1..=5 {
            assert!(m.append(&[(0, &rec(b))]));
        }
        assert_eq!(m.recs.len(), 3);
        assert_eq!(m.all().unwrap(), [rec(3), rec(4), rec(5)].concat(), "the two oldest records were overwritten");
    }

    #[test]
    fn record_ranges_count_from_the_newest_and_return_oldest_first() {
        let mut m = RecordModel::new(4, 8, false);
        for b in 1..=4 {
            m.append(&[(0, &rec(b))]);
        }
        // record 0 is the newest (4)
        assert_eq!(m.read(0, 1).unwrap(), rec(4));
        assert_eq!(m.read(1, 1).unwrap(), rec(3));
        assert_eq!(m.read(0, 2).unwrap(), [rec(3), rec(4)].concat());
        assert_eq!(m.read(1, 2).unwrap(), [rec(2), rec(3)].concat());
        // count 0: from the oldest up to and including the record
        assert_eq!(m.read(1, 0).unwrap(), [rec(1), rec(2), rec(3)].concat());
        assert_eq!(m.read(0, 0).unwrap(), [rec(1), rec(2), rec(3), rec(4)].concat());
        assert!(m.read(0, 5).is_none());
        assert!(m.read(4, 1).is_none());
    }

    #[test]
    fn partial_and_fragmented_records_are_zero_padded() {
        let mut m = RecordModel::new(8, 4, false);
        m.append(&[(2, &[1, 2, 3])]);
        assert_eq!(m.recs[0], vec![0, 0, 1, 2, 3, 0, 0, 0]);
        m.append(&[(0, &[9, 9]), (4, &[8, 8])]);
        assert_eq!(m.recs[1], vec![9, 9, 0, 0, 8, 8, 0, 0]);
        assert!(m.update(1, 1, &[5, 5]));
        assert_eq!(m.recs[0], vec![0, 5, 5, 2, 3, 0, 0, 0]);
        assert!(!m.update(2, 0, &[1]), "no such record");
        assert!(!m.update(0, 7, &[1, 2]), "beyond the record");
        m.clear();
        assert!(m.recs.is_empty());
    }
}
