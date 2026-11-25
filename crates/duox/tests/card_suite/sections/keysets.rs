//! Section `keysets`: application key sets (7.8.5.1, 7.8.6.2 .. 7.8.6.5, 7.8.6.8).
//!
//! Applications are created with several key sets (2 to 16, AES-128 only or with room for AES-256 keys, a roll key,
//! different AppKeySettings). The section then personalises key sets (InitializeKeySet, ChangeKeyEV2 with a key set
//! number, FinalizeKeySet), reads key versions and key set versions (GetKeyVersion), and rolls the active key set
//! (RollKeySet) with every rule of the data sheet: the version must grow, the key type may not get weaker, the roll
//! key is needed, numbering is relative to the active key set and changes after every roll.
//!
//! The expected state of the card is kept in [`KsModel`], a small model of the data sheet rules (unit tested
//! offline). Every operation is predicted by the model first, sent to the card, and then the card must agree: success
//! or the exact refusal, and afterwards key set versions, key versions and authentication with the active keys.
//!
//! Nothing here touches the PICC level; key sets do not exist there and the commands are never sent there.

use crate::ctx::{ensure, ensure_eq, CleanupId, Ctx, StepError, StepResult};
use duox::card::{Aid, AppSpec, AuthKind, ChangeKeySpec, KeySetConfig, KeySetInfo, Status};

pub const NAME: &str = "keysets";
pub const DESCRIPTION: &str =
    "Key sets: create with 2..16 sets, InitializeKeySet, ChangeKeyEV2 with a key set number, FinalizeKeySet, RollKeySet and its rules, key set versions, AES-128 and AES-256 sets.";

const AKS_VERSION: u8 = 5;

pub fn run(ctx: &mut Ctx) {
    reclaim(ctx, "the key set application");
    main_application(ctx);
    reclaim(ctx, "the AES-128 only key set application");
    narrow_application(ctx);
    reclaim(ctx, "the sixteen key set application");
    sixteen_sets(ctx);
    reclaim(ctx, "the change key rights variants");
    rights_variants(ctx);
    reclaim(ctx, "the single key set application and creation errors");
    single_set_and_creation_errors(ctx);
}

// ------------------------------------------------------------------ helpers
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

fn need_memory(c: &mut Ctx, bytes: u32) -> StepResult {
    c.ensure_picc()?;
    let free = c.free_mem()?;
    if free < bytes {
        return Err(StepError::skip(format!("needs {bytes} bytes of free memory, the card has {free}")));
    }
    Ok(())
}

/// Memory of an application with key sets, in blocks (7.8.7 and 7.11.5).
fn app_blocks(n_keys: u32, key_sets: u32, max_key_size: u32) -> u32 {
    let keys = if n_keys == 0 { 0 } else { key_sets * (21 + n_keys * (max_key_size + 4)).div_ceil(32) };
    keys + 1
}

/// An application with key sets. `KeySett3` bit 0 enables the key set block of CreateApplication; it is set
/// explicitly because the library's `key_sets()` alone leaves KeySett3 at 0.
fn ks_spec(aid: Aid, keys: u8, sets: u8, max_key_size: u8, roll_key: u8, key_settings: u8) -> AppSpec {
    AppSpec::new(aid).keys(keys).key_settings(key_settings).key_sett3(0x01).key_sets(KeySetConfig {
        aks_version: AKS_VERSION,
        no_key_sets: sets,
        max_key_size,
        app_key_set_settings: roll_key,
    })
}

fn bytes_taken(before: u32, now: u32) -> StepResult<u32> {
    before.checked_sub(now).ok_or_else(|| StepError::fail(format!("FreeMem rose from {before} to {now}")))
}

fn enter(c: &mut Ctx, aid: Aid, key_no: u8) -> StepResult {
    let z = c.zero_key;
    c.auth_app(aid, key_no, &z)
}

/// Try CreateApplication for an AID that was just allocated; the caller removes the probe application afterwards.
fn attempt_create(c: &mut Ctx, spec: &AppSpec) -> (StepResult, CleanupId) {
    let aid = spec.aid;
    let id = c.push_cleanup(&format!("delete probe application {aid} if it exists"), move |c| c.delete_app_tolerant(aid));
    let r = c.auth_picc().and_then(|_| c.create_application(spec));
    (r, id)
}

// ------------------------------------------------------------------ the model
/// What the data sheet says about a refused key set command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refuse {
    /// The data sheet names this status.
    Exact(Status),
    /// The command must be refused; the data sheet gives no specific status.
    Any,
}

#[derive(Debug, Clone, PartialEq)]
struct SetModel {
    version: u8,
    /// AES-256 (32-byte keys) instead of AES-128.
    wide: bool,
    keys: Vec<Vec<u8>>,
    vers: Vec<u8>,
}

/// All key sets of one application, absolute order of creation, with the index of the active key set.
#[derive(Debug, Clone)]
struct KsModel {
    sets: Vec<SetModel>,
    aks: usize,
    n_keys: usize,
    allow_wide: bool,
}

impl KsModel {
    fn new(n_sets: usize, n_keys: usize, aks_version: u8, key_version: u8, allow_wide: bool) -> Self {
        let sets = (0..n_sets)
            .map(|i| SetModel {
                version: if i == 0 { aks_version } else { 0 },
                wide: false,
                keys: vec![vec![0u8; 16]; n_keys],
                vers: vec![key_version; n_keys],
            })
            .collect();
        KsModel { sets, aks: 0, n_keys, allow_wide }
    }
    fn n(&self) -> usize {
        self.sets.len()
    }
    /// Absolute index of the key set with number `rel` (0 = the active key set).
    fn abs(&self, rel: usize) -> usize {
        (self.aks + rel) % self.n()
    }
    fn set(&self, rel: usize) -> &SetModel {
        &self.sets[self.abs(rel)]
    }
    /// Key set versions in key set number order, active key set first.
    fn versions(&self) -> Vec<u8> {
        (0..self.n()).map(|r| self.set(r).version).collect()
    }
    fn init(&mut self, rel: usize, wide: bool) -> Result<(), Refuse> {
        if rel >= self.n() {
            return Err(Refuse::Exact(Status::NoSuchKey));
        }
        if rel == 0 {
            return Err(Refuse::Any);
        }
        if wide && !self.allow_wide {
            return Err(Refuse::Exact(Status::PermissionDenied));
        }
        let src = self.sets[self.aks].clone();
        let len = if wide { 32 } else { 16 };
        let keys = src
            .keys
            .iter()
            .map(|k| {
                let mut v = k.clone();
                v.resize(len, 0); // padded with zero bytes or truncated (7.8.6.3)
                v
            })
            .collect();
        let abs = self.abs(rel);
        self.sets[abs] = SetModel { version: 0, wide, keys, vers: src.vers };
        Ok(())
    }
    fn finalize(&mut self, rel: usize, version: u8) -> Result<(), Refuse> {
        if rel >= self.n() {
            return Err(Refuse::Exact(Status::NoSuchKey));
        }
        if rel == 0 || version == 0 {
            return Err(Refuse::Any);
        }
        let abs = self.abs(rel);
        if self.sets[abs].version != 0 {
            return Err(Refuse::Exact(Status::PermissionDenied));
        }
        self.sets[abs].version = version;
        Ok(())
    }
    fn change(&mut self, rel: usize, key: usize, value: Vec<u8>, version: u8) -> Result<(), Refuse> {
        if rel >= self.n() || key >= self.n_keys {
            return Err(Refuse::Exact(Status::NoSuchKey));
        }
        let abs = self.abs(rel);
        let want = if self.sets[abs].wide { 32 } else { 16 };
        if value.len() != want {
            return Err(Refuse::Any);
        }
        self.sets[abs].keys[key] = value;
        self.sets[abs].vers[key] = version;
        Ok(())
    }
    fn roll(&mut self, rel: usize) -> Result<(), Refuse> {
        if rel >= self.n() {
            return Err(Refuse::Exact(Status::NoSuchKey));
        }
        if rel == 0 {
            return Err(Refuse::Any);
        }
        let (target, active) = (self.set(rel), self.set(0));
        // the version has to grow, and the key type may not get weaker (7.8.5.1.4)
        if target.version <= active.version || (active.wide && !target.wide) {
            return Err(Refuse::Exact(Status::PermissionDenied));
        }
        self.aks = self.abs(rel);
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Op {
    Init { rel: u8, wide: bool },
    /// `ev2`: ChangeKeyEV2 also for key set 0 (otherwise ChangeKey).
    Change { rel: u8, key: u8, ev2: bool },
    Finalize { rel: u8, version: u8 },
    Roll { rel: u8 },
    /// RollKeySet authenticated with a key that is not the roll key.
    RollAs { rel: u8, key: u8 },
}

impl Op {
    fn describe(&self) -> String {
        match self {
            Op::Init { rel, wide } => format!("InitializeKeySet({rel}, {})", if *wide { "AES-256" } else { "AES-128" }),
            Op::Change { rel, key, ev2 } => {
                format!("{}(key set {rel}, key {key})", if *ev2 || *rel != 0 { "ChangeKeyEV2" } else { "ChangeKey" })
            }
            Op::Finalize { rel, version } => format!("FinalizeKeySet({rel}, version {version})"),
            Op::Roll { rel } => format!("RollKeySet({rel})"),
            Op::RollAs { rel, key } => format!("RollKeySet({rel}) authenticated with key {key}, which is not the roll key"),
        }
    }
    /// What the model says about this operation, without changing the model.
    fn predict(&self, m: &KsModel) -> Result<(), Refuse> {
        let mut t = m.clone();
        match self {
            Op::Init { rel, wide } => t.init(*rel as usize, *wide),
            Op::Change { rel, key, .. } => {
                let len = if (*rel as usize) < t.n() && t.set(*rel as usize).wide { 32 } else { 16 };
                t.change(*rel as usize, *key as usize, vec![0; len], 0)
            }
            Op::Finalize { rel, version } => t.finalize(*rel as usize, *version),
            Op::Roll { rel } => t.roll(*rel as usize),
            Op::RollAs { .. } => Err(Refuse::Exact(Status::AuthenticationError)),
        }
    }
}

fn outcome(p: &Result<(), Refuse>) -> String {
    match p {
        Ok(()) => "accepted".to_string(),
        Err(Refuse::Exact(s)) => format!("refused: {}", s.name()),
        Err(Refuse::Any) => "refused".to_string(),
    }
}

// ------------------------------------------------------------------ talking to the card
/// Authenticate with key `key_no` of the ACTIVE key set (value and length from the model).
fn login_aks(c: &mut Ctx, aid: Aid, m: &KsModel, key_no: u8) -> StepResult {
    c.auth_app(aid, key_no, &m.set(0).keys[key_no as usize])
}

/// The card must agree with the prediction.
fn settle<T, E: Into<StepError>>(c: &Ctx, r: Result<T, E>, pred: Result<(), Refuse>) -> StepResult {
    match pred {
        Ok(()) => r.map(|_| ()).map_err(Into::into),
        Err(Refuse::Exact(s)) => c.expect_err(s, r),
        Err(Refuse::Any) => c.expect_any_status(r).map(|_| ()),
    }
}

/// Send one operation, compare with the model, update the model.
fn exec(c: &mut Ctx, aid: Aid, roll_key: u8, m: &mut KsModel, op: &Op, salt: u8) -> StepResult {
    let pred = op.predict(m);
    let mut next = m.clone();
    match op {
        Op::Init { rel, wide } => {
            let _ = next.init(*rel as usize, *wide);
            login_aks(c, aid, m, 0)?;
            let r = c.initialize_key_set(*rel, if *wide { 3 } else { 2 });
            settle(c, r, pred)?;
        }
        Op::Finalize { rel, version } => {
            let _ = next.finalize(*rel as usize, *version);
            login_aks(c, aid, m, 0)?;
            let r = c.finalize_key_set(*rel, *version);
            settle(c, r, pred)?;
        }
        Op::Change { rel, key, ev2 } => {
            let (r_, k_) = (*rel as usize, *key as usize);
            let len = if r_ < m.n() && m.set(r_).wide { 32 } else { 16 };
            let seed: [u8; 32] = rand::random();
            let new = seed[..len].to_vec();
            let version = 0x40u8.wrapping_add(salt);
            let old = if r_ < m.n() && k_ < m.n_keys { m.set(r_).keys[k_].clone() } else { vec![0; len] };
            let _ = next.change(r_, k_, new.clone(), version);
            login_aks(c, aid, m, 0)?;
            let own = *rel == 0 && *key == 0;
            let mut spec = ChangeKeySpec::new(*key, &new, version);
            if !own {
                spec = spec.old_key(&old);
            }
            if *rel != 0 || *ev2 {
                spec = spec.key_set(*rel);
            }
            let r = c.change_key(&spec);
            settle(c, r, pred)?;
            if pred.is_ok() {
                ensure_eq(c.is_authenticated(), !own, "session after the key change (ends only for the authenticated key)")?;
            }
        }
        Op::Roll { rel } => {
            let _ = next.roll(*rel as usize);
            login_aks(c, aid, m, roll_key)?;
            let r = c.roll_key_set(*rel);
            settle(c, r, pred)?;
            if pred.is_ok() {
                ensure(!c.is_authenticated(), "RollKeySet must end the authentication")?;
            }
        }
        Op::RollAs { rel, key } => {
            login_aks(c, aid, m, *key)?;
            let r = c.roll_key_set(*rel);
            settle(c, r, pred)?;
        }
    }
    let rolled = matches!(op, Op::Roll { .. }) && pred.is_ok();
    let before = m.set(0).clone();
    if pred.is_ok() {
        *m = next;
    }
    if rolled {
        check_new_keys(c, aid, m, &before)?;
    }
    Ok(())
}

/// After a roll: the keys of the new active key set authenticate, the old values (where they differ) do not.
fn check_new_keys(c: &mut Ctx, aid: Aid, m: &KsModel, old: &SetModel) -> StepResult {
    let new = m.set(0);
    for k in 0..m.n_keys {
        c.select_application(aid, None)?;
        if old.keys[k] != new.keys[k] {
            let r = c.authenticate_ev2_first(k as u8, &old.keys[k], &[]);
            c.expect_err(Status::AuthenticationError, r)?;
        }
        login_aks(c, aid, m, k as u8)?;
        let a = c.auth_summary().ok_or("no session")?;
        ensure_eq((a.kind, a.key_no, a.key_bits), (AuthKind::Aes, Some(k as u8), if new.wide { 256 } else { 128 }), "session of the new active key set")?;
    }
    Ok(())
}

/// Compare everything readable with the model; `full` also reads the version of every key of every key set.
fn verify(c: &mut Ctx, aid: Aid, m: &KsModel, full: bool) -> StepResult {
    login_aks(c, aid, m, 0)?;
    ensure_eq(c.get_key_set_versions()?, m.versions(), "key set versions (active key set first)")?;
    let ks = c.get_key_settings()?;
    ensure_eq(ks.key_type, if m.set(0).wide { 3 } else { 2 }, "key type of the active key set")?;
    ensure_eq(ks.max_keys as usize, m.n_keys, "number of keys per key set")?;
    let info = ks.key_sets.ok_or("GetKeySettings reports no key set fields")?;
    ensure_eq((info.aks_version, info.key_sets as usize), (m.set(0).version, m.n()), "AKSVersion / number of key sets")?;
    if full {
        for rel in 0..m.n() {
            for k in 0..m.n_keys {
                let got = c.get_key_version(k as u8, Some(rel as u8))?;
                ensure_eq(got, vec![m.set(rel).vers[k]], &format!("version of key {k} in key set {rel}"))?;
            }
        }
    }
    Ok(())
}

/// Run `ops`, one step each; the card must agree with the model after every one.
fn script(ctx: &mut Ctx, aid: Aid, roll_key: u8, m: &mut KsModel, full: bool, ops: &[Op]) {
    for (i, op) in ops.iter().enumerate() {
        let name = format!("{} -> {}", op.describe(), outcome(&op.predict(m)));
        ctx.step(&name, |c| {
            exec(c, aid, roll_key, m, op, i as u8)?;
            verify(c, aid, m, full)
        });
    }
}

fn init(rel: u8, wide: bool) -> Op {
    Op::Init { rel, wide }
}
fn change(rel: u8, key: u8, ev2: bool) -> Op {
    Op::Change { rel, key, ev2 }
}
fn finalize(rel: u8, version: u8) -> Op {
    Op::Finalize { rel, version }
}
fn roll(rel: u8) -> Op {
    Op::Roll { rel }
}

// ------------------------------------------------------------------ the main application: 3 sets, 3 keys, AES-128 and AES-256
fn main_application(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let before = ctx.step_picc("FreeMem before the key set application", |c| Ok(c.free_mem()?));
    // 3 keys per set, 3 key sets with room for 32-byte keys, key 2 is the roll key
    ctx.app_scope(ks_spec(aid, 3, 3, 0x20, 0x02, 0x0F), |ctx, aid| {
        let dv = ctx.app_default_key_version;
        let mut m = KsModel::new(3, 3, AKS_VERSION, dv, true);
        ctx.step("memory: 3 key sets x ceil((21 + 3 x (32 + 4)) / 32) blocks + 1 overhead block", |c| {
            c.ensure_picc()?;
            let now = c.free_mem()?;
            let before = before.ok_or_else(|| StepError::skip("no FreeMem reading"))?;
            ensure_eq(bytes_taken(before, now)?, app_blocks(3, 3, 32) * 32, "bytes consumed")
        });
        ctx.step("GetKeySettings reports AES-128, 3 keys and the key set parameters (AKSVersion 5, 3 sets, MaxKeySize 0x20, roll key 2)", |c| {
            enter(c, aid, 0)?;
            let k = c.get_key_settings()?;
            c.detail(format!("{k:?}"));
            ensure_eq((k.settings, k.max_keys, k.key_type), (0x0F, 3, 2), "settings / key count / key type")?;
            ensure_eq(
                k.key_sets,
                Some(KeySetInfo { aks_version: AKS_VERSION, key_sets: 3, max_key_size: 0x20, key_set_settings: 0x02 }),
                "key set parameters",
            )
        });
        ctx.step("GetKeyVersion with a key set number: every key of every key set has the default version", |c| {
            enter(c, aid, 0)?;
            for ks in 0..3u8 {
                for k in 0..3u8 {
                    ensure_eq(c.get_key_version(k, Some(ks))?, vec![dv], &format!("key {k} of key set {ks}"))?;
                }
            }
            Ok(())
        });
        ctx.step("key set versions: the active key set has the creation version, the others 0 (GetKeyVersion, key set retrieval)", |c| {
            enter(c, aid, 0)?;
            ensure_eq(c.get_key_set_versions()?, vec![AKS_VERSION, 0, 0], "key set versions")
        });
        ctx.step("key 3 does not exist (NO_SUCH_KEY); key set 3 does not exist either (refused)", |c| {
            enter(c, aid, 0)?;
            let r = c.get_key_version(3, None);
            c.expect_err(Status::NoSuchKey, r)?;
            enter(c, aid, 0)?;
            let r = c.get_key_version(0, Some(3));
            let s = c.expect_any_status(r)?;
            c.detail(format!("a key set that does not exist: {s} (0x{:02X})", s.code()));
            Ok(())
        });
        let ops = [
            // keys of the active key set change with ChangeKey and ChangeKeyEV2 (key set 0), also the roll key and the master key
            change(0, 1, false),
            change(0, 2, true),
            change(0, 0, false),
            change(0, 0, true),
            // personalisation of key set 1
            init(1, false),
            init(0, false),
            init(3, false),
            change(1, 0, true),
            change(1, 1, true),
            change(1, 2, true),
            change(3, 0, true),
            change(1, 7, true),
            finalize(1, 7),
            finalize(1, 8),
            finalize(0, 3),
            finalize(3, 4),
            finalize(2, 0),
            // a finalized key set can still be changed (not recommended)
            change(1, 2, true),
            // rolling
            Op::RollAs { rel: 1, key: 0 },
            Op::RollAs { rel: 1, key: 1 },
            roll(2),
            roll(3),
            roll(0),
            roll(1),
            // after the roll the old active key set has number 2 and an older version
            roll(2),
            roll(1),
            // a second roll: numbering moves again
            init(1, false),
            change(1, 0, true),
            change(1, 1, true),
            change(1, 2, true),
            finalize(1, 9),
            roll(1),
            // AES-256 key set: stronger key type is allowed
            init(1, true),
            change(1, 0, true),
            change(1, 1, true),
            change(1, 2, true),
            finalize(1, 11),
            roll(1),
            // the active key set is AES-256 now: its keys are 32 bytes
            change(0, 1, false),
            change(0, 2, true),
            // a weaker key type is refused
            init(1, false),
            finalize(1, 13),
            roll(1),
            // and another AES-256 key set can follow
            init(2, true),
            finalize(2, 15),
            roll(2),
        ];
        script(ctx, aid, 2, &mut m, true, &ops);
        ctx.step("final state: key set versions and a ChangeKey in the rolled application", |c| {
            verify(c, aid, &m, true)?;
            c.detail(format!("key set versions {:?}", m.versions()));
            Ok(())
        });
    });
}

// ------------------------------------------------------------------ AES-128 only
fn narrow_application(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    // 2 keys, 3 key sets, MaxKeySize 0x10 (AES-128 only), roll key 0
    ctx.app_scope(ks_spec(aid, 2, 3, 0x10, 0x00, 0x0F), |ctx, aid| {
        let mut m = KsModel::new(3, 2, AKS_VERSION, ctx.app_default_key_version, false);
        ctx.step("MaxKeySize 0x10: GetKeySettings reports it", |c| {
            enter(c, aid, 0)?;
            let k = c.get_key_settings()?;
            ensure_eq(
                k.key_sets,
                Some(KeySetInfo { aks_version: AKS_VERSION, key_sets: 3, max_key_size: 0x10, key_set_settings: 0x00 }),
                "key set parameters",
            )
        });
        let ops = [
            init(1, true),
            // a key set that was never initialised can be finalised directly: it holds the default keys
            finalize(1, 4),
            finalize(1, 200),
            roll(1),
            finalize(2, 9),
            change(2, 0, true),
            change(2, 1, true),
            roll(2),
            // now the former active key set has number 2 with version 5; the finalised one with version 4 has number 1
            roll(1),
            roll(2),
            init(1, false),
            finalize(1, 10),
            roll(1),
        ];
        script(ctx, aid, 0, &mut m, true, &ops);
    });
}

// ------------------------------------------------------------------ 16 key sets
fn sixteen_sets(ctx: &mut Ctx) {
    let enough = ctx.step_picc("free memory for 16 key sets (33 blocks)", |c| need_memory(c, app_blocks(1, 16, 16) * 32 + 64));
    if enough.is_none() {
        return;
    }
    let aid = ctx.alloc_aid();
    ctx.app_scope(ks_spec(aid, 1, 16, 0x10, 0x00, 0x0F), |ctx, aid| {
        ctx.step("16 key sets: GetKeySettings and the 16 key set versions", |c| {
            enter(c, aid, 0)?;
            let k = c.get_key_settings()?;
            let info = k.key_sets.ok_or("no key set fields")?;
            ensure_eq((info.key_sets, info.aks_version), (16, AKS_VERSION), "number of key sets / AKSVersion")?;
            let mut want = vec![0u8; 16];
            want[0] = AKS_VERSION;
            ensure_eq(c.get_key_set_versions()?, want, "key set versions")
        });
        let mut m = KsModel::new(16, 1, AKS_VERSION, ctx.app_default_key_version, false);
        let mut ops: Vec<Op> = (1..16u8).map(|i| finalize(i, 10 + i)).collect();
        ops.push(finalize(14, 99)); // already finalised
        ops.push(roll(1)); // version 11 is above 5
        ops.push(roll(15)); // the highest version
        ops.push(roll(1)); // the old active key set (version 5) is far below now
        for (i, op) in ops.iter().enumerate() {
            let name = format!("{} -> {}", op.describe(), outcome(&op.predict(&m)));
            ctx.step(&name, |c| {
                exec(c, aid, 0, &mut m, op, i as u8)?;
                verify(c, aid, &m, false)
            });
        }
        ctx.step("after rolling through the 16 key sets the numbering is relative to the new active key set", |c| {
            verify(c, aid, &m, true)?;
            c.detail(format!("versions {:?}", m.versions()));
            Ok(())
        });
    });
}

// ------------------------------------------------------------------ change key rights and key sets
fn rights_variants(ctx: &mut Ctx) {
    // AppKeySettings bits 7..4 = 0xE: the key itself changes itself (also in other key sets); Initialize / Finalize need the master key
    let aid = ctx.alloc_aid();
    ctx.app_scope(ks_spec(aid, 4, 2, 0x10, 0x01, 0xEF), |ctx, aid| {
        ctx.step("change key = E: InitializeKeySet needs the master key (key 1: AUTHENTICATION_ERROR, master: ok)", |c| {
            enter(c, aid, 1)?;
            let r = c.initialize_key_set(1, 2);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 0)?;
            c.initialize_key_set(1, 2)?;
            Ok(())
        });
        ctx.step("change key = E: ChangeKeyEV2 of key 2 in key set 1 needs the same key of the active key set", |c| {
            let z = c.zero_key;
            let new = [0x31u8; 16];
            for who in [0u8, 3] {
                enter(c, aid, who)?;
                let r = c.change_key(&ChangeKeySpec::new(2, &new, 9).old_key(&z).key_set(1));
                c.expect_err(Status::AuthenticationError, r)?;
            }
            enter(c, aid, 2)?;
            c.change_key(&ChangeKeySpec::new(2, &new, 9).old_key(&z).key_set(1))?;
            ensure(c.is_authenticated(), "changing a key of another key set keeps the session")?;
            ensure_eq(c.get_key_version(2, Some(1))?, vec![9], "version of key 2 in key set 1")?;
            ensure_eq(c.get_key_version(2, None)?, vec![c.app_default_key_version], "key 2 of the active key set is untouched")
        });
        ctx.step("change key = E: FinalizeKeySet needs the master key too", |c| {
            enter(c, aid, 2)?;
            let r = c.finalize_key_set(1, 6);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 0)?;
            c.finalize_key_set(1, 6)?;
            ensure_eq(c.get_key_set_versions()?, vec![AKS_VERSION, 6], "key set versions")
        });
        ctx.step("change key = E: RollKeySet needs the roll key (key 1): the master key is refused, key 1 rolls", |c| {
            enter(c, aid, 0)?;
            let r = c.roll_key_set(1);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 1)?;
            c.roll_key_set(1)?;
            ensure_eq(c.is_authenticated(), false, "session after RollKeySet")?;
            let z = c.zero_key;
            c.select_application(aid, None)?;
            let r = c.authenticate_ev2_first(2, &z, &[]);
            c.expect_err(Status::AuthenticationError, r)?;
            c.auth_app(aid, 2, &[0x31u8; 16])
        });
    });
    // AppKeySettings bits 7..4 = 1: key 1 is the change key
    let aid = ctx.alloc_aid();
    ctx.app_scope(ks_spec(aid, 4, 2, 0x10, 0x00, 0x1F), |ctx, aid| {
        ctx.step("change key = 1: InitializeKeySet and FinalizeKeySet need key 1; the master key is refused", |c| {
            enter(c, aid, 0)?;
            let r = c.initialize_key_set(1, 2);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 1)?;
            c.initialize_key_set(1, 2)?;
            enter(c, aid, 0)?;
            let r = c.finalize_key_set(1, 6);
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 1)?;
            c.finalize_key_set(1, 6)?;
            ensure_eq(c.get_key_set_versions()?, vec![AKS_VERSION, 6], "key set versions")
        });
        ctx.step("change key = 1: ChangeKeyEV2 of key 2 in key set 1 with key 1, refused with the master key", |c| {
            let z = c.zero_key;
            let new = [0x44u8; 16];
            enter(c, aid, 0)?;
            let r = c.change_key(&ChangeKeySpec::new(2, &new, 3).old_key(&z).key_set(1));
            c.expect_err(Status::AuthenticationError, r)?;
            enter(c, aid, 1)?;
            c.change_key(&ChangeKeySpec::new(2, &new, 3).old_key(&z).key_set(1))?;
            ensure_eq(c.get_key_version(2, Some(1))?, vec![3], "version of key 2 in key set 1")
        });
    });
    // AppKeySettings bits 7..4 = 0xF: no key but the master key changes, key set commands are refused
    let aid = ctx.alloc_aid();
    ctx.app_scope(ks_spec(aid, 4, 2, 0x10, 0x00, 0xFF), |ctx, aid| {
        ctx.step("change key = F: InitializeKeySet, FinalizeKeySet and ChangeKeyEV2 of key set 1 are refused (PERMISSION_DENIED)", |c| {
            let z = c.zero_key;
            enter(c, aid, 0)?;
            let r = c.initialize_key_set(1, 2);
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            let r = c.finalize_key_set(1, 6);
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            let r = c.change_key(&ChangeKeySpec::new(2, &[1; 16], 1).old_key(&z).key_set(1));
            c.expect_err(Status::PermissionDenied, r)?;
            enter(c, aid, 0)?;
            ensure_eq(c.get_key_set_versions()?, vec![AKS_VERSION, 0], "key set versions are unchanged")
        });
    });
}

// ------------------------------------------------------------------ no key sets, creation errors
fn single_set_and_creation_errors(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(2), |ctx, aid| {
        ctx.step("an application with one key set: key set version retrieval is refused (PERMISSION_DENIED)", |c| {
            enter(c, aid, 0)?;
            let r = c.get_key_set_versions();
            let st = c.expect_any_status(r)?;
            ensure(matches!(st, Status::PermissionDenied | Status::NoSuchKey), format!("unexpected status {st}"))?;
            enter(c, aid, 0)?;
            let r = c.get_key_version(0, Some(1));
            let st = c.expect_any_status(r)?;
            ensure(matches!(st, Status::PermissionDenied | Status::NoSuchKey), format!("unexpected status {st}"))
        });
        ctx.step("an application with one key set: key set 1 does not exist (NO_SUCH_KEY for Initialize, Finalize, Roll)", |c| {
            enter(c, aid, 0)?;
            let r = c.initialize_key_set(1, 2);
            c.expect_err(Status::NoSuchKey, r)?;
            enter(c, aid, 0)?;
            let r = c.finalize_key_set(1, 3);
            c.expect_err(Status::NoSuchKey, r)?;
            enter(c, aid, 0)?;
            let r = c.roll_key_set(1);
            c.expect_err(Status::NoSuchKey, r)
        });
        ctx.step("an application with one key set: GetKeySettings has no key set fields", |c| {
            enter(c, aid, 0)?;
            ensure(c.get_key_settings()?.key_sets.is_none(), "key set fields reported")
        });
    });
    ctx.step("CreateApplication with key sets: refused combinations (zero keys; 1 or 17 key sets; AES-256 type in an AES-128 only set)", |c| {
        let cfg = |sets: u8, max: u8| KeySetConfig { aks_version: 1, no_key_sets: sets, max_key_size: max, app_key_set_settings: 0 };
        let cases: Vec<(&str, AppSpec, Option<Status>)> = vec![
            ("0 keys with key sets", AppSpec::new(c.alloc_aid()).keys(0).key_sett3(1).key_sets(cfg(2, 0x10)), Some(Status::ParameterError)),
            ("1 key set", AppSpec::new(c.alloc_aid()).keys(1).key_sett3(1).key_sets(cfg(1, 0x10)), None),
            ("17 key sets", AppSpec::new(c.alloc_aid()).keys(1).key_sett3(1).key_sets(cfg(17, 0x10)), None),
            ("AES-256 type, MaxKeySize 0x10", AppSpec::new(c.alloc_aid()).keys(1).aes256().key_sett3(1).key_sets(cfg(2, 0x10)), None),
        ];
        for (what, spec, want) in cases {
            let (r, id) = attempt_create(c, &spec);
            let verdict = match want {
                Some(s) => c.expect_err(s, r),
                None => c.expect_any_status(r).map(|st| c.detail(format!("{what}: {st} (0x{:02X})", st.code()))),
            };
            c.run_cleanup_now(id);
            verdict.map_err(|e| match e {
                StepError::Skip(_) => e,
                e => StepError::fail(format!("{what}: {e}")),
            })?;
        }
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> KsModel {
        KsModel::new(3, 2, 5, 0, true)
    }

    #[test]
    fn spec_sets_the_key_set_flag_and_block() {
        let s = ks_spec(Aid(0xD00001), 3, 3, 0x20, 0x02, 0x0F);
        assert_eq!(s.key_sett3, Some(0x01), "KeySett3 bit 0 enables the key set block");
        assert_eq!(s.extra, vec![AKS_VERSION, 3, 0x20, 0x02]);
        assert_eq!((s.n_keys, s.key_sett1), (3, 0x0F));
    }

    #[test]
    fn memory_formula() {
        // 3 sets x ceil((21 + 3 x 36) / 32) = 3 x 5, plus one overhead block
        assert_eq!(app_blocks(3, 3, 32), 16);
        // 16 sets of one AES-128 key: 16 x ceil(41 / 32) = 32, plus one
        assert_eq!(app_blocks(1, 16, 16), 33);
        assert_eq!(app_blocks(0, 1, 16), 1);
    }

    #[test]
    fn numbering_is_relative_to_the_active_key_set() {
        let mut m = model();
        assert_eq!(m.versions(), vec![5, 0, 0]);
        m.init(1, false).unwrap();
        m.finalize(1, 7).unwrap();
        assert_eq!(m.versions(), vec![5, 7, 0]);
        m.roll(1).unwrap();
        // the old active key set (version 5) is now number 2, the untouched one number 1
        assert_eq!(m.versions(), vec![7, 0, 5]);
        assert_eq!(m.roll(2), Err(Refuse::Exact(Status::PermissionDenied)), "version 5 is below 7");
        assert_eq!(m.roll(1), Err(Refuse::Exact(Status::PermissionDenied)), "version 0 is below 7");
        m.init(1, false).unwrap();
        m.finalize(1, 9).unwrap();
        m.roll(1).unwrap();
        assert_eq!(m.versions(), vec![9, 5, 7]);
    }

    #[test]
    fn refusals_follow_the_data_sheet() {
        let mut m = model();
        assert_eq!(m.init(0, false), Err(Refuse::Any));
        assert_eq!(m.init(3, false), Err(Refuse::Exact(Status::NoSuchKey)));
        assert_eq!(m.finalize(3, 4), Err(Refuse::Exact(Status::NoSuchKey)));
        assert_eq!(m.finalize(0, 4), Err(Refuse::Any));
        assert_eq!(m.finalize(1, 0), Err(Refuse::Any));
        m.finalize(1, 4).unwrap();
        assert_eq!(m.finalize(1, 8), Err(Refuse::Exact(Status::PermissionDenied)), "only version 0 can be finalised");
        assert_eq!(m.roll(0), Err(Refuse::Any));
        assert_eq!(m.roll(3), Err(Refuse::Exact(Status::NoSuchKey)));
        assert_eq!(m.roll(1), Err(Refuse::Exact(Status::PermissionDenied)), "4 is not above 5");
        assert_eq!(m.change(3, 0, vec![0; 16], 1), Err(Refuse::Exact(Status::NoSuchKey)));
        assert_eq!(m.change(1, 2, vec![0; 16], 1), Err(Refuse::Exact(Status::NoSuchKey)), "only 2 keys");
        assert_eq!(m.change(1, 0, vec![0; 32], 1), Err(Refuse::Any), "wrong key length");
        let mut narrow = KsModel::new(2, 1, 1, 0, false);
        assert_eq!(narrow.init(1, true), Err(Refuse::Exact(Status::PermissionDenied)), "MaxKeySize 0x10");
    }

    #[test]
    fn initialize_copies_padded_or_truncated_keys_and_versions() {
        let mut m = model();
        m.change(0, 0, vec![7; 16], 0x21).unwrap();
        m.init(1, true).unwrap();
        let s = m.set(1);
        assert!(s.wide);
        assert_eq!(s.keys[0], [vec![7u8; 16], vec![0u8; 16]].concat(), "AES-128 key padded with 16 zero bytes");
        assert_eq!(s.vers[0], 0x21);
        assert_eq!(s.version, 0);
        // AES-256 keys in set 1: only wide values fit
        assert!(m.change(1, 1, vec![1; 32], 2).is_ok());
        assert_eq!(m.change(1, 1, vec![1; 16], 2), Err(Refuse::Any));
        m.finalize(1, 6).unwrap();
        m.roll(1).unwrap();
        assert!(m.set(0).wide);
        // truncating: initialising a narrow set from a wide active key set keeps the first 16 bytes
        m.init(1, false).unwrap();
        assert_eq!(m.set(1).keys[1], vec![1u8; 16]);
        // a weaker key type cannot be rolled to
        m.finalize(1, 20).unwrap();
        assert_eq!(m.roll(1), Err(Refuse::Exact(Status::PermissionDenied)));
    }

    #[test]
    fn sixteen_sets_rotate() {
        let mut m = KsModel::new(16, 1, 5, 0, false);
        for i in 1..16u8 {
            m.finalize(i as usize, 10 + i).unwrap();
        }
        m.roll(15).unwrap();
        let v = m.versions();
        assert_eq!(v[0], 25);
        assert_eq!(v[1], 5, "the old active key set follows the new one");
        assert_eq!(v[2], 11);
        assert_eq!(v[15], 24);
        assert_eq!(m.abs(0), 15);
    }

    #[test]
    fn operation_descriptions_and_predictions() {
        let m = model();
        assert_eq!(roll(1).predict(&m), Err(Refuse::Exact(Status::PermissionDenied)));
        assert_eq!(init(1, false).predict(&m), Ok(()));
        assert_eq!(change(1, 0, true).describe(), "ChangeKeyEV2(key set 1, key 0)");
        assert_eq!(change(0, 1, false).describe(), "ChangeKey(key set 0, key 1)");
        assert_eq!(Op::RollAs { rel: 1, key: 0 }.predict(&m), Err(Refuse::Exact(Status::AuthenticationError)));
        assert_eq!(outcome(&Ok(())), "accepted");
        assert!(outcome(&Err(Refuse::Exact(Status::NoSuchKey))).contains("NO_SUCH_KEY"));
    }
}
