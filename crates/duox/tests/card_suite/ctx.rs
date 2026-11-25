//! The framework core: [`Ctx`], step recording, the cleanup stack and the guarded card helpers.
//!
//! See `README.md` in this directory for the section author's guide. In short:
//!
//! * `ctx.step("name", |c| { ...; Ok(()) })` runs one check, records pass / fail / skip with timing
//!   and never aborts the run. Return `Err(StepError::skip("reason"))` to record a skip. Panics
//!   (`assert!`) are caught and recorded as failures.
//! * `Ctx` derefs to the connected [`SuiteCard`], so `c.get_version()?` works inside a step.
//!   The card-modifying commands (`format`, `set_configuration`, `change_key`, `change_key_settings`,
//!   `manage_key_pair`, `manage_ca_root_key`, `create_application`, `delete_application`, `native_raw`,
//!   `apdu_raw`) are methods of `Ctx` itself and shadow the card's: they pass the [`Guard`] first and
//!   refuse in DRY mode. Use them, never `c.card.<same name>` directly.
//! * `ctx.app_scope(spec, |c, aid| ...)` creates a throwaway application and always deletes it.
//! * `ctx.push_cleanup(...)` registers a restore action. Every action runs LIFO at the end of the
//!   run, also after a panic or abort, and must tolerate being run in any card state.

use crate::guard::{is_suite_aid, Guard, Level, Op, Violation, SUITE_AID_FIRST, SUITE_AID_LAST};
use crate::keychange::Recovery;
use crate::snapshot::Snapshot;
use crate::wire::GuardedTransport;
use duox::card::{
    Aid, AppSpec, AuthKind, CaRootKeySpec, Card, ChangeKeySpec, CommMode, KeyPairOp, KeyPairSpec, Status,
};
use duox::pki::PkiStore;
use duox::transport::PcscTransport;
use std::fmt;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The card type of the suite: a PC/SC reader behind the wire tripwire.
pub type SuiteCard = Card<GuardedTransport<PcscTransport>>;

// ------------------------------------------------------------------ configuration
/// Run configuration, from the environment (see README).
#[derive(Debug, Clone)]
pub struct Config {
    /// DUOX_READER: substring of the reader name (default "OMNIKEY").
    pub reader: String,
    /// DUOX_SUITE_CONFIRM: must equal the card's UID (hex) for anything destructive.
    pub confirm: Option<String>,
    /// DUOX_SUITE_DRY=1: preflight, snapshot, plan; no writes.
    pub dry: bool,
    /// DUOX_SUITE_ONLY: section names to run (None = all).
    pub only: Option<Vec<String>>,
    /// DUOX_SUITE_ALLOW_WIPE=1: accept a card that already contains applications (they are formatted away).
    pub allow_wipe: bool,
    /// DUOX_SUITE_ALLOW_GPIO=1: lift the guard's GPIO restriction (option 0x11 at PICC level).
    pub allow_gpio: bool,
    /// DUOX_SUITE_TRACE=1: print every APDU.
    pub trace: bool,
}

impl Config {
    pub fn from_env() -> Config {
        let flag = |n: &str| std::env::var(n).map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
        let only = std::env::var("DUOX_SUITE_ONLY").ok().filter(|s| !s.trim().is_empty()).map(|s| {
            s.split([',', ' ', ';']).filter(|p| !p.is_empty()).map(|p| p.to_lowercase()).collect::<Vec<_>>()
        });
        Config {
            reader: std::env::var("DUOX_READER").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "OMNIKEY".into()),
            confirm: std::env::var("DUOX_SUITE_CONFIRM")
                .ok()
                .map(|s| s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase())
                .filter(|s| !s.is_empty()),
            dry: flag("DUOX_SUITE_DRY"),
            only,
            allow_wipe: flag("DUOX_SUITE_ALLOW_WIPE"),
            allow_gpio: flag("DUOX_SUITE_ALLOW_GPIO"),
            trace: flag("DUOX_SUITE_TRACE"),
        }
    }
}

// ------------------------------------------------------------------ errors and results
/// Why a step did not pass.
#[derive(Debug)]
pub enum StepError {
    /// The library returned an error.
    Card(duox::Error),
    /// The guard refused the operation (nothing was sent).
    Guard(Violation),
    /// A check failed.
    Fail(String),
    /// Not a failure: the step could not be exercised. Recorded as skipped.
    Skip(String),
}

pub type StepResult<T = ()> = Result<T, StepError>;

impl StepError {
    pub fn skip(reason: impl Into<String>) -> Self {
        StepError::Skip(reason.into())
    }
    pub fn fail(msg: impl Into<String>) -> Self {
        StepError::Fail(msg.into())
    }
    /// The native status if the card refused a command.
    pub fn status(&self) -> Option<Status> {
        match self {
            StepError::Card(e) => e.status(),
            _ => None,
        }
    }
    fn transport_problem(&self) -> bool {
        matches!(self, StepError::Card(duox::Error::Transport(_)))
    }
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StepError::Card(e) => write!(f, "{e}"),
            StepError::Guard(v) => write!(f, "{v}"),
            StepError::Fail(s) | StepError::Skip(s) => f.write_str(s),
        }
    }
}

impl From<duox::Error> for StepError {
    fn from(e: duox::Error) -> Self {
        StepError::Card(e)
    }
}
impl From<Violation> for StepError {
    fn from(v: Violation) -> Self {
        StepError::Guard(v)
    }
}
impl From<String> for StepError {
    fn from(s: String) -> Self {
        StepError::Fail(s)
    }
}
impl From<&str> for StepError {
    fn from(s: &str) -> Self {
        StepError::Fail(s.into())
    }
}
impl From<std::io::Error> for StepError {
    fn from(e: std::io::Error) -> Self {
        StepError::Fail(format!("io: {e}"))
    }
}
impl From<duox::pki::PkiError> for StepError {
    fn from(e: duox::pki::PkiError) -> Self {
        StepError::Fail(format!("pki: {e}"))
    }
}
impl From<hex::FromHexError> for StepError {
    fn from(e: hex::FromHexError) -> Self {
        StepError::Fail(format!("hex: {e}"))
    }
}

/// `Err(Fail(msg))` unless `cond`.
pub fn ensure(cond: bool, msg: impl Into<String>) -> StepResult<()> {
    if cond {
        Ok(())
    } else {
        Err(StepError::Fail(msg.into()))
    }
}

/// `Err(Fail)` unless the two values are equal.
pub fn ensure_eq<T: PartialEq + fmt::Debug>(got: T, want: T, what: &str) -> StepResult<()> {
    if got == want {
        Ok(())
    } else {
        Err(StepError::Fail(format!("{what}: got {got:?}, expected {want:?}")))
    }
}

// ------------------------------------------------------------------ records
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(String),
    Skip(String),
}

#[derive(Debug, Clone)]
pub struct StepRecord {
    pub section: String,
    pub name: String,
    pub outcome: Outcome,
    pub millis: u128,
    pub details: Vec<String>,
}

/// Handle of a registered cleanup action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupId(pub u64);

type CleanupFn = Box<dyn FnOnce(&mut Ctx) -> StepResult>;

pub(crate) struct CleanupEntry {
    id: CleanupId,
    name: String,
    f: CleanupFn,
}

/// Allocator of file numbers inside one application (0..=0x1F).
#[derive(Debug, Default)]
pub struct FileNos(u8);

impl FileNos {
    /// Next unused file number; panics after 32 (a test application cannot hold more).
    pub fn next(&mut self) -> u8 {
        assert!(self.0 < 0x20, "out of file numbers");
        self.0 += 1;
        self.0 - 1
    }
}

// ------------------------------------------------------------------ Ctx
pub struct Ctx {
    /// The connected card (also reachable through `Deref`).
    pub card: SuiteCard,
    /// The factory AES-128 key (16 zero bytes).
    pub zero_key: [u8; 16],
    /// 32 zero bytes (default AES-256 key).
    pub zero_key32: [u8; 32],
    /// The PICC master key currently in force (all zero unless a key change is in progress).
    pub picc_key: Vec<u8>,
    /// Throwaway PKI store (a temp dir, deleted at the end).
    pub store: PkiStore,
    pub store_dir: PathBuf,
    /// UID of the card.
    pub uid: Vec<u8>,
    pub guard: Guard,
    pub cfg: Config,
    /// DRY mode: no card-modifying helper does anything.
    pub dry: bool,
    /// State of the card at the start (after the preflight Format); set by the runner.
    pub initial: Option<Snapshot>,
    /// Key version of newly created application keys, measured in the preflight (the version the
    /// PICCAppDefaultKey round trip restores).
    pub app_default_key_version: u8,
    /// Where `card-suite-recovery.txt` lives.
    pub target_dir: PathBuf,
    pub(crate) recovery: Recovery,
    pub(crate) restore_ids: Vec<(u64, CleanupId)>,
    pub(crate) records: Vec<StepRecord>,
    pub(crate) section: String,
    details: Vec<String>,
    pub(crate) cleanup: Vec<CleanupEntry>,
    pub(crate) cleanup_failures: Vec<String>,
    next_aid: u32,
    next_id: u64,
    /// The card stopped answering and could not be reconnected; remaining steps are skipped.
    pub dead: bool,
}

impl std::ops::Deref for Ctx {
    type Target = SuiteCard;
    fn deref(&self) -> &SuiteCard {
        &self.card
    }
}
impl std::ops::DerefMut for Ctx {
    fn deref_mut(&mut self) -> &mut SuiteCard {
        &mut self.card
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if !self.cleanup.is_empty() {
            eprintln!("\n!! the suite is ending with {} restore actions pending: running them now", self.cleanup.len());
            self.run_cleanup();
        }
        let _ = std::fs::remove_dir_all(&self.store_dir);
    }
}

impl Ctx {
    pub fn new(card: SuiteCard, cfg: Config, uid: Vec<u8>, target_dir: PathBuf) -> Result<Ctx, String> {
        let store_dir = std::env::temp_dir().join(format!("duox-card-suite-{}", std::process::id()));
        std::fs::create_dir_all(&store_dir).map_err(|e| format!("temp dir: {e}"))?;
        let store = PkiStore::open(store_dir.join("store.json"), None).map_err(|e| format!("pki store: {e}"))?;
        Ok(Ctx {
            card,
            zero_key: [0; 16],
            zero_key32: [0; 32],
            picc_key: vec![0; 16],
            store,
            store_dir,
            uid,
            guard: Guard::new(cfg.allow_gpio),
            dry: cfg.dry,
            cfg,
            initial: None,
            app_default_key_version: 0,
            recovery: Recovery::new(target_dir.join("card-suite-recovery.txt")),
            target_dir,
            restore_ids: vec![],
            records: vec![],
            section: "-".into(),
            details: vec![],
            cleanup: vec![],
            cleanup_failures: vec![],
            next_aid: SUITE_AID_FIRST,
            next_id: 1,
            dead: false,
        })
    }

    // -------------------------------------------------------------- recording
    /// Run one check. Never aborts the run: errors and panics are recorded as failures.
    /// Returns the value on success.
    pub fn step<T>(&mut self, name: &str, f: impl FnOnce(&mut Ctx) -> StepResult<T>) -> Option<T> {
        if self.dead {
            self.record(name, Outcome::Skip("card unreachable after an earlier failure".into()), 0);
            return None;
        }
        self.details.clear();
        let t0 = Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| f(self)));
        let ms = t0.elapsed().as_millis();
        let (outcome, value, needs_probe) = match r {
            Ok(Ok(v)) => (Outcome::Pass, Some(v), false),
            Ok(Err(StepError::Skip(s))) => (Outcome::Skip(s), None, false),
            Ok(Err(e)) => {
                let probe = e.transport_problem();
                (Outcome::Fail(e.to_string()), None, probe)
            }
            Err(p) => (Outcome::Fail(format!("panic: {}", panic_text(&*p))), None, true),
        };
        self.record(name, outcome, ms);
        if needs_probe && !self.revive() {
            self.dead = true;
            println!("  !! the card does not answer any more; the remaining steps are skipped");
        }
        value
    }

    /// Like [`Ctx::step`], but first makes sure the PICC is selected and authenticated with the PICC master key.
    pub fn step_picc<T>(&mut self, name: &str, f: impl FnOnce(&mut Ctx) -> StepResult<T>) -> Option<T> {
        self.step(name, |c| {
            c.ensure_picc()?;
            f(c)
        })
    }

    /// Record a skipped step (something that cannot or must not be exercised, with the reason).
    pub fn skip(&mut self, name: &str, reason: &str) {
        self.details.clear();
        self.record(name, Outcome::Skip(reason.into()), 0);
    }

    /// Attach an informational line to the running step (printed under its result line).
    pub fn detail(&mut self, text: impl Into<String>) {
        self.details.push(text.into());
    }

    fn record(&mut self, name: &str, outcome: Outcome, millis: u128) {
        let tag = match &outcome {
            Outcome::Pass => "PASS",
            Outcome::Fail(_) => "FAIL",
            Outcome::Skip(_) => "SKIP",
        };
        let extra = match &outcome {
            Outcome::Pass => String::new(),
            Outcome::Fail(m) => format!(" - {m}"),
            Outcome::Skip(m) => format!(" - {m}"),
        };
        println!("  [{tag}] {name} ({millis} ms){extra}");
        let details = std::mem::take(&mut self.details);
        for d in &details {
            for line in d.lines() {
                println!("         {line}");
            }
        }
        self.records.push(StepRecord { section: self.section.clone(), name: name.into(), outcome, millis, details });
    }

    pub fn records(&self) -> &[StepRecord] {
        &self.records
    }

    pub fn failures(&self) -> usize {
        self.records.iter().filter(|r| matches!(r.outcome, Outcome::Fail(_))).count()
    }

    /// Probe the card; reconnect (power cycle) up to three times if it does not answer.
    pub fn revive(&mut self) -> bool {
        if self.card.get_version().is_ok() {
            return true;
        }
        for _ in 0..3 {
            println!("  .. card does not answer, reconnecting");
            std::thread::sleep(Duration::from_millis(400));
            if self.card.connect().is_ok() && self.card.get_version().is_ok() {
                return true;
            }
        }
        false
    }

    // -------------------------------------------------------------- allocators
    /// Next unused AID of the reserved range.
    pub fn alloc_aid(&mut self) -> Aid {
        assert!(self.next_aid <= SUITE_AID_LAST, "out of suite AIDs");
        self.next_aid += 1;
        Aid(self.next_aid - 1)
    }

    /// A fresh file number allocator for a new application.
    pub fn file_nos(&self) -> FileNos {
        FileNos::default()
    }

    // -------------------------------------------------------------- cleanup stack
    /// Register a restore action. It runs LIFO at the end of the run (or earlier through
    /// [`Ctx::run_cleanup_now`]), also after a panic. It must be safe to run in any card state:
    /// authenticate first, tolerate "already restored".
    pub fn push_cleanup(&mut self, name: &str, f: impl FnOnce(&mut Ctx) -> StepResult + 'static) -> CleanupId {
        let id = CleanupId(self.next_id);
        self.next_id += 1;
        self.cleanup.push(CleanupEntry { id, name: name.into(), f: Box::new(f) });
        id
    }

    /// Run one registered action now and remove it. Returns false if it failed (a failure is also
    /// remembered for the final report). Unknown ids (already run) return true.
    pub fn run_cleanup_now(&mut self, id: CleanupId) -> bool {
        match self.cleanup.iter().position(|e| e.id == id) {
            Some(i) => {
                let e = self.cleanup.remove(i);
                self.run_entry(e)
            }
            None => true,
        }
    }

    /// Forget an action (its work was done another way).
    pub fn cancel_cleanup(&mut self, id: CleanupId) {
        self.cleanup.retain(|e| e.id != id);
    }

    /// Run every pending action, newest first. Failures are collected, not fatal.
    pub fn run_cleanup(&mut self) {
        if self.cleanup.is_empty() {
            return;
        }
        if self.dry {
            println!("  [dry] {} restore action(s) discarded (nothing was changed)", self.cleanup.len());
            self.cleanup.clear();
            return;
        }
        println!("\n== cleanup ({} restore actions) ==", self.cleanup.len());
        if !self.revive() {
            self.cleanup_failures.push("card does not answer; restore actions will be attempted anyway".into());
        }
        while let Some(e) = self.cleanup.pop() {
            self.run_entry(e);
        }
    }

    fn run_entry(&mut self, e: CleanupEntry) -> bool {
        let name = e.name.clone();
        if self.dry {
            println!("  [dry] restore action not run (nothing was changed): {name}");
            return true;
        }
        match catch_unwind(AssertUnwindSafe(|| (e.f)(self))) {
            Ok(Ok(())) => {
                println!("  [RESTORED] {name}");
                true
            }
            Ok(Err(err)) => {
                println!("  [RESTORE FAILED] {name}: {err}");
                self.cleanup_failures.push(format!("{name}: {err}"));
                false
            }
            Err(p) => {
                println!("  [RESTORE FAILED] {name}: panic: {}", panic_text(&*p));
                self.cleanup_failures.push(format!("{name}: panic {}", panic_text(&*p)));
                false
            }
        }
    }

    // -------------------------------------------------------------- state helpers
    /// Level a command would act at, from the current selection.
    pub fn level(&self) -> Level {
        Guard::level_of(self.card.selection().primary)
    }

    /// Fresh PICC level session: select the PICC, authenticate key 0 with [`Ctx::picc_key`].
    pub fn auth_picc(&mut self) -> StepResult {
        self.card.select_application(Aid::PICC, None)?;
        self.card.authenticate_ev2_first(0, &self.picc_key, &[])?;
        Ok(())
    }

    /// Like [`Ctx::auth_picc`] but does nothing when already authenticated with key 0 at PICC level.
    pub fn ensure_picc(&mut self) -> StepResult {
        let sel = self.card.selection();
        let at_picc = sel.primary == Some(Aid::PICC) && sel.secondary.is_none();
        let key0 = matches!(self.card.auth_summary(), Some(a) if a.kind == AuthKind::Aes && a.key_no == Some(0));
        if at_picc && key0 {
            Ok(())
        } else {
            self.auth_picc()
        }
    }

    /// Fresh PICC level session with another PICC key (PICCDAM keys, VC keys) and an explicit key value.
    pub fn auth_picc_key(&mut self, key_no: u8, key: &[u8]) -> StepResult {
        self.card.select_application(Aid::PICC, None)?;
        self.card.authenticate_ev2_first(key_no, key, &[])?;
        Ok(())
    }

    /// Fresh session in an application: select it, authenticate `key_no` with `key` (16 or 32 bytes).
    pub fn auth_app(&mut self, aid: Aid, key_no: u8, key: &[u8]) -> StepResult {
        self.card.select_application(aid, None)?;
        self.card.authenticate_ev2_first(key_no, key, &[])?;
        Ok(())
    }

    // -------------------------------------------------------------- negative tests
    /// The result must be the library error for `status`, and the authentication must be gone.
    pub fn expect_err<T, E: Into<StepError>>(&self, status: Status, r: Result<T, E>) -> StepResult {
        let got = self.expect_any_status(r)?;
        ensure(got == status, format!("expected {status} (0x{:02X}), the card answered {got} (0x{:02X})", status.code(), got.code()))
    }

    /// The result must be some card status error (and end the authentication); returns the status.
    pub fn expect_any_status<T, E: Into<StepError>>(&self, r: Result<T, E>) -> StepResult<Status> {
        match r {
            Ok(_) => Err(StepError::fail("expected the card to refuse the command, but it succeeded")),
            Err(e) => {
                let e = e.into();
                if let StepError::Skip(_) = e {
                    return Err(e); // a dry-run refusal is a skip, not a card answer
                }
                let Some(s) = e.status() else {
                    return Err(StepError::fail(format!("expected a card status error, got: {e}")));
                };
                ensure(!self.card.is_authenticated(), "the authentication is still active after a refused command")?;
                Ok(s)
            }
        }
    }

    /// The result must be a guard refusal (nothing was sent).
    pub fn expect_violation<T, E: Into<StepError>>(&self, r: Result<T, E>) -> StepResult {
        match r.map_err(Into::<StepError>::into) {
            Err(StepError::Guard(_)) => Ok(()),
            Ok(_) => Err(StepError::fail("the guard let a forbidden operation through")),
            Err(e) => Err(StepError::fail(format!("expected a guard refusal, got: {e}"))),
        }
    }

    // -------------------------------------------------------------- guarded card helpers
    fn writable(&self, what: &str) -> StepResult {
        if self.dry {
            Err(StepError::Skip(format!("DRY run: would {what}")))
        } else {
            Ok(())
        }
    }

    /// SetConfiguration through the guard.
    pub fn set_configuration(&mut self, option: u8, data: &[u8]) -> StepResult {
        let level = self.level();
        self.guard.check(&Op::SetConfiguration { level, option, data })?;
        self.writable(&format!("SetConfiguration 0x{option:02X}"))?;
        Ok(self.card.set_configuration(option, data)?)
    }

    /// ChangeKeySettings through the guard (reads the current value first; needs an authentication).
    pub fn change_key_settings(&mut self, new: u8) -> StepResult {
        let level = self.level();
        let current = self.card.get_key_settings()?.settings;
        self.guard.check(&Op::ChangeKeySettings { level, current, new })?;
        self.writable(&format!("ChangeKeySettings {new:02X}"))?;
        Ok(self.card.change_key_settings(new)?)
    }

    /// ChangeKey / ChangeKeyEV2 inside a suite application. At PICC level use
    /// [`Ctx::change_picc_key`] (it proves the old key and writes the recovery file).
    pub fn change_key(&mut self, spec: &ChangeKeySpec) -> StepResult {
        let level = self.level();
        if level == Level::Picc {
            return Err(StepError::Guard(Violation(
                "PICC level keys are changed with ctx.change_picc_key (proof of the old key, recovery file, restore)".into(),
            )));
        }
        self.guard.check(&Op::ChangeKey { level, key_no: spec.key_no, key_set: spec.key_set })?;
        self.writable("ChangeKey")?;
        Ok(self.card.change_key(spec)?)
    }

    /// The PICC level ChangeKey used by [`Ctx::change_picc_key`] only; it has already done the proof and
    /// the recovery file work.
    pub(crate) fn change_key_unchecked_by_level(&mut self, spec: &ChangeKeySpec) -> StepResult {
        self.guard.check(&Op::ChangeKey { level: Level::Picc, key_no: spec.key_no, key_set: spec.key_set })?;
        self.writable("ChangeKey")?;
        Ok(self.card.change_key(spec)?)
    }

    pub fn manage_key_pair(&mut self, spec: &KeyPairSpec, op: &KeyPairOp, mode: Option<CommMode>) -> StepResult<Vec<u8>> {
        let level = self.level();
        self.guard.check(&Op::ManageKeyPair { level, policy: spec.policy, write_access: spec.write_access })?;
        self.writable("ManageKeyPair")?;
        Ok(self.card.manage_key_pair(spec, op, mode)?)
    }

    pub fn manage_ca_root_key(&mut self, spec: &CaRootKeySpec, mode: Option<CommMode>) -> StepResult {
        let level = self.level();
        self.guard.check(&Op::ManageCaRootKey { level })?;
        self.writable("ManageCARootKey")?;
        Ok(self.card.manage_ca_root_key(spec, mode)?)
    }

    /// CreateApplication; the AID must come from [`Ctx::alloc_aid`].
    pub fn create_application(&mut self, spec: &AppSpec) -> StepResult {
        self.guard.check(&Op::CreateApplication { aid: spec.aid })?;
        self.writable(&format!("create application {}", spec.aid))?;
        Ok(self.card.create_application(spec)?)
    }

    pub fn delete_application(&mut self, aid: Aid, dam_mac: &[u8]) -> StepResult {
        self.guard.check(&Op::DeleteApplication { aid })?;
        self.writable(&format!("delete application {aid}"))?;
        Ok(self.card.delete_application(aid, dam_mac)?)
    }

    /// Format the PICC (releases all applications and files).
    pub fn format(&mut self) -> StepResult {
        let level = self.level();
        self.guard.check(&Op::Format { level })?;
        self.writable("Format")?;
        Ok(self.card.format()?)
    }

    pub fn native_raw(&mut self, cmd_code: u8, payload: &[u8]) -> StepResult<(u8, Vec<Vec<u8>>)> {
        let level = self.level();
        self.guard.check(&Op::RawNative { level, cmd: cmd_code })?;
        Ok(self.card.native_raw(cmd_code, payload)?)
    }

    pub fn apdu_raw(&mut self, apdu: &[u8]) -> StepResult<(Vec<u8>, u16)> {
        let level = self.level();
        self.guard.check(&Op::RawApdu { level, apdu })?;
        Ok(self.card.apdu_raw(apdu)?)
    }

    // -------------------------------------------------------------- application scope
    /// Create the application `spec` (use `AppSpec::new(ctx.alloc_aid())`), run `f`, delete the
    /// application again. The delete is registered in the cleanup stack before the create is
    /// sent, so it also happens after a panic. Returns `None` when the application could not be
    /// created.
    ///
    /// On entry to `f` the PICC is authenticated with the PICC master key (selection: PICC); the
    /// application has its default keys (all zero, AES-128 or AES-256 as per the spec). Use
    /// [`Ctx::auth_app`] to enter it. On return the card is at PICC level, authenticated.
    pub fn app_scope<R>(&mut self, spec: AppSpec, f: impl FnOnce(&mut Ctx, Aid) -> R) -> Option<R> {
        let aid = spec.aid;
        if !is_suite_aid(aid) {
            self.step(&format!("create application {aid}"), |_| {
                Err::<(), _>(StepError::fail("AID is outside the suite range; use ctx.alloc_aid()"))
            });
            return None;
        }
        let id = self.push_cleanup(&format!("delete application {aid}"), move |c| c.delete_app_tolerant(aid));
        let created = self.step(&format!("create application {aid}"), |c| {
            c.auth_picc()?;
            c.create_application(&spec)?;
            Ok(())
        });
        if created.is_none() {
            self.run_cleanup_now(id);
            return None;
        }
        let r = catch_unwind(AssertUnwindSafe(|| f(self, aid)));
        self.step(&format!("delete application {aid}"), |c| {
            let r = c.delete_app_tolerant(aid);
            if r.is_ok() {
                c.cancel_cleanup(id);
            }
            r
        });
        match r {
            Ok(v) => Some(v),
            Err(p) => resume_unwind(p),
        }
    }

    /// Delete an application of the suite range at PICC level; "not found" counts as done.
    pub fn delete_app_tolerant(&mut self, aid: Aid) -> StepResult {
        self.auth_picc()?;
        match self.delete_application(aid, &[]) {
            Ok(()) => Ok(()),
            Err(e) if e.status() == Some(Status::ApplicationNotFound) => {
                self.auth_picc()?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

fn panic_text(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "(non-text panic)".into()
    }
}
