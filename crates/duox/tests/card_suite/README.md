# Card suite: hardware tests for a real DUOX card

An integration test that runs against the real card in a PC/SC reader, exercises the library, and
ends by formatting the PICC back to its factory state and proving that it is there.

```
cargo test -p duox --test card_suite -- --ignored --test-threads=1 --nocapture
```

Without `--ignored` only the offline unit tests run (the guard table, the recovery file, snapshot
diffing). They need no card and run in plain `cargo test -p duox`.

## Run control (environment)

| variable | meaning |
|---|---|
| `DUOX_READER` | substring of the reader name, default `OMNIKEY` |
| `DUOX_SUITE_CONFIRM` | UID of the card (hex). Must equal the connected card's UID or nothing destructive runs |
| `DUOX_SUITE_DRY=1` | preflight, snapshot, plan. No card-modifying command is sent (the guarded helpers refuse) |
| `DUOX_SUITE_DRY_SECTIONS=1` | with DRY: also run the sections, every card-modifying helper refusing (steps that need a write are recorded as skipped); read-only steps run for real; the card is compared with the snapshot afterwards |
| `DUOX_SUITE_ONLY` | comma separated section names, e.g. `picc,sdm` (preflight, cleanup and final Format always run). The opt-in section `lab` runs only when named here |
| `DUOX_LAB_PARTS` | with section `lab`: comma separated parts, default `1,2,3` (1 SDMSIG read-out, 2 ISOReadRecord, 3 plain command in an authenticated session) |
| `DUOX_SUITE_ALLOW_WIPE=1` | accept a card that already holds applications (they are formatted away in the preflight) |
| `DUOX_SUITE_ALLOW_GPIO=1` | lifts the guard's ban on SetConfiguration 0x11 (GPIO) at PICC level |
| `DUOX_SUITE_TRACE=1` | print every APDU |

Recovery after a crashed run that left `target/tmp/card-suite-recovery.txt`:

```
DUOX_SUITE_CONFIRM=<UID> cargo test -p duox --test card_suite recover -- --ignored --test-threads=1 --nocapture
```

## What a run does

1. Preflight: connect, check `DUOX_SUITE_CONFIRM`, refuse if a recovery file exists, authenticate PICC key 0
   with the all-zero key, take the **snapshot**, refuse if applications exist (unless ALLOW_WIPE), **Format the
   empty card** (Format must work before anything else is touched), snapshot again, prove that a new
   application carries the all-zero default key (`ctx.app_default_key_version`).
2. Sections, in registry order, each inside a panic guard.
3. Cleanup stack (LIFO restore actions), the default-key proof, **Format**, reconnect, snapshot, **diff against the
   initial snapshot** (UID, applications, FreeMem, PICCKeySettings, every readable GetConfiguration option,
   key versions, ECC and CA-root key settings, zero key authenticates). Any difference fails the run.
4. Summary: passed / failed / skipped per section. A skipped step was not exercised and is never counted as passed.

## Why the guard exists

Format at PICC level only releases applications and files. It does not reset PICC keys, key settings or
configuration. Some configuration is irreversible (disable Format, enable Random ID, disable chained writes,
enabling a PICCDAM / VCConfiguration key ...), some could make the card unreachable (ATS, SAK, ATQA, protocol
options, I2C). `guard.rs` holds the policy and is unit tested; `wire.rs` is a tripwire on the raw APDUs.

* Everything a section changes at PICC level must be restored by the section, through the cleanup stack.
* PICC level symmetric keys are changed only with `ctx.change_picc_key` (proof of the old value, recovery file
  before ChangeKey, verification, restore action). Keys 0x10..0x12 and 0x20/0x21 are disabled at delivery and
  become enabled for good when written: the suite only touches one if it already authenticates with the zero key.
* Test applications live in AID range `D00000..D0FFFF`, are created through `ctx.app_scope` and are always deleted.
  Inside them the irreversible settings are allowed (the application disappears), except that nothing in the
  suite range may be assumed to survive.
* Never at PICC level: SetConfiguration 0x00 (any value), 0x02, 0x03, 0x04, 0x05, 0x0C, 0x0F, 0x10, 0x15,
  0x16, 0x17, 0xFF, 0x11 (unless GPIO tier); ManageKeyPair; ManageCARootKey; NXPDAM keys 0x18..0x1A;
  PICCKeySettings bit 0 or bit 3 cleared, bit 4 set; deleting an AID outside the suite range; file writes.

## The `lab` section

`sections/lab.rs` is not part of the default run. It holds experiments with raw APDUs (`apdu_raw`) that record every
status word, length and timing with `Ctx::detail`; the run output is the experiment log. Steps that fail with a
transport error revive the card and repeat. In DRY mode the section is skipped.

## Writing a section

Create `sections/<name>.rs` (placeholders for all planned sections exist; replace the body), expose

```rust
pub const NAME: &str = "files_data";
pub const DESCRIPTION: &str = "...";
pub fn run(ctx: &mut Ctx) { ... }
```

and make sure `sections/mod.rs` lists it (`pub mod` + `section!(name)`; already done for the placeholders).

### API (`ctx.rs`)

```rust
pub struct Ctx {
    pub card: SuiteCard,           // also reachable through Deref / DerefMut: c.get_version()?
    pub zero_key: [u8; 16], pub zero_key32: [u8; 32],
    pub picc_key: Vec<u8>,         // the PICC master key currently in force (zero unless a key change is running)
    pub store: PkiStore, pub store_dir: PathBuf,   // throwaway PKI store in a temp dir
    pub uid: Vec<u8>, pub guard: Guard, pub cfg: Config, pub dry: bool,
    pub initial: Option<Snapshot>, pub app_default_key_version: u8, pub target_dir: PathBuf,
}

// recording; never aborts the run; panics are caught and recorded as failures
fn step<T>(&mut self, name: &str, f: impl FnOnce(&mut Ctx) -> StepResult<T>) -> Option<T>;
fn step_picc<T>(&mut self, name: &str, f: ...) -> Option<T>;   // first ensure_picc()
fn skip(&mut self, name: &str, reason: &str);
fn detail(&mut self, text: impl Into<String>);                 // info line printed under the step
// inside a step: Err(StepError::skip("reason")) records a skip, Err("text".into()) / any duox::Error a failure
fn ensure(cond: bool, msg) -> StepResult;  fn ensure_eq(got, want, what) -> StepResult;

// state helpers: they re-establish what a failed step may have ended
fn auth_picc(&mut self) -> StepResult;                 // select PICC, authenticate key 0 with ctx.picc_key
fn ensure_picc(&mut self) -> StepResult;               // only if not already authenticated with key 0 at PICC
fn auth_picc_key(&mut self, key_no: u8, key: &[u8]) -> StepResult;
fn auth_app(&mut self, aid: Aid, key_no: u8, key: &[u8]) -> StepResult;   // 16 or 32 byte key

// allocators
fn alloc_aid(&mut self) -> Aid;          // D00000, D00001, ...
fn file_nos(&self) -> FileNos;           // FileNos::next() -> 0, 1, 2 ... per application

// throwaway application: created, closure runs, deleted (also after a panic)
fn app_scope<R>(&mut self, spec: AppSpec, f: impl FnOnce(&mut Ctx, Aid) -> R) -> Option<R>;
//   spec = AppSpec::new(ctx.alloc_aid()).keys(2) [.aes256() ...]; default keys are zero.
//   On entry: PICC selected and authenticated; use ctx.auth_app(aid, 0, &ctx.zero_key) to enter the application.

// cleanup stack (LIFO, runs at the end, after a panic, tolerant of any card state)
fn push_cleanup(&mut self, name: &str, f: impl FnOnce(&mut Ctx) -> StepResult + 'static) -> CleanupId;
fn run_cleanup_now(&mut self, id) -> bool;   fn cancel_cleanup(&mut self, id);

// negative tests
fn expect_err<T, E: Into<StepError>>(&self, status: Status, r: Result<T, E>) -> StepResult;   // exact status, and the session ended
fn expect_any_status(&self, r) -> StepResult<Status>;
fn expect_violation(&self, r) -> StepResult;                                                   // the guard refused

// PICC level keys
fn change_picc_key(&mut self, KeyChange) -> StepResult<KeyChangeHandle>;
fn revert_key_change(&mut self, KeyChangeHandle) -> StepResult;
```

The card-modifying commands are methods of `Ctx` and shadow the card's own, so `c.format()`,
`c.set_configuration(..)`, `c.change_key(..)`, `c.change_key_settings(..)`, `c.manage_key_pair(..)`,
`c.manage_ca_root_key(..)`, `c.create_application(..)`, `c.delete_application(..)`, `c.native_raw(..)` and
`c.apdu_raw(..)` all pass the guard and refuse in DRY mode. Do not bypass them with `c.card.<name>`. Data commands
inside a throwaway application (`write_data`, `create_*_file`, ...) go straight to the card; the wire tripwire
still blocks them at PICC level.

### Rules for sections

* Every step starts from a state it establishes itself (`ensure_picc`, `auth_app`): any failed command ends the
  authentication.
* Anything that changes PICC state registers a restore action BEFORE the change and cancels it after a verified restore.
* Use `Err(StepError::skip(..))` when the card cannot do something or the guard forbids it. Never report a skip as a pass.
* Do not mention data sheet text in code or comments; cite section numbers.
* Need something the guard forbids (e.g. GPIO)? Ask for it explicitly in the tier switches (`DUOX_SUITE_ALLOW_GPIO`)
  and restore the value you read first; add the new case to the guard's unit-test table.
