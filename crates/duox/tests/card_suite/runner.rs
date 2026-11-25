//! Orchestration: connect, safety checks, preflight, sections, cleanup, final Format, verification.

use crate::ctx::{ensure, Config, Ctx, StepError, SuiteCard};
use crate::guard::Guard;
use crate::keychange::{recover_from_file, Recovery};
use crate::report::print_summary;
use crate::sections::{self, Section};
use crate::snapshot::{diff, print_diff, Snapshot};
use crate::wire::GuardedTransport;
use duox::card::{AppSpec, Card};
use duox::transport::{list_readers, PcscTransport, TraceDir, Transport};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

fn target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

fn connect(cfg: &Config) -> Result<(SuiteCard, Vec<u8>, String), String> {
    let readers = list_readers().map_err(|e| format!("PC/SC: {e}"))?;
    let want = cfg.reader.to_lowercase();
    let name = readers
        .iter()
        .find(|r| r.to_lowercase().contains(&want))
        .ok_or_else(|| format!("no reader matching {:?} among {readers:?} (set DUOX_READER)", cfg.reader))?
        .clone();
    let mut t = GuardedTransport::new(PcscTransport::new(name.clone()), Guard::new(cfg.allow_gpio));
    if cfg.trace {
        t.set_trace(Some(Box::new(|d, b| {
            let arrow = if d == TraceDir::Tx { ">>" } else { "<<" };
            println!("      {arrow} {}", hex::encode_upper(b));
        })));
    }
    let mut card = Card::new(t);
    card.connect().map_err(|e| format!("cannot connect to the card in {name}: {e}"))?;
    let v = card.get_version().map_err(|e| format!("GetVersion: {e}"))?;
    Ok((card, v.uid, name))
}

fn print_snapshot(s: &Snapshot) {
    let w = s.items.iter().map(|i| i.label.len()).max().unwrap_or(10);
    for i in &s.items {
        println!("  {:<w$}  {}", i.label, i.show, w = w);
    }
}

/// The main test body.
pub fn run_suite() {
    let cfg = Config::from_env();
    println!("DUOX card suite  (DRY={}, ONLY={:?}, ALLOW_WIPE={}, ALLOW_GPIO={})", cfg.dry, cfg.only, cfg.allow_wipe, cfg.allow_gpio);
    let (card, uid, reader) = connect(&cfg).unwrap_or_else(|e| panic!("{e}"));
    let uid_hex = hex::encode_upper(&uid);
    println!("reader: {reader}\ncard UID: {uid_hex}");

    if !cfg.dry {
        match &cfg.confirm {
            Some(c) if *c == uid_hex => {}
            Some(c) => panic!("DUOX_SUITE_CONFIRM={c} but the connected card has UID {uid_hex}: wrong card, nothing was done"),
            None => panic!("a destructive run needs DUOX_SUITE_CONFIRM={uid_hex} (the UID of the card in the reader); nothing was done"),
        }
    } else if let Some(c) = &cfg.confirm {
        if *c != uid_hex {
            println!("note: DUOX_SUITE_CONFIRM={c} does not match this card ({uid_hex}); a real run would be refused");
        }
    }

    let chosen = select_sections(&cfg);
    let mut ctx = Ctx::new(card, cfg.clone(), uid, target_dir()).unwrap_or_else(|e| panic!("{e}"));

    let rec = ctx.recovery.path().clone();
    if rec.exists() {
        println!("\n!! unfinished recovery file: {}\n{}", rec.display(), std::fs::read_to_string(&rec).unwrap_or_default());
        if !cfg.dry {
            panic!("a previous run left {}; restore the keys first (cargo test -p duox --test card_suite recover -- --ignored), then delete the file", rec.display());
        }
    }

    if let Err(e) = preflight(&mut ctx) {
        ctx.section = "preflight".into();
        print_summary(&ctx);
        panic!("preflight failed, nothing was changed beyond the preflight Format: {e}");
    }

    if ctx.dry {
        dry_report(&mut ctx, &chosen);
        if std::env::var("DUOX_SUITE_DRY_SECTIONS").is_ok_and(|v| v == "1") {
            println!("
== DUOX_SUITE_DRY_SECTIONS: running the sections with every card-modifying helper refusing ==");
            run_sections(&mut ctx, &chosen);
            ctx.section = "dry-run".into();
            ctx.step("the card is unchanged after the read-only section run", |c| {
                c.ensure_picc()?;
                let init = c.initial.clone().ok_or("no snapshot")?;
                let now = Snapshot::take(c);
                ensure(print_diff("after the section run", &diff(&init, &now)), "the card changed")
            });
        }
        let clean = print_summary(&ctx);
        ctx.card.disconnect();
        assert!(clean, "DRY run found problems (see above)");
        return;
    }

    run_sections(&mut ctx, &chosen);

    finish(&mut ctx);
    let clean = print_summary(&ctx);
    ctx.card.disconnect();
    assert!(clean, "the card suite did not finish clean: see the summary above");
}

fn select_sections(cfg: &Config) -> Vec<Section> {
    let all = sections::all();
    match &cfg.only {
        None => all.into_iter().filter(|s| !s.opt_in).collect(),
        Some(names) => {
            for n in names {
                assert!(all.iter().any(|s| s.name == n), "DUOX_SUITE_ONLY: unknown section {n:?}; known: {:?}", all.iter().map(|s| s.name).collect::<Vec<_>>());
            }
            all.into_iter().filter(|s| names.iter().any(|n| n == s.name)).collect()
        }
    }
}

// ------------------------------------------------------------------ preflight
fn preflight(ctx: &mut Ctx) -> Result<(), String> {
    ctx.section = "preflight".into();
    println!("\n== preflight ==");
    ctx.step("PICC master key authenticates with the all-zero AES-128 key (required)", |c| c.auth_picc())
        .ok_or("the factory all-zero key does not authenticate; nothing is touched")?;
    let before = Snapshot::take(ctx);
    println!("\ncard state before anything is done:");
    print_snapshot(&before);

    let has_apps = before.get("applications (GetApplicationIDs)").is_some_and(|i| i.show != "none");
    if has_apps {
        let list = before.get("applications (GetApplicationIDs)").map(|i| i.show.clone()).unwrap_or_default();
        if ctx.dry {
            println!("\nWARNING: the card contains applications ({list}); a real run needs DUOX_SUITE_ALLOW_WIPE=1 and would format them away");
        } else if !ctx.cfg.allow_wipe {
            return Err(format!("the card already contains applications ({list}); set DUOX_SUITE_ALLOW_WIPE=1 to have them formatted away"));
        }
    }
    if before.get("PICC key 0 authenticates with the all-zero key").is_none_or(|i| i.show != "yes") {
        return Err("snapshot could not prove the zero key".into());
    }
    if ctx.dry {
        ctx.initial = Some(before);
        return Ok(());
    }

    ctx.step("Format on the card (preflight: Format must work before anything else is done)", |c| {
        c.auth_picc()?;
        c.format()?;
        c.auth_picc()
    })
    .ok_or("Format failed on the card; the suite will not continue (its last step must be a working Format)")?;
    let after = Snapshot::take(ctx);
    let rows = diff(&before, &after);
    let bad: Vec<_> = rows
        .iter()
        .filter(|r| !r.same && !(has_apps && matches!(r.label.as_str(), "applications (GetApplicationIDs)" | "FreeMem" | "DF names (GetDFNames)")))
        .collect();
    if !bad.is_empty() {
        print_diff("preflight Format changed PICC state", &rows);
        return Err("Format changed something other than applications; the premise of the suite does not hold".into());
    }
    if let Some(m) = after.get("FreeMem") {
        if m.show != "5120 bytes" {
            println!("note: FreeMem after Format is {} (expected 5120 bytes on a fresh card); it is the reference for the final check", m.show);
        }
    }
    ctx.initial = Some(after);

    // Baseline for the PICCAppDefaultKey proof used by the picc section and the final check.
    let aid = ctx.alloc_aid();
    let ok = ctx
        .app_scope(AppSpec::new(aid).keys(1), |c, aid| {
            c.step("baseline: a new application carries the all-zero default key", |c| {
                let z = c.zero_key;
                c.auth_app(aid, 0, &z)?;
                let v = c.get_key_version(0, None)?;
                ensure(v.len() == 1, format!("unexpected GetKeyVersion {v:02X?}"))?;
                c.app_default_key_version = v[0];
                c.detail(format!("default key version {:02X}", v[0]));
                Ok(())
            })
        })
        .flatten();
    ok.ok_or("the default application key is not all-zero: PICCAppDefaultKey was customised; the suite cannot prove a restore value")?;
    // DeleteApplication does not give back the application's key and file blocks; Format does.
    ctx.step("baseline: after Format FreeMem is back to the initial value", |c| {
        c.auth_picc()?;
        c.format()?;
        c.auth_picc()?;
        let m = c.free_mem()?;
        let want = c.initial.as_ref().and_then(|s| s.get("FreeMem")).map(|i| i.show.clone()).unwrap_or_default();
        crate::ctx::ensure_eq(format!("{m} bytes"), want, "FreeMem")
    });
    Ok(())
}

fn dry_report(ctx: &mut Ctx, chosen: &[Section]) {
    ctx.section = "dry-run".into();
    println!("\n== DRY RUN: no card-modifying command is sent ==");
    ctx.step("the snapshot is stable (second read equals the first)", |c| {
        c.ensure_picc()?;
        let init = c.initial.clone().ok_or("no snapshot")?;
        let now = Snapshot::take(c);
        let rows = diff(&init, &now);
        ensure(print_diff("two consecutive snapshots", &rows), "the snapshot differs between two reads")
    });
    println!("\nplan of a real run:");
    println!("  1. preflight: authenticate, snapshot, Format the empty card, baseline default-key proof");
    for (i, s) in chosen.iter().enumerate() {
        println!("  {}. section {:<14} {}", i + 2, s.name, s.description);
    }
    println!("  {}. cleanup stack (LIFO restore actions), default-key proof, final Format, reconnect, compare with the snapshot", chosen.len() + 2);
    println!("\nguard: GPIO writes {}, PICC option 0x00/0x02/0x03/0x04/0x05/0x0C/0x0F/0x10/0x15/0x16/0x17/0xFF never, ManageKeyPair / ManageCARootKey at PICC level never",
        if ctx.guard.allow_gpio { "ALLOWED (DUOX_SUITE_ALLOW_GPIO=1)" } else { "off" });
    println!("recovery file would be: {}", ctx.recovery.path().display());
    println!("to run for real: DUOX_SUITE_CONFIRM={} (without DUOX_SUITE_DRY)", hex::encode_upper(&ctx.uid));
}

// ------------------------------------------------------------------ finish
fn finish(ctx: &mut Ctx) {
    ctx.section = "final".into();
    ctx.run_cleanup();
    println!("\n== final ==");
    ctx.step("PICC master key is back to the all-zero key", |c| {
        crate::ctx::ensure_eq(c.picc_key.clone(), vec![0u8; 16], "ctx.picc_key")
    });
    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |c, aid| {
        c.step("PICCAppDefaultKey still yields the all-zero key with the initial key version", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            crate::ctx::ensure_eq(c.get_key_version(0, None)?, vec![c.app_default_key_version], "key version")
        });
    });
    ctx.step("Format the PICC (the last operation that changes the card)", |c| {
        c.auth_picc()?;
        c.format()
    });
    ctx.step("reconnect and compare the card with the initial snapshot", |c| {
        c.card.disconnect();
        c.card.connect()?;
        let init = c.initial.clone().ok_or("no initial snapshot")?;
        let now = Snapshot::take(c);
        let rows = diff(&init, &now);
        ensure(print_diff("final state versus initial snapshot", &rows), "the card is not in its initial state")
    });
}

// ------------------------------------------------------------------ recovery mode
pub fn run_recover() {
    let cfg = Config::from_env();
    let path = target_dir().join("card-suite-recovery.txt");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("no recovery file at {}: {e}", path.display()));
    let entries = Recovery::parse(&text);
    assert!(!entries.is_empty(), "the recovery file has no entries");
    let (card, uid, _reader) = connect(&cfg).unwrap_or_else(|e| panic!("{e}"));
    let uid_hex = hex::encode_upper(&uid);
    assert_eq!(cfg.confirm.as_deref(), Some(uid_hex.as_str()), "set DUOX_SUITE_CONFIRM={uid_hex}");
    for e in &entries {
        assert_eq!(e.uid, uid_hex, "the recovery file belongs to the card {}, not {uid_hex}", e.uid);
    }
    let mut ctx = Ctx::new(card, cfg, uid, target_dir()).unwrap_or_else(|e| panic!("{e}"));
    match recover_from_file(&mut ctx, entries) {
        Ok(report) => println!("{report}recovery complete; the recovery file was removed"),
        Err(report) => panic!("recovery incomplete:\n{report}"),
    }
}

fn run_sections(ctx: &mut Ctx, chosen: &[Section]) {
    for s in chosen {
        ctx.section = s.name.into();
        println!("\n== section {}: {} ==", s.name, s.description);
        let run = s.run;
        if let Err(p) = catch_unwind(AssertUnwindSafe(|| run(ctx))) {
            let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            ctx.step("section aborted by a panic outside any step", |_| Err::<(), _>(StepError::fail(msg)));
            ctx.revive();
        }
        // Deleted applications do not return their key and file blocks; only Format does. Reclaim
        // the memory between sections so that a small card does not run out. Format touches no
        // PICC key, key setting or configuration.
        if !ctx.dry {
            ctx.step("reclaim memory between sections (Format)", |c| {
                c.auth_picc()?;
                c.format()
            });
        }
    }
}
