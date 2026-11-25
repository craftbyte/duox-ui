//! Final summary. It only counts what was recorded: a skipped step is never reported as passed, and
//! the totals say how many steps actually ran.

use crate::ctx::{Ctx, Outcome};

/// Print the summary table; returns true if the run is clean (no failed step, no failed restore,
/// no recovery file left behind).
pub fn print_summary(ctx: &Ctx) -> bool {
    let mut order: Vec<String> = vec![];
    for r in ctx.records() {
        if !order.contains(&r.section) {
            order.push(r.section.clone());
        }
    }
    println!("\n==================== summary ====================");
    println!("  {:<16} {:>7} {:>7} {:>8}", "section", "passed", "failed", "skipped");
    let (mut tp, mut tf, mut ts) = (0, 0, 0);
    for s in &order {
        let (mut p, mut f, mut k) = (0, 0, 0);
        for r in ctx.records().iter().filter(|r| &r.section == s) {
            match r.outcome {
                Outcome::Pass => p += 1,
                Outcome::Fail(_) => f += 1,
                Outcome::Skip(_) => k += 1,
            }
        }
        println!("  {:<16} {:>7} {:>7} {:>8}", s, p, f, k);
        tp += p;
        tf += f;
        ts += k;
    }
    println!("  {:<16} {:>7} {:>7} {:>8}", "TOTAL", tp, tf, ts);
    println!("  ({} steps recorded; skipped steps were NOT exercised)", tp + tf + ts);

    let fails: Vec<_> = ctx.records().iter().filter(|r| matches!(r.outcome, Outcome::Fail(_))).collect();
    if !fails.is_empty() {
        println!("\n  FAILED steps:");
        for r in fails {
            if let Outcome::Fail(m) = &r.outcome {
                println!("    [{}] {}: {}", r.section, r.name, m);
            }
        }
    }
    let skips: Vec<_> = ctx.records().iter().filter(|r| matches!(r.outcome, Outcome::Skip(_))).collect();
    if !skips.is_empty() {
        println!("\n  Skipped steps:");
        for r in skips {
            if let Outcome::Skip(m) = &r.outcome {
                println!("    [{}] {}: {}", r.section, r.name, m);
            }
        }
    }
    let mut clean = tf == 0;
    if !ctx.cleanup_failures.is_empty() {
        clean = false;
        println!("\n  !!!!! RESTORE FAILURES - THE CARD MAY NOT BE IN ITS INITIAL STATE !!!!!");
        for f in &ctx.cleanup_failures {
            println!("    {f}");
        }
    }
    let rec = ctx.recovery.path();
    if rec.exists() {
        clean = false;
        println!("\n  !!!!! RECOVERY FILE STILL EXISTS: {} !!!!!", rec.display());
        println!("  A PICC key may still be changed. Read the file, then run:");
        println!("    DUOX_SUITE_CONFIRM=<UID> cargo test -p duox --test card_suite recover -- --ignored --test-threads=1 --nocapture");
    }
    println!("  result: {}", if clean { "CLEAN" } else { "NOT CLEAN" });
    clean
}
