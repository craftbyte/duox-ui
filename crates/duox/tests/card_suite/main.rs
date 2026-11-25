//! Hardware test suite for a real MIFARE DUOX card. See README.md in this directory.
//!
//!     cargo test -p duox --test card_suite -- --ignored --test-threads=1 --nocapture
//!
//! Without `--ignored` only the offline unit tests (the guard, the recovery file, the snapshot
//! comparison) run.

#![allow(dead_code)] // the framework API is larger than what the picc section uses

mod ctx;
mod guard;
mod keychange;
mod report;
mod runner;
mod sections;
mod snapshot;
mod wire;

/// The suite: preflight, sections, cleanup, final Format, verification. Needs DUOX_SUITE_CONFIRM=<UID>
/// unless DUOX_SUITE_DRY=1.
#[test]
#[ignore = "needs the real card in the reader: see crates/duox/tests/card_suite/README.md"]
fn card_suite() {
    runner::run_suite();
}

/// Put back PICC keys listed in target/tmp/card-suite-recovery.txt after an aborted run.
#[test]
#[ignore = "recovery tool: needs the real card in the reader"]
fn recover_keys() {
    runner::run_recover();
}
