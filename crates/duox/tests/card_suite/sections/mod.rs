//! Section registry. One file per section, each exposing `pub const NAME`, `pub const DESCRIPTION`
//! and `pub fn run(ctx: &mut Ctx)`.
//!
//! To add a section: create `sections/<name>.rs`, add `pub mod <name>;` and one `section!(<name>)`
//! line below. The order of the list is the order of execution; `picc` goes first.

use crate::ctx::Ctx;

pub mod application;
pub mod asymmetric;
pub mod delegated;
pub mod files_data;
pub mod iso_ev;
pub mod keysets;
pub mod lab;
pub mod picc;
pub mod pki_ecc_auth;
pub mod proximity_gpio;
pub mod sdm;
pub mod transactions;

pub struct Section {
    pub name: &'static str,
    pub description: &'static str,
    pub run: fn(&mut Ctx),
    /// Opt-in sections run only when `DUOX_SUITE_ONLY` names them.
    pub opt_in: bool,
}

macro_rules! section {
    ($m:ident) => {
        Section { name: $m::NAME, description: $m::DESCRIPTION, run: $m::run, opt_in: false }
    };
    ($m:ident, opt_in) => {
        Section { name: $m::NAME, description: $m::DESCRIPTION, run: $m::run, opt_in: true }
    };
}

/// All sections in execution order.
pub fn all() -> Vec<Section> {
    vec![
        section!(picc),
        section!(application),
        section!(files_data),
        section!(keysets),
        section!(asymmetric),
        section!(pki_ecc_auth),
        section!(sdm),
        section!(transactions),
        section!(iso_ev),
        section!(delegated),
        section!(proximity_gpio),
        section!(lab, opt_in),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn lab_is_opt_in_and_last() {
        let all = super::all();
        assert!(all.iter().find(|s| s.name == "lab").is_some_and(|s| s.opt_in));
        assert!(all.iter().filter(|s| s.opt_in).count() == 1);
    }
}
