//! Protocol library for NXP MIFARE DUOX (MF3E(H)x3) cards.
//!
//! Section numbers in comments refer to the NXP MIFARE DUOX product data sheet, Rev. 1.2.

pub mod crypto;

pub mod dam;
pub mod evcert;
pub mod sdm;
pub mod txmac;
pub mod pki;
pub mod card;
pub mod error;
pub mod transport;

pub use error::{Error, Result};
