//! PKI layer: certificate authorities, certificates in the card's profile, revocation lists and the store.
//!
//! Map of the module:
//! - [`der`], [`pem`], [`time`], [`name`], [`signature`]: encodings (ASN.1 DER, PEM, validity times, X.501 names,
//!   ECDSA signature forms).
//! - [`keys`]: SPKI, SEC1 and PKCS#8 key encodings, passphrase protection.
//! - [`cert`]: [`Certificate`] (parse, verify, describe) and [`CertificateBuilder`].
//! - [`access_rights`]: the NXP access-rights extension and [`AcMap`] (7.6.4).
//! - [`profile`]: the card's reader certificate profile (7.10.2.1) and [`CertKind`].
//! - [`chain`]: the card's chain validation (7.10.2.2) and verification of card certificates.
//! - [`crl`]: CRLFile image, CRLSignature message and revocation check (7.10.2.3).
//! - [`certfile`]: certificate file image for writing a card certificate (7.10.1.1).
//! - [`store`]: persistent store of CAs, certificates, keys, CRL state and named AES keys.

pub mod access_rights;
pub mod cert;
pub mod certfile;
pub mod chain;
pub mod crl;
pub mod der;
pub mod error;
pub mod keys;
pub mod name;
pub mod pem;
pub mod profile;
pub mod signature;
pub mod store;
pub mod time;

pub use access_rights::{AcMap, AccessRights, DamOperation, DamRights, RightsScope};
pub use cert::{describe_der, Certificate, CertificateBuilder, Extension};
pub use chain::{leaf_public_key, validate_reader_chain, verify_card_chain, CardChain, ChainParams, ChainResult, TrustAnchor};
pub use crl::{CrlState, CrlUpdate, CsnOrder, Revocation};
pub use error::{CertError, PkiError, Result};
pub use keys::PrivateKeyFormat;
pub use name::Name;
pub use profile::{CertKind, MAX_READER_CERT, MAX_SERIAL};
pub use store::{Entry, ImportOptions, IssueRequest, PkiStore, PreflightOptions};
pub use time::Time;

#[cfg(test)]
mod tests;
