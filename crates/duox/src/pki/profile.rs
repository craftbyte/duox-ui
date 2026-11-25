//! The card's reader certificate profile (7.10.2.1, parsing rules of 7.10.2.2) and the kinds of certificate
//! the store manages.

use super::cert::Certificate;
use super::der::oids;
use super::error::CertError;
use super::signature;
use crate::crypto;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Largest certificate the card parses.
pub const MAX_READER_CERT: usize = 440;
/// Largest serial number of a reader certificate: a positive 4-byte DER INTEGER.
pub const MAX_SERIAL: u32 = 0x7FFF_FFFF;
/// Longest chain the card accepts (parent and leaf).
pub const MAX_CHAIN_LEN: usize = 2;

/// Role of a store entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertKind {
    /// Self-signed CA whose public key is installed on cards as CARootKey.
    Root,
    /// Delegated CA ("sub"): a certificate with CA delegation that issues reader certificates.
    Sub,
    /// Reader (PCD) certificate.
    Reader,
    /// Card (PICC) certificate or originality certificate.
    Card,
}

impl CertKind {
    /// The identifier used in the store file.
    pub fn as_str(self) -> &'static str {
        match self {
            CertKind::Root => "root",
            CertKind::Sub => "sub",
            CertKind::Reader => "reader",
            CertKind::Card => "card",
        }
    }
    /// Human readable name.
    pub fn label(self) -> &'static str {
        match self {
            CertKind::Root => "Root CA",
            CertKind::Sub => "Delegated CA",
            CertKind::Reader => "Reader",
            CertKind::Card => "Card",
        }
    }
    /// Roots and delegated CAs can issue certificates.
    pub fn is_ca(self) -> bool {
        matches!(self, CertKind::Root | CertKind::Sub)
    }
}

impl fmt::Display for CertKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Apply the parsing rules of 7.10.2.2 (certificate validation, step 1) to `cert`.
///
/// `role` ("parent", "leaf", "certificate") prefixes the messages; `curve_id` is the curve of the CARootKey the
/// chain is validated against. Signature, issuer, access-right and revocation checks are the caller's job.
pub fn check_reader_certificate(cert: &Certificate, role: &str, curve_id: u8) -> Result<(), CertError> {
    let size = cert.to_der().len();
    if size > MAX_READER_CERT {
        return Err(CertError::wrong_data(format!("{role}: {size} bytes exceeds the {MAX_READER_CERT} byte limit")));
    }
    if cert.version() != 2 {
        return Err(CertError::wrong_data(format!("{role}: not an X.509 v3 certificate")));
    }
    if cert.serial_is_negative() || cert.serial().is_none_or(|s| s > u64::from(MAX_SERIAL)) {
        return Err(CertError::wrong_data(format!("{role}: serial number does not fit a 4-byte INTEGER")));
    }
    if !cert.signature_algorithm().is(oids::ECDSA_WITH_SHA256) || !cert.tbs_signature_algorithm().is(oids::ECDSA_WITH_SHA256)
    {
        return Err(CertError::wrong_data(format!("{role}: signature algorithm is not ecdsa-with-SHA256")));
    }
    if cert.curve_id() != Some(curve_id) {
        return Err(CertError::wrong_data(format!(
            "{role}: public key is not on {}",
            crypto::curve_name(curve_id)
        )));
    }
    if let Some(e) = cert.extensions().iter().find(|e| e.critical && !e.oid.is(oids::NXP_ACCESS_RIGHTS)) {
        return Err(CertError::wrong_data(format!("{role}: unknown critical extension {}", e.oid)));
    }
    if signature::der_to_raw(cert.signature_der()).is_err() {
        return Err(CertError::wrong_data(format!("{role}: signature value is not an Ecdsa-Sig-Value")));
    }
    Ok(())
}
