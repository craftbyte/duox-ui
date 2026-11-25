//! Errors of the PKI layer.

use crate::crypto::CryptoError;
use thiserror::Error;

/// Status word a card answers when it refuses a certificate: malformed or not acceptable.
pub const SW_WRONG_DATA: u16 = 0x6A80;
/// Status word a card answers when a signature or a revocation check fails.
pub const SW_SECURITY: u16 = 0x6982;

/// A reader certificate (chain) the card would reject (7.10.2.2). `sw` is the status the card returns.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct CertError {
    pub message: String,
    pub sw: u16,
}

impl CertError {
    /// Rejection answered with 6A80 (format, profile and access-right problems).
    pub fn wrong_data(message: impl Into<String>) -> Self {
        CertError { message: message.into(), sw: SW_WRONG_DATA }
    }
    /// Rejection answered with 6982 (signature or revocation failure).
    pub fn security(message: impl Into<String>) -> Self {
        CertError { message: message.into(), sw: SW_SECURITY }
    }
}

/// Everything that can go wrong in the PKI layer.
#[derive(Debug, Error)]
pub enum PkiError {
    /// Malformed ASN.1 DER.
    #[error("DER: {0}")]
    Der(String),
    /// Malformed PEM text.
    #[error("PEM: {0}")]
    Pem(String),
    /// Malformed or unsupported key encoding.
    #[error("key: {0}")]
    Key(String),
    /// An encrypted private key was given without a passphrase.
    #[error("the private key is passphrase protected")]
    PassphraseRequired,
    /// The passphrase does not decrypt the private key.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// A certificate that is not what the operation needs (unsupported key type, wrong profile, ...).
    #[error("certificate: {0}")]
    Certificate(String),
    /// The card's certificate rules rejected a certificate chain.
    #[error(transparent)]
    Chain(#[from] CertError),
    /// Private keys in the store are passphrase protected and the passphrase is missing or wrong.
    #[error("store locked: {0}")]
    StoreLocked(String),
    /// No store entry with this id.
    #[error("no store entry '{0}'")]
    NoSuchEntry(String),
    /// A request the store refuses (precondition not met); the text says what to change.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("store file: {0}")]
    Io(#[from] std::io::Error),
    #[error("store file format: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T, E = PkiError> = std::result::Result<T, E>;

pub(crate) fn der_err<T>(msg: impl Into<String>) -> Result<T> {
    Err(PkiError::Der(msg.into()))
}
