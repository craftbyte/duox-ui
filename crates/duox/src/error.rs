//! Crate-wide error type.

use crate::card::types::Status;
use crate::crypto::CryptoError;
use crate::transport::TransportError;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while talking to a card.
///
/// Whenever an error is returned by a [`Card`](crate::card::Card) command, any EV2 / ECC
/// authentication that was active has been dropped (the card does the same), so the caller
/// must authenticate again before the next protected command.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The reader or the PC/SC layer failed.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// A cryptographic primitive rejected its input.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    /// The card answered a native command with a status other than success.
    #[error("{command}: {status} (0x{:02X}){}", status.code(), if *.auth_lost { " - authentication lost" } else { "" })]
    Status {
        command: &'static str,
        status: Status,
        auth_lost: bool,
    },

    /// An ISO/IEC 7816-4 status word other than the expected one.
    #[error("{command}: {sw:04X} ({})", crate::card::types::iso_sw_description(*.sw))]
    Iso { command: String, sw: u16 },

    /// The card sent something that cannot be parsed or verified (bad MAC, truncated data,
    /// wrong RndA, invalid signature ...). The session is dropped.
    #[error("{0}")]
    Protocol(String),

    /// A command that needs an authenticated session was issued without one.
    #[error("{0} needs an active authentication")]
    NotAuthenticated(&'static str),

    /// The caller supplied a parameter that cannot be encoded.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl Error {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }
    pub(crate) fn arg(msg: impl Into<String>) -> Self {
        Error::InvalidArgument(msg.into())
    }

    /// The native status code if the card refused a command.
    pub fn status(&self) -> Option<Status> {
        match self {
            Error::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The ISO status word if the failure was an ISO status.
    pub fn iso_sw(&self) -> Option<u16> {
        match self {
            Error::Iso { sw, .. } => Some(*sw),
            _ => None,
        }
    }
}
