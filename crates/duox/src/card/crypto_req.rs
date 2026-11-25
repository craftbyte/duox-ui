//! CryptoRequest (7.15): ECC signature generation with an on-card private key, and Echo.
//!
//! The CommMode of CryptoRequest is configured with SetConfiguration (option 0x15); the caller
//! passes the configured mode.

use super::types::*;
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

const ACTION_ECC_SIGN: u8 = 0x03;
const ACTION_ECHO: u8 = 0xFD;
const INPUT_COMMAND_BUFFER: u8 = 0xF0;
/// Bytes of raw input per frame. The data sheet allows up to 0xEA, but 0xE0 keeps a Full mode
/// command (padding + MAC) inside a short APDU.
const CHUNK: usize = 0xE0;

/// Input of an ECC signature.
#[derive(Debug, Clone, Copy)]
pub enum SignInput<'a> {
    /// Raw data; the card hashes it with SHA-256. Longer than one frame is sent as
    /// initialize / update / finalize.
    Raw(&'a [u8]),
    /// A pre-computed SHA-256 digest (32 bytes).
    Hash(&'a [u8]),
}

impl<T: Transport> Card<T> {
    /// CryptoRequest ECCSign (ECDSA with SHA-256). Returns the 64 byte signature `r || s`.
    pub fn crypto_ecc_sign(&mut self, key_no: u8, input: SignInput<'_>, mode: CommMode) -> Result<Vec<u8>> {
        let c = cmd::CRYPTO_REQUEST;
        match input {
            SignInput::Hash(h) => {
                if h.len() != 32 {
                    return Err(Error::arg("a pre-computed SHA-256 hash is 32 bytes"));
                }
                let mut d = vec![ACTION_ECC_SIGN, 0x05, 0x00, key_no, INPUT_COMMAND_BUFFER, 0x20];
                d.extend_from_slice(h);
                self.command(c, &[], &d, mode)
            }
            SignInput::Raw(data) if data.len() <= CHUNK => {
                let mut d = vec![ACTION_ECC_SIGN, 0x04, 0x00, key_no, INPUT_COMMAND_BUFFER, data.len() as u8];
                d.extend_from_slice(data);
                self.command(c, &[], &d, mode)
            }
            SignInput::Raw(data) => {
                let (first, mut rest) = data.split_at(CHUNK);
                let mut d = vec![ACTION_ECC_SIGN, 0x01, 0x00, key_no, INPUT_COMMAND_BUFFER, first.len() as u8];
                d.extend_from_slice(first);
                self.command(c, &[], &d, mode)?;
                while rest.len() > CHUNK {
                    let mut d = vec![ACTION_ECC_SIGN, 0x02, INPUT_COMMAND_BUFFER, CHUNK as u8];
                    d.extend_from_slice(&rest[..CHUNK]);
                    self.command(c, &[], &d, mode)?;
                    rest = &rest[CHUNK..];
                }
                let mut d = vec![ACTION_ECC_SIGN, 0x03, INPUT_COMMAND_BUFFER, rest.len() as u8];
                d.extend_from_slice(rest);
                self.command(c, &[], &d, mode)
            }
        }
    }

    /// CryptoRequest Echo: the card returns the bytes it was given (1..254).
    pub fn crypto_echo(&mut self, data: &[u8], mode: CommMode) -> Result<Vec<u8>> {
        if data.is_empty() || data.len() > 254 {
            return Err(Error::arg("echo data is 1..254 bytes"));
        }
        let mut d = vec![ACTION_ECHO];
        d.extend_from_slice(data);
        let r = self.command(cmd::CRYPTO_REQUEST, &[], &d, mode)?;
        Ok(if r.first() == Some(&ACTION_ECHO) { r[1..].to_vec() } else { r })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn sign_modes_wire_format() {
        let sig = "AB".repeat(64);
        let mut t = MockTransport::new();
        t.expect_hex(&format!("904C000008 03 04 00 02 F0 02 0102 00"), &format!("{sig}9100"));
        t.expect_hex(&format!("904C000026 03 05 00 02 F0 20 {} 00", "11".repeat(32)), &format!("{sig}9100"));
        // 300 bytes: init (E0) + finalize (0x4C = 76 bytes)
        t.expect_hex(&format!("904C0000E6 03 01 00 02 F0 E0 {} 00", "22".repeat(0xE0)), "9100");
        t.expect_hex(&format!("904C000050 03 03 F0 4C {} 00", "22".repeat(0x4C)), &format!("{sig}9100"));
        t.expect_hex("904C000004 FD 01 02 03 00", "FD 010203 9100");
        let mut card = Card::new(t);
        assert_eq!(card.crypto_ecc_sign(2, SignInput::Raw(&[1, 2]), CommMode::Mac).unwrap().len(), 64);
        assert_eq!(card.crypto_ecc_sign(2, SignInput::Hash(&[0x11; 32]), CommMode::Mac).unwrap().len(), 64);
        assert_eq!(card.crypto_ecc_sign(2, SignInput::Raw(&[0x22; 300]), CommMode::Mac).unwrap().len(), 64);
        assert_eq!(card.crypto_echo(&[1, 2, 3], CommMode::Mac).unwrap(), vec![1, 2, 3]);
        assert!(card.crypto_ecc_sign(2, SignInput::Hash(&[0; 31]), CommMode::Mac).is_err());
        assert!(card.crypto_echo(&[], CommMode::Mac).is_err());
    }
}
