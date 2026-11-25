//! ECDSA signature encodings: the card works with raw `r || s` (64 bytes), certificates carry the
//! `Ecdsa-Sig-Value` SEQUENCE of RFC 3279 (7.10.2.1).

use super::der::{self, tag, Reader};
use super::error::{PkiError, Result};

/// `r || s` (64 bytes) to `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn raw_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() != 64 {
        return Err(PkiError::Der(format!("raw ECDSA signature must be 64 bytes, got {}", raw.len())));
    }
    Ok(der::sequence(&[&der::integer_unsigned(&raw[..32]), &der::integer_unsigned(&raw[32..])]))
}

/// `SEQUENCE { INTEGER r, INTEGER s }` to `r || s` (64 bytes). Rejects anything else, including components
/// that are zero or longer than 32 bytes.
pub fn der_to_raw(sig: &[u8]) -> Result<Vec<u8>> {
    let seq = der::parse_single(sig)?;
    seq.expect_tag(tag::SEQUENCE, "Ecdsa-Sig-Value")?;
    let mut r = Reader::new(seq.value);
    let ri = r.read()?.unsigned_integer()?;
    let si = r.read()?.unsigned_integer()?;
    r.finish("Ecdsa-Sig-Value")?;
    let mut out = vec![0u8; 64];
    for (i, comp) in [ri, si].into_iter().enumerate() {
        if comp.len() > 32 || comp.iter().all(|&b| b == 0) {
            return Err(PkiError::Der("ECDSA signature component out of range".into()));
        }
        out[i * 32 + 32 - comp.len()..(i + 1) * 32].copy_from_slice(comp);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_padding_and_short_values() {
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80; // needs a 0x00 sign byte
        raw[63] = 1;
        raw[32] = 0; // short s: leading zero byte stripped
        raw[33] = 0x7F;
        let der = raw_to_der(&raw).unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(der_to_raw(&der).unwrap(), raw);
    }

    #[test]
    fn rejects_malformed() {
        assert!(der_to_raw(&[0x30, 0x00]).is_err());
        assert!(der_to_raw(&[0x04, 0x00]).is_err());
        assert!(raw_to_der(&[0; 63]).is_err());
        // zero component
        assert!(der_to_raw(&[0x30, 0x06, 2, 1, 0, 2, 1, 1]).is_err());
        // 33 significant bytes
        let big = der::sequence(&[&der::integer_unsigned(&[1u8; 33]), &der::integer_u64(1)]);
        assert!(der_to_raw(&big).is_err());
    }
}
