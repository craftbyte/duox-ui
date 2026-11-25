//! Minimal BER-TLV helpers (one-byte tags, definite lengths up to 65535).

use crate::error::{Error, Result};

pub fn encode(tag: u8, value: &[u8]) -> Vec<u8> {
    let n = value.len();
    let mut v = vec![tag];
    if n < 0x80 {
        v.push(n as u8);
    } else if n < 0x100 {
        v.extend([0x81, n as u8]);
    } else {
        v.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    v.extend_from_slice(value);
    v
}

/// Parse one TLV at `pos`; returns `(tag, value, next_pos)`.
pub fn read(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize)> {
    let bad = || Error::protocol("malformed TLV in card response");
    let tag = *data.get(pos).ok_or_else(bad)?;
    let first = *data.get(pos + 1).ok_or_else(bad)?;
    let mut p = pos + 2;
    let mut n = first as usize;
    if first & 0x80 != 0 {
        let k = (first & 0x7F) as usize;
        if k > 3 {
            return Err(bad());
        }
        let bytes = data.get(p..p + k).ok_or_else(bad)?;
        n = bytes.iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        p += k;
    }
    let value = data.get(p..p + n).ok_or_else(bad)?;
    Ok((tag, value, p + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_lengths() {
        for n in [0usize, 1, 127, 128, 255, 256, 700] {
            let v = vec![0xAB; n];
            let t = encode(0x7C, &v);
            let (tag, val, end) = read(&t, 0).unwrap();
            assert_eq!((tag, val, end), (0x7C, &v[..], t.len()));
        }
    }

    #[test]
    fn truncated_is_error() {
        assert!(read(&[0x7C, 0x05, 1, 2], 0).is_err());
        assert!(read(&[0x7C], 0).is_err());
        assert!(read(&[0x7C, 0x85, 1, 2, 3, 4, 5], 0).is_err());
    }
}
