//! PEM armour (RFC 7468) and the Base64 it needs.

use super::error::{PkiError, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard Base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard Base64; whitespace is ignored, padding is required to be correct when present.
pub fn base64_decode(text: &str) -> Result<Vec<u8>> {
    let mut vals = Vec::with_capacity(text.len());
    let mut pad = 0;
    for c in text.bytes() {
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => {}
            b'=' => pad += 1,
            _ if pad > 0 => return Err(PkiError::Pem("data after Base64 padding".into())),
            b'A'..=b'Z' => vals.push(c - b'A'),
            b'a'..=b'z' => vals.push(c - b'a' + 26),
            b'0'..=b'9' => vals.push(c - b'0' + 52),
            b'+' => vals.push(62),
            b'/' => vals.push(63),
            _ => return Err(PkiError::Pem(format!("invalid Base64 character 0x{c:02X}"))),
        }
    }
    if pad > 2 || (vals.len() + pad) % 4 != 0 || vals.len() % 4 == 1 {
        return Err(PkiError::Pem("bad Base64 length".into()));
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let mut n = 0u32;
        for (i, &v) in chunk.iter().enumerate() {
            n |= u32::from(v) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// One decoded PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The text between `-----BEGIN ` and `-----`, for example `CERTIFICATE` or `EC PRIVATE KEY`.
    pub label: String,
    pub der: Vec<u8>,
}

/// Wrap DER in PEM armour with 64 character lines and a final newline.
pub fn encode(label: &str, der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// True when the text starts (after whitespace) with a PEM boundary.
pub fn looks_like_pem(data: &[u8]) -> bool {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    data[start..].starts_with(b"-----BEGIN")
}

/// Extract every PEM block of the text. Text between blocks is ignored. Legacy encapsulated headers
/// (`Proc-Type`, `DEK-Info`) are rejected rather than silently misread.
pub fn decode_all(text: &str) -> Result<Vec<PemBlock>> {
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut body = String::new();
        let mut closed = false;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end {
                closed = true;
                break;
            }
            if l.contains(':') {
                return Err(PkiError::Pem(format!("{label}: encapsulated headers are not supported")));
            }
            body.push_str(l);
        }
        if !closed {
            return Err(PkiError::Pem(format!("{label}: missing END line")));
        }
        blocks.push(PemBlock { label: label.to_string(), der: base64_decode(&body)? });
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        for (raw, enc) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(raw), enc);
            assert_eq!(base64_decode(enc).unwrap(), raw);
        }
        assert!(base64_decode("Zm9").is_err());
        assert!(base64_decode("Zm9v!").is_err());
    }

    #[test]
    fn pem_roundtrip_and_multiple_blocks() {
        let a = vec![1u8; 100];
        let b = vec![2u8; 5];
        let text = format!("junk\n{}\nmore junk\n{}", encode("CERTIFICATE", &a), encode("X", &b));
        let blocks = decode_all(&text).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], PemBlock { label: "CERTIFICATE".into(), der: a });
        assert_eq!(blocks[1].label, "X");
        assert!(decode_all("-----BEGIN X-----\nAAAA\n").is_err());
        assert!(decode_all("-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END X-----").is_err());
    }
}
