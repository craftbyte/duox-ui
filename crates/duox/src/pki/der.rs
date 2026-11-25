//! A small ASN.1 DER encoder and parser: exactly what the card's certificate profile (7.10.2.1) needs.
//!
//! Only single-byte tags are supported, lengths must be minimal and definite (as DER requires).

use super::error::{der_err, PkiError, Result};

/// Universal and context tags used by the profile.
pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const TELETEX_STRING: u8 = 0x14;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const BMP_STRING: u8 = 0x1E;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    /// `[n] EXPLICIT` / constructed context-specific tag.
    pub const fn context(n: u8) -> u8 {
        0xA0 | n
    }
    /// `[n] IMPLICIT` primitive context-specific tag.
    pub const fn context_primitive(n: u8) -> u8 {
        0x80 | n
    }
}

/// Object identifier values (content octets, without tag and length) used by the certificate profile.
pub mod oids {
    /// id-ecPublicKey, 1.2.840.10045.2.1
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    /// secp256r1 / NIST P-256, 1.2.840.10045.3.1.7
    pub const SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    /// brainpoolP256r1, 1.3.36.3.3.2.8.1.1.7
    pub const BRAINPOOL_P256R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
    /// ecdsa-with-SHA256, 1.2.840.10045.4.3.2
    pub const ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    /// NXP access-rights extension, 1.3.6.1.4.1.28137.64.1
    pub const NXP_ACCESS_RIGHTS: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xDB, 0x69, 0x40, 0x01];
    /// id-ce-basicConstraints, 2.5.29.19
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
    /// PBES2, 1.2.840.113549.1.5.13
    pub const PBES2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
    /// PBKDF2, 1.2.840.113549.1.5.12
    pub const PBKDF2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
    /// hmacWithSHA1, 1.2.840.113549.2.7
    pub const HMAC_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07];
    /// hmacWithSHA256, 1.2.840.113549.2.9
    pub const HMAC_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09];
    /// hmacWithSHA512, 1.2.840.113549.2.11
    pub const HMAC_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B];
    /// aes128-CBC, 2.16.840.1.101.3.4.1.2
    pub const AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
    /// aes256-CBC, 2.16.840.1.101.3.4.1.42
    pub const AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];
}

/// An object identifier, held as its DER content octets.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(Vec<u8>);

impl Oid {
    pub fn from_content(content: &[u8]) -> Oid {
        Oid(content.to_vec())
    }

    /// Parse dotted notation such as `1.2.840.10045.2.1`.
    pub fn from_dotted(text: &str) -> Result<Oid> {
        let arcs: Vec<u64> = text
            .split('.')
            .map(|p| p.parse::<u64>().map_err(|_| PkiError::Der(format!("bad OID '{text}'"))))
            .collect::<Result<_>>()?;
        if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
            return der_err(format!("bad OID '{text}'"));
        }
        let mut out = Vec::new();
        let first = arcs[0] * 40 + arcs[1];
        for &v in std::iter::once(&first).chain(arcs[2..].iter()) {
            let mut groups = vec![(v & 0x7F) as u8];
            let mut rest = v >> 7;
            while rest > 0 {
                groups.push((rest & 0x7F) as u8 | 0x80);
                rest >>= 7;
            }
            groups.reverse();
            out.extend(groups);
        }
        Ok(Oid(out))
    }

    pub fn content(&self) -> &[u8] {
        &self.0
    }

    /// Compare with a constant from [`oids`].
    pub fn is(&self, content: &[u8]) -> bool {
        self.0 == content
    }

    /// Dotted notation.
    pub fn to_dotted(&self) -> String {
        let mut arcs: Vec<u64> = Vec::new();
        let mut acc: u64 = 0;
        for &b in &self.0 {
            acc = (acc << 7) | u64::from(b & 0x7F);
            if b & 0x80 == 0 {
                if arcs.is_empty() {
                    let (a, b) = if acc < 40 {
                        (0, acc)
                    } else if acc < 80 {
                        (1, acc - 40)
                    } else {
                        (2, acc - 80)
                    };
                    arcs.push(a);
                    arcs.push(b);
                } else {
                    arcs.push(acc);
                }
                acc = 0;
            }
        }
        arcs.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
    }

    /// Full TLV encoding.
    pub fn to_der(&self) -> Vec<u8> {
        tlv(tag::OID, &self.0)
    }
}

impl std::fmt::Debug for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Oid({})", self.to_dotted())
    }
}
impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_dotted())
    }
}

// ------------------------------------------------------------------ encoder
/// DER length octets.
pub fn encode_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let mut v = vec![0x80 | (bytes.len() - skip) as u8];
        v.extend_from_slice(&bytes[skip..]);
        v
    }
}

/// Tag, length, content.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 4);
    v.push(tag);
    v.extend(encode_length(content.len()));
    v.extend_from_slice(content);
    v
}

/// SEQUENCE of already encoded parts.
pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

/// SET of already encoded parts (no sorting; callers only build single element sets).
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SET, &parts.concat())
}

/// Non-negative INTEGER from big-endian magnitude bytes (leading zeros are removed, a 0x00 is added when needed).
pub fn integer_unsigned(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude.iter().take_while(|&&b| b == 0).count();
    let m = &magnitude[skip..];
    let mut content = Vec::with_capacity(m.len() + 1);
    if m.is_empty() || m[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(m);
    tlv(tag::INTEGER, &content)
}

pub fn integer_u64(v: u64) -> Vec<u8> {
    integer_unsigned(&v.to_be_bytes())
}

pub fn boolean(v: bool) -> Vec<u8> {
    tlv(tag::BOOLEAN, &[if v { 0xFF } else { 0x00 }])
}

pub fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, content)
}

/// BIT STRING with no unused bits.
pub fn bit_string(content: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(content.len() + 1);
    c.push(0);
    c.extend_from_slice(content);
    tlv(tag::BIT_STRING, &c)
}

pub fn utf8_string(s: &str) -> Vec<u8> {
    tlv(tag::UTF8_STRING, s.as_bytes())
}

pub fn null() -> Vec<u8> {
    tlv(tag::NULL, &[])
}

// ------------------------------------------------------------------- parser
/// One decoded element.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    /// The complete encoding (tag, length and value).
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// A reader over the content of a constructed element.
    pub fn reader(&self) -> Reader<'a> {
        Reader::new(self.value)
    }

    pub fn expect_tag(&self, tag: u8, what: &str) -> Result<()> {
        if self.tag != tag {
            return der_err(format!("{what}: expected tag 0x{tag:02X}, found 0x{:02X}", self.tag));
        }
        Ok(())
    }

    /// Content of a non-negative INTEGER without the sign padding byte.
    pub fn unsigned_integer(&self) -> Result<&'a [u8]> {
        self.expect_tag(tag::INTEGER, "INTEGER")?;
        let v = self.value;
        if v.is_empty() {
            return der_err("empty INTEGER");
        }
        if v.len() > 1 && ((v[0] == 0 && v[1] & 0x80 == 0) || (v[0] == 0xFF && v[1] & 0x80 != 0)) {
            return der_err("INTEGER is not minimally encoded");
        }
        if v[0] & 0x80 != 0 {
            return der_err("INTEGER is negative");
        }
        Ok(if v[0] == 0 && v.len() > 1 { &v[1..] } else { v })
    }

    pub fn oid(&self) -> Result<Oid> {
        self.expect_tag(tag::OID, "OBJECT IDENTIFIER")?;
        if self.value.is_empty() || self.value[self.value.len() - 1] & 0x80 != 0 {
            return der_err("malformed OBJECT IDENTIFIER");
        }
        Ok(Oid::from_content(self.value))
    }

    /// Content of a BIT STRING with no unused bits.
    pub fn bit_string(&self) -> Result<&'a [u8]> {
        self.expect_tag(tag::BIT_STRING, "BIT STRING")?;
        match self.value.split_first() {
            Some((0, rest)) => Ok(rest),
            _ => der_err("BIT STRING with unused bits or empty"),
        }
    }

    pub fn boolean(&self) -> Result<bool> {
        self.expect_tag(tag::BOOLEAN, "BOOLEAN")?;
        match self.value {
            [0x00] => Ok(false),
            [0xFF] => Ok(true),
            _ => der_err("malformed BOOLEAN"),
        }
    }
}

/// Sequential reader over a run of DER elements.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Read the next element.
    pub fn read(&mut self) -> Result<Tlv<'a>> {
        let (t, hdr, len) = parse_header(self.data)?;
        let total = hdr + len;
        if self.data.len() < total {
            return der_err("element runs past the end of its container");
        }
        let (raw, rest) = self.data.split_at(total);
        self.data = rest;
        Ok(Tlv { tag: t, value: &raw[hdr..], raw })
    }

    /// Read the next element and require a tag.
    pub fn expect(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>> {
        let t = self.read().map_err(|e| PkiError::Der(format!("{what}: {e}")))?;
        t.expect_tag(tag, what)?;
        Ok(t)
    }

    /// Read the next element only if it has this tag.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.read()?))
        } else {
            Ok(None)
        }
    }

    /// Fail if elements remain.
    pub fn finish(&self, what: &str) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            der_err(format!("{what}: trailing data"))
        }
    }
}

/// Returns (tag, header length, content length).
fn parse_header(data: &[u8]) -> Result<(u8, usize, usize)> {
    if data.len() < 2 {
        return der_err("truncated element");
    }
    let t = data[0];
    if t & 0x1F == 0x1F {
        return der_err("multi-byte tags are not supported");
    }
    let b = data[1];
    if b < 0x80 {
        return Ok((t, 2, b as usize));
    }
    let n = (b & 0x7F) as usize;
    if n == 0 {
        return der_err("indefinite length is not DER");
    }
    if n > 4 || data.len() < 2 + n {
        return der_err("bad length encoding");
    }
    let len = data[2..2 + n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
    if data[2] == 0 || len < 0x80 {
        return der_err("length is not minimally encoded");
    }
    Ok((t, 2 + n, len))
}

/// Parse exactly one element that fills `data`.
pub fn parse_single(data: &[u8]) -> Result<Tlv<'_>> {
    let mut r = Reader::new(data);
    let t = r.read()?;
    r.finish("DER value")?;
    Ok(t)
}

/// Split concatenated DER SEQUENCEs (a certificate chain). Stops silently at the first byte that does not start
/// a complete SEQUENCE; the caller decides whether trailing bytes matter.
pub fn split_sequences(blob: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0;
    while blob.len() >= pos + 2 && blob[pos] == tag::SEQUENCE {
        match parse_header(&blob[pos..]) {
            Ok((_, hdr, len)) if pos + hdr + len <= blob.len() => {
                out.push(&blob[pos..pos + hdr + len]);
                pos += hdr + len;
            }
            _ => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_constants_match_dotted_notation() {
        for (dotted, content) in [
            ("1.2.840.10045.2.1", oids::EC_PUBLIC_KEY),
            ("1.2.840.10045.3.1.7", oids::SECP256R1),
            ("1.3.36.3.3.2.8.1.1.7", oids::BRAINPOOL_P256R1),
            ("1.2.840.10045.4.3.2", oids::ECDSA_WITH_SHA256),
            ("1.3.6.1.4.1.28137.64.1", oids::NXP_ACCESS_RIGHTS),
            ("2.5.29.19", oids::BASIC_CONSTRAINTS),
            ("1.2.840.113549.1.5.13", oids::PBES2),
            ("1.2.840.113549.1.5.12", oids::PBKDF2),
            ("1.2.840.113549.2.7", oids::HMAC_SHA1),
            ("1.2.840.113549.2.9", oids::HMAC_SHA256),
            ("1.2.840.113549.2.11", oids::HMAC_SHA512),
            ("2.16.840.1.101.3.4.1.2", oids::AES128_CBC),
            ("2.16.840.1.101.3.4.1.42", oids::AES256_CBC),
        ] {
            let oid = Oid::from_dotted(dotted).unwrap();
            assert_eq!(oid.content(), content, "{dotted}");
            assert_eq!(oid.to_dotted(), dotted);
        }
    }

    #[test]
    fn lengths_and_integers() {
        assert_eq!(encode_length(0x7F), [0x7F]);
        assert_eq!(encode_length(0x80), [0x81, 0x80]);
        assert_eq!(encode_length(0x1234), [0x82, 0x12, 0x34]);
        assert_eq!(integer_u64(0), [2, 1, 0]);
        assert_eq!(integer_u64(0x80), [2, 2, 0, 0x80]);
        assert_eq!(integer_u64(0x7FFF_FFFF), [2, 4, 0x7F, 0xFF, 0xFF, 0xFF]);
        assert_eq!(integer_unsigned(&[0, 0, 5]), [2, 1, 5]);
        let long = tlv(tag::OCTET_STRING, &[7u8; 300]);
        let t = parse_single(&long).unwrap();
        assert_eq!(t.value.len(), 300);
    }

    #[test]
    fn parser_is_strict() {
        assert!(parse_single(&[0x30, 0x80, 0, 0]).is_err()); // indefinite
        assert!(parse_single(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).is_err()); // non-minimal length
        assert!(parse_single(&[0x04, 0x02, 1]).is_err()); // truncated
        assert!(parse_single(&[0x04, 0x01, 1, 9]).is_err()); // trailing
        let neg = parse_single(&[2, 1, 0x80]).unwrap();
        assert!(neg.unsigned_integer().is_err());
        let pad = parse_single(&[2, 2, 0, 0x01]).unwrap();
        assert!(pad.unsigned_integer().is_err());
        assert_eq!(parse_single(&[2, 2, 0, 0x80]).unwrap().unsigned_integer().unwrap(), [0x80]);
    }

    #[test]
    fn split_chain() {
        let a = sequence(&[&integer_u64(1)]);
        let b = sequence(&[&integer_u64(2)]);
        let blob = [a.clone(), b.clone(), vec![0xFF, 0xFF]].concat();
        let parts = split_sequences(&blob);
        assert_eq!(parts, vec![&a[..], &b[..]]);
    }
}
