//! X.501 distinguished names (`ReaderName` of 7.10.2.1).
//!
//! The card compares issuer and subject names as encoded bytes (7.10.2.2, step 3), so a [`Name`] keeps its exact
//! DER encoding and equality is byte equality.

use super::der::{self, tag, Oid, Reader};
use super::error::{PkiError, Result};

/// Attribute type OIDs (content octets).
pub mod attr {
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    pub const SERIAL_NUMBER: &[u8] = &[0x55, 0x04, 0x05];
    pub const COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
    pub const LOCALITY: &[u8] = &[0x55, 0x04, 0x07];
    pub const STATE: &[u8] = &[0x55, 0x04, 0x08];
    pub const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0A];
    pub const ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0B];
    pub const DESCRIPTION: &[u8] = &[0x55, 0x04, 0x0D];
    pub const UNIQUE_IDENTIFIER: &[u8] = &[0x55, 0x04, 0x2D];
}

/// One `AttributeTypeAndValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub oid: Oid,
    /// ASN.1 tag of the value (a string type, or something else such as a BIT STRING).
    pub value_tag: u8,
    /// Content octets of the value.
    pub value: Vec<u8>,
}

impl Attribute {
    fn is_text(&self) -> bool {
        matches!(
            self.value_tag,
            tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING | tag::TELETEX_STRING | tag::BMP_STRING
        )
    }

    /// The value as text. String types are decoded; anything else is shown as `#` plus the hex of its encoding
    /// (the RFC 4514 form).
    pub fn text(&self) -> String {
        match self.value_tag {
            tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING => {
                String::from_utf8_lossy(&self.value).into_owned()
            }
            tag::TELETEX_STRING => self.value.iter().map(|&b| b as char).collect(),
            tag::BMP_STRING => char::decode_utf16(self.value.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])))
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .collect(),
            _ => format!("#{}", hex::encode_upper(der::tlv(self.value_tag, &self.value))),
        }
    }
}

/// A distinguished name: a sequence of relative distinguished names, each a set of attributes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name {
    der: Vec<u8>,
}

impl Name {
    /// Parse a DER `Name` (a complete SEQUENCE).
    pub fn from_der(data: &[u8]) -> Result<Name> {
        let n = Name { der: data.to_vec() };
        n.rdns()?; // validate
        Ok(n)
    }

    /// Build from attributes, one RDN each, in the given order, as UTF8String values.
    pub fn from_attributes(attrs: &[(&[u8], &str)]) -> Name {
        let rdns: Vec<Vec<u8>> = attrs
            .iter()
            .map(|(oid, text)| {
                let ava = der::sequence(&[&Oid::from_content(oid).to_der(), &der::utf8_string(text)]);
                der::set(&[&ava])
            })
            .collect();
        let refs: Vec<&[u8]> = rdns.iter().map(Vec::as_slice).collect();
        Name { der: der::sequence(&refs) }
    }

    /// The names the store issues: optional organization, then common name.
    pub fn with_common_name(common_name: &str, organization: &str) -> Name {
        if organization.is_empty() {
            Name::from_attributes(&[(attr::COMMON_NAME, common_name)])
        } else {
            Name::from_attributes(&[(attr::ORGANIZATION, organization), (attr::COMMON_NAME, common_name)])
        }
    }

    /// The DER encoding (as the card's CARootKey issuer parameter expects it).
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// Relative distinguished names in encoded order.
    pub fn rdns(&self) -> Result<Vec<Vec<Attribute>>> {
        let seq = der::parse_single(&self.der)?;
        seq.expect_tag(tag::SEQUENCE, "Name")?;
        let mut out = Vec::new();
        let mut r = seq.reader();
        while !r.is_empty() {
            let set = r.expect(tag::SET, "RDN")?;
            let mut attrs = Vec::new();
            let mut sr = set.reader();
            while !sr.is_empty() {
                let ava = sr.expect(tag::SEQUENCE, "AttributeTypeAndValue")?;
                let mut ar = Reader::new(ava.value);
                let oid = ar.expect(tag::OID, "attribute type")?.oid()?;
                let v = ar.read()?;
                ar.finish("AttributeTypeAndValue")?;
                attrs.push(Attribute { oid, value_tag: v.tag, value: v.value.to_vec() });
            }
            if attrs.is_empty() {
                return Err(PkiError::Der("empty RDN".into()));
            }
            out.push(attrs);
        }
        Ok(out)
    }

    /// First common name, if any.
    pub fn common_name(&self) -> Option<String> {
        self.rdns()
            .ok()?
            .into_iter()
            .flatten()
            .find(|a| a.oid.is(attr::COMMON_NAME))
            .map(|a| a.text())
    }

    /// RFC 4514 string (most specific RDN first), for example `CN=Reader 1,O=Acme`.
    pub fn rfc4514(&self) -> String {
        let Ok(rdns) = self.rdns() else { return String::from("<invalid name>") };
        rdns.iter()
            .rev()
            .map(|rdn| {
                rdn.iter()
                    .map(|a| {
                        let v = if a.is_text() { escape_value(&a.text()) } else { a.text() };
                        format!("{}={v}", short_name(&a.oid))
                    })
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.rfc4514())
    }
}

fn short_name(oid: &Oid) -> String {
    match oid.content() {
        attr::COMMON_NAME => "CN".into(),
        attr::COUNTRY => "C".into(),
        attr::LOCALITY => "L".into(),
        attr::STATE => "ST".into(),
        attr::ORGANIZATION => "O".into(),
        attr::ORGANIZATIONAL_UNIT => "OU".into(),
        [0x55, 0x04, 0x09] => "STREET".into(),
        _ => oid.to_dotted(),
    }
}

fn escape_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let chars: Vec<char> = v.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' ' if i == 0 || i + 1 == chars.len() => out.push_str("\\ "),
            '#' if i == 0 => out.push_str("\\#"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_and_print() {
        let n = Name::with_common_name("Reader 1", "Acme, Inc");
        let back = Name::from_der(n.to_der()).unwrap();
        assert_eq!(n, back);
        assert_eq!(n.rfc4514(), "CN=Reader 1,O=Acme\\, Inc");
        assert_eq!(n.common_name().as_deref(), Some("Reader 1"));
        assert_ne!(n, Name::with_common_name("Reader 1", ""));
        assert_eq!(Name::with_common_name("X", "").rfc4514(), "CN=X");
    }

    #[test]
    fn non_string_values_print_as_hex() {
        let ava = der::sequence(&[&Oid::from_content(attr::UNIQUE_IDENTIFIER).to_der(), &der::bit_string(&[0xAB])]);
        let n = Name::from_der(&der::sequence(&[&der::set(&[&ava])])).unwrap();
        assert_eq!(n.rfc4514(), "2.5.4.45=#030200AB");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Name::from_der(&[0x30, 0x01, 0x00]).is_err());
        assert!(Name::from_der(&[0x04, 0x00]).is_err());
    }
}
