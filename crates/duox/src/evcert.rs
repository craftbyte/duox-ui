//! EV charging certificate in the GlobalPlatform tag layout of VDE-AR-E 2532-100 (data sheet Table 48/49).
//!
//! The certificate is a `7F21` TLV holding serial / CA identifier / subject / key usage / validity /
//! the holder's public key and an ECDSA signature (tag `5F37`, r || s) of the CA over all preceding
//! TLVs.

use crate::crypto::{self, CryptoError, PrivKey, PubKey};
use thiserror::Error;

/// DF name of the EV charging application.
pub const DF_NAME: [u8; 16] = [0xA0, 0x00, 0x00, 0x08, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
/// Application ID of the EV charging application.
pub const AID: u32 = 0x1010F6;

const TAG_CERT: u32 = 0x7F21;
const TAG_SERIAL: u32 = 0x93;
const TAG_CA_ID: u32 = 0x42;
const TAG_SUBJECT: u32 = 0x5F20;
const TAG_KEY_USAGE: u32 = 0x95;
const TAG_EFFECTIVE: u32 = 0x5F25;
const TAG_EXPIRY: u32 = 0x5F24;
const TAG_PROFILE: u32 = 0x45;
const TAG_PUBKEY_TEMPLATE: u32 = 0x7F49;
const TAG_PUBKEY: u32 = 0xB0;
const TAG_KEY_PARAM: u32 = 0xF0;
const TAG_SIGNATURE: u32 = 0x5F37;

/// Errors of the EV certificate module.
#[derive(Debug, Error)]
pub enum EvCertError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("the CA identifier is 14 decimal digits")]
    CaId,
    #[error("invalid date {0:04}-{1:02}-{2:02}")]
    Date(u16, u8, u8),
    #[error("curve 0x{0:02X} has no key parameter reference in an EV charging certificate")]
    Curve(u8),
    #[error("not an EV charging certificate (tag 7F21 expected)")]
    NotACertificate,
    #[error("EV charging certificate truncated or malformed")]
    Malformed,
    #[error("EV charging certificate lacks tag {0:X}")]
    MissingTag(u32),
}

type Result<T> = std::result::Result<T, EvCertError>;

/// Calendar date (stored as packed BCD YYYYMMDD in the certificate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl Date {
    /// Validated constructor.
    pub fn new(year: u16, month: u8, day: u8) -> Result<Date> {
        let dim = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
            2 => 28,
            _ => return Err(EvCertError::Date(year, month, day)),
        };
        if year > 9999 || day == 0 || day > dim {
            return Err(EvCertError::Date(year, month, day));
        }
        Ok(Date { year, month, day })
    }

    /// Today's date (UTC).
    pub fn today_utc() -> Date {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let z = (secs / 86400) as i64 + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = (yoe + era * 400 + i64::from(month <= 2)) as u16;
        Date { year, month, day }
    }

    /// The same date `years` later (29 February becomes 28 February where needed).
    pub fn plus_years(self, years: u16) -> Result<Date> {
        let year = self.year.saturating_add(years);
        Date::new(year, self.month, self.day).or_else(|_| Date::new(year, self.month, 28))
    }

    /// Packed BCD YYYYMMDD.
    pub fn to_bcd(self) -> [u8; 4] {
        let bcd = |v: u8| (v / 10) << 4 | (v % 10);
        [bcd((self.year / 100) as u8), bcd((self.year % 100) as u8), bcd(self.month), bcd(self.day)]
    }

    /// Parse packed BCD YYYYMMDD.
    pub fn from_bcd(b: &[u8]) -> Option<Date> {
        let un = |v: u8| if v >> 4 > 9 || v & 0xF > 9 { None } else { Some((v >> 4) * 10 + (v & 0xF)) };
        let [a, b, c, d] = <[u8; 4]>::try_from(b).ok()?;
        let year = u16::from(un(a)?) * 100 + u16::from(un(b)?);
        Date::new(year, un(c)?, un(d)?).ok()
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Key parameter reference (tag F0) for a CurveID.
pub fn key_param(curve_id: u8) -> Option<u8> {
    match curve_id {
        crypto::CURVE_P256 => Some(0x00),
        crypto::CURVE_BP256 => Some(0x03),
        _ => None,
    }
}

/// CurveID for a key parameter reference.
pub fn param_curve(param: u8) -> Option<u8> {
    match param {
        0x00 => Some(crypto::CURVE_P256),
        0x03 => Some(crypto::CURVE_BP256),
        _ => None,
    }
}

fn tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = if tag > 0xFF { (tag as u16).to_be_bytes().to_vec() } else { vec![tag as u8] };
    let n = value.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(value);
    out
}

/// One parsed TLV: tag, value and the raw encoding (tag + length + value).
struct Tlv<'a> {
    tag: u32,
    value: &'a [u8],
    raw: &'a [u8],
}

/// Parse one TLV header at the start of `data`; returns (tag, header length, value length).
fn tlv_header(data: &[u8]) -> Result<(u32, usize, usize)> {
    let mut pos = 0;
    let mut tag = u32::from(*data.first().ok_or(EvCertError::Malformed)?);
    pos += 1;
    if tag & 0x1F == 0x1F {
        tag = (tag << 8) | u32::from(*data.get(pos).ok_or(EvCertError::Malformed)?);
        pos += 1;
    }
    let first = *data.get(pos).ok_or(EvCertError::Malformed)?;
    pos += 1;
    let n = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let k = usize::from(first & 0x7F);
        if k == 0 || k > 3 {
            return Err(EvCertError::Malformed);
        }
        let b = data.get(pos..pos + k).ok_or(EvCertError::Malformed)?;
        pos += k;
        b.iter().fold(0usize, |a, &x| (a << 8) | usize::from(x))
    };
    Ok((tag, pos, n))
}

fn parse_tlvs(mut data: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let (tag, h, n) = tlv_header(data)?;
        let end = h.checked_add(n).filter(|&e| e <= data.len()).ok_or(EvCertError::Malformed)?;
        out.push(Tlv { tag, value: &data[h..end], raw: &data[..end] });
        data = &data[end..];
    }
    Ok(out)
}

/// Issue an EV charging certificate. `ca_id` is the 14-digit CA identifier; `uid` is both serial
/// and subject; `public_key` is the 65-byte uncompressed holder key on curve `curve_id`.
pub fn build(
    ca_key: &PrivKey,
    ca_id: &str,
    uid: &[u8],
    public_key: &[u8],
    curve_id: u8,
    effective: Date,
    years: u16,
) -> Result<Vec<u8>> {
    if ca_id.len() != 14 || !ca_id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(EvCertError::CaId);
    }
    let ca_bytes = hex::decode(ca_id).map_err(|_| EvCertError::CaId)?;
    let param = key_param(curve_id).ok_or(EvCertError::Curve(curve_id))?;
    let expiry = effective.plus_years(years)?;
    let mut body = Vec::new();
    body.extend(tlv(TAG_SERIAL, uid));
    body.extend(tlv(TAG_CA_ID, &ca_bytes));
    body.extend(tlv(TAG_SUBJECT, uid));
    body.extend(tlv(TAG_KEY_USAGE, &[0x02, 0x00]));
    body.extend(tlv(TAG_EFFECTIVE, &effective.to_bcd()));
    body.extend(tlv(TAG_EXPIRY, &expiry.to_bcd()));
    body.extend(tlv(TAG_PROFILE, &[0x00]));
    let mut pk = tlv(TAG_PUBKEY, public_key);
    pk.extend(tlv(TAG_KEY_PARAM, &[param]));
    body.extend(tlv(TAG_PUBKEY_TEMPLATE, &pk));
    let sig = ca_key.sign_raw(&body)?;
    body.extend(tlv(TAG_SIGNATURE, &sig));
    Ok(tlv(TAG_CERT, &body))
}

/// A parsed EV charging certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvCertificate {
    pub serial: Vec<u8>,
    /// 14-digit CA identifier as hex digits.
    pub ca_id: String,
    pub subject: Vec<u8>,
    pub key_usage: Vec<u8>,
    pub effective: Option<Date>,
    pub expiry: Option<Date>,
    /// 65-byte uncompressed public key (tag B0).
    pub public_key: Vec<u8>,
    /// CurveID, or `None` for an unknown key parameter reference.
    pub curve: Option<u8>,
    /// r || s.
    pub signature: Vec<u8>,
    /// The bytes covered by the signature (all TLVs before the signature).
    pub signed: Vec<u8>,
    /// Total length of the certificate within the blob (excluding trailing file padding).
    pub length: usize,
}

impl EvCertificate {
    /// Parse a certificate (trailing file padding is ignored).
    pub fn parse(blob: &[u8]) -> Result<EvCertificate> {
        if blob.len() < 2 || blob[..2] != [0x7F, 0x21] {
            return Err(EvCertError::NotACertificate);
        }
        let (tag, h, n) = tlv_header(blob)?;
        debug_assert_eq!(tag, TAG_CERT);
        let inner = blob.get(h..h + n).ok_or(EvCertError::Malformed)?;
        let items = parse_tlvs(inner)?;
        let get = |t: u32| items.iter().find(|i| i.tag == t).map(|i| i.value);
        let need = |t: u32| get(t).ok_or(EvCertError::MissingTag(t));
        let signed: Vec<u8> = items.iter().filter(|i| i.tag != TAG_SIGNATURE).flat_map(|i| i.raw.iter().copied()).collect();
        let template = need(TAG_PUBKEY_TEMPLATE)?;
        let pk = parse_tlvs(template)?;
        let pget = |t: u32| pk.iter().find(|i| i.tag == t).map(|i| i.value);
        Ok(EvCertificate {
            serial: need(TAG_SERIAL)?.to_vec(),
            ca_id: hex::encode(need(TAG_CA_ID)?),
            subject: need(TAG_SUBJECT)?.to_vec(),
            key_usage: get(TAG_KEY_USAGE).unwrap_or_default().to_vec(),
            effective: get(TAG_EFFECTIVE).and_then(Date::from_bcd),
            expiry: get(TAG_EXPIRY).and_then(Date::from_bcd),
            public_key: pget(TAG_PUBKEY).unwrap_or_default().to_vec(),
            curve: pget(TAG_KEY_PARAM).and_then(|v| v.first().copied()).and_then(param_curve),
            signature: need(TAG_SIGNATURE)?.to_vec(),
            signed,
            length: h + n,
        })
    }

    /// Verify the CA signature.
    pub fn verify(&self, ca_pub: &PubKey) -> bool {
        ca_pub.verify_raw(&self.signature, &self.signed)
    }

    /// The holder's public key as a crypto key object.
    pub fn holder_key(&self) -> Result<PubKey> {
        let curve = self.curve.ok_or(EvCertError::Malformed)?;
        Ok(PubKey::from_bytes(curve, &self.public_key)?)
    }

    /// Human readable description, one line per item.
    pub fn describe(&self) -> Vec<String> {
        let d = |v: Option<Date>| v.map_or("?".to_string(), |d| d.to_string());
        vec![
            format!("Serial / subject  {} / {}", hex::encode_upper(&self.serial), hex::encode_upper(&self.subject)),
            format!("CA identifier     {}", self.ca_id),
            format!("Validity          {} .. {}", d(self.effective), d(self.expiry)),
            format!("Curve             {}", self.curve.map_or("unknown key parameter reference", crypto::curve_name)),
            format!("Public key        {}", hex::encode_upper(&self.public_key)),
            format!("Size              {} bytes", self.length),
        ]
    }
}

/// Verify a certificate blob against the CA public key.
pub fn verify(blob: &[u8], ca_pub: &PubKey) -> Result<bool> {
    Ok(EvCertificate::parse(blob)?.verify(ca_pub))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(curve: u8) -> (PrivKey, PrivKey, Vec<u8>) {
        let ca = crypto::gen_key(curve).unwrap();
        let holder = crypto::gen_key(curve).unwrap();
        let uid = [0x04, 1, 2, 3, 4, 5, 6];
        let cert = build(&ca, "12345678901234", &uid, &holder.public().to_bytes(), curve, Date::new(2025, 2, 28).unwrap(), 20)
            .unwrap();
        (ca, holder, cert)
    }

    #[test]
    fn build_parse_verify_both_curves() {
        for curve in [crypto::CURVE_P256, crypto::CURVE_BP256] {
            let (ca, holder, cert) = issue(curve);
            assert_eq!(&cert[..2], &[0x7F, 0x21]);
            let mut padded = cert.clone();
            padded.resize(cert.len() + 40, 0);
            let p = EvCertificate::parse(&padded).unwrap();
            assert_eq!(p.length, cert.len());
            assert_eq!(p.ca_id, "12345678901234");
            assert_eq!(p.serial, p.subject);
            assert_eq!(p.curve, Some(curve));
            assert_eq!(p.public_key, holder.public().to_bytes());
            assert_eq!(p.effective, Date::new(2025, 2, 28).ok());
            assert_eq!(p.expiry, Date::new(2045, 2, 28).ok());
            assert!(p.verify(&ca.public()));
            assert!(verify(&cert, &ca.public()).unwrap());
            assert!(!p.verify(&holder.public()));
            assert_eq!(p.holder_key().unwrap(), holder.public());
            assert_eq!(p.describe().len(), 6);
        }
    }

    #[test]
    fn tamper_and_malformed() {
        let (ca, _, cert) = issue(crypto::CURVE_P256);
        let mut bad = cert.clone();
        bad[12] ^= 1;
        assert!(!verify(&bad, &ca.public()).unwrap_or(false));
        assert!(matches!(EvCertificate::parse(&[1, 2, 3]), Err(EvCertError::NotACertificate)));
        assert!(EvCertificate::parse(&cert[..cert.len() - 5]).is_err());
        assert!(EvCertificate::parse(&[0x7F, 0x21]).is_err());
        let ca = crypto::gen_key(crypto::CURVE_P256).unwrap();
        assert!(build(&ca, "123", &[1], &[0; 65], crypto::CURVE_P256, Date::new(2025, 1, 1).unwrap(), 1).is_err());
        assert!(build(&ca, "12345678901234", &[1], &[0; 65], 0x01, Date::new(2025, 1, 1).unwrap(), 1).is_err());
    }

    #[test]
    fn dates() {
        let d = Date::new(2024, 2, 29).unwrap();
        assert_eq!(d.to_bcd(), [0x20, 0x24, 0x02, 0x29]);
        assert_eq!(Date::from_bcd(&d.to_bcd()), Some(d));
        assert_eq!(d.plus_years(1).unwrap(), Date::new(2025, 2, 28).unwrap());
        assert_eq!(d.plus_years(4).unwrap(), Date::new(2028, 2, 29).unwrap());
        assert!(Date::new(2023, 2, 29).is_err());
        assert!(Date::new(2023, 13, 1).is_err());
        assert!(Date::from_bcd(&[0x20, 0x2A, 1, 1]).is_none());
        assert!(Date::today_utc().year >= 2025);
    }

    #[test]
    fn long_form_lengths() {
        let t = tlv(0x5F37, &[0u8; 200]);
        assert_eq!(&t[..4], &[0x5F, 0x37, 0x81, 200]);
        let t = tlv(0x7F21, &[0u8; 300]);
        assert_eq!(&t[..5], &[0x7F, 0x21, 0x82, 0x01, 0x2C]);
    }
}
