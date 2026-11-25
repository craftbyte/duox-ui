//! X.509 v3 certificates in the card's profile (7.10.2.1): parsing, building, signing, describing.
//!
//! Parsing is deliberately general (any certificate that is well-formed DER can be inspected, including the
//! NXP trust-provisioned card certificates); the strict card rules are applied by [`super::profile`] and
//! [`super::chain`].

use super::access_rights::AccessRights;
use super::der::{self, oids, tag, Oid, Tlv};
use super::error::{CertError, PkiError, Result};
use super::keys;
use super::name::Name;
use super::pem;
use super::signature;
use super::time::Time;
use crate::crypto::{self, PrivKey, PubKey};

/// One certificate extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub oid: Oid,
    pub critical: bool,
    /// Content of the extension's OCTET STRING.
    pub value: Vec<u8>,
}

impl Extension {
    fn to_der(&self) -> Vec<u8> {
        let mut parts = vec![self.oid.to_der()];
        if self.critical {
            parts.push(der::boolean(true));
        }
        parts.push(der::octet_string(&self.value));
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        der::sequence(&refs)
    }
}

/// A parsed certificate. Holds its original encoding, so re-encoding is exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
    tbs_start: usize,
    tbs_end: usize,
    version: u8,
    serial: Vec<u8>,
    serial_negative: bool,
    tbs_signature_algorithm: Oid,
    signature_algorithm: Oid,
    issuer: Name,
    subject: Name,
    not_before: Time,
    not_after: Time,
    /// Complete `AlgorithmIdentifier` element of the subject public key.
    spki_algorithm: Vec<u8>,
    /// Content of the subjectPublicKey BIT STRING.
    spki_key: Vec<u8>,
    extensions: Vec<Extension>,
    has_unique_ids: bool,
    /// Content of the signatureValue BIT STRING (an `Ecdsa-Sig-Value` for ECDSA).
    signature: Vec<u8>,
}

impl Certificate {
    /// Parse one DER certificate that fills `data` exactly.
    pub fn from_der(data: &[u8]) -> Result<Certificate> {
        let outer = der::parse_single(data)?;
        outer.expect_tag(tag::SEQUENCE, "Certificate")?;
        let mut r = outer.reader();
        let tbs = r.expect(tag::SEQUENCE, "tbsCertificate")?;
        let sig_alg = r.expect(tag::SEQUENCE, "signatureAlgorithm")?;
        let sig = r.expect(tag::BIT_STRING, "signatureValue")?.bit_string()?.to_vec();
        r.finish("Certificate")?;

        let tbs_start = tbs.raw.as_ptr() as usize - data.as_ptr() as usize;
        let tbs_end = tbs_start + tbs.raw.len();

        let mut t = tbs.reader();
        let version = match t.optional(tag::context(0))? {
            Some(v) => {
                let n = v.reader().expect(tag::INTEGER, "version")?.unsigned_integer()?;
                if n.len() != 1 {
                    return Err(PkiError::Der("unsupported certificate version".into()));
                }
                n[0]
            }
            None => 0,
        };
        let serial_tlv = t.expect(tag::INTEGER, "serialNumber")?;
        if serial_tlv.value.is_empty() {
            return Err(PkiError::Der("empty serialNumber".into()));
        }
        let serial_negative = serial_tlv.value[0] & 0x80 != 0;
        let skip = serial_tlv.value.iter().take_while(|&&b| b == 0).count();
        let serial = serial_tlv.value[skip.min(serial_tlv.value.len() - 1)..].to_vec();
        let tbs_alg = t.expect(tag::SEQUENCE, "signature")?;
        let issuer = Name::from_der(t.expect(tag::SEQUENCE, "issuer")?.raw)?;
        let validity = t.expect(tag::SEQUENCE, "validity")?;
        let mut vr = validity.reader();
        let not_before = Time::from_der(&vr.read()?)?;
        let not_after = Time::from_der(&vr.read()?)?;
        vr.finish("Validity")?;
        let subject = Name::from_der(t.expect(tag::SEQUENCE, "subject")?.raw)?;
        let spki = t.expect(tag::SEQUENCE, "subjectPublicKeyInfo")?;
        let mut sr = spki.reader();
        let spki_algorithm = sr.expect(tag::SEQUENCE, "key algorithm")?.raw.to_vec();
        let spki_key = sr.expect(tag::BIT_STRING, "subjectPublicKey")?.bit_string()?.to_vec();
        sr.finish("SubjectPublicKeyInfo")?;

        let has_unique_ids =
            t.optional(tag::context_primitive(1))?.is_some() | t.optional(tag::context_primitive(2))?.is_some();
        let mut extensions = Vec::new();
        if let Some(e) = t.optional(tag::context(3))? {
            let mut er = e.reader();
            let list = er.expect(tag::SEQUENCE, "Extensions")?;
            er.finish("[3] Extensions")?;
            let mut lr = list.reader();
            while !lr.is_empty() {
                extensions.push(parse_extension(&lr.expect(tag::SEQUENCE, "Extension")?)?);
            }
        }
        t.finish("TBSCertificate")?;

        Ok(Certificate {
            der: data.to_vec(),
            tbs_start,
            tbs_end,
            version,
            serial,
            serial_negative,
            tbs_signature_algorithm: alg_oid(&tbs_alg)?,
            signature_algorithm: alg_oid(&sig_alg)?,
            issuer,
            subject,
            not_before,
            not_after,
            spki_algorithm,
            spki_key,
            extensions,
            has_unique_ids,
            signature: sig,
        })
    }

    /// Parse a PEM `CERTIFICATE` block.
    pub fn from_pem(text: &str) -> Result<Certificate> {
        let blocks = pem::decode_all(text)?;
        let b = blocks
            .iter()
            .find(|b| b.label == "CERTIFICATE")
            .ok_or_else(|| PkiError::Pem("no CERTIFICATE block".into()))?;
        Certificate::from_der(&b.der)
    }

    /// Certificates from a PEM file (all `CERTIFICATE` blocks) or from concatenated DER certificates.
    pub fn load_all(blob: &[u8]) -> Result<Vec<Certificate>> {
        if pem::looks_like_pem(blob) {
            let text = std::str::from_utf8(blob).map_err(|_| PkiError::Pem("PEM is not UTF-8".into()))?;
            pem::decode_all(text)?
                .iter()
                .filter(|b| b.label == "CERTIFICATE")
                .map(|b| Certificate::from_der(&b.der))
                .collect()
        } else {
            der::split_sequences(blob).into_iter().map(Certificate::from_der).collect()
        }
    }

    pub fn to_der(&self) -> &[u8] {
        &self.der
    }
    pub fn to_pem(&self) -> String {
        pem::encode("CERTIFICATE", &self.der)
    }
    /// The signed part (the encoded `tbsCertificate`).
    pub fn tbs_der(&self) -> &[u8] {
        &self.der[self.tbs_start..self.tbs_end]
    }
    /// 0 = v1, 1 = v2, 2 = v3.
    pub fn version(&self) -> u8 {
        self.version
    }
    /// Serial number magnitude, big endian, without leading zeros (at least one byte).
    pub fn serial_bytes(&self) -> &[u8] {
        &self.serial
    }
    /// The serial number if it is non-negative and fits 64 bits.
    pub fn serial(&self) -> Option<u64> {
        if self.serial_negative || self.serial.len() > 8 {
            return None;
        }
        Some(self.serial.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b)))
    }
    pub fn serial_is_negative(&self) -> bool {
        self.serial_negative
    }
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }
    pub fn subject(&self) -> &Name {
        &self.subject
    }
    pub fn not_before(&self) -> Time {
        self.not_before
    }
    pub fn not_after(&self) -> Time {
        self.not_after
    }
    /// The outer signatureAlgorithm.
    pub fn signature_algorithm(&self) -> &Oid {
        &self.signature_algorithm
    }
    /// The signature algorithm repeated inside the signed part.
    pub fn tbs_signature_algorithm(&self) -> &Oid {
        &self.tbs_signature_algorithm
    }
    /// The signatureValue content (DER `Ecdsa-Sig-Value` for ECDSA certificates).
    pub fn signature_der(&self) -> &[u8] {
        &self.signature
    }
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }
    /// issuerUniqueID / subjectUniqueID present.
    pub fn has_unique_ids(&self) -> bool {
        self.has_unique_ids
    }
    pub fn sha256(&self) -> Vec<u8> {
        crypto::sha256(&self.der)
    }

    /// The subject public key, if it is an EC key on a curve the card supports.
    pub fn public_key(&self) -> Result<PubKey> {
        let alg = der::parse_single(&self.spki_algorithm)?;
        keys::public_from_parts(&alg, &self.spki_key)
    }

    /// Card CurveID of the subject key when it is a supported EC key.
    pub fn curve_id(&self) -> Option<u8> {
        self.public_key().ok().map(|k| k.curve_id)
    }

    /// Verify the certificate signature (ecdsa-with-SHA256 over the signed part) with `issuer_key`.
    pub fn verify_signature(&self, issuer_key: &PubKey) -> bool {
        if !self.signature_algorithm.is(oids::ECDSA_WITH_SHA256) {
            return false;
        }
        match signature::der_to_raw(&self.signature) {
            Ok(raw) => issuer_key.verify_raw(&raw, self.tbs_der()),
            Err(_) => false,
        }
    }

    /// True when the subject equals the issuer and the certificate verifies with its own key.
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer && self.public_key().map(|k| self.verify_signature(&k)).unwrap_or(false)
    }

    /// The NXP access-rights extension. `Ok(None)` when absent; an error when there is more than one, or its
    /// value is invalid.
    pub fn access_rights(&self) -> std::result::Result<Option<AccessRights>, CertError> {
        let mut found = self.extensions.iter().filter(|e| e.oid.is(oids::NXP_ACCESS_RIGHTS));
        let Some(ext) = found.next() else { return Ok(None) };
        if found.next().is_some() {
            return Err(CertError::wrong_data("certificate holds more than one ARExtension"));
        }
        AccessRights::decode(&ext.value).map(Some)
    }

    /// Multi-line description for display (subject, issuer, serial, validity, key, extensions, fingerprint).
    pub fn describe(&self) -> Vec<String> {
        let serial = match self.serial() {
            Some(n) => format!("{n} (0x{n:X})"),
            None => format!("{}0x{}", if self.serial_negative { "negative " } else { "" }, hex::encode_upper(&self.serial)),
        };
        let mut l = vec![
            format!("Subject      {}", self.subject),
            format!("Issuer       {}", self.issuer),
            format!("Serial       {serial}"),
            format!("Size         {} bytes", self.der.len()),
            format!("Validity     {} .. {}", self.not_before.date_string(), self.not_after.date_string()),
        ];
        match self.public_key() {
            Ok(k) => {
                l.push(format!("Curve        {}", crypto::curve_name(k.curve_id)));
                l.push(format!("Public key   {}", hex::encode_upper(k.to_bytes())));
            }
            Err(_) => l.push(String::from("Public key   not an EC key on a supported curve")),
        }
        l.push(format!("Signature    {}", self.signature_algorithm));
        for e in &self.extensions {
            let crit = if e.critical { " (critical)" } else { "" };
            if e.oid.is(oids::NXP_ACCESS_RIGHTS) {
                match AccessRights::decode(&e.value) {
                    Ok(ar) => {
                        l.push(format!("Access rights{crit}: {}  raw {}", ar.describe(), hex::encode_upper(&e.value)))
                    }
                    Err(err) => l.push(format!("Access rights INVALID: {err}")),
                }
            } else {
                l.push(format!("Extension    {}{crit}", e.oid));
            }
        }
        l.push(format!("SHA-256      {}", hex::encode_upper(self.sha256())));
        l
    }
}

/// Describe DER bytes that may not be a certificate.
pub fn describe_der(data: &[u8]) -> Vec<String> {
    match Certificate::from_der(data) {
        Ok(c) => c.describe(),
        Err(e) => vec![format!("not an X.509 certificate: {e}"), hex::encode_upper(data)],
    }
}

fn alg_oid(alg: &Tlv<'_>) -> Result<Oid> {
    alg.reader().expect(tag::OID, "algorithm")?.oid()
}

fn parse_extension(e: &Tlv<'_>) -> Result<Extension> {
    let mut r = e.reader();
    let oid = r.expect(tag::OID, "extnID")?.oid()?;
    let critical = match r.optional(tag::BOOLEAN)? {
        Some(b) => b.boolean()?,
        None => false,
    };
    let value = r.expect(tag::OCTET_STRING, "extnValue")?.value.to_vec();
    r.finish("Extension")?;
    Ok(Extension { oid, critical, value })
}

/// Builds and signs a certificate in the card profile: v3, ecdsa-with-SHA256, optional NXP access-rights
/// extension, nothing else except (for self-signed roots that never go to a card) basicConstraints.
#[derive(Debug, Clone)]
pub struct CertificateBuilder {
    subject: Name,
    issuer: Name,
    public_key: PubKey,
    serial: u64,
    not_before: Time,
    not_after: Time,
    access_rights: Option<(AccessRights, bool)>,
    ca: bool,
}

impl CertificateBuilder {
    /// Validity defaults to one day ago until ten years from now; serial defaults to 1.
    pub fn new(subject: Name, issuer: Name, public_key: PubKey) -> Self {
        let now = Time::now();
        CertificateBuilder {
            subject,
            issuer,
            public_key,
            serial: 1,
            not_before: now.plus_days(-1),
            not_after: now.plus_days(3650),
            access_rights: None,
            ca: false,
        }
    }
    pub fn serial(mut self, serial: u64) -> Self {
        self.serial = serial;
        self
    }
    pub fn validity(mut self, not_before: Time, not_after: Time) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }
    /// Add the NXP access-rights extension; `critical` sets its criticality flag (7.6.4 shows TRUE).
    pub fn access_rights(mut self, rights: AccessRights, critical: bool) -> Self {
        self.access_rights = Some((rights, critical));
        self
    }
    /// Add a critical basicConstraints extension with `cA = TRUE` (for roots; not allowed on cards' profile).
    pub fn ca(mut self, ca: bool) -> Self {
        self.ca = ca;
        self
    }

    /// Sign with the issuer's private key.
    pub fn sign(self, signer: &PrivKey) -> Result<Certificate> {
        let sig_alg = der::sequence(&[&Oid::from_content(oids::ECDSA_WITH_SHA256).to_der()]);
        let mut exts = Vec::new();
        if let Some((rights, critical)) = &self.access_rights {
            exts.push(Extension {
                oid: Oid::from_content(oids::NXP_ACCESS_RIGHTS),
                critical: *critical,
                value: rights.encode()?,
            });
        }
        if self.ca {
            exts.push(Extension {
                oid: Oid::from_content(oids::BASIC_CONSTRAINTS),
                critical: true,
                value: der::sequence(&[&der::boolean(true)]),
            });
        }
        let mut tbs_parts = vec![
            der::tlv(tag::context(0), &der::integer_u64(2)),
            der::integer_u64(self.serial),
            sig_alg.clone(),
            self.issuer.to_der().to_vec(),
            der::sequence(&[&self.not_before.to_der(), &self.not_after.to_der()]),
            self.subject.to_der().to_vec(),
            keys::public_to_spki_der(&self.public_key)?,
        ];
        if !exts.is_empty() {
            let encoded: Vec<Vec<u8>> = exts.iter().map(Extension::to_der).collect();
            let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
            tbs_parts.push(der::tlv(tag::context(3), &der::sequence(&refs)));
        }
        let refs: Vec<&[u8]> = tbs_parts.iter().map(Vec::as_slice).collect();
        let tbs = der::sequence(&refs);
        let sig = signature::raw_to_der(&signer.sign_raw(&tbs)?)?;
        let full = der::sequence(&[&tbs, &sig_alg, &der::bit_string(&sig)]);
        Certificate::from_der(&full)
    }
}

#[cfg(test)]
mod tests {
    use super::super::access_rights::AcMap;
    use super::*;
    use crate::crypto::{gen_key, CURVE_BP256, CURVE_P256};

    fn issue(curve: u8, ar: Option<AccessRights>) -> (PrivKey, Certificate) {
        let ca = gen_key(curve).unwrap();
        let subj = gen_key(curve).unwrap();
        let mut b = CertificateBuilder::new(
            Name::with_common_name("Reader", "Acme"),
            Name::with_common_name("Root", "Acme"),
            subj.public(),
        )
        .serial(0x1234_5678);
        if let Some(a) = ar {
            b = b.access_rights(a, true);
        }
        (ca.clone(), b.sign(&ca).unwrap())
    }

    #[test]
    fn build_parse_verify_both_curves() {
        for curve in [CURVE_P256, CURVE_BP256] {
            let rights = AccessRights::for_aid(0x010203, AcMap::new(0x0023)).delegating();
            let (ca, cert) = issue(curve, Some(rights.clone()));
            let parsed = Certificate::from_der(cert.to_der()).unwrap();
            assert_eq!(parsed, cert);
            assert_eq!(cert.version(), 2);
            assert_eq!(cert.serial(), Some(0x1234_5678));
            assert_eq!(cert.curve_id(), Some(curve));
            assert_eq!(cert.access_rights().unwrap(), Some(rights));
            assert!(cert.verify_signature(&ca.public()));
            assert!(!cert.verify_signature(&gen_key(curve).unwrap().public()));
            assert_eq!(cert.subject().common_name().as_deref(), Some("Reader"));
            assert!(cert.signature_algorithm().is(oids::ECDSA_WITH_SHA256));
            assert!(cert.to_der().len() <= 440);
            assert_eq!(Certificate::from_pem(&cert.to_pem()).unwrap(), cert);
        }
    }

    #[test]
    fn tampering_breaks_signature() {
        let (ca, cert) = issue(CURVE_P256, None);
        let mut bytes = cert.to_der().to_vec();
        let i = bytes.windows(6).position(|w| w == b"Reader").unwrap();
        bytes[i] = b'r';
        let tampered = Certificate::from_der(&bytes).unwrap();
        assert!(!tampered.verify_signature(&ca.public()));
    }

    #[test]
    fn self_signed_root_with_basic_constraints() {
        let key = gen_key(CURVE_P256).unwrap();
        let n = Name::with_common_name("Root", "");
        let c = CertificateBuilder::new(n.clone(), n, key.public()).ca(true).sign(&key).unwrap();
        assert!(c.is_self_signed());
        assert_eq!(c.extensions().len(), 1);
        assert!(c.extensions()[0].critical);
        assert_eq!(c.access_rights().unwrap(), None);
    }

    #[test]
    fn load_all_der_and_pem() {
        let (_, a) = issue(CURVE_P256, None);
        let (_, b) = issue(CURVE_P256, None);
        let der = [a.to_der(), b.to_der()].concat();
        assert_eq!(Certificate::load_all(&der).unwrap(), vec![a.clone(), b.clone()]);
        let pem = format!("{}{}", a.to_pem(), b.to_pem());
        assert_eq!(Certificate::load_all(pem.as_bytes()).unwrap(), vec![a, b]);
        assert!(Certificate::load_all(&[]).unwrap().is_empty());
    }

    #[test]
    fn describe_lines() {
        let (_, cert) = issue(CURVE_P256, Some(AccessRights::for_aid(1, AcMap::new(0x0021))));
        let text = cert.describe().join("\n");
        assert!(text.contains("Subject      CN=Reader,O=Acme"), "{text}");
        assert!(text.contains("Serial       305419896 (0x12345678)"));
        assert!(text.contains("Access rights (critical): AID 000001 ACMap 0021 [0,5]"));
        assert!(describe_der(&[1, 2, 3]).join("").contains("not an X.509 certificate"));
    }
}
