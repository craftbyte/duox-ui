//! Key encodings: SPKI public keys, SEC1 / PKCS#8 EC private keys, PKCS#8 password protection (PBES2), PEM.
//! Everything here is interoperable with `openssl`.

use super::der::{self, oids, tag, Oid};
use super::error::{PkiError, Result};
use super::pem;
use crate::crypto::{self, PrivKey, PubKey, CURVE_BP256, CURVE_P256};
use zeroize::Zeroizing;

/// PBKDF2 iterations used when this crate protects a private key.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Curve OID content octets for a card CurveID.
pub fn curve_oid(curve_id: u8) -> Result<&'static [u8]> {
    match curve_id {
        CURVE_P256 => Ok(oids::SECP256R1),
        CURVE_BP256 => Ok(oids::BRAINPOOL_P256R1),
        _ => Err(PkiError::Key(format!("unsupported CurveID 0x{curve_id:02X}"))),
    }
}

/// Card CurveID for a named-curve OID, if the card supports the curve.
pub fn curve_id_from_oid(oid: &Oid) -> Option<u8> {
    if oid.is(oids::SECP256R1) {
        Some(CURVE_P256)
    } else if oid.is(oids::BRAINPOOL_P256R1) {
        Some(CURVE_BP256)
    } else {
        None
    }
}

/// `AlgorithmIdentifier { id-ecPublicKey, namedCurve }`.
pub fn ec_algorithm_identifier(curve_id: u8) -> Result<Vec<u8>> {
    let curve = Oid::from_content(curve_oid(curve_id)?).to_der();
    Ok(der::sequence(&[&Oid::from_content(oids::EC_PUBLIC_KEY).to_der(), &curve]))
}

// ----------------------------------------------------------------- public keys
/// DER `SubjectPublicKeyInfo` of a public key.
pub fn public_to_spki_der(key: &PubKey) -> Result<Vec<u8>> {
    Ok(der::sequence(&[&ec_algorithm_identifier(key.curve_id)?, &der::bit_string(&key.to_bytes())]))
}

/// Parse a DER `SubjectPublicKeyInfo` holding an uncompressed point on a supported curve.
pub fn public_from_spki_der(spki: &[u8]) -> Result<PubKey> {
    let seq = der::parse_single(spki)?;
    seq.expect_tag(tag::SEQUENCE, "SubjectPublicKeyInfo")?;
    let mut r = seq.reader();
    let alg = r.expect(tag::SEQUENCE, "AlgorithmIdentifier")?;
    let point = r.expect(tag::BIT_STRING, "subjectPublicKey")?.bit_string()?;
    r.finish("SubjectPublicKeyInfo")?;
    public_from_parts(&alg, point)
}

/// Build a public key from a parsed `AlgorithmIdentifier` element and the key bits.
pub(crate) fn public_from_parts(alg: &der::Tlv<'_>, point: &[u8]) -> Result<PubKey> {
    let mut a = alg.reader();
    let id = a.expect(tag::OID, "algorithm")?.oid()?;
    if !id.is(oids::EC_PUBLIC_KEY) {
        return Err(PkiError::Key(format!("not an EC public key (algorithm {id})")));
    }
    let curve = a.expect(tag::OID, "named curve")?.oid()?;
    a.finish("AlgorithmIdentifier")?;
    let curve_id = curve_id_from_oid(&curve).ok_or_else(|| PkiError::Key(format!("unsupported curve {curve}")))?;
    Ok(PubKey::from_bytes(curve_id, point)?)
}

pub fn public_to_pem(key: &PubKey) -> Result<String> {
    Ok(pem::encode("PUBLIC KEY", &public_to_spki_der(key)?))
}

pub fn public_from_pem(text: &str) -> Result<PubKey> {
    let block = pem::decode_all(text)?
        .into_iter()
        .find(|b| b.label == "PUBLIC KEY")
        .ok_or_else(|| PkiError::Pem("no PUBLIC KEY block".into()))?;
    public_from_spki_der(&block.der)
}

// ---------------------------------------------------------------- private keys
/// DER `ECPrivateKey` (RFC 5915). With `with_params` the curve OID is included, as a stand-alone SEC1 file needs it.
fn ec_private_key_der(key: &PrivKey, with_params: bool) -> Result<Vec<u8>> {
    let scalar = Zeroizing::new(key.to_bytes());
    let mut parts = vec![der::integer_u64(1), der::octet_string(&scalar)];
    if with_params {
        parts.push(der::tlv(tag::context(0), &Oid::from_content(curve_oid(key.curve_id)?).to_der()));
    }
    parts.push(der::tlv(tag::context(1), &der::bit_string(&key.public().to_bytes())));
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    Ok(der::sequence(&refs))
}

/// Stand-alone SEC1 `ECPrivateKey` with the curve parameters (what `openssl ecparam -genkey` writes).
pub fn private_to_sec1_der(key: &PrivKey) -> Result<Vec<u8>> {
    ec_private_key_der(key, true)
}

/// Unencrypted PKCS#8 `PrivateKeyInfo`.
pub fn private_to_pkcs8_der(key: &PrivKey) -> Result<Vec<u8>> {
    let inner = Zeroizing::new(ec_private_key_der(key, false)?);
    Ok(der::sequence(&[&der::integer_u64(0), &ec_algorithm_identifier(key.curve_id)?, &der::octet_string(&inner)]))
}

/// Parse a SEC1 `ECPrivateKey`; `curve_hint` is the curve from an enclosing PKCS#8 structure, if any.
fn parse_ec_private_key(data: &[u8], curve_hint: Option<u8>) -> Result<PrivKey> {
    let seq = der::parse_single(data)?;
    seq.expect_tag(tag::SEQUENCE, "ECPrivateKey")?;
    let mut r = seq.reader();
    if r.expect(tag::INTEGER, "ECPrivateKey version")?.unsigned_integer()? != [1] {
        return Err(PkiError::Key("unsupported ECPrivateKey version".into()));
    }
    let scalar = r.expect(tag::OCTET_STRING, "privateKey")?.value;
    let mut curve = curve_hint;
    if let Some(p) = r.optional(tag::context(0))? {
        let oid = p.reader().expect(tag::OID, "ECParameters")?.oid()?;
        let id = curve_id_from_oid(&oid).ok_or_else(|| PkiError::Key(format!("unsupported curve {oid}")))?;
        if curve.is_some_and(|c| c != id) {
            return Err(PkiError::Key("curve of the key and of its parameters differ".into()));
        }
        curve = Some(id);
    }
    let embedded_pub = match r.optional(tag::context(1))? {
        Some(p) => Some(p.reader().expect(tag::BIT_STRING, "publicKey")?.bit_string()?.to_vec()),
        None => None,
    };
    let curve = curve.ok_or_else(|| PkiError::Key("EC private key without curve parameters".into()))?;
    if scalar.is_empty() || scalar.len() > 32 {
        return Err(PkiError::Key("EC private key scalar must be 1..32 bytes".into()));
    }
    let mut padded = Zeroizing::new(vec![0u8; 32]);
    padded[32 - scalar.len()..].copy_from_slice(scalar);
    let key = crypto::priv_from_bytes(curve, &padded)?;
    if let Some(p) = embedded_pub {
        if p != key.public().to_bytes() {
            return Err(PkiError::Key("embedded public key does not match the private key".into()));
        }
    }
    Ok(key)
}

/// Parse a DER private key: unencrypted PKCS#8 or SEC1.
pub fn private_from_der(data: &[u8]) -> Result<PrivKey> {
    let seq = der::parse_single(data)?;
    seq.expect_tag(tag::SEQUENCE, "private key")?;
    let mut r = seq.reader();
    let version = r.expect(tag::INTEGER, "version")?.unsigned_integer()?;
    if version == [1] {
        return parse_ec_private_key(data, None); // SEC1
    }
    if version != [0] {
        return Err(PkiError::Key("unsupported private key version".into()));
    }
    let alg = r.expect(tag::SEQUENCE, "AlgorithmIdentifier")?;
    let inner = r.expect(tag::OCTET_STRING, "privateKey")?.value;
    let mut a = alg.reader();
    let id = a.expect(tag::OID, "algorithm")?.oid()?;
    if !id.is(oids::EC_PUBLIC_KEY) {
        return Err(PkiError::Key(format!("not an EC private key (algorithm {id})")));
    }
    let curve = a.expect(tag::OID, "named curve")?.oid()?;
    let curve_id = curve_id_from_oid(&curve).ok_or_else(|| PkiError::Key(format!("unsupported curve {curve}")))?;
    parse_ec_private_key(inner, Some(curve_id))
}

/// Which PEM flavour to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyFormat {
    /// `-----BEGIN PRIVATE KEY-----` (or `ENCRYPTED PRIVATE KEY` with a passphrase).
    Pkcs8,
    /// `-----BEGIN EC PRIVATE KEY-----`, never encrypted.
    Sec1,
}

/// PEM text of a private key. An empty or absent passphrase writes it unprotected.
pub fn private_to_pem(key: &PrivKey, format: PrivateKeyFormat, passphrase: Option<&str>) -> Result<String> {
    let passphrase = passphrase.filter(|p| !p.is_empty());
    match (format, passphrase) {
        (PrivateKeyFormat::Sec1, None) => Ok(pem::encode("EC PRIVATE KEY", &private_to_sec1_der(key)?)),
        (PrivateKeyFormat::Sec1, Some(_)) => Err(PkiError::Key("SEC1 PEM cannot be passphrase protected here".into())),
        (PrivateKeyFormat::Pkcs8, None) => Ok(pem::encode("PRIVATE KEY", &private_to_pkcs8_der(key)?)),
        (PrivateKeyFormat::Pkcs8, Some(p)) => {
            let plain = Zeroizing::new(private_to_pkcs8_der(key)?);
            Ok(pem::encode("ENCRYPTED PRIVATE KEY", &encrypt_pkcs8(&plain, p)?))
        }
    }
}

/// True when the PEM text is an `ENCRYPTED PRIVATE KEY`.
pub fn pem_is_encrypted(text: &str) -> bool {
    text.contains("ENCRYPTED")
}

/// Parse a PEM private key (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` or `EC PRIVATE KEY`).
pub fn private_from_pem(text: &str, passphrase: Option<&str>) -> Result<PrivKey> {
    let block = pem::decode_all(text)?
        .into_iter()
        .find(|b| matches!(b.label.as_str(), "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" | "EC PRIVATE KEY"))
        .ok_or_else(|| PkiError::Pem("no private key block".into()))?;
    if block.label == "ENCRYPTED PRIVATE KEY" {
        let p = passphrase.filter(|p| !p.is_empty()).ok_or(PkiError::PassphraseRequired)?;
        let plain = Zeroizing::new(decrypt_pkcs8(&block.der, p)?);
        private_from_der(&plain).map_err(|_| PkiError::WrongPassphrase)
    } else {
        private_from_der(&block.der)
    }
}

// ------------------------------------------------------------ PBES2 (PKCS#5 v2)
fn pbkdf2(prf: &Oid, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    if iterations == 0 {
        return Err(PkiError::Key("PBKDF2 iteration count is zero".into()));
    }
    if prf.is(oids::HMAC_SHA256) {
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, out);
    } else if prf.is(oids::HMAC_SHA512) {
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, out);
    } else if prf.is(oids::HMAC_SHA1) {
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, out);
    } else {
        return Err(PkiError::Key(format!("unsupported PBKDF2 PRF {prf}")));
    }
    Ok(())
}

/// `EncryptedPrivateKeyInfo` with PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC.
fn encrypt_pkcs8(plain: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let salt = crypto::rnd(16);
    let iv = crypto::rnd(16);
    let mut key = Zeroizing::new(vec![0u8; 32]);
    let prf = Oid::from_content(oids::HMAC_SHA256);
    pbkdf2(&prf, passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key)?;
    let pad = 16 - plain.len() % 16;
    let mut padded = Zeroizing::new(plain.to_vec());
    padded.extend(std::iter::repeat_n(pad as u8, pad));
    let ct = crypto::aes_cbc_enc(&key, &padded, &iv)?;
    let kdf = der::sequence(&[
        &Oid::from_content(oids::PBKDF2).to_der(),
        &der::sequence(&[
            &der::octet_string(&salt),
            &der::integer_u64(u64::from(PBKDF2_ITERATIONS)),
            &der::sequence(&[&prf.to_der(), &der::null()]),
        ]),
    ]);
    let cipher = der::sequence(&[&Oid::from_content(oids::AES256_CBC).to_der(), &der::octet_string(&iv)]);
    let scheme = der::sequence(&[&Oid::from_content(oids::PBES2).to_der(), &der::sequence(&[&kdf, &cipher])]);
    Ok(der::sequence(&[&scheme, &der::octet_string(&ct)]))
}

/// Decrypt an `EncryptedPrivateKeyInfo` (PBES2 with PBKDF2 and AES-CBC); returns the `PrivateKeyInfo`.
fn decrypt_pkcs8(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let top = der::parse_single(data)?;
    top.expect_tag(tag::SEQUENCE, "EncryptedPrivateKeyInfo")?;
    let mut r = top.reader();
    let scheme = r.expect(tag::SEQUENCE, "encryptionAlgorithm")?;
    let ct = r.expect(tag::OCTET_STRING, "encryptedData")?.value;
    r.finish("EncryptedPrivateKeyInfo")?;
    let mut s = scheme.reader();
    if !s.expect(tag::OID, "encryptionAlgorithm")?.oid()?.is(oids::PBES2) {
        return Err(PkiError::Key("unsupported key encryption scheme (only PBES2 is supported)".into()));
    }
    let params = s.expect(tag::SEQUENCE, "PBES2-params")?;
    let mut p = params.reader();
    let kdf = p.expect(tag::SEQUENCE, "keyDerivationFunc")?;
    let cipher = p.expect(tag::SEQUENCE, "encryptionScheme")?;
    let mut k = kdf.reader();
    let kdf_oid = k.expect(tag::OID, "keyDerivationFunc")?.oid()?;
    if !kdf_oid.is(oids::PBKDF2) {
        return Err(PkiError::Key(format!("unsupported key derivation function {kdf_oid} (only PBKDF2)")));
    }
    let kp = k.expect(tag::SEQUENCE, "PBKDF2-params")?;
    let mut kr = kp.reader();
    let salt = kr.expect(tag::OCTET_STRING, "salt")?.value;
    let iterations = {
        let n = kr.expect(tag::INTEGER, "iterationCount")?.unsigned_integer()?;
        if n.len() > 4 {
            return Err(PkiError::Key("PBKDF2 iteration count too large".into()));
        }
        n.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b))
    };
    let key_len_field = kr.optional(tag::INTEGER)?;
    let prf = match kr.optional(tag::SEQUENCE)? {
        Some(alg) => alg.reader().expect(tag::OID, "prf")?.oid()?,
        None => Oid::from_content(oids::HMAC_SHA1),
    };
    let mut c = cipher.reader();
    let cipher_oid = c.expect(tag::OID, "cipher")?.oid()?;
    let iv = c.expect(tag::OCTET_STRING, "IV")?.value;
    let key_len = if cipher_oid.is(oids::AES256_CBC) {
        32
    } else if cipher_oid.is(oids::AES128_CBC) {
        16
    } else {
        return Err(PkiError::Key(format!("unsupported cipher {cipher_oid} (only AES-CBC)")));
    };
    if let Some(f) = key_len_field {
        if f.unsigned_integer()? != [key_len as u8] {
            return Err(PkiError::Key("PBKDF2 key length does not match the cipher".into()));
        }
    }
    if iv.len() != 16 || ct.is_empty() || ct.len() % 16 != 0 {
        return Err(PkiError::Key("malformed encrypted key".into()));
    }
    let mut key = Zeroizing::new(vec![0u8; key_len]);
    pbkdf2(&prf, passphrase.as_bytes(), salt, iterations, &mut key)?;
    let plain = Zeroizing::new(crypto::aes_cbc_dec(&key, ct, iv)?);
    let pad = *plain.last().unwrap_or(&0) as usize;
    if pad == 0 || pad > 16 || pad > plain.len() || plain[plain.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(PkiError::WrongPassphrase);
    }
    Ok(plain[..plain.len() - pad].to_vec())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_roundtrips_on_both_curves() {
        for id in [CURVE_P256, CURVE_BP256] {
            let k = crypto::gen_key(id).unwrap();
            for fmt in [PrivateKeyFormat::Pkcs8, PrivateKeyFormat::Sec1] {
                let text = private_to_pem(&k, fmt, None).unwrap();
                let back = private_from_pem(&text, None).unwrap();
                assert_eq!(back.to_bytes(), k.to_bytes());
                assert_eq!(back.curve_id, id);
            }
            let pubpem = public_to_pem(&k.public()).unwrap();
            assert_eq!(public_from_pem(&pubpem).unwrap(), k.public());
        }
    }

    #[test]
    fn encrypted_pkcs8_roundtrip_and_errors() {
        let k = crypto::gen_key(CURVE_P256).unwrap();
        let text = private_to_pem(&k, PrivateKeyFormat::Pkcs8, Some("secret")).unwrap();
        assert!(text.contains("BEGIN ENCRYPTED PRIVATE KEY") && pem_is_encrypted(&text));
        assert_eq!(private_from_pem(&text, Some("secret")).unwrap().to_bytes(), k.to_bytes());
        assert!(matches!(private_from_pem(&text, None), Err(PkiError::PassphraseRequired)));
        assert!(matches!(private_from_pem(&text, Some("other")), Err(PkiError::WrongPassphrase)));
    }

    /// Key protected by another implementation (PBES2, PBKDF2-HMAC-SHA256 with 2048 rounds, AES-256-CBC).
    #[test]
    fn decrypts_foreign_encrypted_pkcs8() {
        let text = include_str!("testdata/encrypted_p256.pem");
        let k = private_from_pem(text, Some("pass")).unwrap();
        assert_eq!(hex::encode(k.to_bytes()), include_str!("testdata/encrypted_p256.scalar").trim());
        assert!(matches!(private_from_pem(text, Some("nope")), Err(PkiError::WrongPassphrase)));
    }
}
