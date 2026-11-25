//! Cryptographic primitives for MIFARE DUOX (MF3E(H)x3).
//! AES, CMAC, key derivation, ECDSA/ECDH (P-256 and brainpoolP256r1) and the EV2 secure-messaging state.
//!
//! ECC: P-256 (`p256`) and brainpoolP256r1 (`bp256`) on top of RustCrypto `ecdsa`.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
use cmac::{Cmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

pub const ZERO_IV: [u8; 16] = [0; 16];
pub const CURVE_P256: u8 = 0x0C;
pub const CURVE_BP256: u8 = 0x0D;

#[derive(Debug, Clone)]
pub struct CryptoError(pub String);
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CryptoError {}
pub type CResult<T> = Result<T, CryptoError>;
fn err<T>(s: impl Into<String>) -> CResult<T> {
    Err(CryptoError(s.into()))
}
fn ce<E: fmt::Display>(e: E) -> CryptoError {
    CryptoError(e.to_string())
}

// ------------------------------------------------------------------ helpers
pub fn rnd(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}
pub fn rotl(b: &[u8]) -> Vec<u8> {
    let mut v = b[1..].to_vec();
    v.push(b[0]);
    v
}
pub fn rotr(b: &[u8]) -> Vec<u8> {
    let mut v = vec![b[b.len() - 1]];
    v.extend_from_slice(&b[..b.len() - 1]);
    v
}
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
/// CRC32 as used by ChangeKey (no final inversion, LSB first).
pub fn crc32_nk(data: &[u8]) -> [u8; 4] {
    (crc32fast::hash(data) ^ 0xFFFF_FFFF).to_le_bytes()
}

// ---------------------------------------------------------------------- AES
macro_rules! with_key {
    ($key:expr, $f:ident $(, $arg:expr)*) => {
        match $key.len() {
            16 => $f::<aes::Aes128>($key $(, $arg)*),
            32 => $f::<aes::Aes256>($key $(, $arg)*),
            n => err(format!("AES key must be 16 or 32 bytes, got {n}")),
        }
    };
}

fn cbc_enc_g<C>(key: &[u8], data: &[u8], iv: &[u8]) -> CResult<Vec<u8>>
where
    C: aes::cipher::BlockCipher + BlockEncrypt + KeyInit,
{
    if data.len() % 16 != 0 {
        return err("CBC data is not a multiple of 16 bytes");
    }
    let mut e = cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(ce)?;
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(16) {
        e.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}
fn cbc_dec_g<C>(key: &[u8], data: &[u8], iv: &[u8]) -> CResult<Vec<u8>>
where
    C: aes::cipher::BlockCipher + BlockDecrypt + KeyInit,
{
    if data.len() % 16 != 0 {
        return err("CBC data is not a multiple of 16 bytes");
    }
    let mut d = cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(ce)?;
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(16) {
        d.decrypt_block_mut(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}
fn ecb_enc_g<C>(key: &[u8], data: &[u8]) -> CResult<Vec<u8>>
where
    C: aes::cipher::BlockCipher + BlockEncrypt + KeyInit,
{
    if data.len() % 16 != 0 {
        return err("ECB data is not a multiple of 16 bytes");
    }
    let c = C::new_from_slice(key).map_err(ce)?;
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(16) {
        c.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}
fn ecb_dec_g<C>(key: &[u8], data: &[u8]) -> CResult<Vec<u8>>
where
    C: aes::cipher::BlockCipher + BlockDecrypt + KeyInit,
{
    if data.len() % 16 != 0 {
        return err("ECB data is not a multiple of 16 bytes");
    }
    let c = C::new_from_slice(key).map_err(ce)?;
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(16) {
        c.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}
fn cmac_g<C>(key: &[u8], msg: &[u8]) -> CResult<Vec<u8>>
where
    C: aes::cipher::BlockCipher
        + BlockEncrypt
        + KeyInit
        + Clone
        + aes::cipher::BlockSizeUser<BlockSize = aes::cipher::consts::U16>,
{
    let mut m = <Cmac<C> as Mac>::new_from_slice(key).map_err(ce)?;
    m.update(msg);
    Ok(m.finalize().into_bytes().to_vec())
}

pub fn aes_cbc_enc(key: &[u8], data: &[u8], iv: &[u8]) -> CResult<Vec<u8>> {
    with_key!(key, cbc_enc_g, data, iv)
}
pub fn aes_cbc_dec(key: &[u8], data: &[u8], iv: &[u8]) -> CResult<Vec<u8>> {
    with_key!(key, cbc_dec_g, data, iv)
}
pub fn aes_ecb_enc(key: &[u8], data: &[u8]) -> CResult<Vec<u8>> {
    with_key!(key, ecb_enc_g, data)
}
pub fn aes_ecb_dec(key: &[u8], data: &[u8]) -> CResult<Vec<u8>> {
    with_key!(key, ecb_dec_g, data)
}
pub fn aes_cmac(key: &[u8], msg: &[u8]) -> CResult<Vec<u8>> {
    with_key!(key, cmac_g, msg)
}

/// Truncated MAC of 7.5.10.3: the odd-indexed bytes (1,3,..,15) of the CMAC.
pub fn mact(key: &[u8], msg: &[u8]) -> CResult<Vec<u8>> {
    Ok(aes_cmac(key, msg)?.iter().skip(1).step_by(2).copied().collect())
}

/// ISO/IEC 9797-1 padding method 2 (always adds 0x80).
pub fn pad_m2(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    v.push(0x80);
    while v.len() % 16 != 0 {
        v.push(0);
    }
    v
}
pub fn unpad_m2(data: &[u8]) -> CResult<Vec<u8>> {
    match data.iter().rposition(|&b| b != 0) {
        Some(i) if data[i] == 0x80 => Ok(data[..i].to_vec()),
        _ => err("invalid ISO 9797-1 M2 padding"),
    }
}

// ------------------------------------------------------- session key KDFs
/// AES session keys of 7.5.8.4. Returns (K_SesAuthENC, K_SesAuthMAC).
pub fn ev2_session_keys(key: &[u8], rnd_a: &[u8], rnd_b: &[u8]) -> CResult<(Vec<u8>, Vec<u8>)> {
    let ctx = [&rnd_a[0..2], &xor(&rnd_a[2..8], &rnd_b[0..6]), &rnd_b[6..16], &rnd_a[8..16]].concat();
    match key.len() {
        16 => Ok((
            aes_cmac(key, &[&[0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80][..], &ctx].concat())?,
            aes_cmac(key, &[&[0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80][..], &ctx].concat())?,
        )),
        32 => {
            let (mut enc, mut mac) = (vec![], vec![]);
            for i in [1u8, 2] {
                enc.extend(aes_cmac(key, &[&[0xA5, 0x5A, 0x00, i, 0x01, 0x00][..], &ctx].concat())?);
                mac.extend(aes_cmac(key, &[&[0x5A, 0xA5, 0x00, i, 0x01, 0x00][..], &ctx].concat())?);
            }
            Ok((enc, mac))
        }
        _ => err("AES key must be 16 or 32 bytes"),
    }
}

/// Two-step KDF of 7.5.6.4. `epub_*` are 65-byte uncompressed points. Returns (ENC, MAC), AES-128.
pub fn ecc_session_keys(shs: &[u8], epub_a: &[u8], epub_b: &[u8]) -> CResult<(Vec<u8>, Vec<u8>)> {
    let salt = [&epub_a[25..33], &epub_b[25..33]].concat(); // 8 LSB of each x coordinate
    let kdk = aes_cmac(&salt, shs)?;
    let enc = aes_cmac(&kdk, &[&[0xB4, 0x4B, 0x00, 0x01, 0x00, 0x80][..], &[0u8; 10]].concat())?;
    let mac = aes_cmac(&kdk, &[&[0x4B, 0xB4, 0x00, 0x01, 0x00, 0x80][..], &[0u8; 10]].concat())?;
    Ok((enc, mac))
}

// --------------------------------------------------------------------- ECC
// P-256 via the `p256` crate and brainpoolP256r1 via the `bp256` crate, both with RustCrypto `ecdsa`.
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::sec1::ToSec1Point;

pub fn curve_name(id: u8) -> &'static str {
    match id {
        CURVE_P256 => "NIST P-256",
        CURVE_BP256 => "brainpoolP256r1",
        _ => "unknown curve",
    }
}
fn check_curve(id: u8) -> CResult<()> {
    match id {
        CURVE_P256 | CURVE_BP256 => Ok(()),
        _ => err(format!("unsupported CurveID 0x{id:02X}")),
    }
}

type PSk = ecdsa::SigningKey<p256::NistP256>;
type BSk = ecdsa::SigningKey<bp256::r1::BrainpoolP256r1>;
type PVk = ecdsa::VerifyingKey<p256::NistP256>;
type BVk = ecdsa::VerifyingKey<bp256::r1::BrainpoolP256r1>;
type PSig = ecdsa::Signature<p256::NistP256>;
type BSig = ecdsa::Signature<bp256::r1::BrainpoolP256r1>;

#[derive(Clone)]
enum SK {
    P(PSk),
    B(BSk),
}
#[derive(Clone, Debug, PartialEq)]
enum VK {
    P(PVk),
    B(BVk),
}

/// Private key (curve id + scalar).
#[derive(Clone)]
pub struct PrivKey {
    pub curve_id: u8,
    sk: SK,
}
/// Public key (curve id + point).
#[derive(Clone, Debug, PartialEq)]
pub struct PubKey {
    pub curve_id: u8,
    vk: VK,
}

pub fn gen_key(curve_id: u8) -> CResult<PrivKey> {
    check_curve(curve_id)?;
    loop {
        // random scalar, retried until in range
        if let Ok(k) = priv_from_bytes(curve_id, &rnd(32)) {
            return Ok(k);
        }
    }
}
pub fn priv_from_bytes(curve_id: u8, raw: &[u8]) -> CResult<PrivKey> {
    check_curve(curve_id)?;
    if raw.len() != 32 {
        return err("private key must be 32 bytes");
    }
    let bad = |_| CryptoError("private key scalar out of range".into());
    let sk = if curve_id == CURVE_P256 {
        SK::P(PSk::from_slice(raw).map_err(bad)?)
    } else {
        SK::B(BSk::from_slice(raw).map_err(bad)?)
    };
    Ok(PrivKey { curve_id, sk })
}

impl PrivKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.sk {
            SK::P(k) => k.to_bytes().to_vec(),
            SK::B(k) => k.to_bytes().to_vec(),
        }
    }
    pub fn public(&self) -> PubKey {
        let vk = match &self.sk {
            SK::P(k) => VK::P(*k.verifying_key()),
            SK::B(k) => VK::B(*k.verifying_key()),
        };
        PubKey { curve_id: self.curve_id, vk }
    }
    /// ECDH shared secret: the 32-byte x coordinate.
    pub fn ecdh(&self, peer: &PubKey) -> CResult<Vec<u8>> {
        match (&self.sk, &peer.vk) {
            (SK::P(k), VK::P(v)) => {
                let pt = p256::ProjectivePoint::from(*v.as_affine()) * **k.as_nonzero_scalar();
                Ok(pt.to_affine().to_sec1_point(false).as_bytes()[1..33].to_vec())
            }
            (SK::B(k), VK::B(v)) => {
                let pt = bp256::r1::ProjectivePoint::from(*v.as_affine()) * **k.as_nonzero_scalar();
                Ok(pt.to_affine().to_sec1_point(false).as_bytes()[1..33].to_vec())
            }
            _ => err("curve mismatch"),
        }
    }
    /// ECDSA-SHA256, signature as 64-byte r||s (7.5.7.2.1).
    pub fn sign_raw(&self, msg: &[u8]) -> CResult<Vec<u8>> {
        Ok(match &self.sk {
            SK::P(k) => { let s: PSig = k.try_sign(msg).map_err(ce)?; s.to_bytes().to_vec() }
            SK::B(k) => { let s: BSig = k.try_sign(msg).map_err(ce)?; s.to_bytes().to_vec() }
        })
    }
    /// ECDSA over an already computed 32-byte digest (CryptoRequest pre-hashed mode).
    pub fn sign_hash(&self, digest: &[u8]) -> CResult<Vec<u8>> {
        Ok(match &self.sk {
            SK::P(k) => { let s: PSig = k.sign_prehash(digest).map_err(ce)?; s.to_bytes().to_vec() }
            SK::B(k) => { let s: BSig = k.sign_prehash(digest).map_err(ce)?; s.to_bytes().to_vec() }
        })
    }
}

impl PubKey {
    pub fn from_bytes(curve_id: u8, raw: &[u8]) -> CResult<PubKey> {
        check_curve(curve_id)?;
        if raw.len() != 65 || raw[0] != 0x04 {
            return err("public key must be 65 bytes, uncompressed (04||x||y)");
        }
        let bad = |_| CryptoError("point is not on the curve".into());
        let vk = if curve_id == CURVE_P256 {
            VK::P(PVk::from_sec1_bytes(raw).map_err(bad)?)
        } else {
            VK::B(BVk::from_sec1_bytes(raw).map_err(bad)?)
        };
        Ok(PubKey { curve_id, vk })
    }
    /// 65-byte uncompressed point 04||x||y.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.vk {
            VK::P(v) => v.to_sec1_point(false).as_bytes().to_vec(),
            VK::B(v) => v.to_sec1_point(false).as_bytes().to_vec(),
        }
    }
    pub fn verify_raw(&self, sig: &[u8], msg: &[u8]) -> bool {
        match &self.vk {
            VK::P(v) => PSig::from_slice(sig).map(|s| v.verify(msg, &s).is_ok()).unwrap_or(false),
            VK::B(v) => BSig::from_slice(sig).map(|s| v.verify(msg, &s).is_ok()).unwrap_or(false),
        }
    }
    pub fn verify_hash(&self, sig: &[u8], digest: &[u8]) -> bool {
        match &self.vk {
            VK::P(v) => PSig::from_slice(sig).map(|s| v.verify_prehash(digest, &s).is_ok()).unwrap_or(false),
            VK::B(v) => BSig::from_slice(sig).map(|s| v.verify_prehash(digest, &s).is_ok()).unwrap_or(false),
        }
    }
}

// ---------------------------------------------------- EV2 secure messaging
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionKind {
    Aes,
    Ecc,
}

/// State of an active EV2 secure messaging session (7.5.10). `ctr` is the value to be used for
/// the *next* cryptographic operation. Used by the reader side and by the simulator.
#[derive(Clone, Debug)]
pub struct Session {
    pub kind: SessionKind,
    pub enc: Vec<u8>,
    pub mac: Vec<u8>,
    pub ti: [u8; 4],
    pub ctr: u16,
    pub key_no: Option<u8>, // AES: authenticated key number
    pub sai: bool,          // AES: key belongs to the secondary application
    pub acmap: u16,         // ECC: granted access condition bitmap
    pub acmap2: u16,        // ECC: same for the secondary application
    pub info: std::collections::BTreeMap<String, String>,
}

impl Session {
    pub fn new(kind: SessionKind, enc: Vec<u8>, mac: Vec<u8>, ti: [u8; 4], key_no: Option<u8>, acmap: u16) -> Self {
        Session { kind, enc, mac, ti, ctr: 0, key_no, sai: false, acmap, acmap2: 0, info: Default::default() }
    }
    pub fn ctr_le(&self) -> [u8; 2] {
        self.ctr.to_le_bytes()
    }
    pub fn iv(&self, response: bool) -> CResult<Vec<u8>> {
        let label: [u8; 2] = if response { [0x5A, 0xA5] } else { [0xA5, 0x5A] };
        aes_ecb_enc(&self.enc, &[&label[..], &self.ti, &self.ctr_le(), &[0u8; 8]].concat())
    }
    pub fn encrypt(&self, data: &[u8], response: bool) -> CResult<Vec<u8>> {
        aes_cbc_enc(&self.enc, &pad_m2(data), &self.iv(response)?)
    }
    pub fn decrypt(&self, data: &[u8], response: bool) -> CResult<Vec<u8>> {
        if data.is_empty() || data.len() % 16 != 0 {
            return err("encrypted field is not a multiple of 16 bytes");
        }
        unpad_m2(&aes_cbc_dec(&self.enc, data, &self.iv(response)?)?)
    }
    pub fn mac_cmd(&self, cmd: u8, body: &[u8]) -> CResult<Vec<u8>> {
        mact(&self.mac, &[&[cmd][..], &self.ctr_le(), &self.ti, body].concat())
    }
    pub fn mac_resp(&self, rc: u8, body: &[u8]) -> CResult<Vec<u8>> {
        mact(&self.mac, &[&[rc][..], &self.ctr_le(), &self.ti, body].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    #[test]
    fn cmac_rfc4493() {
        let k = hx("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(hex::encode(aes_cmac(&k, &[]).unwrap()), "bb1d6929e95937287fa37d129b756746");
        assert_eq!(
            hex::encode(aes_cmac(&k, &hx("6bc1bee22e409f96e93d7e117393172a")).unwrap()),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
    }
    #[test]
    fn padding() {
        assert_eq!(pad_m2(&[1, 2]).len(), 16);
        assert_eq!(pad_m2(&[0; 16]).len(), 32);
        assert_eq!(unpad_m2(&pad_m2(&[1, 2, 3])).unwrap(), vec![1, 2, 3]);
        assert!(unpad_m2(&[0u8; 16]).is_err());
    }
    #[test]
    fn cbc_roundtrip() {
        for kl in [16, 32] {
            let k = rnd(kl);
            let d = rnd(48);
            let iv = rnd(16);
            assert_eq!(aes_cbc_dec(&k, &aes_cbc_enc(&k, &d, &iv).unwrap(), &iv).unwrap(), d);
        }
    }
    #[test]
    fn ecc_both_curves() {
        for id in [CURVE_P256, CURVE_BP256] {
            let a = gen_key(id).unwrap();
            let b = gen_key(id).unwrap();
            assert_eq!(a.ecdh(&b.public()).unwrap(), b.ecdh(&a.public()).unwrap());
            let sig = a.sign_raw(b"msg").unwrap();
            assert_eq!(sig.len(), 64);
            assert!(a.public().verify_raw(&sig, b"msg"));
            assert!(!a.public().verify_raw(&sig, b"msh"));
            let d = sha256(b"x");
            assert!(a.public().verify_hash(&a.sign_hash(&d).unwrap(), &d));
            assert!(a.public().verify_raw(&a.sign_hash(&sha256(b"m")).unwrap(), b"m"));
            assert_eq!(PubKey::from_bytes(id, &a.public().to_bytes()).unwrap(), a.public());
            assert_eq!(priv_from_bytes(id, &a.to_bytes()).unwrap().public(), a.public());
            assert!(PubKey::from_bytes(id, &[&[4u8][..], &[1u8; 64]].concat()).is_err());
        }
        let p = gen_key(CURVE_P256).unwrap().public().to_bytes();
        assert!(PubKey::from_bytes(CURVE_BP256, &p).is_err());
    }
    #[test]
    fn ev2_session_keys_an12196() {
        let key = [0u8; 16];
        let rnd_a = hx("13C5DB8A5930439FC3DEF9A4C675360F");
        let rnd_b = hx("B9E2FC789B64BF237CCCAA20EC7E6E48");
        let (enc, mac) = ev2_session_keys(&key, &rnd_a, &rnd_b).unwrap();
        assert_eq!(hex::encode_upper(enc), "1309C877509E5A215007FF0ED19CA564");
        assert_eq!(hex::encode_upper(mac), "4C6626F5E72EA694202139295C7A7FC7");
    }
}
