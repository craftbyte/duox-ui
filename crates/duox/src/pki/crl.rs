//! Certificate revocation: the CRLFile image, its signature message and the card's revocation check
//! (7.10.2.3.2, 7.10.2.3.3, 7.10.2.3.5).

use super::error::{PkiError, Result};
use crate::crypto::PrivKey;
use serde::{Deserialize, Serialize};
use std::fmt;

/// CSNSize supported for revocation (7.10.2.3.2).
pub const CSN_SIZE: usize = 4;

/// Byte order of the serial numbers inside the CRLFile. The data sheet does not state it; certificates are
/// encoded most significant byte first, which is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CsnOrder {
    #[default]
    MsbFirst,
    LsbFirst,
}

impl CsnOrder {
    pub fn encode(self, serial: u32) -> [u8; CSN_SIZE] {
        match self {
            CsnOrder::MsbFirst => serial.to_be_bytes(),
            CsnOrder::LsbFirst => serial.to_le_bytes(),
        }
    }
    /// `bytes` must hold at least [`CSN_SIZE`] bytes; extra bytes are ignored.
    pub fn decode(self, bytes: &[u8]) -> u32 {
        let b = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            CsnOrder::MsbFirst => u32::from_be_bytes(b),
            CsnOrder::LsbFirst => u32::from_le_bytes(b),
        }
    }
}

/// `CSNAllBefore || CSN1 .. CSNn || 00000000` (Figure 15). With `size`, the image is zero padded to the file
/// content size; the terminator itself may be cut off when the file is exactly full.
pub fn build_image(all_before: u32, serials: &[u32], size: Option<usize>, order: CsnOrder) -> Result<Vec<u8>> {
    if serials.contains(&0) {
        return Err(PkiError::Invalid("revoked serial numbers must be 1..0xFFFFFFFF".into()));
    }
    let mut img = order.encode(all_before).to_vec();
    for &s in serials {
        img.extend(order.encode(s));
    }
    img.extend([0u8; CSN_SIZE]);
    if let Some(size) = size {
        if img.len() - CSN_SIZE > size {
            return Err(PkiError::Invalid(format!(
                "CRL needs {} bytes but the file holds {size}",
                img.len() - CSN_SIZE
            )));
        }
        img.resize(size, 0);
    }
    Ok(img)
}

/// Read back `(CSNAllBefore, revoked serials)` of a CRLFile image; parsing stops at the first all-zero CSN.
pub fn parse_image(data: &[u8], order: CsnOrder) -> (u32, Vec<u32>) {
    let all_before = if data.len() >= CSN_SIZE { order.decode(data) } else { 0 };
    let serials = data
        .get(CSN_SIZE..)
        .unwrap_or_default()
        .chunks_exact(CSN_SIZE)
        .map(|c| order.decode(c))
        .take_while(|&v| v != 0)
        .collect();
    (all_before, serials)
}

/// Why a certificate serial number is revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// The serial is not above CSNAllBefore.
    AllBefore { serial: u64, threshold: u32 },
    /// The serial is in the list.
    Listed { serial: u64 },
}

impl fmt::Display for Revocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Revocation::AllBefore { serial, threshold } => write!(f, "serial {serial} <= CSNAllBefore {threshold}"),
            Revocation::Listed { serial } => write!(f, "serial {serial} is listed"),
        }
    }
}

/// The revocation check of 7.10.2.3.5. Without a usable image (`csn_size` other than 4, or shorter than one CSN)
/// nothing is revoked, as on the card where the feature is then disabled.
pub fn check_revoked(image: &[u8], serial: u64, csn_size: usize, order: CsnOrder) -> Option<Revocation> {
    if csn_size != CSN_SIZE || image.len() < CSN_SIZE {
        return None;
    }
    let threshold = order.decode(image);
    if serial <= u64::from(threshold) {
        return Some(Revocation::AllBefore { serial, threshold });
    }
    for chunk in image[CSN_SIZE..].chunks_exact(CSN_SIZE) {
        let v = order.decode(chunk);
        if v == 0 {
            break;
        }
        if u64::from(v) == serial {
            return Some(Revocation::Listed { serial });
        }
    }
    None
}

/// The parameters of a CRLFile update that the CRLSignature covers (7.10.2.3.3): the whole native WriteData.
#[derive(Debug, Clone, Copy)]
pub struct CrlUpdate<'a> {
    /// Command code of WriteData.
    pub cmd: u8,
    pub file_no: u8,
    pub version: u16,
    pub offset: u32,
    pub data: &'a [u8],
}

impl CrlUpdate<'_> {
    /// `Cmd || FileNo || CRLVersion || Offset || Length || Data`, multi-byte fields LSB first.
    pub fn message(&self) -> Vec<u8> {
        let mut m = vec![self.cmd, self.file_no];
        m.extend(self.version.to_le_bytes());
        m.extend(&self.offset.to_le_bytes()[..3]);
        m.extend(&(self.data.len() as u32).to_le_bytes()[..3]);
        m.extend(self.data);
        m
    }

    /// 64-byte `r || s` ECDSA-SHA256 signature with the CA key the file's CRLSigKey refers to.
    pub fn sign(&self, key: &PrivKey) -> Result<Vec<u8>> {
        Ok(key.sign_raw(&self.message())?)
    }
}

/// Per-CA revocation state kept in the store.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CrlState {
    /// CRLVersion the next update will carry.
    #[serde(default)]
    pub version: u16,
    /// CSNAllBefore.
    #[serde(default)]
    pub all_before: u32,
    /// Individually revoked serial numbers, sorted.
    #[serde(default)]
    pub serials: Vec<u32>,
}

impl CrlState {
    pub fn image(&self, size: Option<usize>, order: CsnOrder) -> Result<Vec<u8>> {
        build_image(self.all_before, &self.serials, size, order)
    }

    pub fn is_listed(&self, serial: u32) -> bool {
        self.serials.binary_search(&serial).is_ok()
    }

    /// Add or remove a serial, keeping the list sorted and duplicate free.
    pub fn set_revoked(&mut self, serial: u32, revoked: bool) {
        match (self.serials.binary_search(&serial), revoked) {
            (Err(i), true) => self.serials.insert(i, serial),
            (Ok(i), false) => {
                self.serials.remove(i);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{gen_key, CURVE_P256};

    #[test]
    fn image_layout_and_roundtrip() {
        let img = build_image(5, &[7, 9], None, CsnOrder::MsbFirst).unwrap();
        assert_eq!(img, [0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 0]);
        assert_eq!(parse_image(&img, CsnOrder::MsbFirst), (5, vec![7, 9]));
        let le = build_image(5, &[7], Some(16), CsnOrder::LsbFirst).unwrap();
        assert_eq!(le, [5, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_image(&le, CsnOrder::LsbFirst), (5, vec![7]));
        // exactly full file: terminator dropped
        let full = build_image(1, &[2], Some(8), CsnOrder::MsbFirst).unwrap();
        assert_eq!(full.len(), 8);
        assert_eq!(parse_image(&full, CsnOrder::MsbFirst), (1, vec![2]));
        assert!(build_image(1, &[2, 3], Some(8), CsnOrder::MsbFirst).is_err());
        assert!(build_image(1, &[0], None, CsnOrder::MsbFirst).is_err());
        assert_eq!(parse_image(&[], CsnOrder::MsbFirst), (0, vec![]));
    }

    #[test]
    fn revocation_rules() {
        let img = build_image(10, &[20, 30], Some(64), CsnOrder::MsbFirst).unwrap();
        let chk = |s| check_revoked(&img, s, 4, CsnOrder::MsbFirst);
        assert_eq!(chk(10), Some(Revocation::AllBefore { serial: 10, threshold: 10 }));
        assert_eq!(chk(1), Some(Revocation::AllBefore { serial: 1, threshold: 10 }));
        assert_eq!(chk(11), None);
        assert_eq!(chk(20), Some(Revocation::Listed { serial: 20 }));
        assert_eq!(chk(30).unwrap().to_string(), "serial 30 is listed");
        assert_eq!(chk(31), None);
        // entries behind the zero terminator are ignored
        let mut img2 = build_image(0, &[5], Some(64), CsnOrder::MsbFirst).unwrap();
        img2[12..16].copy_from_slice(&99u32.to_be_bytes());
        assert_eq!(check_revoked(&img2, 99, 4, CsnOrder::MsbFirst), None);
        // byte order matters
        assert!(matches!(check_revoked(&img, 20, 4, CsnOrder::LsbFirst), Some(Revocation::AllBefore { .. })));
        // disabled
        assert_eq!(check_revoked(&img, 20, 0, CsnOrder::MsbFirst), None);
        assert_eq!(check_revoked(&[1, 2], 1, 4, CsnOrder::MsbFirst), None);
    }

    #[test]
    fn signature_message_layout() {
        let u = CrlUpdate { cmd: 0x8D, file_no: 4, version: 0x0102, offset: 0x030405, data: &[0xAA, 0xBB] };
        assert_eq!(u.message(), [0x8D, 4, 0x02, 0x01, 0x05, 0x04, 0x03, 2, 0, 0, 0xAA, 0xBB]);
        let k = gen_key(CURVE_P256).unwrap();
        let sig = u.sign(&k).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(k.public().verify_raw(&sig, &u.message()));
    }

    #[test]
    fn state_keeps_sorted_unique() {
        let mut s = CrlState::default();
        for v in [5, 3, 5, 9] {
            s.set_revoked(v, true);
        }
        assert_eq!(s.serials, [3, 5, 9]);
        s.set_revoked(5, false);
        s.set_revoked(77, false);
        assert_eq!(s.serials, [3, 9]);
        assert!(s.is_listed(9) && !s.is_listed(5));
    }
}
