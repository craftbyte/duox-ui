//! Secure Dynamic Messaging (data sheet 7.5.11, 7.12.2.1, 8.7.12).
//!
//! This module covers
//! * [`SdmSettings`]: the SDM part of ChangeFileSettings / GetFileSettings (encode, parse, validate),
//! * [`build_ndef_template`]: an NDEF URL template builder that computes every offset,
//! * [`render`]: the card side, producing the dynamic file data an unauthenticated reader sees,
//! * [`verify`] / [`verify_url`]: the back-end side (PICCData decryption, SDMENCFileData, SDMMAC,
//!   SDMSIG, session keys and read counter checks).

use crate::crypto::{self, CryptoError, PrivKey, PubKey};
use thiserror::Error;

/// `SDMOptions` bit 7: mirror the UID (VCUID).
pub const OPT_UID: u8 = 0x80;
/// `SDMOptions` bit 6: mirror the SDMReadCtr.
pub const OPT_CTR: u8 = 0x40;
/// `SDMOptions` bit 5: SDMReadCtrLimit present.
pub const OPT_CTR_LIMIT: u8 = 0x20;
/// `SDMOptions` bit 4: SDMENCFileData.
pub const OPT_ENC: u8 = 0x10;
/// `SDMOptions` bit 3: GPIOStatus mirroring.
pub const OPT_GPIO: u8 = 0x08;
/// `SDMOptions` bit 0: ASCII encoding (the only mode supported by the card).
pub const OPT_ASCII: u8 = 0x01;

/// Access right nibble: free access / plain mirroring (SDMMetaRead, SDMCtrRet).
pub const AC_FREE: u8 = 0xE;
/// Access right nibble: no access / feature disabled.
pub const AC_NONE: u8 = 0xF;

/// Offset value meaning "counter is enabled but not mirrored in the file".
pub const NO_MIRROR: u32 = 0xFF_FFFF;
/// ASCII length of a mirrored SDMMAC (8 bytes).
pub const MAC_LEN: usize = 16;
/// ASCII length of a mirrored SDMSIG (64 bytes).
pub const SIG_LEN: usize = 128;
/// ASCII length of a mirrored SDMReadCtr (3 bytes).
pub const CTR_LEN: usize = 6;
/// Length of the mirrored GPIOStatus.
pub const GPIO_LEN: usize = 3;

/// Errors of the SDM module.
#[derive(Debug, Error)]
pub enum SdmError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("SDM settings: {0}")]
    Settings(String),
    #[error("SDM settings truncated")]
    Truncated,
    #[error("{0} lies outside the file data")]
    OutOfRange(&'static str),
    #[error("{0} is not ASCII hex - wrong offset or the data was read authenticated")]
    NotHex(&'static str),
    #[error("{0} is required")]
    MissingKey(&'static str),
    #[error("PICCDataTag 0x{0:02X} is not plausible - wrong SDMMetaRead key?")]
    ImplausiblePiccTag(u8),
    #[error("NDEF template: {0}")]
    Template(String),
    #[error("NDEF: {0}")]
    Ndef(String),
}

type Result<T> = std::result::Result<T, SdmError>;

fn le3(v: u32) -> [u8; 3] {
    let b = v.to_le_bytes();
    [b[0], b[1], b[2]]
}
fn from_le3(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], 0])
}
fn upper_hex(b: &[u8]) -> Vec<u8> {
    hex::encode_upper(b).into_bytes()
}

// ------------------------------------------------------------------ settings

/// Optional offset fields of the SDM settings, in wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdmField {
    UidOffset,
    CtrOffset,
    PiccOffset,
    GpioOffset,
    MacInputOffset,
    EncOffset,
    EncLength,
    MacOffset,
    CtrLimit,
}

impl SdmField {
    /// Data sheet name of the field.
    pub fn name(self) -> &'static str {
        match self {
            SdmField::UidOffset => "VCUIDOffset",
            SdmField::CtrOffset => "SDMReadCtrOffset",
            SdmField::PiccOffset => "PICCDataOffset",
            SdmField::GpioOffset => "GPIOStatusOffset",
            SdmField::MacInputOffset => "SDMMACInputOffset",
            SdmField::EncOffset => "SDMENCOffset",
            SdmField::EncLength => "SDMENCLength",
            SdmField::MacOffset => "SDMMACOffset",
            SdmField::CtrLimit => "SDMReadCtrLimit",
        }
    }
}

/// SDM file settings (8.7.12): options, SDM access rights and the offsets that are present for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmSettings {
    /// `SDMOptions` byte (see the `OPT_*` constants).
    pub options: u8,
    /// `SDMAccessRights.SDMMetaRead`: 0..=0xD AES key for encrypted PICCData, 0xE plain, 0xF none.
    pub meta_read: u8,
    /// `SDMFileRead`: AES key number for SDMMAC / SDMENCFileData, 0xF none.
    pub file_read: u8,
    /// `SDMFileRead2`: ECC private key number for SDMSIG, 0xF none.
    pub file_read2: u8,
    /// `SDMCtrRet`: who may read the counter, 0xE free, 0xF none.
    pub ctr_ret: u8,
    pub uid_offset: Option<u32>,
    pub ctr_offset: Option<u32>,
    pub picc_offset: Option<u32>,
    pub gpio_offset: Option<u32>,
    pub mac_input_offset: Option<u32>,
    pub enc_offset: Option<u32>,
    /// ASCII length of the SDMENCFileData placeholder.
    pub enc_length: Option<u32>,
    pub mac_offset: Option<u32>,
    pub ctr_limit: Option<u32>,
}

impl Default for SdmSettings {
    fn default() -> Self {
        SdmSettings {
            options: OPT_ASCII,
            meta_read: AC_NONE,
            file_read: AC_NONE,
            file_read2: AC_NONE,
            ctr_ret: AC_NONE,
            uid_offset: None,
            ctr_offset: None,
            picc_offset: None,
            gpio_offset: None,
            mac_input_offset: None,
            enc_offset: None,
            enc_length: None,
            mac_offset: None,
            ctr_limit: None,
        }
    }
}

/// Kind of a mirrored region of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    Vcuid,
    ReadCtr,
    PiccData,
    GpioStatus,
    EncFileData,
    Mac,
    Sig,
}

impl RegionKind {
    pub fn name(self) -> &'static str {
        match self {
            RegionKind::Vcuid => "VCUID",
            RegionKind::ReadCtr => "SDMReadCtr",
            RegionKind::PiccData => "PICCData",
            RegionKind::GpioStatus => "GPIOStatus",
            RegionKind::EncFileData => "SDMENCFileData",
            RegionKind::Mac => "SDMMAC",
            RegionKind::Sig => "SDMSIG",
        }
    }
}

/// A region of the file that is overwritten with dynamic data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub kind: RegionKind,
    pub offset: usize,
    pub len: usize,
}

impl SdmSettings {
    /// Optional fields present on the wire for this configuration (8.7.12, Table 45).
    pub fn wire_fields(&self) -> Vec<SdmField> {
        let mut f = Vec::new();
        if self.options & OPT_UID != 0 && self.meta_read == AC_FREE {
            f.push(SdmField::UidOffset);
        }
        if self.options & OPT_CTR != 0 && self.meta_read == AC_FREE {
            f.push(SdmField::CtrOffset);
        }
        if self.meta_read <= 0xD {
            f.push(SdmField::PiccOffset);
        }
        if self.options & OPT_GPIO != 0 {
            f.push(SdmField::GpioOffset);
        }
        let sdm_read = self.file_read != AC_NONE || self.file_read2 != AC_NONE;
        if sdm_read {
            f.push(SdmField::MacInputOffset);
        }
        if self.file_read != AC_NONE && self.options & OPT_ENC != 0 {
            f.push(SdmField::EncOffset);
            f.push(SdmField::EncLength);
        }
        if sdm_read {
            f.push(SdmField::MacOffset);
        }
        if self.options & OPT_CTR_LIMIT != 0 {
            f.push(SdmField::CtrLimit);
        }
        f
    }

    /// Read a field by name.
    pub fn get(&self, f: SdmField) -> Option<u32> {
        match f {
            SdmField::UidOffset => self.uid_offset,
            SdmField::CtrOffset => self.ctr_offset,
            SdmField::PiccOffset => self.picc_offset,
            SdmField::GpioOffset => self.gpio_offset,
            SdmField::MacInputOffset => self.mac_input_offset,
            SdmField::EncOffset => self.enc_offset,
            SdmField::EncLength => self.enc_length,
            SdmField::MacOffset => self.mac_offset,
            SdmField::CtrLimit => self.ctr_limit,
        }
    }

    /// Write a field by name.
    pub fn set(&mut self, f: SdmField, v: Option<u32>) {
        match f {
            SdmField::UidOffset => self.uid_offset = v,
            SdmField::CtrOffset => self.ctr_offset = v,
            SdmField::PiccOffset => self.picc_offset = v,
            SdmField::GpioOffset => self.gpio_offset = v,
            SdmField::MacInputOffset => self.mac_input_offset = v,
            SdmField::EncOffset => self.enc_offset = v,
            SdmField::EncLength => self.enc_length = v,
            SdmField::MacOffset => self.mac_offset = v,
            SdmField::CtrLimit => self.ctr_limit = v,
        }
    }

    /// The 16-bit `SDMAccessRights` value (MetaRead | FileRead | FileRead2 | CtrRet nibbles).
    pub fn access_rights(&self) -> u16 {
        (u16::from(self.meta_read & 0xF) << 12)
            | (u16::from(self.file_read & 0xF) << 8)
            | (u16::from(self.file_read2 & 0xF) << 4)
            | u16::from(self.ctr_ret & 0xF)
    }

    /// Serialise as `SDMOptions | SDMAccessRights | offsets...` (all multi-byte values LSB first).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![self.options];
        out.extend_from_slice(&self.access_rights().to_le_bytes());
        for f in self.wire_fields() {
            let v = self
                .get(f)
                .ok_or_else(|| SdmError::Settings(format!("{} is required for this configuration", f.name())))?;
            if v > 0xFF_FFFF {
                return Err(SdmError::Settings(format!("{} does not fit in 3 bytes", f.name())));
            }
            out.extend_from_slice(&le3(v));
        }
        Ok(out)
    }

    /// Parse the serialised form; returns the settings and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(SdmSettings, usize)> {
        if data.len() < 3 {
            return Err(SdmError::Truncated);
        }
        let ar = u16::from_le_bytes([data[1], data[2]]);
        let mut s = SdmSettings {
            options: data[0],
            meta_read: (ar >> 12) as u8,
            file_read: ((ar >> 8) & 0xF) as u8,
            file_read2: ((ar >> 4) & 0xF) as u8,
            ctr_ret: (ar & 0xF) as u8,
            ..Default::default()
        };
        let mut pos = 3;
        for f in s.wire_fields() {
            let b = data.get(pos..pos + 3).ok_or(SdmError::Truncated)?;
            s.set(f, Some(from_le3(b)));
            pos += 3;
        }
        Ok((s, pos))
    }

    /// True if an SDMSIG (ECC signature) is mirrored.
    pub fn uses_sig(&self) -> bool {
        self.file_read2 != AC_NONE
    }

    /// True if a symmetric SDMMAC is mirrored.
    pub fn uses_mac(&self) -> bool {
        self.file_read != AC_NONE && self.file_read2 == AC_NONE
    }

    /// ASCII length of the encrypted PICCData placeholder (32, or 64 for a 10-byte UID without counter).
    pub fn picc_len(&self, uid_len: usize) -> usize {
        if uid_len == 10 && self.options & OPT_UID != 0 && self.options & OPT_CTR == 0 {
            64
        } else {
            32
        }
    }

    /// ASCII length of the mirrored SDMMAC / SDMSIG.
    pub fn auth_len(&self) -> usize {
        if self.uses_sig() {
            SIG_LEN
        } else {
            MAC_LEN
        }
    }

    /// Mirrored regions in wire order.
    pub fn regions(&self, uid_len: usize) -> Vec<Region> {
        let mut r = Vec::new();
        for f in self.wire_fields() {
            let Some(off) = self.get(f) else { continue };
            let offset = off as usize;
            let (kind, len) = match f {
                SdmField::UidOffset => (RegionKind::Vcuid, 2 * uid_len),
                SdmField::CtrOffset if off != NO_MIRROR => (RegionKind::ReadCtr, CTR_LEN),
                SdmField::PiccOffset => (RegionKind::PiccData, self.picc_len(uid_len)),
                SdmField::GpioOffset => (RegionKind::GpioStatus, GPIO_LEN),
                SdmField::EncOffset => match self.enc_length {
                    Some(l) => (RegionKind::EncFileData, l as usize),
                    None => continue,
                },
                SdmField::MacOffset => {
                    (if self.uses_sig() { RegionKind::Sig } else { RegionKind::Mac }, self.auth_len())
                }
                _ => continue,
            };
            r.push(Region { kind, offset, len });
        }
        r
    }

    /// Check the placement rules the card enforces (8.7.12). Returns the problems found.
    pub fn validate(&self, file_size: usize, uid_len: usize) -> Vec<String> {
        let mut p: Vec<String> = Vec::new();
        let o = self.options;
        if o & OPT_ASCII == 0 {
            p.push("Encoding mode must be ASCII (SDMOptions bit 0).".into());
        }
        if let Err(e) = self.encode() {
            p.push(e.to_string());
            return p;
        }
        if self.meta_read != AC_NONE && o & (OPT_UID | OPT_CTR) == 0 {
            p.push("SDMMetaRead is set but neither VCUID nor SDMReadCtr mirroring is enabled.".into());
        }
        if self.meta_read == AC_NONE && o & OPT_UID != 0 {
            p.push("VCUID mirroring enabled while SDMMetaRead = 0xF.".into());
        }
        if self.ctr_ret != AC_NONE && o & OPT_CTR == 0 {
            p.push("SDMCtrRet set while SDMReadCtr is disabled.".into());
        }
        if o & OPT_CTR_LIMIT != 0 && o & OPT_CTR == 0 {
            p.push("SDMReadCtrLimit set while SDMReadCtr is disabled.".into());
        }
        if o & OPT_ENC != 0 {
            if self.file_read == AC_NONE {
                p.push("SDMENCFileData requires SDMFileRead to name an AES key.".into());
            }
            if o & (OPT_UID | OPT_CTR) != (OPT_UID | OPT_CTR) {
                p.push("SDMENCFileData requires both VCUID and SDMReadCtr mirroring.".into());
            }
            if let Some(l) = self.enc_length {
                if l % 32 != 0 || l < 32 {
                    p.push("SDMENCLength must be a non-zero multiple of 32.".into());
                }
            }
        }
        if self.file_read != AC_NONE && self.file_read2 != AC_NONE && o & OPT_ENC == 0 {
            p.push("With both SDMFileRead and SDMFileRead2 set, SDMENCFileData must be enabled (Table 45).".into());
        }
        let regs = self.regions(uid_len);
        for r in &regs {
            if r.offset + r.len > file_size {
                p.push(format!(
                    "{} at {}+{} exceeds the file size ({}).",
                    r.kind.name(),
                    r.offset,
                    r.len,
                    file_size
                ));
            }
        }
        for (i, a) in regs.iter().enumerate() {
            for b in &regs[i + 1..] {
                if a.offset < b.offset + b.len && b.offset < a.offset + a.len {
                    // GPIOStatus may sit in the plaintext half of the ENC region.
                    let pair = match (a.kind, b.kind) {
                        (RegionKind::GpioStatus, RegionKind::EncFileData) => Some((a, b)),
                        (RegionKind::EncFileData, RegionKind::GpioStatus) => Some((b, a)),
                        _ => None,
                    };
                    if let Some((g, e)) = pair {
                        if g.offset >= e.offset && g.offset + GPIO_LEN <= e.offset + e.len / 2 {
                            continue;
                        }
                    }
                    p.push(format!("{} and {} overlap.", a.kind.name(), b.kind.name()));
                }
            }
        }
        if let (Some(mac), Some(inp)) = (self.mac_offset, self.mac_input_offset) {
            if inp > mac {
                p.push("SDMMACInputOffset must not be larger than SDMMACOffset.".into());
            }
            if let (Some(eo), Some(el)) = (self.enc_offset, self.enc_length) {
                if eo < inp {
                    p.push("SDMENCOffset must not be smaller than SDMMACInputOffset.".into());
                }
                if mac < eo + el {
                    p.push("SDMMACOffset must follow the SDMENCFileData placeholder.".into());
                }
            }
        }
        p
    }

    /// Human readable one-line-per-field description.
    pub fn describe(&self) -> Vec<String> {
        let o = self.options;
        let flags: Vec<&str> = [
            (OPT_UID, "VCUID"),
            (OPT_CTR, "SDMReadCtr"),
            (OPT_CTR_LIMIT, "CtrLimit"),
            (OPT_ENC, "SDMENCFileData"),
            (OPT_GPIO, "GPIOStatus"),
            (OPT_ASCII, "ASCII"),
        ]
        .iter()
        .filter(|(b, _)| o & b != 0)
        .map(|(_, n)| *n)
        .collect();
        let ac = |v: u8, plain: &str, none: &str, key: &str| match v {
            0xE => plain.to_string(),
            0xF => none.to_string(),
            k => format!("{key} {k:X}"),
        };
        let mut lines = vec![
            format!("SDMOptions       0x{:02X}  ({})", o, if flags.is_empty() { "-".into() } else { flags.join(", ") }),
            format!("SDMMetaRead      {}", ac(self.meta_read, "plain PICCData", "no PICCData", "key")),
            format!("SDMFileRead      {}", ac(self.file_read, "RFU", "no symmetric SDM", "key")),
            format!("SDMFileRead2     {}", ac(self.file_read2, "RFU", "no SDMSIG", "ECC key")),
            format!("SDMCtrRet        {}", ac(self.ctr_ret, "free", "no access", "key")),
        ];
        for f in self.wire_fields() {
            let v = self.get(f).map_or("?".to_string(), |v| v.to_string());
            lines.push(format!("{:<17}{}", f.name(), v));
        }
        lines
    }
}

// ----------------------------------------------------------- key derivation

/// Session keys `(K_SesSDMFileReadENC, K_SesSDMFileReadMAC)` (7.5.11.1.12).
///
/// `uid` / `ctr` are `None` when not mirrored. The ENC key is only meaningful when both are given.
pub fn session_keys(file_read_key: &[u8], uid: Option<&[u8]>, ctr: Option<u32>) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ctx = uid.map(<[u8]>::to_vec).unwrap_or_default();
    if let Some(c) = ctr {
        ctx.extend_from_slice(&le3(c));
    }
    let sv = |label: [u8; 2], i: u8, len: [u8; 2]| {
        let mut v = vec![label[0], label[1], 0, i, len[0], len[1]];
        v.extend_from_slice(&ctx);
        while v.len() % 16 != 0 {
            v.push(0);
        }
        v
    };
    match file_read_key.len() {
        16 => Ok((
            crypto::aes_cmac(file_read_key, &sv([0xC3, 0x3C], 1, [0x00, 0x80]))?,
            crypto::aes_cmac(file_read_key, &sv([0x3C, 0xC3], 1, [0x00, 0x80]))?,
        )),
        32 => {
            let (mut enc, mut mac) = (Vec::new(), Vec::new());
            for i in [1u8, 2] {
                enc.extend(crypto::aes_cmac(file_read_key, &sv([0xC3, 0x3C], i, [0x01, 0x00]))?);
                mac.extend(crypto::aes_cmac(file_read_key, &sv([0x3C, 0xC3], i, [0x01, 0x00]))?);
            }
            Ok((enc, mac))
        }
        n => Err(SdmError::Settings(format!("AES key must be 16 or 32 bytes, got {n}"))),
    }
}

/// IV of SDMENCFileData: AES-ECB(K_ENC, SDMReadCtr (3 bytes LSB first) || 13 zero bytes).
fn enc_file_iv(kenc: &[u8], ctr: u32) -> Result<Vec<u8>> {
    let mut b = le3(ctr).to_vec();
    b.extend_from_slice(&[0u8; 13]);
    Ok(crypto::aes_ecb_enc(kenc, &b)?)
}

/// Decrypt SDMENCFileData (hex-decoded ciphertext) with the session ENC key.
pub fn decrypt_enc_file_data(kenc: &[u8], ctr: u32, ct: &[u8]) -> Result<Vec<u8>> {
    Ok(crypto::aes_cbc_dec(kenc, ct, &enc_file_iv(kenc, ctr)?)?)
}

/// Encrypt SDMENCFileData plaintext (multiple of 16 bytes) with the session ENC key.
pub fn encrypt_enc_file_data(kenc: &[u8], ctr: u32, pt: &[u8]) -> Result<Vec<u8>> {
    Ok(crypto::aes_cbc_enc(kenc, pt, &enc_file_iv(kenc, ctr)?)?)
}

// -------------------------------------------------------------- PICCData

/// Decoded PICCData.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiccData {
    /// PICCDataTag (bit 7 UID mirrored, bit 6 counter mirrored, low nibble UID length).
    pub tag: u8,
    pub uid: Option<Vec<u8>>,
    pub ctr: Option<u32>,
    /// Full decrypted block(s).
    pub plain: Vec<u8>,
}

/// Build and encrypt the PICCData block for a read (7.5.11.1.12). Padding bytes are random.
pub fn encrypt_picc_data(meta_key: &[u8], options: u8, uid: &[u8], ctr: u32) -> Result<Vec<u8>> {
    let mut tag = 0u8;
    if options & OPT_UID != 0 {
        tag |= 0x80 | (uid.len() as u8 & 0x0F);
    }
    if options & OPT_CTR != 0 {
        tag |= 0x40;
    }
    let pt = if uid.len() == 10 && options & OPT_UID != 0 && options & OPT_CTR == 0 {
        let mut v = vec![tag];
        v.extend(crypto::rnd(21));
        v.extend_from_slice(uid);
        v
    } else {
        let mut v = vec![tag];
        if options & OPT_UID != 0 {
            v.extend_from_slice(uid);
        }
        if options & OPT_CTR != 0 {
            v.extend_from_slice(&le3(ctr));
        }
        if v.len() > 16 {
            return Err(SdmError::Settings("PICCData does not fit in one block".into()));
        }
        let pad = crypto::rnd(16 - v.len());
        v.extend(pad);
        v
    };
    Ok(crypto::aes_cbc_enc(meta_key, &pt, &crypto::ZERO_IV)?)
}

/// Decrypt PICCData (hex-decoded ciphertext, 16 or 32 bytes).
pub fn decrypt_picc_data(meta_key: &[u8], ct: &[u8]) -> Result<PiccData> {
    let pt = crypto::aes_cbc_dec(meta_key, ct, &crypto::ZERO_IV)?;
    let tag = *pt.first().ok_or(SdmError::Truncated)?;
    let ulen = usize::from(tag & 0x0F);
    if tag & 0x80 != 0 && ulen != 7 && ulen != 10 {
        return Err(SdmError::ImplausiblePiccTag(tag));
    }
    if pt.len() == 32 {
        let uid = pt[22..32].to_vec();
        return Ok(PiccData { tag, uid: Some(uid), ctr: None, plain: pt });
    }
    let mut pos = 1;
    let mut uid = None;
    let mut ctr = None;
    if tag & 0x80 != 0 {
        uid = Some(pt.get(pos..pos + ulen).ok_or(SdmError::Truncated)?.to_vec());
        pos += ulen;
    }
    if tag & 0x40 != 0 {
        ctr = Some(from_le3(pt.get(pos..pos + 3).ok_or(SdmError::Truncated)?));
    }
    Ok(PiccData { tag, uid, ctr, plain: pt })
}

// ------------------------------------------------------- render (card side)

/// Keys the card uses when rendering the dynamic file data.
#[derive(Default, Clone, Copy)]
pub struct RenderKeys<'a> {
    /// SDMMetaRead AES key (needed when `meta_read` is 0..=0xD).
    pub meta_key: Option<&'a [u8]>,
    /// SDMFileRead AES key (needed when `file_read` != 0xF).
    pub file_key: Option<&'a [u8]>,
    /// SDMFileRead2 ECC private key; without it the SDMSIG placeholder stays untouched.
    pub sig_key: Option<&'a PrivKey>,
}

fn put(d: &mut [u8], off: u32, data: &[u8], what: &'static str) -> Result<()> {
    let off = off as usize;
    d.get_mut(off..off + data.len()).ok_or(SdmError::OutOfRange(what))?.copy_from_slice(data);
    Ok(())
}
fn need(v: Option<u32>, what: &'static str) -> Result<u32> {
    v.ok_or_else(|| SdmError::Settings(format!("{what} missing")))
}

/// Produce the dynamic file data an unauthenticated reader sees (the card side of SDM).
///
/// `random_id` renders an all-zero VCUID mirror, as a card with Random ID would.
pub fn render(
    static_data: &[u8],
    cfg: &SdmSettings,
    uid: &[u8],
    ctr: u32,
    keys: &RenderKeys<'_>,
    gpio: &[u8; 3],
    random_id: bool,
) -> Result<Vec<u8>> {
    let mut d = static_data.to_vec();
    let o = cfg.options;
    if cfg.meta_read == AC_FREE {
        if o & OPT_UID != 0 {
            let off = need(cfg.uid_offset, "VCUIDOffset")?;
            let shown = if random_id { vec![0u8; uid.len()] } else { uid.to_vec() };
            put(&mut d, off, &upper_hex(&shown), "VCUID")?;
        }
        if o & OPT_CTR != 0 {
            if let Some(off) = cfg.ctr_offset.filter(|&v| v != NO_MIRROR) {
                put(&mut d, off, format!("{:06X}", ctr & 0xFF_FFFF).as_bytes(), "SDMReadCtr")?;
            }
        }
    } else if cfg.meta_read <= 0xD {
        let mk = keys.meta_key.ok_or(SdmError::MissingKey("SDMMetaRead key"))?;
        let off = need(cfg.picc_offset, "PICCDataOffset")?;
        put(&mut d, off, &upper_hex(&encrypt_picc_data(mk, o, uid, ctr)?), "PICCData")?;
    }
    if o & OPT_GPIO != 0 {
        if let Some(off) = cfg.gpio_offset {
            put(&mut d, off, gpio, "GPIOStatus")?;
        }
    }
    let mut kmac = None;
    if cfg.file_read != AC_NONE {
        let fk = keys.file_key.ok_or(SdmError::MissingKey("SDMFileRead key"))?;
        let (kenc, km) =
            session_keys(fk, (o & OPT_UID != 0).then_some(uid), (o & OPT_CTR != 0).then_some(ctr))?;
        kmac = Some(km);
        if o & OPT_ENC != 0 {
            let eo = need(cfg.enc_offset, "SDMENCOffset")? as usize;
            let half = need(cfg.enc_length, "SDMENCLength")? as usize / 2;
            let pt = d.get(eo..eo + half).ok_or(SdmError::OutOfRange("SDMENCFileData"))?.to_vec();
            let ct = encrypt_enc_file_data(&kenc, ctr, &pt)?;
            put(&mut d, eo as u32, &upper_hex(&ct), "SDMENCFileData")?;
        }
    }
    if cfg.file_read != AC_NONE || cfg.file_read2 != AC_NONE {
        let inp = need(cfg.mac_input_offset, "SDMMACInputOffset")?;
        let mo = need(cfg.mac_offset, "SDMMACOffset")?;
        let msg = d.get(inp as usize..mo as usize).ok_or(SdmError::OutOfRange("SDMMAC input"))?.to_vec();
        if cfg.uses_sig() {
            if let Some(k) = keys.sig_key {
                put(&mut d, mo, &upper_hex(&k.sign_raw(&msg)?), "SDMSIG")?;
            }
        } else if let Some(km) = kmac {
            put(&mut d, mo, &upper_hex(&crypto::mact(&km, &msg)?), "SDMMAC")?;
        }
    }
    Ok(d)
}

// ------------------------------------------------------ verify (back-end)

/// Inputs of a back-end verification.
#[derive(Default, Clone, Copy)]
pub struct VerifyParams<'a> {
    /// UID length of the card (7 or 10); 0 is treated as 7.
    pub uid_len: usize,
    pub meta_key: Option<&'a [u8]>,
    pub file_key: Option<&'a [u8]>,
    pub sig_pub: Option<&'a PubKey>,
    /// Real UID, used when the VCUID is not mirrored or the card uses Random ID.
    pub uid: Option<&'a [u8]>,
    /// Highest counter value accepted so far for this card; a read must exceed it (replay protection).
    pub last_ctr: Option<u32>,
}

/// Result of a back-end verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SdmResult {
    pub uid: Option<Vec<u8>>,
    pub ctr: Option<u32>,
    pub picc_tag: Option<u8>,
    /// Decrypted SDMENCFileData.
    pub enc_plain: Option<Vec<u8>>,
    pub gpio: Option<Vec<u8>>,
    pub mac_ok: Option<bool>,
    pub sig_ok: Option<bool>,
    /// `Some(true)` if the counter is greater than `last_ctr`.
    pub ctr_fresh: Option<bool>,
    /// `Some(true)` if the counter is within SDMReadCtrLimit (or at most 0xFFFFFF without a limit).
    pub ctr_within_limit: Option<bool>,
    pub notes: Vec<String>,
}

impl SdmResult {
    /// True if at least one authenticity check ran, all passed, and no counter check failed.
    pub fn ok(&self) -> bool {
        let auth: Vec<bool> = [self.mac_ok, self.sig_ok].into_iter().flatten().collect();
        !auth.is_empty()
            && auth.iter().all(|&b| b)
            && self.ctr_fresh != Some(false)
            && self.ctr_within_limit != Some(false)
    }
}

fn unhex(d: &[u8], off: u32, len: usize, what: &'static str) -> Result<Vec<u8>> {
    let off = off as usize;
    let s = d.get(off..off + len).ok_or(SdmError::OutOfRange(what))?;
    let s = std::str::from_utf8(s).map_err(|_| SdmError::NotHex(what))?;
    hex::decode(s).map_err(|_| SdmError::NotHex(what))
}

/// Verify dynamic file data the way a back-end would (7.5.11).
pub fn verify(dynamic: &[u8], cfg: &SdmSettings, p: &VerifyParams<'_>) -> Result<SdmResult> {
    let uid_len = if p.uid_len == 0 { 7 } else { p.uid_len };
    let mut r = SdmResult::default();
    let o = cfg.options;
    if cfg.meta_read == AC_FREE {
        if o & OPT_UID != 0 {
            if let Some(off) = cfg.uid_offset {
                let u = unhex(dynamic, off, 2 * uid_len, "VCUID mirror")?;
                if u.iter().all(|&b| b == 0) {
                    r.notes.push("VCUID mirror is all zero (card uses Random ID); pass the real UID to verify.".into());
                    r.uid = p.uid.map(<[u8]>::to_vec);
                } else {
                    r.uid = Some(u);
                }
            }
        }
        if o & OPT_CTR != 0 {
            if let Some(off) = cfg.ctr_offset.filter(|&v| v != NO_MIRROR) {
                let b = unhex(dynamic, off, CTR_LEN, "SDMReadCtr mirror")?;
                r.ctr = Some(u32::from_be_bytes([0, b[0], b[1], b[2]]));
            }
        }
    } else if cfg.meta_read <= 0xD {
        let mk = p.meta_key.ok_or(SdmError::MissingKey("SDMMetaRead key"))?;
        let off = need(cfg.picc_offset, "PICCDataOffset")?;
        let ct = unhex(dynamic, off, cfg.picc_len(uid_len), "PICCData")?;
        let pd = decrypt_picc_data(mk, &ct)?;
        r.uid = pd.uid;
        r.ctr = pd.ctr;
        r.picc_tag = Some(pd.tag);
    }
    if r.uid.is_none() && o & OPT_UID != 0 {
        r.uid = p.uid.map(<[u8]>::to_vec);
    }
    if o & OPT_GPIO != 0 && o & OPT_ENC == 0 {
        if let Some(off) = cfg.gpio_offset {
            let off = off as usize;
            r.gpio = Some(dynamic.get(off..off + GPIO_LEN).ok_or(SdmError::OutOfRange("GPIOStatus"))?.to_vec());
        }
    }
    if let Some(c) = r.ctr {
        if let Some(last) = p.last_ctr {
            r.ctr_fresh = Some(c > last);
            if c <= last {
                r.notes.push(format!("SDMReadCtr {c} is not greater than the last accepted value {last} (replay?)."));
            }
        }
        let limit = if o & OPT_CTR_LIMIT != 0 { cfg.ctr_limit.unwrap_or(0xFF_FFFF) } else { 0xFF_FFFF };
        r.ctr_within_limit = Some(c <= limit);
    }
    let mut kmac = None;
    if cfg.file_read != AC_NONE {
        if let Some(fk) = p.file_key {
            let uid_ctx = if o & OPT_UID != 0 { r.uid.as_deref() } else { None };
            let ctr_ctx = if o & OPT_CTR != 0 { r.ctr } else { None };
            let (kenc, km) = session_keys(fk, uid_ctx, ctr_ctx)?;
            kmac = Some(km);
            if o & OPT_ENC != 0 {
                match r.ctr {
                    Some(c) if r.uid.is_some() => {
                        let eo = need(cfg.enc_offset, "SDMENCOffset")?;
                        let el = need(cfg.enc_length, "SDMENCLength")? as usize;
                        let ct = unhex(dynamic, eo, el, "SDMENCFileData")?;
                        r.enc_plain = Some(decrypt_enc_file_data(&kenc, c, &ct)?);
                    }
                    _ => r.notes.push("SDMENCFileData not decrypted (UID or counter missing).".into()),
                }
            }
        } else if o & OPT_ENC != 0 {
            r.notes.push("SDMENCFileData not decrypted (SDMFileRead key missing).".into());
        }
    }
    if let (Some(mo), Some(inp)) = (cfg.mac_offset, cfg.mac_input_offset) {
        let msg = dynamic.get(inp as usize..mo as usize).ok_or(SdmError::OutOfRange("SDMMAC input"))?;
        if cfg.uses_sig() {
            match p.sig_pub {
                None => r.notes.push("SDMSIG not checked (no public key).".into()),
                Some(k) => {
                    let sig = unhex(dynamic, mo, SIG_LEN, "SDMSIG")?;
                    r.sig_ok = Some(k.verify_raw(&sig, msg));
                }
            }
        } else if cfg.file_read != AC_NONE {
            match &kmac {
                None => r.notes.push("SDMMAC not checked (no SDMFileRead key).".into()),
                Some(km) => {
                    let mac = unhex(dynamic, mo, MAC_LEN, "SDMMAC")?;
                    r.mac_ok = Some(crypto::mact(km, msg)? == mac);
                }
            }
        }
    }
    Ok(r)
}

// --------------------------------------------------------------- NDEF / URL

const URI_PREFIXES: [(&str, u8); 4] = [("https://www.", 2), ("http://www.", 1), ("https://", 4), ("http://", 3)];

fn split_prefix(url: &str) -> (u8, &str) {
    for (p, c) in URI_PREFIXES {
        if let Some(rest) = url.strip_prefix(p) {
            return (c, rest);
        }
    }
    (0, url)
}

fn ndef_file_from_payload(code: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = vec![code];
    payload.extend_from_slice(body);
    let mut record = Vec::new();
    if payload.len() <= 255 {
        record.extend_from_slice(&[0xD1, 0x01, payload.len() as u8, 0x55]);
    } else {
        record.extend_from_slice(&[0xC1, 0x01]);
        record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        record.push(0x55);
    }
    record.extend_from_slice(&payload);
    let mut file = (record.len() as u16).to_be_bytes().to_vec();
    file.extend(record);
    file
}

/// Encode a URL as a Type 4 NDEF file: NLEN (2 bytes) followed by one well-known URI record.
/// The URI prefix abbreviation is chosen exactly as [`build_ndef_template`] does, so offsets match.
pub fn ndef_file_from_url(url: &str) -> Vec<u8> {
    let (code, rest) = split_prefix(url);
    ndef_file_from_payload(code, rest.as_bytes())
}

/// Extract the URL from an NDEF file holding a single well-known URI record (trailing bytes ignored).
pub fn url_from_ndef_file(file: &[u8]) -> Result<String> {
    let bad = |s: &str| SdmError::Ndef(s.to_string());
    if file.len() < 2 {
        return Err(bad("file too short"));
    }
    let nlen = usize::from(u16::from_be_bytes([file[0], file[1]]));
    let rec = file.get(2..2 + nlen).ok_or_else(|| bad("NLEN exceeds the file"))?;
    let trunc = || bad("truncated record");
    let hdr = *rec.first().ok_or_else(|| bad("empty record"))?;
    let type_len = usize::from(*rec.get(1).ok_or_else(trunc)?);
    let (plen, mut pos) = if hdr & 0x10 != 0 {
        (usize::from(*rec.get(2).ok_or_else(trunc)?), 3)
    } else {
        let b = rec.get(2..6).ok_or_else(trunc)?;
        (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 6)
    };
    let id_len = if hdr & 0x08 != 0 {
        let l = usize::from(*rec.get(pos).ok_or_else(trunc)?);
        pos += 1;
        l
    } else {
        0
    };
    let typ = rec.get(pos..pos + type_len).ok_or_else(trunc)?;
    pos += type_len + id_len;
    if typ != b"U" {
        return Err(bad("not a URI record"));
    }
    let payload = rec.get(pos..pos + plen).ok_or_else(trunc)?;
    let (code, rest) = payload.split_first().ok_or_else(|| bad("empty payload"))?;
    let prefix = URI_PREFIXES.iter().find(|(_, c)| c == code).map_or("", |(p, _)| p);
    Ok(format!("{prefix}{}", String::from_utf8_lossy(rest)))
}

/// Full back-end read-out of a URL as received from a reader: the URL is placed into the NDEF file
/// layout the offsets refer to and then verified with [`verify`].
pub fn verify_url(url: &str, cfg: &SdmSettings, p: &VerifyParams<'_>) -> Result<SdmResult> {
    verify(&ndef_file_from_url(url), cfg, p)
}

/// Options of [`build_ndef_template`].
#[derive(Debug, Clone)]
pub struct TemplateOptions {
    pub uid_len: usize,
    pub meta_read: u8,
    pub file_read: u8,
    pub file_read2: u8,
    pub ctr_ret: u8,
    /// Plaintext placed into `{enc:N}` placeholders (space padded to N bytes).
    pub enc_fill: Vec<u8>,
    pub ctr_limit: Option<u32>,
}

impl Default for TemplateOptions {
    fn default() -> Self {
        TemplateOptions {
            uid_len: 7,
            meta_read: AC_FREE,
            file_read: AC_NONE,
            file_read2: AC_NONE,
            ctr_ret: AC_NONE,
            enc_fill: Vec::new(),
            ctr_limit: None,
        }
    }
}

/// An NDEF file (static content with zero placeholders) and the SDM settings that match it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdefTemplate {
    pub file_data: Vec<u8>,
    pub settings: SdmSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Uid,
    Ctr,
    Picc,
    Enc(usize),
    Gpio,
    Mac,
    Sig,
    MacStart,
}

impl Token {
    fn key(self) -> &'static str {
        match self {
            Token::Uid => "uid",
            Token::Ctr => "ctr",
            Token::Picc => "picc",
            Token::Enc(_) => "enc",
            Token::Gpio => "gpio",
            Token::Mac => "mac",
            Token::Sig => "sig",
            Token::MacStart => "macstart",
        }
    }
}

fn parse_token(s: &str) -> Option<Token> {
    Some(match s {
        "uid" => Token::Uid,
        "ctr" => Token::Ctr,
        "picc" => Token::Picc,
        "gpio" => Token::Gpio,
        "mac" => Token::Mac,
        "sig" => Token::Sig,
        "macstart" => Token::MacStart,
        _ => Token::Enc(s.strip_prefix("enc:")?.parse().ok()?),
    })
}

/// Build a Type 4 NDEF file (NLEN + URI record) and matching SDM settings from a URL template.
///
/// Tokens: `{uid}` `{ctr}` (plain mirrors), `{picc}` (encrypted PICCData), `{enc:N}` (N plaintext
/// bytes, N a multiple of 16), `{gpio}`, `{mac}` / `{sig}`, and optionally `{macstart}` marking where
/// the MAC / signature input begins (default: the first mirrored field). Other brace text is literal.
pub fn build_ndef_template(url: &str, opt: &TemplateOptions) -> Result<NdefTemplate> {
    let terr = |s: &str| SdmError::Template(s.to_string());
    let (code, text) = split_prefix(url);
    let bytes = text.as_bytes();

    // split into literal chunks and tokens
    let mut parts: Vec<(Option<Token>, &[u8])> = Vec::new();
    let mut pos = 0;
    let mut lit_start = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'{' {
            if let Some(end) = text[pos..].find('}') {
                if let Some(t) = parse_token(&text[pos + 1..pos + end]) {
                    parts.push((None, &bytes[lit_start..pos]));
                    parts.push((Some(t), &[]));
                    pos += end + 1;
                    lit_start = pos;
                    continue;
                }
            }
        }
        pos += 1;
    }
    parts.push((None, &bytes[lit_start..]));

    let kinds: Vec<&str> = parts.iter().filter_map(|(t, _)| t.map(Token::key)).collect();
    for k in &kinds {
        if kinds.iter().filter(|x| *x == k).count() > 1 {
            return Err(SdmError::Template(format!("token {{{k}}} used twice")));
        }
    }
    let has = |k: &str| kinds.contains(&k);

    let mut cfg = SdmSettings {
        meta_read: opt.meta_read,
        file_read: opt.file_read,
        file_read2: opt.file_read2,
        ctr_ret: opt.ctr_ret,
        ..Default::default()
    };
    if has("picc") {
        if opt.meta_read > 0xD {
            return Err(terr("{picc} needs SDMMetaRead to name an AES key (0..D)"));
        }
        if has("uid") || has("ctr") {
            return Err(terr("{picc} cannot be combined with plain {uid}/{ctr}"));
        }
        cfg.options |= OPT_UID | OPT_CTR;
    } else {
        if (has("uid") || has("ctr")) && opt.meta_read != AC_FREE {
            return Err(terr("plain {uid}/{ctr} need SDMMetaRead = E"));
        }
        if has("uid") {
            cfg.options |= OPT_UID;
        }
        if has("ctr") {
            cfg.options |= OPT_CTR;
        }
    }
    if has("enc") {
        cfg.options |= OPT_ENC;
    }
    if has("gpio") {
        cfg.options |= OPT_GPIO;
    }
    if let Some(l) = opt.ctr_limit {
        cfg.options |= OPT_CTR_LIMIT;
        cfg.ctr_limit = Some(l);
    }
    if has("mac") && has("sig") {
        return Err(terr("use either {mac} or {sig}"));
    }
    if has("mac") && (opt.file_read == AC_NONE || opt.file_read2 != AC_NONE) {
        return Err(terr("{mac} needs SDMFileRead = AES key and SDMFileRead2 = F"));
    }
    if has("sig") && opt.file_read2 == AC_NONE {
        return Err(terr("{sig} needs SDMFileRead2 to name an ECC private key"));
    }

    // render the body and remember where each token landed (relative to the body)
    let mut out: Vec<u8> = Vec::new();
    let mut offs: Vec<(&str, usize)> = Vec::new();
    for (tok, lit) in &parts {
        let Some(t) = tok else {
            out.extend_from_slice(lit);
            continue;
        };
        offs.push((t.key(), out.len()));
        match *t {
            Token::Uid => out.extend(vec![b'0'; 2 * opt.uid_len]),
            Token::Ctr => out.extend(vec![b'0'; CTR_LEN]),
            Token::Picc => out.extend(vec![b'0'; cfg.picc_len(opt.uid_len)]),
            Token::Enc(n) => {
                if n % 16 != 0 || n == 0 {
                    return Err(terr("{enc:N}: N must be a non-zero multiple of 16"));
                }
                let mut fill = opt.enc_fill.clone();
                fill.resize(n.max(fill.len()), b' ');
                fill.truncate(n);
                out.extend(fill);
                out.extend(vec![b'0'; n]);
                cfg.enc_length = Some(2 * n as u32);
            }
            Token::Gpio => out.extend_from_slice(b"000"),
            Token::Mac => out.extend(vec![b'0'; MAC_LEN]),
            Token::Sig => out.extend(vec![b'0'; SIG_LEN]),
            Token::MacStart => {}
        }
    }

    let file_data = ndef_file_from_payload(code, &out);
    let base = file_data.len() - out.len();
    let at = |k: &str| offs.iter().find(|(n, _)| *n == k).map(|(_, o)| (base + o) as u32);

    cfg.uid_offset = at("uid");
    if cfg.options & OPT_CTR != 0 && opt.meta_read == AC_FREE {
        cfg.ctr_offset = Some(at("ctr").unwrap_or(NO_MIRROR));
    }
    cfg.picc_offset = at("picc");
    cfg.enc_offset = at("enc");
    cfg.gpio_offset = at("gpio");
    let auth = at("mac").or_else(|| at("sig"));
    if let Some(mo) = auth {
        cfg.mac_offset = Some(mo);
        cfg.mac_input_offset = Some(match at("macstart") {
            Some(s) => s,
            None => ["uid", "ctr", "picc", "enc", "gpio"].iter().filter_map(|k| at(k)).chain([mo]).min().unwrap_or(mo),
        });
    } else if opt.file_read != AC_NONE || opt.file_read2 != AC_NONE {
        return Err(terr("SDMFileRead/SDMFileRead2 set but the template has no {mac} or {sig}"));
    }
    Ok(NdefTemplate { file_data, settings: cfg })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }
    const K0: [u8; 16] = [0; 16];

    #[test]
    fn picc_and_mac_published_vectors() {
        let pd = decrypt_picc_data(&K0, &hx("EF963FF7828658A599F3041510671E88")).unwrap();
        assert_eq!(pd.uid.unwrap(), hx("04DE5F1EACC040"));
        assert_eq!(pd.ctr, Some(0x3D));
        assert_eq!(pd.tag, 0xC7);
        let (_, kmac) = session_keys(&K0, Some(&hx("04DE5F1EACC040")), Some(0x3D)).unwrap();
        assert_eq!(hex::encode_upper(&kmac), "3FB5F6E3A807A03D5E3570ACE393776F");
        assert_eq!(hex::encode_upper(crypto::mact(&kmac, b"").unwrap()), "94EED9EE65337086");
    }

    #[test]
    fn settings_roundtrip() {
        let c = SdmSettings {
            options: 0xF9,
            meta_read: 1,
            file_read: 2,
            file_read2: 0xF,
            ctr_ret: 3,
            picc_offset: Some(20),
            gpio_offset: Some(100),
            mac_input_offset: Some(20),
            enc_offset: Some(60),
            enc_length: Some(32),
            mac_offset: Some(110),
            ctr_limit: Some(1000),
            ..Default::default()
        };
        let raw = c.encode().unwrap();
        assert_eq!(raw.len(), 3 + 7 * 3);
        let mut with_tail = raw.clone();
        with_tail.push(0xAA);
        let (back, used) = SdmSettings::parse(&with_tail).unwrap();
        assert_eq!(back, c);
        assert_eq!(used, raw.len());
        assert!(SdmSettings::parse(&raw[..raw.len() - 1]).is_err());
        assert!(!c.describe().is_empty());
    }

    #[test]
    fn mac_enc_and_counter_flow() {
        let (mk, fk) = ([0x11u8; 16], [0x22u8; 16]);
        let uid = hx("04958CAA5C5E80");
        let t = build_ndef_template(
            "https://example.org/t?p={picc}&e={enc:16}&m={mac}",
            &TemplateOptions {
                meta_read: 1,
                file_read: 2,
                ctr_ret: 0,
                enc_fill: b"SECRET-16-BYTES!".to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(t.settings.validate(256, 7).is_empty(), "{:?}", t.settings.validate(256, 7));
        let keys = RenderKeys { meta_key: Some(&mk), file_key: Some(&fk), sig_key: None };
        let mut padded = t.file_data.clone();
        padded.resize(256, 0);
        let dynamic = render(&padded, &t.settings, &uid, 5, &keys, b"000", false).unwrap();
        assert_ne!(dynamic, padded);
        let p = VerifyParams { meta_key: Some(&mk), file_key: Some(&fk), ..Default::default() };
        let r = verify(&dynamic, &t.settings, &p).unwrap();
        assert!(r.ok());
        assert_eq!(r.uid.as_deref(), Some(&uid[..]));
        assert_eq!(r.ctr, Some(5));
        assert_eq!(r.enc_plain.unwrap(), b"SECRET-16-BYTES!");
        // replay check
        let r = verify(&dynamic, &t.settings, &VerifyParams { last_ctr: Some(5), ..p }).unwrap();
        assert_eq!(r.ctr_fresh, Some(false));
        assert!(!r.ok());
        let r = verify(&dynamic, &t.settings, &VerifyParams { last_ctr: Some(4), ..p }).unwrap();
        assert!(r.ok());
        // wrong file key
        let r = verify(&dynamic, &t.settings, &VerifyParams { file_key: Some(&K0), ..p }).unwrap();
        assert!(!r.ok());
        // URL read-out
        let url = url_from_ndef_file(&dynamic).unwrap();
        assert!(url.starts_with("https://example.org/t?p="));
        let r = verify_url(&url, &t.settings, &p).unwrap();
        assert!(r.ok() && r.ctr == Some(5));
        // tampered MAC
        let mut bad = dynamic.clone();
        let mo = t.settings.mac_offset.unwrap() as usize;
        bad[mo] = if bad[mo] == b'0' { b'1' } else { b'0' };
        assert!(!verify(&bad, &t.settings, &p).unwrap().ok());
    }

    #[test]
    fn counter_limit() {
        let fk = [0x22u8; 16];
        let uid = hx("04958CAA5C5E80");
        let t = build_ndef_template(
            "https://example.org/?c={ctr}&u={uid}&m={mac}",
            &TemplateOptions { file_read: 2, ctr_limit: Some(10), ..Default::default() },
        )
        .unwrap();
        let keys = RenderKeys { file_key: Some(&fk), ..Default::default() };
        let p = VerifyParams { file_key: Some(&fk), ..Default::default() };
        for (c, within) in [(10u32, true), (11, false)] {
            let d = render(&t.file_data, &t.settings, &uid, c, &keys, b"000", false).unwrap();
            let r = verify(&d, &t.settings, &p).unwrap();
            assert_eq!(r.mac_ok, Some(true));
            assert_eq!(r.ctr_within_limit, Some(within));
            assert_eq!(r.ok(), within);
        }
    }

    #[test]
    fn plain_mirror_and_signature() {
        let uid = hx("04958CAA5C5E80");
        let sk = crypto::gen_key(crypto::CURVE_P256).unwrap();
        let t = build_ndef_template(
            "https://example.org/?u={uid}x{ctr}&s={sig}",
            &TemplateOptions { file_read2: 0, ctr_ret: AC_FREE, ..Default::default() },
        )
        .unwrap();
        let s = &t.settings;
        assert!(s.uses_sig());
        assert_eq!(s.mac_offset.unwrap() - s.mac_input_offset.unwrap(), 14 + 1 + 6 + 3);
        let keys = RenderKeys { sig_key: Some(&sk), ..Default::default() };
        let mut f = t.file_data.clone();
        f.resize(256, 0);
        let dynamic = render(&f, s, &uid, 1, &keys, b"000", false).unwrap();
        let pubk = sk.public();
        let p = VerifyParams { sig_pub: Some(&pubk), ..Default::default() };
        let r = verify(&dynamic, s, &p).unwrap();
        assert_eq!(r.sig_ok, Some(true));
        assert_eq!(r.uid.as_deref(), Some(&uid[..]));
        assert_eq!(r.ctr, Some(1));
        let mut bad = dynamic.clone();
        bad[s.ctr_offset.unwrap() as usize + 5] ^= 1;
        assert!(!verify(&bad, s, &p).unwrap().ok());
        // random ID
        let ri = render(&f, s, &uid, 1, &keys, b"000", true).unwrap();
        let r = verify(&ri, s, &VerifyParams { uid: Some(&uid), ..p }).unwrap();
        assert_eq!(r.uid.as_deref(), Some(&uid[..]));
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn validation_and_template_errors() {
        let bad = SdmSettings {
            options: 0xC1,
            meta_read: AC_FREE,
            file_read: 0,
            uid_offset: Some(10),
            ctr_offset: Some(12),
            mac_input_offset: Some(10),
            mac_offset: Some(40),
            ..Default::default()
        };
        assert!(bad.validate(256, 7).iter().any(|p| p.contains("overlap")));
        assert!(build_ndef_template("http://a/{mac}", &TemplateOptions::default()).is_err());
        assert!(build_ndef_template("http://a/{uid}{uid}", &TemplateOptions::default()).is_err());
        assert!(build_ndef_template("http://a/{picc}", &TemplateOptions::default()).is_err());
        let opt = TemplateOptions { file_read: 1, ..Default::default() };
        assert!(build_ndef_template("http://a/{uid}", &opt).is_err());
    }

    #[test]
    fn ten_byte_uid_picc() {
        let mk = [7u8; 16];
        let uid = hx("04112233445566778899");
        let ct = encrypt_picc_data(&mk, OPT_UID, &uid, 0).unwrap();
        assert_eq!(ct.len(), 32);
        let pd = decrypt_picc_data(&mk, &ct).unwrap();
        assert_eq!(pd.uid.unwrap(), uid);
        assert_eq!(pd.ctr, None);
    }

    #[test]
    fn ndef_roundtrip_short_and_long() {
        for n in [10usize, 300] {
            let url = format!("https://example.org/{}", "a".repeat(n));
            let f = ndef_file_from_url(&url);
            assert_eq!(f[2], if n > 200 { 0xC1 } else { 0xD1 });
            assert_eq!(url_from_ndef_file(&f).unwrap(), url);
        }
        assert!(url_from_ndef_file(&[0, 5, 1]).is_err());
    }
}
