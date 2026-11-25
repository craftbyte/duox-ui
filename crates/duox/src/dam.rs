//! Delegated application management (data sheet 7.11.2): the card issuer's cryptograms.
//!
//! The issuer builds an [`AppHeader`] (the first-frame body of CreateDelegatedApplication), encrypts the
//! application's default key into EncK, authenticates both with the DAMMAC and hands the resulting
//! [`Ticket`] to the application provider.

use crate::crypto::{self, CryptoError};
use serde_json::{json, Value};
use thiserror::Error;

/// Command code of CreateDelegatedApplication (first byte of the DAMMAC input).
pub const CMD_CREATE_DELEGATED_APP: u8 = 0xC9;
/// Command code of DeleteApplication (first byte of the delete MAC input).
pub const CMD_DELETE_APP: u8 = 0xDA;
const TICKET_TYPE: &str = "duox-dam-ticket";

/// Errors of the DAM module.
#[derive(Debug, Error)]
pub enum DamError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("delegated application header too short")]
    HeaderTooShort,
    #[error("delegated application header: {0}")]
    Header(String),
    #[error("AppDAMDefaultKey must be {0} bytes")]
    DefaultKeyLength(&'static str),
    #[error("not a delegated application ticket")]
    NotATicket,
    #[error("ticket: {0}")]
    Ticket(String),
}

type Result<T> = std::result::Result<T, DamError>;

/// Header of CreateDelegatedApplication (everything after the command code in the first frame).
/// The same bytes are the DAMPayload of a delegated-application-creation certificate (Table 22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppHeader {
    /// DAMAppID (3 bytes, LSB first on the wire).
    pub aid: u32,
    pub slot_no: u16,
    pub slot_version: u8,
    /// DAMQuota in blocks.
    pub quota: u16,
    pub key_sett1: u8,
    /// Number of keys (low nibble of KeySett2; 0x0F selects the transaction-MAC key layout).
    pub n_keys: u8,
    /// AES-256 application keys (KeySett2 bits 7..6 = 11) instead of AES-128 (10).
    pub aes256: bool,
    /// ISO file IDs enabled (KeySett2 bit 5).
    pub iso_file_ids: bool,
    /// KeySett3, present if KeySett2 bit 4 is set.
    pub key_sett3: Option<u8>,
    /// KeySetParams (4 bytes), present if KeySett3 bit 0 is set.
    pub keyset_params: Vec<u8>,
    pub iso_fid: Option<u16>,
    pub df_name: Vec<u8>,
}

impl AppHeader {
    /// Header with default key settings (KeySett1 = 0x0F, one key, AES-128, no ISO).
    pub fn new(aid: u32, slot_no: u16, slot_version: u8, quota: u16) -> Self {
        AppHeader {
            aid,
            slot_no,
            slot_version,
            quota,
            key_sett1: 0x0F,
            n_keys: 1,
            aes256: false,
            iso_file_ids: false,
            key_sett3: None,
            keyset_params: Vec::new(),
            iso_fid: None,
            df_name: Vec::new(),
        }
    }

    /// Serialise the header.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.aid > 0xFF_FFFF {
            return Err(DamError::Header("AID does not fit in 3 bytes".into()));
        }
        let ks2 = (if self.aes256 { 0xC0 } else { 0x80 })
            | (if self.iso_file_ids { 0x20 } else { 0 })
            | (if self.key_sett3.is_some() { 0x10 } else { 0 })
            | (self.n_keys & 0x0F);
        let mut h = self.aid.to_le_bytes()[..3].to_vec();
        h.extend_from_slice(&self.slot_no.to_le_bytes());
        h.push(self.slot_version);
        h.extend_from_slice(&self.quota.to_le_bytes());
        h.push(self.key_sett1);
        h.push(ks2);
        match self.key_sett3 {
            Some(k3) => {
                let want = if k3 & 0x01 != 0 { 4 } else { 0 };
                if self.keyset_params.len() != want {
                    return Err(DamError::Header(format!("KeySetParams must be {want} bytes for this KeySett3")));
                }
                h.push(k3);
                h.extend_from_slice(&self.keyset_params);
            }
            None if !self.keyset_params.is_empty() => {
                return Err(DamError::Header("KeySetParams without KeySett3".into()));
            }
            None => {}
        }
        if !self.df_name.is_empty() && self.iso_fid.is_none() {
            return Err(DamError::Header("an ISO DF name needs an ISO file ID".into()));
        }
        if let Some(fid) = self.iso_fid {
            h.extend_from_slice(&fid.to_le_bytes());
            h.extend_from_slice(&self.df_name);
        }
        Ok(h)
    }

    /// Parse a serialised header.
    pub fn parse(h: &[u8]) -> Result<AppHeader> {
        if h.len() < 10 {
            return Err(DamError::HeaderTooShort);
        }
        let mut a = AppHeader {
            aid: u32::from_le_bytes([h[0], h[1], h[2], 0]),
            slot_no: u16::from_le_bytes([h[3], h[4]]),
            slot_version: h[5],
            quota: u16::from_le_bytes([h[6], h[7]]),
            key_sett1: h[8],
            n_keys: h[9] & 0x0F,
            aes256: h[9] >> 6 == 3,
            iso_file_ids: h[9] & 0x20 != 0,
            key_sett3: None,
            keyset_params: Vec::new(),
            iso_fid: None,
            df_name: Vec::new(),
        };
        let mut pos = 10;
        if h[9] & 0x10 != 0 {
            let k3 = *h.get(pos).ok_or(DamError::HeaderTooShort)?;
            pos += 1;
            a.key_sett3 = Some(k3);
            if k3 & 0x01 != 0 {
                a.keyset_params = h.get(pos..pos + 4).ok_or(DamError::HeaderTooShort)?.to_vec();
                pos += 4;
            }
        }
        if h.len() > pos {
            let b = h.get(pos..pos + 2).ok_or(DamError::HeaderTooShort)?;
            a.iso_fid = Some(u16::from_le_bytes([b[0], b[1]]));
            a.df_name = h[pos + 2..].to_vec();
        }
        Ok(a)
    }

    /// Blocks the delegated application consumes before any file exists (7.8.7, 7.11.5).
    pub fn overhead_blocks(&self) -> u32 {
        let tmp = self.n_keys == 0x0F;
        let keys = if tmp { 1 } else { u32::from(self.n_keys) };
        let (sets, max_size) = if self.keyset_params.len() >= 3 {
            let ms = u32::from(self.keyset_params[2]);
            (u32::from(self.keyset_params[1]), if ms == 0 { self.default_max_key_size() } else { ms })
        } else {
            (1, self.default_max_key_size())
        };
        let ks3 = self.key_sett3.unwrap_or(0);
        let mut blocks = 2; // general + delegated
        if self.iso_fid.is_some() || ks3 & 0x06 != 0 {
            blocks += 1;
        }
        if keys > 0 {
            blocks += sets * (21 + keys * (max_size + 4)).div_ceil(32);
        }
        if ks3 & 0x02 != 0 {
            blocks += 3;
        }
        if tmp {
            blocks += 2;
        }
        blocks
    }

    fn default_max_key_size(&self) -> u32 {
        if self.aes256 {
            32
        } else {
            16
        }
    }
}

/// `K_AppDAMDefault || KeyVer`: 24 key bytes (zero padded) for AES-128 applications, 32 for AES-256
/// (7.11.2.2.1). AES-128 applications accept a 16 or 24 byte key, AES-256 applications a 32 byte key.
pub fn default_key_blob(key: &[u8], key_ver: u8, aes256: bool) -> Result<Vec<u8>> {
    let n = if aes256 { 32 } else { 24 };
    let ok = if aes256 { key.len() == 32 } else { key.len() == 16 || key.len() == 24 };
    if !ok {
        return Err(DamError::DefaultKeyLength(if aes256 { "32" } else { "16 or 24" }));
    }
    let mut v = key.to_vec();
    v.resize(n, 0);
    v.push(key_ver);
    Ok(v)
}

/// EncK = AES-CBC(K_PICCDAMENC, zero IV, Random || K_AppDAMDefault || KeyVer) with random padding in front.
pub fn enc_k(dam_enc_key: &[u8], key: &[u8], key_ver: u8, aes256: bool) -> Result<Vec<u8>> {
    let blob = default_key_blob(key, key_ver, aes256)?;
    let mut pt = crypto::rnd((16 - blob.len() % 16) % 16);
    pt.extend(blob);
    Ok(crypto::aes_cbc_enc(dam_enc_key, &pt, &crypto::ZERO_IV)?)
}

/// Decrypt EncK and return `(K_AppDAMDefault, KeyVer)`; the key keeps its zero padding to 24 / 32 bytes.
pub fn decrypt_enc_k(dam_enc_key: &[u8], enc_k: &[u8], aes256: bool) -> Result<(Vec<u8>, u8)> {
    let pt = crypto::aes_cbc_dec(dam_enc_key, enc_k, &crypto::ZERO_IV)?;
    let n = if aes256 { 33 } else { 25 };
    if pt.len() < n {
        return Err(DamError::Ticket("EncK too short".into()));
    }
    let blob = &pt[pt.len() - n..];
    Ok((blob[..n - 1].to_vec(), blob[n - 1]))
}

/// DAMMAC for CreateDelegatedApplication over `Cmd || header || EncK` (7.11.2.2.2).
pub fn create_mac(dam_mac_key: &[u8], header: &[u8], enc_k: &[u8]) -> Result<Vec<u8>> {
    let mut m = vec![CMD_CREATE_DELEGATED_APP];
    m.extend_from_slice(header);
    m.extend_from_slice(enc_k);
    Ok(crypto::mact(dam_mac_key, &m)?)
}

/// DAMMAC for deleting a delegated application, over `Cmd || AID`.
pub fn delete_mac(dam_mac_key: &[u8], aid: u32) -> Result<Vec<u8>> {
    let mut m = vec![CMD_DELETE_APP];
    m.extend_from_slice(&aid.to_le_bytes()[..3]);
    Ok(crypto::mact(dam_mac_key, &m)?)
}

/// What the card issuer hands to the application provider for one delegated application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub header: Vec<u8>,
    pub enc_k: Vec<u8>,
    pub dam_mac: Vec<u8>,
    /// Empty if no delete MAC was issued.
    pub delete_mac: Vec<u8>,
}

impl Ticket {
    /// JSON text of the ticket.
    pub fn to_json(&self) -> Result<String> {
        let h = AppHeader::parse(&self.header)?;
        let v = json!({
            "type": TICKET_TYPE,
            "aid": format!("{:06X}", h.aid),
            "slot": h.slot_no,
            "slot_version": h.slot_version,
            "quota_blocks": h.quota,
            "header": hex::encode(&self.header),
            "enc_k": hex::encode(&self.enc_k),
            "dam_mac": hex::encode(&self.dam_mac),
            "delete_mac": hex::encode(&self.delete_mac),
        });
        serde_json::to_string_pretty(&v).map_err(|e| DamError::Ticket(e.to_string()))
    }

    /// Parse the JSON text produced by [`Ticket::to_json`].
    pub fn from_json(text: &str) -> Result<Ticket> {
        let v: Value = serde_json::from_str(text).map_err(|e| DamError::Ticket(e.to_string()))?;
        if v.get("type").and_then(Value::as_str) != Some(TICKET_TYPE) {
            return Err(DamError::NotATicket);
        }
        let field = |name: &str, required: bool| -> Result<Vec<u8>> {
            match v.get(name).and_then(Value::as_str) {
                Some(s) => hex::decode(s).map_err(|_| DamError::Ticket(format!("{name} is not hex"))),
                None if required => Err(DamError::Ticket(format!("{name} missing"))),
                None => Ok(Vec::new()),
            }
        };
        Ok(Ticket {
            header: field("header", true)?,
            enc_k: field("enc_k", true)?,
            dam_mac: field("dam_mac", true)?,
            delete_mac: field("delete_mac", false)?,
        })
    }

    /// Recompute the DAMMAC (and delete MAC, if present) with the issuer's key.
    pub fn verify(&self, dam_mac_key: &[u8]) -> Result<bool> {
        let h = AppHeader::parse(&self.header)?;
        let ok = create_mac(dam_mac_key, &self.header, &self.enc_k)? == self.dam_mac;
        Ok(ok && (self.delete_mac.is_empty() || delete_mac(dam_mac_key, h.aid)? == self.delete_mac))
    }
}

/// Issue a ticket: encrypt the default key, compute the DAMMAC and optionally the delete MAC.
pub fn issue_ticket(
    dam_mac_key: &[u8],
    dam_enc_key: &[u8],
    header: &[u8],
    default_key: &[u8],
    key_ver: u8,
    with_delete: bool,
) -> Result<Ticket> {
    let h = AppHeader::parse(header)?;
    let ek = enc_k(dam_enc_key, default_key, key_ver, h.aes256)?;
    Ok(Ticket {
        header: header.to_vec(),
        dam_mac: create_mac(dam_mac_key, header, &ek)?,
        delete_mac: if with_delete { delete_mac(dam_mac_key, h.aid)? } else { Vec::new() },
        enc_k: ek,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_header() -> AppHeader {
        AppHeader {
            key_sett3: Some(0x01),
            keyset_params: vec![0x01, 0x02, 0x10, 0x00],
            iso_file_ids: true,
            iso_fid: Some(0xE110),
            df_name: vec![0xD2, 0x76, 0x00],
            n_keys: 3,
            ..AppHeader::new(0xD1D2D3, 4, 2, 100)
        }
    }

    #[test]
    fn header_layout_and_roundtrip() {
        let h = AppHeader::new(0x010203, 0x0405, 6, 0x0708);
        let raw = h.encode().unwrap();
        assert_eq!(raw, [3, 2, 1, 5, 4, 6, 8, 7, 0x0F, 0x81]);
        assert_eq!(AppHeader::parse(&raw).unwrap(), h);
        let f = full_header();
        assert_eq!(AppHeader::parse(&f.encode().unwrap()).unwrap(), f);
        let a256 = AppHeader { aes256: true, ..h };
        assert_eq!(a256.encode().unwrap()[9], 0xC1);
        assert!(AppHeader::parse(&raw[..9]).is_err());
        let bad = AppHeader { df_name: vec![1], ..AppHeader::new(1, 0, 0, 0) };
        assert!(bad.encode().is_err());
        let bad = AppHeader { key_sett3: Some(1), ..AppHeader::new(1, 0, 0, 0) };
        assert!(bad.encode().is_err());
    }

    #[test]
    fn enc_k_and_macs() {
        let (km, ke) = ([1u8; 16], [2u8; 16]);
        let hdr = AppHeader::new(0xD1D2D3, 1, 1, 8).encode().unwrap();
        let t = issue_ticket(&km, &ke, &hdr, &[7u8; 16], 5, true).unwrap();
        assert_eq!(t.enc_k.len(), 32);
        let (k, ver) = decrypt_enc_k(&ke, &t.enc_k, false).unwrap();
        assert_eq!(&k[..16], &[7u8; 16]);
        assert_eq!(&k[16..], &[0u8; 8]);
        assert_eq!(ver, 5);
        assert_eq!(t.dam_mac.len(), 8);
        assert_eq!(t.dam_mac, create_mac(&km, &hdr, &t.enc_k).unwrap());
        assert_eq!(t.delete_mac, delete_mac(&km, 0xD1D2D3).unwrap());
        assert!(t.verify(&km).unwrap());
        assert!(!t.verify(&ke).unwrap());
        // AES-256 application: 32 byte key, 48 byte EncK
        let h256 = AppHeader { aes256: true, ..AppHeader::new(1, 1, 1, 8) }.encode().unwrap();
        let t = issue_ticket(&km, &ke, &h256, &[3u8; 32], 0, false).unwrap();
        assert_eq!(t.enc_k.len(), 48);
        assert!(t.delete_mac.is_empty() && t.verify(&km).unwrap());
        assert!(issue_ticket(&km, &ke, &h256, &[3u8; 16], 0, false).is_err());
    }

    #[test]
    fn ticket_json_roundtrip() {
        let hdr = full_header().encode().unwrap();
        let t = issue_ticket(&[1u8; 16], &[2u8; 16], &hdr, &[7u8; 24], 1, true).unwrap();
        let back = Ticket::from_json(&t.to_json().unwrap()).unwrap();
        assert_eq!(back, t);
        assert!(Ticket::from_json("{\"type\":\"other\"}").is_err());
        assert!(Ticket::from_json("nonsense").is_err());
    }

    #[test]
    fn quota_estimate() {
        // one key, one set, AES-128: 2 + ceil((21 + 20) / 32) = 4
        assert_eq!(AppHeader::new(1, 0, 0, 0).overhead_blocks(), 4);
        // ISO file IDs with FID add one block
        let h = AppHeader { iso_fid: Some(1), ..AppHeader::new(1, 0, 0, 0) };
        assert_eq!(h.overhead_blocks(), 5);
        // transaction-MAC layout: 1 key + 2 extra blocks
        let h = AppHeader { n_keys: 0x0F, ..AppHeader::new(1, 0, 0, 0) };
        assert_eq!(h.overhead_blocks(), 6);
    }
}
