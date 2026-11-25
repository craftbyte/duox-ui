//! Application management (7.11): SelectApplication, CreateApplication, DeleteApplication,
//! CreateDelegatedApplication, GetApplicationIDs, GetDFNames, GetDelegatedInfo.

use super::types::*;
use super::Card;
use crate::crypto::SessionKind;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Key set parameters of CreateApplication (sent after KeySett3).
///
/// The data sheet's description of this block is not fully unambiguous; the layout used is
/// `AKSVersion | NoKeySets | MaxKeySize (0x10 AES-128 / 0x20 AES-256) | AppKeySetSettings`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySetConfig {
    pub aks_version: u8,
    pub no_key_sets: u8,
    pub max_key_size: u8,
    pub app_key_set_settings: u8,
}

impl KeySetConfig {
    pub fn to_bytes(self) -> [u8; 4] {
        [self.aks_version, self.no_key_sets, self.max_key_size, self.app_key_set_settings]
    }
}

/// CreateApplication parameters.
#[derive(Debug, Clone)]
pub struct AppSpec {
    pub aid: Aid,
    pub key_sett1: u8,
    /// Number of application keys (0..=14).
    pub n_keys: u8,
    pub aes256: bool,
    /// Enable ISO file identifiers for the application's files.
    pub iso_file_ids: bool,
    pub iso_fid: Option<u16>,
    pub df_name: Vec<u8>,
    pub key_sett3: Option<u8>,
    /// Bytes following KeySett3 (e.g. a [`KeySetConfig`]).
    pub extra: Vec<u8>,
}

impl AppSpec {
    pub fn new(aid: Aid) -> Self {
        AppSpec {
            aid,
            key_sett1: 0x0F,
            n_keys: 1,
            aes256: false,
            iso_file_ids: false,
            iso_fid: None,
            df_name: vec![],
            key_sett3: None,
            extra: vec![],
        }
    }
    pub fn key_settings(mut self, ks1: u8) -> Self {
        self.key_sett1 = ks1;
        self
    }
    pub fn keys(mut self, n: u8) -> Self {
        self.n_keys = n;
        self
    }
    pub fn aes256(mut self) -> Self {
        self.aes256 = true;
        self
    }
    pub fn iso_file_ids(mut self) -> Self {
        self.iso_file_ids = true;
        self
    }
    pub fn iso_name(mut self, fid: u16, df_name: &[u8]) -> Self {
        self.iso_fid = Some(fid);
        self.df_name = df_name.to_vec();
        self
    }
    pub fn key_sett3(mut self, ks3: u8) -> Self {
        self.key_sett3 = Some(ks3);
        self
    }
    pub fn key_sets(mut self, cfg: KeySetConfig) -> Self {
        self.extra = cfg.to_bytes().to_vec();
        // KeySett3 bit 0 announces the key-set parameter block
        self.key_sett3 = Some(self.key_sett3.unwrap_or(0) | 0x01);
        self
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if self.n_keys > 14 {
            return Err(Error::arg("an application has at most 14 keys"));
        }
        if self.aid.0 >> 24 != 0 {
            return Err(Error::arg("an AID is 3 bytes"));
        }
        if !self.df_name.is_empty() && self.iso_fid.is_none() {
            return Err(Error::arg("a DF name needs an ISO file identifier"));
        }
        if !self.df_name.is_empty() && !(1..=16).contains(&self.df_name.len()) {
            return Err(Error::arg("a DF name is 1..16 bytes"));
        }
        let ks2 = (if self.aes256 { 0xC0 } else { 0x80 })
            | (if self.iso_file_ids { 0x20 } else { 0 })
            | (if self.key_sett3.is_some() { 0x10 } else { 0 })
            | (self.n_keys & 0x0F);
        let mut h = self.aid.to_bytes().to_vec();
        h.extend([self.key_sett1, ks2]);
        if let Some(k3) = self.key_sett3 {
            h.push(k3);
            h.extend(&self.extra);
        }
        if let Some(f) = self.iso_fid {
            h.extend(f.to_le_bytes());
            h.extend(&self.df_name);
        }
        Ok(h)
    }
}

/// Key material of CreateDelegatedApplication.
#[derive(Debug, Clone)]
pub enum DelegatedKeys {
    /// AES session (PICCDAMAuthKey): the issuer's EncK (32 or 48 bytes) and DAMMAC (8 bytes).
    Aes { enc_k: Vec<u8>, dam_mac: Vec<u8> },
    /// ECC session (certificate with delegated-application rights): `K_AppDAMDefault || KeyVer`,
    /// protected by the session's secure messaging.
    Ecc { init_k: Vec<u8> },
}

/// CreateDelegatedApplication: the header (as built by the `dam` module) and the key material.
#[derive(Debug, Clone)]
pub struct DelegatedAppSpec {
    pub header: Vec<u8>,
    pub keys: DelegatedKeys,
}

/// GetDelegatedInfo result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedInfo {
    pub slot_version: u8,
    pub quota: u16,
    pub free_blocks: u16,
    pub aid: Aid,
}

/// GetDFNames entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfName {
    pub aid: Aid,
    pub iso_fid: u16,
    pub name: Vec<u8>,
}

impl<T: Transport> Card<T> {
    /// SelectApplication of one or two applications. Ends the authentication and restarts
    /// Transaction MAC recording. Returns 0x00, or 0x01 (OPERATION_OK_LIM) when the application is
    /// selected with limited functionality (TMCLimit reached / signature key unusable). On failure
    /// the PICC level is selected (7.11.3.2).
    pub fn select_application(&mut self, aid: Aid, aid2: Option<Aid>) -> Result<u8> {
        let mut payload = aid.to_bytes().to_vec();
        if let Some(a) = aid2 {
            payload.extend(a.to_bytes());
        }
        self.drop_session();
        self.tm_secondary = false;
        self.log_line(&format!(
            "-- SelectApplication {aid}{}",
            aid2.map(|a| format!(" + {a}")).unwrap_or_default()
        ));
        let (rc, _) = self.wrap(cmd::SELECT_APPLICATION, &payload)?;
        if rc != 0x00 && rc != 0x01 {
            self.selection.primary = Some(Aid::PICC);
            self.selection.secondary = None;
            return Err(self.fail(rc, cmd::SELECT_APPLICATION, false));
        }
        self.selection.primary = Some(aid);
        self.selection.secondary = aid2;
        Ok(rc)
    }

    pub fn get_application_ids(&mut self) -> Result<Vec<Aid>> {
        let d = self.command(cmd::GET_APPLICATION_IDS, &[], &[], CommMode::Mac)?;
        Ok(d.chunks_exact(3).map(Aid::from_bytes).collect())
    }

    pub fn get_df_names(&mut self) -> Result<Vec<DfName>> {
        let r = self.run(cmd::GET_DF_NAMES, &[], &[], CommMode::Mac, &[0x00])?;
        Ok(r.frames
            .iter()
            .filter(|f| f.len() >= 5)
            .map(|f| DfName {
                aid: Aid::from_bytes(&f[..3]),
                iso_fid: u16::from_le_bytes([f[3], f[4]]),
                name: f[5..].to_vec(),
            })
            .collect())
    }

    pub fn create_application(&mut self, spec: &AppSpec) -> Result<()> {
        let h = spec.encode()?;
        self.command(cmd::CREATE_APPLICATION, &h, &[], CommMode::Mac).map(|_| ())
    }

    /// DeleteApplication. `dam_mac` is the issuer's DAMMAC when deleting a delegated application
    /// after PICCDAMAuthKey authentication (7.11.2.3).
    pub fn delete_application(&mut self, aid: Aid, dam_mac: &[u8]) -> Result<()> {
        let mut h = aid.to_bytes().to_vec();
        h.extend_from_slice(dam_mac);
        self.command(cmd::DELETE_APPLICATION, &h, &[], CommMode::Mac)?;
        if self.selection.primary == Some(aid) {
            self.drop_session();
        }
        Ok(())
    }

    /// CreateDelegatedApplication (7.11.2.2): two frames, counted once by CmdCtr.
    pub fn create_delegated_application(&mut self, spec: &DelegatedAppSpec) -> Result<()> {
        let mut s = self.session.take().ok_or(Error::NotAuthenticated("CreateDelegatedApplication"))?;
        let part2 = match (&spec.keys, s.kind) {
            (DelegatedKeys::Ecc { init_k }, SessionKind::Ecc) => {
                if init_k.is_empty() {
                    return Err(Error::arg("an ECC session needs InitK (the initial application key)"));
                }
                s.encrypt(init_k, false)?
            }
            (DelegatedKeys::Aes { enc_k, dam_mac }, SessionKind::Aes) => {
                if (enc_k.len() != 32 && enc_k.len() != 48) || dam_mac.len() != 8 {
                    return Err(Error::arg("an AES session needs the issuer's EncK (32 or 48 bytes) and DAMMAC (8 bytes)"));
                }
                [enc_k.as_slice(), dam_mac.as_slice()].concat()
            }
            (DelegatedKeys::Ecc { .. }, _) => return Err(Error::arg("InitK is for ECC sessions; this session is AES")),
            (DelegatedKeys::Aes { .. }, _) => return Err(Error::arg("EncK / DAMMAC are for AES sessions; this session is ECC")),
        };
        self.log_line("-- CreateDelegatedApplication");
        let (rc, _) = self.wrap(cmd::CREATE_DELEGATED_APPLICATION, &spec.header)?;
        if rc != 0xAF {
            return Err(self.fail(rc, cmd::CREATE_DELEGATED_APPLICATION, true));
        }
        let mut p2 = part2.clone();
        p2.extend(s.mac_cmd(cmd::CREATE_DELEGATED_APPLICATION, &[spec.header.as_slice(), &part2].concat())?);
        let (rc, d) = self.wrap(cmd::ADDITIONAL_FRAME, &p2)?;
        if rc != 0x00 {
            return Err(self.fail(rc, cmd::CREATE_DELEGATED_APPLICATION, true));
        }
        s.ctr = s.ctr.wrapping_add(1);
        if d != s.mac_resp(0, &[])? {
            self.drop_session();
            return Err(Error::protocol("CreateDelegatedApplication: response MAC invalid - session dropped"));
        }
        self.session = Some(s);
        Ok(())
    }

    pub fn get_delegated_info(&mut self, slot_no: u16) -> Result<DelegatedInfo> {
        let d = self.command(cmd::GET_DELEGATED_INFO, &slot_no.to_le_bytes(), &[], CommMode::Mac)?;
        if d.len() < 8 {
            self.drop_session();
            return Err(Error::protocol("GetDelegatedInfo: response too short"));
        }
        Ok(DelegatedInfo {
            slot_version: d[0],
            quota: u16::from_le_bytes([d[1], d[2]]),
            free_blocks: u16::from_le_bytes([d[3], d[4]]),
            aid: Aid::from_bytes(&d[5..8]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn select_and_lists() {
        let mut t = MockTransport::new();
        t.expect_hex("905A000003 563412 00", "9100");
        t.expect_hex("905A000006 563412 010000 00", "9101");
        t.expect_hex("905A000003 FFFFFF 00", "91A0");
        t.expect_hex("906A000000", "563412 010000 9100");
        t.expect_hex("906D000000", "563412 1000 41 42 91AF");
        t.expect_hex("90AF000000", "010000 2000 43 9100");
        let mut card = Card::new(t);
        assert_eq!(card.select_application(Aid(0x123456), None).unwrap(), 0);
        assert_eq!(card.selection().primary, Some(Aid(0x123456)));
        assert_eq!(card.select_application(Aid(0x123456), Some(Aid(1))).unwrap(), 1);
        assert_eq!(card.selection().secondary, Some(Aid(1)));
        let e = card.select_application(Aid(0xFFFFFF), None).unwrap_err();
        assert_eq!(e.status(), Some(Status::ApplicationNotFound));
        assert_eq!(card.selection(), super::super::Selection { primary: Some(Aid::PICC), secondary: None });
        assert_eq!(card.get_application_ids().unwrap(), vec![Aid(0x123456), Aid(1)]);
        let n = card.get_df_names().unwrap();
        assert_eq!(n.len(), 2);
        assert_eq!((n[0].iso_fid, n[0].name.clone()), (0x10, b"AB".to_vec()));
        assert_eq!(n[1].aid, Aid(1));
    }

    #[test]
    fn create_application_encoding() {
        let h = AppSpec::new(Aid(0x010203)).keys(3).encode().unwrap();
        assert_eq!(h, vec![3, 2, 1, 0x0F, 0x83]);
        let h = AppSpec::new(Aid(1)).keys(2).aes256().iso_file_ids().iso_name(0x1234, b"DUOX").key_sett3(0x05).encode().unwrap();
        assert_eq!(h, vec![1, 0, 0, 0x0F, 0xC0 | 0x20 | 0x10 | 2, 5, 0x34, 0x12, b'D', b'U', b'O', b'X']);
        let cfg = KeySetConfig { aks_version: 1, no_key_sets: 2, max_key_size: 0x10, app_key_set_settings: 0 };
        let h = AppSpec::new(Aid(1)).key_sets(cfg).encode().unwrap();
        assert_eq!(&h[5..], &[1, 1, 2, 0x10, 0]);
        assert!(AppSpec::new(Aid(1)).keys(15).encode().is_err());
        let mut bad = AppSpec::new(Aid(1));
        bad.df_name = b"x".to_vec();
        assert!(bad.encode().is_err());
    }

    #[test]
    fn delegated_info_parsing() {
        let mut t = MockTransport::new();
        t.expect_hex("9069000002 0300 00", "02 0A00 0500 563412 9100");
        let mut card = Card::new(t);
        let i = card.get_delegated_info(3).unwrap();
        assert_eq!((i.slot_version, i.quota, i.free_blocks, i.aid), (2, 10, 5, Aid(0x123456)));
    }
}
