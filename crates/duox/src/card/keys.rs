//! Key management (7.8, 7.9): symmetric keys (ChangeKey / ChangeKeyEV2, key sets, key settings,
//! key versions) and asymmetric keys (ManageKeyPair, ManageCARootKey, ExportKey, key settings).

use super::types::*;
use super::Card;
use crate::crypto::{self, SessionKind};
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Parameters of the key set feature, as returned by GetKeySettings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySetInfo {
    pub aks_version: u8,
    pub key_sets: u8,
    pub max_key_size: u8,
    pub key_set_settings: u8,
}

/// GetKeySettings (application / PICC level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySettings {
    pub settings: u8,
    pub max_keys: u8,
    /// Key type bits (b7..b6 of the second byte).
    pub key_type: u8,
    pub key_sets: Option<KeySetInfo>,
    pub raw: Vec<u8>,
}

/// One entry of GetKeySettings option 1 (ECC private keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccKeyInfo {
    pub key_no: u8,
    pub curve: u8,
    pub policy: u16,
    pub write_access: u8,
    pub kuc_limit: u32,
    pub kuc: u32,
}

/// One entry of GetKeySettings option 2 (CA root keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaRootKeyInfo {
    pub key_no: u8,
    pub curve: u8,
    pub access_rights: u16,
    pub write_access: u8,
    pub read_access: u8,
    pub crl_file: u8,
    pub crl_aid: Aid,
}

/// Operation of ManageKeyPair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPairOp {
    /// Generate on the card; the public key is returned.
    Generate,
    /// Import a private key (raw scalar, 32 bytes).
    Import(Vec<u8>),
    /// Change policy / access / usage counter limit only.
    UpdateMetadata,
}

/// Meta data of an ECC private key slot.
#[derive(Debug, Clone)]
pub struct KeyPairSpec {
    pub key_no: u8,
    pub curve_id: u8,
    /// KeyPolicy bits (Table 158 of the data sheet; verify against a real card).
    pub policy: u16,
    pub write_access: u8,
    pub kuc_limit: u32,
}

impl KeyPairSpec {
    pub fn new(key_no: u8, curve_id: u8, policy: u16, write_access: u8) -> Self {
        KeyPairSpec { key_no, curve_id, policy, write_access, kuc_limit: 0 }
    }
    pub fn kuc_limit(mut self, l: u32) -> Self {
        self.kuc_limit = l;
        self
    }
}

/// ManageCARootKey parameters.
#[derive(Debug, Clone)]
pub struct CaRootKeySpec {
    pub key_no: u8,
    pub curve_id: u8,
    pub access_rights: u16,
    pub write_access: u8,
    pub read_access: u8,
    pub crl_file: u8,
    pub crl_aid: Aid,
    /// Uncompressed public key, 65 bytes.
    pub public_key: Vec<u8>,
    /// Trusted issuer name (empty for none), at most 255 bytes.
    pub issuer: Vec<u8>,
}

impl CaRootKeySpec {
    pub fn new(key_no: u8, curve_id: u8, public_key: Vec<u8>) -> Self {
        CaRootKeySpec {
            key_no,
            curve_id,
            access_rights: 0,
            write_access: 0,
            read_access: 0,
            crl_file: 0,
            crl_aid: Aid::PICC,
            public_key,
            issuer: vec![],
        }
    }
}

/// ChangeKey / ChangeKeyEV2 parameters.
#[derive(Debug, Clone)]
pub struct ChangeKeySpec {
    /// Sent as is: at PICC level OR in the key type (0x80 AES-128, 0xC0 AES-256) when required (8.4.1).
    pub key_no: u8,
    pub new_key: Vec<u8>,
    /// Old key; required when changing a key other than the authenticated one.
    pub old_key: Option<Vec<u8>>,
    pub key_version: u8,
    /// Use ChangeKeyEV2 for this key set.
    pub key_set: Option<u8>,
}

impl ChangeKeySpec {
    pub fn new(key_no: u8, new_key: &[u8], key_version: u8) -> Self {
        ChangeKeySpec { key_no, new_key: new_key.to_vec(), old_key: None, key_version, key_set: None }
    }
    pub fn old_key(mut self, k: &[u8]) -> Self {
        self.old_key = Some(k.to_vec());
        self
    }
    pub fn key_set(mut self, ks: u8) -> Self {
        self.key_set = Some(ks);
        self
    }
}

fn entries<'a>(d: &'a [u8], size: usize, what: &str) -> Result<Vec<&'a [u8]>> {
    let n = *d.first().ok_or_else(|| Error::protocol(format!("{what}: empty response")))? as usize;
    let body = d.get(1..1 + n * size).ok_or_else(|| Error::protocol(format!("{what}: response too short")))?;
    Ok(body.chunks(size).collect())
}

fn mode_from_access(b: u8) -> CommMode {
    CommMode::from_bits(b >> 4)
}

impl<T: Transport> Card<T> {
    // -------------------------------------------------------------- settings
    pub fn get_key_settings(&mut self) -> Result<KeySettings> {
        let d = self.command(cmd::GET_KEY_SETTINGS, &[], &[], CommMode::Mac)?;
        if d.len() < 2 {
            self.drop_session();
            return Err(Error::protocol("GetKeySettings: response too short"));
        }
        let key_sets = (d.len() >= 6).then(|| KeySetInfo {
            aks_version: d[2],
            key_sets: d[3],
            max_key_size: d[4],
            key_set_settings: d[5],
        });
        Ok(KeySettings { settings: d[0], max_keys: d[1] & 0x3F, key_type: d[1] >> 6, key_sets, raw: d })
    }

    /// GetKeySettings option 1: ECC private key slots.
    pub fn get_ecc_key_settings(&mut self) -> Result<Vec<EccKeyInfo>> {
        let d = self.command(cmd::GET_KEY_SETTINGS, &[1], &[], CommMode::Mac)?;
        let r = entries(&d, 13, "GetKeySettings");
        let list = match r {
            Ok(e) => e,
            Err(e) => {
                self.drop_session();
                return Err(e);
            }
        };
        Ok(list
            .iter()
            .map(|e| EccKeyInfo {
                key_no: e[0],
                curve: e[1],
                policy: u16::from_le_bytes([e[2], e[3]]),
                write_access: e[4],
                kuc_limit: le_u32(&e[5..9]),
                kuc: le_u32(&e[9..13]),
            })
            .collect())
    }

    /// GetKeySettings option 2: CA root key slots.
    pub fn get_ca_root_key_settings(&mut self) -> Result<Vec<CaRootKeyInfo>> {
        let d = self.command(cmd::GET_KEY_SETTINGS, &[2], &[], CommMode::Mac)?;
        let list = match entries(&d, 10, "GetKeySettings") {
            Ok(e) => e,
            Err(e) => {
                self.drop_session();
                return Err(e);
            }
        };
        Ok(list
            .iter()
            .map(|e| CaRootKeyInfo {
                key_no: e[0],
                curve: e[1],
                access_rights: u16::from_le_bytes([e[2], e[3]]),
                write_access: e[4],
                read_access: e[5],
                crl_file: e[6],
                crl_aid: Aid::from_bytes(&e[7..10]),
            })
            .collect())
    }

    pub fn change_key_settings(&mut self, settings: u8) -> Result<()> {
        self.command(cmd::CHANGE_KEY_SETTINGS, &[], &[settings], CommMode::Full).map(|_| ())
    }

    /// Version byte(s) of a key; with `key_set` the key of that key set (relative to the active one).
    pub fn get_key_version(&mut self, key_no: u8, key_set: Option<u8>) -> Result<Vec<u8>> {
        let h = match key_set {
            None => vec![key_no],
            Some(ks) => vec![key_no | 0x40, ks & 0x0F],
        };
        self.command(cmd::GET_KEY_VERSION, &h, &[], CommMode::Mac)
    }

    /// Versions of all key sets, active key set first.
    pub fn get_key_set_versions(&mut self) -> Result<Vec<u8>> {
        self.command(cmd::GET_KEY_VERSION, &[0x40, 0x80], &[], CommMode::Mac)
    }

    // ------------------------------------------------------- symmetric keys
    /// ChangeKey (or ChangeKeyEV2 when a key set is given). Changing the key used for the current
    /// authentication ends it (the response then carries no MAC).
    pub fn change_key(&mut self, spec: &ChangeKeySpec) -> Result<()> {
        let mut s = self.session.take().ok_or(Error::NotAuthenticated("ChangeKey"))?;
        // From here on every early return leaves the session dropped, as the card would.
        let c = if spec.key_set.is_none() { cmd::CHANGE_KEY } else { cmd::CHANGE_KEY_EV2 };
        let mut header: Vec<u8> = spec.key_set.into_iter().collect();
        header.push(spec.key_no);
        let same = s.kind == SessionKind::Aes
            && Some(spec.key_no & 0x3F) == s.key_no
            // bit 7 of the key number is the secondary-application indicator only while two applications are selected
            && (self.selection.secondary.is_none() || (spec.key_no & 0x80 != 0) == s.sai)
            && spec.key_set.unwrap_or(0) == 0;
        let mut kd;
        if same {
            kd = spec.new_key.clone();
            kd.push(spec.key_version);
        } else {
            let old = match &spec.old_key {
                Some(o) if o.len() == spec.new_key.len() => o,
                _ => {
                    return Err(Error::arg(
                        "changing a key other than the authenticated one needs the old key (same length as the new key)",
                    ))
                }
            };
            kd = crypto::xor(&spec.new_key, old);
            kd.push(spec.key_version);
            kd.extend(crypto::crc32_nk(&spec.new_key));
        }
        self.log_line(&format!("-- {} key {:02X}", command_name(c), spec.key_no));
        let body = s.encrypt(&kd, false)?;
        let mut tx = header.clone();
        tx.extend(&body);
        let mac = s.mac_cmd(c, &tx)?;
        tx.extend(mac);
        let (rc, frames) = self.exchange(c, &tx)?;
        if rc != 0 {
            return Err(self.fail(rc, c, true));
        }
        s.ctr = s.ctr.wrapping_add(1);
        if same {
            self.drop_session(); // authentication is lost; the response carries no MAC
            return Ok(());
        }
        if frames.concat() != s.mac_resp(0, &[])? {
            self.drop_session();
            return Err(Error::protocol("ChangeKey: response MAC invalid - session dropped"));
        }
        self.session = Some(s);
        Ok(())
    }

    pub fn initialize_key_set(&mut self, key_set: u8, key_type: u8) -> Result<()> {
        self.command(cmd::INITIALIZE_KEY_SET, &[key_set, key_type], &[], CommMode::Mac).map(|_| ())
    }

    pub fn finalize_key_set(&mut self, key_set: u8, version: u8) -> Result<()> {
        self.command(cmd::FINALIZE_KEY_SET, &[key_set, version], &[], CommMode::Mac).map(|_| ())
    }

    /// RollKeySet: activates a key set; the authentication ends.
    pub fn roll_key_set(&mut self, key_set: u8) -> Result<()> {
        self.command(cmd::ROLL_KEY_SET, &[key_set], &[], CommMode::Mac)?;
        self.drop_session();
        Ok(())
    }

    // ------------------------------------------------------ asymmetric keys
    /// CommMode of an existing asymmetric key entry (taken from its access field), Full for a
    /// new one, Plain when not authenticated.
    fn asym_mode(&mut self, option: u8, key_no: u8, write: bool) -> Result<CommMode> {
        if self.session.is_none() {
            return Ok(CommMode::Plain);
        }
        if option == 1 {
            for k in self.get_ecc_key_settings()? {
                if k.key_no == key_no {
                    return Ok(mode_from_access(k.write_access));
                }
            }
        } else {
            for k in self.get_ca_root_key_settings()? {
                if k.key_no == key_no {
                    return Ok(mode_from_access(if write { k.write_access } else { k.read_access }));
                }
            }
        }
        Ok(CommMode::Full)
    }

    /// ManageKeyPair. Returns the public key for [`KeyPairOp::Generate`], otherwise empty.
    /// `mode` defaults to the mode configured in the key entry's write access.
    pub fn manage_key_pair(&mut self, spec: &KeyPairSpec, op: &KeyPairOp, mode: Option<CommMode>) -> Result<Vec<u8>> {
        let (option, data): (u8, &[u8]) = match op {
            KeyPairOp::Generate => (0, &[]),
            KeyPairOp::Import(k) => {
                if k.len() != 32 {
                    return Err(Error::arg("private key must be 32 bytes"));
                }
                (1, k)
            }
            KeyPairOp::UpdateMetadata => (2, &[]),
        };
        let mode = match mode {
            Some(m) => m,
            None => self.asym_mode(1, spec.key_no, true)?,
        };
        let mut h = vec![spec.key_no, option, spec.curve_id];
        h.extend(spec.policy.to_le_bytes());
        h.push(spec.write_access);
        h.extend(spec.kuc_limit.to_le_bytes());
        self.command(cmd::MANAGE_KEY_PAIR, &h, data, mode)
    }

    pub fn manage_ca_root_key(&mut self, spec: &CaRootKeySpec, mode: Option<CommMode>) -> Result<()> {
        if spec.public_key.len() != 65 || spec.issuer.len() > 255 {
            return Err(Error::arg("public key must be 65 bytes and the issuer at most 255 bytes"));
        }
        let mode = match mode {
            Some(m) => m,
            None => self.asym_mode(2, spec.key_no, true)?,
        };
        let mut h = vec![spec.key_no, spec.curve_id];
        h.extend(spec.access_rights.to_le_bytes());
        h.extend([spec.write_access, spec.read_access, spec.crl_file]);
        h.extend(spec.crl_aid.to_bytes());
        let mut d = spec.public_key.clone();
        d.push(spec.issuer.len() as u8);
        d.extend(&spec.issuer);
        self.command(cmd::MANAGE_CA_ROOT_KEY, &h, &d, mode).map(|_| ())
    }

    /// ExportKey of a CA root public key (65 byte point).
    pub fn export_key(&mut self, key_no: u8, mode: Option<CommMode>) -> Result<Vec<u8>> {
        let mode = match mode {
            Some(m) => m,
            None => self.asym_mode(2, key_no, false)?,
        };
        self.command(cmd::EXPORT_KEY, &[0x01, key_no], &[], mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::testkit::FakeAesCard;
    use crate::transport::MockTransport;

    #[test]
    fn key_settings_parsing() {
        let mut t = MockTransport::new();
        t.expect_hex("9045000000", "0F 82 9100");
        t.expect_hex("90450000 01 01 00", "01 07 0C 1122 30 0A000000 05000000 9100");
        t.expect_hex("90450000 01 02 00", "01 03 0D 3344 10 20 05 563412 9100");
        t.expect_hex("90450000 01 02 00", "02 03 0D 3344 10 20 05 563412 9100");
        let mut card = Card::new(t);
        let ks = card.get_key_settings().unwrap();
        assert_eq!((ks.settings, ks.max_keys, ks.key_type, ks.key_sets), (0x0F, 2, 2, None));
        let e = card.get_ecc_key_settings().unwrap();
        assert_eq!(e[0].policy, 0x2211);
        assert_eq!((e[0].kuc_limit, e[0].kuc), (10, 5));
        let c = card.get_ca_root_key_settings().unwrap();
        assert_eq!(c[0].crl_aid, Aid(0x123456));
        assert_eq!(c[0].access_rights, 0x4433);
        // declared two entries, delivered one
        assert!(card.get_ca_root_key_settings().is_err());
    }

    #[test]
    fn plain_manage_commands_wire() {
        let mut t = MockTransport::new();
        // ManageKeyPair generate: key 2, option 0, curve 0C, policy 0x0100, write 0x30, kuc 0
        t.expect_hex("904600000A 02 00 0C 0001 30 00000000 00", &format!("{}9100", "04".repeat(65)));
        let mut card = Card::new(t);
        let spec = KeyPairSpec::new(2, 0x0C, 0x0100, 0x30);
        assert_eq!(card.manage_key_pair(&spec, &KeyPairOp::Generate, None).unwrap().len(), 65);
        assert!(card.manage_key_pair(&spec, &KeyPairOp::Import(vec![1; 5]), None).is_err());
        let bad = CaRootKeySpec::new(1, 0x0C, vec![0; 64]);
        assert!(card.manage_ca_root_key(&bad, None).is_err());
    }

    #[test]
    fn change_key_requires_old_key_and_session() {
        let mut card = Card::new(MockTransport::new());
        assert!(matches!(card.change_key(&ChangeKeySpec::new(1, &[0; 16], 0)), Err(Error::NotAuthenticated(_))));
        // authenticated with key 0, changing key 1 without old key
        let key = [0u8; 16];
        let mut fake = FakeAesCard::new(&key);
        let t = MockTransport::with_handler(move |a| fake.auth(a).unwrap_or_else(|| vec![0x91, 0x1C]));
        let mut card = Card::new(t);
        card.authenticate_ev2_first(0, &key, &[]).unwrap();
        let e = card.change_key(&ChangeKeySpec::new(1, &[1; 16], 1)).unwrap_err();
        assert!(matches!(e, Error::InvalidArgument(_)));
        assert!(!card.is_authenticated());
    }
}
