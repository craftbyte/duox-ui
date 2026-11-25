//! Persistent store of CAs, certificates, private keys, CRL state and named AES keys.
//!
//! The file is JSON (`{"format": 1, "entries": [...], "aes_keys": {...}}`). Private keys are PKCS#8 PEM, either
//! unprotected or, once a passphrase is set, `ENCRYPTED PRIVATE KEY` (PBES2). Saved AES keys are always kept in
//! clear. Existing store files load and save back unchanged in structure.

use super::access_rights::AccessRights;
use super::cert::{Certificate, CertificateBuilder};
use super::chain::{validate_reader_chain, ChainParams, ChainResult};
use super::crl::{CrlState, CsnOrder};
use super::error::{PkiError, Result};
use super::keys::{self, PrivateKeyFormat};
use super::name::Name;
use super::profile::{CertKind, MAX_READER_CERT, MAX_SERIAL};
use super::time::Time;
use crate::crypto::{self, PrivKey, PubKey, CURVE_P256};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// ------------------------------------------------------------------- entries
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(text.trim()).map_err(serde::de::Error::custom)
    }
}

fn default_curve() -> u8 {
    CURVE_P256
}
fn default_serial() -> u32 {
    1
}

/// One certificate of the store, with its private key if known.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Short random identifier (8 hex digits).
    pub id: String,
    pub kind: CertKind,
    pub name: String,
    /// DER certificate.
    #[serde(with = "hex_bytes")]
    pub cert: Vec<u8>,
    /// PKCS#8 PEM of the private key, `ENCRYPTED` when protected; empty when the key is not held.
    #[serde(default)]
    pub key_pem: String,
    /// Id of the issuing entry.
    #[serde(default)]
    pub parent: Option<String>,
    /// CurveID of the certificate key.
    #[serde(default = "default_curve")]
    pub curve: u8,
    #[serde(default)]
    pub revoked: bool,
    /// Next serial number this CA will assign (meaningful on roots).
    #[serde(default = "default_serial")]
    pub next_serial: u32,
    /// Revocation state (meaningful on roots).
    #[serde(default)]
    pub crl: CrlState,
    #[serde(default)]
    pub note: String,
}

impl Entry {
    pub fn certificate(&self) -> Result<Certificate> {
        Certificate::from_der(&self.cert)
    }
    pub fn serial(&self) -> Option<u64> {
        self.certificate().ok().and_then(|c| c.serial())
    }
    pub fn public_key(&self) -> Result<PubKey> {
        self.certificate()?.public_key()
    }
    /// 65-byte uncompressed public key.
    pub fn public_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.public_key()?.to_bytes())
    }
    pub fn has_key(&self) -> bool {
        !self.key_pem.is_empty()
    }
    /// The access-rights extension, if present and valid.
    pub fn access_rights(&self) -> Option<AccessRights> {
        self.certificate().ok()?.access_rights().ok().flatten()
    }
}

// ------------------------------------------------------------ saved AES keys
/// Named AES keys, in insertion order (as hex text, the file's representation).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SavedKeys(Vec<(String, String)>);

impl Serialize for SavedKeys {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl<'de> Deserialize<'de> for SavedKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = SavedKeys;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map of key names to hex strings")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> std::result::Result<SavedKeys, A::Error> {
                let mut v: Vec<(String, String)> = Vec::new();
                while let Some((k, val)) = a.next_entry::<String, String>()? {
                    match v.iter_mut().find(|(n, _)| *n == k) {
                        Some(slot) => slot.1 = val,
                        None => v.push((k, val)),
                    }
                }
                Ok(SavedKeys(v))
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    #[serde(default = "one")]
    format: u32,
    #[serde(default)]
    entries: Vec<Entry>,
    #[serde(default)]
    aes_keys: SavedKeys,
}

fn one() -> u32 {
    1
}

/// JSON layout of the store file: one space indentation and `\uXXXX` escapes for non-ASCII text.
struct FileFormatter(serde_json::ser::PrettyFormatter<'static>);

impl serde_json::ser::Formatter for FileFormatter {
    fn begin_array<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_array(w)
    }
    fn end_array<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_array(w)
    }
    fn begin_array_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W, first: bool) -> std::io::Result<()> {
        self.0.begin_array_value(w, first)
    }
    fn end_array_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_array_value(w)
    }
    fn begin_object<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_object(w)
    }
    fn end_object<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_object(w)
    }
    fn begin_object_key<W: ?Sized + std::io::Write>(&mut self, w: &mut W, first: bool) -> std::io::Result<()> {
        self.0.begin_object_key(w, first)
    }
    fn end_object_key<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_object_key(w)
    }
    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_object_value(w)
    }
    fn end_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_object_value(w)
    }
    fn write_string_fragment<W: ?Sized + std::io::Write>(&mut self, w: &mut W, fragment: &str) -> std::io::Result<()> {
        let mut buf = [0u16; 2];
        for c in fragment.chars() {
            if c.is_ascii() {
                w.write_all(&[c as u8])?;
            } else {
                for u in c.encode_utf16(&mut buf) {
                    write!(w, "\\u{u:04x}")?;
                }
            }
        }
        Ok(())
    }
}

// ----------------------------------------------------------------- requests
/// Parameters for issuing a delegated CA, reader or card certificate.
#[derive(Debug, Clone)]
pub struct IssueRequest<'a> {
    pub kind: CertKind,
    pub name: &'a str,
    pub organization: &'a str,
    /// NXP access-rights extension to embed.
    pub access_rights: Option<AccessRights>,
    /// Certify this public key (65-byte uncompressed point) instead of generating a key pair.
    pub public_key: Option<&'a [u8]>,
    /// Curve of the key; defaults to the issuer's.
    pub curve_id: Option<u8>,
    /// Criticality flag of the access-rights extension.
    pub critical: bool,
    pub years: u32,
    /// Explicit serial number; defaults to the root's next serial.
    pub serial: Option<u32>,
}

impl<'a> IssueRequest<'a> {
    pub fn new(kind: CertKind, name: &'a str) -> Self {
        IssueRequest {
            kind,
            name,
            organization: "",
            access_rights: None,
            public_key: None,
            curve_id: None,
            critical: true,
            years: 10,
            serial: None,
        }
    }
    pub fn organization(mut self, org: &'a str) -> Self {
        self.organization = org;
        self
    }
    pub fn access_rights(mut self, ar: AccessRights) -> Self {
        self.access_rights = Some(ar);
        self
    }
    pub fn public_key(mut self, key: &'a [u8]) -> Self {
        self.public_key = Some(key);
        self
    }
    pub fn curve(mut self, curve_id: u8) -> Self {
        self.curve_id = Some(curve_id);
        self
    }
    pub fn critical(mut self, critical: bool) -> Self {
        self.critical = critical;
        self
    }
    pub fn years(mut self, years: u32) -> Self {
        self.years = years;
        self
    }
    pub fn serial(mut self, serial: u32) -> Self {
        self.serial = Some(serial);
        self
    }
}

/// Options for [`PkiStore::import`].
#[derive(Debug, Clone, Default)]
pub struct ImportOptions<'a> {
    /// PEM private key belonging to one of the certificates.
    pub key_pem: Option<&'a str>,
    /// Passphrase of `key_pem` when it is encrypted.
    pub key_passphrase: Option<&'a str>,
    /// Role of the imported entries; by default roots for self-signed or unknown issuers, readers otherwise.
    pub kind: Option<CertKind>,
    /// Display name; defaults to the subject common name.
    pub name: Option<&'a str>,
}

/// What the simulated card selection looks like for [`PkiStore::preflight`].
#[derive(Debug, Clone)]
pub struct PreflightOptions {
    pub aid: u32,
    pub aid2: Option<u32>,
    pub df_name: Option<Vec<u8>>,
    pub uid: Option<Vec<u8>>,
    pub root_acmap: super::access_rights::AcMap,
    /// Whether the card was given the issuer name of the root.
    pub check_issuer: bool,
    pub csn_order: CsnOrder,
}

impl Default for PreflightOptions {
    fn default() -> Self {
        PreflightOptions {
            aid: 0,
            aid2: None,
            df_name: None,
            uid: None,
            root_acmap: super::access_rights::AcMap::ALL,
            check_issuer: true,
            csn_order: CsnOrder::default(),
        }
    }
}

// -------------------------------------------------------------------- store
/// The store. Mutating operations save immediately when the store is bound to a file.
#[derive(Debug, Default)]
pub struct PkiStore {
    path: Option<PathBuf>,
    passphrase: Option<Zeroizing<String>>,
    entries: Vec<Entry>,
    aes_keys: SavedKeys,
}

fn locked(e: PkiError) -> PkiError {
    match e {
        PkiError::PassphraseRequired => PkiError::StoreLocked("the store's private keys are passphrase protected".into()),
        PkiError::WrongPassphrase => PkiError::StoreLocked("wrong passphrase".into()),
        other => other,
    }
}

impl PkiStore {
    /// An empty store that is not bound to a file (nothing is saved).
    pub fn new() -> Self {
        Self::default()
    }

    /// `~/.duoxtool/store.json`
    pub fn default_path() -> Option<PathBuf> {
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
        Some(PathBuf::from(home).join(".duoxtool").join("store.json"))
    }

    /// Bind a store to `path`, loading it when the file exists. `passphrase` unlocks protected keys; it is not
    /// checked until a key is used (see [`PkiStore::unlock`]).
    pub fn open(path: impl AsRef<Path>, passphrase: Option<&str>) -> Result<Self> {
        let mut s = PkiStore {
            path: Some(path.as_ref().to_path_buf()),
            passphrase: passphrase.filter(|p| !p.is_empty()).map(|p| Zeroizing::new(p.to_string())),
            ..Default::default()
        };
        if path.as_ref().exists() {
            s.load()?;
        }
        Ok(s)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    // ---- persistence -------------------------------------------------------
    /// Reload from the bound file.
    pub fn load(&mut self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let text = std::fs::read_to_string(path)?;
        let file: StoreFile = serde_json::from_str(text.trim_start_matches('\u{feff}'))?;
        self.entries = file.entries;
        self.aes_keys = file.aes_keys;
        Ok(())
    }

    /// Write the file atomically (temporary file, then rename); owner-only permissions on Unix.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let text = self.to_json()?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// The file content.
    pub fn to_json(&self) -> Result<String> {
        let file = StoreFile { format: 1, entries: self.entries.clone(), aes_keys: self.aes_keys.clone() };
        let mut out = Vec::new();
        let fmt = FileFormatter(serde_json::ser::PrettyFormatter::with_indent(b" "));
        let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
        file.serialize(&mut ser)?;
        Ok(String::from_utf8(out).unwrap_or_default())
    }

    /// Load a store from JSON text without binding it to a file.
    pub fn from_json(text: &str) -> Result<Self> {
        let file: StoreFile = serde_json::from_str(text)?;
        Ok(PkiStore { entries: file.entries, aes_keys: file.aes_keys, ..Default::default() })
    }

    // ---- passphrase --------------------------------------------------------
    /// True when any private key is stored passphrase protected.
    pub fn is_encrypted(&self) -> bool {
        self.entries.iter().any(|e| keys::pem_is_encrypted(&e.key_pem))
    }

    /// True when a passphrase is held in memory.
    pub fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }

    /// True when protected keys exist and no passphrase is held.
    pub fn is_locked(&self) -> bool {
        self.is_encrypted() && self.passphrase.is_none()
    }

    /// Supply the passphrase of a protected store and verify it against a stored key.
    /// Returns [`PkiError::StoreLocked`] when it is wrong. On a store without protected keys nothing happens.
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        let Some(sample) = self.entries.iter().find(|e| keys::pem_is_encrypted(&e.key_pem)) else {
            return Ok(());
        };
        keys::private_from_pem(&sample.key_pem, Some(passphrase)).map_err(locked)?;
        self.passphrase = Some(Zeroizing::new(passphrase.to_string()));
        Ok(())
    }

    /// Forget the passphrase held in memory.
    pub fn lock(&mut self) {
        self.passphrase = None;
    }

    /// Re-encrypt all private keys with `new` (or remove the protection with `None` or an empty string) and
    /// save. The current passphrase must be available when keys are protected.
    pub fn set_passphrase(&mut self, new: Option<&str>) -> Result<()> {
        let new = new.filter(|p| !p.is_empty());
        let mut fresh = Vec::new();
        for e in self.entries.iter().filter(|e| e.has_key()) {
            let key = self.key_of(&e.id)?;
            fresh.push((e.id.clone(), keys::private_to_pem(&key, PrivateKeyFormat::Pkcs8, new)?));
        }
        for (id, pem) in fresh {
            if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
                e.key_pem = pem;
            }
        }
        self.passphrase = new.map(|p| Zeroizing::new(p.to_string()));
        self.save()
    }

    fn serialize_key(&self, key: &PrivKey) -> Result<String> {
        keys::private_to_pem(key, PrivateKeyFormat::Pkcs8, self.passphrase.as_ref().map(|p| p.as_str()))
    }

    // ---- queries -------------------------------------------------------------
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, id: &str) -> Result<&Entry> {
        self.entries.iter().find(|e| e.id == id).ok_or_else(|| PkiError::NoSuchEntry(id.to_string()))
    }

    fn get_mut(&mut self, id: &str) -> Result<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id).ok_or_else(|| PkiError::NoSuchEntry(id.to_string()))
    }

    /// Entries issued by `parent` (`None`: those without issuer), sorted by kind then name.
    pub fn children(&self, parent: Option<&str>) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.entries.iter().filter(|e| e.parent.as_deref() == parent).collect();
        v.sort_by(|a, b| (a.kind.as_str(), &a.name).cmp(&(b.kind.as_str(), &b.name)));
        v
    }

    pub fn roots(&self) -> Vec<&Entry> {
        self.children(None)
    }

    /// The top of the issuing chain of an entry.
    pub fn root_of(&self, id: &str) -> Result<&Entry> {
        let mut e = self.get(id)?;
        for _ in 0..=self.entries.len() {
            match e.parent.as_deref().and_then(|p| self.entries.iter().find(|x| x.id == p)) {
                Some(p) => e = p,
                None => return Ok(e),
            }
        }
        Err(PkiError::Invalid("issuer chain of the entry is cyclic".into()))
    }

    pub fn by_kind(&self, kinds: &[CertKind]) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.entries.iter().filter(|e| kinds.contains(&e.kind)).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// `name  [Reader #3 1a2b3c4d]`
    pub fn label(&self, e: &Entry) -> String {
        let serial = e.serial().map(|s| s.to_string()).unwrap_or_else(|| "?".into());
        format!("{}  [{} #{serial} {}]", e.name, e.kind.label(), e.id)
    }

    /// `Cert.A` for a reader identity: parent followed by leaf when issued by a delegated CA. Empty for roots.
    pub fn chain_bytes(&self, id: &str) -> Result<Vec<u8>> {
        let e = self.get(id)?;
        if e.kind == CertKind::Root {
            return Ok(Vec::new());
        }
        match e.parent.as_deref().and_then(|p| self.get(p).ok()) {
            Some(p) if p.kind == CertKind::Sub => Ok([p.cert.as_slice(), e.cert.as_slice()].concat()),
            _ => Ok(e.cert.clone()),
        }
    }

    /// The entry's private key. Fails with [`PkiError::StoreLocked`] when keys are protected and the
    /// passphrase is missing or wrong.
    pub fn key_of(&self, id: &str) -> Result<PrivKey> {
        let e = self.get(id)?;
        if e.key_pem.is_empty() {
            return Err(PkiError::Invalid(format!("no private key stored for '{}'", e.name)));
        }
        let pass = if keys::pem_is_encrypted(&e.key_pem) { self.passphrase.as_ref().map(|p| p.as_str()) } else { None };
        keys::private_from_pem(&e.key_pem, pass).map_err(locked)
    }

    // ---- issuing ---------------------------------------------------------------
    fn fresh_id(&self) -> String {
        loop {
            let id = hex::encode(crypto::rnd(4));
            if !self.entries.iter().any(|e| e.id == id) {
                return id;
            }
        }
    }

    /// Create a self-signed root CA with a new key pair. Its certificate is a regular CA certificate (only its
    /// public key goes to a card).
    pub fn new_root(&mut self, name: &str, curve_id: u8, organization: &str, years: u32) -> Result<Entry> {
        let key = crypto::gen_key(curve_id)?;
        let subject = Name::with_common_name(name, organization);
        let serial = rand_serial();
        let now = Time::now();
        let cert = CertificateBuilder::new(subject.clone(), subject, key.public())
            .serial(u64::from(serial))
            .validity(now.plus_days(-1), now.plus_days(365 * i64::from(years)))
            .ca(true)
            .sign(&key)?;
        let e = Entry {
            id: self.fresh_id(),
            kind: CertKind::Root,
            name: name.to_string(),
            cert: cert.to_der().to_vec(),
            key_pem: self.serialize_key(&key)?,
            parent: None,
            curve: curve_id,
            revoked: false,
            next_serial: 1,
            crl: CrlState::default(),
            note: String::new(),
        };
        self.entries.push(e.clone());
        self.save()?;
        Ok(e)
    }

    /// Issue a delegated CA, reader or card certificate under the CA entry `parent_id`.
    pub fn issue(&mut self, parent_id: &str, req: IssueRequest<'_>) -> Result<Entry> {
        let parent = self.get(parent_id)?.clone();
        if !parent.kind.is_ca() {
            return Err(PkiError::Invalid("certificates can only be issued by a CA entry".into()));
        }
        if req.kind == CertKind::Root {
            return Err(PkiError::Invalid("a root CA is created with new_root".into()));
        }
        if req.kind == CertKind::Sub && parent.kind != CertKind::Root {
            return Err(PkiError::Invalid(
                "the card accepts chains of at most two certificates: a delegated CA must be issued by the root".into(),
            ));
        }
        let root = self.root_of(parent_id)?.clone();
        let curve_id = req.curve_id.unwrap_or(parent.curve);
        if matches!(req.kind, CertKind::Sub | CertKind::Reader) {
            if curve_id != root.curve {
                return Err(PkiError::Invalid("reader certificates must use the curve of the CA root key".into()));
            }
            if let (CertKind::Sub, Some(ar)) = (req.kind, &req.access_rights) {
                if !ar.delegation {
                    return Err(PkiError::Invalid(
                        "a delegated CA with an access right extension needs the CA delegation bit".into(),
                    ));
                }
            }
            if let (Some(pa), Some(ar)) = (parent.access_rights(), &req.access_rights) {
                use super::access_rights::RightsScope::{Aid, DfName};
                let narrows = |s: &super::access_rights::RightsScope| matches!(s, Aid { .. } | DfName { .. });
                if narrows(&pa.scope) && narrows(&ar.scope) && !ar.acmap().is_subset_of(pa.acmap()) {
                    return Err(PkiError::Invalid("ACMap exceeds the rights of the issuing CA certificate".into()));
                }
            }
        }
        let signer = self.key_of(parent_id)?;
        let (subject_pub, new_key) = match req.public_key {
            None => {
                let k = crypto::gen_key(curve_id)?;
                (k.public(), Some(k))
            }
            Some(raw) => (PubKey::from_bytes(curve_id, raw)?, None),
        };
        let serial = req.serial.unwrap_or(root.next_serial);
        if serial == 0 || serial > MAX_SERIAL {
            return Err(PkiError::Invalid("serial must be 1..0x7FFFFFFF (4-byte INTEGER; 0 cannot be revoked)".into()));
        }
        let now = Time::now();
        let mut b = CertificateBuilder::new(
            Name::with_common_name(req.name, req.organization),
            parent.certificate()?.subject().clone(),
            subject_pub,
        )
        .serial(u64::from(serial))
        .validity(now.plus_days(-1), now.plus_days(365 * i64::from(req.years)));
        if let Some(ar) = req.access_rights {
            b = b.access_rights(ar, req.critical);
        }
        let cert = b.sign(&signer)?;
        let der = cert.to_der().to_vec();
        if matches!(req.kind, CertKind::Sub | CertKind::Reader) && der.len() > MAX_READER_CERT {
            return Err(PkiError::Invalid(format!(
                "certificate is {} bytes; the card accepts at most {MAX_READER_CERT}. Shorten the names.",
                der.len()
            )));
        }
        let key_pem = match &new_key {
            Some(k) => self.serialize_key(k)?,
            None => String::new(),
        };
        let e = Entry {
            id: self.fresh_id(),
            kind: req.kind,
            name: req.name.to_string(),
            cert: der,
            key_pem,
            parent: Some(parent_id.to_string()),
            curve: curve_id,
            revoked: false,
            next_serial: 1,
            crl: CrlState::default(),
            note: String::new(),
        };
        let root_id = root.id.clone();
        let root_mut = self.get_mut(&root_id)?;
        root_mut.next_serial = root_mut.next_serial.max(serial + 1);
        self.entries.push(e.clone());
        self.save()?;
        Ok(e)
    }

    /// Import certificates from a PEM file or concatenated DER. Issuers already in the store are linked.
    pub fn import(&mut self, blob: &[u8], opts: &ImportOptions<'_>) -> Result<Vec<Entry>> {
        let certs = Certificate::load_all(blob)?;
        if certs.is_empty() {
            return Err(PkiError::Invalid("no certificate found in the file".into()));
        }
        let key = match opts.key_pem {
            Some(pem) => Some(keys::private_from_pem(pem, opts.key_passphrase)?),
            None => None,
        };
        let key_target = match &key {
            Some(k) => Some(
                certs
                    .iter()
                    .position(|c| c.public_key().is_ok_and(|p| p == k.public()))
                    .ok_or_else(|| PkiError::Invalid("private key does not match the certificate".into()))?,
            ),
            None => None,
        };
        let mut out = Vec::new();
        for (i, c) in certs.iter().enumerate() {
            let pk = c
                .public_key()
                .map_err(|_| PkiError::Invalid("only EC certificates on P-256 or brainpoolP256r1 are supported".into()))?;
            let self_signed = c.subject() == c.issuer() && c.verify_signature(&pk);
            let parent = if self_signed {
                None
            } else {
                self.entries
                    .iter()
                    .filter(|e| e.kind.is_ca())
                    .find(|e| {
                        e.certificate().is_ok_and(|pc| {
                            pc.subject() == c.issuer() && pc.public_key().is_ok_and(|k| c.verify_signature(&k))
                        })
                    })
                    .map(|e| e.id.clone())
            };
            let kind = opts.kind.unwrap_or(if self_signed || parent.is_none() { CertKind::Root } else { CertKind::Reader });
            let name = match opts.name {
                Some(n) => n.to_string(),
                None => c.subject().common_name().unwrap_or_else(|| c.subject().rfc4514()),
            };
            let key_pem = match (&key, key_target) {
                (Some(k), Some(t)) if t == i => self.serialize_key(k)?,
                _ => String::new(),
            };
            let e = Entry {
                id: self.fresh_id(),
                kind,
                name,
                cert: c.to_der().to_vec(),
                key_pem,
                parent,
                curve: pk.curve_id,
                revoked: false,
                next_serial: 1,
                crl: CrlState::default(),
                note: String::new(),
            };
            self.entries.push(e.clone());
            out.push(e);
        }
        self.save()?;
        Ok(out)
    }

    /// Delete an entry and everything it issued.
    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.get(id)?;
        let mut doomed = vec![id.to_string()];
        let mut i = 0;
        while i < doomed.len() {
            let parent = doomed[i].clone();
            doomed.extend(self.entries.iter().filter(|e| e.parent.as_deref() == Some(&parent)).map(|e| e.id.clone()));
            i += 1;
        }
        self.entries.retain(|e| !doomed.contains(&e.id));
        self.save()
    }

    /// Mark a certificate revoked (or not) and maintain the serial list of its root's CRL.
    pub fn set_revoked(&mut self, id: &str, revoked: bool) -> Result<()> {
        let e = self.get(id)?;
        if e.kind == CertKind::Root {
            return Err(PkiError::Invalid("a root is revoked by replacing the CARootKey on the cards".into()));
        }
        let serial = e
            .serial()
            .and_then(|s| u32::try_from(s).ok())
            .ok_or_else(|| PkiError::Invalid("the certificate serial number does not fit a CRL entry".into()))?;
        let root_id = self.root_of(id)?.id.clone();
        self.get_mut(id)?.revoked = revoked;
        self.get_mut(&root_id)?.crl.set_revoked(serial, revoked);
        self.save()
    }

    /// Replace a root's CRL settings (CSNAllBefore, CRLVersion, listed serials).
    pub fn set_crl(&mut self, root_id: &str, crl: CrlState) -> Result<()> {
        let mut crl = crl;
        crl.serials.sort_unstable();
        crl.serials.dedup();
        self.get_mut(root_id)?.crl = crl;
        self.save()
    }

    pub fn set_note(&mut self, id: &str, note: &str) -> Result<()> {
        self.get_mut(id)?.note = note.to_string();
        self.save()
    }

    // ---- export ----------------------------------------------------------------
    /// Unprotected PKCS#8 PEM of the entry's private key (for export; handle with care).
    pub fn export_key_pem(&self, id: &str) -> Result<String> {
        keys::private_to_pem(&self.key_of(id)?, PrivateKeyFormat::Pkcs8, None)
    }

    /// Private key PEM in a chosen format, optionally protected with an export passphrase.
    pub fn export_key_pem_as(&self, id: &str, format: PrivateKeyFormat, passphrase: Option<&str>) -> Result<String> {
        keys::private_to_pem(&self.key_of(id)?, format, passphrase)
    }

    pub fn cert_pem(&self, id: &str) -> Result<String> {
        Ok(self.get(id)?.certificate()?.to_pem())
    }

    /// Validate a reader identity exactly as the card would, including the local CRL.
    pub fn preflight(&self, id: &str, opts: &PreflightOptions) -> Result<ChainResult> {
        let root = self.root_of(id)?;
        let root_cert = root.certificate()?;
        let crl = root.crl.image(None, opts.csn_order)?;
        let chain = self.chain_bytes(id)?;
        let params = ChainParams {
            issuer: opts.check_issuer.then(|| root_cert.subject().to_der()),
            root_acmap: opts.root_acmap,
            root_acmap2: None,
            aid: opts.aid,
            aid2: opts.aid2,
            df_name: opts.df_name.as_deref(),
            uid: opts.uid.as_deref(),
            crl: Some(&crl),
            csn_order: opts.csn_order,
        };
        Ok(validate_reader_chain(&chain, &root_cert.public_key()?, &params)?)
    }

    // ---- named AES keys ---------------------------------------------------------
    /// Names of the saved AES keys, sorted.
    pub fn aes_key_names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.aes_keys.0.iter().map(|(k, _)| k.as_str()).collect();
        v.sort_unstable();
        v
    }

    /// A saved key by name.
    pub fn aes_key(&self, name: &str) -> Option<Vec<u8>> {
        let (_, v) = self.aes_keys.0.iter().find(|(k, _)| k == name)?;
        parse_hex(v).ok()
    }

    /// Save (or replace) a named 16- or 32-byte AES key and write the store. Keys are stored in clear.
    pub fn set_aes_key(&mut self, name: &str, key: &[u8]) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(PkiError::Invalid("a saved key needs a name".into()));
        }
        if key.len() != 16 && key.len() != 32 {
            return Err(PkiError::Invalid("an AES key is 16 or 32 bytes".into()));
        }
        let hexed = hex::encode_upper(key);
        match self.aes_keys.0.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = hexed,
            None => self.aes_keys.0.push((name.to_string(), hexed)),
        }
        self.save()
    }

    /// Remove a saved key; returns whether it existed.
    pub fn remove_aes_key(&mut self, name: &str) -> Result<bool> {
        let before = self.aes_keys.0.len();
        self.aes_keys.0.retain(|(k, _)| k != name);
        let removed = self.aes_keys.0.len() != before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Interpret `text` as the name of a saved key, else as a hex string.
    pub fn resolve_aes_key(&self, text: &str) -> Result<Vec<u8>> {
        match self.aes_keys.0.iter().find(|(k, _)| k == text.trim()) {
            Some((_, v)) => parse_hex(v),
            None => parse_hex(text),
        }
    }
}

fn rand_serial() -> u32 {
    let b = crypto::rnd(3);
    (u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2])) | 1
}

/// Hex with optional `0x`, whitespace, `:`, `,` and `-` separators.
fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let cleaned: String = text.trim().replace("0x", "").chars().filter(|c| !c.is_whitespace() && !":,-".contains(*c)).collect();
    if cleaned.len() % 2 == 1 {
        return Err(PkiError::Invalid("hex string has an odd number of digits".into()));
    }
    hex::decode(&cleaned).map_err(|_| PkiError::Invalid("not a hex string".into()))
}
