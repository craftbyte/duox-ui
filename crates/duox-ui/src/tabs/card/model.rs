//! What the card browser knows about the card: scan result, contents of the selected
//! application, tree construction and the texts shown for each kind of node.

use crate::ui::hex;
use crate::ui::tree::Node;
use duox::card::types::picc_key_name;
use duox::card::{
    AccessRight, Aid, CaRootKeyInfo, CommMode, DfName, EccKeyInfo, FileSettings, KeySettings, VersionInfo,
};
use duox::crypto::curve_name;
use duox::pki::AcMap;
use std::collections::BTreeMap;

/// Result of reading one part of an application.
#[derive(Debug, Clone, Default)]
pub enum Section<T> {
    #[default]
    NotLoaded,
    Loaded(T),
    Failed(String),
}

impl<T> Section<T> {
    pub fn loaded(&self) -> Option<&T> {
        match self {
            Section::Loaded(v) => Some(v),
            _ => None,
        }
    }
}

/// Keys and files of the selected (primary) application or of the PICC level.
#[derive(Debug, Clone, Default)]
pub struct Contents {
    pub keys: Section<KeySettings>,
    pub ecc: Section<Vec<EccKeyInfo>>,
    pub ca: Section<Vec<CaRootKeyInfo>>,
    pub files: Section<Vec<FileSettings>>,
    /// Problems that did not fit a section (for example a single unreadable file).
    pub notes: Vec<String>,
}

impl Contents {
    pub fn files(&self) -> &[FileSettings] {
        self.files.loaded().map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn ecc_keys(&self) -> &[EccKeyInfo] {
        self.ecc.loaded().map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn ca_keys(&self) -> &[CaRootKeyInfo] {
        self.ca.loaded().map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Facts read when the card was scanned (PICC level).
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub version: Option<VersionInfo>,
    pub apps: Vec<Aid>,
    pub df_names: BTreeMap<u32, DfName>,
    pub notes: Vec<String>,
}

impl Scan {
    pub fn df_of(&self, aid: Aid) -> Option<&DfName> {
        self.df_names.get(&aid.0)
    }
    pub fn app_with_df_name(&self, name: &[u8]) -> Option<Aid> {
        self.df_names.values().find(|d| d.name == name).map(|d| d.aid)
    }
}

/// What a tree node stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sel {
    None,
    Picc,
    App(Aid),
    Second(Aid),
    AesGroup,
    Aes(u8),
    EccGroup,
    Ecc(u8),
    CaGroup,
    Ca(u8),
    FilesGroup,
    /// File number as addressed on the wire (bit 7 = second application).
    File(u8),
    SecondFilesGroup,
}

pub fn node_id_for_aid(aid: Aid) -> String {
    if aid == Aid::PICC {
        "picc".into()
    } else {
        format!("app:{}", aid.0)
    }
}

impl Sel {
    pub fn from_id(id: Option<&str>) -> Sel {
        let Some(id) = id else { return Sel::None };
        let num = |s: &str| s.parse::<u32>().ok();
        match id.split_once(':') {
            None => match id {
                "picc" => Sel::Picc,
                "grp:aes" => Sel::AesGroup,
                "grp:ecc" => Sel::EccGroup,
                "grp:ca" => Sel::CaGroup,
                "grp:files" => Sel::FilesGroup,
                "grp:files2" => Sel::SecondFilesGroup,
                _ => Sel::None,
            },
            Some((kind, n)) => match (kind, num(n)) {
                ("app", Some(a)) => Sel::App(Aid(a)),
                ("app2", Some(a)) => Sel::Second(Aid(a)),
                ("aes", Some(k)) => Sel::Aes(k as u8),
                ("ecc", Some(k)) => Sel::Ecc(k as u8),
                ("ca", Some(k)) => Sel::Ca(k as u8),
                ("file", Some(f)) => Sel::File(f as u8),
                _ => Sel::None,
            },
        }
    }

    /// Node of an application (or the PICC level) that can be selected on the card.
    pub fn aid(self) -> Option<Aid> {
        match self {
            Sel::Picc => Some(Aid::PICC),
            Sel::App(a) => Some(a),
            _ => None,
        }
    }
}

// ----------------------------------------------------------------------- texts

/// KeyPolicy bits of an ECC private key (the tool follows the key policy table of the data sheet).
pub const POLICY_BITS: [(u16, &str); 6] = [
    (0x0100, "card-unilateral authentication (ISOInternalAuthenticate)"),
    (0x0080, "ECC mutual authentication"),
    (0x0040, "transaction signature"),
    (0x0020, "SDM signature"),
    (0x0010, "CryptoRequest ECC sign"),
    (0x8000, "freeze the key usage limit"),
];

pub fn policy_text(p: u16) -> String {
    let names: Vec<&str> = POLICY_BITS.iter().filter(|(b, _)| p & b != 0).map(|(_, n)| *n).collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// A key access byte: CommMode in bits 5..4, access condition in bits 3..0.
pub fn access_text(v: u8) -> String {
    format!("0x{v:02X} (CommMode.{}, {})", CommMode::from_bits(v >> 4), AccessRight(v & 0x0F))
}

/// Keys of the PICC level that can be addressed with an authentication.
pub const PICC_KEYS: [u8; 9] = [0x00, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1A, 0x20, 0x21];

pub fn curve_label(id: u8) -> String {
    match curve_name(id) {
        "unknown curve" => format!("curve 0x{id:02X}"),
        n => n.to_string(),
    }
}

pub fn acmap_text(bits: u16) -> String {
    AcMap::new(bits).to_string()
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Number of AES keys that can be addressed in the application, and whether the temporary
/// application master key is active (then only key 0 exists).
pub fn app_key_count(k: &KeySettings, picc: bool) -> (u8, bool) {
    let tmp = !picc && k.max_keys == 0x0F;
    (if tmp { 1 } else { k.max_keys }, tmp)
}

pub fn aes_type_name(key_type: u8) -> &'static str {
    match key_type {
        2 => "AES-128",
        3 => "AES-256",
        _ => "?",
    }
}

pub fn key_settings_text(k: &KeySettings, picc: bool) -> Vec<String> {
    let s = k.settings;
    let mut l = vec![
        format!("KeySettings 0x{s:02X}"),
        format!("  bit 0  master key changeable            {}", yes_no(s & 1 != 0)),
        format!("  bit 1  directory listing without auth   {}", yes_no(s & 2 != 0)),
        format!("  bit 2  create/delete without master key {}", yes_no(s & 4 != 0)),
        format!("  bit 3  key settings changeable          {}", yes_no(s & 8 != 0)),
    ];
    if !picc {
        let cac = match s >> 4 {
            0xE => "the key being changed".to_string(),
            0xF => "frozen (all but the master key)".to_string(),
            n => format!("key {n:X}"),
        };
        l.push(format!("  bits 7-4  ChangeKey requires             {cac}"));
        let (n, tmp) = app_key_count(k, picc);
        let count = if tmp { "AppMasterTmpKey".to_string() } else { n.to_string() };
        l.push(format!("Keys         {count} x {}", aes_type_name(k.key_type)));
    } else if s & 0x10 != 0 {
        l.push("  bit 4  NXPDAMKeys enabled".into());
    }
    if let Some(ks) = &k.key_sets {
        l.push(format!(
            "Key sets {}, AKS version {}, max key size 0x{:02X}, roll access {:02X}",
            ks.key_sets, ks.aks_version, ks.max_key_size, ks.key_set_settings
        ));
    }
    l
}

pub fn ecc_key_text(k: &EccKeyInfo) -> Vec<String> {
    vec![
        format!("ECC private key {}", k.key_no),
        format!("Curve        {}", curve_label(k.curve)),
        format!("KeyPolicy    0x{:04X}  ({})", k.policy, policy_text(k.policy)),
        format!("WriteAccess  {}", access_text(k.write_access)),
        format!(
            "Usage limit  {}   counter {}",
            if k.kuc_limit == 0 { "disabled".to_string() } else { k.kuc_limit.to_string() },
            k.kuc
        ),
    ]
}

pub fn ca_key_text(k: &CaRootKeyInfo) -> Vec<String> {
    let crl = if k.crl_file & 0x80 != 0 {
        format!("file {:02X} in application {}", k.crl_file & 0x1F, k.crl_aid)
    } else {
        "disabled".to_string()
    };
    vec![
        format!("CA root key {}", k.key_no),
        format!("Curve        {}", curve_label(k.curve)),
        format!("AccessRights 0x{:04X}  grants [{}]", k.access_rights, acmap_text(k.access_rights)),
        format!("WriteAccess  {}", access_text(k.write_access)),
        format!("ReadAccess   {}", access_text(k.read_access)),
        format!("CRL          {crl}"),
    ]
}

pub fn version_text(v: &VersionInfo, apps: usize) -> Vec<String> {
    let production = match v.production {
        Some((cw, year)) => format!("calendar week {cw:02X} of 20{year:02X}"),
        None => "not reported".into(),
    };
    vec![
        "PICC level (AID 000000)".into(),
        format!("UID            {}", hex::spaced(&v.uid)),
        format!(
            "Hardware       vendor {:02X}  type {:02X}.{:02X}  version {}.{}  storage {}  protocol {:02X}",
            v.vendor, v.hw_type, v.hw_subtype, v.hw_version.0, v.hw_version.1, v.hw_storage, v.hw_protocol
        ),
        format!(
            "Software       type {:02X}.{:02X}  version {}.{}  storage {}  protocol {:02X}",
            v.sw_type, v.sw_subtype, v.sw_version.0, v.sw_version.1, v.sw_storage, v.sw_protocol
        ),
        format!("Batch / TypeID {} / {}", hex::spaced(&v.batch), hex::spaced(&v.type_id)),
        format!("Production     {production}"),
        String::new(),
        format!("Applications   {apps}"),
        String::new(),
        "Select an application to list its keys and files. Selecting ends any authentication.".into(),
    ]
}

pub fn app_text(aid: Aid, df: Option<&DfName>, selected: bool) -> Vec<String> {
    let mut l = vec![format!("Application {aid}")];
    if let Some(d) = df {
        l.push(format!("ISO file ID  {:04X}", d.iso_fid));
        l.push(format!("DF name      {}  {:?}", hex::spaced(&d.name), String::from_utf8_lossy(&d.name)));
    }
    l.push(String::new());
    l.push(if selected {
        "Selected.".into()
    } else {
        "Not selected. Use Select to list its keys and files (this ends the current authentication).".into()
    });
    l
}

// ------------------------------------------------------------------------ tree

fn file_label(fs: &FileSettings) -> (String, String) {
    let size = match (&fs.size, &fs.record, &fs.value) {
        (Some(s), _, _) => format!("{s} B"),
        (_, Some(r), _) => format!("{} x {} B ({} used)", r.max_records, r.record_size, r.current_records),
        (_, _, Some(v)) => format!("{} .. {}", v.lower, v.upper),
        _ => String::new(),
    };
    let a = fs.access;
    (
        format!("File {:02X}  {}", fs.file_no & 0x7F, fs.type_label()),
        format!(
            "{size}   {}   R:{:X} W:{:X} RW:{:X} C:{:X}",
            fs.comm_mode(),
            a.read.0,
            a.write.0,
            a.read_write.0,
            a.change.0
        ),
    )
}

fn failed_node(id: &str, label: &str, e: &str) -> Node {
    Node::new(id, format!("{label}: {e}"))
}

/// Everything shown under the selected application.
fn content_nodes(c: &Contents, picc: bool) -> Vec<Node> {
    let mut out = Vec::new();
    match &c.keys {
        Section::Loaded(k) => {
            let (n, tmp) = app_key_count(k, picc);
            let mut g = Node::new(
                "grp:aes",
                if picc {
                    format!("AES keys   KeySettings {:02X}", k.settings)
                } else {
                    format!(
                        "AES keys: {} x {}   KeySettings {:02X}",
                        if tmp { "AppMasterTmpKey".to_string() } else { n.to_string() },
                        aes_type_name(k.key_type),
                        k.settings
                    )
                },
            );
            if picc {
                for no in PICC_KEYS {
                    g = g.child(Node::new(format!("aes:{no}"), format!("Key {no:02X}")).info(picc_key_name(no)));
                }
            } else {
                for no in 0..n {
                    let mut node = Node::new(format!("aes:{no}"), format!("Key {no:02X}"));
                    if no == 0 {
                        node = node.info("AppMasterKey");
                    }
                    g = g.child(node);
                }
            }
            out.push(g);
        }
        Section::Failed(e) => out.push(failed_node("note:keys", "AES keys", e)),
        Section::NotLoaded => {}
    }
    match &c.ecc {
        Section::Loaded(keys) => out.push(
            Node::new("grp:ecc", format!("ECC private keys: {}", keys.len())).children(keys.iter().map(|k| {
                Node::new(format!("ecc:{}", k.key_no), format!("Key {}", k.key_no))
                    .info(format!("{}   policy {:04X}", curve_label(k.curve), k.policy))
            })),
        ),
        Section::Failed(e) => out.push(failed_node("note:ecc", "ECC private keys", e)),
        Section::NotLoaded => {}
    }
    match &c.ca {
        Section::Loaded(keys) => out.push(
            Node::new("grp:ca", format!("CA root keys: {}", keys.len())).children(keys.iter().map(|k| {
                let crl = if k.crl_file & 0x80 != 0 {
                    format!("   CRL file {:02X}", k.crl_file & 0x1F)
                } else {
                    String::new()
                };
                Node::new(format!("ca:{}", k.key_no), format!("Key {}", k.key_no))
                    .info(format!("{}   ACMap {:04X}{crl}", curve_label(k.curve), k.access_rights))
            })),
        ),
        Section::Failed(e) => out.push(failed_node("note:ca", "CA root keys", e)),
        Section::NotLoaded => {}
    }
    match &c.files {
        Section::Loaded(files) => out.push(
            Node::new("grp:files", format!("Files: {}", files.len())).children(files.iter().map(|f| {
                let (label, info) = file_label(f);
                Node::new(format!("file:{}", f.file_no), label).info(info)
            })),
        ),
        Section::Failed(e) => out.push(failed_node("note:files", "Files", e)),
        Section::NotLoaded => {}
    }
    for (i, n) in c.notes.iter().enumerate() {
        out.push(Node::new(format!("note:{i}"), format!("({n})")));
    }
    out
}

/// The tree: PICC level and applications side by side; the selected application carries its
/// keys and files, a second selected application its probed files.
pub fn build_tree(
    scan: &Scan,
    uid: &[u8],
    selected: Option<Aid>,
    second: Option<Aid>,
    contents: &Contents,
    second_files: &[FileSettings],
) -> Vec<Node> {
    let mut roots = Vec::new();
    let mut picc = Node::new("picc", "PICC level").info(format!("UID {}", hex::compact(uid)));
    if selected == Some(Aid::PICC) {
        picc = picc.children(content_nodes(contents, true));
    }
    roots.push(picc);
    let mut apps = scan.apps.clone();
    for a in [selected, second].into_iter().flatten() {
        if a != Aid::PICC && !apps.contains(&a) {
            apps.push(a);
        }
    }
    for aid in apps {
        let mut node = Node::new(format!("app:{}", aid.0), format!("Application {aid}"));
        if let Some(d) = scan.df_of(aid) {
            node = node.info(format!("ISO {:04X}   DF {}", d.iso_fid, hex::compact(&d.name)));
        }
        if selected == Some(aid) {
            node = node.children(content_nodes(contents, false));
        }
        roots.push(node);
    }
    if let Some(a2) = second {
        let mut files = Node::new("grp:files2", format!("Files found: {}", second_files.len()));
        for f in second_files {
            let (label, info) = file_label(f);
            files = files.child(Node::new(format!("file:{}", f.file_no), format!("{label}  (2nd)")).info(info));
        }
        roots.push(
            Node::new(format!("app2:{}", a2.0), format!("Second application {a2}"))
                .info("keys and files are addressed with bit 7 set")
                .child(files),
        );
    }
    for (i, n) in scan.notes.iter().enumerate() {
        roots.push(Node::new(format!("scan-note:{i}"), format!("({n})")));
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn std_file(no: u8) -> FileSettings {
        // StandardData, CommMode.Full, Read=E Write=0 ReadWrite=0 Change=0 (0xE000), 32 bytes
        FileSettings::parse(no, &[0x00, 0x03, 0x00, 0xE0, 0x20, 0x00, 0x00]).unwrap()
    }

    #[test]
    fn selection_ids_roundtrip() {
        assert_eq!(Sel::from_id(Some("picc")), Sel::Picc);
        assert_eq!(Sel::from_id(Some(&node_id_for_aid(Aid(0x112233)))), Sel::App(Aid(0x112233)));
        assert_eq!(Sel::from_id(Some("file:129")), Sel::File(0x81));
        assert_eq!(Sel::from_id(Some("ca:3")), Sel::Ca(3));
        assert_eq!(Sel::from_id(Some("note:x")), Sel::None);
        assert_eq!(Sel::from_id(None), Sel::None);
        assert_eq!(Sel::App(Aid(5)).aid(), Some(Aid(5)));
        assert_eq!(Sel::Ecc(1).aid(), None);
    }

    #[test]
    fn policy_and_access_texts() {
        assert_eq!(policy_text(0), "none");
        assert!(policy_text(0x0080).contains("mutual"));
        assert!(policy_text(0x8100).contains("freeze"));
        assert_eq!(access_text(0x30), "0x30 (CommMode.Full, key 0)");
        assert_eq!(access_text(0x1E), "0x1E (CommMode.MAC, free)");
        assert_eq!(acmap_text(0x0021), "0,5");
    }

    #[test]
    fn tree_shows_contents_below_selected_application_only() {
        let scan = Scan { apps: vec![Aid(0x10), Aid(0x20)], ..Default::default() };
        let contents = Contents {
            files: Section::Loaded(vec![std_file(1), std_file(2)]),
            ecc: Section::Failed("denied".into()),
            ..Default::default()
        };
        let tree = build_tree(&scan, &[1, 2], Some(Aid(0x20)), None, &contents, &[]);
        assert_eq!(tree.len(), 3);
        assert!(tree[0].children.is_empty() && tree[1].children.is_empty());
        let ids: Vec<&str> = tree[2].children.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, ["note:ecc", "grp:files"]);
        assert_eq!(tree[2].children[1].children.len(), 2);
        assert_eq!(tree[2].children[1].children[0].id, "file:1");
    }

    #[test]
    fn second_application_gets_its_own_node() {
        let f = std_file(0x83);
        let tree = build_tree(&Scan::default(), &[], Some(Aid(1)), Some(Aid(2)), &Contents::default(), &[f]);
        let ids: Vec<&str> = tree.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, ["picc", "app:1", "app:2", "app2:2"]);
        let file = &tree[3].children[0].children[0];
        assert_eq!(file.id, "file:131");
        assert!(file.label.starts_with("File 03"));
        assert_eq!(Sel::from_id(Some(&file.id)), Sel::File(0x83));
    }

    #[test]
    fn app_key_counts() {
        let mk = |max| KeySettings { settings: 0x0F, max_keys: max, key_type: 2, key_sets: None, raw: vec![] };
        assert_eq!(app_key_count(&mk(3), false), (3, false));
        assert_eq!(app_key_count(&mk(0x0F), false), (1, true));
        assert_eq!(app_key_count(&mk(0x0F), true), (0x0F, false));
    }
}
