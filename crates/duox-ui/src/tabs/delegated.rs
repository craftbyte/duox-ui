//! Delegated applications (data sheet 7.11.2).
//!
//! The card issuer reserves memory (a DAM slot with a quota) for an application provider, either
//! with a ticket computed from the PICC DAM keys or with a certificate that carries delegated
//! application rights. This tab covers both sides:
//!
//! * issuer: generate / enter / save / install the three PICC DAM keys, issue tickets (EncK and
//!   DAMMAC for creation, DAMMAC for deletion) and DAM certificates;
//! * provider: load a ticket, create or delete the application, GetDelegatedInfo, format the
//!   application, estimate the memory the application needs against its quota.
//!
//! Every precondition is checked against the cached card state before anything is sent; a card
//! error ends the authentication (the library handles that), so no command is ever used to probe.

use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::ui::files::{self, Filter};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::{clipboard, hex, textview::TextView, theme, widgets};
use duox::card::{AccessRight, Aid, AuthKind, AuthSummary, ChangeKeySpec, DelegatedAppSpec, DelegatedKeys, Selection};
use duox::crypto;
use duox::dam::{self, AppHeader, Ticket};
use duox::pki::{AccessRights, CertKind, DamOperation, IssueRequest};
use iced::widget::{column, container, row, text, text_editor, Button, Space};
use iced::{Element, Length, Task};
use std::path::{Path, PathBuf};

// Form tokens.
const ASK_PARAMS: u32 = 1;
const ASK_KEYS: u32 = 2;
const ASK_INSTALL: u32 = 3;
const ASK_CERT: u32 = 4;
const ASK_SLOT: u32 = 5;
const ASK_BUDGET: u32 = 6;
const OK_SAVE_KEYS: u32 = 7;
const OK_DELETE_TICKET: u32 = 8;
const OK_DELETE: u32 = 9;
const OK_FORMAT: u32 = 10;

/// Saved-key names of the three issuer keys.
const KEY_NAMES: [&str; 3] = ["PICCDAMAuthKey", "PICCDAMMACKey", "PICCDAMENCKey"];
/// Key numbers of the issuer keys at PICC level.
const KEY_NUMBERS: [u8; 3] = [0x10, 0x11, 0x12];
/// Key number of the PICCDAMAuthKey.
const DAM_AUTH_KEY: u8 = 0x10;

const INTRO: &str = "Delegated application management: the card issuer reserves memory (a DAM slot with a quota) \
for an application provider, either with a ticket computed from the PICC DAM keys or with a certificate \
carrying delegated-application rights. The provider then creates and later owns the application without \
knowing any PICC key except the PICCDAMAuthKey.";

// ------------------------------------------------------------------ pure logic

/// Key material kept by the tab. Deliberately not `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
struct Secret(Vec<u8>);

/// Key set part of the application parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeySets {
    active_version: u8,
    count: u8,
    max_key_size: u8,
    roll_key: u8,
}

/// Parameters of CreateDelegatedApplication plus the provider's initial key.
#[derive(Clone)]
struct Params {
    aid: u32,
    slot: u16,
    slot_version: u8,
    quota: u16,
    n_keys: u8,
    key_sett1: u8,
    aes256: bool,
    iso_file_ids: bool,
    iso_fid: Option<u16>,
    df_name: Vec<u8>,
    key_sets: Option<KeySets>,
    init_key: Secret,
    init_key_ver: u8,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            aid: 0xD1D2D3,
            slot: 1,
            slot_version: 0,
            quota: 20,
            n_keys: 3,
            key_sett1: 0x0F,
            aes256: false,
            iso_file_ids: false,
            iso_fid: None,
            df_name: Vec::new(),
            key_sets: None,
            init_key: Secret(vec![0; 16]),
            init_key_ver: 0,
        }
    }
}

impl Params {
    /// The header (also the DAMPayload of a creation certificate), validated.
    fn header(&self) -> Result<AppHeader, String> {
        if self.aid == 0 || self.aid > 0xFF_FFFF {
            return Err("The AID must be between 000001 and FFFFFF (000000 is the PICC level).".into());
        }
        if !(1..=14).contains(&self.n_keys) {
            return Err("An application has 1 to 14 AES keys.".into());
        }
        if !self.df_name.is_empty() {
            if self.iso_fid.is_none() {
                return Err("A DF name needs an ISO file ID: tick \"Application has an ISO file ID\".".into());
            }
            if self.df_name.len() > 16 {
                return Err("A DF name is at most 16 bytes long.".into());
            }
        }
        let mut h = AppHeader::new(self.aid, self.slot, self.slot_version, self.quota);
        h.key_sett1 = self.key_sett1;
        h.n_keys = self.n_keys;
        h.aes256 = self.aes256;
        h.iso_file_ids = self.iso_file_ids;
        h.iso_fid = self.iso_fid;
        h.df_name = self.df_name.clone();
        if let Some(ks) = self.key_sets {
            if !(2..=16).contains(&ks.count) {
                return Err("An application has 2 to 16 key sets (or none).".into());
            }
            if ks.max_key_size != 16 && ks.max_key_size != 32 {
                return Err("The maximum key size of the key sets is 16 or 32 bytes.".into());
            }
            if self.aes256 && ks.max_key_size != 32 {
                return Err("AES-256 keys need a maximum key size of 32 bytes in the key sets.".into());
            }
            h.key_sett3 = Some(0x01);
            h.keyset_params = vec![ks.active_version, ks.count, ks.max_key_size, ks.roll_key];
        }
        Ok(h)
    }

    /// Header and its bytes as sent to the card.
    fn header_bytes(&self) -> Result<(AppHeader, Vec<u8>), String> {
        let h = self.header()?;
        let raw = h.encode().map_err(|e| e.to_string())?;
        Ok((h, raw))
    }

    /// `K_AppDAMDefault || KeyVer` in the form the card expects.
    fn init_blob(&self) -> Result<Vec<u8>, String> {
        let want = if self.aes256 { 32 } else { 16 };
        if self.init_key.0.len() != want {
            return Err(format!(
                "The initial application key must be {want} bytes ({} hex digits) for {}, but it has {}.",
                want * 2,
                key_type(self.aes256),
                self.init_key.0.len()
            ));
        }
        dam::default_key_blob(&self.init_key.0, self.init_key_ver, self.aes256).map_err(|e| e.to_string())
    }

    /// Parameters taken over from a ticket's header; the initial key is kept.
    fn from_header(h: &AppHeader, keep: &Params) -> Params {
        let key_sets = match h.keyset_params.as_slice() {
            [a, n, s, r] => Some(KeySets { active_version: *a, count: *n, max_key_size: *s, roll_key: *r }),
            _ => None,
        };
        Params {
            aid: h.aid,
            slot: h.slot_no,
            slot_version: h.slot_version,
            quota: h.quota,
            n_keys: h.n_keys,
            key_sett1: h.key_sett1,
            aes256: h.aes256,
            iso_file_ids: h.iso_file_ids,
            iso_fid: h.iso_fid,
            df_name: h.df_name.clone(),
            key_sets,
            init_key: keep.init_key.clone(),
            init_key_ver: keep.init_key_ver,
        }
    }

    /// Rows of the parameter table.
    fn rows(&self) -> Vec<(String, String)> {
        let mut r = vec![
            ("AID".to_string(), format!("{:06X}", self.aid)),
            (
                "DAM slot".to_string(),
                format!(
                    "{}   version {}   quota {} blocks ({} bytes)",
                    self.slot,
                    self.slot_version,
                    self.quota,
                    u32::from(self.quota) * 32
                ),
            ),
            (
                "Keys".to_string(),
                format!("{} x {}   KeySett1 {:02X}", self.n_keys, key_type(self.aes256), self.key_sett1),
            ),
        ];
        let mut opts = Vec::new();
        if self.iso_file_ids {
            opts.push("files carry ISO file IDs".to_string());
        }
        if let Some(f) = self.iso_fid {
            opts.push(format!("ISO file ID {f:04X}"));
        }
        if !self.df_name.is_empty() {
            opts.push(format!("DF name {}", hex::compact(&self.df_name)));
        }
        if let Some(k) = self.key_sets {
            opts.push(format!(
                "{} key sets (max. key size {}, active version {}, roll key {})",
                k.count, k.max_key_size, k.active_version, k.roll_key
            ));
        }
        r.push(("Options".to_string(), if opts.is_empty() { "none".to_string() } else { opts.join(", ") }));
        r.push(("Initial key".to_string(), format!("{} bytes, version {:02X}", self.init_key.0.len(), self.init_key_ver)));
        r
    }
}

/// The three issuer keys (PICCDAMAuthKey, PICCDAMMACKey, PICCDAMENCKey).
#[derive(Clone, PartialEq, Eq)]
struct DamKeys {
    auth: Secret,
    mac: Secret,
    enc: Secret,
}

impl DamKeys {
    fn all(&self) -> [&Secret; 3] {
        [&self.auth, &self.mac, &self.enc]
    }
    fn generate() -> DamKeys {
        DamKeys { auth: Secret(crypto::rnd(16)), mac: Secret(crypto::rnd(16)), enc: Secret(crypto::rnd(16)) }
    }
    fn validate(&self) -> Result<(), String> {
        for (k, name) in self.all().into_iter().zip(KEY_NAMES) {
            if k.0.len() != 16 && k.0.len() != 32 {
                return Err(format!("{name} must be 16 or 32 bytes long, it has {}.", k.0.len()));
            }
        }
        Ok(())
    }
}

/// Key number as sent by ChangeKey at PICC level: the key type travels in bits 7..6.
fn picc_key_no(no: u8, key_len: usize) -> u8 {
    no | if key_len == 32 { 0xC0 } else { 0x80 }
}

/// The old key to send for a new key of `new_len` bytes. An all-zero old key (the factory value)
/// is accepted in any length.
fn old_key_for(old: &[u8], new_len: usize) -> Result<Vec<u8>, String> {
    if old.len() == new_len {
        Ok(old.to_vec())
    } else if old.iter().all(|&b| b == 0) {
        Ok(vec![0; new_len])
    } else {
        Err(format!(
            "The current key has {} bytes but the new key has {new_len}: they must have the same length (only an all-zero key may differ).",
            old.len()
        ))
    }
}

/// Check a loaded ticket's structure; returns its header.
fn check_ticket(t: &Ticket) -> Result<AppHeader, String> {
    let h = AppHeader::parse(&t.header).map_err(|e| format!("The ticket is not usable: {e}."))?;
    let want = if h.aes256 { 48 } else { 32 };
    if t.enc_k.len() != want {
        return Err(format!("The ticket's EncK has {} bytes, {want} are expected for this key type.", t.enc_k.len()));
    }
    if t.dam_mac.len() != 8 {
        return Err("The ticket's DAMMAC must be 8 bytes.".into());
    }
    if !t.delete_mac.is_empty() && t.delete_mac.len() != 8 {
        return Err("The ticket's deletion DAMMAC must be 8 bytes.".into());
    }
    Ok(h)
}

fn key_type(aes256: bool) -> &'static str {
    if aes256 {
        "AES-256"
    } else {
        "AES-128"
    }
}

/// Human readable description of a header and its memory consequences.
fn header_report(h: &AppHeader, raw: &[u8]) -> Vec<String> {
    let over = h.overhead_blocks();
    let quota = u32::from(h.quota);
    let mut keys = format!("Keys: {} x {}", h.n_keys, key_type(h.aes256));
    if h.keyset_params.len() == 4 {
        keys.push_str(&format!(", {} key sets", h.keyset_params[1]));
    }
    vec![
        format!("Header / DAMPayload ({} bytes): {}", raw.len(), hex::spaced(raw)),
        format!(
            "AID {:06X}   slot {}   slot version {}   quota {} blocks ({} bytes)",
            h.aid,
            h.slot_no,
            h.slot_version,
            quota,
            quota * 32
        ),
        keys,
        if quota >= over {
            format!("Application overhead: {over} blocks, leaving {} for files", quota - over)
        } else {
            format!("Application overhead: {over} blocks, more than the quota of {quota}: no file would fit")
        },
        "Files: 1 block per two files, plus ceil(size / 32) for standard data (twice that for backup data), 1 for a \
         value file, 1 + ceil(records x size / 32) for record files."
            .into(),
    ]
}

/// Files an application is planned to hold, for the quota estimate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FilePlan {
    /// (files, size of each)
    standard: (u32, u32),
    backup: (u32, u32),
    values: u32,
    /// (files, records per file, record size)
    records: (u32, u32, u32),
}

impl FilePlan {
    fn files(&self) -> u64 {
        u64::from(self.standard.0) + u64::from(self.backup.0) + u64::from(self.values) + u64::from(self.records.0)
    }

    /// Blocks of 32 bytes the files need.
    fn blocks(&self) -> u64 {
        let blk = |bytes: u64| bytes.div_ceil(32);
        let std = u64::from(self.standard.0) * blk(u64::from(self.standard.1));
        let bak = 2 * u64::from(self.backup.0) * blk(u64::from(self.backup.1));
        let (rf, rn, rs) = (u64::from(self.records.0), u64::from(self.records.1), u64::from(self.records.2));
        let rec = rf * (1 + blk(rn * rs));
        self.files().div_ceil(2) + std + bak + u64::from(self.values) + rec
    }
}

/// Memory estimate of a plan against the header's quota.
fn budget_report(h: &AppHeader, plan: &FilePlan) -> Vec<String> {
    let over = u64::from(h.overhead_blocks());
    let quota = u64::from(h.quota);
    let files = plan.blocks();
    let total = over + files;
    let verdict = if total <= quota {
        format!("Fits: {} blocks ({} bytes) remain.", quota - total, (quota - total) * 32)
    } else {
        format!("Does not fit: {} blocks ({} bytes) too many.", total - quota, (total - quota) * 32)
    };
    vec![
        format!("Quota                 {quota} blocks ({} bytes)", quota * 32),
        format!("Application overhead  {over} blocks"),
        format!("Planned files         {files} blocks ({} files)", plan.files()),
        format!("Total                 {total} blocks"),
        verdict,
        "This is an estimate; the card's exact bookkeeping may differ slightly.".into(),
    ]
}

// ------------------------------------------------------------------ card snapshot

/// What the tab needs to know about the card to check preconditions.
struct CardView {
    sel: Selection,
    auth: Option<AuthSummary>,
    master: bool,
}

impl CardView {
    /// Snapshot of the connected card; reports "not connected" and returns `None` otherwise.
    fn take(shared: &mut Shared) -> Option<CardView> {
        let v = shared.card.as_ref().map(|c| CardView {
            sel: c.selection(),
            auth: c.auth_summary(),
            master: c.has_access_condition(AccessRight::key(0), false),
        });
        if v.is_none() {
            shared.report_error("Not connected. Pick a reader and press Connect.");
        }
        v
    }
    fn at_picc(&self) -> bool {
        self.sel.primary == Some(Aid::PICC)
    }
    /// PICC level selected and authenticated with the PICCDAMAuthKey.
    fn dam_auth(&self) -> bool {
        self.at_picc()
            && matches!(&self.auth, Some(a) if a.kind == AuthKind::Aes && a.key_no == Some(DAM_AUTH_KEY) && !a.secondary)
    }
    /// PICC level selected and ECC authenticated.
    fn ecc(&self) -> bool {
        self.at_picc() && matches!(&self.auth, Some(a) if a.kind == AuthKind::Ecc)
    }
}

const NEED_DAM_AUTH: &str =
    "Select the PICC level and authenticate with the PICCDAMAuthKey (key number 10) first (Authenticate tab).";

// ------------------------------------------------------------------ tab

pub struct State {
    params: Params,
    keys: Option<DamKeys>,
    ticket: Option<Ticket>,
    /// (id, label) of the CAs offered by the certificate form.
    ca_choices: Vec<(String, String)>,
    out: TextView,
}

impl Default for State {
    fn default() -> Self {
        State { params: Params::default(), keys: None, ticket: None, ca_choices: Vec::new(), out: TextView::new(INTRO) }
    }
}

// The state holds key material: print nothing from it.
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    /// Answer to `Shared::ask` / `confirm`. `values` is `None` when cancelled or answered "no".
    FormDone { token: u32, values: Option<FormValues> },
    /// Broadcast from the application (connect, disconnect, store changed, tab activated).
    Event(AppEvent),
    View(text_editor::Action),
    Copy,
    AskParams,
    Estimate,
    AskBudget,
    Generate,
    AskKeys,
    SaveKeys,
    AskInstall,
    IssueTicket,
    AskCert,
    LoadTicket,
    TicketPicked(Option<PathBuf>),
    TicketSaveTo(Option<PathBuf>),
    CreateTicket,
    DeleteTicket,
    CreateCert,
    Delete,
    AskSlot,
    Format,
}

impl State {
    fn show(&mut self, lines: impl IntoIterator<Item = String>) {
        let v: Vec<String> = lines.into_iter().collect();
        self.out.set_text(&v.join("\n"));
    }

    fn out_append(&mut self, line: &str) {
        let t = self.out.text();
        self.out.set_text(&format!("{}\n{line}", t.trim_end()));
    }

    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::View(a) => self.out.perform(a),
            Message::Copy => return clipboard::copy(self.out.text()),
            Message::Event(_) => {}
            Message::FormDone { token, values: Some(v) } => self.form_done(token, &v, shared),
            Message::FormDone { .. } => {}
            Message::AskParams => self.ask_params(shared),
            Message::Estimate => match self.params.header_bytes() {
                Ok((h, raw)) => self.show(header_report(&h, &raw)),
                Err(e) => {
                    shared.report_error(e);
                }
            },
            Message::AskBudget => self.ask_budget(shared),
            Message::Generate => {
                self.keys = Some(DamKeys::generate());
                self.show([
                    "Three new random keys were generated (shown on the left).".to_string(),
                    "Save keys stores them in the key store; Install on card writes them to the card (PICC master \
                     key authentication needed)."
                        .to_string(),
                ]);
            }
            Message::AskKeys => self.ask_keys(shared),
            Message::SaveKeys => self.save_keys(shared),
            Message::AskInstall => self.ask_install(shared),
            Message::IssueTicket => return self.issue_ticket(shared),
            Message::AskCert => self.ask_cert(shared),
            Message::LoadTicket => {
                return files::pick_open("Load ticket", &[Filter::new("DAM ticket", &["json"])], |p| {
                    app::Message::Delegated(Message::TicketPicked(p))
                })
            }
            Message::TicketPicked(Some(p)) => self.load_ticket(&p, shared),
            Message::TicketPicked(None) => {}
            Message::TicketSaveTo(Some(p)) => self.save_ticket(&p, shared),
            Message::TicketSaveTo(None) => self.out_append("Ticket kept in memory (not saved)."),
            Message::CreateTicket => self.create_ticket(shared),
            Message::DeleteTicket => self.ask_delete_ticket(shared),
            Message::CreateCert => self.create_cert(shared),
            Message::Delete => self.ask_delete(shared),
            Message::AskSlot => self.ask_slot(shared),
            Message::Format => self.ask_format(shared),
        }
        Task::none()
    }

    fn form_done(&mut self, token: u32, v: &FormValues, shared: &mut Shared) {
        match token {
            ASK_PARAMS => self.apply_params(v, shared),
            ASK_KEYS => self.apply_keys(v, shared),
            ASK_INSTALL => self.install_keys(v, shared),
            ASK_CERT => self.issue_cert(v, shared),
            ASK_SLOT => self.slot_info(v, shared),
            ASK_BUDGET => self.budget(v, shared),
            OK_SAVE_KEYS => self.store_keys(shared),
            OK_DELETE_TICKET => self.delete_ticket(shared),
            OK_DELETE => self.delete(shared),
            OK_FORMAT => self.format(shared),
            _ => {}
        }
    }

    // ---- parameters ------------------------------------------------------------------

    fn ask_params(&mut self, shared: &mut Shared) {
        let p = &self.params;
        let ks = p.key_sets.unwrap_or(KeySets { active_version: 0, count: 0, max_key_size: 16, roll_key: 0 });
        shared.ask(
            FormSpec::new("Delegated application parameters")
                .note(
                    "The parameters of CreateDelegatedApplication. They go into tickets, DAM certificates and the \
                     memory estimate.",
                )
                .ok_text("Apply")
                .hex_int_range("aid", "AID", u64::from(p.aid), 6, 1, 0xFF_FFFF)
                .int_range("slot", "DAM slot", i64::from(p.slot), 0, 65535)
                .int_range("slotver", "Slot version", i64::from(p.slot_version), 0, 255)
                .int_range("quota", "Quota", i64::from(p.quota), 0, 65535)
                .hint("32-byte blocks")
                .int_range("keys", "Number of AES keys", i64::from(p.n_keys), 1, 14)
                .hex_int_range("ks1", "KeySett1", u64::from(p.key_sett1), 2, 0, 255)
                .check("aes256", "AES-256 keys", p.aes256)
                .check("isoids", "Files carry ISO file IDs", p.iso_file_ids)
                .check("hasfid", "Application has an ISO file ID", p.iso_fid.is_some())
                .hex_int_range("fid", "ISO file ID", u64::from(p.iso_fid.unwrap_or(0)), 4, 0, 0xFFFF)
                .hex_len("df", "ISO DF name", &hex::compact(&p.df_name), 0, 16)
                .hint("needs an ISO file ID; empty = none")
                .int_range("sets", "Key sets", i64::from(ks.count), 0, 16)
                .hint("0 = no key sets, otherwise 2 to 16")
                .combo("maxkey", "Max. key size", &["16 bytes", "32 bytes"], usize::from(ks.max_key_size == 32))
                .int_range("roll", "Key number allowed to roll", i64::from(ks.roll_key), 0, 13)
                .int_range("aks", "Version of the active key set", i64::from(ks.active_version), 0, 255)
                .text("key", "Initial application key", &hex::compact(&p.init_key.0))
                .hint("hex, or the name of a saved key; the provider uses it for key 00 after creation")
                .hex_int_range("keyver", "Initial key version", u64::from(p.init_key_ver), 2, 0, 255),
            ASK_PARAMS,
        );
    }

    fn apply_params(&mut self, v: &FormValues, shared: &mut Shared) {
        let u = |k: &str| v.get_uint(k).unwrap_or_default();
        let b = |k: &str| v.get_bool(k).unwrap_or_default();
        let key_text = v.get_str("key").unwrap_or_default().to_string();
        let key = match shared.store.resolve_aes_key(&key_text) {
            Ok(k) => k,
            Err(e) => {
                shared.report_error(format!("The initial application key is neither hex nor the name of a saved key ({e})."));
                return;
            }
        };
        let sets = u("sets") as u8;
        let p = Params {
            aid: u("aid") as u32,
            slot: u("slot") as u16,
            slot_version: u("slotver") as u8,
            quota: u("quota") as u16,
            n_keys: u("keys") as u8,
            key_sett1: u("ks1") as u8,
            aes256: b("aes256"),
            iso_file_ids: b("isoids"),
            iso_fid: b("hasfid").then(|| u("fid") as u16),
            df_name: v.get_hex("df").unwrap_or_default(),
            key_sets: (sets > 0).then(|| KeySets {
                active_version: u("aks") as u8,
                count: sets,
                max_key_size: if v.get_index("maxkey").unwrap_or(0) == 1 { 32 } else { 16 },
                roll_key: u("roll") as u8,
            }),
            init_key: Secret(key),
            init_key_ver: u("keyver") as u8,
        };
        match p.header_bytes().and_then(|_| p.init_blob()) {
            Ok(_) => {
                self.params = p;
                self.show(["Parameters applied.".to_string()]);
            }
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    fn ask_budget(&mut self, shared: &mut Shared) {
        if let Err(e) = self.params.header_bytes() {
            shared.report_error(e);
            return;
        }
        shared.ask(
            FormSpec::new("Memory estimate: planned files")
                .note("Estimates the blocks the files of the application will need and compares them with the quota.")
                .ok_text("Estimate")
                .int_range("std_n", "Standard data files", 2, 0, 32)
                .int_range("std_size", "  size of each", 128, 0, 8192)
                .hint("bytes")
                .int_range("bak_n", "Backup data files", 0, 0, 32)
                .int_range("bak_size", "  size of each", 32, 0, 8192)
                .hint("bytes")
                .int_range("val_n", "Value files", 0, 0, 32)
                .int_range("rec_n", "Record files", 0, 0, 32)
                .int_range("rec_cnt", "  records per file", 10, 0, 65535)
                .int_range("rec_size", "  record size", 16, 0, 8192)
                .hint("bytes"),
            ASK_BUDGET,
        );
    }

    fn budget(&mut self, v: &FormValues, shared: &mut Shared) {
        let n = |k: &str| v.get_uint(k).unwrap_or_default() as u32;
        let plan = FilePlan {
            standard: (n("std_n"), n("std_size")),
            backup: (n("bak_n"), n("bak_size")),
            values: n("val_n"),
            records: (n("rec_n"), n("rec_cnt"), n("rec_size")),
        };
        if plan.files() > 32 {
            shared.report_error("An application has at most 32 files.");
            return;
        }
        match self.params.header_bytes() {
            Ok((h, raw)) => {
                let mut l = header_report(&h, &raw);
                l.truncate(4);
                l.push(String::new());
                l.extend(budget_report(&h, &plan));
                self.show(l);
            }
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    // ---- issuer: keys ----------------------------------------------------------------

    fn ask_keys(&mut self, shared: &mut Shared) {
        let cur = |f: fn(&DamKeys) -> &Secret| self.keys.as_ref().map(|k| hex::compact(&f(k).0)).unwrap_or_default();
        shared.ask(
            FormSpec::new("PICC DAM keys")
                .note("Each key: hex (32 digits for AES-128, 64 for AES-256) or the name of a saved key.")
                .ok_text("Apply")
                .text("auth", "PICCDAMAuthKey (10)", &cur(|k| &k.auth))
                .text("mac", "PICCDAMMACKey (11)", &cur(|k| &k.mac))
                .text("enc", "PICCDAMENCKey (12)", &cur(|k| &k.enc)),
            ASK_KEYS,
        );
    }

    fn apply_keys(&mut self, v: &FormValues, shared: &mut Shared) {
        let mut parts = Vec::new();
        for (key, name) in ["auth", "mac", "enc"].into_iter().zip(KEY_NAMES) {
            let t = v.get_str(key).unwrap_or_default();
            match shared.store.resolve_aes_key(t) {
                Ok(k) => parts.push(Secret(k)),
                Err(e) => {
                    shared.report_error(format!("{name} is neither hex nor the name of a saved key ({e})."));
                    return;
                }
            }
        }
        let mut it = parts.into_iter();
        let keys = DamKeys {
            auth: it.next().unwrap_or_default(),
            mac: it.next().unwrap_or_default(),
            enc: it.next().unwrap_or_default(),
        };
        match keys.validate() {
            Ok(()) => {
                self.keys = Some(keys);
                self.show(["DAM keys applied.".to_string()]);
            }
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    fn save_keys(&mut self, shared: &mut Shared) {
        let Some(keys) = &self.keys else {
            shared.report_error("There are no DAM keys yet: use Generate or Keys... first.");
            return;
        };
        // Overwriting a saved key with a different value could destroy the only copy of a deployed key.
        let differs = keys
            .all()
            .into_iter()
            .zip(KEY_NAMES)
            .any(|(k, name)| shared.store.aes_key(name).is_some_and(|old| old != k.0));
        if differs {
            shared.confirm_danger(
                "Replace saved keys",
                "A saved key named PICCDAMAuthKey, PICCDAMMACKey or PICCDAMENCKey with a different value exists. \
                 Replacing it cannot be undone. Replace it?",
                "Replace",
                OK_SAVE_KEYS,
            );
        } else {
            self.store_keys(shared);
        }
    }

    fn store_keys(&mut self, shared: &mut Shared) {
        let Some(keys) = self.keys.clone() else { return };
        let r = shared.with_store(|st| {
            for (k, name) in keys.all().into_iter().zip(KEY_NAMES) {
                st.set_aes_key(name, &k.0)?;
            }
            Ok(())
        });
        if r.is_ok() {
            shared.store_changed();
            self.show([
                "The three DAM keys are saved in the key store as PICCDAMAuthKey, PICCDAMMACKey and PICCDAMENCKey."
                    .to_string(),
                "Like the other saved AES keys they are stored unencrypted in the store file.".to_string(),
            ]);
        }
    }

    fn ask_install(&mut self, shared: &mut Shared) {
        let Some(keys) = &self.keys else {
            shared.report_error("There are no DAM keys yet: use Generate or Keys... first.");
            return;
        };
        if let Err(e) = keys.validate() {
            shared.report_error(e);
            return;
        }
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.at_picc() {
            shared.report_error("Select the PICC level first, then authenticate with the PICC master key.");
            return;
        }
        if !cv.master {
            shared.report_error("Authenticate at PICC level with the PICC master key (key 00) first (Authenticate tab).");
            return;
        }
        shared.ask(
            FormSpec::new("Install the PICC DAM keys")
                .note(
                    "Sends ChangeKey for keys 10, 11 and 12. On a fresh card these keys are disabled; changing them \
                     (from the all-zero value) enables delegated application management.",
                )
                .ok_text("Install")
                .hex_len("old", "Current value of the three keys", &"00".repeat(16), 16, 32)
                .hex_int_range("ver", "Key version", 0, 2, 0, 255),
            ASK_INSTALL,
        );
    }

    fn install_keys(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(keys) = self.keys.clone() else { return };
        let old = v.get_hex("old").unwrap_or_default();
        let ver = v.get_uint("ver").unwrap_or_default() as u8;
        let mut specs = Vec::new();
        for ((no, k), name) in KEY_NUMBERS.into_iter().zip(keys.all()).zip(KEY_NAMES) {
            match old_key_for(&old, k.0.len()) {
                Ok(o) => specs.push(ChangeKeySpec::new(picc_key_no(no, k.0.len()), &k.0, ver).old_key(&o)),
                Err(e) => {
                    shared.report_error(format!("{name}: {e}"));
                    return;
                }
            }
        }
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.at_picc() || !cv.master {
            shared.report_error("The PICC master key authentication is gone. Authenticate again, then repeat.");
            return;
        }
        let r = shared.with_card(|card| {
            for s in &specs {
                card.change_key(s).map_err(|e| e.to_string())?;
            }
            Ok::<(), String>(())
        });
        if r.is_ok() {
            self.show([
                "PICCDAMAuthKey, PICCDAMMACKey and PICCDAMENCKey installed.".to_string(),
                String::new(),
                "Give the PICCDAMAuthKey to the application provider; keep the MAC and ENC keys, they authorise \
                 every delegated application."
                    .to_string(),
            ]);
        }
    }

    // ---- issuer: tickets and certificates --------------------------------------------

    fn issue_ticket(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let Some(keys) = self.keys.clone() else {
            shared.report_error("There are no DAM keys yet: use Generate or Keys... first.");
            return Task::none();
        };
        let prepared = keys
            .validate()
            .and_then(|_| self.params.header_bytes())
            .and_then(|hb| self.params.init_blob().map(|_| hb));
        let (h, raw) = match prepared {
            Ok(x) => x,
            Err(e) => {
                shared.report_error(e);
                return Task::none();
            }
        };
        let issued =
            dam::issue_ticket(&keys.mac.0, &keys.enc.0, &raw, &self.params.init_key.0, self.params.init_key_ver, true);
        let t = match issued {
            Ok(t) => t,
            Err(e) => {
                shared.report_error(format!("The ticket could not be computed: {e}."));
                return Task::none();
            }
        };
        let mut l = header_report(&h, &raw);
        l.extend([
            String::new(),
            format!("EncK              {}", hex::spaced(&t.enc_k)),
            format!("DAMMAC            {}", hex::spaced(&t.dam_mac)),
            format!("DAMMAC (delete)   {}", hex::spaced(&t.delete_mac)),
            String::new(),
            "The ticket is not secret: it only works for this application, slot and quota. The provider additionally \
             needs the PICCDAMAuthKey and the initial application key."
                .to_string(),
        ]);
        self.ticket = Some(t);
        self.show(l);
        files::pick_save("Save ticket", &format!("dam-{:06X}.json", h.aid), &[Filter::new("DAM ticket", &["json"])], |p| {
            app::Message::Delegated(Message::TicketSaveTo(p))
        })
    }

    fn save_ticket(&mut self, path: &Path, shared: &mut Shared) {
        let Some(t) = &self.ticket else { return };
        let r = t.to_json().map_err(|e| e.to_string()).and_then(|j| files::write_file(path, j.as_bytes()));
        match r {
            Ok(()) => {
                shared.log_info(&format!("Ticket saved to {}", path.display()));
                self.out_append(&format!("Ticket saved to {}.", path.display()));
            }
            Err(e) => {
                shared.report_error(format!("The ticket could not be saved: {e}"));
            }
        }
    }

    fn ask_cert(&mut self, shared: &mut Shared) {
        let cas: Vec<(String, String)> = shared
            .store
            .by_kind(&[CertKind::Root, CertKind::Sub])
            .into_iter()
            .filter(|e| e.has_key())
            .map(|e| {
                let what = if e.kind == CertKind::Root { "root CA" } else { "delegated CA" };
                (e.id.clone(), format!("{}  ({what})", e.name))
            })
            .collect();
        if cas.is_empty() {
            shared.report_error("Create a CA on the 'CAs & certificates' tab first.");
            return;
        }
        let uid_ok = shared.card.as_ref().is_some_and(|c| matches!(c.uid().len(), 7 | 10));
        let labels: Vec<&str> = cas.iter().map(|(_, l)| l.as_str()).collect();
        let spec = FormSpec::new("Issue delegated application certificate")
            .note(
                "The certificate carries the application parameters (creation) or the AID (deletion). The card \
                 accepts it only if the CA root key at PICC level grants access condition 2.",
            )
            .ok_text("Issue")
            .combo("ca", "Issuing CA", &labels, 0)
            .combo("op", "Operation", &["Create this application", "Delete this application"], 0)
            .text("name", "Common name", &format!("DAM {:06X}", self.params.aid))
            .check("bind", "Bind to the UID of the connected card", uid_ok)
            .hex_len("pub", "Provider public key", "", 0, 65)
            .hint("65 bytes (04 || x || y); empty = generate a key pair here")
            .check("critical", "Mark the extension critical", true);
        self.ca_choices = cas;
        shared.ask(spec, ASK_CERT);
    }

    fn issue_cert(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some((ca_id, _)) = self.ca_choices.get(v.get_index("ca").unwrap_or(usize::MAX)).cloned() else { return };
        let delete = v.get_index("op").unwrap_or(0) == 1;
        let payload = if delete {
            Ok(self.params.aid.to_le_bytes()[..3].to_vec())
        } else {
            self.params.header_bytes().map(|(_, raw)| raw)
        };
        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let uid = if v.get_bool("bind").unwrap_or(false) {
            let u = shared.card.as_ref().map(|c| c.uid().to_vec()).unwrap_or_default();
            if !matches!(u.len(), 7 | 10) {
                shared.report_error("Connect to the card to bind the certificate to its UID (7 or 10 bytes).");
                return;
            }
            u
        } else {
            Vec::new()
        };
        let pubkey = v.get_hex("pub").unwrap_or_default();
        if !pubkey.is_empty() && pubkey.len() != 65 {
            shared.report_error(format!(
                "A public key is 65 bytes (130 hex digits, starting with 04); this one has {}.",
                pubkey.len()
            ));
            return;
        }
        let name = match v.get_str("name").unwrap_or_default().trim() {
            "" => format!("DAM {:06X}", self.params.aid),
            n => n.to_string(),
        };
        let op = if delete { DamOperation::Delete } else { DamOperation::Create };
        let rights = AccessRights::for_dam(&uid, op, &payload);
        let critical = v.get_bool("critical").unwrap_or(true);
        let entry = shared.with_store(|st| {
            let mut req = IssueRequest::new(CertKind::Reader, &name).access_rights(rights.clone()).critical(critical);
            if !pubkey.is_empty() {
                req = req.public_key(&pubkey);
            }
            st.issue(&ca_id, req)
        });
        let Ok(e) = entry else { return };
        shared.store_changed();
        let issuer = shared.store.root_of(&e.id).map(|r| r.name.clone()).unwrap_or_default();
        self.show([
            format!("Certificate #{} issued by {issuer}: {}", e.serial().unwrap_or(0), rights.describe()),
            format!("{} bytes", e.cert.len()),
            String::new(),
            "It appears as a reader identity on the Authenticate tab. Authenticate with it at PICC level (ECC), then \
             use 'Create in certificate session' (or 'Delete...') here."
                .to_string(),
        ]);
    }

    // ---- provider --------------------------------------------------------------------

    fn load_ticket(&mut self, path: &Path, shared: &mut Shared) {
        let loaded = files::read_file(path)
            .and_then(|b| String::from_utf8(b).map_err(|_| format!("{} is not a text file.", path.display())))
            .and_then(|s| Ticket::from_json(&s).map_err(|e| format!("{}: {e}.", path.display())))
            .and_then(|t| check_ticket(&t).map(|h| (t, h)));
        match loaded {
            Ok((t, h)) => {
                self.params = Params::from_header(&h, &self.params);
                let raw = t.header.clone();
                self.ticket = Some(t);
                let mut l = vec![format!("Ticket loaded from {}.", path.display()), String::new()];
                l.extend(header_report(&h, &raw));
                self.show(l);
            }
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    fn need_ticket(&self, shared: &mut Shared) -> Option<(Ticket, AppHeader)> {
        let Some(t) = self.ticket.clone() else {
            shared.report_error("Load the issuer's ticket first (or issue one with Issue ticket...).");
            return None;
        };
        match check_ticket(&t) {
            Ok(h) => Some((t, h)),
            Err(e) => {
                shared.report_error(e);
                None
            }
        }
    }

    /// End the authentication by selecting the PICC again and refresh the application list.
    fn back_to_picc(&self, shared: &mut Shared) {
        if shared.with_card(|c| c.select_application(Aid::PICC, None)).is_ok() {
            shared.refresh_scan();
        }
    }

    fn created(&mut self, aid: u32, shared: &mut Shared) {
        self.back_to_picc(shared);
        self.show([
            format!("Delegated application {aid:06X} created."),
            String::new(),
            "The PICC level is selected again. Select the application and authenticate with key 00 and the initial \
             application key, then change the keys."
                .to_string(),
        ]);
    }

    fn create_ticket(&mut self, shared: &mut Shared) {
        let Some((t, h)) = self.need_ticket(shared) else { return };
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.dam_auth() {
            shared.report_error(NEED_DAM_AUTH);
            return;
        }
        let spec = DelegatedAppSpec {
            header: t.header,
            keys: DelegatedKeys::Aes { enc_k: t.enc_k, dam_mac: t.dam_mac },
        };
        if shared.with_card(|c| c.create_delegated_application(&spec)).is_ok() {
            self.created(h.aid, shared);
        }
    }

    fn create_cert(&mut self, shared: &mut Shared) {
        let prepared = self.params.header_bytes().and_then(|hb| self.params.init_blob().map(|b| (hb, b)));
        let ((h, raw), blob) = match prepared {
            Ok(x) => x,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.ecc() {
            shared.report_error(
                "Authenticate at PICC level with the delegated application certificate first (Authenticate tab, ECC).",
            );
            return;
        }
        let spec = DelegatedAppSpec { header: raw, keys: DelegatedKeys::Ecc { init_k: blob } };
        if shared.with_card(|c| c.create_delegated_application(&spec)).is_ok() {
            self.created(h.aid, shared);
        }
    }

    fn ask_delete_ticket(&mut self, shared: &mut Shared) {
        let Some((t, h)) = self.need_ticket(shared) else { return };
        if t.delete_mac.len() != 8 {
            shared.report_error("This ticket carries no DAMMAC for deletion.");
            return;
        }
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.dam_auth() {
            shared.report_error(NEED_DAM_AUTH);
            return;
        }
        shared.confirm_danger(
            "Delete delegated application",
            &format!("Delete delegated application {:06X} with all its files and keys? Its DAM slot stays reserved.", h.aid),
            "Delete",
            OK_DELETE_TICKET,
        );
    }

    fn delete_ticket(&mut self, shared: &mut Shared) {
        let Some((t, h)) = self.need_ticket(shared) else { return };
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.dam_auth() || t.delete_mac.len() != 8 {
            shared.report_error("The PICCDAMAuthKey authentication is gone. Authenticate again, then repeat.");
            return;
        }
        if shared.with_card(|c| c.delete_application(Aid(h.aid), &t.delete_mac)).is_ok() {
            self.back_to_picc(shared);
            self.show([format!("Application {:06X} deleted; its DAM slot stays reserved for the next version.", h.aid)]);
        }
    }

    fn ask_delete(&mut self, shared: &mut Shared) {
        let aid = self.params.aid;
        if aid == 0 || aid > 0xFF_FFFF {
            shared.report_error("Set the AID of the application to delete in the parameters.");
            return;
        }
        let Some(cv) = CardView::take(shared) else { return };
        if cv.auth.is_none() {
            shared.report_error(
                "Authenticate first: at PICC level with a deletion certificate or the PICC master key, or in the \
                 application with its master key.",
            );
            return;
        }
        shared.confirm_danger(
            "Delete application",
            &format!("Delete application {aid:06X} with all its files and keys?"),
            "Delete",
            OK_DELETE,
        );
    }

    fn delete(&mut self, shared: &mut Shared) {
        let aid = self.params.aid;
        let Some(cv) = CardView::take(shared) else { return };
        if cv.auth.is_none() {
            shared.report_error("The authentication is gone. Authenticate again, then repeat.");
            return;
        }
        if shared.with_card(|c| c.delete_application(Aid(aid), &[])).is_ok() {
            self.back_to_picc(shared);
            self.show([format!("Application {aid:06X} deleted.")]);
        }
    }

    fn ask_slot(&mut self, shared: &mut Shared) {
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.at_picc() {
            shared.report_error("GetDelegatedInfo is a PICC level command: select the PICC level first.");
            return;
        }
        shared.ask(
            FormSpec::new("DAM slot info")
                .note("Reads version, quota, free blocks and the application of one DAM slot.")
                .ok_text("Read")
                .int_range("slot", "DAM slot", i64::from(self.params.slot), 0, 65535),
            ASK_SLOT,
        );
    }

    fn slot_info(&mut self, v: &FormValues, shared: &mut Shared) {
        let slot = v.get_uint("slot").unwrap_or_default() as u16;
        let Some(cv) = CardView::take(shared) else { return };
        if !cv.at_picc() {
            shared.report_error("GetDelegatedInfo is a PICC level command: select the PICC level first.");
            return;
        }
        if let Ok(i) = shared.with_card(|c| c.get_delegated_info(slot)) {
            let q = u32::from(i.quota);
            let f = u32::from(i.free_blocks);
            self.show([
                format!("DAM slot {slot}"),
                format!("Slot version   {}", i.slot_version),
                format!("Quota          {q} blocks ({} bytes)", q * 32),
                format!("Free           {f} blocks ({} bytes)", f * 32),
                format!(
                    "Application    {}",
                    if i.aid.0 != 0 { i.aid.to_string() } else { "none (slot is empty)".to_string() }
                ),
            ]);
        }
    }

    fn ask_format(&mut self, shared: &mut Shared) {
        let Some(cv) = CardView::take(shared) else { return };
        let aid = cv.sel.primary.unwrap_or(Aid::PICC);
        if aid == Aid::PICC {
            shared.report_error(
                "Select the delegated application and authenticate with its master key first (at PICC level use \
                 'Format card' on the Configuration & tools tab).",
            );
            return;
        }
        if cv.auth.is_none() {
            shared.report_error("Authenticate with the application's master key first.");
            return;
        }
        shared.confirm_danger(
            "Format application",
            &format!("Format application {aid}? All its files are deleted; keys and quota stay."),
            "Format",
            OK_FORMAT,
        );
    }

    fn format(&mut self, shared: &mut Shared) {
        let Some(cv) = CardView::take(shared) else { return };
        if cv.at_picc() || cv.auth.is_none() {
            shared.report_error("The authentication is gone. Authenticate again, then repeat.");
            return;
        }
        if shared.with_card(|c| c.format()).is_ok() {
            self.show(["Application formatted: all files removed, the quota is free again.".to_string()]);
        }
    }

    // ---- view ------------------------------------------------------------------------

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let connected = shared.is_connected();
        let has_ticket = self.ticket.is_some();
        let has_keys = self.keys.is_some();
        let sp = theme::SPACE_SM;

        let params = widgets::group(
            "Delegated application (parameters of CreateDelegatedApplication)",
            column![
                widgets::kv_table(&self.params.rows(), true),
                row![
                    widgets::primary("Edit parameters...", Message::AskParams),
                    widgets::secondary("Header / memory estimate", Message::Estimate),
                    widgets::secondary("File budget...", Message::AskBudget),
                ]
                .spacing(sp),
            ]
            .spacing(theme::SPACE_MD),
        );

        let key_rows: Vec<(String, String)> = match &self.keys {
            Some(k) => KEY_NAMES
                .iter()
                .zip(KEY_NUMBERS)
                .zip(k.all())
                .map(|((n, no), s)| (format!("{n} ({no:02X})"), hex::compact(&s.0)))
                .collect(),
            None => vec![("DAM keys".to_string(), "not set: Generate or enter them".to_string())],
        };
        let issuer = widgets::group(
            "Card issuer",
            column![
                widgets::kv_table(&key_rows, true),
                row![
                    widgets::secondary("Generate", Message::Generate),
                    widgets::secondary("Keys...", Message::AskKeys),
                    action("Save keys", Message::SaveKeys, has_keys),
                    action("Install on card...", Message::AskInstall, connected && has_keys),
                ]
                .spacing(sp)
                .wrap(),
                row![
                    action("Issue ticket (EncK + DAMMAC)...", Message::IssueTicket, has_keys),
                    widgets::secondary("Issue DAM certificate...", Message::AskCert),
                ]
                .spacing(sp)
                .wrap(),
            ]
            .spacing(theme::SPACE_MD),
        );

        let ticket_line = match &self.ticket {
            Some(t) => match AppHeader::parse(&t.header) {
                Ok(h) => format!(
                    "Ticket: AID {:06X}, slot {} v{}, quota {} blocks, {} x {}",
                    h.aid,
                    h.slot_no,
                    h.slot_version,
                    h.quota,
                    h.n_keys,
                    key_type(h.aes256)
                ),
                Err(_) => "Ticket loaded".to_string(),
            },
            None => "No ticket loaded".to_string(),
        };
        let provider = widgets::group(
            "Application provider",
            column![
                text(ticket_line),
                row![
                    widgets::secondary("Load ticket...", Message::LoadTicket),
                    action("Create from ticket", Message::CreateTicket, connected && has_ticket),
                    danger_action("Delete with ticket", Message::DeleteTicket, connected && has_ticket),
                ]
                .spacing(sp)
                .wrap(),
                row![
                    action("Create in certificate session", Message::CreateCert, connected),
                    danger_action("Delete (certificate / master session)", Message::Delete, connected),
                ]
                .spacing(sp)
                .wrap(),
                row![
                    action("Slot info...", Message::AskSlot, connected),
                    danger_action("Format this application", Message::Format, connected),
                ]
                .spacing(sp)
                .wrap(),
                widgets::hint(
                    "Ticket: select the PICC level and authenticate with the PICCDAMAuthKey (key 10). Certificate: \
                     authenticate at PICC level (ECC) with the delegated application certificate; the initial key is \
                     then sent encrypted by the session. The parameters above describe the application in both cases.",
                ),
            ]
            .spacing(theme::SPACE_MD),
        );

        column![
            params,
            row![container(issuer).width(Length::FillPortion(1)), container(provider).width(Length::FillPortion(1))]
                .spacing(theme::SPACE_MD),
            row![text("Result").size(theme::TEXT_HEADING), Space::new().width(Length::Fill), widgets::secondary("Copy", Message::Copy)]
                .align_y(iced::Alignment::Center),
            self.out.view().map(Message::View),
        ]
        .spacing(theme::SPACE_MD)
        .padding(theme::SPACE_MD)
        .into()
    }
}

fn action<'a>(label: &str, msg: Message, enabled: bool) -> Button<'a, Message> {
    widgets::secondary(label, msg.clone()).on_press_maybe(enabled.then_some(msg))
}

fn danger_action<'a>(label: &str, msg: Message, enabled: bool) -> Button<'a, Message> {
    widgets::danger(label, msg.clone()).on_press_maybe(enabled.then_some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_make_a_valid_header() {
        let (h, raw) = Params::default().header_bytes().unwrap();
        assert_eq!(h.aid, 0xD1D2D3);
        assert_eq!(&raw[..3], &[0xD3, 0xD2, 0xD1]);
        assert_eq!(AppHeader::parse(&raw).unwrap(), h);
    }

    #[test]
    fn parameter_validation_reports_sentences() {
        let ok = Params::default();
        let bad = |f: &dyn Fn(&mut Params)| {
            let mut p = ok.clone();
            f(&mut p);
            p.header().unwrap_err()
        };
        assert!(bad(&|p| p.aid = 0).contains("AID"));
        assert!(bad(&|p| p.n_keys = 0).contains("1 to 14"));
        assert!(bad(&|p| p.df_name = vec![1]).contains("ISO file ID"));
        assert!(bad(&|p| {
            p.iso_fid = Some(1);
            p.df_name = vec![0; 17];
        })
        .contains("16 bytes"));
        let sets = |count, size| KeySets { active_version: 0, count, max_key_size: size, roll_key: 0 };
        assert!(bad(&|p| p.key_sets = Some(sets(1, 16))).contains("2 to 16"));
        assert!(bad(&|p| p.key_sets = Some(sets(2, 24))).contains("16 or 32"));
        assert!(bad(&|p| {
            p.aes256 = true;
            p.key_sets = Some(sets(2, 16));
        })
        .contains("AES-256"));
    }

    #[test]
    fn key_sets_survive_header_round_trip() {
        let mut p = Params::default();
        p.key_sets = Some(KeySets { active_version: 3, count: 4, max_key_size: 32, roll_key: 1 });
        p.iso_fid = Some(0xE110);
        p.df_name = b"DUOX".to_vec();
        let (h, raw) = p.header_bytes().unwrap();
        let back = Params::from_header(&AppHeader::parse(&raw).unwrap(), &Params::default());
        assert_eq!(back.key_sets, p.key_sets);
        assert_eq!((back.iso_fid, back.df_name.as_slice()), (Some(0xE110), &b"DUOX"[..]));
        assert_eq!(back.header().unwrap(), h);
    }

    #[test]
    fn initial_key_must_match_key_type() {
        let mut p = Params::default();
        assert_eq!(p.init_blob().unwrap().len(), 25);
        p.aes256 = true;
        assert!(p.init_blob().unwrap_err().contains("32 bytes"));
        p.init_key = Secret(vec![1; 32]);
        p.init_key_ver = 7;
        let b = p.init_blob().unwrap();
        assert_eq!((b.len(), b[32]), (33, 7));
    }

    #[test]
    fn picc_key_numbers_carry_the_key_type() {
        assert_eq!(picc_key_no(0x10, 16), 0x90);
        assert_eq!(picc_key_no(0x12, 32), 0xD2);
    }

    #[test]
    fn old_key_rules() {
        assert_eq!(old_key_for(&[1; 16], 16).unwrap(), vec![1; 16]);
        assert_eq!(old_key_for(&[0; 16], 32).unwrap(), vec![0; 32]);
        assert!(old_key_for(&[1; 16], 32).unwrap_err().contains("same length"));
    }

    #[test]
    fn issuer_keys_are_checked() {
        let mut k = DamKeys::generate();
        assert!(k.validate().is_ok());
        k.mac = Secret(vec![0; 20]);
        assert!(k.validate().unwrap_err().contains("PICCDAMMACKey"));
    }

    #[test]
    fn ticket_structure_checks() {
        let (_, raw) = Params::default().header_bytes().unwrap();
        let t = dam::issue_ticket(&[1; 16], &[2; 16], &raw, &[0; 16], 0, true).unwrap();
        assert!(check_ticket(&t).is_ok());
        let mut bad = t.clone();
        bad.enc_k.truncate(16);
        assert!(check_ticket(&bad).unwrap_err().contains("EncK"));
        let mut bad = t.clone();
        bad.dam_mac.pop();
        assert!(check_ticket(&bad).unwrap_err().contains("DAMMAC"));
        let mut bad = t;
        bad.delete_mac = vec![0; 3];
        assert!(check_ticket(&bad).is_err());
        let short = Ticket { header: vec![1, 2], enc_k: vec![], dam_mac: vec![], delete_mac: vec![] };
        assert!(check_ticket(&short).is_err());
    }

    #[test]
    fn file_plan_blocks() {
        // two standard files of 100 bytes: 1 block for the pair + 2 * 4 blocks of data
        let p = FilePlan { standard: (2, 100), ..Default::default() };
        assert_eq!(p.blocks(), 1 + 8);
        let p = FilePlan { backup: (1, 33), ..Default::default() };
        assert_eq!(p.blocks(), 1 + 4);
        let p = FilePlan { values: 3, ..Default::default() };
        assert_eq!(p.blocks(), 2 + 3);
        let p = FilePlan { records: (1, 10, 16), ..Default::default() };
        assert_eq!(p.blocks(), 1 + 1 + 5);
        assert_eq!(FilePlan::default().blocks(), 0);
    }

    #[test]
    fn budget_verdicts() {
        let h = Params::default().header().unwrap();
        let fits = FilePlan { values: 1, ..Default::default() };
        assert!(budget_report(&h, &fits).iter().any(|l| l.starts_with("Fits")));
        let big = FilePlan { standard: (1, 32 * 100), ..Default::default() };
        assert!(budget_report(&h, &big).iter().any(|l| l.starts_with("Does not fit")));
    }

    #[test]
    fn header_report_mentions_overhead() {
        let (h, raw) = Params::default().header_bytes().unwrap();
        let l = header_report(&h, &raw);
        assert!(l[1].contains("D1D2D3"));
        assert!(l[3].starts_with("Application overhead"));
        let mut tiny = h.clone();
        tiny.quota = 1;
        assert!(header_report(&tiny, &raw)[3].contains("no file would fit"));
    }
}
