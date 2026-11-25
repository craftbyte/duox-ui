//! Transactions (data sheet 7.14): the TransactionMAC file, CommitReaderID, Commit / Abort and the
//! back-end side check of the returned Transaction MAC Value (TMV) or Transaction Signature (TSV).
//!
//! The library records the Transaction MAC Input (TMI) from the commands it sends after an
//! application was selected, so a TMV / TSV verifies here only when the whole transaction was run
//! through this program, with the card's real UID.
//!
//! Preconditions are checked against cached state before anything is sent. The file settings are
//! read only when the user asks for them (File settings, Settings..., Read TMC / TMV); Commit
//! with TMV / TSV uses the cached copy because a failing command would end the authentication.

use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::{clipboard, hex, textview::TextView, theme, widgets};
use duox::card::{
    AccessRight, AccessRights, Aid, AuthSummary, CommMode, FileSettings, FileSettingsChange, FileType, ModeSel,
    Selection, TmacFileSpec, TmacSettings,
};
use duox::crypto::{self, PubKey};
use duox::txmac;
use iced::widget::{checkbox, column, container, row, text, text_editor, Button, Space};
use iced::{Element, Length, Task};

// Form tokens.
const ASK_FILE: u32 = 1;
const ASK_CREATE: u32 = 2;
const ASK_SETTINGS: u32 = 3;
const ASK_RID: u32 = 4;
const ASK_VERIFY: u32 = 5;

const MODES: [&str; 3] = ["Plain", "MAC", "Full"];
const KINDS: [&str; 3] = ["Transaction MAC, AES-128 key", "Transaction MAC, AES-256 key", "Transaction Signature (ECC key)"];

const INTRO: &str = "Changes to backup data, value and record files take effect with Commit.\n\nWith a TransactionMAC \
file in the application the card computes a Transaction MAC (TMV) or Transaction Signature (TSV) over everything \
read and written in the transaction. This program records the same input (TMI) while you work on the Card tab, so \
the value the card returns can be checked here with the key (or public key) the back end holds.";

// ------------------------------------------------------------------ pure logic

/// Parse "1, 2, 0A" (hex file numbers 00..1F) into the exclusion bitmap.
fn parse_file_list(s: &str) -> Result<u32, String> {
    let mut map = 0u32;
    for part in s.split([',', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        let n = u8::from_str_radix(part, 16).map_err(|_| format!("'{part}' is not a hex file number."))?;
        if n > 0x1F {
            return Err(format!("File number {n:02X} is out of range: file numbers are 00 to 1F."));
        }
        map |= 1 << n;
    }
    Ok(map)
}

/// Inverse of [`parse_file_list`].
fn format_file_list(map: u32) -> String {
    (0..32).filter(|i| map >> i & 1 == 1).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(", ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Aes128,
    Aes256,
    Signature,
}

impl Kind {
    fn from_index(i: usize) -> Kind {
        match i {
            1 => Kind::Aes256,
            2 => Kind::Signature,
            _ => Kind::Aes128,
        }
    }
}

/// The AppTransactionMACKey to send: the given one, a random one, or none (a signature file
/// whose CommitReaderID is disabled needs no AES key).
fn plan_key(kind: Kind, reader_id_access: u8, given: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
    let len = if kind == Kind::Aes256 { 32 } else { 16 };
    match given {
        Some(k) if kind == Kind::Signature => {
            if k.len() == 16 || k.len() == 32 {
                Ok(k)
            } else {
                Err(format!("The AES key must be 16 or 32 bytes long, it has {}.", k.len()))
            }
        }
        Some(k) if k.len() == len => Ok(k),
        Some(k) => Err(format!(
            "The key must be {len} bytes ({} hex digits) for this type, it has {}.",
            len * 2,
            k.len()
        )),
        None if kind != Kind::Signature || reader_id_access <= 0xD => Ok(crypto::rnd(len)),
        None => Ok(Vec::new()),
    }
}

/// Name for a new saved key that does not replace an existing one.
fn unique_key_name(base: &str, exists: impl Fn(&str) -> bool) -> String {
    if !exists(base) {
        return base.to_string();
    }
    (2..1000).map(|n| format!("{base} ({n})")).find(|n| !exists(n)).unwrap_or_else(|| format!("{base} (new)"))
}

fn tmac_access(read: u8, reader_id: u8, change: u8) -> AccessRights {
    AccessRights::new(AccessRight::key(read), AccessRight::NEVER, AccessRight::key(reader_id), AccessRight::key(change))
}

/// Settings of a file as GetFileSettings would report them after creation.
fn settings_after_create(spec: &TmacFileSpec) -> FileSettings {
    let key_type = match spec.tm_key.len() {
        16 => 2,
        32 => 3,
        _ => 0,
    };
    let sig = spec.tsig_key_no.is_some();
    FileSettings {
        file_no: spec.file_no,
        file_type: FileType::TransactionMac,
        option: spec.comm_mode.bits() | if spec.excl_map.is_some() { 0x40 } else { 0 },
        access: spec.access,
        additional: Vec::new(),
        size: None,
        sdm: None,
        crl: None,
        value: None,
        record: None,
        tmac: Some(TmacSettings {
            key_option: key_type | if sig { 0x80 } else { 0 },
            key_version: (key_type != 0).then_some(spec.tm_key_version),
            tsig_key: spec.tsig_key_no,
            excl_map: spec.excl_map,
            tmc_limit: None,
        }),
        raw: Vec::new(),
    }
}

/// New communication mode, access rights, exclusion map and TMC limit as a ChangeFileSettings request.
fn settings_change(fs: &FileSettings, mode: CommMode, access: AccessRights, excl: u32, limit: Option<u32>) -> FileSettingsChange {
    let option = mode.bits() | if excl != 0 { 0x40 } else { 0 } | if limit.is_some() { 0x20 } else { 0 };
    let mut c = FileSettingsChange::new(option, access);
    c.tmac_excl_map = (excl != 0).then_some(excl);
    c.tmc_limit = limit;
    c.current_change_access = fs.access.change;
    c
}

/// The cached settings after a successful change.
fn settings_after_change(fs: &FileSettings, c: &FileSettingsChange) -> FileSettings {
    let mut n = fs.clone();
    n.option = c.option;
    n.access = c.access;
    n.raw = Vec::new();
    if let Some(t) = n.tmac.as_mut() {
        t.excl_map = c.tmac_excl_map;
        t.tmc_limit = c.tmc_limit;
    }
    n
}

/// Description of the key option of a TransactionMAC file.
fn tm_type(t: &TmacSettings) -> String {
    if t.is_signature() {
        let mut s = format!("Transaction Signature, ECC key {}", t.tsig_key.unwrap_or(0));
        if t.key_option & 3 != 0 {
            s.push_str(" (and an AES key for CommitReaderID)");
        }
        s
    } else {
        match t.key_option & 3 {
            2 => format!("Transaction MAC, AES-128 key, version {}", t.key_version.unwrap_or(0)),
            3 => format!("Transaction MAC, AES-256 key, version {}", t.key_version.unwrap_or(0)),
            _ => "no AES key".to_string(),
        }
    }
}

/// Key / value rows describing a TransactionMAC file.
fn tmac_rows(fs: &FileSettings) -> Vec<(String, String)> {
    let mut r = vec![
        (
            "File".to_string(),
            format!("{:02X}{}", fs.file_no & 0x1F, if fs.is_secondary_app() { " (secondary application)" } else { "" }),
        ),
        ("Comm. mode".to_string(), fs.comm_mode().to_string()),
        (
            "Access".to_string(),
            format!("Read {}, CommitReaderID {}, Change {}", fs.access.read, fs.access.read_write, fs.access.change),
        ),
    ];
    if let Some(t) = &fs.tmac {
        r.push(("Type".to_string(), tm_type(t)));
        let excl = t.excl_map.unwrap_or(0);
        r.push(("Left out of TMI".to_string(), if excl == 0 { "none".to_string() } else { format_file_list(excl) }));
        r.push((
            "TMC limit".to_string(),
            match t.tmc_limit {
                None | Some(0xFFFF_FFFF) => "none".to_string(),
                Some(l) => l.to_string(),
            },
        ));
    }
    r
}

/// Value the card returned with a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TmValue {
    Mac(Vec<u8>),
    Signature(Vec<u8>),
}

impl TmValue {
    fn label(&self) -> &'static str {
        match self {
            TmValue::Mac(_) => "TMV",
            TmValue::Signature(_) => "TSV",
        }
    }
    fn bytes(&self) -> &[u8] {
        match self {
            TmValue::Mac(b) | TmValue::Signature(b) => b,
        }
    }
}

/// TMC followed by TMV (8 bytes) or TSV (64 bytes), as returned by ReadData of the file.
fn parse_tm_read(d: &[u8]) -> Result<(u32, TmValue), String> {
    if d.len() < 12 {
        return Err(format!("The file returned only {} bytes: TMC and TMV / TSV were expected.", d.len()));
    }
    let tmc = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let v = d[4..].to_vec();
    Ok((tmc, if v.len() > 8 { TmValue::Signature(v) } else { TmValue::Mac(v) }))
}

/// The last commit that returned a TMC with its value.
#[derive(Debug, Clone)]
struct Commit {
    tmc: u32,
    value: TmValue,
    tmi: Vec<u8>,
}

/// Public key from 65 bytes on P-256 or brainpoolP256r1.
fn pubkey_any(raw: &[u8]) -> Result<PubKey, String> {
    [crypto::CURVE_P256, crypto::CURVE_BP256]
        .into_iter()
        .find_map(|c| PubKey::from_bytes(c, raw).ok())
        .ok_or_else(|| "The public key is not a valid 65-byte point (04 || x || y) on P-256 or brainpoolP256r1.".to_string())
}

/// Check the card's TMV / TSV against the recorded input and, when possible, decrypt the previous
/// ReaderID. `Err` carries a sentence saying what is missing or wrong.
fn verify_lines(c: &Commit, uid: &[u8], key: Option<&[u8]>, pubkey: &[u8], enc_tmri: &[u8]) -> Result<Vec<String>, String> {
    if !matches!(uid.len(), 4 | 7 | 10) {
        return Err("The card's UID is unknown: use 'Get card UID' (needs authentication) first.".into());
    }
    let mut l = Vec::new();
    match &c.value {
        TmValue::Mac(v) => {
            let key = key.ok_or("Enter the AppTransactionMACKey (Verification inputs...) to verify the TMV.")?;
            let good = txmac::tmv(key, c.tmc, uid, &c.tmi).map_err(|e| e.to_string())?;
            let ok = good == *v;
            l.push(format!("TMV expected {}  ->  {}", hex::spaced(&good), if ok { "VALID" } else { "MISMATCH" }));
            if !ok {
                l.push(
                    "Either the key is wrong, the UID differs (with random ID use GetCardUID), or commands of this \
                     transaction were not recorded here."
                        .to_string(),
                );
            }
        }
        TmValue::Signature(sig) => {
            if pubkey.is_empty() {
                return Err("Enter the public key of the transaction signature key (Verification inputs...) to verify the TSV.".into());
            }
            let pk = pubkey_any(pubkey)?;
            let ok = txmac::verify_tsv(&pk, sig, &c.tmi, c.tmc);
            l.push(format!("TSV signature over TMI || TMC: {}", if ok { "VALID" } else { "INVALID" }));
            if !ok {
                l.push(
                    "Either the public key is wrong or commands of this transaction were not recorded here."
                        .to_string(),
                );
            }
        }
    }
    if let (false, Some(key)) = (enc_tmri.is_empty(), key) {
        if let Ok(prev) = txmac::decrypt_reader_id(key, c.tmc, uid, enc_tmri) {
            l.push(previous_reader_id_line(&prev));
        }
    }
    Ok(l)
}

fn previous_reader_id_line(prev: &[u8]) -> String {
    format!("Previous ReaderID: {}{}", hex::spaced(prev), if prev.iter().all(|&b| b == 0) { "  (none yet)" } else { "" })
}

// ------------------------------------------------------------------ card snapshot

struct CardView {
    sel: Selection,
    auth: Option<AuthSummary>,
    uid: Vec<u8>,
}

impl CardView {
    fn take(shared: &mut Shared) -> Option<CardView> {
        let v = shared.card.as_ref().map(|c| CardView { sel: c.selection(), auth: c.auth_summary(), uid: c.uid().to_vec() });
        if v.is_none() {
            shared.report_error("Not connected. Pick a reader and press Connect.");
        }
        v
    }
}

#[derive(Debug, Clone)]
struct Cached {
    sel: Selection,
    fs: FileSettings,
}

/// Key material kept by the tab. Deliberately not `Debug`.
#[derive(Clone)]
struct Secret(Vec<u8>);

// ------------------------------------------------------------------ tab

pub struct State {
    file_no: u8,
    secondary: bool,
    cache: Option<Cached>,
    enc_tmri: Vec<u8>,
    last: Option<Commit>,
    key: Option<Secret>,
    key_text: String,
    pubkey: Vec<u8>,
    out: TextView,
}

impl Default for State {
    fn default() -> Self {
        State {
            file_no: 0x0F,
            secondary: false,
            cache: None,
            enc_tmri: Vec::new(),
            last: None,
            key: None,
            key_text: String::new(),
            pubkey: Vec::new(),
            out: TextView::new(INTRO),
        }
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
    Secondary(bool),
    AskFile,
    AskCreate,
    AskSettings,
    FileSettings,
    ReadTm,
    AskReaderId,
    Commit(bool),
    Abort,
    ShowTmi,
    Restart,
    AskVerify,
    GetUid,
    Verify,
    DecryptReaderId,
}

impl State {
    fn show(&mut self, lines: impl IntoIterator<Item = String>) {
        let v: Vec<String> = lines.into_iter().collect();
        self.out.set_text(&v.join("\n"));
    }

    /// File number as sent: bit 7 addresses the secondary application.
    fn wire_no(&self) -> u8 {
        self.file_no | if self.secondary { 0x80 } else { 0 }
    }

    /// Cached settings of the chosen file, if they belong to the current selection.
    fn cached(&self, sel: Selection) -> Option<&FileSettings> {
        self.cache.as_ref().filter(|c| c.sel == sel && c.fs.file_no == self.wire_no()).map(|c| &c.fs)
    }

    /// Tell the library which application holds the TransactionMAC file (no card traffic).
    fn sync_card(&self, shared: &mut Shared) {
        if let Some(c) = shared.card.as_mut() {
            c.set_tm_secondary(self.secondary);
        }
    }

    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::View(a) => self.out.perform(a),
            Message::Copy => return clipboard::copy(self.out.text()),
            Message::Event(ev) => match ev {
                AppEvent::Connected | AppEvent::Disconnected => {
                    self.cache = None;
                    self.last = None;
                    self.enc_tmri.clear();
                }
                AppEvent::Activated => self.sync_card(shared),
                AppEvent::StoreChanged => {}
            },
            Message::FormDone { token, values: Some(v) } => self.form_done(token, &v, shared),
            Message::FormDone { .. } => {}
            Message::Secondary(on) => {
                self.secondary = on;
                self.cache = None;
                if let Some(c) = shared.card.as_mut() {
                    c.set_tm_secondary(on);
                    c.new_transaction(None);
                }
            }
            Message::AskFile => shared.ask(
                FormSpec::new("TransactionMAC file")
                    .note("Which file is the TransactionMAC file of the selected application.")
                    .ok_text("Apply")
                    .hex_int_range("no", "File number", u64::from(self.file_no), 2, 0, 0x1F),
                ASK_FILE,
            ),
            Message::AskCreate => self.ask_create(shared),
            Message::AskSettings => self.ask_settings(shared),
            Message::FileSettings => self.file_settings(shared),
            Message::ReadTm => self.read_tm(shared),
            Message::AskReaderId => self.ask_reader_id(shared),
            Message::Commit(want_tm) => self.commit(want_tm, shared),
            Message::Abort => self.abort(shared),
            Message::ShowTmi => self.show_tmi(shared),
            Message::Restart => self.restart(shared),
            Message::AskVerify => self.ask_verify(shared),
            Message::GetUid => self.get_uid(shared),
            Message::Verify => self.verify(shared),
            Message::DecryptReaderId => self.decrypt_reader_id(shared),
        }
        Task::none()
    }

    fn form_done(&mut self, token: u32, v: &FormValues, shared: &mut Shared) {
        match token {
            ASK_FILE => {
                self.file_no = v.get_uint("no").unwrap_or(0x0F) as u8;
                self.cache = None;
            }
            ASK_CREATE => self.create(v, shared),
            ASK_SETTINGS => self.change_settings(v, shared),
            ASK_RID => self.reader_id(v, shared),
            ASK_VERIFY => self.apply_verify(v, shared),
            _ => {}
        }
    }

    /// Checks shared by every action that works inside the selected application. Returns the snapshot.
    fn in_application(&self, shared: &mut Shared) -> Option<CardView> {
        let cv = CardView::take(shared)?;
        if cv.sel.primary.is_none_or(|a| a == Aid::PICC) {
            shared.report_error("Select an application first (Card tab): transactions happen inside an application.");
            return None;
        }
        if self.secondary && cv.sel.secondary.is_none() {
            shared.report_error(
                "The file is marked as being in the secondary application, but only one application is selected.",
            );
            return None;
        }
        Some(cv)
    }

    // ---- the file --------------------------------------------------------------------

    fn ask_create(&mut self, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        if cv.auth.is_none() {
            shared.report_error("Authenticate with the application master key first (Authenticate tab).");
            return;
        }
        let names = shared.store.aes_key_names().join(", ");
        let mut spec = FormSpec::new("Create TransactionMAC file")
            .note(
                "One per application; needs the application master key. With CommitReaderID enabled every \
                 transaction must start with it. A signature file needs an AES key as well only when CommitReaderID \
                 requires an authentication.",
            )
            .ok_text("Create")
            .hex_int_range("no", "File number", u64::from(self.file_no), 2, 0, 0x1F)
            .combo("mode", "Communication mode", &MODES, 0)
            .hex_int_range("read", "Read access", 0xE, 1, 0, 0xF)
            .hint("key number 0-D, E = free, F = never")
            .hex_int_range("rid", "CommitReaderID access", 0xF, 1, 0, 0xF)
            .hint("key number 0-D, E = free, F = disabled")
            .hex_int_range("change", "Change access", 0, 1, 0, 0xF)
            .combo("kind", "Type", &KINDS, 0)
            .text("key", "AppTransactionMACKey", "")
            .hint(if names.is_empty() {
                "hex, or the name of a saved key; empty = random (saved in the key store)".to_string()
            } else {
                format!("hex or a saved key name ({names}); empty = random (saved in the key store)")
            })
            .hex_int_range("ver", "Key version", 0, 2, 0, 255)
            .int_range("tsig", "Signature: ECC private key number", 0, 0, 7)
            .hint("only for Transaction Signature; the key needs the 'transaction signature' policy")
            .text("excl", "Files left out of the TMI", "")
            .hint("hex file numbers, comma separated");
        if self.secondary {
            spec = spec.info("Application", "secondary application of the selection");
        }
        shared.ask(spec, ASK_CREATE);
    }

    fn create(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        if cv.auth.is_none() {
            shared.report_error("The authentication is gone. Authenticate again, then repeat.");
            return;
        }
        let kind = Kind::from_index(v.get_index("kind").unwrap_or(0));
        let u = |k: &str| v.get_uint(k).unwrap_or_default() as u8;
        let (no, read, rid, change) = (u("no"), u("read"), u("rid"), u("change"));
        let excl = match parse_file_list(v.get_str("excl").unwrap_or_default()) {
            Ok(m) => m,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let given = match v.get_str("key").unwrap_or_default().trim() {
            "" => None,
            t => match shared.store.resolve_aes_key(t) {
                Ok(k) => Some(k),
                Err(e) => {
                    shared.report_error(format!("The key is neither hex nor the name of a saved key ({e})."));
                    return;
                }
            },
        };
        let key = match plan_key(kind, rid, given) {
            Ok(k) => k,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let wire = no | if self.secondary { 0x80 } else { 0 };
        let mode = [CommMode::Plain, CommMode::Mac, CommMode::Full][v.get_index("mode").unwrap_or(0).min(2)];
        let mut spec = TmacFileSpec::new(wire, tmac_access(read, rid, change)).comm_mode(mode);
        if !key.is_empty() {
            spec = spec.key(&key, u("ver"));
        }
        if kind == Kind::Signature {
            spec = spec.signature_key(u("tsig"));
        }
        if excl != 0 {
            spec = spec.excl_map(excl);
        }

        // The card never returns the key, so it is saved before the file is created.
        let aid = cv.sel.primary.unwrap_or(Aid::PICC);
        let saved = if key.is_empty() {
            None
        } else {
            let name = unique_key_name(&format!("TM key {aid}"), |n| shared.store.aes_key(n).is_some());
            if shared.with_store(|st| st.set_aes_key(&name, &key)).is_err() {
                shared.log_info("TransactionMAC file not created: the key could not be saved first.");
                return;
            }
            Some(name)
        };
        let secondary = self.secondary;
        let created = shared.with_card(|card| {
            card.create_tmac_file(&spec)?;
            card.set_tm_secondary(secondary);
            card.new_transaction(Some(excl));
            Ok::<(), duox::Error>(())
        });
        if created.is_err() {
            if let Some(n) = &saved {
                // The file does not exist; do not leave an unused key behind (best effort).
                let _ = shared.store.remove_aes_key(n);
            }
            return;
        }
        if saved.is_some() {
            shared.store_changed();
        }
        self.file_no = no;
        self.cache = Some(Cached { sel: cv.sel, fs: settings_after_create(&spec) });
        let mut l = vec![format!("TransactionMAC file {no:02X} created ({}).", KINDS[kind as usize])];
        if let Some(name) = saved {
            l.push(format!("AppTransactionMACKey {}", hex::spaced(&key)));
            l.push(format!("Saved in the key store as '{name}'; the card never returns it."));
            self.key_text = name;
            self.key = Some(Secret(key));
        }
        self.show(l);
    }

    /// Settings of the chosen file: cached, or read once from the card.
    fn settings_or_fetch(&mut self, cv: &CardView, shared: &mut Shared, force: bool) -> Option<FileSettings> {
        if !force {
            if let Some(fs) = self.cached(cv.sel) {
                return Some(fs.clone());
            }
        }
        let wire = self.wire_no();
        let fs = shared.with_card(|c| c.get_file_settings(wire)).ok()?;
        if fs.file_type != FileType::TransactionMac {
            shared.report_error(format!(
                "File {:02X} is a {} file, not a TransactionMAC file. Pick the right file number with Choose file...",
                self.file_no,
                fs.file_type.name()
            ));
            return None;
        }
        self.cache = Some(Cached { sel: cv.sel, fs: fs.clone() });
        Some(fs)
    }

    fn file_settings(&mut self, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        if let Some(fs) = self.settings_or_fetch(&cv, shared, true) {
            self.show(fs.describe());
        }
    }

    fn ask_settings(&mut self, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        if cv.auth.is_none() {
            shared.report_error("Authenticate with the application master key first (Authenticate tab).");
            return;
        }
        let Some(fs) = self.settings_or_fetch(&cv, shared, false) else { return };
        let t = fs.tmac.clone().unwrap_or(TmacSettings {
            key_option: 0,
            key_version: None,
            tsig_key: None,
            excl_map: None,
            tmc_limit: None,
        });
        let limit = t.tmc_limit.filter(|&l| l != 0xFFFF_FFFF);
        let mode = [CommMode::Plain, CommMode::Mac, CommMode::Full].iter().position(|&m| m == fs.comm_mode()).unwrap_or(0);
        shared.ask(
            FormSpec::new(format!("TransactionMAC file {:02X} settings", self.file_no))
                .note(
                    "When the transaction counter reaches the limit the application can still be selected and read, \
                     but no further transaction is committed.",
                )
                .ok_text("Change")
                .combo("mode", "Communication mode", &MODES, mode)
                .hex_int_range("read", "Read access", u64::from(fs.access.read.0), 1, 0, 0xF)
                .hex_int_range("rid", "CommitReaderID access", u64::from(fs.access.read_write.0), 1, 0, 0xF)
                .hex_int_range("change", "Change access", u64::from(fs.access.change.0), 1, 0, 0xF)
                .text("excl", "Files left out of the TMI", &format_file_list(t.excl_map.unwrap_or(0)))
                .hint("hex file numbers, comma separated")
                .check("limit_on", "Limit the transaction counter", limit.is_some())
                .int_range("limit", "TMC limit", i64::from(limit.unwrap_or(1000)), 0, i64::from(u32::MAX)),
            ASK_SETTINGS,
        );
    }

    fn change_settings(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        let Some(fs) = self.cached(cv.sel).cloned() else {
            shared.report_error("The file settings are no longer known: press File settings, then repeat.");
            return;
        };
        if cv.auth.is_none() {
            shared.report_error("The authentication is gone. Authenticate again, then repeat.");
            return;
        }
        let excl = match parse_file_list(v.get_str("excl").unwrap_or_default()) {
            Ok(m) => m,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let u = |k: &str| v.get_uint(k).unwrap_or_default() as u8;
        let mut access = fs.access;
        access.read = AccessRight::key(u("read"));
        access.read_write = AccessRight::key(u("rid"));
        access.change = AccessRight::key(u("change"));
        let mode = [CommMode::Plain, CommMode::Mac, CommMode::Full][v.get_index("mode").unwrap_or(0).min(2)];
        let limit = v.get_bool("limit_on").unwrap_or(false).then(|| v.get_uint("limit").unwrap_or_default() as u32);
        let change = settings_change(&fs, mode, access, excl, limit);
        let wire = self.wire_no();
        let done = shared.with_card(|card| {
            card.change_file_settings(wire, &change)?;
            card.new_transaction(Some(excl));
            Ok::<(), duox::Error>(())
        });
        if done.is_ok() {
            self.cache = Some(Cached { sel: cv.sel, fs: settings_after_change(&fs, &change) });
            self.show(["TransactionMAC file settings changed.".to_string()]);
        }
    }

    fn read_tm(&mut self, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        let Some(fs) = self.settings_or_fetch(&cv, shared, false) else { return };
        let wire = self.wire_no();
        let Ok(d) = shared.with_card(|c| c.read_data_with(wire, 0, 0, ModeSel::File(&fs))) else { return };
        match parse_tm_read(&d) {
            Ok((tmc, v)) => {
                let mut l = fs.describe();
                l.extend([String::new(), format!("TMC {tmc}"), format!("{} {}", v.label(), hex::spaced(v.bytes()))]);
                self.show(l);
            }
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    // ---- the transaction -------------------------------------------------------------

    fn ask_reader_id(&mut self, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        if let Some(fs) = self.cached(cv.sel) {
            if fs.access.read_write.is_never() {
                shared.report_error("CommitReaderID is disabled for this file (its CommitReaderID access is 'never').");
                return;
            }
        }
        shared.ask(
            FormSpec::new("CommitReaderID")
                .note(
                    "Starts the transaction with the reader's ID. With an authenticated session the card returns the \
                     previous transaction's ReaderID, encrypted.",
                )
                .ok_text("Commit ReaderID")
                .hex_len("rid", "ReaderID", &hex::compact(&crypto::rnd(16)), 16, 16)
                .hint("16 bytes; the default is a fresh random value"),
            ASK_RID,
        );
    }

    fn reader_id(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(_) = self.in_application(shared) else { return };
        let rid = v.get_hex("rid").unwrap_or_default();
        self.sync_card(shared);
        let Ok(enc) = shared.with_card(|c| c.commit_reader_id(&rid)) else { return };
        let mut l = vec![format!("ReaderID {} committed for this transaction.", hex::spaced(&rid))];
        if !enc.is_empty() {
            l.push(format!("EncTMRI {}", hex::spaced(&enc)));
            l.push(
                "This is the ReaderID of the previous transaction, encrypted with the transaction session key. \
                 'Decrypt previous ReaderID' opens it after the commit."
                    .to_string(),
            );
        }
        self.enc_tmri = enc;
        self.show(l);
    }

    fn commit(&mut self, want_tm: bool, shared: &mut Shared) {
        let Some(cv) = self.in_application(shared) else { return };
        let mut mode = CommMode::Mac;
        if want_tm {
            if cv.auth.is_none() {
                shared.report_error("TMC and TMV / TSV are returned only inside an authenticated session: authenticate first.");
                return;
            }
            match self.cached(cv.sel) {
                Some(fs) => mode = fs.comm_mode(),
                None => {
                    shared.report_error(
                        "The TransactionMAC file's settings are not known yet: press File settings first, so the \
                         response mode of the commit is known.",
                    );
                    return;
                }
            }
        }
        self.sync_card(shared);
        let Ok(r) = shared.with_card(|c| c.commit_transaction(want_tm, mode)) else { return };
        let mut l = vec![if r.status == 0x0C {
            "Nothing to commit: the card reported no changes in this transaction.".to_string()
        } else {
            "Transaction committed.".to_string()
        }];
        match (r.tmc, r.tmv, r.tsv) {
            (Some(tmc), tmv, tsv) => {
                let value = match (tmv, tsv) {
                    (_, Some(s)) => TmValue::Signature(s),
                    (Some(m), None) => TmValue::Mac(m),
                    (None, None) => TmValue::Mac(Vec::new()),
                };
                l.push(format!("TMC {tmc}"));
                l.push(format!("{} {}", value.label(), hex::spaced(value.bytes())));
                l.push(format!("TMI recorded here: {} bytes", r.tmi.len()));
                l.push(String::new());
                let c = Commit { tmc, value, tmi: r.tmi };
                match verify_lines(&c, &cv.uid, self.key.as_ref().map(|k| k.0.as_slice()), &self.pubkey, &self.enc_tmri) {
                    Ok(v) => l.extend(v),
                    Err(e) => l.push(format!("Not verified: {e}")),
                }
                self.last = Some(c);
            }
            (None, ..) if want_tm && r.status == 0 => {
                l.push("The card returned no TMC / TMV: the application may have no TransactionMAC file.".to_string())
            }
            _ => {}
        }
        self.show(l);
    }

    fn abort(&mut self, shared: &mut Shared) {
        if self.in_application(shared).is_none() {
            return;
        }
        if let Ok(st) = shared.with_card(|c| c.abort_transaction()) {
            self.show([if st == 0x0C {
                "Nothing to abort: there were no pending changes.".to_string()
            } else {
                "Transaction aborted: pending changes are discarded.".to_string()
            }]);
        }
    }

    fn show_tmi(&mut self, shared: &mut Shared) {
        let Some(tmi) = shared.card.as_ref().map(|c| c.transaction_input().to_vec()) else {
            shared.report_error("Not connected. Pick a reader and press Connect.");
            return;
        };
        self.show([
            format!("Transaction MAC Input recorded since the last commit / selection: {} bytes", tmi.len()),
            String::new(),
            hex::dump(&tmi),
            "It only matches the card if every command of the transaction went through this program after the \
             application was selected."
                .to_string(),
        ]);
    }

    fn restart(&mut self, shared: &mut Shared) {
        let Some(cv) = CardView::take(shared) else { return };
        let excl = self.cached(cv.sel).and_then(|fs| fs.tmac.as_ref()).map(|t| t.excl_map.unwrap_or(0));
        self.sync_card(shared);
        if let Some(c) = shared.card.as_mut() {
            c.new_transaction(excl);
        }
        self.show(["TMI recording restarted (the card restarts it on selection, commit and abort).".to_string()]);
    }

    // ---- verification ----------------------------------------------------------------

    fn ask_verify(&mut self, shared: &mut Shared) {
        let names = shared.store.aes_key_names().join(", ");
        shared.ask(
            FormSpec::new("Verification inputs")
                .note("What the back end holds: the AppTransactionMACKey for a TMV, the public key for a TSV.")
                .ok_text("Apply")
                .text("key", "AppTransactionMACKey", &self.key_text)
                .hint(if names.is_empty() { "hex or a saved key name".to_string() } else { format!("hex or a saved key name ({names})") })
                .hex_len("pub", "Signature public key", &hex::compact(&self.pubkey), 0, 65)
                .hint("65 bytes (04 || x || y); empty = none"),
            ASK_VERIFY,
        );
    }

    fn apply_verify(&mut self, v: &FormValues, shared: &mut Shared) {
        let text = v.get_str("key").unwrap_or_default().trim().to_string();
        let key = if text.is_empty() {
            None
        } else {
            match shared.store.resolve_aes_key(&text) {
                Ok(k) if k.len() == 16 || k.len() == 32 => Some(Secret(k)),
                Ok(k) => {
                    shared.report_error(format!("An AES key has 16 or 32 bytes, this one has {}.", k.len()));
                    return;
                }
                Err(e) => {
                    shared.report_error(format!("The key is neither hex nor the name of a saved key ({e})."));
                    return;
                }
            }
        };
        let pubkey = v.get_hex("pub").unwrap_or_default();
        if !pubkey.is_empty() {
            if let Err(e) = pubkey_any(&pubkey) {
                shared.report_error(e);
                return;
            }
        }
        self.key = key;
        self.key_text = text;
        self.pubkey = pubkey;
        self.show(["Verification inputs applied.".to_string()]);
    }

    fn get_uid(&mut self, shared: &mut Shared) {
        let Some(cv) = CardView::take(shared) else { return };
        if cv.auth.is_none() {
            shared.report_error("GetCardUID needs an authenticated session: authenticate first.");
            return;
        }
        if let Ok(uid) = shared.with_card(|c| c.get_card_uid()) {
            self.show([format!("Card UID {}", hex::spaced(&uid))]);
        }
    }

    fn verify(&mut self, shared: &mut Shared) {
        let Some(cv) = CardView::take(shared) else { return };
        let Some(c) = self.last.clone() else {
            shared.report_error("Commit a transaction with 'Commit + TMV / TSV' first.");
            return;
        };
        let key = self.key.as_ref().map(|k| k.0.as_slice());
        match verify_lines(&c, &cv.uid, key, &self.pubkey, &self.enc_tmri) {
            Ok(v) => {
                let mut l = vec![format!("TMC {}", c.tmc), format!("TMI ({} bytes)", c.tmi.len()), hex::dump(&c.tmi)];
                l.extend(v);
                self.show(l);
            }
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    fn decrypt_reader_id(&mut self, shared: &mut Shared) {
        let Some(cv) = CardView::take(shared) else { return };
        if self.enc_tmri.is_empty() {
            shared.report_error("There is no EncTMRI yet: it is returned by an authenticated CommitReaderID.");
            return;
        }
        let Some(c) = self.last.clone() else {
            shared.report_error("Commit the transaction first: the session key depends on its counter value.");
            return;
        };
        let Some(key) = self.key.clone() else {
            shared.report_error("Enter the AppTransactionMACKey (Verification inputs...) first.");
            return;
        };
        if !matches!(cv.uid.len(), 4 | 7 | 10) {
            shared.report_error("The card's UID is unknown: use 'Get card UID' (needs authentication) first.");
            return;
        }
        match txmac::decrypt_reader_id(&key.0, c.tmc, &cv.uid, &self.enc_tmri) {
            Ok(prev) => self.show([
                format!("EncTMRI           {}", hex::spaced(&self.enc_tmri)),
                format!("Transaction TMC   {}", c.tmc),
                previous_reader_id_line(&prev).replacen("Previous ReaderID:", "Previous ReaderID", 1),
            ]),
            Err(e) => {
                shared.report_error(e.to_string());
            }
        }
    }

    // ---- view ------------------------------------------------------------------------

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let connected = shared.is_connected();
        let sel = shared.card.as_ref().map(|c| c.selection());
        let sp = theme::SPACE_SM;

        let mut file_rows = vec![(
            "Chosen file".to_string(),
            format!("{:02X}{}", self.file_no, if self.secondary { " in the secondary application" } else { "" }),
        )];
        match sel.and_then(|s| self.cached(s)) {
            Some(fs) => file_rows.extend(tmac_rows(fs).into_iter().skip(1)),
            None => file_rows.push(("Settings".to_string(), "not read yet: press File settings".to_string())),
        }
        let file = widgets::group(
            "TransactionMAC file",
            column![
                widgets::kv_table(&file_rows, false),
                row![
                    action("Create...", Message::AskCreate, connected),
                    action("Settings...", Message::AskSettings, connected),
                    action("File settings", Message::FileSettings, connected),
                    action("Read TMC / TMV", Message::ReadTm, connected),
                ]
                .spacing(sp)
                .wrap(),
                row![
                    widgets::secondary("Choose file...", Message::AskFile),
                    checkbox(self.secondary)
                        .label("file is in the secondary application")
                        .on_toggle(Message::Secondary)
                        .size(16)
                        .text_size(theme::TEXT_BODY),
                ]
                .spacing(theme::SPACE_MD)
                .align_y(iced::Alignment::Center),
            ]
            .spacing(theme::SPACE_MD),
        );

        let txn = widgets::group(
            "Transaction",
            column![
                row![
                    action("CommitReaderID...", Message::AskReaderId, connected),
                    action("Commit", Message::Commit(false), connected),
                    widgets::primary("Commit + TMV / TSV", Message::Commit(true)).on_press_maybe(connected.then_some(Message::Commit(true))),
                ]
                .spacing(sp)
                .wrap(),
                row![
                    widgets::danger("Abort", Message::Abort).on_press_maybe(connected.then_some(Message::Abort)),
                    action("Show recorded TMI", Message::ShowTmi, connected),
                    action("Restart TMI recording", Message::Restart, connected),
                ]
                .spacing(sp)
                .wrap(),
                widgets::hint(
                    "Work on the files on the Card tab between CommitReaderID and Commit. The TMI is recorded from the \
                     commands sent after the application was selected.",
                ),
            ]
            .spacing(theme::SPACE_MD),
        );

        let key_label = match (&self.key, self.key_text.as_str()) {
            (None, _) => "not set".to_string(),
            (Some(k), t) if shared.store.aes_key(t).is_some() => format!("saved key '{t}' ({} bytes)", k.0.len()),
            (Some(k), _) => format!("entered as hex ({} bytes)", k.0.len()),
        };
        let pub_label = if self.pubkey.is_empty() { "not set".to_string() } else { hex::compact(&self.pubkey) };
        let verify = widgets::group(
            "Verification (back-end side)",
            column![
                widgets::kv_table(
                    &[
                        ("AppTransactionMACKey".to_string(), key_label),
                        ("Signature public key".to_string(), pub_label),
                    ],
                    false,
                ),
                row![
                    widgets::secondary("Verification inputs...", Message::AskVerify),
                    action("Get card UID", Message::GetUid, connected),
                    action("Verify last commit", Message::Verify, connected && self.last.is_some()),
                    action("Decrypt previous ReaderID", Message::DecryptReaderId, connected && !self.enc_tmri.is_empty()),
                ]
                .spacing(sp)
                .wrap(),
            ]
            .spacing(theme::SPACE_MD),
        );

        column![
            row![container(file).width(Length::FillPortion(1)), container(txn).width(Length::FillPortion(1))]
                .spacing(theme::SPACE_MD),
            verify,
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


#[cfg(test)]
mod tests {
    use super::*;
    use duox::txmac::Tmi;

    const UID: [u8; 7] = [0x04, 0x95, 0x8C, 0xAA, 0x5C, 0x5E, 0x80];

    #[test]
    fn file_lists() {
        assert_eq!(parse_file_list("").unwrap(), 0);
        assert_eq!(parse_file_list("1, 2, 0A").unwrap(), 0b100_0000_0110);
        assert_eq!(parse_file_list("1F;00").unwrap(), 0x8000_0001);
        assert!(parse_file_list("20").unwrap_err().contains("out of range"));
        assert!(parse_file_list("zz").unwrap_err().contains("hex"));
        assert_eq!(format_file_list(0b100_0000_0110), "01, 02, 0A");
        assert_eq!(parse_file_list(&format_file_list(0x8000_8421)).unwrap(), 0x8000_8421);
    }

    #[test]
    fn key_planning() {
        assert_eq!(plan_key(Kind::Aes128, 0xF, None).unwrap().len(), 16);
        assert_eq!(plan_key(Kind::Aes256, 0xF, None).unwrap().len(), 32);
        // signature without an authenticated CommitReaderID needs no AES key
        assert!(plan_key(Kind::Signature, 0xF, None).unwrap().is_empty());
        assert!(plan_key(Kind::Signature, 0xE, None).unwrap().is_empty());
        assert_eq!(plan_key(Kind::Signature, 0x1, None).unwrap().len(), 16);
        assert_eq!(plan_key(Kind::Aes128, 0xF, Some(vec![1; 16])).unwrap(), vec![1; 16]);
        assert!(plan_key(Kind::Aes128, 0xF, Some(vec![1; 32])).unwrap_err().contains("16 bytes"));
        assert!(plan_key(Kind::Aes256, 0xF, Some(vec![1; 16])).unwrap_err().contains("32 bytes"));
        assert!(plan_key(Kind::Signature, 0xF, Some(vec![1; 24])).is_err());
    }

    #[test]
    fn unique_names() {
        let taken = ["TM key 000001", "TM key 000001 (2)"];
        assert_eq!(unique_key_name("TM key 000002", |n| taken.contains(&n)), "TM key 000002");
        assert_eq!(unique_key_name("TM key 000001", |n| taken.contains(&n)), "TM key 000001 (3)");
    }

    #[test]
    fn created_settings_match_the_wire_layout() {
        let spec = TmacFileSpec::new(0x0F, tmac_access(0xE, 0xF, 0))
            .comm_mode(CommMode::Full)
            .key(&[7; 16], 3)
            .excl_map(0b110);
        let fs = settings_after_create(&spec);
        assert_eq!(fs.access.to_u16(), 0xEFF0);
        let back = FileSettings::parse(0x0F, &fs.encode()).unwrap();
        assert_eq!(back.tmac, fs.tmac);
        assert_eq!(back.comm_mode(), CommMode::Full);
        let t = back.tmac.unwrap();
        assert_eq!((t.key_version, t.excl_map, t.is_signature()), (Some(3), Some(0b110), false));

        let sig = TmacFileSpec::new(0x8F, tmac_access(0xE, 0xF, 0)).signature_key(2);
        let fs = settings_after_create(&sig);
        let t = fs.tmac.clone().unwrap();
        assert!(t.is_signature());
        assert_eq!((t.tsig_key, t.key_version), (Some(2), None));
        assert!(fs.is_secondary_app());
    }

    #[test]
    fn settings_change_encoding() {
        let spec = TmacFileSpec::new(0x0F, tmac_access(0xE, 0xF, 0x1)).key(&[7; 16], 0);
        let fs = settings_after_create(&spec);
        let c = settings_change(&fs, CommMode::Mac, fs.access, 0b10, Some(500));
        assert_eq!(c.option, 0x01 | 0x40 | 0x20);
        assert_eq!((c.tmac_excl_map, c.tmc_limit), (Some(2), Some(500)));
        assert_eq!(c.current_change_access, AccessRight::key(1));
        let after = settings_after_change(&fs, &c);
        let t = after.tmac.clone().unwrap();
        assert_eq!((t.excl_map, t.tmc_limit), (Some(2), Some(500)));
        assert_eq!(after.comm_mode(), CommMode::Mac);
        // no exclusion, no limit
        let c = settings_change(&fs, CommMode::Plain, fs.access, 0, None);
        assert_eq!((c.option, c.tmac_excl_map, c.tmc_limit), (0, None, None));
        let rows = tmac_rows(&after);
        assert!(rows.iter().any(|(k, v)| k == "TMC limit" && v == "500"));
        assert!(rows.iter().any(|(k, v)| k == "Left out of TMI" && v == "01"));
    }

    #[test]
    fn reading_tmc_and_value() {
        let mut d = 7u32.to_le_bytes().to_vec();
        d.extend([1; 8]);
        assert_eq!(parse_tm_read(&d).unwrap(), (7, TmValue::Mac(vec![1; 8])));
        let mut d = 9u32.to_le_bytes().to_vec();
        d.extend([2; 64]);
        assert_eq!(parse_tm_read(&d).unwrap().1, TmValue::Signature(vec![2; 64]));
        assert!(parse_tm_read(&[0; 5]).unwrap_err().contains("5 bytes"));
    }

    fn recorded() -> Tmi {
        let mut t = Tmi::new(0);
        t.data(0x8D, 3, 0, &[1, 2, 3]);
        t
    }

    #[test]
    fn tmv_verification() {
        let key = [9u8; 16];
        let tmi = recorded().as_bytes().to_vec();
        let good = txmac::tmv(&key, 7, &UID, &tmi).unwrap();
        let c = Commit { tmc: 7, value: TmValue::Mac(good.clone()), tmi: tmi.clone() };
        let l = verify_lines(&c, &UID, Some(&key), &[], &[]).unwrap();
        assert!(l[0].ends_with("VALID") && !l[0].contains("MISMATCH"));
        // wrong key, wrong UID
        assert!(verify_lines(&c, &UID, Some(&[8u8; 16]), &[], &[]).unwrap()[0].contains("MISMATCH"));
        assert!(verify_lines(&c, &[0; 7], Some(&key), &[], &[]).unwrap()[0].contains("MISMATCH"));
        // missing inputs are sentences
        assert!(verify_lines(&c, &UID, None, &[], &[]).unwrap_err().contains("AppTransactionMACKey"));
        assert!(verify_lines(&c, &[], Some(&key), &[], &[]).unwrap_err().contains("UID"));
        assert!(verify_lines(&c, &UID, Some(&[1; 5]), &[], &[]).is_err());
    }

    #[test]
    fn reader_id_round_trip_in_verification() {
        let key = [9u8; 16];
        let tmi = recorded().as_bytes().to_vec();
        let ks = txmac::session_keys(&key, 7, &UID).unwrap();
        let prev = [0x5Au8; 16];
        let enc = crypto::aes_cbc_enc(&ks.enc, &prev, &crypto::ZERO_IV).unwrap();
        let c = Commit { tmc: 7, value: TmValue::Mac(txmac::tmv(&key, 7, &UID, &tmi).unwrap()), tmi };
        let l = verify_lines(&c, &UID, Some(&key), &[], &enc).unwrap();
        assert_eq!(l[1], format!("Previous ReaderID: {}", hex::spaced(&prev)));
        let zero = crypto::aes_cbc_enc(&ks.enc, &[0u8; 16], &crypto::ZERO_IV).unwrap();
        assert!(verify_lines(&c, &UID, Some(&key), &[], &zero).unwrap()[1].contains("none yet"));
    }

    #[test]
    fn tsv_verification() {
        let sk = crypto::gen_key(crypto::CURVE_P256).unwrap();
        let tmi = recorded().as_bytes().to_vec();
        let sig = txmac::sign_tsv(&sk, &tmi, 7).unwrap();
        let c = Commit { tmc: 7, value: TmValue::Signature(sig), tmi };
        let public = sk.public().to_bytes();
        assert!(verify_lines(&c, &UID, None, &public, &[]).unwrap()[0].ends_with("VALID") );
        let other = crypto::gen_key(crypto::CURVE_P256).unwrap().public().to_bytes();
        assert!(verify_lines(&c, &UID, None, &other, &[]).unwrap()[0].contains("INVALID"));
        assert!(verify_lines(&c, &UID, None, &[], &[]).unwrap_err().contains("public key"));
        assert!(verify_lines(&c, &UID, None, &[4; 65], &[]).unwrap_err().contains("not a valid"));
    }
}
