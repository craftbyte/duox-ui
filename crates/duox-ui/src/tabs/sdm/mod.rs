//! SDM tab: build an NDEF URL file and its SDM settings from a template, manage the file on the
//! card, read it unauthenticated and verify what a back end would receive.

mod model;

use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::textview::TextView;
use crate::ui::{clipboard, hex, theme, widgets};
use duox::card::{CommMode, DataFileSpec, FileSettings, FileSettingsChange, FileType, IsoSelect, ModeSel};
use duox::card::AccessRights;
use duox::crypto::PubKey;
use duox::pki::CertKind;
use duox::sdm::{self, RenderKeys, SdmSettings, TemplateOptions, VerifyParams};
use iced::widget::{column, container, pick_list, row, scrollable, text, text_editor, text_input, Row};
use iced::{Element, Length, Task};
use model::{AC_LABELS, OFFSET_FIELDS};

const ASK_TEMPLATE: u32 = 1;
const ASK_SETTINGS: u32 = 2;
const ASK_CREATE: u32 = 3;
const ASK_CONTENT: u32 = 4;
const ASK_DYNAMIC: u32 = 5;
const ASK_KEYS: u32 = 6;
const ASK_ISO: u32 = 7;
const ASK_URL: u32 = 8;
const CONFIRM_END_AUTH: u32 = 9;
const CONFIRM_APPLY: u32 = 10;

const DEFAULT_URL: &str = "https://example.org/tap?p={picc}&m={mac}";
const OPTION_FLAGS: [(u8, &str); 5] = [
    (sdm::OPT_UID, "VCUID"),
    (sdm::OPT_CTR, "SDMReadCtr"),
    (sdm::OPT_CTR_LIMIT, "Counter limit"),
    (sdm::OPT_ENC, "Encrypted file data"),
    (sdm::OPT_GPIO, "GPIO status"),
];
const MODES: [&str; 3] = ["Plain", "MAC", "Full"];

/// Last values of the template dialog.
#[derive(Debug, Clone)]
struct Template {
    url: String,
    meta_read: u8,
    file_read: u8,
    file_read2: u8,
    ctr_ret: u8,
    enc_fill: String,
    ctr_limit: Option<u32>,
}

impl Default for Template {
    fn default() -> Self {
        Template {
            url: DEFAULT_URL.into(),
            meta_read: 0,
            file_read: 0,
            file_read2: sdm::AC_NONE,
            ctr_ret: 0,
            enc_fill: String::new(),
            ctr_limit: None,
        }
    }
}

/// Key entry of the verifier. Kept as typed (hex or the name of a saved key); never logged.
#[derive(Clone)]
struct KeyInput {
    meta: String,
    file: String,
    /// Label of a card identity in the store; empty when the key is given as hex.
    sig_card: String,
    sig_hex: String,
}

impl Default for KeyInput {
    fn default() -> Self {
        KeyInput { meta: "00".repeat(16), file: "00".repeat(16), sig_card: String::new(), sig_hex: String::new() }
    }
}

struct ResolvedKeys {
    meta: Option<Vec<u8>>,
    file: Option<Vec<u8>>,
    sig_pub: Option<PubKey>,
}

pub struct State {
    file_no: String,
    uid_len: usize,
    tpl: Template,
    cfg: SdmSettings,
    content: Vec<u8>,
    dynamic: Vec<u8>,
    keys: KeyInput,
    /// Size of the file the settings were last loaded from, for the offline check.
    known_size: Option<(u8, u32)>,
    /// Settings waiting for the user's decision after a failed plausibility check.
    pending_apply: Option<(FileSettings, SdmSettings)>,
    content_view: TextView,
    dynamic_view: TextView,
    out: TextView,
}

impl Default for State {
    fn default() -> Self {
        let mut s = State {
            file_no: "02".into(),
            uid_len: 7,
            tpl: Template::default(),
            cfg: SdmSettings::default(),
            content: Vec::new(),
            dynamic: Vec::new(),
            keys: KeyInput::default(),
            known_size: None,
            pending_apply: None,
            content_view: TextView::default(),
            dynamic_view: TextView::default(),
            out: TextView::default(),
        };
        s.out.set_text(INTRO);
        s
    }
}

impl std::fmt::Debug for State {
    // No derive: the key entry must never end up in a debug print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("sdm::State").field("file_no", &self.file_no).finish_non_exhaustive()
    }
}

const INTRO: &str = "\
Typical flow
  1. Build from template...   enter a URL such as https://example.org/tap?p={picc}&m={mac}
  2. Create file...           an SDM-capable standard data file (needs authentication)
  3. Write content            the static NDEF content
  4. Apply SDM settings       enables SDM with the settings shown above
  5. Read unauthenticated     reads the mirrored data (this increments SDMReadCtr) and verifies it

Template tokens
  {uid} {ctr}   plain mirrors of the UID and the read counter
  {picc}        encrypted UID + counter (SDMMetaRead names the AES key)
  {enc:16}      16 bytes of encrypted file data (any multiple of 16)
  {gpio}        GPIO status
  {mac} {sig}   SDMMAC (AES) or SDMSIG (ECC signature)
  {macstart}    where the MAC / signature input begins (default: the first mirrored field)";

#[derive(Debug, Clone)]
pub enum Message {
    FormDone { token: u32, values: Option<FormValues> },
    Event(AppEvent),
    FileNo(String),
    UidLen(usize),
    // card
    Load,
    Create,
    WriteContent,
    Apply,
    Disable,
    Counter,
    // offline
    Template,
    EditSettings,
    Validate,
    EditContent,
    EditDynamic,
    Keys,
    // reading and verifying
    ReadNative,
    ReadIso,
    Verify,
    Preview,
    VerifyUrl,
    // text views
    CopyContent,
    CopyDynamic,
    CopyOut,
    ViewContent(text_editor::Action),
    ViewDynamic(text_editor::Action),
    ViewOut(text_editor::Action),
}

// ---------------------------------------------------------------- helpers on Shared

fn require_card(shared: &mut Shared) -> bool {
    if shared.is_connected() {
        true
    } else {
        shared.report_error("Not connected. Pick a reader and press Connect.");
        false
    }
}

fn authenticated(shared: &Shared) -> bool {
    shared.card.as_ref().is_some_and(|c| c.is_authenticated())
}

fn require_auth(shared: &mut Shared, what: &str) -> bool {
    if !require_card(shared) {
        return false;
    }
    if authenticated(shared) {
        return true;
    }
    shared.report_error(format!("{what} needs an authenticated session. Authenticate on the Authenticate tab first."));
    false
}

fn copy_text(view: &TextView) -> Task<app::Message> {
    clipboard::copy(view.selection().unwrap_or_else(|| view.text()))
}

fn mode_of(index: usize) -> CommMode {
    match index {
        1 => CommMode::Mac,
        2 => CommMode::Full,
        _ => CommMode::Plain,
    }
}

fn action<'a>(label: &str, msg: Message, enabled: bool) -> Element<'a, Message> {
    if enabled {
        widgets::secondary(label, msg).into()
    } else {
        iced::widget::button(text(label.to_string())).padding([5, 14]).into()
    }
}

/// Buttons in a row that wraps when the window is narrow.
fn buttons<'a>(items: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    Row::with_children(items).spacing(theme::SPACE_SM).wrap().vertical_spacing(theme::SPACE_SM).into()
}

// ---------------------------------------------------------------- state logic

impl State {
    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::FormDone { token, values } => self.form_done(token, values, shared),
            Message::Event(AppEvent::Disconnected) => {
                self.known_size = None;
                self.pending_apply = None;
            }
            Message::Event(AppEvent::Connected | AppEvent::Activated) => self.sync_uid_len(shared),
            Message::Event(AppEvent::StoreChanged) => {}
            Message::FileNo(s) => self.file_no = s,
            Message::UidLen(n) => self.uid_len = n,
            Message::Load => self.load(shared),
            Message::Create => self.ask_create(shared),
            Message::WriteContent => self.write_content(shared),
            Message::Apply => self.apply(shared),
            Message::Disable => self.disable(shared),
            Message::Counter => self.counter(shared),
            Message::Template => self.ask_template(shared),
            Message::EditSettings => self.ask_settings(shared),
            Message::Validate => self.validate(shared),
            Message::EditContent => self.ask_bytes(shared, ASK_CONTENT, "Static file content", &self.content.clone()),
            Message::EditDynamic => self.ask_bytes(shared, ASK_DYNAMIC, "Dynamic data", &self.dynamic.clone()),
            Message::Keys => self.ask_keys(shared),
            Message::ReadNative => self.read_native(shared),
            Message::ReadIso => self.ask_iso(shared),
            Message::Verify => self.verify_dynamic(shared),
            Message::Preview => self.preview(shared),
            Message::VerifyUrl => self.ask_url(shared),
            Message::CopyContent => return copy_text(&self.content_view),
            Message::CopyDynamic => return copy_text(&self.dynamic_view),
            Message::CopyOut => return copy_text(&self.out),
            Message::ViewContent(a) => self.content_view.perform(a),
            Message::ViewDynamic(a) => self.dynamic_view.perform(a),
            Message::ViewOut(a) => self.out.perform(a),
        }
        Task::none()
    }

    fn form_done(&mut self, token: u32, values: Option<FormValues>, shared: &mut Shared) {
        let Some(v) = values else {
            if token == CONFIRM_APPLY {
                self.pending_apply = None;
            }
            return;
        };
        match token {
            ASK_TEMPLATE => self.build_template(&v, shared),
            ASK_SETTINGS => self.apply_settings_form(&v),
            ASK_CREATE => self.create_file(&v, shared),
            ASK_CONTENT => {
                if let Some(b) = read_bytes_form(&v, shared) {
                    self.content = b;
                    self.refresh_views();
                }
            }
            ASK_DYNAMIC => {
                if let Some(b) = read_bytes_form(&v, shared) {
                    self.dynamic = b;
                    self.refresh_views();
                }
            }
            ASK_KEYS => match self.read_keys(&v, shared) {
                Ok(k) => {
                    self.keys = k;
                    self.set_out("Keys updated. They are used by Verify and Preview and are not written anywhere.");
                }
                Err(e) => {
                    shared.report_error(e);
                }
            },
            ASK_ISO => self.read_iso(&v, shared),
            ASK_URL => self.verify_url(&v, shared),
            CONFIRM_END_AUTH => self.read_native_now(shared),
            CONFIRM_APPLY => {
                if let Some((fs, cfg)) = self.pending_apply.take() {
                    self.send_apply(shared, &fs, &cfg);
                }
            }
            _ => {}
        }
    }

    fn set_out(&mut self, s: impl AsRef<str>) {
        self.out.set_text(s.as_ref());
    }

    fn refresh_views(&mut self) {
        self.content_view.set_text(&hex::spaced(&self.content));
        self.dynamic_view.set_text(&hex::spaced(&self.dynamic));
    }

    /// The UID length of the connected card wins over the manual choice.
    fn sync_uid_len(&mut self, shared: &Shared) {
        if let Some(c) = &shared.card {
            if matches!(c.uid().len(), 7 | 10) {
                self.uid_len = c.uid().len();
            }
        }
    }

    fn file_no(&self, shared: &mut Shared) -> Option<u8> {
        match model::parse_file_no(&self.file_no) {
            Ok(n) => Some(n),
            Err(e) => {
                shared.report_error(e);
                None
            }
        }
    }

    // ------------------------------------------------------------ template and settings

    fn ask_template(&mut self, shared: &mut Shared) {
        self.sync_uid_len(shared);
        let t = &self.tpl;
        shared.ask(
            FormSpec::new("Build content and SDM settings from a URL template")
                .note(
                    "Tokens: {uid} {ctr} plain mirrors, {picc} encrypted UID + counter, {enc:16} encrypted file \
                     bytes, {gpio}, {mac} or {sig}, {macstart}.",
                )
                .ok_text("Build")
                .text("url", "URL template", &t.url)
                .combo("meta_read", "SDMMetaRead", &AC_LABELS, usize::from(t.meta_read))
                .hint("Key for {picc}; E for plain {uid} / {ctr}")
                .combo("file_read", "SDMFileRead", &AC_LABELS, usize::from(t.file_read))
                .hint("AES key for {mac} and {enc}")
                .combo("file_read2", "SDMFileRead2 (ECC)", &AC_LABELS, usize::from(t.file_read2))
                .hint("ECC private key for {sig}; F = off")
                .combo("ctr_ret", "SDMCtrRet", &AC_LABELS, usize::from(t.ctr_ret))
                .text("enc_fill", "{enc} plaintext", &t.enc_fill)
                .hint("Placed in the encrypted region, space padded")
                .int_range("ctr_limit", "SDMReadCtrLimit", model::offset_to_form(t.ctr_limit), -1, 0xFF_FFFF)
                .hint("-1 = no limit")
                .info("UID length", &format!("{} bytes (taken from the connected card, else the selector)", self.uid_len)),
            ASK_TEMPLATE,
        );
    }

    fn build_template(&mut self, v: &FormValues, shared: &mut Shared) {
        let nibble = |k: &str| v.get_index(k).unwrap_or(0) as u8;
        self.tpl = Template {
            url: v.get_str("url").unwrap_or_default().trim().to_string(),
            meta_read: nibble("meta_read"),
            file_read: nibble("file_read"),
            file_read2: nibble("file_read2"),
            ctr_ret: nibble("ctr_ret"),
            enc_fill: v.get_str("enc_fill").unwrap_or_default().to_string(),
            ctr_limit: model::offset_from_form(v.get_int("ctr_limit").unwrap_or(-1)),
        };
        if self.tpl.url.is_empty() {
            shared.report_error("The URL template is empty.");
            return;
        }
        let opts = TemplateOptions {
            uid_len: self.uid_len,
            meta_read: self.tpl.meta_read,
            file_read: self.tpl.file_read,
            file_read2: self.tpl.file_read2,
            ctr_ret: self.tpl.ctr_ret,
            enc_fill: self.tpl.enc_fill.as_bytes().to_vec(),
            ctr_limit: self.tpl.ctr_limit,
        };
        match sdm::build_ndef_template(&self.tpl.url, &opts) {
            Err(e) => {
                shared.report_error(e.to_string());
            }
            Ok(t) => {
                self.cfg = t.settings;
                self.content = t.file_data;
                self.refresh_views();
                let mut s = format!(
                    "NDEF file content: {} bytes (NLEN + URI record). The file must be at least that large.\n\n",
                    self.content.len()
                );
                s.push_str(&self.cfg.describe().join("\n"));
                s.push_str("\n\nMirrored regions (file offsets):\n");
                s.push_str(&model::region_lines(&self.cfg, self.uid_len).join("\n"));
                s.push_str("\n\n");
                s.push_str(&hex::dump(&self.content));
                self.set_out(s);
            }
        }
    }

    fn ask_settings(&mut self, shared: &mut Shared) {
        let c = &self.cfg;
        let mut spec = FormSpec::new("SDM settings")
            .note("Values for ChangeFileSettings. Offsets are file offsets of the mirrored fields.")
            .ok_text("Apply to editor")
            .combo("meta_read", "SDMMetaRead", &AC_LABELS, usize::from(c.meta_read))
            .combo("file_read", "SDMFileRead", &AC_LABELS, usize::from(c.file_read))
            .combo("file_read2", "SDMFileRead2 (ECC)", &AC_LABELS, usize::from(c.file_read2))
            .combo("ctr_ret", "SDMCtrRet", &AC_LABELS, usize::from(c.ctr_ret));
        for (bit, label) in OPTION_FLAGS {
            spec = spec.check(&format!("opt{bit}"), label, c.options & bit != 0);
        }
        for (field, key) in OFFSET_FIELDS {
            spec = spec.int_range(key, field.name(), model::offset_to_form(c.get(field)), -1, 0xFF_FFFF);
            if field == sdm::SdmField::MacInputOffset {
                spec = spec.hint("-1 = not used; 16777215 (0xFFFFFF) = counter enabled but not mirrored");
            }
        }
        shared.ask(spec, ASK_SETTINGS);
    }

    fn apply_settings_form(&mut self, v: &FormValues) {
        let nibble = |k: &str| v.get_index(k).unwrap_or(0xF) as u8;
        let mut c = SdmSettings {
            options: sdm::OPT_ASCII,
            meta_read: nibble("meta_read"),
            file_read: nibble("file_read"),
            file_read2: nibble("file_read2"),
            ctr_ret: nibble("ctr_ret"),
            ..Default::default()
        };
        for (bit, _) in OPTION_FLAGS {
            if v.get_bool(&format!("opt{bit}")).unwrap_or(false) {
                c.options |= bit;
            }
        }
        for (field, key) in OFFSET_FIELDS {
            c.set(field, model::offset_from_form(v.get_int(key).unwrap_or(-1)));
        }
        model::normalize(&mut c);
        self.set_out(format!("Settings in the editor:\n\n{}", c.describe().join("\n")));
        self.cfg = c;
    }

    fn validate(&mut self, shared: &mut Shared) {
        let no = model::parse_file_no(&self.file_no).ok();
        let (size, note) = match self.known_size {
            Some((n, s)) if Some(n) == no => (s as usize, "size read from the card".to_string()),
            _ if !self.content.is_empty() => (self.content.len(), "length of the static content".to_string()),
            _ => (256, "assumed, load the file from the card to use its real size".to_string()),
        };
        let uid_len = self.effective_uid_len(shared);
        self.set_out(model::validation_report(&self.cfg, size, &note, uid_len));
    }

    fn effective_uid_len(&mut self, shared: &Shared) -> usize {
        self.sync_uid_len(shared);
        self.uid_len
    }

    fn ask_bytes(&self, shared: &mut Shared, token: u32, title: &str, current: &[u8]) {
        shared.ask(
            FormSpec::new(title)
                .note(if token == ASK_CONTENT {
                    "The bytes written to the file by Write content."
                } else {
                    "Data as an unauthenticated reader received it; Verify checks it against the settings."
                })
                .ok_text("Set")
                .hex("data", "Hex bytes", &hex::spaced(current))
                .file_open("file", "or load from a file", vec![crate::ui::files::Filter::new("Binary", &["bin", "ndef"])])
                .hint("When a file is chosen it replaces the hex above"),
            token,
        );
    }

    // ------------------------------------------------------------ card commands

    fn load(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        let Some(no) = self.file_no(shared) else { return };
        let r = shared.with_card(|c| {
            let fs = c.get_file_settings(no)?;
            let content = if c.is_authenticated() && fs.file_type == FileType::StandardData {
                Some(c.read_data_with(fs.file_no, 0, 0, ModeSel::File(&fs))?)
            } else {
                None
            };
            Ok::<_, duox::Error>((fs, content))
        });
        let Ok((fs, content)) = r else { return };
        let mut lines = fs.describe();
        self.known_size = fs.size.map(|s| (no, s));
        match fs.sdm.as_deref().map(SdmSettings::parse) {
            Some(Ok((s, _))) => {
                self.cfg = s;
                lines.push(String::new());
                lines.extend(self.cfg.describe());
            }
            Some(Err(e)) => lines.push(format!("The SDM settings could not be decoded: {e}")),
            None if fs.file_type == FileType::StandardData => {
                lines.push("SDM is not enabled on this file.".into());
                if fs.option & 0x40 == 0 {
                    lines.push("It can only be switched on if the file was created SDM-capable.".into());
                }
            }
            None => lines.push("Only standard data files support SDM.".into()),
        }
        match content {
            Some(d) => {
                self.content = d;
                self.refresh_views();
            }
            None if fs.file_type == FileType::StandardData => lines.push(
                "Not authenticated: the static content was not loaded (an unauthenticated read returns the \
                 mirrored data and increments the counter)."
                    .into(),
            ),
            None => {}
        }
        self.set_out(lines.join("\n"));
    }

    fn ask_create(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        let no = model::parse_file_no(&self.file_no).unwrap_or(2) & 0x1F;
        shared.ask(
            FormSpec::new("Create SDM-capable standard data file")
                .note(
                    "SDM has to be pre-enabled when the file is created. Free read access (E) lets phones read the \
                     file; once SDM is enabled the card also gives unauthenticated readers the mirrored data.",
                )
                .ok_text("Create")
                .hex_int_range("no", "File number", u64::from(no), 2, 0, 0x1F)
                .hex_len("fid", "ISO file ID", "", 0, 2)
                .hint("Optional, 2 bytes. An NDEF file is usually E104")
                .int_range("size", "Size", 256, 1, 0xFF_FFFF)
                .hint("bytes")
                .hex_int_range("ar", "Access rights", 0xE000, 4, 0, 0xFFFF)
                .hint("Four nibbles: Read Write ReadWrite Change (0-D key, E free, F never)")
                .combo("mode", "Communication mode", &MODES, 0),
            ASK_CREATE,
        );
    }

    fn create_file(&mut self, v: &FormValues, shared: &mut Shared) {
        let fid = v.get_hex("fid").unwrap_or_default();
        if !matches!(fid.len(), 0 | 2) {
            shared.report_error("The ISO file ID is exactly 2 bytes (for example E104) or empty.");
            return;
        }
        let no = v.get_uint("no").unwrap_or(2) as u8;
        let size = v.get_uint("size").unwrap_or(256) as u32;
        let ar = AccessRights::from_u16(v.get_uint("ar").unwrap_or(0xE000) as u16);
        let mut spec = DataFileSpec::new(no, size, ar).comm_mode(mode_of(v.get_index("mode").unwrap_or(0))).sdm();
        if let [a, b] = fid[..] {
            spec = spec.iso_fid(u16::from_be_bytes([a, b]));
        }
        if shared.with_card(|c| c.create_data_file(&spec)).is_ok() {
            self.file_no = format!("{no:02X}");
            self.known_size = Some((no, size));
            self.set_out(format!(
                "File {no:02X} created: {size} bytes, {ar}, CommMode.{}, SDM pre-enabled.\n\nWrite the content, then apply the SDM settings.",
                spec.comm_mode
            ));
        }
    }

    fn write_content(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        let Some(no) = self.file_no(shared) else { return };
        if self.content.is_empty() {
            shared.report_error("There is no content to write. Build it from a template or enter hex with Edit.");
            return;
        }
        if let Some((n, size)) = self.known_size {
            if n == no && self.content.len() > size as usize {
                shared.report_error(format!(
                    "The content is {} bytes but file {no:02X} holds only {size}.",
                    self.content.len()
                ));
                return;
            }
        }
        let data = self.content.clone();
        if shared.with_card(|c| c.write_data(no, 0, &data)).is_ok() {
            shared.log_info(&format!("wrote {} bytes of static content to file {no:02X}", data.len()));
            self.set_out(format!("Wrote {} bytes to file {no:02X}.", data.len()));
        }
    }

    /// May the current session (or no session) change the file's settings?
    fn change_allowed(shared: &Shared, fs: &FileSettings) -> Result<(), String> {
        let ch = fs.access.change;
        if ch.is_never() {
            return Err(format!("The Change access right of file {:02X} is F (never): its settings are frozen.", fs.file_no));
        }
        if ch.is_free() {
            return Ok(());
        }
        let card = shared.card.as_ref().ok_or("Not connected.")?;
        if !card.is_authenticated() {
            return Err(format!(
                "Changing the settings of file {:02X} needs authentication with the key named by its Change access right (key {:X}).",
                fs.file_no, ch.0
            ));
        }
        if !card.has_access_condition(ch, fs.is_secondary_app()) {
            return Err(format!(
                "The current authentication does not satisfy the Change access right of file {:02X} (key {:X}). \
                 Authenticate with that key first.",
                fs.file_no, ch.0
            ));
        }
        Ok(())
    }

    fn apply(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        let Some(no) = self.file_no(shared) else { return };
        if let Err(e) = self.cfg.encode() {
            shared.report_error(format!("The SDM settings cannot be sent: {e}"));
            return;
        }
        let Ok(fs) = shared.with_card(|c| c.get_file_settings(no)) else { return };
        if fs.file_type != FileType::StandardData {
            shared.report_error(format!("File {no:02X} is a {} file; SDM exists only on standard data files.", fs.file_type));
            return;
        }
        if let Err(e) = Self::change_allowed(shared, &fs) {
            shared.report_error(e);
            return;
        }
        self.known_size = fs.size.map(|s| (no, s));
        let uid_len = self.effective_uid_len(shared);
        let problems = self.cfg.validate(fs.size.unwrap_or(0) as usize, uid_len);
        if problems.is_empty() {
            let cfg = self.cfg.clone();
            self.send_apply(shared, &fs, &cfg);
        } else {
            let list = problems.iter().map(|p| format!("- {p}")).collect::<Vec<_>>().join("\n");
            self.pending_apply = Some((fs, self.cfg.clone()));
            shared.confirm(
                "SDM settings look invalid",
                &format!("{list}\n\nSend them to the card anyway?"),
                "Send anyway",
                CONFIRM_APPLY,
            );
        }
    }

    fn send_apply(&mut self, shared: &mut Shared, fs: &FileSettings, cfg: &SdmSettings) {
        let Ok(bytes) = cfg.encode() else { return };
        let mut change = FileSettingsChange::new((fs.option & 0x83) | 0x40, fs.access);
        change.additional = fs.additional.clone();
        change.sdm = bytes;
        change.current_change_access = fs.access.change;
        if shared.with_card(|c| c.change_file_settings(fs.file_no, &change)).is_ok() {
            self.set_out(format!(
                "SDM enabled on file {:02X}; SDMReadCtr was reset to 0.\n\n{}",
                fs.file_no,
                cfg.describe().join("\n")
            ));
        }
    }

    fn disable(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        let Some(no) = self.file_no(shared) else { return };
        let Ok(fs) = shared.with_card(|c| c.get_file_settings(no)) else { return };
        if fs.option & 0x40 == 0 {
            self.set_out(format!("SDM is not enabled on file {no:02X}; nothing to disable."));
            return;
        }
        if let Err(e) = Self::change_allowed(shared, &fs) {
            shared.report_error(e);
            return;
        }
        let mut change = FileSettingsChange::new(fs.option & 0x83, fs.access);
        change.additional = fs.additional.clone();
        change.current_change_access = fs.access.change;
        if shared.with_card(|c| c.change_file_settings(fs.file_no, &change)).is_ok() {
            self.set_out(format!("SDM disabled on file {:02X}.", fs.file_no));
        }
    }

    fn counter(&mut self, shared: &mut Shared) {
        if !require_auth(shared, "Reading the SDM counter") {
            return;
        }
        let Some(no) = self.file_no(shared) else { return };
        if let Ok(n) = shared.with_card(|c| c.get_file_counters(no)) {
            self.set_out(format!("SDMReadCtr of file {no:02X}: {n}"));
        }
    }

    // ------------------------------------------------------------ reading

    fn read_native(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        if self.file_no(shared).is_none() {
            return;
        }
        if authenticated(shared) {
            if shared.card.as_ref().is_some_and(|c| c.selection().primary.is_none()) {
                shared.report_error(
                    "The authentication cannot be ended because the selected application is unknown. \
                     Select the application on the Card tab first.",
                );
                return;
            }
            shared.confirm(
                "End the authentication?",
                "SDM is only applied to unauthenticated reads. The application is selected again, which ends the \
                 current authentication.",
                "End authentication and read",
                CONFIRM_END_AUTH,
            );
        } else {
            self.read_native_now(shared);
        }
    }

    fn read_native_now(&mut self, shared: &mut Shared) {
        let Some(no) = self.file_no(shared) else { return };
        let r = shared.with_card(|c| {
            if c.is_authenticated() {
                let sel = c.selection();
                let aid = sel.primary.ok_or_else(|| duox::Error::InvalidArgument("no application selected".into()))?;
                c.select_application(aid, sel.secondary)?;
            }
            c.read_data_with(no, 0, 0, ModeSel::Explicit(CommMode::Plain))
        });
        if let Ok(d) = r {
            self.dynamic = d;
            self.refresh_views();
            self.verify_dynamic(shared);
        }
    }

    fn ask_iso(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        shared.ask(
            FormSpec::new("Read like an NDEF reader")
                .note(
                    "ISOSelectFile by DF name, ISOSelectFile of the file, then ISOReadBinary. Ends any \
                     authentication.",
                )
                .ok_text("Read")
                .hex_len("df", "Application DF name", "D2760000850101", 1, 16)
                .hex_int_range("fid", "ISO file ID", 0xE104, 4, 1, 0xFFFF),
            ASK_ISO,
        );
    }

    fn read_iso(&mut self, v: &FormValues, shared: &mut Shared) {
        let df = v.get_hex("df").unwrap_or_default();
        let fid = v.get_uint("fid").unwrap_or(0xE104) as u16;
        let r = shared.with_card(|c| {
            c.iso_select(&IsoSelect::Raw { p1: 0x04, p2: 0x0C, data: &df })?;
            c.iso_select(&IsoSelect::Raw { p1: 0x02, p2: 0x0C, data: &fid.to_be_bytes() })?;
            let mut data = Vec::new();
            while data.len() < 0x7F00 {
                let chunk = c.iso_read_binary(data.len() as u32, 0, None)?;
                let short = chunk.len() < 255;
                data.extend(chunk);
                if short || model::ndef_complete(&data) {
                    break;
                }
            }
            Ok::<_, duox::Error>(data)
        });
        if let Ok(d) = r {
            self.dynamic = d;
            self.refresh_views();
            self.verify_dynamic(shared);
        }
    }

    // ------------------------------------------------------------ keys and verification

    fn ask_keys(&mut self, shared: &mut Shared) {
        let spec = FormSpec::new("Verification keys")
            .note("Used by Verify and Preview. They stay in this window and are not logged or stored.")
            .ok_text("Use these keys");
        shared.ask(self.key_fields(spec, shared), ASK_KEYS);
    }

    fn key_fields(&self, spec: FormSpec, shared: &Shared) -> FormSpec {
        let labels = card_labels(shared);
        let mut options: Vec<&str> = vec!["(none - use the hex field)"];
        options.extend(labels.iter().map(String::as_str));
        let selected = labels.iter().position(|l| *l == self.keys.sig_card).map_or(0, |i| i + 1);
        let saved = shared.store.aes_key_names().join(", ");
        let hint = if saved.is_empty() {
            "32 hex digits".to_string()
        } else {
            format!("32 hex digits or a saved key name ({saved})")
        };
        spec.text("meta", "SDMMetaRead key", &self.keys.meta)
            .hint(hint.clone())
            .text("file", "SDMFileRead key", &self.keys.file)
            .hint(hint)
            .combo("sig_card", "SDMSIG key of card", &options, selected)
            .hint("A card identity from the CAs & certificates tab")
            .hex("sig_hex", "or public key", &self.keys.sig_hex)
            .hint("65 bytes: 04 || x || y")
    }

    fn read_keys(&self, v: &FormValues, shared: &Shared) -> Result<KeyInput, String> {
        let k = KeyInput {
            meta: v.get_str("meta").unwrap_or_default().trim().to_string(),
            file: v.get_str("file").unwrap_or_default().trim().to_string(),
            sig_card: match v.get_index("sig_card").unwrap_or(0) {
                0 => String::new(),
                _ => v.get_str("sig_card").unwrap_or_default().to_string(),
            },
            sig_hex: hex::spaced(&v.get_hex("sig_hex").unwrap_or_default()),
        };
        resolve_aes(shared, &k.meta, "SDMMetaRead key")?;
        resolve_aes(shared, &k.file, "SDMFileRead key")?;
        if k.sig_card.is_empty() && !k.sig_hex.is_empty() {
            model::parse_sig_pub(&hex::parse(&k.sig_hex)?)?;
        }
        Ok(k)
    }

    /// Resolve the keys the settings call for.
    fn resolve_keys(&self, shared: &Shared, cfg: &SdmSettings) -> Result<ResolvedKeys, String> {
        let meta = (cfg.meta_read <= 0xD)
            .then(|| resolve_aes(shared, &self.keys.meta, "SDMMetaRead key"))
            .transpose()?;
        let file = (cfg.file_read != sdm::AC_NONE)
            .then(|| resolve_aes(shared, &self.keys.file, "SDMFileRead key"))
            .transpose()?;
        let sig_pub = if cfg.file_read2 == sdm::AC_NONE {
            None
        } else if !self.keys.sig_card.is_empty() {
            let e = shared
                .store
                .by_kind(&[CertKind::Card])
                .into_iter()
                .find(|e| shared.store.label(e) == self.keys.sig_card)
                .ok_or("The chosen card identity is no longer in the store. Pick it again under Keys.")?;
            Some(e.public_key().map_err(|e| e.to_string())?)
        } else if !self.keys.sig_hex.is_empty() {
            Some(model::parse_sig_pub(&hex::parse(&self.keys.sig_hex)?)?)
        } else {
            None
        };
        Ok(ResolvedKeys { meta, file, sig_pub })
    }

    fn verify_dynamic(&mut self, shared: &mut Shared) {
        if self.dynamic.is_empty() {
            shared.report_error("There is no dynamic data. Read the file unauthenticated or paste the data with Edit.");
            return;
        }
        let uid = shared.card.as_ref().map(|c| c.uid().to_vec()).filter(|u| !u.is_empty());
        let uid_len = self.effective_uid_len(shared);
        let data = self.dynamic.clone();
        match self.run_verify(shared, &data, false, uid, uid_len, None) {
            Ok(s) => self.set_out(s),
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    fn run_verify(
        &self,
        shared: &Shared,
        data: &[u8],
        is_url: bool,
        uid: Option<Vec<u8>>,
        uid_len: usize,
        last_ctr: Option<u32>,
    ) -> Result<String, String> {
        let keys = self.resolve_keys(shared, &self.cfg)?;
        let params = VerifyParams {
            uid_len,
            meta_key: keys.meta.as_deref(),
            file_key: keys.file.as_deref(),
            sig_pub: keys.sig_pub.as_ref(),
            uid: uid.as_deref(),
            last_ctr,
        };
        let (r, ndef) = if is_url {
            let url = std::str::from_utf8(data).map_err(|_| "The URL is not valid text.".to_string())?;
            (sdm::verify_url(url, &self.cfg, &params), sdm::ndef_file_from_url(url))
        } else {
            (sdm::verify(data, &self.cfg, &params), data.to_vec())
        };
        let r = r.map_err(|e| e.to_string())?;
        Ok(model::verify_report(&r, &self.cfg, &ndef))
    }

    fn ask_url(&mut self, shared: &mut Shared) {
        let spec = FormSpec::new("Verify a URL like a back end")
            .note(
                "Paste the URL a reader received. It is checked against the SDM settings shown in the editor, so \
                 build or load the settings of the card's file first. No card is needed.",
            )
            .ok_text("Verify")
            .multiline("url", "URL", "")
            .int_range("last", "Last accepted counter", -1, -1, 0xFF_FFFF)
            .hint("-1 = no replay check; otherwise the counter must be larger")
            .hex_len("uid", "Real UID", "", 0, 10)
            .hint("Optional, 7 or 10 bytes: needed when the card mirrors a random ID or no UID");
        shared.ask(self.key_fields(spec, shared), ASK_URL);
    }

    fn verify_url(&mut self, v: &FormValues, shared: &mut Shared) {
        let url = v.get_str("url").unwrap_or_default().trim().to_string();
        if url.is_empty() {
            shared.report_error("Paste the URL to verify.");
            return;
        }
        let uid = v.get_hex("uid").unwrap_or_default();
        if !matches!(uid.len(), 0 | 7 | 10) {
            shared.report_error("The UID has 7 or 10 bytes (or leave it empty).");
            return;
        }
        match self.read_keys(v, shared) {
            Ok(k) => self.keys = k,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        }
        let uid_len = if uid.is_empty() { self.uid_len } else { uid.len() };
        let last = model::offset_from_form(v.get_int("last").unwrap_or(-1));
        let uid = (!uid.is_empty()).then_some(uid);
        match self.run_verify(shared, url.as_bytes(), true, uid, uid_len, last) {
            Ok(s) => self.set_out(s),
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    fn preview(&mut self, shared: &mut Shared) {
        if self.content.is_empty() {
            shared.report_error("There is no static content to render. Build it from a template or enter it with Edit.");
            return;
        }
        let uid_len = self.effective_uid_len(shared);
        let uid = shared
            .card
            .as_ref()
            .map(|c| c.uid().to_vec())
            .filter(|u| u.len() == uid_len)
            .unwrap_or_else(|| model::placeholder_uid(uid_len));
        let keys = match self.resolve_keys(shared, &self.cfg) {
            Ok(k) => k,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        // Signing needs the card identity's private key from the store.
        let mut sig_key = None;
        if self.cfg.file_read2 != sdm::AC_NONE && !self.keys.sig_card.is_empty() {
            let id = shared
                .store
                .by_kind(&[CertKind::Card])
                .into_iter()
                .find(|e| shared.store.label(e) == self.keys.sig_card && e.has_key())
                .map(|e| e.id.clone());
            match id {
                Some(id) => match shared.with_store(|s| s.key_of(&id)) {
                    Ok(k) => sig_key = Some(k),
                    Err(_) => return,
                },
                None => {
                    shared.report_error("The chosen card identity has no private key in the store, so SDMSIG cannot be rendered.");
                    return;
                }
            }
        }
        let rk = RenderKeys { meta_key: keys.meta.as_deref(), file_key: keys.file.as_deref(), sig_key: sig_key.as_ref() };
        match sdm::render(&self.content, &self.cfg, &uid, 1, &rk, b"000", false) {
            Ok(d) => {
                self.set_out(format!(
                    "Local rendering for UID {}, SDMReadCtr 1 (not read from a card)\n\n{}",
                    hex::spaced(&uid),
                    hex::dump(&d)
                ));
                self.dynamic = d;
                self.refresh_views();
            }
            Err(e) => {
                shared.report_error(e.to_string());
            }
        }
    }

    // ------------------------------------------------------------ view

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let on = shared.is_connected();

        let file_row = buttons(vec![
            text("File").into(),
            text_input("02", &self.file_no).on_input(Message::FileNo).font(theme::MONO).width(56).into(),
            action("Load from card", Message::Load, on),
            action("Create file...", Message::Create, on),
            action("Write content", Message::WriteContent, on),
            action("Apply SDM settings", Message::Apply, on),
            action("Disable SDM", Message::Disable, on),
            action("Read counter", Message::Counter, on),
        ]);

        let lines = self.cfg.describe();
        let (left, right) = lines.split_at(lines.len().min(5));
        let settings = column![
            buttons(vec![
                widgets::primary("Build from template...", Message::Template).into(),
                widgets::secondary("Edit settings...", Message::EditSettings).into(),
                widgets::secondary("Validate", Message::Validate).into(),
                text("UID bytes").into(),
                pick_list(vec![7usize, 10], Some(self.uid_len), Message::UidLen).into(),
            ]),
            row![
                container(widgets::mono(left.join("\n"))).width(Length::FillPortion(1)),
                container(widgets::mono(right.join("\n"))).width(Length::FillPortion(1)),
            ]
            .spacing(theme::SPACE_LG),
        ]
        .spacing(theme::SPACE_SM);

        let content = column![
            container(self.content_view.view().map(Message::ViewContent)).height(84),
            buttons(vec![
                widgets::secondary("Edit...", Message::EditContent).into(),
                widgets::secondary("Copy", Message::CopyContent).into(),
            ]),
        ]
        .spacing(theme::SPACE_SM);
        let dynamic = column![
            container(self.dynamic_view.view().map(Message::ViewDynamic)).height(84),
            buttons(vec![
                widgets::secondary("Edit...", Message::EditDynamic).into(),
                widgets::secondary("Copy", Message::CopyDynamic).into(),
            ]),
        ]
        .spacing(theme::SPACE_SM);

        let verify = buttons(vec![
            action("Read unauthenticated", Message::ReadNative, on),
            action("Read as NDEF (ISO)...", Message::ReadIso, on),
            widgets::primary("Verify", Message::Verify).into(),
            widgets::secondary("Preview", Message::Preview).into(),
            widgets::secondary("Keys...", Message::Keys).into(),
            widgets::secondary("Verify URL...", Message::VerifyUrl).into(),
        ]);

        let controls = scrollable(
            column![
                file_row,
                widgets::group("Template and SDM settings", settings),
                row![
                    container(widgets::group("Static file content (hex)", content)).width(Length::FillPortion(1)),
                    container(widgets::group("Dynamic data as read unauthenticated (hex)", dynamic)).width(Length::FillPortion(1)),
                ]
                .spacing(theme::SPACE_MD),
                widgets::group("Read and verify like a back end", column![
                    verify,
                    widgets::hint("An unauthenticated read increments SDMReadCtr. Verify and Preview use the keys from Keys...; Verify URL needs no card."),
                ].spacing(theme::SPACE_SM)),
            ]
            .spacing(theme::SPACE_MD)
            .padding([theme::SPACE_SM, 0.0]),
        )
        .height(Length::FillPortion(3));

        let output = column![
            row![text("Result").size(theme::TEXT_HEADING), widgets::secondary("Copy", Message::CopyOut)]
                .spacing(theme::SPACE_MD)
                .align_y(iced::Alignment::Center),
            container(self.out.view().map(Message::ViewOut)).height(Length::Fill),
        ]
        .spacing(theme::SPACE_XS)
        .height(Length::FillPortion(2));

        column![controls, output].spacing(theme::SPACE_SM).into()
    }
}

// ---------------------------------------------------------------- free helpers

/// Labels of the card identities in the store, as shown in the key form.
fn card_labels(shared: &Shared) -> Vec<String> {
    shared.store.by_kind(&[CertKind::Card]).into_iter().map(|e| shared.store.label(e)).collect()
}

/// A saved key name or hex, as an AES key (16 or 32 bytes).
fn resolve_aes(shared: &Shared, text: &str, what: &str) -> Result<Vec<u8>, String> {
    let k = shared.store.resolve_aes_key(text).map_err(|e| format!("{what}: {e}"))?;
    if k.len() != 16 && k.len() != 32 {
        return Err(format!("{what} must be 16 or 32 bytes (32 or 64 hex digits), not {}.", k.len()));
    }
    Ok(k)
}

/// Bytes from a hex field or, when a file is chosen, from that file.
fn read_bytes_form(v: &FormValues, shared: &mut Shared) -> Option<Vec<u8>> {
    match v.get_path("file").unwrap_or(None) {
        Some(p) => match crate::ui::files::read_file(&p) {
            Ok(b) => Some(b),
            Err(e) => {
                shared.report_error(e);
                None
            }
        },
        None => v.get_hex("data").ok(),
    }
}
