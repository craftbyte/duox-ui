//! Configuration and tools tab: card level commands, Get/SetConfiguration, key sets, CryptoRequest
//! and raw commands.

mod model;

use crate::app;
use crate::shared::{AppEvent, DynCard, Shared};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::textview::TextView;
use crate::ui::{clipboard, hex, theme, widgets};
use duox::card::{AccessRight, Aid, CommMode, SignInput};
use iced::widget::{column, container, pick_list, row, scrollable, text, text_editor, Row};
use iced::{Element, Length, Task};

const ASK_CFG_SET: u32 = 1;
const ASK_SIGN: u32 = 2;
const ASK_ECHO: u32 = 3;
const ASK_KS_INIT: u32 = 4;
const ASK_KS_FINAL: u32 = 5;
const ASK_KS_ROLL: u32 = 6;
const ASK_KEY_VERSION: u32 = 7;
const ASK_RAW_NATIVE: u32 = 8;
const ASK_RAW_APDU: u32 = 9;
const CONFIRM_FORMAT: u32 = 10;
const CONFIRM_CFG: u32 = 11;
const CONFIRM_ROLL: u32 = 12;
const CONFIRM_RAW: u32 = 13;

const MODES: [&str; 3] = ["Plain", "MAC", "Full"];

/// An action that waits for the user's confirmation.
#[derive(Debug, Clone)]
enum Pending {
    Config(u8, Vec<u8>),
    Roll(u8),
    Native(u8, Vec<u8>),
    Apdu(Vec<u8>),
}

pub struct State {
    /// Selected option of Get/SetConfiguration (index into the option table).
    cfg_index: usize,
    /// Data of the last GetConfiguration, offered as the default of the Set form.
    cfg_data: Vec<u8>,
    /// CommMode of CryptoRequest: read from option 15, MAC (the default) until then.
    crypto_mode: CommMode,
    pending: Option<Pending>,
    sign_key: i64,
    sign_data: String,
    raw_cmd: u64,
    raw_header: String,
    raw_data: String,
    raw_apdu: String,
    out: TextView,
}

impl Default for State {
    fn default() -> Self {
        let mut s = State {
            cfg_index: model::option_index(0x04),
            cfg_data: Vec::new(),
            crypto_mode: CommMode::Mac,
            pending: None,
            sign_key: 0,
            sign_data: String::new(),
            raw_cmd: 0x6E,
            raw_header: String::new(),
            raw_data: String::new(),
            raw_apdu: String::new(),
            out: TextView::default(),
        };
        let t = s.option_text();
        s.out.set_text(&t);
        s
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("tools::State").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    FormDone { token: u32, values: Option<FormValues> },
    Event(AppEvent),
    Version,
    CardUid,
    FreeMem,
    Format,
    CfgPick(String),
    CfgGet,
    CfgSet,
    CfgManufacturer,
    KsInit,
    KsFinal,
    KsRoll,
    KsVersions,
    KsKeyVersion,
    KsHelp,
    Sign,
    Echo,
    RawNative,
    RawApdu,
    CopyOut,
    ViewOut(text_editor::Action),
}

// ---------------------------------------------------------------- helpers

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

fn mode_of(index: usize) -> CommMode {
    match index {
        1 => CommMode::Mac,
        2 => CommMode::Full,
        _ => CommMode::Plain,
    }
}

fn mode_index(m: CommMode) -> usize {
    match m {
        CommMode::Plain => 0,
        CommMode::Mac => 1,
        CommMode::Full => 2,
    }
}

/// Select the application again, which ends an authentication on the card as well as locally.
fn end_authentication(c: &mut DynCard) -> Result<(), duox::Error> {
    if c.is_authenticated() {
        let sel = c.selection();
        let aid = sel
            .primary
            .ok_or_else(|| duox::Error::InvalidArgument("the selected application is unknown".into()))?;
        c.select_application(aid, sel.secondary)?;
    }
    Ok(())
}

fn action<'a>(label: &str, msg: Message, enabled: bool) -> Element<'a, Message> {
    if enabled {
        widgets::secondary(label, msg).into()
    } else {
        iced::widget::button(text(label.to_string())).padding([5, 14]).into()
    }
}

fn buttons<'a>(items: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    Row::with_children(items).spacing(theme::SPACE_SM).wrap().vertical_spacing(theme::SPACE_SM).into()
}

// ---------------------------------------------------------------- logic

impl State {
    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::FormDone { token, values } => self.form_done(token, values, shared),
            Message::Event(AppEvent::Disconnected) => {
                self.crypto_mode = CommMode::Mac;
                self.cfg_data.clear();
                self.pending = None;
            }
            Message::Event(_) => {}
            Message::Version => {
                if let Ok(v) = shared.with_card(|c| c.get_version()) {
                    self.set_out(model::format_version(&v));
                }
            }
            Message::CardUid => {
                if require_auth(shared, "GetCardUID") {
                    if let Ok(u) = shared.with_card(|c| c.get_card_uid()) {
                        self.set_out(format!(
                            "UID {}\n\nGetCardUID returns the real UID even when Random ID is enabled.",
                            hex::spaced(&u)
                        ));
                    }
                }
            }
            Message::FreeMem => {
                if let Ok(n) = shared.with_card(|c| c.free_mem()) {
                    self.set_out(format!("Free memory: {n} bytes"));
                }
            }
            Message::Format => self.ask_format(shared),
            Message::CfgPick(label) => {
                if let Some(o) = model::option_from_label(&label) {
                    self.cfg_index = model::option_index(o);
                    let t = self.option_text();
                    self.set_out(t);
                }
            }
            Message::CfgGet => self.cfg_get(shared, false),
            Message::CfgManufacturer => self.cfg_get(shared, true),
            Message::CfgSet => self.ask_cfg_set(shared),
            Message::KsInit => self.ask_key_set(shared, ASK_KS_INIT),
            Message::KsFinal => self.ask_key_set(shared, ASK_KS_FINAL),
            Message::KsRoll => self.ask_key_set(shared, ASK_KS_ROLL),
            Message::KsVersions => {
                if let Ok(v) = shared.with_card(|c| c.get_key_set_versions()) {
                    self.set_out(format!(
                        "Key set versions (active set first): {}\nVersion 00 marks a set that is not finalised.",
                        hex::spaced(&v)
                    ));
                }
            }
            Message::KsKeyVersion => self.ask_key_version(shared),
            Message::KsHelp => self.set_out(model::KEY_SET_HELP),
            Message::Sign => self.ask_sign(shared, true),
            Message::Echo => self.ask_sign(shared, false),
            Message::RawNative => self.ask_raw_native(shared),
            Message::RawApdu => self.ask_raw_apdu(shared),
            Message::CopyOut => {
                return clipboard::copy(self.out.selection().unwrap_or_else(|| self.out.text()));
            }
            Message::ViewOut(a) => self.out.perform(a),
        }
        Task::none()
    }

    fn set_out(&mut self, s: impl AsRef<str>) {
        self.out.set_text(s.as_ref());
    }

    fn option(&self) -> u8 {
        model::CONFIG_OPTIONS[self.cfg_index].0
    }

    fn option_text(&self) -> String {
        let o = self.option();
        format!(
            "Option {o:02X} - {}\n\n{}\n\nSetConfiguration is sent with CommMode.Full and needs the PICC / application \
             master key (options 05 and 06 at PICC level: the VC configuration key). Several options are permanent.",
            model::option_name(o),
            model::config_help(o)
        )
    }

    fn form_done(&mut self, token: u32, values: Option<FormValues>, shared: &mut Shared) {
        let Some(v) = values else {
            if matches!(token, CONFIRM_CFG | CONFIRM_ROLL | CONFIRM_RAW) {
                self.pending = None;
            }
            return;
        };
        match token {
            ASK_CFG_SET => self.cfg_set_form(&v, shared),
            ASK_SIGN => self.sign(&v, shared),
            ASK_ECHO => self.echo(&v, shared),
            ASK_KS_INIT => {
                let (set, ty) = (v.get_uint("set").unwrap_or(1) as u8, v.get_index("type").unwrap_or(0));
                // key type codes of InitializeKeySet: 2 = AES-128, 3 = AES-256
                let code = if ty == 1 { 3 } else { 2 };
                if shared.with_card(|c| c.initialize_key_set(set, code)).is_ok() {
                    self.set_out(format!(
                        "Key set {set} initialised for {} keys.\n\n{}",
                        if ty == 1 { "AES-256" } else { "AES-128" },
                        model::KEY_SET_HELP
                    ));
                }
            }
            ASK_KS_FINAL => {
                let (set, ver) = (v.get_uint("set").unwrap_or(1) as u8, v.get_uint("version").unwrap_or(1) as u8);
                if shared.with_card(|c| c.finalize_key_set(set, ver)).is_ok() {
                    self.set_out(format!("Key set {set} finalised with version {ver:02X}; it can be rolled in."));
                }
            }
            ASK_KS_ROLL => {
                let set = v.get_uint("set").unwrap_or(1) as u8;
                self.pending = Some(Pending::Roll(set));
                shared.confirm(
                    "Roll key set",
                    &format!("Roll to key set {set}? The current authentication ends and the old keys stop working."),
                    "Roll",
                    CONFIRM_ROLL,
                );
            }
            ASK_KEY_VERSION => self.key_version(&v, shared),
            ASK_RAW_NATIVE => self.raw_native_form(&v, shared),
            ASK_RAW_APDU => self.raw_apdu_form(&v, shared),
            CONFIRM_FORMAT => self.format_now(shared),
            CONFIRM_CFG | CONFIRM_ROLL | CONFIRM_RAW => match self.pending.take() {
                Some(Pending::Config(o, d)) => self.cfg_set_now(shared, o, d),
                Some(Pending::Roll(set)) => {
                    if shared.with_card(|c| c.roll_key_set(set)).is_ok() {
                        self.set_out(format!("Key set {set} is active. The authentication has ended."));
                    }
                }
                Some(Pending::Native(cmd, payload)) => self.native_now(shared, cmd, payload),
                Some(Pending::Apdu(apdu)) => self.apdu_now(shared, apdu),
                None => {}
            },
            _ => {}
        }
    }

    // ------------------------------------------------------------ format

    fn ask_format(&mut self, shared: &mut Shared) {
        if !require_auth(shared, "Format") {
            return;
        }
        let at_picc = shared.card.as_ref().is_some_and(|c| c.selection().primary == Some(Aid::PICC));
        if !at_picc {
            shared.report_error(
                "Format works at PICC level. Select the PICC (application 000000) and authenticate with the PICC \
                 master key first.",
            );
            return;
        }
        if !shared.card.as_ref().is_some_and(|c| c.has_access_condition(AccessRight::key(0), false)) {
            shared.report_error("Format needs the PICC master key. Authenticate with key 00 at PICC level first.");
            return;
        }
        shared.confirm_danger(
            "Format card",
            "Format erases ALL applications and files on the card and cannot be undone.\n\nContinue?",
            "Format",
            CONFIRM_FORMAT,
        );
    }

    fn format_now(&mut self, shared: &mut Shared) {
        if shared.with_card(|c| c.format()).is_ok() {
            // The session is still valid, so the application list is not read again; after a format
            // there are none.
            if let Some(s) = shared.scan.as_mut() {
                s.applications.clear();
            }
            self.set_out("Card formatted. All applications and files are gone.");
        }
    }

    // ------------------------------------------------------------ configuration

    fn cfg_get(&mut self, shared: &mut Shared, manufacturer: bool) {
        if !require_auth(shared, "GetConfiguration") {
            return;
        }
        if manufacturer {
            if let Ok(d) = shared.with_card(|c| c.get_configuration(None)) {
                self.set_out(format!("Manufacturer data: {}", hex::spaced(&d)));
            }
            return;
        }
        let o = self.option();
        if o == 0x01 {
            shared.report_error("The default application key (option 01) can only be written, not read.");
            return;
        }
        if let Ok(d) = shared.with_card(|c| c.get_configuration(Some(o))) {
            if o == 0x15 {
                if let Some(m) = model::crypto_mode_from_config(&d) {
                    self.crypto_mode = m;
                }
            }
            let decoded = model::describe_config(o, &d).join("\n");
            self.set_out(format!(
                "Option {o:02X} - {}\n{}\n\n{decoded}\n\n{}",
                model::option_name(o),
                hex::spaced(&d),
                model::config_help(o)
            ));
            self.cfg_data = d;
        }
    }

    fn ask_cfg_set(&mut self, shared: &mut Shared) {
        if !require_auth(shared, "SetConfiguration") {
            return;
        }
        let o = self.option();
        shared.ask(
            FormSpec::new(format!("SetConfiguration {o:02X} - {}", model::option_name(o)))
                .note("Some settings cannot be undone. You will be asked to confirm with a decoded summary.")
                .ok_text("Review")
                .info("Layout", model::config_help(o))
                .hex("data", "Data", &hex::spaced(&self.cfg_data)),
            ASK_CFG_SET,
        );
    }

    fn cfg_set_form(&mut self, v: &FormValues, shared: &mut Shared) {
        let o = self.option();
        let data = match model::check_config_data(o, &v.get_hex("data").unwrap_or_default()) {
            Ok(d) => d,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let decoded = model::describe_config(o, &data).join("\n");
        shared.confirm(
            "SetConfiguration",
            &format!(
                "Option {o:02X} ({})\n\ndata {}\n{decoded}\n\nSome settings cannot be undone. Send?",
                model::option_name(o),
                hex::spaced(&data)
            ),
            "Send",
            CONFIRM_CFG,
        );
        self.pending = Some(Pending::Config(o, data));
    }

    fn cfg_set_now(&mut self, shared: &mut Shared, o: u8, data: Vec<u8>) {
        if shared.with_card(|c| c.set_configuration(o, &data)).is_ok() {
            if o == 0x15 {
                if let Some(m) = model::crypto_mode_from_config(&data) {
                    self.crypto_mode = m;
                }
            }
            self.set_out(format!("Option {o:02X} written: {}", hex::spaced(&data)));
            self.cfg_data = data;
        }
    }

    // ------------------------------------------------------------ key sets

    fn ask_key_set(&mut self, shared: &mut Shared, token: u32) {
        let what = match token {
            ASK_KS_INIT => "InitializeKeySet",
            ASK_KS_FINAL => "FinalizeKeySet",
            _ => "RollKeySet",
        };
        if !require_auth(shared, what) {
            return;
        }
        let mut spec = FormSpec::new(match token {
            ASK_KS_INIT => "Initialize key set",
            ASK_KS_FINAL => "Finalize key set",
            _ => "Roll key set",
        })
        .ok_text(match token {
            ASK_KS_INIT => "Initialize",
            ASK_KS_FINAL => "Finalize",
            _ => "Continue",
        })
        .hex_int_range("set", "Key set number", 1, 1, 1, 0xF)
        .hint("1 is the set after the active one; the active set (0) cannot be targeted");
        spec = match token {
            ASK_KS_INIT => spec.combo("type", "Key type", &["AES-128", "AES-256"], 0),
            ASK_KS_FINAL => spec
                .hex_int_range("version", "Key set version", 1, 2, 1, 0xFF)
                .hint("Must be higher than the active set's version to be rollable; 00 is not allowed"),
            _ => spec,
        };
        shared.ask(spec, token);
    }

    fn ask_key_version(&mut self, shared: &mut Shared) {
        if !require_card(shared) {
            return;
        }
        shared.ask(
            FormSpec::new("Key version")
                .ok_text("Read")
                .hex_int_range("key", "Key number", 0, 2, 0, 0x3F)
                .check("use_set", "Address a key set", false)
                .int_range("set", "Key set number", 0, 0, 15)
                .hint("Relative to the active set; ignored unless the box above is ticked")
                .check("second", "Key of the second application", false),
            ASK_KEY_VERSION,
        );
    }

    fn key_version(&mut self, v: &FormValues, shared: &mut Shared) {
        let mut key = v.get_uint("key").unwrap_or(0) as u8;
        let set = v.get_bool("use_set").unwrap_or(false).then(|| v.get_uint("set").unwrap_or(0) as u8);
        if v.get_bool("second").unwrap_or(false) {
            if !shared.card.as_ref().is_some_and(|c| c.selection().secondary.is_some()) {
                shared.report_error(
                    "No second application is selected, so there is no second application key to ask for.",
                );
                return;
            }
            key |= 0x80;
        }
        if let Ok(ver) = shared.with_card(|c| c.get_key_version(key, set)) {
            self.set_out(format!(
                "Key {:02X}{}{}: version {}",
                key & 0x3F,
                if key & 0x80 != 0 { " of the second application" } else { "" },
                set.map(|s| format!(" in key set {s}")).unwrap_or_default(),
                hex::spaced(&ver)
            ));
        }
    }

    // ------------------------------------------------------------ CryptoRequest

    fn ask_sign(&mut self, shared: &mut Shared, sign: bool) {
        if !require_card(shared) {
            return;
        }
        let mut spec = FormSpec::new(if sign { "ECC signature by the card" } else { "CryptoRequest Echo" })
            .note(
                "CryptoRequest must have been enabled with option 15. The CommMode below defaults to what \
                 GetConfiguration 15 reported (MAC if it was not read).",
            )
            .ok_text(if sign { "Sign" } else { "Echo" });
        if sign {
            spec = spec
                .int_range("key", "ECC key number", self.sign_key, 0, 255)
                .hex("data", "Data", &self.sign_data)
                .hint("Input of the card's SHA-256. More than 224 bytes are sent as initialize / update / finalize")
                .check("hash", "Data is a SHA-256 hash (32 bytes)", false);
        } else {
            spec = spec.hex_len("data", "Data", &self.sign_data, 1, 254);
        }
        shared.ask(
            spec.combo("mode", "CommMode", &MODES, mode_index(self.crypto_mode)),
            if sign { ASK_SIGN } else { ASK_ECHO },
        );
    }

    fn sign(&mut self, v: &FormValues, shared: &mut Shared) {
        let key = v.get_int("key").unwrap_or(0);
        let data = v.get_hex("data").unwrap_or_default();
        let is_hash = v.get_bool("hash").unwrap_or(false);
        let mode = mode_of(v.get_index("mode").unwrap_or(1));
        self.sign_key = key;
        self.sign_data = hex::spaced(&data);
        if data.is_empty() {
            shared.report_error("Enter the data to sign (hex).");
            return;
        }
        if is_hash && data.len() != 32 {
            shared.report_error(format!("A SHA-256 hash is 32 bytes; {} were given.", data.len()));
            return;
        }
        if mode != CommMode::Plain && !require_auth(shared, "CryptoRequest in MAC / Full mode") {
            return;
        }
        let input = if is_hash { SignInput::Hash(&data) } else { SignInput::Raw(&data) };
        if let Ok(sig) = shared.with_card(|c| c.crypto_ecc_sign(key as u8, input, mode)) {
            self.crypto_mode = mode;
            let how = if is_hash {
                "Sent as a pre-computed hash.".to_string()
            } else if model::sign_frames(data.len()) == 1 {
                "Sent as one command.".to_string()
            } else {
                format!("Sent as initialize / update / finalize ({} commands).", model::sign_frames(data.len()))
            };
            let (r, s) = sig.split_at(sig.len() / 2);
            self.set_out(format!(
                "ECDSA-SHA256 signature by key {key} over {} (r || s):\n{}\n\nr  {}\ns  {}\n\n{how}",
                if is_hash { "the given hash".to_string() } else { format!("{} bytes", data.len()) },
                hex::spaced(&sig),
                hex::spaced(r),
                hex::spaced(s)
            ));
        }
    }

    fn echo(&mut self, v: &FormValues, shared: &mut Shared) {
        let data = v.get_hex("data").unwrap_or_default();
        let mode = mode_of(v.get_index("mode").unwrap_or(1));
        self.sign_data = hex::spaced(&data);
        if mode != CommMode::Plain && !require_auth(shared, "CryptoRequest in MAC / Full mode") {
            return;
        }
        if let Ok(back) = shared.with_card(|c| c.crypto_echo(&data, mode)) {
            self.crypto_mode = mode;
            let verdict = if back == data {
                " - identical.".to_string()
            } else {
                format!(" - DIFFERENT:\n{}", hex::spaced(&back))
            };
            self.set_out(format!("CryptoRequest Echo: sent {} bytes, received {}{verdict}", data.len(), back.len()));
        }
    }

    // ------------------------------------------------------------ raw commands

    /// Can a raw command go out? It ends an authentication, which needs the application to be known.
    fn raw_precondition(shared: &mut Shared) -> bool {
        if !require_card(shared) {
            return false;
        }
        if authenticated(shared) && shared.card.as_ref().is_some_and(|c| c.selection().primary.is_none()) {
            shared.report_error(
                "A raw command ends the authentication, which needs the selected application to be known. \
                 Select the application on the Card tab first.",
            );
            return false;
        }
        true
    }

    fn ask_raw_native(&mut self, shared: &mut Shared) {
        if !Self::raw_precondition(shared) {
            return;
        }
        shared.ask(
            FormSpec::new("Raw native command")
                .note(
                    "Sent as a native command without secure messaging; additional frames are followed. An \
                     active authentication is ended first. The command may change the card.",
                )
                .ok_text("Send")
                .hex_int_range("cmd", "Command code", self.raw_cmd, 2, 0, 0xFF)
                .hex("header", "Header", &self.raw_header)
                .hex("data", "Data", &self.raw_data),
            ASK_RAW_NATIVE,
        );
    }

    fn raw_native_form(&mut self, v: &FormValues, shared: &mut Shared) {
        let cmd = v.get_uint("cmd").unwrap_or(0) as u8;
        let (header, data) = (v.get_hex("header").unwrap_or_default(), v.get_hex("data").unwrap_or_default());
        self.raw_cmd = u64::from(cmd);
        self.raw_header = hex::spaced(&header);
        self.raw_data = hex::spaced(&data);
        let payload = [header, data].concat();
        if authenticated(shared) {
            shared.confirm(
                "Raw native command",
                "A raw command bypasses secure messaging. The current authentication is ended first (the \
                 application is selected again). Continue?",
                "Send",
                CONFIRM_RAW,
            );
            self.pending = Some(Pending::Native(cmd, payload));
        } else {
            self.native_now(shared, cmd, payload);
        }
    }

    fn native_now(&mut self, shared: &mut Shared, cmd: u8, payload: Vec<u8>) {
        let r = shared.with_card(|c| {
            end_authentication(c)?;
            c.native_raw(cmd, &payload)
        });
        if let Ok((rc, frames)) = r {
            self.set_out(model::format_native(rc, &frames));
        }
    }

    fn ask_raw_apdu(&mut self, shared: &mut Shared) {
        if !Self::raw_precondition(shared) {
            return;
        }
        shared.ask(
            FormSpec::new("Raw APDU")
                .note(
                    "Sent as is, outside secure messaging. An active authentication is ended first (the \
                     application is selected again).",
                )
                .ok_text("Send")
                .hex_len("apdu", "APDU", &self.raw_apdu, 4, 65_550),
            ASK_RAW_APDU,
        );
    }

    fn raw_apdu_form(&mut self, v: &FormValues, shared: &mut Shared) {
        let apdu = v.get_hex("apdu").unwrap_or_default();
        self.raw_apdu = hex::spaced(&apdu);
        if authenticated(shared) {
            shared.confirm(
                "Raw APDU",
                "A raw APDU bypasses secure messaging. The current authentication is ended first (the application \
                 is selected again). Continue?",
                "Send",
                CONFIRM_RAW,
            );
            self.pending = Some(Pending::Apdu(apdu));
        } else {
            self.apdu_now(shared, apdu);
        }
    }

    fn apdu_now(&mut self, shared: &mut Shared, apdu: Vec<u8>) {
        let r = shared.with_card(|c| {
            end_authentication(c)?;
            c.apdu_raw(&apdu)
        });
        if let Ok((data, sw)) = r {
            self.set_out(model::format_apdu(sw, &data));
        }
    }

    // ------------------------------------------------------------ view

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let on = shared.is_connected();

        let format_button: Element<'_, Message> = if on {
            widgets::danger("Format card...", Message::Format).into()
        } else {
            iced::widget::button(text("Format card...")).padding([5, 14]).into()
        };
        let card = widgets::group(
            "Card",
            buttons(vec![
                action("GetVersion", Message::Version, on),
                action("GetCardUID", Message::CardUid, on),
                action("FreeMem", Message::FreeMem, on),
                format_button,
            ]),
        );

        let config = widgets::group(
            "Configuration (GetConfiguration / SetConfiguration)",
            column![
                pick_list(model::option_labels(), Some(model::option_label(self.cfg_index)), Message::CfgPick)
                    .width(Length::Fill),
                buttons(vec![
                    action("Get", Message::CfgGet, on),
                    action("Set...", Message::CfgSet, on),
                    action("Manufacturer data", Message::CfgManufacturer, on),
                ]),
                widgets::hint(model::config_help(self.option())),
            ]
            .spacing(theme::SPACE_SM),
        );

        let key_sets = widgets::group(
            "Key sets",
            buttons(vec![
                action("Initialize...", Message::KsInit, on),
                action("Finalize...", Message::KsFinal, on),
                action("Roll...", Message::KsRoll, on),
                action("Key set versions", Message::KsVersions, on),
                action("Key version...", Message::KsKeyVersion, on),
                widgets::secondary("How to...", Message::KsHelp).into(),
            ]),
        );

        let crypto = widgets::group(
            "CryptoRequest (ECC signature by the card)",
            column![
                buttons(vec![action("Sign...", Message::Sign, on), action("Echo...", Message::Echo, on)]),
                widgets::hint(format!("CommMode offered: {}", self.crypto_mode)),
            ]
            .spacing(theme::SPACE_SM),
        );

        let raw = widgets::group(
            "Raw commands",
            column![
                buttons(vec![
                    action("Send native command...", Message::RawNative, on),
                    action("Send APDU...", Message::RawApdu, on),
                ]),
                widgets::hint(
                    "Raw commands run outside secure messaging and end an active authentication (the application \
                     is selected again). Use them with care: they can change the card.",
                ),
            ]
            .spacing(theme::SPACE_SM),
        );

        let controls = scrollable(
            column![
                row![card, key_sets].spacing(theme::SPACE_MD),
                config,
                row![crypto, raw].spacing(theme::SPACE_MD),
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
        .height(Length::FillPortion(3));

        column![controls, output].spacing(theme::SPACE_SM).into()
    }
}
