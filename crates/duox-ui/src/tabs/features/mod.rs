//! ISO / GPIO / EV tab: ISO/IEC 7816-4 file commands, fast confidential UID retrieval, two
//! applications selected at once, proximity check, GPIO and EV charging (VDE-AR-E 2532-100).
//!
//! Every input goes through a form; results are written to one selectable text view. Conditions
//! that can be known from cached state (connection, authentication, selection, saved keys) are
//! checked before anything is sent to the card.

mod apps;
mod ev;
mod gpio;
mod iso;
mod plan;
mod report;
mod view;

use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::textview::TextView;
use crate::ui::clipboard;
use duox::card::CommMode;
use iced::widget::text_editor;
use iced::Task;
use std::fmt;

/// Tokens that identify which form was answered.
mod token {
    pub const SELECT_DF: u32 = 1;
    pub const SELECT_EF: u32 = 2;
    pub const CHALLENGE: u32 = 3;
    pub const READ_BINARY: u32 = 4;
    pub const UPDATE_BINARY: u32 = 5;
    pub const READ_RECORD: u32 = 6;
    pub const APPEND_RECORD: u32 = 7;
    pub const FAST_UID: u32 = 8;
    pub const SELECT_TWO: u32 = 9;
    pub const SECOND_SETTINGS: u32 = 10;
    pub const SECOND_READ: u32 = 11;
    pub const SECOND_WRITE: u32 = 12;
    pub const PROXIMITY: u32 = 13;
    pub const GPIO_CONFIG: u32 = 14;
    pub const GPIO_MANAGE: u32 = 15;
    pub const GPIO_READ: u32 = 16;
    pub const EV_PROVISION: u32 = 17;
    pub const EV_WRITE: u32 = 18;
    pub const EV_LOCK: u32 = 19;
}

/// Buttons of the tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    SelectDf,
    SelectEf,
    SelectMf,
    GetChallenge,
    ReadBinary,
    UpdateBinary,
    ReadRecord,
    AppendRecord,
    FastUid,
    SelectTwo,
    SecondSettings,
    SecondRead,
    SecondWrite,
    Proximity,
    GpioConfig,
    GpioManage,
    GpioRead,
    EvProvision,
    EvRead,
    EvChallenge,
    EvData,
    EvWrite,
    EvLock,
}

#[derive(Debug, Clone)]
pub enum Message {
    /// Answer to `Shared::ask` / `confirm`. `values` is `None` when cancelled or answered "no".
    FormDone { token: u32, values: Option<FormValues> },
    /// Broadcast from the application (connect, disconnect, store changed, tab activated).
    Event(AppEvent),
    Do(Action),
    CaPicked(CaChoice),
    View(text_editor::Action),
    Copy,
    Clear,
}

/// A CA of the store that can be used as certificate issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaChoice {
    id: String,
    label: String,
    has_key: bool,
}

impl fmt::Display for CaChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

/// Values the forms start with: what was entered last.
#[derive(Debug, Clone)]
struct Remembered {
    df_name: String,
    file_id: u64,
    offset: i64,
    length: i64,
    use_sfi: bool,
    sfi: u64,
    record: i64,
    aid1: u64,
    aid2: u64,
    second_file: u64,
    split: String,
    gpio_no: usize,
    gpio_op: usize,
    comm_mode: usize,
}

impl Default for Remembered {
    fn default() -> Self {
        Remembered {
            // The registered application name of the NFC Forum type 4 tag application.
            df_name: "D2760000850101".into(),
            file_id: 0xE103,
            offset: 0,
            length: 0,
            use_sfi: false,
            sfi: 1,
            record: 1,
            aid1: 0,
            aid2: 0,
            second_file: 1,
            split: "8".into(),
            gpio_no: 0,
            gpio_op: 1,
            comm_mode: 1,
        }
    }
}

#[derive(Default)]
pub struct State {
    out: TextView,
    last: Remembered,
    cas: Vec<CaChoice>,
    ca: Option<String>,
    /// Certificate read from (or written to) the card, to save a read for the challenge.
    cert: Vec<u8>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State").field("ca", &self.ca).field("cert_len", &self.cert.len()).finish()
    }
}

impl State {
    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::Do(a) => self.start(a, shared),
            Message::FormDone { token, values: Some(v) } => self.form_done(token, &v, shared),
            Message::FormDone { .. } => {}
            Message::Event(ev) => self.on_event(ev, shared),
            Message::CaPicked(c) => self.ca = Some(c.id),
            Message::View(a) => self.out.perform(a),
            Message::Copy => {
                let text = self.out.selection().unwrap_or_else(|| self.out.text());
                return clipboard::copy(text);
            }
            Message::Clear => self.out.set_text(""),
        }
        Task::none()
    }

    fn on_event(&mut self, ev: AppEvent, shared: &Shared) {
        match ev {
            AppEvent::Connected | AppEvent::Disconnected => {
                self.cert.clear();
                if ev == AppEvent::Disconnected {
                    self.out.set_text("");
                }
                self.reload_cas(shared);
            }
            AppEvent::StoreChanged | AppEvent::Activated => self.reload_cas(shared),
        }
    }

    /// A button was pressed: open its form or run the command.
    fn start(&mut self, a: Action, shared: &mut Shared) {
        match a {
            Action::SelectDf | Action::SelectEf | Action::SelectMf | Action::GetChallenge | Action::ReadBinary
            | Action::UpdateBinary | Action::ReadRecord | Action::AppendRecord | Action::FastUid => {
                self.start_iso(a, shared)
            }
            Action::SelectTwo | Action::SecondSettings | Action::SecondRead | Action::SecondWrite
            | Action::Proximity => self.start_apps(a, shared),
            Action::GpioConfig | Action::GpioManage | Action::GpioRead => self.start_gpio(a, shared),
            Action::EvProvision | Action::EvRead | Action::EvChallenge | Action::EvData | Action::EvWrite
            | Action::EvLock => self.start_ev(a, shared),
        }
    }

    fn form_done(&mut self, token: u32, v: &FormValues, shared: &mut Shared) {
        use token::*;
        match token {
            SELECT_DF | SELECT_EF | CHALLENGE | READ_BINARY | UPDATE_BINARY | READ_RECORD | APPEND_RECORD
            | FAST_UID => self.iso_done(token, v, shared),
            SELECT_TWO | SECOND_SETTINGS | SECOND_READ | SECOND_WRITE | PROXIMITY => {
                self.apps_done(token, v, shared)
            }
            GPIO_CONFIG | GPIO_MANAGE | GPIO_READ => self.gpio_done(token, v, shared),
            EV_PROVISION | EV_WRITE | EV_LOCK => self.ev_done(token, v, shared),
            _ => {}
        }
    }

    fn show(&mut self, text: impl AsRef<str>) {
        self.out.set_text(text.as_ref());
    }
}

// ------------------------------------------------------------------ helpers shared by the parts

const COMM_MODES: [&str; 3] = ["Plain", "MAC", "Full"];

fn comm_mode(index: usize) -> CommMode {
    match index {
        0 => CommMode::Plain,
        1 => CommMode::Mac,
        _ => CommMode::Full,
    }
}

fn comm_index(mode: CommMode) -> usize {
    match mode {
        CommMode::Plain => 0,
        CommMode::Mac => 1,
        CommMode::Full => 2,
    }
}

fn is_authenticated(shared: &Shared) -> bool {
    shared.card.as_ref().is_some_and(|c| c.is_authenticated())
}

/// The plain ISO and EV commands are refused by the card in an authenticated session (and the
/// refusal would end that session): say so before sending.
fn require_unauthenticated(shared: &mut Shared, command: &str) -> bool {
    if is_authenticated(shared) {
        shared.report_error(format!(
            "{command} is a plain command and is only accepted while no authentication is active. \
             Select the application again (for example with 'Select DF name...') to end the \
             authentication, then repeat it."
        ));
        return false;
    }
    true
}

/// Add a key chooser (saved key or hex) to a form. The answer is read with [`read_key`].
fn key_chooser(spec: FormSpec, shared: &Shared, prefix: &str, label: &str, default_hex: &str) -> FormSpec {
    let names = shared.store.aes_key_names();
    let mut options: Vec<&str> = vec![plan::KEY_HEX];
    options.extend(names);
    spec.combo(&format!("{prefix}_name"), label, &options, 0)
        .hint("A key saved in the key store, or the hex field below.")
        .hex_len(&format!("{prefix}_hex"), "Key (hex)", default_hex, 0, 32)
}

fn read_key(shared: &Shared, v: &FormValues, prefix: &str) -> Result<Option<Vec<u8>>, String> {
    let choice = v.get_str(&format!("{prefix}_name")).unwrap_or(plan::KEY_HEX).to_string();
    let hex = v.get_hex(&format!("{prefix}_hex")).unwrap_or_default();
    plan::pick_key(&choice, &hex, |n| shared.store.aes_key(n))
}

impl State {
    /// Refill the issuer list from the store, keeping the selection when possible.
    fn reload_cas(&mut self, shared: &Shared) {
        use duox::pki::CertKind;
        self.cas = shared
            .store
            .by_kind(&[CertKind::Root, CertKind::Sub])
            .into_iter()
            .map(|e| CaChoice {
                id: e.id.clone(),
                label: format!("{}  ({})", e.name, duox::crypto::curve_name(e.curve)),
                has_key: e.has_key(),
            })
            .collect();
        if !self.ca.as_ref().is_some_and(|id| self.cas.iter().any(|c| &c.id == id)) {
            self.ca = self.cas.first().map(|c| c.id.clone());
        }
    }

    fn selected_ca(&self) -> Option<&CaChoice> {
        self.ca.as_ref().and_then(|id| self.cas.iter().find(|c| &c.id == id))
    }
}
