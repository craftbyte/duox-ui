//! Application shell: window layout, connection handling, tab routing and modal dialogs.
//!
//! Adding behaviour to a tab never requires touching this file: tabs talk to the shell through
//! [`Shared`] (dialog requests, events, card and store access) and through the `Task`s they
//! return (e.g. `Task::done(app::Message::Goto(TabId::Auth))`).

use crate::log::{LineKind, LogBuf};
use crate::shared::{AppEvent, DialogRequest, Shared, UNLOCK_TOKEN};
use crate::tabs::{self, TabId};
use crate::ui::form::{DialogState, FormMsg, FormValues, Outcome};
use crate::ui::{clipboard, files, hex, style, textview::TextView, theme, widgets};
use duox::card::Card;
use duox::pki::PkiStore;
use duox::transport::{self, Transport};
use iced::widget::{
    checkbox, column, container, opaque, operation, pick_list, row, stack, text, text_editor, Space,
};
use iced::{keyboard, theme as iced_theme, Element, Length, Subscription, Task, Theme};
use std::collections::VecDeque;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Message {
    // One variant per tab; each wraps that tab's own message type.
    Card(tabs::card::Message),
    Auth(tabs::auth::Message),
    Pki(tabs::pki::Message),
    Crl(tabs::crl::Message),
    Sdm(tabs::sdm::Message),
    Delegated(tabs::delegated::Message),
    Transactions(tabs::transactions::Message),
    Features(tabs::features::Message),
    Tools(tabs::tools::Message),

    /// Switch to a tab. Tabs may return `Task::done(Message::Goto(..))`.
    Goto(TabId),
    RefreshReaders,
    ReaderPicked(String),
    ToggleConnect,
    CycleTheme,
    SystemTheme(iced_theme::Mode),

    ShowApdus(bool),
    LogAction(text_editor::Action),
    LogCopy,
    LogClear,
    LogSave,
    LogSaveTo(Option<PathBuf>),

    Form(FormMsg),
    Escape,
    FocusNext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThemeMode {
    System,
    Light,
    Dark,
}

struct ActiveDialog {
    state: DialogState,
    token: Option<u32>,
    owner: Option<TabId>,
}

pub struct App {
    shared: Shared,
    active: TabId,

    card: tabs::card::State,
    auth: tabs::auth::State,
    pki: tabs::pki::State,
    crl: tabs::crl::State,
    sdm: tabs::sdm::State,
    delegated: tabs::delegated::State,
    transactions: tabs::transactions::State,
    features: tabs::features::State,
    tools: tabs::tools::State,

    readers: Vec<String>,
    reader: Option<String>,
    theme_mode: ThemeMode,
    system_mode: iced_theme::Mode,

    log_view: TextView,
    log_seen: (u64, bool),
    show_apdus: bool,

    dialog: Option<ActiveDialog>,
    queue: VecDeque<DialogRequest>,
}

/// `duox-ui [store.json]`
fn store_path_from_args() -> Option<PathBuf> {
    std::env::args_os().nth(1).map(PathBuf::from).or_else(PkiStore::default_path)
}

pub fn boot() -> (App, Task<Message>) {
    let log = LogBuf::default();
    let mut open_error = None;
    let store = match store_path_from_args() {
        Some(path) => PkiStore::open(&path, None).unwrap_or_else(|e| {
            open_error = Some(format!("Cannot open the key store {}: {e}", path.display()));
            PkiStore::new()
        }),
        None => PkiStore::new(),
    };
    let mut shared = Shared::new(store, log);
    if let Some(e) = open_error {
        shared.report_error(e);
    }
    if shared.store.is_locked() {
        shared.unlock_wanted = Some("The key store has passphrase protected private keys.".into());
    }
    let mut app = App {
        shared,
        active: TabId::Card,
        card: Default::default(),
        auth: Default::default(),
        pki: Default::default(),
        crl: Default::default(),
        sdm: Default::default(),
        delegated: Default::default(),
        transactions: Default::default(),
        features: Default::default(),
        tools: Default::default(),
        readers: Vec::new(),
        reader: None,
        theme_mode: ThemeMode::System,
        system_mode: iced_theme::Mode::None,
        log_view: TextView::default(),
        log_seen: (u64::MAX, true),
        show_apdus: true,
        dialog: None,
        queue: VecDeque::new(),
    };
    app.refresh_readers();
    let pump = app.pump();
    (app, Task::batch([pump, iced::system::theme().map(Message::SystemTheme)]))
}

impl App {
    // ---- connection ---------------------------------------------------------------

    fn refresh_readers(&mut self) {
        match transport::list_readers() {
            Ok(list) => {
                self.readers = list;
                if self.reader.as_ref().is_none_or(|r| !self.readers.contains(r)) {
                    self.reader = self.readers.first().cloned();
                }
            }
            Err(e) => {
                self.readers.clear();
                self.reader = None;
                self.shared.log.push(LineKind::Error, format!("!! reader list: {e}"));
            }
        }
    }

    fn connect(&mut self) {
        let Some(name) = self.reader.clone() else {
            self.shared.report_error("No reader selected. Attach a reader and press Refresh.");
            return;
        };
        let mut t: Box<dyn Transport> = Box::new(transport::PcscTransport::new(name.clone()));
        t.set_trace(Some(self.shared.log.trace_hook()));
        let mut card: Card<Box<dyn Transport>> = Card::new(t);
        card.set_log(Some(self.shared.log.command_hook()));
        match card.connect() {
            Ok(atr) => {
                self.shared.log.info(format!("-- connected to {name}, ATR {}", hex::spaced(&atr)));
                self.shared.card = Some(card);
                self.shared.reader = Some(name);
                self.shared.scan = Some(crate::shared::ScanInfo { atr, ..Default::default() });
                self.shared.refresh_scan();
                self.shared.events.push(AppEvent::Connected);
            }
            Err(e) => {
                self.shared.report_error(format!("Cannot connect to {name}: {e}"));
            }
        }
    }

    fn disconnect(&mut self) {
        if let Some(mut card) = self.shared.card.take() {
            card.disconnect();
            self.shared.log.info("-- disconnected");
        }
        self.shared.scan = None;
        self.shared.reader = None;
        self.shared.events.push(AppEvent::Disconnected);
    }

    // ---- tab routing --------------------------------------------------------------

    fn tab_update(&mut self, id: TabId, msg: Message) -> Task<Message> {
        self.shared.ctx = Some(id);
        let sh = &mut self.shared;
        let task = match msg {
            Message::Card(m) => self.card.update(m, sh),
            Message::Auth(m) => self.auth.update(m, sh),
            Message::Pki(m) => self.pki.update(m, sh),
            Message::Crl(m) => self.crl.update(m, sh),
            Message::Sdm(m) => self.sdm.update(m, sh),
            Message::Delegated(m) => self.delegated.update(m, sh),
            Message::Transactions(m) => self.transactions.update(m, sh),
            Message::Features(m) => self.features.update(m, sh),
            Message::Tools(m) => self.tools.update(m, sh),
            _ => Task::none(),
        };
        self.shared.ctx = None;
        task
    }

    /// Deliver an application event to one tab.
    fn send_event(&mut self, id: TabId, ev: AppEvent) -> Task<Message> {
        use tabs::*;
        let m = match id {
            TabId::Card => Message::Card(card::Message::Event(ev)),
            TabId::Auth => Message::Auth(auth::Message::Event(ev)),
            TabId::Pki => Message::Pki(pki::Message::Event(ev)),
            TabId::Crl => Message::Crl(crl::Message::Event(ev)),
            TabId::Sdm => Message::Sdm(sdm::Message::Event(ev)),
            TabId::Delegated => Message::Delegated(delegated::Message::Event(ev)),
            TabId::Transactions => Message::Transactions(transactions::Message::Event(ev)),
            TabId::Features => Message::Features(features::Message::Event(ev)),
            TabId::Tools => Message::Tools(tools::Message::Event(ev)),
        };
        self.tab_update(id, m)
    }

    /// Deliver a dialog answer to the tab that asked.
    fn send_form_done(&mut self, id: TabId, token: u32, values: Option<FormValues>) -> Task<Message> {
        use tabs::*;
        let m = match id {
            TabId::Card => Message::Card(card::Message::FormDone { token, values }),
            TabId::Auth => Message::Auth(auth::Message::FormDone { token, values }),
            TabId::Pki => Message::Pki(pki::Message::FormDone { token, values }),
            TabId::Crl => Message::Crl(crl::Message::FormDone { token, values }),
            TabId::Sdm => Message::Sdm(sdm::Message::FormDone { token, values }),
            TabId::Delegated => Message::Delegated(delegated::Message::FormDone { token, values }),
            TabId::Transactions => Message::Transactions(transactions::Message::FormDone { token, values }),
            TabId::Features => Message::Features(features::Message::FormDone { token, values }),
            TabId::Tools => Message::Tools(tools::Message::FormDone { token, values }),
        };
        self.tab_update(id, m)
    }

    fn tab_of(msg: &Message) -> Option<TabId> {
        Some(match msg {
            Message::Card(_) => TabId::Card,
            Message::Auth(_) => TabId::Auth,
            Message::Pki(_) => TabId::Pki,
            Message::Crl(_) => TabId::Crl,
            Message::Sdm(_) => TabId::Sdm,
            Message::Delegated(_) => TabId::Delegated,
            Message::Transactions(_) => TabId::Transactions,
            Message::Features(_) => TabId::Features,
            Message::Tools(_) => TabId::Tools,
            _ => return None,
        })
    }

    /// Drain what tabs and the shell queued in `Shared` (dialogs, events) until quiet.
    fn pump(&mut self) -> Task<Message> {
        let mut tasks = Vec::new();
        for _ in 0..16 {
            if let Some(why) = self.shared.unlock_wanted.take() {
                let already = self.queue.iter().any(|r| r.token == Some(UNLOCK_TOKEN))
                    || self.dialog.as_ref().is_some_and(|d| d.token == Some(UNLOCK_TOKEN));
                if !already && self.shared.store.is_locked() {
                    self.shared.ask_unlock(&why);
                }
            }
            let reqs = std::mem::take(&mut self.shared.requests);
            let evs = std::mem::take(&mut self.shared.events);
            if reqs.is_empty() && evs.is_empty() {
                break;
            }
            self.queue.extend(reqs);
            for ev in evs {
                for id in TabId::ALL {
                    tasks.push(self.send_event(id, ev));
                }
            }
        }
        if self.dialog.is_none() {
            if let Some(r) = self.queue.pop_front() {
                self.dialog = Some(ActiveDialog { state: r.dialog.into(), token: r.token, owner: r.owner });
            }
        }
        self.sync_log();
        Task::batch(tasks)
    }

    fn sync_log(&mut self) {
        let key = (self.shared.log.revision(), self.show_apdus);
        if key != self.log_seen {
            self.log_seen = key;
            self.log_view.set_text(&self.shared.log.text(self.show_apdus));
            self.log_view.scroll_to_end();
        }
    }

    fn finish_dialog(&mut self, values: Option<FormValues>) -> Task<Message> {
        let Some(d) = self.dialog.take() else { return Task::none() };
        match (d.token, d.owner) {
            (Some(UNLOCK_TOKEN), None) => {
                if let Some(v) = values {
                    let pw = v.get_str("passphrase").unwrap_or_default().to_string();
                    match self.shared.store.unlock(&pw) {
                        Ok(()) => {
                            self.shared.info("Key store", "Unlocked. Repeat the action that needed the keys.");
                            self.shared.store_changed();
                        }
                        Err(e) => {
                            self.shared.report_error(e.to_string());
                        }
                    }
                }
                Task::none()
            }
            (Some(token), Some(owner)) => self.send_form_done(owner, token, values),
            _ => Task::none(),
        }
    }

    // ---- theme ---------------------------------------------------------------------

    fn current_theme(&self) -> Theme {
        match self.theme_mode {
            ThemeMode::Light => Theme::Light,
            ThemeMode::Dark => Theme::Dark,
            ThemeMode::System => match self.system_mode {
                iced_theme::Mode::Dark => Theme::Dark,
                _ => Theme::Light,
            },
        }
    }
}

pub fn update(app: &mut App, msg: Message) -> Task<Message> {
    let mut task = Task::none();
    if let Some(id) = App::tab_of(&msg) {
        task = app.tab_update(id, msg);
    } else {
        match msg {
            Message::Goto(id) => {
                if app.active != id {
                    app.active = id;
                    task = app.send_event(id, AppEvent::Activated);
                }
            }
            Message::RefreshReaders => app.refresh_readers(),
            Message::ReaderPicked(r) => app.reader = Some(r),
            Message::ToggleConnect => {
                if app.shared.is_connected() {
                    app.disconnect();
                } else {
                    app.connect();
                }
            }
            Message::CycleTheme => {
                app.theme_mode = match app.theme_mode {
                    ThemeMode::System => ThemeMode::Light,
                    ThemeMode::Light => ThemeMode::Dark,
                    ThemeMode::Dark => ThemeMode::System,
                }
            }
            Message::SystemTheme(m) => app.system_mode = m,
            Message::ShowApdus(v) => app.show_apdus = v,
            Message::LogAction(a) => app.log_view.perform(a),
            Message::LogCopy => {
                let t = app.log_view.selection().unwrap_or_else(|| app.log_view.text());
                task = clipboard::copy(t);
            }
            Message::LogClear => app.shared.log.clear(),
            Message::LogSave => {
                task = files::pick_save(
                    "Save log",
                    "duox-log.txt",
                    &[files::Filter::new("Text", &["txt", "log"])],
                    Message::LogSaveTo,
                );
            }
            Message::LogSaveTo(path) => {
                if let Some(p) = path {
                    let text = app.shared.log.text(app.show_apdus);
                    if let Err(e) = files::write_file(&p, text.as_bytes()) {
                        app.shared.report_error(e);
                    }
                }
            }
            Message::Form(m) => {
                if let Some(d) = app.dialog.as_mut() {
                    let (out, t) = d.state.update(m);
                    let t = t.map(Message::Form);
                    task = match out {
                        Outcome::Pending => t,
                        Outcome::Submitted(v) => Task::batch([t, app.finish_dialog(Some(v))]),
                        Outcome::Cancelled => Task::batch([t, app.finish_dialog(None)]),
                    };
                }
            }
            Message::Escape => {
                if app.dialog.is_some() {
                    return update(app, Message::Form(FormMsg::Cancel));
                }
            }
            Message::FocusNext => {
                if app.dialog.is_some() {
                    task = operation::focus_next();
                }
            }
            // handled by tab_of
            Message::Card(_)
            | Message::Auth(_)
            | Message::Pki(_)
            | Message::Crl(_)
            | Message::Sdm(_)
            | Message::Delegated(_)
            | Message::Transactions(_)
            | Message::Features(_)
            | Message::Tools(_) => {}
        }
    }
    Task::batch([task, app.pump()])
}

pub fn theme(app: &App) -> Theme {
    app.current_theme()
}

pub fn title(app: &App) -> String {
    match &app.shared.reader {
        Some(r) => format!("DUOX tool - {r}"),
        None => "DUOX tool".into(),
    }
}

pub fn subscription(_app: &App) -> Subscription<Message> {
    Subscription::batch([
        iced::system::theme_changes().map(Message::SystemTheme),
        iced::event::listen_with(|event, _status, _window| match event {
            iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => match key {
                keyboard::Key::Named(keyboard::key::Named::Escape) => Some(Message::Escape),
                keyboard::Key::Named(keyboard::key::Named::Tab) if !modifiers.shift() => Some(Message::FocusNext),
                _ => None,
            },
            _ => None,
        }),
    ])
}

// ------------------------------------------------------------------------- view

pub fn view(app: &App) -> Element<'_, Message> {
    let base = column![top_bar(app), status_line(app), tab_bar(app), tab_view(app), log_pane(app)]
        .spacing(0)
        .width(Length::Fill)
        .height(Length::Fill);
    match &app.dialog {
        None => base.into(),
        Some(d) => stack![
            base,
            opaque(
                container(d.state.view().map(Message::Form))
                    .center(Length::Fill)
                    .padding(theme::SPACE_LG)
                    .style(style::backdrop)
            )
        ]
        .into(),
    }
}

fn top_bar(app: &App) -> Element<'_, Message> {
    let connected = app.shared.is_connected();
    let readers = pick_list(app.readers.clone(), app.reader.clone(), Message::ReaderPicked)
        .placeholder("No reader found")
        .width(Length::FillPortion(3));
    let connect = if connected {
        widgets::secondary("Disconnect", Message::ToggleConnect)
    } else if app.reader.is_some() {
        widgets::primary("Connect", Message::ToggleConnect)
    } else {
        iced::widget::button("Connect").padding([5, 14])
    };
    let theme_label = match app.theme_mode {
        ThemeMode::System => "Theme: system",
        ThemeMode::Light => "Theme: light",
        ThemeMode::Dark => "Theme: dark",
    };
    container(
        row![
            text("Reader").size(theme::TEXT_BODY),
            readers,
            widgets::secondary("Refresh", Message::RefreshReaders),
            connect,
            Space::new().width(Length::Fill),
            widgets::secondary(theme_label, Message::CycleTheme),
        ]
        .spacing(theme::SPACE_SM)
        .align_y(iced::Alignment::Center),
    )
    .padding([theme::SPACE_SM, theme::SPACE_MD])
    .into()
}

fn status_line(app: &App) -> Element<'_, Message> {
    let connected = app.shared.is_connected();
    let color = if connected {
        iced::Color::from_rgb8(0x2e, 0xa0, 0x43)
    } else {
        iced::Color::from_rgb8(0x8a, 0x8f, 0x98)
    };
    let mut line = row![container(Space::new()).width(10).height(10).style(style::dot(color))]
        .spacing(theme::SPACE_SM)
        .align_y(iced::Alignment::Center);
    if connected {
        let reader = app.shared.reader.clone().unwrap_or_default();
        line = line.push(text(reader).size(theme::TEXT_BODY));
        if let Some(scan) = &app.shared.scan {
            line = line.push(widgets::hint(format!("ATR {}", hex::compact(&scan.atr))));
        }
        line = line.push(widgets::mono(app.shared.status_text()));
    } else {
        line = line.push(text("Not connected").size(theme::TEXT_BODY));
    }
    container(line).padding([theme::SPACE_XS + 2.0, theme::SPACE_MD]).width(Length::Fill).style(style::status_bar).into()
}

fn tab_bar(app: &App) -> Element<'_, Message> {
    let mut r = row![].spacing(theme::SPACE_XS);
    for id in TabId::ALL {
        r = r.push(
            iced::widget::button(text(id.title()).size(theme::TEXT_BODY))
                .on_press(Message::Goto(id))
                .padding([6, 14])
                .style(style::tab_button(app.active == id)),
        );
    }
    container(r).padding([theme::SPACE_SM, theme::SPACE_MD]).into()
}

fn tab_view(app: &App) -> Element<'_, Message> {
    let sh = &app.shared;
    let body: Element<'_, Message> = match app.active {
        TabId::Card => app.card.view(sh).map(Message::Card),
        TabId::Auth => app.auth.view(sh).map(Message::Auth),
        TabId::Pki => app.pki.view(sh).map(Message::Pki),
        TabId::Crl => app.crl.view(sh).map(Message::Crl),
        TabId::Sdm => app.sdm.view(sh).map(Message::Sdm),
        TabId::Delegated => app.delegated.view(sh).map(Message::Delegated),
        TabId::Transactions => app.transactions.view(sh).map(Message::Transactions),
        TabId::Features => app.features.view(sh).map(Message::Features),
        TabId::Tools => app.tools.view(sh).map(Message::Tools),
    };
    container(body).padding([0.0, theme::SPACE_MD]).width(Length::Fill).height(Length::Fill).into()
}

fn log_pane(app: &App) -> Element<'_, Message> {
    let head = row![
        text("Log").size(theme::TEXT_HEADING),
        checkbox(app.show_apdus).label("show APDUs").on_toggle(Message::ShowApdus).size(16).text_size(theme::TEXT_BODY),
        Space::new().width(Length::Fill),
        widgets::secondary("Copy", Message::LogCopy),
        widgets::secondary("Save...", Message::LogSave),
        widgets::secondary("Clear", Message::LogClear),
    ]
    .spacing(theme::SPACE_MD)
    .align_y(iced::Alignment::Center);
    container(
        column![head, app.log_view.view().map(Message::LogAction)].spacing(theme::SPACE_SM),
    )
    .padding(theme::SPACE_MD)
    .width(Length::Fill)
    .height(220)
    .style(style::status_bar)
    .into()
}
