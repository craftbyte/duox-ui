//! State shared by every tab: the card session, the PKI store, the log and the dialog queue.
//!
//! # Threading
//!
//! Card I/O is synchronous and runs inside `update` on the UI thread. A command takes a few
//! milliseconds to a few hundred (key generation, signatures), during which the window does not
//! repaint. That is deliberate: it keeps the protocol state (`Card` is `&mut`, sessions are
//! stateful, errors drop the authentication) trivially correct. All card access goes through
//! [`Shared::with_card`], so moving to a worker thread later changes one function.

use crate::log::{LineKind, LogBuf};
use crate::tabs::TabId;
use crate::ui::form::{Dialog, FormSpec};
use crate::ui::hex;
use duox::card::{Aid, Card, VersionInfo};
use duox::pki::{PkiError, PkiStore};
use duox::transport::Transport;
use std::fmt::Display;

/// The card type every tab works with.
pub type DynCard = Card<Box<dyn Transport>>;

/// Notifications the application broadcasts to every tab (as `Message::Event`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    /// A card was connected (and `Shared::scan` refreshed).
    Connected,
    /// The card was disconnected; `Shared::card` is `None`.
    Disconnected,
    /// The PKI store changed (see [`Shared::store_changed`]) or was unlocked.
    StoreChanged,
    /// Sent only to the tab that was just selected.
    Activated,
}

/// Facts read once when connecting (best effort; fields stay empty when the card refuses).
#[derive(Debug, Clone, Default)]
pub struct ScanInfo {
    pub atr: Vec<u8>,
    pub version: Option<VersionInfo>,
    pub applications: Vec<Aid>,
}

/// A dialog waiting to be shown, with the tab that gets the answer.
pub(crate) struct DialogRequest {
    pub dialog: Dialog,
    /// `None` for dialogs that produce no answer (info, error) and for the application's own.
    pub token: Option<u32>,
    pub owner: Option<TabId>,
}

/// Token the application uses for its passphrase prompt. Tabs must not use it.
pub const UNLOCK_TOKEN: u32 = u32::MAX;

pub struct Shared {
    pub card: Option<DynCard>,
    pub reader: Option<String>,
    pub store: PkiStore,
    pub log: LogBuf,
    /// Information gathered at connect time; `None` while disconnected.
    pub scan: Option<ScanInfo>,
    /// Incremented whenever [`Shared::store_changed`] is called; lets views cache derived data.
    pub store_rev: u64,

    pub(crate) requests: Vec<DialogRequest>,
    pub(crate) events: Vec<AppEvent>,
    pub(crate) unlock_wanted: Option<String>,
    /// Tab currently inside `update`; dialogs requested meanwhile are answered to it.
    pub(crate) ctx: Option<TabId>,
}

impl Shared {
    pub fn new(store: PkiStore, log: LogBuf) -> Self {
        Shared {
            card: None,
            reader: None,
            store,
            log,
            scan: None,
            store_rev: 0,
            requests: Vec::new(),
            events: Vec::new(),
            unlock_wanted: None,
            ctx: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.card.is_some()
    }

    // ---- card ------------------------------------------------------------------------

    /// Run `f` against the connected card.
    ///
    /// * Not connected: logs it, opens an error dialog and returns `Err`.
    /// * `f` fails: the error text is logged (`!! ...`), shown in an error dialog and returned.
    ///
    /// The tab therefore only has to stop on `Err`; it must not show the message again. The
    /// status line is derived from the card on every redraw, so it is current afterwards
    /// (including the "authentication lost" case after a failed command).
    pub fn with_card<R, E: Display>(&mut self, f: impl FnOnce(&mut DynCard) -> Result<R, E>) -> Result<R, String> {
        match self.with_card_quiet(f) {
            Ok(v) => Ok(v),
            Err(e) => Err(self.report_error(e)),
        }
    }

    /// Like [`Shared::with_card`] but the error is only returned, not logged or shown. For
    /// best-effort probes where failure is an expected outcome.
    pub fn with_card_quiet<R, E: Display>(&mut self, f: impl FnOnce(&mut DynCard) -> Result<R, E>) -> Result<R, String> {
        match self.card.as_mut() {
            None => Err("Not connected. Pick a reader and press Connect.".into()),
            Some(card) => f(card).map_err(|e| e.to_string()),
        }
    }

    /// Log `msg` as an error and show it in the error dialog. Returns `msg` for chaining.
    pub fn report_error(&mut self, msg: impl Into<String>) -> String {
        let msg = msg.into();
        self.log.push(LineKind::Error, format!("!! {msg}"));
        self.requests.push(DialogRequest { dialog: Dialog::Error(msg.clone()), token: None, owner: None });
        msg
    }

    /// Status text for the status line: UID, selection and authentication state.
    pub fn status_text(&self) -> String {
        let Some(card) = self.card.as_ref() else { return "not connected".into() };
        let sel = card.selection();
        let name = |a: Aid| if a == Aid::PICC { "PICC".to_string() } else { a.to_string() };
        let mut selected = sel.primary.map(name).unwrap_or_else(|| "?".into());
        if let Some(s) = sel.secondary {
            selected.push_str(&format!(" + {}", name(s)));
        }
        let uid = if card.uid().is_empty() { "?".to_string() } else { hex::compact(card.uid()) };
        format!("UID {uid}   |   selected {selected}   |   {}", card.state_text())
    }

    /// Re-read the connect-time facts (version, application list). Call it only while not
    /// authenticated: a failing command ends the authentication.
    pub fn refresh_scan(&mut self) {
        let atr = self.scan.as_ref().map(|s| s.atr.clone()).unwrap_or_default();
        let version = self.with_card_quiet(|c| c.get_version()).ok();
        let applications = self.with_card_quiet(|c| c.get_application_ids()).unwrap_or_default();
        self.scan = Some(ScanInfo { atr, version, applications });
    }

    // ---- store -----------------------------------------------------------------------

    /// Run `f` against the PKI store. Errors are logged and shown; when the store is locked
    /// (passphrase protected keys and no passphrase yet) the application opens its passphrase
    /// prompt instead and the tab simply gets `Err` and can ask the user to repeat the action.
    ///
    /// Call [`Shared::store_changed`] after operations that modify the store.
    pub fn with_store<R>(&mut self, f: impl FnOnce(&mut PkiStore) -> duox::pki::Result<R>) -> Result<R, String> {
        match f(&mut self.store) {
            Ok(v) => Ok(v),
            Err(e) => {
                let msg = e.to_string();
                if matches!(e, PkiError::StoreLocked(_) | PkiError::PassphraseRequired | PkiError::WrongPassphrase) {
                    self.log.push(LineKind::Error, format!("!! {msg}"));
                    self.unlock_wanted = Some(msg.clone());
                    Err(msg)
                } else {
                    Err(self.report_error(msg))
                }
            }
        }
    }

    /// Tell every tab (as `AppEvent::StoreChanged`) that CAs, certificates or saved keys changed.
    pub fn store_changed(&mut self) {
        self.store_rev += 1;
        self.events.push(AppEvent::StoreChanged);
    }

    // ---- dialogs ---------------------------------------------------------------------

    /// Show a form. The answer arrives in the calling tab as
    /// `Message::FormDone { token, values }` (`None` = cancelled).
    pub fn ask(&mut self, spec: FormSpec, token: u32) {
        self.requests.push(DialogRequest { dialog: Dialog::Form(spec), token: Some(token), owner: self.ctx });
    }

    /// Yes/no question. The answer arrives like a form's: `Some(empty)` for yes, `None` for no.
    pub fn confirm(&mut self, title: &str, text: &str, ok_text: &str, token: u32) {
        self.requests.push(DialogRequest {
            dialog: Dialog::Confirm { title: title.into(), text: text.into(), ok_text: ok_text.into(), danger: false },
            token: Some(token),
            owner: self.ctx,
        });
    }

    /// Like [`Shared::confirm`], with a red confirm button (delete, format).
    pub fn confirm_danger(&mut self, title: &str, text: &str, ok_text: &str, token: u32) {
        self.requests.push(DialogRequest {
            dialog: Dialog::Confirm { title: title.into(), text: text.into(), ok_text: ok_text.into(), danger: true },
            token: Some(token),
            owner: self.ctx,
        });
    }

    /// Notice with an OK button.
    pub fn info(&mut self, title: &str, text: &str) {
        self.requests.push(DialogRequest {
            dialog: Dialog::Info { title: title.into(), text: text.into() },
            token: None,
            owner: None,
        });
    }

    /// Append an informational line to the log pane.
    pub fn log_info(&self, line: &str) {
        self.log.info(line);
    }
}

impl Shared {
    /// The application's passphrase prompt (answered in `app.rs`, never delivered to tabs).
    pub(crate) fn ask_unlock(&mut self, why: &str) {
        let spec = FormSpec::new("Key store locked")
            .note(format!("{why}\nEnter the passphrase to use the private keys."))
            .ok_text("Unlock")
            .secret("passphrase", "Passphrase");
        self.requests.push(DialogRequest { dialog: Dialog::Form(spec), token: Some(UNLOCK_TOKEN), owner: None });
    }
}
