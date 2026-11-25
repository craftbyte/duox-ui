//! Authenticate tab: AES (AuthenticateEV2First / NonFirst), ECC reader authentication
//! (mutual or reader-unilateral, with a certificate chain or the CA key itself) and the
//! card-unilateral authentication with the originality check.

mod plan;

use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::tabs::card::forms::{combo_refs, key_choice_options, key_from_fields};
use crate::tabs::card::{self, Output, Snapshot};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::{clipboard, hex, theme, widgets};
use duox::card::{Aid, EccAuthOptions, IsoSelect};
use duox::crypto::rnd;
use duox::pki::{leaf_public_key, verify_card_chain, CertKind, PkiStore};
use iced::widget::{button, column, container, row, text_editor, Space};
use iced::{Element, Length, Task};
use plan::{AesEnv, AesInput, EccChecked, EccInput, LocalCheck};

const T_AES_FIRST: u32 = 1;
const T_AES_NON_FIRST: u32 = 2;
const T_SAVE_KEY: u32 = 3;
const T_FORGET_KEY: u32 = 4;
const T_ECC: u32 = 5;
const T_PREFLIGHT: u32 = 6;
const T_UNILATERAL: u32 = 7;
/// Answer of every yes/no question; what it was about is in `State::pending`.
const T_CONFIRM: u32 = 8;

/// An identity of the store that can sign: label shown, entry id.
type Identity = (String, String);

/// Values of the last dialogs, offered again as defaults.
#[derive(Debug, Clone)]
struct Last {
    aes_no: u8,
    aes_key_name: Option<String>,
    ecc_mutual: bool,
    ecc_identity: Option<String>,
    ca_no: u8,
    ca2_no: u8,
    cert_file: u8,
    priv_no: u8,
    uni_key: u8,
    uni_file: u8,
}

impl Default for Last {
    fn default() -> Self {
        Last {
            aes_no: 0,
            aes_key_name: None,
            ecc_mutual: true,
            ecc_identity: None,
            ca_no: 0,
            ca2_no: 0,
            cert_file: 1,
            priv_no: 0,
            uni_key: 1,
            uni_file: 1,
        }
    }
}

#[derive(Debug)]
enum Pending {
    /// The local check failed; the user may still send the certificate.
    Ecc(Box<EccRun>),
    Originality,
}

#[derive(Debug)]
struct EccRun {
    input: EccInput,
    id: String,
    checked: EccChecked,
    acmap: u16,
    acmap2: u16,
    local: Vec<String>,
}

#[derive(Debug, Default)]
pub struct State {
    out: Output,
    snap: Snapshot,
    last: Last,
    pending: Option<Pending>,
}

#[derive(Debug, Clone)]
pub enum Message {
    FormDone { token: u32, values: Option<FormValues> },
    Event(AppEvent),
    /// What the Card tab knows about the selected application.
    Snapshot(Snapshot),
    View(text_editor::Action),
    Copy,

    AesFirst,
    AesNonFirst,
    SaveKey,
    ForgetKey,
    EccAuth,
    Preflight,
    EndSession,
    Unilateral,
    Originality,
}

impl State {
    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::Event(ev) => {
                if ev == AppEvent::Disconnected {
                    self.snap = Snapshot::default();
                    self.out.0.set_text("");
                }
                Task::none()
            }
            Message::Snapshot(s) => {
                self.snap = s;
                Task::none()
            }
            Message::View(a) => {
                self.out.0.perform(a);
                Task::none()
            }
            Message::Copy => clipboard::copy(self.out.0.selection().unwrap_or_else(|| self.out.0.text())),
            Message::FormDone { token, values } => self.on_answer(token, values, shared),

            Message::AesFirst => {
                self.ask_aes(true, shared);
                Task::none()
            }
            Message::AesNonFirst => {
                self.ask_aes(false, shared);
                Task::none()
            }
            Message::SaveKey => {
                shared.ask(save_key_form(), T_SAVE_KEY);
                Task::none()
            }
            Message::ForgetKey => {
                let names = saved_keys(shared);
                if names.is_empty() {
                    shared.info("Forget key", "There are no saved AES keys.");
                } else {
                    let refs = combo_refs(&names);
                    shared.ask(
                        FormSpec::new("Forget key")
                            .note("Removes the key from the store. The card is not changed.")
                            .ok_text("Forget")
                            .combo("name", "Saved key", &refs, 0),
                        T_FORGET_KEY,
                    );
                }
                Task::none()
            }
            Message::EccAuth => {
                self.ask_ecc(true, shared);
                Task::none()
            }
            Message::Preflight => {
                self.ask_ecc(false, shared);
                Task::none()
            }
            Message::EndSession => self.end_session(shared),
            Message::Unilateral => {
                if shared.is_connected() {
                    let last = &self.last;
                    shared.ask(unilateral_form(last), T_UNILATERAL);
                } else {
                    shared.report_error("Not connected. Pick a reader and press Connect.");
                }
                Task::none()
            }
            Message::Originality => self.originality(shared),
        }
    }

    // ------------------------------------------------------------------ helpers

    /// The browser's snapshot, distrusted where the card has been re-selected since.
    fn effective(&self, shared: &Shared) -> Snapshot {
        let mut s = self.snap.clone();
        if let Some(c) = shared.card.as_ref() {
            let sel = c.selection();
            if (sel.primary.is_some() && sel.primary != s.selected) || sel.secondary != s.second {
                s.selected = sel.primary;
                s.second = sel.secondary;
                s.keys = None;
                s.ca_known = false;
                s.ca_keys.clear();
                s.ecc_keys.clear();
            }
        }
        s
    }

    fn show(&mut self, lines: &[String]) {
        self.out.0.set_text(&lines.join("\n"));
    }

    fn reload_card() -> Task<app::Message> {
        Task::done(app::Message::Card(card::Message::Reload))
    }

    fn connected(shared: &mut Shared) -> bool {
        if shared.is_connected() {
            true
        } else {
            shared.report_error("Not connected. Pick a reader and press Connect.");
            false
        }
    }

    // ---------------------------------------------------------------------- AES

    fn ask_aes(&mut self, first: bool, shared: &mut Shared) {
        if !Self::connected(shared) {
            return;
        }
        let saved = saved_keys(shared);
        let second = shared.card.as_ref().is_some_and(|c| c.selection().secondary.is_some());
        shared.ask(aes_form(first, &self.last, &saved, second), if first { T_AES_FIRST } else { T_AES_NON_FIRST });
    }

    fn aes(&mut self, first: bool, v: &FormValues, shared: &mut Shared) -> Task<app::Message> {
        let saved = saved_keys(shared);
        let key = match key_from_fields(v, "key_sel", "key_hex", &saved, |n| shared.store.aes_key(n)) {
            Ok(Some(k)) => k,
            Ok(None) => {
                shared.report_error("Enter the AES key or choose a saved key.");
                return Task::none();
            }
            Err(e) => {
                shared.report_error(e);
                return Task::none();
            }
        };
        let input = AesInput {
            key_no: v.get_uint("no").unwrap_or(0) as u8,
            second_app: v.get_bool("second").unwrap_or(false),
            key,
            pcd_cap2: if first { v.get_hex("cap2").unwrap_or_default() } else { Vec::new() },
        };
        let snap = self.effective(shared);
        let aes_session = shared
            .card
            .as_ref()
            .and_then(|c| c.auth_summary())
            .is_some_and(|a| a.kind == duox::card::AuthKind::Aes);
        let env = AesEnv {
            selected: snap.selected,
            second_selected: snap.second.is_some(),
            keys: snap.keys.as_ref(),
            aes_session,
        };
        let key_no = match plan::plan_aes(&input, &env, first) {
            Ok(n) => n,
            Err(e) => {
                shared.report_error(e);
                return Task::none();
            }
        };
        self.last.aes_no = input.key_no;
        self.last.aes_key_name = v
            .get_index("key_sel")
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| saved.get(i).cloned());
        let r = if first {
            shared
                .with_card(|c| c.authenticate_ev2_first(key_no, &input.key, &input.pcd_cap2).map(Some))
                .map(|info| info.map(|i| (i.ti, i.pd_cap2, i.pcd_cap2)))
        } else {
            shared.with_card(|c| c.authenticate_ev2_non_first(key_no, &input.key).map(|_| None::<duox::card::AesAuthInfo>)).map(|_| None)
        };
        let Ok(info) = r else { return Task::none() };
        let state = shared.card.as_ref().map(|c| c.state_text()).unwrap_or_default();
        let mut l = vec![format!("AuthenticateEV2{} OK", if first { "First" } else { "NonFirst" }), state];
        if let Some((ti, pd, pcd)) = info {
            l.push(format!("TI      {}", hex::spaced(&ti)));
            l.push(format!("PDcap2  {}", hex::spaced(&pd)));
            l.push(format!("PCDcap2 {}", hex::spaced(&pcd)));
        }
        self.show(&l);
        Self::reload_card()
    }

    fn save_key(&mut self, v: &FormValues, shared: &mut Shared) {
        let name = v.get_str("name").unwrap_or_default().trim().to_string();
        if name.is_empty() {
            shared.report_error("Give the key a name.");
            return;
        }
        let key = if v.get_bool("random").unwrap_or(false) {
            rnd(if v.get_index("size").unwrap_or(0) == 1 { 32 } else { 16 })
        } else {
            v.get_hex("key").unwrap_or_default()
        };
        if !matches!(key.len(), 16 | 32) {
            shared.report_error("An AES key has 16 bytes (AES-128) or 32 bytes (AES-256). Enter one or tick \"Generate a random key\".");
            return;
        }
        if shared.with_store(|s| s.set_aes_key(&name, &key)).is_ok() {
            shared.store_changed();
            shared.log_info(&format!("-- saved AES-{} key '{name}'", key.len() * 8));
            self.last.aes_key_name = Some(name.clone());
            self.show(&[format!("Saved the AES-{} key as '{name}'.", key.len() * 8), "Choose it by name in the authentication dialogs.".into()]);
        }
    }

    fn forget_key(&mut self, v: &FormValues, shared: &mut Shared) {
        let names = saved_keys(shared);
        let Some(name) = v.get_index("name").ok().and_then(|i| names.get(i).cloned()) else { return };
        if shared.with_store(|s| s.remove_aes_key(&name)).is_ok() {
            shared.store_changed();
            if self.last.aes_key_name.as_deref() == Some(name.as_str()) {
                self.last.aes_key_name = None;
            }
            self.show(&[format!("Forgot the saved key '{name}'.")]);
        }
    }

    // ---------------------------------------------------------------------- ECC

    fn ask_ecc(&mut self, authenticate: bool, shared: &mut Shared) {
        if authenticate && !Self::connected(shared) {
            return;
        }
        let ids = identities(&shared.store);
        if ids.is_empty() {
            shared.report_error(
                "There is no reader identity in the store. Create a CA and a reader certificate (with its key) on the \
                 CAs & certificates tab.",
            );
            return;
        }
        let snap = self.effective(shared);
        shared.ask(
            ecc_form(authenticate, &self.last, &ids, snap.second.is_some(), &snap),
            if authenticate { T_ECC } else { T_PREFLIGHT },
        );
    }

    /// Everything that can be checked without the card: identity, CA key, local certificate check.
    fn prepare_ecc(&mut self, v: &FormValues, shared: &mut Shared) -> Option<EccRun> {
        let (input, id) = read_ecc_form(v, &identities(&shared.store))?;
        self.last.ecc_mutual = input.mutual;
        self.last.ecc_identity = Some(id.clone());
        self.last.ca_no = input.ca_no;
        self.last.ca2_no = input.ca2_no;
        self.last.cert_file = input.cert_file;
        self.last.priv_no = input.priv_no;
        let root_curve = match shared.store.root_of(&id) {
            Ok(r) => r.curve,
            Err(e) => {
                shared.report_error(e.to_string());
                return None;
            }
        };
        let snap = self.effective(shared);
        let checked = match plan::plan_ecc(&input, &snap, root_curve) {
            Ok(c) => c,
            Err(e) => {
                shared.report_error(e);
                return None;
            }
        };
        let uid = shared.card.as_ref().map(|c| c.uid().to_vec()).unwrap_or_default();
        let LocalCheck { acmap, acmap2, report, failure } =
            plan::local_check(&shared.store, &id, &checked, snap.second, &uid, input.check_issuer);
        let run = EccRun { input, id, checked, acmap, acmap2, local: report };
        if let Some(f) = failure {
            self.pending = Some(Pending::Ecc(Box::new(run)));
            shared.confirm_danger(
                "Certificate check failed",
                &format!(
                    "Checked with the card's own rules, the reader certificate will be rejected:\n\n{f}\n\n\
                     Send it to the card anyway?"
                ),
                "Send anyway",
                T_CONFIRM,
            );
            return None;
        }
        Some(run)
    }

    fn preflight(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some((input, id)) = read_ecc_form(v, &identities(&shared.store)) else { return };
        let root_curve = shared.store.root_of(&id).map(|r| r.curve).unwrap_or(duox::crypto::CURVE_P256);
        let snap = self.effective(shared);
        let checked = match plan::plan_ecc(&input, &snap, root_curve) {
            Ok(c) => c,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let uid = shared.card.as_ref().map(|c| c.uid().to_vec()).unwrap_or_default();
        let r = plan::local_check(&shared.store, &id, &checked, snap.second, &uid, input.check_issuer);
        let mut l = vec!["Local validation of the reader certificate (the card's own rules, including the local CRL):".to_string(), String::new()];
        l.extend(r.report);
        l.push(String::new());
        l.push(match r.failure {
            Some(_) => "The card is expected to reject this certificate.".into(),
            None => format!("The card is expected to accept it and to grant access conditions {}.", crate::tabs::card::model::acmap_text(r.acmap)),
        });
        self.show(&l);
    }

    fn run_ecc(&mut self, run: EccRun, shared: &mut Shared) -> Task<app::Message> {
        let EccRun { input, id, checked, acmap, acmap2, local } = run;
        let Ok(signer) = shared.with_store(|s| s.key_of(&id)) else { return Task::none() };
        let Ok(chain) = shared.with_store(|s| s.chain_bytes(&id)) else { return Task::none() };
        let Ok(curve) = shared.with_store(|s| Ok(s.root_of(&id)?.curve)) else { return Task::none() };
        let anchors = card::trust_anchors(shared);
        let df = input.select_df.clone();
        let res = shared.with_card(|card| {
            let epub = match &df {
                Some(name) => Some(card.select_for_ecc_auth(&IsoSelect::DfName(name))?),
                None => None,
            };
            let key_of_cert = |c: &[u8]| leaf_public_key(c).ok();
            let mut o = EccAuthOptions::new(input.ca_no, curve, &signer)
                .cert_chain(&chain)
                .card_certificate(input.cert_file, input.priv_no)
                .secondary_ca_key(input.ca2_no)
                .access_map(acmap, acmap2)
                .card_key_from_cert(&key_of_cert);
            if !input.mutual {
                o = o.reader_unilateral();
            }
            if let Some(e) = &epub {
                o = o.epub_b(e);
            }
            card.authenticate_ecc(&o)
        });
        let Ok(res) = res else { return Task::none() };
        let state = shared.card.as_ref().map(|c| c.state_text()).unwrap_or_default();
        let trust = (input.mutual && res.card_verified == Some(true)).then(|| verify_card_chain(&res.card_cert, &anchors));
        self.show(&plan::ecc_report(input.mutual, df.is_some(), &state, &res, &local, trust));
        let mut tasks = Vec::new();
        if df.is_some() && checked.aid != Aid::PICC {
            tasks.push(Task::done(app::Message::Card(card::Message::AssumeSelected(checked.aid))));
        }
        tasks.push(Self::reload_card());
        Task::batch(tasks)
    }

    fn end_session(&mut self, shared: &mut Shared) -> Task<app::Message> {
        if !Self::connected(shared) {
            return Task::none();
        }
        let r = shared.with_card(|c| {
            let s = c.selection();
            match s.primary {
                Some(p) if p != Aid::PICC => c.select_application(p, s.secondary),
                _ => c.select_application(Aid::PICC, None),
            }
        });
        if r.is_ok() {
            self.show(&["Application selected again: there is no active authentication.".to_string()]);
            return Self::reload_card();
        }
        Task::none()
    }

    // ------------------------------------------------------- card-unilateral

    fn unilateral(&mut self, v: &FormValues, shared: &mut Shared) {
        let key_no = v.get_int("key").unwrap_or(0) as u8;
        let use_cert = v.get_index("source").unwrap_or(0) == 0;
        let file = v.get_uint("file").unwrap_or(0) as u8;
        let opts = v.get_bool("opts").unwrap_or(false);
        let pasted = v.get_hex("pub").unwrap_or_default();
        self.last.uni_key = key_no;
        self.last.uni_file = file;
        let snap = self.effective(shared);
        if let Some(p) = plan::unilateral_problem(key_no, &snap.ecc_keys) {
            shared.report_error(p);
            return;
        }
        let pasted_key = if use_cert {
            None
        } else {
            match plan::parse_public_key(&pasted) {
                Ok(k) => Some(k),
                Err(e) => {
                    shared.report_error(e);
                    return;
                }
            }
        };
        let anchors = card::trust_anchors(shared);
        let opts_a: Option<&[u8]> = opts.then_some(&[0x00, 0x00][..]);
        let outcome = shared.with_card(|card| {
            let mut source = Vec::new();
            let mut trusted = None;
            let key = match pasted_key {
                Some(k) => {
                    source.push("Public key: entered manually (not checked against a CA).".to_string());
                    k
                }
                None => {
                    let cert = card.read_cert_file(file)?;
                    let chain = verify_card_chain(&cert, &anchors);
                    source.extend(plan::trust_lines(&chain));
                    match chain {
                        Ok(c) => {
                            trusted = Some(c.trusted);
                            c.public_key
                        }
                        Err(e) => return Err(duox::Error::InvalidArgument(format!("the certificate in file {file:02X} cannot be used: {e}"))),
                    }
                }
            };
            let r = card.internal_authenticate(key_no, Some(&key), opts_a)?;
            Ok::<_, duox::Error>((source, trusted, r))
        });
        if let Ok((source, trusted, r)) = outcome {
            let note = plan::unilateral_policy_note(key_no, &snap.ecc_keys);
            self.show(&plan::unilateral_report(&r, &source, trusted, note));
        }
    }

    fn originality(&mut self, shared: &mut Shared) -> Task<app::Message> {
        if !Self::connected(shared) {
            return Task::none();
        }
        let (authenticated, at_picc) = shared
            .card
            .as_ref()
            .map(|c| {
                let s = c.selection();
                (c.is_authenticated(), s.primary == Some(Aid::PICC) && s.secondary.is_none())
            })
            .unwrap_or((false, true));
        if authenticated && !at_picc {
            self.pending = Some(Pending::Originality);
            shared.confirm(
                "Originality check",
                "The originality check works at PICC level. Selecting it ends the current authentication. Continue?",
                "Check",
                T_CONFIRM,
            );
            return Task::none();
        }
        self.run_originality(shared)
    }

    fn run_originality(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let anchors = card::trust_anchors(shared);
        let r = shared.with_card(|card| {
            let key_of_cert = |c: &[u8]| leaf_public_key(c).ok();
            card.originality_check(None, Some(&key_of_cert))
        });
        let Ok(r) = r else { return Self::reload_card() };
        let mut source = Vec::new();
        let mut trusted = None;
        match &r.certificate {
            Some(cert) => {
                let chain = verify_card_chain(cert, &anchors);
                trusted = chain.as_ref().ok().map(|c| c.trusted);
                source.extend(plan::trust_lines(&chain));
                if !r.key_from_certificate {
                    source.push("The public key could not be taken from the certificate.".into());
                }
            }
            None => source.push("Cert.Orig (file 01) could not be read, so there is no public key to check against.".into()),
        }
        let mut l = vec!["Originality check (ISOInternalAuthenticate with the originality key 01 at PICC level)".to_string(), String::new()];
        l.extend(plan::unilateral_report(&r.auth, &source, trusted, None));
        self.show(&l);
        Self::reload_card()
    }

    // ------------------------------------------------------------------ answers

    fn on_answer(&mut self, token: u32, values: Option<FormValues>, shared: &mut Shared) -> Task<app::Message> {
        if token == T_CONFIRM {
            let pending = self.pending.take();
            if values.is_none() {
                return Task::none();
            }
            return match pending {
                Some(Pending::Ecc(run)) => self.run_ecc(*run, shared),
                Some(Pending::Originality) => self.run_originality(shared),
                None => Task::none(),
            };
        }
        let Some(v) = values else { return Task::none() };
        match token {
            T_AES_FIRST => return self.aes(true, &v, shared),
            T_AES_NON_FIRST => return self.aes(false, &v, shared),
            T_SAVE_KEY => self.save_key(&v, shared),
            T_FORGET_KEY => self.forget_key(&v, shared),
            T_ECC => {
                if let Some(run) = self.prepare_ecc(&v, shared) {
                    return self.run_ecc(run, shared);
                }
            }
            T_PREFLIGHT => self.preflight(&v, shared),
            T_UNILATERAL => self.unilateral(&v, shared),
            _ => {}
        }
        Task::none()
    }

    // --------------------------------------------------------------------- view

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let connected = shared.is_connected();
        let go = |label: &str, m: Message, primary: bool, needs_card: bool| {
            let b = button(iced::widget::text(label.to_string())).on_press_maybe((connected || !needs_card).then_some(m)).padding([5, 14]);
            if primary { b.style(button::primary) } else { b.style(button::secondary) }
        };
        let saved = saved_keys(shared);
        let ids = identities(&shared.store);
        let session = shared.card.as_ref().map(|c| c.state_text()).unwrap_or_else(|| "not connected".into());
        let status = widgets::kv_table::<Message>(
            &[
                ("Session".to_string(), session),
                ("Saved AES keys".to_string(), if saved.is_empty() { "none".into() } else { saved.join(", ") }),
                ("Reader identities".to_string(), format!("{} in the store", ids.len())),
            ],
            false,
        );
        let aes = widgets::group(
            "AES (AuthenticateEV2)",
            column![
                widgets::hint("AES-128 and AES-256 keys; the key is typed in or chosen from the saved keys."),
                row![
                    go("Authenticate (First)...", Message::AesFirst, true, true),
                    go("NonFirst...", Message::AesNonFirst, false, true),
                    go("Save key...", Message::SaveKey, false, false),
                    go("Forget key...", Message::ForgetKey, false, false),
                ]
                .spacing(theme::SPACE_SM)
                .wrap(),
            ]
            .spacing(theme::SPACE_SM),
        );
        let uni = widgets::group(
            "Card-unilateral (ISOInternalAuthenticate)",
            column![
                widgets::hint("The card proves it holds a private key. The public key comes from a certificate file or is typed in."),
                row![
                    go("Authenticate card...", Message::Unilateral, true, true),
                    go("Originality check", Message::Originality, false, true),
                ]
                .spacing(theme::SPACE_SM)
                .wrap(),
            ]
            .spacing(theme::SPACE_SM),
        );
        let ecc = widgets::group(
            "ECC reader authentication (ISOGeneralAuthenticate)",
            column![
                widgets::hint(
                    "Mutual or reader-unilateral, with a reader certificate (or a two-certificate chain) or the CA key itself, \
                     started by ISOGeneralAuthenticate or by ISOSelectFile. Certificates need a reader with extended APDU support."
                ),
                row![
                    go("Authenticate...", Message::EccAuth, true, true),
                    go("Check certificate locally...", Message::Preflight, false, false),
                    go("End session (re-select)", Message::EndSession, false, true),
                ]
                .spacing(theme::SPACE_SM)
                .wrap(),
            ]
            .spacing(theme::SPACE_SM),
        );
        let output = column![
            row![widgets::hint("Result"), Space::new().width(Length::Fill), go("Copy", Message::Copy, false, false)]
                .align_y(iced::Alignment::Center),
            container(self.out.0.view().map(Message::View))
                .padding(theme::SPACE_SM)
                .width(Length::Fill)
                .height(Length::Fill)
                .style(crate::ui::style::panel),
        ]
        .spacing(theme::SPACE_XS)
        .height(Length::Fill);
        column![
            widgets::panel(status),
            row![container(aes).width(Length::FillPortion(1)), container(uni).width(Length::FillPortion(1))].spacing(theme::SPACE_MD),
            ecc,
            output,
        ]
        .spacing(theme::SPACE_MD)
        .padding(theme::SPACE_SM)
        .into()
    }
}

// ------------------------------------------------------------------- dialogs

fn saved_keys(shared: &Shared) -> Vec<String> {
    shared.store.aes_key_names().into_iter().map(str::to_string).collect()
}

/// Readers and delegated CAs with a private key, then root CAs ("the CA key itself").
fn identities(store: &PkiStore) -> Vec<Identity> {
    let mut out = Vec::new();
    for e in store.by_kind(&[CertKind::Reader, CertKind::Sub]).into_iter().filter(|e| e.has_key()) {
        let issuer = store.root_of(&e.id).map(|r| r.name.clone()).unwrap_or_default();
        let serial = e.serial().map(|s| s.to_string()).unwrap_or_else(|| "?".into());
        out.push((format!("{}  (certificate #{serial}, issued by {issuer})", e.name), e.id.clone()));
    }
    for e in store.by_kind(&[CertKind::Root]).into_iter().filter(|e| e.has_key()) {
        out.push((format!("{}  (sign with the CA key itself, no certificate sent)", e.name), e.id.clone()));
    }
    out
}

fn aes_form(first: bool, last: &Last, saved: &[String], second_selected: bool) -> FormSpec {
    let opts = key_choice_options(saved);
    let default_sel = last
        .aes_key_name
        .as_ref()
        .and_then(|n| saved.iter().position(|s| s == n))
        .map(|i| i + 1)
        .unwrap_or(0);
    let mut f = FormSpec::new(if first { "AuthenticateEV2First" } else { "AuthenticateEV2NonFirst" })
        .note(if first {
            "Starts a new session with an AES key of the selected application (or of the PICC level)."
        } else {
            "Authenticates again inside the running AES session with another (or the same) key."
        })
        .ok_text("Authenticate")
        .hex_int_range("no", "Key number", last.aes_no as u64, 2, 0, 0x3F)
        .combo("key_sel", "Key", &combo_refs(&opts), default_sel)
        .hex("key_hex", "Key (hex)", "00000000000000000000000000000000")
        .hint("32 hex digits for AES-128, 64 for AES-256; used when no saved key is chosen");
    if second_selected {
        f = f
            .check("second", "Key of the second application", false)
            .hint("Keys and files of the second application are addressed with bit 7 set.");
    }
    if first {
        f = f.hex_len("cap2", "PCDcap2 (optional)", "", 0, 6).hint("up to 6 bytes of reader capabilities");
    }
    f
}

fn save_key_form() -> FormSpec {
    FormSpec::new("Save AES key")
        .note("Saved keys are stored in clear in the key store file and can be chosen by name.")
        .ok_text("Save")
        .text("name", "Name", "")
        .hex("key", "Key (hex)", "")
        .hint("16 or 32 bytes")
        .check("random", "Generate a random key instead", false)
        .combo("size", "Size of a generated key", &["AES-128", "AES-256"], 0)
}

fn ecc_form(authenticate: bool, last: &Last, ids: &[Identity], second_selected: bool, snap: &Snapshot) -> FormSpec {
    let labels: Vec<String> = ids.iter().map(|i| i.0.clone()).collect();
    let default_id = last.ecc_identity.as_ref().and_then(|id| ids.iter().position(|i| &i.1 == id)).unwrap_or(0);
    let df_default = snap
        .df_names
        .iter()
        .find(|d| Some(d.aid) == snap.selected)
        .map(|d| hex::spaced(&d.name))
        .unwrap_or_default();
    let mut f = FormSpec::new(if authenticate { "ECC authentication" } else { "Check certificate locally" })
        .note(if authenticate {
            "The reader proves its identity (and, if mutual, the card proves its own) with ISOGeneralAuthenticate."
        } else {
            "Validates the reader certificate with the card's own rules and the local CRL. Nothing is sent to the card."
        })
        .ok_text(if authenticate { "Authenticate" } else { "Check" })
        .combo("mode", "Authentication", &["Mutual (reader and card)", "Reader-unilateral"], usize::from(!last.ecc_mutual))
        .combo("identity", "Reader identity", &combo_refs(&labels), default_id)
        .int_range("ca", "CA root key number on the card", last.ca_no as i64, 0, 4);
    if second_selected {
        f = f.int_range("ca2", "CA root key in the second application", last.ca2_no as i64, 0, 4);
    }
    f.hex_int_range("cert_file", "Card certificate file (mutual)", last.cert_file as u64, 2, 0, 0x1F)
        .int_range("priv", "Card private key number (mutual)", last.priv_no as i64, 0, 4)
        .check("use_select", "Start with ISOSelectFile (integrated variant)", false)
        .hex_len("df", "DF name of the application", &df_default, 0, 16)
        .hint("used with the ISOSelectFile variant; the application must be configured for it")
        .check("issuer", "Check the issuer name as well", false)
        .hint("tick if the CA root key was installed with a trusted issuer name")
}

fn unilateral_form(last: &Last) -> FormSpec {
    FormSpec::new("Card-unilateral authentication")
        .note(
            "ISOInternalAuthenticate: the card signs a challenge with a private key. Key 1 at PICC level is the \
             originality key; its certificate is in file 01.",
        )
        .ok_text("Authenticate card")
        .int_range("key", "Card private key number", last.uni_key as i64, 0, 4)
        .combo("source", "Public key from", &["Certificate file on the card", "Public key typed in"], 0)
        .hex_int_range("file", "Certificate file", last.uni_file as u64, 2, 0, 0x1F)
        .hex("pub", "Public key (hex)", "")
        .hint("65 bytes, 04 || x || y; used when typed in")
        .check("opts", "Send OptsA (covered by the signature)", false)
}


/// The ECC dialog's answer: the parameters and the chosen store entry.
fn read_ecc_form(v: &FormValues, ids: &[Identity]) -> Option<(EccInput, String)> {
    let id = ids.get(v.get_index("identity").ok()?)?.1.clone();
    let df = v.get_hex("df").unwrap_or_default();
    let input = EccInput {
        mutual: v.get_index("mode").unwrap_or(0) == 0,
        ca_no: v.get_int("ca").unwrap_or(0) as u8,
        ca2_no: v.get_int("ca2").unwrap_or(0) as u8,
        cert_file: v.get_uint("cert_file").unwrap_or(0) as u8,
        priv_no: v.get_int("priv").unwrap_or(0) as u8,
        select_df: v.get_bool("use_select").unwrap_or(false).then_some(df),
        check_issuer: v.get_bool("issuer").unwrap_or(false),
    };
    Some((input, id))
}
