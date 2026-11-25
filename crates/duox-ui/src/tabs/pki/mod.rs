//! CAs & certificates: the local store of root CAs, delegated CAs, reader and card certificates, and the
//! operations that connect it to a card (install a CA root key, write a certificate file, pre-check a chain).

mod model;
pub mod rootkey;

use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::files::{self, Filter};
use crate::ui::textview::TextView;
use crate::ui::tree::{self, Node, TreeEvent, TreeState};
use crate::ui::{clipboard, hex, style, theme, widgets};
use duox::pki::{keys::pem_is_encrypted, CertKind, CsnOrder, Entry, ImportOptions, IssueRequest, PrivateKeyFormat, PkiStore, RightsScope};
use iced::widget::{column, container, scrollable, text, text_editor, Row};
use iced::{Element, Length, Task};
use model::{CheckInput, ExportFormat, RightsInput};
use std::fmt;
use std::path::PathBuf;

const ASK_ROOT: u32 = 1;
const ASK_ISSUE: u32 = 2;
const ASK_IMPORT: u32 = 3;
const ASK_EXPORT: u32 = 4;
const ASK_KEY_FILE: u32 = 5;
const CONFIRM_KEY: u32 = 6;
const CONFIRM_DELETE: u32 = 7;
const ASK_PASSPHRASE: u32 = 8;
const ASK_INSTALL: u32 = 9;
const ASK_WRITE: u32 = 10;
const ASK_CHECK: u32 = 11;

const NOT_CONNECTED: &str = "Not connected. Pick a reader and press Connect first.";
const EMPTY_HELP: &str = "Select an entry to see its certificate.";

/// A private key export waiting for the user to confirm writing it unencrypted.
struct KeyExport {
    id: String,
    path: PathBuf,
    format: PrivateKeyFormat,
    passphrase: Option<String>,
}

#[derive(Default)]
pub struct State {
    nodes: Vec<Node>,
    tree: TreeState,
    known: std::collections::HashSet<String>,
    detail: TextView,
    notice: String,
    /// Entry the open dialog is about (the list cannot change while a dialog is open).
    target: Option<String>,
    issue_kind: Option<CertKind>,
    key_export: Option<KeyExport>,
}

// Dialog answers can hold passphrases, so the state prints nothing of its content.
impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("pki::State").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    /// Answer to `Shared::ask` / `confirm`. `values` is `None` when cancelled or answered "no".
    FormDone { token: u32, values: Option<FormValues> },
    /// Broadcast from the application (connect, disconnect, store changed, tab activated).
    Event(AppEvent),
    Tree(TreeEvent),
    View(text_editor::Action),
    NewRoot,
    Issue(CertKind),
    Import,
    ExportCert,
    ExportKey,
    CopyPublicKey,
    CopyDetail,
    Revoke,
    Delete,
    Passphrase,
    Install,
    WriteCert,
    Check,
}

fn fail(shared: &mut Shared, msg: impl Into<String>) -> Task<app::Message> {
    shared.report_error(msg);
    Task::none()
}

/// Make the user enter the store passphrase when private keys are locked. True when the prompt was opened.
fn prompt_if_locked(shared: &mut Shared) -> bool {
    if !shared.store.is_locked() {
        return false;
    }
    let Some(id) = shared.store.entries().iter().find(|e| e.has_key()).map(|e| e.id.clone()) else {
        return false;
    };
    // Using a key is what makes the store ask for the passphrase.
    let _ = shared.with_store(|s| s.key_of(&id).map(|_| ()));
    true
}

fn store_status(store: &PkiStore) -> String {
    let keys = if store.is_locked() {
        "private keys encrypted (locked)"
    } else if store.is_encrypted() {
        "private keys encrypted (unlocked)"
    } else {
        "private keys stored unencrypted"
    };
    let place = store.path().map(|p| p.display().to_string()).unwrap_or_else(|| "not saved (no file)".into());
    format!("{} entries, {keys}   |   {place}", store.entries().len())
}

impl State {
    fn selected<'a>(&self, shared: &'a Shared) -> Option<&'a Entry> {
        self.tree.selected.as_deref().and_then(|id| shared.store.get(id).ok())
    }

    fn current(&self, shared: &Shared) -> Result<Entry, String> {
        self.selected(shared).cloned().ok_or_else(|| "Select an entry in the list first.".to_string())
    }

    /// Rebuild the list from the store and keep the selection when the entry still exists.
    fn refresh(&mut self, shared: &Shared) {
        self.nodes = model::tree_nodes(&shared.store);
        let mut fresh = Vec::new();
        fn collect(n: &Node, out: &mut Vec<Node>) {
            out.push(Node { children: Vec::new(), ..n.clone() });
            n.children.iter().for_each(|c| collect(c, out));
        }
        for n in &self.nodes {
            collect(n, &mut fresh);
        }
        for n in &fresh {
            if self.known.insert(n.id.clone()) {
                self.tree.expanded.insert(n.id.clone());
            }
        }
        if self.tree.selected.as_deref().is_some_and(|id| shared.store.get(id).is_err()) {
            self.tree.selected = None;
        }
        self.show(shared);
    }

    fn show(&mut self, shared: &Shared) {
        let text = match self.selected(shared) {
            Some(e) => model::describe_entry(&shared.store, e),
            None => EMPTY_HELP.to_string(),
        };
        self.detail.set_text(&text);
    }

    fn select(&mut self, id: &str, shared: &Shared) {
        self.tree.selected = Some(id.to_string());
        self.refresh(shared);
    }

    fn say(&mut self, shared: &Shared, text: impl Into<String>) {
        self.notice = text.into();
        shared.log_info(&self.notice);
    }

    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::Event(AppEvent::Connected | AppEvent::Disconnected) => {}
            Message::Event(_) => self.refresh(shared),
            Message::Tree(ev) => {
                let select = matches!(ev, TreeEvent::Select(_));
                self.tree.update(ev);
                if select {
                    self.notice.clear();
                    self.show(shared);
                }
            }
            Message::View(action) => self.detail.perform(action),
            Message::CopyDetail => {
                let text = self.detail.selection().unwrap_or_else(|| self.detail.text());
                return clipboard::copy(text);
            }
            Message::CopyPublicKey => match self.current(shared).and_then(|e| e.public_bytes().map_err(|e| e.to_string())) {
                Ok(pk) => {
                    self.say(shared, "Public key copied to the clipboard.");
                    return clipboard::copy(hex::compact(&pk));
                }
                Err(e) => return fail(shared, e),
            },
            Message::NewRoot => shared.ask(
                FormSpec::new("New root CA")
                    .note(
                        "The CA key pair is generated and kept in the local store. Its public key is what gets \
                         installed on cards as a CA root key.",
                    )
                    .ok_text("Create")
                    .text("name", "Common name", "DUOX Reader Root CA")
                    .text("org", "Organisation (optional)", "")
                    .combo("curve", "Curve", &model::curve_labels(), 0)
                    .int_range("years", "Validity (years)", 10, 1, 50),
                ASK_ROOT,
            ),
            Message::Issue(kind) => return self.ask_issue(kind, shared),
            Message::Import => shared.ask(
                FormSpec::new("Import certificate")
                    .note(
                        "For the root CA certificates of trust-provisioned cards, or CAs and reader identities \
                         created elsewhere. A PEM file may hold several certificates.",
                    )
                    .ok_text("Import")
                    .file_open("cert", "Certificate file", vec![Filter::new("Certificates", &["pem", "crt", "cer", "der"])])
                    .hint("PEM or DER")
                    .file_open("key", "Private key file", vec![Filter::new("PEM keys", &["pem", "key"])])
                    .hint("Optional; PEM, PKCS#8 or SEC1.")
                    .secret("pass", "Key passphrase")
                    .hint("Only for an encrypted key file.")
                    .combo("kind", "Treat as", &["Detect automatically", "Root CA", "Delegated CA", "Reader", "Card"], 0)
                    .text("name", "Name", "")
                    .hint("Empty = common name of the certificate."),
                ASK_IMPORT,
            ),
            Message::ExportCert => match self.current(shared) {
                Ok(e) => {
                    self.target = Some(e.id.clone());
                    shared.ask(
                        FormSpec::new(format!("Export '{}'", e.name))
                            .ok_text("Export")
                            .combo("fmt", "Format", &ExportFormat::LABELS, 0)
                            .file_save(
                                "path",
                                "File",
                                &model::file_name(&e.name, "", "pem"),
                                vec![Filter::new("Certificates", &["pem", "der", "crt", "cer"])],
                            )
                            .hint("Change the extension to .der when you pick a DER format."),
                        ASK_EXPORT,
                    );
                }
                Err(m) => return fail(shared, m),
            },
            Message::ExportKey => return self.ask_export_key(shared),
            Message::Revoke => return self.revoke(shared),
            Message::Delete => match self.current(shared) {
                Ok(e) => {
                    let kids = shared.store.children(Some(&e.id)).len();
                    let text = if kids == 0 {
                        format!("Delete '{}' from the store? Its private key is lost.", e.name)
                    } else {
                        format!(
                            "Delete '{}' and the {kids} entries issued by it from the store? Their private keys are lost.",
                            e.name
                        )
                    };
                    self.target = Some(e.id);
                    shared.confirm_danger("Delete from store", &text, "Delete", CONFIRM_DELETE);
                }
                Err(m) => return fail(shared, m),
            },
            Message::Passphrase => {
                if prompt_if_locked(shared) {
                    self.say(shared, "Enter the current passphrase, then press Passphrase again.");
                    return Task::none();
                }
                let now = if shared.store.is_encrypted() {
                    "The private keys are encrypted."
                } else {
                    "The private keys are stored unencrypted."
                };
                shared.ask(
                    FormSpec::new("Store passphrase")
                        .note(format!(
                            "{now} Choose a new passphrase for the private keys in the store; leave both fields \
                             empty to store them unencrypted. Saved AES keys are always kept in clear."
                        ))
                        .ok_text("Set")
                        .secret("first", "New passphrase")
                        .secret("again", "Repeat"),
                    ASK_PASSPHRASE,
                );
            }
            Message::Install => return self.ask_install(shared),
            Message::WriteCert => return self.ask_write(shared),
            Message::Check => return self.ask_check(shared),
            Message::FormDone { token, values } => return self.form_done(token, values, shared),
        }
        Task::none()
    }

    // ------------------------------------------------------------------- dialogs

    fn ask_issue(&mut self, kind: CertKind, shared: &mut Shared) -> Task<app::Message> {
        let issuer_id = match model::issuer_for(&shared.store, self.tree.selected.as_deref(), kind) {
            Ok(id) => id,
            Err(m) => return fail(shared, m),
        };
        let issuer = match shared.store.get(&issuer_id) {
            Ok(e) => e.clone(),
            Err(e) => return fail(shared, e.to_string()),
        };
        let ctx = rootkey::CardContext::of(shared);
        let (title, default_name, note) = match kind {
            CertKind::Sub => (
                "New delegated CA",
                "Site CA".to_string(),
                "A delegated CA can issue reader certificates; the card then receives a chain of two. Without \
                 restriction it inherits the rights of the CA root key.",
            ),
            CertKind::Card => (
                "Issue card certificate",
                shared.card.as_ref().map(|c| c.uid().to_vec()).filter(|u| !u.is_empty()).map_or("Card".to_string(), |u| hex::compact(&u)),
                "Card certificates are returned by the card during mutual authentication. Leave the key empty to \
                 create an identity whose private key can be imported with ManageKeyPair, or paste the public key \
                 a card generated.",
            ),
            _ => (
                "Issue reader certificate",
                "Reader 1".to_string(),
                "Rights must be a subset of the issuer's. Without the extension the reader inherits everything the \
                 CA root key (or delegated CA) grants.",
            ),
        };
        let mut form = FormSpec::new(format!("{title} - issuer: {}", issuer.name))
            .note(note)
            .ok_text("Issue")
            .text("name", "Common name", &default_name)
            .text("org", "Organisation (optional)", "")
            .hex("pub", "Public key", "")
            .hint("65 bytes (130 hex digits); empty = generate a key pair here.")
            .int_range("years", "Validity (years)", 10, 1, 50);
        if kind != CertKind::Card {
            let (def_ar, def_df) = match issuer.access_rights().map(|a| a.scope) {
                Some(RightsScope::DfName { name, .. }) => (ctx.aid.unwrap_or(0), name),
                Some(RightsScope::Aid { aid, .. }) if ctx.aid.is_none() => (aid, Vec::new()),
                _ => (ctx.aid.unwrap_or(0), Vec::new()),
            };
            form = form
                .check("restrict", "Restrict access rights", kind == CertKind::Reader)
                .hint("Adds the NXP access-right extension.")
                .combo("by", "Application identified by", &["AID", "DF name"], 0)
                .hex_int_range("aid", "AID", u64::from(def_ar), 6, 0, 0xFF_FFFF)
                .hex("df", "DF name", &hex::spaced(&def_df))
                .text("ac", "Access conditions granted", "0")
                .hint("e.g. 0,5 or 0-D")
                .text("aid2", "Secondary AID", "")
                .hint("Optional, hex; with an AID only.")
                .text("ac2", "Secondary access conditions", "0")
                .check("critical", "Mark the extension critical", true);
        }
        self.target = Some(issuer_id);
        self.issue_kind = Some(kind);
        shared.ask(form, ASK_ISSUE);
        Task::none()
    }

    fn ask_export_key(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let e = match self.current(shared) {
            Ok(e) => e,
            Err(m) => return fail(shared, m),
        };
        if !e.has_key() {
            return fail(shared, format!("The store holds no private key for '{}'.", e.name));
        }
        if prompt_if_locked(shared) {
            self.say(shared, "Enter the store passphrase, then export the key again.");
            return Task::none();
        }
        self.target = Some(e.id.clone());
        shared.ask(
            FormSpec::new(format!("Export private key of '{}'", e.name))
                .note("Anyone with this file can act as this CA or reader. Protect it with a passphrase if you can.")
                .ok_text("Export")
                .combo("fmt", "Format", &["PKCS#8", "SEC1 (EC PRIVATE KEY)"], 0)
                .secret("pass", "Passphrase")
                .hint("Empty = write the key unencrypted. PKCS#8 only.")
                .file_save("path", "File", &model::file_name(&e.name, "-key", "pem"), vec![Filter::new("PEM", &["pem", "key"])]),
            ASK_KEY_FILE,
        );
        Task::none()
    }

    fn revoke(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let e = match self.current(shared) {
            Ok(e) => e,
            Err(m) => return fail(shared, m),
        };
        if e.kind == CertKind::Root {
            return fail(
                shared,
                "A root CA cannot be revoked in the list. Replace or remove its CA root key on the cards instead.",
            );
        }
        let root = match shared.store.root_of(&e.id) {
            Ok(r) => r.name.clone(),
            Err(err) => return fail(shared, err.to_string()),
        };
        let revoke = !e.revoked;
        if shared.with_store(|s| s.set_revoked(&e.id, revoke)).is_ok() {
            shared.store_changed();
            let serial = e.serial().map_or("?".to_string(), |s| s.to_string());
            let text = if revoke {
                format!("Serial {serial} added to the revocation list of '{root}'.")
            } else {
                format!("Serial {serial} removed from the revocation list of '{root}'.")
            };
            self.say(shared, format!("{text} Cards only learn about it when the CRL is pushed to them (CRL tab)."));
            self.refresh(shared);
        }
        Task::none()
    }

    fn ask_install(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let e = match self.current(shared) {
            Ok(e) => e,
            Err(m) => return fail(shared, m),
        };
        if !e.kind.is_ca() {
            return fail(shared, "Select a CA entry (root or delegated CA) to install as a CA root key.");
        }
        if !shared.is_connected() {
            return fail(shared, NOT_CONNECTED);
        }
        let ctx = rootkey::CardContext::of(shared);
        shared.ask(rootkey::form(&shared.store, ctx, Some(&e.id), None), ASK_INSTALL);
        Task::none()
    }

    fn ask_write(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let e = match self.current(shared) {
            Ok(e) => e,
            Err(m) => return fail(shared, m),
        };
        if !shared.is_connected() {
            return fail(shared, NOT_CONNECTED);
        }
        let issued_by_sub = e.parent.as_deref().and_then(|p| shared.store.get(p).ok()).is_some_and(|p| p.kind == CertKind::Sub);
        self.target = Some(e.id.clone());
        let mut form = FormSpec::new(format!("Write '{}' to a card file", e.name))
            .note(
                "Stored as CertificateLength (3 bytes, LSB first) || certificate || padding, the format the card \
                 expects for the certificate it returns in mutual authentication. The file must exist and the \
                 current authentication must allow writing it.",
            )
            .ok_text("Write")
            .hex_int_range("file", "File number", 1, 2, 0, 0x1F);
        if issued_by_sub {
            form = form.check("chain", "Append the issuing delegated CA certificate", true);
        }
        shared.ask(form, ASK_WRITE);
        Task::none()
    }

    fn ask_check(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let e = match self.current(shared) {
            Ok(e) => e,
            Err(m) => return fail(shared, m),
        };
        if !matches!(e.kind, CertKind::Reader | CertKind::Sub) {
            return fail(shared, "Select a reader certificate or a delegated CA to check.");
        }
        let ctx = rootkey::CardContext::of(shared);
        let (ar_aid, ar_df) = match e.access_rights().map(|a| a.scope) {
            Some(RightsScope::Aid { aid, .. }) => (Some(aid), Vec::new()),
            Some(RightsScope::DfName { name, .. }) => (None, name),
            _ => (None, Vec::new()),
        };
        let uid = shared.card.as_ref().map(|c| model::uid_text(c.uid())).unwrap_or_default();
        self.target = Some(e.id.clone());
        shared.ask(
            FormSpec::new(format!("Check '{}' as the card would", e.name))
                .note(
                    "Applies the card's own chain rules to the certificate against its root CA, as if the card held \
                     the CA as CA root key. Nothing is sent to the card.",
                )
                .ok_text("Check")
                .hex_int_range("aid", "Selected application (AID)", u64::from(ctx.aid.or(ar_aid).unwrap_or(0)), 6, 0, 0xFF_FFFF)
                .hex("df", "DF name of the application", &hex::spaced(&ar_df))
                .hex("uid", "Card UID", &uid)
                .hint("Only needed for rights bound to a card.")
                .text("rootac", "CA root key access conditions", "0-D")
                .check("issuer", "Card checks the certificate issuer name", true)
                .combo("order", "Serial byte order in the CRL file", &["MSB first", "LSB first"], 0),
            ASK_CHECK,
        );
        Task::none()
    }

    // ------------------------------------------------------------- dialog answers

    fn form_done(&mut self, token: u32, values: Option<FormValues>, shared: &mut Shared) -> Task<app::Message> {
        let target = self.target.take();
        let issue_kind = self.issue_kind.take();
        if token == CONFIRM_KEY {
            let pending = self.key_export.take();
            return match (values, pending) {
                (Some(_), Some(p)) => self.write_key(p, shared),
                _ => Task::none(),
            };
        }
        let Some(v) = values else { return Task::none() };
        let result = match token {
            ASK_ROOT => self.do_new_root(&v, shared),
            ASK_ISSUE => self.do_issue(&v, target, issue_kind, shared),
            ASK_IMPORT => self.do_import(&v, shared),
            ASK_EXPORT => self.do_export(&v, target, shared),
            ASK_KEY_FILE => return self.do_key_file(&v, target, shared),
            CONFIRM_DELETE => self.do_delete(target, shared),
            ASK_PASSPHRASE => self.do_passphrase(&v, shared),
            ASK_INSTALL => self.do_install(&v, shared),
            ASK_WRITE => self.do_write(&v, target, shared),
            ASK_CHECK => self.do_check(&v, target, shared),
            _ => Ok(()),
        };
        match result {
            Ok(()) => Task::none(),
            Err(m) => fail(shared, m),
        }
    }

    fn do_new_root(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let name = v.get_str("name")?.trim().to_string();
        if name.is_empty() {
            return Err("A CA needs a common name.".into());
        }
        let org = v.get_str("org")?.trim().to_string();
        let curve = model::curve_at(v.get_index("curve")?);
        let years = v.get_int("years")? as u32;
        if let Ok(e) = shared.with_store(|s| s.new_root(&name, curve, &org, years)) {
            shared.store_changed();
            self.select(&e.id, shared);
            self.say(shared, format!("Root CA '{name}' created."));
        }
        Ok(())
    }

    fn do_issue(
        &mut self,
        v: &FormValues,
        issuer_id: Option<String>,
        kind: Option<CertKind>,
        shared: &mut Shared,
    ) -> Result<(), String> {
        let (Some(issuer_id), Some(kind)) = (issuer_id, kind) else { return Ok(()) };
        let name = v.get_str("name")?.trim().to_string();
        if name.is_empty() {
            return Err("A certificate needs a common name.".into());
        }
        let org = v.get_str("org")?.trim().to_string();
        let issuer_curve = shared.store.get(&issuer_id).map_err(|e| e.to_string())?.curve;
        let public = model::check_public_key(&v.get_hex("pub")?, issuer_curve)?;
        let years = v.get_int("years")? as u32;
        let rights = if kind != CertKind::Card && v.get_bool("restrict")? {
            Some(model::build_rights(&RightsInput {
                by_df_name: v.get_index("by")? == 1,
                aid: v.get_uint("aid")? as u32,
                df_name: v.get_hex("df")?,
                acmap: v.get_str("ac")?.to_string(),
                secondary_aid: v.get_str("aid2")?.to_string(),
                secondary_acmap: v.get_str("ac2")?.to_string(),
                delegation: kind == CertKind::Sub,
            })?)
        } else {
            None
        };
        let critical = if kind == CertKind::Card { true } else { v.get_bool("critical")? };
        let mut req = IssueRequest::new(kind, &name).organization(&org).years(years).critical(critical);
        if let Some(r) = rights {
            req = req.access_rights(r);
        }
        if let Some(p) = &public {
            req = req.public_key(p);
        }
        if let Ok(e) = shared.with_store(|s| s.issue(&issuer_id, req)) {
            shared.store_changed();
            self.select(&e.id, shared);
            self.say(shared, format!("{} '{name}' issued, serial {}.", kind.label(), e.serial().unwrap_or(0)));
        }
        Ok(())
    }

    fn do_import(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let cert_path = v.get_path("cert")?.ok_or("Choose the certificate file to import.")?;
        let blob = files::read_file(&cert_path)?;
        let key_text = match v.get_path("key")? {
            Some(p) => {
                let raw = files::read_file(&p)?;
                Some(String::from_utf8(raw).map_err(|_| format!("{} is not a PEM text file.", p.display()))?)
            }
            None => None,
        };
        let pass = v.get_str("pass")?.to_string();
        if let Some(k) = &key_text {
            if pem_is_encrypted(k) && pass.is_empty() {
                return Err("The private key file is encrypted; enter its passphrase.".into());
            }
        }
        let kind = match v.get_index("kind")? {
            1 => Some(CertKind::Root),
            2 => Some(CertKind::Sub),
            3 => Some(CertKind::Reader),
            4 => Some(CertKind::Card),
            _ => None,
        };
        let name = v.get_str("name")?.trim().to_string();
        let opts = ImportOptions {
            key_pem: key_text.as_deref(),
            key_passphrase: (!pass.is_empty()).then_some(pass.as_str()),
            kind,
            name: (!name.is_empty()).then_some(name.as_str()),
        };
        if let Ok(list) = shared.with_store(|s| s.import(&blob, &opts)) {
            shared.store_changed();
            if let Some(first) = list.first() {
                self.select(&first.id, shared);
            }
            self.say(shared, format!("{} certificate(s) imported.", list.len()));
        }
        Ok(())
    }

    fn do_export(&mut self, v: &FormValues, id: Option<String>, shared: &mut Shared) -> Result<(), String> {
        let Some(id) = id else { return Ok(()) };
        let path = v.get_path("path")?.ok_or("Choose the file to write.")?;
        let format = ExportFormat::from_index(v.get_index("fmt")?);
        let e = shared.store.get(&id).map_err(|e| e.to_string())?;
        let data = format.bytes(&shared.store, e)?;
        files::write_file(&path, &data)?;
        self.say(shared, format!("{} bytes written to {}.", data.len(), path.display()));
        Ok(())
    }

    fn do_key_file(&mut self, v: &FormValues, id: Option<String>, shared: &mut Shared) -> Task<app::Message> {
        let Some(id) = id else { return Task::none() };
        let parsed = (|| -> Result<KeyExport, String> {
            let format = if v.get_index("fmt")? == 1 { PrivateKeyFormat::Sec1 } else { PrivateKeyFormat::Pkcs8 };
            let pass = v.get_str("pass")?.to_string();
            if format == PrivateKeyFormat::Sec1 && !pass.is_empty() {
                return Err("A passphrase can only be used with the PKCS#8 format; clear it or switch the format.".into());
            }
            let path = v.get_path("path")?.ok_or("Choose the file to write.")?;
            Ok(KeyExport { id: id.clone(), path, format, passphrase: (!pass.is_empty()).then_some(pass) })
        })();
        match parsed {
            Err(m) => fail(shared, m),
            Ok(p) if p.passphrase.is_some() => self.write_key(p, shared),
            Ok(p) => {
                self.key_export = Some(p);
                shared.confirm_danger(
                    "Write unencrypted private key",
                    "The private key will be written to the file WITHOUT encryption. Continue?",
                    "Write key",
                    CONFIRM_KEY,
                );
                Task::none()
            }
        }
    }

    fn write_key(&mut self, p: KeyExport, shared: &mut Shared) -> Task<app::Message> {
        let pem = shared.with_store(|s| s.export_key_pem_as(&p.id, p.format, p.passphrase.as_deref()));
        if let Ok(pem) = pem {
            match files::write_file(&p.path, pem.as_bytes()) {
                Ok(()) => self.say(shared, format!("Private key written to {}.", p.path.display())),
                Err(m) => return fail(shared, m),
            }
        }
        Task::none()
    }

    fn do_delete(&mut self, id: Option<String>, shared: &mut Shared) -> Result<(), String> {
        let Some(id) = id else { return Ok(()) };
        if shared.with_store(|s| s.delete(&id)).is_ok() {
            shared.store_changed();
            self.tree.selected = None;
            self.refresh(shared);
            self.say(shared, "Deleted from the store.");
        }
        Ok(())
    }

    fn do_passphrase(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let new = model::new_passphrase(v.get_str("first")?, v.get_str("again")?)?;
        if shared.with_store(|s| s.set_passphrase(new.as_deref())).is_ok() {
            shared.store_changed();
            let text = if new.is_some() { "Private keys are now encrypted with the passphrase." } else { "Private keys are now stored unencrypted." };
            self.say(shared, text);
        }
        Ok(())
    }

    fn do_install(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let ctx = rootkey::CardContext::of(shared);
        let input = rootkey::Input::from_values(v)?;
        let (spec, text) = rootkey::build(&shared.store, ctx, &input)?;
        if shared.with_card(|c| c.manage_ca_root_key(&spec, None)).is_ok() {
            self.say(shared, format!("{text}."));
        }
        Ok(())
    }

    fn do_write(&mut self, v: &FormValues, id: Option<String>, shared: &mut Shared) -> Result<(), String> {
        let Some(id) = id else { return Ok(()) };
        let e = shared.store.get(&id).map_err(|e| e.to_string())?.clone();
        let append = v.get_bool("chain").unwrap_or(false);
        let data = model::card_file_payload(&shared.store, &e, append)?;
        let file = v.get_uint("file")? as u8;
        if shared.with_card(|c| c.write_cert_file(file, &data)).is_ok() {
            self.say(shared, format!("{} bytes written to file {file:02X}.", data.len()));
        }
        Ok(())
    }

    fn do_check(&mut self, v: &FormValues, id: Option<String>, shared: &mut Shared) -> Result<(), String> {
        let Some(id) = id else { return Ok(()) };
        let aid = v.get_uint("aid")? as u32;
        let input = CheckInput {
            aid,
            df_name: v.get_hex("df")?,
            uid: v.get_hex("uid")?,
            root_acmap: v.get_str("rootac")?.to_string(),
            check_issuer: v.get_bool("issuer")?,
            order: if v.get_index("order")? == 1 { CsnOrder::LsbFirst } else { CsnOrder::MsbFirst },
        };
        let opts = model::preflight_options(&input)?;
        let text = model::format_check(shared.store.preflight(&id, &opts), aid)?;
        shared.log_info(text.lines().next().unwrap_or_default());
        self.detail.set_text(&text);
        Ok(())
    }

    // ------------------------------------------------------------------------ view

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let connected = shared.is_connected();
        let kind = self.selected(shared).map(|e| e.kind);
        let any = kind.is_some();
        let is_ca = kind.is_some_and(CertKind::is_ca);
        let checkable = matches!(kind, Some(CertKind::Reader | CertKind::Sub));
        let has_key = self.selected(shared).is_some_and(Entry::has_key);

        let create = buttons(vec![
            btn("New root CA...", Message::NewRoot, true, true),
            btn("New delegated CA...", Message::Issue(CertKind::Sub), any, false),
            btn("Issue reader certificate...", Message::Issue(CertKind::Reader), any, false),
            btn("Issue card certificate...", Message::Issue(CertKind::Card), any, false),
            btn("Import...", Message::Import, true, false),
        ]);
        let manage = buttons(vec![
            btn("Export certificate...", Message::ExportCert, any, false),
            btn("Export private key...", Message::ExportKey, has_key, false),
            btn("Copy public key", Message::CopyPublicKey, any, false),
            btn("Revoke / reinstate", Message::Revoke, any && kind != Some(CertKind::Root), false),
            btn("Passphrase...", Message::Passphrase, true, false),
            danger_btn("Delete", Message::Delete, any),
        ]);
        let card = buttons(vec![
            btn("Install on card as CA root key...", Message::Install, is_ca && connected, false),
            btn("Write certificate to card file...", Message::WriteCert, any && connected, false),
            btn("Check as reader certificate...", Message::Check, checkable, false),
            btn("Copy text", Message::CopyDetail, true, false),
        ]);

        let list: Element<'_, Message> = if self.nodes.is_empty() {
            container(widgets::hint("The store is empty. Create a root CA or import a certificate."))
                .padding(theme::SPACE_MD)
                .into()
        } else {
            scrollable(tree::view(&self.nodes, &self.tree).map(Message::Tree)).width(Length::Fill).into()
        };

        let mut col = column![
            widgets::panel(column![create, manage, card].spacing(theme::SPACE_SM)),
            widgets::hint(store_status(&shared.store)),
        ]
        .spacing(theme::SPACE_SM);
        if !self.notice.is_empty() {
            col = col.push(text(self.notice.as_str()).size(theme::TEXT_BODY));
        }
        col.push(container(list).padding(theme::SPACE_XS).width(Length::Fill).height(Length::FillPortion(3)).style(style::panel))
            .push(container(self.detail.view().map(Message::View)).height(Length::FillPortion(2)))
            .padding(theme::SPACE_MD)
            .into()
    }
}

fn btn<'a>(label: &str, msg: Message, enabled: bool, primary: bool) -> iced::widget::Button<'a, Message> {
    let b = if primary { widgets::primary(label, msg) } else { widgets::secondary(label, msg) };
    if enabled { b } else { b.on_press_maybe(None) }
}

fn danger_btn<'a>(label: &str, msg: Message, enabled: bool) -> iced::widget::Button<'a, Message> {
    let b = widgets::danger(label, msg);
    if enabled { b } else { b.on_press_maybe(None) }
}

fn buttons<'a>(items: Vec<iced::widget::Button<'a, Message>>) -> Element<'a, Message> {
    Row::with_children(items.into_iter().map(Element::from)).spacing(theme::SPACE_SM).wrap().vertical_spacing(theme::SPACE_SM).into()
}
