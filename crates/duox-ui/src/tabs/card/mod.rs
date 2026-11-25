//! Card tab: browse applications, keys and files, read and write data, and manage them.
//!
//! * `model`  what is known about the card and how it is shown (tree, texts)
//! * `plan`   user input -> library specifications, all preconditions checked up front
//! * `forms`  the dialogs and their answers
//! * `ops`    the card commands of the browser (scan, load, read)

pub(crate) mod forms;
pub(crate) mod model;
mod ops;
pub(crate) mod plan;

use crate::app;
use crate::shared::{AppEvent, ScanInfo, Shared};
use crate::tabs::auth;
use crate::ui::form::FormValues;
use crate::ui::textview::TextView;
use crate::ui::tree::{self, Node, TreeEvent, TreeState};
use crate::ui::{clipboard, files, hex, theme, widgets};
use duox::card::{AccessRight, Aid, CaRootKeyInfo, DfName, EccKeyInfo, FileSettings, FileType, KeySettings, ModeSel};
use duox::pki::{CertKind, IssueRequest, TrustAnchor};
use forms::Choice;
use iced::widget::{button, column, row, scrollable, text_editor};
use iced::{Element, Length, Task};
use model::{Contents, Scan, Sel};
use plan::{RecordOp, ValueOp};
use std::path::PathBuf;

// Dialog tokens.
const T_SELECT_TWO: u32 = 1;
const T_PROBE: u32 = 2;
const T_WRITE: u32 = 3;
const T_VALUE: u32 = 4;
const T_RECORD: u32 = 5;
const T_NEW_APP: u32 = 6;
const T_NEW_FILE: u32 = 7;
const T_FILE_SETTINGS: u32 = 8;
const T_CHANGE_KEY: u32 = 9;
const T_KEY_SETTINGS: u32 = 10;
const T_KEY_PAIR: u32 = 11;
const T_CA_KEY: u32 = 12;
/// Answer of every yes/no question; what it was about is in `State::pending`.
const T_CONFIRM: u32 = 13;

/// What the browser knows about the selected application, for the Authenticate tab.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Primary selected application (`Aid::PICC` for the PICC level).
    pub selected: Option<Aid>,
    pub second: Option<Aid>,
    pub apps: Vec<Aid>,
    pub df_names: Vec<DfName>,
    pub keys: Option<KeySettings>,
    /// The CA root key list of the selected application was read.
    pub ca_known: bool,
    pub ca_keys: Vec<CaRootKeyInfo>,
    pub ecc_keys: Vec<EccKeyInfo>,
}

#[derive(Debug)]
struct LastRead {
    file_no: u8,
    data: Vec<u8>,
}

/// A question asked of the user whose answer continues an action.
#[derive(Debug)]
enum Pending {
    Scan,
    Delete(Sel),
    EditSdmFile(u8),
    KeySettings(u8),
    KeyPair { plan: plan::KeyPairPlan, certify: Option<Certify> },
    CaKey(plan::CaKeyPlan),
}

#[derive(Debug)]
struct Certify {
    ca_id: String,
    subject: String,
    file: Option<u8>,
}

#[derive(Debug, Default)]
pub struct State {
    scan: Option<Scan>,
    contents: Contents,
    second_files: Vec<FileSettings>,
    /// Application the card was selected with by DF name (the library cannot name it).
    hint_aid: Option<Aid>,
    nodes: Vec<Node>,
    tree: TreeState,
    detail: Output,
    last_read: Option<LastRead>,
    pending: Option<Pending>,
    publish: bool,
}

/// Selectable output text; a thin wrapper so the tab state stays `Debug`.
#[derive(Default)]
pub(crate) struct Output(pub TextView);

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Output")
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    FormDone { token: u32, values: Option<FormValues> },
    Event(AppEvent),
    Tree(TreeEvent),
    View(text_editor::Action),

    Scan,
    Select,
    SelectTwo,
    Refresh,
    Probe,
    Read,
    SaveData,
    SaveTo(Option<PathBuf>),
    DecodeCert,
    CopyOutput,
    Write,
    Value,
    Records,
    NewApp,
    NewFile,
    FileSettings,
    Delete,
    ChangeKey,
    KeySettings,
    KeyPair,
    CaKey,
    ExportKey,

    /// From the Authenticate tab: list the selected application again after an authentication.
    Reload,
    /// From the Authenticate tab: the application with this DF name was selected by ISOSelectFile.
    AssumeSelected(Aid),
}

impl State {
    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        let task = self.dispatch(msg, shared);
        if std::mem::take(&mut self.publish) {
            let snap = self.snapshot(shared);
            return Task::batch([task, Task::done(app::Message::Auth(auth::Message::Snapshot(snap)))]);
        }
        task
    }

    fn dispatch(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::Event(ev) => self.on_event(ev, shared),
            Message::FormDone { token, values } => self.on_answer(token, values, shared),
            Message::Tree(ev) => {
                let select = matches!(ev, TreeEvent::Select(_));
                self.tree.update(ev);
                if select {
                    self.show_detail(shared);
                }
            }
            Message::View(a) => self.detail.0.perform(a),
            Message::CopyOutput => {
                let t = self.detail.0.selection().unwrap_or_else(|| self.detail.0.text());
                return clipboard::copy(t);
            }
            Message::Scan => {
                if shared.card.as_ref().is_some_and(|c| c.is_authenticated()) {
                    self.pending = Some(Pending::Scan);
                    shared.confirm(
                        "Scan card",
                        "Scanning selects the PICC level again, which ends the current authentication. Continue?",
                        "Scan",
                        T_CONFIRM,
                    );
                } else {
                    self.scan(shared);
                }
            }
            Message::Select => self.select(shared),
            Message::SelectTwo => self.ask_select_two(shared),
            Message::Refresh => {
                if self.connected(shared) {
                    self.load(shared);
                    self.show_detail(shared);
                }
            }
            Message::Reload => {
                if shared.is_connected() {
                    self.load(shared);
                    self.show_detail(shared);
                }
            }
            Message::AssumeSelected(aid) => {
                self.hint_aid = Some(aid);
                self.rebuild(shared);
            }
            Message::Probe => self.ask_probe(shared),
            Message::Read => self.read(shared),
            Message::SaveData => return self.save_data(shared),
            Message::SaveTo(path) => {
                if let (Some(path), Some(r)) = (path, &self.last_read) {
                    match files::write_file(&path, &r.data) {
                        Ok(()) => shared.log_info(&format!("-- saved {} bytes to {}", r.data.len(), path.display())),
                        Err(e) => {
                            shared.report_error(e);
                        }
                    }
                }
            }
            Message::DecodeCert => self.decode_cert(shared),
            Message::Write => self.ask_write(shared),
            Message::Value => self.ask_value(shared),
            Message::Records => self.ask_record(shared),
            Message::NewApp => self.ask_new_app(shared),
            Message::NewFile => self.ask_new_file(shared),
            Message::FileSettings => self.file_settings(shared),
            Message::Delete => self.delete(shared),
            Message::ChangeKey => self.ask_change_key(shared),
            Message::KeySettings => self.ask_key_settings(shared),
            Message::KeyPair => self.ask_key_pair(shared),
            Message::CaKey => self.ask_ca_key(shared),
            Message::ExportKey => self.export_key(shared),
        }
        Task::none()
    }

    // ------------------------------------------------------------------ helpers

    fn connected(&self, shared: &mut Shared) -> bool {
        if shared.is_connected() {
            true
        } else {
            shared.report_error("Not connected. Pick a reader and press Connect.");
            false
        }
    }

    fn sel(&self) -> Sel {
        Sel::from_id(self.tree.selected.as_deref())
    }

    /// Primary and secondary application as the card has them selected.
    fn selection(&self, shared: &Shared) -> (Option<Aid>, Option<Aid>) {
        match shared.card.as_ref() {
            Some(c) => {
                let s = c.selection();
                (s.primary.or(self.hint_aid), s.secondary)
            }
            None => (None, None),
        }
    }

    fn at_picc(&self, shared: &Shared) -> bool {
        self.selection(shared).0 == Some(Aid::PICC)
    }

    fn file(&self, no: u8) -> Option<&FileSettings> {
        self.contents.files().iter().chain(&self.second_files).find(|f| f.file_no == no)
    }

    /// The selected file's settings, or an error message for the user.
    fn need_file(&self, shared: &mut Shared) -> Option<FileSettings> {
        if !self.connected(shared) {
            return None;
        }
        match self.sel() {
            Sel::File(no) => match self.file(no) {
                Some(f) => Some(f.clone()),
                None => {
                    shared.report_error("The file is not in the list any more. Refresh the application first.");
                    None
                }
            },
            _ => {
                shared.report_error("Select a file in the tree first.");
                None
            }
        }
    }

    fn out(&mut self, lines: &[String]) {
        self.detail.0.set_text(&lines.join("\n"));
    }

    fn out_text(&mut self, text: &str) {
        self.detail.0.set_text(text);
    }

    fn rebuild(&mut self, shared: &Shared) {
        let Some(scan) = self.scan.as_ref() else {
            self.nodes.clear();
            return;
        };
        let (primary, second) = self.selection(shared);
        let uid = shared.card.as_ref().map(|c| c.uid().to_vec()).unwrap_or_default();
        self.nodes = model::build_tree(scan, &uid, primary, second, &self.contents, &self.second_files);
        // keep the selection only if its node still exists
        fn exists(nodes: &[Node], id: &str) -> bool {
            nodes.iter().any(|n| n.id == id || exists(&n.children, id))
        }
        if let Some(id) = &self.tree.selected {
            if !exists(&self.nodes, id) {
                self.tree.selected = None;
            }
        }
        if let Some(a) = primary {
            self.tree.expanded.insert(model::node_id_for_aid(a));
        }
        for g in ["grp:aes", "grp:ecc", "grp:ca", "grp:files", "grp:files2"] {
            self.tree.expanded.insert(g.to_string());
        }
        if let Some(a) = second {
            self.tree.expanded.insert(format!("app2:{}", a.0));
        }
    }

    fn snapshot(&self, shared: &Shared) -> Snapshot {
        let (selected, second) = self.selection(shared);
        let scan = self.scan.as_ref();
        Snapshot {
            selected,
            second,
            apps: scan.map(|s| s.apps.clone()).unwrap_or_default(),
            df_names: scan.map(|s| s.df_names.values().cloned().collect()).unwrap_or_default(),
            keys: self.contents.keys.loaded().cloned(),
            ca_known: self.contents.ca.loaded().is_some(),
            ca_keys: self.contents.ca_keys().to_vec(),
            ecc_keys: self.contents.ecc_keys().to_vec(),
        }
    }

    fn reset(&mut self) {
        *self = State::default();
    }

    // -------------------------------------------------------------------- events

    fn on_event(&mut self, ev: AppEvent, shared: &mut Shared) {
        match ev {
            AppEvent::Connected => self.scan(shared),
            AppEvent::Disconnected => {
                self.reset();
                self.publish = true;
            }
            AppEvent::StoreChanged | AppEvent::Activated => {}
        }
    }

    // ------------------------------------------------------------- scan, select

    fn scan(&mut self, shared: &mut Shared) {
        let Ok(scan) = shared.with_card(ops::scan) else { return };
        for n in &scan.notes {
            shared.log_info(&format!("   ({n})"));
        }
        let atr = shared.scan.as_ref().map(|s| s.atr.clone()).unwrap_or_default();
        shared.scan = Some(ScanInfo { atr, version: scan.version.clone(), applications: scan.apps.clone() });
        self.scan = Some(scan);
        self.second_files.clear();
        self.last_read = None;
        self.hint_aid = None;
        self.load(shared);
        self.tree.selected = Some("picc".into());
        self.show_detail(shared);
    }

    /// Read keys and files of the selected application.
    fn load(&mut self, shared: &mut Shared) {
        if self.scan.is_none() {
            self.scan = Some(Scan::default());
        }
        if let Ok(c) = shared.with_card_quiet(|c| Ok::<_, String>(ops::load_contents(c))) {
            let failures = [
                ("AES keys", matches!(c.keys, model::Section::Failed(_)), section_error(&c.keys)),
                ("ECC private keys", matches!(c.ecc, model::Section::Failed(_)), section_error(&c.ecc)),
                ("CA root keys", matches!(c.ca, model::Section::Failed(_)), section_error(&c.ca)),
                ("Files", matches!(c.files, model::Section::Failed(_)), section_error(&c.files)),
            ];
            for (name, failed, e) in failures {
                if failed {
                    shared.log_info(&format!("   ({name}: {e})"));
                }
            }
            for n in &c.notes {
                shared.log_info(&format!("   ({n})"));
            }
            self.contents = c;
        }
        self.rebuild(shared);
        self.publish = true;
    }

    fn select(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let Some(aid) = self.sel().aid() else {
            shared.report_error("Select the PICC level or an application in the tree first.");
            return;
        };
        match shared.with_card(|c| c.select_application(aid, None)) {
            Ok(rc) => {
                self.hint_aid = None;
                self.second_files.clear();
                self.last_read = None;
                self.contents = Contents::default();
                self.load(shared);
                self.tree.selected = Some(model::node_id_for_aid(aid));
                self.show_detail(shared);
                if rc == 1 {
                    shared.log_info("   (selected with limited functionality)");
                }
            }
            Err(_) => {
                // the card falls back to the PICC level
                self.contents = Contents::default();
                self.load(shared);
            }
        }
    }

    fn ask_select_two(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let apps = self.scan.as_ref().map(|s| s.apps.clone()).unwrap_or_default();
        let (first, second) = match (self.sel().aid().filter(|a| *a != Aid::PICC), apps.as_slice()) {
            (Some(a), _) => (a, apps.iter().copied().find(|x| *x != a).unwrap_or(a)),
            (None, [a, b, ..]) => (*a, *b),
            (None, [a]) => (*a, *a),
            (None, []) => (Aid(0x112233), Aid(0x445566)),
        };
        shared.ask(forms::select_two_form(first, second), T_SELECT_TWO);
    }

    fn select_two(&mut self, v: &FormValues, shared: &mut Shared) {
        let a1 = Aid(v.get_uint("a1").unwrap_or(0) as u32);
        let a2 = Aid(v.get_uint("a2").unwrap_or(0) as u32);
        if a1 == a2 {
            shared.report_error("Choose two different applications.");
            return;
        }
        if let Some(scan) = &self.scan {
            if !scan.apps.is_empty() {
                for a in [a1, a2] {
                    if !scan.apps.contains(&a) {
                        shared.report_error(format!("Application {a} is not on the card (see the scan)."));
                        return;
                    }
                }
            }
        }
        match shared.with_card(|c| c.select_application(a1, Some(a2))) {
            Ok(rc) => {
                self.hint_aid = None;
                self.second_files.clear();
                self.last_read = None;
                self.contents = Contents::default();
                self.load(shared);
                self.tree.selected = Some(model::node_id_for_aid(a1));
                let mut l = vec![
                    format!("Applications {a1} and {a2} selected{}.", if rc == 1 { " (limited functionality)" } else { "" }),
                    String::new(),
                    format!("{a1} is the primary application and is listed in the tree."),
                    format!("The card cannot list the files of {a2}: use \"Find files...\" to look for them by number."),
                    "Keys and files of the second application are addressed with bit 7 set.".into(),
                    "For ECC authentication both need the same CA root key, and the reader certificate must list both AIDs.".into(),
                ];
                if !self.contents.files().is_empty() || !self.contents.ca_keys().is_empty() {
                    l.push(String::new());
                }
                self.out(&l);
            }
            Err(_) => {
                self.contents = Contents::default();
                self.load(shared);
            }
        }
    }

    fn ask_probe(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        if self.selection(shared).1.is_none() {
            shared.report_error("No second application is selected. Use \"Select two...\" first.");
            return;
        }
        shared.ask(forms::probe_form(), T_PROBE);
    }

    fn probe(&mut self, v: &FormValues, shared: &mut Shared) {
        let numbers = match forms::parse_file_numbers(v.get_str("list").unwrap_or_default()) {
            Ok(n) => n,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let Ok(p) = shared.with_card_quiet(|c| Ok::<_, String>(ops::probe_second(c, &numbers))) else { return };
        let mut l = vec![format!("{} file(s) found in the second application.", p.found.len())];
        l.extend(p.notes.iter().map(|n| format!("({n})")));
        self.second_files = p.found;
        self.rebuild(shared);
        self.publish = true;
        self.out(&l);
    }

    // ------------------------------------------------------------------ details

    fn show_detail(&mut self, shared: &Shared) {
        let picc = self.at_picc(shared);
        let (primary, _) = self.selection(shared);
        let lines: Vec<String> = match self.sel() {
            Sel::Picc => match self.scan.as_ref().and_then(|s| s.version.as_ref().map(|v| (v, s.apps.len()))) {
                Some((v, n)) => model::version_text(v, n),
                None => vec!["PICC level (AID 000000)".into()],
            },
            Sel::App(a) => model::app_text(a, self.scan.as_ref().and_then(|s| s.df_of(a)), primary == Some(a)),
            Sel::Second(a) => vec![
                format!("Second application {a}"),
                String::new(),
                "Its keys and files are addressed with bit 7 set (key 81, file 81 ...).".into(),
                "The card cannot list its files. \"Find files...\" asks for them by number.".into(),
            ],
            Sel::AesGroup | Sel::Aes(_) => match self.contents.keys.loaded() {
                Some(k) => {
                    let mut l = model::key_settings_text(k, picc);
                    if let (Sel::Aes(n), true) = (self.sel(), picc) {
                        l.insert(0, format!("Key {n:02X}  {}", duox::card::types::picc_key_name(n)));
                        l.insert(1, String::new());
                    }
                    l
                }
                None => vec![],
            },
            Sel::Ecc(n) => self.contents.ecc_keys().iter().find(|k| k.key_no == n).map(model::ecc_key_text).unwrap_or_default(),
            Sel::Ca(n) => self.contents.ca_keys().iter().find(|k| k.key_no == n).map(model::ca_key_text).unwrap_or_default(),
            Sel::File(n) => self.file(n).map(|f| f.describe()).unwrap_or_default(),
            Sel::EccGroup | Sel::CaGroup | Sel::FilesGroup | Sel::SecondFilesGroup | Sel::None => vec![],
        };
        if !lines.is_empty() {
            self.out(&lines);
        }
    }

    // -------------------------------------------------------------------- reading

    fn read(&mut self, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        let free_value = fs.value.as_ref().is_some_and(|v| v.free_get_value());
        if !free_value {
            if let Some(p) = plan::access_problem(&fs, false, has(shared)) {
                shared.report_error(p);
                return;
            }
        }
        if let Ok(r) = shared.with_card(|c| ops::read_file(c, &fs)) {
            self.last_read = r.data.map(|data| LastRead { file_no: fs.file_no, data });
            self.out_text(&r.text);
        }
    }

    fn save_data(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let Some(r) = &self.last_read else {
            shared.report_error("Read a file first; Save writes what was read.");
            return Task::none();
        };
        let name = format!("file{:02X}.bin", r.file_no & 0x7F);
        files::pick_save("Save file data", &name, &[files::Filter::new("Binary", &["bin"])], |p| {
            app::Message::Card(Message::SaveTo(p))
        })
    }

    fn decode_cert(&mut self, shared: &mut Shared) {
        let Some(r) = &self.last_read else {
            shared.report_error("Read a certificate file first; Decode works on the data that was read.");
            return;
        };
        let anchors = trust_anchors(shared);
        match plan::decode_certificates(&r.data, &anchors) {
            Ok(l) => self.out(&l),
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    // -------------------------------------------------------------------- writing

    fn ask_write(&mut self, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        if !plan::is_data_file(&fs) {
            shared.report_error("Write applies to data files. Use Value... or Records... for the other file types.");
            return;
        }
        if fs.crl.is_some() {
            shared.report_error("This is a CRL file. Update it on the CRL tab so the version and signature are handled.");
            return;
        }
        if let Some(p) = plan::access_problem(&fs, true, has(shared)) {
            shared.report_error(p);
            return;
        }
        shared.ask(forms::write_form(&fs), T_WRITE);
    }

    fn write(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        let input = match forms::parse_write(v) {
            Ok(i) => i,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let raw = match &input.path {
            Some(p) => match files::read_file(p) {
                Ok(d) => d,
                Err(e) => {
                    shared.report_error(e);
                    return;
                }
            },
            None => input.hex_data,
        };
        let payload = if input.wrap_cert {
            match plan::certificate_file_payload(&raw) {
                Ok(p) => p,
                Err(e) => {
                    shared.report_error(e);
                    return;
                }
            }
        } else {
            raw
        };
        if let Err(e) = plan::plan_write(&fs, input.offset, &payload) {
            shared.report_error(e);
            return;
        }
        let no = fs.file_no;
        if shared.with_card(|c| c.write_data_with(no, input.offset, &payload, ModeSel::File(&fs))).is_ok() {
            let mut text = format!("Wrote {} bytes to file {:02X} at offset {}.", payload.len(), no & 0x7F, input.offset);
            if fs.file_type == FileType::BackupData {
                text.push_str("\nBackup file: the data becomes effective with CommitTransaction (Transactions tab).");
            }
            shared.log_info(&format!("-- {text}"));
            self.out_text(&text);
        }
    }

    fn ask_value(&mut self, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        if fs.value.is_none() {
            shared.report_error("Select a value file.");
            return;
        }
        shared.ask(forms::value_form(&fs), T_VALUE);
    }

    fn value_op(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        let (op, amount) = forms::parse_value(v);
        let amount = match plan::plan_value(&fs, op, amount) {
            Ok(a) => a,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let problem = match op {
            // debiting is also allowed with the read right
            ValueOp::Debit => plan::access_problem(&fs, false, has(shared)).and(plan::access_problem(&fs, true, has(shared))),
            _ => plan::access_problem(&fs, true, has(shared)),
        };
        if let Some(p) = problem {
            shared.report_error(p);
            return;
        }
        let no = fs.file_no;
        let sel = ModeSel::File(&fs);
        let r = match op {
            ValueOp::Credit => shared.with_card(|c| c.credit_with(no, amount, sel)),
            ValueOp::Debit => shared.with_card(|c| c.debit_with(no, amount, sel)),
            ValueOp::LimitedCredit => shared.with_card(|c| c.limited_credit_with(no, amount, sel)),
        };
        if r.is_ok() {
            let name = ValueOp::ALL.iter().find(|(_, o)| *o == op).map(|(n, _)| *n).unwrap_or("");
            self.out_text(&format!(
                "{name} {amount} sent to file {:02X}.\nThe change takes effect with CommitTransaction (Transactions tab).",
                no & 0x7F
            ));
        }
    }

    fn ask_record(&mut self, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        if fs.record.is_none() {
            shared.report_error("Select a record file.");
            return;
        }
        shared.ask(forms::record_form(&fs), T_RECORD);
    }

    fn record_op(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        let i = match forms::parse_record(v) {
            Ok(i) => i,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        if let Err(e) = plan::plan_record(&fs, i.op, i.rec, i.offset, &i.data) {
            shared.report_error(e);
            return;
        }
        if let Some(p) = plan::access_problem(&fs, true, has(shared)) {
            shared.report_error(p);
            return;
        }
        let no = fs.file_no;
        let sel = ModeSel::File(&fs);
        let r = match i.op {
            RecordOp::Clear => shared.with_card(|c| c.clear_record_file(no)),
            RecordOp::Write => shared.with_card(|c| c.write_record_with(no, i.offset, &i.data, sel)),
            RecordOp::Update => shared.with_card(|c| c.update_record_with(no, i.rec, i.offset, &i.data, sel)),
        };
        if r.is_ok() {
            self.out_text(&format!(
                "Record command sent to file {:02X}.\nChanges take effect with CommitTransaction (Transactions tab).",
                no & 0x7F
            ));
        }
    }

    // ----------------------------------------------------------------- management

    fn ask_new_app(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        if !self.at_picc(shared) {
            shared.report_error(
                "Applications are created at PICC level. Select the PICC level (this ends the authentication), then \
                 authenticate with the PICC master key if the card requires it.",
            );
            return;
        }
        let picc_keys = self.contents.keys.loaded();
        if let Some(p) = plan::master_key_problem(
            "Creating an application",
            picc_keys.is_some_and(|k| k.settings & 0x04 == 0),
            has(shared),
        ) {
            shared.report_error(p);
            return;
        }
        let existing: Vec<Aid> = self.scan.as_ref().map(|s| s.apps.clone()).unwrap_or_default();
        let mut aid = 0x112233u32;
        while existing.contains(&Aid(aid)) {
            aid += 1;
        }
        shared.ask(forms::app_form(aid), T_NEW_APP);
    }

    fn new_app(&mut self, v: &FormValues, shared: &mut Shared) {
        let existing: Vec<Aid> = self.scan.as_ref().map(|s| s.apps.clone()).unwrap_or_default();
        let spec = match plan::plan_app(&forms::parse_app(v), &existing) {
            Ok(s) => s,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        if shared.with_card(|c| c.create_application(&spec)).is_ok() {
            let aid = spec.aid;
            self.refresh_applications(shared);
            self.out_text(&format!(
                "Application {aid} created with all-zero keys.\nSelect it, then authenticate with key 00 to create files."
            ));
        }
    }

    /// Re-list the applications at PICC level without selecting anything (keeps the authentication).
    fn refresh_applications(&mut self, shared: &mut Shared) {
        let mut scan = self.scan.take().unwrap_or_default();
        if shared.with_card_quiet(|c| Ok::<_, String>(ops::list_applications(c, &mut scan))).is_ok() {
            if let Some(info) = shared.scan.as_mut() {
                info.applications = scan.apps.clone();
            }
        }
        self.scan = Some(scan);
        self.load(shared);
    }

    fn ask_new_file(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let (primary, second) = self.selection(shared);
        if primary.is_none() {
            shared.report_error("The selected application is not known. Select an application in the tree first.");
            return;
        }
        let picc = primary == Some(Aid::PICC);
        if !picc {
            if let Some(p) = plan::master_key_problem(
                "Creating a file",
                self.contents.keys.loaded().is_some_and(|k| k.settings & 0x04 == 0),
                has(shared),
            ) {
                shared.report_error(p);
                return;
            }
        }
        let used: Vec<u8> = self.contents.files().iter().map(|f| f.file_no).collect();
        let no = (1..=0x1Fu8).find(|n| !used.contains(n)).unwrap_or(1);
        shared.ask(forms::file_form(no, second.is_some(), picc), T_NEW_FILE);
    }

    fn new_file(&mut self, v: &FormValues, shared: &mut Shared) {
        let picc = self.at_picc(shared);
        let input = forms::parse_file(v);
        let mut existing = forms::existing_files(self.contents.files());
        existing.extend(forms::existing_files(&self.second_files));
        let spec = match plan::plan_new_file(&input, &existing, picc) {
            Ok(s) => s,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let r = match &spec {
            plan::FileSpec::Data(s) => shared.with_card(|c| c.create_data_file(s)),
            plan::FileSpec::Value(s) => shared.with_card(|c| c.create_value_file(s)),
            plan::FileSpec::Record(s) => shared.with_card(|c| c.create_record_file(s)),
            plan::FileSpec::Tmac(s) => shared.with_card(|c| c.create_tmac_file(s)),
        };
        if r.is_ok() {
            self.load(shared);
            self.out_text(&format!("File {:02X} created.", input.number));
        }
    }

    fn file_settings(&mut self, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        if let Some(p) = plan::condition_problem("Changing the file settings", fs.access.change, fs.is_secondary_app(), has(shared)) {
            shared.report_error(p);
            return;
        }
        if fs.sdm.is_some() || (fs.option & 0x40 != 0 && fs.file_type == FileType::StandardData) {
            self.pending = Some(Pending::EditSdmFile(fs.file_no));
            shared.confirm_danger(
                "Secure Dynamic Messaging file",
                "This file uses Secure Dynamic Messaging. Edit it on the SDM tab so the SDM settings are kept.\n\n\
                 Change it here anyway? This DISABLES SDM.",
                "Change anyway",
                T_CONFIRM,
            );
            return;
        }
        shared.ask(forms::change_settings_form(&fs), T_FILE_SETTINGS);
    }

    fn change_file_settings(&mut self, v: &FormValues, shared: &mut Shared) {
        let Some(fs) = self.need_file(shared) else { return };
        let change = match forms::parse_change(v, &fs).and_then(|i| plan::plan_file_change(&fs, &i)) {
            Ok(c) => c,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let no = fs.file_no;
        if shared.with_card(|c| c.change_file_settings(no, &change)).is_ok() {
            self.load(shared);
            self.out_text(&format!("Settings of file {:02X} changed.", no & 0x7F));
        }
    }

    fn delete(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let sel = self.sel();
        match sel {
            Sel::File(no) => {
                let Some(fs) = self.file(no).cloned() else {
                    shared.report_error("The file is not in the list any more. Refresh the application first.");
                    return;
                };
                let needs_master = self.contents.keys.loaded().is_some_and(|k| k.settings & 0x04 == 0);
                if let Some(p) = plan::master_key_problem("Deleting a file", needs_master, has(shared)) {
                    shared.report_error(p);
                    return;
                }
                self.pending = Some(Pending::Delete(sel));
                shared.confirm_danger(
                    "Delete file",
                    &format!(
                        "Delete file {:02X} ({})? Its memory is only reclaimed by formatting the card.",
                        fs.file_no & 0x7F,
                        fs.type_label()
                    ),
                    "Delete",
                    T_CONFIRM,
                );
            }
            Sel::App(aid) => {
                let (primary, _) = self.selection(shared);
                if primary != Some(Aid::PICC) && primary != Some(aid) {
                    shared.report_error(
                        "An application is deleted from the PICC level or, with its master key, while it is selected. \
                         Select the PICC level or this application first.",
                    );
                    return;
                }
                if let Some(p) = plan::master_key_problem("Deleting an application", true, has(shared)) {
                    shared.report_error(p);
                    return;
                }
                self.pending = Some(Pending::Delete(sel));
                shared.confirm_danger(
                    "Delete application",
                    &format!("Delete application {aid} with all its files and keys?"),
                    "Delete",
                    T_CONFIRM,
                );
            }
            _ => {
                shared.report_error("Select a file or an application to delete.");
            }
        }
    }

    fn do_delete(&mut self, sel: Sel, shared: &mut Shared) {
        match sel {
            Sel::File(no) => {
                if shared.with_card(|c| c.delete_file(no)).is_ok() {
                    self.load(shared);
                    self.out_text(&format!("File {:02X} deleted.", no & 0x7F));
                }
            }
            Sel::App(aid) => {
                let was_selected = self.selection(shared).0 == Some(aid);
                if shared.with_card(|c| c.delete_application(aid, &[])).is_ok() {
                    if was_selected {
                        self.scan(shared);
                    } else {
                        self.refresh_applications(shared);
                    }
                    self.out_text(&format!("Application {aid} deleted."));
                }
            }
            _ => {}
        }
    }

    // ----------------------------------------------------------------------- keys

    fn saved_keys(shared: &Shared) -> Vec<String> {
        shared.store.aes_key_names().into_iter().map(str::to_string).collect()
    }

    fn ask_change_key(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let default = if let Sel::Aes(n) = self.sel() { n } else { 0 };
        let has_sets = self.contents.keys.loaded().is_some_and(|k| k.key_sets.is_some());
        let second = self.selection(shared).1.is_some();
        shared.ask(forms::change_key_form(default, &Self::saved_keys(shared), second, has_sets), T_CHANGE_KEY);
    }

    fn change_key(&mut self, v: &FormValues, shared: &mut Shared) {
        let saved = Self::saved_keys(shared);
        let input = match forms::parse_change_key(v, &saved, |n| shared.store.aes_key(n)) {
            Ok(i) => i,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let auth = shared.card.as_ref().and_then(|c| c.auth_summary());
        let picc = self.at_picc(shared);
        let second_selected = self.selection(shared).1.is_some();
        let env = plan::KeyEnv { picc, auth: auth.as_ref(), keys: self.contents.keys.loaded(), second_selected };
        let spec = match plan::plan_change_key(&input, &env) {
            Ok(s) => s,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        if shared.with_card(|c| c.change_key(&spec)).is_ok() {
            let still = shared.card.as_ref().is_some_and(|c| c.is_authenticated());
            self.out_text(&format!(
                "Key {:02X} changed.{}",
                input.key_no,
                if still { "" } else { "\nThe authentication ended; authenticate again with the new key." }
            ));
        }
    }

    fn ask_key_settings(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let picc = self.at_picc(shared);
        shared.ask(forms::key_settings_form(self.contents.keys.loaded(), picc), T_KEY_SETTINGS);
    }

    fn key_settings(&mut self, v: &FormValues, shared: &mut Shared) {
        let picc = self.at_picc(shared);
        let input = forms::parse_key_settings(v, picc);
        let auth = shared.card.as_ref().and_then(|c| c.auth_summary());
        let env = plan::KeyEnv { picc, auth: auth.as_ref(), keys: self.contents.keys.loaded(), second_selected: false };
        let byte = match plan::plan_key_settings(&input, &env) {
            Ok(b) => b,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        if let Some(p) = plan::master_key_problem("Changing the key settings", true, has(shared)) {
            shared.report_error(p);
            return;
        }
        let frozen = !input.settings_changeable || (!picc && input.upper == 0xF);
        if frozen {
            self.pending = Some(Pending::KeySettings(byte));
            shared.confirm_danger(
                "Freeze key settings",
                "These settings cannot be changed afterwards (or freeze the keys). This is permanent. Continue?",
                "Change",
                T_CONFIRM,
            );
        } else {
            self.do_key_settings(byte, shared);
        }
    }

    fn do_key_settings(&mut self, byte: u8, shared: &mut Shared) {
        if shared.with_card(|c| c.change_key_settings(byte)).is_ok() {
            self.load(shared);
            self.out_text(&format!("Key settings changed to 0x{byte:02X}."));
        }
    }

    fn ask_key_pair(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let cur = match self.sel() {
            Sel::Ecc(n) => self.contents.ecc_keys().iter().find(|k| k.key_no == n).cloned(),
            _ => None,
        };
        let no = if let Sel::Ecc(n) = self.sel() { n } else { 0 };
        let cards = store_choices(shared, &[CertKind::Card], true);
        let cas = store_choices(shared, &[CertKind::Root, CertKind::Sub], true);
        let uid = shared.card.as_ref().map(|c| hex::compact(c.uid())).filter(|s| !s.is_empty()).unwrap_or_else(|| "card".into());
        let has_files = self.contents.files().iter().any(plan::is_data_file);
        shared.ask(forms::key_pair_form(no, cur.as_ref(), &cards, &cas, &uid, has_files), T_KEY_PAIR);
    }

    fn key_pair(&mut self, v: &FormValues, shared: &mut Shared) {
        let cards = store_choices(shared, &[CertKind::Card], true);
        let cas = store_choices(shared, &[CertKind::Root, CertKind::Sub], true);
        let mut f = match forms::parse_key_pair(v, &cards, &cas) {
            Ok(f) => f,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        if f.input.action == plan::PairAction::Import {
            if let Some(id) = &f.import_from_store {
                let Ok((key, curve)) = shared.with_store(|s| {
                    let e = s.get(id)?;
                    let curve = e.curve;
                    Ok((s.key_of(id)?.to_bytes(), curve))
                }) else {
                    return;
                };
                f.input.import_key = key;
                f.input.curve = curve;
            }
        }
        let picc = self.at_picc(shared);
        let authenticated = shared.card.as_ref().is_some_and(|c| c.is_authenticated());
        let kp = match plan::plan_key_pair(&f.input, picc, authenticated, self.contents.ecc_keys()) {
            Ok(p) => p,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        // certification: everything that can be checked before the key is generated
        let mut certify = None;
        if let Some(ca_id) = f.certify_with.clone() {
            if f.input.action != plan::PairAction::Generate {
                shared.report_error("A certificate can only be issued for a key generated on the card.");
                return;
            }
            if f.subject.is_empty() {
                shared.report_error("Enter a subject name for the card certificate.");
                return;
            }
            if shared.with_store(|s| s.key_of(&ca_id).map(|_| ())).is_err() {
                return;
            }
            if let Some(no) = f.cert_file {
                match self.contents.files().iter().find(|x| x.file_no == no) {
                    Some(fs) if plan::is_data_file(fs) && fs.crl.is_none() => {
                        if fs.size.unwrap_or(0) < plan::MIN_CARD_CERT_FILE {
                            shared.report_error(format!(
                                "File {no:02X} has only {} bytes, too small for a card certificate. Create a larger data file first.",
                                fs.size.unwrap_or(0)
                            ));
                            return;
                        }
                        if let Some(p) = plan::access_problem(fs, true, has(shared)) {
                            shared.report_error(p);
                            return;
                        }
                    }
                    Some(_) => {
                        shared.report_error(format!("File {no:02X} is not a plain data file that can hold a certificate."));
                        return;
                    }
                    None => {
                        shared.report_error(format!("File {no:02X} does not exist in this application. Create it first."));
                        return;
                    }
                }
            }
            certify = Some(Certify { ca_id, subject: f.subject.clone(), file: f.cert_file });
        }
        if kp.replaces {
            let msg = format!("ECC private key {} exists and will be replaced. Continue?", f.input.key_no);
            self.pending = Some(Pending::KeyPair { plan: kp, certify });
            shared.confirm_danger("Replace key", &msg, "Replace", T_CONFIRM);
        } else {
            self.do_key_pair(kp, certify, shared);
        }
    }

    fn do_key_pair(&mut self, p: plan::KeyPairPlan, certify: Option<Certify>, shared: &mut Shared) {
        let no = p.spec.key_no;
        let curve = p.spec.curve_id;
        let Ok(public) = shared.with_card(|c| c.manage_key_pair(&p.spec, &p.op, Some(p.mode))) else { return };
        let mut l = vec![format!("ManageKeyPair key {no}: done.")];
        if !public.is_empty() {
            l.push(String::new());
            l.push("Public key (keep it, the card never exports it again):".into());
            l.push(hex::spaced(&public));
            if let Some(c) = certify {
                match shared.with_store(|s| {
                    s.issue(&c.ca_id, IssueRequest::new(CertKind::Card, &c.subject).public_key(&public).curve(curve))
                }) {
                    Ok(entry) => {
                        shared.store_changed();
                        l.push(String::new());
                        l.push(format!(
                            "Issued card certificate #{} ({} bytes) for '{}'.",
                            entry.serial().unwrap_or(0),
                            entry.cert.len(),
                            c.subject
                        ));
                        if let Some(file) = c.file {
                            match shared.with_card(|card| card.write_cert_file(file, &entry.cert)) {
                                Ok(()) => l.push(format!("Certificate written to file {file:02X}.")),
                                Err(_) => l.push(format!(
                                    "The certificate could NOT be written to file {file:02X}; the key was generated and is in the store's certificate."
                                )),
                            }
                        }
                    }
                    Err(_) => l.push("The certificate could not be issued (see the message); the key itself was generated.".into()),
                }
            }
        }
        self.load(shared);
        self.out(&l);
    }

    fn ask_ca_key(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let (cur, no) = match self.sel() {
            Sel::Ca(n) => (self.contents.ca_keys().iter().find(|k| k.key_no == n).cloned(), n),
            _ => (None, 0),
        };
        let cas = store_choices(shared, &[CertKind::Root, CertKind::Sub], false);
        shared.ask(forms::ca_key_form(no, cur.as_ref(), &cas, usize::from(!cas.is_empty())), T_CA_KEY);
    }

    fn ca_key(&mut self, v: &FormValues, shared: &mut Shared) {
        let cas = store_choices(shared, &[CertKind::Root, CertKind::Sub], false);
        let f = match forms::parse_ca_key(v, &cas) {
            Ok(f) => f,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let acmap = match f.acmap {
            Ok(a) => a,
            Err(e) => {
                shared.report_error(format!("Access conditions: {e}"));
                return;
            }
        };
        let (public_key, curve, issuer) = match &f.store_ca {
            Some(id) => {
                let r = shared.with_store(|s| {
                    let e = s.get(id)?;
                    let issuer = if f.check_issuer { e.certificate()?.subject().to_der().to_vec() } else { Vec::new() };
                    Ok((e.public_bytes()?, e.curve, issuer))
                });
                match r {
                    Ok(t) => t,
                    Err(_) => return,
                }
            }
            None => {
                if f.pasted_pub.is_empty() {
                    shared.report_error("Choose a CA from the store or enter its public key.");
                    return;
                }
                (f.pasted_pub.clone(), f.pasted_curve, Vec::new())
            }
        };
        let (primary, _) = self.selection(shared);
        let input = plan::CaKeyInput {
            key_no: f.no,
            curve,
            public_key,
            issuer,
            acmap,
            write_mode: f.write_mode,
            write_ac: f.write_ac,
            read_mode: f.read_mode,
            read_ac: f.read_ac,
            crl: f.crl.map(|(file, aid)| (file, aid.or(primary).unwrap_or(Aid::PICC))),
        };
        let picc = self.at_picc(shared);
        let authenticated = shared.card.as_ref().is_some_and(|c| c.is_authenticated());
        match plan::plan_ca_key(&input, picc, authenticated, self.contents.ca_keys()) {
            Ok(p) if p.replaces => {
                let msg = format!("CA root key {} exists and will be replaced. Continue?", input.key_no);
                self.pending = Some(Pending::CaKey(p));
                shared.confirm_danger("Replace key", &msg, "Replace", T_CONFIRM);
            }
            Ok(p) => self.do_ca_key(p, shared),
            Err(e) => {
                shared.report_error(e);
            }
        }
    }

    fn do_ca_key(&mut self, p: plan::CaKeyPlan, shared: &mut Shared) {
        let no = p.spec.key_no;
        if shared.with_card(|c| c.manage_ca_root_key(&p.spec, Some(p.mode))).is_ok() {
            self.load(shared);
            self.out_text(&format!("CA root key {no} stored."));
        }
    }

    fn export_key(&mut self, shared: &mut Shared) {
        if !self.connected(shared) {
            return;
        }
        let Sel::Ca(no) = self.sel() else {
            shared.report_error("Select a CA root key in the tree first.");
            return;
        };
        let Some(info) = self.contents.ca_keys().iter().find(|k| k.key_no == no).cloned() else {
            shared.report_error("The key is not in the list any more. Refresh the application first.");
            return;
        };
        let authenticated = shared.card.as_ref().is_some_and(|c| c.is_authenticated());
        let mode = plan::export_mode(authenticated, &info);
        let Ok(public) = shared.with_card(|c| c.export_key(no, Some(mode))) else { return };
        let matches: Vec<String> = shared
            .store
            .by_kind(&[CertKind::Root, CertKind::Sub])
            .into_iter()
            .filter(|e| e.public_bytes().is_ok_and(|p| p == public))
            .map(|e| e.name.clone())
            .collect();
        let mut l = vec![format!("CA root key {no} public key:"), hex::spaced(&public), String::new()];
        l.push(if matches.is_empty() {
            "No matching CA in the store.".to_string()
        } else {
            format!("Matches store entry: {}", matches.join(", "))
        });
        self.out(&l);
    }

    // ------------------------------------------------------------------- answers

    fn on_answer(&mut self, token: u32, values: Option<FormValues>, shared: &mut Shared) {
        if token == T_CONFIRM {
            let pending = self.pending.take();
            if values.is_none() {
                return;
            }
            match pending {
                Some(Pending::Scan) => self.scan(shared),
                Some(Pending::Delete(sel)) => self.do_delete(sel, shared),
                Some(Pending::EditSdmFile(no)) => {
                    if let Some(fs) = self.file(no).cloned() {
                        shared.ask(forms::change_settings_form(&fs), T_FILE_SETTINGS);
                    }
                }
                Some(Pending::KeySettings(b)) => self.do_key_settings(b, shared),
                Some(Pending::KeyPair { plan, certify }) => self.do_key_pair(plan, certify, shared),
                Some(Pending::CaKey(p)) => self.do_ca_key(p, shared),
                None => {}
            }
            return;
        }
        let Some(v) = values else { return };
        match token {
            T_SELECT_TWO => self.select_two(&v, shared),
            T_PROBE => self.probe(&v, shared),
            T_WRITE => self.write(&v, shared),
            T_VALUE => self.value_op(&v, shared),
            T_RECORD => self.record_op(&v, shared),
            T_NEW_APP => self.new_app(&v, shared),
            T_NEW_FILE => self.new_file(&v, shared),
            T_FILE_SETTINGS => self.change_file_settings(&v, shared),
            T_CHANGE_KEY => self.change_key(&v, shared),
            T_KEY_SETTINGS => self.key_settings(&v, shared),
            T_KEY_PAIR => self.key_pair(&v, shared),
            T_CA_KEY => self.ca_key(&v, shared),
            _ => {}
        }
    }

    // ---------------------------------------------------------------------- view

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let connected = shared.is_connected();
        let sel = self.sel();
        let file = match sel {
            Sel::File(n) => self.file(n),
            _ => None,
        };
        let is_data = file.is_some_and(plan::is_data_file);
        let on = |cond: bool, m: Message| (connected && cond).then_some(m);

        let toolbar = row![
            action("Scan card", on(true, Message::Scan), Kind::Primary),
            action("Select", on(sel.aid().is_some(), Message::Select), Kind::Secondary),
            action("Select two...", on(true, Message::SelectTwo), Kind::Secondary),
            action("Refresh", on(true, Message::Refresh), Kind::Secondary),
        ]
        .spacing(theme::SPACE_SM);

        let tree_view: Element<'_, Message> = if self.nodes.is_empty() {
            widgets::hint(if connected { "Press Scan card." } else { "Connect a card to browse it." }).into()
        } else {
            scrollable(tree::view(&self.nodes, &self.tree).map(Message::Tree)).width(Length::Fill).height(Length::Fill).into()
        };
        let left = column![toolbar, framed(tree_view)]
            .spacing(theme::SPACE_SM)
            .width(Length::Fixed(440.0));

        let second_selected = shared.card.as_ref().is_some_and(|c| c.selection().secondary.is_some());
        let groups = column![
            widgets::group(
                "Read",
                buttons([
                    action("Read", on(file.is_some(), Message::Read), Kind::Secondary),
                    action("Save data...", on(self.last_read.is_some(), Message::SaveData), Kind::Secondary),
                    action("Decode certificate", on(self.last_read.is_some(), Message::DecodeCert), Kind::Secondary),
                    action("Find files...", on(second_selected, Message::Probe), Kind::Secondary),
                ])
            ),
            widgets::group(
                "Write",
                buttons([
                    action("Write...", on(is_data, Message::Write), Kind::Secondary),
                    action("Value...", on(file.is_some_and(|f| f.value.is_some()), Message::Value), Kind::Secondary),
                    action("Records...", on(file.is_some_and(|f| f.record.is_some()), Message::Records), Kind::Secondary),
                ])
            ),
            widgets::group(
                "Manage",
                buttons([
                    action("New application...", on(true, Message::NewApp), Kind::Secondary),
                    action("New file...", on(true, Message::NewFile), Kind::Secondary),
                    action("File settings...", on(file.is_some(), Message::FileSettings), Kind::Secondary),
                    action("Delete", on(file.is_some() || matches!(sel, Sel::App(_)), Message::Delete), Kind::Danger),
                ])
            ),
            widgets::group(
                "Keys",
                buttons([
                    action("Change AES key...", on(true, Message::ChangeKey), Kind::Secondary),
                    action("Key settings...", on(true, Message::KeySettings), Kind::Secondary),
                    action("ECC key pair...", on(true, Message::KeyPair), Kind::Secondary),
                    action("CA root key...", on(true, Message::CaKey), Kind::Secondary),
                    action("Export CA key", on(matches!(sel, Sel::Ca(_)), Message::ExportKey), Kind::Secondary),
                ])
            ),
        ]
        .spacing(theme::SPACE_SM);

        let output = column![
            row![widgets::hint("Output"), iced::widget::Space::new().width(Length::Fill), action("Copy", Some(Message::CopyOutput), Kind::Secondary)]
                .align_y(iced::Alignment::Center),
            framed(self.detail.0.view().map(Message::View)),
        ]
        .spacing(theme::SPACE_XS)
        .height(Length::Fill);

        let right = column![groups, output].spacing(theme::SPACE_MD).width(Length::Fill);
        row![left, right].spacing(theme::SPACE_MD).padding(theme::SPACE_SM).into()
    }
}

// --------------------------------------------------------------------- helpers

fn section_error<T>(s: &model::Section<T>) -> String {
    match s {
        model::Section::Failed(e) => e.clone(),
        _ => String::new(),
    }
}

/// Does the active authentication satisfy an access condition?
fn has(shared: &Shared) -> impl Fn(AccessRight, bool) -> bool + '_ {
    move |ac, secondary| shared.card.as_ref().is_some_and(|c| c.has_access_condition(ac, secondary))
}

fn store_choices(shared: &Shared, kinds: &[CertKind], need_key: bool) -> Vec<Choice> {
    shared
        .store
        .by_kind(kinds)
        .into_iter()
        .filter(|e| !need_key || e.has_key())
        .map(|e| (shared.store.label(e), e.id.clone()))
        .collect()
}

/// CA and delegated CA certificates of the store as trust anchors for card certificates.
pub(crate) fn trust_anchors(shared: &Shared) -> Vec<TrustAnchor> {
    shared
        .store
        .by_kind(&[CertKind::Root, CertKind::Sub])
        .into_iter()
        .filter_map(|e| e.certificate().ok())
        .map(TrustAnchor::Certificate)
        .collect()
}

#[derive(Clone, Copy)]
enum Kind {
    Primary,
    Secondary,
    Danger,
}

fn action<'a>(label: &str, msg: Option<Message>, kind: Kind) -> Element<'a, Message> {
    let b = button(iced::widget::text(label.to_string())).on_press_maybe(msg).padding([5, 14]);
    match kind {
        Kind::Primary => b.style(button::primary),
        Kind::Secondary => b.style(button::secondary),
        Kind::Danger => b.style(button::danger),
    }
    .into()
}

fn buttons<'a, const N: usize>(items: [Element<'a, Message>; N]) -> Element<'a, Message> {
    row(items).spacing(theme::SPACE_SM).wrap().into()
}


/// Bordered area that fills the space it is given.
fn framed<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    iced::widget::container(content)
        .padding(theme::SPACE_SM)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(crate::ui::style::panel)
        .into()
}
