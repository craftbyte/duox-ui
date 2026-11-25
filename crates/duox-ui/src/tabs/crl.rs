//! CRL: the revocation list kept per root CA, the CRL file on the card, and pushing updates to it.

use super::pki::rootkey::{self, CardContext};
use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::ui::files::{self, Filter};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::textview::TextView;
use crate::ui::tree::{self, Node, TreeEvent, TreeState};
use crate::ui::{clipboard, hex, style, theme, widgets};
use duox::card::{
    types::cmd, AccessRights, CommMode, CrlChange, CrlSettings, DataFileSpec, FileSettings, FileSettingsChange,
    FileType, ModeSel,
};
use duox::pki::crl::{self, CrlUpdate};
use duox::pki::{CertKind, CrlState, CsnOrder, PkiStore};
use iced::widget::{column, container, pick_list, row, scrollable, text, text_editor, text_input};
use iced::{Alignment, Element, Length, Task};
use std::fmt;

const ASK_CREATE: u32 = 1;
const ASK_CONFIGURE: u32 = 2;
const ASK_LINK: u32 = 3;
const ASK_ADD: u32 = 4;
const ASK_VALUES: u32 = 5;
const ASK_EXPORT: u32 = 6;

const MODES: [&str; 3] = ["Plain", "MAC", "Full"];
const NOT_CONNECTED: &str = "Not connected. Pick a reader and press Connect first.";
const NO_ROOT: &str = "Create a root CA first (CAs & certificates tab).";

// -------------------------------------------------------------------- pick lists

/// A root CA in a pick list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootChoice {
    id: String,
    label: String,
}

impl fmt::Display for RootChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

/// Serial byte order of the CRL file, as a pick list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderChoice(CsnOrder);

impl OrderChoice {
    const ALL: [OrderChoice; 2] = [OrderChoice(CsnOrder::MsbFirst), OrderChoice(CsnOrder::LsbFirst)];
}

impl Default for OrderChoice {
    fn default() -> Self {
        OrderChoice(CsnOrder::MsbFirst)
    }
}

impl fmt::Display for OrderChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            CsnOrder::MsbFirst => "MSB first",
            CsnOrder::LsbFirst => "LSB first",
        })
    }
}

// ---------------------------------------------------------------- pure helpers

/// A file number typed as hex: 00 to 1F.
pub fn parse_file_no(text: &str) -> Result<u8, String> {
    let t = text.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    match u8::from_str_radix(t, 16) {
        Ok(n) if n <= 0x1F && !t.is_empty() => Ok(n),
        _ => Err(format!("'{}' is not a file number; use two hex digits, 00 to 1F.", text.trim())),
    }
}

/// CRLVersion of the next update. With "increase by exactly 1" the card's own version decides; otherwise the
/// version must exceed everything pushed so far.
pub fn next_version(on_card: u32, last_pushed: u16, exact_increment: bool) -> Result<u16, String> {
    let next = if exact_increment { on_card } else { on_card.max(u32::from(last_pushed)) } + 1;
    u16::try_from(next)
        .map_err(|_| format!("CRLVersion is exhausted: the next version would be {next}, but it is a 16 bit number."))
}

/// CRLOptions / CSNSize / CRLSigKey for ChangeFileSettings.
pub fn crl_change(active: bool, signed: bool, exact_increment: bool, sig_key: u8) -> Result<CrlChange, String> {
    if exact_increment && !signed {
        return Err("'Increase by exactly 1' needs the signature requirement as well.".into());
    }
    if sig_key > 4 {
        return Err("CA root key numbers are 0 to 4.".into());
    }
    Ok(CrlChange {
        options: u8::from(signed) | u8::from(exact_increment) << 1,
        csn_size: if active { crl::CSN_SIZE as u8 } else { 0 },
        sig_key: signed.then_some(sig_key),
    })
}

/// How many serials a file of `size` bytes can list (8 bytes: CSNAllBefore and the terminator).
pub fn capacity(size: u32) -> u32 {
    size.saturating_sub(8) / 4
}

pub fn same_list(before: u32, serials: &[u32], local: &CrlState) -> bool {
    before == local.all_before && serials == local.serials.as_slice()
}

/// Entries below `root_id` (anything but the root) whose certificate has this serial number.
pub fn entries_with_serial(store: &PkiStore, root_id: &str, serial: u32) -> Vec<String> {
    store
        .entries()
        .iter()
        .filter(|e| e.kind != CertKind::Root && e.serial() == Some(u64::from(serial)))
        .filter(|e| store.root_of(&e.id).is_ok_and(|r| r.id == root_id))
        .map(|e| e.id.clone())
        .collect()
}

/// Text for the result pane after reading the file.
pub fn describe_read(
    fs: &FileSettings,
    version: u32,
    data: &[u8],
    order: CsnOrder,
    local: Option<&CrlState>,
) -> String {
    let (before, serials) = crl::parse_image(data, order);
    let mut lines = fs.describe();
    lines.pop(); // the raw settings bytes
    lines.push(String::new());
    lines.push(format!("CRLVersion on card   {version}"));
    lines.push(format!("Revoked up to serial {before}"));
    let listed = if serials.is_empty() {
        "none".to_string()
    } else {
        serials.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
    };
    lines.push(format!("Listed serials       {listed}"));
    lines.push(format!("Capacity             {} listed serials", capacity(fs.size.unwrap_or(0))));
    if let Some(l) = local {
        let same = same_list(before, &serials, l);
        lines.push(format!(
            "Local list           {}",
            if same { "identical" } else { "DIFFERS - push to update the card" }
        ));
    }
    lines.push(String::new());
    lines.push(hex::dump(data));
    lines.join("\n")
}

// ------------------------------------------------------------------------ tab

#[derive(Default)]
pub struct State {
    roots: Vec<RootChoice>,
    root: Option<String>,
    signer: Option<String>,
    file_no: String,
    order: OrderChoice,
    serial_list: Vec<Node>,
    serial_tree: TreeState,
    out: TextView,
    /// File settings read for the open Configure dialog.
    pending_fs: Option<FileSettings>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("crl::State").field("root", &self.root).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    /// Answer to `Shared::ask` / `confirm`. `values` is `None` when cancelled or answered "no".
    FormDone { token: u32, values: Option<FormValues> },
    /// Broadcast from the application (connect, disconnect, store changed, tab activated).
    Event(AppEvent),
    PickRoot(RootChoice),
    PickSigner(RootChoice),
    PickOrder(OrderChoice),
    FileNo(String),
    Serials(TreeEvent),
    View(text_editor::Action),
    AddSerial,
    RemoveSerial,
    EditValues,
    Create,
    Configure,
    Link,
    Read,
    Push,
    Export,
    CopyOutput,
}

fn fail(shared: &mut Shared, msg: impl Into<String>) -> Task<app::Message> {
    shared.report_error(msg);
    Task::none()
}

impl State {
    fn file_no_text(&self) -> &str {
        if self.file_no.is_empty() {
            "04"
        } else {
            &self.file_no
        }
    }

    fn file_no(&self) -> Result<u8, String> {
        parse_file_no(self.file_no_text())
    }

    fn root_id(&self) -> Result<String, String> {
        self.root.clone().ok_or_else(|| NO_ROOT.to_string())
    }

    fn local(&self, shared: &Shared) -> Option<CrlState> {
        self.root.as_deref().and_then(|id| shared.store.get(id).ok()).map(|e| e.crl.clone())
    }

    /// Re-read the root list and the serial list from the store.
    fn refresh(&mut self, shared: &Shared) {
        let store = &shared.store;
        self.roots = store
            .by_kind(&[CertKind::Root])
            .into_iter()
            .map(|e| RootChoice { id: e.id.clone(), label: store.label(e) })
            .collect();
        if self.root.as_deref().is_none_or(|id| !self.roots.iter().any(|r| r.id == id)) {
            self.root = self.roots.first().map(|r| r.id.clone());
        }
        let can_sign = |id: &str| store.get(id).is_ok_and(|e| e.has_key() && e.kind == CertKind::Root);
        if self.signer.as_deref().is_none_or(|id| !can_sign(id)) {
            self.signer = self
                .root
                .clone()
                .filter(|id| can_sign(id))
                .or_else(|| self.roots.iter().map(|r| r.id.clone()).find(|id| can_sign(id)));
        }
        self.serial_list.clear();
        if let Some(root) = self.root.as_deref().and_then(|id| store.get(id).ok()) {
            for s in &root.crl.serials {
                let names: Vec<String> = entries_with_serial(store, &root.id, *s)
                    .iter()
                    .filter_map(|id| store.get(id).ok().map(|e| e.name.clone()))
                    .collect();
                let mut n = Node::new(s.to_string(), s.to_string());
                if !names.is_empty() {
                    n = n.info(names.join(", "));
                }
                self.serial_list.push(n);
            }
        }
        if self.serial_tree.selected.as_deref().is_some_and(|s| !self.serial_list.iter().any(|n| n.id == s)) {
            self.serial_tree.selected = None;
        }
    }

    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::Event(AppEvent::Connected | AppEvent::Disconnected) => {}
            Message::Event(_) => self.refresh(shared),
            Message::PickRoot(c) => {
                if shared.store.get(&c.id).is_ok_and(|e| e.has_key()) {
                    self.signer = Some(c.id.clone());
                }
                self.root = Some(c.id);
                self.serial_tree.selected = None;
                self.refresh(shared);
            }
            Message::PickSigner(c) => self.signer = Some(c.id),
            Message::PickOrder(o) => self.order = o,
            Message::FileNo(t) => self.file_no = t.trim().chars().take(4).collect(),
            Message::Serials(ev) => self.serial_tree.update(ev),
            Message::View(a) => self.out.perform(a),
            Message::CopyOutput => {
                return clipboard::copy(self.out.selection().unwrap_or_else(|| self.out.text()));
            }
            Message::AddSerial => match self.root_id() {
                Ok(_) => shared.ask(
                    FormSpec::new("Revoke a serial number")
                        .note(
                            "The serial is added to the local list; certificates of this CA with that serial are \
                             marked revoked.",
                        )
                        .ok_text("Revoke")
                        .int_range("serial", "Certificate serial number", 1, 1, i64::from(u32::MAX)),
                    ASK_ADD,
                ),
                Err(m) => return fail(shared, m),
            },
            Message::RemoveSerial => return self.remove_serial(shared),
            Message::EditValues => match self.local(shared) {
                Some(l) => shared.ask(
                    FormSpec::new("Revocation list values")
                        .note("The next push sends these values. Serials up to the first number count as revoked.")
                        .ok_text("Save")
                        .int_range("before", "Revoke all serials up to", i64::from(l.all_before), 0, i64::from(u32::MAX))
                        .int_range("version", "Last pushed CRLVersion", i64::from(l.version), 0, i64::from(u16::MAX)),
                    ASK_VALUES,
                ),
                None => return fail(shared, NO_ROOT),
            },
            Message::Create => return self.ask_create(shared),
            Message::Configure => return self.ask_configure(shared),
            Message::Link => return self.ask_link(shared),
            Message::Read => return self.read(shared),
            Message::Push => return self.push(shared),
            Message::Export => match self.root_id() {
                Ok(_) => shared.ask(
                    FormSpec::new("Export CRL image")
                        .note("The file content as it would be pushed, without padding, in the chosen serial byte order.")
                        .ok_text("Export")
                        .file_save("path", "File", "crl.bin", vec![Filter::new("Binary", &["bin"])]),
                    ASK_EXPORT,
                ),
                Err(m) => return fail(shared, m),
            },
            Message::FormDone { token, values } => {
                let Some(v) = values else {
                    self.pending_fs = None;
                    return Task::none();
                };
                let result = match token {
                    ASK_CREATE => self.do_create(&v, shared),
                    ASK_CONFIGURE => return self.do_configure(&v, shared),
                    ASK_LINK => self.do_link(&v, shared),
                    ASK_ADD => self.do_add(&v, shared),
                    ASK_VALUES => self.do_values(&v, shared),
                    ASK_EXPORT => self.do_export(&v, shared),
                    _ => Ok(()),
                };
                if let Err(m) = result {
                    return fail(shared, m);
                }
            }
        }
        Task::none()
    }

    // -------------------------------------------------------------- local list

    fn set_serial(&mut self, shared: &mut Shared, serial: u32, revoked: bool) -> Result<(), String> {
        let root_id = self.root_id()?;
        let ids = entries_with_serial(&shared.store, &root_id, serial);
        let done = shared.with_store(|s| {
            for id in &ids {
                s.set_revoked(id, revoked)?;
            }
            let mut state = s.get(&root_id)?.crl.clone();
            state.set_revoked(serial, revoked);
            s.set_crl(&root_id, state)
        });
        if done.is_ok() {
            shared.store_changed();
            self.refresh(shared);
        }
        Ok(())
    }

    fn do_add(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let serial = u32::try_from(v.get_int("serial")?).map_err(|_| "Serial numbers are 1 to 4294967295.".to_string())?;
        self.set_serial(shared, serial, true)
    }

    fn remove_serial(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let Some(sel) = self.serial_tree.selected.clone().and_then(|s| s.parse::<u32>().ok()) else {
            return fail(shared, "Select a serial in the list first.");
        };
        match self.set_serial(shared, sel, false) {
            Ok(()) => Task::none(),
            Err(m) => fail(shared, m),
        }
    }

    fn do_values(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let root_id = self.root_id()?;
        let mut state = self.local(shared).unwrap_or_default();
        state.all_before = u32::try_from(v.get_int("before")?).map_err(|_| "The value does not fit 32 bits.".to_string())?;
        state.version = u16::try_from(v.get_int("version")?).map_err(|_| "CRLVersion is a 16 bit number.".to_string())?;
        if shared.with_store(|s| s.set_crl(&root_id, state)).is_ok() {
            shared.store_changed();
            self.refresh(shared);
        }
        Ok(())
    }

    fn do_export(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let path = v.get_path("path")?.ok_or("Choose the file to write.")?;
        let local = self.local(shared).ok_or(NO_ROOT)?;
        let image = local.image(None, self.order.0).map_err(|e| e.to_string())?;
        files::write_file(&path, &image)?;
        shared.log_info(&format!("CRL image ({} bytes) written to {}.", image.len(), path.display()));
        Ok(())
    }

    // --------------------------------------------------------------- card side

    fn ask_create(&mut self, shared: &mut Shared) -> Task<app::Message> {
        if !shared.is_connected() {
            return fail(shared, NOT_CONNECTED);
        }
        if CardContext::of(shared).at_picc {
            return fail(shared, "A CRL file lives inside an application. Select the application first (Card tab).");
        }
        let default_no = self.file_no().unwrap_or(4);
        shared.ask(
            FormSpec::new("Create CRL file")
                .note(
                    "Readers that should distribute CRL updates need write access; with required signatures that can \
                     safely be many readers.",
                )
                .ok_text("Create")
                .hex_int_range("no", "File number", u64::from(default_no), 2, 0, 0x1F)
                .hex_len("fid", "ISO file ID", "", 0, 2)
                .hint("Two bytes in hex; empty if the application does not use ISO file IDs.")
                .check("backup", "Backup data file", false)
                .hint("Updates then need a Commit.")
                .int_range("size", "Size in bytes", 128, 8, 8192)
                .hint("8 plus 4 per listed serial.")
                .combo("mode", "Communication mode", &MODES, 1)
                .hex_int_range("ar", "Access rights", 0xE000, 4, 0, 0xFFFF)
                .hint("Hex nibbles: Read, Write, ReadWrite, Change (E = free, F = never)."),
            ASK_CREATE,
        );
        Task::none()
    }

    fn do_create(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let no = v.get_uint("no")? as u8;
        let fid = match v.get_hex("fid")?.as_slice() {
            [] => None,
            [a, b] => Some(u16::from_be_bytes([*a, *b])),
            _ => return Err("The ISO file ID is two bytes (four hex digits), or empty.".into()),
        };
        let mode = match v.get_index("mode")? {
            1 => CommMode::Mac,
            2 => CommMode::Full,
            _ => CommMode::Plain,
        };
        let access = AccessRights::from_u16(v.get_uint("ar")? as u16);
        let mut spec = DataFileSpec::new(no, v.get_int("size")? as u32, access).comm_mode(mode).crl();
        if v.get_bool("backup")? {
            spec = spec.backup();
        }
        if let Some(f) = fid {
            spec = spec.iso_fid(f);
        }
        if shared.with_card(|c| c.create_data_file(&spec)).is_ok() {
            self.file_no = format!("{no:02X}");
            let line = format!("CRL file {no:02X} created.");
            shared.log_info(&line);
            self.out.set_text(&format!(
                "{line}\n\nNext: Configure... to activate revocation, Link to CA root key... to tie it to a CA, then Push to card."
            ));
        }
        Ok(())
    }

    fn ask_configure(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let no = match self.file_no() {
            Ok(n) => n,
            Err(m) => return fail(shared, m),
        };
        // The current settings are needed to keep everything except the CRL part unchanged.
        let Ok(fs) = shared.with_card(|c| c.get_file_settings(no)) else { return Task::none() };
        let Some(c) = fs.crl.clone() else {
            return fail(shared, format!("File {no:02X} was not created as a CRL file."));
        };
        let current = CrlSettings { ..c };
        shared.ask(
            FormSpec::new(format!("Configure CRL file {no:02X}"))
                .note(
                    "Uses ChangeFileSettings, which needs the file's Change access right. Protect that right: \
                     whoever holds it can switch revocation off again.",
                )
                .ok_text("Apply")
                .check("active", "Revocation active (CSNSize = 4)", true)
                .check("sig", "Require CRLSignature and strictly increasing CRLVersion", current.options & 1 != 0)
                .check("inc", "CRLVersion must increase by exactly 1 (delta updates)", current.options & 2 != 0)
                .int_range(
                    "sigkey",
                    "CA root key number that verifies the signature",
                    i64::from(current.sig_key.unwrap_or(0)),
                    0,
                    4,
                ),
            ASK_CONFIGURE,
        );
        self.pending_fs = Some(fs);
        Task::none()
    }

    fn do_configure(&mut self, v: &FormValues, shared: &mut Shared) -> Task<app::Message> {
        let Some(fs) = self.pending_fs.take() else { return Task::none() };
        let change = crl_change(
            v.get_bool("active").unwrap_or(true),
            v.get_bool("sig").unwrap_or(false),
            v.get_bool("inc").unwrap_or(false),
            v.get_int("sigkey").unwrap_or(0) as u8,
        );
        let change = match change {
            Ok(c) => c,
            Err(m) => return fail(shared, m),
        };
        let mut req = FileSettingsChange::new(fs.option & 0x83, fs.access);
        req.additional = fs.additional.clone();
        req.crl = Some(change);
        req.current_change_access = fs.access.change;
        if shared.with_card(|c| c.change_file_settings(fs.file_no, &req)).is_ok() {
            shared.log_info(&format!("CRL file {:02X} configured.", fs.file_no));
            return self.read(shared);
        }
        Task::none()
    }

    fn ask_link(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let root = match self.root_id() {
            Ok(r) => r,
            Err(m) => return fail(shared, m),
        };
        let no = match self.file_no() {
            Ok(n) => n,
            Err(m) => return fail(shared, m),
        };
        if !shared.is_connected() {
            return fail(shared, NOT_CONNECTED);
        }
        let ctx = CardContext::of(shared);
        shared.ask(rootkey::form(&shared.store, ctx, Some(&root), Some(no)), ASK_LINK);
        Task::none()
    }

    fn do_link(&mut self, v: &FormValues, shared: &mut Shared) -> Result<(), String> {
        let ctx = CardContext::of(shared);
        let input = rootkey::Input::from_values(v)?;
        if !input.crl {
            return Err("Revocation is not ticked in the form, so the key would not be linked to a CRL file.".into());
        }
        let (spec, text) = rootkey::build(&shared.store, ctx, &input)?;
        if shared.with_card(|c| c.manage_ca_root_key(&spec, None)).is_ok() {
            shared.log_info(&format!("{text}."));
            self.out.set_text(&format!("{text}.\n\nPush the list to the card with Push to card."));
        }
        Ok(())
    }

    fn read(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let no = match self.file_no() {
            Ok(n) => n,
            Err(m) => return fail(shared, m),
        };
        let order = self.order.0;
        let result = shared.with_card(|c| -> Result<_, String> {
            let fs = c.get_file_settings(no).map_err(|e| e.to_string())?;
            if fs.crl.is_none() {
                return Err(format!("File {no:02X} was not created as a CRL file."));
            }
            let data = c.read_data_with(no, 0, 0, ModeSel::File(&fs)).map_err(|e| e.to_string())?;
            let version = c.read_crl_version(no, ModeSel::File(&fs)).map_err(|e| e.to_string())?;
            Ok((fs, data, version))
        });
        if let Ok((fs, data, version)) = result {
            let local = self.local(shared);
            self.out.set_text(&describe_read(&fs, version, &data, order, local.as_ref()));
        }
        Task::none()
    }

    fn push(&mut self, shared: &mut Shared) -> Task<app::Message> {
        let (root_id, no) = match (self.root_id(), self.file_no()) {
            (Ok(r), Ok(n)) => (r, n),
            (Err(m), _) | (_, Err(m)) => return fail(shared, m),
        };
        let Some(local) = self.local(shared) else { return fail(shared, NO_ROOT) };

        // 1. what the card says about the file and its current version
        let state = shared.with_card(|c| -> Result<_, String> {
            let fs = c.get_file_settings(no).map_err(|e| e.to_string())?;
            if fs.crl.is_none() {
                return Err(format!("File {no:02X} was not created as a CRL file."));
            }
            let version = c.read_crl_version(no, ModeSel::File(&fs)).map_err(|e| e.to_string())?;
            Ok((fs, version))
        });
        let Ok((fs, on_card)) = state else { return Task::none() };
        let Some(settings) = fs.crl.clone() else { return Task::none() };

        // 2. everything that can be wrong locally, before the card receives anything
        let prepared = (|| -> Result<_, String> {
            let size = fs.size.ok_or("The card did not report the size of the CRL file.")? as usize;
            let image = local.image(Some(size), self.order.0).map_err(|e| e.to_string())?;
            let version = next_version(on_card, local.version, settings.options & 2 != 0)?;
            Ok((image, version))
        })();
        let (image, version) = match prepared {
            Ok(p) => p,
            Err(m) => return fail(shared, m),
        };
        let signature = if settings.options & 1 != 0 {
            let Some(id) = self.signer.clone() else {
                let key_no = settings.sig_key.unwrap_or(0);
                return fail(
                    shared,
                    format!("The file requires signed updates. Choose the CA whose key is CA root key {key_no} on the card."),
                );
            };
            // A locked store opens its passphrase prompt here; the push can then be repeated.
            let Ok(key) = shared.with_store(|s| s.key_of(&id)) else { return Task::none() };
            let update = CrlUpdate { cmd: cmd::WRITE_DATA_CRL, file_no: fs.file_no, version, offset: 0, data: &image };
            match update.sign(&key) {
                Ok(s) => s,
                Err(e) => return fail(shared, e.to_string()),
            }
        } else {
            Vec::new()
        };

        // 3. send
        if shared.with_card(|c| c.write_crl(fs.file_no, version, 0, &image, &signature, ModeSel::File(&fs))).is_err() {
            return Task::none();
        }
        let mut updated = local;
        updated.version = version;
        if shared.with_store(|s| s.set_crl(&root_id, updated)).is_ok() {
            shared.store_changed();
            self.refresh(shared);
        }
        let mut lines = vec![format!(
            "CRL pushed to file {:02X} as CRLVersion {version} ({} bytes, {})",
            fs.file_no,
            image.len(),
            if signature.is_empty() { "unsigned" } else { "signed" }
        )];
        if fs.file_type == FileType::BackupData {
            lines.push("Backup file: send Commit (Configuration & tools tab) to make it effective.".into());
        }
        if settings.csn_size == 0 {
            lines.push("NOTE: CSNSize is 0 - revocation is not active until the file is configured.".into());
        }
        if !signature.is_empty() {
            lines.push(format!("CRLSignature {}", hex::compact(&signature)));
        }
        shared.log_info(&lines[0]);
        lines.push(String::new());
        lines.push(hex::dump(&image));
        self.out.set_text(&lines.join("\n"));
        Task::none()
    }

    // ------------------------------------------------------------------- view

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let connected = shared.is_connected();
        let have_root = self.root.is_some();
        let selected_root = self.roots.iter().find(|r| Some(&r.id) == self.root.as_ref()).cloned();
        let signers: Vec<RootChoice> = self
            .roots
            .iter()
            .filter(|r| shared.store.get(&r.id).is_ok_and(|e| e.has_key()))
            .cloned()
            .collect();
        let selected_signer = signers.iter().find(|r| Some(&r.id) == self.signer.as_ref()).cloned();

        let top = row![
            text("Revocation list of CA").size(theme::TEXT_BODY),
            pick_list(self.roots.clone(), selected_root, Message::PickRoot)
                .placeholder("No root CA in the store")
                .width(Length::Fixed(420.0)),
        ]
        .spacing(theme::SPACE_MD)
        .align_y(Alignment::Center);

        let local = self.local(shared).unwrap_or_default();
        let summary = widgets::kv_table(
            &[
                ("Revoked up to serial".to_string(), local.all_before.to_string()),
                ("Last pushed CRLVersion".to_string(), local.version.to_string()),
                ("Individually revoked".to_string(), local.serials.len().to_string()),
            ],
            true,
        );
        let serials: Element<'_, Message> = if self.serial_list.is_empty() {
            container(widgets::hint("No individual serials revoked.")).padding(theme::SPACE_SM).into()
        } else {
            scrollable(tree::view(&self.serial_list, &self.serial_tree).map(Message::Serials)).into()
        };
        let local_group = widgets::group(
            "Local list",
            column![
                summary,
                container(serials).height(Length::Fixed(130.0)).width(Length::Fill).style(style::panel),
                row![
                    btn("Add serial...", Message::AddSerial, have_root, false),
                    btn("Remove", Message::RemoveSerial, self.serial_tree.selected.is_some(), false),
                    btn("Edit values...", Message::EditValues, have_root, false),
                ]
                .spacing(theme::SPACE_SM),
            ]
            .spacing(theme::SPACE_SM),
        );

        let card_group = widgets::group(
            "CRL file on the card",
            column![
                labeled(
                    "File number (hex)",
                    text_input("04", self.file_no_text()).on_input(Message::FileNo).width(Length::Fixed(70.0)).into()
                ),
                labeled(
                    "Sign updates with",
                    pick_list(signers, selected_signer, Message::PickSigner)
                        .placeholder("No CA with a private key")
                        .width(Length::Fixed(320.0))
                        .into()
                ),
                labeled("Serial byte order", pick_list(OrderChoice::ALL, Some(self.order), Message::PickOrder).into()),
                row![
                    btn("Create CRL file...", Message::Create, connected, false),
                    btn("Configure...", Message::Configure, connected, false),
                    btn("Link to CA root key...", Message::Link, connected && have_root, false),
                ]
                .spacing(theme::SPACE_SM),
                row![
                    btn("Read from card", Message::Read, connected, false),
                    btn("Push to card", Message::Push, connected && have_root, true),
                    btn("Export image...", Message::Export, have_root, false),
                    btn("Copy output", Message::CopyOutput, true, false),
                ]
                .spacing(theme::SPACE_SM),
                widgets::hint(
                    "Setup: create the file, configure it (CSNSize 4 activates revocation), link the CA root key \
                     to it, then push. A signature is only sent when the file requires one. The data sheet does \
                     not state the byte order of serials inside the file; MSB first matches the certificate \
                     encoding."
                ),
            ]
            .spacing(theme::SPACE_SM),
        );

        column![
            top,
            row![container(local_group).width(Length::FillPortion(2)), container(card_group).width(Length::FillPortion(3))]
                .spacing(theme::SPACE_MD),
            container(self.out.view().map(Message::View)).height(Length::Fill),
        ]
        .spacing(theme::SPACE_MD)
        .padding(theme::SPACE_MD)
        .into()
    }
}

fn btn<'a>(label: &str, msg: Message, enabled: bool, primary: bool) -> iced::widget::Button<'a, Message> {
    let b = if primary { widgets::primary(label, msg) } else { widgets::secondary(label, msg) };
    if enabled {
        b
    } else {
        b.on_press_maybe(None)
    }
}

fn labeled<'a>(label: &str, control: Element<'a, Message>) -> Element<'a, Message> {
    row![container(text(label.to_string()).size(theme::TEXT_BODY)).width(theme::LABEL_WIDTH), control]
        .spacing(theme::SPACE_MD)
        .align_y(Alignment::Center)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use duox::crypto::CURVE_P256;
    use duox::pki::IssueRequest;

    #[test]
    fn file_numbers() {
        assert_eq!(parse_file_no("04").unwrap(), 4);
        assert_eq!(parse_file_no(" 1f ").unwrap(), 0x1F);
        assert!(parse_file_no("20").is_err());
        assert!(parse_file_no("").is_err());
        assert!(parse_file_no("zz").unwrap_err().contains("'zz'"));
    }

    #[test]
    fn version_rules() {
        assert_eq!(next_version(0, 0, false).unwrap(), 1);
        // the larger of card and local counts
        assert_eq!(next_version(5, 9, false).unwrap(), 10);
        assert_eq!(next_version(9, 5, false).unwrap(), 10);
        // delta mode follows the card only
        assert_eq!(next_version(5, 9, true).unwrap(), 6);
        assert!(next_version(0xFFFF, 0, false).unwrap_err().contains("exhausted"));
        assert_eq!(next_version(0xFFFE, 0, false).unwrap(), 0xFFFF);
    }

    #[test]
    fn crl_settings_encoding() {
        let c = crl_change(true, true, true, 2).unwrap();
        assert_eq!((c.options, c.csn_size, c.sig_key), (3, 4, Some(2)));
        let c = crl_change(false, false, false, 3).unwrap();
        assert_eq!((c.options, c.csn_size, c.sig_key), (0, 0, None));
        assert!(crl_change(true, false, true, 0).is_err());
        assert!(crl_change(true, true, false, 5).is_err());
    }

    #[test]
    fn capacity_and_comparison() {
        assert_eq!(capacity(128), 30);
        assert_eq!(capacity(4), 0);
        let local = CrlState { version: 1, all_before: 5, serials: vec![7, 9] };
        assert!(same_list(5, &[7, 9], &local));
        assert!(!same_list(5, &[7], &local));
        assert!(!same_list(4, &[7, 9], &local));
    }

    #[test]
    fn serial_owners() {
        let mut s = PkiStore::new();
        let root = s.new_root("A", CURVE_P256, "", 1).unwrap();
        let other = s.new_root("B", CURVE_P256, "", 1).unwrap();
        let r = s.issue(&root.id, IssueRequest::new(CertKind::Reader, "R")).unwrap();
        let serial = r.serial().unwrap() as u32;
        assert_eq!(entries_with_serial(&s, &root.id, serial), vec![r.id.clone()]);
        assert!(entries_with_serial(&s, &other.id, serial).is_empty());
        assert!(entries_with_serial(&s, &root.id, 4_000_000).is_empty());
    }

    #[test]
    fn read_report_compares_with_local_list() {
        let base = FileSettings::parse(4, &hex::parse("00 00 EE E0 20 00 00 03 04 01").unwrap()).unwrap();
        let fs = FileSettings { crl: Some(CrlSettings { options: 3, csn_size: 4, sig_key: Some(1) }), ..base };
        let image = crl::build_image(5, &[7, 9], Some(32), CsnOrder::MsbFirst).unwrap();
        let local = CrlState { version: 2, all_before: 5, serials: vec![7, 9] };
        let text = describe_read(&fs, 2, &image, CsnOrder::MsbFirst, Some(&local));
        assert!(text.contains("CRLVersion on card   2"), "{text}");
        assert!(text.contains("Revoked up to serial 5") && text.contains("Listed serials       7, 9"), "{text}");
        assert!(text.contains("Local list           identical"), "{text}");
        assert!(text.contains("CRLSigKey"), "{text}");
        assert!(!text.contains("raw:"));
        let other = CrlState { serials: vec![7], ..local };
        assert!(describe_read(&fs, 2, &image, CsnOrder::MsbFirst, Some(&other)).contains("DIFFERS"));
        // the wrong byte order reads something else
        assert!(describe_read(&fs, 2, &image, CsnOrder::LsbFirst, Some(&other)).contains("DIFFERS"));
    }
}
