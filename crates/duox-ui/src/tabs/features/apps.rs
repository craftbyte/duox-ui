//! Two applications selected at once, access to the files of the second one, proximity check.

use super::{is_authenticated, key_chooser, plan, read_key, report, token, Action, State};
use crate::shared::{DynCard, Shared};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::hex;
use duox::card::{Aid, FileType, ModeSel};

const SECOND_NOTE: &str = "Keys and files of the second application are addressed with bit 7 set: authenticate with key \
                           number 81 for its key 1; file 01 is sent as 81.";

/// Outcome of a file command on the second application: text for the view and, when the access
/// was refused up front, the sentence for the error dialog.
struct SecondOutcome {
    text: String,
    problem: Option<String>,
}

fn file_form(title: &str, note: &str, ok: &str, file: u64) -> FormSpec {
    FormSpec::new(title).note(note).ok_text(ok).hex_int_range("file", "File number (hex)", file, 2, 0, 0x1F)
}

impl State {
    pub(super) fn start_apps(&mut self, a: Action, shared: &mut Shared) {
        let l = self.last.clone();
        if matches!(a, Action::SecondSettings | Action::SecondRead | Action::SecondWrite) {
            let two = shared.card.as_ref().is_some_and(|c| c.selection().secondary.is_some());
            if !two {
                shared.report_error("Select two applications first.");
                return;
            }
        }
        match a {
            Action::SelectTwo => shared.ask(
                FormSpec::new("Select two applications")
                    .note(
                        "SelectApplication with two AIDs. The first one is the primary application. For ECC \
                         authentication both need the same CA root key, and the reader certificate must list \
                         both AIDs. Any authentication ends.",
                    )
                    .ok_text("Select both")
                    .hex_int_range("aid1", "First AID (hex)", l.aid1, 6, 0, 0xFF_FFFF)
                    .hex_int_range("aid2", "Second AID (hex)", l.aid2, 6, 0, 0xFF_FFFF),
                token::SELECT_TWO,
            ),
            Action::SecondSettings => shared.ask(
                file_form("File settings of the second application", SECOND_NOTE, "Read", l.second_file),
                token::SECOND_SETTINGS,
            ),
            Action::SecondRead => shared.ask(
                file_form("Read a file of the second application", SECOND_NOTE, "Read", l.second_file),
                token::SECOND_READ,
            ),
            Action::SecondWrite => shared.ask(
                file_form("Write a file of the second application", SECOND_NOTE, "Write", l.second_file)
                    .int_range("offset", "Offset", 0, 0, 0xFF_FFFF)
                    .hex_len("data", "Data (hex)", "", 1, 4096)
                    .hint("Data files only. A backup file needs CommitTransaction (Transactions tab)."),
                token::SECOND_WRITE,
            ),
            Action::Proximity => {
                let mut spec = FormSpec::new("Proximity check")
                    .note(
                        "PreparePC, ProximityCheck and VerifyPC. With an active authentication the session MAC \
                         key is used; otherwise the VCProximityKey is needed.",
                    )
                    .ok_text("Run");
                if is_authenticated(shared) {
                    spec = spec.info("MAC key", "session key of the active authentication");
                } else {
                    spec = key_chooser(spec, shared, "key", "VCProximityKey", "");
                }
                spec = spec
                    .text("split", "Challenge split (bytes per round)", &l.split)
                    .hint("Numbers adding up to 8, for example 8 or 3,5.");
                shared.ask(spec, token::PROXIMITY);
            }
            _ => {}
        }
    }

    pub(super) fn apps_done(&mut self, tok: u32, v: &FormValues, shared: &mut Shared) {
        match tok {
            token::SELECT_TWO => {
                let (a1, a2) = (v.get_uint("aid1").unwrap_or(0) as u32, v.get_uint("aid2").unwrap_or(0) as u32);
                (self.last.aid1, self.last.aid2) = (u64::from(a1), u64::from(a2));
                if a1 == 0 || a2 == 0 {
                    shared.report_error("Both applications need an AID other than 000000 (the PICC level).");
                    return;
                }
                if a1 == a2 {
                    shared.report_error("The two applications must be different.");
                    return;
                }
                if let Ok(rc) = shared.with_card(|c| c.select_application(Aid(a1), Some(Aid(a2)))) {
                    self.show(format!(
                        "Applications {a1:06X} and {a2:06X} selected{}.\n\n{SECOND_NOTE} The Card tab keeps showing \
                         the first application.",
                        if rc != 0 { " (limited functionality)" } else { "" }
                    ));
                }
            }
            token::SECOND_SETTINGS | token::SECOND_READ | token::SECOND_WRITE => self.second_file(tok, v, shared),
            token::PROXIMITY => self.proximity(v, shared),
            _ => {}
        }
    }

    fn second_file(&mut self, tok: u32, v: &FormValues, shared: &mut Shared) {
        let no = 0x80 | (v.get_uint("file").unwrap_or(1) as u8 & 0x1F);
        self.last.second_file = u64::from(no & 0x1F);
        if !shared.card.as_ref().is_some_and(|c| c.selection().secondary.is_some()) {
            shared.report_error("Select two applications first.");
            return;
        }
        let r = match tok {
            token::SECOND_SETTINGS => shared.with_card(|c| {
                let fs = c.get_file_settings(no)?;
                Ok::<_, duox::Error>(SecondOutcome { text: fs.describe().join("\n"), problem: None })
            }),
            token::SECOND_READ => shared.with_card(|c| read_second(c, no)),
            _ => {
                let offset = v.get_int("offset").unwrap_or(0) as u32;
                let data = v.get_hex("data").unwrap_or_default();
                shared.with_card(|c| write_second(c, no, offset, &data))
            }
        };
        if let Ok(o) = r {
            self.show(o.text);
            if let Some(p) = o.problem {
                shared.report_error(p);
            }
        }
    }

    fn proximity(&mut self, v: &FormValues, shared: &mut Shared) {
        let split = match plan::parse_split(v.get_str("split").unwrap_or("8")) {
            Ok(s) => s,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        self.last.split = v.get_str("split").unwrap_or("8").trim().to_string();
        let key = if is_authenticated(shared) {
            None
        } else {
            match read_key(shared, v, "key") {
                Ok(Some(k)) => Some(k),
                Ok(None) => {
                    shared.report_error(
                        "Not authenticated: the VCProximityKey is needed. Enter it as hex or choose a saved key.",
                    );
                    return;
                }
                Err(e) => {
                    shared.report_error(e);
                    return;
                }
            }
        };
        if let Ok(r) = shared.with_card(|c| c.proximity_check(key.as_deref(), &split)) {
            self.show(report::proximity_report(&r));
        }
    }
}

fn read_second(card: &mut DynCard, no: u8) -> Result<SecondOutcome, duox::Error> {
    let fs = card.get_file_settings(no)?;
    let mut lines = fs.describe();
    lines.push(String::new());
    let auth = card.is_authenticated();
    let problem = plan::access_problem(&fs.access_conditions(false), no, false, auth, |a| {
        card.has_access_condition(a, true)
    });
    if let Some(p) = problem {
        lines.push("Not read.".into());
        return Ok(SecondOutcome { text: lines.join("\n"), problem: Some(p) });
    }
    match fs.file_type {
        FileType::StandardData | FileType::BackupData | FileType::TransactionMac => {
            lines.push(hex::dump(&card.read_data_with(no, 0, 0, ModeSel::File(&fs))?).trim_end().to_string())
        }
        FileType::Value => lines.push(format!("Value: {}", card.get_value_with(no, ModeSel::File(&fs))?)),
        FileType::LinearRecord | FileType::CyclicRecord => {
            lines.push(hex::dump(&card.read_records_with(no, 0, 0, ModeSel::File(&fs))?).trim_end().to_string())
        }
    }
    Ok(SecondOutcome { text: lines.join("\n"), problem: None })
}

fn write_second(card: &mut DynCard, no: u8, offset: u32, data: &[u8]) -> Result<SecondOutcome, duox::Error> {
    let fs = card.get_file_settings(no)?;
    let refuse = |text: String, problem: String| Ok(SecondOutcome { text, problem: Some(problem) });
    let shown = fs.describe().join("\n");
    if !matches!(fs.file_type, FileType::StandardData | FileType::BackupData) {
        return refuse(shown, "Only data files can be written here.".into());
    }
    if let Some(size) = fs.size {
        if u64::from(offset) + data.len() as u64 > u64::from(size) {
            return refuse(
                shown,
                format!("The data ({} bytes at offset {offset}) does not fit the file of {size} bytes.", data.len()),
            );
        }
    }
    let auth = card.is_authenticated();
    if let Some(p) = plan::access_problem(&fs.access_conditions(true), no, true, auth, |a| {
        card.has_access_condition(a, true)
    }) {
        return refuse(shown, p);
    }
    card.write_data_with(no, offset, data, ModeSel::File(&fs))?;
    let backup = if fs.file_type == FileType::BackupData { " Backup file: commit on the Transactions tab." } else { "" };
    Ok(SecondOutcome { text: format!("Written.{backup}"), problem: None })
}

