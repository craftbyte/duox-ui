//! Card access of the browser: scanning, loading the contents of an application and reading
//! files. Everything here runs inside `Shared::with_card`.

use super::model::{Contents, Scan, Section};
use super::plan;
use crate::ui::hex;
use duox::card::{Aid, Card, FileSettings, FileType, ModeSel, Status};
use duox::pki::crl;
use duox::pki::CsnOrder;
use duox::transport::Transport;
use duox::Error;

/// Read the version, select the PICC level and list the applications.
pub fn scan<T: Transport>(card: &mut Card<T>) -> Result<Scan, Error> {
    let mut scan = Scan::default();
    match card.get_version() {
        Ok(v) => scan.version = Some(v),
        Err(e) => scan.notes.push(format!("GetVersion: {e}")),
    }
    card.select_application(Aid::PICC, None)?;
    list_applications(card, &mut scan);
    Ok(scan)
}

/// Application IDs and DF names of the card (PICC level must be selected).
pub fn list_applications<T: Transport>(card: &mut Card<T>, scan: &mut Scan) {
    scan.apps.clear();
    scan.df_names.clear();
    scan.notes.retain(|n| !n.starts_with("GetApplicationIDs") && !n.starts_with("GetDFNames"));
    match card.get_application_ids() {
        Ok(ids) => scan.apps = ids,
        Err(e) => {
            scan.notes.push(format!("GetApplicationIDs: {e}"));
            return;
        }
    }
    match card.get_df_names() {
        Ok(list) => scan.df_names = list.into_iter().map(|d| (d.aid.0, d)).collect(),
        Err(e) => scan.notes.push(format!("GetDFNames: {e}")),
    }
}

fn section<T>(r: Result<T, Error>) -> Section<T> {
    match r {
        Ok(v) => Section::Loaded(v),
        Err(e) => Section::Failed(e.to_string()),
    }
}

/// Keys and files of the selected application. When a command fails the card has dropped any
/// authentication, so loading stops there instead of probing further.
pub fn load_contents<T: Transport>(card: &mut Card<T>) -> Contents {
    let was_authenticated = card.is_authenticated();
    let mut c = Contents::default();
    let lost = |card: &Card<T>| was_authenticated && !card.is_authenticated();
    let stop_note = "the authentication ended after this failure; refresh to read the rest";

    c.keys = section(card.get_key_settings());
    if lost(card) {
        c.notes.push(stop_note.into());
        return c;
    }
    c.ecc = section(card.get_ecc_key_settings());
    if lost(card) {
        c.notes.push(stop_note.into());
        return c;
    }
    c.ca = section(card.get_ca_root_key_settings());
    if lost(card) {
        c.notes.push(stop_note.into());
        return c;
    }
    match card.get_file_ids() {
        Ok(ids) => {
            let mut files = Vec::new();
            for no in ids {
                match card.get_file_settings(no) {
                    Ok(fs) => files.push(fs),
                    Err(e) => {
                        c.notes.push(format!("GetFileSettings {no:02X}: {e}"));
                        break;
                    }
                }
            }
            c.files = Section::Loaded(files);
        }
        Err(e) => c.files = Section::Failed(e.to_string()),
    }
    sync_transaction_recorder(card, &c);
    c
}

/// The reader records the Transaction MAC Input itself; the exclusion map of the application's
/// TransactionMAC file decides which files are left out.
fn sync_transaction_recorder<T: Transport>(card: &mut Card<T>, c: &Contents) {
    if !card.transaction_input().is_empty() {
        return;
    }
    if let Some(t) = c.files().iter().find_map(|f| f.tmac.as_ref()) {
        card.new_transaction(Some(t.excl_map.unwrap_or(0)));
    }
}

/// Result of probing the second application.
#[derive(Debug, Default)]
pub struct Probe {
    pub found: Vec<FileSettings>,
    pub notes: Vec<String>,
}

/// GetFileSettings for each number with bit 7 set. Without an authentication missing files are
/// simply skipped; with one, the first failure (which ends the authentication) stops the probe.
pub fn probe_second<T: Transport>(card: &mut Card<T>, numbers: &[u8]) -> Probe {
    let mut p = Probe::default();
    for &n in numbers {
        let addressed = n | 0x80;
        let authenticated = card.is_authenticated();
        match card.get_file_settings(addressed) {
            Ok(fs) => p.found.push(fs),
            Err(e) if !authenticated && e.status() == Some(Status::FileNotFound) => {}
            Err(e) => {
                p.notes.push(format!("File {n:02X}: {e}"));
                break;
            }
        }
    }
    if let Some(t) = p.found.iter().find_map(|f| f.tmac.as_ref()) {
        card.set_tm_secondary(true);
        if card.transaction_input().is_empty() {
            card.new_transaction(Some(t.excl_map.unwrap_or(0)));
        }
    }
    p
}

/// Result of reading a file: the text for the detail view and the bytes for saving / decoding.
#[derive(Debug)]
pub struct ReadOutcome {
    pub text: String,
    /// Raw content of a data file (kept for Save and Decode certificate).
    pub data: Option<Vec<u8>>,
}

pub fn read_file<T: Transport>(card: &mut Card<T>, fs: &FileSettings) -> Result<ReadOutcome, Error> {
    let no = fs.file_no;
    let mut lines = fs.describe();
    lines.push(String::new());
    let sel = ModeSel::File(fs);
    let mut data = None;
    match fs.file_type {
        FileType::StandardData | FileType::BackupData => {
            let d = card.read_data_with(no, 0, 0, sel)?;
            if fs.crl.is_some() {
                let version = card.read_crl_version(no, sel)?;
                let (before, serials) = crl::parse_image(&d, CsnOrder::default());
                lines.push(format!("CRLVersion {version}"));
                lines.push(format!("CSNAllBefore {before}"));
                lines.push(format!(
                    "Revoked serials: {}",
                    if serials.is_empty() { "none".to_string() } else { serials.iter().map(u32::to_string).collect::<Vec<_>>().join(", ") }
                ));
                lines.push(String::new());
            }
            if !card.is_authenticated() && fs.sdm.is_some() {
                lines.push("Read without authentication: this is the dynamic (mirrored) SDM data.".into());
                lines.push(String::new());
            }
            lines.push(hex::dump(&d).trim_end().to_string());
            data = Some(d);
        }
        FileType::Value => {
            let v = card.get_value_with(no, sel)?;
            lines.push(format!("Value: {v}"));
        }
        FileType::LinearRecord | FileType::CyclicRecord => {
            let d = card.read_records_with(no, 0, 0, sel)?;
            let size = fs.record.as_ref().map(|r| r.record_size).unwrap_or(0);
            if d.is_empty() {
                lines.push("The file holds no records.".into());
            } else {
                lines.push(plan::records_text(&d, size).trim_end().to_string());
            }
            data = Some(d);
        }
        FileType::TransactionMac => {
            let d = card.read_data_with(no, 0, 0, sel)?;
            lines.extend(plan::tmac_read_text(&d));
            data = Some(d);
        }
    }
    Ok(ReadOutcome { text: lines.join("\n"), data })
}

/// Refresh one cached file after a command changed it (record count, limits).
pub fn refresh_file<T: Transport>(card: &mut Card<T>, no: u8) -> Result<FileSettings, Error> {
    card.get_file_settings(no)
}

#[cfg(test)]
mod tests {
    use super::*;
    use duox::transport::MockTransport;

    #[test]
    fn scan_selects_picc_and_lists_applications() {
        let mut t = MockTransport::new();
        // GetVersion: hardware, software, production frames
        t.expect_hex("9060000000", "04010112001A05 91AF");
        t.expect_hex("90AF000000", "04010112001A05 91AF");
        t.expect_hex("90AF000000", "04112233445566 112233 4455 2321 9100");
        t.expect_hex("905A000003 000000 00", "9100");
        t.expect_hex("906A000000", "563412 010000 9100");
        t.expect_hex("906D000000", "563412 1000 41 42 9100");
        let mut card = Card::new(t);
        let s = scan(&mut card).unwrap();
        assert_eq!(s.apps, vec![Aid(0x123456), Aid(1)]);
        assert_eq!(s.df_of(Aid(0x123456)).unwrap().name, b"AB");
        assert!(s.df_of(Aid(1)).is_none());
        assert_eq!(s.app_with_df_name(b"AB"), Some(Aid(0x123456)));
    }

    #[test]
    fn contents_loading_stops_when_the_authentication_ends() {
        // not authenticated: a refusal of one section does not stop the others
        let mut t = MockTransport::new();
        t.expect_hex("9045000000", "919D");
        t.expect_hex("90450000 01 01 00", "919D");
        t.expect_hex("90450000 01 02 00", "919D");
        t.expect_hex("906F000000", "01 02 9100");
        t.expect_hex("90F5000001 01 00", "00 03 00 E0 20 00 00 9100");
        t.expect_hex("90F5000001 02 00", "919D");
        let mut card = Card::new(t);
        let c = load_contents(&mut card);
        assert!(matches!(c.keys, Section::Failed(_)));
        assert!(matches!(c.ecc, Section::Failed(_)));
        assert_eq!(c.files().len(), 1);
        assert_eq!(c.notes.len(), 1);
        assert!(c.notes.iter().any(|n| n.contains("GetFileSettings 02")));
    }

    #[test]
    fn probing_skips_missing_files_without_authentication() {
        let mut t = MockTransport::new();
        t.expect_hex("90F5000001 81 00", "00 03 00 E0 10 00 00 9100");
        t.expect_hex("90F5000001 82 00", "91F0");
        t.expect_hex("90F5000001 83 00", "00 03 00 E0 10 00 00 9100");
        let mut card = Card::new(t);
        let p = probe_second(&mut card, &[1, 2, 3]);
        assert_eq!(p.found.iter().map(|f| f.file_no).collect::<Vec<_>>(), vec![0x81, 0x83]);
        assert!(p.notes.is_empty());
    }

    #[test]
    fn probing_reports_other_errors() {
        let mut t = MockTransport::new();
        t.expect_hex("90F5000001 81 00", "919D");
        let mut card = Card::new(t);
        let p = probe_second(&mut card, &[1, 2]);
        assert!(p.found.is_empty());
        assert_eq!(p.notes.len(), 1);
        assert!(p.notes[0].contains("PERMISSION_DENIED"));
    }

    #[test]
    fn reading_a_data_file_keeps_the_bytes() {
        let mut t = MockTransport::new();
        t.expect_hex("90BD00000 7 01 000000 000000 00", "AABBCC 9100");
        let mut card = Card::new(t);
        let fs = FileSettings::parse(1, &[0x00, 0x00, 0xEE, 0xEE, 0x03, 0x00, 0x00]).unwrap();
        let r = read_file(&mut card, &fs).unwrap();
        assert_eq!(r.data.as_deref(), Some(&[0xAA, 0xBB, 0xCC][..]));
        assert!(r.text.contains("File 01") && r.text.contains("AA BB CC"), "{}", r.text);
    }
}
