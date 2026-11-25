//! ISO/IEC 7816-4 commands and fast confidential UID retrieval.

use super::{key_chooser, plan, read_key, report, require_unauthenticated, token, Action, State};
use crate::shared::{DynCard, Shared};
use crate::ui::form::{FormSpec, FormValues};
use duox::card::IsoSelect;

const SELECT_EF_MODES: [&str; 2] = ["EF below the current DF (P1 = 02)", "File ID: MF, DF or EF (P1 = 00)"];
const ISO_PLAIN: &str = "ISO/IEC 7816-4 file commands are plain, only valid while no authentication is active and \
                         are refused in an application that holds a TransactionMAC file.";

impl State {
    pub(super) fn start_iso(&mut self, a: Action, shared: &mut Shared) {
        let l = self.last.clone();
        match a {
            Action::SelectDf => shared.ask(
                FormSpec::new("ISOSelectFile: DF name")
                    .note("Selects an application by its DF name. This ends any authentication.")
                    .ok_text("Select")
                    .hex_len("name", "DF name (hex)", &l.df_name, 1, 16),
                token::SELECT_DF,
            ),
            Action::SelectEf => shared.ask(
                FormSpec::new("ISOSelectFile: file ID")
                    .note("Selects a file by its ISO file ID in the selected application.")
                    .ok_text("Select")
                    .hex_int_range("fid", "File ID", l.file_id, 4, 0, 0xFFFF)
                    .combo("how", "Select", &SELECT_EF_MODES, 0)
                    .hint("A DF or the MF selected by file ID ends the authentication; an EF below the current DF does not.")
                    .check("fci", "Return the file control information", true),
                token::SELECT_EF,
            ),
            Action::SelectMf => {
                // 3F00 without FCI.
                let r = shared.with_card(|c| {
                    c.iso_select(&IsoSelect::Raw { p1: 0x00, p2: 0x0C, data: &[0x3F, 0x00] })
                });
                if let Ok((fci, sw)) = r {
                    self.show(report::select_report(sw, &fci, false, true));
                }
            }
            Action::GetChallenge => {
                if require_unauthenticated(shared, "ISOGetChallenge") {
                    shared.ask(
                        FormSpec::new("ISOGetChallenge")
                            .note("Asks the card for random bytes.")
                            .ok_text("Get")
                            .int_range("len", "Length", 16, 1, 255)
                            .hint("bytes"),
                        token::CHALLENGE,
                    );
                }
            }
            Action::ReadBinary => {
                if require_unauthenticated(shared, "ISOReadBinary") {
                    shared.ask(
                        FormSpec::new("ISOReadBinary")
                            .note(format!("Reads from the selected EF or by short file ID. {ISO_PLAIN}"))
                            .ok_text("Read")
                            .int_range("offset", "Offset", l.offset, 0, 0x7FFF)
                            .int_range("len", "Length", l.length, 0, 255)
                            .hint("0 reads to the end of the file (at most 256 bytes per command).")
                            .check("use_sfi", "Address the file by short file ID", l.use_sfi)
                            .hex_int_range("sfi", "Short file ID", l.sfi.clamp(1, 0x1F), 2, 1, 0x1F),
                        token::READ_BINARY,
                    );
                }
            }
            Action::UpdateBinary => {
                if require_unauthenticated(shared, "ISOUpdateBinary") {
                    shared.ask(
                        FormSpec::new("ISOUpdateBinary")
                            .note(
                                "Writes at the offset to the selected EF or by short file ID. The file must allow \
                                 free write access. Changes are committed immediately.",
                            )
                            .ok_text("Write")
                            .int_range("offset", "Offset", l.offset, 0, 0x7FFF)
                            .check("use_sfi", "Address the file by short file ID", l.use_sfi)
                            .hex_int_range("sfi", "Short file ID", l.sfi.clamp(1, 0x1F), 2, 1, 0x1F)
                            .hex_len("data", "Data (hex)", "", 1, 255),
                        token::UPDATE_BINARY,
                    );
                }
            }
            Action::ReadRecord => {
                if require_unauthenticated(shared, "ISOReadRecord") {
                    shared.ask(
                        FormSpec::new("ISOReadRecord")
                            .note(format!("Reads a record of the selected record file. {ISO_PLAIN}"))
                            .ok_text("Read")
                            .int_range("rec", "Record number", l.record, 0, 255)
                            .hint("0 is the current (last written) record.")
                            .check("following", "... and all following records", false)
                            .hex_int_range("sfi", "Short file ID", l.sfi.min(0x1F), 2, 0, 0x1F)
                            .hint("0 addresses the selected file.")
                            .int_range("len", "Length", l.length.clamp(0, 255), 0, 255)
                            .hint("0 reads the whole record."),
                        token::READ_RECORD,
                    );
                }
            }
            Action::AppendRecord => {
                if require_unauthenticated(shared, "ISOAppendRecord") {
                    shared.ask(
                        FormSpec::new("ISOAppendRecord")
                            .note("A shorter record is padded with zeros. The record is committed immediately.")
                            .ok_text("Append")
                            .hex_int_range("sfi", "Short file ID", l.sfi.min(0x1F), 2, 0, 0x1F)
                            .hint("0 addresses the selected file.")
                            .hex_len("data", "Record data (hex)", "", 1, 255),
                        token::APPEND_RECORD,
                    );
                }
            }
            Action::FastUid => {
                let spec = FormSpec::new("Fast confidential UID")
                    .note(
                        "Selects the application by DF name and decrypts the UID carried in the file control \
                         information with the AppUIDENCKey. No authentication is needed.",
                    )
                    .ok_text("Select and decrypt")
                    .hex_len("name", "DF name (hex)", &l.df_name, 1, 16);
                shared.ask(key_chooser(spec, shared, "key", "AppUIDENCKey", ""), token::FAST_UID);
            }
            _ => {}
        }
    }

    pub(super) fn iso_done(&mut self, tok: u32, v: &FormValues, shared: &mut Shared) {
        match tok {
            token::SELECT_DF => {
                let name = v.get_hex("name").unwrap_or_default();
                self.last.df_name = hex::encode_upper(&name);
                let r = shared.with_card(|c| {
                    let (fci, sw) = c.iso_select(&IsoSelect::DfName(&name))?;
                    Ok::<_, duox::Error>((DynCard::fci_ephemeral_key(&fci).is_some(), fci, sw))
                });
                if let Ok((eph, fci, sw)) = r {
                    let text = report::select_report(sw, &fci, eph, true);
                    self.show(format!(
                        "{text}\nThe application is identified by its DF name only, so the status line cannot name it."
                    ));
                }
            }
            token::SELECT_EF => {
                let fid = v.get_uint("fid").unwrap_or(0) as u16;
                self.last.file_id = u64::from(fid);
                let below_df = v.get_index("how").unwrap_or(0) == 0;
                let want_fci = v.get_bool("fci").unwrap_or(true);
                let p1 = if below_df { 0x02 } else { 0x00 };
                let p2 = if want_fci { 0x00 } else { 0x0C };
                let data = fid.to_be_bytes();
                if let Ok((fci, sw)) = shared.with_card(|c| c.iso_select(&IsoSelect::Raw { p1, p2, data: &data })) {
                    self.show(report::select_report(sw, &fci, false, !below_df));
                }
            }
            token::CHALLENGE => {
                if !require_unauthenticated(shared, "ISOGetChallenge") {
                    return;
                }
                let len = v.get_int("len").unwrap_or(16) as u8;
                if let Ok(d) = shared.with_card(|c| c.iso_get_challenge(len)) {
                    self.show(format!("ISOGetChallenge: {}", crate::ui::hex::spaced(&d)));
                }
            }
            token::READ_BINARY => {
                if !require_unauthenticated(shared, "ISOReadBinary") {
                    return;
                }
                let offset = v.get_int("offset").unwrap_or(0);
                let len = v.get_int("len").unwrap_or(0);
                let use_sfi = v.get_bool("use_sfi").unwrap_or(false);
                let sfi_raw = v.get_uint("sfi").unwrap_or(1);
                (self.last.offset, self.last.length, self.last.use_sfi, self.last.sfi) = (offset, len, use_sfi, sfi_raw);
                let sfi = plan::sfi_choice(use_sfi, sfi_raw);
                if let Err(e) = plan::check_binary_offset(offset as u32, sfi) {
                    shared.report_error(e);
                    return;
                }
                if let Ok(d) = shared.with_card(|c| c.iso_read_binary(offset as u32, len as u8, sfi)) {
                    self.show(report::binary_report("ISOReadBinary", &d));
                }
            }
            token::UPDATE_BINARY => {
                if !require_unauthenticated(shared, "ISOUpdateBinary") {
                    return;
                }
                let offset = v.get_int("offset").unwrap_or(0);
                let use_sfi = v.get_bool("use_sfi").unwrap_or(false);
                let sfi_raw = v.get_uint("sfi").unwrap_or(1);
                (self.last.offset, self.last.use_sfi, self.last.sfi) = (offset, use_sfi, sfi_raw);
                let sfi = plan::sfi_choice(use_sfi, sfi_raw);
                let data = v.get_hex("data").unwrap_or_default();
                if let Err(e) = plan::check_binary_offset(offset as u32, sfi) {
                    shared.report_error(e);
                    return;
                }
                if shared.with_card(|c| c.iso_update_binary(&data, offset as u32, sfi)).is_ok() {
                    self.show(format!("ISOUpdateBinary: {} bytes written.", data.len()));
                }
            }
            token::READ_RECORD => {
                if !require_unauthenticated(shared, "ISOReadRecord") {
                    return;
                }
                let rec = v.get_int("rec").unwrap_or(0);
                let sfi = v.get_uint("sfi").unwrap_or(0) as u8;
                let len = v.get_int("len").unwrap_or(0);
                let following = v.get_bool("following").unwrap_or(false);
                (self.last.record, self.last.sfi) = (rec, u64::from(sfi));
                if let Ok(d) = shared.with_card(|c| c.iso_read_record(rec as u8, following, sfi, len as u8)) {
                    self.show(report::record_report(&d));
                }
            }
            token::APPEND_RECORD => {
                if !require_unauthenticated(shared, "ISOAppendRecord") {
                    return;
                }
                let sfi = v.get_uint("sfi").unwrap_or(0) as u8;
                self.last.sfi = u64::from(sfi);
                let data = v.get_hex("data").unwrap_or_default();
                if shared.with_card(|c| c.iso_append_record(&data, sfi)).is_ok() {
                    self.show("ISOAppendRecord: record written.");
                }
            }
            token::FAST_UID => self.fast_uid(v, shared),
            _ => {}
        }
    }

    fn fast_uid(&mut self, v: &FormValues, shared: &mut Shared) {
        let key = match read_key(shared, v, "key") {
            Ok(Some(k)) => k,
            Ok(None) => {
                shared.report_error("Enter the AppUIDENCKey as hex or choose a saved key.");
                return;
            }
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let name = v.get_hex("name").unwrap_or_default();
        self.last.df_name = hex::encode_upper(&name);
        let r = shared.with_card(|c| {
            let (fci, _) = c.iso_select(&IsoSelect::DfName(&name))?;
            let uid = c.fci_fast_uid(&fci, &key)?;
            Ok::<_, duox::Error>((fci, uid))
        });
        match r {
            Ok((fci, Some(u))) => self.show(report::fast_uid_report(&fci, &u.uid, u.vctid, u.pd_cap1)),
            Ok((fci, None)) => self.show(report::no_fast_uid_report(&fci)),
            Err(_) => {}
        }
    }
}
