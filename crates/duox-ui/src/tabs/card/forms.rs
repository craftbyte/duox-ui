//! Dialog definitions of the card browser and the conversion of their answers into the plain
//! inputs the planner works with.

use super::model::POLICY_BITS;
use super::plan::{
    parse_additional_sets, AppInput, ChangeInput, ChangeKeyInput, CrlInput, FileInput, KeyPairInput,
    KeySettingsInput, KeySetsInput, NewFileKind, PairAction, RecordOp, ValueOp,
};
use crate::ui::files::Filter;
use crate::ui::form::{FormSpec, FormValues};
use duox::card::{AccessRights, Aid, CaRootKeyInfo, CommMode, EccKeyInfo, FileSettings, FileType, KeySettings};
use duox::crypto::{CURVE_BP256, CURVE_P256};
use duox::pki::AcMap;
use std::path::PathBuf;

pub const MODES: [&str; 3] = ["Plain", "MAC", "Full"];
pub const CURVES: [(&str, u8); 2] = [("NIST P-256", CURVE_P256), ("brainpoolP256r1", CURVE_BP256)];
const ACCESS_OPTIONS: [&str; 16] = [
    "Key 0", "Key 1", "Key 2", "Key 3", "Key 4", "Key 5", "Key 6", "Key 7", "Key 8", "Key 9", "Key A", "Key B",
    "Key C", "Key D", "Free (E)", "Never (F)",
];
const SECOND_APP_HINT: &str = "Keys and files of the second application are addressed with bit 7 set.";

// ------------------------------------------------------------------ helpers

fn mode_index(m: CommMode) -> usize {
    match m {
        CommMode::Plain => 0,
        CommMode::Mac => 1,
        CommMode::Full => 2,
    }
}

fn mode_of(index: usize) -> CommMode {
    [CommMode::Plain, CommMode::Mac, CommMode::Full][index.min(2)]
}

fn get_mode(v: &FormValues, key: &str) -> CommMode {
    mode_of(v.get_index(key).unwrap_or(0))
}

/// Four combos for the access rights of a file.
fn access_fields(spec: FormSpec, prefix: &str, default: AccessRights) -> FormSpec {
    spec.combo(&format!("{prefix}_r"), "Read", &ACCESS_OPTIONS, default.read.0 as usize)
        .combo(&format!("{prefix}_w"), "Write", &ACCESS_OPTIONS, default.write.0 as usize)
        .combo(&format!("{prefix}_rw"), "Read & write", &ACCESS_OPTIONS, default.read_write.0 as usize)
        .combo(&format!("{prefix}_c"), "Change settings", &ACCESS_OPTIONS, default.change.0 as usize)
}

fn get_access(v: &FormValues, prefix: &str) -> AccessRights {
    let nib = |k: &str| v.get_index(&format!("{prefix}_{k}")).unwrap_or(0xF) as u16;
    AccessRights::from_u16(nib("r") << 12 | nib("w") << 8 | nib("rw") << 4 | nib("c"))
}

fn uint(v: &FormValues, key: &str) -> u64 {
    v.get_uint(key).unwrap_or(0)
}

fn int(v: &FormValues, key: &str) -> i64 {
    v.get_int(key).unwrap_or(0)
}

fn flag(v: &FormValues, key: &str) -> bool {
    v.get_bool(key).unwrap_or(false)
}

pub fn curve_index(curve: u8) -> usize {
    CURVES.iter().position(|(_, c)| *c == curve).unwrap_or(0)
}

fn curve_from(v: &FormValues, key: &str) -> u8 {
    CURVES[v.get_index(key).unwrap_or(0).min(CURVES.len() - 1)].1
}

// -------------------------------------------------------------------- write

pub fn write_form(fs: &FileSettings) -> FormSpec {
    FormSpec::new(format!("Write file {:02X}", fs.file_no & 0x7F))
        .note(format!(
            "Writes to the data file{}.",
            if fs.file_type == FileType::BackupData { "; a backup file takes the data over with CommitTransaction" } else { "" }
        ))
        .ok_text("Write")
        .int_range("offset", "Offset", 0, 0, 0xFF_FFFF)
        .hint("bytes from the start of the file")
        .multiline("data", "Data (hex)", "")
        .file_open("path", "... or data from file", vec![Filter::new("All files", &["*"])])
        .check("cert", "Wrap as certificate file", false)
        .hint("PEM is converted to DER, then CertificateLength (3 bytes) is put in front")
}

pub struct WriteInput {
    pub offset: u32,
    pub hex_data: Vec<u8>,
    pub path: Option<PathBuf>,
    pub wrap_cert: bool,
}

pub fn parse_write(v: &FormValues) -> Result<WriteInput, String> {
    let text = v.get_str("data")?;
    let hex_data = crate::ui::hex::parse(text).map_err(|e| format!("The data is not valid hex: {e}"))?;
    Ok(WriteInput {
        offset: uint_i(v, "offset"),
        hex_data,
        path: v.get_path("path")?,
        wrap_cert: flag(v, "cert"),
    })
}

fn uint_i(v: &FormValues, key: &str) -> u32 {
    v.get_int(key).unwrap_or(0).clamp(0, u32::MAX as i64) as u32
}

pub fn value_form(fs: &FileSettings) -> FormSpec {
    let limited = fs.value.as_ref().is_some_and(|v| v.limited_credit_enabled());
    let ops: Vec<&str> = ValueOp::ALL.iter().map(|(n, _)| *n).collect();
    FormSpec::new(format!("Value file {:02X}", fs.file_no & 0x7F))
        .note("The change takes effect with CommitTransaction (Transactions tab).")
        .ok_text("Send")
        .combo("op", "Operation", &ops, 0)
        .hint(if limited { "LimitedCredit is enabled for this file." } else { "LimitedCredit is not enabled for this file." })
        .int_range("amount", "Amount", 1, 1, i32::MAX as i64)
}

pub fn parse_value(v: &FormValues) -> (ValueOp, i64) {
    (ValueOp::ALL[v.get_index("op").unwrap_or(0).min(2)].1, int(v, "amount"))
}

pub fn record_form(fs: &FileSettings) -> FormSpec {
    let ops: Vec<&str> = RecordOp::ALL.iter().map(|(n, _)| *n).collect();
    let size = fs.record.as_ref().map(|r| r.record_size).unwrap_or(0);
    FormSpec::new(format!("Record file {:02X}", fs.file_no & 0x7F))
        .note(format!("Records are {size} bytes. Changes take effect with CommitTransaction (Transactions tab)."))
        .ok_text("Send")
        .combo("op", "Operation", &ops, 0)
        .int_range("rec", "Record number", 0, 0, 0xFF_FFFF)
        .hint("UpdateRecord only; 0 is the newest record")
        .int_range("offset", "Offset in record", 0, 0, 0xFF_FFFF)
        .multiline("data", "Data (hex)", "")
}

pub struct RecordInput {
    pub op: RecordOp,
    pub rec: u32,
    pub offset: u32,
    pub data: Vec<u8>,
}

pub fn parse_record(v: &FormValues) -> Result<RecordInput, String> {
    let data = crate::ui::hex::parse(v.get_str("data")?).map_err(|e| format!("The data is not valid hex: {e}"))?;
    Ok(RecordInput {
        op: RecordOp::ALL[v.get_index("op").unwrap_or(0).min(2)].1,
        rec: uint_i(v, "rec"),
        offset: uint_i(v, "offset"),
        data,
    })
}

// ------------------------------------------------------------- applications

pub fn app_form(suggested_aid: u32) -> FormSpec {
    FormSpec::new("Create application")
        .note(
            "Created at PICC level. The keys start as all-zero AES keys. Delegated applications are created on the \
             Delegated apps tab.",
        )
        .ok_text("Create")
        .hex_int_range("aid", "AID", suggested_aid as u64, 6, 1, 0xFF_FFFF)
        .int_range("keys", "Number of AES keys", 3, 0, 14)
        .check("aes256", "AES-256 keys", false)
        .hex_int_range("ks1", "KeySett1", 0x0F, 2, 0, 0xFF)
        .hint("bit 0 master key changeable, 1 listing free, 2 create/delete free, 3 settings changeable, 7-4 ChangeKey rights")
        .check("isofids", "Files carry ISO file IDs", false)
        .check("use_fid", "Give the application an ISO file ID", false)
        .hex_int_range("fid", "ISO file ID", 0x1000, 4, 0, 0xFFFF)
        .hex_len("df", "ISO DF name", "", 0, 16)
        .hint("optional, 1 to 16 bytes; needs the ISO file ID")
        .check("use_sets", "Use key sets", false)
        .int_range("sets", "Number of key sets", 2, 2, 16)
        .combo("maxkey", "Largest key type to roll in", &["AES-128", "AES-256"], 0)
        .int_range("roll", "Key allowed to roll key sets", 0, 0, 13)
        .int_range("aks", "Version of the active key set", 0, 0, 255)
}

pub fn parse_app(v: &FormValues) -> AppInput {
    AppInput {
        aid: uint(v, "aid") as u32,
        keys: int(v, "keys") as u8,
        aes256: flag(v, "aes256"),
        key_sett1: uint(v, "ks1") as u8,
        iso_file_ids: flag(v, "isofids"),
        iso_fid: flag(v, "use_fid").then(|| uint(v, "fid") as u16),
        df_name: v.get_hex("df").unwrap_or_default(),
        key_sets: flag(v, "use_sets").then(|| KeySetsInput {
            count: int(v, "sets") as u8,
            max_aes256: v.get_index("maxkey").unwrap_or(0) == 1,
            roll_key: int(v, "roll") as u8,
            aks_version: int(v, "aks") as u8,
        }),
    }
}

pub const FILE_TYPES: [&str; 6] = ["StandardData", "BackupData", "Value", "LinearRecord", "CyclicRecord", "TransactionMAC"];

pub fn file_form(suggested_no: u8, second_selected: bool, at_picc: bool) -> FormSpec {
    let mut f = FormSpec::new("Create file")
        .note(if at_picc {
            "At PICC level only standard data files with an ISO file ID are possible."
        } else {
            "Fields that do not belong to the chosen file type are ignored."
        })
        .ok_text("Create")
        .combo("type", "File type", &FILE_TYPES, 0)
        .hex_int_range("no", "File number", suggested_no as u64, 2, 0, 0x1F);
    if second_selected {
        f = f.check("second", "File of the second application", false).hint(SECOND_APP_HINT);
    }
    let f = f
        .check("use_fid", "Give the file an ISO file ID", at_picc)
        .hex_int_range("fid", "ISO file ID", 0xE001, 4, 0, 0xFFFF)
        .combo("mode", "Communication mode", &MODES, 2);
    access_fields(f, "ar", AccessRights::all(duox::card::AccessRight::key(0)))
        .int_range("size", "Size / record size", 256, 1, 0xFF_FFFF)
        .hint("bytes of a data file, or bytes per record")
        .int_range("recs", "Maximum number of records", 10, 1, 0xFF_FFFF)
        .int_range("lower", "Value file: lower limit", 0, i32::MIN as i64, i32::MAX as i64)
        .int_range("upper", "Value file: upper limit", 1000, i32::MIN as i64, i32::MAX as i64)
        .int_range("initial", "Value file: initial value", 0, i32::MIN as i64, i32::MAX as i64)
        .check("limited", "Value file: allow LimitedCredit", false)
        .check("freeget", "Value file: GetValue without authentication", false)
        .check("sdm", "Standard file: prepare for SDM", false)
        .check("crl", "Data file: CRL file", false)
        .check("addar", "Allow additional access right sets", false)
        .hex_len("tmkey", "TransactionMAC key", "", 0, 32)
        .hint("16 or 32 bytes; empty for none")
        .int_range("tmver", "TransactionMAC key version", 0, 0, 255)
        .check("use_tsig", "Sign transactions (Transaction Signature)", false)
        .int_range("tsig", "Signature key number (ECC private key)", 0, 0, 4)
}

pub fn parse_file(v: &FormValues) -> FileInput {
    let kind_index = v.get_index("type").unwrap_or(0);
    let size = int(v, "size") as u32;
    let kind = match kind_index {
        0 | 1 => NewFileKind::Data { backup: kind_index == 1, size, sdm: flag(v, "sdm"), crl: flag(v, "crl") },
        2 => NewFileKind::Value {
            lower: int(v, "lower") as i32,
            upper: int(v, "upper") as i32,
            initial: int(v, "initial") as i32,
            limited_credit: flag(v, "limited"),
            free_get_value: flag(v, "freeget"),
        },
        3 | 4 => NewFileKind::Record { cyclic: kind_index == 4, record_size: size, max_records: int(v, "recs") as u32 },
        _ => NewFileKind::Tmac {
            key: v.get_hex("tmkey").unwrap_or_default(),
            key_version: int(v, "tmver") as u8,
            signature_key: flag(v, "use_tsig").then(|| int(v, "tsig") as u8),
        },
    };
    FileInput {
        number: uint(v, "no") as u8,
        second_app: flag(v, "second"),
        iso_fid: flag(v, "use_fid").then(|| uint(v, "fid") as u16),
        mode: get_mode(v, "mode"),
        access: get_access(v, "ar"),
        additional_access: flag(v, "addar"),
        kind,
    }
}

pub fn change_settings_form(fs: &FileSettings) -> FormSpec {
    let mut f = FormSpec::new(format!("ChangeFileSettings - file {:02X}", fs.file_no & 0x7F))
        .note("Needs the Change access right of the file. The new values replace the current ones.")
        .ok_text("Change")
        .combo("mode", "Communication mode", &MODES, mode_index(fs.comm_mode()));
    f = access_fields(f, "ar", fs.access);
    if fs.option & 0x80 != 0 {
        let sets: Vec<String> = fs.additional.iter().map(|a| format!("{:04X}", a.to_u16())).collect();
        f = f
            .text("add", "Additional access right sets", &sets.join(", "))
            .hint("hex values (Read Write ReadWrite Change), separated by commas");
    }
    if let Some(c) = &fs.crl {
        f = f
            .check("sig", "CRL: require CRLSignature and a rising CRLVersion", c.options & 1 != 0)
            .check("inc", "CRL: the version must rise by exactly 1", c.options & 2 != 0)
            .check("active", "CRL: revocation active", c.csn_size == 4)
            .int_range("sigkey", "CRL: CA root key that signs updates", c.sig_key.unwrap_or(0) as i64, 0, 4);
    }
    f
}

pub fn parse_change(v: &FormValues, fs: &FileSettings) -> Result<ChangeInput, String> {
    Ok(ChangeInput {
        mode: get_mode(v, "mode"),
        access: get_access(v, "ar"),
        additional: if fs.option & 0x80 != 0 { Some(parse_additional_sets(v.get_str("add")?)?) } else { None },
        crl: fs.crl.as_ref().map(|_| CrlInput {
            require_signature: flag(v, "sig"),
            increment_by_one: flag(v, "inc"),
            active: flag(v, "active"),
            sig_key: int(v, "sigkey") as u8,
        }),
    })
}

// --------------------------------------------------------------------- keys

/// Names offered for a key: saved keys first, then the hex field of the form.
pub const KEY_FROM_HEX: &str = "(use the hex field)";

pub fn key_choice_options(saved: &[String]) -> Vec<String> {
    std::iter::once(KEY_FROM_HEX.to_string()).chain(saved.iter().cloned()).collect()
}

/// Resolve a "saved key or hex" pair of fields. `resolve` looks a saved key up by name.
pub fn key_from_fields(
    v: &FormValues,
    choice: &str,
    hex_key: &str,
    saved: &[String],
    resolve: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, String> {
    let idx = v.get_index(choice)?;
    if idx == 0 {
        let h = v.get_hex(hex_key)?;
        return Ok((!h.is_empty()).then_some(h));
    }
    let name = saved.get(idx - 1).ok_or("The chosen saved key no longer exists.")?;
    resolve(name).map(Some).ok_or_else(|| format!("The saved key '{name}' cannot be read."))
}

pub fn combo_refs(options: &[String]) -> Vec<&str> {
    options.iter().map(String::as_str).collect()
}

pub fn change_key_form(default_no: u8, saved: &[String], second_selected: bool, has_sets: bool) -> FormSpec {
    let opts = key_choice_options(saved);
    let mut f = FormSpec::new("Change AES key")
        .note(
            "Needs an authentication that may change this key (see the key settings). Changing the key you are \
             authenticated with ends the session.",
        )
        .ok_text("Change key")
        .hex_int_range("no", "Key number", default_no as u64, 2, 0, 0x3F)
        .combo("new_sel", "New key", &combo_refs(&opts), 0)
        .hex("new_hex", "New key (hex)", "")
        .hint("16 bytes for AES-128, 32 for AES-256")
        .combo("old_sel", "Current key", &combo_refs(&opts), 0)
        .hex("old_hex", "Current key (hex)", "")
        .hint("only needed when it is not the key you are authenticated with")
        .hex_int_range("ver", "Key version", 0, 2, 0, 0xFF);
    if has_sets {
        f = f
            .check("use_set", "Use ChangeKeyEV2 for a key set", false)
            .int_range("set", "Key set number", 1, 0, 15);
    }
    if second_selected {
        f = f.check("second", "Key of the second application", false).hint(SECOND_APP_HINT);
    }
    f
}

pub fn parse_change_key(
    v: &FormValues,
    saved: &[String],
    resolve: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<ChangeKeyInput, String> {
    let new_key = key_from_fields(v, "new_sel", "new_hex", saved, &resolve)?.ok_or("Enter the new key or choose a saved key.")?;
    let old_key = key_from_fields(v, "old_sel", "old_hex", saved, &resolve)?;
    Ok(ChangeKeyInput {
        key_no: uint(v, "no") as u8,
        second_app: flag(v, "second"),
        new_key,
        old_key,
        version: uint(v, "ver") as u8,
        key_set: flag(v, "use_set").then(|| int(v, "set") as u8),
    })
}

pub fn key_settings_form(current: Option<&KeySettings>, picc: bool) -> FormSpec {
    let cur = current.map(|k| k.settings).unwrap_or(0x0F);
    let f = FormSpec::new("ChangeKeySettings")
        .note("Needs the master key. The new settings replace the current ones.")
        .ok_text("Change")
        .check("b0", "Master key changeable", cur & 1 != 0)
        .check("b1", "Directory / file listing without authentication", cur & 2 != 0)
        .check("b2", "Create / delete without master key", cur & 4 != 0)
        .check("b3", "Key settings changeable (clearing this is permanent)", cur & 8 != 0);
    if picc {
        f.check("hi", "NXPDAMKeys enabled", cur & 0x10 != 0)
    } else {
        f.hex_int_range("hi", "ChangeKey requires", (cur >> 4) as u64, 1, 0, 0xF)
            .hint("0 master key, 1-D that key, E the key being changed, F all keys frozen")
    }
}

pub fn parse_key_settings(v: &FormValues, picc: bool) -> KeySettingsInput {
    KeySettingsInput {
        master_changeable: flag(v, "b0"),
        listing_free: flag(v, "b1"),
        create_delete_free: flag(v, "b2"),
        settings_changeable: flag(v, "b3"),
        upper: if picc { u8::from(flag(v, "hi")) } else { uint(v, "hi") as u8 },
    }
}

pub const PAIR_ACTIONS: [&str; 3] = ["Generate on card", "Import private key", "Update meta-data only"];

/// A choice list entry from the store: label shown, entry id.
pub type Choice = (String, String);

pub fn key_pair_form(
    default_no: u8,
    cur: Option<&EccKeyInfo>,
    card_ids: &[Choice],
    cas: &[Choice],
    uid_text: &str,
    cert_file_choices: bool,
) -> FormSpec {
    let pol = cur.map(|k| k.policy).unwrap_or(0x0080);
    let mut f = FormSpec::new("ManageKeyPair")
        .note("A new entry needs the master key and CommMode.Full. Generating or importing replaces an existing key.")
        .ok_text("Send")
        .int_range("no", "Key number", default_no as i64, 0, 4)
        .hint("0 to 4 in an application, 0 to 1 at PICC level")
        .combo("action", "Action", &PAIR_ACTIONS, 0)
        .combo("curve", "Curve", &CURVES.map(|(n, _)| n), cur.map(|k| curve_index(k.curve)).unwrap_or(0));
    for (bit, name) in POLICY_BITS {
        let label = if bit == 0x8000 { "Freeze the key usage limit".to_string() } else { format!("Allow {name}") };
        f = f.check(&format!("p{bit}"), &label, pol & bit != 0);
    }
    let wa = cur.map(|k| k.write_access).unwrap_or(0x30);
    f = f
        .combo("wmode", "Update requires CommMode", &MODES, mode_index(CommMode::from_bits(wa >> 4)))
        .hex_int_range("wac", "Update access condition", (wa & 0xF) as u64, 1, 0, 0xF)
        .hint("a key number 0-D, E free, F never")
        .int_range("limit", "Key usage limit", cur.map(|k| k.kuc_limit as i64).unwrap_or(0), 0, u32::MAX as i64)
        .hint("0 switches the limit off");
    let ids: Vec<String> = std::iter::once("(none)".to_string()).chain(card_ids.iter().map(|c| c.0.clone())).collect();
    f = f
        .combo("imp", "Import: card identity from the store", &combo_refs(&ids), 0)
        .hex("imphex", "... or private key (hex)", "")
        .hint("32 bytes");
    let cas: Vec<String> = std::iter::once("(none)".to_string()).chain(cas.iter().map(|c| c.0.clone())).collect();
    f = f
        .combo("ca", "Generate: certify the public key with", &combo_refs(&cas), 0)
        .text("cn", "... certificate subject name", uid_text);
    if cert_file_choices {
        f = f.check("use_file", "... and write the certificate to a file", false);
    }
    f.hex_int_range("file", "Certificate file number", 1, 2, 0, 0x1F)
}

pub struct KeyPairForm {
    pub input: KeyPairInput,
    pub import_from_store: Option<String>,
    pub certify_with: Option<String>,
    pub subject: String,
    pub cert_file: Option<u8>,
}

pub fn parse_key_pair(v: &FormValues, card_ids: &[Choice], cas: &[Choice]) -> Result<KeyPairForm, String> {
    let action = match v.get_index("action")? {
        0 => PairAction::Generate,
        1 => PairAction::Import,
        _ => PairAction::UpdateMetaData,
    };
    let policy = POLICY_BITS.iter().filter(|(b, _)| flag(v, &format!("p{b}"))).fold(0u16, |a, (b, _)| a | b);
    let imp = v.get_index("imp")?;
    let ca = v.get_index("ca")?;
    Ok(KeyPairForm {
        input: KeyPairInput {
            key_no: int(v, "no") as u8,
            action,
            curve: curve_from(v, "curve"),
            policy,
            write_mode: get_mode(v, "wmode"),
            write_ac: uint(v, "wac") as u8,
            limit: int(v, "limit") as u32,
            import_key: v.get_hex("imphex")?,
        },
        import_from_store: imp.checked_sub(1).and_then(|i| card_ids.get(i)).map(|c| c.1.clone()),
        certify_with: ca.checked_sub(1).and_then(|i| cas.get(i)).map(|c| c.1.clone()),
        subject: v.get_str("cn")?.trim().to_string(),
        cert_file: flag(v, "use_file").then(|| uint(v, "file") as u8),
    })
}

pub fn ca_key_form(default_no: u8, cur: Option<&CaRootKeyInfo>, cas: &[Choice], preselect: usize) -> FormSpec {
    let names: Vec<String> = std::iter::once("(none)".to_string()).chain(cas.iter().map(|c| c.0.clone())).collect();
    let wa = cur.map(|k| k.write_access).unwrap_or(0x30);
    let ra = cur.map(|k| k.read_access).unwrap_or(0x1E);
    FormSpec::new("ManageCARootKey")
        .note("Stores the public key that readers must be certified by. A new entry needs the master key.")
        .ok_text("Send")
        .int_range("no", "Key number", default_no as i64, 0, 4)
        .hint("0 to 4 in an application, 0 to 1 at PICC level")
        .combo("ca", "CA from the store", &combo_refs(&names), preselect)
        .hex("pub", "... or public key (hex)", "")
        .hint("65 bytes, 04 || x || y")
        .combo("curve", "Curve (for a pasted key)", &CURVES.map(|(n, _)| n), cur.map(|k| curve_index(k.curve)).unwrap_or(0))
        .text("ac", "Access conditions granted", &cur.map(|k| super::model::acmap_text(k.access_rights)).unwrap_or_else(|| "0-D".into()))
        .hint("for example 0,5 or 0-D; certificates can grant at most these")
        .check("issuer", "The card checks the issuer name of certificates", true)
        .combo("wmode", "Update requires CommMode", &MODES, mode_index(CommMode::from_bits(wa >> 4)))
        .hex_int_range("wac", "Update access condition", (wa & 0xF) as u64, 1, 0, 0xF)
        .combo("rmode", "ExportKey CommMode", &MODES, mode_index(CommMode::from_bits(ra >> 4)))
        .hex_int_range("rac", "ExportKey access condition", (ra & 0xF) as u64, 1, 0, 0xF)
        .hint("a key number 0-D, E free, F never")
        .check("crl", "Enable certificate revocation", cur.is_some_and(|k| k.crl_file & 0x80 != 0))
        .hex_int_range("crlfile", "CRL file number", cur.map(|k| (k.crl_file & 0x1F) as u64).unwrap_or(0), 2, 0, 0x1F)
        .check("crlaid_set", "The CRL file is in another application", false)
        .hex_int_range("crlaid", "AID holding the CRL file", 0, 6, 0, 0xFF_FFFF)
}

pub struct CaKeyForm {
    pub no: u8,
    pub store_ca: Option<String>,
    pub pasted_pub: Vec<u8>,
    pub pasted_curve: u8,
    pub acmap: Result<AcMap, String>,
    pub check_issuer: bool,
    pub write_mode: CommMode,
    pub write_ac: u8,
    pub read_mode: CommMode,
    pub read_ac: u8,
    pub crl: Option<(u8, Option<Aid>)>,
}

pub fn parse_ca_key(v: &FormValues, cas: &[Choice]) -> Result<CaKeyForm, String> {
    let ca = v.get_index("ca")?;
    Ok(CaKeyForm {
        no: int(v, "no") as u8,
        store_ca: ca.checked_sub(1).and_then(|i| cas.get(i)).map(|c| c.1.clone()),
        pasted_pub: v.get_hex("pub")?,
        pasted_curve: curve_from(v, "curve"),
        acmap: AcMap::parse(v.get_str("ac")?).map_err(|e| e.to_string()),
        check_issuer: flag(v, "issuer"),
        write_mode: get_mode(v, "wmode"),
        write_ac: uint(v, "wac") as u8,
        read_mode: get_mode(v, "rmode"),
        read_ac: uint(v, "rac") as u8,
        crl: flag(v, "crl").then(|| (uint(v, "crlfile") as u8, flag(v, "crlaid_set").then(|| Aid(uint(v, "crlaid") as u32)))),
    })
}

// -------------------------------------------------------------- applications

pub fn select_two_form(first: Aid, second: Aid) -> FormSpec {
    FormSpec::new("Select two applications")
        .note(
            "Both applications are selected at once. The first one is the primary application. Keys and files of the \
             second one are addressed with bit 7 set. Selecting ends the authentication.",
        )
        .ok_text("Select")
        .hex_int_range("a1", "Primary AID", first.0 as u64, 6, 1, 0xFF_FFFF)
        .hex_int_range("a2", "Second AID", second.0 as u64, 6, 1, 0xFF_FFFF)
}

pub fn probe_form() -> FormSpec {
    FormSpec::new("Find files of the second application")
        .note(
            "The card cannot list the files of the second application, so they are asked for one by one with \
             GetFileSettings. A file that does not exist ends an active authentication; probe before authenticating.",
        )
        .ok_text("Probe")
        .text("list", "File numbers", "01-1F")
        .hint("hex numbers and ranges, for example 01, 03-05")
}

/// Parse "01, 03-05" (hex) into file numbers 0..=0x1F.
pub fn parse_file_numbers(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in text.split([',', ' ', ';']).filter(|p| !p.is_empty()) {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let parse = |s: &str| u8::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|_| format!("'{s}' is not a hex file number."));
        let (a, b) = (parse(lo)?, parse(hi)?);
        if a > b || b > 0x1F {
            return Err(format!("'{part}' is not a range of file numbers within 00 to 1F."));
        }
        out.extend(a..=b);
    }
    out.dedup();
    if out.is_empty() {
        return Err("Enter at least one file number.".into());
    }
    Ok(out)
}

/// Existing (addressed number, type) pairs of the cached files.
pub fn existing_files(files: &[FileSettings]) -> Vec<(u8, FileType)> {
    files.iter().map(|f| (f.file_no, f.file_type)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_number_lists() {
        assert_eq!(parse_file_numbers("01, 03-05").unwrap(), vec![1, 3, 4, 5]);
        assert_eq!(parse_file_numbers("1F").unwrap(), vec![0x1F]);
        assert_eq!(parse_file_numbers("01-1F").unwrap().len(), 31);
        assert!(parse_file_numbers("20").is_err());
        assert!(parse_file_numbers("05-03").is_err());
        assert!(parse_file_numbers("zz").is_err());
        assert!(parse_file_numbers("  ").is_err());
    }

    #[test]
    fn mode_mapping_roundtrips() {
        for (i, m) in [CommMode::Plain, CommMode::Mac, CommMode::Full].into_iter().enumerate() {
            assert_eq!(mode_index(m), i);
            assert_eq!(mode_of(i), m);
        }
        assert_eq!(MODES.len(), 3);
        assert_eq!(curve_index(CURVE_BP256), 1);
        assert_eq!(curve_index(0x77), 0);
    }

    #[test]
    fn key_options_lead_with_hex_entry() {
        let o = key_choice_options(&["a".to_string(), "b".to_string()]);
        assert_eq!(o, [KEY_FROM_HEX, "a", "b"]);
    }
}
