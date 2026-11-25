//! Read-only snapshot of everything at PICC level that Format does not reset, taken at the start
//! (after the preflight Format) and again at the very end; the two must be equal.
//!
//! Everything here is a read: GetCardUID, GetVersion, GetApplicationIDs, GetDFNames, FreeMem,
//! GetKeySettings (PICC, ECC and CA root variants), GetKeyVersion, GetConfiguration for every readable
//! option, and one authentication proving that PICC key 0 still accepts the all-zero key.
//!
//! Two values are deliberately left out of the equality check because the card changes them by
//! being used: the usage counter (KUC) of ECC keys and the trailing authentication counter that
//! GetConfiguration option 0x16 appends. They are still shown.

use crate::ctx::{Ctx, SuiteCard};
use duox::card::Aid;

#[derive(Debug, Clone)]
pub struct Item {
    pub label: String,
    /// Human readable value.
    pub show: String,
    /// Value used for the equality check.
    pub cmp: String,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub items: Vec<Item>,
}

/// GetConfiguration options read at PICC level (`None` = no option byte: manufacturer data).
pub const CONFIG_OPTIONS: &[Option<u8>] = &[
    None,
    Some(0x00),
    Some(0x02),
    Some(0x03),
    Some(0x04),
    Some(0x05),
    Some(0x06),
    Some(0x0C),
    Some(0x0F),
    Some(0x10),
    Some(0x11),
    Some(0x15),
    Some(0x16),
];

/// PICC key numbers whose version byte is read.
pub const KEY_VERSION_KEYS: &[u8] = &[0x00, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1A, 0x20, 0x21];

pub fn option_name(option: Option<u8>) -> &'static str {
    match option {
        None => "manufacturer data",
        Some(0x00) => "PICCConfig",
        Some(0x01) => "PICCAppDefaultKey (write only)",
        Some(0x02) => "ATS",
        Some(0x03) => "SAK",
        Some(0x04) => "SMConfig",
        Some(0x05) => "capability data",
        Some(0x06) => "VCIID",
        Some(0x0C) => "ATQA",
        Some(0x0F) => "NFC protocol options",
        Some(0x10) => "I2C",
        Some(0x11) => "GPIO",
        Some(0x15) => "Crypto API",
        Some(0x16) => "authentication counter",
        Some(0x17) => "HALT / wake-up",
        Some(0xFF) => "lock map",
        Some(_) => "unknown",
    }
}

fn hx(b: &[u8]) -> String {
    hex::encode_upper(b)
}

fn protocol_bits(a: u8) -> String {
    let mut v = vec![];
    for (bit, n) in [(0, "AES auth"), (1, "ECC mutual/reader"), (2, "ECC card-unilateral"), (3, "ECDSA sign")] {
        v.push(format!("{n}={}", (a >> bit) & 1));
    }
    v.join(" ")
}

/// Decode a GetConfiguration response (layouts as in the SetConfiguration option table).
pub fn decode_config(option: Option<u8>, d: &[u8]) -> String {
    let raw = hx(d);
    let dec = match (option, d) {
        (None, _) => String::new(),
        (Some(0x00), [b, ..]) => format!(
            "FormatDisabled={} RandomID={} UID0Legacy={}",
            b & 1,
            (b >> 1) & 1,
            (b >> 5) & 1
        ),
        (Some(0x02), [tl, rest @ ..]) => format!("TL={tl} ({} further bytes)", rest.len()),
        (Some(0x03), [a, b, ..]) => format!("SAK1={a:02X} SAK2={b:02X}"),
        (Some(0x04), [a, b, ..]) => format!(
            "A={a:02X} B={b:02X} (ChainedWriteDisabled={} FastUID={} I2CFree={} EV={} ISOSelectECC={})",
            (b >> 2) & 1,
            (b >> 6) & 1,
            (b >> 5) & 1,
            (b >> 4) & 1,
            (b >> 3) & 1
        ),
        (Some(0x05), d) if d.len() >= 10 => {
            format!("VCTID override={:02X} PDCap1.2={:02X} PDCap2.2(TransactionTimer)={:02X}", d[1], d[3], d[5])
        }
        (Some(0x06), [len, rest @ ..]) => {
            let n = (*len as usize).min(rest.len());
            let s: String = rest[..n].iter().map(|&c| if c.is_ascii_graphic() { c as char } else { '.' }).collect();
            format!("len={len} id=\"{s}\"")
        }
        (Some(0x0C), [a, b, ..]) => format!("ATQA={a:02X}{b:02X}"),
        (Some(0x0F), [_, a, b, ..]) => format!("{} (B={b:02X})", protocol_bits(*a)),
        (Some(0x10), [_, addr, a, b, ..]) => format!("I2C address={addr:02X}; {} (B={b:02X})", protocol_bits(*a)),
        (Some(0x11), d) if d.len() >= 3 => format!("GPIO1Mode={:02X} GPIO2Mode={:02X}..", d[0], d.get(6).copied().unwrap_or(0)),
        (Some(0x15), [support, ac, ..]) => format!("support={support:02X} CommMode={} access={:X}", (ac >> 4) & 3, ac & 0xF),
        (Some(0x16), d) if d.len() >= 6 => format!(
            "AES-auth counting={} limit={}{}",
            d[1] & 1,
            u32::from_le_bytes([d[2], d[3], d[4], d[5]]),
            if d.len() >= 10 { format!(" counter={}", u32::from_le_bytes([d[6], d[7], d[8], d[9]])) } else { String::new() }
        ),
        _ => String::new(),
    };
    if dec.is_empty() {
        raw
    } else {
        format!("{raw}  [{dec}]")
    }
}

/// The part of a GetConfiguration response that is compared (option 0x16 appends a running counter).
fn config_cmp(option: Option<u8>, d: &[u8]) -> String {
    if option == Some(0x16) && d.len() > 6 {
        hx(&d[..6])
    } else {
        hx(d)
    }
}

impl Snapshot {
    pub fn get(&self, label: &str) -> Option<&Item> {
        self.items.iter().find(|i| i.label == label)
    }

    /// Read everything. Never fails: unreadable things are recorded with the error text (and compare
    /// equal only to the same error). Leaves the card authenticated at PICC level if possible.
    pub fn take(ctx: &mut Ctx) -> Snapshot {
        let mut items: Vec<Item> = vec![];
        let mut add = |label: &str, show: String, cmp: Option<String>| {
            items.push(Item { label: label.into(), cmp: cmp.unwrap_or_else(|| show.clone()), show });
        };

        // Prove the zero key (the state the suite promises to restore), keep a working session.
        let zero = vec![0u8; 16];
        let zero_ok = ctx.card.select_application(Aid::PICC, None).is_ok()
            && ctx.card.authenticate_ev2_first(0, &zero, &[]).is_ok();
        add(
            "PICC key 0 authenticates with the all-zero key",
            if zero_ok { "yes".into() } else { "NO".into() },
            None,
        );
        let key = if zero_ok { zero } else { ctx.picc_key.clone() };

        fn reauth_as(card: &mut SuiteCard, key_no: u8, key: &[u8]) {
            let _ = card.select_application(Aid::PICC, None);
            let _ = card.authenticate_ev2_first(key_no, key, &[]);
        }
        fn reauth(card: &mut SuiteCard, key: &[u8]) {
            reauth_as(card, 0, key)
        }
        fn read_as<T>(
            card: &mut SuiteCard,
            key_no: u8,
            key: &[u8],
            mut f: impl FnMut(&mut SuiteCard) -> duox::Result<T>,
        ) -> Result<T, String> {
            if !card.is_authenticated() {
                reauth_as(card, key_no, key);
            }
            let mut r = f(card);
            // a transient link problem (card moved, reader hiccup): power-cycle once and retry
            if matches!(r, Err(duox::Error::Transport(_))) {
                std::thread::sleep(std::time::Duration::from_millis(300));
                let _ = card.connect();
                reauth_as(card, key_no, key);
                r = f(card);
            }
            match r {
                Ok(v) => Ok(v),
                Err(e) => {
                    reauth_as(card, key_no, key);
                    Err(format!("ERR {e}"))
                }
            }
        }
        fn read<T>(card: &mut SuiteCard, key: &[u8], f: impl FnMut(&mut SuiteCard) -> duox::Result<T>) -> Result<T, String> {
            read_as(card, 0, key, f)
        }

        let card = &mut ctx.card;
        match read(card, &key, |c| c.get_card_uid()) {
            Ok(u) => add("UID (GetCardUID)", hx(&u), None),
            Err(e) => add("UID (GetCardUID)", e, None),
        }
        match read(card, &key, |c| c.get_version()) {
            Ok(v) => add(
                "GetVersion",
                format!(
                    "HW {}.{} SW {}.{} storage {} batch {} production week/year (BCD) {}",
                    v.hw_version.0, v.hw_version.1, v.sw_version.0, v.sw_version.1, v.hw_storage, hx(&v.batch), v.production.map(|(w, y)| format!("{w:02X}/{y:02X}")).unwrap_or_default()
                ),
                Some(hx(&v.raw)),
            ),
            Err(e) => add("GetVersion", e, None),
        }
        match read(card, &key, |c| c.get_application_ids()) {
            Ok(mut a) => {
                a.sort();
                let s = if a.is_empty() { "none".to_string() } else { a.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",") };
                add("applications (GetApplicationIDs)", s, None)
            }
            Err(e) => add("applications (GetApplicationIDs)", e, None),
        }
        match read(card, &key, |c| c.get_df_names()) {
            Ok(n) => add("DF names (GetDFNames)", if n.is_empty() { "none".into() } else { format!("{n:?}") }, None),
            Err(e) => add("DF names (GetDFNames)", e, None),
        }
        match read(card, &key, |c| c.free_mem()) {
            Ok(m) => add("FreeMem", format!("{m} bytes"), None),
            Err(e) => add("FreeMem", e, None),
        }
        match read(card, &key, |c| c.get_key_settings()) {
            Ok(k) => add(
                "PICCKeySettings (GetKeySettings)",
                format!(
                    "{:02X} [bit0 master key changeable={} bit1 free directory={} bit2 free create={} bit3 settings changeable={} bit4 NXPDAM={}] max keys {} type {}",
                    k.settings,
                    k.settings & 1,
                    (k.settings >> 1) & 1,
                    (k.settings >> 2) & 1,
                    (k.settings >> 3) & 1,
                    (k.settings >> 4) & 1,
                    k.max_keys,
                    k.key_type
                ),
                Some(hx(&k.raw)),
            ),
            Err(e) => add("PICCKeySettings (GetKeySettings)", e, None),
        }
        // Options 0x05 and 0x06 need the VCConfigurationKey, which is disabled at delivery (it can only be
        // enabled, irreversibly, by writing it: the suite never does). Prove here whether it works.
        let vc_ok = card.select_application(Aid::PICC, None).is_ok() && card.authenticate_ev2_first(0x20, &[0u8; 16], &[]).is_ok();
        reauth(card, &key);
        add(
            "VCConfigurationKey 0x20 authenticates with the all-zero key",
            if vc_ok { "yes".into() } else { "no (disabled / not usable)".into() },
            None,
        );
        for &opt in CONFIG_OPTIONS {
            let label = match opt {
                None => "GetConfiguration (no option)".to_string(),
                Some(o) => format!("GetConfiguration 0x{o:02X} {}", option_name(opt)),
            };
            let r = if matches!(opt, Some(0x05) | Some(0x06)) {
                if vc_ok {
                    let r = read_as(card, 0x20, &[0u8; 16], |c| c.get_configuration(opt));
                    reauth(card, &key);
                    r
                } else {
                    Err("not readable: VCConfigurationKey (needed for this option) is disabled".to_string())
                }
            } else {
                read(card, &key, |c| c.get_configuration(opt))
            };
            match r {
                Ok(d) => add(&label, decode_config(opt, &d), Some(config_cmp(opt, &d))),
                Err(e) => add(&label, e, None),
            }
        }
        for &k in KEY_VERSION_KEYS {
            let label = format!("GetKeyVersion 0x{k:02X}");
            match read(card, &key, |c| c.get_key_version(k, None)) {
                Ok(v) => add(&label, hx(&v), None),
                Err(e) => add(&label, e, None),
            }
        }
        match read(card, &key, |c| c.get_ecc_key_settings()) {
            Ok(list) => {
                let show = list
                    .iter()
                    .map(|k| {
                        format!(
                            "key {:02X}: curve {:02X} policy {:04X} write {:02X} KUC limit {} used {}",
                            k.key_no, k.curve, k.policy, k.write_access, k.kuc_limit, k.kuc
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                let cmp = list
                    .iter()
                    .map(|k| format!("{:02X}/{:02X}/{:04X}/{:02X}/{}", k.key_no, k.curve, k.policy, k.write_access, k.kuc_limit))
                    .collect::<Vec<_>>()
                    .join(";");
                add("ECC key settings (GetKeySettings opt 1)", if show.is_empty() { "none".into() } else { show }, Some(cmp));
            }
            Err(e) => add("ECC key settings (GetKeySettings opt 1)", e, None),
        }
        match read(card, &key, |c| c.get_ca_root_key_settings()) {
            Ok(list) => {
                let show = list.iter().map(|k| format!("{k:?}")).collect::<Vec<_>>().join("; ");
                add("CA root key settings (GetKeySettings opt 2)", if show.is_empty() { "none".into() } else { show }, None);
            }
            Err(e) => add("CA root key settings (GetKeySettings opt 2)", e, None),
        }
        if !card.is_authenticated() {
            reauth(card, &key);
        }
        Snapshot { items }
    }
}

/// One row of the comparison.
#[derive(Debug, Clone)]
pub struct DiffRow {
    pub label: String,
    pub initial: String,
    pub now: String,
    pub same: bool,
}

pub fn diff(initial: &Snapshot, now: &Snapshot) -> Vec<DiffRow> {
    let mut rows = vec![];
    for i in &initial.items {
        let n = now.get(&i.label);
        rows.push(DiffRow {
            label: i.label.clone(),
            initial: i.show.clone(),
            now: n.map(|n| n.show.clone()).unwrap_or_else(|| "(missing)".into()),
            same: n.is_some_and(|n| n.cmp == i.cmp),
        });
    }
    for n in &now.items {
        if initial.get(&n.label).is_none() {
            rows.push(DiffRow { label: n.label.clone(), initial: "(missing)".into(), now: n.show.clone(), same: false });
        }
    }
    rows
}

/// Print the comparison; returns true if everything is equal.
pub fn print_diff(title: &str, rows: &[DiffRow]) -> bool {
    println!("\n== {title} ==");
    let w = rows.iter().map(|r| r.label.len()).max().unwrap_or(10);
    let mut all = true;
    for r in rows {
        all &= r.same;
        if r.same {
            println!("  [ ok ] {:<w$}  {}", r.label, r.now, w = w);
        } else {
            println!("  [DIFF] {:<w$}\n           initial: {}\n           now:     {}", r.label, r.initial, r.now, w = w);
        }
    }
    println!("  {}", if all { "all values equal" } else { "DIFFERENCES FOUND" });
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(l: &str, show: &str, cmp: &str) -> Item {
        Item { label: l.into(), show: show.into(), cmp: cmp.into() }
    }

    #[test]
    fn diff_uses_the_compare_value() {
        let a = Snapshot { items: vec![item("x", "1 (counter 5)", "1"), item("y", "a", "a")] };
        let b = Snapshot { items: vec![item("x", "1 (counter 9)", "1"), item("y", "b", "b"), item("z", "new", "new")] };
        let rows = diff(&a, &b);
        assert_eq!(rows.iter().map(|r| r.same).collect::<Vec<_>>(), vec![true, false, false]);
        assert!(!print_diff("test", &rows));
    }

    #[test]
    fn config_decoding() {
        assert!(decode_config(Some(0x00), &[0x00]).contains("FormatDisabled=0"));
        assert!(decode_config(Some(0x0F), &[0, 0x0F, 0]).contains("AES auth=1"));
        assert!(decode_config(Some(0x06), &[4, b'T', b'E', b'S', b'T', 0]).contains("TEST"));
        assert_eq!(config_cmp(Some(0x16), &[0, 1, 5, 0, 0, 0, 9, 0, 0, 0]), "000105000000");
        assert_eq!(decode_config(None, &[1, 2]), "0102");
    }
}
