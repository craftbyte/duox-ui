//! Pure logic of the tab: argument checks, the GPIO configuration record, key selection and
//! access-condition checks. Nothing here touches the card or the UI, so it is unit tested.

use duox::card::{AccessRight, CommMode, GpioControl, GpioOperation};

// ------------------------------------------------------------------ keys

/// First entry of every key chooser: take the hex field instead of a saved key.
pub const KEY_HEX: &str = "Use the hex field below";

/// Turn the answer of a key chooser (saved-key name or [`KEY_HEX`], plus the hex field) into key
/// bytes. `Ok(None)` means nothing was entered. `lookup` resolves saved key names.
pub fn pick_key(
    choice: &str,
    hex: &[u8],
    lookup: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, String> {
    let key = if choice == KEY_HEX {
        if hex.is_empty() {
            return Ok(None);
        }
        hex.to_vec()
    } else {
        lookup(choice).ok_or_else(|| format!("The saved key '{choice}' no longer exists."))?
    };
    match key.len() {
        16 | 32 => Ok(Some(key)),
        n => Err(format!("An AES key is 16 or 32 bytes long, the one given has {n}.")),
    }
}

// ------------------------------------------------------------------ ISO

/// The short file ID of a command, or `None` to address the selected file.
pub fn sfi_choice(use_sfi: bool, sfi: u64) -> Option<u8> {
    use_sfi.then_some((sfi & 0x1F) as u8)
}

/// ISOReadBinary / ISOUpdateBinary address the offset in one byte when a short file ID is used.
pub fn check_binary_offset(offset: u32, sfi: Option<u8>) -> Result<(), String> {
    match sfi {
        Some(_) if offset > 0xFF => {
            Err("With a short file ID the offset is limited to 255. Select the file by its file ID instead.".into())
        }
        None if offset > 0x7FFF => Err("The offset is limited to 32767.".into()),
        _ => Ok(()),
    }
}

/// Parse a challenge split such as `3,5` or `8`. Parts are 1..=8 bytes and add up to 8.
pub fn parse_split(text: &str) -> Result<Vec<u8>, String> {
    let mut parts = Vec::new();
    for tok in text.split([',', ' ', ';']).filter(|t| !t.is_empty()) {
        let n: u8 = tok.parse().map_err(|_| format!("'{tok}' is not a number of bytes."))?;
        parts.push(n);
    }
    if parts.is_empty() {
        return Err("Give the challenge split as numbers of bytes, for example 8 or 3,5.".into());
    }
    if parts.iter().any(|&n| n == 0 || n > 8) {
        return Err("Every part of the challenge split is 1 to 8 bytes.".into());
    }
    let sum: u32 = parts.iter().map(|&n| u32::from(n)).sum();
    if sum != 8 {
        return Err(format!("The challenge split must add up to 8 bytes, it adds up to {sum}."));
    }
    Ok(parts)
}

// ------------------------------------------------------------------ access conditions

/// Describe the conditions that would grant an access, for messages.
pub fn describe_conditions(acs: &[AccessRight]) -> String {
    let mut names: Vec<String> = Vec::new();
    for a in acs {
        let n = a.to_string();
        if !names.contains(&n) {
            names.push(n);
        }
    }
    names.join(" or ")
}

/// `None` when one of the conditions `acs` is free or satisfied by the active session (`has`),
/// otherwise a sentence saying what is missing.
pub fn access_problem(
    acs: &[AccessRight],
    file_no: u8,
    write: bool,
    authenticated: bool,
    has: impl Fn(AccessRight) -> bool,
) -> Option<String> {
    if acs.iter().any(|a| a.is_free() || has(*a)) {
        return None;
    }
    let verb = if write { "Writing" } else { "Reading" };
    let file = format!("file {:02X} of the second application", file_no & 0x1F);
    if acs.iter().all(|a| a.is_never()) {
        return Some(format!("{verb} {file} is never allowed ({}).", describe_conditions(acs)));
    }
    let hint = if authenticated {
        "The active authentication does not satisfy it. Authenticate with the right key first (key number 80 + n addresses a key of the second application)."
    } else {
        "Authenticate with the right key first (key number 80 + n addresses a key of the second application)."
    };
    Some(format!("{verb} {file} needs access condition {}. {hint}", describe_conditions(acs)))
}

// ------------------------------------------------------------------ GPIO operation

/// Entries of the ManageGPIO operation chooser.
pub const GPIO_OPS: [&str; 10] = [
    "Output: clear (LOW)",
    "Output: set (HIGH)",
    "Output: toggle",
    "Power out: enable at the default level",
    "Power out: enable and measure",
    "Power out: stop",
    "Power out: custom (level, measure, enable below)",
    "Auto WTX: enable",
    "Auto WTX: disable",
    "Raw operation byte",
];

/// Build the operation from the form's answers.
pub fn gpio_operation(choice: usize, nfc: bool, level: u8, measure: bool, enable: bool, raw: u8) -> GpioOperation {
    let out = |control| GpioOperation::Output { control, nfc_control: nfc };
    let power = |level, measure, enable| GpioOperation::PowerDownstream { level, measure, enable };
    match choice {
        0 => out(GpioControl::Clear),
        1 => out(GpioControl::Set),
        2 => out(GpioControl::Toggle),
        3 => power(0, false, true),
        4 => power(0, true, true),
        5 => power(0, false, false),
        6 => power(level, measure, enable),
        7 => GpioOperation::AutoWtx { enable: true },
        8 => GpioOperation::AutoWtx { enable: false },
        _ => GpioOperation::Raw(raw),
    }
}

// ------------------------------------------------------------------ GPIO configuration

pub const G1_MODES: &[(u8, &str)] = &[(0, "disabled"), (1, "input"), (2, "output"), (4, "down-stream power out")];
pub const G2_MODES: &[(u8, &str)] =
    &[(0, "disabled"), (1, "input"), (2, "output"), (5, "output with NFCPause file")];
pub const NOTIFICATIONS: &[(u8, &str)] = &[(0, "none"), (1, "authentication"), (2, "NFC field")];

/// Option texts for a chooser (`"2  output"`) and the index of `current`. A value outside the
/// table is appended so that it survives an edit of another field.
pub fn choices(table: &[(u8, &str)], current: u8) -> (Vec<String>, usize) {
    let mut opts: Vec<String> = table.iter().map(|(v, n)| format!("{v}  {n}")).collect();
    let idx = match table.iter().position(|(v, _)| *v == current) {
        Some(i) => i,
        None => {
            opts.push(format!("{current}  reserved value"));
            opts.len() - 1
        }
    };
    (opts, idx)
}

/// The number at the start of a chooser text.
pub fn choice_value(text: &str) -> u8 {
    text.split_whitespace().next().and_then(|t| t.parse().ok()).unwrap_or(0)
}

fn choice_name(table: &[(u8, &str)], v: u8) -> String {
    table.iter().find(|(x, _)| *x == v).map_or_else(|| format!("{v} (reserved)"), |(_, n)| (*n).to_string())
}

/// CommMode and access condition of one command, as stored in one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub mode: CommMode,
    pub condition: u8,
}

impl Access {
    pub fn byte(self) -> u8 {
        (self.mode.bits() << 4) | (self.condition & 0x0F)
    }
    pub fn from_byte(b: u8) -> Self {
        Access { mode: CommMode::from_bits(b >> 4), condition: b & 0x0F }
    }
    fn describe(self) -> String {
        format!("{} mode, condition {}", self.mode, AccessRight(self.condition))
    }
}

/// The GPIO configuration record of SetConfiguration option 0x11 (33 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpioConfig {
    pub mode1: u8,
    pub pad1: [u8; 5],
    pub mode2: u8,
    pub pad2: [u8; 5],
    pub notify1: u8,
    pub notify2: u8,
    pub manage: Access,
    pub read: Access,
    /// Application with additional access rights (0 = none).
    pub extra_aid: u32,
    pub extra_manage_condition: u8,
    pub extra_read: Access,
    pub power_out: [u8; 5],
    pub nfc_pause: [u8; 7],
}

pub const GPIO_CONFIG_LEN: usize = 33;

impl GpioConfig {
    /// Everything disabled, both commands closed.
    pub fn closed() -> Self {
        let never = Access { mode: CommMode::Plain, condition: 0x0F };
        GpioConfig {
            mode1: 0,
            pad1: [0; 5],
            mode2: 0,
            pad2: [0; 5],
            notify1: 0,
            notify2: 0,
            manage: never,
            read: never,
            extra_aid: 0,
            extra_manage_condition: 0x0F,
            extra_read: never,
            power_out: [0; 5],
            nfc_pause: [0; 7],
        }
    }

    pub fn parse(d: &[u8]) -> Result<Self, String> {
        if d.len() != GPIO_CONFIG_LEN {
            return Err(format!(
                "Unexpected GPIO configuration length ({} bytes instead of {GPIO_CONFIG_LEN}).",
                d.len()
            ));
        }
        let arr5 = |i: usize| <[u8; 5]>::try_from(&d[i..i + 5]).unwrap_or_default();
        Ok(GpioConfig {
            mode1: d[0],
            pad1: arr5(1),
            mode2: d[6],
            pad2: arr5(7),
            notify1: d[12],
            notify2: d[13],
            manage: Access::from_byte(d[14]),
            read: Access::from_byte(d[15]),
            extra_aid: u32::from_le_bytes([d[16], d[17], d[18], 0]),
            extra_manage_condition: d[19] & 0x0F,
            extra_read: Access::from_byte(d[20]),
            power_out: arr5(21),
            nfc_pause: <[u8; 7]>::try_from(&d[26..33]).unwrap_or_default(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(GPIO_CONFIG_LEN);
        v.push(self.mode1);
        v.extend(self.pad1);
        v.push(self.mode2);
        v.extend(self.pad2);
        v.extend([self.notify1, self.notify2, self.manage.byte(), self.read.byte()]);
        v.extend(&self.extra_aid.to_le_bytes()[..3]);
        v.push(self.extra_manage_condition & 0x0F);
        v.push(self.extra_read.byte());
        v.extend(self.power_out);
        v.extend(self.nfc_pause);
        v
    }

    pub fn describe(&self) -> Vec<String> {
        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ");
        let mut l = vec![
            format!(
                "GPIO1       {}, pad control {}, notification {}",
                choice_name(G1_MODES, self.mode1),
                h(&self.pad1),
                choice_name(NOTIFICATIONS, self.notify1)
            ),
            format!(
                "GPIO2       {}, pad control {}, notification {}",
                choice_name(G2_MODES, self.mode2),
                h(&self.pad2),
                choice_name(NOTIFICATIONS, self.notify2)
            ),
            format!("ManageGPIO  {}", self.manage.describe()),
            format!("ReadGPIO    {}", self.read.describe()),
        ];
        if self.extra_aid != 0 {
            l.push(format!(
                "Additional access in application {:06X}: ManageGPIO condition {}, ReadGPIO {}",
                self.extra_aid,
                AccessRight(self.extra_manage_condition),
                self.extra_read.describe()
            ));
        }
        l.push(format!("Power out   {}", h(&self.power_out)));
        l.push(format!("NFCPause    {}", h(&self.nfc_pause)));
        l
    }
}

// ------------------------------------------------------------------ EV charging

/// The CA identifier of an EV charging certificate is 14 decimal digits.
pub fn check_ca_id(id: &str) -> Result<(), String> {
    if id.len() == 14 && id.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err("The CA identifier is 14 decimal digits.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_choice() {
        let lookup = |n: &str| (n == "prox").then(|| vec![7u8; 16]);
        assert_eq!(pick_key(KEY_HEX, &[], lookup).unwrap(), None);
        assert_eq!(pick_key(KEY_HEX, &[1; 16], lookup).unwrap(), Some(vec![1; 16]));
        assert_eq!(pick_key("prox", &[], lookup).unwrap(), Some(vec![7; 16]));
        assert!(pick_key("gone", &[], lookup).unwrap_err().contains("no longer exists"));
        assert!(pick_key(KEY_HEX, &[1; 8], lookup).unwrap_err().contains("16 or 32"));
        assert!(pick_key(KEY_HEX, &[1; 32], lookup).is_ok());
    }

    #[test]
    fn iso_offsets() {
        assert_eq!(sfi_choice(false, 5), None);
        assert_eq!(sfi_choice(true, 5), Some(5));
        assert!(check_binary_offset(255, Some(1)).is_ok());
        assert!(check_binary_offset(256, Some(1)).is_err());
        assert!(check_binary_offset(0x7FFF, None).is_ok());
        assert!(check_binary_offset(0x8000, None).is_err());
    }

    #[test]
    fn split_parsing() {
        assert_eq!(parse_split("8").unwrap(), vec![8]);
        assert_eq!(parse_split("3, 5").unwrap(), vec![3, 5]);
        assert_eq!(parse_split("1,1,1,1,1,1,1,1").unwrap().len(), 8);
        assert!(parse_split("").is_err());
        assert!(parse_split("4,3").unwrap_err().contains("adds up to 7"));
        assert!(parse_split("0,8").is_err());
        assert!(parse_split("9").is_err());
        assert!(parse_split("a").is_err());
    }

    #[test]
    fn access_messages() {
        let free = [AccessRight::FREE, AccessRight(1)];
        assert!(access_problem(&free, 0x81, false, false, |_| false).is_none());
        let keys = [AccessRight(1), AccessRight(2)];
        assert!(access_problem(&keys, 0x81, false, true, |a| a == AccessRight(2)).is_none());
        let m = access_problem(&keys, 0x81, true, false, |_| false).unwrap();
        assert!(m.starts_with("Writing file 01 of the second application needs access condition key 1 or key 2."), "{m}");
        let never = [AccessRight::NEVER, AccessRight::NEVER];
        assert!(access_problem(&never, 0x80, false, true, |_| false).unwrap().contains("never allowed (never)"));
    }

    #[test]
    fn gpio_operations() {
        let byte = |c, nfc, level, m, e, raw| gpio_operation(c, nfc, level, m, e, raw).byte().unwrap();
        assert_eq!(byte(1, false, 0, false, false, 0), 0x01);
        assert_eq!(byte(1, true, 0, false, false, 0), 0x81);
        assert_eq!(byte(2, false, 0, false, false, 0), 0x02);
        assert_eq!(byte(3, false, 9, false, false, 0), 0x01);
        assert_eq!(byte(4, false, 0, false, false, 0), 0x03);
        assert_eq!(byte(5, false, 0, true, true, 0), 0x00);
        assert_eq!(byte(6, false, 0x11, true, true, 0), 0x47);
        assert_eq!(byte(7, false, 0, false, false, 0), 0x81);
        assert_eq!(byte(8, false, 0, false, false, 0), 0x80);
        assert_eq!(byte(9, true, 0, false, false, 0xA5), 0xA5);
        assert_eq!(GPIO_OPS.len(), 10);
    }

    #[test]
    fn gpio_config_layout() {
        let closed = GpioConfig::closed().encode();
        assert_eq!(closed.len(), GPIO_CONFIG_LEN);
        assert_eq!((closed[14], closed[15], closed[19], closed[20]), (0x0F, 0x0F, 0x0F, 0x0F));
        assert!(closed[..14].iter().all(|&b| b == 0) && closed[21..].iter().all(|&b| b == 0));

        let mut c = GpioConfig::closed();
        c.mode1 = 2;
        c.pad1 = [1, 2, 3, 4, 5];
        c.mode2 = 5;
        c.notify2 = 2;
        c.manage = Access { mode: CommMode::Full, condition: 0 };
        c.read = Access { mode: CommMode::Mac, condition: 0xE };
        c.extra_aid = 0x123456;
        c.extra_manage_condition = 3;
        c.extra_read = Access { mode: CommMode::Plain, condition: 4 };
        c.power_out = [9; 5];
        c.nfc_pause = [1, 2, 3, 4, 5, 6, 7];
        let bytes = c.encode();
        assert_eq!(&bytes[14..16], &[0x30, 0x1E]);
        assert_eq!(&bytes[16..19], &[0x56, 0x34, 0x12]);
        assert_eq!((bytes[19], bytes[20]), (3, 4));
        assert_eq!(&bytes[26..], &[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(GpioConfig::parse(&bytes).unwrap(), c);
        assert!(GpioConfig::parse(&bytes[..32]).is_err());
        assert!(c.describe().iter().any(|l| l.contains("123456")));
    }

    #[test]
    fn chooser_texts() {
        let (opts, i) = choices(G1_MODES, 4);
        assert_eq!((opts[i].as_str(), opts.len()), ("4  down-stream power out", 4));
        let (opts, i) = choices(G2_MODES, 9);
        assert_eq!((i, opts.len()), (4, 5));
        assert_eq!(choice_value(&opts[i]), 9);
        assert_eq!(choice_value("5  output with NFCPause file"), 5);
    }

    #[test]
    fn ca_identifier() {
        assert!(check_ca_id("00000000000001").is_ok());
        assert!(check_ca_id("1234").is_err());
        assert!(check_ca_id("0000000000000a").is_err());
    }
}
