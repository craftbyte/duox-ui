//! Hex formatting and parsing helpers.

/// `"01 AB FF"`
pub fn spaced(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// `"01ABFF"`
pub fn compact(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect()
}

/// Classic dump: offset, 16 bytes per line in hex, printable characters.
pub fn dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (n, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!("{:04X}  {:<47}  {}\n", n * 16, hex.join(" "), ascii));
    }
    out
}

/// Parse hex text. Whitespace, `:`, `-`, `,` and a leading `0x` are ignored.
pub fn parse(text: &str) -> Result<Vec<u8>, String> {
    let t = text.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let digits: Vec<char> = t.chars().filter(|c| !c.is_whitespace() && !matches!(c, ':' | '-' | ',')).collect();
    if let Some(bad) = digits.iter().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("'{bad}' is not a hex digit"));
    }
    if digits.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    Ok(digits
        .chunks(2)
        .map(|p| (p[0].to_digit(16).unwrap_or(0) * 16 + p[1].to_digit(16).unwrap_or(0)) as u8)
        .collect())
}
