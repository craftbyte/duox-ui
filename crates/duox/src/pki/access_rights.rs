//! The NXP access-rights certificate extension (7.6.4, Tables 19-22) and access condition maps (Table 18).

use super::error::{CertError, PkiError, Result};
use std::fmt;

/// Bitmap of granted access conditions 0x0..=0xD (bit n = access condition n), LSB first on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AcMap(u16);

impl AcMap {
    pub const NONE: AcMap = AcMap(0);
    /// Access conditions 0..=D.
    pub const ALL: AcMap = AcMap(0x3FFF);
    /// Access condition 2 only: what delegated application management rights grant.
    pub const DAM: AcMap = AcMap(0x0004);

    /// Bits above access condition D are discarded.
    pub const fn new(bits: u16) -> AcMap {
        AcMap(bits & 0x3FFF)
    }
    pub const fn bits(self) -> u16 {
        self.0
    }
    pub const fn contains(self, access_condition: u8) -> bool {
        access_condition < 14 && self.0 >> access_condition & 1 == 1
    }
    /// True when every condition in `self` is also in `other`.
    pub const fn is_subset_of(self, other: AcMap) -> bool {
        self.0 & !other.0 == 0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Parse `0,5,A`, `0-3` or a hex bitmap like `0x3FFF`.
    pub fn parse(text: &str) -> Result<AcMap> {
        let text = text.trim();
        let bad = || PkiError::Invalid(format!("'{text}' is not a list of access conditions (0..D)"));
        if let Some(h) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            return Ok(AcMap::new(u16::from_str_radix(h, 16).map_err(|_| bad())? & 0x3FFF));
        }
        let mut m = 0u16;
        for part in text.replace(' ', "").split(',') {
            if part.is_empty() || part == "-" {
                continue;
            }
            let (lo, hi) = part.split_once('-').unwrap_or((part, part));
            let hi = if hi.is_empty() { lo } else { hi };
            let a = u8::from_str_radix(lo, 16).map_err(|_| bad())?;
            let b = u8::from_str_radix(hi, 16).map_err(|_| bad())?;
            if a > b || b > 0xD {
                return Err(PkiError::Invalid("access conditions are 0..D".into()));
            }
            for i in a..=b {
                m |= 1 << i;
            }
        }
        Ok(AcMap(m))
    }
}

impl fmt::Display for AcMap {
    /// `0,5,A` style list, `-` when empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("-");
        }
        let list: Vec<String> = (0..14u8).filter(|&i| self.contains(i)).map(|i| format!("{i:X}")).collect();
        f.write_str(&list.join(","))
    }
}
impl fmt::Debug for AcMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AcMap({:04X})", self.0)
    }
}
impl From<u16> for AcMap {
    fn from(v: u16) -> Self {
        AcMap::new(v)
    }
}

/// DAMOperation of Table 22.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DamOperation {
    Create = 0,
    Delete = 1,
}

/// Delegated application management rights (ARType 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamRights {
    /// Restricts the rights to one card: empty, 7 or 10 bytes.
    pub uid: Vec<u8>,
    pub operation: DamOperation,
    /// CreateDelegatedApplication parameters (10..=33 bytes) or, for deletion, the AID (3 bytes).
    pub payload: Vec<u8>,
}

/// What the extension grants, by ARType.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RightsScope {
    /// ARType 1: application selected by AID, optionally with a secondary application.
    Aid { aid: u32, acmap: AcMap, secondary: Option<(u32, AcMap)> },
    /// ARType 2: application selected by DF name (1..=16 bytes).
    DfName { name: Vec<u8>, acmap: AcMap },
    /// ARType 3.
    DelegatedManagement(DamRights),
}

/// Decoded ARExtensionValue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRights {
    /// Bit 7 of ARType: the certificate may act as parent (intermediate CA).
    pub delegation: bool,
    pub scope: RightsScope,
}

impl AccessRights {
    /// Rights for the application with this AID.
    pub fn for_aid(aid: u32, acmap: AcMap) -> Self {
        AccessRights { delegation: false, scope: RightsScope::Aid { aid, acmap, secondary: None } }
    }
    /// Rights for the application with this DF name.
    pub fn for_df_name(name: &[u8], acmap: AcMap) -> Self {
        AccessRights { delegation: false, scope: RightsScope::DfName { name: name.to_vec(), acmap } }
    }
    /// Delegated application management rights.
    pub fn for_dam(uid: &[u8], operation: DamOperation, payload: &[u8]) -> Self {
        AccessRights {
            delegation: false,
            scope: RightsScope::DelegatedManagement(DamRights { uid: uid.to_vec(), operation, payload: payload.to_vec() }),
        }
    }
    /// Same rights with the CA delegation bit set.
    pub fn delegating(mut self) -> Self {
        self.delegation = true;
        self
    }
    /// Add the secondary application (ARType 1 only).
    pub fn with_secondary(mut self, aid2: u32, acmap2: AcMap) -> Self {
        if let RightsScope::Aid { secondary, .. } = &mut self.scope {
            *secondary = Some((aid2, acmap2));
        }
        self
    }

    /// ARType without the delegation bit.
    pub fn ar_type(&self) -> u8 {
        match self.scope {
            RightsScope::Aid { .. } => 1,
            RightsScope::DfName { .. } => 2,
            RightsScope::DelegatedManagement(_) => 3,
        }
    }

    /// Access conditions of the primary application this extension grants. Delegated application management
    /// grants access condition 2.
    pub fn acmap(&self) -> AcMap {
        match &self.scope {
            RightsScope::Aid { acmap, .. } | RightsScope::DfName { acmap, .. } => *acmap,
            RightsScope::DelegatedManagement(_) => AcMap::DAM,
        }
    }

    pub fn acmap2(&self) -> Option<AcMap> {
        match &self.scope {
            RightsScope::Aid { secondary, .. } => secondary.map(|s| s.1),
            _ => None,
        }
    }

    /// ARExtensionValue (the content of the extension's OCTET STRING).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let t = self.ar_type() | if self.delegation { 0x80 } else { 0 };
        let aid3 = |aid: u32| -> Result<[u8; 3]> {
            if aid > 0xFF_FFFF {
                return Err(PkiError::Invalid(format!("AID {aid:#X} does not fit 3 bytes")));
            }
            Ok([aid as u8, (aid >> 8) as u8, (aid >> 16) as u8])
        };
        let mut v = vec![t];
        match &self.scope {
            RightsScope::Aid { aid, acmap, secondary } => {
                v.extend(aid3(*aid)?);
                v.extend(acmap.bits().to_le_bytes());
                if let Some((aid2, acmap2)) = secondary {
                    v.extend(aid3(*aid2)?);
                    v.extend(acmap2.bits().to_le_bytes());
                }
            }
            RightsScope::DfName { name, acmap } => {
                if !(1..=16).contains(&name.len()) {
                    return Err(PkiError::Invalid("DF name must be 1..16 bytes".into()));
                }
                v.push(name.len() as u8);
                v.extend(name);
                v.extend(acmap.bits().to_le_bytes());
            }
            RightsScope::DelegatedManagement(d) => {
                if ![0, 7, 10].contains(&d.uid.len()) {
                    return Err(PkiError::Invalid("UID must be empty, 7 or 10 bytes".into()));
                }
                check_dam_payload(d.operation, d.payload.len()).map_err(|e| PkiError::Invalid(e.message))?;
                v.push(d.uid.len() as u8);
                v.extend(&d.uid);
                v.push(d.operation as u8);
                v.push(d.payload.len() as u8);
                v.extend(&d.payload);
            }
        }
        Ok(v)
    }

    /// Parse and validate an ARExtensionValue (rules 4b, 4c of 7.10.2.2).
    pub fn decode(v: &[u8]) -> std::result::Result<AccessRights, CertError> {
        let bad = |m: &str| CertError::wrong_data(m);
        let Some(&t) = v.first() else { return Err(bad("empty ARExtension value")) };
        let delegation = t & 0x80 != 0;
        let le16 = |b: &[u8]| AcMap::new(u16::from_le_bytes([b[0], b[1]]));
        let le24 = |b: &[u8]| u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16;
        let scope = match t & 0x7F {
            1 => {
                if v.len() != 6 && v.len() != 11 {
                    return Err(bad("ARExtension (AID) has wrong length"));
                }
                let secondary = (v.len() == 11).then(|| (le24(&v[6..9]), le16(&v[9..11])));
                RightsScope::Aid { aid: le24(&v[1..4]), acmap: le16(&v[4..6]), secondary }
            }
            2 => {
                let n = *v.get(1).ok_or_else(|| bad("ARExtension value truncated"))? as usize;
                if !(1..=16).contains(&n) || v.len() != 4 + n {
                    return Err(bad("ARExtension (DFName) has wrong length"));
                }
                RightsScope::DfName { name: v[2..2 + n].to_vec(), acmap: le16(&v[2 + n..4 + n]) }
            }
            3 => {
                let n = *v.get(1).ok_or_else(|| bad("ARExtension value truncated"))? as usize;
                if ![0, 7, 10].contains(&n) {
                    return Err(bad("ARExtension (DAM) has invalid UIDLen"));
                }
                if v.len() < 4 + n {
                    return Err(bad("ARExtension value truncated"));
                }
                let operation = match v[2 + n] {
                    0 => DamOperation::Create,
                    1 => DamOperation::Delete,
                    other => return Err(bad(&format!("ARExtension (DAM) has unknown operation 0x{other:02X}"))),
                };
                let payload = &v[4 + n..];
                if payload.len() != v[3 + n] as usize {
                    return Err(bad("ARExtension (DAM) has wrong payload length"));
                }
                check_dam_payload(operation, payload.len())?;
                RightsScope::DelegatedManagement(DamRights {
                    uid: v[2..2 + n].to_vec(),
                    operation,
                    payload: payload.to_vec(),
                })
            }
            other => return Err(bad(&format!("unknown ARType 0x{other:02X}"))),
        };
        Ok(AccessRights { delegation, scope })
    }

    /// One line, for logs and the certificate description.
    pub fn describe(&self) -> String {
        let d = if self.delegation { " +CA delegation" } else { "" };
        match &self.scope {
            RightsScope::Aid { aid, acmap, secondary } => {
                let mut s = format!("AID {aid:06X} ACMap {:04X} [{acmap}]", acmap.bits());
                if let Some((aid2, acmap2)) = secondary {
                    s.push_str(&format!("; AID2 {aid2:06X} ACMap2 {:04X}", acmap2.bits()));
                }
                s + d
            }
            RightsScope::DfName { name, acmap } => {
                format!("DFName {} ACMap {:04X} [{acmap}]{d}", hex::encode_upper(name), acmap.bits())
            }
            RightsScope::DelegatedManagement(m) => {
                let op = if m.operation == DamOperation::Delete { "delete" } else { "create" };
                let uid = if m.uid.is_empty() { String::new() } else { format!(" UID {}", hex::encode_upper(&m.uid)) };
                format!("DAM {op} payload {}{uid}{d}", hex::encode_upper(&m.payload))
            }
        }
    }
}

fn check_dam_payload(op: DamOperation, len: usize) -> std::result::Result<(), CertError> {
    let ok = match op {
        DamOperation::Create => (0x0A..=0x21).contains(&len),
        DamOperation::Delete => len == 3,
    };
    if ok {
        Ok(())
    } else {
        Err(CertError::wrong_data("ARExtension (DAM) payload length does not fit the operation"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acmap_text_and_parse() {
        let m = AcMap::parse("0,5,A").unwrap();
        assert_eq!(m.bits(), 0x0421);
        assert_eq!(m.to_string(), "0,5,A");
        assert_eq!(AcMap::parse("0-3").unwrap().bits(), 0x000F);
        assert_eq!(AcMap::parse("0xFFFF").unwrap(), AcMap::ALL);
        assert_eq!(AcMap::parse("-").unwrap(), AcMap::NONE);
        assert_eq!(AcMap::NONE.to_string(), "-");
        assert!(AcMap::parse("E").is_err());
        assert!(AcMap::parse("zz").is_err());
        assert!(AcMap::new(0x0003).is_subset_of(AcMap::new(0x0023)));
        assert!(!AcMap::new(0x0040).is_subset_of(AcMap::new(0x0023)));
    }

    #[test]
    fn aid_encoding() {
        let ar = AccessRights::for_aid(0x123456, AcMap::new(0x0023)).delegating();
        let v = ar.encode().unwrap();
        assert_eq!(v, [0x81, 0x56, 0x34, 0x12, 0x23, 0x00]);
        assert_eq!(AccessRights::decode(&v).unwrap(), ar);
        let two = AccessRights::for_aid(1, AcMap::new(3)).with_secondary(0xABCDEF, AcMap::new(4));
        let v = two.encode().unwrap();
        assert_eq!(v.len(), 11);
        assert_eq!(AccessRights::decode(&v).unwrap(), two);
        assert_eq!(two.acmap2(), Some(AcMap::new(4)));
        assert!(AccessRights::decode(&v[..7]).is_err());
        assert!(AccessRights::for_aid(0x1_000000, AcMap::NONE).encode().is_err());
    }

    #[test]
    fn df_name_encoding() {
        let ar = AccessRights::for_df_name(b"DUOX", AcMap::new(1));
        let v = ar.encode().unwrap();
        assert_eq!(v, [0x02, 4, b'D', b'U', b'O', b'X', 1, 0]);
        assert_eq!(AccessRights::decode(&v).unwrap(), ar);
        assert!(AccessRights::for_df_name(&[], AcMap::NONE).encode().is_err());
        assert!(AccessRights::for_df_name(&[0; 17], AcMap::NONE).encode().is_err());
        assert!(AccessRights::decode(&[2, 4, 1, 2]).is_err());
    }

    #[test]
    fn dam_encoding() {
        let create = AccessRights::for_dam(&[], DamOperation::Create, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let v = create.encode().unwrap();
        assert_eq!(v[..4], [3, 0, 0, 10]);
        let back = AccessRights::decode(&v).unwrap();
        assert_eq!(back, create);
        assert_eq!(back.acmap(), AcMap::DAM);
        let del = AccessRights::for_dam(&[7; 7], DamOperation::Delete, &[1, 2, 3]).delegating();
        assert_eq!(AccessRights::decode(&del.encode().unwrap()).unwrap(), del);
        assert!(AccessRights::for_dam(&[7; 5], DamOperation::Delete, &[1, 2, 3]).encode().is_err());
        assert!(AccessRights::for_dam(&[], DamOperation::Delete, &[1, 2]).encode().is_err());
        assert!(AccessRights::decode(&[3, 0, 9, 0]).is_err());
        assert!(AccessRights::decode(&[4, 0, 0]).is_err());
        assert!(AccessRights::decode(&[]).is_err());
        assert!(create.describe().starts_with("DAM create payload 0102"));
    }
}
