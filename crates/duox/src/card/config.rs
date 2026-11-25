//! Card level commands: GetVersion, GetCardUID, FreeMem, Format, SetConfiguration,
//! GetConfiguration (7.4, 7.6).

use super::types::*;
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Storage size code as used in the version information: `2^(code>>1)` bytes, `+` if the low bit is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageSize(pub u8);

impl StorageSize {
    pub fn bytes(self) -> u64 {
        1u64 << (self.0 >> 1)
    }
    /// The actual size is somewhere between this and the next power of two.
    pub fn is_lower_bound(self) -> bool {
        self.0 & 1 != 0
    }
}

impl std::fmt::Display for StorageSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bytes{}", self.bytes(), if self.is_lower_bound() { "+" } else { "" })
    }
}

/// GetVersion result (three frames: hardware, software, production data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub vendor: u8,
    pub hw_type: u8,
    pub hw_subtype: u8,
    pub hw_version: (u8, u8),
    pub hw_storage: StorageSize,
    pub hw_protocol: u8,
    pub sw_type: u8,
    pub sw_subtype: u8,
    pub sw_version: (u8, u8),
    pub sw_storage: StorageSize,
    pub sw_protocol: u8,
    pub uid: Vec<u8>,
    pub batch: Vec<u8>,
    pub type_id: Vec<u8>,
    /// Production calendar week (BCD) and year (BCD, 20xx), if the card reports them.
    pub production: Option<(u8, u8)>,
    /// All response bytes concatenated.
    pub raw: Vec<u8>,
}

impl VersionInfo {
    pub fn parse(frames: &[Vec<u8>]) -> Result<VersionInfo> {
        let bad = || Error::protocol("GetVersion: unexpected response");
        if frames.len() != 3 || frames[0].len() < 7 || frames[1].len() < 7 {
            return Err(bad());
        }
        let (hw, sw, p) = (&frames[0], &frames[1], &frames[2]);
        // UID:7 | BatchNo:3 | TypeID:2 | CW | Year [| FabID]  or  UIDFormat | UIDLength | UID | ...
        let (uid, tail): (&[u8], &[u8]) = if p.len() == 14 || p.len() == 15 {
            (&p[..7], &p[7..])
        } else {
            let n = *p.get(1).ok_or_else(bad)? as usize;
            (p.get(2..2 + n).ok_or_else(bad)?, &p[2 + n..])
        };
        Ok(VersionInfo {
            vendor: hw[0],
            hw_type: hw[1],
            hw_subtype: hw[2],
            hw_version: (hw[3], hw[4]),
            hw_storage: StorageSize(hw[5]),
            hw_protocol: hw[6],
            sw_type: sw[1],
            sw_subtype: sw[2],
            sw_version: (sw[3], sw[4]),
            sw_storage: StorageSize(sw[5]),
            sw_protocol: sw[6],
            uid: uid.to_vec(),
            batch: tail.get(..3).unwrap_or(&[]).to_vec(),
            type_id: tail.get(3..5).unwrap_or(&[]).to_vec(),
            production: if tail.len() >= 7 { Some((tail[5], tail[6])) } else { None },
            raw: frames.concat(),
        })
    }
}

impl<T: Transport> Card<T> {
    pub fn get_version(&mut self) -> Result<VersionInfo> {
        let r = self.run(cmd::GET_VERSION, &[], &[], CommMode::Mac, &[0x00])?;
        match VersionInfo::parse(&r.frames) {
            Ok(v) => {
                self.uid = v.uid.clone();
                Ok(v)
            }
            Err(e) => {
                self.drop_session();
                Err(e)
            }
        }
    }

    /// GetCardUID (Full). Returns the real UID, also with random-ID enabled.
    pub fn get_card_uid(&mut self) -> Result<Vec<u8>> {
        let mut d = self.command(cmd::GET_CARD_UID, &[], &[], CommMode::Full)?;
        if d.len() > 2 && d[1] as usize == d.len() - 2 {
            d.drain(..2);
        }
        self.uid = d.clone();
        Ok(d)
    }

    /// Free NV memory in bytes.
    pub fn free_mem(&mut self) -> Result<u32> {
        Ok(le_u32(&self.command(cmd::FREE_MEM, &[], &[], CommMode::Mac)?))
    }

    /// Format: deletes all applications and files.
    pub fn format(&mut self) -> Result<()> {
        self.command(cmd::FORMAT, &[], &[], CommMode::Mac).map(|_| ())
    }

    pub fn set_configuration(&mut self, option: u8, data: &[u8]) -> Result<()> {
        self.command(cmd::SET_CONFIGURATION, &[option], data, CommMode::Full).map(|_| ())
    }

    pub fn get_configuration(&mut self, option: Option<u8>) -> Result<Vec<u8>> {
        let h: Vec<u8> = option.into_iter().collect();
        self.command(cmd::GET_CONFIGURATION, &h, &[], CommMode::Full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn version_frames() {
        let mut t = MockTransport::new();
        t.expect_hex("9060000000", "04 01 02 01 00 1B 05 91AF".replace(' ', "").as_str());
        t.expect_hex("90AF000000", "04 01 02 01 00 1B 05 91AF".replace(' ', "").as_str());
        t.expect_hex("90AF000000", "04112233445566 AABBCC 0102 2B 24 9100".replace(' ', "").as_str());
        let mut card = Card::new(t);
        let v = card.get_version().unwrap();
        assert_eq!(v.uid, hex::decode("04112233445566").unwrap());
        assert_eq!(v.batch, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(v.hw_storage.bytes(), 1 << 13);
        assert!(v.hw_storage.is_lower_bound());
        assert_eq!(v.production, Some((0x2B, 0x24)));
        assert_eq!(card.uid(), &v.uid[..]);
    }

    #[test]
    fn uid_and_config_commands() {
        let mut t = MockTransport::new();
        t.expect_hex("906E000000", "00 10 00 9100".replace(' ', "").as_str());
        t.expect_hex("90FC000000", "9100");
        t.expect_hex("9065000001 11 00", "AABB 9100".replace(' ', "").as_str());
        let mut card = Card::new(t);
        assert_eq!(card.free_mem().unwrap(), 0x1000);
        card.format().unwrap();
        assert_eq!(card.get_configuration(Some(0x11)).unwrap(), vec![0xAA, 0xBB]);
    }
}
