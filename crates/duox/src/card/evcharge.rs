//! EV charging commands according to VDE-AR-E 2532-100 (7.19): VDE_ReadData, VDE_WriteData,
//! VDE lock and VDE_ECDSASign. Proprietary class 0x80, plain, only valid while not authenticated
//! and rejected in an application that holds a TransactionMAC file.

use super::secure_messaging::Le;
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

impl<T: Transport> Card<T> {
    pub fn vde_read_data(&mut self, file_no: u8) -> Result<Vec<u8>> {
        self.iso_checked("VDE_ReadData", 0x80, 0x02, file_no, 0x00, &[], Le::Short(0))
    }

    /// Write to file 01 of the VDE application.
    pub fn vde_write_data(&mut self, data: &[u8]) -> Result<()> {
        self.iso_checked("VDE_WriteData", 0x80, 0x01, 0x06, 0x00, data, Le::Short(0)).map(|_| ())
    }

    /// Lock the VDE file against further writing.
    pub fn vde_lock(&mut self) -> Result<()> {
        self.iso_checked("VDE_WriteData (lock)", 0x80, 0x01, 0x06, 0x01, &[], Le::Short(0)).map(|_| ())
    }

    /// ECDSA signature over a 32 byte challenge.
    pub fn vde_ecdsa_sign(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        if challenge.len() != 32 {
            return Err(Error::arg("the challenge must be 32 bytes"));
        }
        self.iso_checked("VDE_ECDSASign", 0x80, 0x03, 0x0C, 0x09, challenge, Le::Short(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn vde_wire_format() {
        let mut t = MockTransport::new();
        t.expect_hex("80 02 01 00 00", "AA 9000");
        t.expect_hex("80 01 06 00 02 0102 00", "9000");
        t.expect_hex("80 01 06 01 00", "9000");
        t.expect_hex(&format!("80 03 0C 09 20 {} 00", "11".repeat(32)), &format!("{}9000", "22".repeat(64)));
        t.expect_hex("80 02 01 00 00", "6A82");
        let mut card = Card::new(t);
        assert_eq!(card.vde_read_data(1).unwrap(), vec![0xAA]);
        card.vde_write_data(&[1, 2]).unwrap();
        card.vde_lock().unwrap();
        assert_eq!(card.vde_ecdsa_sign(&[0x11; 32]).unwrap().len(), 64);
        assert!(card.vde_ecdsa_sign(&[0; 31]).is_err());
        assert_eq!(card.vde_read_data(1).unwrap_err().iso_sw(), Some(0x6A82));
    }
}
