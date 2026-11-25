//! GPIO (7.16): ManageGPIO and ReadGPIO. Their CommMode is configured with SetConfiguration
//! (option 0x11); the caller passes the configured mode.

use super::types::*;
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Output level control of an output GPIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioControl {
    Clear = 0,
    Set = 1,
    Toggle = 2,
}

/// The Operation byte of ManageGPIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioOperation {
    /// GPIO configured as output; optionally pause (over NFC) / release the NFC pause (over I2C).
    Output { control: GpioControl, nfc_control: bool },
    /// GPIO configured for down-stream power out. `level` is the 5 bit voltage / current code
    /// (0 = configured default, 0x01..0x09 / 0x0F at 1.8 V, 0x11..0x19 / 0x1F at 2 V).
    PowerDownstream { level: u8, measure: bool, enable: bool },
    /// Auto WTX of the down-stream power mode.
    AutoWtx { enable: bool },
    /// Any other value.
    Raw(u8),
}

impl GpioOperation {
    pub fn byte(self) -> Result<u8> {
        Ok(match self {
            GpioOperation::Output { control, nfc_control } => (control as u8) | if nfc_control { 0x80 } else { 0 },
            GpioOperation::PowerDownstream { level, measure, enable } => {
                if level > 0x1F {
                    return Err(Error::arg("power level code is 0..=0x1F"));
                }
                (level << 2) | if measure { 0x02 } else { 0 } | if enable { 0x01 } else { 0 }
            }
            GpioOperation::AutoWtx { enable } => 0x80 | enable as u8,
            GpioOperation::Raw(b) => b,
        })
    }
}

/// State of one GPIO as reported by ReadGPIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioLevel {
    High,
    Low,
    /// Not configured as input / output.
    Invalid,
    Unknown(u8),
}

impl From<u8> for GpioLevel {
    fn from(b: u8) -> Self {
        match b {
            0x48 => GpioLevel::High,
            0x4C => GpioLevel::Low,
            0x49 => GpioLevel::Invalid,
            x => GpioLevel::Unknown(x),
        }
    }
}

/// ReadGPIO result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpioStatus {
    pub gpio1: GpioLevel,
    pub gpio2: GpioLevel,
}

impl<T: Transport> Card<T> {
    /// ManageGPIO. `gpio_no` 0 = GPIO1, 1 = GPIO2. `nfc_pause_resp` is the optional NFC pause
    /// response data (up to 239 bytes). Returns NFC pause response data or the measurement result.
    pub fn manage_gpio(&mut self, gpio_no: u8, op: GpioOperation, nfc_pause_resp: &[u8], mode: CommMode) -> Result<Vec<u8>> {
        if gpio_no > 1 {
            return Err(Error::arg("GPIO number is 0 (GPIO1) or 1 (GPIO2)"));
        }
        if nfc_pause_resp.len() > 239 {
            return Err(Error::arg("NFC pause response data is at most 239 bytes"));
        }
        let mut h = vec![gpio_no, op.byte()?];
        h.extend_from_slice(nfc_pause_resp);
        self.command(cmd::MANAGE_GPIO, &h, &[], mode)
    }

    /// ReadGPIO: raw status bytes (GPIOByte0 = 0x49, GPIOByte1, GPIOByte2).
    pub fn read_gpio_raw(&mut self, mode: CommMode) -> Result<Vec<u8>> {
        self.command(cmd::READ_GPIO, &[], &[], mode)
    }

    pub fn read_gpio(&mut self, mode: CommMode) -> Result<GpioStatus> {
        let d = self.read_gpio_raw(mode)?;
        if d.len() < 3 {
            self.drop_session();
            return Err(Error::protocol("ReadGPIO: response shorter than 3 bytes"));
        }
        Ok(GpioStatus { gpio1: d[1].into(), gpio2: d[2].into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn operation_bytes() {
        assert_eq!(GpioOperation::Output { control: GpioControl::Toggle, nfc_control: true }.byte().unwrap(), 0x82);
        assert_eq!(GpioOperation::PowerDownstream { level: 0x04, measure: true, enable: true }.byte().unwrap(), 0x13);
        assert_eq!(GpioOperation::AutoWtx { enable: true }.byte().unwrap(), 0x81);
        assert!(GpioOperation::PowerDownstream { level: 0x20, measure: false, enable: false }.byte().is_err());
    }

    #[test]
    fn gpio_wire_format() {
        let mut t = MockTransport::new();
        t.expect_hex("9042000002 01 01 00", "9100");
        t.expect_hex("9043000000", "49 48 4C 9100");
        let mut card = Card::new(t);
        card.manage_gpio(1, GpioOperation::Output { control: GpioControl::Set, nfc_control: false }, &[], CommMode::Mac).unwrap();
        let s = card.read_gpio(CommMode::Mac).unwrap();
        assert_eq!((s.gpio1, s.gpio2), (GpioLevel::High, GpioLevel::Low));
        assert!(card.manage_gpio(2, GpioOperation::Raw(0), &[], CommMode::Mac).is_err());
    }
}
