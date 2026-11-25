//! GPIO: configuration (SetConfiguration option 0x11), ManageGPIO and ReadGPIO.

use super::plan::{self, Access, GpioConfig};
use super::{comm_index, comm_mode, is_authenticated, report, token, Action, State, COMM_MODES};
use crate::shared::Shared;
use crate::ui::form::{FormSpec, FormValues};
use duox::card::{AccessRight, Aid, CommMode};

const GPIO_CONFIG_OPTION: u8 = 0x11;

fn hex_of(b: &[u8]) -> String {
    hex::encode_upper(b)
}

/// Settings are written at the PICC level with the PICC master key.
fn master_key_session(shared: &Shared) -> bool {
    shared.card.as_ref().is_some_and(|c| {
        c.selection().primary == Some(Aid::PICC) && c.has_access_condition(AccessRight::key(0), false)
    })
}

/// Commands in MAC or Full mode need a session.
fn session_missing(shared: &mut Shared, mode: CommMode, command: &str) -> bool {
    if mode != CommMode::Plain && !is_authenticated(shared) {
        shared.report_error(format!(
            "{command} in {mode} mode needs an authentication (Authenticate tab). Choose Plain only if the command \
             is configured for free access."
        ));
        return true;
    }
    false
}

impl State {
    pub(super) fn start_gpio(&mut self, a: Action, shared: &mut Shared) {
        match a {
            Action::GpioConfig => self.ask_gpio_config(shared),
            Action::GpioManage => {
                let l = &self.last;
                shared.ask(
                    FormSpec::new("ManageGPIO")
                        .note("Drives an output GPIO, controls the power out or the auto WTX. The communication mode is the one configured for ManageGPIO.")
                        .ok_text("Send")
                        .combo("gpio", "GPIO", &["GPIO1", "GPIO2"], l.gpio_no)
                        .combo("op", "Operation", &plan::GPIO_OPS, l.gpio_op)
                        .check("nfc", "Pause NFC (output operations, bit 7)", false)
                        .hex_int_range("level", "Power out level code", 0, 2, 0, 0x1F)
                        .hint("Only for 'Power out: custom'. 0 is the configured default.")
                        .check("measure", "Measure (custom power out)", false)
                        .check("enable", "Enable (custom power out)", true)
                        .hex_int_range("raw", "Raw operation byte (hex)", 0, 2, 0, 0xFF)
                        .hint("Only for 'Raw operation byte'.")
                        .hex_len("resp", "NFC pause response data (hex, optional)", "", 0, 239)
                        .combo("mode", "Communication mode", &COMM_MODES, l.comm_mode),
                    token::GPIO_MANAGE,
                );
            }
            Action::GpioRead => shared.ask(
                FormSpec::new("ReadGPIO")
                    .note("Reads the state of both GPIOs. The communication mode is the one configured for ReadGPIO.")
                    .ok_text("Read")
                    .combo("mode", "Communication mode", &COMM_MODES, self.last.comm_mode),
                token::GPIO_READ,
            ),
            _ => {}
        }
    }

    fn ask_gpio_config(&mut self, shared: &mut Shared) {
        if !master_key_session(shared) {
            shared.report_error(
                "The GPIO configuration is written with SetConfiguration at the PICC level. Select the PICC level \
                 and authenticate with the PICC master key on the Authenticate tab first.",
            );
            return;
        }
        let Ok(raw) = shared.with_card(|c| c.get_configuration(Some(GPIO_CONFIG_OPTION))) else { return };
        let cur = match GpioConfig::parse(&raw) {
            Ok(c) => c,
            Err(e) => {
                shared.report_error(e);
                return;
            }
        };
        let (m1, m1i) = plan::choices(plan::G1_MODES, cur.mode1);
        let (m2, m2i) = plan::choices(plan::G2_MODES, cur.mode2);
        let (n1, n1i) = plan::choices(plan::NOTIFICATIONS, cur.notify1);
        let (n2, n2i) = plan::choices(plan::NOTIFICATIONS, cur.notify2);
        fn r(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        let spec = FormSpec::new("GPIO configuration (SetConfiguration option 11)")
            .note(
                "Needs the PICC level and the PICC master key. Access conditions: 0 to D key or certificate right, \
                 E free, F never. See the data sheet (GPIO configuration table) for the pad control and power-out \
                 values.",
            )
            .ok_text("Write")
            .info("Shown values", "the configuration read from the card")
            .combo("m1", "GPIO1 mode", &r(&m1), m1i)
            .hex_len("c1", "GPIO1 config / pad control (5 bytes)", &hex_of(&cur.pad1), 5, 5)
            .combo("n1", "GPIO1 notification (output mode)", &r(&n1), n1i)
            .combo("m2", "GPIO2 mode", &r(&m2), m2i)
            .hex_len("c2", "GPIO2 config / pad control (5 bytes)", &hex_of(&cur.pad2), 5, 5)
            .combo("n2", "GPIO2 notification (output mode)", &r(&n2), n2i)
            .combo("mm", "ManageGPIO: communication mode", &COMM_MODES, comm_index(cur.manage.mode))
            .hex_int_range("ma", "ManageGPIO: access condition (PICC level)", cur.manage.condition.into(), 1, 0, 0xF)
            .combo("rm", "ReadGPIO: communication mode", &COMM_MODES, comm_index(cur.read.mode))
            .hex_int_range("ra", "ReadGPIO: access condition (PICC level)", cur.read.condition.into(), 1, 0, 0xF)
            .hex_int_range("aid", "Application with additional access (AID)", cur.extra_aid.into(), 6, 0, 0xFF_FFFF)
            .hint("000000 means none.")
            .hex_int_range("ama", "... ManageGPIO access condition there", cur.extra_manage_condition.into(), 1, 0, 0xF)
            .combo("arm", "... ReadGPIO communication mode there", &COMM_MODES, comm_index(cur.extra_read.mode))
            .hex_int_range("ara", "... ReadGPIO access condition there", cur.extra_read.condition.into(), 1, 0, 0xF)
            .hex_len(
                "pwr",
                "Power out (5 bytes)",
                &hex_of(&cur.power_out),
                5,
                5,
            )
            .hint("Default target, in-rush target, duration (2 bytes), extra current.")
            .hex_len("pause", "NFCPause (7 bytes)", &hex_of(&cur.nfc_pause), 7, 7)
            .hint("File number, offset (3 bytes), length (3 bytes).");
        shared.ask(spec, token::GPIO_CONFIG);
    }

    pub(super) fn gpio_done(&mut self, tok: u32, v: &FormValues, shared: &mut Shared) {
        match tok {
            token::GPIO_CONFIG => self.write_gpio_config(v, shared),
            token::GPIO_MANAGE => self.manage_gpio(v, shared),
            token::GPIO_READ => {
                let idx = v.get_index("mode").unwrap_or(1);
                self.last.comm_mode = idx;
                let mode = comm_mode(idx);
                if session_missing(shared, mode, "ReadGPIO") {
                    return;
                }
                if let Ok(d) = shared.with_card(|c| c.read_gpio_raw(mode)) {
                    self.show(report::gpio_read_report(&d));
                }
            }
            _ => {}
        }
    }

    fn manage_gpio(&mut self, v: &FormValues, shared: &mut Shared) {
        let gpio = v.get_index("gpio").unwrap_or(0);
        let choice = v.get_index("op").unwrap_or(1);
        let mode_idx = v.get_index("mode").unwrap_or(1);
        (self.last.gpio_no, self.last.gpio_op, self.last.comm_mode) = (gpio, choice, mode_idx);
        let op = plan::gpio_operation(
            choice,
            v.get_bool("nfc").unwrap_or(false),
            v.get_uint("level").unwrap_or(0) as u8,
            v.get_bool("measure").unwrap_or(false),
            v.get_bool("enable").unwrap_or(false),
            v.get_uint("raw").unwrap_or(0) as u8,
        );
        let byte = match op.byte() {
            Ok(b) => b,
            Err(e) => {
                shared.report_error(e.to_string());
                return;
            }
        };
        let resp = v.get_hex("resp").unwrap_or_default();
        let mode = comm_mode(mode_idx);
        if session_missing(shared, mode, "ManageGPIO") {
            return;
        }
        if let Ok(d) = shared.with_card(|c| c.manage_gpio(gpio as u8, op, &resp, mode)) {
            self.show(report::gpio_manage_report(["GPIO1", "GPIO2"][gpio.min(1)], byte, &d));
        }
    }

    fn write_gpio_config(&mut self, v: &FormValues, shared: &mut Shared) {
        if !master_key_session(shared) {
            shared.report_error(
                "The authentication with the PICC master key is gone. Authenticate again, then repeat the \
                 configuration.",
            );
            return;
        }
        let text = |k: &str| v.get_str(k).unwrap_or_default().to_string();
        let uint = |k: &str| v.get_uint(k).unwrap_or(0);
        let access = |m: &str, c: &str| Access { mode: comm_mode(v.get_index(m).unwrap_or(0)), condition: uint(c) as u8 };
        let fixed = |k: &str| v.get_hex(k).unwrap_or_default();
        let (Ok(pad1), Ok(pad2), Ok(power_out), Ok(nfc_pause)) = (
            <[u8; 5]>::try_from(fixed("c1")),
            <[u8; 5]>::try_from(fixed("c2")),
            <[u8; 5]>::try_from(fixed("pwr")),
            <[u8; 7]>::try_from(fixed("pause")),
        ) else {
            shared.report_error("The pad control and power-out fields are 5 bytes, the NFCPause field 7 bytes.");
            return;
        };
        let cfg = GpioConfig {
            mode1: plan::choice_value(&text("m1")),
            pad1,
            mode2: plan::choice_value(&text("m2")),
            pad2,
            notify1: plan::choice_value(&text("n1")),
            notify2: plan::choice_value(&text("n2")),
            manage: access("mm", "ma"),
            read: access("rm", "ra"),
            extra_aid: uint("aid") as u32,
            extra_manage_condition: uint("ama") as u8,
            extra_read: access("arm", "ara"),
            power_out,
            nfc_pause,
        };
        let bytes = cfg.encode();
        if shared.with_card(|c| c.set_configuration(GPIO_CONFIG_OPTION, &bytes)).is_ok() {
            let mut l = vec![format!("GPIO configuration written ({} bytes):", bytes.len()), crate::ui::hex::spaced(&bytes), String::new()];
            l.extend(cfg.describe());
            self.show(l.join("\n"));
        }
    }
}
