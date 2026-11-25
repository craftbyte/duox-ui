//! Section `proximity_gpio`: proximity check (7.18) and GPIO (7.16).
//!
//! Proximity check: PreparePC / ProximityCheck / VerifyPC run inside a throwaway application that
//! overrides the VCProximityKey (KeySett3 bit 1, key 0x21; it starts with the PICCAppDefaultKey value,
//! the all-zero key). The PICC level VCProximityKey is disabled at delivery and is only probed (the
//! command is refused), never written.
//!
//! GPIO: GetConfiguration 0x11 and ReadGPIO are read only. ManageGPIO is only sent where the data sheet
//! says it is refused and where it can not drive a pin. SetConfiguration 0x11 is written only with
//! DUOX_SUITE_ALLOW_GPIO=1, after the 33 bytes read first are registered for restore, and the restore is
//! verified byte for byte.

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use duox::card::{Aid, AppSpec, ChangeKeySpec, CommMode, GpioControl, GpioLevel, GpioOperation, Status};

pub const NAME: &str = "proximity_gpio";
pub const DESCRIPTION: &str =
    "Proximity check with the application VCProximityKey; GPIO: GetConfiguration 0x11 / ReadGPIO, SetConfiguration 0x11 only with DUOX_SUITE_ALLOW_GPIO=1.";

pub fn run(ctx: &mut Ctx) {
    proximity(ctx);
    gpio_read_only(ctx);
    gpio_write(ctx);
}

// ------------------------------------------------------------------ proximity check
fn proximity(ctx: &mut Ctx) {
    ctx.step("proximity check: arguments are validated before anything is sent", |c| {
        c.select_application(Aid::PICC, None)?;
        let k = [0u8; 16];
        for split in [&[4u8, 3][..], &[0, 8], &[9], &[]] {
            match c.proximity_check(Some(&k), split) {
                Err(duox::Error::InvalidArgument(_)) => {}
                other => return Err(StepError::fail(format!("split {split:?}: expected an argument error, got {other:?}"))),
            }
        }
        match c.proximity_check(None, &[8]) {
            Err(duox::Error::InvalidArgument(_)) => Ok(()),
            other => Err(StepError::fail(format!("no key, not authenticated: expected an argument error, got {other:?}"))),
        }
    });

    ctx.step("proximity check at PICC level: the PICC VCProximityKey is disabled at delivery, PreparePC is refused", |c| {
        c.select_application(Aid::PICC, None)?;
        let z = c.zero_key;
        match c.proximity_check(Some(&z), &[8]) {
            Err(e) => {
                c.detail(format!("refused: {e}"));
                ensure(!c.is_authenticated(), "no session may exist")
            }
            Ok(r) => Err(StepError::skip(format!(
                "the PICC level VCProximityKey is enabled on this card (check ok={}); only the application key is exercised",
                r.ok
            ))),
        }
    });

    // an application without the key override
    let plain = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(plain).keys(1), |ctx, aid| {
        ctx.step("proximity check in an application without a VCProximityKey override, not authenticated: refused like at PICC level", |c| {
            c.select_application(aid, None)?;
            let z = c.zero_key;
            match c.proximity_check(Some(&z), &[8]) {
                Err(e) => {
                    c.detail(format!("refused: {e}"));
                    Ok(())
                }
                Ok(r) => Err(StepError::skip(format!("accepted with the PICC level key (ok={}): the PICC key is enabled", r.ok))),
            }
        });
        ctx.step("proximity check in an application without override, authenticated: uses the session MAC key", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let r = c.proximity_check(None, &[8])?;
            ensure(r.ok && r.authenticated_key, format!("{r:?}"))?;
            c.get_key_settings()?; // the session is still in step: the check does not count in CmdCtr
            Ok(())
        });
    });

    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1).key_sett3(0x02), |ctx, aid| {
        let z = ctx.zero_key;
        ctx.step("proximity check, application VCProximityKey (default value), not authenticated: single ProximityCheck, MAC verifies", |c| {
            c.select_application(aid, None)?;
            let r = c.proximity_check(Some(&z), &[8])?;
            c.detail(format!(
                "option {:02X}, announced response time {} us, PPS1 {:?}, measured {:?} us",
                r.option, r.announced_resp_time_us, r.pps1, r.round_trip_us
            ));
            ensure_eq((r.ok, r.authenticated_key, r.round_trip_us.len()), (true, false, 1), "result")?;
            ensure(!c.is_authenticated(), "the check must not create a session")
        });
        ctx.step("proximity check: challenge split into 3+5 and into eight single bytes", |c| {
            c.select_application(aid, None)?;
            let r = c.proximity_check(Some(&z), &[3, 5])?;
            ensure_eq((r.ok, r.round_trip_us.len()), (true, 2), "3+5")?;
            let r = c.proximity_check(Some(&z), &[1; 8])?;
            ensure_eq((r.ok, r.round_trip_us.len()), (true, 8), "eight times one byte")
        });
        ctx.step("proximity check with a wrong VCProximityKey: the card's MAC does not verify (ok = false)", |c| {
            c.select_application(aid, None)?;
            let r = c.proximity_check(Some(&[0x55; 16]), &[8])?;
            ensure_eq(r.ok, false, "result with the wrong key")
        });
        ctx.step("proximity check authenticated: uses the session MAC key, the session survives", |c| {
            c.auth_app(aid, 0, &z)?;
            let before = c.auth_summary().ok_or("no session")?.cmd_ctr;
            let r = c.proximity_check(None, &[8])?;
            ensure_eq((r.ok, r.authenticated_key), (true, true), "result")?;
            ensure_eq(c.auth_summary().ok_or("no session")?.cmd_ctr, before, "CmdCtr (proximity commands do not count)")?;
            c.get_key_settings()?;
            Ok(())
        });
        ctx.step("proximity check: ChangeKey of the application VCProximityKey (0x21) from the application master key", |c| {
            let new: [u8; 16] = rand::random();
            c.auth_app(aid, 0, &z)?;
            c.change_key(&ChangeKeySpec::new(0xA1, &new, 0x44).old_key(&z))?;
            c.select_application(aid, None)?;
            let r = c.proximity_check(Some(&new), &[8])?;
            ensure_eq(r.ok, true, "check with the new key")?;
            c.select_application(aid, None)?;
            let r = c.proximity_check(Some(&z), &[8])?;
            ensure_eq(r.ok, false, "check with the old key")?;
            c.auth_app(aid, 0, &z)?;
            match c.get_key_version(0x21, None) {
                Ok(v) => ensure_eq(v, vec![0x44], "version of the VCProximityKey after the change")?,
                Err(e) => c.detail(format!("GetKeyVersion 0x21 not answered ({e}); version not checked")),
            }
            Ok(())
        });
    });
    ctx.skip(
        "proximity check with an AES-256 VCProximityKey",
        "an AES-256 application needs a 32-byte PICCAppDefaultKey at PICC level; PICC state is not changed here",
    );
    ctx.skip(
        "proximity check with the PICC level VCProximityKey (0x21)",
        "the key is disabled at delivery and is enabled for good by writing it (needs the VCConfigurationKey 0x20); the suite does not enable it",
    );
}

// ------------------------------------------------------------------ GPIO helpers
/// The fields of GetConfiguration 0x11 the suite uses (offsets of the 33 byte block).
#[derive(Debug, Clone, PartialEq, Eq)]
struct GpioCfg {
    mode1: u8,
    mode2: u8,
    manage_ac: u8,
    read_ac: u8,
    aid: Aid,
}

fn parse_gpio(d: &[u8]) -> Result<GpioCfg, String> {
    if d.len() != 33 {
        return Err(format!("option 0x11 holds {} bytes, expected 33", d.len()));
    }
    Ok(GpioCfg { mode1: d[0], mode2: d[6], manage_ac: d[14], read_ac: d[15], aid: Aid::from_bytes(&d[16..19]) })
}

/// Does the status byte of this pin carry H / L (input, output, power out; GPIO2 also output with NFCPause)?
fn pin_reports(mode: u8, second: bool) -> bool {
    matches!((second, mode), (false, 1 | 2 | 4) | (true, 1 | 2 | 5))
}

/// Check the three ReadGPIO bytes against the configuration (Table 47 / 316).
fn check_gpio_bytes(raw: &[u8], cfg: &GpioCfg) -> Result<(), String> {
    if raw.len() != 3 {
        return Err(format!("ReadGPIO returned {} bytes", raw.len()));
    }
    if raw[0] != 0x49 {
        return Err(format!("GPIOByte0 is {:02X}, expected 49", raw[0]));
    }
    for (i, (b, rep)) in [(raw[1], pin_reports(cfg.mode1, false)), (raw[2], pin_reports(cfg.mode2, true))].into_iter().enumerate() {
        let ok = if rep { b == 0x48 || b == 0x4C } else { b == 0x49 };
        if !ok {
            return Err(format!("GPIO{} byte {b:02X} does not fit mode {}", i + 1, if i == 0 { cfg.mode1 } else { cfg.mode2 }));
        }
    }
    Ok(())
}

/// The block with the access conditions replaced (everything else byte for byte as read).
fn with_access(orig: &[u8], manage: Option<u8>, read: u8) -> Vec<u8> {
    let mut v = orig.to_vec();
    if let Some(m) = manage {
        v[14] = m;
    }
    v[15] = read;
    v
}

fn access_mode(ac: u8) -> CommMode {
    CommMode::from_bits(ac >> 4)
}

fn level_name(l: GpioLevel) -> String {
    format!("{l:?}")
}

fn read_cfg(c: &mut Ctx) -> StepResult<Vec<u8>> {
    c.ensure_picc()?;
    let d = c.get_configuration(Some(0x11))?;
    ensure_eq(d.len(), 33, "length of GetConfiguration 0x11")?;
    Ok(d)
}

// ------------------------------------------------------------------ GPIO read only
fn gpio_read_only(ctx: &mut Ctx) {
    let cfg = ctx.step("GetConfiguration 0x11 (GPIO) at PICC level: 33 bytes, decoded", |c| {
        let d = read_cfg(c)?;
        let g = parse_gpio(&d).map_err(StepError::Fail)?;
        c.detail(format!(
            "GPIO1Mode {:02X}, GPIO2Mode {:02X}, ManageGPIO AC {:02X}, ReadGPIO AC {:02X}, AID {}",
            g.mode1, g.mode2, g.manage_ac, g.read_ac, g.aid
        ));
        Ok(g)
    });
    let Some(g) = cfg else {
        ctx.skip("ReadGPIO", "the GPIO configuration could not be read");
        return;
    };

    ctx.step("ReadGPIO at PICC level follows ReadGPIOAccessCondition (refused when 0xF, otherwise statuses fit the configuration)", |c| {
        c.ensure_picc()?;
        let cond = g.read_ac & 0x0F;
        if cond == 0x0F {
            let r = c.read_gpio(CommMode::Mac);
            return c.expect_err(Status::PermissionDenied, r);
        }
        if cond != 0 {
            return Err(StepError::skip(format!("ReadGPIO access condition is {cond:X} (not the PICC master key); not exercised")));
        }
        let mode = access_mode(g.read_ac);
        let raw = c.read_gpio_raw(mode)?;
        c.detail(format!("raw {} (mode {mode})", hex::encode_upper(&raw)));
        check_gpio_bytes(&raw, &g).map_err(StepError::Fail)?;
        c.ensure_picc()?;
        let s = c.read_gpio(mode)?;
        c.detail(format!("GPIO1 {}, GPIO2 {}", level_name(s.gpio1), level_name(s.gpio2)));
        Ok(())
    });

    let aid = ctx.alloc_aid();
    ctx.app_scope(AppSpec::new(aid).keys(1), |ctx, aid| {
        ctx.step("ReadGPIO inside an application that is not the delegated AID: PERMISSION_DENIED", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let r = c.read_gpio(CommMode::Mac);
            c.expect_err(Status::PermissionDenied, r)
        });
        ctx.step("ManageGPIO inside an application that is not the delegated AID: PERMISSION_DENIED (no pin is driven)", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let r = c.manage_gpio(0, GpioOperation::Output { control: GpioControl::Clear, nfc_control: false }, &[], CommMode::Mac);
            c.expect_err(Status::PermissionDenied, r)
        });
    });

    if g.manage_ac & 0x0F == 0x0F {
        ctx.step("ManageGPIO at PICC level with ManageGPIOAccessCondition 0xF: PERMISSION_DENIED (no pin is driven)", |c| {
            c.ensure_picc()?;
            let r = c.manage_gpio(0, GpioOperation::Output { control: GpioControl::Clear, nfc_control: false }, &[], CommMode::Mac);
            c.expect_err(Status::PermissionDenied, r)
        });
    } else {
        ctx.skip(
            "ManageGPIO at PICC level",
            "ManageGPIOAccessCondition is configured on this card: a ManageGPIO command could drive a real pin, so it is not sent",
        );
    }
}

// ------------------------------------------------------------------ GPIO configuration (ALLOW_GPIO only)
fn gpio_write(ctx: &mut Ctx) {
    const NEED: &str = "DUOX_SUITE_ALLOW_GPIO=1 is not set: SetConfiguration 0x11 is never sent by default";
    if !ctx.cfg.allow_gpio {
        ctx.skip("SetConfiguration 0x11: change the GPIO access conditions, read back, ReadGPIO with the new mode", NEED);
        ctx.skip("SetConfiguration 0x11: restore the original 33 bytes and verify", NEED);
        ctx.skip("ManageGPIO on disabled pins with ManageGPIOAccessCondition granted: PERMISSION_DENIED", NEED);
        return;
    }
    let Some(orig) = ctx.step("GPIO write tier: read the 33 byte configuration to restore", read_cfg) else { return };
    let o = match parse_gpio(&orig) {
        Ok(o) => o,
        Err(e) => {
            ctx.skip("SetConfiguration 0x11", &e);
            return;
        }
    };
    let both_disabled = o.mode1 == 0 && o.mode2 == 0;
    // registered BEFORE anything is written; "already restored" is fine
    let restore = orig.clone();
    let cid = ctx.push_cleanup("restore SetConfiguration 0x11 (GPIO) to the value read first", move |c| {
        c.auth_picc()?;
        if c.get_configuration(Some(0x11))? != restore {
            c.auth_picc()?;
            c.set_configuration(0x11, &restore)?;
            c.auth_picc()?;
            ensure_eq(c.get_configuration(Some(0x11))?, restore.clone(), "GPIO configuration after the restore")?;
        }
        Ok(())
    });
    // new read condition: Full + key 0, or MAC + key 0 if that is what is configured already
    let new_read = if o.read_ac == 0x30 { 0x10 } else { 0x30 };
    let new_manage = if both_disabled { Some(0x30) } else { None };
    let new = with_access(&orig, new_manage, new_read);
    let changed = ctx.step_picc(
        "SetConfiguration 0x11: set ReadGPIO (and, with both pins disabled, ManageGPIO) access conditions; read back",
        |c| {
            c.set_configuration(0x11, &new)?;
            c.auth_picc()?;
            let back = c.get_configuration(Some(0x11))?;
            ensure_eq(hex::encode_upper(&back), hex::encode_upper(&new), "GPIO configuration read back")
        },
    );
    if changed.is_some() {
        ctx.step_picc("ReadGPIO with the new access condition: three status bytes that fit the (unchanged) pin modes", |c| {
            let mode = access_mode(new_read);
            let raw = c.read_gpio_raw(mode)?;
            c.detail(format!("raw {} (mode {mode})", hex::encode_upper(&raw)));
            check_gpio_bytes(&raw, &o).map_err(StepError::Fail)
        });
        if both_disabled {
            ctx.step_picc("ManageGPIO on a disabled pin with the access condition granted: PERMISSION_DENIED (pin not configured)", |c| {
                let r = c.manage_gpio(0, GpioOperation::Output { control: GpioControl::Clear, nfc_control: false }, &[], access_mode(0x30));
                c.expect_err(Status::PermissionDenied, r)
            });
        } else {
            ctx.skip(
                "ManageGPIO with the access condition granted",
                "a GPIO is configured on this card; ManageGPIO could drive a real pin, so ManageGPIOAccessCondition was left unchanged",
            );
        }
    } else {
        ctx.skip("ReadGPIO / ManageGPIO with the new access conditions", "the configuration could not be changed");
    }
    // restore and prove
    ctx.step_picc("SetConfiguration 0x11: restore the original 33 bytes and verify", |c| {
        c.set_configuration(0x11, &orig)?;
        c.auth_picc()?;
        let back = c.get_configuration(Some(0x11))?;
        ensure_eq(hex::encode_upper(&back), hex::encode_upper(&orig), "GPIO configuration after the restore")
    });
    // whatever happened above, make sure the restore action has done (or confirmed) its job
    if !ctx.run_cleanup_now(cid) {
        ctx.step("GPIO restore action", |_| Err::<(), _>(StepError::fail("the GPIO configuration could not be restored; see the cleanup report")));
    }
}

// ------------------------------------------------------------------ offline tests
#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> Vec<u8> {
        let mut d = vec![0u8; 33];
        d[0] = 2; // GPIO1 output
        d[6] = 1; // GPIO2 input
        d[14] = 0x0F;
        d[15] = 0x30;
        d[16..19].copy_from_slice(&[1, 0, 0]);
        d
    }

    #[test]
    fn parsing() {
        let g = parse_gpio(&block()).unwrap();
        assert_eq!((g.mode1, g.mode2, g.manage_ac, g.read_ac, g.aid), (2, 1, 0x0F, 0x30, Aid(1)));
        assert!(parse_gpio(&[0u8; 32]).is_err());
    }

    #[test]
    fn status_bytes_follow_the_modes() {
        let g = parse_gpio(&block()).unwrap();
        assert!(check_gpio_bytes(&[0x49, 0x48, 0x4C], &g).is_ok());
        assert!(check_gpio_bytes(&[0x49, 0x49, 0x4C], &g).is_err()); // GPIO1 is an output: must report
        assert!(check_gpio_bytes(&[0x00, 0x48, 0x4C], &g).is_err());
        assert!(check_gpio_bytes(&[0x49, 0x48], &g).is_err());
        let off = GpioCfg { mode1: 0, mode2: 0, ..g.clone() };
        assert!(check_gpio_bytes(&[0x49, 0x49, 0x49], &off).is_ok());
        assert!(check_gpio_bytes(&[0x49, 0x48, 0x49], &off).is_err());
        let power = GpioCfg { mode1: 4, mode2: 5, ..g };
        assert!(check_gpio_bytes(&[0x49, 0x4C, 0x48], &power).is_ok());
        assert!(!pin_reports(3, false) && !pin_reports(5, false) && !pin_reports(4, true));
    }

    #[test]
    fn access_condition_rewrite_changes_only_its_bytes() {
        let o = block();
        let n = with_access(&o, Some(0x30), 0x10);
        let diff: Vec<usize> = (0..33).filter(|&i| o[i] != n[i]).collect();
        assert_eq!(diff, vec![14, 15]);
        let n = with_access(&o, None, 0x10);
        let diff: Vec<usize> = (0..33).filter(|&i| o[i] != n[i]).collect();
        assert_eq!(diff, vec![15]);
        assert_eq!(with_access(&n, None, 0x30), o);
        assert_eq!(access_mode(0x30), CommMode::Full);
        assert_eq!(access_mode(0x10), CommMode::Mac);
        assert_eq!(access_mode(0x00), CommMode::Plain);
    }

    #[test]
    fn the_guard_policy_for_option_0x11() {
        use crate::guard::{Guard, Level, Op};
        let data = block();
        let off = Guard::new(false);
        let on = Guard::new(true);
        let op = Op::SetConfiguration { level: Level::Picc, option: 0x11, data: &data };
        assert!(off.check(&op).is_err());
        assert!(on.check(&op).is_ok());
        let short = Op::SetConfiguration { level: Level::Picc, option: 0x11, data: &data[..32] };
        assert!(on.check(&short).is_err());
    }
}
