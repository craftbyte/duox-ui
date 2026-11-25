//! Proximity check (7.18): PreparePC, ProximityCheck, VerifyPC.
//!
//! These three commands are not secure-messaging commands: they do not increase CmdCtr. The MAC
//! key is the session MAC key when authenticated, else the VCProximityKey. The round-trip times
//! reported here are measured on the reader side (including reader and bus latency), so the check
//! proves the cryptographic part only, not that the card answered within the published time.

use super::secure_messaging::Le;
use super::types::*;
use super::Card;
use crate::crypto;
use crate::error::{Error, Result};
use crate::transport::Transport;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub struct ProximityResult {
    /// The card's VerifyPC MAC matched.
    pub ok: bool,
    /// Option byte returned by PreparePC.
    pub option: u8,
    /// Response time announced by PreparePC (microseconds).
    pub announced_resp_time_us: u16,
    pub pps1: Option<u8>,
    /// Measured round trip per ProximityCheck command (microseconds).
    pub round_trip_us: Vec<f64>,
    /// The MAC key was the active session key (otherwise the supplied VCProximityKey).
    pub authenticated_key: bool,
}

impl<T: Transport> Card<T> {
    fn pc_command(&mut self, c: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let (data, sw) = self.iso_apdu(0x90, c, 0, 0, payload, Le::Short(0), false)?;
        if sw != 0x9190 {
            self.drop_session();
            if sw >> 8 == 0x91 {
                return Err(Error::protocol(format!(
                    "{}: {sw:04X} ({})",
                    command_name(c),
                    pc_status_name((sw & 0xFF) as u8)
                )));
            }
            return Err(Error::Iso { command: command_name(c).into(), sw });
        }
        Ok(data)
    }

    /// Run the proximity check. `split` divides the 8 random bytes into ProximityCheck commands
    /// (each part 1..=8 bytes, summing to 8); `[8]` is a single command.
    pub fn proximity_check(&mut self, vc_proximity_key: Option<&[u8]>, split: &[u8]) -> Result<ProximityResult> {
        if split.iter().map(|&n| n as usize).sum::<usize>() != 8 || split.iter().any(|&n| n == 0 || n > 8) {
            return Err(Error::arg("the challenge split must be 1..8 parts adding up to 8 bytes"));
        }
        let key: Vec<u8> = match (&self.session, vc_proximity_key) {
            (Some(s), _) => s.mac.clone(),
            (None, Some(k)) => k.to_vec(),
            (None, None) => return Err(Error::arg("not authenticated: the VCProximityKey is needed")),
        };
        let authenticated = self.session.is_some();
        self.log_line("-- PreparePC / ProximityCheck / VerifyPC");
        let pubd = self.pc_command(cmd::PREPARE_PC, &[])?;
        if pubd.len() < 3 {
            self.drop_session();
            return Err(Error::protocol("PreparePC: unexpected response"));
        }
        let rnd_c = crypto::rnd(8);
        let mut transcript = vec![];
        let mut times = vec![];
        let mut pos = 0usize;
        for &n in split {
            let n = n as usize;
            let part = &rnd_c[pos..pos + n];
            pos += n;
            let mut p = vec![n as u8];
            p.extend_from_slice(part);
            let t0 = Instant::now();
            let r = self.pc_command(cmd::PROXIMITY_CHECK, &p)?;
            times.push(t0.elapsed().as_secs_f64() * 1e6);
            if r.len() != n {
                self.drop_session();
                return Err(Error::protocol("ProximityCheck: response length does not match the challenge"));
            }
            transcript.extend_from_slice(&r);
            transcript.extend_from_slice(part);
        }
        let mac_in = |tag: u8| [&[tag][..], &pubd, &transcript].concat();
        let mac = self.pc_command(cmd::VERIFY_PC, &crypto::mact(&key, &mac_in(cmd::VERIFY_PC))?)?;
        let ok = mac == crypto::mact(&key, &mac_in(0x90))?;
        Ok(ProximityResult {
            ok,
            option: pubd[0],
            announced_resp_time_us: u16::from_be_bytes([pubd[1], pubd[2]]),
            pps1: if pubd[0] & 1 != 0 { pubd.get(3).copied() } else { None },
            round_trip_us: times,
            authenticated_key: authenticated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Card side of the proximity check using `key`.
    fn fake(key: Vec<u8>, corrupt: bool) -> MockTransport {
        let transcript = Rc::new(RefCell::new(Vec::<u8>::new()));
        let pubd = vec![0x00, 0x01, 0x2C];
        MockTransport::with_handler(move |a| {
            let ins = a[1];
            let mut r = match ins {
                0xF0 => pubd.clone(),
                0xF2 => {
                    let n = a[5] as usize;
                    let part = &a[6..6 + n];
                    let resp: Vec<u8> = part.iter().map(|b| b ^ 0xFF).collect();
                    transcript.borrow_mut().extend(&resp);
                    transcript.borrow_mut().extend(part);
                    resp
                }
                0xFD => {
                    let want = crypto::mact(&key, &[&[0xFD][..], &pubd, &transcript.borrow()].concat()).unwrap();
                    assert_eq!(&a[5..13], &want[..], "reader MAC");
                    let mut m = crypto::mact(&key, &[&[0x90][..], &pubd, &transcript.borrow()].concat()).unwrap();
                    if corrupt {
                        m[0] ^= 1;
                    }
                    m
                }
                _ => panic!("unexpected {ins:02X}"),
            };
            r.extend([0x91, 0x90]);
            r
        })
    }

    #[test]
    fn check_with_vc_key() {
        let key = vec![5u8; 16];
        let mut card = Card::new(fake(key.clone(), false));
        let r = card.proximity_check(Some(&key), &[3, 5]).unwrap();
        assert!(r.ok && !r.authenticated_key);
        assert_eq!((r.announced_resp_time_us, r.round_trip_us.len()), (0x012C, 2));
        let mut card = Card::new(fake(key.clone(), true));
        assert!(!card.proximity_check(Some(&key), &[8]).unwrap().ok);
    }

    #[test]
    fn argument_checks() {
        let mut card = Card::new(MockTransport::new());
        assert!(card.proximity_check(Some(&[0; 16]), &[4, 3]).is_err());
        assert!(card.proximity_check(Some(&[0; 16]), &[0, 8]).is_err());
        assert!(card.proximity_check(None, &[8]).is_err());
        assert!(card.transport().sent().is_empty());
    }
}
