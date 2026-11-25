//! APDU framing, native command wrapping, additional-frame chaining and EV2 secure messaging.
//!
//! Native commands travel in ISO/IEC 7816-4 wrapped form (CLA 0x90, P1 = P2 = 0, 7.17.2); the
//! native status byte comes back as SW2 of a `91xx` status word. [`Card::run`] is the single
//! place where MAC / encryption is applied to commands and removed from responses (7.5.10):
//!
//! * command MAC input: `Cmd || CmdCtr || TI || header || data` (data encrypted in Full mode),
//! * the MAC is appended after the (possibly encrypted) data; the header stays in clear,
//! * CmdCtr increases once per command (also for Plain commands while authenticated), after the
//!   response arrived and before the response MAC is verified,
//! * response MAC input: `RC || CmdCtr || TI || response data`,
//! * Full responses carry the encrypted data followed by the 8-byte MAC.

use super::tlv;
use super::types::{cmd, command_name, iso_sw_description, CommMode, Status};
use super::Card;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Length of the truncated MAC.
pub const MAC_LEN: usize = 8;

/// Commands whose data is sent in several native frames when it exceeds one frame.
const CHAINED_TX: [u8; 3] = [cmd::WRITE_DATA, cmd::WRITE_RECORD, cmd::UPDATE_RECORD];

/// Safety net against a card that never stops asking for further frames.
const MAX_FRAMES: usize = 2048;
/// Consecutive additional frames without data after which the exchange is given up.
const MAX_EMPTY_FRAMES: usize = 24;

/// Le field of an APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Le {
    /// No Le byte.
    None,
    /// One Le byte (0 means 256).
    Short(u8),
}

/// Build a command APDU. Extended length is chosen when the data exceeds 255 bytes or when
/// `extended` is set and there is data (Lc is then three bytes, Le two bytes).
pub fn build_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Le, extended: bool) -> Vec<u8> {
    let mut apdu = vec![cla, ins, p1, p2];
    if data.len() > 255 || (extended && !data.is_empty()) {
        apdu.push(0);
        apdu.extend((data.len() as u16).to_be_bytes());
        apdu.extend_from_slice(data);
        if le != Le::None {
            apdu.extend([0, 0]);
        }
    } else {
        if !data.is_empty() {
            apdu.push(data.len() as u8);
            apdu.extend_from_slice(data);
        }
        if let Le::Short(n) = le {
            apdu.push(n);
        }
    }
    apdu
}

/// Result of one native command after secure messaging was removed.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub status: u8,
    /// Response frames without MAC (a single entry for Full mode).
    pub frames: Vec<Vec<u8>>,
}

impl Reply {
    pub fn data(&self) -> Vec<u8> {
        self.frames.concat()
    }
}

impl<T: Transport> Card<T> {
    // ------------------------------------------------------------ plain APDUs
    /// Transmit, dropping all protocol state if the transport itself fails.
    pub(crate) fn tx(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        match self.transport.transmit(apdu) {
            Ok(r) => Ok(r),
            Err(e) => {
                self.drop_session();
                Err(e.into())
            }
        }
    }

    pub(crate) fn drop_session(&mut self) {
        self.session = None;
        self.auth_info = None;
        self.new_transaction(None);
    }

    /// Build and send an ISO APDU (no status interpretation).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn iso_apdu(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Le,
        extended: bool,
    ) -> Result<(Vec<u8>, u16)> {
        let apdu = build_apdu(cla, ins, p1, p2, data, le, extended);
        self.tx(&apdu)
    }

    /// Standard ISO command expected to answer 9000; any other status ends the authentication.
    pub(crate) fn iso_checked(
        &mut self,
        name: &str,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Le,
    ) -> Result<Vec<u8>> {
        self.log_line(&format!("-- {name}"));
        let (resp, sw) = self.iso_apdu(cla, ins, p1, p2, data, le, false)?;
        if sw != 0x9000 {
            self.drop_session();
            return Err(Error::Iso { command: name.into(), sw });
        }
        Ok(resp)
    }

    /// Send one native frame; returns the native status byte and the data.
    pub(crate) fn wrap(&mut self, cmd_code: u8, payload: &[u8]) -> Result<(u8, Vec<u8>)> {
        let (data, sw) = self.iso_apdu(0x90, cmd_code, 0, 0, payload, Le::Short(0), false)?;
        if sw >> 8 != 0x91 {
            self.drop_session();
            return Err(Error::Iso { command: command_name(cmd_code).into(), sw });
        }
        Ok(((sw & 0xFF) as u8, data))
    }

    /// Send a command (chaining the request if needed) and collect all response frames.
    pub(crate) fn exchange(&mut self, cmd_code: u8, payload: &[u8]) -> Result<(u8, Vec<Vec<u8>>)> {
        let mf = self.max_native_frame;
        let (mut rc, d);
        if CHAINED_TX.contains(&cmd_code) && payload.len() + 1 > mf {
            let (r0, mut dd) = self.wrap(cmd_code, &payload[..mf - 1])?;
            rc = r0;
            let mut rest = &payload[mf - 1..];
            while !rest.is_empty() {
                if rc != 0xAF {
                    return Ok((rc, vec![dd]));
                }
                let n = rest.len().min(mf - 1);
                let (r, nd) = self.wrap(cmd::ADDITIONAL_FRAME, &rest[..n])?;
                rc = r;
                dd = nd;
                rest = &rest[n..];
            }
            d = dd;
        } else {
            let (r, dd) = self.wrap(cmd_code, payload)?;
            rc = r;
            d = dd;
        }
        let mut frames = vec![d];
        let mut empty_run = 0usize;
        while rc == 0xAF {
            if frames.len() > MAX_FRAMES || empty_run > MAX_EMPTY_FRAMES {
                self.drop_session();
                // The card is still in the chained exchange and would answer the next command with
                // COMMAND_ABORTED. Any other command ends the chain; send a harmless one.
                let _ = self.wrap(cmd::SELECT_APPLICATION, &[0, 0, 0]);
                return Err(Error::protocol("card keeps requesting additional frames"));
            }
            let (r, dd) = self.wrap(cmd::ADDITIONAL_FRAME, &[])?;
            empty_run = if dd.is_empty() { empty_run + 1 } else { 0 };
            rc = r;
            frames.push(dd);
        }
        Ok((rc, frames))
    }

    /// Error for a native status the caller did not accept: ends authentication and restarts the
    /// Transaction MAC Input.
    pub(crate) fn fail(&mut self, rc: u8, cmd_code: u8, was_authenticated: bool) -> Error {
        self.drop_session();
        Error::Status { command: command_name(cmd_code), status: Status::from(rc), auth_lost: was_authenticated }
    }

    // ------------------------------------------------------- secure messaging
    /// Execute a native command with secure messaging.
    ///
    /// `mode` is ignored (Plain) when not authenticated. `ok` lists the acceptable native
    /// statuses. On any error the session is gone.
    pub(crate) fn run(
        &mut self,
        cmd_code: u8,
        header: &[u8],
        data: &[u8],
        mode: CommMode,
        ok: &[u8],
    ) -> Result<Reply> {
        let name = command_name(cmd_code);
        let mut sess = self.session.take();
        let mode = if sess.is_some() { mode } else { CommMode::Plain };
        if self.log.is_some() {
            let m = if sess.is_some() { mode.to_string() } else { "not authenticated".into() };
            self.log_line(&format!("-- {name} [{m}]"));
        }
        let mut tx = header.to_vec();
        match &sess {
            Some(s) => {
                if mode == CommMode::Full && !data.is_empty() {
                    tx.extend(s.encrypt(data, false)?);
                } else {
                    tx.extend_from_slice(data);
                }
                if mode != CommMode::Plain {
                    let mac = s.mac_cmd(cmd_code, &tx)?;
                    tx.extend(mac);
                }
            }
            None => tx.extend_from_slice(data),
        }
        let was_auth = sess.is_some();
        let (rc, mut frames) = self.exchange(cmd_code, &tx)?;
        if !ok.contains(&rc) {
            return Err(self.fail(rc, cmd_code, was_auth));
        }
        if let Some(s) = sess.as_mut() {
            s.ctr = s.ctr.wrapping_add(1);
            if mode != CommMode::Plain {
                let joined = frames.concat();
                // Deleting the application that is selected ends the card's session together with the
                // application, so the answer carries no response MAC.
                if joined.is_empty()
                    && cmd_code == cmd::DELETE_APPLICATION
                    && header.len() >= 3
                    && self.selection.primary.map(|a| a.to_bytes()[..] == header[..3]).unwrap_or(false)
                {
                    self.drop_session();
                    return Ok(Reply { status: rc, frames: vec![] });
                }
                // RollKeySet ends the card's session with the key set switch: no response MAC.
                if joined.is_empty() && cmd_code == cmd::ROLL_KEY_SET && rc == 0x00 {
                    self.drop_session();
                    return Ok(Reply { status: rc, frames: vec![] });
                }
                // NO_CHANGES (0x0C) carries no MAC and, as observed on silicon, ends the authentication
                // like an error return does: the next MAC protected command is answered with LENGTH_ERROR.
                if joined.is_empty() && rc == 0x0C {
                    self.drop_session();
                    return Ok(Reply { status: rc, frames: vec![] });
                }
                if joined.len() < MAC_LEN {
                    self.drop_session();
                    return Err(Error::protocol(format!("{name}: response MAC missing - session dropped")));
                }
                let (rdata, rmac) = joined.split_at(joined.len() - MAC_LEN);
                if s.mac_resp(rc, rdata)? != rmac {
                    self.drop_session();
                    return Err(Error::protocol(format!("{name}: response MAC invalid - session dropped")));
                }
                if mode == CommMode::Full && !rdata.is_empty() {
                    match s.decrypt(rdata, true) {
                        Ok(p) => frames = vec![p],
                        Err(e) => {
                            self.drop_session();
                            return Err(Error::protocol(format!("{name}: response decryption failed: {e}")));
                        }
                    }
                } else {
                    frames = strip_tail(frames, MAC_LEN);
                }
            }
        }
        self.session = sess;
        Ok(Reply { status: rc, frames })
    }

    /// Execute a command and return its response data.
    pub(crate) fn command(&mut self, cmd_code: u8, header: &[u8], data: &[u8], mode: CommMode) -> Result<Vec<u8>> {
        Ok(self.run(cmd_code, header, data, mode, &[0x00])?.data())
    }

    // -------------------------------------------------------- escape hatches
    /// Send an arbitrary APDU and return `(data, SW)`.
    ///
    /// The reader cannot know what such a command does to the card's session state, so any
    /// authentication tracked by this `Card` is dropped first. The card itself keeps an active
    /// session until it is ended (SelectApplication ends it) and then rejects commands without a
    /// MAC, so select the PICC first when sending plain commands after an authentication.
    pub fn apdu_raw(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        self.drop_session();
        self.tx(apdu)
    }

    /// Send a native command (ISO wrapped) exactly as given, following additional-frame
    /// requests, without any secure messaging. Returns the final native status byte and all
    /// response frames. Drops the tracked authentication (see [`Card::apdu_raw`]).
    pub fn native_raw(&mut self, cmd_code: u8, payload: &[u8]) -> Result<(u8, Vec<Vec<u8>>)> {
        self.drop_session();
        self.log_line(&format!("-- raw {}", command_name(cmd_code)));
        let (rc, frames) = self.exchange(cmd_code, payload)?;
        Ok((rc, frames))
    }

    // ------------------------------------------------------------ misc
    /// Description for an ISO status word (for UIs).
    pub fn describe_sw(sw: u16) -> &'static str {
        iso_sw_description(sw)
    }

    /// Parse a `7C` constructed response and return its first-level children as `(tag, value)`.
    pub(crate) fn parse_7c(data: &[u8], what: &str) -> Result<Vec<(u8, Vec<u8>)>> {
        let (tag, inner, _) = tlv::read(data, 0)?;
        if tag != 0x7C {
            return Err(Error::protocol(format!("{what}: unexpected response format")));
        }
        let mut out = vec![];
        let mut pos = 0;
        while pos < inner.len() {
            let (t, v, next) = tlv::read(inner, pos)?;
            out.push((t, v.to_vec()));
            pos = next;
        }
        Ok(out)
    }
}

/// Remove the last `n` bytes spread over `frames`, dropping frames that become empty.
pub(crate) fn strip_tail(frames: Vec<Vec<u8>>, n: usize) -> Vec<Vec<u8>> {
    let total: usize = frames.iter().map(Vec::len).sum();
    let mut left = total.saturating_sub(n);
    let mut out = Vec::new();
    for mut f in frames {
        f.truncate(left);
        left -= f.len();
        if !f.is_empty() {
            out.push(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_encoding() {
        assert_eq!(build_apdu(0x90, 0x60, 0, 0, &[], Le::Short(0), false), [0x90, 0x60, 0, 0, 0]);
        assert_eq!(build_apdu(0x90, 0x5A, 0, 0, &[1, 2, 3], Le::Short(0), false), [0x90, 0x5A, 0, 0, 3, 1, 2, 3, 0]);
        assert_eq!(build_apdu(0, 0xD6, 0, 0, &[9], Le::None, false), [0, 0xD6, 0, 0, 1, 9]);
        // forced extended
        assert_eq!(build_apdu(0, 0x87, 0, 0, &[7], Le::Short(0), true), [0, 0x87, 0, 0, 0, 0, 1, 7, 0, 0]);
        // long data switches to extended on its own
        let a = build_apdu(0, 0xD6, 0, 0, &[0u8; 300], Le::None, false);
        assert_eq!(&a[4..7], &[0, 1, 44]);
        assert_eq!(a.len(), 7 + 300);
        // extended without data still uses the short form
        assert_eq!(build_apdu(0, 0xB0, 0, 0, &[], Le::Short(0), true), [0, 0xB0, 0, 0, 0]);
    }

    #[test]
    fn strip_tail_spans_frames() {
        let f = vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8]];
        assert_eq!(strip_tail(f.clone(), 4), vec![vec![1, 2, 3], vec![4]]);
        assert_eq!(strip_tail(f, 8), Vec::<Vec<u8>>::new());
    }
}
