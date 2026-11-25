//! AES authentication: AuthenticateEV2First / AuthenticateEV2NonFirst (7.5.8).
//!
//! Both are three-pass protocols: the card sends `E(K, RndB)`, the reader answers
//! `E(K, RndA || RndB')` (RndB rotated left by one byte), the card finishes with
//! `E(K, ...)` proving knowledge of RndA. Session keys come from the KDF in
//! [`crate::crypto::ev2_session_keys`]. AES-128 and AES-256 keys are accepted. A failure at any
//! step leaves the card unauthenticated.

use super::types::*;
use super::Card;
use crate::crypto::{self, Session, SessionKind, ZERO_IV};
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Data returned by AuthenticateEV2First.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesAuthInfo {
    pub ti: [u8; 4],
    /// Capabilities the card reported (6 bytes).
    pub pd_cap2: Vec<u8>,
    /// Capabilities the card echoes back for the reader (6 bytes).
    pub pcd_cap2: Vec<u8>,
}

impl<T: Transport> Card<T> {
    /// Run the first two passes common to both commands. Returns (RndA, RndB, final decrypted payload).
    fn aes_passes(&mut self, c: u8, key_no: u8, key: &[u8], extra: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if key.len() != 16 && key.len() != 32 {
            return Err(Error::arg("AES key must be 16 or 32 bytes"));
        }
        self.log_line(&format!("-- {} key {:02X}", command_name(c), key_no));
        let mut p1 = vec![key_no];
        p1.extend_from_slice(extra);
        let (rc, d) = self.wrap(c, &p1)?;
        if rc != 0xAF {
            return Err(self.fail(rc, c, false));
        }
        if d.len() != 16 {
            self.drop_session();
            return Err(Error::protocol(format!("{}: unexpected length of the card challenge", command_name(c))));
        }
        let rnd_b = crypto::aes_cbc_dec(key, &d, &ZERO_IV)?;
        let rnd_a = crypto::rnd(16);
        let plain = [rnd_a.clone(), crypto::rotl(&rnd_b)].concat();
        let (rc, d) = self.wrap(cmd::ADDITIONAL_FRAME, &crypto::aes_cbc_enc(key, &plain, &ZERO_IV)?)?;
        if rc != 0x00 {
            return Err(self.fail(rc, c, false));
        }
        if d.is_empty() || d.len() % 16 != 0 {
            self.drop_session();
            return Err(Error::protocol(format!("{}: malformed final response", command_name(c))));
        }
        let pt = crypto::aes_cbc_dec(key, &d, &ZERO_IV)?;
        Ok((rnd_a, rnd_b, pt))
    }

    /// AuthenticateEV2First: starts a new session (CmdCtr 0). `key_no` may carry the
    /// secondary-application bit (0x80) when two applications are selected. `pcd_cap2` is the
    /// optional reader capability string (up to 6 bytes).
    pub fn authenticate_ev2_first(&mut self, key_no: u8, key: &[u8], pcd_cap2: &[u8]) -> Result<AesAuthInfo> {
        self.drop_session();
        if pcd_cap2.len() > 6 {
            return Err(Error::arg("PCDcap2 is at most 6 bytes"));
        }
        let mut extra = vec![pcd_cap2.len() as u8];
        extra.extend_from_slice(pcd_cap2);
        let (rnd_a, rnd_b, pt) = self.aes_passes(cmd::AUTH_EV2_FIRST, key_no, key, &extra)?;
        if pt.len() != 32 || pt[4..20] != crypto::rotl(&rnd_a)[..] {
            self.drop_session();
            return Err(Error::protocol("AuthenticateEV2First: card response does not match RndA - wrong key?"));
        }
        let (enc, mac) = crypto::ev2_session_keys(key, &rnd_a, &rnd_b)?;
        let ti = [pt[0], pt[1], pt[2], pt[3]];
        let mut s = Session::new(SessionKind::Aes, enc, mac, ti, Some(key_no & 0x3F), 0);
        s.sai = key_no & SECOND_APP_BIT != 0 && self.selection.secondary.is_some();
        self.session = Some(s);
        let info = AesAuthInfo { ti, pd_cap2: pt[20..26].to_vec(), pcd_cap2: pt[26..32].to_vec() };
        self.auth_info = Some(info.clone());
        Ok(info)
    }

    /// AuthenticateEV2NonFirst: re-authenticates within the running session. TI and CmdCtr are
    /// kept, only the session keys change.
    pub fn authenticate_ev2_non_first(&mut self, key_no: u8, key: &[u8]) -> Result<()> {
        let mut s = match self.session.take() {
            Some(s) if s.kind == SessionKind::Aes => s,
            other => {
                self.session = other;
                return Err(Error::NotAuthenticated("AuthenticateEV2NonFirst (AES session)"));
            }
        };
        let info = self.auth_info.take();
        let (rnd_a, rnd_b, pt) = match self.aes_passes(cmd::AUTH_EV2_NON_FIRST, key_no, key, &[]) {
            Ok(r) => r,
            Err(e) => {
                self.drop_session();
                return Err(e);
            }
        };
        if pt.len() < 16 || pt[..16] != crypto::rotl(&rnd_a)[..] {
            self.drop_session();
            return Err(Error::protocol("AuthenticateEV2NonFirst: card response does not match RndA - wrong key?"));
        }
        let (enc, mac) = crypto::ev2_session_keys(key, &rnd_a, &rnd_b)?;
        s.enc = enc;
        s.mac = mac;
        s.key_no = Some(key_no & 0x3F);
        s.sai = key_no & SECOND_APP_BIT != 0 && self.selection.secondary.is_some();
        self.session = Some(s);
        self.auth_info = info;
        Ok(())
    }

    /// Capabilities / TI of the last AuthenticateEV2First.
    pub fn aes_auth_info(&self) -> Option<&AesAuthInfo> {
        self.auth_info.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::testkit::FakeAesCard;
    use crate::transport::MockTransport;

    #[test]
    fn ev2_first_and_non_first() {
        for klen in [16usize, 32] {
            let key: Vec<u8> = (0..klen as u8).collect();
            let mut fake = FakeAesCard::new(&key);
            let t = MockTransport::with_handler(move |a| fake.auth(a).unwrap_or_else(|| vec![0x91, 0x1C]));
            let mut card = Card::new(t);
            let info = card.authenticate_ev2_first(0x01, &key, &[]).unwrap();
            assert_eq!(info.ti, [0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(info.pd_cap2, vec![1, 2, 3, 4, 5, 6]);
            let a = card.auth_summary().unwrap();
            assert_eq!((a.kind, a.key_no, a.cmd_ctr, a.key_bits), (super::super::AuthKind::Aes, Some(1), 0, klen * 8));
            // first-pass APDU: key number, PCDcap2 length
            assert_eq!(card.transport().sent()[0], [0x90, 0x71, 0, 0, 2, 0x01, 0x00, 0]);
            card.authenticate_ev2_non_first(0x02, &key).unwrap();
            assert_eq!(card.auth_summary().unwrap().key_no, Some(2));
            assert_eq!(card.auth_summary().unwrap().ti, [0xDE, 0xAD, 0xBE, 0xEF]);
        }
    }

    #[test]
    fn wrong_key_ends_authentication() {
        let key = [7u8; 16];
        let mut fake = FakeAesCard::new(&key);
        let t = MockTransport::with_handler(move |a| fake.auth(a).unwrap_or_else(|| vec![0x91, 0x1C]));
        let mut card = Card::new(t);
        // the fake asserts on a wrong RndB', so use the right key length but let the card refuse:
        let mut t2 = MockTransport::new();
        t2.reply(&[0x91, 0xAE]);
        let mut card2 = Card::new(t2);
        let e = card2.authenticate_ev2_first(0, &key, &[]).unwrap_err();
        assert_eq!(e.status(), Some(Status::AuthenticationError));
        assert!(!card2.is_authenticated());
        assert!(card.authenticate_ev2_first(0, &[1u8; 10], &[]).is_err());
        assert!(card.authenticate_ev2_non_first(0, &key).is_err());
    }
}
