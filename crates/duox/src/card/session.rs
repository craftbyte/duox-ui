//! Authentication state queries and access-condition evaluation.

use super::files::FileSettings;
use super::types::{AccessRight, Aid, CommMode, SECOND_APP_BIT};
use super::Card;
use crate::crypto::SessionKind;
use crate::transport::Transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Aes,
    Ecc,
}

/// Read-only snapshot of the active authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSummary {
    pub kind: AuthKind,
    /// AES: authenticated key number (without the secondary-application bit).
    pub key_no: Option<u8>,
    /// AES: the key belongs to the secondary application.
    pub secondary: bool,
    /// AES session key length in bits (128 / 256); ECC sessions are AES-128 internally.
    pub key_bits: usize,
    /// ECC: granted access conditions (bit n = access condition n), primary / secondary application.
    pub acmap: u16,
    pub acmap2: u16,
    /// Command counter (the value for the next command).
    pub cmd_ctr: u16,
    /// Transaction identifier (all zero for ECC sessions).
    pub ti: [u8; 4],
}

impl<T: Transport> Card<T> {
    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    pub fn auth_summary(&self) -> Option<AuthSummary> {
        let s = self.session.as_ref()?;
        Some(AuthSummary {
            kind: match s.kind {
                SessionKind::Aes => AuthKind::Aes,
                SessionKind::Ecc => AuthKind::Ecc,
            },
            key_no: s.key_no,
            secondary: s.sai,
            key_bits: s.enc.len() * 8,
            acmap: s.acmap,
            acmap2: s.acmap2,
            cmd_ctr: s.ctr,
            ti: s.ti,
        })
    }

    /// One-line description of the authentication state.
    pub fn state_text(&self) -> String {
        match self.auth_summary() {
            None => "not authenticated".into(),
            Some(a) if a.kind == AuthKind::Aes => format!(
                "AES key {:02X}{} (AES-{}), CmdCtr {}",
                a.key_no.unwrap_or(0),
                if a.secondary { " of the secondary application" } else { "" },
                a.key_bits,
                a.cmd_ctr
            ),
            Some(a) => format!(
                "ECC, ACMap {:04X}{}, CmdCtr {}",
                a.acmap,
                if self.selection.secondary.is_some() { format!(" / secondary {:04X}", a.acmap2) } else { String::new() },
                a.cmd_ctr
            ),
        }
    }

    /// Does the active authentication satisfy access condition `ac` in the primary
    /// (`secondary == false`) or secondary application?
    pub fn has_access_condition(&self, ac: AccessRight, secondary: bool) -> bool {
        let Some(s) = self.session.as_ref() else { return false };
        if !ac.is_key() {
            return false;
        }
        if s.kind == SessionKind::Ecc {
            let map = if secondary { s.acmap2 } else { s.acmap };
            return (map >> ac.0) & 1 == 1;
        }
        if s.sai != secondary {
            return false;
        }
        let Some(key_no) = s.key_no else { return false };
        if self.selection.primary == Some(Aid::PICC) {
            // At PICC level the master key (0x00) satisfies condition 0 and the configuration
            // key (0x20) satisfies condition 1.
            return match key_no {
                0x00 => ac.0 == 0,
                0x20 => ac.0 == 1,
                _ => false,
            };
        }
        key_no == ac.0
    }

    /// CommMode for a data command on the file: the file's own mode if the session satisfies one
    /// of the relevant access conditions, Plain if access is only granted as "free".
    pub fn file_comm_mode(&self, fs: &FileSettings, write: bool) -> CommMode {
        if self.session.is_none() {
            return CommMode::Plain;
        }
        let acs = fs.access_conditions(write);
        let secondary = fs.file_no & SECOND_APP_BIT != 0;
        let satisfied = acs.iter().any(|&a| self.has_access_condition(a, secondary));
        if !satisfied && acs.contains(&AccessRight::FREE) {
            return CommMode::Plain;
        }
        fs.comm_mode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::files::FileSettings;
    use crate::crypto::Session;
    use crate::transport::MockTransport;

    fn settings(option: u8, ar: u16) -> FileSettings {
        let mut d = vec![0x00, option];
        d.extend(ar.to_le_bytes());
        d.extend([0x10, 0, 0]);
        FileSettings::parse(1, &d).unwrap()
    }

    fn aes_card(key_no: u8, aid: Aid) -> Card<MockTransport> {
        let mut c = Card::new(MockTransport::new());
        c.selection.primary = Some(aid);
        c.session = Some(Session::new(SessionKind::Aes, vec![0; 16], vec![0; 16], [0; 4], Some(key_no), 0));
        c
    }

    #[test]
    fn mode_follows_access_conditions() {
        // Read=E (free), Write=1, ReadWrite=2, Change=0; CommMode Full
        let fs = settings(0x03, 0xE120);
        assert_eq!(fs.access.read, AccessRight::FREE);
        let unauth = Card::new(MockTransport::new());
        assert_eq!(unauth.file_comm_mode(&fs, false), CommMode::Plain);
        // key 1 authenticated: write needs key 1 -> Full; read is free but key 1 does not satisfy
        // the ReadWrite condition 2 -> plain access through "free"
        let c = aes_card(1, Aid(0x42));
        assert_eq!(c.file_comm_mode(&fs, true), CommMode::Full);
        assert_eq!(c.file_comm_mode(&fs, false), CommMode::Plain);
        // key 2 satisfies ReadWrite for both
        let c = aes_card(2, Aid(0x42));
        assert_eq!(c.file_comm_mode(&fs, false), CommMode::Full);
    }

    #[test]
    fn picc_level_key_mapping_and_second_application() {
        let c = aes_card(0x00, Aid::PICC);
        assert!(c.has_access_condition(AccessRight::key(0), false));
        assert!(!c.has_access_condition(AccessRight::key(1), false));
        let c = aes_card(0x20, Aid::PICC);
        assert!(c.has_access_condition(AccessRight::key(1), false));
        let mut c = aes_card(3, Aid(1));
        assert!(c.has_access_condition(AccessRight::key(3), false));
        assert!(!c.has_access_condition(AccessRight::key(3), true));
        assert!(!c.has_access_condition(AccessRight::FREE, false));
        c.session.as_mut().unwrap().sai = true;
        assert!(c.has_access_condition(AccessRight::key(3), true));
    }

    #[test]
    fn ecc_access_map() {
        let mut c = Card::new(MockTransport::new());
        let mut s = Session::new(SessionKind::Ecc, vec![0; 16], vec![0; 16], [0; 4], None, 0b0101);
        s.acmap2 = 0b0010;
        c.session = Some(s);
        assert!(c.has_access_condition(AccessRight::key(0), false));
        assert!(!c.has_access_condition(AccessRight::key(1), false));
        assert!(c.has_access_condition(AccessRight::key(2), false));
        assert!(c.has_access_condition(AccessRight::key(1), true));
        assert!(c.state_text().starts_with("ECC, ACMap 0005"));
    }
}
