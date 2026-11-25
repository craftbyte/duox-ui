//! Test support: a card-side model of EV2 authentication and secure messaging, written directly
//! against the crypto primitives (not against `Session`) so that the reader implementation is
//! checked against an independent statement of the rules of 7.5.8 / 7.5.10.

use crate::card::types::CommMode;
use crate::crypto::{self, ZERO_IV};
use crate::transport::MockTransport;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

/// Card side of the AES EV2 authentication, usable as a MockTransport handler.
pub struct FakeAesCard {
    pub key: Vec<u8>,
    pub ti: [u8; 4],
    pub rnd_b: Vec<u8>,
    pub rnd_a: Vec<u8>,
    pub pending: Option<u8>,
    pub enc: Vec<u8>,
    pub mac: Vec<u8>,
    pub ctr: u16,
    pub first: bool,
    /// Set when the last frame of an authentication was answered.
    pub just_authenticated: bool,
}

impl FakeAesCard {
    pub fn new(key: &[u8]) -> Self {
        FakeAesCard {
            key: key.to_vec(),
            ti: [0xDE, 0xAD, 0xBE, 0xEF],
            rnd_b: (0..16).map(|i| 0xB0 + i as u8).collect(),
            rnd_a: vec![],
            pending: None,
            enc: vec![],
            mac: vec![],
            ctr: 0,
            first: true,
            just_authenticated: false,
        }
    }

    /// Handle a wrapped authentication APDU; returns None if it is not one.
    pub fn auth(&mut self, apdu: &[u8]) -> Option<Vec<u8>> {
        let ins = apdu[1];
        let body = if apdu.len() > 5 { &apdu[5..5 + apdu[4] as usize] } else { &[][..] };
        match ins {
            0x71 | 0x77 => {
                self.pending = Some(ins);
                self.first = ins == 0x71;
                let mut r = crypto::aes_cbc_enc(&self.key, &self.rnd_b, &ZERO_IV).unwrap();
                r.extend([0x91, 0xAF]);
                Some(r)
            }
            0xAF if self.pending.is_some() => {
                let pt = crypto::aes_cbc_dec(&self.key, body, &ZERO_IV).unwrap();
                self.rnd_a = pt[..16].to_vec();
                assert_eq!(pt[16..], crypto::rotl(&self.rnd_b)[..], "reader returned wrong RndB'");
                let mut plain = vec![];
                if self.first {
                    plain.extend(self.ti);
                    plain.extend(crypto::rotl(&self.rnd_a));
                    plain.extend([1, 2, 3, 4, 5, 6]);
                    plain.extend([6, 5, 4, 3, 2, 1]);
                    self.ctr = 0;
                } else {
                    plain.extend(crypto::rotl(&self.rnd_a));
                }
                let (e, m) = crypto::ev2_session_keys(&self.key, &self.rnd_a, &self.rnd_b).unwrap();
                self.enc = e;
                self.mac = m;
                self.pending = None;
                self.just_authenticated = true;
                let mut r = crypto::aes_cbc_enc(&self.key, &plain, &ZERO_IV).unwrap();
                r.extend([0x91, 0x00]);
                Some(r)
            }
            _ => None,
        }
    }
}

/// A command as the card sees it after verifying the MAC and decrypting.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Request {
    pub cmd: u8,
    pub header: Vec<u8>,
    pub data: Vec<u8>,
    pub ctr: u16,
    pub authenticated: bool,
}

/// What the card answers.
#[derive(Debug, Clone)]
pub struct Response {
    pub rc: u8,
    pub data: Vec<u8>,
    /// Response protection; `None` = same as the command used.
    pub mode: Option<CommMode>,
    /// Card ends the authentication after this command.
    pub drops_auth: bool,
}

impl Response {
    pub fn ok(data: &[u8]) -> Self {
        Response { rc: 0, data: data.to_vec(), mode: None, drops_auth: false }
    }
    pub fn status(rc: u8) -> Self {
        Response { rc, data: vec![], mode: None, drops_auth: true }
    }
}

type Handler = Box<dyn FnMut(&Request) -> Response>;

/// Secure messaging card model.
pub struct SmCard {
    pub auth: FakeAesCard,
    authed: bool,
    pending: Option<(u8, Vec<u8>)>,
    out_frames: VecDeque<Vec<u8>>,
    header_len: fn(u8) -> usize,
    mode_for: fn(u8) -> CommMode,
    handler: Handler,
    /// Payload size at which a chained command is assumed to continue (reader frame size - 1).
    pub chain_frame: usize,
    /// Split responses into frames of this size (0 = single frame).
    pub resp_frame: Rc<Cell<usize>>,
    /// Corrupt the next response MAC.
    pub tamper: Rc<Cell<bool>>,
    /// Counter values seen per command: (cmd, ctr used by the reader).
    pub seen: Rc<RefCell<Vec<(u8, u16)>>>,
}

impl SmCard {
    pub fn new(
        key: &[u8],
        header_len: fn(u8) -> usize,
        mode_for: fn(u8) -> CommMode,
        handler: impl FnMut(&Request) -> Response + 'static,
    ) -> Self {
        SmCard {
            auth: FakeAesCard::new(key),
            authed: false,
            pending: None,
            out_frames: VecDeque::new(),
            header_len,
            mode_for,
            handler: Box::new(handler),
            chain_frame: 54,
            resp_frame: Rc::new(Cell::new(0)),
            tamper: Rc::new(Cell::new(false)),
            seen: Rc::new(RefCell::new(vec![])),
        }
    }

    pub fn into_transport(mut self) -> MockTransport {
        MockTransport::with_handler(move |a| self.handle(a))
    }

    fn iv(&self, label: [u8; 2]) -> Vec<u8> {
        let mut b = label.to_vec();
        b.extend(self.auth.ti);
        b.extend(self.auth.ctr.to_le_bytes());
        b.extend([0u8; 8]);
        crypto::aes_ecb_enc(&self.auth.enc, &b).unwrap()
    }

    fn mac_of(&self, parts: &[&[u8]]) -> Vec<u8> {
        crypto::mact(&self.auth.mac, &parts.concat()).unwrap()
    }

    fn wire_status(rc: u8, mut data: Vec<u8>) -> Vec<u8> {
        data.extend([0x91, rc]);
        data
    }

    pub fn handle(&mut self, apdu: &[u8]) -> Vec<u8> {
        let ins = apdu[1];
        let payload: Vec<u8> = if apdu.len() > 5 { apdu[5..5 + apdu[4] as usize].to_vec() } else { vec![] };
        if let Some(r) = self.auth.auth(apdu) {
            if self.auth.just_authenticated {
                self.auth.just_authenticated = false;
                self.authed = true;
            }
            return r;
        }
        if ins == 0xAF {
            if let Some((cmd, mut acc)) = self.pending.take() {
                acc.extend(&payload);
                if payload.len() == self.chain_frame {
                    self.pending = Some((cmd, acc));
                    return Self::wire_status(0xAF, vec![]);
                }
                return self.process(cmd, &acc);
            }
            if let Some(f) = self.out_frames.pop_front() {
                let rc = if self.out_frames.is_empty() { 0x00 } else { 0xAF };
                return Self::wire_status(rc, f);
            }
            return Self::wire_status(0xCA, vec![]);
        }
        let chained = matches!(ins, 0x3D | 0x3B | 0xDB);
        if chained && payload.len() == self.chain_frame {
            self.pending = Some((ins, payload));
            return Self::wire_status(0xAF, vec![]);
        }
        self.process(ins, &payload)
    }

    fn process(&mut self, cmd: u8, wire: &[u8]) -> Vec<u8> {
        if cmd == 0x5A {
            self.authed = false; // SelectApplication ends the authentication
        }
        let mode = if self.authed { (self.mode_for)(cmd) } else { CommMode::Plain };
        let hl = (self.header_len)(cmd).min(wire.len());
        let (header, body) = wire.split_at(hl);
        let mut data = body.to_vec();
        if self.authed {
            self.seen.borrow_mut().push((cmd, self.auth.ctr));
            if mode != CommMode::Plain {
                assert!(body.len() >= 8, "command MAC missing");
                let (b, m) = body.split_at(body.len() - 8);
                let want = self.mac_of(&[&[cmd], &self.auth.ctr.to_le_bytes(), &self.auth.ti, header, b]);
                if want != m {
                    self.authed = false;
                    return Self::wire_status(0x1E, vec![]);
                }
                data = b.to_vec();
                if mode == CommMode::Full && !b.is_empty() {
                    if b.len() % 16 != 0 {
                        self.authed = false;
                        return Self::wire_status(0x1E, vec![]);
                    }
                    let iv = self.iv([0xA5, 0x5A]);
                    let pt = crypto::aes_cbc_dec(&self.auth.enc, b, &iv).unwrap();
                    data = crypto::unpad_m2(&pt).expect("valid padding");
                }
            }
        }
        let req = Request { cmd, header: header.to_vec(), data, ctr: self.auth.ctr, authenticated: self.authed };
        let resp = (self.handler)(&req);
        if !self.authed {
            return self.send(resp.rc, resp.data, CommMode::Plain);
        }
        if resp.rc != 0 && resp.rc != 0x0C {
            self.authed = false;
            return Self::wire_status(resp.rc, vec![]);
        }
        self.auth.ctr = self.auth.ctr.wrapping_add(1);
        if resp.drops_auth {
            self.authed = false;
            return self.send(resp.rc, resp.data, CommMode::Plain);
        }
        self.send(resp.rc, resp.data, resp.mode.unwrap_or(mode))
    }

    fn send(&mut self, rc: u8, data: Vec<u8>, mode: CommMode) -> Vec<u8> {
        let mut wire = match mode {
            CommMode::Full if !data.is_empty() => {
                let iv = self.iv([0x5A, 0xA5]);
                crypto::aes_cbc_enc(&self.auth.enc, &crypto::pad_m2(&data), &iv).unwrap()
            }
            _ => data,
        };
        if mode != CommMode::Plain {
            let mut m = self.mac_of(&[&[rc], &self.auth.ctr.to_le_bytes(), &self.auth.ti, &wire]);
            if self.tamper.replace(false) {
                m[0] ^= 1;
            }
            wire.extend(m);
        }
        let fs = self.resp_frame.get();
        if fs == 0 || wire.len() <= fs {
            return Self::wire_status(rc, wire);
        }
        let mut chunks: VecDeque<Vec<u8>> = wire.chunks(fs).map(|c| c.to_vec()).collect();
        let first = chunks.pop_front().unwrap();
        self.out_frames = chunks;
        Self::wire_status(0xAF, first)
    }
}
