//! Secure messaging tests against the independent card model in `testkit`.

use super::testkit::{FakeAesCard, Request, Response, SmCard};
use super::types::CommMode::{Full, Mac, Plain};
use super::types::*;
use super::*;
use crate::crypto;
use crate::error::Error;
use crate::transport::MockTransport;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn header_len(c: u8) -> usize {
    match c {
        0x3D | 0xBD => 7,
        0x6C | 0xF5 | 0xC4 => 1,
        _ => 0,
    }
}
fn mode_for(c: u8) -> CommMode {
    match c {
        0x3D | 0xBD | 0xC4 => Full,
        0x6C => Plain,
        _ => Mac,
    }
}

struct Fixture {
    file: Rc<RefCell<Vec<u8>>>,
    last: Rc<RefCell<Option<Request>>>,
    tamper: Rc<Cell<bool>>,
    resp_frame: Rc<Cell<usize>>,
    seen: Rc<RefCell<Vec<(u8, u16)>>>,
}

fn setup(key: &[u8]) -> (Card<MockTransport>, Fixture) {
    let file = Rc::new(RefCell::new(vec![0u8; 512]));
    let last = Rc::new(RefCell::new(None::<Request>));
    let (f, l) = (file.clone(), last.clone());
    let card = SmCard::new(key, header_len, mode_for, move |r| {
        *l.borrow_mut() = Some(r.clone());
        match r.cmd {
            0x45 => Response::ok(&[0x0F, 0x82]),
            0x6A => Response::ok(&[1, 0, 0, 2, 0, 0, 3, 0, 0]),
            0x3D => {
                let off = le_u32(&r.header[1..4]) as usize;
                let len = le_u32(&r.header[4..7]) as usize;
                assert_eq!(len, r.data.len());
                f.borrow_mut()[off..off + len].copy_from_slice(&r.data);
                Response::ok(&[])
            }
            0xBD => {
                let off = le_u32(&r.header[1..4]) as usize;
                let len = le_u32(&r.header[4..7]) as usize;
                Response::ok(&f.borrow()[off..off + len])
            }
            0x6C => Response::ok(&(-5i32).to_le_bytes()),
            0xC4 => {
                if r.header[0] == 0 {
                    // the key used for the authentication: no response MAC, session over
                    Response { rc: 0, data: vec![], mode: None, drops_auth: true }
                } else {
                    Response { rc: 0, data: vec![], mode: Some(Mac), drops_auth: false }
                }
            }
            0x5A => Response::ok(&[]),
            0xF5 => Response::status(0x9D),
            _ => Response::status(0x1C),
        }
    });
    let fx = Fixture {
        file,
        last,
        tamper: card.tamper.clone(),
        resp_frame: card.resp_frame.clone(),
        seen: card.seen.clone(),
    };
    let mut c = Card::new(card.into_transport());
    c.connect().unwrap();
    (c, fx)
}

#[test]
fn mac_full_plain_roundtrip_with_chaining_and_counter() {
    for key in [vec![0u8; 16], (0..32u8).collect::<Vec<_>>()] {
        let (mut card, fx) = setup(&key);
        card.authenticate_ev2_first(0, &key, &[]).unwrap();
        let ks = card.get_key_settings().unwrap(); // Mac
        assert_eq!(ks.max_keys, 2);
        let data: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        card.write_data_with(1, 0, &data, Full.into()).unwrap(); // Full, chained over 5 frames
        assert_eq!(&fx.file.borrow()[..200], &data[..]);
        assert_eq!(fx.last.borrow().as_ref().unwrap().data, data, "card decrypted the data");
        let back = card.read_data_with(1, 0, 200, Full.into()).unwrap(); // Full response
        assert_eq!(back, data);
        assert_eq!(card.get_value_with(1, Plain.into()).unwrap(), -5); // Plain still counts
        card.get_key_settings().unwrap();
        let ctrs: Vec<u16> = fx.seen.borrow().iter().map(|&(_, c)| c).collect();
        assert_eq!(ctrs, vec![0, 1, 2, 3, 4]);
        assert_eq!(card.auth_summary().unwrap().cmd_ctr, 5);
        // TMI: write (8 -> 16, + 208), read (16 + 208), value (16)
        assert_eq!(card.transaction_input().len(), 224 + 224 + 16);
        assert_eq!(&card.transaction_input()[..8], &[0x3D, 1, 0, 0, 0, 200, 0, 0]);
    }
}

#[test]
fn multi_frame_responses_are_reassembled() {
    let key = [1u8; 16];
    let (mut card, fx) = setup(&key);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    fx.resp_frame.set(5);
    let ids = card.get_application_ids().unwrap();
    assert_eq!(ids, vec![Aid(1), Aid(2), Aid(3)]);
    assert!(card.is_authenticated());
}

#[test]
fn bad_response_mac_drops_session() {
    let key = [1u8; 16];
    let (mut card, fx) = setup(&key);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    fx.tamper.set(true);
    let e = card.get_key_settings().unwrap_err();
    assert!(matches!(e, Error::Protocol(ref m) if m.contains("response MAC invalid")), "{e}");
    assert!(!card.is_authenticated());
}

#[test]
fn card_error_ends_authentication_and_restarts_tmi() {
    let key = [1u8; 16];
    let (mut card, _fx) = setup(&key);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    // the card expects Full for WriteData: it answers INTEGRITY_ERROR to a MAC-only command
    let e = card.write_data_with(1, 0, &[1, 2, 3], Mac.into()).unwrap_err();
    assert_eq!(e.status(), Some(Status::IntegrityError));
    assert!(!card.is_authenticated());
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    card.read_data_with(1, 0, 4, Full.into()).unwrap();
    assert!(!card.transaction_input().is_empty());
    let e = card.get_file_settings(1).unwrap_err();
    assert!(matches!(e, Error::Status { status: Status::PermissionDenied, auth_lost: true, .. }), "{e}");
    assert!(!card.is_authenticated());
    assert!(card.transaction_input().is_empty());
}

#[test]
fn select_application_ends_authentication() {
    let key = [1u8; 16];
    let (mut card, _fx) = setup(&key);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    card.read_data_with(1, 0, 4, Full.into()).unwrap();
    card.select_application(Aid(0x42), None).unwrap();
    assert!(!card.is_authenticated());
    assert!(card.transaction_input().is_empty());
}

#[test]
fn non_first_keeps_command_counter() {
    let key = [1u8; 16];
    let (mut card, fx) = setup(&key);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    card.get_key_settings().unwrap();
    card.get_key_settings().unwrap();
    card.authenticate_ev2_non_first(0, &key).unwrap();
    card.get_key_settings().unwrap();
    assert_eq!(fx.seen.borrow().iter().map(|&(_, c)| c).collect::<Vec<_>>(), vec![0, 1, 2]);
}

#[test]
fn change_key_flows() {
    let key = [9u8; 16];
    let (mut card, fx) = setup(&key);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    // another key: needs the old key, response carries a MAC, session stays
    let new = [0x55u8; 16];
    let old = [0x11u8; 16];
    card.change_key(&ChangeKeySpec::new(2, &new, 7).old_key(&old)).unwrap();
    assert!(card.is_authenticated());
    {
        let r = fx.last.borrow().clone().unwrap();
        assert_eq!(r.header, vec![2]);
        assert_eq!(&r.data[..16], &crypto::xor(&new, &old)[..]);
        assert_eq!(r.data[16], 7);
        assert_eq!(&r.data[17..], &crypto::crc32_nk(&new));
    }
    // the authenticated key itself: version appended, no old key, authentication ends
    card.change_key(&ChangeKeySpec::new(0, &new, 8)).unwrap();
    assert_eq!(fx.last.borrow().as_ref().unwrap().data.len(), 17);
    assert!(!card.is_authenticated());
}

#[test]
fn delegated_application_is_two_frames_counted_once() {
    let key = [3u8; 16];
    let mut fake = FakeAesCard::new(&key);
    let header = vec![0xAA; 20];
    let h2 = header.clone();
    let t = MockTransport::with_handler(move |a| {
        if let Some(r) = fake.auth(a) {
            return r;
        }
        let body = &a[5..5 + a[4] as usize];
        match a[1] {
            0xC9 => {
                assert_eq!(body, &h2[..]);
                vec![0x91, 0xAF]
            }
            0xAF => {
                let (part2, mac) = body.split_at(body.len() - 8);
                let input = [&[0xC9][..], &fake.ctr.to_le_bytes(), &fake.ti, &h2, part2].concat();
                assert_eq!(mac, &crypto::mact(&fake.mac, &input).unwrap()[..]);
                assert_eq!(part2.len(), 40);
                fake.ctr += 1;
                let mut r = crypto::mact(&fake.mac, &[&[0u8][..], &fake.ctr.to_le_bytes(), &fake.ti].concat()).unwrap();
                r.extend([0x91, 0x00]);
                r
            }
            _ => vec![0x91, 0x1C],
        }
    });
    let mut card = Card::new(t);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    let spec = DelegatedAppSpec { header, keys: DelegatedKeys::Aes { enc_k: vec![1; 32], dam_mac: vec![2; 8] } };
    card.create_delegated_application(&spec).unwrap();
    assert_eq!(card.auth_summary().unwrap().cmd_ctr, 1);
    let bad = DelegatedAppSpec { header: vec![], keys: DelegatedKeys::Ecc { init_k: vec![1] } };
    assert!(matches!(card.create_delegated_application(&bad), Err(Error::InvalidArgument(_))));
}

#[test]
fn raw_escape_hatches_drop_the_session() {
    let key = [1u8; 16];
    let (mut card, _fx) = setup(&key);
    card.authenticate_ev2_first(0, &key, &[]).unwrap();
    let (rc, frames) = card.native_raw(0x6C, &[1]).unwrap();
    assert_eq!(rc, 0x00);
    assert!(!frames.is_empty());
    assert!(!card.is_authenticated());
    let (_, sw) = card.apdu_raw(&[0x90, 0x6C, 0, 0, 1, 1, 0]).unwrap();
    assert_eq!(sw >> 8, 0x91);
}

#[test]
fn transport_failure_is_reported() {
    let mut t = MockTransport::new();
    t.fail_next("reader removed");
    let mut card = Card::new(t);
    assert!(matches!(card.get_version().unwrap_err(), Error::Transport(_)));
}
