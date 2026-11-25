//! ECC based authentication (7.5.6, 7.5.7, 7.21).
//!
//! * mutual and reader-unilateral authentication with `ISOGeneralAuthenticate` (two exchanges:
//!   the first carries the reader's ephemeral key E.Pub.A, the second the encrypted reader
//!   message), or - when the application was selected with `ISOSelectFile` and the card
//!   returned its ephemeral key in the FCI - the single-exchange `ISOGeneralAuthenticateFinal`,
//! * card-unilateral authentication with `ISOInternalAuthenticate`, also used for the
//!   originality check of the PICC.
//!
//! The session keys come from ECDH over the ephemeral keys and the two-step KDF in
//! [`crate::crypto::ecc_session_keys`]. An ECC session has TI = 00000000.
//!
//! Certificate parsing is not done here. The caller supplies the reader certificate chain as
//! bytes, and either the card's public key or a closure that extracts the leaf public key from
//! Cert.B (typically `pki::leaf_public_key`).

use super::iso::IsoSelect;
use super::secure_messaging::Le;
use super::tlv;
use super::types::*;
use super::Card;
use crate::crypto::{self, PrivKey, PubKey, Session, SessionKind, ZERO_IV};
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Function extracting the public key of the leaf certificate in `Cert.B`.
pub type CertKeyFn<'a> = &'a dyn Fn(&[u8]) -> Option<PubKey>;

/// Parameters of an ECC authentication.
pub struct EccAuthOptions<'a> {
    /// CARootKey number the reader certificate chains to (also selects the CA key for the card side).
    pub ca_key_no: u8,
    pub curve_id: u8,
    /// Key signing Sig.A: the reader's private key, or the CA key itself when no Cert.A is sent.
    pub signer: &'a PrivKey,
    /// Cert.A: one DER certificate or parent||leaf; empty to omit.
    pub cert_chain: &'a [u8],
    pub mutual: bool,
    /// File number of the card certificate to use (mutual authentication).
    pub cert_file_no: u8,
    /// Card private key number to use (mutual authentication).
    pub priv_key_no: u8,
    pub sec_ca_key_no: u8,
    /// E.Pub.B from the FCI of ISOSelectFile: selects the single-exchange "Final" variant.
    pub epub_b: Option<&'a [u8]>,
    /// Public key to verify Sig.B with.
    pub card_pub: Option<&'a PubKey>,
    /// Alternative to `card_pub`: take the key from the returned Cert.B.
    pub cert_key: Option<CertKeyFn<'a>>,
    /// Access conditions this authentication is expected to grant (reader bookkeeping).
    pub acmap: u16,
    pub acmap2: u16,
}

impl<'a> EccAuthOptions<'a> {
    pub fn new(ca_key_no: u8, curve_id: u8, signer: &'a PrivKey) -> Self {
        EccAuthOptions {
            ca_key_no,
            curve_id,
            signer,
            cert_chain: &[],
            mutual: true,
            cert_file_no: 0,
            priv_key_no: 0,
            sec_ca_key_no: 0,
            epub_b: None,
            card_pub: None,
            cert_key: None,
            acmap: 0x3FFF,
            acmap2: 0,
        }
    }
    pub fn cert_chain(mut self, chain: &'a [u8]) -> Self {
        self.cert_chain = chain;
        self
    }
    pub fn reader_unilateral(mut self) -> Self {
        self.mutual = false;
        self
    }
    pub fn card_certificate(mut self, file_no: u8, priv_key_no: u8) -> Self {
        self.cert_file_no = file_no;
        self.priv_key_no = priv_key_no;
        self
    }
    pub fn secondary_ca_key(mut self, n: u8) -> Self {
        self.sec_ca_key_no = n;
        self
    }
    pub fn epub_b(mut self, e: &'a [u8]) -> Self {
        self.epub_b = Some(e);
        self
    }
    pub fn card_public_key(mut self, k: &'a PubKey) -> Self {
        self.card_pub = Some(k);
        self
    }
    pub fn card_key_from_cert(mut self, f: CertKeyFn<'a>) -> Self {
        self.cert_key = Some(f);
        self
    }
    pub fn access_map(mut self, acmap: u16, acmap2: u16) -> Self {
        self.acmap = acmap;
        self.acmap2 = acmap2;
        self
    }
}

/// Layout of the card's contribution in Msg.B (the data sheet shows both orders).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSigOrder {
    CertThenSig,
    SigThenCert,
    /// Could not be checked (no public key available).
    Undetermined,
    /// Reader-unilateral: the card sends no certificate.
    None,
}

#[derive(Debug, Clone)]
pub struct EccAuthResult {
    pub mutual: bool,
    /// Capabilities the card reported (OptsB content).
    pub pd_cap2: Vec<u8>,
    pub card_cert: Vec<u8>,
    pub card_sig: Vec<u8>,
    /// `Some(true)` Sig.B verified; `None` reader-unilateral or no public key to check against.
    pub card_verified: Option<bool>,
    pub order: CertSigOrder,
}

/// Outcome of ISOInternalAuthenticate.
#[derive(Debug, Clone)]
pub struct InternalAuthResult {
    pub rnd_a: Vec<u8>,
    pub rnd_b: Vec<u8>,
    pub signature: Vec<u8>,
    /// The signed message `F0F0 || OptsA || RndB || RndA`.
    pub message: Vec<u8>,
    /// Signature check against the supplied public key, if one was given.
    pub valid: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct OriginalityResult {
    pub auth: InternalAuthResult,
    /// Cert.Orig as read from file 01, if readable.
    pub certificate: Option<Vec<u8>>,
    /// The public key was taken from the certificate (rather than supplied by the caller).
    pub key_from_certificate: bool,
}

fn zero_iv_enc(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    Ok(crypto::aes_cbc_enc(key, data, &ZERO_IV)?)
}

impl<T: Transport> Card<T> {
    fn iso_auth_check(&mut self, name: &str, sw: u16) -> Result<()> {
        if sw != 0x9000 {
            self.drop_session();
            return Err(Error::Iso { command: name.into(), sw });
        }
        Ok(())
    }

    /// ECC mutual or reader-unilateral authentication (see module docs).
    pub fn authenticate_ecc(&mut self, o: &EccAuthOptions<'_>) -> Result<EccAuthResult> {
        self.drop_session();
        let final_variant = o.epub_b.is_some();
        let e = crypto::gen_key(o.curve_id)?;
        let epa = e.public().to_bytes();
        let mut v = vec![
            (if o.mutual { 0x80 } else { 0x40 }) | (if o.cert_chain.is_empty() { 0x20 } else { 0x00 }),
            0x00,
        ];
        if o.mutual {
            v.extend([o.cert_file_no, o.priv_key_no]);
        }
        let mut opts_a = vec![0x80, v.len() as u8];
        opts_a.extend(&v);
        let do_epa = tlv::encode(0x85, &epa);
        self.log_line(&format!(
            "-- ISOGeneralAuthenticate{} ({}, CARootKey {}, {} Cert.A)",
            if final_variant { "Final" } else { "" },
            if o.mutual { "mutual" } else { "reader-unilateral" },
            o.ca_key_no,
            if o.cert_chain.is_empty() { "without" } else { "with" }
        ));

        let epub_b: Vec<u8> = match o.epub_b {
            Some(b) => b.to_vec(),
            None => {
                let data = [opts_a.clone(), tlv::encode(0x7C, &do_epa)].concat();
                let (rd, sw) = self.iso_apdu(0x00, 0x87, 0x00, (o.sec_ca_key_no << 4) | o.ca_key_no, &data, Le::Short(0), false)?;
                self.iso_auth_check("ISOGeneralAuthenticate", sw)?;
                let kids = Self::parse_7c(&rd, "ISOGeneralAuthenticate")?;
                match kids.into_iter().find(|(t, _)| *t == 0x85) {
                    Some((_, k)) if k.len() == 65 => k,
                    _ => {
                        self.drop_session();
                        return Err(Error::protocol("ISOGeneralAuthenticate: unexpected response format"));
                    }
                }
            }
        };

        let shs = PubKey::from_bytes(o.curve_id, &epub_b)
            .and_then(|p| e.ecdh(&p))
            .map_err(|ex| Error::protocol(format!("card ephemeral key invalid: {ex}")))?;
        let (enc, mac) = crypto::ecc_session_keys(&shs, &epa, &epub_b)?;
        let sig_a = o.signer.sign_raw(&[&[0xE0, 0xE0][..], &opts_a, &epa, &epub_b].concat())?;
        let msg_a = [&[0xE0, 0xE0][..], o.cert_chain, &sig_a].concat();
        let do_msg = tlv::encode(0x86, &zero_iv_enc(&enc, &crypto::pad_m2(&msg_a))?);

        // Mutual: Msg.B.enc carries Cert.B and usually exceeds 256 bytes, so ask with an extended Le.
        let (rd, sw) = if final_variant {
            let data = [opts_a.clone(), tlv::encode(0x7C, &[do_epa.clone(), do_msg].concat())].concat();
            self.iso_apdu(0x00, 0x87, 0x00, o.ca_key_no, &data, Le::Short(0), o.mutual)?
        } else {
            self.iso_apdu(0x00, 0x87, 0x00, 0x00, &tlv::encode(0x7C, &do_msg), Le::Short(0), o.mutual)?
        };
        self.iso_auth_check("ISOGeneralAuthenticate part 2", sw)?;
        let kids = Self::parse_7c(&rd, "ISOGeneralAuthenticate part 2")?;
        let msg_b = match kids.into_iter().find(|(t, _)| *t == 0x82) {
            Some((_, m)) if !m.is_empty() && m.len() % 16 == 0 => m,
            _ => {
                self.drop_session();
                return Err(Error::protocol("ISOGeneralAuthenticate part 2: unexpected response format"));
            }
        };
        let pl = crypto::aes_cbc_dec(&enc, &msg_b, &ZERO_IV)?;
        if pl.len() < 3 || pl[..2] != [0xE1, 0xE1] || 3 + pl[2] as usize > pl.len() {
            self.drop_session();
            return Err(Error::protocol("Msg.B does not decrypt to 0xE1E1||OptsB - session keys differ"));
        }
        let opts_len = pl[2] as usize;
        let opts_b = pl[2..3 + opts_len].to_vec();
        let mut res = EccAuthResult {
            mutual: o.mutual,
            pd_cap2: opts_b[1..].to_vec(),
            card_cert: vec![],
            card_sig: vec![],
            card_verified: None,
            order: CertSigOrder::None,
        };
        if o.mutual {
            let body = match crypto::unpad_m2(&pl) {
                Ok(p) if p.len() >= 3 + opts_len => p[3 + opts_len..].to_vec(),
                _ => {
                    self.drop_session();
                    return Err(Error::protocol("Msg.B has invalid padding"));
                }
            };
            if body.len() < 64 {
                self.drop_session();
                return Err(Error::protocol("Msg.B carries no card signature - card did not authenticate"));
            }
            let msg = [&[0xE1, 0xE1][..], &opts_b, &epub_b, &epa].concat();
            // The data sheet gives both Cert.B||Sig.B (tables) and Sig.B||Cert.B (text): try both.
            let candidates = [
                (CertSigOrder::CertThenSig, &body[..body.len() - 64], &body[body.len() - 64..]),
                (CertSigOrder::SigThenCert, &body[64..], &body[..64]),
            ];
            let mut verified: Option<bool> = None;
            let mut matched = false;
            for (order, cert, sig) in candidates {
                let key = match (o.card_pub, o.cert_key) {
                    (Some(k), _) => Some(k.clone()),
                    (None, Some(f)) => f(cert),
                    _ => None,
                };
                let Some(key) = key else { continue };
                verified = Some(false);
                if key.verify_raw(sig, &msg) {
                    res.card_cert = cert.to_vec();
                    res.card_sig = sig.to_vec();
                    res.order = order;
                    verified = Some(true);
                    matched = true;
                    break;
                }
            }
            if verified == Some(false) {
                self.drop_session();
                return Err(Error::protocol("card signature Sig.B is INVALID - card not authenticated"));
            }
            if !matched {
                res.card_cert = body[..body.len() - 64].to_vec();
                res.card_sig = body[body.len() - 64..].to_vec();
                res.order = CertSigOrder::Undetermined;
            }
            res.card_verified = verified;
        }
        let mut s = Session::new(SessionKind::Ecc, enc, mac, [0; 4], None, o.acmap);
        s.acmap2 = o.acmap2;
        self.session = Some(s);
        Ok(res)
    }

    /// ISOSelectFile of an application configured for ISOSelectFile-integrated authentication.
    /// Returns E.Pub.B (65 bytes) from the FCI; pass it to [`EccAuthOptions::epub_b`].
    pub fn select_for_ecc_auth(&mut self, target: &IsoSelect<'_>) -> Result<Vec<u8>> {
        let (fci, _) = self.iso_select(target)?;
        Self::fci_ephemeral_key(&fci).ok_or_else(|| Error::protocol("the FCI carries no ephemeral key E.Pub.B"))
    }

    /// E.Pub.B from the FCI (tag 0x85, 65 bytes), if present.
    pub fn fci_ephemeral_key(fci: &[u8]) -> Option<Vec<u8>> {
        let i = fci.windows(2).position(|w| w == [0x85, 0x41])?;
        fci.get(i + 2..i + 67).map(|b| b.to_vec())
    }

    /// ECC card-unilateral authentication (ISOInternalAuthenticate, 7.5.7). `opts_a` is the value
    /// of the optional OptsA data object. Does not create a session.
    pub fn internal_authenticate(
        &mut self,
        priv_key_no: u8,
        public_key: Option<&PubKey>,
        opts_a: Option<&[u8]>,
    ) -> Result<InternalAuthResult> {
        let rnd_a = crypto::rnd(16);
        let opts = match opts_a {
            Some(v) => {
                let mut o = vec![0x80, v.len() as u8];
                o.extend_from_slice(v);
                o
            }
            None => vec![],
        };
        self.log_line(&format!("-- ISOInternalAuthenticate key {priv_key_no}"));
        let data = [opts.clone(), tlv::encode(0x7C, &[&[0x81, 0x10][..], &rnd_a].concat())].concat();
        let (rd, sw) = self.iso_apdu(0x00, 0x88, 0x00, priv_key_no, &data, Le::Short(0), false)?;
        if sw != 0x9000 {
            return Err(Error::Iso { command: "ISOInternalAuthenticate".into(), sw });
        }
        let kids = Self::parse_7c(&rd, "ISOInternalAuthenticate")?;
        let (rnd_b, sig) = match kids.as_slice() {
            [(0x81, b), (0x82, s)] if b.len() == 16 && s.len() == 64 => (b.clone(), s.clone()),
            _ => return Err(Error::protocol("ISOInternalAuthenticate: unexpected response format")),
        };
        let message = [&[0xF0, 0xF0][..], &opts, &rnd_b, &rnd_a].concat();
        let valid = public_key.map(|k| k.verify_raw(&sig, &message));
        Ok(InternalAuthResult { rnd_a, rnd_b, signature: sig, message, valid })
    }

    /// Originality check (7.21): card-unilateral authentication with the Priv.Orig key (KeyNo 1)
    /// at PICC level. The PICC level is selected first if needed. The public key is the one
    /// supplied, else the one `cert_key` extracts from Cert.Orig (file 01, ISO FID EF01).
    pub fn originality_check(&mut self, public_key: Option<&PubKey>, cert_key: Option<CertKeyFn<'_>>) -> Result<OriginalityResult> {
        // ISO commands are only valid while not authenticated (the card answers 6985 otherwise), so an
        // active session counts like a wrong selection: SelectApplication ends it.
        if self.session.is_some() || self.selection.primary != Some(Aid::PICC) || self.selection.secondary.is_some() {
            self.select_application(Aid::PICC, None)?;
        }
        let certificate = self.read_cert_file(0x01).ok();
        let mut from_cert = false;
        let key = match (public_key, cert_key, &certificate) {
            (Some(k), _, _) => Some(k.clone()),
            (None, Some(f), Some(c)) => {
                from_cert = true;
                f(c)
            }
            _ => None,
        };
        let auth = self.internal_authenticate(0x01, key.as_ref(), None)?;
        Ok(OriginalityResult { auth, certificate, key_from_certificate: from_cert && key.is_some() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Card side of ECC mutual authentication with a self-contained Sig.B||Cert.B or Cert.B||Sig.B.
    fn fake_card(curve: u8, card_key: PrivKey, cert: Vec<u8>, sig_first: bool, mutual: bool) -> MockTransport {
        fake_card_ex(curve, crypto::gen_key(curve).unwrap(), card_key, cert, sig_first, mutual, false)
    }

    fn fake_card_ex(
        curve: u8,
        eph: PrivKey,
        card_key: PrivKey,
        cert: Vec<u8>,
        sig_first: bool,
        mutual: bool,
        final_variant: bool,
    ) -> MockTransport {
        let epb = eph.public().to_bytes();
        let state: Rc<RefCell<Option<Vec<u8>>>> = Rc::new(RefCell::new(None));
        MockTransport::with_handler(move |apdu| {
            assert_eq!(apdu[1], 0x87);
            let (body, ext) = if apdu[4] == 0 && apdu.len() > 7 {
                let n = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
                (&apdu[7..7 + n], true)
            } else {
                (&apdu[5..5 + apdu[4] as usize], false)
            };
            assert_eq!(ext, mutual && state.borrow().is_some() || final_variant && mutual);
            // Msg.A (86 TLV) and E.Pub.A
            let (epa, msg_a) = if final_variant {
                // OptsA || 7C(85 E.Pub.A || 86 Msg.A), CA key number in P2
                assert_eq!(apdu[3], 2);
                let (_, _, p) = tlv::read(body, 0).unwrap();
                let (_, inner, _) = tlv::read(body, p).unwrap();
                let (_, epa, p2) = tlv::read(inner, 0).unwrap();
                let (_, m, _) = tlv::read(inner, p2).unwrap();
                (epa.to_vec(), m.to_vec())
            } else if state.borrow().is_none() {
                // part 1: OptsA || 7C(85 E.Pub.A)
                let (tag, _, p) = tlv::read(body, 0).unwrap();
                assert_eq!(tag, 0x80);
                let (_, inner, _) = tlv::read(body, p).unwrap();
                let (_, epa, _) = tlv::read(inner, 0).unwrap();
                *state.borrow_mut() = Some(epa.to_vec());
                let mut r = tlv::encode(0x7C, &tlv::encode(0x85, &epb));
                r.extend([0x90, 0x00]);
                return r;
            } else {
                let (_, inner, _) = tlv::read(body, 0).unwrap();
                let (_, m, _) = tlv::read(inner, 0).unwrap();
                (state.borrow().clone().unwrap(), m.to_vec())
            };
            let shs = eph.ecdh(&PubKey::from_bytes(curve, &epa).unwrap()).unwrap();
            let (enc, _mac) = crypto::ecc_session_keys(&shs, &epa, &epb).unwrap();
            let pt = crypto::unpad_m2(&crypto::aes_cbc_dec(&enc, &msg_a, &ZERO_IV).unwrap()).unwrap();
            assert_eq!(&pt[..2], &[0xE0, 0xE0]);
            let opts_b = vec![0x06, 1, 2, 3, 4, 5, 6];
            let mut plain = vec![0xE1, 0xE1];
            plain.extend(&opts_b);
            if mutual {
                let sig = card_key.sign_raw(&[&[0xE1, 0xE1][..], &opts_b, &epb, &epa].concat()).unwrap();
                if sig_first {
                    plain.extend(&sig);
                    plain.extend(&cert);
                } else {
                    plain.extend(&cert);
                    plain.extend(&sig);
                }
            }
            let mut r = tlv::encode(0x7C, &tlv::encode(0x82, &zero_iv_enc(&enc, &crypto::pad_m2(&plain)).unwrap()));
            r.extend([0x90, 0x00]);
            r
        })
    }

    #[test]
    fn final_variant_after_select() {
        let curve = crypto::CURVE_P256;
        let reader = crypto::gen_key(curve).unwrap();
        let card_key = crypto::gen_key(curve).unwrap();
        let eph = crypto::gen_key(curve).unwrap();
        let epb = eph.public().to_bytes();
        let t = fake_card_ex(curve, eph, card_key.clone(), vec![7; 30], false, true, true);
        let mut card = Card::new(t);
        let pubk = card_key.public();
        let o = EccAuthOptions::new(2, curve, &reader).card_certificate(1, 0).card_public_key(&pubk).epub_b(&epb);
        let r = card.authenticate_ecc(&o).unwrap();
        assert_eq!(r.card_verified, Some(true));
        // a single APDU was sent, extended length because the response carries Cert.B
        assert_eq!(card.transport().sent().len(), 1);
        assert_eq!(card.transport().sent()[0][4], 0);
    }

    #[test]
    fn select_for_ecc_auth_returns_epub() {
        let mut fci = vec![0x6F, 0x46, 0x85, 0x41];
        fci.extend(vec![4u8; 65]);
        fci.extend([0x90, 0x00]);
        let mut t = MockTransport::new();
        t.reply(&fci);
        let mut card = Card::new(t);
        let k = card.select_for_ecc_auth(&IsoSelect::DfName(b"DUOX")).unwrap();
        assert_eq!(k.len(), 65);
        let mut t = MockTransport::new();
        t.reply(&[0x6F, 0x00, 0x90, 0x00]);
        let mut card = Card::new(t);
        assert!(card.select_for_ecc_auth(&IsoSelect::Mf).is_err());
    }

    #[test]
    fn mutual_authentication_both_orders_both_curves() {
        for curve in [crypto::CURVE_P256, crypto::CURVE_BP256] {
            for sig_first in [false, true] {
                let reader = crypto::gen_key(curve).unwrap();
                let card_key = crypto::gen_key(curve).unwrap();
                let cert = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB];
                let t = fake_card(curve, card_key.clone(), cert.clone(), sig_first, true);
                let mut card = Card::new(t);
                let pubk = card_key.public();
                let o = EccAuthOptions::new(2, curve, &reader)
                    .cert_chain(&[1, 2, 3])
                    .card_certificate(1, 0)
                    .card_public_key(&pubk)
                    .access_map(0x0003, 0);
                let r = card.authenticate_ecc(&o).unwrap();
                assert_eq!(r.card_verified, Some(true));
                assert_eq!(r.order, if sig_first { CertSigOrder::SigThenCert } else { CertSigOrder::CertThenSig });
                assert_eq!(r.card_cert, cert);
                assert_eq!(r.pd_cap2, vec![1, 2, 3, 4, 5, 6]);
                let a = card.auth_summary().unwrap();
                assert_eq!((a.kind, a.ti, a.acmap), (super::super::AuthKind::Ecc, [0; 4], 3));
                // part 2 used extended length (mutual)
                assert_eq!(card.transport().sent()[1][4], 0);
                // part 1 header: CLA INS P1 P2 = 00 87 00 CAkey
                assert_eq!(&card.transport().sent()[0][..4], &[0, 0x87, 0, 2]);
            }
        }
    }

    #[test]
    fn cert_key_extractor_and_wrong_card_key() {
        let curve = crypto::CURVE_P256;
        let reader = crypto::gen_key(curve).unwrap();
        let card_key = crypto::gen_key(curve).unwrap();
        let other = crypto::gen_key(curve).unwrap().public();
        let kb = card_key.public();
        let extract = move |_c: &[u8]| Some(kb.clone());
        let t = fake_card(curve, card_key.clone(), vec![9; 40], false, true);
        let mut card = Card::new(t);
        let o = EccAuthOptions::new(0, curve, &reader).card_certificate(1, 0).card_key_from_cert(&extract);
        assert_eq!(card.authenticate_ecc(&o).unwrap().card_verified, Some(true));

        let t = fake_card(curve, card_key.clone(), vec![9; 40], false, true);
        let mut card = Card::new(t);
        let o = EccAuthOptions::new(0, curve, &reader).card_certificate(1, 0).card_public_key(&other);
        assert!(matches!(card.authenticate_ecc(&o), Err(Error::Protocol(_))));
        assert!(!card.is_authenticated());

        // no key at all: authenticated but unverified
        let t = fake_card(curve, card_key, vec![9; 40], false, true);
        let mut card = Card::new(t);
        let o = EccAuthOptions::new(0, curve, &reader).card_certificate(1, 0);
        let r = card.authenticate_ecc(&o).unwrap();
        assert_eq!((r.card_verified, r.order), (None, CertSigOrder::Undetermined));
    }

    #[test]
    fn reader_unilateral_and_final_variant() {
        let curve = crypto::CURVE_BP256;
        let reader = crypto::gen_key(curve).unwrap();
        let t = fake_card(curve, reader.clone(), vec![], false, false);
        let mut card = Card::new(t);
        let o = EccAuthOptions::new(1, curve, &reader).reader_unilateral();
        let r = card.authenticate_ecc(&o).unwrap();
        assert!(!r.mutual && r.card_verified.is_none());
        assert_eq!(r.order, CertSigOrder::None);
        assert!(card.is_authenticated());
        // OptsA: 80 02 40 20 (reader-unilateral, no Cert.A)
        assert_eq!(&card.transport().sent()[0][5..9], &[0x80, 0x02, 0x60, 0x00]);
    }

    #[test]
    fn internal_authenticate_verifies_signature() {
        let card_key = crypto::gen_key(crypto::CURVE_P256).unwrap();
        let kc = card_key.clone();
        let t = MockTransport::with_handler(move |apdu| {
            assert_eq!(&apdu[..4], &[0, 0x88, 0, 1]);
            let (_, inner, _) = tlv::read(&apdu[5..], 0).unwrap();
            let rnd_a = inner[2..18].to_vec();
            let rnd_b = vec![0x55; 16];
            let sig = kc.sign_raw(&[&[0xF0, 0xF0][..], &rnd_b, &rnd_a].concat()).unwrap();
            let mut r = tlv::encode(0x7C, &[tlv::encode(0x81, &rnd_b), tlv::encode(0x82, &sig)].concat());
            r.extend([0x90, 0x00]);
            r
        });
        let mut card = Card::new(t);
        let r = card.internal_authenticate(1, Some(&card_key.public()), None).unwrap();
        assert_eq!(r.valid, Some(true));
        let other = crypto::gen_key(crypto::CURVE_P256).unwrap().public();
        // the fake signs with the original key, so another public key must fail
        assert_eq!(card.internal_authenticate(1, Some(&other), None).unwrap().valid, Some(false));
        assert_eq!(card.internal_authenticate(1, None, None).unwrap().valid, None);
    }

    #[test]
    fn fci_key_extraction() {
        let mut fci = vec![0x6F, 0x50, 0x84, 0x02, 0xAA, 0xBB, 0x85, 0x41];
        fci.extend(vec![0x04; 65]);
        assert_eq!(Card::<MockTransport>::fci_ephemeral_key(&fci).unwrap().len(), 65);
        assert!(Card::<MockTransport>::fci_ephemeral_key(&[0x85, 0x41, 1, 2]).is_none());
    }
}
