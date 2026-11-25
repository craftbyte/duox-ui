//! EV charging (VDE-AR-E 2532-100): provisioning, certificate, data file, challenge.

use super::plan;
use super::report::{self, IssuerCheck};
use super::{key_chooser, read_key, token, Action, State};
use crate::shared::{DynCard, Shared};
use crate::ui::form::{FormSpec, FormValues};
use duox::card::{
    AccessRights, Aid, AppSpec, CommMode, DataFileSpec, IsoSelect, KeyPairOp, KeyPairSpec,
};
use duox::crypto::{self, PubKey};
use duox::evcert::{self, Date, EvCertificate};
use std::cell::Cell;

/// Data file 01 is written with one short APDU.
const VDE_WRITE_MAX: usize = 255;
const CURVES: [(&str, u8); 2] = [("brainpoolP256r1", crypto::CURVE_BP256), ("NIST P-256", crypto::CURVE_P256)];
const DEFAULT_KEY: &str = "00000000000000000000000000000000";

/// Everything the provisioning needs, checked before the first command.
struct Provision {
    ca_key: crypto::PrivKey,
    ca_name: String,
    ca_id: String,
    curve: u8,
    years: u16,
    uid: Vec<u8>,
    picc_key: Option<Vec<u8>>,
    app_key: Vec<u8>,
}

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Select the EV charging application by its DF name (ends any authentication).
fn select_ev(card: &mut DynCard) -> Result<(), duox::Error> {
    card.iso_select(&IsoSelect::DfName(&evcert::DF_NAME)).map(|_| ())
}

impl State {
    pub(super) fn start_ev(&mut self, a: Action, shared: &mut Shared) {
        match a {
            Action::EvProvision => self.ask_provision(shared),
            Action::EvRead => self.ev_read(shared),
            Action::EvChallenge => self.ev_challenge(shared),
            Action::EvData => {
                if let Ok(d) = shared.with_card(|c| {
                    select_ev(c)?;
                    c.vde_read_data(1)
                }) {
                    self.show(format!(
                        "VDE_ReadData file 01: first {} bytes\n{}",
                        d.len(),
                        crate::ui::hex::dump(&d).trim_end()
                    ));
                }
            }
            Action::EvWrite => shared.ask(
                FormSpec::new("VDE_WriteData")
                    .note(
                        "Written from offset 0 of data file 01, without authentication, until the file is locked. \
                         The EV charging application is selected first, which ends any authentication.",
                    )
                    .ok_text("Write")
                    .hex_len("data", "Data (hex)", "", 1, VDE_WRITE_MAX),
                token::EV_WRITE,
            ),
            Action::EvLock => shared.confirm_danger(
                "Lock the EV charging data file",
                "Free write access to data file 01 is removed permanently. VDE_WriteData is refused afterwards.",
                "Lock",
                token::EV_LOCK,
            ),
            _ => {}
        }
    }

    pub(super) fn ev_done(&mut self, tok: u32, v: &FormValues, shared: &mut Shared) {
        match tok {
            token::EV_PROVISION => self.provision(v, shared),
            token::EV_WRITE => {
                let data = v.get_hex("data").unwrap_or_default();
                let r = shared.with_card(|c| {
                    select_ev(c)?;
                    c.vde_write_data(&data)
                });
                if r.is_ok() {
                    self.show(format!("VDE_WriteData: {} bytes written to file 01.", data.len()));
                }
            }
            token::EV_LOCK => {
                let r = shared.with_card(|c| {
                    select_ev(c)?;
                    c.vde_lock()
                });
                if r.is_ok() {
                    self.show("Data file locked: VDE_WriteData is no longer accepted.");
                }
            }
            _ => {}
        }
    }

    /// Public key and name of the selected issuer, if any. Reports a damaged certificate.
    fn issuer(&self, shared: &mut Shared) -> Result<Option<(String, PubKey)>, ()> {
        let Some(ca) = self.selected_ca() else { return Ok(None) };
        let name = ca.label.clone();
        match shared.store.get(&ca.id).and_then(|e| e.public_key()) {
            Ok(k) => Ok(Some((name, k))),
            Err(e) => {
                shared.report_error(format!("The certificate of '{name}' cannot be read from the store: {e}"));
                Err(())
            }
        }
    }

    // ---------------------------------------------------------------- read and verify

    fn ev_read(&mut self, shared: &mut Shared) {
        let Ok(issuer) = self.issuer(shared) else { return };
        let Ok((blob, uid)) = shared.with_card(|c| {
            select_ev(c)?;
            let blob = c.vde_read_data(0)?;
            Ok::<_, duox::Error>((blob, c.uid().to_vec()))
        }) else {
            return;
        };
        let cert = match EvCertificate::parse(&blob) {
            Ok(c) => c,
            Err(e) => {
                self.show(format!("VDE_ReadData file 00: {} bytes\n{}", blob.len(), crate::ui::hex::dump(&blob).trim_end()));
                shared.report_error(format!("File 00 does not hold an EV charging certificate: {e}."));
                return;
            }
        };
        self.cert = blob.clone();
        let check = match &issuer {
            Some((name, key)) => IssuerCheck::Checked { name, valid: cert.verify(key) },
            None => IssuerCheck::NotChecked,
        };
        let mut lines = vec![format!("VDE_ReadData file 00: {} bytes", blob.len()), String::new()];
        lines.extend(report::certificate_report(&cert, check, &uid, Date::today_utc()));
        self.show(lines.join("\n"));
    }

    fn ev_challenge(&mut self, shared: &mut Shared) {
        let challenge = crypto::rnd(32);
        let have_cert = !self.cert.is_empty();
        let Ok((fresh, sig)) = shared.with_card(|c| {
            select_ev(c)?;
            let fresh = if have_cert { None } else { Some(c.vde_read_data(0)?) };
            let sig = c.vde_ecdsa_sign(&challenge)?;
            Ok::<_, duox::Error>((fresh, sig))
        }) else {
            return;
        };
        if let Some(blob) = fresh {
            self.cert = blob;
        }
        let key = match EvCertificate::parse(&self.cert).map_err(s).and_then(|c| c.holder_key().map_err(s)) {
            Ok(k) => k,
            Err(e) => {
                shared.report_error(format!("The card signed the challenge, but its certificate cannot be used to check it: {e}."));
                return;
            }
        };
        self.show(report::challenge_report(&challenge, &sig, key.verify_raw(&sig, &challenge)));
    }

    // ---------------------------------------------------------------- provisioning

    fn ask_provision(&mut self, shared: &mut Shared) {
        let Some(ca) = self.selected_ca() else {
            shared.report_error(
                "Create a CA on the 'CAs & certificates' tab first (the standard asks for brainpoolP256r1), then \
                 pick it as certificate issuer.",
            );
            return;
        };
        if !ca.has_key {
            shared.report_error(format!(
                "The store holds no private key for '{}', so it cannot issue the certificate. Pick a CA with a key.",
                ca.label
            ));
            return;
        }
        let ca_label = ca.label.clone();
        let (uid_known, listed) = (
            shared.card.as_ref().is_some_and(|c| !c.uid().is_empty()),
            shared.scan.as_ref().is_some_and(|s| s.applications.contains(&Aid(evcert::AID))),
        );
        if !uid_known {
            shared.report_error(
                "The UID of the card is not known yet; the certificate is issued for it. Reconnect the card and try again.",
            );
            return;
        }
        if listed {
            shared.report_error(format!(
                "Application {:06X} already exists on this card. Read and verify its certificate instead, or delete \
                 the application first.",
                evcert::AID
            ));
            return;
        }
        let curves: Vec<&str> = CURVES.iter().map(|c| c.0).collect();
        let spec = FormSpec::new("Provision the EV charging application")
            .note(format!(
                "Creates application {:06X} with the DF name of VDE-AR-E 2532-100, generates the card key pair \
                 (signing only), writes a certificate issued by '{ca_label}' to file 00, creates the 1024 byte data \
                 file 01 and enables the VDE commands. NXP ships cards with this pre-provisioned; use it on blank \
                 cards.",
                evcert::AID
            ))
            .ok_text("Provision")
            .text("ca_id", "CA identifier (14 digits)", "00000000000001")
            .combo("curve", "Curve of the card key", &curves, 0)
            .int_range("years", "Certificate validity (years)", 20, 1, 100);
        let spec = key_chooser(spec, shared, "picc", "PICC master key", "");
        let spec = spec.hint("Leave the hex field empty if creating applications is free on this card.");
        let spec = key_chooser(spec, shared, "app", "Default application key on this card", DEFAULT_KEY);
        shared.ask(spec, token::EV_PROVISION);
    }

    /// Collect and check every input before any command is sent.
    fn plan_provision(&self, v: &FormValues, shared: &mut Shared) -> Result<Provision, String> {
        let ca = self.selected_ca().ok_or("No issuer is selected.")?;
        let ca_id = v.get_str("ca_id").unwrap_or_default().trim().to_string();
        plan::check_ca_id(&ca_id)?;
        let curve = CURVES[v.get_index("curve").unwrap_or(0).min(1)].1;
        let years = v.get_int("years").unwrap_or(20) as u16;
        let picc_key = read_key(shared, v, "picc")?;
        let app_key = read_key(shared, v, "app")?.ok_or("Enter the current application key of the card.")?;
        let uid = shared.card.as_ref().map(|c| c.uid().to_vec()).unwrap_or_default();
        if uid.is_empty() {
            return Err("The UID of the card is not known yet. Reconnect the card and try again.".into());
        }
        let (ca_id_entry, ca_name) = (ca.id.clone(), ca.label.clone());
        let ca_key = shared.with_store(|st| st.key_of(&ca_id_entry)).map_err(|e| {
            format!("The key of '{ca_name}' is not available ({e}). If the store is locked, unlock it and repeat.")
        })?;
        // Dry run with a dummy holder key: catches a bad identifier or validity before the card is touched.
        let mut dummy = vec![0x04];
        dummy.extend([1u8; 64]);
        evcert::build(&ca_key, &ca_id, &uid, &dummy, curve, Date::today_utc(), years).map_err(s)?;
        Ok(Provision { ca_key, ca_name, ca_id, curve, years, uid, picc_key, app_key })
    }

    fn provision(&mut self, v: &FormValues, shared: &mut Shared) {
        let p = match self.plan_provision(v, shared) {
            Ok(p) => p,
            Err(e) => {
                // A locked store has already opened its own prompt; the sentence still explains.
                shared.report_error(e);
                return;
            }
        };
        let created = Cell::new(false);
        let outcome = shared.with_card(|card| run_provision(card, &p, &created).map_err(|e| {
            if created.get() {
                format!(
                    "{e}\nApplication {:06X} was already created and may be incomplete: look at it on the Card tab \
                     and delete it (with the PICC master key) before provisioning again.",
                    evcert::AID
                )
            } else {
                e
            }
        }));
        let Ok(blob) = outcome else { return };
        self.cert = blob.clone();
        // The application list changed: leave the session and refresh the shell's view of the card.
        let _ = shared.with_card_quiet(|c| c.select_application(Aid::PICC, None));
        shared.refresh_scan();
        let mut l = vec![format!("EV charging application provisioned (issuer '{}').", p.ca_name), String::new()];
        if let Ok(cert) = EvCertificate::parse(&blob) {
            l.extend(cert.describe());
        }
        l.push(String::new());
        l.push("The five application keys are still the default key. Change them before the card leaves you.".into());
        self.show(l.join("\n"));
    }
}

/// The card side of provisioning. `created` is set once the application exists.
fn run_provision(card: &mut DynCard, p: &Provision, created: &Cell<bool>) -> Result<Vec<u8>, String> {
    let app = Aid(evcert::AID);
    card.select_application(Aid::PICC, None).map_err(s)?;
    if let Some(k) = &p.picc_key {
        card.authenticate_ev2_first(0, k, &[]).map_err(s)?;
    }
    let spec = AppSpec::new(app)
        .key_settings(0x09)
        .keys(5)
        .iso_file_ids()
        .key_sett3(0x04)
        .iso_name(0x00DF, &evcert::DF_NAME);
    card.create_application(&spec).map_err(s)?;
    created.set(true);
    card.select_application(app, None).map_err(s)?;
    card.authenticate_ev2_first(0, &p.app_key, &[]).map_err(s)?;
    // CryptoAuthAC: free access to VDE_ECDSASign.
    card.set_configuration(0x15, &[0x02, 0x0E]).map_err(s)?;
    let key_spec = KeyPairSpec::new(0, p.curve, 0x0010, 0x0F);
    let public = card.manage_key_pair(&key_spec, &KeyPairOp::Generate, None).map_err(s)?;
    let cert = evcert::build(&p.ca_key, &p.ca_id, &p.uid, &public, p.curve, Date::today_utc(), p.years).map_err(s)?;
    card.create_data_file(
        &DataFileSpec::new(0, cert.len() as u32, AccessRights::from_u16(0xE000))
            .comm_mode(CommMode::Full)
            .iso_fid(0x00EF),
    )
    .map_err(s)?;
    card.create_data_file(&DataFileSpec::new(1, 1024, AccessRights::from_u16(0xEEEE)).iso_fid(0x01EF)).map_err(s)?;
    card.write_data(0, 0, &cert).map_err(s)?;
    // SMConfigB: enable the EV charging commands.
    card.set_configuration(0x04, &[0x00, 0x10]).map_err(s)?;
    Ok(cert)
}
