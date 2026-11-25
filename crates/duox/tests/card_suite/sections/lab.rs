//! Section `lab` (opt-in: only runs when `DUOX_SUITE_ONLY` names it): controlled experiments with raw APDUs that
//! find out why the card answers some reads unexpectedly. Every observation is written with `Ctx::detail`, so the
//! run output is the experiment log. Nothing here asserts card behaviour; a step fails only when an experiment could
//! not be carried out (setup or transport problem).
//!
//! * Part 1: SDMSIG read-out of an NDEF-style file (7.5.11.1.10, 7.12.2.1) with an ECC key in the application.
//! * Part 2: ISOReadRecord "all records from P1" on a linear and a cyclic record file (7.17.3.7), against ReadRecords.
//! * Part 3: a plain native command inside an authenticated EV2 session (7.5.10), MAC / Plain / Full files.
//!
//! `DUOX_LAB_PARTS=1,2,3` (default all) selects parts. Applications are created in the suite range and deleted.

use crate::ctx::{Ctx, Outcome, StepError, StepResult};
use duox::card::{
    build_apdu, Aid, AccessRight, AccessRights, AppSpec, ChangeKeySpec, CommMode, DataFileSpec, FileSettingsChange,
    IsoSelect, KeyPairOp, KeyPairSpec, Le, ModeSel, RecordFileSpec,
};
use duox::crypto::{self, PubKey, Session, SessionKind, CURVE_BP256, CURVE_P256, ZERO_IV};
use duox::sdm::{SdmSettings, AC_FREE, AC_NONE, OPT_CTR, OPT_ENC, OPT_UID, OPT_ASCII};
use std::time::{Duration, Instant};

pub const NAME: &str = "lab";
pub const DESCRIPTION: &str =
    "opt-in experiments with raw APDUs: SDMSIG read-out stall, ISOReadRecord 'all from P1', plain command inside an authenticated session.";

const P_SDM: u16 = 0x0020;
const FILE_SIZE: u32 = 512;
const SIG_LEN: u32 = 128;

pub fn run(ctx: &mut Ctx) {
    if ctx.dry {
        ctx.skip("lab experiments", "DRY run: the experiments need throwaway applications");
        return;
    }
    let parts = std::env::var("DUOX_LAB_PARTS").unwrap_or_else(|_| "1,2,3".into());
    let want = |n: &str| parts.split(',').any(|p| p.trim() == n);
    let mut first = true;
    let mut part = |ctx: &mut Ctx, f: &mut dyn FnMut(&mut Ctx)| {
        if !first {
            // deleted applications do not give back their blocks; only Format does
            ctx.step("lab: reclaim memory between parts (Format)", |c| {
                c.auth_picc()?;
                c.format()
            });
        }
        first = false;
        f(ctx);
    };
    if want("1") {
        part(ctx, &mut part1);
    }
    if want("2") {
        part(ctx, &mut part2);
    }
    if want("3") {
        part(ctx, &mut part3);
        part(ctx, &mut part3b);
        part(ctx, &mut part3d);
        part(ctx, &mut part3e);
    }
}

// ------------------------------------------------------------------ raw helpers
/// Provisioning is not repeatable step by step, so after a transport error the application is deleted and created
/// again before the step is run once more. The failed attempt is removed from the records (it says nothing about
/// the card) and noted on the console.
fn provision<T>(c: &mut Ctx, spec: &AppSpec, name: &str, mut f: impl FnMut(&mut Ctx) -> StepResult<T>) -> Option<T> {
    for attempt in 1..=4 {
        if let Some(v) = c.step(name, |c| f(c)) {
            return Some(v);
        }
        let transport = matches!(c.records.last(), Some(r) if matches!(&r.outcome, Outcome::Fail(m) if m.contains("communications error") || m.contains("transmit failed")));
        if !transport || attempt == 4 {
            return None;
        }
        c.records.pop();
        println!("  .. transport error while provisioning; rebuilding the application and repeating (attempt {})", attempt + 1);
        if !c.revive() {
            return None;
        }
        let aid = spec.aid;
        let _ = c.auth_picc().and_then(|_| c.delete_app_tolerant(aid)).and_then(|_| c.auth_picc()).and_then(|_| c.create_application(spec));
    }
    None
}

/// A step that survives transport errors (about 1 to 3 percent of exchanges): the card is revived and the
/// whole step is run again. Steps built with this helper establish their own state.
fn lab_step<T>(c: &mut Ctx, name: &str, mut f: impl FnMut(&mut Ctx) -> StepResult<T>) -> Option<T> {
    c.step(name, |c| retry(c, &mut f))
}

/// Run `f`; after a transport error revive the card and run it again (at most 4 attempts).
fn retry<T>(c: &mut Ctx, f: &mut impl FnMut(&mut Ctx) -> StepResult<T>) -> StepResult<T> {
    for attempt in 1..=4 {
        match f(c) {
            Err(StepError::Card(duox::Error::Transport(e))) if attempt < 4 => {
                c.detail(format!("!! transport error ({e}); card revived, repeating this experiment (attempt {})", attempt + 1));
                if !c.revive() {
                    return Err(StepError::fail("the card does not answer any more"));
                }
            }
            other => return other,
        }
    }
    Err(StepError::fail("unreachable"))
}
fn hx(d: &[u8], max: usize) -> String {
    if d.len() <= max {
        hex::encode_upper(d)
    } else {
        format!("{}..", hex::encode_upper(&d[..max]))
    }
}

fn show(d: &[u8], sw: u16) -> String {
    format!("SW {sw:04X} len {} [{}]", d.len(), hx(d, 12))
}

/// Send one APDU through the guarded raw helper and log it.
fn raw(c: &mut Ctx, label: &str, apdu: &[u8]) -> StepResult<(Vec<u8>, u16)> {
    let t0 = Instant::now();
    let (d, sw) = c.apdu_raw(apdu)?;
    c.detail(format!("{label}: {} ({} ms)", show(&d, sw), t0.elapsed().as_millis()));
    Ok((d, sw))
}

/// Native command in ISO wrapped form, one frame, Le = 0.
fn nat(c: &mut Ctx, label: &str, cmd: u8, payload: &[u8]) -> StepResult<(Vec<u8>, u16)> {
    let a = build_apdu(0x90, cmd, 0, 0, payload, Le::Short(0), false);
    raw(c, label, &a)
}

fn le3(v: u32) -> [u8; 3] {
    [v as u8, (v >> 8) as u8, (v >> 16) as u8]
}

fn read_payload(file: u8, off: u32, len: u32) -> Vec<u8> {
    let mut p = vec![file];
    p.extend(le3(off));
    p.extend(le3(len));
    p
}

/// Native SelectApplication until it is accepted. A pending additional-frame chain answers the first one with
/// COMMAND_ABORTED (91CA); that is logged because it is itself an observation.
fn reset(c: &mut Ctx, aid: Aid) -> StepResult {
    let a = build_apdu(0x90, 0x5A, 0, 0, &aid.to_bytes(), Le::Short(0), false);
    for i in 0..3 {
        let (_, sw) = c.apdu_raw(&a)?;
        if sw == 0x9100 {
            return Ok(());
        }
        c.detail(format!("  select #{i} -> {sw:04X}"));
    }
    Err(StepError::fail("could not select the application again"))
}

/// Continue a chain with plain additional-frame requests, at most `n`, logging each. Returns all data.
fn continuations(c: &mut Ctx, label: &str, mut sw: u16, n: usize, delay: Option<u64>) -> StepResult<Vec<u8>> {
    let mut all = vec![];
    let mut i = 0;
    while sw == 0x91AF && i < n {
        if let Some(ms) = delay {
            std::thread::sleep(Duration::from_millis(ms));
        }
        i += 1;
        let (d, s) = nat(c, &format!("{label} AF#{i}"), 0xAF, &[])?;
        all.extend(&d);
        sw = s;
    }
    Ok(all)
}

/// How much of `[sig, sig+128)` lies inside `data` that started at file offset `off`, and how much of that is hex.
fn sig_overlap(off: u32, data: &[u8], sig: u32) -> String {
    let (a, b) = (off.max(sig), (off + data.len() as u32).min(sig + SIG_LEN));
    if b <= a {
        return "no signature bytes".into();
    }
    let part = &data[(a - off) as usize..(b - off) as usize];
    let hexd = part.iter().filter(|x| x.is_ascii_hexdigit() && !x.is_ascii_lowercase()).count();
    format!("{} of {} signature bytes present, {} of them upper-case hex digits", part.len(), SIG_LEN, hexd)
}

// ------------------------------------------------------------------ part 1: SDMSIG
const NDEF_FID: u16 = 0xE104;

struct Sd {
    aid: Aid,
    name: Vec<u8>,
    keys: [Vec<u8>; 3],
    pubs: Vec<PubKey>,
}

/// One SDM configuration.
#[derive(Clone)]
struct V {
    name: &'static str,
    /// SDMMetaRead: AC_FREE plain, AC_NONE none, key number encrypted PICCData.
    meta: u8,
    file_read: u8,
    sig_key: u8,
    uid: Option<u32>,
    ctr: Option<u32>,
    picc: Option<u32>,
    enc: Option<(u32, u32)>,
    mac_in: u32,
    mac_off: u32,
}

impl V {
    fn base() -> V {
        V {
            name: "plain UID+ctr, SDMSIG key 0, SDMFileRead 0xF, input 0, sig @256",
            meta: AC_FREE,
            file_read: AC_NONE,
            sig_key: 0,
            uid: Some(16),
            ctr: Some(40),
            picc: None,
            enc: None,
            mac_in: 0,
            mac_off: 256,
        }
    }
    fn settings(&self) -> SdmSettings {
        let mut s = SdmSettings { meta_read: self.meta, file_read: self.file_read, file_read2: self.sig_key, ..Default::default() };
        s.options = OPT_ASCII;
        if self.uid.is_some() || self.picc.is_some() {
            s.options |= OPT_UID | OPT_CTR;
        }
        s.ctr_ret = if s.options & OPT_CTR != 0 { 0 } else { AC_NONE };
        if self.picc.is_none() {
            s.uid_offset = self.uid;
            s.ctr_offset = self.ctr;
        }
        if self.picc.is_none() && self.uid.is_none() {
            s.options &= !(OPT_UID | OPT_CTR);
            s.ctr_ret = AC_NONE;
        }
        s.picc_offset = self.picc;
        if let Some((o, l)) = self.enc {
            s.options |= OPT_ENC;
            s.enc_offset = Some(o);
            s.enc_length = Some(l);
        }
        s.mac_input_offset = Some(self.mac_in);
        s.mac_offset = Some(self.mac_off);
        s
    }
}

fn ap(c: &mut Ctx, sd: &Sd) -> StepResult {
    c.auth_app(sd.aid, 0, &sd.keys[0])
}

fn configure(c: &mut Ctx, sd: &Sd, v: &V) -> StepResult {
    let s = v.settings();
    let problems = s.validate(FILE_SIZE as usize, 7);
    if !problems.is_empty() {
        c.detail(format!("library validation problems (sent anyway): {problems:?}"));
    }
    ap(c, sd)?;
    let fs = c.get_file_settings(0)?;
    let mut ch = FileSettingsChange::new(0x40 | CommMode::Plain.bits(), fs.access);
    ch.sdm = s.encode().map_err(|e| StepError::fail(format!("sdm encode: {e}")))?;
    c.change_file_settings(0, &ch)?;
    let back = c.get_file_settings(0)?;
    c.detail(format!("configured [{}]: SDM block {}", v.name, hx(&back.sdm.clone().unwrap_or_default(), 40)));
    Ok(())
}

fn kuc(c: &mut Ctx, sd: &Sd, key: u8) -> StepResult<(u32, u32)> {
    ap(c, sd)?;
    let k = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == key).ok_or("ECC key missing")?;
    Ok((k.kuc, k.kuc_limit))
}

fn p1_setup(c: &mut Ctx, spec: &AppSpec, name: &[u8]) -> Option<Sd> {
    let aid = spec.aid;
    provision(c, spec, "lab 1: provision application, keys 1/2, ECC keys 0..3 (P-256 limit 1000, bp256, P-256 unlimited, P-256 policy 0x30), 512 byte SDM file", |c| {
        let zero = vec![0u8; 16];
        let (k1, k2) = (crypto::rnd(16), crypto::rnd(16));
        c.auth_app(aid, 0, &zero)?;
        c.change_key(&ChangeKeySpec::new(1, &k1, 1).old_key(&zero))?;
        c.change_key(&ChangeKeySpec::new(2, &k2, 2).old_key(&zero))?;
        c.auth_app(aid, 0, &zero)?;
        let specs = [
            KeyPairSpec::new(0, CURVE_P256, P_SDM, 0x30).kuc_limit(1000),
            KeyPairSpec::new(1, CURVE_BP256, P_SDM, 0x30),
            KeyPairSpec::new(2, CURVE_P256, P_SDM, 0x30),
            KeyPairSpec::new(3, CURVE_P256, P_SDM | 0x10, 0x30),
        ];
        let mut pubs = vec![];
        for s in &specs {
            match c.manage_key_pair(s, &KeyPairOp::Generate, None) {
                Ok(raw) => pubs.push(PubKey::from_bytes(s.curve_id, &raw).map_err(|e| StepError::fail(e.0))?),
                Err(e) => c.detail(format!("ECC key {} could not be created: {e}", s.key_no)),
            }
        }
        let ar = AccessRights::new(AccessRight::FREE, AccessRight::key(0), AccessRight::NEVER, AccessRight::key(0));
        c.create_data_file(&DataFileSpec::new(0, FILE_SIZE, ar).comm_mode(CommMode::Plain).sdm().iso_fid(NDEF_FID))?;
        c.write_data_with(0, 0, &vec![b'.'; FILE_SIZE as usize], ModeSel::Explicit(CommMode::Plain))?;
        c.detail(format!("{} ECC keys created", pubs.len()));
        Ok(Sd { aid, name: name.to_vec(), keys: [zero, k1, k2], pubs })
    })
}

/// One unauthenticated native ReadData experiment: fresh selection, the command, up to `cap` plain continuations, reset.
fn read_exp(c: &mut Ctx, sd: &Sd, sig: u32, label: &str, off: u32, len: u32, cap: usize) -> StepResult<Vec<u8>> {
    reset(c, sd.aid)?;
    let (d, sw) = nat(c, &format!("{label} ReadData({off},{len})"), 0xBD, &read_payload(0, off, len))?;
    let mut all = d;
    all.extend(continuations(c, label, sw, cap, None)?);
    let total_start = off;
    c.detail(format!("  => {} bytes in total from offset {total_start}: {}", all.len(), sig_overlap(total_start, &all, sig)));
    reset(c, sd.aid)?;
    Ok(all)
}

fn part1(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let name = format!("DUOXLAB{:06X}", aid.0).into_bytes();
    let spec = AppSpec::new(aid).keys(3).iso_file_ids().iso_name(0xD200 | (aid.0 & 0xFF) as u16, &name);
    let spec2 = spec.clone();
    ctx.app_scope(spec, |c, aid| {
        let _ = aid;
        let Some(sd) = p1_setup(c, &spec2, &name) else { return };
        let base = V::base();
        let ok = lab_step(c, "lab 1: configure the baseline SDMSIG file", |c| configure(c, &sd, &base));
        if ok.is_none() {
            return;
        }
        let sig = base.mac_off;
        lab_step(c, "lab 1 (baseline): whole-file read and the key usage counter", |c| {
            let before = kuc(c, &sd, 0)?;
            let all = read_exp(c, &sd, sig, "whole file", 0, 0, 8)?;
            let after = kuc(c, &sd, 0)?;
            c.detail(format!("KUC (counter, limit) before {before:?}, after {after:?}; data {}", hx(&all, 8)));
            Ok(())
        });
        // (a) signature region only, several chunk sizes
        lab_step(c, "lab 1a: read only inside [sig, sig+128) with chunk sizes 128/64/55/32/16/1", |c| {
            let before = kuc(c, &sd, 0)?;
            for cs in [128u32, 64, 55, 32, 16, 1] {
                let mut got = vec![];
                let mut o = sig;
                let mut chunks = 0;
                while o < sig + SIG_LEN && chunks < 8 {
                    let n = cs.min(sig + SIG_LEN - o);
                    let d = read_exp(c, &sd, sig, &format!("a cs={cs}"), o, n, 2)?;
                    got.extend(&d[..d.len().min(n as usize)]);
                    o += n;
                    chunks += 1;
                }
                c.detail(format!("a: chunk size {cs}: {chunks} reads, reassembled {} bytes, {}", got.len(), sig_overlap(sig, &got, sig)));
            }
            for (o, n) in [(sig + 10, 50u32), (sig + 100, 28), (sig - 4, 8), (sig, 1)] {
                read_exp(c, &sd, sig, "a-offset", o, n, 2)?;
            }
            let after = kuc(c, &sd, 0)?;
            c.detail(format!("KUC before {before:?} after {after:?}"));
            Ok(())
        });
        lab_step(c, "lab 1b: reads that end before the signature, and exactly at its first byte", |c| {
            for (o, n) in [(0u32, 256u32), (0, 255), (0, 257), (0, 200), (100, 156), (0, 0)] {
                read_exp(c, &sd, sig, "b", o, n, 2)?;
            }
            Ok(())
        });
        lab_step(c, "lab 1c: reads entirely behind the signature, and one covering its last byte", |c| {
            for (o, n) in [(384u32, 128u32), (384, 100), (400, 112), (383, 129), (384, 0)] {
                read_exp(c, &sd, sig, "c", o, n, 2)?;
            }
            Ok(())
        });
        lab_step(c, "lab 1d: ISOReadBinary (00 B0) variants incl. reads covering the signature", |c| {
            for how in ["name", "fid"] {
                c.select_application(Aid::PICC, None)?;
                if how == "name" {
                    c.iso_select(&IsoSelect::DfName(&sd.name))?;
                } else {
                    c.iso_select(&IsoSelect::FileId(0xD200 | (sd.aid.0 & 0xFF) as u16))?;
                }
                c.iso_select(&IsoSelect::EfUnderCurrent(NDEF_FID))?;
                c.detail(format!("d: EF selected via DF {how}"));
                let cases: Vec<(&str, Vec<u8>)> = vec![
                    ("off 0 Le 00", vec![0x00, 0xB0, 0, 0, 0x00]),
                    ("off 0 Le FF", vec![0x00, 0xB0, 0, 0, 0xFF]),
                    ("off 0 Le 80", vec![0x00, 0xB0, 0, 0, 0x80]),
                    ("off 255 Le FF (covers sig)", vec![0x00, 0xB0, 0x00, 0xFF, 0xFF]),
                    ("off 256 Le 80 (sig only)", vec![0x00, 0xB0, 0x01, 0x00, 0x80]),
                    ("off 256 Le 40", vec![0x00, 0xB0, 0x01, 0x00, 0x40]),
                    ("off 320 Le 40", vec![0x00, 0xB0, 0x01, 0x40, 0x40]),
                    ("off 300 Le 10", vec![0x00, 0xB0, 0x01, 0x2C, 0x10]),
                    ("off 384 Le 80", vec![0x00, 0xB0, 0x01, 0x80, 0x80]),
                    ("off 256 Le 00", vec![0x00, 0xB0, 0x01, 0x00, 0x00]),
                    ("off 0 ext Le 00 00 00", vec![0x00, 0xB0, 0, 0, 0, 0, 0]),
                    ("off 256 ext Le 00 00 80", vec![0x00, 0xB0, 0x01, 0x00, 0, 0, 0x80]),
                    ("SFI 4 off 0 Le FF", vec![0x00, 0xB0, 0x84, 0x00, 0xFF]),
                    ("SFI 4 off 200 Le FF", vec![0x00, 0xB0, 0x84, 0xC8, 0xFF]),
                    ("SFI 4 off 128 Le 80", vec![0x00, 0xB0, 0x84, 0x80, 0x80]),
                ];
                for (l, a) in cases {
                    // each case in a fresh ISO selection (a failing read may end it)
                    let (d, sw) = raw(c, &format!("d[{how}] {l}"), &a)?;
                    let mut all = d;
                    if sw == 0x91AF {
                        all.extend(continuations(c, l, sw, 2, None)?);
                    }
                    let off0 = if a[2] & 0x80 != 0 { u32::from(a[3]) } else { u32::from(a[2]) << 8 | u32::from(a[3]) };
                    c.detail(format!("  => {} bytes, {}", all.len(), sig_overlap(off0, &all, sig)));
                    reset(c, sd.aid)?;
                    c.select_application(Aid::PICC, None)?;
                    c.iso_select(&IsoSelect::DfName(&sd.name))?;
                    c.iso_select(&IsoSelect::EfUnderCurrent(NDEF_FID))?;
                }
            }
            Ok(())
        });
        lab_step(c, "lab 1e: ReadData as extended-length APDUs (3 byte Lc, 2 or 3 byte Le)", |c| {
            for (o, n) in [(0u32, 0u32), (256, 128), (0, 300), (384, 128)] {
                reset(c, sd.aid)?;
                let p = read_payload(0, o, n);
                for (l, le) in [("Le 00 00", vec![0u8, 0]), ("Le 01 00", vec![1, 0]), ("no Le", vec![])] {
                    let mut a = vec![0x90, 0xBD, 0, 0, 0, 0, p.len() as u8];
                    a.extend(&p);
                    a.extend(le);
                    let (d, sw) = raw(c, &format!("e ext ReadData({o},{n}) {l}"), &a)?;
                    let mut all = d;
                    if sw == 0x91AF {
                        all.extend(continuations(c, "e", sw, 2, None)?);
                    }
                    c.detail(format!("  => {} bytes, {}", all.len(), sig_overlap(o, &all, sig)));
                    reset(c, sd.aid)?;
                }
            }
            Ok(())
        });
        lab_step(c, "lab 1f: delays between additional-frame requests (0, 20, 200, 1000, 3000 ms), each continuation logged", |c| {
            for ms in [0u64, 20, 200, 1000, 3000] {
                reset(c, sd.aid)?;
                let (d, sw) = nat(c, &format!("f delay {ms} ms ReadData(0,0)"), 0xBD, &read_payload(0, 0, 0))?;
                let more = continuations(c, &format!("f{ms}"), sw, 4, Some(ms))?;
                c.detail(format!("  => first frame {} bytes, continuations {} bytes", d.len(), more.len()));
                reset(c, sd.aid)?;
            }
            // delay before the very first continuation of a read that starts inside the signature
            reset(c, sd.aid)?;
            let (d, sw) = nat(c, "f ReadData(256,128)", 0xBD, &read_payload(0, sig, SIG_LEN))?;
            let more = continuations(c, "f-sig", sw, 3, Some(500))?;
            c.detail(format!("  => {} + {} bytes", d.len(), more.len()));
            reset(c, sd.aid)?;
            Ok(())
        });
        lab_step(c, "lab 1g: continuation APDU variants after a whole-file read", |c| {
            let variants: Vec<(&str, Vec<u8>)> = vec![
                ("Le 00", vec![0x90, 0xAF, 0, 0, 0x00]),
                ("Le FF", vec![0x90, 0xAF, 0, 0, 0xFF]),
                ("no Le", vec![0x90, 0xAF, 0, 0]),
                ("Lc 00 Le 00", vec![0x90, 0xAF, 0, 0, 0x00, 0x00]),
                ("ext Lc 0 Le 0", vec![0x90, 0xAF, 0, 0, 0, 0, 0]),
                ("Lc 1 data 00 Le 00", vec![0x90, 0xAF, 0, 0, 1, 0, 0]),
                ("Lc 1 data 00 no Le", vec![0x90, 0xAF, 0, 0, 1, 0]),
            ];
            for (l, a) in variants {
                reset(c, sd.aid)?;
                let (_, sw) = nat(c, &format!("g first frame ({l})"), 0xBD, &read_payload(0, 0, 0))?;
                if sw != 0x91AF {
                    c.detail("  (no additional frame requested)");
                    continue;
                }
                for i in 0..2 {
                    raw(c, &format!("g continuation {i} {l}"), &a)?;
                }
                reset(c, sd.aid)?;
            }
            Ok(())
        });
        // (h) key usage counter and key variants
        lab_step(c, "lab 1h: KUC around failed whole-file reads and chunked reads, per key (P-256 limit, bp256, P-256 unlimited, policy 0x30)", |c| {
            for k in 0..sd.pubs.len() as u8 {
                let mut v = base.clone();
                v.sig_key = k;
                v.name = "key variant";
                if configure(c, &sd, &v).is_err() {
                    c.detail(format!("h: key {k}: configuring SDMSIG failed"));
                    continue;
                }
                let b0 = kuc(c, &sd, k)?;
                read_exp(c, &sd, sig, &format!("h key {k} whole"), 0, 0, 2)?;
                let b1 = kuc(c, &sd, k)?;
                read_exp(c, &sd, sig, &format!("h key {k} sig-only"), sig, SIG_LEN, 2)?;
                let b2 = kuc(c, &sd, k)?;
                read_exp(c, &sd, sig, &format!("h key {k} 96-byte reads"), 0, 96, 1)?;
                read_exp(c, &sd, sig, &format!("h key {k} 96-byte reads"), 96, 96, 1)?;
                let b3 = kuc(c, &sd, k)?;
                c.detail(format!("h: key {k} KUC (count, limit): start {b0:?}, after whole read {b1:?}, after sig-only read {b2:?}, after two 96-byte reads {b3:?}"));
            }
            Ok(())
        });
        // (i) SDM variants
        let variants = vec![
            V { name: "sig only (no UID/counter), sig @256", meta: AC_NONE, uid: None, ctr: None, ..V::base() },
            V { name: "signature at the far end (@384)", mac_off: 384, ..V::base() },
            V { name: "SDMMACInputOffset 16 (later start)", mac_in: 16, ..V::base() },
            V { name: "sig @128, input 0", mac_off: 128, ..V::base() },
            V { name: "encrypted PICCData (key 2) @16, sig key 0 @256", meta: 2, uid: None, ctr: None, picc: Some(16), ..V::base() },
            V {
                name: "Table 45 row: SDMFileRead key 1 + ENC (plain UID/ctr, enc @64 len 32), sig key 0 @256",
                file_read: 1,
                enc: Some((64, 32)),
                ..V::base()
            },
            V {
                name: "Table 45 row: encrypted PICCData key 2 + SDMFileRead key 1 + ENC @64 len 32, sig key 0 @256",
                meta: 2,
                file_read: 1,
                uid: None,
                ctr: None,
                picc: Some(16),
                enc: Some((64, 32)),
                ..V::base()
            },
            V { name: "bp256 key 1, sig @256", sig_key: 1, ..V::base() },
            V { name: "control: SDMMAC (key 1, no sig), plain UID/ctr, mac @256", file_read: 1, sig_key: AC_NONE, ..V::base() },
        ];
        for v in variants {
            let sig = v.mac_off;
            let is_sig = v.sig_key != AC_NONE;
            lab_step(c, &format!("lab 1i/k: {}", v.name), |c| {
                configure(c, &sd, &v)?;
                let region = if is_sig { SIG_LEN } else { 16 };
                let k = v.sig_key;
                let before = if is_sig { Some(kuc(c, &sd, k)?) } else { None };
                read_exp(c, &sd, sig, "whole", 0, 0, 8)?;
                read_exp(c, &sd, sig, "mac/sig region only", sig, region, 2)?;
                read_exp(c, &sd, sig, "0..sigOff", 0, sig, 2)?;
                read_exp(c, &sd, sig, "after region", sig + region, FILE_SIZE - sig - region, 2)?;
                if let Some(b) = before {
                    let a = kuc(c, &sd, k)?;
                    c.detail(format!("KUC before {b:?}, after {a:?}"));
                }
                Ok(())
            });
        }
        // (j) authenticated reads
        lab_step(c, "lab 1j: the same file read after authentication, comm mode Plain, MAC and Full, with SDM enabled and then disabled", |c| {
            let v = V::base();
            configure(c, &sd, &v)?;
            let reads: [(u32, u32); 7] = [(0, 16), (0, 57), (0, 64), (0, 128), (0, 0), (256, 128), (384, 128)];
            for (label, opt) in [("Plain", CommMode::Plain), ("MAC", CommMode::Mac), ("Full", CommMode::Full)] {
                for sdm_on in [true, false] {
                    if opt == CommMode::Plain && !sdm_on {
                        continue;
                    }
                    ap(c, &sd)?;
                    let fs = c.get_file_settings(0)?;
                    let mut ch = FileSettingsChange::new(if sdm_on { 0x40 } else { 0 } | opt.bits(), fs.access);
                    if sdm_on {
                        ch.sdm = v.settings().encode().map_err(|e| StepError::fail(e.to_string()))?;
                    }
                    if let Err(e) = c.change_file_settings(0, &ch) {
                        c.detail(format!("j: switching the file to {label}, SDM {sdm_on}: refused: {e}"));
                        continue;
                    }
                    ap(c, &sd)?;
                    let fs = c.get_file_settings(0)?;
                    c.detail(format!("j: file now option {:02X} (mode {label}, SDM {sdm_on}), SDM block {}", fs.option, hx(&fs.sdm.clone().unwrap_or_default(), 24)));
                    if opt != CommMode::Plain {
                        for (o, n) in [(0u32, 16u32), (0, 0)] {
                            ap(c, &sd)?;
                            match c.read_data_with(0, o, n, ModeSel::Explicit(CommMode::Plain)) {
                                Ok(d) => c.detail(format!("j {label} sdm={sdm_on} authenticated PLAIN ReadData({o},{n}): {} bytes", d.len())),
                                Err(e) => c.detail(format!("j {label} sdm={sdm_on} authenticated PLAIN ReadData({o},{n}) FAILED: {e}")),
                            }
                        }
                        c.select_application(sd.aid, None)?;
                        match c.read_data_with(0, 0, 16, ModeSel::Explicit(CommMode::Plain)) {
                            Ok(d) => c.detail(format!("j {label} sdm={sdm_on} unauthenticated ReadData(0,16): {} bytes", d.len())),
                            Err(e) => c.detail(format!("j {label} sdm={sdm_on} unauthenticated ReadData(0,16) FAILED: {e}")),
                        }
                    }
                    for (o, n) in reads {
                        ap(c, &sd)?;
                        match c.read_data_with(0, o, n, ModeSel::Explicit(opt)) {
                            Ok(d) => c.detail(format!("j {label} sdm={sdm_on} ReadData({o},{n}): {} bytes, all static dots? {}", d.len(), d.iter().all(|b| *b == b'.'))),
                            Err(e) => c.detail(format!("j {label} sdm={sdm_on} ReadData({o},{n}) FAILED: {e}")),
                        }
                    }
                }
            }
            Ok(())
        });
        // 1l / 1m / 1n: what does work
        lab_step(c, "lab 1l: configure the baseline again; ISOReadBinary of the whole file (extended Le) verifies as an SDMSIG", |c| {
            let v = V::base();
            configure(c, &sd, &v)?;
            let b = kuc(c, &sd, 0)?;
            iso_enter(c, &sd)?;
            let (d, sw) = raw(c, "ISOReadBinary(0, ext Le 0)", &[0x00, 0xB0, 0, 0, 0, 0, 0])?;
            verify_file(c, &sd, &v, &d, sw, "ISOReadBinary whole file");
            let a = kuc(c, &sd, 0)?;
            c.detail(format!("KUC before {b:?}, after one whole-file ISOReadBinary {a:?}"));
            Ok(())
        });
        lab_step(c, "lab 1m: native ReadData with command code 0xAD (ISO 14443-4 chaining variant), ISO wrapped, several Le forms", |c| {
            let v = V::base();
            configure(c, &sd, &v)?;
            let b = kuc(c, &sd, 0)?;
            for (o, n) in [(0u32, 0u32), (256, 128), (256, 64), (320, 64), (0, 256), (255, 255), (0, 300), (384, 128)] {
                for (l, ext) in [("Le 00", false), ("ext Le 00 00", true)] {
                    reset(c, sd.aid)?;
                    let a = read_ad(o, n, ext);
                    let (d, sw) = raw(c, &format!("ReadData 0xAD({o},{n}) {l}"), &a)?;
                    let mut all = d;
                    if sw == 0x91AF {
                        all.extend(continuations(c, "0xAD", sw, 6, None)?);
                    }
                    c.detail(format!("  => {} bytes, {}", all.len(), sig_overlap(o, &all, v.mac_off)));
                    if (o == 0 && n == 0) || (o == 0 && n == 300) {
                        verify_file(c, &sd, &v, &all, sw, "0xAD whole file");
                    }
                    reset(c, sd.aid)?;
                }
            }
            let a = kuc(c, &sd, 0)?;
            c.detail(format!("KUC before {b:?}, after {a:?}"));
            Ok(())
        });
        for kind in ["ISOReadBinary", "ReadData 0xAD"] {
            for cs in [128u32, 64, 55, 32, 16, 1] {
                lab_step(c, &format!("lab 1n: {kind}, consecutive chunked reads of the signature region with chunk size {cs}: reassembled file verifies?"), |c| {
                    let v = V::base();
                    configure(c, &sd, &v)?;
                    let mut pieces: Vec<(u32, u32)> = vec![(0, 256)];
                    let mut o = 256;
                    while o < 384 {
                        let n = cs.min(384 - o);
                        pieces.push((o, n));
                        o += n;
                    }
                    pieces.push((384, 128));
                    let b = kuc(c, &sd, 0)?;
                    reset(c, sd.aid)?;
                    if kind == "ISOReadBinary" {
                        iso_enter(c, &sd)?;
                    }
                    let mut file = vec![];
                    let mut bad = None;
                    for (o, n) in &pieces {
                        let a = if kind == "ISOReadBinary" {
                            vec![0x00, 0xB0, (*o >> 8) as u8, *o as u8, if *n >= 256 { 0 } else { *n as u8 }]
                        } else {
                            read_ad(*o, *n, false)
                        };
                        let (d, sw) = c.apdu_raw(&a)?;
                        if (sw != 0x9000 && sw != 0x9100) || d.len() != *n as usize {
                            bad = Some(format!("piece ({o},{n}) answered {}", show(&d, sw)));
                            break;
                        }
                        file.extend(d);
                    }
                    match bad {
                        Some(m) => c.detail(format!("1n {kind} cs={cs}: {m}")),
                        None => verify_file(c, &sd, &v, &file, 0x9000, &format!("1n {kind} cs={cs} ({} reads)", pieces.len())),
                    }
                    reset(c, sd.aid)?;
                    let a = kuc(c, &sd, 0)?;
                    c.detail(format!("  KUC before {b:?}, after {a:?}"));
                    Ok(())
                });
            }
        }
    });
}

fn iso_enter(c: &mut Ctx, sd: &Sd) -> StepResult {
    c.select_application(Aid::PICC, None)?;
    c.iso_select(&IsoSelect::DfName(&sd.name))?;
    c.iso_select(&IsoSelect::EfUnderCurrent(NDEF_FID))?;
    Ok(())
}

/// ReadData with command code 0xAD of file 0, ISO wrapped.
fn read_ad(off: u32, len: u32, ext: bool) -> Vec<u8> {
    let p = read_payload(0, off, len);
    let mut a = vec![0x90, 0xAD, 0, 0];
    if ext {
        a.extend([0, 0, p.len() as u8]);
        a.extend(&p);
        a.extend([0, 0]);
    } else {
        a.push(p.len() as u8);
        a.extend(&p);
        a.push(0);
    }
    a
}

/// Verify a whole-file read-out against the SDM settings and the application's public key.
fn verify_file(c: &mut Ctx, sd: &Sd, v: &V, file: &[u8], sw: u16, what: &str) {
    if file.len() != FILE_SIZE as usize {
        c.detail(format!("  verify {what}: not the whole file ({} bytes, SW {sw:04X})", file.len()));
        return;
    }
    let uid = c.uid.clone();
    let p = duox::sdm::VerifyParams { uid_len: uid.len(), meta_key: None, file_key: None, sig_pub: sd.pubs.get(v.sig_key as usize), uid: Some(&uid), last_ctr: None };
    match duox::sdm::verify(file, &v.settings(), &p) {
        Ok(r) => c.detail(format!("  verify {what}: sig_ok {:?}, ctr {:?}, uid ok {}", r.sig_ok, r.ctr, r.uid.as_deref() == Some(&uid[..]))),
        Err(e) => c.detail(format!("  verify {what}: error {e}")),
    }
}

// ------------------------------------------------------------------ part 2: ISOReadRecord
const F_LIN: u16 = 0xE102;
const F_CYC: u16 = 0xE103;
const F_LIN_MAC: u16 = 0xE104;
const F_LIN_FULL: u16 = 0xE105;
const F_LIN4: u16 = 0xE106;

fn rec(tag: u8, n: u8) -> Vec<u8> {
    (0..16u8).map(|i| tag.wrapping_add(n << 4).wrapping_add(i)).collect()
}

fn part2(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let name = format!("DUOXLAB{:06X}", aid.0).into_bytes();
    let spec = AppSpec::new(aid).keys(2).iso_file_ids().iso_name(0xD300 | (aid.0 & 0xFF) as u16, &name);
    let spec2 = spec.clone();
    ctx.app_scope(spec, |c, aid| {
        let ok = provision(c, &spec2, "lab 2: provision linear (file 1), cyclic (file 2), MAC and Full linear record files; append 4 records each", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let (free, k0) = (AccessRight::FREE, AccessRight::key(0));
            let ar = AccessRights::new(free, free, free, k0);
            let ar_k = AccessRights::new(free, k0, k0, k0);
            c.create_record_file(&RecordFileSpec::new(1, ar, 16, 6).comm_mode(CommMode::Plain).iso_fid(F_LIN))?;
            c.create_record_file(&RecordFileSpec::new(2, ar, 16, 4).cyclic().comm_mode(CommMode::Plain).iso_fid(F_CYC))?;
            c.create_record_file(&RecordFileSpec::new(3, ar_k, 16, 6).comm_mode(CommMode::Mac).iso_fid(F_LIN_MAC))?;
            c.create_record_file(&RecordFileSpec::new(4, ar_k, 16, 6).comm_mode(CommMode::Full).iso_fid(F_LIN_FULL))?;
            c.create_record_file(&RecordFileSpec::new(5, ar, 16, 4).comm_mode(CommMode::Plain).iso_fid(F_LIN4))?;
            c.select_application(Aid::PICC, None)?;
            c.iso_select(&IsoSelect::DfName(&name))?;
            for n in 1..=4u8 {
                c.iso_append_record(&rec(0x10, n), (F_LIN4 & 0x1F) as u8)?;
                c.iso_append_record(&rec(0x10, n), (F_LIN & 0x1F) as u8)?;
                c.iso_append_record(&rec(0x80, n), (F_CYC & 0x1F) as u8)?;
            }
            // MAC / Full files: authenticated native writes
            c.auth_app(aid, 0, &z)?;
            for n in 1..=3u8 {
                c.write_record_with(3, 0, &rec(0x30, n), ModeSel::Explicit(CommMode::Mac))?;
                c.write_record_with(4, 0, &rec(0x40, n), ModeSel::Explicit(CommMode::Full))?;
                c.commit_transaction(false, CommMode::Mac)?;
            }
            Ok(())
        });
        if ok.is_none() {
            return;
        }
        let files: [(&str, u16, u8, u8, usize); 5] = [("linear", F_LIN, 1, 0x10, 4), ("linear full (max 4, 4 records)", F_LIN4, 5, 0x10, 4), ("cyclic", F_CYC, 2, 0x80, 3), ("linear MAC-mode", F_LIN_MAC, 3, 0x30, 3), ("linear Full-mode", F_LIN_FULL, 4, 0x40, 3)];
        for (lbl, fid, fno, tag, count) in files {
            let sfi = (fid & 0x1F) as u8;
            lab_step(c, &format!("lab 2: {lbl} file (SFI {sfi}, {count} records): native ReadRecords reference (unauthenticated)"), |c| {
                reset(c, aid)?;
                for (r, n) in [(0u32, 0u32), (1, 0), (1, 1), (2, 0), (1, 2), (3, 1)] {
                    let (d, sw) = nat(c, &format!("native ReadRecords(rec {r}, count {n})"), 0xBB, &read_payload(fno, r, n))?;
                    let mut all = d;
                    if sw == 0x91AF {
                        all.extend(continuations(c, "native", sw, 4, None)?);
                    }
                    c.detail(format!("  => {} bytes, first byte {:02X?}", all.len(), all.first()));
                    reset(c, aid)?;
                }
                Ok(())
            });
            lab_step(c, &format!("lab 2: {lbl} file: ISOReadRecord matrix (P1, P2 form, Le form)"), |c| {
                let _ = tag;
                // selection variants: DF only (SFI in P2), EF selected (SFI 0 in P2)
                for sel in ["DF + SFI in P2", "EF selected + SFI 0"] {
                    let enter = |c: &mut Ctx| -> StepResult {
                        c.select_application(Aid::PICC, None)?;
                        c.iso_select(&IsoSelect::DfName(&name))?;
                        if sel.starts_with("EF") {
                            c.iso_select(&IsoSelect::EfUnderCurrent(fid))?;
                        }
                        Ok(())
                    };
                    let s = if sel.starts_with("EF") { 0 } else { sfi };
                    for p1 in [1u8, 2, 3, 0] {
                        for low in [0b101u8, 0b110, 0b100] {
                            let p2 = (s << 3) | low;
                            let lens: [(&str, Vec<u8>); 8] = [
                                ("Le 00", vec![0x00]),
                                ("Le FF", vec![0xFF]),
                                ("Le 10", vec![0x10]),
                                ("Le 20", vec![0x20]),
                                ("Le 30", vec![0x30]),
                                ("Le 40", vec![0x40]),
                                ("no Le", vec![]),
                                ("ext Le 00 00 00", vec![0, 0, 0]),
                            ];
                            for (ll, le) in lens {
                                if low != 0b101 && !(["Le 00", "no Le"].contains(&ll)) {
                                    continue; // the other P2 forms only with two Le variants
                                }
                                if p1 == 0 && low != 0b101 {
                                    continue;
                                }
                                retry(c, &mut |c: &mut Ctx| -> StepResult {
                                    enter(c)?;
                                    let mut a = vec![0x00, 0xB2, p1, p2];
                                    a.extend(le.clone());
                                    let (d, sw) = raw(c, &format!("{sel} P1={p1} P2={p2:02X} {ll}"), &a)?;
                                    let mut all = d;
                                    if sw == 0x91AF || sw >> 8 == 0x61 {
                                        c.detail(format!("  (status {sw:04X}: trying continuation)"));
                                        if sw == 0x91AF {
                                            all.extend(continuations(c, "iso rec", sw, 4, None)?);
                                        } else {
                                            let (d2, sw2) = raw(c, "  GET RESPONSE", &[0x00, 0xC0, 0, 0, (sw & 0xFF) as u8])?;
                                            c.detail(format!("  GET RESPONSE SW {sw2:04X}"));
                                            all.extend(d2);
                                        }
                                    }
                                    c.detail(format!("  => {} bytes ({} record(s))", all.len(), all.len() / 16));
                                    reset(c, aid)?;
                                    Ok(())
                                })?;
                            }
                        }
                    }
                }
                Ok(())
            });
        }
        // the cyclic file after n appends: does "all records from P1" depend on where the ring wrapped?
        lab_step(c, "lab 2w: cyclic file after 1..9 more appends: ISOReadRecord all-from-P1 (P1 = 1, 2, 3, Le 00) against ReadRecords", |c| {
            let cyc_sfi = (F_CYC & 0x1F) as u8;
            for n in 5..=13u8 {
                c.select_application(Aid::PICC, None)?;
                c.iso_select(&IsoSelect::DfName(&name))?;
                c.iso_append_record(&rec(0x80, n), cyc_sfi)?;
                let mut line = format!("after append #{n} (newest tag {:02X}):", rec(0x80, n)[0]);
                for p1 in [1u8, 2, 3] {
                    reset(c, aid)?;
                    c.select_application(Aid::PICC, None)?;
                    c.iso_select(&IsoSelect::DfName(&name))?;
                    let (d, sw) = c.apdu_raw(&[0x00, 0xB2, p1, (cyc_sfi << 3) | 5, 0x00])?;
                    let tags: Vec<String> = d.chunks(16).map(|r| format!("{:02X}", r[0])).collect();
                    line.push_str(&format!("  P1={p1}: SW {sw:04X} {} rec {:?};", d.len() / 16, tags));
                }
                reset(c, aid)?;
                let (d, sw) = c.apdu_raw(&build_apdu(0x90, 0xBB, 0, 0, &read_payload(2, 0, 0), Le::Short(0), false))?;
                let tags: Vec<String> = d.chunks(16).map(|r| format!("{:02X}", r[0])).collect();
                line.push_str(&format!("  native ReadRecords(0,0): SW {sw:04X} {tags:?}"));
                c.detail(line);
            }
            Ok(())
        });
        lab_step(c, "lab 2: the same, one record at a time, for the linear file (records 1..4 individually, Le 00)", |c| {
            for r in 1..=5u8 {
                reset(c, aid)?;
                c.select_application(Aid::PICC, None)?;
                c.iso_select(&IsoSelect::DfName(&name))?;
                let (d, _) = raw(c, &format!("record {r}"), &[0x00, 0xB2, r, ((F_LIN & 0x1F) as u8) << 3 | 4, 0x00])?;
                let _ = d;
                reset(c, aid)?;
            }
            Ok(())
        });
    });
}

// ------------------------------------------------------------------ part 3: plain command in an authenticated session
fn lab_auth(c: &mut Ctx, key_no: u8, key: &[u8]) -> StepResult<Session> {
    let (d, sw) = nat(c, "auth part 1", 0x71, &[key_no, 0x00])?;
    if sw != 0x91AF || d.len() != 16 {
        return Err(StepError::fail(format!("authentication part 1: {sw:04X}")));
    }
    fn cr<T>(r: Result<T, crypto::CryptoError>) -> StepResult<T> {
        r.map_err(|e| StepError::fail(e.0))
    }
    let rnd_b = cr(crypto::aes_cbc_dec(key, &d, &ZERO_IV))?;
    let rnd_a = crypto::rnd(16);
    let enc = cr(crypto::aes_cbc_enc(key, &[rnd_a.clone(), crypto::rotl(&rnd_b)].concat(), &ZERO_IV))?;
    let (d2, sw2) = nat(c, "auth part 2", 0xAF, &enc)?;
    if sw2 != 0x9100 || d2.len() != 32 {
        return Err(StepError::fail(format!("authentication part 2: {sw2:04X}")));
    }
    let pt = cr(crypto::aes_cbc_dec(key, &d2, &ZERO_IV))?;
    let (e, m) = cr(crypto::ev2_session_keys(key, &rnd_a, &rnd_b))?;
    Ok(Session::new(SessionKind::Aes, e, m, [pt[0], pt[1], pt[2], pt[3]], Some(key_no), 0))
}

/// Native command with a command MAC for the counter `ctr` (the session keeps its own).
fn mac_cmd(c: &mut Ctx, s: &Session, label: &str, cmd: u8, body: &[u8], ctr: u16, mac_len: usize, flip: bool) -> StepResult<(Vec<u8>, u16)> {
    let mut t = s.clone();
    t.ctr = ctr;
    let mut mac = t.mac_cmd(cmd, body).map_err(|e| StepError::fail(e.0))?;
    if flip {
        mac[7] ^= 0x01;
    }
    mac.truncate(mac_len);
    nat(c, label, cmd, &[body.to_vec(), mac].concat())
}

fn part3(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let spec = AppSpec::new(aid).keys(1);
    let spec2 = spec.clone();
    ctx.app_scope(spec, |c, aid| {
        let ok = provision(c, &spec2, "lab 3: provision a MAC, a Plain and a Full StandardData file (256 bytes, patterned)", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let k0 = AccessRight::key(0);
            let ar = AccessRights::new(k0, k0, k0, k0);
            let free = AccessRight::FREE;
            let ar_rf = AccessRights::new(free, k0, k0, k0);
            let ar_all = AccessRights::new(free, free, free, k0);
            let table = [
                (0u8, CommMode::Mac, ar, CommMode::Mac),
                (1, CommMode::Plain, ar, CommMode::Plain),
                (2, CommMode::Full, ar, CommMode::Full),
                (3, CommMode::Mac, ar_rf, CommMode::Mac),
                (4, CommMode::Full, ar_rf, CommMode::Full),
                (5, CommMode::Mac, ar_all, CommMode::Plain),
            ];
            for (n, m, a, wm) in table {
                c.create_data_file(&DataFileSpec::new(n, 256, a).comm_mode(m))?;
                let data: Vec<u8> = (0..=255u8).collect();
                c.write_data_with(n, 0, &data, ModeSel::Explicit(wm))?;
            }
            Ok(())
        });
        if ok.is_none() {
            return;
        }
        let z = c.zero_key.to_vec();
        for (fno, fmode) in [(0u8, "MAC (key 0)"), (1, "Plain (key 0)"), (2, "Full (key 0)"), (3, "MAC (read free)"), (4, "Full (read free)"), (5, "MAC (all free)")] {
            #[derive(Clone, Copy)]
            enum K {
                PlainCmd,
                Mac,
                MacTrunc4,
                MacWrong,
                MacCtrPlus1,
                MacExtraByte,
            }
            let variants: [(&str, K, u32); 12] = [
                ("plain len 0", K::PlainCmd, 0),
                ("plain len 16", K::PlainCmd, 16),
                ("plain len 200", K::PlainCmd, 200),
                ("MAC ok len 0", K::Mac, 0),
                ("MAC ok len 16", K::Mac, 16),
                ("MAC ok len 200", K::Mac, 200),
                ("MAC truncated to 4, len 16", K::MacTrunc4, 16),
                ("MAC wrong (bit flipped), len 16", K::MacWrong, 16),
                ("MAC for counter+1, len 16", K::MacCtrPlus1, 16),
                ("MAC + 1 extra byte, len 16", K::MacExtraByte, 16),
                ("MAC truncated to 4, len 0", K::MacTrunc4, 0),
                ("MAC wrong, len 0", K::MacWrong, 0),
            ];
            for (vl, kind, len) in variants {
                if fno >= 3 && !(vl.starts_with("plain") || vl.starts_with("MAC ok")) {
                    continue;
                }
                for follow_ctr in [0u16, 1] {
                    // the second follow-up counter is only interesting for the plain variants
                    if follow_ctr == 1 && !matches!(kind, K::PlainCmd) {
                        continue;
                    }
                    lab_step(c, &format!("lab 3: {fmode} file, {vl}; follow-up with counter {}", if follow_ctr == 0 { "unchanged" } else { "+1" }), |c| {
                        reset(c, aid)?;
                        let s = lab_auth(c, 0, &z)?;
                        let hdr = read_payload(fno, 0, len);
                        let (d, sw) = match kind {
                            K::PlainCmd => nat(c, "ReadData without MAC", 0xBD, &hdr)?,
                            K::Mac => mac_cmd(c, &s, "ReadData with MAC", 0xBD, &hdr, 0, 8, false)?,
                            K::MacTrunc4 => mac_cmd(c, &s, "ReadData with 4 byte MAC", 0xBD, &hdr, 0, 4, false)?,
                            K::MacWrong => mac_cmd(c, &s, "ReadData with wrong MAC", 0xBD, &hdr, 0, 8, true)?,
                            K::MacCtrPlus1 => mac_cmd(c, &s, "ReadData with MAC of counter+1", 0xBD, &hdr, 1, 8, false)?,
                            K::MacExtraByte => {
                                let m = s.mac_cmd(0xBD, &hdr).map_err(|e| StepError::fail(e.0))?;
                                nat(c, "ReadData with MAC and a stray byte", 0xBD, &[hdr.clone(), m, vec![0xEE]].concat())?
                            }
                        };
                        let mut ctr_after = 1u16;
                        if sw == 0x91AF {
                            // per-frame log, hard cap of 6
                            let mut empty = 0;
                            let mut total = d.len();
                            for i in 1..=6 {
                                let (d2, sw2) = nat(c, &format!("  AF#{i}"), 0xAF, &[])?;
                                total += d2.len();
                                if d2.is_empty() {
                                    empty += 1;
                                }
                                if sw2 != 0x91AF {
                                    break;
                                }
                            }
                            c.detail(format!("  chain: {total} data bytes in total, {empty} empty frame(s)"));
                        } else if sw == 0x9100 {
                            // a successful MAC'd response: verify the response MAC, the counter moved
                            if d.len() >= 8 && !matches!(kind, K::PlainCmd) {
                                let mut t = s.clone();
                                t.ctr = 1;
                                let ok = t.mac_resp(0, &d[..d.len() - 8]).map(|m| m == d[d.len() - 8..]).unwrap_or(false);
                                c.detail(format!("  response MAC valid for counter 1: {ok}"));
                            }
                        } else {
                            ctr_after = 0;
                        }
                        // does the session survive? A well formed MAC read of 16 bytes, counter as per the experiment
                        let want = (follow_ctr + if ctr_after == 1 { 1 } else { 0 }).min(2);
                        let (_, sw3) = mac_cmd(c, &s, &format!("follow-up MAC ReadData(16) with counter {want}"), 0xBD, &read_payload(fno, 0, 16), want, 8, false)?;
                        if sw3 != 0x9100 && want > 0 {
                            mac_cmd(c, &s, &format!("follow-up again with counter {}", want - 1), 0xBD, &read_payload(fno, 0, 16), want - 1, 8, false)?;
                        }
                        reset(c, aid)?;
                        Ok(())
                    });
                }
            }
        }
        // the same plain commands without any authentication, free-access style reference: unauthenticated read of a key-0 file
        lab_step(c, "lab 3: reference, no authentication: plain ReadData of the key-0 files", |c| {
            for fno in 0..6u8 {
                reset(c, aid)?;
                nat(c, &format!("unauthenticated ReadData(file {fno}, 0, 0)"), 0xBD, &read_payload(fno, 0, 0))?;
                reset(c, aid)?;
            }
            Ok(())
        });
    });
}

/// One authenticated session, one ReadData(file, 0, 0) without or with a command MAC; returns a one-line summary.
fn session_probe(c: &mut Ctx, aid: Aid, key_no: u8, fno: u8, with_mac: bool, pre: u16) -> StepResult<String> {
    session_probe_key(c, aid, key_no, &[0u8; 16], fno, with_mac, pre)
}

fn session_probe_key(c: &mut Ctx, aid: Aid, key_no: u8, z: &[u8], fno: u8, with_mac: bool, pre: u16) -> StepResult<String> {
    reset(c, aid)?;
    let mut s = lab_auth(c, key_no, z)?;
    for i in 0..pre {
        let (_, sw) = mac_cmd(c, &s, &format!("preceding MAC ReadData(16) #{i}"), 0xBD, &read_payload(fno, 0, 16), i, 8, false)?;
        if sw != 0x9100 {
            return Ok(format!("the preceding well-formed command was refused with {sw:04X}"));
        }
    }
    s.ctr = pre;
    let hdr = read_payload(fno, 0, 0);
    let a = if with_mac {
        let body = [hdr.clone(), s.mac_cmd(0xBD, &hdr).map_err(|e| StepError::fail(e.0))?].concat();
        build_apdu(0x90, 0xBD, 0, 0, &body, Le::Short(0), false)
    } else {
        build_apdu(0x90, 0xBD, 0, 0, &hdr, Le::Short(0), false)
    };
    let t0 = Instant::now();
    let (d, mut sw) = c.apdu_raw(&a)?;
    let mut line = format!("{} -> {:04X} ({} B)", if with_mac { "MAC cmd  " } else { "plain cmd" }, sw, d.len());
    let (mut n, mut empty, mut total) = (0, 0, d.len());
    while sw == 0x91AF && n < 6 {
        n += 1;
        let (d2, s2) = c.apdu_raw(&build_apdu(0x90, 0xAF, 0, 0, &[], Le::Short(0), false))?;
        if d2.is_empty() {
            empty += 1;
        }
        total += d2.len();
        sw = s2;
    }
    if n > 0 {
        line.push_str(&format!(", {n} continuation(s), {empty} empty, final {sw:04X}, {total} B"));
    }
    line.push_str(&format!(" [{} ms]", t0.elapsed().as_millis()));
    reset(c, aid)?;
    Ok(line)
}

/// Part 3b: which combinations of file mode, access rights and authenticated key give the endless empty additional frames?
fn part3b(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let spec = AppSpec::new(aid).keys(2);
    let spec2 = spec.clone();
    ctx.app_scope(spec, |c, aid| {
        let (k0, k1, free, never) = (AccessRight::key(0), AccessRight::key(1), AccessRight::FREE, AccessRight::NEVER);
        // (label, read, write, read-write)
        let rights = [("r=k0 w=k0 rw=k0", k0, k0, k0), ("r=k1 w=k0 rw=never", k1, k0, never), ("r=free w=k0 rw=never", free, k0, never), ("r=never w=k0 rw=k1", never, k0, k1), ("r=k0 w=k0 rw=k1", k0, k0, k1)];
        let modes = [("Plain", CommMode::Plain), ("MAC", CommMode::Mac), ("Full", CommMode::Full)];
        let ok = provision(c, &spec2, "lab 3b: provision 15 StandardData files (3 modes x 5 access right sets), 64 bytes, all with AppKey 0 as change key", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let mut n = 0u8;
            for (_, m) in modes {
                for (_, r, w, rw) in rights {
                    c.create_data_file(&DataFileSpec::new(n, 64, AccessRights::new(r, w, rw, k0)).comm_mode(m))?;
                    // write with key 0: its right is Write (k0) in every set
                    c.write_data_with(n, 0, &(0..64u8).collect::<Vec<_>>(), ModeSel::Explicit(m))?;
                    n += 1;
                }
            }
            Ok(())
        });
        if ok.is_none() {
            return;
        }
        let mut n = 0u8;
        for (ml, _) in modes {
            for (rl, _, _, _) in rights {
                let fno = n;
                n += 1;
                lab_step(c, &format!("lab 3b: {ml} file, {rl}"), |c| {
                    for key_no in [0u8, 1] {
                        for with_mac in [false, true] {
                            let l = session_probe(c, aid, key_no, fno, with_mac, 0)?;
                            c.detail(format!("auth key {key_no}: {l}"));
                        }
                    }
                    Ok(())
                });
            }
        }
        for (fno, label) in [(5u8, "MAC file (key 0)"), (10, "Full file (key 0)"), (0, "Plain file (key 0)")] {
            lab_step(c, &format!("lab 3c: {label}: a plain ReadData(0,0) after 0..3 well-formed MAC commands of the same session"), |c| {
                for pre in 0..4u16 {
                    let l = session_probe(c, aid, 0, fno, false, pre)?;
                    c.detail(format!("after {pre} MAC command(s): {l}"));
                }
                Ok(())
            });
        }
    });
}

/// Part 3d: the same probe in an AES-256 application (when the card creates one with the factory default key).
fn part3d(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let spec = AppSpec::new(aid).keys(1).aes256();
    let created = ctx.step_picc("lab 3d: create an AES-256 application with the factory default key", |c| {
        c.auth_picc()?;
        match c.create_application(&spec) {
            Ok(()) => Ok(()),
            Err(e) if e.status().is_some() => Err(StepError::skip(format!("the card refuses an AES-256 application with the 16-byte default key: {e}"))),
            Err(e) => Err(e),
        }
    });
    if created.is_none() {
        return;
    }
    let cid = ctx.push_cleanup(&format!("delete application {aid}"), move |c| c.delete_app_tolerant(aid));
    let z = vec![0u8; 32];
    lab_step(ctx, "lab 3d: AES-256 session, 3 files (MAC, Plain, Full; key 0 for everything), plain and MAC ReadData(0,0)", |c| {
        c.auth_app(aid, 0, &z)?;
        let k0 = AccessRight::key(0);
        for (n, m) in [(0u8, CommMode::Mac), (1, CommMode::Plain), (2, CommMode::Full)] {
            let _ = c.delete_file(n);
            c.auth_app(aid, 0, &z)?;
            c.create_data_file(&DataFileSpec::new(n, 64, AccessRights::new(k0, k0, k0, k0)).comm_mode(m))?;
            c.write_data_with(n, 0, &(0..64u8).collect::<Vec<_>>(), ModeSel::Explicit(m))?;
        }
        for (fno, l) in [(0u8, "MAC"), (1, "Plain"), (2, "Full")] {
            for with_mac in [false, true] {
                let r = session_probe_key(c, aid, 0, &z, fno, with_mac, 0)?;
                c.detail(format!("AES-256, {l} file: {r}"));
            }
        }
        Ok(())
    });
    ctx.step("lab 3d: delete the AES-256 application", |c| {
        let r = c.delete_app_tolerant(aid);
        if r.is_ok() {
            c.cancel_cleanup(cid);
        }
        r
    });
}

/// Part 3e: MAC-mode files of several sizes (and an ISO file id), plain ReadData(0,0) inside a session.
fn part3e(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    let spec = AppSpec::new(aid).keys(1).iso_file_ids();
    let spec2 = spec.clone();
    ctx.app_scope(spec, |c, aid| {
        let sizes = [1u32, 16, 59, 60, 128, 512, 1024];
        let ok = provision(c, &spec2, "lab 3e: provision MAC-mode files of 1, 16, 59, 60, 128, 512 and 1024 bytes (ISO file ids, key 0 rights)", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let k0 = AccessRight::key(0);
            for (i, n) in sizes.iter().enumerate() {
                c.create_data_file(&DataFileSpec::new(i as u8, *n, AccessRights::all(k0)).comm_mode(CommMode::Mac).iso_fid(0xE101 + i as u16))?;
            }
            Ok(())
        });
        if ok.is_none() {
            return;
        }
        for (i, n) in sizes.iter().enumerate() {
            lab_step(c, &format!("lab 3e: MAC file of {n} bytes"), |c| {
                for with_mac in [false, true] {
                    let l = session_probe(c, aid, 0, i as u8, with_mac, 0)?;
                    c.detail(l);
                }
                Ok(())
            });
        }
        lab_step(c, "lab 3f: through the library: authenticate, then ReadData with an explicit Plain mode (no MAC) on the 512 byte MAC file, then a well-formed MAC read", |c| {
            let z = c.zero_key;
            c.auth_app(aid, 0, &z)?;
            let r = c.read_data_with(5, 0, 0, ModeSel::Explicit(CommMode::Plain));
            match &r {
                Ok(d) => c.detail(format!("plain read through the library succeeded: {} bytes", d.len())),
                Err(e) => c.detail(format!("plain read through the library failed: {e}; authenticated afterwards: {}", c.is_authenticated())),
            }
            c.auth_app(aid, 0, &z)?;
            let d = c.read_data_with(5, 0, 0, ModeSel::Explicit(CommMode::Mac))?;
            c.detail(format!("well-formed MAC read after a fresh authentication: {} bytes", d.len()));
            Ok(())
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_settings_are_valid_and_encode() {
        let v = V::base();
        assert!(v.settings().validate(FILE_SIZE as usize, 7).is_empty());
        assert!(v.settings().encode().is_ok());
    }

    #[test]
    fn overlap_text() {
        assert_eq!(sig_overlap(0, &[0u8; 10], 20), "no signature bytes");
        assert!(sig_overlap(250, &[b'A'; 20], 256).starts_with("14 of 128"));
    }
}
