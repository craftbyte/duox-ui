//! Section `sdm`: Secure Dynamic Messaging (7.5.11, 7.12.2.1, 8.7.12) in throwaway applications with AES-128 and
//! AES-256 application keys.
//!
//! An NDEF file (ISO file identifier E104) is created with the SDM flag. The library's template builder produces
//! the NDEF content and the matching SDM settings; they are written with ChangeFileSettings and read back.
//! The file is then read without authentication, natively (ReadData) and as an NDEF reader would (ISOSelectFile
//! by DF name, by file identifier, ISOReadBinary), and every mirrored item is verified with the library's
//! back-end side: PICCData (plain and encrypted), SDMReadCtr, SDMENCFileData, SDMMAC and SDMSIG (ECC key in the
//! application, both curves). The counter is checked against GetFileCounters after every read.
//!
//! Also covered: counter increment rules (repeated reads of one command type, authenticated reads), the
//! SDMReadCtrLimit (reached, refused, raised), disabling SDM, the ASCII only encoding, and the settings the card
//! must reject.

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use duox::card::{
    Aid, AccessRight, AccessRights, AppSpec, ChangeKeySpec, CommMode, DataFileSpec, FileSettingsChange, IsoSelect,
    KeyPairOp, KeyPairSpec, ModeSel, Status,
};
use duox::crypto::{self, PubKey, CURVE_BP256, CURVE_P256};
use duox::sdm::{
    build_ndef_template, url_from_ndef_file, verify, verify_url, NdefTemplate, SdmError, SdmResult, SdmSettings,
    TemplateOptions, VerifyParams, AC_FREE, AC_NONE, OPT_ASCII, OPT_CTR, OPT_CTR_LIMIT, OPT_ENC, OPT_UID,
};

pub const NAME: &str = "sdm";
pub const DESCRIPTION: &str =
    "Secure Dynamic Messaging: NDEF templates, PICCData / SDMMAC / SDMENCFileData / SDMSIG read-out and verification, counter and limit, AES-128 and AES-256.";

const P_SDM: u16 = 0x0020;
const P_SIGN: u16 = 0x0010;
const FILE_SIZE: u32 = 512;
const NDEF_FID: u16 = 0xE104;
const NDEF_FILE: u8 = 0;
const PLAIN_FILE: u8 = 1;

pub fn run(ctx: &mut Ctx) {
    suite(ctx, false);
    aes256_gate(ctx, |ctx| suite(ctx, true));
}

// ------------------------------------------------------------------ test table
/// One SDM configuration to run against the card.
struct Case {
    name: &'static str,
    url: &'static str,
    /// SDMMetaRead: key number, or AC_FREE for plain mirroring.
    meta: u8,
    /// SDMFileRead key number or AC_NONE.
    file: u8,
    /// SDMFileRead2 ECC key number or AC_NONE.
    sig: u8,
    enc_fill: &'static [u8],
}

const CASES: [Case; 6] = [
    Case { name: "plain UID and counter", url: "https://suite.example/n?u={uid}x{ctr}", meta: AC_FREE, file: AC_NONE, sig: AC_NONE, enc_fill: b"" },
    Case { name: "plain UID and counter + SDMMAC (key 1)", url: "https://suite.example/n?u={uid}&c={ctr}&m={mac}", meta: AC_FREE, file: 1, sig: AC_NONE, enc_fill: b"" },
    Case {
        name: "encrypted PICCData (key 2) + SDMENCFileData + SDMMAC (key 1)",
        url: "https://suite.example/n?p={picc}&e={enc:32}&m={mac}",
        meta: 2,
        file: 1,
        sig: AC_NONE,
        enc_fill: b"SUITE-SECRET-0123",
    },
    Case { name: "plain UID and counter + SDMSIG (P-256 key 0)", url: "https://suite.example/n?u={uid}&c={ctr}&s={sig}", meta: AC_FREE, file: AC_NONE, sig: 0, enc_fill: b"" },
    Case { name: "plain UID and counter + SDMSIG (brainpoolP256r1 key 1)", url: "https://suite.example/n?u={uid}&c={ctr}&s={sig}", meta: AC_FREE, file: AC_NONE, sig: 1, enc_fill: b"" },
    Case {
        name: "encrypted PICCData + SDMENCFileData + SDMSIG (key 0) with SDMFileRead key 1 for the encryption",
        url: "https://suite.example/n?p={picc}&e={enc:32}&s={sig}",
        meta: 2,
        file: 1,
        sig: 0,
        enc_fill: b"ECC-AND-AES-DATA",
    },
];

fn template(case: &Case, uid_len: usize, ctr_limit: Option<u32>) -> Result<NdefTemplate, SdmError> {
    build_ndef_template(
        case.url,
        &TemplateOptions {
            uid_len,
            meta_read: case.meta,
            file_read: case.file,
            file_read2: case.sig,
            ctr_ret: 0,
            enc_fill: case.enc_fill.to_vec(),
            ctr_limit,
        },
    )
}

fn sdok<T>(r: Result<T, SdmError>) -> StepResult<T> {
    r.map_err(|e| StepError::fail(format!("sdm: {e}")))
}

fn cf<T>(r: Result<T, crypto::CryptoError>) -> StepResult<T> {
    r.map_err(|e| StepError::fail(format!("crypto: {}", e.0)))
}

/// Static offset of the first mirrored item (everything before it must come back unchanged).
fn first_region(tpl: &NdefTemplate, uid_len: usize) -> usize {
    tpl.settings.regions(uid_len).iter().map(|r| r.offset).min().unwrap_or(tpl.file_data.len())
}

// ------------------------------------------------------------------ the application under test
struct Sd {
    aid: Aid,
    df_name: Vec<u8>,
    /// Application keys 0 (zero), 1 (SDMFileRead), 2 (SDMMetaRead).
    keys: [Vec<u8>; 3],
    uid: Vec<u8>,
    pubs: [PubKey; 2],
    aes256: bool,
}

impl Sd {
    fn auth(&self, c: &mut Ctx) -> StepResult {
        c.auth_app(self.aid, 0, &self.keys[0])
    }
    fn counter(&self, c: &mut Ctx) -> StepResult<u32> {
        self.auth(c)?;
        Ok(c.get_file_counters(NDEF_FILE)?)
    }
    fn params<'a>(&'a self, case: &Case) -> VerifyParams<'a> {
        VerifyParams {
            uid_len: self.uid.len(),
            meta_key: (case.meta <= 0xD).then(|| &self.keys[case.meta as usize][..]),
            file_key: (case.file <= 0xD).then(|| &self.keys[case.file as usize][..]),
            sig_pub: (case.sig <= 1).then(|| &self.pubs[case.sig as usize]),
            uid: Some(&self.uid),
            last_ctr: None,
        }
    }
}

fn suite(ctx: &mut Ctx, aes256: bool) {
    let label = if aes256 { "AES-256" } else { "AES-128" };
    let aid = ctx.alloc_aid();
    let df_name = format!("DUOXSUITE{:06X}", aid.0).into_bytes();
    let mut spec = AppSpec::new(aid).keys(3).iso_file_ids().iso_name(0xD200 | (aid.0 & 0xFF) as u16, &df_name);
    if aes256 {
        spec = spec.aes256();
    }
    let uid = ctx.uid.clone();
    ctx.app_scope(spec, |c, aid| {
        let Some(sd) = provision(c, aid, df_name.clone(), uid.clone(), aes256, label) else { return };
        for case in CASES.iter() {
            run_case(c, &sd, case, label);
        }
        extras(c, &sd, label);
    });
}

fn provision(c: &mut Ctx, aid: Aid, df_name: Vec<u8>, uid: Vec<u8>, aes256: bool, label: &str) -> Option<Sd> {
    c.step(&format!("{label}: provision application keys 1 and 2, SDM ECC keys (P-256, brainpool), NDEF file with the SDM flag"), |c| {
        let kl = if aes256 { 32 } else { 16 };
        let zero = vec![0u8; kl];
        let k1 = crypto::rnd(kl);
        let k2 = crypto::rnd(kl);
        c.auth_app(aid, 0, &zero)?;
        c.change_key(&ChangeKeySpec::new(1, &k1, 1).old_key(&zero))?;
        c.change_key(&ChangeKeySpec::new(2, &k2, 2).old_key(&zero))?;
        c.auth_app(aid, 0, &zero)?;
        let raw0 = c.manage_key_pair(&KeyPairSpec::new(0, CURVE_P256, P_SDM, 0x30).kuc_limit(1000), &KeyPairOp::Generate, None)?;
        let raw1 = c.manage_key_pair(&KeyPairSpec::new(1, CURVE_BP256, P_SDM, 0x30), &KeyPairOp::Generate, None)?;
        // key 2: a signing key without the SDM policy (negative test)
        c.manage_key_pair(&KeyPairSpec::new(2, CURVE_P256, P_SIGN, 0x30), &KeyPairOp::Generate, None)?;
        let pubs = [cf(PubKey::from_bytes(CURVE_P256, &raw0))?, cf(PubKey::from_bytes(CURVE_BP256, &raw1))?];
        let mut nos = c.file_nos();
        ensure_eq(nos.next(), NDEF_FILE, "file number")?;
        ensure_eq(nos.next(), PLAIN_FILE, "file number")?;
        let k = AccessRight::key;
        let ar = AccessRights::new(AccessRight::FREE, k(0), AccessRight::NEVER, k(0));
        c.create_data_file(&DataFileSpec::new(NDEF_FILE, FILE_SIZE, ar).comm_mode(CommMode::Plain).sdm().iso_fid(NDEF_FID))?;
        c.create_data_file(&DataFileSpec::new(PLAIN_FILE, 64, ar).comm_mode(CommMode::Plain).iso_fid(0xE105))?;
        let fs = c.get_file_settings(NDEF_FILE)?;
        // "pre-enabled" at creation: whether GetFileSettings reports the flag before settings exist is not specified
        c.detail(format!("NDEF file FileOption after creation: 0x{:02X} (SDM flag {})", fs.option, if fs.option & 0x40 != 0 { "reported" } else { "not reported" }));
        c.detail(format!("UID {}, {} byte NDEF file, application keys of {kl} bytes", hex::encode_upper(&uid), FILE_SIZE));
        Ok(Sd { aid, df_name, keys: [zero, k1, k2], uid, pubs, aes256 })
    })
}

// ------------------------------------------------------------------ configure / read
/// Write the static NDEF content, enable SDM with the template's settings and read them back.
fn configure(c: &mut Ctx, sd: &Sd, tpl: &NdefTemplate) -> StepResult {
    let problems = tpl.settings.validate(FILE_SIZE as usize, sd.uid.len());
    ensure(problems.is_empty(), format!("the library rejects its own template: {problems:?}"))?;
    sd.auth(c)?;
    c.write_data_with(NDEF_FILE, 0, &tpl.file_data, ModeSel::Explicit(CommMode::Plain))?;
    let fs = c.get_file_settings(NDEF_FILE)?;
    let mut ch = FileSettingsChange::new(0x40 | CommMode::Plain.bits(), fs.access);
    ch.sdm = sdok(tpl.settings.encode())?;
    c.change_file_settings(NDEF_FILE, &ch)?;
    let fs = c.get_file_settings(NDEF_FILE)?;
    ensure(fs.option & 0x40 != 0, "SDM flag lost")?;
    let raw = fs.sdm.clone().ok_or("GetFileSettings returned no SDM block")?;
    let (back, used) = sdok(SdmSettings::parse(&raw))?;
    c.detail(format!("SDM block read back: {} bytes, {}", used, hex::encode_upper(&raw)));
    ensure_eq(back, tpl.settings.clone(), "SDM settings read back from the card")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    Native,
    IsoByName,
    IsoByFid,
}

/// Read the NDEF file without authentication. Native: ReadData of the whole file. ISO: select, read NLEN, read the message.
fn read_dynamic(c: &mut Ctx, sd: &Sd, how: How) -> StepResult<Vec<u8>> {
    match how {
        How::Native => {
            c.select_application(sd.aid, None)?;
            // ReadData command 0xAD (ISO-wrapped variant): the native 0xBD cannot deliver the bytes of
            // an SDMSIG on this card (measured with the lab section); 0xAD and ISOReadBinary can.
            Ok(c.read_data_iso_with(NDEF_FILE, 0, FILE_SIZE, ModeSel::Explicit(CommMode::Plain))?)
        }
        How::IsoByName | How::IsoByFid => {
            c.select_application(Aid::PICC, None)?;
            if how == How::IsoByName {
                c.iso_select(&IsoSelect::DfName(&sd.df_name))?;
            } else {
                c.iso_select(&IsoSelect::FileId(0xD200 | (sd.aid.0 & 0xFF) as u16))?;
            }
            c.iso_select(&IsoSelect::EfUnderCurrent(NDEF_FID))?;
            let mut file = c.iso_read_binary(0, 2, None)?;
            ensure_eq(file.len(), 2, "NLEN length")?;
            let nlen = usize::from(u16::from_be_bytes([file[0], file[1]]));
            while file.len() < 2 + nlen {
                let n = (2 + nlen - file.len()).min(0xE0);
                let part = c.iso_read_binary(file.len() as u32, n as u8, None)?;
                ensure_eq(part.len(), n, "ISOReadBinary chunk")?;
                file.extend(part);
            }
            Ok(file)
        }
    }
}

/// Everything the back-end can check for one read.
fn check_read(_c: &mut Ctx, sd: &Sd, case: &Case, tpl: &NdefTemplate, file: &[u8], expected_ctr: u32) -> StepResult<SdmResult> {
    let uid_len = sd.uid.len();
    let first = first_region(tpl, uid_len);
    ensure_eq(&file[..first], &tpl.file_data[..first], "static content in front of the first mirror")?;
    let p = sd.params(case);
    let r = sdok(verify(file, &tpl.settings, &p))?;
    ensure_eq(r.ctr, Some(expected_ctr), "SDMReadCtr mirrored by the card")?;
    ensure_eq(r.uid.clone(), Some(sd.uid.clone()), "VCUID")?;
    if case.meta <= 0xD {
        ensure_eq(r.picc_tag, Some(0xC0 | sd.uid.len() as u8), "PICCDataTag")?;
    }
    if case.file <= 0xD {
        // the MAC stands (or the encrypted data), a wrong key must not verify
        if case.sig == AC_NONE {
            ensure_eq(r.mac_ok, Some(true), "SDMMAC")?;
            let wrong = &sd.keys[if case.file == 1 { 2 } else { 1 }];
            let w = sdok(verify(file, &tpl.settings, &VerifyParams { file_key: Some(wrong), ..p }))?;
            ensure_eq(w.mac_ok, Some(false), "SDMMAC under the wrong key")?;
        } else {
            ensure_eq(r.mac_ok, None, "no SDMMAC when SDMSIG is used")?;
        }
    }
    if case.sig <= 1 {
        ensure_eq(r.sig_ok, Some(true), "SDMSIG")?;
        let other = cf(crypto::gen_key(sd.pubs[case.sig as usize].curve_id))?.public();
        let w = sdok(verify(file, &tpl.settings, &VerifyParams { sig_pub: Some(&other), ..p }))?;
        ensure_eq(w.sig_ok, Some(false), "SDMSIG under another public key")?;
    }
    if tpl.settings.options & OPT_ENC != 0 {
        let mut want = case.enc_fill.to_vec();
        let n = (tpl.settings.enc_length.unwrap_or(0) / 2) as usize;
        want.resize(n, b' ');
        ensure_eq(r.enc_plain.clone(), Some(want), "decrypted SDMENCFileData")?;
    }
    // a flipped character in the authenticated part is detected
    if let (Some(mo), true) = (tpl.settings.mac_offset, case.sig <= 1 || case.file <= 0xD) {
        let mut bad = file.to_vec();
        bad[mo as usize] = if bad[mo as usize] == b'0' { b'1' } else { b'0' };
        let t = sdok(verify(&bad, &tpl.settings, &p))?;
        ensure(!t.ok(), "a tampered SDMMAC / SDMSIG still verifies")?;
    }
    ensure(r.ctr_within_limit != Some(false), "counter beyond the limit")?;
    Ok(r)
}

fn run_case(c: &mut Ctx, sd: &Sd, case: &Case, label: &str) {
    let n = format!("{label}: {}", case.name);
    let Ok(tpl) = template(case, sd.uid.len(), None) else {
        c.step(&format!("{n}: build the NDEF template"), |_| Err::<(), _>(StepError::fail("template builder refused the case")));
        return;
    };
    let ok = c.step(&format!("{n}: template -> ChangeFileSettings -> GetFileSettings round trip"), |c| configure(c, sd, &tpl));
    if ok.is_none() {
        return;
    }
    for how in [How::Native, How::IsoByName, How::IsoByFid] {
        c.step(&format!("{n}: unauthenticated read ({how:?}) mirrors everything and the counter advances by one"), |c| {
            let base = sd.counter(c)?;
            let file = read_dynamic(c, sd, how)?;
            let r = check_read(c, sd, case, &tpl, &file, base + 1)?;
            // the NDEF reader's view: the URL carries the same values
            if how != How::Native {
                let url = sdok(url_from_ndef_file(&file))?;
                ensure(url.starts_with("https://suite.example/n?"), format!("unexpected URL {url}"))?;
                let r2 = sdok(verify_url(&url, &tpl.settings, &sd.params(case)))?;
                ensure_eq((r2.ctr, r2.uid.clone(), r2.mac_ok, r2.sig_ok), (r.ctr, r.uid.clone(), r.mac_ok, r.sig_ok), "URL read-out")?;
                c.detail(url);
            }
            ensure_eq(sd.counter(c)?, base + 1, "GetFileCounters after the read")
        });
    }
    if case.sig == 0 {
        c.step(&format!("{n}: every SDMSIG read counts one key usage of the ECC key (limit 1000)"), |c| {
            sd.auth(c)?;
            let before = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
            let file = read_dynamic(c, sd, How::Native)?;
            let _ = file;
            sd.auth(c)?;
            let after = c.get_ecc_key_settings()?.into_iter().find(|k| k.key_no == 0).ok_or("key 0 missing")?;
            ensure_eq((before.kuc_limit, after.kuc), (1000, before.kuc + 1), "key usage counter")
        });
    }
    if case.name.starts_with("plain UID and counter + SDMMAC") {
        c.step(&format!("{n}: a repeated read of the same command keeps the counter, another command in between advances it"), |c| {
            let base = sd.counter(c)?;
            c.select_application(sd.aid, None)?;
            let a = c.read_data_with(NDEF_FILE, 0, 0, ModeSel::Explicit(CommMode::Plain))?;
            let b = c.read_data_with(NDEF_FILE, 0, 0, ModeSel::Explicit(CommMode::Plain))?;
            ensure_eq(a.clone(), b, "two consecutive reads")?;
            c.get_file_settings(NDEF_FILE)?;
            let d = c.read_data_with(NDEF_FILE, 0, 0, ModeSel::Explicit(CommMode::Plain))?;
            let ra = sdok(verify(&a, &tpl.settings, &sd.params(case)))?;
            let rd = sdok(verify(&d, &tpl.settings, &sd.params(case)))?;
            ensure_eq((ra.ctr, rd.ctr), (Some(base + 1), Some(base + 2)), "counters of the reads")?;
            ensure_eq((ra.mac_ok, rd.mac_ok), (Some(true), Some(true)), "SDMMAC of both")
        });
        c.step(&format!("{n}: an authenticated read returns the static file data and does not count"), |c| {
            let base = sd.counter(c)?;
            sd.auth(c)?;
            let d = c.read_data_with(NDEF_FILE, 0, tpl.file_data.len() as u32, ModeSel::Explicit(CommMode::Plain))?;
            ensure_eq(d, tpl.file_data.clone(), "static file data")?;
            ensure_eq(sd.counter(c)?, base, "counter after an authenticated read")
        });
    }
}

// ------------------------------------------------------------------ further behaviour
fn extras(c: &mut Ctx, sd: &Sd, label: &str) {
    let case = &CASES[1];
    // counter limit
    c.step(&format!("{label}: SDMReadCtrLimit: reads up to the limit work, the next one is refused, a bigger limit re-enables reading"), |c| {
        let t0 = sdok(template(case, sd.uid.len(), None))?;
        configure(c, sd, &t0)?;
        let b = sd.counter(c)?;
        let limit = b + 3;
        let tpl = sdok(template(case, sd.uid.len(), Some(limit)))?;
        configure(c, sd, &tpl)?;
        let b2 = sd.counter(c)?;
        if b2 != b {
            c.detail(format!("counter before / after enabling the limit: {b} / {b2} (ChangeFileSettings reset it)"));
        }
        ensure(b2 < limit, "counter is not below the limit after configuring")?;
        for i in 0..(limit - b2) {
            let file = read_dynamic(c, sd, How::Native)?;
            let r = check_read(c, sd, case, &tpl, &file, b2 + i + 1)?;
            ensure_eq(r.ctr_within_limit, Some(true), "counter within the limit")?;
        }
        ensure_eq(sd.counter(c)?, limit, "counter at the limit")?;
        c.select_application(sd.aid, None)?;
        let r = c.read_data_with(NDEF_FILE, 0, 0, ModeSel::Explicit(CommMode::Plain));
        let st = c.expect_any_status(r)?;
        c.detail(format!("read at the limit: {st}"));
        // authenticated reads are not affected
        sd.auth(c)?;
        c.read_data_with(NDEF_FILE, 0, 16, ModeSel::Explicit(CommMode::Plain))?;
        // a limit that is not above the counter is rejected
        let same = sdok(template(case, sd.uid.len(), Some(limit)))?;
        sd.auth(c)?;
        let fs = c.get_file_settings(NDEF_FILE)?;
        let mut ch = FileSettingsChange::new(0x40, fs.access);
        ch.sdm = sdok(same.settings.encode())?;
        let r = c.change_file_settings(NDEF_FILE, &ch);
        c.expect_err(Status::ParameterError, r)?;
        // raise it
        let bigger = sdok(template(case, sd.uid.len(), Some(limit + 5)))?;
        configure(c, sd, &bigger)?;
        let after = sd.counter(c)?;
        let file = read_dynamic(c, sd, How::Native)?;
        check_read(c, sd, case, &bigger, &file, after + 1)?;
        Ok(())
    });
    // disable SDM
    c.step(&format!("{label}: disabling SDM (ChangeFileSettings without the SDM option) returns the static file data"), |c| {
        let tpl = sdok(template(case, sd.uid.len(), None))?;
        configure(c, sd, &tpl)?;
        sd.auth(c)?;
        let fs = c.get_file_settings(NDEF_FILE)?;
        c.change_file_settings(NDEF_FILE, &FileSettingsChange::new(CommMode::Plain.bits(), fs.access))?;
        let fs = c.get_file_settings(NDEF_FILE)?;
        ensure(fs.option & 0x40 == 0 && fs.sdm.is_none(), "SDM still enabled")?;
        c.select_application(sd.aid, None)?;
        let d = c.read_data_with(NDEF_FILE, 0, tpl.file_data.len() as u32, ModeSel::Explicit(CommMode::Plain))?;
        ensure_eq(d, tpl.file_data.clone(), "file read with SDM disabled")
    });
    c.step(&format!("{label}: enabling SDM again works and mirrors again"), |c| {
        let tpl = sdok(template(case, sd.uid.len(), None))?;
        configure(c, sd, &tpl)?;
        let base = sd.counter(c)?;
        let file = read_dynamic(c, sd, How::IsoByName)?;
        check_read(c, sd, case, &tpl, &file, base + 1)?;
        Ok(())
    });
    rejected_settings(c, sd, label);
}

/// A well formed template with one setting made wrong.
fn change_with(c: &mut Ctx, sd: &Sd, file: u8, s: &SdmSettings) -> StepResult<duox::Result<()>> {
    sd.auth(c)?;
    let fs = c.get_file_settings(file)?;
    let mut ch = FileSettingsChange::new(0x40, fs.access);
    ch.sdm = sd_encode(s)?;
    Ok(c.change_file_settings(file, &ch))
}

fn sd_encode(s: &SdmSettings) -> StepResult<Vec<u8>> {
    sdok(s.encode())
}

fn bad_settings(uid_len: usize) -> Vec<(&'static str, SdmSettings, bool)> {
    let base = |case: &Case| template(case, uid_len, None).expect("template").settings;
    let plain = base(&CASES[0]);
    let mut v: Vec<(&'static str, SdmSettings, bool)> = vec![];
    let mut s = plain.clone();
    s.meta_read = AC_NONE;
    v.push(("VCUID mirroring while SDMMetaRead is 0xF", s, true));
    let mut s = SdmSettings { options: OPT_ASCII | OPT_UID | OPT_CTR | OPT_ENC, meta_read: AC_FREE, uid_offset: Some(10), ctr_offset: Some(40), ..Default::default() };
    s.file_read = AC_NONE;
    v.push(("SDMENCFileData without an SDMFileRead key", s, true));
    let s = SdmSettings { options: OPT_ASCII | OPT_UID, meta_read: AC_FREE, ctr_ret: 0, uid_offset: Some(10), ..Default::default() };
    v.push(("SDMCtrRet set while the counter is disabled", s, true));
    let s = SdmSettings { options: OPT_ASCII | OPT_UID | OPT_CTR, meta_read: AC_FREE, uid_offset: Some(10), ctr_offset: Some(12), ..Default::default() };
    v.push(("VCUID and SDMReadCtr overlap", s, true));
    let s = SdmSettings { options: OPT_ASCII | OPT_UID | OPT_CTR_LIMIT, meta_read: AC_FREE, uid_offset: Some(10), ctr_limit: Some(5), ..Default::default() };
    v.push(("SDMReadCtrLimit while the counter is disabled", s, true));
    for (what, key) in [("SDMFileRead2 names a key without the SDM policy (key 2)", 2u8), ("SDMFileRead2 names a key that does not exist (4)", 4u8)] {
        let s = SdmSettings { options: OPT_ASCII, file_read2: key, mac_input_offset: Some(0), mac_offset: Some(100), ..Default::default() };
        v.push((what, s, false));
    }
    v
}

fn rejected_settings(c: &mut Ctx, sd: &Sd, label: &str) {
    for (what, s, local_problem) in bad_settings(sd.uid.len()) {
        c.step(&format!("{label}: rejected settings: {what} (PARAMETER_ERROR)"), |c| {
            if local_problem {
                ensure(!s.validate(FILE_SIZE as usize, sd.uid.len()).is_empty(), "the library's own validation accepts these settings")?;
            }
            let r = change_with(c, sd, NDEF_FILE, &s)?;
            c.expect_err(Status::ParameterError, r)
        });
    }
    c.step(&format!("{label}: binary (non-ASCII) mirroring is refused: only ASCII encoding exists"), |c| {
        let mut s = template(&CASES[0], sd.uid.len(), None).map_err(|e| StepError::fail(e.to_string()))?.settings;
        s.options &= !OPT_ASCII;
        ensure(!s.validate(FILE_SIZE as usize, sd.uid.len()).is_empty(), "library validation accepts binary mode")?;
        let r = change_with(c, sd, NDEF_FILE, &s)?;
        let st = c.expect_any_status(r)?;
        c.detail(format!("the card answered {st}"));
        Ok(())
    });
    c.step(&format!("{label}: mirror placed beyond the end of the file is refused"), |c| {
        let mut s = template(&CASES[0], sd.uid.len(), None).map_err(|e| StepError::fail(e.to_string()))?.settings;
        s.uid_offset = Some(FILE_SIZE - 3);
        ensure(!s.validate(FILE_SIZE as usize, sd.uid.len()).is_empty(), "library validation accepts the offset")?;
        let r = change_with(c, sd, NDEF_FILE, &s)?;
        let st = c.expect_any_status(r)?;
        c.detail(format!("the card answered {st}"));
        Ok(())
    });
    c.step(&format!("{label}: SDM cannot be enabled on a file created without the SDM flag (PERMISSION_DENIED)"), |c| {
        let s = template(&CASES[0], sd.uid.len(), None).map_err(|e| StepError::fail(e.to_string()))?.settings;
        let r = change_with(c, sd, PLAIN_FILE, &s)?;
        c.expect_err(Status::PermissionDenied, r)
    });
    c.step(&format!("{label}: ChangeFileSettings of the SDM file without authentication is refused (AUTHENTICATION_ERROR)"), |c| {
        let s = template(&CASES[0], sd.uid.len(), None).map_err(|e| StepError::fail(e.to_string()))?.settings;
        sd.auth(c)?;
        let fs = c.get_file_settings(NDEF_FILE)?;
        let mut ch = FileSettingsChange::new(0x40, fs.access);
        ch.sdm = sd_encode(&s)?;
        ch.mode = Some(CommMode::Plain);
        c.select_application(sd.aid, None)?;
        let r = c.change_file_settings(NDEF_FILE, &ch);
        c.expect_err(Status::AuthenticationError, r)
    });
}

// ------------------------------------------------------------------ AES-256 applications
/// Run `f` when AES-256 applications can be created. The data sheet ties this to a 32-byte PICCAppDefaultKey; if the
/// card refuses with the factory default, the 32-byte all-zero form is set for the duration (with a restore action).
fn aes256_gate(ctx: &mut Ctx, f: impl FnOnce(&mut Ctx)) {
    let direct = ctx.step_picc("SDM AES-256: an AES-256 application can be created with the factory default key", probe_aes256);
    let Some(direct) = direct else {
        ctx.skip("SDM AES-256 steps", "could not determine whether AES-256 applications can be created");
        return;
    };
    if direct {
        f(ctx);
        return;
    }
    let (zero, version) = (ctx.zero_key, ctx.app_default_key_version);
    let mut restore = zero.to_vec();
    restore.extend([0u8; 8]);
    restore.push(version);
    let r2 = restore.clone();
    let cid = ctx.push_cleanup("restore PICCAppDefaultKey (24 byte form, all zero)", move |c| {
        c.auth_picc()?;
        c.set_configuration(0x01, &r2)
    });
    let mut wide = vec![0u8; 32];
    wide.push(version);
    let set = ctx.step_picc("SDM AES-256: set a 32-byte all-zero PICCAppDefaultKey (needed for AES-256 applications)", |c| {
        c.set_configuration(0x01, &wide)
    });
    if set.is_some() {
        f(ctx);
    } else {
        ctx.skip("SDM AES-256 steps", "the 32-byte default key could not be set");
    }
    let ok = ctx.step_picc("SDM AES-256: write the 24-byte all-zero default key back", |c| c.set_configuration(0x01, &restore));
    if ok.is_some() {
        ctx.cancel_cleanup(cid);
    }
}

fn probe_aes256(c: &mut Ctx) -> StepResult<bool> {
    let aid = c.alloc_aid();
    let cid = c.push_cleanup(&format!("delete application {aid} if it exists"), move |c| c.delete_app_tolerant(aid));
    c.auth_picc()?;
    match c.create_application(&AppSpec::new(aid).keys(1).aes256()) {
        Ok(()) => {
            c.delete_app_tolerant(aid)?;
            c.cancel_cleanup(cid);
            Ok(true)
        }
        Err(e) if e.status().is_some() => {
            c.cancel_cleanup(cid);
            c.detail(format!("creation refused: {e}"));
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------------------ offline tests
#[cfg(test)]
mod tests {
    use super::*;
    use duox::sdm::{render, RenderKeys};

    #[test]
    fn every_case_builds_validates_and_round_trips_with_both_key_sizes() {
        for uid_len in [7usize, 10] {
            for kl in [16usize, 32] {
                let keys: [Vec<u8>; 3] = [vec![0; kl], crypto::rnd(kl), crypto::rnd(kl)];
                let pubs = [crypto::gen_key(CURVE_P256).unwrap(), crypto::gen_key(CURVE_BP256).unwrap()];
                let uid = crypto::rnd(uid_len);
                for case in CASES.iter() {
                    let tpl = template(case, uid_len, None).unwrap();
                    assert!(tpl.settings.validate(FILE_SIZE as usize, uid_len).is_empty(), "{}: {:?}", case.name, tpl.settings.validate(FILE_SIZE as usize, uid_len));
                    assert!(tpl.file_data.len() <= FILE_SIZE as usize);
                    let mut file = tpl.file_data.clone();
                    file.resize(FILE_SIZE as usize, 0);
                    let rk = RenderKeys {
                        meta_key: (case.meta <= 0xD).then(|| &keys[case.meta as usize][..]),
                        file_key: (case.file <= 0xD).then(|| &keys[case.file as usize][..]),
                        sig_key: (case.sig <= 1).then(|| &pubs[case.sig as usize]),
                    };
                    let dynamic = render(&file, &tpl.settings, &uid, 9, &rk, b"000", false).unwrap();
                    let p = VerifyParams {
                        uid_len,
                        meta_key: rk.meta_key,
                        file_key: rk.file_key,
                        sig_pub: None,
                        uid: Some(&uid),
                        last_ctr: None,
                    };
                    let pk = (case.sig <= 1).then(|| pubs[case.sig as usize].public());
                    let p = VerifyParams { sig_pub: pk.as_ref(), ..p };
                    let r = verify(&dynamic, &tpl.settings, &p).unwrap();
                    assert!(r.ok() || (case.file == AC_NONE && case.sig == AC_NONE), "{}: {r:?}", case.name);
                    assert_eq!(r.ctr, Some(9));
                    assert_eq!(r.uid.as_deref(), Some(&uid[..]));
                    assert_eq!(&dynamic[..first_region(&tpl, uid_len)], &tpl.file_data[..first_region(&tpl, uid_len)]);
                    if tpl.settings.options & OPT_ENC != 0 {
                        let mut want = case.enc_fill.to_vec();
                        want.resize(32, b' ');
                        assert_eq!(r.enc_plain.unwrap(), want);
                    }
                    // the settings survive the wire round trip the card step relies on
                    let enc = tpl.settings.encode().unwrap();
                    assert_eq!(SdmSettings::parse(&enc).unwrap().0, tpl.settings);
                }
            }
        }
    }

    #[test]
    fn rejected_settings_are_rejected_by_the_library_too() {
        for (what, s, local) in bad_settings(7) {
            if local {
                assert!(!s.validate(FILE_SIZE as usize, 7).is_empty(), "{what}");
            }
            assert!(s.encode().is_ok(), "{what} must be encodable so that the card sees it");
        }
    }

    #[test]
    fn counter_limit_arithmetic() {
        // limit = base + 3: with the counter at b2 the loop performs limit - b2 reads
        for (b, b2) in [(0u32, 0u32), (5, 0), (5, 5)] {
            let limit = b + 3;
            assert!(b2 < limit);
            assert_eq!((b2..limit).count() as u32, limit - b2);
        }
    }
}
