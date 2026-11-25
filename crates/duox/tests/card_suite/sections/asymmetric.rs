//! Section `asymmetric`: application level asymmetric keys, always inside a throwaway application.
//!
//! * ManageKeyPair: generate, import, metadata-only update, every KeyPolicy bit that is safe in a
//!   throwaway application, every WriteAccess form (plain / MAC / full, key 0, key 1, free, never),
//!   both curves, the KeyUsageCtr limit (reach, raise, freeze, reset by regeneration).
//! * GetKeySettings options 1 and 2 (ECC key and CA root key lists).
//! * ManageCARootKey (issuer, access rights, ReadAccess, CRL file link) and ExportKey.
//! * CryptoRequest: ECC sign (one shot, streamed, pre-hashed; verified with the returned public key on
//!   both curves), Echo, the CommMode / access condition of SetConfiguration 0x15, negative tests.
//!
//! Data sheet section numbers: 7.9, 7.15, 8.5, 8.10. PICC level asymmetric keys are never touched
//! (the guard refuses them); everything lives in applications from `ctx.alloc_aid()`.

use crate::ctx::{ensure, ensure_eq, Ctx, StepError, StepResult};
use duox::card::{
    Aid, AppSpec, CaRootKeyInfo, CaRootKeySpec, ChangeKeySpec, CommMode, EccKeyInfo, KeyPairOp, KeyPairSpec, SignInput,
    Status,
};
use duox::crypto::{self, PubKey, CURVE_BP256, CURVE_P256};

pub const NAME: &str = "asymmetric";
pub const DESCRIPTION: &str =
    "Asymmetric keys in throwaway applications: ManageKeyPair, key policies, usage limit, ManageCARootKey, ExportKey, CryptoRequest sign / echo.";

// KeyPolicy bits (Table 158).
const P_SIGN: u16 = 0x0010;
const P_SDM: u16 = 0x0020;
const P_TSIG: u16 = 0x0040;
const P_MUTUAL: u16 = 0x0080;
const P_INTERNAL: u16 = 0x0100;
const P_FREEZE: u16 = 0x8000;

pub fn run(ctx: &mut Ctx) {
    let aid = ctx.alloc_aid();
    // KeySett3 bit 2 enables the application specific CryptoAPI configuration (SetConfiguration 0x15).
    let spec = AppSpec::new(aid).keys(3).key_sett3(0x04);
    ctx.app_scope(spec, |c, aid| {
        let Some(k1) = provision(c, aid) else { return };
        key_settings_empty(c, aid);
        generate_both_curves(c, aid);
        import_keys(c, aid);
        policy_variants(c, aid);
        write_access_variants(c, aid, &k1);
        metadata_update(c, aid);
        usage_limit(c, aid);
        crypto_sign(c, aid);
        crypto_echo(c, aid);
        ca_root_keys(c, aid, &k1);
        negative(c, aid, &k1);
        crypto_access_config(c, aid, &k1);
    });
}

// ------------------------------------------------------------------ helpers
fn cf<T>(r: Result<T, crypto::CryptoError>) -> StepResult<T> {
    r.map_err(|e| StepError::fail(format!("crypto: {}", e.0)))
}

fn enter(c: &mut Ctx, aid: Aid, key: u8, k1: Option<&[u8; 16]>) -> StepResult {
    match (key, k1) {
        (1, Some(k)) => c.auth_app(aid, 1, k),
        _ => {
            let z = c.zero_key;
            c.auth_app(aid, key, &z)
        }
    }
}

fn zero_auth(c: &mut Ctx, aid: Aid) -> StepResult {
    enter(c, aid, 0, None)
}

fn ecc_entry(c: &mut Ctx, key_no: u8) -> StepResult<EccKeyInfo> {
    c.get_ecc_key_settings()?
        .into_iter()
        .find(|k| k.key_no == key_no)
        .ok_or_else(|| StepError::fail(format!("ECC key {key_no} is not listed by GetKeySettings")))
}

fn ca_entry(c: &mut Ctx, key_no: u8) -> StepResult<CaRootKeyInfo> {
    c.get_ca_root_key_settings()?
        .into_iter()
        .find(|k| k.key_no == key_no)
        .ok_or_else(|| StepError::fail(format!("CA root key {key_no} is not listed by GetKeySettings")))
}

/// Generate a key pair and return the validated public key.
fn generate(c: &mut Ctx, spec: &KeyPairSpec) -> StepResult<PubKey> {
    let raw = c.manage_key_pair(spec, &KeyPairOp::Generate, None)?;
    ensure_eq(raw.len(), 65, "public key length")?;
    ensure_eq(raw[0], 0x04, "public key format byte")?;
    cf(PubKey::from_bytes(spec.curve_id, &raw))
}

fn check_entry(e: &EccKeyInfo, curve: u8, policy: u16, wa: u8, limit: u32, used: u32) -> StepResult {
    ensure_eq(
        (e.curve, e.policy, e.write_access, e.kuc_limit, e.kuc),
        (curve, policy, wa, limit, used),
        &format!("ECC key {} (curve, policy, write access, limit, counter)", e.key_no),
    )
}

fn sign_check(c: &mut Ctx, key_no: u8, pubk: &PubKey, msg: &[u8], mode: CommMode) -> StepResult {
    let sig = c.crypto_ecc_sign(key_no, SignInput::Raw(msg), mode)?;
    ensure_eq(sig.len(), 64, "signature length")?;
    ensure(
        pubk.verify_raw(&sig, msg),
        format!("signature over {} bytes does not verify with the returned public key", msg.len()),
    )
}

// ------------------------------------------------------------------ steps
/// Key 1 gets a non-default value so that "authenticated with key 1" and "with key 0" differ.
fn provision(c: &mut Ctx, aid: Aid) -> Option<[u8; 16]> {
    c.step("provision: ChangeKey of application key 1 (used by the write access tests)", |c| {
        let k1: [u8; 16] = rand::random();
        zero_auth(c, aid)?;
        let z = c.zero_key;
        c.change_key(&ChangeKeySpec::new(1, &k1, 0x01).old_key(&z))?;
        enter(c, aid, 1, Some(&k1))?;
        Ok(k1)
    })
}

fn key_settings_empty(c: &mut Ctx, aid: Aid) {
    c.step("GetKeySettings on the new application: three keys, AES-128, empty ECC and CA root lists", |c| {
        zero_auth(c, aid)?;
        let k = c.get_key_settings()?;
        ensure_eq((k.max_keys, k.key_type), (3, 2), "MaxNoOfKeys / key type")?;
        ensure_eq(c.get_ecc_key_settings()?.len(), 0, "ECC key entries")?;
        ensure_eq(c.get_ca_root_key_settings()?.len(), 0, "CA root key entries")
    });
}

fn generate_both_curves(c: &mut Ctx, aid: Aid) {
    c.step("ManageKeyPair generate NIST P-256 (key 0, sign policy, write access 0x30)", |c| {
        zero_auth(c, aid)?;
        let pubk = generate(c, &KeyPairSpec::new(0, CURVE_P256, P_SIGN, 0x30))?;
        c.detail(format!("public key {}", hex::encode_upper(pubk.to_bytes())));
        let e = ecc_entry(c, 0)?;
        check_entry(&e, CURVE_P256, P_SIGN, 0x30, 0, 0)
    });
    c.step("ManageKeyPair generate brainpoolP256r1 (key 1, sign + SDM policy)", |c| {
        zero_auth(c, aid)?;
        generate(c, &KeyPairSpec::new(1, CURVE_BP256, P_SIGN | P_SDM, 0x30))?;
        let e = ecc_entry(c, 1)?;
        check_entry(&e, CURVE_BP256, P_SIGN | P_SDM, 0x30, 0, 0)?;
        ensure_eq(c.get_ecc_key_settings()?.len(), 2, "ECC key entries")
    });
    c.step("two generated keys in the same slot have different public keys (key 2)", |c| {
        zero_auth(c, aid)?;
        let a = generate(c, &KeyPairSpec::new(2, CURVE_P256, P_SIGN, 0x30))?;
        let b = generate(c, &KeyPairSpec::new(2, CURVE_P256, P_SIGN, 0x30))?;
        ensure(a != b, "regenerating a key returned the same public key")
    });
}

fn import_keys(c: &mut Ctx, aid: Aid) {
    for curve in [CURVE_P256, CURVE_BP256] {
        c.step(
            &format!("ManageKeyPair import ({}): signature verifies with the imported key's public half", crypto::curve_name(curve)),
            |c| {
                let local = cf(crypto::gen_key(curve))?;
                zero_auth(c, aid)?;
                let r = c.manage_key_pair(&KeyPairSpec::new(2, curve, P_SIGN, 0x30), &KeyPairOp::Import(local.to_bytes()), None)?;
                ensure_eq(r.len(), 0, "import returns no public key")?;
                check_entry(&ecc_entry(c, 2)?, curve, P_SIGN, 0x30, 0, 0)?;
                sign_check(c, 2, &local.public(), b"imported key signature test", CommMode::Mac)
            },
        );
    }
}

fn policy_variants(c: &mut Ctx, aid: Aid) {
    // Slot 2 is regenerated with every policy; the entry must report exactly what was written.
    let policies: [(u16, &str); 9] = [
        (0x0000, "no operation allowed"),
        (P_SIGN, "ECC sign"),
        (P_SDM, "SDM signature"),
        (P_TSIG, "transaction signature"),
        (P_MUTUAL, "mutual authentication"),
        (P_INTERNAL, "card-unilateral authentication"),
        (P_MUTUAL | P_INTERNAL, "mutual + unilateral"),
        (P_SIGN | P_SDM | P_TSIG | P_MUTUAL | P_INTERNAL, "all operations"),
        (P_SIGN | P_FREEZE, "sign + frozen usage limit"),
    ];
    for (policy, name) in policies {
        c.step(&format!("KeyPolicy 0x{policy:04X} ({name}) is stored and reported"), |c| {
            zero_auth(c, aid)?;
            generate(c, &KeyPairSpec::new(2, CURVE_P256, policy, 0x30))?;
            check_entry(&ecc_entry(c, 2)?, CURVE_P256, policy, 0x30, 0, 0)
        });
    }
}

fn write_access_variants(c: &mut Ctx, aid: Aid, k1: &[u8; 16]) {
    // Slot 3 walks through the write access forms. Replacing an existing key needs its current
    // write access, so the authenticating key follows the previous entry.
    let k1 = *k1;
    let mut prev: Option<u8> = None;
    for wa in [0x00u8, 0x10, 0x30, 0x31, 0x0E, 0x3F] {
        let prev_wa = prev;
        let name = match wa & 0x30 {
            0x00 => "plain",
            0x10 => "MAC",
            _ => "full",
        };
        let ar = match wa & 0x0F {
            0xE => "free access".to_string(),
            0xF => "no access".to_string(),
            n => format!("key {n}"),
        };
        c.step(&format!("WriteAccess 0x{wa:02X} ({name}, {ar}): create / replace key 3 and read it back"), |c| {
            let key = if prev_wa.is_some_and(|p| p & 0x0F == 1) { 1 } else { 0 };
            enter(c, aid, key, Some(&k1))?;
            generate(c, &KeyPairSpec::new(3, CURVE_P256, P_SIGN, wa))?;
            check_entry(&ecc_entry(c, 3)?, CURVE_P256, P_SIGN, wa, 0, 0)
        });
        prev = Some(wa);
        match wa {
            0x00 | 0x10 | 0x30 => {
                c.step(&format!("WriteAccess 0x{wa:02X}: metadata update with key 0 succeeds"), |c| {
                    zero_auth(c, aid)?;
                    c.manage_key_pair(&KeyPairSpec::new(3, CURVE_P256, P_SIGN | P_SDM, wa), &KeyPairOp::UpdateMetadata, None)?;
                    check_entry(&ecc_entry(c, 3)?, CURVE_P256, P_SIGN | P_SDM, wa, 0, 0)
                });
            }
            0x31 => {
                c.step("WriteAccess 0x31: key 0 is refused (AUTHENTICATION_ERROR), key 1 may update", |c| {
                    zero_auth(c, aid)?;
                    let r = c.manage_key_pair(&KeyPairSpec::new(3, CURVE_P256, P_SIGN | P_SDM, wa), &KeyPairOp::UpdateMetadata, None);
                    c.expect_err(Status::AuthenticationError, r)?;
                    enter(c, aid, 1, Some(&k1))?;
                    c.manage_key_pair(&KeyPairSpec::new(3, CURVE_P256, P_SIGN | P_SDM, wa), &KeyPairOp::UpdateMetadata, None)?;
                    check_entry(&ecc_entry(c, 3)?, CURVE_P256, P_SIGN | P_SDM, wa, 0, 0)
                });
            }
            0x0E => {
                c.step("WriteAccess 0x0E: a metadata update works without any authentication", |c| {
                    c.select_application(aid, None)?;
                    c.manage_key_pair(
                        &KeyPairSpec::new(3, CURVE_P256, P_SIGN | P_TSIG, wa),
                        &KeyPairOp::UpdateMetadata,
                        Some(CommMode::Plain),
                    )?;
                    zero_auth(c, aid)?;
                    check_entry(&ecc_entry(c, 3)?, CURVE_P256, P_SIGN | P_TSIG, wa, 0, 0)
                });
            }
            _ => {
                c.step("WriteAccess 0x3F (no access): update and replacement are refused with PERMISSION_DENIED", |c| {
                    zero_auth(c, aid)?;
                    let r = c.manage_key_pair(&KeyPairSpec::new(3, CURVE_P256, P_SIGN, wa), &KeyPairOp::UpdateMetadata, None);
                    c.expect_err(Status::PermissionDenied, r)?;
                    zero_auth(c, aid)?;
                    let r = c.manage_key_pair(&KeyPairSpec::new(3, CURVE_P256, P_SIGN, wa), &KeyPairOp::Generate, None);
                    c.expect_err(Status::PermissionDenied, r)?;
                    zero_auth(c, aid)?;
                    check_entry(&ecc_entry(c, 3)?, CURVE_P256, P_SIGN, wa, 0, 0)
                });
            }
        }
    }
}

fn metadata_update(c: &mut Ctx, aid: Aid) {
    c.step("metadata update keeps the key value (same public key verifies signatures before and after)", |c| {
        zero_auth(c, aid)?;
        let pubk = generate(c, &KeyPairSpec::new(0, CURVE_P256, P_SIGN, 0x30))?;
        sign_check(c, 0, &pubk, b"before", CommMode::Mac)?;
        c.manage_key_pair(&KeyPairSpec::new(0, CURVE_P256, P_SIGN | P_MUTUAL, 0x30), &KeyPairOp::UpdateMetadata, None)?;
        // no usage limit configured: nothing is counted
        check_entry(&ecc_entry(c, 0)?, CURVE_P256, P_SIGN | P_MUTUAL, 0x30, 0, 0)?;
        sign_check(c, 0, &pubk, b"after", CommMode::Mac)
    });
    c.step("metadata update with another CurveID is refused (PERMISSION_DENIED)", |c| {
        zero_auth(c, aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(0, CURVE_BP256, P_SIGN, 0x30), &KeyPairOp::UpdateMetadata, None);
        c.expect_err(Status::PermissionDenied, r)
    });
    c.step("metadata update of a key that does not exist is refused (NO_SUCH_KEY)", |c| {
        zero_auth(c, aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(4, CURVE_P256, P_SIGN, 0x30), &KeyPairOp::UpdateMetadata, None);
        c.expect_err(Status::NoSuchKey, r)
    });
}

fn usage_limit(c: &mut Ctx, aid: Aid) {
    // Key 4 carries the limit.
    let pubk = c.step("KeyUsageCtrLimit 2: key is created with the limit and counter 0", |c| {
        zero_auth(c, aid)?;
        let p = generate(c, &KeyPairSpec::new(4, CURVE_P256, P_SIGN, 0x30).kuc_limit(2))?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN, 0x30, 2, 0)?;
        Ok(p)
    });
    let Some(pubk) = pubk else { return };
    c.step("two signatures count up to the limit, the third is refused (PERMISSION_DENIED)", |c| {
        zero_auth(c, aid)?;
        sign_check(c, 4, &pubk, b"one", CommMode::Mac)?;
        sign_check(c, 4, &pubk, b"two", CommMode::Mac)?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN, 0x30, 2, 2)?;
        let r = c.crypto_ecc_sign(4, SignInput::Raw(b"three"), CommMode::Mac);
        c.expect_err(Status::PermissionDenied, r)
    });
    c.step("raising the limit by metadata update re-enables the key and keeps the counter", |c| {
        zero_auth(c, aid)?;
        c.manage_key_pair(&KeyPairSpec::new(4, CURVE_P256, P_SIGN, 0x30).kuc_limit(5), &KeyPairOp::UpdateMetadata, None)?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN, 0x30, 5, 2)?;
        sign_check(c, 4, &pubk, b"three", CommMode::Mac)?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN, 0x30, 5, 3)
    });
    c.step("limit equal to the counter disables the key at once; limit 0 re-enables it without counting", |c| {
        zero_auth(c, aid)?;
        c.manage_key_pair(&KeyPairSpec::new(4, CURVE_P256, P_SIGN, 0x30).kuc_limit(3), &KeyPairOp::UpdateMetadata, None)?;
        let r = c.crypto_ecc_sign(4, SignInput::Raw(b"x"), CommMode::Mac);
        c.expect_err(Status::PermissionDenied, r)?;
        zero_auth(c, aid)?;
        c.manage_key_pair(&KeyPairSpec::new(4, CURVE_P256, P_SIGN, 0x30).kuc_limit(0), &KeyPairOp::UpdateMetadata, None)?;
        sign_check(c, 4, &pubk, b"unlimited", CommMode::Mac)?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN, 0x30, 0, 3)
    });
    c.step("frozen limit (KeyPolicy bit 15): a different limit or a cleared bit is refused (PERMISSION_DENIED)", |c| {
        zero_auth(c, aid)?;
        c.manage_key_pair(&KeyPairSpec::new(4, CURVE_P256, P_SIGN | P_FREEZE, 0x30).kuc_limit(10), &KeyPairOp::UpdateMetadata, None)?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN | P_FREEZE, 0x30, 10, 3)?;
        let r = c.manage_key_pair(
            &KeyPairSpec::new(4, CURVE_P256, P_SIGN | P_FREEZE, 0x30).kuc_limit(11),
            &KeyPairOp::UpdateMetadata,
            None,
        );
        c.expect_err(Status::PermissionDenied, r)?;
        zero_auth(c, aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(4, CURVE_P256, P_SIGN, 0x30).kuc_limit(10), &KeyPairOp::UpdateMetadata, None);
        c.expect_err(Status::PermissionDenied, r)?;
        // the same limit with the bit still set is accepted
        zero_auth(c, aid)?;
        c.manage_key_pair(&KeyPairSpec::new(4, CURVE_P256, P_SIGN | P_FREEZE, 0x30).kuc_limit(10), &KeyPairOp::UpdateMetadata, None)?;
        Ok(())
    });
    c.step("generating a new key pair resets the counter, also with a frozen limit", |c| {
        zero_auth(c, aid)?;
        let p = generate(c, &KeyPairSpec::new(4, CURVE_P256, P_SIGN, 0x30).kuc_limit(4))?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN, 0x30, 4, 0)?;
        sign_check(c, 4, &p, b"fresh", CommMode::Mac)?;
        check_entry(&ecc_entry(c, 4)?, CURVE_P256, P_SIGN, 0x30, 4, 1)
    });
}

fn crypto_sign(c: &mut Ctx, aid: Aid) {
    // Keys 0 (P-256) and 1 (brainpool) sign every message shape; the public key from the key
    // generation verifies each signature.
    for (key_no, curve) in [(0u8, CURVE_P256), (1u8, CURVE_BP256)] {
        let cname = crypto::curve_name(curve);
        let pubk = c.step(&format!("CryptoRequest sign: fresh {cname} key {key_no}"), |c| {
            zero_auth(c, aid)?;
            generate(c, &KeyPairSpec::new(key_no, curve, P_SIGN, 0x30))
        });
        let Some(pubk) = pubk else { continue };
        c.step(&format!("{cname}: one-shot raw data of 0, 3, 100 and 224 bytes"), |c| {
            zero_auth(c, aid)?;
            for n in [0usize, 3, 100, 224] {
                let msg: Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
                sign_check(c, key_no, &pubk, &msg, CommMode::Mac)?;
            }
            Ok(())
        });
        c.step(&format!("{cname}: streamed raw data (initialize / update / finalize) of 225, 448, 449 and 1000 bytes"), |c| {
            zero_auth(c, aid)?;
            for n in [225usize, 448, 449, 1000] {
                let msg: Vec<u8> = (0..n).map(|i| (i * 13 + 5) as u8).collect();
                sign_check(c, key_no, &pubk, &msg, CommMode::Mac)?;
            }
            Ok(())
        });
        c.step(&format!("{cname}: pre-hashed input (SHA-256 digest)"), |c| {
            zero_auth(c, aid)?;
            let msg = b"pre-hashed message for the card suite";
            let digest = crypto::sha256(msg);
            let sig = c.crypto_ecc_sign(key_no, SignInput::Hash(&digest), CommMode::Mac)?;
            ensure_eq(sig.len(), 64, "signature length")?;
            ensure(pubk.verify_hash(&sig, &digest), "pre-hashed signature does not verify over the digest")?;
            ensure(pubk.verify_raw(&sig, msg), "pre-hashed signature does not verify over the original message")
        });
        c.step(&format!("{cname}: two signatures of the same data differ (random nonce) and both verify"), |c| {
            zero_auth(c, aid)?;
            let a = c.crypto_ecc_sign(key_no, SignInput::Raw(b"same"), CommMode::Mac)?;
            let b = c.crypto_ecc_sign(key_no, SignInput::Raw(b"same"), CommMode::Mac)?;
            ensure(pubk.verify_raw(&a, b"same") && pubk.verify_raw(&b, b"same"), "signature does not verify")?;
            ensure(a != b, "two signatures of the same data are identical")
        });
    }
}

fn crypto_echo(c: &mut Ctx, aid: Aid) {
    c.step("CryptoRequest echo returns the bytes it was given (MAC mode, 1 / 16 / 100 / 200 bytes)", |c| {
        zero_auth(c, aid)?;
        for n in [1usize, 16, 100, 200] {
            let d: Vec<u8> = (0..n).map(|i| (i as u8) ^ 0xA5).collect();
            ensure_eq(c.crypto_echo(&d, CommMode::Mac)?, d, &format!("echo of {n} bytes"))?;
        }
        Ok(())
    });
    c.step("CryptoRequest echo with empty or oversized data is refused by the library", |c| {
        zero_auth(c, aid)?;
        ensure(c.crypto_echo(&[], CommMode::Mac).is_err(), "empty echo accepted")?;
        ensure(c.crypto_echo(&[0u8; 255], CommMode::Mac).is_err(), "255 byte echo accepted")
    });
}

fn crypto_access_config(c: &mut Ctx, aid: Aid, k1: &[u8; 16]) {
    let k1 = *k1;
    let pubk = c.step("CryptoRequest access: key 0 is a fresh P-256 signing key", |c| {
        zero_auth(c, aid)?;
        generate(c, &KeyPairSpec::new(0, CURVE_P256, P_SIGN, 0x30))
    });
    let Some(pubk) = pubk else { return };
    c.step("SetConfiguration 0x15 CommMode Full (0x30): sign and echo work in Full mode, configuration reads back", |c| {
        zero_auth(c, aid)?;
        c.set_configuration(0x15, &[0x02, 0x30])?;
        zero_auth(c, aid)?;
        let cfg = c.get_configuration(Some(0x15))?;
        c.detail(format!("GetConfiguration 0x15: {}", hex::encode_upper(&cfg)));
        ensure(cfg.starts_with(&[0x02, 0x30]), "configuration 0x15 does not read back as written")?;
        sign_check(c, 0, &pubk, b"full mode", CommMode::Full)?;
        ensure_eq(c.crypto_echo(b"full echo", CommMode::Full)?, b"full echo".to_vec(), "echo in Full mode")
    });
    c.step("SetConfiguration 0x15 plain (0x00): sign works in plain mode", |c| {
        zero_auth(c, aid)?;
        c.set_configuration(0x15, &[0x02, 0x00])?;
        zero_auth(c, aid)?;
        sign_check(c, 0, &pubk, b"plain mode", CommMode::Plain)
    });
    c.step("SetConfiguration 0x15 access condition key 1 (0x11): key 0 is refused, key 1 signs", |c| {
        zero_auth(c, aid)?;
        c.set_configuration(0x15, &[0x02, 0x11])?;
        zero_auth(c, aid)?;
        let r = c.crypto_ecc_sign(0, SignInput::Raw(b"x"), CommMode::Mac);
        c.expect_err(Status::AuthenticationError, r)?;
        enter(c, aid, 1, Some(&k1))?;
        sign_check(c, 0, &pubk, b"key one", CommMode::Mac)
    });
    c.step("SetConfiguration 0x15 access 0x0F (no access): CryptoRequest is refused (PERMISSION_DENIED), then restore", |c| {
        zero_auth(c, aid)?;
        c.set_configuration(0x15, &[0x02, 0x1F])?;
        zero_auth(c, aid)?;
        let r = c.crypto_ecc_sign(0, SignInput::Raw(b"x"), CommMode::Mac);
        c.expect_err(Status::PermissionDenied, r)?;
        zero_auth(c, aid)?;
        c.set_configuration(0x15, &[0x02, 0x10])?;
        zero_auth(c, aid)?;
        sign_check(c, 0, &pubk, b"restored", CommMode::Mac)
    });
    c.step("SetConfiguration 0x15 with an unsupported Support byte is refused (PARAMETER_ERROR)", |c| {
        zero_auth(c, aid)?;
        let r = c.set_configuration(0x15, &[0x01, 0x10]);
        c.expect_err(Status::ParameterError, r)
    });
}

fn ca_root_keys(c: &mut Ctx, aid: Aid, k1: &[u8; 16]) {
    let k1 = *k1;
    // (slot, curve, ReadAccess)
    let slots: [(u8, u8, u8); 4] =
        [(0, CURVE_P256, 0x0E), (1, CURVE_BP256, 0x10), (2, CURVE_P256, 0x30), (3, CURVE_BP256, 0x3F)];
    let mut keys: Vec<(u8, u8, Vec<u8>)> = vec![];
    for (slot, curve, ra) in slots {
        let made = c.step(
            &format!("ManageCARootKey slot {slot} ({}), ReadAccess 0x{ra:02X}: stored and listed", crypto::curve_name(curve)),
            |c| {
                let ca = cf(crypto::gen_key(curve))?;
                let public = ca.public().to_bytes();
                zero_auth(c, aid)?;
                let mut spec = CaRootKeySpec::new(slot, curve, public.clone());
                spec.access_rights = 0x0005 | ((slot as u16) << 8);
                spec.write_access = 0x30;
                spec.read_access = ra;
                spec.issuer = format!("Suite CA {slot}").into_bytes();
                c.manage_ca_root_key(&spec, None)?;
                let e = ca_entry(c, slot)?;
                ensure_eq(
                    (e.curve, e.access_rights, e.write_access, e.read_access, e.crl_file, e.crl_aid),
                    (curve, spec.access_rights, 0x30, ra, 0, Aid::PICC),
                    "CA root key entry",
                )?;
                Ok(public)
            },
        );
        if let Some(p) = made {
            keys.push((slot, ra, p));
        }
    }
    for (slot, ra, public) in keys {
        match ra {
            0x0E => {
                c.step(&format!("ExportKey slot {slot}: free read access works without authentication (plain)"), |c| {
                    c.select_application(aid, None)?;
                    ensure_eq(c.export_key(slot, None)?, public.clone(), "exported key")
                });
            }
            0x10 | 0x30 => {
                let m = if ra == 0x10 { "MAC" } else { "Full" };
                c.step(&format!("ExportKey slot {slot}: ReadAccess 0x{ra:02X} (key 0, {m}) returns the stored key"), |c| {
                    zero_auth(c, aid)?;
                    ensure_eq(c.export_key(slot, None)?, public.clone(), "exported key")?;
                    // not authenticated: the access condition is not met
                    c.select_application(aid, None)?;
                    let r = c.export_key(slot, Some(CommMode::Plain));
                    c.expect_err(Status::AuthenticationError, r)
                });
            }
            _ => {
                c.step(&format!("ExportKey slot {slot}: ReadAccess 0x{ra:02X} (no access) is refused (PERMISSION_DENIED)"), |c| {
                    zero_auth(c, aid)?;
                    let r = c.export_key(slot, None);
                    c.expect_err(Status::PermissionDenied, r)
                });
            }
        }
    }
    c.step("ExportKey of a CA root slot that does not exist (4) is refused (NO_SUCH_KEY)", |c| {
        zero_auth(c, aid)?;
        let r = c.export_key(4, Some(CommMode::Mac));
        c.expect_err(Status::NoSuchKey, r)
    });
    c.step("ManageCARootKey update (WriteAccess 0x30): access rights, ReadAccess and issuer change, key stays", |c| {
        zero_auth(c, aid)?;
        let before = c.export_key(2, None)?;
        let mut spec = CaRootKeySpec::new(2, CURVE_P256, before.clone());
        spec.access_rights = 0x3FFF;
        spec.write_access = 0x30;
        spec.read_access = 0x30;
        spec.issuer = vec![0x5A; 255];
        c.manage_ca_root_key(&spec, None)?;
        let e = ca_entry(c, 2)?;
        ensure_eq((e.access_rights, e.read_access), (0x3FFF, 0x30), "updated entry")?;
        ensure_eq(c.export_key(2, None)?, before, "exported key after the update")
    });
    c.step("ManageCARootKey slot 4: CRL file link (file 5 of this application) and WriteAccess 0x31", |c| {
        let ca = cf(crypto::gen_key(CURVE_P256))?;
        zero_auth(c, aid)?;
        let mut spec = CaRootKeySpec::new(4, CURVE_P256, ca.public().to_bytes());
        spec.access_rights = 0x0001;
        spec.write_access = 0x31;
        spec.read_access = 0x30;
        spec.crl_file = 0x85;
        spec.crl_aid = aid;
        // the file does not exist: the command is accepted, revocation just is not active
        c.manage_ca_root_key(&spec, None)?;
        let e = ca_entry(c, 4)?;
        ensure_eq((e.crl_file, e.crl_aid, e.write_access), (0x85, aid, 0x31), "CRL link in the entry")?;
        // key 0 does not satisfy write access 1
        zero_auth(c, aid)?;
        let r = c.manage_ca_root_key(&spec, None);
        c.expect_err(Status::AuthenticationError, r)?;
        enter(c, aid, 1, Some(&k1))?;
        spec.access_rights = 0x0003;
        c.manage_ca_root_key(&spec, None)?;
        ensure_eq(ca_entry(c, 4)?.access_rights, 0x0003, "access rights after the update by key 1")
    });
    c.step("GetKeySettings lists five CA root entries and five ECC entries (the application maximum)", |c| {
        zero_auth(c, aid)?;
        ensure_eq(c.get_ca_root_key_settings()?.len(), 5, "CA root entries")?;
        ensure_eq(c.get_ecc_key_settings()?.len(), 5, "ECC entries")
    });
}

fn negative(c: &mut Ctx, aid: Aid, k1: &[u8; 16]) {
    let k1 = *k1;
    c.step("ManageKeyPair creating a key without authentication is refused (AUTHENTICATION_ERROR)", |c| {
        c.select_application(aid, None)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(3, CURVE_P256, P_SIGN, 0x30), &KeyPairOp::Generate, Some(CommMode::Plain));
        // measured: PERMISSION_DENIED (key creation needs authentication; the card names the missing permission)
        let st = c.expect_any_status(r)?;
        ensure(matches!(st, Status::AuthenticationError | Status::PermissionDenied), format!("unexpected status {st}"))
    });
    c.step("ManageCARootKey without authentication is refused (AUTHENTICATION_ERROR)", |c| {
        let ca = cf(crypto::gen_key(CURVE_P256))?;
        c.select_application(aid, None)?;
        let r = c.manage_ca_root_key(&CaRootKeySpec::new(0, CURVE_P256, ca.public().to_bytes()), Some(CommMode::Plain));
        c.expect_err(Status::AuthenticationError, r)
    });
    c.step("ManageKeyPair with CurveID 0x0E is refused (PARAMETER_ERROR)", |c| {
        zero_auth(c, aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(0, 0x0E, P_SIGN, 0x30), &KeyPairOp::Generate, None);
        c.expect_err(Status::ParameterError, r)
    });
    c.step("ManageKeyPair import of the scalar 0 is refused", |c| {
        zero_auth(c, aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(2, CURVE_P256, P_SIGN, 0x30), &KeyPairOp::Import(vec![0u8; 32]), None);
        let st = c.expect_any_status(r)?;
        c.detail(format!("the card answered {st}"));
        Ok(())
    });
    c.step("ManageKeyPair import with a private key of the wrong length is refused by the library", |c| {
        zero_auth(c, aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(2, CURVE_P256, P_SIGN, 0x30), &KeyPairOp::Import(vec![1u8; 31]), None);
        ensure(matches!(r, Err(StepError::Card(duox::Error::InvalidArgument(_)))), "31 byte private key accepted")
    });
    c.step("ManageCARootKey with a 64 byte public key is refused by the library", |c| {
        zero_auth(c, aid)?;
        let r = c.manage_ca_root_key(&CaRootKeySpec::new(0, CURVE_P256, vec![4u8; 64]), None);
        ensure(matches!(r, Err(StepError::Card(duox::Error::InvalidArgument(_)))), "64 byte public key accepted")
    });
    c.step("ManageKeyPair for key number 5 (one past the application maximum) is refused", |c| {
        zero_auth(c, aid)?;
        let r = c.manage_key_pair(&KeyPairSpec::new(5, CURVE_P256, P_SIGN, 0x30), &KeyPairOp::Generate, Some(CommMode::Full));
        let st = c.expect_any_status(r)?;
        ensure(matches!(st, Status::ParameterError | Status::NoSuchKey | Status::LengthError), format!("unexpected status {st}"))?;
        c.detail(format!("the card answered {st}"));
        Ok(())
    });
    c.step("updating a CA root key (WriteAccess 0x30) with key 1 only is refused (AUTHENTICATION_ERROR)", |c| {
        enter(c, aid, 1, Some(&k1))?;
        let ca = cf(crypto::gen_key(CURVE_P256))?;
        let mut spec = CaRootKeySpec::new(0, CURVE_P256, ca.public().to_bytes());
        spec.write_access = 0x30;
        let r = c.manage_ca_root_key(&spec, None);
        c.expect_err(Status::AuthenticationError, r)
    });
    c.step("CryptoRequest sign with a key whose policy lacks ECC sign is refused (PERMISSION_DENIED)", |c| {
        zero_auth(c, aid)?;
        generate(c, &KeyPairSpec::new(2, CURVE_P256, P_MUTUAL | P_INTERNAL | P_SDM | P_TSIG, 0x30))?;
        let r = c.crypto_ecc_sign(2, SignInput::Raw(b"no"), CommMode::Mac);
        c.expect_err(Status::PermissionDenied, r)
    });
    c.step("CryptoRequest sign with key number 5 is refused", |c| {
        zero_auth(c, aid)?;
        let r = c.crypto_ecc_sign(5, SignInput::Raw(b"no"), CommMode::Mac);
        let st = c.expect_any_status(r)?;
        ensure(matches!(st, Status::NoSuchKey | Status::ParameterError), format!("unexpected status {st}"))?;
        c.detail(format!("the card answered {st}"));
        Ok(())
    });
    c.step("CryptoRequest sign without authentication is refused (AUTHENTICATION_ERROR)", |c| {
        c.select_application(aid, None)?;
        let r = c.crypto_ecc_sign(0, SignInput::Raw(b"no"), CommMode::Plain);
        c.expect_err(Status::AuthenticationError, r)
    });
    c.step("CryptoRequest pre-hashed input of the wrong length is refused by the library", |c| {
        zero_auth(c, aid)?;
        let r = c.crypto_ecc_sign(0, SignInput::Hash(&[0u8; 31]), CommMode::Mac);
        ensure(matches!(r, Err(duox::Error::InvalidArgument(_))), "31 byte digest accepted")
    });
}
