//! `KeyChange`: the only way the suite changes a PICC level symmetric key.
//!
//! Format does not reset PICC keys, so a key left changed would lock the owner out of the card.
//! [`Ctx::change_picc_key`] therefore
//!
//! 1. asks the [`Guard`](crate::guard::Guard) (PICC master key, PICCDAM keys 0x10..0x12, VC keys only,
//!    AES-128 only, never the NXPDAM keys),
//! 2. PROVES the value it will restore to by authenticating with it (the factory value is never assumed)
//!    and reads the version byte to restore,
//! 3. writes old key, new key, UID and the way back to `card-suite-recovery.txt` BEFORE ChangeKey is sent,
//! 4. sends ChangeKey (or ChangeKeyEV2) and re-authenticates with the new key to verify it,
//! 5. registers a restore action in the cleanup stack.
//!
//! The recovery entry is deleted (and the file with the last entry) only after the old key
//! authenticates again and its version matches. [`Ctx::revert_key_change`] restores early.
//!
//! If the run dies in between, `cargo test -p duox --test card_suite recover -- --ignored --nocapture`
//! with `DUOX_SUITE_CONFIRM` set reads the file and puts every key back.

use crate::ctx::{ensure, Ctx, StepError, StepResult};
use crate::guard::{Level, Op};
use duox::card::ChangeKeySpec;
use std::path::PathBuf;

/// Wire byte of a PICC key number: the key type (AES-128) travels in bits 7..6 for the master key and the VC keys.
pub fn wire_key_no(key_no: u8) -> u8 {
    match key_no {
        0x00 | 0x20 | 0x21 => 0x80 | key_no,
        n => n,
    }
}

// ------------------------------------------------------------------ recovery file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecEntry {
    pub id: u64,
    pub uid: String,
    pub key_no: u8,
    pub old_key: String,
    pub old_version: u8,
    pub new_key: String,
    pub new_version: u8,
    pub ev2: bool,
}

#[derive(Debug)]
pub struct Recovery {
    path: PathBuf,
    entries: Vec<RecEntry>,
    next: u64,
}

impl Recovery {
    pub fn new(path: PathBuf) -> Self {
        Recovery { path, entries: vec![], next: 1 }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn entries(&self) -> &[RecEntry] {
        &self.entries
    }

    pub fn get(&self, id: u64) -> Option<&RecEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn pending_for(&self, key_no: u8) -> bool {
        self.entries.iter().any(|e| e.key_no == key_no)
    }

    /// Add an entry and write the file (fails if the file cannot be written: then no key may be changed).
    pub fn add(&mut self, mut e: RecEntry) -> std::io::Result<u64> {
        e.id = self.next;
        self.next += 1;
        self.entries.push(e);
        if let Err(err) = self.write() {
            self.entries.pop();
            return Err(err);
        }
        Ok(self.next - 1)
    }

    /// Drop an entry (its key is restored and verified) and rewrite or delete the file.
    pub fn remove(&mut self, id: u64) -> std::io::Result<()> {
        self.entries.retain(|e| e.id != id);
        self.write()
    }

    pub fn write(&self) -> std::io::Result<()> {
        if self.entries.is_empty() {
            return match std::fs::remove_file(&self.path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&self.path, self.render())
    }

    fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("DUOX card-suite recovery file\n");
        s.push_str("==============================\n");
        s.push_str("Written BEFORE a PICC level key was changed. If this file exists, the last run did not finish\n");
        s.push_str("restoring: the card may carry the NEW key below instead of the OLD one.\n\n");
        s.push_str("Automatic undo (card in the reader, UID below):\n");
        s.push_str("  set DUOX_SUITE_CONFIRM=<UID>\n");
        s.push_str("  cargo test -p duox --test card_suite recover -- --ignored --test-threads=1 --nocapture\n\n");
        s.push_str("Manual undo: authenticate AES-128 with the NEW key (or the OLD one if the change did not\n");
        s.push_str("happen), then ChangeKey the same key number back to the OLD key with the OLD version.\n");
        s.push_str("For key numbers other than the master key authenticate the PICC master key first.\n");
        s.push_str("Delete this file only after the card authenticates with the OLD key again.\n\n");
        for e in &self.entries {
            s.push_str("[entry]\n");
            s.push_str(&format!("uid={}\n", e.uid));
            s.push_str(&format!("key_no={:02X}\n", e.key_no));
            s.push_str(&format!("old_key={}\n", e.old_key));
            s.push_str(&format!("old_version={:02X}\n", e.old_version));
            s.push_str(&format!("new_key={}\n", e.new_key));
            s.push_str(&format!("new_version={:02X}\n", e.new_version));
            s.push_str(&format!("ev2={}\n\n", e.ev2));
        }
        s
    }

    /// Parse a file written by [`Recovery::write`].
    pub fn parse(text: &str) -> Vec<RecEntry> {
        let mut out: Vec<RecEntry> = vec![];
        let mut cur: Option<RecEntry> = None;
        for line in text.lines().map(str::trim) {
            if line == "[entry]" {
                out.extend(cur.take());
                cur = Some(RecEntry {
                    id: out.len() as u64 + 1,
                    uid: String::new(),
                    key_no: 0,
                    old_key: String::new(),
                    old_version: 0,
                    new_key: String::new(),
                    new_version: 0,
                    ev2: false,
                });
                continue;
            }
            let (Some(e), Some((k, v))) = (cur.as_mut(), line.split_once('=')) else { continue };
            match k {
                "uid" => e.uid = v.into(),
                "key_no" => e.key_no = u8::from_str_radix(v, 16).unwrap_or(0),
                "old_key" => e.old_key = v.into(),
                "old_version" => e.old_version = u8::from_str_radix(v, 16).unwrap_or(0),
                "new_key" => e.new_key = v.into(),
                "new_version" => e.new_version = u8::from_str_radix(v, 16).unwrap_or(0),
                "ev2" => e.ev2 = v == "true",
                _ => {}
            }
        }
        out.extend(cur);
        out
    }

    /// Replace the in-memory entries (recovery mode).
    pub fn load(&mut self, entries: Vec<RecEntry>) {
        self.next = entries.iter().map(|e| e.id).max().unwrap_or(0) + 1;
        self.entries = entries;
    }
}

// ------------------------------------------------------------------ the helper
/// What to change. Build with [`KeyChange::master`] or [`KeyChange::picc_dam`].
#[derive(Debug, Clone)]
pub struct KeyChange {
    /// Logical PICC key number: 0x00, 0x10..=0x12, 0x20, 0x21 (type bits are added automatically).
    pub key_no: u8,
    /// AES-128 key to change to.
    pub new_key: Vec<u8>,
    pub new_version: u8,
    /// The value to restore to. Required for every key except the master key (whose current value is
    /// `ctx.picc_key`). It is proven by authenticating with it before anything is changed.
    pub old_key: Option<Vec<u8>>,
    /// Use ChangeKeyEV2 (key set 0) instead of ChangeKey for the forward change.
    pub ev2: bool,
}

impl KeyChange {
    /// Change the PICC master key (restores to the key currently in `ctx.picc_key`).
    pub fn master(new_key: &[u8], new_version: u8) -> Self {
        KeyChange { key_no: 0, new_key: new_key.to_vec(), new_version, old_key: None, ev2: false }
    }

    /// Change another PICC key whose current value is `old_key` (e.g. PICCDAMAuthKey 0x10, factory zero).
    pub fn other(key_no: u8, old_key: &[u8], new_key: &[u8], new_version: u8) -> Self {
        KeyChange { key_no, new_key: new_key.to_vec(), new_version, old_key: Some(old_key.to_vec()), ev2: false }
    }

    pub fn ev2(mut self) -> Self {
        self.ev2 = true;
        self
    }
}

/// Returned by [`Ctx::change_picc_key`]; pass to [`Ctx::revert_key_change`] to restore early.
#[derive(Debug, Clone, Copy)]
pub struct KeyChangeHandle {
    entry: u64,
    key_no: u8,
}

fn recovery_error(path: &std::path::Path) -> String {
    format!("see {} for the exact recovery instructions", path.display())
}

impl Ctx {
    /// Change a PICC level key with proof of the restore value, recovery file, verification and a
    /// registered restore action. On success the card is authenticated with the PICC master key
    /// (the new one if the master key was changed; `ctx.picc_key` is updated accordingly).
    pub fn change_picc_key(&mut self, kc: KeyChange) -> StepResult<KeyChangeHandle> {
        let wire = wire_key_no(kc.key_no);
        let key_set = kc.ev2.then_some(0);
        self.guard.check(&Op::ChangeKey { level: Level::Picc, key_no: wire, key_set })?;
        if self.dry {
            return Err(StepError::skip("DRY run: would change a PICC key"));
        }
        ensure(kc.new_key.len() == 16, "only AES-128 PICC keys are used")?;
        let master = kc.key_no == 0;
        let old_key = if master {
            self.picc_key.clone()
        } else {
            kc.old_key.clone().ok_or_else(|| StepError::fail("KeyChange::other needs the old key"))?
        };
        ensure(old_key.len() == 16 && old_key != kc.new_key, "old and new key must be two different AES-128 keys")?;
        ensure(!self.recovery.pending_for(kc.key_no), "an earlier change of this key is still unresolved (see the recovery file)")?;

        // 1. prove the old key (never assume the factory value)
        self.auth_picc_key(kc.key_no, &old_key)
            .map_err(|e| StepError::fail(format!("cannot prove the old value of PICC key {:02X}: {e}", kc.key_no)))?;
        if !master {
            self.auth_picc()?;
        }
        let old_version = *self
            .card
            .get_key_version(kc.key_no, None)?
            .first()
            .ok_or_else(|| StepError::fail("GetKeyVersion returned nothing"))?;

        // 2. recovery file first
        let entry = crate::keychange::RecEntry {
            id: 0,
            uid: hex::encode_upper(&self.uid),
            key_no: kc.key_no,
            old_key: hex::encode_upper(&old_key),
            old_version,
            new_key: hex::encode_upper(&kc.new_key),
            new_version: kc.new_version,
            ev2: kc.ev2,
        };
        let id = self
            .recovery
            .add(entry)
            .map_err(|e| StepError::fail(format!("cannot write the recovery file, key NOT changed: {e}")))?;
        let path = self.recovery.path().clone();
        self.detail(format!("recovery file written: {}", path.display()));

        // 3. restore action before the change is sent
        let handle = KeyChangeHandle { entry: id, key_no: kc.key_no };
        self.push_restore(handle);

        // 4. send
        let spec = ChangeKeySpec {
            key_no: wire,
            new_key: kc.new_key.clone(),
            old_key: if master { None } else { Some(old_key.clone()) },
            key_version: kc.new_version,
            key_set,
        };
        if let Err(e) = self.change_key_unchecked_by_level(&spec) {
            // The card refused (or the link broke). Find out which key is live.
            if self.auth_picc_key(kc.key_no, &old_key).is_ok() {
                self.pop_restore(handle);
                let _ = self.recovery.remove(id);
                if !master {
                    let _ = self.auth_picc();
                }
                return Err(e);
            }
            if master && self.auth_picc_key(0, &kc.new_key).is_ok() {
                self.picc_key = kc.new_key.clone();
            }
            return Err(StepError::fail(format!(
                "ChangeKey failed ({e}) and the state of key {:02X} must be checked; the restore action is armed, {}",
                kc.key_no,
                recovery_error(&path)
            )));
        }
        if master {
            self.picc_key = kc.new_key.clone();
        }

        // 5. verify the new key
        self.auth_picc_key(kc.key_no, &kc.new_key).map_err(|e| {
            StepError::fail(format!(
                "after ChangeKey the NEW key does not authenticate ({e}); the restore action is armed, {}",
                recovery_error(&path)
            ))
        })?;
        if !master {
            self.auth_picc()?;
        }
        let v = self.card.get_key_version(kc.key_no, None)?;
        ensure(v.first() == Some(&kc.new_version), format!("key version after the change is {v:02X?}, expected {:02X}", kc.new_version))?;
        Ok(handle)
    }

    /// Restore the key now (instead of at the end of the run) and verify it. On failure the restore
    /// action stays armed for the end-of-run cleanup.
    pub fn revert_key_change(&mut self, h: KeyChangeHandle) -> StepResult {
        self.pop_restore(h);
        let r = self.restore_key_entry(h.entry);
        if r.is_err() {
            self.push_restore(h);
        }
        r
    }

    fn push_restore(&mut self, h: KeyChangeHandle) {
        let id = self.push_cleanup(&format!("restore PICC key {:02X}", h.key_no), move |c| c.restore_key_entry(h.entry));
        self.restore_ids.push((h.entry, id));
    }

    fn pop_restore(&mut self, h: KeyChangeHandle) {
        let ids: Vec<_> = self.restore_ids.iter().filter(|(e, _)| *e == h.entry).map(|(_, c)| *c).collect();
        for id in ids {
            self.cancel_cleanup(id);
        }
        self.restore_ids.retain(|(e, _)| *e != h.entry);
    }

    /// Put the key of a recovery entry back, verify, and delete the entry. Idempotent.
    pub(crate) fn restore_key_entry(&mut self, entry_id: u64) -> StepResult {
        let Some(e) = self.recovery.get(entry_id).cloned() else { return Ok(()) };
        let old = hex::decode(&e.old_key)?;
        let new = hex::decode(&e.new_key)?;
        let master = e.key_no == 0;
        let wire = wire_key_no(e.key_no);
        if self.auth_picc_key(e.key_no, &old).is_ok() {
            // nothing to do: the old key is live
        } else if master {
            self.auth_picc_key(0, &new)
                .map_err(|err| StepError::fail(format!("neither the old nor the new PICC master key authenticates ({err})")))?;
            let spec = ChangeKeySpec { key_no: wire, new_key: old.clone(), old_key: None, key_version: e.old_version, key_set: None };
            self.change_key_unchecked_by_level(&spec)?;
        } else {
            self.auth_picc()?;
            let spec = ChangeKeySpec {
                key_no: wire,
                new_key: old.clone(),
                old_key: Some(new.clone()),
                key_version: e.old_version,
                key_set: None,
            };
            self.change_key_unchecked_by_level(&spec)?;
        }
        // verify
        self.auth_picc_key(e.key_no, &old)
            .map_err(|err| StepError::fail(format!("after the restore the old key of PICC key {:02X} does not authenticate: {err}", e.key_no)))?;
        if master {
            self.picc_key = old.clone();
        } else {
            self.auth_picc()?;
        }
        let v = self.card.get_key_version(e.key_no, None)?;
        ensure(v.first() == Some(&e.old_version), format!("restored key version is {v:02X?}, expected {:02X}", e.old_version))?;
        self.recovery.remove(entry_id)?;
        Ok(())
    }
}

/// Recovery mode: put back every key listed in the recovery file. Returns a report.
pub fn recover_from_file(ctx: &mut Ctx, entries: Vec<RecEntry>) -> Result<String, String> {
    ctx.recovery.load(entries);
    let all: Vec<RecEntry> = ctx.recovery.entries().to_vec();
    let mut candidates: Vec<Vec<u8>> = vec![vec![0; 16]];
    for e in all.iter().filter(|e| e.key_no == 0) {
        for h in [&e.old_key, &e.new_key] {
            if let Ok(k) = hex::decode(h) {
                if !candidates.contains(&k) {
                    candidates.push(k);
                }
            }
        }
    }
    let mut found = None;
    for k in candidates {
        if ctx.auth_picc_key(0, &k).is_ok() {
            found = Some(k);
            break;
        }
    }
    let master = found.ok_or("no candidate authenticates the PICC master key")?;
    ctx.picc_key = master;
    let mut report = String::new();
    for e in all.iter().filter(|e| e.key_no != 0).chain(all.iter().rev().filter(|e| e.key_no == 0)) {
        let r = ctx.restore_key_entry(e.id);
        report.push_str(&format!("key {:02X}: {}\n", e.key_no, match &r {
            Ok(()) => "restored and verified".to_string(),
            Err(err) => format!("FAILED: {err}"),
        }));
    }
    if ctx.recovery.entries().is_empty() {
        Ok(report)
    } else {
        Err(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_numbers() {
        assert_eq!(wire_key_no(0), 0x80);
        assert_eq!(wire_key_no(0x10), 0x10);
        assert_eq!(wire_key_no(0x20), 0xA0);
        assert_eq!(wire_key_no(0x21), 0xA1);
    }

    #[test]
    fn recovery_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("duox-recovery-test-{}", std::process::id()));
        let path = dir.join("card-suite-recovery.txt");
        let mut r = Recovery::new(path.clone());
        let e = |key_no, new: &str| RecEntry {
            id: 0,
            uid: "04330F72431F90".into(),
            key_no,
            old_key: "00".repeat(16),
            old_version: 0,
            new_key: new.repeat(16),
            new_version: 0x42,
            ev2: key_no == 0,
        };
        let a = r.add(e(0, "AB")).unwrap();
        let b = r.add(e(0x10, "CD")).unwrap();
        assert!(path.exists());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("04330F72431F90") && text.contains(&"AB".repeat(16)) && text.contains("undo"));
        let parsed = Recovery::parse(&text);
        assert_eq!(parsed.len(), 2);
        assert_eq!((parsed[1].key_no, parsed[1].new_version, parsed[0].ev2), (0x10, 0x42, true));
        r.remove(a).unwrap();
        assert!(path.exists());
        r.remove(b).unwrap();
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
