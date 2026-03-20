// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

// key = epoch(8)|shard(2)|round(8) (big-endian), value = header_id(32)
const CF_VOTE_LOG: &str = "vote_log";
const DB_DIR: &str = "slashdb";

#[cfg(unix)]
fn chmod_owner_only(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {:o} '{}'", mode, path.display()))
}

pub struct SlashDb {
    db: DB,
    write_guard: Mutex<()>,
    #[allow(dead_code)]
    lock_file: std::fs::File,
}

#[cfg(unix)]
fn chmod_rocksdb_recursive(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir '{}'", dir.display()))? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_file() {
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))?;
        } else if ft.is_dir() {
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o700))?;
            chmod_rocksdb_recursive(&entry.path())?;
        }
    }
    Ok(())
}

fn open_slashdb_rocks(path: &Path) -> Result<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    let cfs = vec![ColumnFamilyDescriptor::new(CF_VOTE_LOG, Options::default())];
    let db = DB::open_cf_descriptors(&opts, path, cfs)
        .with_context(|| format!("open slashdb rocksdb at '{}'", path.display()))?;
    #[cfg(unix)]
    {
        chmod_owner_only(path, 0o700)?;
        chmod_rocksdb_recursive(path)?;
    }
    Ok(db)
}

fn key_from(epoch: u64, shard: u16, round: u64) -> [u8; 18] {
    let mut k = [0u8; 18];
    k[0..8].copy_from_slice(&epoch.to_be_bytes());
    k[8..10].copy_from_slice(&shard.to_be_bytes());
    k[10..18].copy_from_slice(&round.to_be_bytes());
    k
}

fn to_fixed32(v: &[u8]) -> Result<[u8; 32]> {
    if v.len() != 32 {
        return Err(anyhow!("expected 32 bytes value, got {}", v.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(v);
    Ok(out)
}

impl SlashDb {
    pub fn init(db_path: &Path) -> Result<()> {
        if !db_path.exists() {
            std::fs::create_dir_all(db_path)
                .with_context(|| format!("create db dir '{}'", db_path.display()))?;
        }
        #[cfg(unix)]
        chmod_owner_only(db_path, 0o700)?;

        let db_dir = db_path.join(DB_DIR);
        let _db = open_slashdb_rocks(&db_dir)?;
        #[cfg(unix)]
        chmod_owner_only(&db_dir, 0o700)?;
        Ok(())
    }

    pub fn open_locked(db_path: &Path) -> Result<Self> {
        if !db_path.exists() {
            return Err(anyhow!(
                "slashing-db nicht gefunden: {} (zuerst 'slashdb init' ausführen)",
                db_path.display()
            ));
        }
        let lock_path = db_path.join(".lock");
        let mut lock_opts = OpenOptions::new();
        lock_opts
            .create(true)
            .read(true)
            .write(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_opts.mode(0o600);
        }
        let mut lock_file = lock_opts
            .open(&lock_path)
            .with_context(|| format!("open lock file '{}'", lock_path.display()))?;
        #[cfg(unix)]
        chmod_owner_only(&lock_path, 0o600)?;

        lock_file
            .try_lock_exclusive()
            .with_context(|| "acquire exclusive lock on slashing db")?;
        let _ = lock_file.set_len(0);
        let _ = lock_file.write_all(std::process::id().to_string().as_bytes());

        let db_dir = db_path.join(DB_DIR);
        if !db_dir.exists() {
            return Err(anyhow!(
                "slashing-db datei nicht gefunden: {} (zuerst 'slashdb init' ausführen)",
                db_dir.display()
            ));
        }
        let db = open_slashdb_rocks(&db_dir)?;
        Ok(Self {
            db,
            write_guard: Mutex::new(()),
            lock_file,
        })
    }
}

impl SlashDb {
    pub fn get_vote(&self, epoch: u64, shard: u16, round: u64) -> Result<Option<[u8; 32]>> {
        let cf = self
            .db
            .cf_handle(CF_VOTE_LOG)
            .ok_or_else(|| anyhow!("slashdb: cf '{}' not found", CF_VOTE_LOG))?;
        let k = key_from(epoch, shard, round);
        match self.db.get_cf(&cf, k).with_context(|| "slashdb get_vote")? {
            Some(v) => Ok(Some(to_fixed32(&v)?)),
            None => Ok(None),
        }
    }

    pub fn put_vote_if_absent(
        &self,
        epoch: u64,
        shard: u16,
        round: u64,
        header: [u8; 32],
    ) -> Result<()> {
        let _guard = self
            .write_guard
            .lock()
            .map_err(|_| anyhow!("slashdb write lock poisoned"))?;
        let cf = self
            .db
            .cf_handle(CF_VOTE_LOG)
            .ok_or_else(|| anyhow!("slashdb: cf '{}' not found", CF_VOTE_LOG))?;
        let k = key_from(epoch, shard, round);
        match self.db.get_cf(&cf, k).with_context(|| "slashdb get_vote")? {
            Some(existing) => {
                let cur32 = to_fixed32(&existing)?;
                if cur32 != header {
                    return Err(anyhow!(
                        "vote_log mismatch: double vote für selben (epoch,shard,round)"
                    ));
                }
            }
            None => {
                self.db
                    .put_cf(&cf, k, header)
                    .with_context(|| "slashdb put_vote")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f47_slashdb_lockfile_is_not_truncated_on_failed_lock_acquire() {
        let td = tempfile::tempdir().unwrap();
        let db_dir = td.path();
        SlashDb::init(db_dir).unwrap();

        let db1 = SlashDb::open_locked(db_dir).unwrap();
        let lock_path = db_dir.join(".lock");
        let pid_before = std::fs::read_to_string(&lock_path).unwrap();
        assert!(!pid_before.trim().is_empty(), "lock file must contain pid");

        assert!(
            SlashDb::open_locked(db_dir).is_err(),
            "second open_locked must fail while lock is held"
        );
        let pid_after = std::fs::read_to_string(&lock_path).unwrap();
        assert_eq!(
            pid_after, pid_before,
            "failed lock acquire must not truncate/overwrite existing pid"
        );

        drop(db1);
    }

    #[test]
    fn slashdb_put_get_roundtrip() {
        let td = tempfile::tempdir().unwrap();
        let db_dir = td.path();
        SlashDb::init(db_dir).unwrap();
        let db = SlashDb::open_locked(db_dir).unwrap();
        let header = [42u8; 32];
        db.put_vote_if_absent(1, 0, 10, header).unwrap();
        assert_eq!(db.get_vote(1, 0, 10).unwrap(), Some(header));
        assert_eq!(db.get_vote(1, 0, 11).unwrap(), None);
        // Idempotent: same header is ok
        db.put_vote_if_absent(1, 0, 10, header).unwrap();
        // Different header: must fail
        let other = [99u8; 32];
        assert!(db.put_vote_if_absent(1, 0, 10, other).is_err());
    }
}
