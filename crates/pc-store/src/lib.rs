// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
pub mod segment;

use anyhow::{anyhow, Result};
use pc_codec::{decode_exact, Encodable};
use pc_types::{
    payload_merkle_root, payload_merkle_root_v2, payload_merkle_root_v3, payload_v2_to_v3,
    AnchorHeader, AnchorHeaderV2, AnchorPayload, AnchorPayloadV2, AnchorPayloadV3,
    MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES,
};
use segment::SegmentStore;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

fn is_symlink(p: &Path) -> bool {
    match fs::symlink_metadata(p) {
        Ok(md) => md.file_type().is_symlink(),
        Err(_) => false,
    }
}

#[cfg(unix)]
fn set_dir_mode_secure(p: &Path) -> Result<()> {
    let md = fs::metadata(p)?;
    let mut perms = md.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(p, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode_secure(_p: &Path) -> Result<()> {
    Ok(())
}

fn create_dir_all_secure(p: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mut b = fs::DirBuilder::new();
        b.recursive(true);
        // Create directories with restrictive permissions to minimize the TOCTOU window
        // before chmod(0700) is applied.
        b.mode(0o700);
        b.create(p)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::create_dir_all(p)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_file_mode_secure(p: &Path) -> Result<()> {
    let md = fs::metadata(p)?;
    let mut perms = md.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(p, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_secure(_p: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn open_dir_nofollow(p: &Path) -> Result<File> {
    // Use O_NOFOLLOW + O_DIRECTORY to avoid symlink traversal (best effort hardening
    // against path-based TOCTOU attacks).
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(p)?;
    // Ensure it's a directory (defense-in-depth; open() already used O_DIRECTORY).
    if !f.metadata()?.is_dir() {
        return Err(anyhow!("not a directory: {}", p.display()));
    }
    Ok(f)
}

pub struct FileStore {
    headers_dir: PathBuf,
    payloads_dir: PathBuf,
    payload_segments: SegmentStore,
    fsync: bool,
}

impl std::fmt::Debug for FileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStore")
            .field("headers_dir", &self.headers_dir)
            .field("payloads_dir", &self.payloads_dir)
            .field("fsync", &self.fsync)
            .field("segment_entries", &self.payload_segments.entry_count())
            .finish()
    }
}

impl FileStore {
    pub fn open<P: AsRef<Path>>(root: P, fsync: bool) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        // Strict symlink policy: root must not be a symlink.
        // Strikte Symlink-Policy: root darf kein Symlink sein.
        if is_symlink(&root) {
            return Err(anyhow!(
                "store_dir must not be a symlink: {}",
                root.display()
            ));
        }
        let headers_dir = root.join("headers");
        let payloads_dir = root.join("payloads");
        // `headers/` and `payloads/` must not be symlinks (if they exist).
        // headers/ und payloads/ dürfen keine Symlinks sein (falls vorhanden).
        if headers_dir.exists() && is_symlink(&headers_dir) {
            return Err(anyhow!("headers/ must not be a symlink under store_dir"));
        }
        if payloads_dir.exists() && is_symlink(&payloads_dir) {
            return Err(anyhow!("payloads/ must not be a symlink under store_dir"));
        }
        create_dir_all_secure(&headers_dir)?;
        create_dir_all_secure(&payloads_dir)?;
        // Re-check after create_dir_all to narrow TOCTOU before chmod/fsync.
        // Nach create_dir_all erneut prüfen, um TOCTOU vor chmod/fsync zu verengen.
        if is_symlink(&root) {
            return Err(anyhow!(
                "store_dir must not be a symlink: {}",
                root.display()
            ));
        }
        if is_symlink(&headers_dir) {
            return Err(anyhow!("headers/ must not be a symlink under store_dir"));
        }
        if is_symlink(&payloads_dir) {
            return Err(anyhow!("payloads/ must not be a symlink under store_dir"));
        }
        #[cfg(unix)]
        {
            // Stronger, kernel-enforced symlink rejection (O_NOFOLLOW) for the final check.
            if let Err(e) = open_dir_nofollow(&root) {
                if is_symlink(&root) {
                    return Err(anyhow!(
                        "store_dir must not be a symlink: {}",
                        root.display()
                    ));
                }
                return Err(e);
            }
            if let Err(e) = open_dir_nofollow(&headers_dir) {
                if is_symlink(&headers_dir) {
                    return Err(anyhow!("headers/ must not be a symlink under store_dir"));
                }
                return Err(e);
            }
            if let Err(e) = open_dir_nofollow(&payloads_dir) {
                if is_symlink(&payloads_dir) {
                    return Err(anyhow!("payloads/ must not be a symlink under store_dir"));
                }
                return Err(e);
            }
        }
        // Harden Unix permissions (0700 for directories).
        // Unix-Rechte härten (0700 für Verzeichnisse).
        set_dir_mode_secure(&root)?;
        set_dir_mode_secure(&headers_dir)?;
        set_dir_mode_secure(&payloads_dir)?;
        // Directory fsync for crash safety (best effort).
        // dir fsync für Crash-Sicherheit (best effort).
        if fsync {
            Self::fsync_dir(&root)?;
            Self::fsync_dir(&headers_dir)?;
            Self::fsync_dir(&payloads_dir)?;
        }
        let segments_dir = root.join("payload_segments");
        if segments_dir.exists() && is_symlink(&segments_dir) {
            return Err(anyhow!(
                "payload_segments/ must not be a symlink under store_dir"
            ));
        }
        create_dir_all_secure(&segments_dir)?;
        if is_symlink(&segments_dir) {
            return Err(anyhow!(
                "payload_segments/ must not be a symlink under store_dir"
            ));
        }
        #[cfg(unix)]
        {
            if let Err(e) = open_dir_nofollow(&segments_dir) {
                if is_symlink(&segments_dir) {
                    return Err(anyhow!(
                        "payload_segments/ must not be a symlink under store_dir"
                    ));
                }
                return Err(e);
            }
        }
        set_dir_mode_secure(&segments_dir)?;
        if fsync {
            Self::fsync_dir(&segments_dir)?;
        }
        let payload_segments = SegmentStore::open(&segments_dir, fsync)?;
        Ok(Self {
            headers_dir,
            payloads_dir,
            payload_segments,
            fsync,
        })
    }

    fn fsync_dir(dir: &Path) -> Result<()> {
        let f = OpenOptions::new().read(true).open(dir)?;
        f.sync_all()?;
        Ok(())
    }

    fn write_atomic(dir: &Path, file_name: &str, data: &[u8], fsync: bool) -> Result<()> {
        let target = dir.join(file_name);
        let parent = dir;
        let mut tmp = NamedTempFile::new_in(parent)?;
        tmp.write_all(data)?;
        if fsync {
            tmp.as_file().sync_all()?;
        }
        tmp.persist(&target)
            .map_err(|e| anyhow!("persist failed: {}", e))?;
        // Harden Unix file permissions (0600).
        // Unix-Dateirechte härten (0600).
        set_file_mode_secure(&target)?;
        if fsync {
            // Fsync the target file and then the directory.
            // Ziel-Datei fsyncen und Verzeichnis fsyncen.
            let f = OpenOptions::new().read(true).open(&target)?;
            f.sync_all()?;
            Self::fsync_dir(parent)?;
        }
        Ok(())
    }

    fn read_all(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
        let meta = fs::metadata(path)?;
        if meta.len() > max_bytes as u64 {
            return Err(anyhow!(
                "file too large: {} bytes (limit {})",
                meta.len(),
                max_bytes
            ));
        }
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        if buf.len() > max_bytes {
            return Err(anyhow!(
                "file too large after read: {} bytes (limit {})",
                buf.len(),
                max_bytes
            ));
        }
        Ok(buf)
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        hex::encode(bytes)
    }

    pub fn put_header(&self, h: &AnchorHeader) -> Result<[u8; 32]> {
        let size = h.encoded_len();
        if size > MAX_HEADER_BYTES {
            return Err(anyhow!("header too large: {} bytes", size));
        }
        let id = h.id_digest();
        let fname = format!("{}.bin", Self::hex32(&id));
        let mut buf = Vec::with_capacity(h.encoded_len());
        h.encode(&mut buf)?;
        Self::write_atomic(&self.headers_dir, &fname, &buf, self.fsync)?;
        Ok(id)
    }

    pub fn has_header(&self, id: &[u8; 32]) -> bool {
        self.headers_dir
            .join(format!("{}.bin", Self::hex32(id)))
            .exists()
    }

    pub fn get_header(&self, id: &[u8; 32]) -> Result<Option<AnchorHeader>> {
        let path = self.headers_dir.join(format!("{}.bin", Self::hex32(id)));
        if !path.exists() {
            return Ok(None);
        }
        // P1-1: decode_exact rejects trailing bytes.
        // P1-1: decode_exact lehnt Trailing-Bytes ab.
        let h: AnchorHeader = decode_exact(&Self::read_all(&path, MAX_HEADER_BYTES)?)?;
        // P2-1: Re-verify integrity after load (silent corruption defense).
        // P2-1: Integrität nach Laden re-verifizieren (Schutz gegen Silent Corruption).
        let actual_id = h.id_digest();
        if &actual_id != id {
            return Err(anyhow!(
                "header integrity check failed: expected {}, got {}",
                Self::hex32(id),
                Self::hex32(&actual_id)
            ));
        }
        Ok(Some(h))
    }

    pub fn put_payload(&self, p: &AnchorPayload) -> Result<[u8; 32]> {
        let size = p.encoded_len();
        if size > MAX_PAYLOAD_BYTES {
            return Err(anyhow!("payload too large: {} bytes", size));
        }
        let root = payload_merkle_root(p);
        let fname = format!("{}.bin", Self::hex32(&root));
        let mut buf = Vec::with_capacity(p.encoded_len());
        p.encode(&mut buf)?;
        Self::write_atomic(&self.payloads_dir, &fname, &buf, self.fsync)?;
        Ok(root)
    }

    pub fn has_payload(&self, root: &[u8; 32]) -> bool {
        self.payloads_dir
            .join(format!("{}.bin", Self::hex32(root)))
            .exists()
    }

    pub fn get_payload(&self, root: &[u8; 32]) -> Result<Option<AnchorPayload>> {
        let path = self.payloads_dir.join(format!("{}.bin", Self::hex32(root)));
        if !path.exists() {
            return Ok(None);
        }
        // P1-1: decode_exact rejects trailing bytes.
        // P1-1: decode_exact lehnt Trailing-Bytes ab.
        let p: AnchorPayload = decode_exact(&Self::read_all(&path, MAX_PAYLOAD_BYTES)?)?;
        // P2-1: Re-verify integrity after load (silent corruption defense).
        // P2-1: Integrität nach Laden re-verifizieren (Schutz gegen Silent Corruption).
        let actual_root = payload_merkle_root(&p);
        if &actual_root != root {
            return Err(anyhow!(
                "payload integrity check failed: expected {}, got {}",
                Self::hex32(root),
                Self::hex32(&actual_root)
            ));
        }
        Ok(Some(p))
    }

    // V2 support: store/load header and payload V2.
    // V2-Support: Header/Payload V2 speichern/lesen.
    pub fn put_header_v2(&self, h: &AnchorHeaderV2) -> Result<[u8; 32]> {
        let size = h.encoded_len();
        if size > MAX_HEADER_BYTES {
            return Err(anyhow!("header too large: {} bytes", size));
        }
        let id = h.id_digest();
        let fname = format!("{}.bin", Self::hex32(&id));
        let mut buf = Vec::with_capacity(h.encoded_len());
        h.encode(&mut buf)?;
        Self::write_atomic(&self.headers_dir, &fname, &buf, self.fsync)?;
        Ok(id)
    }

    pub fn get_header_v2(&self, id: &[u8; 32]) -> Result<Option<AnchorHeaderV2>> {
        let path = self.headers_dir.join(format!("{}.bin", Self::hex32(id)));
        if !path.exists() {
            return Ok(None);
        }
        // P1-1: decode_exact rejects trailing bytes.
        // P1-1: decode_exact lehnt Trailing-Bytes ab.
        let h: AnchorHeaderV2 = decode_exact(&Self::read_all(&path, MAX_HEADER_BYTES)?)?;
        // P2-1: Re-verify integrity after load (silent corruption defense).
        // P2-1: Integrität nach Laden re-verifizieren (Schutz gegen Silent Corruption).
        let actual_id = h.id_digest();
        if &actual_id != id {
            return Err(anyhow!(
                "header_v2 integrity check failed: expected {}, got {}",
                Self::hex32(id),
                Self::hex32(&actual_id)
            ));
        }
        Ok(Some(h))
    }

    pub fn put_payload_v2(&self, p: &AnchorPayloadV2) -> Result<[u8; 32]> {
        let size = p.encoded_len();
        if size > MAX_PAYLOAD_BYTES {
            return Err(anyhow!("payload too large: {} bytes", size));
        }
        let root = payload_merkle_root_v2(p);
        let fname = format!("{}.bin", Self::hex32(&root));
        let mut buf = Vec::with_capacity(p.encoded_len());
        p.encode(&mut buf)?;
        Self::write_atomic(&self.payloads_dir, &fname, &buf, self.fsync)?;
        Ok(root)
    }

    pub fn get_payload_v2(&self, root: &[u8; 32]) -> Result<Option<AnchorPayloadV2>> {
        let path = self.payloads_dir.join(format!("{}.bin", Self::hex32(root)));
        if !path.exists() {
            return Ok(None);
        }
        // P1-1: decode_exact rejects trailing bytes.
        // P1-1: decode_exact lehnt Trailing-Bytes ab.
        let p: AnchorPayloadV2 = decode_exact(&Self::read_all(&path, MAX_PAYLOAD_BYTES)?)?;
        // P2-1: Re-verify integrity after load (silent corruption defense).
        // P2-1: Integrität nach Laden re-verifizieren (Schutz gegen Silent Corruption).
        let actual_root = payload_merkle_root_v2(&p);
        if &actual_root != root {
            return Err(anyhow!(
                "payload_v2 integrity check failed: expected {}, got {}",
                Self::hex32(root),
                Self::hex32(&actual_root)
            ));
        }
        Ok(Some(p))
    }

    pub fn put_payload_v3(&self, p: &AnchorPayloadV3) -> Result<[u8; 32]> {
        let root = payload_merkle_root_v3(p);
        let size = p.encoded_len();
        if size > MAX_PAYLOAD_BYTES {
            return Err(anyhow!("payload too large: {} bytes", size));
        }
        if self.payload_segments.contains(&root) {
            return Ok(root);
        }
        let mut buf = Vec::with_capacity(size);
        p.encode(&mut buf)?;
        self.payload_segments.put(root, &buf)?;
        Ok(root)
    }

    pub fn get_payload_v3(&self, root: &[u8; 32]) -> Result<Option<AnchorPayloadV3>> {
        // 1) SegmentStore lookup
        if let Some(raw) = self.payload_segments.get(root)? {
            return Self::decode_payload_v3_raw(root, &raw);
        }

        // 2) Legacy single-file fallback
        let path = self.payloads_dir.join(format!("{}.bin", Self::hex32(root)));
        if !path.exists() {
            return Ok(None);
        }
        let raw = Self::read_all(&path, MAX_PAYLOAD_BYTES)?;
        Self::decode_payload_v3_raw(root, &raw)
    }

    fn decode_payload_v3_raw(root: &[u8; 32], raw: &[u8]) -> Result<Option<AnchorPayloadV3>> {
        // New format first.
        if let Ok(p3) = decode_exact::<AnchorPayloadV3>(raw) {
            let actual_root = payload_merkle_root_v3(&p3);
            if &actual_root != root {
                return Err(anyhow!(
                    "payload_v3 integrity check failed: expected {}, got {}",
                    Self::hex32(root),
                    Self::hex32(&actual_root)
                ));
            }
            return Ok(Some(p3));
        }

        // Backward-compat fallback: decode legacy payload_v2 and map to v3(null_mint=false).
        let p2: AnchorPayloadV2 = decode_exact(raw)?;
        let p3 = payload_v2_to_v3(&p2);
        let actual_root = payload_merkle_root_v3(&p3);
        if &actual_root != root {
            return Err(anyhow!(
                "payload_v3(v2-fallback) integrity check failed: expected {}, got {}",
                Self::hex32(root),
                Self::hex32(&actual_root)
            ));
        }
        Ok(Some(p3))
    }

    pub fn has_payload_v3(&self, root: &[u8; 32]) -> bool {
        if self.payload_segments.contains(root) {
            return true;
        }
        self.payloads_dir
            .join(format!("{}.bin", Self::hex32(root)))
            .exists()
    }

    pub fn migrate_legacy_payloads(&self, delete_after: bool) -> Result<MigrationStats> {
        let mut stats = MigrationStats::default();
        let entries: Vec<_> = match fs::read_dir(&self.payloads_dir) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(_) => return Ok(stats),
        };

        for entry in entries {
            let fname = entry.file_name();
            let name = fname.to_string_lossy();
            if !name.ends_with(".bin") {
                continue;
            }
            let hex_str = name.trim_end_matches(".bin");
            if hex_str.len() != 64 {
                continue;
            }
            let key_bytes = match hex::decode(hex_str) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => continue,
            };

            if self.payload_segments.contains(&key_bytes) {
                stats.skipped += 1;
                if delete_after {
                    let _ = fs::remove_file(entry.path());
                    stats.deleted += 1;
                }
                continue;
            }

            let raw = match Self::read_all(&entry.path(), MAX_PAYLOAD_BYTES) {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("migrate: skip {}: {}", name, e);
                    stats.errors += 1;
                    continue;
                }
            };

            if let Err(e) = self.payload_segments.put(key_bytes, &raw) {
                log::warn!("migrate: segment put failed for {}: {}", name, e);
                stats.errors += 1;
                continue;
            }
            stats.migrated += 1;

            if delete_after {
                let _ = fs::remove_file(entry.path());
                stats.deleted += 1;
            }
        }

        log::info!(
            "migrate_legacy_payloads: migrated={} skipped={} deleted={} errors={}",
            stats.migrated,
            stats.skipped,
            stats.deleted,
            stats.errors,
        );
        Ok(stats)
    }

    pub fn payload_segment_entry_count(&self) -> usize {
        self.payload_segments.entry_count()
    }
}

#[derive(Debug, Default, Clone)]
pub struct MigrationStats {
    pub migrated: usize,
    pub skipped: usize,
    pub deleted: usize,
    pub errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_types::payload_merkle_root;
    use pc_types::{AnchorHeader, AnchorId, AnchorPayload, ParentList, PayoutEntry, PayoutSet};
    use tempfile::TempDir;

    fn sample_header(payload_hash: [u8; 32]) -> AnchorHeader {
        let mut parents = ParentList::default();
        let _ = parents.push(AnchorId([1u8; 32]));
        AnchorHeader {
            version: 1,
            shard_id: 7,
            parents,
            payload_hash,
            creator_index: 5,
            vote_mask: 0xABCD,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
        }
    }

    fn sample_payload() -> AnchorPayload {
        let set = PayoutSet {
            entries: vec![
                PayoutEntry {
                    recipient_id: [2u8; 32],
                    amount: 10,
                },
                PayoutEntry {
                    recipient_id: [1u8; 32],
                    amount: 5,
                },
            ],
        };
        let pr = set.payout_root();
        AnchorPayload {
            version: 1,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: pr,
        }
    }

    #[test]
    fn header_roundtrip_store() {
        let dir = TempDir::new().expect("tempdir");
        let store = FileStore::open(dir.path(), false).expect("open store");
        let payload = sample_payload();
        let p_root = payload_merkle_root(&payload);
        let h = sample_header(p_root);
        let id = store.put_header(&h).expect("put header");
        assert!(store.has_header(&id));
        let got = store
            .get_header(&id)
            .expect("get header")
            .expect("some header");
        assert_eq!(h, got);
    }

    #[test]
    fn payload_roundtrip_store() {
        let dir = TempDir::new().expect("tempdir");
        let store = FileStore::open(dir.path(), false).expect("open store");
        let payload = sample_payload();
        let root = store.put_payload(&payload).expect("put payload");
        assert!(store.has_payload(&root));
        let got = store
            .get_payload(&root)
            .expect("get payload")
            .expect("some payload");
        assert_eq!(payload, got);
    }

    #[test]
    fn get_payload_rejects_oversized_file() {
        let dir = TempDir::new().expect("tempdir");
        let store = FileStore::open(dir.path(), false).expect("open store");
        let root = [0xAB; 32];
        let path = dir
            .path()
            .join("payloads")
            .join(format!("{}.bin", hex::encode(root)));
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        fs::write(&path, oversized).expect("write oversized payload file");
        let err = store
            .get_payload(&root)
            .expect_err("must reject oversized payload");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("file too large"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn atomic_write_paths_and_fsync() {
        let dir = TempDir::new().expect("tempdir");
        let store = FileStore::open(dir.path(), true).expect("open store fsync");
        // header
        let payload = sample_payload();
        let p_root = payload_merkle_root(&payload);
        let h = sample_header(p_root);
        let id = store.put_header(&h).expect("put header");
        let header_path = dir
            .path()
            .join("headers")
            .join(format!("{}.bin", hex::encode(id)));
        assert!(header_path.exists(), "header file should exist");
        // payload
        let pr = store.put_payload(&payload).expect("put payload");
        let payload_path = dir
            .path()
            .join("payloads")
            .join(format!("{}.bin", hex::encode(pr)));
        assert!(payload_path.exists(), "payload file should exist");
    }

    #[test]
    fn payload_v3_no_decision_roundtrip_store() {
        let dir = TempDir::new().expect("tempdir");
        let store = FileStore::open(dir.path(), false).expect("open store");
        let payload = AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        };
        let root = store.put_payload_v3(&payload).expect("put payload v3");
        let got = store
            .get_payload_v3(&root)
            .expect("get payload v3")
            .expect("some payload v3");
        assert_eq!(payload, got);
    }

    #[cfg(unix)]
    #[test]
    fn f51_unix_permissions_and_symlink_policy() {
        use std::os::unix::fs as unixfs;
        let tmp = TempDir::new().expect("tmp");

        // 1) Reject symlink root.
        // 1) Symlink-Root ablehnen.
        let real = tmp.path().join("real");
        fs::create_dir_all(&real).expect("create real dir");
        let link = tmp.path().join("link_root");
        unixfs::symlink(&real, &link).expect("symlink root");
        let err = FileStore::open(&link, false).expect_err("open symlink root should error");
        assert!(format!("{}", err).contains("store_dir must not be a symlink"));

        // 2) Reject symlink subdirectories.
        // 2) Symlink-Unterverzeichnisse ablehnen.
        let root = tmp.path().join("root");
        fs::create_dir_all(&root).expect("create root dir");
        let hdrs_real = tmp.path().join("hdrs_real");
        fs::create_dir_all(&hdrs_real).expect("create hdrs_real dir");
        let hdrs_link = root.join("headers");
        unixfs::symlink(&hdrs_real, &hdrs_link).expect("symlink headers");
        let e2 =
            FileStore::open(&root, false).expect_err("open root with symlink headers should error");
        assert!(format!("{}", e2).contains("headers/ must not be a symlink"));

        // 3) Check permission hardening.
        // 3) Rechte-Härtung prüfen.
        let root2 = tmp.path().join("root2");
        let store = FileStore::open(&root2, false).expect("open root2");
        let md_root = fs::metadata(&root2).expect("metadata root2");
        assert_eq!(md_root.permissions().mode() & 0o777, 0o700);
        let md_hdr = fs::metadata(root2.join("headers")).expect("metadata headers");
        assert_eq!(md_hdr.permissions().mode() & 0o777, 0o700);
        let md_pl = fs::metadata(root2.join("payloads")).expect("metadata payloads");
        assert_eq!(md_pl.permissions().mode() & 0o777, 0o700);
        // Files should have mode 0600.
        // Dateien sollten 0600 sein.
        let payload = sample_payload();
        let root_hash = store.put_payload(&payload).expect("put payload");
        let pth = root2
            .join("payloads")
            .join(format!("{}.bin", hex::encode(root_hash)));
        let md_file = fs::metadata(&pth).expect("metadata payload file");
        assert_eq!(md_file.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn integrity_check_detects_corrupted_header_p2_1() {
        // P2-1: Simulate silent corruption by writing wrong data under a valid filename.
        // P2-1: Silent Corruption simulieren durch Schreiben falscher Daten unter gültigem Dateinamen.
        let dir = TempDir::new().expect("tempdir");
        let store = FileStore::open(dir.path(), false).expect("open store");

        let payload = sample_payload();
        let p_root = payload_merkle_root(&payload);
        let h = sample_header(p_root);
        let id = store.put_header(&h).expect("put header");

        // Corrupt the file: write a different header under the same filename.
        // Datei korrumpieren: anderen Header unter gleichem Dateinamen schreiben.
        let mut h_corrupt = h.clone();
        h_corrupt.shard_id = 99; // Different shard_id changes the digest.
        let mut buf = Vec::new();
        h_corrupt.encode(&mut buf).expect("encode");
        let path = dir
            .path()
            .join("headers")
            .join(format!("{}.bin", hex::encode(id)));
        fs::write(&path, &buf).expect("overwrite with corrupt data");

        // get_header should now fail integrity check.
        // get_header sollte jetzt Integritätsprüfung fehlschlagen.
        let err = store.get_header(&id).expect_err("should detect corruption");
        assert!(format!("{}", err).contains("integrity check failed"));
    }

    #[test]
    fn integrity_check_detects_corrupted_payload_p2_1() {
        // P2-1: Simulate silent corruption for payload.
        // P2-1: Silent Corruption für Payload simulieren.
        let dir = TempDir::new().expect("tempdir");
        let store = FileStore::open(dir.path(), false).expect("open store");

        let payload = sample_payload();
        let root = store.put_payload(&payload).expect("put payload");

        // Corrupt: write different payload under same filename.
        // Korrumpieren: anderen Payload unter gleichem Dateinamen schreiben.
        // Change payout_root to alter the merkle root.
        // payout_root ändern um den Merkle-Root zu ändern.
        let mut p_corrupt = payload.clone();
        p_corrupt.payout_root = [0xFFu8; 32]; // Different payout_root changes merkle root.
        let mut buf = Vec::new();
        p_corrupt.encode(&mut buf).expect("encode");
        let path = dir
            .path()
            .join("payloads")
            .join(format!("{}.bin", hex::encode(root)));
        fs::write(&path, &buf).expect("overwrite with corrupt data");

        // get_payload should fail integrity check.
        // get_payload sollte Integritätsprüfung fehlschlagen.
        let err = store
            .get_payload(&root)
            .expect_err("should detect corruption");
        assert!(format!("{}", err).contains("integrity check failed"));
    }
}
