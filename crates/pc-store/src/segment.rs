// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Result};
#[cfg(unix)]
use rustix::fs::{openat, Mode, OFlags};
use std::collections::HashMap;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

const SEGMENT_MAGIC: &[u8; 4] = b"PCSG";
const SEGMENT_VERSION: u8 = 1;
const SEGMENT_HEADER_LEN: usize = 4 + 1; // magic(4) + version(1)
const RECORD_HEADER_LEN: usize = 32 + 4; // key(32) + len(u32 LE)
const RECORD_FOOTER_LEN: usize = 4; // crc32(4)
const DEFAULT_MAX_SEGMENT_BYTES: u64 = 32 * 1024 * 1024; // 32 MB

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    segment_id: u64,
    offset: u64,
    len: u32,
}

struct WriteState {
    active_segment_id: u64,
    active_file: Option<File>,
    active_file_pos: u64,
    max_segment_bytes: u64,
}

pub struct SegmentStore {
    dir: PathBuf,
    #[cfg(unix)]
    dir_handle: File,
    fsync: bool,
    index: RwLock<HashMap<[u8; 32], IndexEntry>>,
    writer: Mutex<WriteState>,
}

impl SegmentStore {
    pub fn open(dir: &Path, fsync: bool) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let dir = fs::canonicalize(dir)?;
        #[cfg(unix)]
        let dir_handle = File::open(&dir)?;
        let store = Self {
            dir,
            #[cfg(unix)]
            dir_handle,
            fsync,
            index: RwLock::new(HashMap::new()),
            writer: Mutex::new(WriteState {
                active_segment_id: 0,
                active_file: None,
                active_file_pos: 0,
                max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            }),
        };
        let mut index = HashMap::new();
        let active_segment_id = store.rebuild_index(&mut index)?;
        *store.index_write() = index;
        store.writer_lock().active_segment_id = active_segment_id;
        Ok(store)
    }

    pub fn entry_count(&self) -> usize {
        self.index_read().len()
    }

    #[cfg(not(unix))]
    fn segment_path(dir: &Path, id: u64) -> PathBuf {
        dir.join(format!("{:08}.seg", id))
    }

    fn rebuild_index(&self, index: &mut HashMap<[u8; 32], IndexEntry>) -> Result<u64> {
        index.clear();
        let mut max_id: u64 = 0;
        let mut seg_ids: Vec<u64> = Vec::new();

        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let fname = entry.file_name();
            let name = fname.to_string_lossy();
            if !name.ends_with(".seg") {
                continue;
            }
            let stem = name.trim_end_matches(".seg");
            let id: u64 = match stem.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            seg_ids.push(id);
            if id > max_id {
                max_id = id;
            }
        }

        seg_ids.sort_unstable();

        let mut total_records: usize = 0;
        let mut skipped: usize = 0;

        for &seg_id in &seg_ids {
            match self.scan_segment(seg_id, index) {
                Ok(n) => total_records += n,
                Err(e) => {
                    log::warn!("segment {:08}.seg scan error, skipping: {}", seg_id, e);
                    skipped += 1;
                }
            }
        }

        let active_id = if seg_ids.is_empty() { 0 } else { max_id };

        log::info!(
            "SegmentStore::rebuild_index dir={} segments={} records={} skipped={}",
            self.dir.display(),
            seg_ids.len(),
            total_records,
            skipped,
        );

        Ok(active_id)
    }

    fn scan_segment(
        &self,
        seg_id: u64,
        index: &mut HashMap<[u8; 32], IndexEntry>,
    ) -> Result<usize> {
        let mut f = self.open_segment_for_read(seg_id)?;
        let file_len = f.metadata()?.len();
        if file_len < SEGMENT_HEADER_LEN as u64 {
            return Err(anyhow!("segment file too small: {} bytes", file_len));
        }

        let mut header = [0u8; SEGMENT_HEADER_LEN];
        f.read_exact(&mut header)?;
        if &header[0..4] != SEGMENT_MAGIC {
            return Err(anyhow!("invalid segment magic"));
        }
        if header[4] != SEGMENT_VERSION {
            return Err(anyhow!("unsupported segment version: {}", header[4]));
        }

        let mut pos = SEGMENT_HEADER_LEN as u64;
        let mut count: usize = 0;

        loop {
            if pos + RECORD_HEADER_LEN as u64 > file_len {
                break;
            }

            let mut rec_header = [0u8; RECORD_HEADER_LEN];
            f.read_exact(&mut rec_header)?;

            let mut key = [0u8; 32];
            key.copy_from_slice(&rec_header[0..32]);
            let data_len = u32::from_le_bytes([
                rec_header[32],
                rec_header[33],
                rec_header[34],
                rec_header[35],
            ]);

            let record_total =
                RECORD_HEADER_LEN as u64 + data_len as u64 + RECORD_FOOTER_LEN as u64;
            if pos + record_total > file_len {
                log::warn!(
                    "segment {:08}.seg truncated record at offset {}, stopping scan",
                    seg_id,
                    pos,
                );
                break;
            }

            let data_offset = pos + RECORD_HEADER_LEN as u64;

            let mut data_buf = vec![0u8; data_len as usize];
            f.read_exact(&mut data_buf)?;

            let mut crc_buf = [0u8; 4];
            f.read_exact(&mut crc_buf)?;
            let stored_crc = u32::from_le_bytes(crc_buf);
            let computed_crc = crc32fast::hash(&data_buf);

            if stored_crc != computed_crc {
                log::warn!(
                    "segment {:08}.seg crc mismatch at offset {} (stored={:08x} computed={:08x}), skipping record",
                    seg_id, pos, stored_crc, computed_crc,
                );
                pos += record_total;
                continue;
            }

            index.insert(
                key,
                IndexEntry {
                    segment_id: seg_id,
                    offset: data_offset,
                    len: data_len,
                },
            );
            pos += record_total;
            count += 1;
        }

        Ok(count)
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.index_read().contains_key(key)
    }

    pub fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let entry = {
            let idx = self.index_read();
            match idx.get(key) {
                Some(e) => *e,
                None => return Ok(None),
            }
        };

        let mut f = self.open_segment_for_read(entry.segment_id)?;
        f.seek(SeekFrom::Start(entry.offset))?;

        let mut buf = vec![0u8; entry.len as usize];
        f.read_exact(&mut buf)?;

        let mut crc_buf = [0u8; 4];
        f.read_exact(&mut crc_buf)?;
        let stored_crc = u32::from_le_bytes(crc_buf);
        let computed_crc = crc32fast::hash(&buf);
        if stored_crc != computed_crc {
            return Err(anyhow!(
                "segment {:08}.seg crc mismatch on read at offset {} (stored={:08x} computed={:08x})",
                entry.segment_id,
                entry.offset,
                stored_crc,
                computed_crc,
            ));
        }

        Ok(Some(buf))
    }

    pub fn put(&self, key: [u8; 32], data: &[u8]) -> Result<()> {
        let mut ws = self.writer_lock();

        // Rotate if needed
        if ws.active_file_pos >= ws.max_segment_bytes {
            if let Some(f) = ws.active_file.take() {
                if self.fsync {
                    f.sync_all()?;
                }
                drop(f);
            }
            ws.active_segment_id += 1;
            ws.active_file_pos = 0;
            log::info!(
                "SegmentStore: rotated to segment {:08}.seg",
                ws.active_segment_id,
            );
        }

        // Ensure active file
        if ws.active_file.is_none() {
            let (f, pos) = self.open_segment_for_append(ws.active_segment_id)?;
            ws.active_file_pos = pos;
            ws.active_file = Some(f);
        }

        let data_len = data.len() as u32;
        let crc = crc32fast::hash(data);
        let offset_before = ws.active_file_pos;

        let f = ws
            .active_file
            .as_mut()
            .ok_or_else(|| anyhow!("active segment file missing after initialization"))?;
        f.write_all(&key)?;
        f.write_all(&data_len.to_le_bytes())?;
        f.write_all(data)?;
        f.write_all(&crc.to_le_bytes())?;

        if self.fsync {
            f.sync_data()?;
        }

        let data_offset = offset_before + RECORD_HEADER_LEN as u64;
        let record_total = RECORD_HEADER_LEN as u64 + data_len as u64 + RECORD_FOOTER_LEN as u64;
        ws.active_file_pos += record_total;

        let seg_id = ws.active_segment_id;

        // Release writer lock before taking index write lock
        drop(ws);

        self.index_write().insert(
            key,
            IndexEntry {
                segment_id: seg_id,
                offset: data_offset,
                len: data_len,
            },
        );

        Ok(())
    }

    #[cfg(test)]
    fn set_max_segment_bytes(&self, max: u64) {
        self.writer_lock().max_segment_bytes = max;
    }

    #[cfg(test)]
    fn active_segment_id(&self) -> u64 {
        self.writer_lock().active_segment_id
    }

    fn recover_poisoned<T>(kind: &'static str, poisoned: PoisonError<T>) -> T {
        log::error!("SegmentStore: recovering from poisoned {} lock", kind);
        poisoned.into_inner()
    }

    fn index_read(&self) -> RwLockReadGuard<'_, HashMap<[u8; 32], IndexEntry>> {
        match self.index.read() {
            Ok(guard) => guard,
            Err(poisoned) => Self::recover_poisoned("index(read)", poisoned),
        }
    }

    fn index_write(&self) -> RwLockWriteGuard<'_, HashMap<[u8; 32], IndexEntry>> {
        match self.index.write() {
            Ok(guard) => guard,
            Err(poisoned) => Self::recover_poisoned("index(write)", poisoned),
        }
    }

    fn writer_lock(&self) -> MutexGuard<'_, WriteState> {
        match self.writer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => Self::recover_poisoned("writer", poisoned),
        }
    }

    #[cfg(not(unix))]
    fn reject_symlink_segment_path(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(anyhow!(
                "segment path must not be a symlink: {}",
                path.display()
            )),
            Ok(_) | Err(_) => Ok(()),
        }
    }

    fn open_segment_for_read(&self, seg_id: u64) -> Result<File> {
        #[cfg(unix)]
        {
            let name = Self::segment_name(seg_id);
            let fd = openat(
                &self.dir_handle,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| anyhow!("open segment for read {}: {}", name, e))?;
            let f = File::from(fd);
            let meta = f.metadata()?;
            if !meta.is_file() {
                bail!("segment path is not a regular file: {}", name);
            }
            return Ok(f);
        }
        #[cfg(not(unix))]
        {
            let path = Self::segment_path(&self.dir, seg_id);
            Self::reject_symlink_segment_path(&path)?;
            File::open(&path)
                .map_err(|e| anyhow!("open segment for read {}: {}", path.display(), e))
        }
    }

    fn open_segment_for_append(&self, seg_id: u64) -> Result<(File, u64)> {
        #[cfg(unix)]
        {
            let name = Self::segment_name(seg_id);
            let mut f = File::from(
                openat(
                    &self.dir_handle,
                    name.as_str(),
                    OFlags::RDWR
                        | OFlags::APPEND
                        | OFlags::CREATE
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|e| anyhow!("open segment for append {}: {}", name, e))?,
            );
            let meta = f.metadata()?;
            if !meta.is_file() {
                bail!("segment path is not a regular file: {}", name);
            }
            let pos = f.seek(SeekFrom::End(0))?;
            if pos == 0 {
                f.write_all(SEGMENT_MAGIC)?;
                f.write_all(&[SEGMENT_VERSION])?;
                if self.fsync {
                    f.sync_data()?;
                }
                return Ok((f, SEGMENT_HEADER_LEN as u64));
            }
            if pos < SEGMENT_HEADER_LEN as u64 {
                bail!(
                    "segment {} is truncated ({} bytes) and cannot be used as active segment",
                    name,
                    pos
                );
            }
            return Ok((f, pos));
        }
        #[cfg(not(unix))]
        {
            let path = Self::segment_path(&self.dir, seg_id);
            Self::reject_symlink_segment_path(&path)?;

            let mut f = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(&path)
                .map_err(|e| anyhow!("open segment for append {}: {}", path.display(), e))?;
            let pos = f.seek(SeekFrom::End(0))?;
            if pos == 0 {
                f.write_all(SEGMENT_MAGIC)?;
                f.write_all(&[SEGMENT_VERSION])?;
                if self.fsync {
                    f.sync_data()?;
                }
                return Ok((f, SEGMENT_HEADER_LEN as u64));
            }
            if pos < SEGMENT_HEADER_LEN as u64 {
                bail!(
                    "segment {} is truncated ({} bytes) and cannot be used as active segment",
                    path.display(),
                    pos
                );
            }
            Ok((f, pos))
        }
    }

    #[cfg(unix)]
    fn segment_name(id: u64) -> String {
        format!("{:08}.seg", id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs as unixfs;
    use tempfile::TempDir;

    #[test]
    fn put_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = SegmentStore::open(dir.path(), false).unwrap();

        let key = [0xABu8; 32];
        let data = b"hello segment store";
        store.put(key, data).unwrap();

        assert!(store.contains(&key));
        let got = store.get(&key).unwrap().unwrap();
        assert_eq!(&got, data);
    }

    #[test]
    fn missing_key_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = SegmentStore::open(dir.path(), false).unwrap();
        let key = [0x01u8; 32];
        assert!(!store.contains(&key));
        assert!(store.get(&key).unwrap().is_none());
    }

    #[test]
    fn overwrite_key_updates_index() {
        let dir = TempDir::new().unwrap();
        let store = SegmentStore::open(dir.path(), false).unwrap();

        let key = [0x42u8; 32];
        store.put(key, b"first").unwrap();
        store.put(key, b"second").unwrap();

        let got = store.get(&key).unwrap().unwrap();
        assert_eq!(&got, b"second");
    }

    #[test]
    fn rebuild_index_after_reopen() {
        let dir = TempDir::new().unwrap();
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let data1 = b"record one";
        let data2 = vec![0xFFu8; 1024];

        {
            let store = SegmentStore::open(dir.path(), false).unwrap();
            store.put(key1, data1).unwrap();
            store.put(key2, &data2).unwrap();
            assert_eq!(store.entry_count(), 2);
        }

        let store2 = SegmentStore::open(dir.path(), false).unwrap();
        assert_eq!(store2.entry_count(), 2);
        assert!(store2.contains(&key1));
        assert!(store2.contains(&key2));
        let got1 = store2.get(&key1).unwrap().unwrap();
        assert_eq!(&got1, data1);
        let got2 = store2.get(&key2).unwrap().unwrap();
        assert_eq!(got2, data2);
    }

    #[test]
    fn segment_rotation() {
        let dir = TempDir::new().unwrap();
        let store = SegmentStore::open(dir.path(), false).unwrap();
        store.set_max_segment_bytes(200);

        let mut keys = Vec::new();
        for i in 0u8..10 {
            let mut key = [0u8; 32];
            key[0] = i;
            let data = vec![i; 50];
            store.put(key, &data).unwrap();
            keys.push((key, data));
        }

        assert!(store.active_segment_id() > 0, "expected segment rotation");

        for (key, data) in &keys {
            let got = store.get(key).unwrap().unwrap();
            assert_eq!(&got, data);
        }

        drop(store);
        let store2 = SegmentStore::open(dir.path(), false).unwrap();
        assert_eq!(store2.entry_count(), 10);
        for (key, data) in &keys {
            let got = store2.get(key).unwrap().unwrap();
            assert_eq!(&got, data);
        }
    }

    #[test]
    fn detects_crc_corruption() {
        let dir = TempDir::new().unwrap();
        let key = [0xCCu8; 32];
        let data = b"important data";

        {
            let store = SegmentStore::open(dir.path(), false).unwrap();
            store.put(key, data).unwrap();
        }

        let seg_path = dir.path().join("00000000.seg");
        let mut raw = fs::read(&seg_path).unwrap();
        let data_start = SEGMENT_HEADER_LEN + 32 + 4;
        raw[data_start] ^= 0xFF;
        fs::write(&seg_path, &raw).unwrap();

        let store2 = SegmentStore::open(dir.path(), false).unwrap();
        assert_eq!(store2.entry_count(), 0);
    }

    #[test]
    fn empty_data_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = SegmentStore::open(dir.path(), false).unwrap();
        let key = [0xEEu8; 32];
        store.put(key, &[]).unwrap();
        assert!(store.contains(&key));
        let got = store.get(&key).unwrap().unwrap();
        assert!(got.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_active_segment_path() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.seg");
        std::fs::write(&real, b"not a segment").unwrap();
        let link = dir.path().join("00000000.seg");
        unixfs::symlink(&real, &link).unwrap();

        let store = SegmentStore::open(dir.path(), false).unwrap();
        let key = [0x33u8; 32];
        let err = store.put(key, b"payload").unwrap_err().to_string();
        assert!(
            err.contains("open segment for append") || err.contains("regular file"),
            "unexpected error: {err}"
        );
    }
}
