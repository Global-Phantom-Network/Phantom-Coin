// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
use anyhow::{anyhow, Result};
use pc_codec::{Decodable, Encodable};
use pc_types::{payload_merkle_root, AnchorHeader, AnchorPayload};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

pub struct FileStore {
    headers_dir: PathBuf,
    payloads_dir: PathBuf,
    fsync: bool,
}

impl FileStore {
    pub fn open<P: AsRef<Path>>(root: P, fsync: bool) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let headers_dir = root.join("headers");
        let payloads_dir = root.join("payloads");
        fs::create_dir_all(&headers_dir)?;
        fs::create_dir_all(&payloads_dir)?;
        // dir fsync für Crash-Sicherheit (best effort)
        if fsync {
            Self::fsync_dir(&root)?;
            Self::fsync_dir(&headers_dir)?;
            Self::fsync_dir(&payloads_dir)?;
        }
        Ok(Self {
            headers_dir,
            payloads_dir,
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
        if fsync {
            // Ziel-Datei fsyncen und Verzeichnis fsyncen
            let f = OpenOptions::new().read(true).open(&target)?;
            f.sync_all()?;
            Self::fsync_dir(parent)?;
        }
        Ok(())
    }

    fn read_all(path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        hex::encode(bytes)
    }

    pub fn put_header(&self, h: &AnchorHeader) -> Result<[u8; 32]> {
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
        let mut slice = &Self::read_all(&path)?[..];
        let h = AnchorHeader::decode(&mut slice)?;
        Ok(Some(h))
    }

    pub fn put_payload(&self, p: &AnchorPayload) -> Result<[u8; 32]> {
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
        let mut slice = &Self::read_all(&path)?[..];
        let p = AnchorPayload::decode(&mut slice)?;
        Ok(Some(p))
    }
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
}
