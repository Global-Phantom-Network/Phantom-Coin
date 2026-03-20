// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

//! RocksDB-based persistent store for P2P data with TTL cleanup.
//! RocksDB-basierter persistenter Store für P2P-Daten mit TTL-Cleanup

#[cfg(all(feature = "async", feature = "persistent"))]
pub mod persistent {
    use crate::async_svc::StoreDelegate;
    use async_trait::async_trait;
    use pc_codec::{Decodable, Encodable};
    use pc_types::{
        payload_merkle_root_v3 as payload_merkle_root, AnchorHeaderV2 as AnchorHeader, AnchorId,
        AnchorPayloadV3 as AnchorPayload, MicroTx, MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES,
        MAX_TX_BYTES,
    };
    use rocksdb::{Options, DB};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::{debug, warn};

    const CF_HEADERS: &str = "headers";
    const CF_PAYLOADS: &str = "payloads";
    const CF_TXS: &str = "txs";
    const CF_METADATA: &str = "metadata";

    /// TTL metadata for store entries.
    /// TTL-Metadaten für Store-Einträge
    #[derive(Clone, Copy, Debug)]
    struct EntryMeta {
        inserted_at: u64, // Unix timestamp in Sekunden
    }

    impl EntryMeta {
        fn new() -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Self { inserted_at: now }
        }

        fn is_expired(&self, ttl_secs: u64) -> bool {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(self.inserted_at) > ttl_secs
        }

        fn to_bytes(self) -> [u8; 8] {
            self.inserted_at.to_le_bytes()
        }

        fn from_bytes(b: &[u8]) -> Option<Self> {
            let prefix = b.get(..8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(prefix);
            Some(Self {
                inserted_at: u64::from_le_bytes(arr),
            })
        }
    }

    /// RocksDB-based persistent store with TTL support.
    /// RocksDB-basierter persistenter Store mit TTL-Support
    pub struct RocksDbStore {
        db: Arc<DB>,
        ttl_secs: u64,
    }

    impl RocksDbStore {
        /// Creates/opens a RocksDB store at the given path.
        /// Erstellt/öffnet einen RocksDB-Store am gegebenen Pfad
        pub fn new<P: AsRef<Path>>(path: P, ttl_secs: u64) -> Result<Self, String> {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);

            let cfs = vec![CF_HEADERS, CF_PAYLOADS, CF_TXS, CF_METADATA];
            let db = DB::open_cf(&opts, path, cfs).map_err(|e| format!("rocksdb open: {}", e))?;

            Ok(Self {
                db: Arc::new(db),
                ttl_secs,
            })
        }

        /// Background task for periodic TTL cleanup.
        /// Hintergrund-Task für periodischen TTL-Cleanup
        pub async fn run_cleanup_loop(store: Arc<Self>, interval_secs: u64) {
            use tokio::time::{interval, Duration};

            let mut ticker = interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                if let Err(e) = store.cleanup_expired().await {
                    warn!(target: "pc_p2p.rocksdb", error = %e, "TTL cleanup failed");
                }
            }
        }

        /// Removes expired entries.
        /// Entfernt abgelaufene Einträge
        async fn cleanup_expired(&self) -> Result<(), String> {
            let cf_headers = self.db.cf_handle(CF_HEADERS).ok_or("missing cf: headers")?;
            let cf_payloads = self
                .db
                .cf_handle(CF_PAYLOADS)
                .ok_or("missing cf: payloads")?;
            let cf_txs = self.db.cf_handle(CF_TXS).ok_or("missing cf: txs")?;
            let cf_meta = self
                .db
                .cf_handle(CF_METADATA)
                .ok_or("missing cf: metadata")?;

            let mut expired_keys = Vec::new();

            // Scan metadata CF for expired entries.
            // Scanne Metadata CF für abgelaufene Einträge
            let iter = self.db.iterator_cf(&cf_meta, rocksdb::IteratorMode::Start);
            for item in iter {
                let (key, value) = item.map_err(|e| format!("iter error: {}", e))?;
                if let Some(meta) = EntryMeta::from_bytes(&value) {
                    if meta.is_expired(self.ttl_secs) {
                        expired_keys.push(key.to_vec());
                    }
                }
            }

            debug!(target: "pc_p2p.rocksdb", expired_count = expired_keys.len(), "cleanup expired entries");

            // Delete expired entries from all column families (CFs).
            // Lösche abgelaufene Einträge aus allen CFs
            for key in expired_keys {
                // Try to delete in all data CFs (key prefix determines CF).
                // Versuche in allen Data-CFs zu löschen (Key-Präfix bestimmt CF)
                if key.starts_with(b"h:") {
                    if let Some(data_key) = key.get(2..) {
                        let _ = self.db.delete_cf(&cf_headers, data_key);
                    }
                } else if key.starts_with(b"p:") {
                    if let Some(data_key) = key.get(2..) {
                        let _ = self.db.delete_cf(&cf_payloads, data_key);
                    }
                } else if key.starts_with(b"t:") {
                    if let Some(data_key) = key.get(2..) {
                        let _ = self.db.delete_cf(&cf_txs, data_key);
                    }
                }
                // Delete metadata entry.
                // Lösche Metadata-Eintrag
                let _ = self.db.delete_cf(&cf_meta, &key);
            }

            Ok(())
        }

        fn put_with_meta(
            &self,
            cf_name: &str,
            key_prefix: u8,
            key: &[u8],
            value: &[u8],
        ) -> Result<(), String> {
            let cf = self
                .db
                .cf_handle(cf_name)
                .ok_or_else(|| format!("missing cf: {}", cf_name))?;
            let cf_meta = self
                .db
                .cf_handle(CF_METADATA)
                .ok_or("missing cf: metadata")?;

            // Write data.
            // Schreibe Daten
            self.db
                .put_cf(&cf, key, value)
                .map_err(|e| format!("put cf {}: {}", cf_name, e))?;

            // Write metadata with prefix encoding the CF type.
            // Schreibe Metadata mit Präfix für CF-Typ
            let mut meta_key = Vec::with_capacity(1 + key.len());
            meta_key.push(key_prefix);
            meta_key.push(b':');
            meta_key.extend_from_slice(key);

            let meta = EntryMeta::new();
            self.db
                .put_cf(&cf_meta, &meta_key, meta.to_bytes())
                .map_err(|e| format!("put meta: {}", e))?;

            Ok(())
        }

        fn get_if_valid(&self, cf_name: &str, key: &[u8]) -> Option<Vec<u8>> {
            let cf = self.db.cf_handle(cf_name)?;
            self.db.get_cf(&cf, key).ok().flatten()
        }

        async fn has_header(&self, id: &AnchorId) -> bool {
            self.get_if_valid(CF_HEADERS, &id.0).is_some()
        }
    }

    #[async_trait]
    impl StoreDelegate for RocksDbStore {
        async fn insert_header(&self, h: AnchorHeader) {
            let id = h.id_digest();
            let size = h.encoded_len();
            if size > MAX_HEADER_BYTES {
                warn!(size, "drop header: too large");
                return;
            }
            let mut buf = Vec::new();
            if h.encode(&mut buf).is_ok() {
                let _ = self.put_with_meta(CF_HEADERS, b'h', &id, &buf);
            }
        }

        async fn insert_payload(&self, p: AnchorPayload) {
            let root = payload_merkle_root(&p);
            let size = p.encoded_len();
            if size > MAX_PAYLOAD_BYTES {
                warn!(size, "drop payload: too large");
                return;
            }
            let mut buf = Vec::new();
            if p.encode(&mut buf).is_ok() {
                let _ = self.put_with_meta(CF_PAYLOADS, b'p', &root, &buf);
            }
        }

        async fn has_payload(&self, root: &[u8; 32]) -> bool {
            self.get_if_valid(CF_PAYLOADS, root).is_some()
        }

        async fn has_tx(&self, id: &[u8; 32]) -> bool {
            self.get_if_valid(CF_TXS, id).is_some()
        }

        async fn get_headers(&self, ids: &[AnchorId]) -> (Vec<AnchorHeader>, Vec<[u8; 32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();

            for id in ids {
                if let Some(data) = self.get_if_valid(CF_HEADERS, &id.0) {
                    if let Ok(h) = AnchorHeader::decode(&mut &data[..]) {
                        found.push(h);
                        continue;
                    }
                }
                missing.push(id.0);
            }

            (found, missing)
        }

        async fn get_payloads(&self, roots: &[[u8; 32]]) -> (Vec<AnchorPayload>, Vec<[u8; 32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();

            for root in roots {
                if let Some(data) = self.get_if_valid(CF_PAYLOADS, root) {
                    if let Ok(p) = AnchorPayload::decode(&mut &data[..]) {
                        found.push(p);
                        continue;
                    }
                }
                missing.push(*root);
            }

            (found, missing)
        }

        async fn get_txs(&self, ids: &[[u8; 32]]) -> (Vec<MicroTx>, Vec<[u8; 32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();

            for id in ids {
                if let Some(data) = self.get_if_valid(CF_TXS, id) {
                    if let Ok(tx) = MicroTx::decode(&mut &data[..]) {
                        found.push(tx);
                        continue;
                    }
                }
                missing.push(*id);
            }

            (found, missing)
        }

        async fn insert_tx(&self, tx: MicroTx) {
            use pc_types::digest_microtx;
            let size = tx.encoded_len();
            if size > MAX_TX_BYTES {
                warn!(size, "drop tx: too large");
                return;
            }
            let id = digest_microtx(&tx);
            let mut buf = Vec::new();
            if tx.encode(&mut buf).is_ok() {
                let _ = self.put_with_meta(CF_TXS, b't', &id, &buf);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pc_types::ParentList;
        use std::sync::Arc;
        use tokio::time::{sleep, Duration};

        #[tokio::test]
        async fn rocksdb_store_roundtrip() {
            let temp_dir = tempfile::tempdir().unwrap();
            let store = RocksDbStore::new(temp_dir.path(), 3600).unwrap();

            // Test Header
            let parents = ParentList::default();
            let h = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [1u8; 32],
                creator_index: 0,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };

            store.insert_header(h.clone()).await;
            let id = AnchorId(h.id_digest());
            assert!(store.has_header(&id).await);

            let (found, missing) = store.get_headers(&[id]).await;
            assert_eq!(found.len(), 1);
            assert_eq!(missing.len(), 0);
            assert_eq!(found[0].id_digest(), h.id_digest());
        }

        #[tokio::test]
        async fn rocksdb_store_ttl_cleanup() {
            let temp_dir = tempfile::tempdir().unwrap();
            let ttl = 1; // 1 Sekunde TTL
            let store = Arc::new(RocksDbStore::new(temp_dir.path(), ttl).unwrap());

            // Insert Header
            let parents = ParentList::default();
            let h = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [2u8; 32],
                creator_index: 0,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };
            store.insert_header(h.clone()).await;
            let id = AnchorId(h.id_digest());

            assert!(store.has_header(&id).await);

            // Wait for TTL to expire.
            // Warte für TTL-Ablauf
            sleep(Duration::from_secs(2)).await;

            // Cleanup
            store.cleanup_expired().await.unwrap();

            // Header should be deleted.
            // Header sollte gelöscht sein
            assert!(!store.has_header(&id).await);
        }
    }
}
