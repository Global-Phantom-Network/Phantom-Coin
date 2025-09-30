// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use clap::{Args, Parser, Subcommand};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use lru::LruCache;
use pc_codec::{self, Decodable, Encodable};
use pc_consensus::{
    check_mint_pow, compute_ack_distances_for_seats, compute_committee_payout,
    compute_committee_payout_from_headers, compute_total_payout_root, consts, finality_threshold,
    is_final, popcount_u64, pow_hash, pow_meets, set_bit, AnchorGraphCache, ConsensusConfig,
    ConsensusEngine, FeeSplitParams,
};
use pc_crypto::blake3_32;
use pc_p2p::async_svc::{
    inbound_subscribe, metrics_snapshot, outbox_deq_inc, OutboundSink, StoreDelegate,
};
use pc_p2p::messages::{P2pMessage, RespMsg};
use pc_p2p::quic_transport::{
    client_config_from_cert, connect, spawn_client_reader, start_server, QuicClientSink,
};
use pc_p2p::RateLimitConfig;
#[cfg(not(feature = "rocksdb"))]
use pc_state::InMemoryBackend;
use pc_state::UtxoState;
use pc_store::FileStore;
use pc_types::digest_microtx;
use pc_types::payload_merkle_root;
use pc_types::validate_microtx_sanity;
use pc_types::validate_mint_sanity;
use pc_types::validate_payload_sanity;
use pc_types::MAX_PAYLOAD_MICROTX;
use pc_types::{
    AnchorHeader, AnchorId, AnchorPayload, ClaimEvent, EvidenceEvent, LockCommitment, MicroTx,
    MintEvent, OutPoint, ParentList, PayoutEntry, PayoutSet, TxOut,
};
use serde::Deserialize;
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use tracing::{info, warn};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::io::Write as _;

    fn unique_tmp(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pc_journal_test_{}_{}", prefix, nanos))
    }

    #[test]
    fn journal_recovery_roundtrip() {
        let base = unique_tmp("recovery");
        let mempool_dir = base.join("mempool");
        std::fs::create_dir_all(&mempool_dir).unwrap();
        let journal_path = mempool_dir.join("mempool.journal");

        // Baue minimalen MicroTx (leer), schreibe Datei + Journal
        let tx = MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
        };
        let id = digest_microtx(&tx);
        let fname = format!("{}.bin", hex::encode(id));
        let path = mempool_dir.join(fname);
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        atomic_write(&path, &buf, false).unwrap();
        journal_append(&journal_path, false, b'A', &id).unwrap();

        // Recovery nach Journal: aktive IDs
        let contents = std::fs::read_to_string(&journal_path).unwrap();
        let mut active: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for line in contents.lines() {
            let (op, hexid) = line.split_at(1);
            let bytes = hex::decode(hexid).unwrap();
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            match op.as_bytes()[0] {
                b'A' => {
                    active.insert(id);
                }
                b'D' => {
                    active.remove(&id);
                }
                _ => {}
            }
        }
        assert!(active.contains(&id));

        // Datei laden und decodieren
        let mut fb = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut fb)
            .unwrap();
        let got = MicroTx::decode(&mut &fb[..]).unwrap();
        assert_eq!(tx, got);
    }

    #[test]
    fn ttl_eviction_removes_expired_file() {
        let base = unique_tmp("ttl");
        let mempool_dir = base.join("mempool");
        std::fs::create_dir_all(&mempool_dir).unwrap();

        // Eine Datei erzeugen und dann entfernen
        let path = mempool_dir.join("dead.bin");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"x").unwrap();
        remove_with_dir_sync(&path, false).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn deterministic_sort_matches_payload_root() {
        // Drei Txs, unsortiert
        let mk = |n: u8| MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                amount: n as u64,
                lock: LockCommitment([n; 32]),
            }],
        };
        let txs = vec![mk(3), mk(1), mk(2)];
        let sorted = {
            let mut v = txs.clone();
            v.sort_unstable_by(|a, b| digest_microtx(a).cmp(&digest_microtx(b)));
            v
        };
        let p_unsorted = AnchorPayload {
            version: 1,
            micro_txs: txs,
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
        };
        let p_sorted = AnchorPayload {
            version: 1,
            micro_txs: sorted,
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
        };
        assert_eq!(
            payload_merkle_root(&p_unsorted),
            payload_merkle_root(&p_sorted)
        );
    }

    #[test]
    fn pending_finalization_invalidation() {
        // Setup: zwei Txs im Mempool (Dateien + Journal), Payload enthält eine davon
        let base = unique_tmp("finalize");
        let mempool_dir = base.join("mempool");
        std::fs::create_dir_all(&mempool_dir).unwrap();
        let journal_path = mempool_dir.join("mempool.journal");

        let mk = |n: u8| MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                amount: n as u64,
                lock: LockCommitment([n; 32]),
            }],
        };
        let tx_keep = mk(7);
        let tx_inval = mk(9);
        let id_keep = digest_microtx(&tx_keep);
        let id_inval = digest_microtx(&tx_inval);

        // Schreibe beide Txs in Dateien + Journal
        for (tx, id) in [(&tx_keep, &id_keep), (&tx_inval, &id_inval)] {
            let fname = format!("{}.bin", hex::encode(id));
            let path = mempool_dir.join(fname);
            let mut buf = Vec::new();
            tx.encode(&mut buf).unwrap();
            atomic_write(&path, &buf, false).unwrap();
            journal_append(&journal_path, false, b'A', id).unwrap();
        }

        // RAM‑Mempool und Order füllen
        let mut mempool: HashMap<[u8; 32], (MicroTx, Instant)> = HashMap::new();
        let mut order: VecDeque<[u8; 32]> = VecDeque::new();
        let _ = mempool.insert(id_keep, (tx_keep.clone(), Instant::now()));
        let _ = mempool.insert(id_inval, (tx_inval.clone(), Instant::now()));
        order.push_back(id_keep);
        order.push_back(id_inval);

        // Payload mit tx_inval
        let payload = AnchorPayload {
            version: 1,
            micro_txs: vec![tx_inval.clone()],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
        };

        // Invalidation simulieren (inline wie im State‑Task)
        let mut invalidated: u64 = 0;
        for tx in &payload.micro_txs {
            let id = digest_microtx(tx);
            if mempool.remove(&id).is_some() {
                invalidated += 1;
                if let Some(pos) = order.iter().position(|k| *k == id) {
                    let _ = order.remove(pos);
                }
                let fname = format!("{}.bin", hex::encode(id));
                let path = mempool_dir.join(fname);
                journal_append(&journal_path, false, b'D', &id).unwrap();
                remove_with_dir_sync(&path, false).unwrap();
            }
        }

        // Prüfen: eine Tx invalidiert, Datei entfernt, die andere existiert
        assert_eq!(invalidated, 1);
        assert!(mempool.get(&id_inval).is_none());
        assert!(mempool.get(&id_keep).is_some());
        let keep_path = mempool_dir.join(format!("{}.bin", hex::encode(id_keep)));
        assert!(keep_path.exists());
        let inval_path = mempool_dir.join(format!("{}.bin", hex::encode(id_inval)));
        assert!(!inval_path.exists());
        // Order enthält nur id_keep
        assert_eq!(order.len(), 1);
        assert_eq!(order.front().copied(), Some(id_keep));
    }
}
fn rewrite_mempool_journal(
    journal_path: &std::path::Path,
    ids: &VecDeque<[u8; 32]>,
    do_fsync: bool,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = journal_path.to_path_buf();
    tmp.set_extension("journal.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        for id in ids.iter() {
            f.write_all(b"A")?;
            f.write_all(hex::encode(id).as_bytes())?;
            f.write_all(b"\n")?;
        }
        if do_fsync {
            let _ = f.sync_data();
        }
    }
    std::fs::rename(&tmp, journal_path)?;
    if do_fsync {
        if let Some(dir) = journal_path.parent() {
            if let Ok(dirf) = std::fs::File::open(dir) {
                let _ = dirf.sync_data();
            }
        }
    }
    Ok(())
}

fn journal_append(
    journal_path: &std::path::Path,
    do_fsync: bool,
    op: u8,
    id: &[u8; 32],
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)?;
    // Zeile: 'A' oder 'D' + hex + '\n'
    let mut line = Vec::with_capacity(1 + 64 + 1);
    line.push(op);
    line.extend_from_slice(hex::encode(id).as_bytes());
    line.push(b'\n');
    f.write_all(&line)?;
    if do_fsync {
        let _ = f.sync_data();
    }
    Ok(())
}

fn remove_with_dir_sync(path: &std::path::Path, do_fsync: bool) -> std::io::Result<()> {
    std::fs::remove_file(path)?;
    if do_fsync {
        if let Some(dir) = path.parent() {
            if let Ok(dirf) = std::fs::File::open(dir) {
                let _ = dirf.sync_data();
            }
        }
    }
    Ok(())
}

fn atomic_write(path: &std::path::Path, data: &[u8], do_fsync: bool) -> std::io::Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        use std::io::Write as _;
        f.write_all(data)?;
        if do_fsync {
            let _ = f.sync_data();
        }
    }
    std::fs::rename(&tmp, path)?;
    if do_fsync {
        if let Some(dir) = path.parent() {
            if let Ok(dirf) = std::fs::File::open(dir) {
                let _ = dirf.sync_data();
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Args)]
struct CacheBenchArgs {
    /// Pfad zum Store-Root (enthält headers/ und payloads/)
    #[arg(long, default_value = "pc-data")]
    store_dir: String,
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true)
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// Modus: headers | payloads
    #[arg(long)]
    mode: String,
    /// Anzahl eindeutiger Elemente aus dem Store (max.)
    #[arg(long, default_value_t = 100)]
    sample: usize,
    /// Wiederholungen über dem gleichen Sample (>=1)
    #[arg(long, default_value_t = 3)]
    iterations: usize,
    /// Header-Cache-Kapazität (0=aus)
    #[arg(long, default_value_t = 1000)]
    cache_hdr_cap: usize,
    /// Payload-Cache-Kapazität (0=aus)
    #[arg(long, default_value_t = 1000)]
    cache_pl_cap: usize,
}

// Node-weite Metriken (nicht Teil von pc_p2p): Persistenz und Observer-Lag
static NODE_PERSIST_HEADERS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_HEADERS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PERSIST_PAYLOADS_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_INBOUND_OBS_LAGGED_TOTAL: AtomicU64 = AtomicU64::new(0);
// Cache-Metriken
static NODE_CACHE_HEADERS_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_HEADERS_MISSES_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_PAYLOADS_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_CACHE_PAYLOADS_MISSES_TOTAL: AtomicU64 = AtomicU64::new(0);
// Mempool-Metriken
static NODE_MEMPOOL_SIZE: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_DUPLICATE_TOTAL: AtomicU64 = AtomicU64::new(0);
// Zusätzliche Mempool-Metriken
static NODE_MEMPOOL_TTL_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_CAP_EVICT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_MEMPOOL_INVALIDATED_TOTAL: AtomicU64 = AtomicU64::new(0);
// Proposer-Metriken
static NODE_PROPOSER_BUILT_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_LAST_SIZE: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODE_PROPOSER_PENDING: AtomicU64 = AtomicU64::new(0);

// Disk-Read Latenz (Header/Payload) als Histogramm (Buckets analog P2P: 1ms,5ms,10ms,50ms,100ms,500ms,+Inf)
static NODE_STORE_HDR_READ_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_READ_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_1MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_5MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_10MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_HDR_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);

static NODE_STORE_PL_READ_COUNT: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_READ_SUM_MICROS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_1MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_5MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_10MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_50MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_100MS: AtomicU64 = AtomicU64::new(0);
static NODE_STORE_PL_BUCKET_LE_500MS: AtomicU64 = AtomicU64::new(0);

fn observe_hdr_read(d: std::time::Duration) {
    let us = d.as_micros() as u64;
    NODE_STORE_HDR_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    NODE_STORE_HDR_READ_SUM_MICROS.fetch_add(us, Ordering::Relaxed);
    if us <= 1_000 {
        NODE_STORE_HDR_BUCKET_LE_1MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 5_000 {
        NODE_STORE_HDR_BUCKET_LE_5MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 10_000 {
        NODE_STORE_HDR_BUCKET_LE_10MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 50_000 {
        NODE_STORE_HDR_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 100_000 {
        NODE_STORE_HDR_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 500_000 {
        NODE_STORE_HDR_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    }
    // +Inf implizit über count
}

fn observe_pl_read(d: std::time::Duration) {
    let us = d.as_micros() as u64;
    NODE_STORE_PL_READ_COUNT.fetch_add(1, Ordering::Relaxed);
    NODE_STORE_PL_READ_SUM_MICROS.fetch_add(us, Ordering::Relaxed);
    if us <= 1_000 {
        NODE_STORE_PL_BUCKET_LE_1MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 5_000 {
        NODE_STORE_PL_BUCKET_LE_5MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 10_000 {
        NODE_STORE_PL_BUCKET_LE_10MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 50_000 {
        NODE_STORE_PL_BUCKET_LE_50MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 100_000 {
        NODE_STORE_PL_BUCKET_LE_100MS.fetch_add(1, Ordering::Relaxed);
    } else if us <= 500_000 {
        NODE_STORE_PL_BUCKET_LE_500MS.fetch_add(1, Ordering::Relaxed);
    }
}

// Sharded-LRU zur Reduktion von Mutex-Contention
struct ShardedLru<K, V> {
    shards: Vec<Mutex<LruCache<K, V>>>,
}

impl<K: Hash + Eq + Clone, V: Clone> ShardedLru<K, V> {
    fn new(n_shards: usize, total_cap: usize) -> Self {
        let n = std::cmp::max(1, n_shards);
        let per = std::cmp::max(1, total_cap / n);
        let mut shards = Vec::with_capacity(n);
        for _ in 0..n {
            shards.push(Mutex::new(LruCache::new(NonZeroUsize::new(per).unwrap())));
        }
        Self { shards }
    }
    fn index(&self, key: &K) -> usize {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        (h.finish() as usize) % self.shards.len()
    }
    async fn get_clone(&self, key: &K) -> Option<V> {
        let idx = self.index(key);
        let mut g = self.shards[idx].lock().await;
        g.get(key).cloned()
    }
    async fn put(&self, key: K, val: V) {
        let idx = self.index(&key);
        let mut g = self.shards[idx].lock().await;
        g.put(key, val);
    }
    async fn touch_present(&self, key: &K) -> bool {
        let idx = self.index(key);
        let mut g = self.shards[idx].lock().await;
        g.get(key).is_some()
    }
}

// StoreDelegate-Wrapper: persistiert Header/Payloads auf Disk via FileStore, mit optionalem LRU-Cache (sharded)
#[derive(Clone)]
struct NodeDiskStore {
    inner: Arc<FileStore>,
    hdr_cache: Option<Arc<ShardedLru<AnchorId, AnchorHeader>>>,
    pl_cache: Option<Arc<ShardedLru<[u8; 32], AnchorPayload>>>,
    txs: Arc<tokio::sync::Mutex<HashMap<[u8; 32], MicroTx>>>,
}

impl NodeDiskStore {
    fn new(store: FileStore, hdr_cap: usize, pl_cap: usize) -> Self {
        let shards = std::cmp::max(1, num_cpus::get());
        let hdr_cache = if hdr_cap > 0 {
            Some(Arc::new(ShardedLru::new(shards, hdr_cap)))
        } else {
            None
        };
        let pl_cache = if pl_cap > 0 {
            Some(Arc::new(ShardedLru::new(shards, pl_cap)))
        } else {
            None
        };
        Self {
            inner: Arc::new(store),
            hdr_cache,
            pl_cache,
            txs: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl pc_p2p::async_svc::StoreDelegate for NodeDiskStore {
    async fn insert_header(&self, h: AnchorHeader) {
        let store = self.inner.clone();
        let h_clone_for_cache = h.clone();
        match tokio::task::spawn_blocking(move || store.put_header(&h)).await {
            Ok(Ok(_)) => {
                NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
                if let Some(c) = &self.hdr_cache {
                    let id = AnchorId(h_clone_for_cache.id_digest());
                    c.put(id, h_clone_for_cache).await;
                }
            }
            _ => {
                NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!("store.put_header failed");
            }
        }
    }
    async fn insert_payload(&self, p: AnchorPayload) {
        let store = self.inner.clone();
        let p_clone_for_cache = p.clone();
        match tokio::task::spawn_blocking(move || store.put_payload(&p)).await {
            Ok(Ok(_)) => {
                NODE_PERSIST_PAYLOADS_TOTAL.fetch_add(1, Ordering::Relaxed);
                if let Some(c) = &self.pl_cache {
                    let root = payload_merkle_root(&p_clone_for_cache);
                    c.put(root, p_clone_for_cache).await;
                }
            }
            _ => {
                NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!("store.put_payload failed");
            }
        }
    }
    async fn has_payload(&self, root: &[u8; 32]) -> bool {
        let r = *root;
        if let Some(c) = &self.pl_cache {
            if c.touch_present(&r).await {
                NODE_CACHE_PAYLOADS_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
                return true;
            } else {
                NODE_CACHE_PAYLOADS_MISSES_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        }
        let store = self.inner.clone();
        match tokio::task::spawn_blocking(move || store.has_payload(&r)).await {
            Ok(v) => v,
            Err(_) => false,
        }
    }
    async fn get_headers(&self, ids: &[AnchorId]) -> (Vec<AnchorHeader>, Vec<[u8; 32]>) {
        let mut found: Vec<AnchorHeader> = Vec::new();
        let mut to_fetch: Vec<AnchorId> = Vec::new();
        if let Some(c) = &self.hdr_cache {
            for id in ids.iter().cloned() {
                if let Some(h) = c.get_clone(&id).await {
                    NODE_CACHE_HEADERS_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    found.push(h);
                } else {
                    NODE_CACHE_HEADERS_MISSES_TOTAL.fetch_add(1, Ordering::Relaxed);
                    to_fetch.push(id);
                }
            }
        } else {
            to_fetch.extend_from_slice(ids);
        }
        // Disk-Fetch in einem Blocking-Block
        let store = self.inner.clone();
        let fetched: Vec<AnchorHeader> = match tokio::task::spawn_blocking(move || {
            let mut v = Vec::new();
            for id in to_fetch.iter() {
                let t0 = std::time::Instant::now();
                let res = store.get_header(&id.0);
                let dt = t0.elapsed();
                observe_hdr_read(dt);
                match res {
                    Ok(Some(h)) => v.push(h),
                    _ => {}
                }
            }
            v
        })
        .await
        {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        // Cache auffüllen
        if let Some(c) = &self.hdr_cache {
            for h in &fetched {
                let id = AnchorId(h.id_digest());
                c.put(id, h.clone()).await;
            }
        }
        // Missing ermitteln
        let mut missing: Vec<[u8; 32]> = Vec::new();
        let mut seen_ids: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for h in &found {
            seen_ids.insert(h.id_digest());
        }
        for h in &fetched {
            seen_ids.insert(h.id_digest());
        }
        for id in ids.iter() {
            if !seen_ids.contains(&id.0) {
                missing.push(id.0);
            }
        }
        // Zusammenführen
        let mut all_found = found;
        all_found.extend(fetched.into_iter());
        (all_found, missing)
    }
    async fn get_payloads(&self, roots: &[[u8; 32]]) -> (Vec<AnchorPayload>, Vec<[u8; 32]>) {
        let mut found: Vec<AnchorPayload> = Vec::new();
        let mut to_fetch: Vec<[u8; 32]> = Vec::new();
        if let Some(c) = &self.pl_cache {
            for r in roots.iter().cloned() {
                if let Some(p) = c.get_clone(&r).await {
                    NODE_CACHE_PAYLOADS_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
                    found.push(p);
                } else {
                    NODE_CACHE_PAYLOADS_MISSES_TOTAL.fetch_add(1, Ordering::Relaxed);
                    to_fetch.push(r);
                }
            }
        } else {
            to_fetch.extend_from_slice(roots);
        }
        // Disk-Fetch in einem Blocking-Block
        let store = self.inner.clone();
        let fetched: Vec<(AnchorPayload, [u8; 32])> = match tokio::task::spawn_blocking(move || {
            let mut v = Vec::new();
            for r in to_fetch.iter() {
                let t0 = std::time::Instant::now();
                let res = store.get_payload(r);
                let dt = t0.elapsed();
                observe_pl_read(dt);
                match res {
                    Ok(Some(p)) => v.push((p, *r)),
                    _ => {}
                }
            }
            v
        })
        .await
        {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        // Cache auffüllen
        if let Some(c) = &self.pl_cache {
            for (p, r) in &fetched {
                c.put(*r, p.clone()).await;
            }
        }
        // Missing ermitteln
        let mut missing: Vec<[u8; 32]> = Vec::new();
        let mut seen_roots: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for p in &found {
            seen_roots.insert(payload_merkle_root(p));
        }
        for (_p, r) in &fetched {
            seen_roots.insert(*r);
        }
        for r in roots.iter() {
            if !seen_roots.contains(r) {
                missing.push(*r);
            }
        }
        // Zusammenführen
        let mut all_found = found;
        all_found.extend(fetched.into_iter().map(|(p, _r)| p));
        (all_found, missing)
    }

    async fn insert_tx(&self, tx: MicroTx) {
        let id = digest_microtx(&tx);
        let mut g = self.txs.lock().await;
        let _ = g.insert(id, tx);
    }
    async fn has_tx(&self, id: &[u8; 32]) -> bool {
        let g = self.txs.lock().await;
        g.contains_key(id)
    }
    async fn get_txs(&self, ids: &[[u8; 32]]) -> (Vec<MicroTx>, Vec<[u8; 32]>) {
        let g = self.txs.lock().await;
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for id in ids {
            if let Some(tx) = g.get(id) {
                found.push(tx.clone());
            } else {
                missing.push(*id);
            }
        }
        (found, missing)
    }
}

fn run_consensus_ack_dists(args: &ConsensusAckDistsArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let headers: Vec<AnchorHeader> = load_vec_decodable(&args.headers_file)?;
    // k aus Genesis (falls vorhanden) oder CLI ableiten; Genesis hat Vorrang
    let k_eff = if let Some(ref gpath) = args.genesis {
        let g = load_genesis(gpath)?;
        let k = g.consensus.k;
        if k == 0 || k > 64 {
            bail!("invalid k in genesis: {} (must be 1..=64)", k);
        }
        println!(
            "{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}",
            k, g.commitment
        );
        k
    } else {
        if args.k == 0 || args.k > 64 {
            bail!("invalid k: {} (must be 1..=64)", args.k);
        }
        println!(
            "{{\"type\":\"k_selected\",\"k\":{},\"source\":\"cli\"}}",
            args.k
        );
        args.k
    };
    let mut cfg = ConsensusConfig::recommended(k_eff);
    if let Some(dm) = args.d_max {
        cfg.fee_params.d_max = dm;
    }
    let dmax_out = cfg.fee_params.d_max;
    let mut eng = ConsensusEngine::new(cfg);
    for h in headers {
        let _ = eng.insert_header(h);
    }
    let dists = eng.ack_distances(AnchorId(ack));
    // Baue JSON deterministisch ohne Format-String-Brace-Escapes
    let mut out = String::new();
    out.push_str("{\"k\":");
    out.push_str(&args.k.to_string());
    out.push_str(",\"d_max\":");
    out.push_str(&dmax_out.to_string());
    out.push_str(",\"distances\":[");
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match d {
            Some(v) => out.push_str(&v.to_string()),
            None => out.push_str("null"),
        }
    }
    out.push_str("]}");
    println!("{}", out);
    Ok(())
}

fn run_consensus_payout_root(args: &ConsensusPayoutRootArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let headers: Vec<AnchorHeader> = load_vec_decodable(&args.headers_file)?;
    let recipients = parse_hex32_list(&args.recipients)?;
    // k aus Genesis (falls vorhanden) oder CLI ableiten; Genesis hat Vorrang
    let k_eff = if let Some(ref gpath) = args.genesis {
        let g = load_genesis(gpath)?;
        let k = g.consensus.k;
        if k == 0 || k > 64 {
            bail!("invalid k in genesis: {} (must be 1..=64)", k);
        }
        println!(
            "{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}",
            k, g.commitment
        );
        k
    } else {
        if args.k == 0 || args.k > 64 {
            bail!("invalid k: {} (must be 1..=64)", args.k);
        }
        println!(
            "{{\"type\":\"k_selected\",\"k\":{},\"source\":\"cli\"}}",
            args.k
        );
        args.k
    };
    if recipients.len() != k_eff as usize {
        bail!(
            "recipients length ({}) must equal k ({})",
            recipients.len(),
            k_eff
        );
    }
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let mut cfg = ConsensusConfig::recommended(k_eff);
    if let Some(dm) = args.d_max {
        cfg.fee_params.d_max = dm;
    }
    let mut eng = ConsensusEngine::new(cfg);
    for h in headers {
        let _ = eng.insert_header(h);
    }
    let root = eng.committee_payout_root_for_ack(
        args.fees,
        &recipients,
        args.proposer_index,
        AnchorId(ack),
    )?;
    println!("{}", hex::encode(root));
    Ok(())
}

#[derive(Debug, Clone, Args)]
struct ConsensusAckDistsArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    genesis: Option<String>,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
}

#[derive(Debug, Clone, Args)]
struct ConsensusPayoutRootArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert) – muss Länge k haben
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: usize,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    genesis: Option<String>,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
}

#[derive(Debug, Clone, Args, Default)]
struct RateArgs {
    /// HeaderAnnounce Bucket-Kapazität
    #[arg(long)]
    hdr_capacity: Option<u32>,
    /// HeaderAnnounce Tokens pro Sekunde
    #[arg(long)]
    hdr_refill_per_sec: Option<u32>,
    /// PayloadInv Bucket-Kapazität
    #[arg(long)]
    inv_capacity: Option<u32>,
    /// PayloadInv Tokens pro Sekunde
    #[arg(long)]
    inv_refill_per_sec: Option<u32>,
    /// Req Bucket-Kapazität
    #[arg(long)]
    req_capacity: Option<u32>,
    /// Req Tokens pro Sekunde
    #[arg(long)]
    req_refill_per_sec: Option<u32>,
    /// Resp Bucket-Kapazität
    #[arg(long)]
    resp_capacity: Option<u32>,
    /// Resp Tokens pro Sekunde
    #[arg(long)]
    resp_refill_per_sec: Option<u32>,
    /// Per-Peer-Limits aktivieren (true/false)
    #[arg(long)]
    per_peer: Option<bool>,
    /// TTL für per-Peer Rate-Limiter in Sekunden (Cleanup), 0 = Default
    #[arg(long)]
    peer_ttl_secs: Option<u64>,
}

fn rate_cfg_opt(r: &RateArgs) -> Option<RateLimitConfig> {
    let any = r.hdr_capacity.is_some()
        || r.hdr_refill_per_sec.is_some()
        || r.inv_capacity.is_some()
        || r.inv_refill_per_sec.is_some()
        || r.req_capacity.is_some()
        || r.req_refill_per_sec.is_some()
        || r.resp_capacity.is_some()
        || r.resp_refill_per_sec.is_some()
        || r.per_peer.is_some()
        || r.peer_ttl_secs.is_some();
    if !any {
        return None;
    }
    Some(RateLimitConfig {
        hdr_capacity: r.hdr_capacity.unwrap_or(0),
        hdr_refill_per_sec: r.hdr_refill_per_sec.unwrap_or(0),
        inv_capacity: r.inv_capacity.unwrap_or(0),
        inv_refill_per_sec: r.inv_refill_per_sec.unwrap_or(0),
        req_capacity: r.req_capacity.unwrap_or(0),
        req_refill_per_sec: r.req_refill_per_sec.unwrap_or(0),
        resp_capacity: r.resp_capacity.unwrap_or(0),
        resp_refill_per_sec: r.resp_refill_per_sec.unwrap_or(0),
        per_peer: r.per_peer.unwrap_or(true),
        peer_ttl_secs: r.peer_ttl_secs.unwrap_or(0),
    })
}

#[derive(Debug, Clone, Args)]
struct P2pInjectHeadersArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    cert_file: String,
    /// Datei mit Vec<AnchorHeader> (pc-codec)
    #[arg(long)]
    headers_file: String,
}

#[derive(Debug, Clone, Args)]
struct P2pInjectPayloadsArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    cert_file: String,
    /// Datei mit Vec<AnchorPayload> (pc-codec)
    #[arg(long)]
    payloads_file: String,
    /// Zusätzlich zur Inventory die Payloads direkt mitsenden (RespMsg::Payloads)
    #[arg(long, default_value_t = false)]
    with_payloads: bool,
}

#[derive(Debug, Clone, Args)]
struct P2pQuicListenArgs {
    /// QUIC Listen-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Optional: schreibe Zertifikat (DER) in Datei
    #[arg(long)]
    cert_out: Option<String>,
    /// Pfad zu einer TOML-Konfigurationsdatei (optional)
    #[arg(long)]
    config: Option<String>,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    genesis: Option<String>,
    /// Persistenz-Verzeichnis für Headers/Payloads (wird angelegt)
    #[arg(long, default_value = "pc-data")]
    store_dir: String,
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true)
    #[arg(long, default_value_t = true)]
    fsync: bool,
    /// Committee-Größe k (1..=64) für ConsensusEngine
    #[arg(long, default_value_t = 21)]
    k: u8,
    /// Header-Cache-Kapazität (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    cache_hdr_cap: Option<usize>,
    /// Payload-Cache-Kapazität (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    cache_pl_cap: Option<usize>,
    /// Rate-Limits (optional)
    #[command(flatten)]
    rate: RateArgs,
    /// Aktiviere einfachen PoW-Miner für Mint-Emission (Dev)
    #[arg(long, default_value_t = false)]
    pow_miner: bool,
    /// Mint-Amount (in kleinster Einheit)
    #[arg(long)]
    mint_amount: Option<u64>,
    /// Payout-Lock (32-Byte Hex Commitment)
    #[arg(long)]
    mint_lock: Option<String>,
    /// Aktiviere Tx-Proposer: baut periodisch Payloads aus Mempool-TXs und announced sie
    #[arg(long, default_value_t = false)]
    tx_proposer: bool,
    /// Intervall für Tx-Proposer in Millisekunden
    #[arg(long, default_value_t = 5000)]
    tx_proposer_interval_ms: u64,
    /// Max. Anzahl MicroTxs pro Payload (Default: MAX_PAYLOAD_MICROTX)
    #[arg(long)]
    txs_per_payload: Option<usize>,
    /// Optionales Payload-Größenbudget (Bytes, encoded_len Summe); übersteigt Auswahl nicht diesen Wert
    #[arg(long)]
    payload_budget_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    consensus: Option<ConsensusCfg>,
    node: Option<NodeSection>,
}

#[derive(Debug, Deserialize)]
struct ConsensusCfg {
    k: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct NodeSection {
    cache: Option<CacheCfg>,
}

#[derive(Debug, Deserialize)]
struct CacheCfg {
    header_cap: Option<usize>,
    payload_cap: Option<usize>,
}

fn load_node_config(path: &str) -> Result<NodeConfig> {
    let s = std::fs::read_to_string(path).map_err(|e| anyhow!("read config '{}': {}", path, e))?;
    let cfg: NodeConfig =
        toml::from_str(&s).map_err(|e| anyhow!("parse toml '{}': {}", path, e))?;
    Ok(cfg)
}

#[derive(Debug, Deserialize)]
struct Genesis {
    consensus: GenesisConsensus,
    genesis_note: String,
    commitment: String,
}

#[derive(Debug, Deserialize)]
struct GenesisConsensus {
    k: u8,
    // Optional: PoW-Difficulty in führenden Nullbits für Mint-PoW
    pow_bits: Option<u8>,
}

fn load_genesis(path: &str) -> Result<Genesis> {
    let s = std::fs::read_to_string(path).map_err(|e| anyhow!("read genesis '{}': {}", path, e))?;
    let g: Genesis = toml::from_str(&s).map_err(|e| anyhow!("parse toml '{}': {}", path, e))?;
    // Validierung: commitment == blake3_32(genesis_note)
    let note = parse_hex32(&g.genesis_note)?;
    let got = blake3_32(&note);
    let want = parse_hex32(&g.commitment)?;
    if got != want {
        bail!(
            "genesis commitment mismatch: computed={}, expected={}",
            hex::encode(got),
            g.commitment
        );
    }
    Ok(g)
}

#[derive(Debug, Clone, Args)]
struct P2pQuicConnectArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    cert_file: String,
    /// Rate-Limits (optional)
    #[command(flatten)]
    rate: RateArgs,
}

fn run_p2p_run(args: &P2pRunArgs) -> Result<()> {
    // Runtime erstellen
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::async_svc as p2p_async;
        use pc_p2p::P2pConfig;
        let cfg = P2pConfig {
            max_peers: args.max_peers,
            rate: rate_cfg_opt(&args.rate),
        };
        let (svc, mut out_rx, handle) = p2p_async::spawn(cfg);
        let print_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                outbox_deq_inc();
                match msg {
                    P2pMessage::HeaderAnnounce(h) => {
                        println!(
                            "{{\"type\":\"header_announce\",\"creator\":{},\"id\":\"{}\"}}",
                            h.creator_index,
                            hex::encode(h.id_digest())
                        );
                    }
                    P2pMessage::HeadersInv { ids } => {
                        let mut out = String::from("{\"type\":\"headers_inv\",\"ids\":[");
                        for (i, id) in ids.iter().enumerate() {
                            if i > 0 {
                                out.push(',');
                            }
                            out.push('"');
                            out.push_str(&hex::encode(id.0));
                            out.push('"');
                        }
                        out.push_str("]}");
                        println!("{}", out);
                    }
                    P2pMessage::PayloadInv { roots } => {
                        // JSON-Ausgabe sicher zusammenbauen
                        let mut out = String::from("{\"type\":\"payload_inv\",\"roots\":[");
                        for (i, r) in roots.iter().enumerate() {
                            if i > 0 {
                                out.push(',');
                            }
                            out.push('"');
                            out.push_str(&hex::encode(r));
                            out.push('"');
                        }
                        out.push_str("]}");
                        println!("{}", out);
                    }
                    P2pMessage::TxInv { ids } => {
                        let mut out = String::from("{\"type\":\"tx_inv\",\"ids\":[");
                        for (i, id) in ids.iter().enumerate() {
                            if i > 0 {
                                out.push(',');
                            }
                            out.push('"');
                            out.push_str(&hex::encode(id));
                            out.push('"');
                        }
                        out.push_str("]}");
                        println!("{}", out);
                    }
                    P2pMessage::Req(_) => {
                        println!("{{\"type\":\"req\"}}");
                    }
                    P2pMessage::Resp(_) => {
                        println!("{{\"type\":\"resp\"}}");
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        // Hinweis: Dev-PoW-Miner ist nur im QUIC-Listen-Server implementiert.
        // Warte auf Ctrl-C und stoppe dann
        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = print_task.await;
        let res = handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))
    })
}

fn read_hex32_files_in(dir: &std::path::Path, max_n: usize) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if let Some(name) = p.file_stem().and_then(|s| s.to_str()) {
            if name.len() == 64 {
                // 32 bytes hex
                if let Ok(bytes) = hex::decode(name) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        out.push(arr);
                        if out.len() >= max_n {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

fn run_cache_bench(args: &CacheBenchArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = FileStore::open(&args.store_dir, args.fsync)?;
        let delegate = NodeDiskStore::new(store, args.cache_hdr_cap, args.cache_pl_cap);
        let start_hits_hdr = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
        let start_miss_hdr = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
        let start_hits_pl = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
        let start_miss_pl = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
        let t0 = Instant::now();
        match args.mode.as_str() {
            "headers" => {
                let ids = read_hex32_files_in(&std::path::Path::new(&args.store_dir).join("headers"), args.sample)?
                    .into_iter().map(AnchorId).collect::<Vec<_>>();
                if ids.is_empty() { bail!("no headers found in store_dir"); }
                for _ in 0..args.iterations {
                    let _ = delegate.get_headers(&ids).await;
                }
            }
            "payloads" => {
                let roots = read_hex32_files_in(&std::path::Path::new(&args.store_dir).join("payloads"), args.sample)?;
                if roots.is_empty() { bail!("no payloads found in store_dir"); }
                for _ in 0..args.iterations {
                    let _ = delegate.get_payloads(&roots).await;
                }
            }
            other => { bail!("invalid mode: {} (use 'headers' or 'payloads')", other); }
        }
        let elapsed = t0.elapsed();
        let end_hits_hdr = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
        let end_miss_hdr = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
        let end_hits_pl = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
        let end_miss_pl = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
        let dh_hdr = end_hits_hdr.saturating_sub(start_hits_hdr);
        let dm_hdr = end_miss_hdr.saturating_sub(start_miss_hdr);
        let dh_pl = end_hits_pl.saturating_sub(start_hits_pl);
        let dm_pl = end_miss_pl.saturating_sub(start_miss_pl);
        println!(
            "{{\"type\":\"cache_bench\",\"mode\":\"{}\",\"sample\":{},\"iterations\":{},\"hdr_hits\":{},\"hdr_misses\":{},\"pl_hits\":{},\"pl_misses\":{},\"elapsed_ms\":{}}}",
            args.mode, args.sample, args.iterations, dh_hdr, dm_hdr, dh_pl, dm_pl, elapsed.as_millis()
        );
        Ok::<(), anyhow::Error>(())
    })
}

fn run_p2p_metrics() -> Result<()> {
    let m = metrics_snapshot();
    let n_hdr = NODE_PERSIST_HEADERS_TOTAL.load(Ordering::Relaxed);
    let n_hdr_err = NODE_PERSIST_HEADERS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_pl = NODE_PERSIST_PAYLOADS_TOTAL.load(Ordering::Relaxed);
    let n_pl_err = NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_lag = NODE_INBOUND_OBS_LAGGED_TOTAL.load(Ordering::Relaxed);
    println!(
        "{{\"inbound_total\":{},\"inbound_dropped_rate\":{},\"outbound_total\":{},\"peer_rl_purged_total\":{},\"in_hdr_total\":{},\"in_inv_total\":{},\"in_req_total\":{},\"in_resp_total\":{},\"out_hdr_total\":{},\"out_inv_total\":{},\"out_req_total\":{},\"out_resp_total\":{},\"out_errors_total\":{},\"outbox_enq_total\":{},\"outbox_deq_total\":{},\"in_handle_count\":{},\"in_handle_sum_micros\":{},\"in_bucket_le_1ms\":{},\"in_bucket_le_5ms\":{},\"in_bucket_le_10ms\":{},\"in_bucket_le_50ms\":{},\"in_bucket_le_100ms\":{},\"in_bucket_le_500ms\":{},\"node_persist_headers_total\":{},\"node_persist_headers_errors_total\":{},\"node_persist_payloads_total\":{},\"node_persist_payloads_errors_total\":{},\"node_inbound_obs_lagged_total\":{}}}",
        m.inbound_total,
        m.inbound_dropped_rate,
        m.outbound_total,
        m.peer_rl_purged_total,
        m.in_hdr_total,
        m.in_inv_total,
        m.in_req_total,
        m.in_resp_total,
        m.out_hdr_total,
        m.out_inv_total,
        m.out_req_total,
        m.out_resp_total,
        m.out_errors_total,
        m.outbox_enq_total,
        m.outbox_deq_total,
        m.in_handle_count,
        m.in_handle_sum_micros,
        m.in_bucket_le_1ms,
        m.in_bucket_le_5ms,
        m.in_bucket_le_10ms,
        m.in_bucket_le_50ms,
        m.in_bucket_le_100ms,
        m.in_bucket_le_500ms,
        n_hdr,
        n_hdr_err,
        n_pl,
        n_pl_err,
        n_lag
    );
    Ok(())
}

fn run_p2p_metrics_serve(args: &MetricsServeArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = args.addr.parse().map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let make_svc = make_service_fn(|_conn| async move {
            Ok::<_, anyhow::Error>(service_fn(|req: Request<Body>| async move {
                if req.uri().path() != "/metrics" {
                    let mut resp = Response::builder()
                        .status(404)
                        .body(Body::from("Not Found"))
                        .unwrap();
                    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain"));
                    return Ok::<_, anyhow::Error>(resp);
                }
                let m = metrics_snapshot();
                let sum_sec = (m.in_handle_sum_micros as f64) / 1_000_000.0;
                let c1 = m.in_bucket_le_1ms;
                let c5 = c1 + m.in_bucket_le_5ms;
                let c10 = c5 + m.in_bucket_le_10ms;
                let c50 = c10 + m.in_bucket_le_50ms;
                let c100 = c50 + m.in_bucket_le_100ms;
                let c500 = c100 + m.in_bucket_le_500ms;
                let count = m.in_handle_count;
                let n_hdr = NODE_PERSIST_HEADERS_TOTAL.load(Ordering::Relaxed);
                let n_hdr_err = NODE_PERSIST_HEADERS_ERRORS_TOTAL.load(Ordering::Relaxed);
                let n_pl = NODE_PERSIST_PAYLOADS_TOTAL.load(Ordering::Relaxed);
                let n_pl_err = NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.load(Ordering::Relaxed);
                let n_lag = NODE_INBOUND_OBS_LAGGED_TOTAL.load(Ordering::Relaxed);
                // Node-Store Read Latenzen
                let hdr_cnt = NODE_STORE_HDR_READ_COUNT.load(Ordering::Relaxed);
                let hdr_sum_sec = (NODE_STORE_HDR_READ_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
                let h1 = NODE_STORE_HDR_BUCKET_LE_1MS.load(Ordering::Relaxed);
                let h5 = h1 + NODE_STORE_HDR_BUCKET_LE_5MS.load(Ordering::Relaxed);
                let h10 = h5 + NODE_STORE_HDR_BUCKET_LE_10MS.load(Ordering::Relaxed);
                let h50 = h10 + NODE_STORE_HDR_BUCKET_LE_50MS.load(Ordering::Relaxed);
                let h100 = h50 + NODE_STORE_HDR_BUCKET_LE_100MS.load(Ordering::Relaxed);
                let h500 = h100 + NODE_STORE_HDR_BUCKET_LE_500MS.load(Ordering::Relaxed);

                let pl_cnt = NODE_STORE_PL_READ_COUNT.load(Ordering::Relaxed);
                let pl_sum_sec = (NODE_STORE_PL_READ_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
                let p1 = NODE_STORE_PL_BUCKET_LE_1MS.load(Ordering::Relaxed);
                let p5 = p1 + NODE_STORE_PL_BUCKET_LE_5MS.load(Ordering::Relaxed);
                let p10 = p5 + NODE_STORE_PL_BUCKET_LE_10MS.load(Ordering::Relaxed);
                let p50 = p10 + NODE_STORE_PL_BUCKET_LE_50MS.load(Ordering::Relaxed);
                let p100 = p50 + NODE_STORE_PL_BUCKET_LE_100MS.load(Ordering::Relaxed);
                let p500 = p100 + NODE_STORE_PL_BUCKET_LE_500MS.load(Ordering::Relaxed);
                let cache_hdr_hit = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
                let cache_hdr_miss = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
                let cache_pl_hit = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
                let cache_pl_miss = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
                // Mempool-Kennzahlen
                let mp_size = NODE_MEMPOOL_SIZE.load(Ordering::Relaxed);
                let mp_acc = NODE_MEMPOOL_ACCEPTED_TOTAL.load(Ordering::Relaxed);
                let mp_rej = NODE_MEMPOOL_REJECTED_TOTAL.load(Ordering::Relaxed);
                let mp_dup = NODE_MEMPOOL_DUPLICATE_TOTAL.load(Ordering::Relaxed);
                let mp_ttl = NODE_MEMPOOL_TTL_EVICT_TOTAL.load(Ordering::Relaxed);
                let mp_cap = NODE_MEMPOOL_CAP_EVICT_TOTAL.load(Ordering::Relaxed);
                let mp_invld = NODE_MEMPOOL_INVALIDATED_TOTAL.load(Ordering::Relaxed);
                let prop_built = NODE_PROPOSER_BUILT_TOTAL.load(Ordering::Relaxed);
                let prop_last = NODE_PROPOSER_LAST_SIZE.load(Ordering::Relaxed);
                let prop_err = NODE_PROPOSER_ERRORS_TOTAL.load(Ordering::Relaxed);
                let prop_pending = NODE_PROPOSER_PENDING.load(Ordering::Relaxed);
                let body = format!(
                    "# HELP pc_p2p_inbound_total Total inbound messages\n# TYPE pc_p2p_inbound_total counter\npc_p2p_inbound_total {}\n\
# HELP pc_p2p_inbound_dropped_rate Dropped inbound messages due to rate limiting\n# TYPE pc_p2p_inbound_dropped_rate counter\npc_p2p_inbound_dropped_rate {}\n\
# HELP pc_p2p_outbound_total Total outbound messages\n# TYPE pc_p2p_outbound_total counter\npc_p2p_outbound_total {}\n\
# HELP pc_p2p_peer_rl_purged_total Purged per-peer rate limiters due to TTL\n# TYPE pc_p2p_peer_rl_purged_total counter\npc_p2p_peer_rl_purged_total {}\n\
# HELP pc_p2p_in_hdr_total Total inbound HeaderAnnounce\n# TYPE pc_p2p_in_hdr_total counter\npc_p2p_in_hdr_total {}\n\
# HELP pc_p2p_in_inv_total Total inbound PayloadInv\n# TYPE pc_p2p_in_inv_total counter\npc_p2p_in_inv_total {}\n\
# HELP pc_p2p_in_req_total Total inbound Req\n# TYPE pc_p2p_in_req_total counter\npc_p2p_in_req_total {}\n\
# HELP pc_p2p_in_resp_total Total inbound Resp\n# TYPE pc_p2p_in_resp_total counter\npc_p2p_in_resp_total {}\n\
# HELP pc_p2p_out_hdr_total Total outbound HeaderAnnounce\n# TYPE pc_p2p_out_hdr_total counter\npc_p2p_out_hdr_total {}\n\
# HELP pc_p2p_out_inv_total Total outbound PayloadInv\n# TYPE pc_p2p_out_inv_total counter\npc_p2p_out_inv_total {}\n\
# HELP pc_p2p_out_req_total Total outbound Req\n# TYPE pc_p2p_out_req_total counter\npc_p2p_out_req_total {}\n\
# HELP pc_p2p_out_resp_total Total outbound Resp\n# TYPE pc_p2p_out_resp_total counter\npc_p2p_out_resp_total {}\n\
# HELP pc_p2p_out_errors_total Total outbound transport errors (QUIC/network)\n# TYPE pc_p2p_out_errors_total counter\npc_p2p_out_errors_total {}\n\
# HELP pc_p2p_outbox_enq_total Total enqueued messages to outbox\n# TYPE pc_p2p_outbox_enq_total counter\npc_p2p_outbox_enq_total {}\n\
# HELP pc_p2p_outbox_deq_total Total dequeued messages from outbox\n# TYPE pc_p2p_outbox_deq_total counter\npc_p2p_outbox_deq_total {}\n\
# HELP pc_p2p_in_handle_seconds Inbound message handling latency\n# TYPE pc_p2p_in_handle_seconds histogram\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_p2p_in_handle_seconds_sum {}\n\
pc_p2p_in_handle_seconds_count {}\n",
                    m.inbound_total, m.inbound_dropped_rate, m.outbound_total,
                    m.peer_rl_purged_total,
                    m.in_hdr_total, m.in_inv_total, m.in_req_total, m.in_resp_total,
                    m.out_hdr_total, m.out_inv_total, m.out_req_total, m.out_resp_total,
                    m.out_errors_total, m.outbox_enq_total, m.outbox_deq_total,
                    c1, c5, c10, c50, c100, c500, count, sum_sec, count
                );
                // Node-Metriken (Persistenz/Observer-Lag/Cache) anhängen
                let node_metrics = format!(
                    "# HELP pc_node_persist_headers_total Total persisted headers\n# TYPE pc_node_persist_headers_total counter\npc_node_persist_headers_total {}\n\
# HELP pc_node_persist_headers_errors_total Total errors persisting headers\n# TYPE pc_node_persist_headers_errors_total counter\npc_node_persist_headers_errors_total {}\n\
# HELP pc_node_persist_payloads_total Total persisted payloads\n# TYPE pc_node_persist_payloads_total counter\npc_node_persist_payloads_total {}\n\
# HELP pc_node_persist_payloads_errors_total Total errors persisting payloads\n# TYPE pc_node_persist_payloads_errors_total counter\npc_node_persist_payloads_errors_total {}\n\
# HELP pc_node_inbound_obs_lagged_total Total dropped messages in node inbound observer due to lag\n# TYPE pc_node_inbound_obs_lagged_total counter\npc_node_inbound_obs_lagged_total {}\n\
# HELP pc_node_cache_headers_hits_total Cache hits for headers\n# TYPE pc_node_cache_headers_hits_total counter\npc_node_cache_headers_hits_total {}\n\
# HELP pc_node_cache_headers_misses_total Cache misses for headers\n# TYPE pc_node_cache_headers_misses_total counter\npc_node_cache_headers_misses_total {}\n\
# HELP pc_node_cache_payloads_hits_total Cache hits for payloads\n# TYPE pc_node_cache_payloads_hits_total counter\npc_node_cache_payloads_hits_total {}\n\
# HELP pc_node_cache_payloads_misses_total Cache misses for payloads\n# TYPE pc_node_cache_payloads_misses_total counter\npc_node_cache_payloads_misses_total {}\n\
# HELP pc_node_store_header_read_seconds Node store header read latency\n# TYPE pc_node_store_header_read_seconds histogram\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_store_header_read_seconds_sum {}\n\
pc_node_store_header_read_seconds_count {}\n\
# HELP pc_node_store_payload_read_seconds Node store payload read latency\n# TYPE pc_node_store_payload_read_seconds histogram\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_store_payload_read_seconds_sum {}\n\
pc_node_store_payload_read_seconds_count {}\n\
# HELP pc_node_mempool_size Current mempool size\n# TYPE pc_node_mempool_size gauge\npc_node_mempool_size {}\n\
# HELP pc_node_mempool_accepted_total Total accepted txs into mempool\n# TYPE pc_node_mempool_accepted_total counter\npc_node_mempool_accepted_total {}\n\
# HELP pc_node_mempool_rejected_total Total rejected txs (stateless invalid)\n# TYPE pc_node_mempool_rejected_total counter\npc_node_mempool_rejected_total {}\n\
# HELP pc_node_mempool_duplicate_total Total duplicate txs ignored\n# TYPE pc_node_mempool_duplicate_total counter\npc_node_mempool_duplicate_total {}\n\
# HELP pc_node_mempool_ttl_evict_total Total mempool evictions due to TTL\n# TYPE pc_node_mempool_ttl_evict_total counter\npc_node_mempool_ttl_evict_total {}\n\
# HELP pc_node_mempool_cap_evict_total Total mempool evictions due to cap limit\n# TYPE pc_node_mempool_cap_evict_total counter\npc_node_mempool_cap_evict_total {}\n\
# HELP pc_node_mempool_invalidated_total Total mempool txs invalidated by finalized state\n# TYPE pc_node_mempool_invalidated_total counter\npc_node_mempool_invalidated_total {}\n\
# HELP pc_node_proposer_built_total Total payloads built by proposer\n# TYPE pc_node_proposer_built_total counter\npc_node_proposer_built_total {}\n\
# HELP pc_node_proposer_last_size Last built payload micro_txs count\n# TYPE pc_node_proposer_last_size gauge\npc_node_proposer_last_size {}\n\
# HELP pc_node_proposer_errors_total Total proposer errors\n# TYPE pc_node_proposer_errors_total counter\npc_node_proposer_errors_total {}\n\
# HELP pc_node_proposer_pending Current pending payloads awaiting finalization\n# TYPE pc_node_proposer_pending gauge\npc_node_proposer_pending {}\n",
                    n_hdr, n_hdr_err, n_pl, n_pl_err, n_lag,
                    cache_hdr_hit, cache_hdr_miss, cache_pl_hit, cache_pl_miss,
                    h1, h5, h10, h50, h100, h500, hdr_cnt, hdr_sum_sec, hdr_cnt,
                    p1, p5, p10, p50, p100, p500, pl_cnt, pl_sum_sec, pl_cnt,
                    mp_size, mp_acc, mp_rej, mp_dup,
                    mp_ttl, mp_cap, mp_invld, prop_built, prop_last, prop_err, prop_pending
                );
                let body = format!("{}{}", body, node_metrics);
                let mut resp = Response::new(Body::from(body));
                resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"));
                Ok::<_, anyhow::Error>(resp)
            }))
        });
        let server = Server::bind(&addr).serve(make_svc);
        println!("{{\"type\":\"metrics_serve\",\"addr\":\"{}\"}}", addr);
        let graceful = server.with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        graceful.await.map_err(|e| anyhow!("metrics server error: {e}"))
    })
}

fn run_da_run(args: &DaRunArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_da::async_svc as da_async;
        use pc_da::DaConfig;
        let cfg = DaConfig {
            max_chunks: args.max_chunks,
        };
        let (svc, handle) = da_async::spawn(cfg);
        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let res = handle
            .await
            .map_err(|e| anyhow!("da task join error: {e}"))?;
        res.map_err(|e| anyhow!("da loop error: {e}"))
    })
}

fn run_graph_insert_and_ack(args: &GraphInsertAndAckArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    // Datei laden
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let mut slice = &buf[..];
    let headers: Vec<AnchorHeader> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;

    let d_max = args
        .d_max
        .unwrap_or_else(|| FeeSplitParams::recommended().d_max);

    let mut cache = AnchorGraphCache::new();
    for h in headers {
        let _ = cache.insert(h);
    }
    let dists = cache.compute_ack_distances(AnchorId(ack), args.k, d_max);

    // Optional Committee-Payout-Root
    let mut payout_root_hex: Option<String> = None;
    if let (Some(fees), Some(prop_idx)) = (args.fees, args.proposer_index) {
        if !args.recipients.is_empty() {
            let recipients = parse_hex32_list(&args.recipients)?;
            if recipients.len() != args.k as usize {
                bail!(
                    "recipients length ({}) must equal k ({})",
                    recipients.len(),
                    args.k
                );
            }
            if prop_idx >= recipients.len() {
                bail!(
                    "proposer_index {} out of range (k={})",
                    prop_idx,
                    recipients.len()
                );
            }
            let params = FeeSplitParams::recommended();
            let set = compute_committee_payout(fees, &params, &recipients, prop_idx, &dists)
                .map_err(|e| anyhow!("committee payout failed: {e}"))?;
            payout_root_hex = Some(hex::encode(set.payout_root()));
        }
    }

    // JSON-Ausgabe
    print!("{{\"k\":{},\"d_max\":{},\"distances\":[", args.k, d_max);
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        match d {
            Some(v) => print!("{}", v),
            None => print!("null"),
        }
    }
    if let Some(root) = payout_root_hex {
        println!("],\"committee_payout_root\":\"{}\"}}", root);
    } else {
        println!("]}}");
    }
    Ok(())
}

#[derive(Debug, Clone, Args)]
struct GraphInsertAndAckArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
    /// Optional: Gesamt-Gebühren (wenn gesetzt, wird Committee-Payout-Root berechnet)
    #[arg(long)]
    fees: Option<u64>,
    /// Optional: Recipients (32-Byte Hex, komma-separiert) – muss Länge k haben
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Optional: Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: Option<usize>,
}

#[derive(Debug, Clone, Args)]
struct GraphAckArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    k: u8,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    d_max: Option<u8>,
}

#[derive(Debug, Clone, Args)]
struct P2pRunArgs {
    /// Maximale Anzahl Peers
    #[arg(long, default_value_t = 128)]
    max_peers: u16,
    /// Rate-Limits (optional)
    #[command(flatten)]
    rate: RateArgs,
}

#[derive(Debug, Clone, Args)]
struct DaRunArgs {
    /// Maximale Anzahl Chunks im DA-Service
    #[arg(long, default_value_t = 4096)]
    max_chunks: u32,
}

fn load_vec_decodable<T: pc_codec::Decodable>(path: &str) -> Result<Vec<T>> {
    let mut f =
        std::fs::File::open(path).map_err(|e| anyhow!("cannot open file '{}': {e}", path))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read file '{}': {e}", path))?;
    let mut slice = &buf[..];
    let v: Vec<T> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec: {e}"))?;
    Ok(v)
}

fn run_build_payload(args: &BuildPayloadArgs) -> Result<()> {
    // Events ggf. laden
    let mut micro_txs: Vec<MicroTx> = if let Some(p) = &args.microtx_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    // Optional: Mempool lesen und anhängen (deterministisch sortieren, deduplizieren, cap)
    if args.from_mempool {
        let base = args
            .store_dir
            .clone()
            .unwrap_or_else(|| "pc-data".to_string());
        let mp_dir = std::path::Path::new(&base).join("mempool");
        if let Ok(rd) = std::fs::read_dir(&mp_dir) {
            for ent in rd.flatten() {
                if let Ok(meta) = ent.metadata() {
                    if !meta.is_file() {
                        continue;
                    }
                }
                if let Ok(mut f) = std::fs::File::open(ent.path()) {
                    let mut buf = Vec::new();
                    use std::io::Read as _;
                    if f.read_to_end(&mut buf).is_ok() {
                        let mut s = &buf[..];
                        if let Ok(tx) = MicroTx::decode(&mut s) {
                            if validate_microtx_sanity(&tx).is_ok() {
                                micro_txs.push(tx);
                            }
                        }
                    }
                }
            }
        }
        // Dedupe + Sort + Cap
        use std::collections::HashSet;
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut uniq: Vec<MicroTx> = Vec::with_capacity(micro_txs.len());
        for tx in micro_txs.into_iter() {
            let id = digest_microtx(&tx);
            if seen.insert(id) {
                uniq.push(tx);
            }
        }
        uniq.sort_unstable_by(|a, b| digest_microtx(a).cmp(&digest_microtx(b)));
        if uniq.len() > MAX_PAYLOAD_MICROTX {
            uniq.truncate(MAX_PAYLOAD_MICROTX);
        }
        micro_txs = uniq;
    }
    let mints: Vec<MintEvent> = if let Some(p) = &args.mints_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    let claims: Vec<ClaimEvent> = if let Some(p) = &args.claims_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    let evidences: Vec<EvidenceEvent> = if let Some(p) = &args.evidences_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };

    // Payout-Root bestimmen
    let payout_root = if let Some(payout_path) = &args.payout_file {
        let entries: Vec<PayoutEntry> = load_vec_decodable(payout_path)?;
        let set = PayoutSet { entries };
        set.payout_root()
    } else {
        // via Fees/Recipients/Acks/Attestors
        let fees = args
            .fees
            .ok_or_else(|| anyhow!("missing --fees when --payout_file is not provided"))?;
        let proposer_index = args.proposer_index.ok_or_else(|| {
            anyhow!("missing --proposer-index when --payout_file is not provided")
        })?;
        let recipients = parse_hex32_list(&args.recipients)?;
        let acks = parse_acks(&args.acks)?;
        let attestors = parse_hex32_list(&args.attestors)?;
        if recipients.len() != acks.len() {
            bail!(
                "recipients ({}) and acks ({}) length mismatch",
                recipients.len(),
                acks.len()
            );
        }
        if proposer_index >= recipients.len() {
            bail!(
                "proposer_index {} out of range (k={})",
                proposer_index,
                recipients.len()
            );
        }
        let params = FeeSplitParams::recommended();
        compute_total_payout_root(
            fees,
            &params,
            &recipients,
            proposer_index,
            &acks,
            &attestors,
        )?
    };

    let payload = AnchorPayload {
        version: 1,
        micro_txs,
        mints,
        claims,
        evidences,
        payout_root,
    };
    let root = compute_payload_hash(&payload);
    println!("{}", hex::encode(root));
    if let Some(out) = &args.out_file {
        let mut buf = Vec::with_capacity(payload.encoded_len());
        payload
            .encode(&mut buf)
            .map_err(|e| anyhow!("encode payload failed: {e}"))?;
        std::fs::write(out, &buf).map_err(|e| anyhow!("write out_file failed: {e}"))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Args)]
struct BuildPayloadArgs {
    /// Datei mit Vec<MicroTx> (pc-codec)
    #[arg(long)]
    microtx_file: Option<String>,
    /// Optional: auch aus dem Mempool lesen (store_dir/mempool)
    #[arg(long, default_value_t = false)]
    from_mempool: bool,
    /// Basisverzeichnis für Mempool/UTXO/Store
    #[arg(long)]
    store_dir: Option<String>,
    /// Datei mit Vec<MintEvent> (pc-codec)
    #[arg(long)]
    mints_file: Option<String>,
    /// Datei mit Vec<ClaimEvent> (pc-codec)
    #[arg(long)]
    claims_file: Option<String>,
    /// Datei mit Vec<EvidenceEvent> (pc-codec)
    #[arg(long)]
    evidences_file: Option<String>,
    /// Datei mit Vec<PayoutEntry> (pc-codec); alternativ fees/recipients/acks/attestors verwenden
    #[arg(long)]
    payout_file: Option<String>,

    /// Falls keine payout_file: Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: Option<u64>,
    /// Falls keine payout_file: Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Falls keine payout_file: Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: Option<usize>,
    /// Falls keine payout_file: Ack-Distanzen (z. B. "1,2,none,4"; gleiche Länge wie recipients)
    #[arg(long, value_delimiter = ',')]
    acks: Vec<String>,
    /// Falls keine payout_file: Attestors (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    attestors: Vec<String>,

    /// Optional: schreibe AnchorPayload (pc-codec) in Datei
    #[arg(long)]
    out_file: Option<String>,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "phantom-node",
    version,
    about = "PhantomCoin Fullnode/Validator/Miner",
    disable_help_subcommand = true
)]
struct NodeOpts {
    /// Aktiviere Fullnode-Rolle
    #[arg(long, default_value_t = true)]
    fullnode: bool,
    /// Aktiviere Validator-Rolle (benötigt später Seat-Key/HSM)
    #[arg(long, default_value_t = false)]
    validator: bool,
    /// Aktiviere Miner-Worker (PoW nur für Emission)
    #[arg(long, default_value_t = false)]
    miner: bool,
    /// Dienstprogramme
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Berechne die finale Payout-Merkle-Root (Committee + Attestors)
    PayoutRoot(PayoutArgs),
    /// Berechne die Committee-Payout-Root aus Header-Datei und ack_id
    CommitteePayoutFromHeaders(CommitteePayoutHeadersArgs),
    /// Baue einen AnchorPayload aus Event-Dateien oder Parametern
    BuildPayload(BuildPayloadArgs),
    /// Berechne Ack-Distanzen aus einer Header-Datei für eine gegebene ack_id
    GraphAck(GraphAckArgs),
    /// Füge Header in einen In-Memory DAG (AnchorGraphCache) ein und berechne Ack-Distanzen; optional Committee-Payout-Root
    GraphInsertAndAck(GraphInsertAndAckArgs),
    /// Starte den P2P-Service (Tokio-basiert); beendet mit Ctrl-C
    P2pRun(P2pRunArgs),
    /// Starte den DA-Service (Tokio-basiert); beendet mit Ctrl-C
    DaRun(DaRunArgs),
    /// Starte QUIC-Listener, gibt cert_der (Hex) aus und broadcastet P2P-Messages an Clients; beendet mit Ctrl-C
    P2pQuicListen(P2pQuicListenArgs),
    /// Verbinde zu QUIC-Server, forwarde lokale P2P-Outbox an Remote und verarbeite eingehende Nachrichten; beendet mit Ctrl-C
    P2pQuicConnect(P2pQuicConnectArgs),
    /// Injiziere Header-Announce-Messages über QUIC in einen Remote-Knoten
    P2pInjectHeaders(P2pInjectHeadersArgs),
    /// Injiziere Payload-Inventory (und optional Payloads) über QUIC in einen Remote-Knoten
    P2pInjectPayloads(P2pInjectPayloadsArgs),
    /// Gib aktuelle P2P-Metriken als JSON auf stdout aus
    P2pMetrics,
    /// Starte einen HTTP-Server, der Prometheus-kompatible Metriken liefert (Default: 127.0.0.1:9100)
    P2pMetricsServe(MetricsServeArgs),
    /// Konsens: Ack-Distanzen via ConsensusEngine aus Header-Datei berechnen
    ConsensusAckDists(ConsensusAckDistsArgs),
    /// Konsens: Committee-Payout-Root via ConsensusEngine berechnen
    ConsensusPayoutRoot(ConsensusPayoutRootArgs),
    /// Cache-Benchmark: misst Cache-Hits/Misses und Laufzeit gegen FileStore
    CacheBench(CacheBenchArgs),
}

#[derive(Debug, Clone, Args)]
struct MetricsServeArgs {
    /// HTTP Listen-Adresse, z. B. 127.0.0.1:9100
    #[arg(long, default_value = "127.0.0.1:9100")]
    addr: String,
}

#[derive(Debug, Clone, Args)]
struct PayoutArgs {
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: usize,
    /// Ack-Distanzen (z. B. "1,2,none,4"; muss gleiche Länge wie recipients haben)
    #[arg(long, value_delimiter = ',')]
    acks: Vec<String>,
    /// Attestors (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    attestors: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct CommitteePayoutHeadersArgs {
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    proposer_index: usize,
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    headers_file: String,
}

fn compute_payload_hash(payload: &AnchorPayload) -> pc_crypto::Hash32 {
    payload_merkle_root(payload)
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex for 32-byte id: {e}"))?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex32_list(v: &[String]) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::with_capacity(v.len());
    for s in v {
        out.push(parse_hex32(s)?);
    }
    Ok(out)
}

fn parse_acks(v: &[String]) -> Result<Vec<Option<u8>>> {
    let mut out = Vec::with_capacity(v.len());
    for s in v {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("none") || t == "-" {
            out.push(None);
        } else {
            out.push(Some(
                t.parse::<u8>()
                    .map_err(|e| anyhow!("invalid ack distance '{t}': {e}"))?,
            ));
        }
    }
    Ok(out)
}

fn run_payout_root(args: &PayoutArgs) -> Result<()> {
    let recipients = parse_hex32_list(&args.recipients)?;
    let acks = parse_acks(&args.acks)?;
    let attestors = parse_hex32_list(&args.attestors)?;
    if recipients.len() != acks.len() {
        bail!(
            "recipients ({}) and acks ({}) length mismatch",
            recipients.len(),
            acks.len()
        );
    }
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let params = FeeSplitParams::recommended();
    let root = compute_total_payout_root(
        args.fees,
        &params,
        &recipients,
        args.proposer_index,
        &acks,
        &attestors,
    )?;
    println!("{}", hex::encode(root));
    Ok(())
}

fn run_committee_payout_from_headers(args: &CommitteePayoutHeadersArgs) -> Result<()> {
    let recipients = parse_hex32_list(&args.recipients)?;
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let ack = parse_hex32(&args.ack_id)?;
    // Datei laden
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let mut slice = &buf[..];
    let headers: Vec<AnchorHeader> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;
    let params = FeeSplitParams::recommended();
    let set = compute_committee_payout_from_headers(
        args.fees,
        &params,
        &recipients,
        args.proposer_index,
        AnchorId(ack),
        &headers,
        recipients.len() as u8,
    )?;
    println!("{}", hex::encode(set.payout_root()));
    Ok(())
}

fn run_graph_ack(args: &GraphAckArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let mut slice = &buf[..];
    let headers: Vec<AnchorHeader> = pc_codec::Decodable::decode(&mut slice)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;
    let d_max = args
        .d_max
        .unwrap_or_else(|| FeeSplitParams::recommended().d_max);
    let dists = compute_ack_distances_for_seats(AnchorId(ack), &headers, args.k, d_max);
    // JSON Ausgabe minimal, ohne externe Abhängigkeit
    print!("{{\"k\":{},\"d_max\":{},\"distances\":[", args.k, d_max);
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        match d {
            Some(v) => print!("{}", v),
            None => print!("null"),
        }
    }
    println!("]}}");
    Ok(())
}

fn print_p2p_json(msg: &P2pMessage) {
    match msg {
        P2pMessage::HeaderAnnounce(h) => {
            println!(
                "{{\"type\":\"header_announce\",\"creator\":{},\"id\":\"{}\"}}",
                h.creator_index,
                hex::encode(h.id_digest())
            );
        }
        P2pMessage::HeadersInv { ids } => {
            let mut out = String::from("{\"type\":\"headers_inv\",\"ids\":[");
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(id.0));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::PayloadInv { roots } => {
            let mut out = String::from("{\"type\":\"payload_inv\",\"roots\":[");
            for (i, r) in roots.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(r));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::TxInv { ids } => {
            let mut out = String::from("{\"type\":\"tx_inv\",\"ids\":[");
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(id));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::Req(_) => {
            println!("{{\"type\":\"req\"}}");
        }
        P2pMessage::Resp(_) => {
            println!("{{\"type\":\"resp\"}}");
        }
    }
}

fn run_p2p_quic_listen(args: &P2pQuicListenArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::P2pConfig;
        use pc_p2p::async_svc as p2p_async;
        let cfg = P2pConfig { max_peers: 256, rate: rate_cfg_opt(&args.rate) };
        let store = FileStore::open(&args.store_dir, args.fsync)?;
        println!("{{\"type\":\"store_opened\",\"dir\":\"{}\",\"fsync\":{}}}", &args.store_dir, args.fsync);
        // Cache-Kapazitäten: CLI > Config > 0
        let (cfg_hdr_cap, cfg_pl_cap) = if let Some(ref path) = args.config {
            let nc = load_node_config(path)?;
            let h = nc.node.as_ref().and_then(|n| n.cache.as_ref()).and_then(|c| c.header_cap).unwrap_or(0);
            let p = nc.node.as_ref().and_then(|n| n.cache.as_ref()).and_then(|c| c.payload_cap).unwrap_or(0);
            (h, p)
        } else { (0usize, 0usize) };
        let hdr_cap_eff = args.cache_hdr_cap.unwrap_or(cfg_hdr_cap);
        let pl_cap_eff = args.cache_pl_cap.unwrap_or(cfg_pl_cap);
        let delegate = NodeDiskStore::new(store, hdr_cap_eff, pl_cap_eff);
        let (svc, mut out_rx, handle) = p2p_async::spawn_with_store(cfg, Arc::new(delegate));
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let (_endpoint, cert_der, server_task, tx_broadcast) = start_server(addr, svc.clone())
            .await
            .map_err(|e| anyhow!("quic start_server failed: {e}"))?;
        println!(
            "{{\"type\":\"quic_listen\",\"addr\":\"{}\",\"cert_der\":\"{}\"}}",
            addr,
            hex::encode(&cert_der)
        );
        if let Some(path) = &args.cert_out {
            std::fs::write(path, &cert_der).map_err(|e| anyhow!("write cert_out failed: {e}"))?;
            println!("{{\"type\":\"cert_written\",\"path\":\"{}\"}}", path);
        }

        let tx_b = tx_broadcast.clone();
        let forward_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                outbox_deq_inc();
                print_p2p_json(&msg);
                let _ = tx_b.send(msg).await;
            }
            Ok::<(), anyhow::Error>(())
        });

        // pow_bits aus Genesis (falls vorhanden), sonst Default
        let pow_bits_eff: u8 = if let Some(ref gpath) = args.genesis {
            let g = load_genesis(gpath)?;
            let b = g.consensus.pow_bits.unwrap_or(consts::POW_DEFAULT_BITS);
            if (b as u16) > 256 { return Err(anyhow!("invalid pow_bits in genesis: {} (must be 0..=256)", b)); }
            println!("{{\"type\":\"pow_bits\",\"bits\":{}}}", b);
            b
        } else { consts::POW_DEFAULT_BITS };

        // Optional: Dev-PoW-Miner für Mint-Emission (nur im Listen-Server sinnvoll)
        if args.pow_miner {
            let svc_miner = svc.clone();
            let tx_inv = tx_broadcast.clone();
            let amount = args.mint_amount.ok_or_else(|| anyhow!("--pow_miner requires --mint_amount"))?;
            let lock = if let Some(l) = &args.mint_lock { LockCommitment(parse_hex32(l)?) } else { return Err(anyhow!("--pow_miner requires --mint_lock")); };
            let bits = pow_bits_eff;
            tokio::spawn(async move {
                let mut prev_mint_id = [0u8;32];
                let mut seed_ctr: u64 = 0;
                loop {
                    let mut buf = Vec::with_capacity(32 + 8);
                    buf.extend_from_slice(&prev_mint_id);
                    buf.extend_from_slice(&seed_ctr.to_be_bytes());
                    let seed = blake3_32(&buf);
                    seed_ctr = seed_ctr.wrapping_add(1);
                    let mut nonce: u64 = 0;
                    loop {
                        let h = pow_hash(&seed, nonce);
                        if pow_meets(bits, &h) {
                            let txout = TxOut { amount, lock };
                            let mint = MintEvent { version:1, prev_mint_id, outputs: vec![txout], pow_seed: seed, pow_nonce: nonce };
                            let payload = AnchorPayload { version:1, micro_txs: vec![], mints: vec![mint], claims: vec![], evidences: vec![], payout_root: [0u8;32] };
                            let root = payload_merkle_root(&payload);
                            let _ = svc_miner.put_payload(payload).await;
                            let _ = tx_inv.send(P2pMessage::PayloadInv { roots: vec![root] }).await;
                            prev_mint_id = h;
                            break;
                        }
                        nonce = nonce.wrapping_add(1);
                        if (nonce & 0xFFFF) == 0 { tokio::task::yield_now().await; }
                    }
                }
            });
        }

        // k aus Genesis (falls vorhanden) oder Konfig/CLI ableiten; Genesis hat Vorrang
        let k_eff = if let Some(ref gpath) = args.genesis {
            let g = load_genesis(gpath)?;
            let k = g.consensus.k;
            if k == 0 || k > 64 { return Err(anyhow!("invalid k in genesis: {} (must be 1..=64)", k)); }
            println!("{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}", k, g.commitment);
            k
        } else {
            let cfg_k = if let Some(ref path) = args.config { Some(load_node_config(path)?.consensus.and_then(|c| c.k).unwrap_or(args.k)) } else { None };
            let k = cfg_k.unwrap_or(args.k);
            if k == 0 || k > 64 { return Err(anyhow!("invalid k: {} (must be 1..=64)", k)); }
            println!("{{\"type\":\"k_selected\",\"k\":{},\"source\":\"{}\"}}", k, if args.config.is_some() { "config" } else { "cli" });
            k
        };

        

        // Konsens-Task: beobachtet Header, pflegt Graph und markiert finale Payload-Roots
        let mut rx_in = inbound_subscribe();
        let k = k_eff; // in Task bewegen
        let final_roots: Arc<tokio::sync::Mutex<HashSet<[u8;32]>>> = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let finals_for_cons = final_roots.clone();
        // Notify-Kanal für Finalisierungen an den State-Task
        let (tx_final, mut rx_final) = mpsc::unbounded_channel::<[u8;32]>();
        let tx_final_cons = tx_final.clone();
        let consensus_task = tokio::spawn(async move {
            let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(k));
            let finals = finals_for_cons;
            loop {
                match rx_in.recv().await {
                    Ok(P2pMessage::HeaderAnnounce(h)) => {
                        // Finalität prüfen und finalen Payload-Root merken
                        if eng.is_final_mask(h.vote_mask) {
                            let mut g = finals.lock().await;
                            let _ = g.insert(h.payload_hash);
                            let _ = tx_final_cons.send(h.payload_hash);
                        }
                        let _ = eng.insert_header(h);
                    }
                    Ok(P2pMessage::Resp(RespMsg::Headers { headers })) => {
                        for h in headers {
                            if eng.is_final_mask(h.vote_mask) {
                                let mut g = finals.lock().await;
                                let _ = g.insert(h.payload_hash);
                                let _ = tx_final_cons.send(h.payload_hash);
                            }
                            let _ = eng.insert_header(h);
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => { NODE_INBOUND_OBS_LAGGED_TOTAL.fetch_add(n as u64, Ordering::Relaxed); continue; }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => { break; }
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        // State-Task: beobachtet Payload-/Tx-Responses und aktualisiert den UTXO-State deterministisch
        let mut rx_state = inbound_subscribe();
        let finals_for_state = final_roots.clone();
        // mpsc Receiver für Finalisierungen
        let _utxo_path = std::path::Path::new(&args.store_dir).join("utxo").to_string_lossy().to_string();
        let mempool_path = std::path::Path::new(&args.store_dir).join("mempool").to_string_lossy().to_string();
        // Tx-Proposer Parameter aus CLI
        let proposer_enabled = args.tx_proposer;
        let proposer_interval_ms = args.tx_proposer_interval_ms;
        let proposer_cap = args.txs_per_payload.unwrap_or(MAX_PAYLOAD_MICROTX);
        let svc_prop = svc.clone();
        let tx_b_prop = tx_broadcast.clone();
        let fsync_flag = args.fsync;
        let payload_budget = args.payload_budget_bytes;
        let state_task = tokio::spawn(async move {
            #[cfg(feature = "rocksdb")]
            let mut st = {
                let _ = std::fs::create_dir_all(&_utxo_path);
                let backend = pc_state::RocksDbBackend::open(&_utxo_path).expect("open rocksdb utxo");
                UtxoState::new(backend)
            };
            #[cfg(not(feature = "rocksdb"))]
            let mut st = UtxoState::new(InMemoryBackend::new());
            let mut mempool: HashMap<[u8;32], (MicroTx, Instant)> = HashMap::new();
            let mut mempool_order: VecDeque<[u8;32]> = VecDeque::new();
            const MEMPOOL_MAX: usize = 65536;
            const MEMPOOL_TTL_SECS: u64 = 3600; // 1h
            let _ = std::fs::create_dir_all(&mempool_path);
            let journal_path = std::path::Path::new(&mempool_path).join("mempool.journal");
            // Bootstrap: Recovery via Journal (falls vorhanden), sonst Verzeichnis lesen
            let mut active_ids: Option<std::collections::HashSet<[u8;32]>> = None;
            if let Ok(contents) = std::fs::read_to_string(&journal_path) {
                let mut set: std::collections::HashSet<[u8;32]> = std::collections::HashSet::new();
                for line in contents.lines() {
                    if line.len() < 65 { continue; }
                    let (opch, hexid) = line.split_at(1);
                    if let Ok(bytes) = hex::decode(hexid) {
                        if bytes.len() == 32 {
                            let mut id = [0u8;32];
                            id.copy_from_slice(&bytes);
                            match opch.as_bytes()[0] {
                                b'A' => { set.insert(id); }
                                b'D' => { set.remove(&id); }
                                _ => {}
                            }
                        }
                    }
                }
                active_ids = Some(set);
            }
            if let Some(ids) = active_ids {
                // Lade nur IDs aus Journal
                for id in ids.iter() {
                    let fname = format!("{}.bin", hex::encode(id));
                    let p = std::path::Path::new(&mempool_path).join(fname);
                    if let Ok(mut f) = std::fs::File::open(&p) {
                        let mut buf = Vec::new();
                        use std::io::Read as _;
                        if f.read_to_end(&mut buf).is_ok() {
                            let mut s = &buf[..];
                            if let Ok(tx) = MicroTx::decode(&mut s) {
                                if validate_microtx_sanity(&tx).is_ok() && st.can_apply_micro_tx(&tx).is_ok() {
                                    let _ = mempool.insert(*id, (tx, Instant::now()));
                                    mempool_order.push_back(*id);
                                }
                            }
                        }
                    }
                }
                NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
            } else if let Ok(rd) = std::fs::read_dir(&mempool_path) {
                // Fallback: Verzeichnis
                let mut files: Vec<std::path::PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
                files.sort();
                for p in files {
                    if let Ok(mut f) = std::fs::File::open(&p) {
                        let mut buf = Vec::new();
                        use std::io::Read as _;
                        if f.read_to_end(&mut buf).is_ok() {
                            let mut s = &buf[..];
                            if let Ok(tx) = MicroTx::decode(&mut s) {
                                if validate_microtx_sanity(&tx).is_ok() && st.can_apply_micro_tx(&tx).is_ok() {
                                    let id = digest_microtx(&tx);
                                    let _ = mempool.insert(id, (tx, Instant::now()));
                                    mempool_order.push_back(id);
                                }
                            }
                        }
                    }
                }
                NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
            }
            // Pending-Queue Limits
            const PENDING_MAX: usize = 8192; // Obergrenze für gepufferte Payloads
            const PENDING_TTL_SECS: u64 = 600; // 10 Minuten TTL
            let mut pending: HashMap<[u8;32], (AnchorPayload, Instant)> = HashMap::new();
            let mut order: VecDeque<[u8;32]> = VecDeque::new();
            let mut tick = interval(Duration::from_secs(30));
            let mut prop_tick = interval(Duration::from_millis(proposer_interval_ms));
            loop {
                tokio::select! {
                    // Finalisierungsmeldung: versuche pending Payload anzuwenden
                    Some(root) = rx_final.recv() => {
                        if let Some((p, _ts)) = pending.remove(&root) {
                            // aus Order entfernen
                            if let Some(pos) = order.iter().position(|k| *k == root) { let _ = order.remove(pos); }
                            if let Err(e) = validate_payload_sanity(&p) { warn!(root = %hex::encode(root), err = %e, "drop pending payload: invalid"); continue; }
                            // Mint-PoW-Validierung
                            let mut mint_ok = true;
                            for m in &p.mints {
                                if validate_mint_sanity(m).is_err() || !check_mint_pow(m, pow_bits_eff) { mint_ok = false; break; }
                            }
                            if !mint_ok { warn!(root = %hex::encode(root), bits = pow_bits_eff, "drop pending payload: mint pow invalid"); continue; }
                            for m in &p.mints { st.apply_mint(m); }
                            for tx in &p.micro_txs {
                                if let Err(e) = st.apply_micro_tx(tx) { warn!(%e, "utxo apply_micro_tx failed (pending)"); }
                            }
                            // Entferne bestätigte MicroTxs aus dem Mempool (inkl. Dateien) und zähle Invalidationen
                            let mut invalidated: u64 = 0;
                            for tx in &p.micro_txs {
                                let id = digest_microtx(tx);
                                if mempool.remove(&id).is_some() {
                                    invalidated = invalidated.saturating_add(1);
                                    if let Some(pos) = mempool_order.iter().position(|k| *k == id) { let _ = mempool_order.remove(pos); }
                                    let fname = format!("{}.bin", hex::encode(id));
                                    let path = std::path::Path::new(&mempool_path).join(fname);
                                    let _ = journal_append(&journal_path, fsync_flag, b'D', &id);
                                    let _ = remove_with_dir_sync(&path, fsync_flag);
                                }
                            }
                            if invalidated > 0 { NODE_MEMPOOL_INVALIDATED_TOTAL.fetch_add(invalidated, Ordering::Relaxed); }
                            NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
                            NODE_PROPOSER_PENDING.store(pending.len() as u64, Ordering::Relaxed);
                            let r = st.root();
                            info!(root = %hex::encode(root), state_root = %hex::encode(r), "applied pending payload after finalization");
                        }
                    }
                    // Periodischer TTL-Cleanup
                    _ = tick.tick() => {
                        let now = Instant::now();
                        // Entferne abgelaufene Einträge von vorne
                        loop {
                            if let Some(front) = order.front().copied() {
                                if let Some((_, ts)) = pending.get(&front) {
                                    if now.duration_since(*ts) > Duration::from_secs(PENDING_TTL_SECS) {
                                        let _ = order.pop_front();
                                        let _ = pending.remove(&front);
                                        warn!(root = %hex::encode(front), "dropped pending payload due to TTL");
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                        NODE_PROPOSER_PENDING.store(pending.len() as u64, Ordering::Relaxed);
                        // Mempool TTL-Cleanup
                        loop {
                            if let Some(front) = mempool_order.front().copied() {
                                if let Some((_, ts)) = mempool.get(&front) {
                                    if now.duration_since(*ts) > Duration::from_secs(MEMPOOL_TTL_SECS) {
                                        let _ = mempool_order.pop_front();
                                        let _ = mempool.remove(&front);
                                        // Datei löschen
                                        let fname = format!("{}.bin", hex::encode(front));
                                        let path = std::path::Path::new(&mempool_path).join(fname);
                                        let _ = journal_append(&journal_path, fsync_flag, b'D', &front);
                                        let _ = remove_with_dir_sync(&path, fsync_flag);
                                        NODE_MEMPOOL_TTL_EVICT_TOTAL.fetch_add(1, Ordering::Relaxed);
                                        NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                        // Journal-Komprimierung bei zu großer Datei
                        if let Ok(meta) = std::fs::metadata(&journal_path) {
                            if meta.len() > 5_000_000 { // ~5 MB Schwellwert
                                let _ = rewrite_mempool_journal(&journal_path, &mempool_order, fsync_flag);
                            }
                        }
                    }
                    // Periodischer Tx-Proposer
                    _ = prop_tick.tick(), if proposer_enabled => {
                        // Proposer-Policy: bevorzugt kleine Txs, dann älter (Index aus mempool_order), ohne Konflikte/Reservierungen
                        let mut txs: Vec<MicroTx> = Vec::new();
                        let mut used: HashSet<OutPoint> = HashSet::new();
                        // Reservierte TX-IDs aus pending nicht erneut vorschlagen
                        let mut reserved_ids: HashSet<[u8;32]> = HashSet::new();
                        for (pl, _) in pending.values() { for tx in &pl.micro_txs { reserved_ids.insert(digest_microtx(tx)); } }
                        // Kandidaten sammeln mit Größe und Alter (Index) und Group-Key (LockCommitment der ersten Output)
                        let mut cands: Vec<(MicroTx, [u8;32], usize, usize, [u8;32])> = Vec::new();
                        for (idx, id) in mempool_order.iter().enumerate() {
                            if let Some((tx, _ts)) = mempool.get(id) {
                                let tx_id = digest_microtx(tx);
                                if reserved_ids.contains(&tx_id) { continue; }
                                let size = tx.encoded_len();
                                let group_key = tx.outputs.get(0).map(|o| o.lock.0).unwrap_or([0u8;32]);
                                cands.push((tx.clone(), *id, size, idx, group_key));
                            }
                        }
                        // Sortiere Kandidaten nach Größe, dann Alter
                        cands.sort_by(|a, b| a.2.cmp(&b.2).then(a.3.cmp(&b.3)));
                        // Round-Robin über Gruppen: deterministische Gruppenreihenfolge
                        use std::collections::BTreeMap;
                        let mut groups: BTreeMap<[u8;32], Vec<(MicroTx, usize)>> = BTreeMap::new();
                        for (tx, _id, size, _idx, gk) in cands.into_iter() {
                            groups.entry(gk).or_default().push((tx, size));
                        }
                        // Budget-Logik
                        let mut budget_used: usize = 0;
                        'outer: loop {
                            let mut progressed = false;
                            for (_gk, vecq) in groups.iter_mut() {
                                // Nimm nächste Tx der Gruppe, die konfliktfrei ist und ins Budget passt
                                while let Some((tx, sz)) = vecq.first().cloned() {
                                    let mut conflict = false;
                                    for tin in &tx.inputs { if used.contains(&tin.prev_out) { conflict = true; break; } }
                                    if conflict { let _ = vecq.remove(0); continue; }
                                    if let Some(b) = payload_budget { if budget_used + sz > b { break; } }
                                    // accept
                                    for tin in &tx.inputs { let _ = used.insert(tin.prev_out); }
                                    txs.push(tx);
                                    budget_used += sz;
                                    let _ = vecq.remove(0);
                                    progressed = true;
                                    if txs.len() >= proposer_cap { break 'outer; }
                                    break;
                                }
                            }
                            if !progressed { break; }
                        }
                        if !txs.is_empty() {
                            // deterministische Ordnung: nach digest_microtx sortieren
                            txs.sort_unstable_by(|a, b| digest_microtx(a).cmp(&digest_microtx(b)));
                            let txs_len = txs.len();
                            let payload = AnchorPayload { version:1, micro_txs: txs, mints: vec![], claims: vec![], evidences: vec![], payout_root: [0u8;32] };
                            let root = payload_merkle_root(&payload);
                            let payload_clone = payload.clone();
                            match svc_prop.put_payload(payload).await {
                                Ok(()) => {
                                    NODE_PROPOSER_BUILT_TOTAL.fetch_add(1, Ordering::Relaxed);
                                    NODE_PROPOSER_LAST_SIZE.store(txs_len as u64, Ordering::Relaxed);
                                    // Für spätere State-Anwendung zwischenspeichern (Pending), falls nicht vorhanden
                                    if !pending.contains_key(&root) {
                                        pending.insert(root, (payload_clone, Instant::now()));
                                        order.push_back(root);
                                    }
                                }
                                Err(_e) => {
                                    NODE_PROPOSER_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if tx_b_prop.send(P2pMessage::PayloadInv { roots: vec![root] }).await.is_err() {
                                NODE_PROPOSER_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                            }
                            info!(proposer = true, root = %hex::encode(root), "proposed payload from mempool");
                        }
                    }
                    res = rx_state.recv() => {
                        match res {
                            Ok(P2pMessage::Resp(RespMsg::Payloads { payloads })) => {
                                for p in payloads.into_iter() {
                                    let root = payload_merkle_root(&p);
                                    let apply = { let g = finals_for_state.lock().await; g.contains(&root) };
                                    if apply {
                                        if let Err(e) = validate_payload_sanity(&p) { warn!(root = %hex::encode(root), err = %e, "drop payload: invalid"); continue; }
                                        // Mint-PoW-Validierung
                                        let mut mint_ok = true;
                                        for m in &p.mints {
                                            if validate_mint_sanity(m).is_err() || !check_mint_pow(m, pow_bits_eff) { mint_ok = false; break; }
                                        }
                                        if !mint_ok { warn!(root = %hex::encode(root), bits = pow_bits_eff, "drop payload: mint pow invalid"); continue; }
                                        for m in &p.mints { st.apply_mint(m); }
                                        for tx in &p.micro_txs {
                                            if let Err(e) = st.apply_micro_tx(tx) { warn!(%e, "utxo apply_micro_tx failed"); }
                                        }
                                        let r = st.root();
                                        info!(root = %hex::encode(root), state_root = %hex::encode(r), "applied payload (final)");
                                    } else {
                                        // Nur einmal penden (Duplikate ignorieren)
                                        if !pending.contains_key(&root) {
                                            // Evict bei Überlauf
                                            if pending.len() >= PENDING_MAX {
                                                if let Some(old_key) = order.pop_front() {
                                                    let _ = pending.remove(&old_key);
                                                    warn!(root = %hex::encode(old_key), "evicted oldest pending payload due to cap");
                                                }
                                            }
                                            // Nur valide Payloads penden
                                            if let Err(e) = validate_payload_sanity(&p) {
                                                warn!(root = %hex::encode(root), err = %e, "drop payload: invalid (not queued)");
                                            } else {
                                                // Mint-PoW-Validierung vor dem Queuen
                                                let mut mint_ok = true;
                                                for m in &p.mints {
                                                    if validate_mint_sanity(m).is_err() || !check_mint_pow(m, pow_bits_eff) { mint_ok = false; break; }
                                                }
                                                if !mint_ok {
                                                    warn!(root = %hex::encode(root), bits = pow_bits_eff, "drop payload: mint pow invalid (not queued)");
                                                    continue;
                                                }
                                                pending.insert(root, (p, Instant::now()));
                                                order.push_back(root);
                                                warn!(root = %hex::encode(root), "queued payload: header not final yet");
                                            }
                                        } else {
                                            warn!(root = %hex::encode(root), "duplicate payload ignored (pending exists)");
                                        }
                                    }
                                }
                            }
                            Ok(P2pMessage::Resp(RespMsg::Txs { txs })) => {
                                for tx in txs.into_iter() {
                                    match validate_microtx_sanity(&tx) {
                                        Ok(()) => {
                                            let id = digest_microtx(&tx);
                                            if mempool.contains_key(&id) {
                                                NODE_MEMPOOL_DUPLICATE_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                            // Stateful-Check gegen aktuellen UTXO-State
                                            if let Err(_e) = st.can_apply_micro_tx(&tx) {
                                                NODE_MEMPOOL_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                            // Cap-Eviction: älteste entfernen, falls voll
                                            if mempool.len() >= MEMPOOL_MAX {
                                                if let Some(old_id) = mempool_order.pop_front() {
                                                    let _ = mempool.remove(&old_id);
                                                    let old_fname = format!("{}.bin", hex::encode(old_id));
                                                    let old_path = std::path::Path::new(&mempool_path).join(old_fname);
                                                    let _ = journal_append(&journal_path, fsync_flag, b'D', &old_id);
                                                    let _ = remove_with_dir_sync(&old_path, fsync_flag);
                                                    NODE_MEMPOOL_CAP_EVICT_TOTAL.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            let _ = mempool.insert(id, (tx.clone(), Instant::now()));
                                            mempool_order.push_back(id);
                                            // Persistiere in store_dir/mempool/<hexid>.bin
                                            let fname = format!("{}.bin", hex::encode(id));
                                            let path = std::path::Path::new(&mempool_path).join(fname);
                                            let mut buf = Vec::with_capacity(tx.encoded_len());
                                            if tx.encode(&mut buf).is_ok() {
                                                if atomic_write(&path, &buf, fsync_flag).is_ok() {
                                                    let _ = journal_append(&journal_path, fsync_flag, b'A', &id);
                                                }
                                            }
                                            NODE_MEMPOOL_ACCEPTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            NODE_MEMPOOL_SIZE.store(mempool.len() as u64, Ordering::Relaxed);
                                        }
                                        Err(e) => {
                                            warn!(err = %e, "drop microtx: invalid");
                                            NODE_MEMPOOL_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => { NODE_INBOUND_OBS_LAGGED_TOTAL.fetch_add(n as u64, Ordering::Relaxed); }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => { break; }
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = forward_task.await;
        let _ = server_task.await;
        let _ = consensus_task.await;
        let _ = state_task.await;
        let res = handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))
    })
}

fn run_p2p_quic_connect(args: &P2pQuicConnectArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::async_svc as p2p_async;
        use pc_p2p::P2pConfig;
        let cfg = P2pConfig {
            max_peers: 256,
            rate: None,
        };
        let (svc, mut out_rx, handle) = p2p_async::spawn(cfg);
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let _reader = spawn_client_reader(conn.clone(), svc.clone());
        let sink = QuicClientSink::new(conn);

        let forward_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                outbox_deq_inc();
                print_p2p_json(&msg);
                let _ = sink.deliver(msg).await;
            }
            Ok::<(), anyhow::Error>(())
        });

        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = forward_task.await;
        let res = handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))
    })
}

fn run_p2p_inject_headers(args: &P2pInjectHeadersArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let sink = QuicClientSink::new(conn);
        let headers: Vec<AnchorHeader> = load_vec_decodable(&args.headers_file)?;
        let mut sent = 0usize;
        for h in headers.into_iter() {
            sink.deliver(P2pMessage::HeaderAnnounce(h))
                .await
                .map_err(|e| anyhow!("deliver header_announce failed: {e}"))?;
            sent += 1;
        }
        println!(
            "{{\"type\":\"inject\",\"kind\":\"headers\",\"count\":{}}}",
            sent
        );
        Ok(())
    })
}

fn run_p2p_inject_payloads(args: &P2pInjectPayloadsArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = args
            .addr
            .parse()
            .map_err(|e| anyhow!("invalid addr '{}': {e}", &args.addr))?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let sink = QuicClientSink::new(conn);
        let payloads: Vec<AnchorPayload> = load_vec_decodable(&args.payloads_file)?;
        let mut roots = Vec::with_capacity(payloads.len());
        for p in &payloads {
            roots.push(payload_merkle_root(p));
        }
        sink.deliver(P2pMessage::PayloadInv {
            roots: roots.clone(),
        })
        .await
        .map_err(|e| anyhow!("deliver payload_inv failed: {e}"))?;
        if args.with_payloads {
            sink.deliver(P2pMessage::Resp(RespMsg::Payloads { payloads }))
                .await
                .map_err(|e| anyhow!("deliver payloads failed: {e}"))?;
        }
        println!(
            "{{\"type\":\"inject\",\"kind\":\"payloads\",\"roots\":{}}}",
            roots.len()
        );
        Ok(())
    })
}

fn self_check() -> Result<()> {
    // Build a minimal header and compute its id
    let mut parents = ParentList::default();
    parents.push(AnchorId([0u8; 32]))?;
    let header = AnchorHeader {
        version: 1,
        shard_id: 0,
        parents,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
    };
    let id = header.id_digest();
    info!(hash = %hex::encode(id), "anchor header digest computed");

    // Payload-Hash (leer) deterministisch berechnen
    let empty_payout = PayoutSet { entries: vec![] };
    let payload = AnchorPayload {
        version: 1,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: empty_payout.payout_root(),
    };
    let ph = compute_payload_hash(&payload);
    info!(payload_root = %hex::encode(ph), "payload merkle root computed");

    // Consensus threshold check for k=21
    let k = 21u8;
    let t = finality_threshold(k);
    let mask = set_bit(0, 0)?;
    let pc = popcount_u64(mask);
    warn!(
        k,
        threshold = t,
        popcount = pc,
        "consensus threshold sample"
    );
    let f = is_final(pc, k);
    info!(finalized = f, "finality check (expected false)");
    Ok(())
}

fn main() -> Result<()> {
    init_tracing();
    let opts = NodeOpts::parse();
    info!(?opts, "starting phantom-node roles");
    if let Some(cmd) = &opts.command {
        match cmd {
            Command::PayoutRoot(args) => {
                run_payout_root(args)?;
                return Ok(());
            }
            Command::CommitteePayoutFromHeaders(args) => {
                run_committee_payout_from_headers(args)?;
                return Ok(());
            }
            Command::BuildPayload(args) => {
                run_build_payload(args)?;
                return Ok(());
            }
            Command::GraphAck(args) => {
                run_graph_ack(args)?;
                return Ok(());
            }
            Command::GraphInsertAndAck(args) => {
                run_graph_insert_and_ack(args)?;
                return Ok(());
            }
            Command::P2pRun(args) => {
                run_p2p_run(args)?;
                return Ok(());
            }
            Command::DaRun(args) => {
                run_da_run(args)?;
                return Ok(());
            }
            Command::P2pQuicListen(args) => {
                run_p2p_quic_listen(args)?;
                return Ok(());
            }
            Command::P2pQuicConnect(args) => {
                run_p2p_quic_connect(args)?;
                return Ok(());
            }
            Command::P2pInjectHeaders(args) => {
                run_p2p_inject_headers(args)?;
                return Ok(());
            }
            Command::P2pInjectPayloads(args) => {
                run_p2p_inject_payloads(args)?;
                return Ok(());
            }
            Command::P2pMetrics => {
                run_p2p_metrics()?;
                return Ok(());
            }
            Command::P2pMetricsServe(args) => {
                run_p2p_metrics_serve(args)?;
                return Ok(());
            }
            Command::ConsensusAckDists(args) => {
                run_consensus_ack_dists(args)?;
                return Ok(());
            }
            Command::ConsensusPayoutRoot(args) => {
                run_consensus_payout_root(args)?;
                return Ok(());
            }
            Command::CacheBench(args) => {
                run_cache_bench(args)?;
                return Ok(());
            }
        }
    }
    self_check()?;
    Ok(())
}
