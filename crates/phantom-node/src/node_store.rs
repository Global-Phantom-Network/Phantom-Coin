use super::*;

// Sharded-LRU zur Reduktion von Mutex-Contention
pub(crate) struct ShardedLru<K, V> {
    shards: Vec<Mutex<LruCache<K, V>>>,
}

impl<K: Hash + Eq + Clone, V: Clone> ShardedLru<K, V> {
    pub(crate) fn new(n_shards: usize, total_cap: usize) -> Self {
        let n = std::cmp::max(1, n_shards);
        let per = std::cmp::max(1, total_cap / n);
        let mut shards = Vec::with_capacity(n);
        let cap = NonZeroUsize::new(per).unwrap_or(NonZeroUsize::MIN);
        for _ in 0..n {
            shards.push(Mutex::new(LruCache::new(cap)));
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
        if let Some(m) = self.shards.get(idx) {
            let mut g = m.lock().await;
            g.get(key).cloned()
        } else {
            None
        }
    }
    async fn put(&self, key: K, val: V) {
        let idx = self.index(&key);
        if let Some(m) = self.shards.get(idx) {
            let mut g = m.lock().await;
            g.put(key, val);
        }
    }
    async fn touch_present(&self, key: &K) -> bool {
        let idx = self.index(key);
        if let Some(m) = self.shards.get(idx) {
            let mut g = m.lock().await;
            g.get(key).is_some()
        } else {
            false
        }
    }
}

pub(crate) struct WeightedLruShard<K, V> {
    entries: LruCache<K, (V, usize)>,
    total_bytes: usize,
    max_bytes: usize,
}

pub(crate) struct WeightedShardedLru<K, V> {
    shards: Vec<Mutex<WeightedLruShard<K, V>>>,
}

impl<K: Hash + Eq + Clone, V: Clone> WeightedShardedLru<K, V> {
    pub(crate) fn new(n_shards: usize, max_total_bytes: usize) -> Self {
        let n = std::cmp::max(1, n_shards);
        let per = std::cmp::max(1, max_total_bytes / n);
        let mut shards = Vec::with_capacity(n);
        for _ in 0..n {
            shards.push(Mutex::new(WeightedLruShard {
                entries: LruCache::unbounded(),
                total_bytes: 0,
                max_bytes: per,
            }));
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
        if let Some(m) = self.shards.get(idx) {
            let mut g = m.lock().await;
            g.entries.get(key).map(|(v, _)| v.clone())
        } else {
            None
        }
    }
    async fn put(&self, key: K, val: V, weight: usize) {
        let idx = self.index(&key);
        if let Some(m) = self.shards.get(idx) {
            let mut g = m.lock().await;
            if let Some((_, old_weight)) = g.entries.pop(&key) {
                g.total_bytes = g.total_bytes.saturating_sub(old_weight);
            }
            while g.total_bytes + weight > g.max_bytes {
                if let Some((_, (_, evicted_weight))) = g.entries.pop_lru() {
                    g.total_bytes = g.total_bytes.saturating_sub(evicted_weight);
                } else {
                    break;
                }
            }
            g.entries.put(key, (val, weight));
            g.total_bytes += weight;
        }
    }
    async fn touch_present(&self, key: &K) -> bool {
        let idx = self.index(key);
        if let Some(m) = self.shards.get(idx) {
            let mut g = m.lock().await;
            g.entries.get(key).is_some()
        } else {
            false
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct HeaderAdmissionState {
    consensus_network_id: Option<[u8; 32]>,
    committee_cache: Option<CommitteeCache>,
    // Throttle expensive committee recomputations to make epoch/seed_anchor thrashing harder.
    committee_recompute_last: Option<Instant>,
}

#[derive(Debug)]
pub(crate) struct HeaderAdmission {
    k: u8,
    mempool_dir: String,
    role_policy: Option<Arc<RolePolicy>>,
    state: tokio::sync::Mutex<HeaderAdmissionState>,
}

// StoreDelegate-Wrapper: persistiert Header/Payloads auf Disk via FileStore, mit optionalem LRU-Cache (sharded)
#[derive(Clone)]
pub(crate) struct NodeDiskStore {
    inner: Arc<FileStore>,
    hdr_cache: Option<Arc<ShardedLru<AnchorId, pc_types::AnchorHeaderV2>>>,
    pl_cache: Option<Arc<WeightedShardedLru<[u8; 32], pc_types::AnchorPayloadV3>>>,
    tx_cache: Option<Arc<ShardedLru<[u8; 32], MicroTx>>>,
    evid_cache: Option<Arc<ShardedLru<[u8; 32], EvidenceEvent>>>,
    evidences_dir: Arc<std::path::PathBuf>,
    evidence_journal_path: Arc<std::path::PathBuf>,
    genesis_features: u64,
    header_admission: Option<Arc<HeaderAdmission>>,
    empty_payload_roots: Arc<ShardedLru<[u8; 32], ()>>,
    fsync: bool,
}

impl NodeDiskStore {
    pub(crate) fn new(
        store: FileStore,
        store_dir: &str,
        fsync: bool,
        hdr_cap: usize,
        pl_mb: usize,
        admission_k: Option<u8>,
        role_policy: Option<Arc<RolePolicy>>,
    ) -> Self {
        let shards = std::cmp::max(1, num_cpus::get());
        let hdr_cache = if hdr_cap > 0 {
            Some(Arc::new(ShardedLru::new(shards, hdr_cap)))
        } else {
            None
        };
        let pl_cache = if pl_mb > 0 {
            let pl_max_bytes = pl_mb * 1024 * 1024;
            Some(Arc::new(WeightedShardedLru::new(shards, pl_max_bytes)))
        } else {
            None
        };
        // TX cache is intentionally capped to avoid unbounded memory growth from remote floods.
        // It is only an optimization; peers can always re-request missing txs.
        const TX_CACHE_CAP: usize = 8192;
        let tx_cache = Some(Arc::new(ShardedLru::new(shards, TX_CACHE_CAP)));
        // Evidence cache is intentionally capped to avoid unbounded memory growth from remote INV floods.
        // It is only an optimization; disk is the source of truth.
        const EVID_CACHE_CAP: usize = 2048;
        let evid_cache = Some(Arc::new(ShardedLru::new(shards, EVID_CACHE_CAP)));
        let mempool_dir = std::path::Path::new(store_dir).join("mempool");
        let mempool_dir_str = mempool_dir.to_string_lossy().to_string();
        let genesis_features = load_genesis_features_from_mempool(&mempool_dir_str).unwrap_or(0);
        let header_admission = admission_k.map(|k| {
            Arc::new(HeaderAdmission {
                k,
                mempool_dir: mempool_dir_str.clone(),
                role_policy,
                state: tokio::sync::Mutex::new(HeaderAdmissionState::default()),
            })
        });
        let evidences_dir = mempool_dir.join("evidences");
        let _ = std::fs::create_dir_all(&evidences_dir);
        let evidence_journal_path = mempool_dir.join("evidences.journal");
        const EMPTY_PL_ROOTS_CAP: usize = 8192;
        let empty_payload_roots = Arc::new(ShardedLru::new(shards, EMPTY_PL_ROOTS_CAP));
        Self {
            inner: Arc::new(store),
            hdr_cache,
            pl_cache,
            tx_cache,
            evid_cache,
            evidences_dir: Arc::new(evidences_dir),
            evidence_journal_path: Arc::new(evidence_journal_path),
            genesis_features,
            header_admission,
            empty_payload_roots,
            fsync,
        }
    }
}

#[async_trait]
impl pc_p2p::async_svc::StoreDelegate for NodeDiskStore {
    async fn admit_header(&self, h: &pc_types::AnchorHeaderV2) -> bool {
        let adm = match self.header_admission.as_ref() {
            Some(a) => a,
            None => return true,
        };

        // Basic prefilter: empty signer sets are never final.
        if h.vote_mask == 0 {
            return false;
        }

        let mut st = adm.state.lock().await;
        let HeaderAdmissionState {
            consensus_network_id,
            committee_cache,
            committee_recompute_last,
        } = &mut *st;
        if h.state_root.is_some() {
            verify_header_finality(
                h,
                adm.k,
                consensus_network_id,
                &adm.mempool_dir,
                committee_cache,
                committee_recompute_last,
                adm.role_policy.as_deref(),
            )
            .await
        } else {
            verify_header_prevote(
                h,
                adm.k,
                consensus_network_id,
                &adm.mempool_dir,
                committee_cache,
                committee_recompute_last,
                adm.role_policy.as_deref(),
            )
            .await
        }
    }

    async fn insert_header(&self, h: pc_types::AnchorHeaderV2) {
        let is_empty_payload = self
            .empty_payload_roots
            .touch_present(&h.payload_hash)
            .await;
        if is_empty_payload {
            if let Some(c) = &self.hdr_cache {
                let id = AnchorId(h.id_digest());
                c.put(id, h).await;
            }
            NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let store = self.inner.clone();
        let h_clone_for_cache = h.clone();
        match tokio::task::spawn_blocking(move || {
            let t0 = std::time::Instant::now();
            let res = store.put_header_v2(&h);
            let dt = t0.elapsed();
            (res, dt)
        })
        .await
        {
            Ok((Ok(_), dt)) => {
                observe_persist(dt);
                NODE_PERSIST_HEADERS_TOTAL.fetch_add(1, Ordering::Relaxed);
                if let Some(c) = &self.hdr_cache {
                    let id = AnchorId(h_clone_for_cache.id_digest());
                    c.put(id, h_clone_for_cache).await;
                }
            }
            Ok((Err(_e), dt)) => {
                observe_persist(dt);
                NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!("store.put_header failed");
            }
            Err(_e) => {
                NODE_PERSIST_HEADERS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!("store.put_header failed");
            }
        }
    }
    async fn insert_payload(&self, p: pc_types::AnchorPayloadV3) {
        let store = self.inner.clone();
        let p_clone_for_cache = p.clone();
        match tokio::task::spawn_blocking(move || {
            let t0 = std::time::Instant::now();
            let res = store.put_payload_v3(&p);
            let dt = t0.elapsed();
            (res, dt)
        })
        .await
        {
            Ok((Ok(_), dt)) => {
                observe_persist(dt);
                NODE_PERSIST_PAYLOADS_TOTAL.fetch_add(1, Ordering::Relaxed);
                if let Some(c) = &self.pl_cache {
                    let root = pc_types::payload_merkle_root_v3(&p_clone_for_cache);
                    let weight = p_clone_for_cache.encoded_len();
                    c.put(root, p_clone_for_cache, weight).await;
                }
            }
            Ok((Err(_e), dt)) => {
                observe_persist(dt);
                NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!("store.put_payload failed");
            }
            Err(_e) => {
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
        (tokio::task::spawn_blocking(move || store.has_payload_v3(&r)).await).unwrap_or(false)
    }
    async fn get_headers(
        &self,
        ids: &[AnchorId],
    ) -> (Vec<pc_types::AnchorHeaderV2>, Vec<[u8; 32]>) {
        let mut found: Vec<pc_types::AnchorHeaderV2> = Vec::new();
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
        let fetched: Vec<pc_types::AnchorHeaderV2> = tokio::task::spawn_blocking(move || {
            let mut v = Vec::new();
            for id in to_fetch.iter() {
                let t0 = std::time::Instant::now();
                let res = store.get_header_v2(&id.0);
                let dt = t0.elapsed();
                observe_hdr_read(dt);
                if let Ok(Some(h)) = res {
                    v.push(h)
                }
            }
            v
        })
        .await
        .unwrap_or_default();

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
        all_found.extend(fetched);
        (all_found, missing)
    }
    async fn get_payloads(
        &self,
        roots: &[[u8; 32]],
    ) -> (Vec<pc_types::AnchorPayloadV3>, Vec<[u8; 32]>) {
        let mut found: Vec<pc_types::AnchorPayloadV3> = Vec::new();
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
        let fetched: Vec<(pc_types::AnchorPayloadV3, [u8; 32])> =
            tokio::task::spawn_blocking(move || {
                let mut v = Vec::new();
                for r in to_fetch.iter() {
                    let t0 = std::time::Instant::now();
                    let res = store.get_payload_v3(r);
                    let dt = t0.elapsed();
                    observe_pl_read(dt);
                    if let Ok(Some(p)) = res {
                        v.push((p, *r))
                    }
                }
                v
            })
            .await
            .unwrap_or_default();

        // Cache auffüllen
        if let Some(c) = &self.pl_cache {
            for (p, r) in &fetched {
                let weight = p.encoded_len();
                c.put(*r, p.clone(), weight).await;
            }
        }
        // Missing ermitteln
        let mut missing: Vec<[u8; 32]> = Vec::new();
        let mut seen_roots: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for p in &found {
            seen_roots.insert(pc_types::payload_merkle_root_v3(p));
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
        // Sanity-filter: never cache obviously invalid txs from the network.
        if pc_types::validate_microtx_sanity(&tx).is_err() {
            return;
        }
        let id = digest_microtx(&tx);
        if let Some(c) = &self.tx_cache {
            c.put(id, tx).await;
        }
    }
    async fn has_tx(&self, id: &[u8; 32]) -> bool {
        let key = *id;
        if let Some(c) = &self.tx_cache {
            return c.touch_present(&key).await;
        }
        false
    }
    async fn get_txs(&self, ids: &[[u8; 32]]) -> (Vec<MicroTx>, Vec<[u8; 32]>) {
        let mut found = Vec::new();
        let mut missing = Vec::new();
        if let Some(c) = &self.tx_cache {
            for id in ids {
                if let Some(tx) = c.get_clone(id).await {
                    found.push(tx);
                } else {
                    missing.push(*id);
                }
            }
            (found, missing)
        } else {
            (found, ids.to_vec())
        }
    }

    async fn insert_evidence(&self, evid: EvidenceEvent) {
        if pc_types::validate_evidence_sanity(&evid).is_err() {
            return;
        }
        if mint_window_evidence_ingest_allowed_live(&evid, self.genesis_features).is_err() {
            return;
        }
        let id = pc_types::digest_evidence(&evid);
        if let Some(c) = &self.evid_cache {
            if c.touch_present(&id).await {
                return;
            }
            c.put(id, evid.clone()).await;
        }

        let dir = self.evidences_dir.clone();
        let journal = self.evidence_journal_path.clone();
        let fsync = self.fsync;
        let _ = tokio::task::spawn_blocking(move || {
            let _ = std::fs::create_dir_all(&*dir);
            let fname = format!("{}.bin", hex::encode(id));
            let path = dir.join(fname);
            let mut buf = Vec::with_capacity(evid.encoded_len());
            if evid.encode(&mut buf).is_ok() {
                let _ = atomic_write(&path, &buf, fsync);
                let _ = journal_append(&journal, fsync, b'A', &id);
            }
        })
        .await;
    }

    async fn has_evidence(&self, id: &[u8; 32]) -> bool {
        let key = *id;
        if let Some(c) = &self.evid_cache {
            if c.touch_present(&key).await {
                return true;
            }
        }
        let dir = self.evidences_dir.clone();
        tokio::task::spawn_blocking(move || {
            let fname = format!("{}.bin", hex::encode(key));
            dir.join(fname).exists()
        })
        .await
        .unwrap_or(false)
    }

    async fn get_evidences(&self, ids: &[[u8; 32]]) -> (Vec<EvidenceEvent>, Vec<[u8; 32]>) {
        let mut found: Vec<EvidenceEvent> = Vec::new();
        let mut to_fetch: Vec<[u8; 32]> = Vec::new();
        if let Some(c) = &self.evid_cache {
            for id in ids {
                if let Some(ev) = c.get_clone(id).await {
                    if mint_window_evidence_ingest_allowed_live(&ev, self.genesis_features).is_ok()
                    {
                        found.push(ev);
                    } else {
                        to_fetch.push(*id);
                    }
                } else {
                    to_fetch.push(*id);
                }
            }
        } else {
            to_fetch.extend_from_slice(ids);
        }

        if to_fetch.is_empty() {
            return (found, Vec::new());
        }

        let dir = self.evidences_dir.clone();
        let genesis_features = self.genesis_features;
        let (fetched, missing): (Vec<EvidenceEvent>, Vec<[u8; 32]>) =
            tokio::task::spawn_blocking(move || {
                const MAX_EVIDENCE_FILE_BYTES: usize = 32 * 1024;
                let mut out: Vec<EvidenceEvent> = Vec::new();
                let mut miss: Vec<[u8; 32]> = Vec::new();
                for id in to_fetch.iter().copied() {
                    let fname = format!("{}.bin", hex::encode(id));
                    let path = dir.join(fname);
                    let meta = match std::fs::metadata(&path) {
                        Ok(m) => m,
                        Err(_) => {
                            miss.push(id);
                            continue;
                        }
                    };
                    if meta.len() as usize > MAX_EVIDENCE_FILE_BYTES {
                        miss.push(id);
                        continue;
                    }
                    let buf = match std::fs::read(&path) {
                        Ok(b) => b,
                        Err(_) => {
                            miss.push(id);
                            continue;
                        }
                    };
                    let ev = match pc_codec::decode_exact::<EvidenceEvent>(&buf) {
                        Ok(e) => e,
                        Err(_) => {
                            miss.push(id);
                            continue;
                        }
                    };
                    if pc_types::digest_evidence(&ev) != id {
                        miss.push(id);
                        continue;
                    }
                    if pc_types::validate_evidence_sanity(&ev).is_err() {
                        miss.push(id);
                        continue;
                    }
                    if mint_window_evidence_ingest_allowed_live(&ev, genesis_features).is_err() {
                        miss.push(id);
                        continue;
                    }
                    out.push(ev);
                }
                (out, miss)
            })
            .await
            .unwrap_or_default();

        if let Some(c) = &self.evid_cache {
            for ev in fetched.iter() {
                let id = pc_types::digest_evidence(ev);
                c.put(id, ev.clone()).await;
            }
        }

        found.extend(fetched);

        // Maintain stable missing ordering according to input order.
        let mut missing_out: Vec<[u8; 32]> = Vec::new();
        let got: std::collections::HashSet<[u8; 32]> =
            found.iter().map(pc_types::digest_evidence).collect();
        let missing_set: std::collections::HashSet<[u8; 32]> = missing.into_iter().collect();
        for id in ids {
            if !got.contains(id) && missing_set.contains(id) {
                missing_out.push(*id);
            }
        }
        (found, missing_out)
    }
}
