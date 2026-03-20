use super::*;

use pc_p2p::async_svc::{spawn_with_store, watch_header, watch_payload, OutboundEnvelope};
use pc_p2p::messages::{P2pMessage, ReqMsg, RespMsg};
use pc_p2p::P2pConfig;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("pc_journal_test_{}_{}", prefix, nanos))
}

fn write_bootstrap_genesis_for_finality_test(
    mempool_dir: &std::path::Path,
    kp: &pc_crypto::BlsKeypair,
) -> Result<GenesisNote> {
    let note = GenesisNote {
        version: 1,
        network_name: b"pc-finality-test".to_vec(),
        seed: [0x22; 32],
        params: pc_types::GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: pc_types::GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![pc_types::GenesisValidatorV1 {
            operator_id: [0x77; 32],
            bls_pk: kp.pk.to_bytes(),
            bls_pop: pc_crypto::bls_pop_prove(&kp.sk),
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::create_dir_all(mempool_dir)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;
    let seed_anchor = pc_types::genesis_payload_root(&note);
    let store_dir = mempool_dir
        .parent()
        .ok_or_else(|| anyhow!("mempool_dir must have parent"))?;
    std::fs::write(
        store_dir.join("last_final_payload_root"),
        hex::encode(seed_anchor),
    )?;
    Ok(note)
}

fn signed_finality_header(
    network_id: [u8; 32],
    state_root: [u8; 32],
    bls_sk: &pc_crypto::BlsSecretKey,
) -> AnchorHeaderV2 {
    signed_finality_header_for_payload(network_id, [0x44; 32], state_root, bls_sk)
}

fn signed_prevote_header(network_id: [u8; 32], bls_sk: &pc_crypto::BlsSecretKey) -> AnchorHeaderV2 {
    signed_prevote_header_for_payload(network_id, [0x44; 32], bls_sk)
}

fn signed_prevote_header_for_payload(
    network_id: [u8; 32],
    payload_hash: [u8; 32],
    bls_sk: &pc_crypto::BlsSecretKey,
) -> AnchorHeaderV2 {
    let mut hdr = AnchorHeaderV2 {
        version: 5,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash,
        creator_index: 0,
        vote_mask: 1,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id,
        vote_epoch: 1,
        vote_round: 0,
        attest_sig: None,
        state_root: None,
    };
    let msg = pc_consensus::attestation::committee_vote_message(
        &network_id,
        hdr.vote_epoch,
        &hdr.vote_target_hash(),
    );
    hdr.attest_sig = Some(pc_crypto::bls_sign(&msg, bls_sk));
    hdr
}

fn signed_finality_header_for_payload(
    network_id: [u8; 32],
    payload_hash: [u8; 32],
    state_root: [u8; 32],
    bls_sk: &pc_crypto::BlsSecretKey,
) -> AnchorHeaderV2 {
    let mut hdr = AnchorHeaderV2 {
        version: 5,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash,
        creator_index: 0,
        vote_mask: 1,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id,
        vote_epoch: 1,
        vote_round: 0,
        attest_sig: None,
        state_root: Some(state_root),
    };
    let msg = pc_consensus::attestation::committee_precommit_message(
        &network_id,
        hdr.vote_epoch,
        &hdr.vote_target_hash(),
        &state_root,
    );
    hdr.attest_sig = Some(pc_crypto::bls_sign(&msg, bls_sk));
    hdr
}

#[test]
fn candidate_replaces_existing_best_prefers_lower_pow_hash() {
    assert!(
        crate::mint_candidate_runtime::candidate_replaces_existing_best(
            &[0x00; 32],
            &[0x11; 32],
            &[0x22; 32],
            &[0x01; 32],
            &[0x11; 32],
            &[0x22; 32],
        )
    );
    assert!(
        !crate::mint_candidate_runtime::candidate_replaces_existing_best(
            &[0x02; 32],
            &[0x11; 32],
            &[0x22; 32],
            &[0x01; 32],
            &[0x11; 32],
            &[0x22; 32],
        )
    );
}

#[test]
fn candidate_replaces_existing_best_uses_commitment_and_id_as_tiebreakers() {
    let same_pow = [0x44; 32];
    assert!(
        crate::mint_candidate_runtime::candidate_replaces_existing_best(
            &same_pow,
            &[0x10; 32],
            &[0x22; 32],
            &same_pow,
            &[0x11; 32],
            &[0x22; 32],
        )
    );
    assert!(
        crate::mint_candidate_runtime::candidate_replaces_existing_best(
            &same_pow,
            &[0x11; 32],
            &[0x20; 32],
            &same_pow,
            &[0x11; 32],
            &[0x21; 32],
        )
    );
    assert!(
        !crate::mint_candidate_runtime::candidate_replaces_existing_best(
            &same_pow,
            &[0x11; 32],
            &[0x21; 32],
            &same_pow,
            &[0x11; 32],
            &[0x21; 32],
        )
    );
}

#[test]
fn runtime_work_handle_v1_hashes_exact_domain_and_bound_context() {
    let network_id = [0x44; 32];
    let prev_mint_id = [0x55; 32];
    let window_id: u64 = 12;
    let window_open_anchor_id = [0x66; 32];
    let pow_seed = [0x33; 32];
    let mut expect_in = Vec::new();
    expect_in.extend_from_slice(b"PHANTOM:MINT:WORK:v1");
    expect_in.extend_from_slice(&network_id);
    expect_in.extend_from_slice(&prev_mint_id);
    expect_in.extend_from_slice(&window_id.to_le_bytes());
    expect_in.extend_from_slice(&window_open_anchor_id);
    expect_in.extend_from_slice(&pow_seed);
    assert_eq!(
        crate::mint_candidate_runtime::runtime_work_handle_v1(
            &network_id,
            &prev_mint_id,
            window_id,
            &window_open_anchor_id,
            &pow_seed,
        ),
        pc_crypto::blake3_32(&expect_in)
    );
}

#[test]
fn metrics_export_includes_continuous_mining_counters() {
    NODE_POW_MINING_ACTIVE.store(1, Ordering::Relaxed);
    NODE_POW_ACTIVE_LOCAL_SLOTS.store(1, Ordering::Relaxed);
    NODE_POW_CANDIDATE_ACTIVE_WORK_SLOTS.store(3, Ordering::Relaxed);
    NODE_POW_CANDIDATE_QUEUED_TOTAL.store(11, Ordering::Relaxed);
    NODE_POW_CANDIDATE_REPLACED_TOTAL.store(5, Ordering::Relaxed);
    NODE_POW_CANDIDATE_SKIPPED_NOT_BETTER_TOTAL.store(7, Ordering::Relaxed);
    NODE_POW_CANDIDATE_SCOPE_RESETS_TOTAL.store(2, Ordering::Relaxed);

    let text = crate::cli::render_p2p_metrics_prometheus_text();
    assert!(text.contains("pc_node_pow_active_local_slots 1"));
    assert!(text.contains("pc_node_pow_candidate_active_work_slots 3"));
    assert!(text.contains("pc_node_pow_candidate_queued_total 11"));
    assert!(text.contains("pc_node_pow_candidate_replaced_total 5"));
    assert!(text.contains("pc_node_pow_candidate_skipped_not_better_total 7"));
    assert!(text.contains("pc_node_pow_candidate_scope_resets_total 2"));
}

#[test]
fn candidate_scope_advance_does_not_clear_state_within_same_scope() {
    let scope = ([0x11; 32], 7);
    let mut active_scope = Some(scope);
    let mut candidate_nonce_cursor = HashMap::from([([0x21; 32], 99u64)]);
    let mut emitted_candidate_work = HashMap::from([([0x31; 32], 123u64)]);

    let transition = crate::mint_candidate_runtime::advance_candidate_scope(
        &mut active_scope,
        scope,
        &mut candidate_nonce_cursor,
        &mut emitted_candidate_work,
    );

    assert_eq!(
        transition,
        crate::mint_candidate_runtime::CandidateScopeAdvance::Unchanged
    );
    assert_eq!(active_scope, Some(scope));
    assert_eq!(candidate_nonce_cursor.len(), 1);
    assert_eq!(emitted_candidate_work.len(), 1);
}

#[test]
fn candidate_scope_advance_clears_state_on_tip_change() {
    let old_scope = ([0x11; 32], 7);
    let new_scope = ([0x12; 32], 7);
    let mut active_scope = Some(old_scope);
    let mut candidate_nonce_cursor = HashMap::from([([0x21; 32], 99u64)]);
    let mut emitted_candidate_work = HashMap::from([([0x31; 32], 123u64)]);

    let transition = crate::mint_candidate_runtime::advance_candidate_scope(
        &mut active_scope,
        new_scope,
        &mut candidate_nonce_cursor,
        &mut emitted_candidate_work,
    );

    assert_eq!(
        transition,
        crate::mint_candidate_runtime::CandidateScopeAdvance::Reset {
            previous: old_scope,
        }
    );
    assert_eq!(active_scope, Some(new_scope));
    assert!(candidate_nonce_cursor.is_empty());
    assert!(emitted_candidate_work.is_empty());
}

#[test]
fn candidate_scope_advance_clears_state_on_window_change() {
    let old_scope = ([0x11; 32], 7);
    let new_scope = ([0x11; 32], 8);
    let mut active_scope = Some(old_scope);
    let mut candidate_nonce_cursor = HashMap::from([([0x21; 32], 99u64)]);
    let mut emitted_candidate_work = HashMap::from([([0x31; 32], 123u64)]);

    let transition = crate::mint_candidate_runtime::advance_candidate_scope(
        &mut active_scope,
        new_scope,
        &mut candidate_nonce_cursor,
        &mut emitted_candidate_work,
    );

    assert_eq!(
        transition,
        crate::mint_candidate_runtime::CandidateScopeAdvance::Reset {
            previous: old_scope,
        }
    );
    assert_eq!(active_scope, Some(new_scope));
    assert!(candidate_nonce_cursor.is_empty());
    assert!(emitted_candidate_work.is_empty());
}

#[test]
fn mint_file_read_error_classification_treats_not_found_as_transient() {
    let err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
    assert_eq!(
        crate::quic_server::classify_mint_file_read_error(&err),
        crate::quic_server::MintFileReadDisposition::SkipTransientMissing
    );
}

#[test]
fn mint_file_read_error_classification_drops_other_read_errors() {
    let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    assert_eq!(
        crate::quic_server::classify_mint_file_read_error(&err),
        crate::quic_server::MintFileReadDisposition::DropUnreadable
    );
}

#[test]
fn runtime_candidate_work_id_is_omitted_when_feature_is_disabled() {
    let work_id = [0x55; 32];
    assert_eq!(
        crate::mint_candidate_runtime::runtime_candidate_work_id(work_id, 0),
        None
    );
}

#[test]
fn runtime_candidate_work_id_is_emitted_when_feature_is_enabled() {
    let work_id = [0x77; 32];
    assert_eq!(
        crate::mint_candidate_runtime::runtime_candidate_work_id(
            work_id,
            pc_types::MINT_CANDIDATE_FEATURE_WORK_ID_V1
        ),
        Some(work_id)
    );
}

#[test]
fn runtime_work_handle_v2_matches_v2_slot_binding_without_serialized_work_id() {
    let network_id = [0x91; 32];
    let prev_mint_id = [0x92; 32];
    let window_id: u64 = 7;
    let window_open_anchor_id = [0x93; 32];
    let mint_commitment = [0x94; 32];
    let nonce = 17;
    let runtime_work_handle = crate::mint_candidate_runtime::runtime_work_handle_v2(
        &network_id,
        &prev_mint_id,
        window_id,
        &window_open_anchor_id,
        &mint_commitment,
    );
    let candidate = pc_types::MintCandidateEventV2 {
        version: 2,
        network_id,
        prev_mint_id,
        window_id,
        window_open_anchor_id,
        mint_commitment,
        nonce,
        miner_pubkey: None,
        recipient_lock: None,
    };
    let cert = pc_types::MintPoWCertV2 {
        version: 2,
        network_id,
        prev_mint_id,
        window_id,
        window_open_anchor_id,
        mint_commitment,
        nonce,
    };
    assert_eq!(
        pc_types::candidate_slot_id_v2(&candidate),
        runtime_work_handle
    );
    assert_eq!(pc_types::pow_cert_slot_id_v2(&cert), runtime_work_handle);
}

#[test]
fn applied_local_mint_files_are_pruned_in_mint_censor_mode() {
    assert!(crate::quic_server::should_prune_applied_local_mint_file(
        true
    ));
    assert!(!crate::quic_server::should_prune_applied_local_mint_file(
        false
    ));
}

fn p2p_test_cfg() -> P2pConfig {
    P2pConfig {
        max_peers: 8,
        rate: None,
        peers_json_path: None,
        enable_peer_exchange: false,
        network_id: None,
    }
}

fn open_node_disk_store(
    store_dir: &std::path::Path,
    admission_k: Option<u8>,
) -> Result<Arc<NodeDiskStore>> {
    let store_dir_s = store_dir.to_string_lossy().to_string();
    let store = pc_store::FileStore::open(store_dir, false)?;
    Ok(Arc::new(NodeDiskStore::new(
        store,
        &store_dir_s,
        false,
        64,
        4,
        admission_k,
        None,
    )))
}

#[tokio::test]
async fn node_disk_store_persists_no_decision_payloads_and_headers() -> Result<()> {
    let base = unique_tmp("node_disk_store_empty_payload");
    let store = open_node_disk_store(&base, None)?;
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
    let payload_root = pc_types::payload_merkle_root_v3(&payload);
    pc_p2p::async_svc::StoreDelegate::insert_payload(store.as_ref(), payload.clone()).await;

    let fs = pc_store::FileStore::open(&base, false)?;
    let stored_payload = fs
        .get_payload_v3(&payload_root)?
        .ok_or_else(|| anyhow!("payload not persisted"))?;
    assert_eq!(stored_payload, payload);

    let kp =
        pc_crypto::bls_keygen_from_ikm(&[0x24; 32]).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let header = signed_prevote_header_for_payload([0x42; 32], payload_root, &kp.sk);
    let header_id = header.id_digest();
    pc_p2p::async_svc::StoreDelegate::insert_header(store.as_ref(), header.clone()).await;

    let stored_header = fs
        .get_header_v2(&header_id)?
        .ok_or_else(|| anyhow!("header not persisted"))?;
    assert_eq!(stored_header, header);
    Ok(())
}

async fn recv_outbox<T, F>(rx: &mut mpsc::Receiver<OutboundEnvelope>, mut map: F) -> Result<T>
where
    F: FnMut(&P2pMessage) -> Option<T>,
{
    timeout(Duration::from_secs(2), async {
        loop {
            let msg = rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("p2p outbox closed"))?;
            if let Some(value) = map(msg.message()) {
                return Ok(value);
            }
        }
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for p2p outbox message"))?
}

#[tokio::test]
async fn journal_recovery_roundtrip() -> Result<()> {
    let base = unique_tmp("recovery");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;
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
    tx.encode(&mut buf)?;
    atomic_write_async(&path, buf.clone(), false).await?;
    journal_append(&journal_path, false, b'A', &id)?;

    // Recovery nach Journal: aktive IDs
    let (active, fmt) = journal_read_active_ids(&journal_path)?
        .ok_or_else(|| anyhow!("journal must exist after append"))?;
    assert_eq!(fmt, JournalFormat::BinaryV1);
    assert!(active.contains(&id));

    // Datei laden und decodieren
    let mut fb = Vec::new();
    let mut f = std::fs::File::open(&path)?;
    std::io::Read::read_to_end(&mut f, &mut fb)?;
    let got = pc_codec::decode_exact::<MicroTx>(&fb)?;
    assert_eq!(tx, got);
    Ok(())
}

#[test]
fn journal_recovery_ignores_truncated_tail_record() -> Result<()> {
    let base = unique_tmp("journal_trunc");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;
    let journal_path = mempool_dir.join("mempool.journal");

    let tx1 = MicroTx {
        version: 1,
        inputs: vec![],
        outputs: vec![],
    };
    let tx2 = MicroTx {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            amount: 1,
            lock: LockCommitment([1u8; 32]),
        }],
    };
    let id1 = digest_microtx(&tx1);
    let id2 = digest_microtx(&tx2);

    journal_append(&journal_path, false, b'A', &id1)?;
    journal_append(&journal_path, false, b'A', &id2)?;

    // Simulate a crash during the last append: truncate the file mid-record.
    let meta = std::fs::metadata(&journal_path)?;
    assert!(meta.len() > 1);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&journal_path)?;
    f.set_len(meta.len() - 1)?;

    let (active, fmt) =
        journal_read_active_ids(&journal_path)?.ok_or_else(|| anyhow!("journal must exist"))?;
    assert_eq!(fmt, JournalFormat::BinaryV1);
    assert!(active.contains(&id1), "valid earlier record must survive");
    assert!(
        !active.contains(&id2),
        "truncated tail record must be ignored"
    );
    Ok(())
}

#[test]
fn ttl_eviction_removes_expired_file() -> Result<()> {
    let base = unique_tmp("ttl");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;

    // Eine Datei erzeugen und dann entfernen
    let path = mempool_dir.join("dead.bin");
    let mut f = std::fs::File::create(&path)?;
    std::io::Write::write_all(&mut f, b"x")?;
    remove_with_dir_sync(&path, false)?;
    assert!(!path.exists());
    Ok(())
}

#[test]
fn deterministic_sort_matches_payload_root() -> Result<()> {
    // Drei Txs, unsortiert
    let mk = |n: u8| MicroTx {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            amount: n as u64,
            lock: LockCommitment([n; 32]),
        }],
    };
    let txs_a = vec![mk(3), mk(1), mk(2)];
    let txs_b = vec![mk(2), mk(3), mk(1)];
    let sort = |mut v: Vec<MicroTx>| {
        v.sort_unstable_by_key(digest_microtx);
        v
    };
    let p_a = AnchorPayload {
        version: 1,
        micro_txs: sort(txs_a),
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
    };
    let p_b = AnchorPayload {
        version: 1,
        micro_txs: sort(txs_b),
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
    };
    assert_eq!(payload_merkle_root(&p_a), payload_merkle_root(&p_b));
    Ok(())
}

#[test]
fn committee_seed_anchor_none_without_finalized_root_or_genesis() -> Result<()> {
    let base = unique_tmp("seed_anchor_none");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;
    assert_eq!(
        committee_seed_anchor_from_mempool(&mempool_dir.to_string_lossy()),
        None
    );
    Ok(())
}

#[test]
fn committee_seed_anchor_prefers_last_final_payload_root() -> Result<()> {
    let base = unique_tmp("seed_anchor_root");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;
    let root = [0xAB; 32];
    std::fs::write(base.join("last_final_payload_root"), hex::encode(root))?;
    assert_eq!(
        committee_seed_anchor_from_mempool(&mempool_dir.to_string_lossy()),
        Some(root)
    );
    Ok(())
}

#[test]
fn finalized_payload_index_preserves_all_finalized_headers_for_same_root() {
    let root = [0xAA; 32];
    let mut idx = FinalizedPayloadIndex::default();
    let h1 = [0x11; 32];
    let h0 = [0x01; 32];

    let m1 = FinalizedPayloadMeta {
        header_id: h1,
        root,
        creator_index: 7,
        vote_epoch: 1,
        shard_id: 0,
        state_root: None,
    };
    let m0 = FinalizedPayloadMeta {
        header_id: h0,
        root,
        creator_index: 3,
        vote_epoch: 1,
        shard_id: 0,
        state_root: None,
    };

    idx.by_header_id.insert(h1, m1);
    idx.by_payload_root.entry(root).or_default().insert(h1);
    idx.by_header_id.insert(h0, m0);
    idx.by_payload_root.entry(root).or_default().insert(h0);

    let out = finalized_headers_for_root(&idx, root);
    assert_eq!(out.len(), 2);
    assert_eq!(
        out.first().map(|m| (m.header_id, m.creator_index)),
        Some((h0, 3))
    );
    assert_eq!(
        out.get(1).map(|m| (m.header_id, m.creator_index)),
        Some((h1, 7))
    );
}

#[test]
fn finalized_payload_index_cleanup_header_keeps_other_same_root_entries() {
    let root = [0xAA; 32];
    let mut idx = FinalizedPayloadIndex::default();
    let h1 = [0x11; 32];
    let h0 = [0x01; 32];

    let m1 = FinalizedPayloadMeta {
        header_id: h1,
        root,
        creator_index: 7,
        vote_epoch: 1,
        shard_id: 0,
        state_root: None,
    };
    let m0 = FinalizedPayloadMeta {
        header_id: h0,
        root,
        creator_index: 3,
        vote_epoch: 1,
        shard_id: 0,
        state_root: None,
    };

    idx.by_header_id.insert(h1, m1);
    idx.by_payload_root.entry(root).or_default().insert(h1);
    idx.insert_order.push_back(h1);
    idx.by_header_id.insert(h0, m0);
    idx.by_payload_root.entry(root).or_default().insert(h0);
    idx.insert_order.push_back(h0);

    let removed = cleanup_finalized_header_entry(&mut idx, h1);
    assert_eq!(removed.map(|m| m.header_id), Some(h1));

    let out = finalized_headers_for_root(&idx, root);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].header_id, h0);
    assert!(!idx.by_header_id.contains_key(&h1));
    assert!(!idx.insert_order.contains(&h1));
    assert!(idx.insert_order.contains(&h0));
}

#[test]
fn finalized_queue_total_order_determinism_with_meta() {
    use pc_consensus::finalized_queue::FinalizedQueue;

    let mut q: FinalizedQueue<FinalizedPayloadMeta> = FinalizedQueue::new();

    // Insert out-of-order: epoch 3 before epoch 1, mixed shards
    let mk = |epoch: u64, shard: u16, hid: u8, root: u8, ci: u8| FinalizedPayloadMeta {
        header_id: [hid; 32],
        root: [root; 32],
        creator_index: ci,
        vote_epoch: epoch,
        shard_id: shard,
        state_root: None,
    };

    q.insert(3, 0, [0x33; 32], mk(3, 0, 0x33, 0xA3, 0));
    q.insert(1, 0, [0x11; 32], mk(1, 0, 0x11, 0xA1, 1));
    q.insert(2, 0, [0x22; 32], mk(2, 0, 0x22, 0xA2, 2));
    q.insert(1, 0, [0x12; 32], mk(1, 0, 0x12, 0xA1, 3));

    let mut out = Vec::new();
    while let Some((epoch, shard, hid, meta)) = q.pop_next(|_| 1) {
        out.push((epoch, shard, hid, meta.creator_index));
    }

    assert_eq!(out.len(), 4);
    // Epoch 1, shard 0, header 0x11 first (lower hash)
    assert_eq!(out[0], (1, 0, [0x11; 32], 1));
    // Epoch 1, shard 0, header 0x12 second
    assert_eq!(out[1], (1, 0, [0x12; 32], 3));
    // Epoch 2
    assert_eq!(out[2], (2, 0, [0x22; 32], 2));
    // Epoch 3
    assert_eq!(out[3], (3, 0, [0x33; 32], 0));

    // Same entries, reversed insert order → identical pop order
    let mut q2: FinalizedQueue<FinalizedPayloadMeta> = FinalizedQueue::new();
    q2.insert(1, 0, [0x12; 32], mk(1, 0, 0x12, 0xA1, 3));
    q2.insert(2, 0, [0x22; 32], mk(2, 0, 0x22, 0xA2, 2));
    q2.insert(1, 0, [0x11; 32], mk(1, 0, 0x11, 0xA1, 1));
    q2.insert(3, 0, [0x33; 32], mk(3, 0, 0x33, 0xA3, 0));

    let mut out2 = Vec::new();
    while let Some((epoch, shard, hid, meta)) = q2.pop_next(|_| 1) {
        out2.push((epoch, shard, hid, meta.creator_index));
    }
    assert_eq!(
        out, out2,
        "different insert order must produce identical pop order"
    );
}

#[tokio::test]
async fn validator_eligibility_accepts_genesis_bootstrap_without_stake() -> Result<()> {
    let base = unique_tmp("bootstrap_eligibility");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;

    let ikm = [0x31u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let vid = pc_crypto::attestor_recipient_id_from_bls(&kp.pk);
    let note = GenesisNote {
        version: 1,
        network_name: b"pc-test".to_vec(),
        seed: [0x12; 32],
        params: pc_types::GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: pc_types::GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![pc_types::GenesisValidatorV1 {
            operator_id: [0x77; 32],
            bls_pk: kp.pk.to_bytes(),
            bls_pop: pc_crypto::bls_pop_prove(&kp.sk),
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;

    let store_dir = base.to_string_lossy().to_string();
    let eligibility = check_validator_eligibility(Some(vid), None, &store_dir).await;
    assert!(
        eligibility.eligible,
        "bootstrap validator should be eligible"
    );
    assert!(eligibility.pop_ok, "bootstrap bls_pop must verify");
    assert!(eligibility.policy_ok, "policy should allow by default");
    assert_eq!(eligibility.stake, 0, "bootstrap seat has no staked UTXO");
    Ok(())
}

#[cfg(feature = "rocksdb")]
#[tokio::test]
async fn verify_payout_root_rejects_wrong_root_for_finalized_apply_path() -> Result<()> {
    let base = unique_tmp("payout_root_reject");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;

    let ikm = [0x42u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = GenesisNote {
        version: 1,
        network_name: b"pc-test".to_vec(),
        seed: [0x33; 32],
        params: pc_types::GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: pc_types::GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![pc_types::GenesisValidatorV1 {
            operator_id: [0x77; 32],
            bls_pk: kp.pk.to_bytes(),
            bls_pop: pc_crypto::bls_pop_prove(&kp.sk),
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;

    let utxo_dir = base.join("utxo");
    std::fs::create_dir_all(&utxo_dir)?;
    let utxo_dir_s = utxo_dir.to_string_lossy().to_string();
    let backend = open_rocksdb_primary_with_recovery(&utxo_dir_s, "utxo-test")?;
    let mut st = UtxoState::new(backend);

    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0xA5; 32], // intentionally wrong for bootstrap fee-eligibility=false set
        genesis_note: None,
        null_mint: false,
    };
    let mempool_dir_s = mempool_dir.to_string_lossy().to_string();
    let network_id = digest_genesis_note(&note);
    let res = compute_payload_payout_root_strict_by_creator_index(
        &mut st,
        &mempool_dir_s,
        network_id,
        1,
        1,
        &payload.micro_txs,
        None,
        0,
    )
    .await;
    match res {
        Ok(root) => assert_ne!(root, payload.payout_root, "wrong payout_root must differ"),
        Err(_) => {} // also acceptable
    }
    Ok(())
}

#[cfg(feature = "rocksdb")]
#[tokio::test]
async fn verify_payout_root_accepts_any_matching_finalized_header_candidate() -> Result<()> {
    let base = unique_tmp("payout_root_any_match");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;

    let ikm = [0x51u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = GenesisNote {
        version: 1,
        network_name: b"pc-test".to_vec(),
        seed: [0x44; 32],
        params: pc_types::GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: pc_types::GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![pc_types::GenesisValidatorV1 {
            operator_id: [0x66; 32],
            bls_pk: kp.pk.to_bytes(),
            bls_pop: pc_crypto::bls_pop_prove(&kp.sk),
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;

    let utxo_dir = base.join("utxo");
    std::fs::create_dir_all(&utxo_dir)?;
    let utxo_dir_s = utxo_dir.to_string_lossy().to_string();
    let backend = open_rocksdb_primary_with_recovery(&utxo_dir_s, "utxo-test")?;
    let mut st = UtxoState::new(backend);

    let mempool_dir_s = mempool_dir.to_string_lossy().to_string();
    let network_id = digest_genesis_note(&note);
    let expected_root = compute_payload_payout_root_strict_by_creator_index(
        &mut st,
        &mempool_dir_s,
        network_id,
        1,
        1,
        &[],
        None,
        0,
    )
    .await?;

    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: expected_root,
        genesis_note: None,
        null_mint: false,
    };
    let payload_root = pc_types::payload_merkle_root_v3(&payload);
    let headers = vec![
        // Bad creator index first: helper must continue and accept later valid candidate.
        FinalizedPayloadMeta {
            header_id: [0x91; 32],
            root: payload_root,
            creator_index: 1,
            vote_epoch: 1,
            shard_id: 0,
            state_root: None,
        },
        FinalizedPayloadMeta {
            header_id: [0x92; 32],
            root: payload_root,
            creator_index: 0,
            vote_epoch: 1,
            shard_id: 0,
            state_root: None,
        },
    ];

    let matched = verify_payload_payout_root_against_finalized_headers(
        &mut st,
        &mempool_dir_s,
        network_id,
        1,
        1,
        &payload,
        None,
        &headers,
    )
    .await?;
    assert_eq!(matched.creator_index, 0);
    assert_eq!(matched.header_id, [0x92; 32]);
    Ok(())
}

#[tokio::test]
async fn payout_root_helper_rejects_ambiguous_matching_finalized_headers() -> Result<()> {
    let base = unique_tmp("payout_root_helper_ambiguous");
    let mempool_dir = base.join("mempool");
    let utxo_dir = base.join("utxo");
    std::fs::create_dir_all(&mempool_dir)?;
    std::fs::create_dir_all(&utxo_dir)?;

    let ikm = [0x61u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = GenesisNote {
        version: 1,
        network_name: b"pc-test".to_vec(),
        seed: [0x45; 32],
        params: pc_types::GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: pc_types::GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![pc_types::GenesisValidatorV1 {
            operator_id: [0x67; 32],
            bls_pk: kp.pk.to_bytes(),
            bls_pop: pc_crypto::bls_pop_prove(&kp.sk),
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;

    let utxo_dir_s = utxo_dir.to_string_lossy().to_string();
    let backend = open_rocksdb_primary_with_recovery(&utxo_dir_s, "utxo-test-ambiguous")?;
    let mut st = UtxoState::new(backend);

    let mempool_dir_s = mempool_dir.to_string_lossy().to_string();
    let network_id = digest_genesis_note(&note);
    let expected_root = compute_payload_payout_root_strict_by_creator_index(
        &mut st,
        &mempool_dir_s,
        network_id,
        1,
        1,
        &[],
        None,
        0,
    )
    .await?;

    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: expected_root,
        genesis_note: None,
        null_mint: false,
    };
    let payload_root = pc_types::payload_merkle_root_v3(&payload);
    let headers = vec![
        FinalizedPayloadMeta {
            header_id: [0xA1; 32],
            root: payload_root,
            creator_index: 0,
            vote_epoch: 1,
            shard_id: 0,
            state_root: Some([0x11; 32]),
        },
        FinalizedPayloadMeta {
            header_id: [0xA2; 32],
            root: payload_root,
            creator_index: 0,
            vote_epoch: 1,
            shard_id: 0,
            state_root: Some([0x22; 32]),
        },
    ];

    let err = verify_payload_payout_root_against_finalized_headers(
        &mut st,
        &mempool_dir_s,
        network_id,
        1,
        1,
        &payload,
        None,
        &headers,
    )
    .await
    .expect_err("ambiguous matching finalized headers must be rejected");
    assert!(err
        .to_string()
        .contains("matches multiple finalized header candidates"));
    Ok(())
}

#[tokio::test]
async fn state_committee_helper_prefers_state_validator_set_over_bootstrap() -> Result<()> {
    let base = unique_tmp("state_committee_payout");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;

    let boot_ikm = [0x61u8; 32];
    let boot_kp =
        pc_crypto::bls_keygen_from_ikm(&boot_ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let boot_vid = pc_crypto::attestor_recipient_id_from_bls(&boot_kp.pk);

    let state_ikm = [0x62u8; 32];
    let state_kp =
        pc_crypto::bls_keygen_from_ikm(&state_ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let state_vid = pc_crypto::attestor_recipient_id_from_bls(&state_kp.pk);

    let note = GenesisNote {
        version: 1,
        network_name: b"pc-test".to_vec(),
        seed: [0x55; 32],
        params: pc_types::GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: pc_types::GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![pc_types::GenesisValidatorV1 {
            operator_id: [0x71; 32],
            bls_pk: boot_kp.pk.to_bytes(),
            bls_pop: pc_crypto::bls_pop_prove(&boot_kp.sk),
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;

    let mut st = UtxoState::new(pc_state::InMemoryBackend::new());
    let stake_lock = LockCommitment([0x84; 32]);
    let op = OutPoint {
        txid: [0x91; 32],
        vout: 0,
    };
    pc_state::StateBackend::put_validator_record(
        st.backend_mut(),
        state_vid,
        pc_types::ValidatorRecordV1 {
            version: 1,
            stake_lock,
            sequence: 1,
            operator_id: [0x72; 32],
            bls_pk: state_kp.pk.to_bytes(),
            bls_pop: pc_crypto::bls_pop_prove(&state_kp.sk),
        },
    );
    pc_state::StateBackend::put(
        st.backend_mut(),
        op,
        (pc_consensus::consts::MIN_ATTESTOR_STAKE, stake_lock),
    );
    pc_state::StateBackend::set_minted_at(st.backend_mut(), op, 0);
    pc_state::StateBackend::set_staked(st.backend_mut(), op);

    let mempool_dir_s = mempool_dir.to_string_lossy().to_string();
    let network_id = digest_genesis_note(&note);
    let seed_anchor = pc_types::genesis_payload_root(&note);
    let staked = compute_committee_from_utxo_state(&mut st, 1, seed_anchor, 1, network_id, None)
        .ok_or_else(|| anyhow!("missing state committee"))?;
    let bootstrap =
        compute_committee_from_genesis_note(&mempool_dir_s, 1, seed_anchor, 1, network_id, None)
            .await
            .ok_or_else(|| anyhow!("missing bootstrap committee"))?;
    let chosen = choose_effective_committee(1, Some(staked), Some(bootstrap))
        .ok_or_else(|| anyhow!("missing chosen committee"))?;

    assert_eq!(chosen.recipient_ids, vec![state_vid]);
    assert_ne!(chosen.recipient_ids, vec![boot_vid]);
    assert!(
        !chosen.bootstrap_mode,
        "state committee must win over bootstrap fallback"
    );
    Ok(())
}

#[tokio::test]
async fn verify_header_finality_accepts_valid_bootstrap_precommit_header() -> Result<()> {
    let base = unique_tmp("verify_header_finality_ok");
    let mempool_dir = base.join("mempool");

    let ikm = [0x81u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&mempool_dir, &kp)?;
    let network_id = digest_genesis_note(&note);
    let state_root = [0x91; 32];
    let hdr = signed_finality_header(network_id, state_root, &kp.sk);

    let mut consensus_network_id = None;
    let mut committee_cache = None;
    let mut committee_recompute_last = None;
    let ok = verify_header_finality(
        &hdr,
        1,
        &mut consensus_network_id,
        &mempool_dir.to_string_lossy(),
        &mut committee_cache,
        &mut committee_recompute_last,
        None,
    )
    .await;

    assert!(ok, "valid bootstrap precommit header must verify");
    assert_eq!(consensus_network_id, Some(network_id));
    assert!(
        committee_cache.is_some(),
        "committee cache must be populated"
    );
    Ok(())
}

#[tokio::test]
async fn verify_header_finality_rejects_network_id_mismatch_even_with_valid_signature_for_other_network(
) -> Result<()> {
    let base = unique_tmp("verify_header_finality_bad_nid");
    let mempool_dir = base.join("mempool");

    let ikm = [0x82u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&mempool_dir, &kp)?;
    let network_id = digest_genesis_note(&note);
    let wrong_network_id = [0xEE; 32];
    let state_root = [0x92; 32];
    let hdr = signed_finality_header(wrong_network_id, state_root, &kp.sk);

    let mut consensus_network_id = None;
    let mut committee_cache = None;
    let mut committee_recompute_last = None;
    let ok = verify_header_finality(
        &hdr,
        1,
        &mut consensus_network_id,
        &mempool_dir.to_string_lossy(),
        &mut committee_cache,
        &mut committee_recompute_last,
        None,
    )
    .await;

    assert!(!ok, "header with mismatched network_id must be rejected");
    assert_eq!(consensus_network_id, Some(network_id));
    Ok(())
}

#[tokio::test]
async fn verify_header_finality_precheck_rejects_missing_state_root_before_committee_resolution(
) -> Result<()> {
    let base = unique_tmp("verify_header_finality_missing_state_root");
    let mempool_dir = base.join("mempool");

    let ikm = [0x83u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&mempool_dir, &kp)?;
    let network_id = digest_genesis_note(&note);
    let mut hdr = signed_finality_header(network_id, [0x93; 32], &kp.sk);
    hdr.state_root = None;

    let mut consensus_network_id = None;
    let mut committee_cache = None;
    let mut committee_recompute_last = None;
    let ok = verify_header_finality(
        &hdr,
        1,
        &mut consensus_network_id,
        &mempool_dir.to_string_lossy(),
        &mut committee_cache,
        &mut committee_recompute_last,
        None,
    )
    .await;

    assert!(
        !ok,
        "header without committed state_root must be rejected in A-stage"
    );
    assert_eq!(consensus_network_id, Some(network_id));
    assert!(
        committee_cache.is_none(),
        "A-stage rejection must happen before committee resolution"
    );
    assert!(
        committee_recompute_last.is_none(),
        "A-stage rejection must not trigger committee recomputation throttling"
    );
    Ok(())
}

#[tokio::test]
async fn verify_header_prevote_accepts_valid_bootstrap_prevote_header() -> Result<()> {
    let base = unique_tmp("verify_header_prevote_ok");
    let mempool_dir = base.join("mempool");

    let ikm = [0x84u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&mempool_dir, &kp)?;
    let network_id = digest_genesis_note(&note);
    let hdr = signed_prevote_header(network_id, &kp.sk);

    let mut consensus_network_id = None;
    let mut committee_cache = None;
    let mut committee_recompute_last = None;
    let ok = verify_header_prevote(
        &hdr,
        1,
        &mut consensus_network_id,
        &mempool_dir.to_string_lossy(),
        &mut committee_cache,
        &mut committee_recompute_last,
        None,
    )
    .await;

    assert!(ok, "valid bootstrap prevote header must verify");
    assert_eq!(consensus_network_id, Some(network_id));
    assert!(
        committee_cache.is_some(),
        "committee cache must be populated"
    );
    Ok(())
}

#[tokio::test]
async fn verify_header_prevote_rejects_header_with_post_state_root() -> Result<()> {
    let base = unique_tmp("verify_header_prevote_state_root_present");
    let mempool_dir = base.join("mempool");

    let ikm = [0x85u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&mempool_dir, &kp)?;
    let network_id = digest_genesis_note(&note);
    let mut hdr = signed_prevote_header(network_id, &kp.sk);
    hdr.state_root = Some([0x95; 32]);

    let mut consensus_network_id = None;
    let mut committee_cache = None;
    let mut committee_recompute_last = None;
    let ok = verify_header_prevote(
        &hdr,
        1,
        &mut consensus_network_id,
        &mempool_dir.to_string_lossy(),
        &mut committee_cache,
        &mut committee_recompute_last,
        None,
    )
    .await;

    assert!(!ok, "prevote header with post_state_root must be rejected");
    assert_eq!(consensus_network_id, Some(network_id));
    assert!(
        committee_cache.is_none(),
        "stage split must reject prevote/precommit hybrids before committee resolution"
    );
    Ok(())
}

#[tokio::test]
async fn p2p_header_announce_with_node_disk_store_fetches_and_persists_payload() -> Result<()> {
    let sender_base = unique_tmp("p2p_header_sender");
    let receiver_base = unique_tmp("p2p_header_receiver");
    let sender_mempool = sender_base.join("mempool");
    let receiver_mempool = receiver_base.join("mempool");
    std::fs::create_dir_all(&sender_mempool)?;
    std::fs::create_dir_all(&receiver_mempool)?;

    let ikm = [0x84u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&sender_mempool, &kp)?;
    write_bootstrap_genesis_for_finality_test(&receiver_mempool, &kp)?;
    let network_id = digest_genesis_note(&note);
    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: Some(note.clone()),
        null_mint: false,
    };
    let root = pc_types::payload_merkle_root_v3(&payload);
    let hdr = signed_finality_header_for_payload(network_id, root, [0xA1; 32], &kp.sk);

    let sender_store = pc_store::FileStore::open(&sender_base, false)?;
    sender_store.put_payload_v3(&payload)?;

    let (svc_a, mut out_a, handle_a) =
        spawn_with_store(p2p_test_cfg(), open_node_disk_store(&sender_base, Some(1))?);
    let (svc_b, mut out_b, handle_b) = spawn_with_store(
        p2p_test_cfg(),
        open_node_disk_store(&receiver_base, Some(1))?,
    );

    svc_a.announce_header(hdr.clone()).await?;
    let announced = recv_outbox(&mut out_a, |msg| {
        pc_p2p::messages::announced_header(&msg).cloned()
    })
    .await?;
    assert_eq!(announced.id_digest(), hdr.id_digest());

    svc_b
        .send_message(pc_p2p::messages::explicit_announce_for_header(announced))
        .await?;
    let requested_roots = recv_outbox(&mut out_b, |msg| match msg {
        P2pMessage::Req(ReqMsg::GetPayloads { roots }) => Some(roots.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(requested_roots, vec![root]);

    let payload_rx = watch_payload(root);
    svc_a
        .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
            roots: requested_roots.clone(),
        }))
        .await?;
    let payloads = recv_outbox(&mut out_a, |msg| match msg {
        P2pMessage::Resp(RespMsg::Payloads { payloads }) => Some(payloads.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(payloads.len(), 1);
    assert_eq!(pc_types::payload_merkle_root_v3(&payloads[0]), root);

    svc_b
        .send_message(P2pMessage::Resp(RespMsg::Payloads {
            payloads: payloads.clone(),
        }))
        .await?;
    match timeout(Duration::from_secs(2), payload_rx)
        .await
        .map_err(|_| anyhow!("timed out waiting for payload watcher"))??
    {
        RespMsg::Payloads { payloads: watched } => {
            assert_eq!(watched.len(), 1);
            assert_eq!(pc_types::payload_merkle_root_v3(&watched[0]), root);
        }
        other => return Err(anyhow!("unexpected payload watcher message: {:?}", other)),
    }

    let receiver_store = pc_store::FileStore::open(&receiver_base, false)?;
    let stored_header = receiver_store
        .get_header_v2(&hdr.id_digest())?
        .ok_or_else(|| anyhow!("missing persisted header"))?;
    let stored_payload = receiver_store
        .get_payload_v3(&root)?
        .ok_or_else(|| anyhow!("missing persisted payload"))?;
    assert_eq!(stored_header.id_digest(), hdr.id_digest());
    assert_eq!(pc_types::payload_merkle_root_v3(&stored_payload), root);

    let mut idx = FinalizedPayloadIndex::default();
    let meta = record_finalized_header(&mut idx, &stored_header)
        .ok_or_else(|| anyhow!("finalized header should be indexed once"))?;
    assert_eq!(meta.root, root);
    let metas = finalized_headers_for_root(&idx, root);
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].root, meta.root);
    assert_eq!(metas[0].header_id, meta.header_id);
    assert_eq!(metas[0].creator_index, meta.creator_index);
    assert_eq!(metas[0].vote_epoch, meta.vote_epoch);
    assert_eq!(metas[0].shard_id, meta.shard_id);
    assert_eq!(metas[0].state_root, meta.state_root);
    assert!(record_finalized_header(&mut idx, &stored_header).is_none());

    svc_a.shutdown().await?;
    svc_b.shutdown().await?;
    handle_a
        .await
        .map_err(|e| anyhow!("sender p2p task join failed: {e}"))??;
    handle_b
        .await
        .map_err(|e| anyhow!("receiver p2p task join failed: {e}"))??;
    Ok(())
}

#[tokio::test]
async fn p2p_prevote_header_announce_with_node_disk_store_fetches_and_persists_payload(
) -> Result<()> {
    let sender_base = unique_tmp("p2p_prevote_header_sender");
    let receiver_base = unique_tmp("p2p_prevote_header_receiver");
    let sender_mempool = sender_base.join("mempool");
    let receiver_mempool = receiver_base.join("mempool");
    std::fs::create_dir_all(&sender_mempool)?;
    std::fs::create_dir_all(&receiver_mempool)?;

    let ikm = [0x86u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&sender_mempool, &kp)?;
    write_bootstrap_genesis_for_finality_test(&receiver_mempool, &kp)?;
    let network_id = digest_genesis_note(&note);
    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: Some(note.clone()),
        null_mint: false,
    };
    let root = pc_types::payload_merkle_root_v3(&payload);
    let hdr = signed_prevote_header_for_payload(network_id, root, &kp.sk);

    let sender_store = pc_store::FileStore::open(&sender_base, false)?;
    sender_store.put_payload_v3(&payload)?;

    let (svc_a, mut out_a, handle_a) =
        spawn_with_store(p2p_test_cfg(), open_node_disk_store(&sender_base, Some(1))?);
    let (svc_b, mut out_b, handle_b) = spawn_with_store(
        p2p_test_cfg(),
        open_node_disk_store(&receiver_base, Some(1))?,
    );

    svc_a.announce_header(hdr.clone()).await?;
    let announced = recv_outbox(&mut out_a, |msg| {
        pc_p2p::messages::announced_header(&msg).cloned()
    })
    .await?;
    assert_eq!(announced.id_digest(), hdr.id_digest());

    svc_b
        .send_message(pc_p2p::messages::explicit_announce_for_header(announced))
        .await?;
    let requested_roots = recv_outbox(&mut out_b, |msg| match msg {
        P2pMessage::Req(ReqMsg::GetPayloads { roots }) => Some(roots.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(requested_roots, vec![root]);

    let payload_rx = watch_payload(root);
    svc_a
        .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
            roots: requested_roots.clone(),
        }))
        .await?;
    let payloads = recv_outbox(&mut out_a, |msg| match msg {
        P2pMessage::Resp(RespMsg::Payloads { payloads }) => Some(payloads.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(payloads.len(), 1);
    assert_eq!(pc_types::payload_merkle_root_v3(&payloads[0]), root);

    svc_b
        .send_message(P2pMessage::Resp(RespMsg::Payloads {
            payloads: payloads.clone(),
        }))
        .await?;
    match timeout(Duration::from_secs(2), payload_rx)
        .await
        .map_err(|_| anyhow!("timed out waiting for payload watcher"))??
    {
        RespMsg::Payloads { payloads: watched } => {
            assert_eq!(watched.len(), 1);
            assert_eq!(pc_types::payload_merkle_root_v3(&watched[0]), root);
        }
        other => return Err(anyhow!("unexpected payload watcher message: {:?}", other)),
    }

    let receiver_store = pc_store::FileStore::open(&receiver_base, false)?;
    let stored_header = receiver_store
        .get_header_v2(&hdr.id_digest())?
        .ok_or_else(|| anyhow!("missing persisted prevote header"))?;
    let stored_payload = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(p) = receiver_store.get_payload_v3(&root)? {
                break p;
            }
            if std::time::Instant::now() > deadline {
                return Err(anyhow!("missing persisted payload"));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    assert_eq!(stored_header.id_digest(), hdr.id_digest());
    assert_eq!(pc_types::payload_merkle_root_v3(&stored_payload), root);

    svc_a.shutdown().await?;
    svc_b.shutdown().await?;
    handle_a
        .await
        .map_err(|e| anyhow!("sender p2p task join failed: {e}"))??;
    handle_b
        .await
        .map_err(|e| anyhow!("receiver p2p task join failed: {e}"))??;
    Ok(())
}

#[tokio::test]
async fn p2p_headers_response_with_node_disk_store_admits_requested_header_and_fetches_payload(
) -> Result<()> {
    let sender_base = unique_tmp("p2p_headers_sender");
    let receiver_base = unique_tmp("p2p_headers_receiver");
    let sender_mempool = sender_base.join("mempool");
    let receiver_mempool = receiver_base.join("mempool");
    std::fs::create_dir_all(&sender_mempool)?;
    std::fs::create_dir_all(&receiver_mempool)?;

    let ikm = [0x85u8; 32];
    let kp = pc_crypto::bls_keygen_from_ikm(&ikm).ok_or_else(|| anyhow!("bls keygen failed"))?;
    let note = write_bootstrap_genesis_for_finality_test(&sender_mempool, &kp)?;
    write_bootstrap_genesis_for_finality_test(&receiver_mempool, &kp)?;
    let network_id = digest_genesis_note(&note);
    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: Some(note.clone()),
        null_mint: false,
    };
    let root = pc_types::payload_merkle_root_v3(&payload);
    let hdr = signed_finality_header_for_payload(network_id, root, [0xA2; 32], &kp.sk);

    let sender_store = pc_store::FileStore::open(&sender_base, false)?;
    sender_store.put_header_v2(&hdr)?;
    sender_store.put_payload_v3(&payload)?;

    let (svc_a, mut out_a, handle_a) =
        spawn_with_store(p2p_test_cfg(), open_node_disk_store(&sender_base, Some(1))?);
    let (svc_b, mut out_b, handle_b) = spawn_with_store(
        p2p_test_cfg(),
        open_node_disk_store(&receiver_base, Some(1))?,
    );

    let header_rx = watch_header(AnchorId(hdr.id_digest()));
    svc_b
        .send_req(ReqMsg::GetHeaders {
            ids: vec![AnchorId(hdr.id_digest())],
        })
        .await?;
    let requested_ids = recv_outbox(&mut out_b, |msg| match msg {
        P2pMessage::Req(ReqMsg::GetHeaders { ids }) => Some(ids.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(requested_ids, vec![AnchorId(hdr.id_digest())]);

    svc_a
        .send_message(P2pMessage::Req(ReqMsg::GetHeaders {
            ids: requested_ids.clone(),
        }))
        .await?;
    let headers = recv_outbox(&mut out_a, |msg| match msg {
        P2pMessage::Resp(resp) => pc_p2p::messages::header_response_headers(&resp),
        _ => None,
    })
    .await?;
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].id_digest(), hdr.id_digest());

    svc_b
        .send_message(P2pMessage::Resp(
            pc_p2p::messages::explicit_header_response_for_headers(headers.clone()),
        ))
        .await?;
    match timeout(Duration::from_secs(2), header_rx)
        .await
        .map_err(|_| anyhow!("timed out waiting for header watcher"))??
    {
        resp => {
            let watched = pc_p2p::messages::header_response_headers(&resp)
                .ok_or_else(|| anyhow!("unexpected header watcher message: {:?}", resp))?;
            assert_eq!(watched.len(), 1);
            assert_eq!(
                watched.first().map(|h| h.id_digest()),
                Some(hdr.id_digest())
            );
        }
    }

    let requested_roots = recv_outbox(&mut out_b, |msg| match msg {
        P2pMessage::Req(ReqMsg::GetPayloads { roots }) => Some(roots.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(requested_roots, vec![root]);

    let payload_rx = watch_payload(root);
    svc_a
        .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
            roots: requested_roots.clone(),
        }))
        .await?;
    let payloads = recv_outbox(&mut out_a, |msg| match msg {
        P2pMessage::Resp(RespMsg::Payloads { payloads }) => Some(payloads.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(payloads.len(), 1);
    assert_eq!(pc_types::payload_merkle_root_v3(&payloads[0]), root);

    svc_b
        .send_message(P2pMessage::Resp(RespMsg::Payloads {
            payloads: payloads.clone(),
        }))
        .await?;
    match timeout(Duration::from_secs(2), payload_rx)
        .await
        .map_err(|_| anyhow!("timed out waiting for payload watcher"))??
    {
        RespMsg::Payloads { payloads: watched } => {
            assert_eq!(watched.len(), 1);
            assert_eq!(pc_types::payload_merkle_root_v3(&watched[0]), root);
        }
        other => return Err(anyhow!("unexpected payload watcher message: {:?}", other)),
    }

    let receiver_store = pc_store::FileStore::open(&receiver_base, false)?;
    let stored_header = receiver_store
        .get_header_v2(&hdr.id_digest())?
        .ok_or_else(|| anyhow!("missing persisted header"))?;
    let stored_payload = receiver_store
        .get_payload_v3(&root)?
        .ok_or_else(|| anyhow!("missing persisted payload"))?;
    assert_eq!(stored_header.id_digest(), hdr.id_digest());
    assert_eq!(pc_types::payload_merkle_root_v3(&stored_payload), root);

    let mut idx = FinalizedPayloadIndex::default();
    let meta = record_finalized_header(&mut idx, &stored_header)
        .ok_or_else(|| anyhow!("finalized header should be indexed once"))?;
    assert_eq!(meta.root, root);
    let metas = finalized_headers_for_root(&idx, root);
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].root, meta.root);
    assert_eq!(metas[0].header_id, meta.header_id);
    assert_eq!(metas[0].creator_index, meta.creator_index);
    assert_eq!(metas[0].vote_epoch, meta.vote_epoch);
    assert_eq!(metas[0].shard_id, meta.shard_id);
    assert_eq!(metas[0].state_root, meta.state_root);
    assert!(record_finalized_header(&mut idx, &stored_header).is_none());

    svc_a.shutdown().await?;
    svc_b.shutdown().await?;
    handle_a
        .await
        .map_err(|e| anyhow!("sender p2p task join failed: {e}"))??;
    handle_b
        .await
        .map_err(|e| anyhow!("receiver p2p task join failed: {e}"))??;
    Ok(())
}

#[test]
fn finality_vote_epoch_uses_node_rotation_config() -> Result<()> {
    let base = unique_tmp("finality_vote_epoch_cfg");
    std::fs::create_dir_all(&base)?;
    std::fs::write(base.join("anchor_index"), b"13")?;

    let next_anchor_index =
        finality_pipeline::next_anchor_index_from_store_dir(&base.to_string_lossy());
    let node_rot_cfg = NodeRotationCfg {
        epoch_len: Some(7),
        cooldown_anchors: None,
        min_attendance_pct: None,
    };

    assert_eq!(next_anchor_index, 14);
    assert_eq!(
        finality_pipeline::derive_vote_epoch(next_anchor_index, Some(&node_rot_cfg)),
        2,
        "vote_epoch must be derived from node rotation config instead of a client constant"
    );
    Ok(())
}

#[tokio::test]
async fn pending_finalization_invalidation() -> Result<()> {
    // Setup: two txs in the mempool (files + journal), payload contains one of them.
    // Setup: zwei Txs im Mempool (Dateien + Journal), Payload enthält eine davon.
    let base = unique_tmp("finalize");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;
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

    // Write both txs to files and journal.
    // Schreibe beide Txs in Dateien + Journal.
    for (tx, id) in [(&tx_keep, &id_keep), (&tx_inval, &id_inval)] {
        let fname = format!("{}.bin", hex::encode(id));
        let path = mempool_dir.join(fname);
        let mut buf = Vec::new();
        tx.encode(&mut buf)?;
        atomic_write_async(&path, buf.clone(), false).await?;
        journal_append(&journal_path, false, b'A', id)?;
    }

    // Fill in-memory mempool and order queue.
    // RAM‑Mempool und Order füllen.
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
            assert!(
                journal_append(&journal_path, false, b'D', &id).is_ok(),
                "journal append del failed"
            );
            assert!(
                remove_with_dir_sync(&path, false).is_ok(),
                "remove with dir sync failed"
            );
        }
    }

    // Check: one tx is invalidated and its file removed, the other still exists.
    // Prüfen: eine Tx invalidiert, Datei entfernt, die andere existiert.
    assert_eq!(invalidated, 1);
    assert!(!mempool.contains_key(&id_inval));
    assert!(mempool.contains_key(&id_keep));
    let keep_path = mempool_dir.join(format!("{}.bin", hex::encode(id_keep)));
    assert!(keep_path.exists());
    let inval_path = mempool_dir.join(format!("{}.bin", hex::encode(id_inval)));
    assert!(!inval_path.exists());
    // Order contains only id_keep.
    // Order enthält nur id_keep.
    assert_eq!(order.len(), 1);
    assert_eq!(order.front().copied(), Some(id_keep));

    Ok(())
}

#[tokio::test]
async fn readyz_check_mempool_dir_uses_blocking_bridge_and_reports_errors() -> Result<()> {
    let base = unique_tmp("readyz_check");
    let existing = base.join("mempool");
    std::fs::create_dir_all(&existing)?;

    assert!(readyz_check_mempool_dir(&existing.to_string_lossy())
        .await
        .is_ok());

    let missing = base.join("missing");
    let err = readyz_check_mempool_dir(&missing.to_string_lossy())
        .await
        .err()
        .ok_or_else(|| anyhow!("missing mempool dir must fail readiness check"))?;
    assert!(
        err.contains("mempool_dir:"),
        "error must preserve mempool_dir context: {err}"
    );
    Ok(())
}

#[test]
fn persist_supply_state_sync_missing_dir_is_non_panicking() {
    let base = unique_tmp("persist_supply_missing");
    let missing_mempool = base.join("does-not-exist");
    let st = pc_consensus::SupplyState::default();
    persist_supply_state_sync(&missing_mempool.to_string_lossy(), &st, false);
    let out = missing_mempool.join("supply_state.json");
    assert!(
        !out.exists(),
        "persist must not create files when mempool dir is missing"
    );
}

#[test]
fn refresh_supply_state_from_disk_enables_followup_mint_validation() -> Result<()> {
    let base = unique_tmp("refresh_supply_followup");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;

    let first_reward = pc_consensus::consts::compute_mint_reward(1);
    let second_reward = pc_consensus::consts::compute_mint_reward(2);
    let first_mint = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32],
        outputs: vec![TxOut {
            amount: first_reward,
            lock: LockCommitment([0x11; 32]),
        }],
        pow_seed: [0x22; 32],
        pow_nonce: 1,
        minted_at: 71,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    let first_mint_id = pc_types::digest_mint(&first_mint);
    let persisted = pc_consensus::SupplyState {
        total_supply: first_reward as u128,
        mint_height: 1,
        last_mint_id: first_mint_id,
        pow_bits: pc_consensus::consts::POW_DEFAULT_BITS,
        last_minted_at_index: 71,
        last_final_emission_bucket: 0,
        pow_asert_ref_bucket: 0,
        pow_bits_min: pc_consensus::consts::POW_DEFAULT_BITS,
        pow_retarget_start_mint_height: 1,
        pow_retarget_start_anchor_index: 71,
    };
    std::fs::write(
        mempool_dir.join("supply_state.json"),
        serde_json::to_vec(&persisted)?,
    )?;

    let followup_mint = MintEvent {
        version: 1,
        prev_mint_id: first_mint_id,
        outputs: vec![TxOut {
            amount: second_reward,
            lock: LockCommitment([0x33; 32]),
        }],
        pow_seed: [0x44; 32],
        pow_nonce: 2,
        minted_at: 135,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };

    let mut stale = pc_consensus::SupplyState::default();
    assert!(stale.process_mint(&followup_mint, 135).is_err());

    refresh_supply_state_from_disk(&mempool_dir.to_string_lossy(), &mut stale);
    stale.process_mint(&followup_mint, 135)?;
    assert_eq!(stale.mint_height, 2);
    assert_eq!(stale.last_minted_at_index, 135);

    Ok(())
}

#[test]
fn load_supply_state_snapshot_uses_genesis_emission_bootstrap_bucket_for_empty_state() -> Result<()>
{
    let base = unique_tmp("bootstrap_bucket_empty_state");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir)?;

    let note = GenesisNote {
        version: 3,
        network_name: b"pc-bootstrap-bucket".to_vec(),
        seed: [0x66; 32],
        params: pc_types::GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 16,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 1_773_964_800,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf)?;
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf)?;

    let st = load_supply_state_snapshot(&mempool_dir.to_string_lossy());
    assert_eq!(st.pow_asert_ref_bucket, note.emission_bootstrap_bucket);
    assert_eq!(st.last_final_emission_bucket, 0);

    Ok(())
}

#[test]
fn mint_round_state_reconcile_expires_collecting_round_and_resets_to_searching() {
    let mut supply = pc_consensus::SupplyState::new();
    supply.mint_height = 4;
    supply.last_mint_id = [0xAA; 32];

    let mut round = MintRoundState {
        prev_mint_id: supply.last_mint_id,
        next_mint_height: supply.mint_height + 1,
        round_id: pc_consensus::mint_round_id_v1(&supply.last_mint_id, supply.mint_height + 1),
        phase: MintRoundPhase::Collecting,
        frozen_hit_bucket: Some(10),
        frozen_bits: Some(7),
        collection_deadline_bucket: Some(15),
        finalize_deadline_bucket: Some(20),
        best_candidate_id: Some([0x11; 32]),
        best_pow_hash: Some([0x22; 32]),
    };

    assert!(round.reconcile_with_supply(&supply, 21));
    assert_eq!(round.phase, MintRoundPhase::Searching);
    assert_eq!(round.prev_mint_id, supply.last_mint_id);
    assert_eq!(round.next_mint_height, supply.mint_height + 1);
    assert_eq!(
        round.round_id,
        pc_consensus::mint_round_id_v1(&supply.last_mint_id, supply.mint_height + 1)
    );
    assert_eq!(round.frozen_hit_bucket, None);
    assert_eq!(round.frozen_bits, None);
    assert_eq!(round.best_candidate_id, None);
    assert_eq!(round.best_pow_hash, None);
}

#[test]
fn mint_round_state_reconcile_resets_malformed_collecting_round() {
    let mut supply = pc_consensus::SupplyState::new();
    supply.mint_height = 2;
    supply.last_mint_id = [0xCC; 32];

    let mut round = MintRoundState {
        prev_mint_id: supply.last_mint_id,
        next_mint_height: supply.mint_height + 1,
        round_id: pc_consensus::mint_round_id_v1(&supply.last_mint_id, supply.mint_height + 1),
        phase: MintRoundPhase::Collecting,
        frozen_hit_bucket: Some(10),
        frozen_bits: None,
        collection_deadline_bucket: Some(15),
        finalize_deadline_bucket: Some(20),
        best_candidate_id: Some([0x11; 32]),
        best_pow_hash: Some([0x22; 32]),
    };

    assert!(round.reconcile_with_supply(&supply, 12));
    assert_eq!(round.phase, MintRoundPhase::Searching);
    assert_eq!(round.frozen_hit_bucket, None);
    assert_eq!(round.frozen_bits, None);
    assert_eq!(round.collection_deadline_bucket, None);
    assert_eq!(round.finalize_deadline_bucket, None);
}

#[test]
fn active_mint_target_bits_uses_frozen_bits_during_collecting() {
    let mut supply = pc_consensus::SupplyState::new();
    supply.pow_bits = 12;
    supply.pow_bits_min = 4;
    supply.pow_asert_ref_bucket = 100;
    let round = MintRoundState {
        prev_mint_id: supply.last_mint_id,
        next_mint_height: 1,
        round_id: pc_consensus::mint_round_id_v1(&supply.last_mint_id, 1),
        phase: MintRoundPhase::Collecting,
        frozen_hit_bucket: Some(111),
        frozen_bits: Some(9),
        collection_deadline_bucket: Some(116),
        finalize_deadline_bucket: Some(126),
        best_candidate_id: None,
        best_pow_hash: None,
    };

    assert_eq!(active_mint_target_bits(&supply, &round, 150), 9);
}

#[test]
fn validate_mint_timing_for_current_supply_enforces_collect_window_for_v2_mints() {
    let hit_bucket = 100;
    let mint = MintEvent {
        version: pc_types::MINT_VERSION_V2,
        prev_mint_id: [0u8; 32],
        outputs: vec![TxOut {
            amount: pc_consensus::consts::compute_mint_reward(1),
            lock: LockCommitment([0x42; 32]),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: [0x11; 32],
        hit_bucket,
        bits_used: 0,
    };

    assert!(validate_mint_timing_for_current_supply(
        &mint,
        pc_consensus::consts::emission_collect_deadline_bucket(hit_bucket) - 1,
    )
    .is_err());
    assert!(validate_mint_timing_for_current_supply(
        &mint,
        pc_consensus::consts::emission_collect_deadline_bucket(hit_bucket),
    )
    .is_ok());
}

#[test]
fn validate_mint_for_current_supply_rejects_legacy_mints() {
    let network_id = [0x11; 32];
    let supply = pc_consensus::SupplyState::new();
    let mut mint = MintEvent {
        version: 1,
        prev_mint_id: supply.last_mint_id,
        outputs: vec![TxOut {
            amount: pc_consensus::consts::compute_mint_reward(1),
            lock: LockCommitment([0x33; 32]),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    mint.pow_seed = pc_consensus::mint_pow_seed_v1(&network_id, &mint);

    let err = validate_mint_for_current_supply(&network_id, &supply, &mint)
        .expect_err("legacy mint must be rejected");
    assert!(err.to_string().contains("legacy_mint_not_supported"));
}
