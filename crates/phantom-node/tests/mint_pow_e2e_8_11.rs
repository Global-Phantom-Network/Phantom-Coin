// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use pc_codec::Decodable;
use pc_codec::Encodable;
use pc_consensus::attestor_pool::committee_precommit_message;
use pc_consensus::committee_vrf::{derive_epoch, derive_vrf_seed};
use pc_crypto::{
    attestor_recipient_id_from_bls, blake3_32, bls_keygen_from_ikm, bls_pop_prove, bls_sign,
    bls_vrf_prove, BlsKeypair,
};
use pc_types::{
    digest_genesis_note, digest_mint, AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV2,
    AnchorPayloadV3, GenesisNote, GenesisParams, GenesisValidatorV1, LockCommitment, MintEvent,
    MintTemplate, ParentList, TxOut, GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
    GENESIS_FEATURE_MINT_POW_BIND_V1, MINT_VERSION_V2,
};
use reqwest::Client;

static MINT_POW_E2E_8_11_SERIAL: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_mint_pow_e2e_{}_{}", prefix, nanos))
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

fn tcp_ephemeral_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral tcp");
    let p = l.local_addr().expect("local_addr for tcp ephemeral").port();
    drop(l);
    p
}

fn udp_ephemeral_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp");
    let p = s.local_addr().expect("local_addr for udp ephemeral").port();
    drop(s);
    p
}

async fn wait_http_ready(client: &Client, addr: &str, token: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if Instant::now() > deadline {
            panic!("server not ready in time");
        }
        let url = format!("http://{}/readyz", addr);
        match client.get(url).bearer_auth(token).send().await {
            Ok(resp) if resp.status().is_success() => return,
            _ => tokio::time::sleep(Duration::from_millis(80)).await,
        }
    }
}

async fn fetch_mint_template(client: &Client, addr: &str, token: &str) -> MintTemplate {
    let url = format!("http://{}/mint/template", addr);
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .expect("GET /mint/template");
    assert!(resp.status().is_success(), "mint/template must succeed");
    resp.json::<MintTemplate>()
        .await
        .expect("decode MintTemplate json")
}

fn decode_hex32(input: &str) -> [u8; 32] {
    let raw = hex::decode(input).expect("decode hex32");
    assert_eq!(raw.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

fn ready_hit_bucket() -> u64 {
    pc_consensus::current_emission_bucket()
        .saturating_sub(pc_consensus::consts::EMISSION_COLLECT_BUCKETS.saturating_add(1))
}

fn build_round_mint(
    network_id: [u8; 32],
    template: &MintTemplate,
    amount: u64,
    lock: [u8; 32],
    hit_bucket: u64,
) -> MintEvent {
    let mut mint = MintEvent {
        version: MINT_VERSION_V2,
        prev_mint_id: decode_hex32(&template.prev_mint_id),
        outputs: vec![TxOut {
            amount,
            lock: LockCommitment(lock),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: decode_hex32(&template.round_id),
        hit_bucket,
        bits_used: template.target_bits,
    };
    mint.pow_seed = pc_consensus::mint_pow_seed_v2(&network_id, &mint);
    mint
}

fn write_supply_state_pow_bits(mempool_dir: &std::path::Path, pow_bits: u8) {
    let mut supply_state = pc_consensus::SupplyState::new();
    supply_state.pow_bits = pow_bits;
    supply_state.pow_bits_min = pow_bits;
    let supply_json = serde_json::to_string(&supply_state).expect("serialize SupplyState");
    std::fs::write(mempool_dir.join("supply_state.json"), supply_json)
        .expect("write supply_state.json");
}

fn write_genesis_files_with_pow_bind(
    store_or_mempool_root: &std::path::Path,
    network_name: &str,
) -> (pc_types::NetworkId, [u8; 32], BlsKeypair) {
    let mempool_dir = store_or_mempool_root.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    let sk0 = blake3_32(network_name.as_bytes());

    // Deterministic BLS key used for genesis committee fallback (k=1 in these tests).
    // This breaks the circular dependency where `network_id` would otherwise depend on the BLS key.
    const IKM_DOMAIN: &[u8] = b"pc:test:genesis_validators:bls_ikm:v1\x01";
    let mut ikm_in = Vec::with_capacity(IKM_DOMAIN.len() + network_name.len() + 32);
    ikm_in.extend_from_slice(IKM_DOMAIN);
    ikm_in.extend_from_slice(network_name.as_bytes());
    ikm_in.extend_from_slice(&sk0);
    let ikm = blake3_32(&ikm_in);
    let bls_kp = bls_keygen_from_ikm(&ikm).expect("bls_keygen_from_ikm");
    let bls_pk = bls_kp.pk.to_bytes();
    let bls_pop = bls_pop_prove(&bls_kp.sk);

    let note = GenesisNote {
        version: 1,
        network_name: network_name.as_bytes().to_vec(),
        seed: blake3_32(format!("{}:seed", network_name).as_bytes()),
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 1,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1 | GENESIS_FEATURE_GENESIS_VALIDATORS_V1,
        },
        genesis_validators: vec![GenesisValidatorV1 {
            operator_id: blake3_32(b"op-0"),
            bls_pk,
            bls_pop,
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let expected_nid = digest_genesis_note(&note);
    let mut note_buf = Vec::with_capacity(note.encoded_len());
    note.encode(&mut note_buf).expect("encode genesis_note");
    atomic_write(&mempool_dir.join("genesis_note.bin"), &note_buf, true)
        .expect("write genesis_note.bin");

    atomic_write(&mempool_dir.join("seat_sk_0.bin"), &sk0, true).expect("write seat_sk_0.bin");

    let vrf_ctx = format!(
        "{{\"current_anchor_index\":0,\"epoch_len\":1,\"network_id\":\"{}\",\"last_anchor_id\":\"{}\"}}",
        hex::encode(expected_nid),
        hex::encode([0u8; 32])
    );
    atomic_write(
        &mempool_dir.join("vrf_rotation_ctx.json"),
        vrf_ctx.as_bytes(),
        true,
    )
    .expect("write vrf_rotation_ctx.json");

    let bls_pk_hex = hex::encode(bls_kp.pk.to_bytes());
    let epoch_len = 1u64;
    let current_anchor_index = 0u64;
    let epoch = derive_epoch(current_anchor_index, epoch_len);
    let seed = derive_vrf_seed(expected_nid, pc_types::AnchorId([0u8; 32]));
    let msg = {
        const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
        let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
        m.extend_from_slice(VRF_MSG_DOMAIN);
        m.extend_from_slice(&seed);
        m.extend_from_slice(&epoch.to_le_bytes());
        m
    };
    let (proof, _y) = bls_vrf_prove(&msg, &bls_kp.sk);
    let vrf_cands = serde_json::json!([
        {
            "recipient_id": hex::encode(attestor_recipient_id_from_bls(&bls_kp.pk)),
            "operator_id": hex::encode(blake3_32(b"op-0")),
            "bls_pk": bls_pk_hex,
            "bls_pop": hex::encode(bls_pop_prove(&bls_kp.sk)),
            "last_selected_at": 0u64,
            "attendance_recent_pct": 100u8,
            "vrf_proof": hex::encode(proof),
        }
    ]);
    atomic_write(
        &mempool_dir.join("vrf_candidates.json"),
        vrf_cands.to_string().as_bytes(),
        true,
    )
    .expect("write vrf_candidates.json");

    let committee_doc = format!(
        "{{\"epoch\":0,\"seats\":[{{\"bls_pk\":\"{}\"}}]}}",
        bls_pk_hex
    );
    atomic_write(
        &mempool_dir.join("vrf_committee.json"),
        committee_doc.as_bytes(),
        true,
    )
    .expect("write vrf_committee.json");

    (expected_nid, sk0, bls_kp)
}

fn write_genesis_toml(base: &std::path::Path, k: u8, pow_bits: u8) -> std::path::PathBuf {
    let genesis_note_raw = [0x42u8; 32];
    let commitment = blake3_32(&genesis_note_raw);
    let path = base.join(format!("genesis_k{}_pow{}.toml", k, pow_bits));
    let s = format!(
        "genesis_note = \"{}\"\ncommitment = \"{}\"\n\n[consensus]\nk = {}\npow_bits = {}\n",
        hex::encode(genesis_note_raw),
        hex::encode(commitment),
        k,
        pow_bits
    );
    std::fs::write(&path, s.as_bytes()).expect("write genesis.toml");
    path
}

async fn http_mint_submit(
    client: &Client,
    addr: &str,
    token: &str,
    mint: &MintEvent,
) -> reqwest::Response {
    let url = format!("http://{}/mint/submit", addr);
    client
        .post(url)
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "mint": {
                    "version": mint.version,
                    "prev_mint_id": hex::encode(mint.prev_mint_id),
                    "pow_seed": hex::encode(mint.pow_seed),
                    "pow_nonce": mint.pow_nonce,
                    "minted_at": 0,
                    "round_id": hex::encode(mint.round_id),
                    "hit_bucket": mint.hit_bucket,
                    "bits_used": mint.bits_used,
                    "outputs": mint.outputs.iter().map(|o| serde_json::json!({
                        "amount": o.amount,
                        "lock": hex::encode(o.lock.0),
                    })).collect::<Vec<_>>(),
                }
            })
            .to_string(),
        )
        .send()
        .await
        .expect("/mint/submit resp")
}

fn persist_payload_in_store(store_dir: &std::path::Path, p: &AnchorPayloadV2) {
    let root = pc_types::payload_merkle_root_v2(p);
    let payloads_dir = store_dir.join("payloads");
    std::fs::create_dir_all(&payloads_dir).expect("create store payloads dir");
    let path = payloads_dir.join(format!("{}.bin", hex::encode(root)));
    let mut buf = Vec::with_capacity(p.encoded_len());
    p.encode(&mut buf).expect("encode payload for store");
    atomic_write(&path, &buf, true).expect("write payload into store");
}

fn spawn_p2p_listen(
    store_dir: &std::path::Path,
    quic_addr: &str,
    cert_file: &std::path::Path,
    genesis_toml: &std::path::Path,
    tx_proposer: bool,
    pow_miner: bool,
    mint_amount: u64,
    mint_lock_hex: &str,
) -> std::process::Child {
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let mut cmd = Command::new(bin);
    if tx_proposer {
        let updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time since UNIX_EPOCH")
            .as_secs();
        let control = serde_json::json!({
            "version": 1,
            "kill_switch": false,
            "maintenance": false,
            "manual_disable": false,
            "auto_reenable": true,
            "reason": "e2e-enable-proposer",
            "updated_at": updated_at,
            "cooldown_until": 0,
            "last_changed_by": "test",
        });
        atomic_write(
            &store_dir.join("validator_control.json"),
            control.to_string().as_bytes(),
            true,
        )
        .expect("write validator_control.json");
    }
    cmd.arg("p2p-quic-listen")
        .arg("--addr")
        .arg(quic_addr)
        .arg("--store-dir")
        .arg(store_dir.to_string_lossy().to_string())
        .arg("--cert-out")
        .arg(cert_file.to_string_lossy().to_string())
        .arg("--genesis")
        .arg(genesis_toml.to_string_lossy().to_string())
        .arg("--k")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if tx_proposer {
        cmd.arg("--tx-proposer");
    }

    if pow_miner {
        cmd.arg("--pow-miner")
            .arg("--mint-amount")
            .arg(mint_amount.to_string())
            .arg("--mint-lock")
            .arg(mint_lock_hex);
    }

    cmd.spawn().expect("spawn phantom-node p2p-quic-listen")
}

fn wait_for_file(path: &std::path::Path, timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            panic!("timeout waiting for file");
        }
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn write_vec_pc_codec<T: pc_codec::Encodable + Clone>(path: &std::path::Path, v: &[T]) {
    let mut buf = Vec::new();
    pc_codec::Encodable::encode(&v.to_vec(), &mut buf).expect("encode vec");
    std::fs::write(path, &buf).expect("write vec file");
}

fn apply_payload_and_state_root(
    st: &mut pc_state::UtxoState<pc_state::InMemoryBackend>,
    payload: &AnchorPayloadV2,
    network_id: [u8; 32],
    anchor_index: u64,
) -> [u8; 32] {
    let skipped = if pc_state::verify_microtx_sigs_parallel(&payload.micro_txs, &network_id) {
        st.apply_payload_v2_tolerant_presigned(
            &payload.mints,
            &payload.micro_txs,
            &[],
            anchor_index,
            pc_consensus::consts::MATURITY_L1,
            &network_id,
        )
        .expect("apply valid payload presigned")
    } else {
        st.apply_payload_v2_tolerant(
            &payload.mints,
            &payload.micro_txs,
            &[],
            anchor_index,
            pc_consensus::consts::MATURITY_L1,
            &network_id,
        )
        .expect("apply valid payload")
    };
    assert!(skipped.is_empty(), "valid payload must not skip microtxs");
    st.root()
}

fn compute_post_state_root(payload: &AnchorPayloadV2, network_id: [u8; 32]) -> [u8; 32] {
    let mut st = pc_state::UtxoState::new(pc_state::InMemoryBackend::new());
    apply_payload_and_state_root(&mut st, payload, network_id, 1)
}

fn payload_root_from_path(path: &std::path::Path) -> [u8; 32] {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("payload filename stem");
    let bytes = hex::decode(name).expect("decode payload root hex");
    assert_eq!(bytes.len(), 32, "payload filename must encode 32-byte root");
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    root
}

fn decode_payload_v2_compatible(buf: &[u8]) -> Option<AnchorPayloadV2> {
    if let Ok(payload) = AnchorPayloadV3::decode(&mut &buf[..]) {
        if payload.null_mint {
            return None;
        }
        return Some(AnchorPayloadV2 {
            version: 2,
            micro_txs: payload.micro_txs,
            mints: payload.mints,
            claims: payload.claims,
            evidences: payload.evidences,
            payout_root: payload.payout_root,
            genesis_note: payload.genesis_note,
        });
    }
    AnchorPayloadV2::decode(&mut &buf[..]).ok()
}

fn collect_mint_payloads_from_store(
    store_dir: &std::path::Path,
) -> Vec<([u8; 32], AnchorPayloadV2)> {
    let mut payloads: Vec<([u8; 32], AnchorPayloadV2)> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    let legacy_dir = store_dir.join("payloads");
    if let Ok(rd) = std::fs::read_dir(&legacy_dir) {
        for ent in rd.flatten() {
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !name.ends_with(".bin") {
                continue;
            }
            let root = payload_root_from_path(&path);
            if !seen.insert(root) {
                continue;
            }
            let Ok(buf) = std::fs::read(&path) else {
                continue;
            };
            let Some(payload) = decode_payload_v2_compatible(&buf) else {
                continue;
            };
            if payload.mints.len() == 1 {
                payloads.push((root, payload));
            }
        }
    }

    let segments_dir = store_dir.join("payload_segments");
    let mut segments: Vec<std::path::PathBuf> = match std::fs::read_dir(&segments_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => Vec::new(),
    };
    segments.sort();
    for seg_path in segments {
        let Ok(buf) = std::fs::read(&seg_path) else {
            continue;
        };
        if buf.len() < 5 || &buf[..4] != b"PCSG" || buf[4] != 1 {
            continue;
        }
        let mut pos: usize = 5;
        while pos + 36 <= buf.len() {
            let mut root = [0u8; 32];
            root.copy_from_slice(&buf[pos..pos + 32]);
            let data_len =
                u32::from_le_bytes([buf[pos + 32], buf[pos + 33], buf[pos + 34], buf[pos + 35]])
                    as usize;
            let total_len = 36usize.saturating_add(data_len).saturating_add(4);
            if pos + total_len > buf.len() {
                break;
            }
            let data = &buf[pos + 36..pos + 36 + data_len];
            if seen.insert(root) {
                if let Some(payload) = decode_payload_v2_compatible(data) {
                    if payload.mints.len() == 1 {
                        payloads.push((root, payload));
                    }
                }
            }
            pos += total_len;
        }
    }

    payloads.sort_by(|a, b| a.0.cmp(&b.0));
    payloads
}

fn wait_for_n_mint_payloads(
    store_dir: &std::path::Path,
    n: usize,
    timeout_secs: u64,
) -> Vec<([u8; 32], AnchorPayloadV2)> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            panic!("timeout waiting for mint payloads");
        }
        let mut payloads = collect_mint_payloads_from_store(store_dir);
        if payloads.len() >= n {
            payloads.truncate(n);
            return payloads;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn inject_headers_file(
    quic_addr: &str,
    cert_file: &std::path::Path,
    headers_file: &std::path::Path,
) {
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let out = Command::new(bin)
        .arg("p2p-inject-headers")
        .arg("--addr")
        .arg(quic_addr)
        .arg("--cert-file")
        .arg(cert_file.to_string_lossy().to_string())
        .arg("--headers-file")
        .arg(headers_file.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("inject headers output");
    if !out.status.success() {
        panic!(
            "inject headers failed: status={:?} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn build_final_header(
    network_id: [u8; 32],
    payload_hash: [u8; 32],
    state_root: [u8; 32],
    vote_epoch: u64,
    bls_kp: &BlsKeypair,
) -> AnchorHeader {
    let mut parents = ParentList::default();
    parents
        .push(AnchorId([1u8; 32]))
        .expect("push parent into ParentList");
    let mut hdr = AnchorHeader {
        version: 5,
        shard_id: 0,
        parents,
        payload_hash,
        creator_index: 0,
        vote_mask: 1,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id,
        vote_epoch,
        vote_round: 0,
        attest_sig: None,
        state_root: Some(state_root),
    };
    let msg = committee_precommit_message(
        &network_id,
        vote_epoch,
        &hdr.vote_target_hash(),
        &state_root,
    );
    let sig = bls_sign(&msg, &bls_kp.sk);
    hdr.attest_sig = Some(sig);
    hdr
}

#[tokio::test]
async fn e2e_8_pow_miner_produces_valid_mint_chain() {
    let _serial = MINT_POW_E2E_8_11_SERIAL.lock().await;
    let base = unique_tmp("t8");
    std::fs::create_dir_all(&base).expect("create base dir");

    let store_dir = base.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");

    let (nid, _sk0, bls_kp) = write_genesis_files_with_pow_bind(&store_dir, "e2e_8_pow_miner");
    write_supply_state_pow_bits(&store_dir.join("mempool"), 0);

    let genesis_toml = write_genesis_toml(&base, 1, 0);

    let udp_port = udp_ephemeral_port();
    let quic_addr = format!("127.0.0.1:{}", udp_port);
    let cert_file = base.join("cert.der");

    let mint_amount = pc_consensus::consts::compute_mint_reward(1);
    let mint_lock_hex = hex::encode([7u8; 32]);

    let mut child = spawn_p2p_listen(
        &store_dir,
        &quic_addr,
        &cert_file,
        &genesis_toml,
        true,
        true,
        mint_amount,
        &mint_lock_hex,
    );

    wait_for_file(&cert_file, 8);

    let first_batch = wait_for_n_mint_payloads(&store_dir, 1, 8);
    let (first_root, first_payload) = first_batch[0].clone();

    let mut local_state = pc_state::UtxoState::new(pc_state::InMemoryBackend::new());
    let first_state_root = apply_payload_and_state_root(&mut local_state, &first_payload, nid, 1);
    let first_header = build_final_header(nid, first_root, first_state_root, 0, &bls_kp);
    let first_headers_file = base.join("headers_first_mint.bin");
    write_vec_pc_codec(&first_headers_file, &[first_header]);
    inject_headers_file(&quic_addr, &cert_file, &first_headers_file);

    let anchor_index_path = store_dir.join("anchor_index");
    let anchor_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > anchor_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("anchor_index did not advance to 1 after first mint finalization");
        }
        if let Ok(s) = std::fs::read_to_string(&anchor_index_path) {
            if s.trim() == "1" {
                break;
            }
        }
        if let Ok(Some(st)) = child.try_wait() {
            panic!("p2p-quic-listen exited early: {st:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let mint_payloads = wait_for_n_mint_payloads(&store_dir, 2, 12);

    let mut mints: Vec<MintEvent> = Vec::new();
    for (_root, payload) in mint_payloads.iter() {
        mints.push(payload.mints[0].clone());
    }

    let mut start_idx: Option<usize> = None;
    for (i, m) in mints.iter().enumerate() {
        if m.prev_mint_id == [0u8; 32] {
            start_idx = Some(i);
            break;
        }
    }
    let Some(start) = start_idx else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("no mint with prev_mint_id=0 found");
    };

    let m0 = mints[start].clone();
    let id0 = digest_mint(&m0);

    let mut next: Option<MintEvent> = None;
    for m in mints.iter() {
        if m.prev_mint_id == id0 {
            next = Some(m.clone());
            break;
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(next.is_some(), "mint chain must link via prev_mint_id");
}

#[tokio::test]
async fn e2e_9_http_rejects_pow_theft_same_seed_nonce_different_outputs() {
    let _serial = MINT_POW_E2E_8_11_SERIAL.lock().await;
    let base = unique_tmp("t9");
    std::fs::create_dir_all(&base).expect("create base dir");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    let (nid, _sk0, _bls_kp) = write_genesis_files_with_pow_bind(&base, "e2e_9_http_pow_theft");

    let port = tcp_ephemeral_port();
    let addr = format!("127.0.0.1:{}", port);
    let token = "e2e_9_token";

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let genesis_note_path = mempool_dir.join("genesis_note.bin");
    write_supply_state_pow_bits(&mempool_dir, 0);
    let mut child = Command::new(bin)
        .arg("status-serve")
        .arg("--addr")
        .arg(addr.clone())
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .arg("--genesis-note")
        .arg(genesis_note_path.to_string_lossy().to_string())
        .arg("--auth-token")
        .arg(token)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");

    let client_http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest client");

    wait_http_ready(&client_http, &addr, token, 15).await;

    let amount = pc_consensus::consts::compute_mint_reward(1);
    let lock1 = [1u8; 32];
    let lock2 = [2u8; 32];
    let tpl = fetch_mint_template(&client_http, &addr, token).await;
    let mint_ok = build_round_mint(nid, &tpl, amount, lock1, ready_hit_bucket());

    let resp_ok = http_mint_submit(&client_http, &addr, token, &mint_ok).await;
    let resp_ok_status = resp_ok.status();
    let resp_ok_body = resp_ok.text().await.expect("read first mint response body");
    assert!(
        resp_ok_status.is_success(),
        "first mint must be accepted: status={} body={}",
        resp_ok_status,
        resp_ok_body
    );

    let mint_theft = MintEvent {
        outputs: vec![TxOut {
            amount,
            lock: LockCommitment(lock2),
        }],
        ..mint_ok.clone()
    };
    let resp_bad = http_mint_submit(&client_http, &addr, token, &mint_theft).await;
    assert!(
        resp_bad.status().is_client_error(),
        "pow theft must be rejected"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn e2e_10_rpc_and_gossip_accept_same_valid_mint() {
    let _serial = MINT_POW_E2E_8_11_SERIAL.lock().await;
    let base = unique_tmp("t10");
    std::fs::create_dir_all(&base).expect("create base dir");

    let store_dir = base.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");

    let (nid, _sk0, bls_kp) = write_genesis_files_with_pow_bind(&store_dir, "e2e_10_rpc_gossip_ok");

    // pow_bits=0 auch in store_dir/mempool setzen, damit p2p-quic-listen die gleichen bits verwendet
    write_supply_state_pow_bits(&store_dir.join("mempool"), 0);

    let genesis_toml = write_genesis_toml(&base, 1, 0);

    let udp_port = udp_ephemeral_port();
    let quic_addr = format!("127.0.0.1:{}", udp_port);
    let cert_file = base.join("cert.der");

    let mut p2p_child = spawn_p2p_listen(
        &store_dir,
        &quic_addr,
        &cert_file,
        &genesis_toml,
        false,
        false,
        0,
        "",
    );

    wait_for_file(&cert_file, 8);

    if let Ok(Some(st)) = p2p_child.try_wait() {
        panic!("p2p-quic-listen exited early: {st:?}");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");
    {
        let src = store_dir.join("mempool").join("genesis_note.bin");
        let dst = mempool_dir.join("genesis_note.bin");
        let buf = std::fs::read(src).expect("read genesis_note.bin");
        atomic_write(&dst, &buf, true).expect("write genesis_note.bin");
    }

    let port = tcp_ephemeral_port();
    let addr = format!("127.0.0.1:{}", port);
    let token = "e2e_10_token";
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let genesis_note_path = mempool_dir.join("genesis_note.bin");
    write_supply_state_pow_bits(&mempool_dir, 0);
    let mut http_child = Command::new(bin)
        .arg("status-serve")
        .arg("--addr")
        .arg(addr.clone())
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .arg("--genesis-note")
        .arg(genesis_note_path.to_string_lossy().to_string())
        .arg("--auth-token")
        .arg(token)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");

    let client_http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest client");
    wait_http_ready(&client_http, &addr, token, 15).await;

    let amount = pc_consensus::consts::compute_mint_reward(1);
    let lock = [9u8; 32];
    let tpl = fetch_mint_template(&client_http, &addr, token).await;
    let mint = build_round_mint(nid, &tpl, amount, lock, ready_hit_bucket());

    let resp_ok = http_mint_submit(&client_http, &addr, token, &mint).await;
    let resp_ok_status = resp_ok.status();
    let resp_ok_body = resp_ok.text().await.expect("read rpc mint response body");
    assert!(
        resp_ok_status.is_success(),
        "rpc must accept valid mint: status={} body={}",
        resp_ok_status,
        resp_ok_body
    );

    let payload = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![mint.clone()],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
    };
    let root = pc_types::payload_merkle_root_v2(&payload);
    persist_payload_in_store(&store_dir, &payload);
    let state_root = compute_post_state_root(&payload, nid);

    let payloads_file = base.join("payloads.bin");
    write_vec_pc_codec(&payloads_file, &[payload]);

    let headers_file = base.join("headers.bin");
    let hdr = build_final_header(nid, root, state_root, 0, &bls_kp);
    write_vec_pc_codec(&headers_file, &[hdr]);

    let out_inj_pl = Command::new(bin)
        .arg("p2p-inject-payloads")
        .arg("--addr")
        .arg(&quic_addr)
        .arg("--cert-file")
        .arg(cert_file.to_string_lossy().to_string())
        .arg("--payloads-file")
        .arg(payloads_file.to_string_lossy().to_string())
        .arg("--with-payloads")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("inject payloads output");
    if !out_inj_pl.status.success() {
        panic!(
            "inject payloads failed: status={:?} stdout={} stderr={}",
            out_inj_pl.status,
            String::from_utf8_lossy(&out_inj_pl.stdout),
            String::from_utf8_lossy(&out_inj_pl.stderr)
        );
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let out_inj_hdr = Command::new(bin)
        .arg("p2p-inject-headers")
        .arg("--addr")
        .arg(&quic_addr)
        .arg("--cert-file")
        .arg(cert_file.to_string_lossy().to_string())
        .arg("--headers-file")
        .arg(headers_file.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("inject headers output");
    if !out_inj_hdr.status.success() {
        panic!(
            "inject headers failed: status={:?} stdout={} stderr={}",
            out_inj_hdr.status,
            String::from_utf8_lossy(&out_inj_hdr.stdout),
            String::from_utf8_lossy(&out_inj_hdr.stderr)
        );
    }

    let anchor_index_path = store_dir.join("anchor_index");
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut next_inject_at = Instant::now() + Duration::from_secs(1);
    let mut inject_backoff_secs: u64 = 1;
    let mut injects_done: u64 = 0;
    loop {
        if Instant::now() > deadline {
            let _ = http_child.kill();
            let _ = http_child.wait();
            let _ = p2p_child.kill();
            let _ = p2p_child.wait();
            panic!("anchor_index did not advance");
        }
        if let Ok(s) = std::fs::read_to_string(&anchor_index_path) {
            if s.trim() == "1" {
                break;
            }
        }
        if let Ok(Some(st)) = p2p_child.try_wait() {
            let _ = http_child.kill();
            let _ = http_child.wait();
            panic!("p2p-quic-listen exited early: {st:?}");
        }

        if injects_done < 8 && Instant::now() >= next_inject_at {
            let out_inj_pl = Command::new(bin)
                .arg("p2p-inject-payloads")
                .arg("--addr")
                .arg(&quic_addr)
                .arg("--cert-file")
                .arg(cert_file.to_string_lossy().to_string())
                .arg("--payloads-file")
                .arg(payloads_file.to_string_lossy().to_string())
                .arg("--with-payloads")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("inject payloads output");
            if !out_inj_pl.status.success() {
                panic!(
                    "inject payloads failed: status={:?} stdout={} stderr={}",
                    out_inj_pl.status,
                    String::from_utf8_lossy(&out_inj_pl.stdout),
                    String::from_utf8_lossy(&out_inj_pl.stderr)
                );
            }

            tokio::time::sleep(Duration::from_millis(200)).await;

            let out_inj_hdr = Command::new(bin)
                .arg("p2p-inject-headers")
                .arg("--addr")
                .arg(&quic_addr)
                .arg("--cert-file")
                .arg(cert_file.to_string_lossy().to_string())
                .arg("--headers-file")
                .arg(headers_file.to_string_lossy().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("inject headers output");
            if !out_inj_hdr.status.success() {
                panic!(
                    "inject headers failed: status={:?} stdout={} stderr={}",
                    out_inj_hdr.status,
                    String::from_utf8_lossy(&out_inj_hdr.stdout),
                    String::from_utf8_lossy(&out_inj_hdr.stderr)
                );
            }

            injects_done = injects_done.saturating_add(1);
            next_inject_at = Instant::now() + Duration::from_secs(inject_backoff_secs);
            inject_backoff_secs = (inject_backoff_secs.saturating_mul(2)).min(10);
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    let _ = http_child.kill();
    let _ = http_child.wait();
    let _ = p2p_child.kill();
    let _ = p2p_child.wait();
}

#[tokio::test]
async fn e2e_11_rpc_and_gossip_reject_invalid_seed_and_nonce() {
    let _serial = MINT_POW_E2E_8_11_SERIAL.lock().await;
    let base = unique_tmp("t11");
    std::fs::create_dir_all(&base).expect("create base dir");

    let store_dir = base.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");

    let (nid, _sk0, bls_kp) = write_genesis_files_with_pow_bind(&store_dir, "e2e_11_reject");

    let genesis_toml_pow0 = write_genesis_toml(&base, 1, 0);

    let udp_port = udp_ephemeral_port();
    let quic_addr = format!("127.0.0.1:{}", udp_port);
    let cert_file = base.join("cert.der");

    let mut p2p_child = spawn_p2p_listen(
        &store_dir,
        &quic_addr,
        &cert_file,
        &genesis_toml_pow0,
        false,
        false,
        0,
        "",
    );

    wait_for_file(&cert_file, 8);

    if let Ok(Some(st)) = p2p_child.try_wait() {
        panic!("p2p-quic-listen exited early: {st:?}");
    }

    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");
    {
        let src = store_dir.join("mempool").join("genesis_note.bin");
        let dst = mempool_dir.join("genesis_note.bin");
        let buf = std::fs::read(src).expect("read genesis_note.bin");
        atomic_write(&dst, &buf, true).expect("write genesis_note.bin");
    }

    let port = tcp_ephemeral_port();
    let addr = format!("127.0.0.1:{}", port);
    let token = "e2e_11_token";
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let genesis_note_path = mempool_dir.join("genesis_note.bin");
    write_supply_state_pow_bits(&mempool_dir, 8);
    let mut http_child = Command::new(bin)
        .arg("status-serve")
        .arg("--addr")
        .arg(addr.clone())
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .arg("--genesis-note")
        .arg(genesis_note_path.to_string_lossy().to_string())
        .arg("--auth-token")
        .arg(token)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");

    let client_http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest client");
    wait_http_ready(&client_http, &addr, token, 15).await;

    let amount = pc_consensus::consts::compute_mint_reward(1);
    let lock = [0xAAu8; 32];
    let tpl = fetch_mint_template(&client_http, &addr, token).await;
    let mint_template = build_round_mint(nid, &tpl, amount, lock, ready_hit_bucket());

    let bad_seed = [0u8; 32];

    let mint_bad_seed_submit = MintEvent {
        pow_seed: bad_seed,
        ..mint_template.clone()
    };
    let resp_bad_seed = http_mint_submit(&client_http, &addr, token, &mint_bad_seed_submit).await;
    assert!(
        resp_bad_seed.status().is_client_error(),
        "rpc must reject invalid seed"
    );

    let mint_bad_seed = MintEvent {
        pow_seed: bad_seed,
        pow_nonce: 0,
        ..mint_template.clone()
    };

    let payload_bad_seed = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![mint_bad_seed],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
    };
    let root_bad_seed = pc_types::payload_merkle_root_v2(&payload_bad_seed);
    persist_payload_in_store(&store_dir, &payload_bad_seed);

    let payloads_file = base.join("payloads_bad_seed.bin");
    write_vec_pc_codec(&payloads_file, &[payload_bad_seed]);

    let headers_file = base.join("headers_bad_seed.bin");
    let hdr = build_final_header(nid, root_bad_seed, [0x22u8; 32], 0, &bls_kp);
    write_vec_pc_codec(&headers_file, &[hdr]);

    let st_inj_pl = Command::new(bin)
        .arg("p2p-inject-payloads")
        .arg("--addr")
        .arg(&quic_addr)
        .arg("--cert-file")
        .arg(cert_file.to_string_lossy().to_string())
        .arg("--payloads-file")
        .arg(payloads_file.to_string_lossy().to_string())
        .arg("--with-payloads")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("inject payloads status");
    assert!(st_inj_pl.success(), "inject payloads must succeed");

    let st_inj_hdr = Command::new(bin)
        .arg("p2p-inject-headers")
        .arg("--addr")
        .arg(&quic_addr)
        .arg("--cert-file")
        .arg(cert_file.to_string_lossy().to_string())
        .arg("--headers-file")
        .arg(headers_file.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("inject headers status");
    assert!(st_inj_hdr.success(), "inject headers must succeed");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let anchor_index_path = store_dir.join("anchor_index");
    if let Ok(s) = std::fs::read_to_string(&anchor_index_path) {
        assert_ne!(s.trim(), "1", "invalid seed must not be applied");
    }

    let seed_ok = mint_template.pow_seed;
    let mut bad_nonce: u64 = 0;
    loop {
        let h = pc_consensus::pow_hash(&seed_ok, bad_nonce);
        if !pc_consensus::pow_meets(mint_template.bits_used, &h) {
            break;
        }
        bad_nonce = bad_nonce.wrapping_add(1);
    }

    let mint_bad_nonce = MintEvent {
        pow_nonce: bad_nonce,
        ..mint_template.clone()
    };
    let resp_bad_nonce = http_mint_submit(&client_http, &addr, token, &mint_bad_nonce).await;
    assert!(
        resp_bad_nonce.status().is_client_error(),
        "rpc must reject invalid nonce"
    );

    let _ = http_child.kill();
    let _ = http_child.wait();
    let _ = p2p_child.kill();
    let _ = p2p_child.wait();
}
