#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pc_codec::Encodable;
use pc_consensus::attestor_pool::committee_precommit_message;
use pc_consensus::committee_vrf::{derive_epoch, derive_vrf_seed};
use pc_crypto::{
    attestor_recipient_id_from_bls, blake3_32, bls_keygen_from_ikm, bls_pop_prove, bls_sign,
    bls_vrf_prove, BlsKeypair,
};
use pc_types::{
    digest_genesis_note, AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV2, GenesisNote,
    GenesisParams, GenesisValidatorV1, LockCommitment, MintEvent, MintTemplate, ParentList, TxOut,
    GENESIS_FEATURE_GENESIS_VALIDATORS_V1, GENESIS_FEATURE_MINT_POW_BIND_V1, MINT_VERSION_V2,
};
use reqwest::Client;

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_mint_pow_e2e_{}_{}", prefix, nanos))
}

fn tcp_ephemeral_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral tcp");
    let p = l.local_addr().expect("local_addr for tcp ephemeral").port();
    drop(l);
    p
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
    prev_mint_id: [u8; 32],
    mint_height: u64,
    amount: u64,
    lock: [u8; 32],
    hit_bucket: u64,
    bits_used: u8,
) -> MintEvent {
    let mut mint = MintEvent {
        version: MINT_VERSION_V2,
        prev_mint_id,
        outputs: vec![TxOut {
            amount,
            lock: LockCommitment(lock),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: pc_consensus::mint_round_id_v1(&prev_mint_id, mint_height),
        hit_bucket,
        bits_used,
    };
    mint.pow_seed = pc_consensus::mint_pow_seed_v2(&network_id, &mint);
    mint
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

fn read_anchor_index_or_zero(store_dir: &std::path::Path) -> u64 {
    let p = store_dir.join("anchor_index");
    match std::fs::read_to_string(&p) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or(0),
        Err(_) => 0,
    }
}

fn wait_anchor_index_eq_checked(
    store_dir: &std::path::Path,
    want: u64,
    timeout_secs: u64,
    child: &mut std::process::Child,
    quic_addr: &str,
    cert_file: &std::path::Path,
    headers_file: &std::path::Path,
) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut next_inject_at = Instant::now();
    let mut inject_backoff_secs: u64 = 1;
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("anchor_index did not reach expected value");
        }
        if read_anchor_index_or_zero(store_dir) == want {
            return;
        }
        if let Ok(Some(st)) = child.try_wait() {
            panic!("p2p-quic-listen exited early: {st:?}");
        }
        if Instant::now() >= next_inject_at {
            inject_headers(quic_addr, cert_file, headers_file);
            next_inject_at = Instant::now() + Duration::from_secs(inject_backoff_secs);
            inject_backoff_secs = (inject_backoff_secs.saturating_mul(2)).min(10);
        }
        std::thread::sleep(Duration::from_millis(80));
    }
}

fn wait_anchor_index_never_reaches(store_dir: &std::path::Path, forbidden: u64, timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            return;
        }
        if read_anchor_index_or_zero(store_dir) == forbidden {
            panic!("anchor_index reached forbidden value");
        }
        std::thread::sleep(Duration::from_millis(80));
    }
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

fn write_genesis_files_with_pow_bind(
    store_dir: &std::path::Path,
    network_name: &str,
) -> (pc_types::NetworkId, [u8; 32], BlsKeypair) {
    let mempool_dir = store_dir.join("mempool");
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

    let nid = digest_genesis_note(&note);

    let mut note_buf = Vec::with_capacity(note.encoded_len());
    note.encode(&mut note_buf).expect("encode genesis_note");
    atomic_write(&mempool_dir.join("genesis_note.bin"), &note_buf, true)
        .expect("write genesis_note.bin");

    atomic_write(&mempool_dir.join("seat_sk_0.bin"), &sk0, true).expect("write seat_sk_0.bin");

    let vrf_ctx = format!(
        "{{\"current_anchor_index\":0,\"epoch_len\":1,\"network_id\":\"{}\",\"last_anchor_id\":\"{}\"}}",
        hex::encode(nid),
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
    let seed = derive_vrf_seed(nid, pc_types::AnchorId([0u8; 32]));
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

    (nid, sk0, bls_kp)
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

fn spawn_p2p_listen(
    store_dir: &std::path::Path,
    quic_addr: &str,
    cert_file: &std::path::Path,
    genesis_toml: &std::path::Path,
) -> std::process::Child {
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let mut cmd = Command::new(bin);
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

    cmd.spawn().expect("spawn phantom-node p2p-quic-listen")
}

fn inject_payloads(quic_addr: &str, cert_file: &std::path::Path, payloads_file: &std::path::Path) {
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let out = Command::new(bin)
        .arg("p2p-inject-payloads")
        .arg("--addr")
        .arg(quic_addr)
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
    if !out.status.success() {
        panic!(
            "inject payloads failed: status={:?} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn inject_headers(quic_addr: &str, cert_file: &std::path::Path, headers_file: &std::path::Path) {
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

fn compute_post_state_root(payload: &AnchorPayloadV2, network_id: [u8; 32]) -> [u8; 32] {
    let mut st = pc_state::UtxoState::new(pc_state::InMemoryBackend::new());
    let skipped = if pc_state::verify_microtx_sigs_parallel(&payload.micro_txs, &network_id) {
        st.apply_payload_v2_tolerant_presigned(
            &payload.mints,
            &payload.micro_txs,
            &[],
            1,
            pc_consensus::consts::MATURITY_L1,
            &network_id,
        )
        .expect("apply valid payload presigned")
    } else {
        st.apply_payload_v2_tolerant(
            &payload.mints,
            &payload.micro_txs,
            &[],
            1,
            pc_consensus::consts::MATURITY_L1,
            &network_id,
        )
        .expect("apply valid payload")
    };
    assert!(skipped.is_empty(), "valid payload must not skip microtxs");
    st.root()
}

fn build_final_header(
    network_id: [u8; 32],
    payload_hash: [u8; 32],
    state_root: [u8; 32],
    parent_id: [u8; 32],
    vote_epoch: u64,
    bls_kp: &BlsKeypair,
) -> AnchorHeader {
    let mut parents = ParentList::default();
    parents
        .push(AnchorId(parent_id))
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
async fn e2e_12_fork_race_same_prev_mint_id_only_one_wins() {
    let base = unique_tmp("t12");
    std::fs::create_dir_all(&base).expect("create base dir");

    let store_dir = base.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");

    let (nid, _sk0, bls_kp) = write_genesis_files_with_pow_bind(&store_dir, "e2e_12_fork_race");
    let genesis_toml = write_genesis_toml(&base, 1, 0);

    let udp_port = udp_ephemeral_port();
    let quic_addr = format!("127.0.0.1:{}", udp_port);
    let cert_file = base.join("cert.der");

    let mut child = spawn_p2p_listen(&store_dir, &quic_addr, &cert_file, &genesis_toml);
    wait_for_file(&cert_file, 8);

    let amount_1 = pc_consensus::consts::compute_mint_reward(1);

    let mint_a = build_round_mint(
        nid,
        [0u8; 32],
        1,
        amount_1,
        [0x11u8; 32],
        ready_hit_bucket(),
        0,
    );
    let payload_a = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![mint_a.clone()],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
    };
    let root_a = pc_types::payload_merkle_root_v2(&payload_a);
    let state_root_a = compute_post_state_root(&payload_a, nid);
    persist_payload_in_store(&store_dir, &payload_a);

    let mint_b = build_round_mint(
        nid,
        [0u8; 32],
        1,
        amount_1,
        [0x22u8; 32],
        ready_hit_bucket(),
        0,
    );
    let payload_b = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![mint_b.clone()],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
    };
    let root_b = pc_types::payload_merkle_root_v2(&payload_b);
    persist_payload_in_store(&store_dir, &payload_b);

    let payloads_file_a = base.join("payloads_a.bin");
    write_vec_pc_codec(&payloads_file_a, &[payload_a]);
    inject_payloads(&quic_addr, &cert_file, &payloads_file_a);

    std::thread::sleep(Duration::from_millis(200));

    let hdr_a = build_final_header(nid, root_a, state_root_a, [1u8; 32], 0, &bls_kp);
    let headers_file_a = base.join("headers_a.bin");
    write_vec_pc_codec(&headers_file_a, &[hdr_a]);
    wait_anchor_index_eq_checked(
        &store_dir,
        1,
        120,
        &mut child,
        &quic_addr,
        &cert_file,
        &headers_file_a,
    );

    let payloads_file_b = base.join("payloads_b.bin");
    write_vec_pc_codec(&payloads_file_b, &[payload_b]);
    inject_payloads(&quic_addr, &cert_file, &payloads_file_b);

    std::thread::sleep(Duration::from_millis(200));

    let hdr_b = build_final_header(nid, root_b, [0x22u8; 32], [2u8; 32], 0, &bls_kp);
    let headers_file_b = base.join("headers_b.bin");
    write_vec_pc_codec(&headers_file_b, &[hdr_b]);
    inject_headers(&quic_addr, &cert_file, &headers_file_b);

    wait_anchor_index_never_reaches(&store_dir, 2, 3);

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn e2e_13_low_difficulty_still_no_reuse_possible() {
    let base = unique_tmp("t13");
    std::fs::create_dir_all(&base).expect("create base dir");
    let (nid, _sk0, _bls_kp) = write_genesis_files_with_pow_bind(&base, "e2e_13_low_bits_abuse");
    let mempool_dir = base.join("mempool");

    let mut supply_state = pc_consensus::SupplyState::new();
    supply_state.pow_bits = 0;
    supply_state.pow_bits_min = 0;
    let supply_json = serde_json::to_string(&supply_state).expect("serialize SupplyState");
    std::fs::write(mempool_dir.join("supply_state.json"), supply_json)
        .expect("write supply_state.json");

    let port = tcp_ephemeral_port();
    let addr = format!("127.0.0.1:{}", port);
    let token = "e2e_13_token";
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let genesis_note_path = mempool_dir.join("genesis_note.bin");
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

    let amount_1 = pc_consensus::consts::compute_mint_reward(1);
    let lock = [0x33u8; 32];

    let tpl = fetch_mint_template(&client_http, &addr, token).await;
    let mint_template = build_round_mint(
        nid,
        decode_hex32(&tpl.prev_mint_id),
        tpl.mint_height.saturating_add(1),
        amount_1,
        lock,
        ready_hit_bucket(),
        tpl.target_bits,
    );

    let resp_ok = http_mint_submit(&client_http, &addr, token, &mint_template).await;
    let resp_ok_status = resp_ok.status();
    let resp_ok_body = resp_ok.text().await.expect("read first mint response body");
    assert!(
        resp_ok_status.is_success(),
        "first mint must be accepted: status={} body={}",
        resp_ok_status,
        resp_ok_body
    );

    let resp_reuse = http_mint_submit(&client_http, &addr, token, &mint_template).await;
    let resp_reuse_status = resp_reuse.status();
    let resp_reuse_body = resp_reuse.text().await.expect("read reuse response body");
    assert!(
        resp_reuse_status.is_client_error(),
        "seed reuse must be rejected even with bits=0: status={} body={}",
        resp_reuse_status,
        resp_reuse_body
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn e2e_14_payload_manipulation_outputs_changed_without_seed_update_is_rejected() {
    let base = unique_tmp("t14");
    std::fs::create_dir_all(&base).expect("create base dir");

    let store_dir = base.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");

    let (nid, _sk0, bls_kp) =
        write_genesis_files_with_pow_bind(&store_dir, "e2e_14_payload_manipulation");
    let genesis_toml = write_genesis_toml(&base, 1, 0);

    let udp_port = udp_ephemeral_port();
    let quic_addr = format!("127.0.0.1:{}", udp_port);
    let cert_file = base.join("cert.der");

    let mut child = spawn_p2p_listen(&store_dir, &quic_addr, &cert_file, &genesis_toml);
    wait_for_file(&cert_file, 8);

    let amount_1 = pc_consensus::consts::compute_mint_reward(1);

    let tmpl_ok = build_round_mint(
        nid,
        [0u8; 32],
        1,
        amount_1,
        [0x55u8; 32],
        ready_hit_bucket(),
        0,
    );
    let seed_ok = tmpl_ok.pow_seed;

    let mint_manipulated = MintEvent {
        outputs: vec![TxOut {
            amount: amount_1,
            lock: LockCommitment([0x66u8; 32]),
        }],
        pow_seed: seed_ok,
        pow_nonce: 0,
        ..tmpl_ok
    };

    let payload = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![mint_manipulated],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
    };
    let root = pc_types::payload_merkle_root_v2(&payload);
    persist_payload_in_store(&store_dir, &payload);

    let payloads_file = base.join("payloads.bin");
    write_vec_pc_codec(&payloads_file, &[payload]);
    inject_payloads(&quic_addr, &cert_file, &payloads_file);

    let hdr = build_final_header(nid, root, [0x33u8; 32], [1u8; 32], 0, &bls_kp);
    let headers_file = base.join("headers.bin");
    write_vec_pc_codec(&headers_file, &[hdr]);
    inject_headers(&quic_addr, &cert_file, &headers_file);

    wait_anchor_index_never_reaches(&store_dir, 1, 3);

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn e2e_15_regression_free_seed_is_rejected() {
    let base = unique_tmp("t15");
    std::fs::create_dir_all(&base).expect("create base dir");

    let store_dir = base.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");

    let (nid, _sk0, bls_kp) =
        write_genesis_files_with_pow_bind(&store_dir, "e2e_15_free_seed_regression");
    let genesis_toml = write_genesis_toml(&base, 1, 0);

    let udp_port = udp_ephemeral_port();
    let quic_addr = format!("127.0.0.1:{}", udp_port);
    let cert_file = base.join("cert.der");

    let mut child = spawn_p2p_listen(&store_dir, &quic_addr, &cert_file, &genesis_toml);
    wait_for_file(&cert_file, 8);

    let amount_1 = pc_consensus::consts::compute_mint_reward(1);

    let mint = MintEvent {
        pow_seed: [0x99u8; 32],
        ..build_round_mint(
            nid,
            [0u8; 32],
            1,
            amount_1,
            [0x77u8; 32],
            ready_hit_bucket(),
            0,
        )
    };

    let payload = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![mint],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
    };
    let root = pc_types::payload_merkle_root_v2(&payload);
    persist_payload_in_store(&store_dir, &payload);

    let payloads_file = base.join("payloads.bin");
    write_vec_pc_codec(&payloads_file, &[payload]);
    inject_payloads(&quic_addr, &cert_file, &payloads_file);

    let hdr = build_final_header(nid, root, [0x44u8; 32], [1u8; 32], 0, &bls_kp);
    let headers_file = base.join("headers.bin");
    write_vec_pc_codec(&headers_file, &[hdr]);
    inject_headers(&quic_addr, &cert_file, &headers_file);

    wait_anchor_index_never_reaches(&store_dir, 1, 3);

    let _ = child.kill();
    let _ = child.wait();
}
