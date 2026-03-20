// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hyper::body::HttpBody as _;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use tokio::time::sleep;

use pc_codec::Encodable;
use pc_types::{
    GenesisNote, GenesisParams, LockCommitment, MintEvent, MintEventJson, SubmitMintRequest,
    SubmitMintResponse, TxOut, TxOutJson, GENESIS_FEATURE_MINT_POW_BIND_V1, MINT_VERSION_V2,
};

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_f17_{}_{}", prefix, nanos))
}

async fn wait_ready(client: &Client<hyper::client::HttpConnector>, addr: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if Instant::now() > deadline {
            panic!("server not ready in time");
        }
        let uri: Uri = format!("http://{}/readyz", addr)
            .parse()
            .expect("parse /readyz uri");
        match client.get(uri).await {
            Ok(resp) if resp.status() == StatusCode::OK => return,
            _ => sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn read_body(resp: hyper::Response<Body>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut body = resp.into_body();
    while let Some(next) = body.data().await {
        let chunk = next.expect("read body chunk");
        out.extend_from_slice(&chunk);
    }
    out
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

#[tokio::test]
async fn f17_parallel_mint_submissions_with_same_seed_only_one_is_accepted() {
    // Temp store + mempool dir.
    let base = unique_tmp("mempool");
    let store_dir = base.join("store");
    let mempool_dir = store_dir.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // Minimal genesis_note.bin so status-serve resolves a deterministic network_id.
    let note = GenesisNote {
        version: 0,
        network_name: b"test".to_vec(),
        seed: [7u8; 32],
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 1,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut note_buf = Vec::new();
    note.encode(&mut note_buf).expect("encode genesis note");
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_buf).expect("write genesis_note.bin");

    // Make PoW trivial for the test (bits=0).
    let mut supply = pc_consensus::SupplyState::new();
    supply.pow_bits = 0;
    supply.pow_bits_min = 0;
    let supply_json = serde_json::to_string(&supply).expect("serialize supply state");
    std::fs::write(mempool_dir.join("supply_state.json"), supply_json)
        .expect("write supply_state.json");

    // Start status-serve without auth (requires --unsafe-confirm).
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let p = l.local_addr().expect("local_addr").port();
        drop(l);
        p
    };
    let addr = format!("127.0.0.1:{}", port);
    let mut child = Command::new(bin)
        .arg("status-serve")
        .arg("--addr")
        .arg(&addr)
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .arg("--no-require-auth")
        .arg("--unsafe-confirm")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn phantom-node status-serve");

    let client: Client<hyper::client::HttpConnector> = Client::new();
    wait_ready(&client, &addr, 20).await;

    // Fetch template to get network_id and the active round context.
    let uri_tpl: Uri = format!("http://{}/mint/template", addr)
        .parse()
        .expect("parse /mint/template uri");
    let resp_tpl = client.get(uri_tpl).await.expect("GET /mint/template");
    assert_eq!(resp_tpl.status(), StatusCode::OK);
    let tpl_bytes = read_body(resp_tpl).await;
    let tpl: pc_types::MintTemplate =
        serde_json::from_slice(&tpl_bytes).expect("decode MintTemplate json");

    let nid_raw = hex::decode(tpl.network_id).expect("decode network_id hex");
    assert_eq!(nid_raw.len(), 32);
    let mut network_id = [0u8; 32];
    network_id.copy_from_slice(&nid_raw);

    // Build a valid mint (pow_bits=0 => no mining required).
    let outputs = vec![TxOut {
        amount: 1,
        lock: LockCommitment([42u8; 32]),
    }];
    let mut mint = MintEvent {
        version: MINT_VERSION_V2,
        prev_mint_id: decode_hex32(&tpl.prev_mint_id),
        outputs,
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: decode_hex32(&tpl.round_id),
        hit_bucket: ready_hit_bucket(),
        bits_used: tpl.target_bits,
    };
    mint.pow_seed = pc_consensus::mint_pow_seed_v2(&network_id, &mint);

    let req_body = SubmitMintRequest {
        mint: MintEventJson {
            version: mint.version,
            prev_mint_id: hex::encode(mint.prev_mint_id),
            outputs: mint
                .outputs
                .iter()
                .map(|o| TxOutJson {
                    amount: o.amount,
                    lock: hex::encode(o.lock.0),
                })
                .collect(),
            pow_seed: hex::encode(mint.pow_seed),
            pow_nonce: mint.pow_nonce,
            minted_at: 0,
            round_id: Some(hex::encode(mint.round_id)),
            hit_bucket: Some(mint.hit_bucket),
            bits_used: Some(mint.bits_used),
        },
    };
    let body = serde_json::to_vec(&req_body).expect("encode submit json");

    // Submit the same mint twice concurrently; only one must reserve the seed.
    let uri_submit: Uri = format!("http://{}/mint/submit", addr)
        .parse()
        .expect("parse /mint/submit uri");
    let mk_req = || {
        Request::builder()
            .method(Method::POST)
            .uri(uri_submit.clone())
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .expect("build submit request")
    };
    let (r1, r2) = tokio::join!(client.request(mk_req()), client.request(mk_req()));
    let resp1 = r1.expect("submit resp1");
    let resp2 = r2.expect("submit resp2");

    let (s1, b1) = (resp1.status(), read_body(resp1).await);
    let (s2, b2) = (resp2.status(), read_body(resp2).await);

    let j1: SubmitMintResponse = serde_json::from_slice(&b1).expect("decode submit resp1 json");
    let j2: SubmitMintResponse = serde_json::from_slice(&b2).expect("decode submit resp2 json");

    // Exactly one OK.
    assert!(
        (s1 == StatusCode::OK && s2 != StatusCode::OK)
            || (s2 == StatusCode::OK && s1 != StatusCode::OK),
        "expected exactly one 200 OK; got statuses {s1} and {s2}"
    );
    assert!(
        (j1.ok && !j2.ok) || (j2.ok && !j1.ok),
        "expected exactly one ok=true; got ok flags {} and {}",
        j1.ok,
        j2.ok
    );

    let err = if !j1.ok {
        j1.error.unwrap_or_default()
    } else {
        j2.error.unwrap_or_default()
    };
    assert!(
        err.contains("seed already used"),
        "expected seed reservation error; got: {err}"
    );

    // Cleanup.
    let _ = child.kill();
    let _ = child.wait();
}
