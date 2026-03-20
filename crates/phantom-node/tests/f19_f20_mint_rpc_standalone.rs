// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hyper::body::HttpBody as _;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use tokio::time::sleep;

use pc_types::{
    digest_mint, LockCommitment, MintEvent, MintEventJson, MintTemplate, SubmitMintRequest,
    SubmitMintResponse, TxOut, TxOutJson, MINT_VERSION_V2,
};

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_f19f20_{}_{}", prefix, nanos))
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

async fn wait_template(
    client: &Client<hyper::client::HttpConnector>,
    addr: &str,
    child: &mut std::process::Child,
    secs: u64,
) -> MintTemplate {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if Instant::now() > deadline {
            panic!("mint_rpc not ready in time");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("mint_rpc exited early: {:?}", status);
        }
        let uri: Uri = format!("http://{}/mint/template", addr)
            .parse()
            .expect("parse /mint/template uri");
        match client.get(uri).await {
            Ok(resp) if resp.status() == StatusCode::OK => {
                let bytes = read_body(resp).await;
                return serde_json::from_slice::<MintTemplate>(&bytes)
                    .expect("decode MintTemplate json");
            }
            _ => sleep(Duration::from_millis(100)).await,
        }
    }
}

#[tokio::test]
async fn f19_f20_standalone_mint_rpc_persists_mint_and_rejects_seed_replay() {
    // Standalone server uses <store_dir>/mempool by default.
    let base = unique_tmp("store");
    let store_dir = base.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");
    let mempool_dir = store_dir.join("mempool");

    let bin = assert_cmd::cargo::cargo_bin!("mint_rpc");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let p = l.local_addr().expect("local_addr").port();
        drop(l);
        p
    };
    let addr = format!("127.0.0.1:{}", port);
    let mut child = Command::new(bin)
        .arg("--addr")
        .arg(&addr)
        .arg("--store-dir")
        .arg(store_dir.to_string_lossy().to_string())
        .arg("--pow-bits")
        .arg("0")
        .arg("--no-tls")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mint_rpc");

    let client: Client<hyper::client::HttpConnector> = Client::new();
    let tpl = wait_template(&client, &addr, &mut child, 20).await;

    let nid_raw = hex::decode(tpl.network_id).expect("decode network_id hex");
    assert_eq!(nid_raw.len(), 32);
    let mut network_id = [0u8; 32];
    network_id.copy_from_slice(&nid_raw);

    let prev_raw = hex::decode(tpl.prev_mint_id).expect("decode prev_mint_id hex");
    assert_eq!(prev_raw.len(), 32);
    let mut prev_mint_id = [0u8; 32];
    prev_mint_id.copy_from_slice(&prev_raw);

    // Create a valid mint (pow_bits=0 => nonce=0 is fine, but seed binding MUST be correct).
    let outputs = vec![TxOut {
        amount: 1,
        lock: LockCommitment([11u8; 32]),
    }];
    let round_id = hex::decode(&tpl.round_id).expect("decode round_id hex");
    assert_eq!(round_id.len(), 32);
    let mut round_id_arr = [0u8; 32];
    round_id_arr.copy_from_slice(&round_id);
    let hit_bucket = pc_consensus::current_emission_bucket();
    let mut mint = MintEvent {
        version: MINT_VERSION_V2,
        prev_mint_id,
        outputs,
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: round_id_arr,
        hit_bucket,
        bits_used: tpl.target_bits,
    };
    mint.pow_seed = pc_consensus::mint_pow_seed_v2(&network_id, &mint);

    let seed_hex = hex::encode(mint.pow_seed);
    let submit = SubmitMintRequest {
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
    let body = serde_json::to_vec(&submit).expect("encode submit json");

    let uri_submit: Uri = format!("http://{}/mint/submit", addr)
        .parse()
        .expect("parse /mint/submit uri");
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri_submit.clone())
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .expect("build submit request");
    let resp = client.request(req).await.expect("submit resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = read_body(resp).await;
    let j: SubmitMintResponse =
        serde_json::from_slice(&bytes).expect("decode SubmitMintResponse json");
    assert!(j.ok, "expected ok=true, got {:?}", j);
    let mint_id_hex = j.mint_id.expect("mint_id must be present");

    // F19: mint must be persisted as mempool_dir/mints/<id>.bin
    let mint_path = mempool_dir
        .join("mints")
        .join(format!("{}.bin", mint_id_hex));
    assert!(
        mint_path.exists(),
        "missing persisted mint at {}",
        mint_path.display()
    );

    // Decode persisted mint and verify digest matches filename.
    let buf = std::fs::read(&mint_path).expect("read persisted mint");
    let persisted = pc_codec::decode_exact::<MintEvent>(&buf).expect("decode persisted mint");
    let got_id = digest_mint(&persisted);
    assert_eq!(hex::encode(got_id), mint_id_hex, "mint_id mismatch");

    // Seed marker must exist.
    let seed_marker = mempool_dir.join("mint_seeds").join(&seed_hex);
    assert!(
        seed_marker.exists(),
        "missing seed marker at {}",
        seed_marker.display()
    );

    // F20: submitting the same seed again must be rejected.
    let req2 = Request::builder()
        .method(Method::POST)
        .uri(uri_submit)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("build submit request 2");
    let resp2 = client.request(req2).await.expect("submit resp2");
    assert_ne!(resp2.status(), StatusCode::OK, "expected non-OK on replay");
    let bytes2 = read_body(resp2).await;
    let j2: SubmitMintResponse =
        serde_json::from_slice(&bytes2).expect("decode SubmitMintResponse json (2)");
    assert!(!j2.ok, "expected ok=false on replay; got {:?}", j2);
    let err = j2.error.unwrap_or_default();
    assert!(
        err.contains("seed already used") || err.contains("prev_mint_id does not match"),
        "expected seed replay or stale template error; got: {err}"
    );

    // Cleanup.
    let _ = child.kill();
    let _ = child.wait();
}
