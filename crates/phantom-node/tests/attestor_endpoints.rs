// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use assert_cmd::cargo::cargo_bin;
use tokio::time::sleep;
use pc_crypto::{merkle_verify_with_proof, MerkleStep};

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pc_att_e2e_{}_{}", prefix, nanos))
}

fn hex32(b: &[u8; 32]) -> String { hex::encode(b) }
fn hex48(b: &[u8; 48]) -> String { hex::encode(b) }
fn hex96(b: &[u8; 96]) -> String { hex::encode(b) }

// Repliziere VRF-Nachricht (siehe pc-consensus/src/committee_vrf.rs)
fn vrf_msg(seed: &[u8; 32], epoch: u64) -> Vec<u8> {
    const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
    let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
    m.extend_from_slice(VRF_MSG_DOMAIN);
    m.extend_from_slice(seed);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

// Hinweis: E2E-Netzwerk-Test; standardmäßig ignoriert, da er einen echten HTTP-Port benötigt
// und in CI/eng Umgebungen flakey sein kann. Lokal ausführen mit:
//   cargo test -p phantom-node --test attestor_endpoints -- --ignored
#[tokio::test]
#[ignore]
async fn attestor_endpoints_e2e() {
    // 1) Temp-Mempool-Verzeichnis
    let base = unique_tmp("att_e2e");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // 2) Server als Child-Prozess starten (phantom-node StatusServe)
    async fn wait_ready(client: &Client<hyper::client::HttpConnector>, addr: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if Instant::now() > deadline { return false; }
            let uri: Uri = format!("http://{}/readyz", addr).parse().unwrap();
            match client.get(uri).await {
                Ok(resp) if resp.status() == StatusCode::OK => return true,
                _ => sleep(Duration::from_millis(100)).await,
            }
        }
    }

    let client: Client<hyper::client::HttpConnector> = Client::new();
    let bin = cargo_bin("phantom-node");
    // Wähle freien Port per Ephemeral-Bind
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let addr = format!("127.0.0.1:{}", port);
    let mut child = Command::new(&bin)
        .arg("status-serve")
        .arg("--addr").arg(&addr)
        .arg("--mempool-dir").arg(mempool_dir.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");
    // Readiness mit Prozess-Liveness koppeln
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline { panic!("server not ready in time"); }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("status-serve exited early: {:?}", status);
        }
        if wait_ready(&client, &addr, 1).await { break; }
    }

    // 3) VRF-Testdaten generieren
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_vrf_prove};
    use pc_consensus::committee_vrf::{derive_epoch, derive_vrf_seed};

    let ikm = blake3_32(b"att_e2e_k1");
    let kp = bls_keygen_from_ikm(&ikm).expect("keygen");

    // Request-Parameter konsistent wählen
    let m: u16 = 1;
    let current_anchor_index: u64 = 20_000;
    let epoch_len: u64 = 10_000;
    let epoch = derive_epoch(current_anchor_index, epoch_len);
    let network_id = blake3_32(b"nid-att-e2e");
    let last_anchor_id = blake3_32(b"aid-att-e2e");

    let seed = derive_vrf_seed(network_id, pc_types::AnchorId(last_anchor_id));
    let msg = vrf_msg(&seed, epoch);
    let (proof, _y) = bls_vrf_prove(&msg, &kp.sk);

    // Kandidat konstruieren (alle Felder hex)
    let cand = serde_json::json!({
        "recipient_id": hex32(&blake3_32(b"rcpt-att-e2e")),
        "operator_id": hex32(&blake3_32(b"op-att-e2e")),
        "bls_pk": hex48(&kp.pk.to_bytes()),
        "last_selected_at": 0u64,
        "attendance_recent_pct": 100u8,
        "vrf_proof": hex96(&proof),
    });

    // 4) POST /consensus/select_attestors
    let req_body = serde_json::json!({
        "m": m,
        "current_anchor_index": current_anchor_index,
        "epoch_len": epoch_len,
        "network_id": hex32(&network_id),
        "last_anchor_id": hex32(&last_anchor_id),
        "rotation": { "cooldown_anchors": 10_000u64, "min_attendance_pct": 50u8 },
        "candidates": [cand.clone()],
    });
    let uri: Uri = format!("http://{}/consensus/select_attestors", addr).parse().unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(req_body.to_string()))
        .unwrap();
    let resp = client.request(req).await.expect("select_attestors resp");
    assert_eq!(resp.status(), StatusCode::OK);

    // 5) POST /consensus/select_attestors_fair mit Caps/Perf
    let recent = serde_json::json!([{ "operator_id": hex32(&blake3_32(b"op-att-e2e")), "count": 0u32 }]);
    let perf = serde_json::json!([{ "operator_id": hex32(&blake3_32(b"op-att-e2e")), "score": 100u32 }]);
    let req_body_fair = serde_json::json!({
        "m": m,
        "current_anchor_index": current_anchor_index,
        "epoch_len": epoch_len,
        "network_id": hex32(&network_id),
        "last_anchor_id": hex32(&last_anchor_id),
        "rotation": { "cooldown_anchors": 10_000u64, "min_attendance_pct": 50u8 },
        "cap_limit_per_op": 1u32,
        "recent_op_selection_count": recent,
        "perf_index": perf,
        "candidates": [cand],
    });
    let uri2: Uri = format!("http://{}/consensus/select_attestors_fair", addr).parse().unwrap();
    let req2 = Request::builder()
        .method(Method::POST)
        .uri(uri2)
        .header("content-type", "application/json")
        .body(Body::from(req_body_fair.to_string()))
        .unwrap();
    let resp2 = client.request(req2).await.expect("select_attestors_fair resp");
    assert_eq!(resp2.status(), StatusCode::OK);

    // 6) POST /consensus/attestor_payout_proof und Proof verifizieren
    //    Verwenden wir genau einen Seat (unseren Kandidaten), so muss der Proof gültig sein.
    let recipient_hex = hex32(&blake3_32(b"rcpt-att-e2e"));
    let seats = serde_json::json!([{ "recipient_id": recipient_hex }]);
    let req_body_proof = serde_json::json!({
        "fees_total": 123456u64,
        "fee_params": serde_json::Value::Null,
        "seats": seats,
        "recipient_id": hex32(&blake3_32(b"rcpt-att-e2e")),
    });
    let uri3: Uri = format!("http://{}/consensus/attestor_payout_proof", addr).parse().unwrap();
    let req3 = Request::builder()
        .method(Method::POST)
        .uri(uri3)
        .header("content-type", "application/json")
        .body(Body::from(req_body_proof.to_string()))
        .unwrap();
    let resp3 = client.request(req3).await.expect("attestor_payout_proof resp");
    assert_eq!(resp3.status(), StatusCode::OK);
    let body_bytes = hyper::body::to_bytes(resp3.into_body()).await.expect("read proof body");
    let v: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json proof");
    assert!(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false));
    let leaf_hex = v.get("leaf").and_then(|x| x.as_str()).expect("leaf hex");
    let root_hex = v.get("payout_root").and_then(|x| x.as_str()).expect("root hex");
    let proof_arr = v.get("proof").and_then(|x| x.as_array()).expect("proof array");

    fn hex32_to_arr(s: &str) -> [u8;32] { let mut out=[0u8;32]; let raw=hex::decode(s).expect("hex32"); assert_eq!(raw.len(),32); out.copy_from_slice(&raw); out }
    let leaf = hex32_to_arr(leaf_hex);
    let root = hex32_to_arr(root_hex);
    let mut steps: Vec<MerkleStep> = Vec::with_capacity(proof_arr.len());
    for it in proof_arr {
        let h = it.get("hash").and_then(|x| x.as_str()).expect("step.hash");
        let r = it.get("right").and_then(|x| x.as_bool()).expect("step.right");
        steps.push(MerkleStep{ hash: hex32_to_arr(h), right: r });
    }
    assert!(merkle_verify_with_proof(&leaf, &steps, &root));

    // 7) Aufräumen
    let _ = child.kill();
    let _ = child.wait();
}
