// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use tokio::time::sleep;

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pc_auth_e2e_{}_{}", prefix, nanos))
}

fn hex32(b: &[u8; 32]) -> String { hex::encode(b) }
fn hex48(b: &[u8; 48]) -> String { hex::encode(b) }
fn hex96(b: &[u8; 96]) -> String { hex::encode(b) }

#[tokio::test]
#[ignore]
async fn auth_gating_select_attestors() {
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_vrf_prove};
    use pc_consensus::committee_vrf::{derive_epoch, derive_vrf_seed};

    // 1) Temp-Mempool-Verzeichnis
    let base = unique_tmp("auth");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // 2) Server starten mit Auth
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
        .arg("--require-auth").arg("true")
        .arg("--auth-token").arg("supersecret")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline { panic!("server not ready in time"); }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("status-serve exited early: {:?}", status);
        }
        if wait_ready(&client, &addr, 1).await { break; }
    }

    // 3) VRF-Setup für gültige Anfrage
    let ikm = blake3_32(b"auth_e2e_k1");
    let kp = bls_keygen_from_ikm(&ikm).expect("keygen");

    let current_anchor_index: u64 = 42_000;
    let epoch_len: u64 = 10_000;
    let epoch = derive_epoch(current_anchor_index, epoch_len);
    let network_id = blake3_32(b"nid-auth-e2e");
    let last_anchor_id = blake3_32(b"aid-auth-e2e");

    let seed = derive_vrf_seed(network_id, pc_types::AnchorId(last_anchor_id));
    // Repliziere VRF-Nachricht (siehe committee_vrf)
    let msg = {
        const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
        let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
        m.extend_from_slice(VRF_MSG_DOMAIN);
        m.extend_from_slice(&seed);
        m.extend_from_slice(&epoch.to_le_bytes());
        m
    };
    let (proof, _y) = bls_vrf_prove(&msg, &kp.sk);

    let cand = serde_json::json!({
        "recipient_id": hex32(&blake3_32(b"rcpt-auth-e2e")),
        "operator_id": hex32(&blake3_32(b"op-auth-e2e")),
        "bls_pk": hex48(&kp.pk.to_bytes()),
        "last_selected_at": 0u64,
        "attendance_recent_pct": 100u8,
        "vrf_proof": hex96(&proof),
    });

    let req_body = serde_json::json!({
        "m": 1,
        "current_anchor_index": current_anchor_index,
        "epoch_len": epoch_len,
        "network_id": hex32(&network_id),
        "last_anchor_id": hex32(&last_anchor_id),
        "rotation": { "cooldown_anchors": 10_000u64, "min_attendance_pct": 50u8 },
        "candidates": [cand.clone()],
    });

    // 4) Ohne Auth (sollte 401 liefern)
    let uri_sa: Uri = format!("http://{}/consensus/select_attestors", addr).parse().unwrap();
    let req_noauth = Request::builder()
        .method(Method::POST)
        .uri(uri_sa.clone())
        .header("content-type", "application/json")
        .body(Body::from(req_body.to_string()))
        .unwrap();
    let resp_na = client.request(req_noauth).await.expect("select_attestors noauth resp");
    assert_eq!(resp_na.status(), StatusCode::UNAUTHORIZED);

    // 5) Mit Auth (sollte 200 liefern)
    let req_auth = Request::builder()
        .method(Method::POST)
        .uri(uri_sa)
        .header("content-type", "application/json")
        .header("authorization", "Bearer supersecret")
        .body(Body::from(req_body.to_string()))
        .unwrap();
    let resp_auth = client.request(req_auth).await.expect("select_attestors auth resp");
    assert_eq!(resp_auth.status(), StatusCode::OK);

    // 6) Aufräumen
    let _ = child.kill();
    let _ = child.wait();
}
