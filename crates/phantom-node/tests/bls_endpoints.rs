// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use assert_cmd::cargo::cargo_bin;
use tokio::time::sleep;

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pc_bls_e2e_{}_{}", prefix, nanos))
}

fn hex32(b: &[u8; 32]) -> String { hex::encode(b) }
fn hex48(b: &[u8; 48]) -> String { hex::encode(b) }
fn hex96(b: &[u8; 96]) -> String { hex::encode(b) }

#[tokio::test]
#[ignore]
async fn bls_agg_endpoints_e2e() {
    // 1) Temp-Mempool-Verzeichnis
    let base = unique_tmp("bls_e2e");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // 2) Server starten
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

    // 3) BLS Keys, Message und Signaturen vorbereiten
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_sign};
    use pc_consensus::attestor_pool::attestation_message;

    let ikm1 = blake3_32(b"bls_e2e_k1");
    let ikm2 = blake3_32(b"bls_e2e_k2");
    let kp1 = bls_keygen_from_ikm(&ikm1).expect("keygen1");
    let kp2 = bls_keygen_from_ikm(&ikm2).expect("keygen2");

    let network_id = blake3_32(b"nid-bls-e2e");
    let epoch: u64 = 1;
    let topic = b"topic-bls-e2e".to_vec();
    let msg = attestation_message(&network_id, epoch, &topic);

    let sig1 = bls_sign(&msg, &kp1.sk);
    let sig2 = bls_sign(&msg, &kp2.sk);

    // 4) Aggregation via Endpoint
    let agg_req_body = serde_json::json!({ "parts": [hex96(&sig1), hex96(&sig2)] });
    let uri_agg: Uri = format!("http://{}/consensus/attestor_aggregate_sigs", addr).parse().unwrap();
    let req_agg = Request::builder()
        .method(Method::POST)
        .uri(uri_agg)
        .header("content-type", "application/json")
        .body(Body::from(agg_req_body.to_string()))
        .unwrap();
    let resp_agg = client.request(req_agg).await.expect("agg resp");
    assert_eq!(resp_agg.status(), StatusCode::OK);
    let body_agg = hyper::body::to_bytes(resp_agg.into_body()).await.expect("agg body");
    let v_agg: serde_json::Value = serde_json::from_slice(&body_agg).expect("agg json");
    assert!(v_agg.get("ok").and_then(|x| x.as_bool()).unwrap_or(false));
    let agg_sig_hex = v_agg.get("agg_sig").and_then(|x| x.as_str()).expect("agg_sig hex");

    // 5) Fast Verify via Endpoint
    let verify_body = serde_json::json!({
        "network_id": hex32(&network_id),
        "epoch": epoch,
        "topic": hex::encode(&topic),
        "bls_pks": [hex48(&kp1.pk.to_bytes()), hex48(&kp2.pk.to_bytes())],
        "agg_sig": agg_sig_hex,
    });
    let uri_v: Uri = format!("http://{}/consensus/attestor_fast_verify", addr).parse().unwrap();
    let req_v = Request::builder()
        .method(Method::POST)
        .uri(uri_v)
        .header("content-type", "application/json")
        .body(Body::from(verify_body.to_string()))
        .unwrap();
    let resp_v = client.request(req_v).await.expect("verify resp");
    assert_eq!(resp_v.status(), StatusCode::OK);
    let body_v = hyper::body::to_bytes(resp_v.into_body()).await.expect("verify body");
    let v: serde_json::Value = serde_json::from_slice(&body_v).expect("verify json");
    assert!(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false));
    assert_eq!(v.get("valid").and_then(|x| x.as_bool()).unwrap_or(false), true);

    // 6) Aufräumen
    let _ = child.kill();
    let _ = child.wait();
}
