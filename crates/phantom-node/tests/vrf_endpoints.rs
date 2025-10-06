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
    std::env::temp_dir().join(format!("pc_vrf_e2e_{}_{}", prefix, nanos))
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
// und in CI/eng umgebungen flakey sein kann. Lokal ausführen mit:
//   cargo test -p phantom-node --test vrf_endpoints -- --ignored
#[tokio::test]
#[ignore]
async fn vrf_endpoints_e2e() {
    // 1) Temp-Mempool-Verzeichnis
    let base = unique_tmp("vrf_e2e");
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // 2) Server als Child-Prozess starten (phantom-node StatusServe)
    //    Suche freien Port im Bereich 18081..18100 und prüfe Readiness.
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
    let (chosen_addr, mut child) = {
        let mut chosen: Option<String> = None;
        let mut child_opt: Option<std::process::Child> = None;
        for port in 18081..=18100 {
            let addr = format!("127.0.0.1:{}", port);
            let child_try = Command::new(&bin)
                .arg("StatusServe")
                .arg("--addr").arg(&addr)
                .arg("--mempool-dir").arg(mempool_dir.to_string_lossy().to_string())
                .arg("--fsync").arg("false")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            let mut child = match child_try { Ok(c) => c, Err(_) => { continue; } };
            if wait_ready(&client, &addr, 3).await {
                chosen = Some(addr);
                child_opt = Some(child);
                break;
            } else {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        let addr = chosen.expect("server not ready on any port in range");
        let child = child_opt.expect("child missing despite readiness");
        (addr, child)
    };
    // endgültige Readiness bis 10s (stabilisieren)
    assert!(wait_ready(&client, &chosen_addr, 10).await, "server not ready in time");
    let addr = chosen_addr.as_str();

    // 4) VRF-Testdaten generieren: Keypair, Proofs
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_vrf_prove};
    use pc_consensus::committee_vrf::{derive_epoch, derive_vrf_seed};

    let ikm = blake3_32(b"vrf_e2e_k1");
    let kp = bls_keygen_from_ikm(&ikm).expect("keygen");

    // Request-Parameter konsistent wählen
    let k: u8 = 1;
    let current_anchor_index: u64 = 20_000;
    let epoch_len: u64 = 10_000;
    let epoch = derive_epoch(current_anchor_index, epoch_len);
    let network_id = blake3_32(b"nid-e2e");
    let last_anchor_id = blake3_32(b"aid-e2e");

    let seed = derive_vrf_seed(network_id, pc_types::AnchorId(last_anchor_id));
    let msg = vrf_msg(&seed, epoch);
    let (proof, _y) = bls_vrf_prove(&msg, &kp.sk);

    // Kandidat konstruieren (alle Felder hex)
    let cand = serde_json::json!({
        "recipient_id": hex32(&blake3_32(b"rcpt-e2e")),
        "operator_id": hex32(&blake3_32(b"op-e2e")),
        "bls_pk": hex48(&kp.pk.to_bytes()),
        "last_selected_at": 0u64,
        "attendance_recent_pct": 100u8,
        "vrf_proof": hex96(&proof),
    });

    // 5) POST /consensus/select_committee
    let req_body = serde_json::json!({
        "k": k,
        "current_anchor_index": current_anchor_index,
        "epoch_len": epoch_len,
        "network_id": hex32(&network_id),
        "last_anchor_id": hex32(&last_anchor_id),
        "rotation": { "cooldown_anchors": 10_000u64, "min_attendance_pct": 50u8 },
        "candidates": [cand.clone()],
    });
    let uri: Uri = format!("http://{}/consensus/select_committee", addr).parse().unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(req_body.to_string()))
        .unwrap();
    let resp = client.request(req).await.expect("select_committee resp");
    assert_eq!(resp.status(), StatusCode::OK);

    // 6) POST /consensus/select_committee_persist
    let uri2: Uri = format!("http://{}/consensus/select_committee_persist", addr).parse().unwrap();
    let req2 = Request::builder()
        .method(Method::POST)
        .uri(uri2)
        .header("content-type", "application/json")
        .body(Body::from(req_body.to_string()))
        .unwrap();
    let resp2 = client.request(req2).await.expect("select_committee_persist resp");
    assert_eq!(resp2.status(), StatusCode::OK);

    // 7) GET /consensus/current_committee
    let uri3: Uri = format!("http://{}/consensus/current_committee", addr).parse().unwrap();
    let resp3 = client.get(uri3).await.expect("current_committee resp");
    assert_eq!(resp3.status(), StatusCode::OK);

    // 8) Aufräumen: Kindprozess beenden
    let _ = child.kill();
    let _ = child.wait();
}
