// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use reqwest::Client;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use pc_codec::Encodable as _;
use pc_consensus::SupplyState;
use pc_types::{digest_genesis_note, GenesisNote, GenesisParams};

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_a2_{}_{}", prefix, nanos))
}

#[tokio::test]
async fn a2_rejects_removed_apply_mint_with_future_telemetry_time() {
    let base = unique_tmp("e2e");
    let _ = std::fs::create_dir_all(&base);
    let mempool_dir = base.join("mempool");
    std::fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // status-serve derives `network_id` from mempool_dir/genesis_note.bin.
    let note = GenesisNote {
        version: 0,
        network_name: b"test".to_vec(),
        seed: [0u8; 32],
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 1,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let _nid = digest_genesis_note(&note);
    let mut note_bytes = Vec::with_capacity(note.encoded_len());
    note.encode(&mut note_bytes).expect("encode GenesisNote");
    std::fs::write(mempool_dir.join("genesis_note.bin"), note_bytes).expect("write genesis_note");

    // Make the PoW check deterministic for this test: focus is the telemetry time handling,
    // not mining difficulty.
    let ss = SupplyState {
        pow_bits: 0,
        pow_bits_min: 0,
        ..SupplyState::default()
    };
    let ss_raw = serde_json::to_string(&ss).expect("serialize supply_state");
    std::fs::write(mempool_dir.join("supply_state.json"), ss_raw).expect("write supply_state");

    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let p = l
            .local_addr()
            .expect("local_addr for ephemeral bind")
            .port();
        drop(l);
        p
    };
    let addr = format!("127.0.0.1:{}", port);

    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let auth_token = "testtoken";
    let mut child = Command::new(bin)
        .arg("status-serve")
        .arg("--unsafe-confirm")
        .arg("--addr")
        .arg(addr.clone())
        .arg("--mempool-dir")
        .arg(mempool_dir.to_string_lossy().to_string())
        .env("PHANTOM_STATUS_AUTH_TOKEN", auth_token)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node status-serve");

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build reqwest client");

    async fn wait_ready(client: &Client, addr: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if Instant::now() > deadline {
                return false;
            }
            let url = format!("http://{}/readyz", addr);
            match client.get(url).send().await {
                Ok(resp) if resp.status().is_success() => return true,
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("server not ready in time");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("status-serve exited early: {:?}", status);
        }
        if wait_ready(&client, &addr, 1).await {
            break;
        }
    }

    let now_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let client_submit_future_ms = now_ms.saturating_add(3u64 * 60 * 60 * 1000);

    let url = format!("http://{}/state/apply_mint_with_index", addr);
    let body = serde_json::json!({
        "prev_mint_id": null,
        "outputs": [{"amount": 1u64, "lock": "0000000000000000000000000000000000000000000000000000000000000000"}],
        "pow_seed": hex::encode([0u8; 32]),
        "pow_nonce": 0u64,
        "minted_at": 1u64,
        "client_local_submit_time_ms": client_submit_future_ms
    });

    let resp = client
        .post(url)
        .header("content-type", "application/json")
        .bearer_auth(auth_token)
        .json(&body)
        .send()
        .await
        .expect("apply_mint_with_index response");

    assert_eq!(resp.status(), reqwest::StatusCode::GONE);

    let _ = child.kill();
    let _ = child.wait();
}
