// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hyper::{Client, StatusCode, Uri};
use pc_codec::Encodable;
use pc_consensus::attestor_pool::committee_precommit_message;
use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_sign};
use pc_types::{
    digest_genesis_note, AnchorHeaderV2 as AnchorHeader, AnchorId, GenesisNote, GenesisParams,
    ParentList, GENESIS_FEATURE_MINT_POW_BIND_V1,
};

fn unique_tmp(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time since UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("pc_da_metrics_e2e_{}_{}", prefix, nanos))
}

async fn http_get_text(client: &Client<hyper::client::HttpConnector>, url: &str) -> Option<String> {
    let uri: Uri = url.parse().ok()?;
    match client.get(uri).await {
        Ok(resp) if resp.status() == StatusCode::OK => {
            let bytes = hyper::body::to_bytes(resp.into_body()).await.ok()?;
            Some(String::from_utf8_lossy(&bytes).to_string())
        }
        _ => None,
    }
}

// keine Helper notwendig; wir matchen exakte Gauge-Zeilen via contains()

#[tokio::test]
#[ignore]
async fn da_gating_retry_metrics_e2e() {
    // 1) Temp-Verzeichnisse und Ports
    let base = unique_tmp("e2e");
    let _ = std::fs::create_dir_all(&base);
    let store_dir = base.join("store");
    let _ = std::fs::create_dir_all(&store_dir);
    let mempool_dir = store_dir.join("mempool");
    let _ = std::fs::create_dir_all(&mempool_dir);

    // Genesis + Committee für Finalitäts-Verification
    let note = GenesisNote {
        version: 0,
        network_name: b"e2e-da-metrics".to_vec(),
        seed: blake3_32(b"e2e-da-metrics-seed"),
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
    let nid = digest_genesis_note(&note);
    let mut note_buf = Vec::with_capacity(note.encoded_len());
    note.encode(&mut note_buf).expect("encode genesis_note");
    std::fs::write(mempool_dir.join("genesis_note.bin"), &note_buf)
        .expect("write genesis_note.bin");

    const IKM_DOMAIN: &[u8] = b"pc:p2p:quic:handshake_v2:bls_ikm\x01";
    let mut ikm_in = Vec::with_capacity(IKM_DOMAIN.len() + 32);
    ikm_in.extend_from_slice(IKM_DOMAIN);
    ikm_in.extend_from_slice(&nid);
    let ikm = blake3_32(&ikm_in);
    let bls_kp = bls_keygen_from_ikm(&ikm).expect("bls_keygen_from_ikm");
    let bls_pk_hex = hex::encode(bls_kp.pk.to_bytes());
    let committee_doc = format!(
        "{{\"epoch\":0,\"seats\":[{{\"bls_pk\":\"{}\"}}]}}",
        bls_pk_hex
    );
    std::fs::write(
        mempool_dir.join("vrf_committee.json"),
        committee_doc.as_bytes(),
    )
    .expect("write vrf_committee.json");

    // UDP-Port für QUIC wählen
    let udp_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp ephemeral");
        let p = s
            .local_addr()
            .expect("udp local_addr for ephemeral bind")
            .port();
        drop(s);
        p
    };
    // TCP-Port für Metrics wählen
    let metrics_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp ephemeral");
        let p = l
            .local_addr()
            .expect("tcp local_addr for ephemeral bind")
            .port();
        drop(l);
        p
    };

    let quic_addr = format!("127.0.0.1:{}", udp_port);
    let metrics_addr = format!("127.0.0.1:{}", metrics_port);
    let cert_file = base.join("cert.der");

    // 2) p2p-quic-listen starten
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let mut child = Command::new(bin)
        .arg("p2p-quic-listen")
        .arg("--addr")
        .arg(&quic_addr)
        .arg("--store-dir")
        .arg(store_dir.to_string_lossy().to_string())
        .arg("--k")
        .arg("1")
        .arg("--metrics-addr")
        .arg(&metrics_addr)
        .arg("--cert-out")
        .arg(cert_file.to_string_lossy().to_string())
        .arg("--da-payload-wait-timeout-secs")
        .arg("1")
        .arg("--da-retry-initial-delay-ms")
        .arg("50")
        .arg("--da-retry-max-delay-ms")
        .arg("80")
        .arg("--da-retry-max-retries")
        .arg("3")
        .arg("--da-retry-jitter-pct")
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn phantom-node p2p-quic-listen");

    // 3) Warte auf /metrics Ready
    let client: Client<hyper::client::HttpConnector> = Client::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let url_metrics = format!("http://{}/metrics", metrics_addr);
    loop {
        if Instant::now() > deadline {
            panic!("metrics server not ready in time");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("p2p-quic-listen exited early: {:?}", status);
        }
        if let Some(text) = http_get_text(&client, &url_metrics).await {
            if !text.is_empty() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 4) Finalen Header-Datei (pc-codec) schreiben und injizieren
    let parents = ParentList::default();
    let hdr = AnchorHeader {
        version: 5,
        shard_id: 0,
        parents,
        payload_hash: [9u8; 32],
        creator_index: 0,
        vote_mask: 1, // final bei k=1
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: nid,
        vote_epoch: 0,
        vote_round: 0,
        attest_sig: None,
        state_root: Some([0x11u8; 32]),
    };
    let mut hdr = hdr;
    let msg = committee_precommit_message(
        &nid,
        0,
        &hdr.vote_target_hash(),
        &hdr.state_root.expect("state_root set"),
    );
    let sig = bls_sign(&msg, &bls_kp.sk);
    hdr.attest_sig = Some(sig);
    let headers_file = base.join("headers.bin");
    {
        let mut buf = Vec::new();
        let vec1 = vec![hdr];
        pc_codec::Encodable::encode(&vec1, &mut buf).expect("encode headers vec");
        let mut f = std::fs::File::create(&headers_file).expect("create headers.bin");
        f.write_all(&buf).expect("write headers.bin");
    }

    // Warte auf Zertifikatsdatei
    let cert_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > cert_deadline {
            panic!("cert file not written in time");
        }
        if cert_file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Header injizieren
    let mut inj = Command::new(bin)
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
        .spawn()
        .expect("spawn inject headers");
    let _ = inj.wait().expect("inject headers wait");

    // 5) Warte auf DA-Gating Config-Gauges (Counters können je nach Timing flakey sein)
    let deadline2 = Instant::now() + Duration::from_secs(12);
    let mut _ok_cfg = false;
    let mut last_dump = String::new();
    loop {
        if Instant::now() > deadline2 {
            panic!("metrics not reached in time; last=\n{}", last_dump);
        }
        if let Some(text) = http_get_text(&client, &url_metrics).await {
            last_dump = text.clone();
            _ok_cfg = text.contains("pc_node_da_gating_cfg_payload_wait_timeout_secs 1")
                && text.contains("pc_node_da_gating_cfg_retry_initial_delay_ms 50")
                && text.contains("pc_node_da_gating_cfg_retry_max_delay_ms 80")
                && text.contains("pc_node_da_gating_cfg_retry_max_retries 3")
                && text.contains("pc_node_da_gating_cfg_retry_jitter_pct 0");
            if _ok_cfg {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 6) Aufräumen
    let _ = child.kill();
    let _ = child.wait();
}
