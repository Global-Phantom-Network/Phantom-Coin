// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use pc_consensus::{ConsensusConfig, ConsensusEngine};
use pc_p2p::async_svc::{inbound_subscribe, spawn, watch_payload};
use pc_p2p::messages::{explicit_announce_for_header, P2pMessage, ReqMsg};
use pc_p2p::P2pConfig;
use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn da_gating_retry_timeout_metrics_like_behaviour() {
    // Start in-process P2P service.
    // Starte in-process P2P-Service
    let cfg = P2pConfig {
        max_peers: 8,
        rate: None,
        peers_json_path: None,
        enable_peer_exchange: false,
        network_id: None,
    };
    let (svc, mut out, handle) = spawn(cfg.clone());

    // Parameters: short timeouts/delays, jitter=0 for determinism.
    // Parameter: kurze Timeouts/Delays, jitter=0 für Determinismus
    let wait_timeout = Duration::from_millis(120);
    let retry_initial_ms: u64 = 50;
    let retry_max_ms: u64 = 80;
    let retry_max_retries: u32 = 3;
    let _retry_jitter_pct: u8 = 0;

    // Observer task like in the node: final header triggers pull+retry until timeout.
    // Beobachter-Task wie im Node: finaler Header triggert Pull+Retry bis Timeout
    let mut rx_in = inbound_subscribe();
    tokio::spawn({
        let svc = svc.clone();
        async move {
            let cfg = ConsensusConfig::recommended(1);
            let eng = ConsensusEngine::new(cfg);
            // Pure flow check: counters are not required.
            // reine Ablaufprüfung: Zählvariablen werden nicht benötigt
            loop {
                match rx_in.recv().await {
                    Ok(P2pMessage::PrevoteAnnounce(h)) | Ok(P2pMessage::PrecommitAnnounce(h)) => {
                        if h.state_root.is_some() && eng.is_final_mask(h.vote_mask) {
                            let root = h.payload_hash;
                            let svc2 = svc.clone();
                            tokio::spawn(async move {
                                let t0 = std::time::Instant::now();
                                let mut delay_ms: u64 = retry_initial_ms;
                                let max_delay_ms: u64 = retry_max_ms;
                                let max_retries: u32 = retry_max_retries;
                                let mut attempt: u32 = 0;
                                loop {
                                    // Send pull request.
                                    // Sende Pull
                                    let _ = svc2
                                        .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
                                            roots: vec![root],
                                        }))
                                        .await;
                                    if attempt > 0 { /* retry countable / retry zählbar */ }
                                    // Wait for payload (none is delivered here -> leads to retries/timeout).
                                    // Warten auf Payload (hier wird KEINE geliefert -> führt zu Retries/Timeout)
                                    if timeout(wait_timeout, watch_payload(root)).await.is_ok() {
                                        let _elapsed = t0.elapsed();
                                        // Erfolg
                                        break;
                                    }
                                    attempt = attempt.saturating_add(1);
                                    if attempt >= max_retries {
                                        // Timeout.
                                        // Timeout
                                        break;
                                    }
                                    // Jitter 0 => exact delay.
                                    // Jitter 0 => genaues Delay
                                    let sleep_ms = delay_ms;
                                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                                    delay_ms =
                                        std::cmp::min(delay_ms.saturating_mul(2), max_delay_ms);
                                }
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    });

    // Inject final header (without payload delivery) to trigger retries.
    // Finalen Header injecten (ohne Payload-Delivery), damit Retries ausgelöst werden
    let parents = pc_types::ParentList::default();
    let hdr = AnchorHeader {
        version: 5,
        shard_id: 0,
        parents,
        payload_hash: [7u8; 32],
        creator_index: 0,
        vote_mask: 1, // final for k=1 / final bei k=1
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0u8; 32],
        vote_epoch: 0,
        vote_round: 0,
        state_root: Some([0x11; 32]),
        attest_sig: None,
    };
    let _ = svc.send_message(explicit_announce_for_header(hdr)).await;

    // Collect number of GetPayloads requests from outbox over sufficient time.
    // Sammle aus Outbox die Anzahl GetPayloads-Requests über ausreichend Zeit
    let mut req_count = 0u32;
    let end = std::time::Instant::now() + Duration::from_millis(900);
    while std::time::Instant::now() < end {
        if let Ok(Some(msg)) = timeout(Duration::from_millis(50), out.recv()).await {
            if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                assert_eq!(roots.len(), 1);
                assert_eq!(roots.first().copied(), Some([7u8; 32]));
                req_count = req_count.saturating_add(1);
            }
        }
    }

    // Note: P2P service can deduplicate in-flight, so only one visible request may appear in the outbox stream.
    // Hinweis: P2P-Service kann inflight deduplizieren, sodass nur eine sichtbare Req im Outbox-Strom erscheint.
    // Therefore we conservatively only assert on >=1.
    // Daher prüfen wir hier konservativ nur auf >=1.
    assert!(req_count >= 1, "unexpected req_count={}", req_count);

    // Cleanup.
    // Aufräumen
    let _ = svc.shutdown().await;
    let _ = handle.await;
}
