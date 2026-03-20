// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use pc_consensus::{ConsensusConfig, ConsensusEngine};
use pc_p2p::async_svc::{inbound_subscribe, spawn, watch_payload};
use pc_p2p::messages::{explicit_announce_for_header, P2pMessage, ReqMsg};
use pc_p2p::P2pConfig;
use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn da_gating_inflight_dedupe_single_getpayloads() {
    // Start P2P service.
    // P2P-Service starten
    let cfg = P2pConfig {
        max_peers: 8,
        rate: None,
        peers_json_path: None,
        enable_peer_exchange: false,
        network_id: None,
    };
    let (svc, mut out, handle) = spawn(cfg.clone());

    // Consensus task with in-flight dedupe (like the node).
    // Konsensus-Task mit In-Flight Dedupe (wie Node)
    let mut rx_in = inbound_subscribe();
    let inflight: Arc<tokio::sync::Mutex<HashSet<[u8; 32]>>> =
        Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    tokio::spawn({
        let inflight = inflight.clone();
        let svc = svc.clone();
        async move {
            let cfg = ConsensusConfig::recommended(1);
            let eng = ConsensusEngine::new(cfg);
            loop {
                match rx_in.recv().await {
                    Ok(P2pMessage::PrevoteAnnounce(h)) | Ok(P2pMessage::PrecommitAnnounce(h)) => {
                        if h.state_root.is_some() && eng.is_final_mask(h.vote_mask) {
                            let root = h.payload_hash;
                            let should_spawn = {
                                let mut g = inflight.lock().await;
                                if g.contains(&root) {
                                    false
                                } else {
                                    g.insert(root);
                                    true
                                }
                            };
                            if should_spawn {
                                let svc2 = svc.clone();
                                let inflight2 = inflight.clone();
                                tokio::spawn(async move {
                                    // Pull payloads.
                                    // Pull
                                    let _ = svc2
                                        .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
                                            roots: vec![root],
                                        }))
                                        .await;
                                    // Watch payload (short timeout, we do not deliver; dedupe is the goal).
                                    // Watch Payload (kurzes Timeout, wir liefern nicht; dedupe ist das Ziel)
                                    let _ =
                                        timeout(Duration::from_millis(200), watch_payload(root))
                                            .await;
                                    // Remove entry from in-flight set.
                                    // In-Flight entfernen
                                    let mut g = inflight2.lock().await;
                                    let _ = g.remove(&root);
                                });
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    });

    // Announce final header twice in quick succession.
    // Finalen Header zweimal kurz hintereinander announcen
    let parents = pc_types::ParentList::default();
    let hdr = AnchorHeader {
        version: 5,
        shard_id: 0,
        parents,
        payload_hash: [9u8; 32],
        creator_index: 0,
        vote_mask: 1,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0u8; 32],
        vote_epoch: 0,
        vote_round: 0,
        state_root: Some([0x11; 32]),
        attest_sig: None,
    };
    let _ = svc
        .send_message(explicit_announce_for_header(hdr.clone()))
        .await;
    let _ = svc
        .send_message(explicit_announce_for_header(hdr.clone()))
        .await;

    // Briefly collect outbox and count GetPayloads for the root.
    // Sammle Outbox kurzzeitig und zähle GetPayloads für den Root
    let mut count = 0usize;
    let _ = timeout(Duration::from_millis(400), async {
        while let Some(msg) = out.recv().await {
            if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                count += roots.iter().filter(|r| **r == [9u8; 32]).count();
            }
        }
    })
    .await; // Timeout expected / Timeout erwartet

    assert_eq!(count, 1, "es darf nur ein GetPayloads pro Root geben");

    // Shutdown.
    // Shutdown
    let _ = svc.shutdown().await;
    let _ = handle.await;
}
