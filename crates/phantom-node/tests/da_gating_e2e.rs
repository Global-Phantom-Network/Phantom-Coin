// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

// No external HTTP/CLI dependencies required.
// keine externen HTTP/CLI Abhängigkeiten nötig
use pc_consensus::{ConsensusConfig, ConsensusEngine};
use pc_p2p::async_svc::{inbound_subscribe, spawn, watch_payload};
use pc_p2p::messages::{explicit_announce_for_header, P2pMessage, ReqMsg, RespMsg};
use pc_p2p::P2pConfig;
use pc_types::payload_merkle_root_v3 as payload_merkle_root;
use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV3 as AnchorPayload};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn da_gating_finalizes_only_after_payload() {
    // 1) Start internal P2P service (in-process).
    // 1) Starte internen P2P-Service (In-Process)
    let cfg = P2pConfig {
        max_peers: 8,
        rate: None,
        peers_json_path: None,
        enable_peer_exchange: false,
        network_id: None,
    };
    let (svc, mut out, handle) = spawn(cfg.clone());

    // 2) Consensus DA-gating minimal task.
    // 2) Konsensus-DA-Gating Minimal-Task
    let mut rx_in = inbound_subscribe();
    let (tx_final, mut rx_final) = tokio::sync::mpsc::unbounded_channel::<[u8; 32]>();
    let svc_c = svc.clone();
    tokio::spawn(async move {
        let eng = ConsensusEngine::new(ConsensusConfig::recommended(1));
        loop {
            match rx_in.recv().await {
                Ok(P2pMessage::PrevoteAnnounce(h)) | Ok(P2pMessage::PrecommitAnnounce(h)) => {
                    if h.state_root.is_some() && eng.is_final_mask(h.vote_mask) {
                        let root = h.payload_hash;
                        let txf = tx_final.clone();
                        let svc2 = svc_c.clone();
                        tokio::spawn(async move {
                            // Pull and then wait for payload.
                            // Pull und dann auf Payload warten
                            let _ = svc2
                                .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
                                    roots: vec![root],
                                }))
                                .await;
                            if timeout(Duration::from_secs(2), watch_payload(root))
                                .await
                                .is_ok()
                            {
                                let _ = txf.send(root);
                            }
                        });
                    }
                }
                Ok(P2pMessage::Resp(
                    RespMsg::PrevoteHeaders { headers } | RespMsg::PrecommitHeaders { headers },
                )) => {
                    for h in headers.into_iter() {
                        if h.state_root.is_some() && eng.is_final_mask(h.vote_mask) {
                            let root = h.payload_hash;
                            let txf = tx_final.clone();
                            let svc2 = svc_c.clone();
                            tokio::spawn(async move {
                                let _ = svc2
                                    .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
                                        roots: vec![root],
                                    }))
                                    .await;
                                if timeout(Duration::from_secs(2), watch_payload(root))
                                    .await
                                    .is_ok()
                                {
                                    let _ = txf.send(root);
                                }
                            });
                        }
                    }
                }
                Ok(P2pMessage::Resp(RespMsg::StagedHeaders {
                    prevote_headers,
                    precommit_headers,
                })) => {
                    for h in prevote_headers
                        .into_iter()
                        .chain(precommit_headers.into_iter())
                    {
                        if h.state_root.is_some() && eng.is_final_mask(h.vote_mask) {
                            let root = h.payload_hash;
                            let txf = tx_final.clone();
                            let svc2 = svc_c.clone();
                            tokio::spawn(async move {
                                let _ = svc2
                                    .send_message(P2pMessage::Req(ReqMsg::GetPayloads {
                                        roots: vec![root],
                                    }))
                                    .await;
                                if timeout(Duration::from_secs(2), watch_payload(root))
                                    .await
                                    .is_ok()
                                {
                                    let _ = txf.send(root);
                                }
                            });
                        }
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    });

    // 3) Prepare header and payload (root identical).
    // 3) Header + Payload vorbereiten (Root identisch)
    let payload = AnchorPayload {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
        null_mint: false,
    };
    let root = payload_merkle_root(&payload);
    let parents = pc_types::ParentList::default();
    let hdr = AnchorHeader {
        version: 5,
        shard_id: 0,
        parents,
        payload_hash: root,
        creator_index: 0,
        vote_mask: 1, // k=1 -> threshold = 1 -> final
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0u8; 32],
        vote_epoch: 0,
        vote_round: 0,
        state_root: Some([0x11; 32]),
        attest_sig: None,
    };

    // 4) Announce header (final) while payload is not yet delivered.
    // 4) Announce Header (final), Payload noch nicht geliefert
    let _ = svc.send_message(explicit_announce_for_header(hdr)).await;

    // Expectation: GetPayloads appears in the outbox stream.
    // Erwartung: GetPayloads im Outbox-Strom
    let req_roots = timeout(Duration::from_secs(1), async {
        loop {
            if let Some(msg) = out.recv().await {
                if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                    return Some(roots.clone());
                }
            } else {
                return None;
            }
        }
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    assert_eq!(req_roots, vec![root]);

    // Expectation: no finalization as long as no payload has been delivered.
    // Erwartung: Noch keine Finalisierung, solange keine Payload geliefert
    let not_final = timeout(Duration::from_millis(200), rx_final.recv()).await;
    assert!(not_final.is_err(), "should not finalize without payload");

    // 5) Deliver payload response (matching root).
    // 5) Liefere Payload-Resp (matching root)
    let _ = svc
        .send_message(P2pMessage::Resp(RespMsg::Payloads {
            payloads: vec![payload],
        }))
        .await;

    // Finalization should happen now.
    // Jetzt sollte finalisiert werden
    let done = timeout(Duration::from_secs(2), rx_final.recv())
        .await
        .ok()
        .flatten()
        .expect("finalization expected after payload arrival");
    assert_eq!(done, root);

    // Shutdown
    let _ = svc.shutdown().await;
    let _ = handle.await;
}
