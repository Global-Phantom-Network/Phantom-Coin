// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(feature = "async")]

use criterion::{criterion_group, criterion_main, Criterion};
use pc_p2p::async_svc::spawn as p2p_spawn;
use pc_p2p::messages::{explicit_announce_for_header, P2pMessage, ReqMsg};
use pc_p2p::P2pConfig;
use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId, ParentList};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::runtime::Runtime;
use tokio::time::{timeout, Duration};

static CTR: AtomicU64 = AtomicU64::new(0);

fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .measurement_time(std::time::Duration::from_secs(60))
}

fn bench_inv_to_req_payload_missing(c: &mut Criterion) {
    let rt = Runtime::new().expect("create tokio runtime");

    c.bench_function("p2p_inv_to_req_payload_missing", |b| {
        b.to_async(&rt).iter(|| async {
            let cfg = P2pConfig {
                max_peers: 16,
                rate: None,
                peers_json_path: None,
                enable_peer_exchange: false,
                network_id: None,
            };
            let (svc, mut out_rx, handle) = p2p_spawn(cfg);

            // einzigartiger Root
            let ctr = CTR.fetch_add(1, Ordering::Relaxed);
            let mut root = [0u8; 32];
            root[..8].copy_from_slice(&ctr.to_be_bytes());

            // PAYLOAD_INV does not trigger GET_PAYLOADS (DoS-hardening).
            // A header referencing the root triggers a GET_PAYLOADS request instead.
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents: ParentList::default(),
                payload_hash: root,
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };
            let _ = svc.send_message(explicit_announce_for_header(hdr)).await;
            let got_req = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_rx.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                            if roots.contains(&root) {
                                return true;
                            }
                        }
                    } else {
                        return false;
                    }
                }
            })
            .await
            .ok()
            .unwrap_or(false);
            assert!(got_req, "expected GetPayloads req for missing root");

            let _ = svc.shutdown().await;
            let _ = handle.await;
        })
    });
}

fn bench_inv_to_req_headers_missing(c: &mut Criterion) {
    let rt = Runtime::new().expect("create tokio runtime");

    c.bench_function("p2p_inv_to_req_headers_missing", |b| {
        b.to_async(&rt).iter(|| async {
            let cfg = P2pConfig {
                max_peers: 16,
                rate: None,
                peers_json_path: None,
                enable_peer_exchange: false,
                network_id: None,
            };
            let (svc, mut out_rx, handle) = p2p_spawn(cfg);

            // einzigartiger HeaderId
            let ctr = CTR.fetch_add(1, Ordering::Relaxed);
            let mut id_bytes = [0u8; 32];
            id_bytes[..8].copy_from_slice(&ctr.to_be_bytes());
            let id = AnchorId(id_bytes);

            let _ = svc
                .send_message(P2pMessage::HeadersInv { ids: vec![id] })
                .await;
            let got_req = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_rx.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetHeaders { ids }) = msg.message() {
                            if ids.contains(&id) {
                                return true;
                            }
                        }
                    } else {
                        return false;
                    }
                }
            })
            .await
            .ok()
            .unwrap_or(false);
            assert!(got_req, "expected GetHeaders req for missing header");

            let _ = svc.shutdown().await;
            let _ = handle.await;
        })
    });
}

criterion_group!(
    name = benches;
    config = bench_config();
    targets = bench_inv_to_req_payload_missing, bench_inv_to_req_headers_missing
);
criterion_main!(benches);
