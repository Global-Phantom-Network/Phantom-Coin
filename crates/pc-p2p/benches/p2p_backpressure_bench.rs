// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(feature = "async")]

use criterion::{criterion_group, criterion_main, Criterion};
use pc_p2p::async_svc::spawn as p2p_spawn;
use pc_p2p::messages::{explicit_announce_for_header, P2pMessage, ReqMsg};
use pc_p2p::P2pConfig;
use pc_types::{AnchorHeaderV2 as AnchorHeader, ParentList};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

static CTR: AtomicU64 = AtomicU64::new(0);

fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .measurement_time(std::time::Duration::from_secs(60))
}

fn bench_inv_to_req_under_backpressure(c: &mut Criterion) {
    let rt = Runtime::new().expect("create tokio runtime");

    c.bench_function("p2p_backpressure_inv_to_req_payload", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let cfg = P2pConfig {
                max_peers: 16,
                rate: None,
                peers_json_path: None,
                enable_peer_exchange: false,
                network_id: None,
            };
            let (svc, mut out_rx, handle) = p2p_spawn(cfg);

            // Consumer, der langsam drainiert, um Backpressure zu erzeugen
            let (obs_tx, mut obs_rx) = mpsc::channel::<pc_p2p::async_svc::OutboundEnvelope>(4096);
            let consumer = tokio::spawn(async move {
                while let Some(msg) = out_rx.recv().await {
                    // Nur relevante Req-Nachrichten weiterreichen, um obs-Kanal nicht zu fluten
                    if matches!(msg.message(), P2pMessage::Req(_)) {
                        let _ = obs_tx.send(msg).await;
                    }
                    tokio::time::sleep(Duration::from_micros(20)).await;
                }
            });

            let mut elapsed_total = Duration::ZERO;
            for _ in 0..iters {
                // Outbox mit niedriger Priorität füllen (HeaderAnnounce werden bei Voll-Druck gedroppt)
                for _ in 0..2000 {
                    let parents = ParentList::default();
                    let hdr = AnchorHeader {
                        version: 2,
                        shard_id: 0,
                        parents,
                        payload_hash: [0u8; 32],
                        creator_index: 1,
                        vote_mask: 0,
                        ack_present: false,
                        ack_id: pc_types::AnchorId([0u8; 32]),
                        network_id: [0u8; 32],
                        vote_epoch: 0,
                        vote_round: 0,
                        state_root: None,
                        attest_sig: None,
                    };
                    let _ = svc.announce_header(hdr).await;
                }

                // Einzigartigen Root erzeugen
                let ctr = CTR.fetch_add(1, Ordering::Relaxed);
                let mut root = [0u8; 32];
                root[..8].copy_from_slice(&ctr.to_be_bytes());

                // Under the current DoS-hardening rules, `PayloadInv` is treated as a hint only
                // and does not trigger fetching/persisting payloads on its own.
                //
                // Instead, the node requests payloads when they are needed, e.g. referenced by an
                // admitted header. This bench therefore measures how quickly an inbound
                // HeaderAnnounce leads to an outbound GetPayloads request under backpressure.
                let parents = ParentList::default();
                let hdr = AnchorHeader {
                    version: 2,
                    shard_id: 0,
                    parents,
                    payload_hash: root,
                    creator_index: 2,
                    vote_mask: 0,
                    ack_present: false,
                    ack_id: pc_types::AnchorId([0u8; 32]),
                    network_id: [0u8; 32],
                    vote_epoch: 0,
                    vote_round: 0,
                    state_root: None,
                    attest_sig: None,
                };

                let start_i = Instant::now();
                let _ = svc.send_message(explicit_announce_for_header(hdr)).await;

                // Auf den zugehörigen GetPayloads-Req warten (etwas großzügigeres Timeout)
                let got = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if let Some(msg) = obs_rx.recv().await {
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
                assert!(got, "expected GetPayloads under backpressure");
                elapsed_total += start_i.elapsed();
            }

            // Shutdown
            let _ = svc.shutdown().await;
            let _ = handle.await;
            let _ = consumer.await;

            elapsed_total
        })
    });
}

criterion_group!(
    name = benches;
    config = bench_config();
    targets = bench_inv_to_req_under_backpressure
);
criterion_main!(benches);
