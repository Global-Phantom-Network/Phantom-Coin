// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(feature = "async")]

use criterion::{criterion_group, criterion_main, Criterion};
use pc_p2p::async_svc::spawn as p2p_spawn;
use pc_p2p::messages::{P2pMessage, ReqMsg};
use pc_p2p::{P2pConfig, RateLimitConfig};
use pc_types::AnchorId;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::time::timeout;

fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .measurement_time(Duration::from_secs(60))
}

fn bench_ratelimit_inv_to_req_1rps(c: &mut Criterion) {
    let rt = Runtime::new().expect("create tokio runtime");

    c.bench_function("p2p_ratelimit_inv_to_req_1rps", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            // Rate limit: throttle INV to 1 token per second.
            // RateLimit: INV auf 1 Token/Sekunde drosseln
            let rl = RateLimitConfig {
                hdr_capacity: 1000,
                hdr_refill_per_sec: 1000,
                inv_capacity: 1,
                inv_refill_per_sec: 1,
                req_capacity: 1000,
                req_refill_per_sec: 1000,
                resp_capacity: 1000,
                resp_refill_per_sec: 1000,
                bytes_capacity: 0,
                bytes_refill_per_sec: 0,
                per_peer: true,
                peer_ttl_secs: 60,
            };
            let cfg = P2pConfig {
                max_peers: 16,
                rate: Some(rl),
                peers_json_path: None,
                enable_peer_exchange: false,
                network_id: None,
            };
            let (svc, mut out_rx, handle) = p2p_spawn(cfg);

            let start_all = Instant::now();
            for i in 0..iters {
                // Unique header id (INV is rate-limited, and HEADERS_INV triggers GET_HEADERS).
                // Eindeutige HeaderId (INV ist rate-limited, und HEADERS_INV triggert GET_HEADERS).
                let mut id_bytes = [0u8; 32];
                id_bytes[..8].copy_from_slice(&i.to_be_bytes());
                let id = AnchorId(id_bytes);

                let iter_start = Instant::now();
                let got_req = loop {
                    // Send INV (possibly throttled by rate limiter).
                    // INV senden (möglicherweise durch RL gedrosselt)
                    let _ = svc
                        .send_message(P2pMessage::HeadersInv { ids: vec![id] })
                        .await;

                    // Wait briefly and look for the matching Req.
                    // Kurz warten und nach dem passenden Req suchen
                    let mut found = false;
                    // Collect several outbox messages in a short burst.
                    // Sammelt kurzfristig mehrere Outbox-Nachrichten
                    for _ in 0..8 {
                        match timeout(Duration::from_millis(20), out_rx.recv()).await {
                            Ok(Some(msg))
                                if matches!(
                                    msg.message(),
                                    P2pMessage::Req(ReqMsg::GetHeaders { .. })
                                ) =>
                            {
                                let P2pMessage::Req(ReqMsg::GetHeaders { ids }) = msg.message()
                                else {
                                    unreachable!();
                                };
                                if ids.contains(&id) {
                                    found = true;
                                    break;
                                }
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(_) => {}
                        }
                    }
                    if found {
                        break true;
                    }

                    // If not found, sleep briefly before the next attempt.
                    // Wenn nicht gefunden, kurze Pause bis zum nächsten Versuch
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Guard against excessively long wait times.
                    // Schutz gegen extrem lange Wartezeiten
                    if iter_start.elapsed() > Duration::from_secs(3) {
                        break false;
                    }
                };
                assert!(got_req, "expected GetHeaders under rate limit");
            }
            let elapsed = start_all.elapsed();

            // Shutdown.
            // Shutdown
            let _ = svc.shutdown().await;
            let _ = handle.await;

            elapsed
        })
    });
}

criterion_group!(
    name = benches;
    config = bench_config();
    targets = bench_ratelimit_inv_to_req_1rps
);
criterion_main!(benches);
