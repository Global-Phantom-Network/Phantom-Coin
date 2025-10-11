// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![cfg(feature = "async")]

use criterion::{criterion_group, criterion_main, Criterion};
use pc_p2p::async_svc::spawn as p2p_spawn;
use pc_p2p::messages::{P2pMessage, ReqMsg};
use pc_p2p::{P2pConfig, RateLimitConfig};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::time::timeout;

fn bench_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .measurement_time(Duration::from_secs(60))
}

fn bench_ratelimit_inv_to_req_1rps(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("p2p_ratelimit_inv_to_req_1rps", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
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
                per_peer: true,
                peer_ttl_secs: 60,
            };
            let cfg = P2pConfig { max_peers: 16, rate: Some(rl) };
            let (svc, mut out_rx, handle) = p2p_spawn(cfg);

            let start_all = Instant::now();
            for i in 0..iters {
                // Eindeutiger Root
                let mut root = [0u8; 32];
                root[..8].copy_from_slice(&i.to_be_bytes());

                let iter_start = Instant::now();
                let got_req = loop {
                    // INV senden (möglicherweise durch RL gedrosselt)
                    let _ = svc
                        .send_message(P2pMessage::PayloadInv { roots: vec![root] })
                        .await;

                    // Kurz warten und nach dem passenden Req suchen
                    let mut found = false;
                    // Sammelt kurzfristig mehrere Outbox-Nachrichten
                    for _ in 0..8 {
                        match timeout(Duration::from_millis(20), out_rx.recv()).await {
                            Ok(Some(P2pMessage::Req(ReqMsg::GetPayloads { roots }))) => {
                                if roots.contains(&root) {
                                    found = true;
                                    break;
                                }
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(_) => {}
                        }
                    }
                    if found { break true; }

                    // Wenn nicht gefunden, kurze Pause bis zum nächsten Versuch
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    // Schutz gegen extrem lange Wartezeiten
                    if iter_start.elapsed() > Duration::from_secs(3) {
                        break false;
                    }
                };
                assert!(got_req, "expected GetPayloads under rate limit");
            }
            let elapsed = start_all.elapsed();

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
