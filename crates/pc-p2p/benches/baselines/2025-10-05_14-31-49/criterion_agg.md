# Criterion Aggregation

| bench | p50 | p95 | timeout_rate | n | timeouts |
|---|---:|---:|---:|---:|---:|
| p2p_backpressure_inv_to_req_payload | 1300146713.5 |  |  |  |  |
| p2p_batch_headers_inv_rr | 778272.6777777778 | 1480253 | 0 | 62 |  |
| p2p_dedupe_ttl_payload_inv | 1201210961.5 | 1202596991 | 0 | 11 |  |
| p2p_header_announce_gossip | 21614935.708333336 | 22643358 | 0 | 62 |  |
| p2p_header_announce_gossip_hb_1s | 31768825.742857143 | 32460624 | 0 | 62 |  |
| p2p_header_announce_gossip_relaxed | 21701733.67857143 | 22379000 | 0 | 62 |  |
| p2p_inv_to_req_headers_missing | 34454.44512476737 |  |  |  |  |
| p2p_inv_to_req_payload_missing | 30545.59936842376 |  |  |  |  |
| p2p_libp2p_e2e_inv_to_resp_headers | 271718.50941780827 | 415936 | 0 | 72431 |  |
| p2p_libp2p_e2e_inv_to_resp_headers_gossip | 588599.4 | 960618 | 0 | 117 |  |
| p2p_libp2p_e2e_inv_to_resp_payloads | 362608.8428571429 | 515907 | 0 | 117 |  |
| p2p_libp2p_e2e_inv_to_resp_payloads_gossip | 561667.4047619047 | 954119 | 0 | 117 |  |
| p2p_libp2p_rpc_get_headers | 416584.34375 | 664294 | 0 | 117 |  |
| p2p_libp2p_rpc_get_payloads | 421235.9375 | 750000 | 0 | 117 |  |
| p2p_quic_rpc_warm_get_headers | 284746.725 | 497128 | 0 | 117 |  |
| p2p_quic_rpc_warm_get_payloads | 302783 | 562425 | 0 | 117 |  |
| p2p_ratelimit_inv_to_req_1rps | 853063317 |  |  |  |  |
| p2p_rpc_cold_start_get_headers | 1834604.3111702127 | 2279771 | 0 | 6193 |  |
| p2p_rpc_notfound_headers | 499688.4583333334 | 788673 | 0 | 62 |  |
| p2p_rpc_parallel_get_payloads_8 | 864712.3666666667 | 1235694 | 0 | 62 |  |
| p2p_rpc_payload_size_sweep | 2487436.5267857146 | 7357370 | 0 | 125 |  |
| p2p_rpc_retry_get_headers | 2553407464 |  |  |  | 11 |
| p2p_rpc_warm_start_get_headers | 410584.375 | 648386 | 0 | 125 |  |
| p2p_two_hop_headers_gossip | 801145860.5 |  |  |  | 11 |
