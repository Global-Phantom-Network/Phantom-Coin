# Criterion Aggregation

| bench | p50 | p95 | timeout_rate | n | timeouts |
|---|---:|---:|---:|---:|---:|
| p2p_backpressure_inv_to_req_payload | 1302214151.75 |  |  |  |  |
| p2p_batch_headers_inv_rr | 682190.09375 | 1481115 | 0 | 117 |  |
| p2p_dedupe_ttl_payload_inv | 1201498848 | 1202901541 | 0 | 11 |  |
| p2p_header_announce_gossip | 22195331.095238097 | 23572508 | 0 | 62 |  |
| p2p_header_announce_gossip_hb_1s | 32104287.05 | 33783625 | 0 | 117 |  |
| p2p_header_announce_gossip_relaxed | 22287301.333333336 | 23564542 | 0 | 62 |  |
| p2p_inv_to_req_headers_missing | 34232.53845395135 |  |  |  |  |
| p2p_inv_to_req_payload_missing | 32442.39557797072 |  |  |  |  |
| p2p_libp2p_e2e_inv_to_resp_headers | 268576.82799841143 | 461171 | 0 | 77436 |  |
| p2p_libp2p_e2e_inv_to_resp_headers_gossip | 672566.3333333333 | 1267556 | 0 | 117 |  |
| p2p_libp2p_e2e_inv_to_resp_payloads | 394474.1666666667 | 647861 | 0 | 117 |  |
| p2p_libp2p_e2e_inv_to_resp_payloads_gossip | 644791.0305555556 | 1169128 | 0 | 117 |  |
| p2p_libp2p_rpc_get_headers | 421059.2083333334 | 706126 | 0 | 117 |  |
| p2p_libp2p_rpc_get_payloads | 371414.2 | 579455 | 0 | 117 |  |
| p2p_quic_rpc_warm_get_headers | 284746.725 | 497128 | 0 | 117 |  |
| p2p_quic_rpc_warm_get_payloads | 302783 | 562425 | 0 | 117 |  |
| p2p_ratelimit_inv_to_req_1rps | 851674353.75 |  |  |  |  |
| p2p_rpc_cold_start_get_headers | 1889238.2996697156 | 2522670 | 0.00009957184108334163 | 10042 | 1 |
| p2p_rpc_notfound_headers | 473593.56111111114 | 777410 | 0 | 117 |  |
| p2p_rpc_parallel_get_payloads_8 | 804396.3333333333 | 1511751 | 0 | 117 |  |
| p2p_rpc_payload_size_sweep | 2225545.537037037 | 7046250 | 0 | 180 |  |
| p2p_rpc_retry_get_headers | 2554916711 |  |  |  | 11 |
| p2p_rpc_warm_start_get_headers | 369973.47222222225 | 774478 | 0 | 180 |  |
| p2p_two_hop_headers_gossip | 801613237.5 |  |  |  | 11 |
