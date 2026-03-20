# Criterion Aggregation

| bench | p50 | p95 | timeout_rate | tp_ops | n | timeouts |
|---|---:|---:|---:|---:|---:|---:|
| p2p_backpressure_inv_to_req_payload | 1190577808 |  |  |  |  |  |
| p2p_batch_headers_inv_rr | 726134.78125 | 1507961 | 0 |  | 1 |  |
| p2p_dedupe_ttl_payload_inv | 1201545040.5 | 1201575890 | 0 |  | 1 |  |
| p2p_header_announce_gossip | 21845220.145833336 | 21940832 | 0 |  | 1 |  |
| p2p_header_announce_gossip_hb_1s | 31687251.333333336 | 32840371 | 0 |  | 1 |  |
| p2p_header_announce_gossip_relaxed | 21953844.97777778 | 21555129 | 0 |  | 1 |  |
| p2p_inv_to_req_headers_missing | 287185.45946655667 |  |  |  |  |  |
| p2p_inv_to_req_payload_missing | 742971.8385397692 |  |  |  |  |  |
| p2p_libp2p_e2e_inv_to_resp_headers | 377531.76964038727 | 1075258 | 0 |  | 1 |  |
| p2p_libp2p_e2e_inv_to_resp_headers_gossip | 681210.9666666667 | 930198 | 0 |  | 1 |  |
| p2p_libp2p_e2e_inv_to_resp_payloads | 349573.1125 | 524735 | 0 |  | 1 |  |
| p2p_libp2p_e2e_inv_to_resp_payloads_gossip | 700096.8055555555 | 998588 | 0 |  | 1 |  |
| p2p_libp2p_rpc_get_headers | 603930.125 | 1099771 | 0 |  | 1 |  |
| p2p_libp2p_rpc_get_payloads | 520043.5 | 747027 | 0 |  | 1 |  |
| p2p_quic_rpc_warm_get_headers | 342973.375 | 432342 | 0 |  | 1 |  |
| p2p_quic_rpc_warm_get_payloads | 306251.15 | 949781 | 0 |  | 1 |  |
| p2p_ratelimit_inv_to_req_1rps | 843072196.75 |  |  |  |  |  |
| p2p_rpc_cold_start_get_headers | 1696403.7865497076 | 3471008 | 0 |  | 1 |  |
| p2p_rpc_notfound_headers | 485900.125 | 792511 | 0 |  | 1 |  |
| p2p_rpc_parallel_get_payloads_8 | 897632.1428571428 | 1349777 | 0 |  | 1 |  |
| p2p_rpc_payload_size_sweep | 2095505.6555555556 | 1480956 | 0 |  | 1 |  |
| p2p_rpc_retry_get_headers | 2554137533 |  |  |  |  | 1 |
| p2p_rpc_warm_start_get_headers | 288745.9444444445 | 1390830 | 0 |  | 1 |  |
| p2p_throughput_headers | 20815698428.5 |  |  | 8262.832 |  | 1345 |
| p2p_two_hop_headers_gossip | 801743035 |  |  |  |  | 1 |
