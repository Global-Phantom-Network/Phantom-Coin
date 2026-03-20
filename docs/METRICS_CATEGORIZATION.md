# Phantom-Coin Metrics: Inventory + Placement (Core vs Clients)

This document lists the observability surfaces in this repo and classifies what belongs in:

- Core/runtime (node/miner/p2p processes): single source of truth, machine-readable (Prometheus or JSON).
- Clients (GUI/CLI/TUI): presentation and derived views (rates, sparklines, warnings), plus safe actions.

## Core: Prometheus `/metrics`

### `phantom-node` (P2P + node runtime metrics)

Exposed by:

- `phantom-node p2p-quic-listen --metrics-addr 127.0.0.1:9100` (in-process; loopback only)
- `phantom-node p2p-metrics-serve --addr 127.0.0.1:9100` (separate helper process; also loopback only)

Metrics families (names as exported):

- P2P (core, `pc-p2p`)
  - `pc_p2p_inbound_total`, `pc_p2p_outbound_total`
  - `pc_p2p_inbound_bytes_total`, `pc_p2p_outbound_bytes_total`
  - `pc_p2p_inbound_dropped_rate`
  - `pc_p2p_peer_rl_purged_total`
  - `pc_p2p_in_hdr_total`, `pc_p2p_in_inv_total`, `pc_p2p_in_req_total`, `pc_p2p_in_resp_total`
  - `pc_p2p_out_hdr_total`, `pc_p2p_out_inv_total`, `pc_p2p_out_req_total`, `pc_p2p_out_resp_total`
  - `pc_p2p_out_errors_total`
  - `pc_p2p_outbox_enq_total`, `pc_p2p_outbox_deq_total`, `pc_p2p_outbox_drop_total`, `pc_p2p_outbox_depth`
  - `pc_p2p_in_dedup_total`
  - `pc_p2p_peers_known_total`, `pc_p2p_peers_miner_total`, `pc_p2p_peers_validator_total`, `pc_p2p_peers_banned_total`
  - `pc_p2p_in_handle_seconds` (histogram)

- Node store/cache/mempool/proposer (core, `phantom-node`)
  - Persist counters:
    - `pc_node_persist_headers_total`, `pc_node_persist_headers_errors_total`
    - `pc_node_persist_payloads_total`, `pc_node_persist_payloads_errors_total`
    - `pc_node_inbound_obs_lagged_total`
  - Persist latency:
    - `pc_node_persist_seconds` (histogram)
  - Cache counters:
    - `pc_node_cache_headers_hits_total`, `pc_node_cache_headers_misses_total`
    - `pc_node_cache_payloads_hits_total`, `pc_node_cache_payloads_misses_total`
  - Disk-read histograms:
    - `pc_node_store_header_read_seconds`
    - `pc_node_store_payload_read_seconds`
  - Mempool:
    - `pc_node_mempool_size`
    - `pc_node_mempool_accepted_total`, `pc_node_mempool_rejected_total`, `pc_node_mempool_duplicate_total`
    - `pc_node_mempool_ttl_evict_total`, `pc_node_mempool_cap_evict_total`, `pc_node_mempool_invalidated_total`
  - Proposer:
    - `pc_node_proposer_built_total`, `pc_node_proposer_last_size`, `pc_node_proposer_pending`
    - `pc_node_proposer_errors_total`

- Consensus/verification (core)
  - Finality:
    - `pc_node_finality_seconds` (histogram)
    - `pc_node_finality_events_total`
  - Aggregate verify latency:
    - `pc_node_verify_seconds` (histogram)
  - Vote verification counters:
    - `pc_node_votes_sent_total`, `pc_node_votes_accepted_total`, `pc_node_votes_rejected_total`

- Process (core; local best-effort)
  - `pc_node_process_cpu_percent`
  - `pc_node_process_rss_bytes`

- Role/Validator (core; local, no labels)
  - `pc_node_role_flags` (0=fullnode,1=validator,2=miner)
  - Eligibility:
    - `pc_node_validator_id_configured`
    - `pc_node_validator_stake`, `pc_node_validator_min_stake`
    - `pc_node_validator_pop_ok`, `pc_node_validator_policy_ok`
    - `pc_node_validator_eligible`, `pc_node_validator_conditions_ok`
    - `pc_node_validator_voting_enabled`
  - Control:
    - `pc_node_validator_control_kill_switch`
    - `pc_node_validator_control_maintenance`
    - `pc_node_validator_control_manual_disable`
    - `pc_node_validator_control_auto_reenable`
    - `pc_node_validator_control_cooldown_until_epoch`
    - `pc_node_validator_control_updated_at_epoch`

- DA gating config gauges (core; currently "config as metrics" for debugging)
  - `pc_node_da_gating_cfg_payload_wait_timeout_secs`
  - `pc_node_da_gating_cfg_retry_initial_delay_ms`
  - `pc_node_da_gating_cfg_retry_max_delay_ms`
  - `pc_node_da_gating_cfg_retry_max_retries`
  - `pc_node_da_gating_cfg_retry_jitter_pct`

Notes:

- These metrics are process-local. A separate process cannot "see" the node's counters unless the node itself exposes them.
- `p2p-quic-listen --metrics-addr ...` is the recommended way because it exposes the live node's counters.

### `phantom-node status-serve` (HTTP service metrics)

Exposed by `phantom-node status-serve` at `GET /metrics` (loopback only).

This is separate from the P2P runtime metrics above and focuses on HTTP/RPC counters, e.g.:

- `phantom_node_rpc_broadcast_*`
- `phantom_node_consensus_*` (totals + `_errors_total` per endpoint)
- plus some shared `pc_node_*` histograms/counters (finality/verify/votes) and genesis gauges

### `phantom-miner` (mining process metrics)

Exposed by:

- `phantom-miner mine --metrics-addr 127.0.0.1:9200 ...` (in-process; loopback only)

Metrics (names as exported):

- Process/runtime:
  - `pc_miner_uptime_seconds`
  - `pc_miner_process_rss_bytes`
  - `pc_miner_threads`
- Hashing:
  - `pc_miner_hashes_total`
  - `pc_miner_hashrate_hps`
- Template + submit results:
  - `pc_miner_templates_total`
  - `pc_miner_template_errors_total`
  - `pc_miner_submit_accepted_total`
  - `pc_miner_submit_stale_total` (409 CONFLICT)
  - `pc_miner_submit_rejected_total`
  - `pc_miner_submit_errors_total`
  - `pc_miner_last_template_epoch`
  - `pc_miner_last_submit_ok_epoch`

## Core: JSON status endpoints

### `status_http` (read-only wallet/status)

`phantom-node --bin status_http` provides:

- `GET /status` minimal readiness JSON (ok/service/ts)
- `GET /wallet/history/<lock_hex>` wallet UTXO history and balances (including staked vs unstaked)
- Local helper for GUI/TUI and loopback workflows; not the recommended production API surface.
- For production use `phantom-node status-serve` with explicit TLS/Auth configuration.
- Auto-generated certificates in `status_http` are a local convenience path, not a production deployment mode.

Used by:

- GUI wallet: Wallet tab, UTXO selection (validator staking UI), status readiness.
- TUI: `phantom-tui` `Status` reads `/status`.

### `mint_rpc` (minting RPC)

`phantom-node --bin mint_rpc` provides:

- `GET /mint/status` (`pc_types::MintStatus`)
- `GET /mint/template` (`pc_types::MintTemplate`)
- `POST /mint/submit` (`pc_types::SubmitMintRequest` -> `SubmitMintResponse`)

Used by:

- `phantom-miner` and GUI Mining dashboard (block height, supply, difficulty).

### `status-serve` (node/mempool/consensus service)

`phantom-node status-serve` provides:

- `GET /status`, `/readyz`, `/healthz`
- `GET /consensus/config` (includes DA-gating and rotation config)
- `POST /consensus/set_rotation_context`
- consensus endpoints used by validators/clients

## Core: On-disk "status/config" files

These are not Prometheus metrics, but they are core state/config surfaces used by multiple clients.

- `/var/lib/phantom-coin/data/stake_registry.json`: legacy/bootstrap validator registry if present
  - Read by node startup as a fallback input for initial network-scale calculation.
  - Runtime validator eligibility is derived from on-chain validator records + staked UTXOs, not from this file.
- `/var/lib/phantom-coin/data/validator_control.json` (see `pc_consensus::validator_control`)
  - Single source of truth for fail-safe controls: kill-switch, maintenance, manual disable, auto re-enable.
  - Read by node runtime; edited by GUI; can be managed by `phantom-node validator-control ...`.
- `/var/lib/phantom-coin/data/mempool/role_policy.json` (role allow-list policy)
  - Enforced by node runtime.

## Client-only (GUI/CLI/TUI): what should NOT go into core

These are presentation/UX and should remain in clients:

- Formatting:
  - human readable byte formatting, short hashes, time formatting
  - colors, icons, warning triangles, etc
- Derived views:
  - vote rates 1m/10m/1h (derived from monotonic counters)
  - sparklines (time-series rendering)
  - tip age, "connecting..." heuristics
- UI safety:
  - double-confirm dialogs/timers for critical actions (GUI)
  - local preference toggles like "show rates" / "show sparklines"

## Placement rules (pragmatic)

Put it in core if:

- multiple frontends need it (GUI + CLI + TUI), or
- it is security-/safety-relevant (eligibility, role state, kill-switch state), or
- it is required to debug consensus/network issues reliably.

Keep it in clients if:

- it's just presentation or aggregation (rates, sparklines), or
- it requires interactive confirmation UX.

## Remaining TODOs (optional, next iteration)

- (done) Unify the Prometheus renderer between `p2p-metrics-serve` and `p2p-quic-listen --metrics-addr`.
- (done) Export local role/eligibility/control as low-cardinality gauges.
- (done) Add CLI/TUI views for miner metrics (HTTP GET + parse) so GUI is not the only consumer.
