# Continuous Mining Change Journal

Timestamp: `2026-03-14 13:55:43 Europe/Berlin`

## Rollback Base

- Snapshot root: `.codex-tmp/continuous-mining-20260314-135543/snapshots`
- Preexisting diff patch: `.codex-tmp/continuous-mining-20260314-135543/meta/preexisting-diff.patch`
- Intent: keep every change small and reversible back to the captured current state

## Scope

- Goal: replace stop-and-wait internal mining with continuous mining plus `best-so-far` replacement semantics
- Safety rule: no destructive reset; every touched file must be logged here before and after the change

## Phase Log

### Phase 0: Snapshot and rollback prep

- Status: completed
- Files snapshotted:
  - `crates/pc-types/src/lib.rs`
  - `crates/pc-consensus/src/mint_censor_v1.rs`
  - `crates/phantom-node/src/main.rs`
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
  - `apps/phantom-dashboard/src/App.tsx`
  - `apps/phantom-dashboard/src-tauri/src/node_service.rs`
- Notes:
  - repository already contains many unrelated modifications; rollback for this task must use the snapshots above, not blind git checkout

### Phase 1: Stable work binding in protocol model

- Status: completed
- Implemented:
  - added stable optional `work_id` to `MintCandidateEvent` and `MintPoWCertV1`
  - added `GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1` and derived candidate feature bit mapping
  - added `mint_work_id_v1`, `candidate_work_id_v1`, and `pow_cert_work_id_v1`
  - kept legacy compatibility by falling back to `mint_commitment` when `work_id` is absent
  - switched mint-censor dedupe from `mint_commitment` to `work_id`
- Files touched:
  - `crates/pc-types/src/lib.rs`
  - `crates/pc-types/src/tests/mint_candidate_v1_tests.rs`
  - `crates/pc-consensus/src/mint_censor_v1.rs`
  - `crates/pc-consensus/src/tests/main_tests.rs`
- Verification:
  - `cargo test -p pc-types mint_candidate_v1_tests -- --nocapture`
  - `cargo test -p pc-consensus mint_censor_v1 -- --nocapture`

### Phase 2: Continuous local mining plus best-so-far replacement

- Status: in_progress
- Implemented so far:
  - local internal miner no longer waits for `last_mint_id` after every found mint
  - current tip keeps one active local mint slot, replacing the older local file when a better/newer local find appears
  - candidate evidence emission now tracks `best-so-far` per `work_id`
  - worse-or-equal replacements for the same `work_id` are dropped before persistence/gossip
  - better replacements remove older candidate/pow-cert evidence for the same `work_id`
- Files touched:
  - `crates/phantom-node/src/main.rs`
  - `crates/phantom-node/src/cli.rs`
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
  - `crates/phantom-node/tests/precommit_context_endpoints.rs`
- Verification:
  - `cargo test -p phantom-node candidate_replaces_existing_best -- --nocapture`
  - `cargo test -p phantom-node --bin phantom-node --no-run`
  - `cargo test -p phantom-node --no-run`
- Open items:
  - add focused runtime/behavior tests for replacement semantics
  - extend metrics/dashboard once runtime path is stable

### Phase 2a: Comparison helper and compile cleanup

- Status: completed
- Implemented:
  - extracted candidate replacement ordering into `candidate_replaces_existing_best(...)`
  - added unit coverage for pow-hash priority and deterministic tie-breakers
  - completed missing `work_id` propagation in integration test fixture `precommit_context_endpoints`
- Files touched:
  - `crates/phantom-node/src/main.rs`
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
  - `crates/phantom-node/tests/precommit_context_endpoints.rs`

### Phase 2b: Scope lifecycle and observability

- Status: completed
- Implemented:
  - added current candidate scope reset on `(prev_mint_id, window_id)` changes so in-memory best-so-far state does not grow unbounded across old windows/tips
  - added Prometheus metrics for active local mint slots, active candidate work slots, queued candidates, replacements, skipped-not-better candidates, and scope resets
  - added export test to verify the new continuous-mining metrics appear in `/metrics`
- Files touched:
  - `crates/phantom-node/src/main.rs`
  - `crates/phantom-node/src/cli.rs`
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
- Verification:
  - `cargo test -p phantom-node metrics_export_includes_continuous_mining_counters -- --nocapture`
  - `cargo test -p phantom-node --bin phantom-node --no-run`
  - `cargo test -p phantom-node --no-run`

### Phase 2c: Scope transition behavior tests

- Status: completed
- Implemented:
  - extracted candidate scope advancement into `advance_candidate_scope(...)`
  - added focused tests for:
    - no reset within the same `(prev_mint_id, window_id)` scope
    - reset on tip change
    - reset on window change
- Files touched:
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
- Verification:
  - `cargo test -p phantom-node candidate_scope_advance -- --nocapture`
  - `cargo test -p phantom-node --bin phantom-node --no-run`

### Phase 2d: Dashboard observability wiring

- Status: completed
- Implemented:
  - wired continuous-mining metrics into the frontend miner state and polling path
  - extended the Miner tab with:
    - active local slots
    - active work slots
    - queued candidates
    - replaced candidates
    - skipped candidates
    - scope resets
  - added the required frontend and backend i18n keys for all dashboard locales
- Files touched:
  - `apps/phantom-dashboard/src/App.tsx`
  - `apps/phantom-dashboard/src/i18n/en.ts`
  - `apps/phantom-dashboard/src/i18n/types.ts`
  - `crates/phantom-i18n/src/dashboard.rs`
- Verification:
  - `npm run build` in `apps/phantom-dashboard`
  - `cargo check -p phantom-i18n`
  - `cargo check -p phantom-dashboard`

### Phase 2e: Log- and validator-path visibility

- Status: completed
- Implemented:
  - exposed the new continuous-mining counters directly in the Validator tab consensus/finality section
  - added compact live metric strips above:
    - `Miner + Mint Logs`
    - `Validator + Finality Logs`
- Files touched:
  - `apps/phantom-dashboard/src/App.tsx`
- Verification:
  - `npm run build` in `apps/phantom-dashboard`

### Phase 2f: Mint-file replacement race hardening

- Status: completed
- Implemented:
  - classified `mint file read failed` into:
    - transient `NotFound` races caused by continuous miner replacement
    - permanent unreadable-file failures
  - changed the mint-scan loop to silently skip transient missing files instead of logging and tombstoning them
  - kept the old drop-and-mark behavior for non-transient read failures
  - added focused unit tests for the classification helper
- Files touched:
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
- Verification:
  - `cargo test -p phantom-node mint_file_read_error_classification -- --nocapture`
  - `cargo build -p phantom-node --bin phantom-node`

### Phase 2g: Genesis-compatible work_id emission

- Status: completed
- Implemented:
  - gated `work_id` emission in mint candidate / pow-cert evidences behind the existing genesis feature bit
  - kept the internal best-so-far slot keyed by deterministic work-id even when the current genesis cannot encode `work_id`
  - added focused tests for enabled/disabled work-id emission
- Files touched:
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
- Verification:
  - `cargo test -p phantom-node runtime_candidate_work_id -- --nocapture`
  - `cargo build -p phantom-node --bin phantom-node`

### Phase 2h: Legacy work_id evidence cleanup hygiene

- Status: completed
- Implemented:
  - kept deleting legacy local evidence files that contain `work_id` on a genesis without the `work_id` feature
  - suppressed the corresponding bootstrap-ingest warning spam for this one known compatibility case
  - added a focused helper test for the bootstrap-ingest logging policy
- Files touched:
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
- Verification:
  - `cargo test -p phantom-node bootstrap_evidence_drop_logging -- --nocapture`
  - `cargo build -p phantom-node --bin phantom-node`

## Rollback Notes

- To restore a touched file to the captured base state, copy it back from:
  - `.codex-tmp/continuous-mining-20260314-135543/snapshots/<relative-path>`
- Do not use blind `git checkout` in this repository state; unrelated user changes already exist outside this task scope.

### Phase 2i: Dashboard bootstrap genesis lifts work_id feature

- Status: completed
- Implemented:
  - added `GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1` to the dashboard bootstrap genesis builder so new bootstrap resets carry continuous-mining replacement semantics into consensus
  - extended the existing solo-bootstrap feature test to assert the new work-id feature bit
  - extended the existing bootstrap feature-upgrade / single-seat autofix path so older `features=0x0d` bootstrap notes are rewritten to include `work_id`
  - rebuilt `phantom-dashboard` and mirrored the fresh binary to `target/debug/Phantom.Coin Miner Dashboard`
- Files touched:
  - `apps/phantom-dashboard/src-tauri/src/node_service.rs`
- Verification:
  - `cargo check -p phantom-dashboard`
  - `cargo test -p phantom-dashboard build_bootstrap_genesis_note_enables_required_solo_features -- --nocapture`
  - `cargo build -p phantom-dashboard`

### Phase 2j: Drop stale mint-censor evidences on network_id change

- Status: completed
- Implemented:
  - reject `MintCandidateV1` and `MintPoWCertV1` during mint-censor ingest when their `network_id` does not match the active runtime network
  - this prevents old mempool evidences from a pre-upgrade bootstrap genesis from poisoning new pending payloads after the dashboard rewrites `genesis_note.bin`
  - exposed `should_log_bootstrap_evidence_drop` as `pub(crate)` so the existing helper tests remain valid
- Files touched:
  - `crates/phantom-node/src/main.rs`
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
- Verification:
  - `cargo test -p phantom-node mint_censor_evidence_ingest_policy_rejects_candidate_network_mismatch -- --nocapture`
  - `cargo test -p phantom-node mint_censor_evidence_ingest_policy_rejects_pow_cert_network_mismatch -- --nocapture`
  - `cargo build -p phantom-node --bin phantom-node`

### Phase 2k: Prune already-finalized local mint files from candidate scanning

- Status: in_progress
- Implemented:
  - prune a local mint file immediately when it already matches the current finalized `last_mint_id` and mint-censor mode is active
  - this prevents the mint tick from rewinding candidate generation onto the previous tip and repeatedly resetting the active candidate scope inside the same mint window
  - added a focused helper test for the pruning decision
- Files touched:
  - `crates/phantom-node/src/quic_server.rs`
  - `crates/phantom-node/src/tests.rs`
- Verification:
  - pending

### Phase 2l: Temporary local finalizer helper for live continuous-mining verification

- Status: in_progress
- Implemented:
  - added a temporary helper binary that mirrors the dashboard single-seat finalizer flow without depending on the GUI start path
  - helper resolves local prevote/precommit context from `status-serve`, signs with `phantom-signer`, and injects headers with `phantom-node p2p-inject-headers`
  - intended only for reproducible live verification while the dashboard-managed finalizer path is unstable
- Files touched:
  - `apps/phantom-dashboard/src-tauri/src/bin/local_single_seat_finalizer.rs`
- Verification:
  - pending

### Phase 2m: Align dashboard start path with bootstrap continuous-mining runtime

- Status: completed
- Implemented:
  - `Node Start` now respects the persisted `nodePowMiner` role flag instead of forcibly starting with `pow_miner=false`
  - added a dashboard backend readiness barrier before the local single-seat finalizer starts: wait for a non-empty `p2p_quic_cert.der` and for `status-serve /readyz` to answer successfully
  - on readiness failure, the partially started `p2p`/`status-serve` children are cleaned up immediately instead of leaving a half-started stack behind
- Files touched:
  - `apps/phantom-dashboard/src/App.tsx`
  - `apps/phantom-dashboard/src-tauri/src/node_service.rs`
- Verification:
  - `npm run build` in `apps/phantom-dashboard`
  - `cargo check -p phantom-dashboard`
  - `cargo build -p phantom-dashboard`
