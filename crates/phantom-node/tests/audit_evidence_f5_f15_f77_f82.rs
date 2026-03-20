// SPDX-License-Identifier: AGPL-3.0-only
//! Audit evidence tests for findings that are easiest to verify via deterministic source checks.
//!
//! The evidence matrix generator maps `fn f<ID>_*` test names to finding IDs.

use std::path::PathBuf;

fn node_main_rs_src() -> &'static str {
    include_str!("../src/main.rs")
}

fn node_quic_server_src() -> &'static str {
    include_str!("../src/quic_server.rs")
}

fn node_http_api_src() -> &'static str {
    include_str!("../src/http_api.rs")
}

fn node_finality_pipeline_src() -> &'static str {
    include_str!("../src/finality_pipeline.rs")
}

fn node_committee_selection_src() -> &'static str {
    include_str!("../src/committee_selection.rs")
}

fn node_status_http_src() -> &'static str {
    include_str!("../src/bin/status_http.rs")
}

fn dashboard_node_service_src() -> &'static str {
    include_str!("../../../apps/phantom-dashboard/src-tauri/src/node_service.rs")
}

fn node_cli_src() -> &'static str {
    include_str!("../src/cli.rs")
}

fn p2p_lib_src() -> &'static str {
    include_str!("../../pc-p2p/src/lib.rs")
}

fn p2p_libp2p_node_src() -> &'static str {
    include_str!("../../pc-p2p/src/libp2p_node.rs")
}

#[test]
fn f5_mempool_eviction_is_o1_and_fifo() {
    let src = node_quic_server_src();
    // Evidence of queue-based eviction (VecDeque) rather than `sort` on every insert.
    assert!(
        src.contains("mempool_order.pop_front()"),
        "expected FIFO eviction via VecDeque::pop_front"
    );
    assert!(
        src.contains("let mut mempool_order: VecDeque"),
        "expected mempool insertion order tracking via VecDeque"
    );
}

#[test]
fn f6_proposer_tick_has_random_jitter() {
    let src = node_quic_server_src();
    assert!(
        src.contains("prop_jitter_ms") && src.contains("interval_at("),
        "expected proposer tick to use interval_at(start+jitter, period)"
    );
    assert!(
        src.contains("random_range(0..=500)"),
        "expected bounded jitter range (0..=500ms)"
    );
}

#[test]
fn f7_peer_discovery_mutations_are_locked() {
    let src = node_quic_server_src();
    assert!(
        src.contains("outbound_active: Arc<Mutex<HashSet<SocketAddr>>>"),
        "expected peer set to be behind Arc<Mutex<...>> (no unlocked mutable Vec)"
    );
    assert!(
        src.contains(".lock().await") && src.contains("outbound_active"),
        "expected peer set mutations to be performed under a lock"
    );
}

#[test]
#[ignore = "yield_now not yet implemented in PoW miner"]
fn f8_pow_miner_does_not_block_the_runtime() {
    let src = node_quic_server_src();
    // Minimal liveness evidence: the miner yields periodically while searching for a nonce.
    assert!(
        src.contains("tokio::task::yield_now().await"),
        "expected PoW miner to periodically yield to avoid starving the runtime"
    );
}

#[test]
fn f9_status_serve_default_binds_to_loopback() {
    let src = node_http_api_src();
    assert!(
        src.contains("struct StatusServeArgs")
            && src.contains("default_value = \"127.0.0.1:8080\""),
        "expected status serve default bind to be 127.0.0.1:8080"
    );
}

#[test]
fn f10_max_payload_microtx_is_not_hardcoded_in_node_binary() {
    let src = node_main_rs_src();
    assert!(
        src.contains("use pc_types::MAX_PAYLOAD_MICROTX;"),
        "expected MAX_PAYLOAD_MICROTX to be imported from pc_types"
    );
    assert!(
        !src.contains("const MAX_PAYLOAD_MICROTX"),
        "expected no local hardcoded MAX_PAYLOAD_MICROTX constant"
    );
}

#[test]
fn f11_read_hex32_files_in_is_name_based_and_capped() {
    let src = node_cli_src();
    let start = src
        .find("fn read_hex32_files_in")
        .expect("read_hex32_files_in fn missing");
    let end = src[start..]
        .find("fn run_cache_bench")
        .map(|rel| start + rel)
        .unwrap_or(src.len());
    let body = &src[start..end];
    assert!(
        body.contains("file_stem") && body.contains("name.len() == 64"),
        "expected hex32 parsing from filename stem with fixed length"
    );
    assert!(
        body.contains("if out.len() >= max_n"),
        "expected max_n cap on directory traversal"
    );
    assert!(
        !body.contains("read_to_end")
            && !body.contains("std::fs::read(")
            && !body.contains("File::open"),
        "expected no file-content reads in read_hex32_files_in (OOM hardening)"
    );
}

#[test]
fn f12_db_reset_requires_yes_flag() {
    // This is a CLI behavior test: without `--yes`, db reset must fail before touching any DB.
    let bin = assert_cmd::cargo::cargo_bin!("phantom-node");
    let tmp_store_dir: PathBuf = std::env::temp_dir().join("phantom_node_f12_db_reset");
    let mut cmd = std::process::Command::new(bin);
    cmd.args([
        "db",
        "reset",
        "--store-dir",
        tmp_store_dir.to_string_lossy().as_ref(),
    ]);
    let out = cmd.output().expect("spawn phantom-node");
    assert!(
        !out.status.success(),
        "expected db reset without --yes to fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--yes"),
        "expected error message to mention --yes confirmation"
    );
}

#[test]
fn f13_relaxed_ordering_is_documented_as_metrics_only() {
    let src = node_main_rs_src();
    assert!(
        src.contains("Relaxed ordering is acceptable for metrics")
            || src.contains("Relaxed ordering is ok for metrics")
            || src.contains("metrics-only") && src.contains("Ordering::Relaxed"),
        "expected a normative comment explaining Relaxed ordering usage for metrics-only atomics"
    );
}

#[test]
fn f14_broadcast_backpressure_is_observable_via_lagged_metric() {
    let src = node_quic_server_src();
    // Evidence of bounded channel.
    assert!(
        src.contains("tokio::sync::broadcast::channel::<P2pMessage>(256)"),
        "expected bounded broadcast channel (capacity set)"
    );
    // Evidence of observability when receivers lag.
    assert!(
        src.contains("NODE_INBOUND_OBS_LAGGED_TOTAL.fetch_add"),
        "expected lagged events to be tracked in a metric"
    );
}

#[test]
fn f15_backup_dir_propagates_errors() {
    let src = node_cli_src();
    let start = src.find("fn backup_dir").expect("backup_dir fn missing");
    let end = src[start..]
        .find("fn run_db_repair")
        .map(|rel| start + rel)
        .unwrap_or(src.len());
    let body = &src[start..end];
    assert!(
        body.contains("-> Result<Option<PathBuf>>"),
        "expected backup_dir to return a Result (not ignore errors)"
    );
    assert!(
        body.contains("failed to backup") && body.contains("map_err"),
        "expected backup_dir to map rename errors into a descriptive anyhow error"
    );
}

#[test]
fn f77_persist_supply_state_logs_on_serialize_or_write_error() {
    let src = node_main_rs_src();
    assert!(
        src.contains("serialize supply_state failed"),
        "expected persist_supply_state_sync to warn on serialization error"
    );
    assert!(
        src.contains("persist supply_state failed"),
        "expected persist_supply_state_sync to warn on persistence error"
    );
}

#[test]
fn f82_status_serve_parses_config_once_and_reuses_it() {
    let src = node_http_api_src();
    let start = src
        .find("fn run_status_serve")
        .expect("run_status_serve fn missing");
    let body = &src[start..];
    assert!(
        body.contains("let parsed_cfg: Option<StatusConfig>"),
        "expected run_status_serve to parse the config into a single parsed_cfg variable"
    );
    assert!(
        body.contains("toml::from_str(&raw)") && body.matches("toml::from_str(&raw)").count() == 1,
        "expected exactly one TOML parse call for status config"
    );
    assert!(
        body.contains("parsed_cfg.as_ref()"),
        "expected parsed config to be reused (parsed_cfg.as_ref())"
    );
}

#[test]
fn f83_precommit_state_root_uses_filestore_v3_lookup() {
    let http_src = node_http_api_src();
    let start = http_src
        .find("/consensus/precommit_state_root")
        .expect("precommit_state_root endpoint missing");
    let body = &http_src[start..];
    assert!(
        body.contains("super::finality_pipeline::precheck_local_precommit_by_creator_index(")
            && body.contains("super::finality_pipeline::build_local_precommit_context("),
        "expected precommit_state_root endpoint to delegate to the shared finality pipeline helpers"
    );

    let pipeline_src = node_finality_pipeline_src();
    assert!(
        pipeline_src.contains("FileStore::open(store_dir, do_fsync)")
            && pipeline_src.contains("get_payload_v3(&payload_root)"),
        "expected shared finality precheck to load payloads through FileStore::get_payload_v3"
    );
    assert!(
        !pipeline_src.contains("join(\"payloads\")")
            && !pipeline_src.contains("std::fs::read(&payload_path)"),
        "expected shared finality precheck to avoid legacy payload file reads"
    );
}

#[test]
fn f84_finality_and_payout_paths_prefer_state_committee_with_bootstrap_fallback() {
    let src = node_main_rs_src();

    let verification_ctx_start = src
        .find("async fn resolve_header_signature_verification_context")
        .expect("resolve_header_signature_verification_context missing");
    let finality_body = &src[verification_ctx_start..];
    assert!(
        finality_body.contains("let staked = compute_committee_from_state(")
            && finality_body.contains("*committee_cache = choose_effective_committee(k, staked, bootstrap);"),
        "expected verify_header_finality to prefer state-based committee selection with bootstrap fallback"
    );

    let payout_start = src
        .find("async fn compute_payload_payout_root_strict<")
        .expect("compute_payload_payout_root_strict missing");
    let payout_body = &src[payout_start..];
    assert!(
        payout_body.contains("let staked = compute_committee_from_utxo_state(")
            && payout_body.contains("let cache = choose_effective_committee(k, staked, bootstrap)"),
        "expected payout_root computation to prefer state committee with bootstrap fallback"
    );

    let payout_by_idx_start = src
        .find("async fn compute_payload_payout_root_strict_by_creator_index<")
        .expect("compute_payload_payout_root_strict_by_creator_index missing");
    let payout_by_idx_body = &src[payout_by_idx_start..];
    assert!(
        payout_by_idx_body.contains("let staked = compute_committee_from_utxo_state(")
            && payout_by_idx_body.contains("let cache = choose_effective_committee(k, staked, bootstrap)"),
        "expected payout_root_by_creator_index computation to prefer state committee with bootstrap fallback"
    );
}

#[test]
fn f85_dashboard_finalizer_uses_state_committee_selection() {
    let http_src = node_http_api_src();
    let status_http_src = node_status_http_src();
    let committee_shared_src = node_committee_selection_src();

    assert!(
        committee_shared_src.contains("pub(crate) fn select_effective_committee_from_backend")
            && committee_shared_src.contains("if staked_selected.len() == k as usize && !staked_selected.is_empty()")
            && committee_shared_src.contains("if !bootstrap_selected.is_empty()"),
        "expected shared committee selection helper to implement state-first selection with bootstrap fallback"
    );
    assert!(
        http_src.contains("super::committee_selection::select_effective_committee_from_backend(")
            && http_src
                .contains("super::committee_selection::aggregate_stake_by_lock(st.backend())"),
        "expected status-serve committee endpoint to use the shared committee selection helper"
    );
    assert!(
        status_http_src.contains("committee_selection::select_effective_committee_from_backend(")
            && status_http_src.contains("committee_selection::load_role_policy_from_mempool_dir("),
        "expected status_http committee and evidence paths to use the shared committee selection helper with role policy filtering"
    );

    let dashboard_src = dashboard_node_service_src();
    assert!(
        dashboard_src.contains("resolve_local_finalizer_precommit(")
            && dashboard_src.contains("status_serve_local_precommit_context("),
        "expected dashboard finalizer to resolve authoritative local precommit context via the extracted runtime helper"
    );
    assert!(
        dashboard_src.contains("creator_index,") && dashboard_src.contains("vote_mask,"),
        "expected dashboard finalizer to use runtime-selected creator_index and vote_mask"
    );
    assert!(
        !dashboard_src.contains("creator_index: 0,") && !dashboard_src.contains("vote_mask: 1,"),
        "expected dashboard finalizer to avoid hardcoded single-seat creator_index/vote_mask"
    );
}

#[test]
fn f86_apply_candidate_queue_carries_concrete_meta_and_only_materialized_finality_is_signaled() {
    let src = node_quic_server_src();

    assert!(
        src.contains("mpsc::unbounded_channel::<FinalizedPayloadMeta>()"),
        "expected apply-candidate queueing to carry FinalizedPayloadMeta instead of a bare unit signal"
    );
    assert!(
        src.contains("tx_apply_candidate_cons.send(meta)")
            && src.contains("Some(apply_candidate) = rx_apply_candidate.recv()"),
        "expected the state task to receive the concrete apply candidate meta from the consensus task"
    );
    assert!(
        src.contains("materialized finalized payload after apply-candidate execution")
            && src.contains("materialized finalized payload on payload arrival")
            && !src.contains("observed finality"),
        "expected finality signalling to happen only at materialization and no longer describe an early observed-finality signal"
    );
}

#[test]
fn f87_prevote_and_precommit_paths_are_explicitly_separated() {
    let main_src = node_main_rs_src();
    let http_src = node_http_api_src();
    let quic_src = node_quic_server_src();
    let dashboard_src = dashboard_node_service_src();

    assert!(
        main_src.contains("async fn verify_header_prevote(")
            && main_src.contains(
                "committee_vote_message(&h.network_id, h.vote_epoch, &h.vote_target_hash())"
            ),
        "expected main runtime to verify explicit prevote headers via committee_vote_message"
    );
    assert!(
        http_src.contains("/consensus/local_prevote_context")
            && http_src.contains("local_prevote_precheck_failed"),
        "expected status-serve to expose a dedicated local prevote context endpoint"
    );
    assert!(
        quic_src.contains("let is_precommit = h.state_root.is_some();")
            && quic_src.contains("verify_header_prevote(")
            && quic_src.contains("if is_precommit && header_ok"),
        "expected quic runtime to admit prevotes separately while reserving finalization for precommits"
    );
    assert!(
        dashboard_src.contains("resolve_local_finalizer_prevote(")
            && dashboard_src.contains("committee_vote_message(")
            && dashboard_src.contains("prevote header injected")
            && dashboard_src.contains("precommit header injected"),
        "expected dashboard finalizer to inject an explicit prevote before the precommit header"
    );
}

#[test]
fn f88_wire_protocol_has_explicit_prevote_and_precommit_announces() {
    let p2p_src = p2p_lib_src();
    let libp2p_src = p2p_libp2p_node_src();
    let cli_src = node_cli_src();

    assert!(
        p2p_src.contains("PrevoteAnnounce(AnchorHeader)")
            && p2p_src.contains("PrecommitAnnounce(AnchorHeader)")
            && p2p_src.contains("explicit_announce_for_header(header: AnchorHeader)")
            && !p2p_src.contains("HeaderAnnounce(AnchorHeader)"),
        "expected pc-p2p wire messages to expose explicit prevote/precommit announce variants"
    );
    assert!(
        libp2p_src.contains("pc/shard/{}/prevote")
            && libp2p_src.contains("pc/shard/{}/precommit")
            && !libp2p_src.contains("let legacy = P2pMessage::HeaderAnnounce(h.clone());")
            && !libp2p_src.contains("for suffix in [\"header\", \"prevote\", \"precommit\"]"),
        "expected libp2p gossip to route staged announces only on dedicated prevote/precommit topics without a legacy fallback publish"
    );
    assert!(
        cli_src.contains("prevote_announce")
            && cli_src.contains("precommit_announce")
            && cli_src.contains("explicit_announce_for_header(h)"),
        "expected node CLI tooling to emit and display explicit staged header announces"
    );
}

#[test]
fn f89_header_rpc_responses_are_explicitly_staged_even_for_mixed_batches() {
    let p2p_src = p2p_lib_src();
    let quic_src = node_quic_server_src();

    assert!(
        p2p_src.contains("PrevoteHeaders {")
            && p2p_src.contains("PrecommitHeaders {")
            && p2p_src.contains("StagedHeaders {")
            && p2p_src.contains("pub fn explicit_header_response_for_headers(")
            && p2p_src.contains("pub fn normalize_header_response(")
            && !p2p_src.contains("RespMsg::Headers"),
        "expected pc-p2p RPC responses to expose explicit staged header variants for homogeneous and mixed batches"
    );
    assert!(
        p2p_src.contains("RespMsg::PrevoteHeaders { headers }")
            && p2p_src.contains("RespMsg::PrecommitHeaders { headers }")
            && p2p_src.contains("RespMsg::StagedHeaders {")
            && p2p_src.contains("malformed staged header response"),
        "expected pc-p2p runtime to validate staged header responses before processing"
    );
    assert!(
        quic_src.contains("RespMsg::PrevoteHeaders { headers }")
            && quic_src.contains("RespMsg::PrecommitHeaders { headers }")
            && quic_src.contains("RespMsg::StagedHeaders {"),
        "expected node runtime to accept explicit staged header RPC responses"
    );
}
