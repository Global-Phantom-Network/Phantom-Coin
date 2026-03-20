use super::*;

pub(crate) const DEFAULT_FINALITY_VOTE_EPOCH_LEN: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FinalityHeaderPrecheck {
    pub(crate) attest_sig: [u8; 96],
    pub(crate) committed_state_root: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrevoteHeaderPrecheck {
    pub(crate) attest_sig: [u8; 96],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrevoteHeaderPrecheckError {
    HeaderVersionTooLow {
        version: u8,
    },
    AttestSigMissing,
    PostStateRootPresent,
    NetworkIdMismatch {
        header_network_id: [u8; 32],
        local_network_id: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalityHeaderPrecheckError {
    HeaderVersionTooLow {
        version: u8,
    },
    AttestSigMissing,
    PostStateRootMissing,
    NetworkIdMismatch {
        header_network_id: [u8; 32],
        local_network_id: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalFinalityPrecheck {
    pub(crate) network_id: [u8; 32],
    pub(crate) payload_root: [u8; 32],
    pub(crate) payload: AnchorPayloadV3,
    pub(crate) next_anchor_index: u64,
    pub(crate) vote_epoch: u64,
    pub(crate) creator_index: u8,
    pub(crate) vote_mask: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalPrecommitContext {
    pub(crate) network_id: [u8; 32],
    pub(crate) payload_root: [u8; 32],
    pub(crate) next_anchor_index: u64,
    pub(crate) vote_epoch: u64,
    pub(crate) creator_index: u8,
    pub(crate) vote_mask: u64,
    pub(crate) committed_state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalPrevoteContext {
    pub(crate) network_id: [u8; 32],
    pub(crate) payload_root: [u8; 32],
    pub(crate) next_anchor_index: u64,
    pub(crate) vote_epoch: u64,
    pub(crate) creator_index: u8,
    pub(crate) vote_mask: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalFinalityBaseInputs {
    note: GenesisNote,
    payload_root: [u8; 32],
    payload: AnchorPayloadV3,
    network_id: [u8; 32],
    k: u8,
    next_anchor_index: u64,
    vote_epoch: u64,
    seed_anchor: [u8; 32],
}

pub(crate) fn effective_vote_epoch_len(node_rot_cfg: Option<&NodeRotationCfg>) -> u64 {
    node_rot_cfg
        .and_then(|cfg| cfg.epoch_len)
        .unwrap_or(DEFAULT_FINALITY_VOTE_EPOCH_LEN)
        .max(1)
}

pub(crate) fn derive_vote_epoch(
    next_anchor_index: u64,
    node_rot_cfg: Option<&NodeRotationCfg>,
) -> u64 {
    pc_consensus::committee_vrf::derive_epoch(
        next_anchor_index,
        effective_vote_epoch_len(node_rot_cfg),
    )
}

pub(crate) fn next_anchor_index_from_store_dir(store_dir: &str) -> u64 {
    let anchor_index_now =
        std::fs::read_to_string(std::path::Path::new(store_dir).join("anchor_index"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
    anchor_index_now.saturating_add(1)
}

pub(crate) fn precheck_finality_header(
    h: &AnchorHeaderV2,
    local_network_id: [u8; 32],
) -> std::result::Result<FinalityHeaderPrecheck, FinalityHeaderPrecheckError> {
    if h.version < 5 {
        return Err(FinalityHeaderPrecheckError::HeaderVersionTooLow { version: h.version });
    }
    let attest_sig = h
        .attest_sig
        .ok_or(FinalityHeaderPrecheckError::AttestSigMissing)?;
    let committed_state_root = h
        .state_root
        .ok_or(FinalityHeaderPrecheckError::PostStateRootMissing)?;
    if h.network_id != local_network_id {
        return Err(FinalityHeaderPrecheckError::NetworkIdMismatch {
            header_network_id: h.network_id,
            local_network_id,
        });
    }
    Ok(FinalityHeaderPrecheck {
        attest_sig,
        committed_state_root,
    })
}

pub(crate) fn precheck_prevote_header(
    h: &AnchorHeaderV2,
    local_network_id: [u8; 32],
) -> std::result::Result<PrevoteHeaderPrecheck, PrevoteHeaderPrecheckError> {
    if h.version < 5 {
        return Err(PrevoteHeaderPrecheckError::HeaderVersionTooLow { version: h.version });
    }
    let attest_sig = h
        .attest_sig
        .ok_or(PrevoteHeaderPrecheckError::AttestSigMissing)?;
    if h.state_root.is_some() {
        return Err(PrevoteHeaderPrecheckError::PostStateRootPresent);
    }
    if h.network_id != local_network_id {
        return Err(PrevoteHeaderPrecheckError::NetworkIdMismatch {
            header_network_id: h.network_id,
            local_network_id,
        });
    }
    Ok(PrevoteHeaderPrecheck { attest_sig })
}

fn parse_bls_pk_hex(bls_pk_hex: &str) -> Result<[u8; 48]> {
    let raw = hex::decode(bls_pk_hex.trim()).map_err(|e| anyhow!("bls_pk_invalid: {e}"))?;
    if raw.len() != 48 {
        bail!("bls_pk_invalid_length:{}", raw.len());
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn load_local_finality_base_inputs(
    mempool_dir: &str,
    store_dir: &str,
    do_fsync: bool,
    network_id: [u8; 32],
    payload_root: [u8; 32],
    node_rot_cfg: Option<&NodeRotationCfg>,
) -> Result<LocalFinalityBaseInputs> {
    let payload = FileStore::open(store_dir, do_fsync)
        .and_then(|store| store.get_payload_v3(&payload_root))
        .map_err(|e| anyhow!("payload_unavailable: {e}"))?
        .ok_or_else(|| anyhow!("payload_unavailable"))?;
    let computed_root = pc_types::payload_merkle_root_v3(&payload);
    if computed_root != payload_root {
        bail!(
            "payload_root_mismatch: computed={}",
            hex::encode(computed_root)
        );
    }
    if let Err(e) = pc_types::validate_payload_sanity_v3(&payload) {
        bail!("payload_sanity_failed: {e}");
    }
    if payload.mints.len() > 1 {
        bail!("payload_too_many_mints");
    }
    let note = load_genesis_note_from_mempool(mempool_dir)
        .ok_or_else(|| anyhow!("genesis_note_unavailable"))?;
    let k = note.params.committee_k;
    if k == 0 || k > 64 {
        bail!("committee_k_invalid:{k}");
    }
    let next_anchor_index = next_anchor_index_from_store_dir(store_dir);
    let vote_epoch = derive_vote_epoch(next_anchor_index, node_rot_cfg);
    let seed_anchor = committee_seed_anchor_from_mempool(mempool_dir)
        .unwrap_or_else(|| genesis_payload_root(&note));
    Ok(LocalFinalityBaseInputs {
        note,
        payload_root,
        payload,
        network_id,
        k,
        next_anchor_index,
        vote_epoch,
        seed_anchor,
    })
}

fn select_local_committee<B: StateBackend>(
    st: &pc_state::UtxoState<B>,
    base: &LocalFinalityBaseInputs,
    role_policy: Option<&RolePolicy>,
) -> committee_selection::CommitteeSelection {
    let stake_by_lock = committee_selection::aggregate_stake_by_lock(st.backend());
    committee_selection::select_effective_committee_from_backend(
        st.backend(),
        &base.note,
        &stake_by_lock,
        base.k,
        base.vote_epoch,
        base.seed_anchor,
        base.network_id,
        role_policy,
    )
}

fn vote_mask_for_creator_index(creator_index: u8) -> Result<u64> {
    let vote_mask = 1u64
        .checked_shl(creator_index as u32)
        .ok_or_else(|| anyhow!("creator_index_out_of_range:{creator_index}"))?;
    if vote_mask == 0 {
        bail!("creator_index_out_of_range:{creator_index}");
    }
    Ok(vote_mask)
}

async fn build_local_precheck_for_creator_index<B: StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    base: LocalFinalityBaseInputs,
    creator_index: u8,
    role_policy: Option<&RolePolicy>,
) -> Result<LocalFinalityPrecheck> {
    let committee = select_local_committee(st, &base, role_policy);
    if (creator_index as usize) >= committee.seats.len() {
        bail!(
            "creator_index_out_of_range:{} committee_size={}",
            creator_index,
            committee.seats.len()
        );
    }
    let expected_payout_root = compute_payload_payout_root_strict_by_creator_index(
        st,
        mempool_dir,
        base.network_id,
        base.k,
        base.next_anchor_index,
        &base.payload.micro_txs,
        role_policy,
        creator_index,
    )
    .await?;
    if expected_payout_root != base.payload.payout_root {
        bail!(
            "payout_root_mismatch: expected={} actual={}",
            hex::encode(expected_payout_root),
            hex::encode(base.payload.payout_root)
        );
    }
    let vote_mask = vote_mask_for_creator_index(creator_index)?;
    Ok(LocalFinalityPrecheck {
        network_id: base.network_id,
        payload_root: base.payload_root,
        payload: base.payload,
        next_anchor_index: base.next_anchor_index,
        vote_epoch: base.vote_epoch,
        creator_index,
        vote_mask,
    })
}

pub(crate) async fn precheck_local_prevote_by_bls_pk<B: StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    store_dir: &str,
    do_fsync: bool,
    network_id: [u8; 32],
    payload_root: [u8; 32],
    bls_pk_hex: &str,
    node_rot_cfg: Option<&NodeRotationCfg>,
    role_policy: Option<&RolePolicy>,
) -> Result<LocalFinalityPrecheck> {
    let base = load_local_finality_base_inputs(
        mempool_dir,
        store_dir,
        do_fsync,
        network_id,
        payload_root,
        node_rot_cfg,
    )?;
    let committee = select_local_committee(st, &base, role_policy);
    let local_pk_bytes = parse_bls_pk_hex(bls_pk_hex)?;
    let creator_index = committee
        .seats
        .iter()
        .position(|seat| seat.bls_pk.to_bytes() == local_pk_bytes)
        .map(|idx| idx as u8)
        .ok_or_else(|| {
            anyhow!(
                "local_bls_pk_not_in_committee: vote_epoch={} seats={} bootstrap_mode={}",
                base.vote_epoch,
                committee.seats.len(),
                committee.bootstrap_mode
            )
        })?;
    build_local_precheck_for_creator_index(st, mempool_dir, base, creator_index, role_policy).await
}

pub(crate) async fn precheck_local_precommit_by_bls_pk<B: StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    store_dir: &str,
    do_fsync: bool,
    network_id: [u8; 32],
    payload_root: [u8; 32],
    bls_pk_hex: &str,
    node_rot_cfg: Option<&NodeRotationCfg>,
    role_policy: Option<&RolePolicy>,
) -> Result<LocalFinalityPrecheck> {
    let base = load_local_finality_base_inputs(
        mempool_dir,
        store_dir,
        do_fsync,
        network_id,
        payload_root,
        node_rot_cfg,
    )?;
    let committee = select_local_committee(st, &base, role_policy);
    let local_pk_bytes = parse_bls_pk_hex(bls_pk_hex)?;
    let creator_index = committee
        .seats
        .iter()
        .position(|seat| seat.bls_pk.to_bytes() == local_pk_bytes)
        .map(|idx| idx as u8)
        .ok_or_else(|| {
            anyhow!(
                "local_bls_pk_not_in_committee: vote_epoch={} seats={} bootstrap_mode={}",
                base.vote_epoch,
                committee.seats.len(),
                committee.bootstrap_mode
            )
        })?;
    build_local_precheck_for_creator_index(st, mempool_dir, base, creator_index, role_policy).await
}

pub(crate) async fn precheck_local_precommit_by_creator_index<B: StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    store_dir: &str,
    do_fsync: bool,
    network_id: [u8; 32],
    payload_root: [u8; 32],
    creator_index: u8,
    node_rot_cfg: Option<&NodeRotationCfg>,
    role_policy: Option<&RolePolicy>,
) -> Result<LocalFinalityPrecheck> {
    let base = load_local_finality_base_inputs(
        mempool_dir,
        store_dir,
        do_fsync,
        network_id,
        payload_root,
        node_rot_cfg,
    )?;
    build_local_precheck_for_creator_index(st, mempool_dir, base, creator_index, role_policy).await
}

pub(crate) async fn build_local_precommit_context<B: StateBackend>(
    st: &mut pc_state::UtxoState<B>,
    mempool_dir: &str,
    precheck: LocalFinalityPrecheck,
    role_policy: Option<&RolePolicy>,
) -> Result<LocalPrecommitContext> {
    let supply_mutex = global_supply_state(mempool_dir);
    let supply_guard = supply_mutex.lock().await;
    let mut supply_snapshot = supply_guard.clone();
    drop(supply_guard);
    refresh_supply_state_from_disk(mempool_dir, &mut supply_snapshot);
    let mut candidate_supply = supply_snapshot;

    let mut dry_run_state =
        pc_state::UtxoState::new(pc_state::OverlayBackend::new(st.backend_mut()));
    let mut slash_committee_cache: Option<CommitteeCache> = None;
    let slash_ops = verify_and_extract_slash_ops(
        &dry_run_state,
        mempool_dir,
        precheck.network_id,
        role_policy,
        &mut slash_committee_cache,
        &precheck.payload.evidences,
    )
    .await?;
    let (_slashed, _rewarded, burned_total) = dry_run_state.preview_slash_ops(&slash_ops)?;
    if burned_total > 0 {
        candidate_supply.total_supply = candidate_supply.total_supply.saturating_sub(burned_total);
    }
    for mint in &precheck.payload.mints {
        validate_mint_for_current_supply(&precheck.network_id, &candidate_supply, mint)?;
        if let Some(policy) = role_policy {
            if !policy.allows_mint(mint) {
                bail!("mint_rejected_by_role_policy");
            }
        }
        rewind_preaccounted_supply_for_mint(&mut candidate_supply, mint)
            .map_err(|e| anyhow!("mint_supply_rewind_failed: {e}"))?;
        if dry_run_state.is_prev_mint_used(&mint.prev_mint_id) {
            bail!("prev_mint_id_already_used");
        }
        candidate_supply
            .process_mint(mint, precheck.next_anchor_index)
            .map_err(|e| anyhow!("process_mint_failed: {e}"))?;
    }
    let sig_ok =
        pc_state::verify_microtx_sigs_parallel(&precheck.payload.micro_txs, &precheck.network_id);
    let apply_result = if sig_ok {
        dry_run_state.apply_payload_v2_tolerant_presigned(
            &precheck.payload.mints,
            &precheck.payload.micro_txs,
            &slash_ops,
            precheck.next_anchor_index,
            consts::MATURITY_L1,
            &precheck.network_id,
        )
    } else {
        dry_run_state.apply_payload_v2_tolerant(
            &precheck.payload.mints,
            &precheck.payload.micro_txs,
            &slash_ops,
            precheck.next_anchor_index,
            consts::MATURITY_L1,
            &precheck.network_id,
        )
    };
    match apply_result {
        Ok(skipped) if skipped.is_empty() => {}
        Ok(skipped) => bail!("microtxs_skipped:{}", skipped.len()),
        Err(e) => bail!("apply_failed: {e}"),
    }
    Ok(LocalPrecommitContext {
        network_id: precheck.network_id,
        payload_root: precheck.payload_root,
        next_anchor_index: precheck.next_anchor_index,
        vote_epoch: precheck.vote_epoch,
        creator_index: precheck.creator_index,
        vote_mask: precheck.vote_mask,
        committed_state_root: dry_run_state.root(),
    })
}

pub(crate) fn build_local_prevote_context(precheck: &LocalFinalityPrecheck) -> LocalPrevoteContext {
    LocalPrevoteContext {
        network_id: precheck.network_id,
        payload_root: precheck.payload_root,
        next_anchor_index: precheck.next_anchor_index,
        vote_epoch: precheck.vote_epoch,
        creator_index: precheck.creator_index,
        vote_mask: precheck.vote_mask,
    }
}
