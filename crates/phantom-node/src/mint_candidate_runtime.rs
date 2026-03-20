#[cfg(test)]
use pc_crypto::blake3_32;
use pc_types::cmp_hash_be_u256;
#[cfg(test)]
use pc_types::{slot_id_v2, MINT_CANDIDATE_FEATURE_WORK_ID_V1};
#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
const RUNTIME_WORK_DOMAIN_V1: &[u8] = b"PHANTOM:MINT:WORK:v1";

#[cfg(test)]
pub(crate) type RuntimeWorkHandle = [u8; 32];

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateScopeAdvance {
    Unchanged,
    Initialized,
    Reset { previous: ([u8; 32], u64) },
}

#[cfg(test)]
pub(crate) fn advance_candidate_scope<T>(
    active_scope: &mut Option<([u8; 32], u64)>,
    new_scope: ([u8; 32], u64),
    candidate_nonce_cursor: &mut HashMap<RuntimeWorkHandle, u64>,
    emitted_candidate_work: &mut HashMap<RuntimeWorkHandle, T>,
) -> CandidateScopeAdvance {
    if *active_scope == Some(new_scope) {
        return CandidateScopeAdvance::Unchanged;
    }

    let transition = match *active_scope {
        Some(previous) => CandidateScopeAdvance::Reset { previous },
        None => CandidateScopeAdvance::Initialized,
    };

    *active_scope = Some(new_scope);
    candidate_nonce_cursor.clear();
    emitted_candidate_work.clear();
    transition
}

#[cfg(test)]
pub(crate) fn runtime_work_handle_v1(
    network_id: &[u8; 32],
    prev_mint_id: &[u8; 32],
    window_id: u64,
    window_open_anchor_id: &[u8; 32],
    pow_seed: &[u8; 32],
) -> RuntimeWorkHandle {
    let mut buf = Vec::with_capacity(RUNTIME_WORK_DOMAIN_V1.len() + (32 * 4) + 8);
    buf.extend_from_slice(RUNTIME_WORK_DOMAIN_V1);
    buf.extend_from_slice(network_id);
    buf.extend_from_slice(prev_mint_id);
    buf.extend_from_slice(&window_id.to_le_bytes());
    buf.extend_from_slice(window_open_anchor_id);
    buf.extend_from_slice(pow_seed);
    blake3_32(&buf)
}

#[cfg(test)]
pub(crate) fn runtime_work_handle_v2(
    network_id: &[u8; 32],
    prev_mint_id: &[u8; 32],
    window_id: u64,
    window_open_anchor_id: &[u8; 32],
    mint_commitment: &[u8; 32],
) -> RuntimeWorkHandle {
    slot_id_v2(
        network_id,
        prev_mint_id,
        window_id,
        window_open_anchor_id,
        mint_commitment,
    )
}

#[cfg(test)]
pub(crate) fn runtime_candidate_work_id(
    runtime_work_handle: RuntimeWorkHandle,
    candidate_feature_bits: u64,
) -> Option<RuntimeWorkHandle> {
    if (candidate_feature_bits & MINT_CANDIDATE_FEATURE_WORK_ID_V1) != 0 {
        Some(runtime_work_handle)
    } else {
        None
    }
}

pub(crate) fn candidate_replaces_existing_best(
    candidate_pow_hash: &[u8; 32],
    mint_commitment: &[u8; 32],
    candidate_id: &[u8; 32],
    previous_pow_hash: &[u8; 32],
    previous_mint_commitment: &[u8; 32],
    previous_candidate_id: &[u8; 32],
) -> bool {
    cmp_hash_be_u256(candidate_pow_hash, previous_pow_hash)
        .then_with(|| {
            mint_commitment
                .as_slice()
                .cmp(previous_mint_commitment.as_slice())
        })
        .then_with(|| {
            candidate_id
                .as_slice()
                .cmp(previous_candidate_id.as_slice())
        })
        .is_lt()
}
