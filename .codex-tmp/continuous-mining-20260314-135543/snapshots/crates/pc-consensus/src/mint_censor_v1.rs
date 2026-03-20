// SPDX-License-Identifier: AGPL-3.0-only
//! Deterministic mint-candidate window engine (v1).
//!
//! This module implements the consensus-side mechanics for:
//! - window bounds (`W/K`, anchor-index based),
//! - candidate admission (`pow_hash <= candidate_target`),
//! - dedupe + top-N selection,
//! - freeze + winner + candidate_root derivation,
//! - AnchorPayloadV3 phase validation,
//! - compact censorship evidence verification.

use pc_crypto::blake3_32;
use pc_types::{
    candidate_id_v1, candidate_pow_hash_v1, cmp_hash_be_u256, mint_candidate_from_pow_cert_v1,
    mint_id_v1, pow_cert_id_v1, validate_mint_candidate_features_v1, AnchorPayloadV3, EvidenceKind,
    MintCandidateEvent, MintPoWCertV1, MINT_CANDROOT_DOMAIN_V1,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintCensorError {
    InvalidParams(&'static str),
    ConsensusInvalid(&'static str),
    UnsupportedEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    DuplicateNoOp,
    StateIrrelevantNoOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowBoundsV1 {
    pub window_id: u64,
    pub window_open_anchor: u64,
    pub close_anchor: u64,
    pub deadline_anchor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintCensorParamsV1 {
    pub network_id: Hash32,
    pub windows_start_anchor: u64,
    pub w: u64,
    pub k: u64,
    pub n: usize,
    pub e: u64,
    pub min_target: Hash32,
    pub max_target: Hash32,
    pub initial_target: Hash32,
    pub candidate_feature_bits: u64,
}

impl MintCensorParamsV1 {
    pub fn validate(&self) -> Result<(), MintCensorError> {
        if self.w == 0 {
            return Err(MintCensorError::InvalidParams("W must be >= 1"));
        }
        if self.n == 0 {
            return Err(MintCensorError::InvalidParams("N must be >= 1"));
        }
        if self.n > u32::MAX as usize {
            return Err(MintCensorError::InvalidParams(
                "N must be <= u32::MAX for candidate_root encoding",
            ));
        }
        if self.e == 0 {
            return Err(MintCensorError::InvalidParams("E must be >= 1"));
        }
        if is_zero_hash(&self.min_target) {
            return Err(MintCensorError::InvalidParams("MIN_TARGET must be >= 1"));
        }
        if cmp_hash_be_u256(&self.min_target, &self.max_target).is_gt() {
            return Err(MintCensorError::InvalidParams(
                "MIN_TARGET must be <= MAX_TARGET",
            ));
        }
        if cmp_hash_be_u256(&self.initial_target, &self.min_target).is_lt()
            || cmp_hash_be_u256(&self.initial_target, &self.max_target).is_gt()
        {
            return Err(MintCensorError::InvalidParams(
                "INITIAL_TARGET must be in [MIN_TARGET, MAX_TARGET]",
            ));
        }
        Ok(())
    }

    pub fn window_bounds_for_anchor(&self, anchor_index: u64) -> Option<WindowBoundsV1> {
        if anchor_index < self.windows_start_anchor {
            return None;
        }
        let rel = anchor_index.saturating_sub(self.windows_start_anchor);
        let window_id = rel / self.w;
        let window_open_anchor = self
            .windows_start_anchor
            .saturating_add(window_id.saturating_mul(self.w));
        let close_anchor = window_open_anchor.saturating_add(self.w.saturating_sub(1));
        let deadline_anchor = close_anchor.saturating_add(self.k);
        Some(WindowBoundsV1 {
            window_id,
            window_open_anchor,
            close_anchor,
            deadline_anchor,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRecordV1 {
    pub candidate_id: Hash32,
    pub mint_id: Hash32,
    pub mint_commitment: Hash32,
    pub pow_hash: Hash32,
    pub finalized_at_anchor_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowStateV1 {
    pub prev_mint_id: Hash32,
    pub window_id: u64,
    pub window_open_anchor_id: Hash32,
    pub close_anchor: u64,
    pub deadline_anchor: u64,
    pub candidate_target: Hash32,
    pub top_n: Vec<CandidateRecordV1>,
    pub top_n_frozen: Option<Vec<CandidateRecordV1>>,
    pub winner: Option<CandidateRecordV1>,
    pub candidate_root: Hash32,
    pub obs_prev_window: u64,
    dedupe_by_commitment: BTreeMap<Hash32, CandidateRecordV1>,
    seen_candidate_ids: BTreeSet<Hash32>,
    pow_cert_to_candidate_id: BTreeMap<Hash32, Hash32>,
}

impl WindowStateV1 {
    pub fn new(
        prev_mint_id: Hash32,
        window_open_anchor_id: Hash32,
        bounds: WindowBoundsV1,
        candidate_target: Hash32,
    ) -> Self {
        let top_n: Vec<CandidateRecordV1> = Vec::new();
        let candidate_root = compute_candidate_root_v1(bounds.window_id, &top_n);
        Self {
            prev_mint_id,
            window_id: bounds.window_id,
            window_open_anchor_id,
            close_anchor: bounds.close_anchor,
            deadline_anchor: bounds.deadline_anchor,
            candidate_target,
            top_n,
            top_n_frozen: None,
            winner: None,
            candidate_root,
            obs_prev_window: 0,
            dedupe_by_commitment: BTreeMap::new(),
            seen_candidate_ids: BTreeSet::new(),
            pow_cert_to_candidate_id: BTreeMap::new(),
        }
    }

    pub fn is_frozen(&self) -> bool {
        self.top_n_frozen.is_some()
    }

    pub fn winner_exists(&self) -> bool {
        !self.top_n_ref().is_empty()
    }

    pub fn top_n_ref(&self) -> &[CandidateRecordV1] {
        match &self.top_n_frozen {
            Some(v) => v.as_slice(),
            None => self.top_n.as_slice(),
        }
    }

    pub fn maybe_freeze(&mut self, anchor_index: u64) {
        if self.is_frozen() || anchor_index < self.close_anchor.saturating_add(1) {
            return;
        }
        self.obs_prev_window = self.dedupe_by_commitment.len() as u64;
        let frozen = self.top_n.clone();
        self.candidate_root = compute_candidate_root_v1(self.window_id, &frozen);
        self.winner = frozen.first().cloned();
        self.top_n_frozen = Some(frozen);
    }

    pub fn apply_finalized_candidate(
        &mut self,
        finalized_at_anchor_index: u64,
        candidate: &MintCandidateEvent,
        state_last_mint_id: &Hash32,
        params: &MintCensorParamsV1,
    ) -> Result<ApplyOutcome, MintCensorError> {
        if finalized_at_anchor_index > self.close_anchor {
            return Ok(ApplyOutcome::StateIrrelevantNoOp);
        }
        if self.is_frozen() {
            return Ok(ApplyOutcome::StateIrrelevantNoOp);
        }

        validate_mint_candidate_features_v1(candidate, params.candidate_feature_bits)
            .map_err(MintCensorError::ConsensusInvalid)?;

        if candidate.network_id != params.network_id {
            return Err(MintCensorError::ConsensusInvalid(
                "candidate network_id mismatch",
            ));
        }
        if candidate.window_id != self.window_id {
            return Err(MintCensorError::ConsensusInvalid(
                "candidate window_id mismatch",
            ));
        }
        if candidate.window_open_anchor_id != self.window_open_anchor_id {
            return Err(MintCensorError::ConsensusInvalid(
                "candidate window_open_anchor_id mismatch",
            ));
        }
        if candidate.prev_mint_id != *state_last_mint_id {
            return Ok(ApplyOutcome::StateIrrelevantNoOp);
        }

        let candidate_id = candidate_id_v1(candidate);
        if self.seen_candidate_ids.contains(&candidate_id) {
            return Ok(ApplyOutcome::DuplicateNoOp);
        }

        let pow_hash = candidate_pow_hash_v1(candidate);
        if cmp_hash_be_u256(&pow_hash, &self.candidate_target).is_gt() {
            return Err(MintCensorError::ConsensusInvalid(
                "candidate pow hash does not meet target",
            ));
        }

        let rec = CandidateRecordV1 {
            candidate_id,
            mint_id: candidate.mint_commitment,
            mint_commitment: candidate.mint_commitment,
            pow_hash,
            finalized_at_anchor_index,
        };

        self.seen_candidate_ids.insert(rec.candidate_id);
        match self.dedupe_by_commitment.get_mut(&rec.mint_commitment) {
            Some(existing) => {
                if candidate_record_key_cmp(&rec, existing).is_lt() {
                    *existing = rec;
                }
            }
            None => {
                self.dedupe_by_commitment.insert(rec.mint_commitment, rec);
            }
        }

        self.recompute_top_n(params.n);
        Ok(ApplyOutcome::Applied)
    }

    pub fn apply_finalized_pow_cert(
        &mut self,
        finalized_at_anchor_index: u64,
        cert: &MintPoWCertV1,
        state_last_mint_id: &Hash32,
        params: &MintCensorParamsV1,
    ) -> Result<ApplyOutcome, MintCensorError> {
        let cert_id = pow_cert_id_v1(cert);
        let candidate = mint_candidate_from_pow_cert_v1(cert);
        let candidate_id = candidate_id_v1(&candidate);
        if let Some(existing) = self.pow_cert_to_candidate_id.get(&cert_id) {
            if *existing == candidate_id {
                return Ok(ApplyOutcome::DuplicateNoOp);
            }
            return Err(MintCensorError::ConsensusInvalid(
                "pow-cert id maps to conflicting candidate_id",
            ));
        }

        let out = self.apply_finalized_candidate(
            finalized_at_anchor_index,
            &candidate,
            state_last_mint_id,
            params,
        )?;
        if matches!(out, ApplyOutcome::Applied | ApplyOutcome::DuplicateNoOp) {
            self.pow_cert_to_candidate_id.insert(cert_id, candidate_id);
        }
        Ok(out)
    }

    pub fn validate_anchor_payload_v3(
        &self,
        anchor_index: u64,
        payload: &AnchorPayloadV3,
    ) -> Result<(), MintCensorError> {
        let decision = decode_payload_decision(payload)?;
        let winner = self.winner_ref();

        if anchor_index < self.close_anchor {
            if matches!(decision, AnchorDecisionV1::None) {
                return Ok(());
            }
            return Err(MintCensorError::ConsensusInvalid(
                "mint decision not allowed before close_anchor",
            ));
        }

        if anchor_index < self.deadline_anchor {
            return match decision {
                AnchorDecisionV1::None => Ok(()),
                AnchorDecisionV1::Mint(mint_id) => match winner {
                    Some(w) if mint_id == w.mint_commitment => Ok(()),
                    _ => Err(MintCensorError::ConsensusInvalid(
                        "mint decision does not match winner",
                    )),
                },
                AnchorDecisionV1::Null => {
                    if winner.is_none() {
                        Ok(())
                    } else {
                        Err(MintCensorError::ConsensusInvalid(
                            "null decision not allowed when winner exists",
                        ))
                    }
                }
            };
        }

        // Hard phase: after deadline no NoDecision allowed.
        match winner {
            Some(w) => match decision {
                AnchorDecisionV1::Mint(mint_id) if mint_id == w.mint_commitment => Ok(()),
                _ => Err(MintCensorError::ConsensusInvalid(
                    "deadline violation: winner must be minted",
                )),
            },
            None => match decision {
                AnchorDecisionV1::Null => Ok(()),
                _ => Err(MintCensorError::ConsensusInvalid(
                    "deadline violation: null decision required for empty window",
                )),
            },
        }
    }

    pub fn verify_mint_censorship_evidence(
        &self,
        evidence: &EvidenceKind,
        offending_anchor_id: pc_types::AnchorId,
        offending_anchor_index: u64,
        offending_payload: &AnchorPayloadV3,
    ) -> Result<(), MintCensorError> {
        let (
            prev_mint_id,
            window_id,
            expected_winner_candidate_id,
            offending_anchor_id_in_evidence,
        ) = match evidence {
            EvidenceKind::MintCensorshipV1 {
                prev_mint_id,
                window_id,
                expected_winner_candidate_id,
                offending_anchor_id,
            } => (
                prev_mint_id,
                *window_id,
                expected_winner_candidate_id,
                offending_anchor_id,
            ),
            _ => return Err(MintCensorError::UnsupportedEvidence),
        };

        if *prev_mint_id != self.prev_mint_id || window_id != self.window_id {
            return Err(MintCensorError::ConsensusInvalid(
                "evidence window binding mismatch",
            ));
        }
        if offending_anchor_index < self.deadline_anchor {
            return Err(MintCensorError::ConsensusInvalid(
                "offending anchor is before deadline",
            ));
        }
        if *offending_anchor_id_in_evidence != offending_anchor_id {
            return Err(MintCensorError::ConsensusInvalid(
                "offending_anchor_id mismatch",
            ));
        }
        let winner = self.winner_ref().ok_or(MintCensorError::ConsensusInvalid(
            "no winner in evidence window",
        ))?;
        if *expected_winner_candidate_id != winner.candidate_id {
            return Err(MintCensorError::ConsensusInvalid(
                "expected_winner_candidate_id mismatch",
            ));
        }

        // Evidence is valid only when offending payload violates the rules.
        if self
            .validate_anchor_payload_v3(offending_anchor_index, offending_payload)
            .is_ok()
        {
            return Err(MintCensorError::ConsensusInvalid(
                "offending payload is valid; no censorship proof",
            ));
        }
        Ok(())
    }

    pub fn verify_mint_missing_import_evidence(
        &self,
        evidence: &EvidenceKind,
        offending_anchor_id: pc_types::AnchorId,
        offending_anchor_index: u64,
        offending_payload: &AnchorPayloadV3,
    ) -> Result<(), MintCensorError> {
        let (
            prev_mint_id,
            window_id,
            expected_winner_candidate_id,
            required_pow_cert_id,
            offending_anchor_id_in_evidence,
        ) = match evidence {
            EvidenceKind::MintMissingImportV1 {
                prev_mint_id,
                window_id,
                expected_winner_candidate_id,
                required_pow_cert_id,
                offending_anchor_id,
            } => (
                prev_mint_id,
                *window_id,
                expected_winner_candidate_id,
                required_pow_cert_id,
                offending_anchor_id,
            ),
            _ => return Err(MintCensorError::UnsupportedEvidence),
        };

        if *prev_mint_id != self.prev_mint_id || window_id != self.window_id {
            return Err(MintCensorError::ConsensusInvalid(
                "evidence window binding mismatch",
            ));
        }
        if offending_anchor_index < self.deadline_anchor {
            return Err(MintCensorError::ConsensusInvalid(
                "offending anchor is before deadline",
            ));
        }
        if *offending_anchor_id_in_evidence != offending_anchor_id {
            return Err(MintCensorError::ConsensusInvalid(
                "offending_anchor_id mismatch",
            ));
        }
        let winner = self.winner_ref().ok_or(MintCensorError::ConsensusInvalid(
            "no winner in evidence window",
        ))?;
        if *expected_winner_candidate_id != winner.candidate_id {
            return Err(MintCensorError::ConsensusInvalid(
                "expected_winner_candidate_id mismatch",
            ));
        }
        let mapped_candidate = self
            .pow_cert_to_candidate_id
            .get(required_pow_cert_id)
            .ok_or(MintCensorError::ConsensusInvalid(
                "required_pow_cert_id not found in finalized window",
            ))?;
        if *mapped_candidate != winner.candidate_id {
            return Err(MintCensorError::ConsensusInvalid(
                "required_pow_cert_id does not map to winner candidate",
            ));
        }

        // Evidence is valid only when offending payload violates deadline/winner rules.
        if self
            .validate_anchor_payload_v3(offending_anchor_index, offending_payload)
            .is_ok()
        {
            return Err(MintCensorError::ConsensusInvalid(
                "offending payload is valid; no missing-import proof",
            ));
        }
        Ok(())
    }

    fn winner_ref(&self) -> Option<&CandidateRecordV1> {
        match &self.top_n_frozen {
            Some(v) => v.first(),
            None => self.top_n.first(),
        }
    }

    fn recompute_top_n(&mut self, n: usize) {
        let mut winners: Vec<CandidateRecordV1> =
            self.dedupe_by_commitment.values().cloned().collect();
        winners.sort_by(candidate_record_key_cmp);
        if winners.len() > n {
            winners.truncate(n);
        }
        self.top_n = winners.clone();
        self.winner = winners.first().cloned();
        self.candidate_root = compute_candidate_root_v1(self.window_id, &winners);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedCandidateTransition {
    pub anchor_index: u64,
    pub candidate: MintCandidateEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedPowCertTransition {
    pub anchor_index: u64,
    pub cert: MintPoWCertV1,
}

pub fn sort_candidate_transitions_deterministic(transitions: &mut [FinalizedCandidateTransition]) {
    transitions.sort_by(|a, b| {
        a.anchor_index.cmp(&b.anchor_index).then_with(|| {
            candidate_id_v1(&a.candidate)
                .as_slice()
                .cmp(candidate_id_v1(&b.candidate).as_slice())
        })
    });
}

pub fn sort_pow_cert_transitions_deterministic(transitions: &mut [FinalizedPowCertTransition]) {
    transitions.sort_by(|a, b| {
        a.anchor_index.cmp(&b.anchor_index).then_with(|| {
            pow_cert_id_v1(&a.cert)
                .as_slice()
                .cmp(pow_cert_id_v1(&b.cert).as_slice())
        })
    });
}

pub fn compute_candidate_root_v1(
    window_id: u64,
    candidates_sorted: &[CandidateRecordV1],
) -> Hash32 {
    let mut buf =
        Vec::with_capacity(MINT_CANDROOT_DOMAIN_V1.len() + 8 + 4 + candidates_sorted.len() * 32);
    buf.extend_from_slice(MINT_CANDROOT_DOMAIN_V1);
    buf.extend_from_slice(&window_id.to_le_bytes());
    let m_u32 = u32::try_from(candidates_sorted.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&m_u32.to_le_bytes());
    for c in candidates_sorted {
        buf.extend_from_slice(&c.candidate_id);
    }
    blake3_32(&buf)
}

pub fn next_candidate_target_v1(
    prev_target: Hash32,
    obs_prev_window: u64,
    expected_candidates_per_window: u64,
    min_target: Hash32,
    max_target: Hash32,
) -> Hash32 {
    let prev_le = u256_words_le_from_be_bytes(&prev_target);

    // raw is computed in a >256-bit intermediate (u320), then clamped to [min_target, max_target].
    let raw_u320_le: [u64; 5] = if obs_prev_window == 0 {
        mul_u256_by_u64_to_u320_le(prev_le, 2)
    } else {
        let num = mul_u256_by_u64_to_u320_le(prev_le, expected_candidates_per_window);
        div_u320_by_u64_to_u320_le(num, obs_prev_window)
    };

    // Clamp: anything that doesn't fit in 256 bits is definitely > max_target (since max_target is
    // a 256-bit threshold).
    if raw_u320_le[4] != 0 {
        return max_target;
    }
    let raw_be = u256_be_bytes_from_words_le([
        raw_u320_le[0],
        raw_u320_le[1],
        raw_u320_le[2],
        raw_u320_le[3],
    ]);
    if cmp_hash_be_u256(&raw_be, &min_target).is_lt() {
        return min_target;
    }
    if cmp_hash_be_u256(&raw_be, &max_target).is_gt() {
        return max_target;
    }
    raw_be
}

fn u256_words_le_from_be_bytes(x: &Hash32) -> [u64; 4] {
    fn read_u64_be(slice: &[u8]) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(slice);
        u64::from_be_bytes(b)
    }
    [
        read_u64_be(&x[24..32]),
        read_u64_be(&x[16..24]),
        read_u64_be(&x[8..16]),
        read_u64_be(&x[0..8]),
    ]
}

fn u256_be_bytes_from_words_le(words: [u64; 4]) -> Hash32 {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&words[3].to_be_bytes());
    out[8..16].copy_from_slice(&words[2].to_be_bytes());
    out[16..24].copy_from_slice(&words[1].to_be_bytes());
    out[24..32].copy_from_slice(&words[0].to_be_bytes());
    out
}

fn mul_u256_by_u64_to_u320_le(a: [u64; 4], m: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for (ai, oi) in a.iter().zip(out.iter_mut()) {
        let prod = (*ai as u128) * (m as u128) + carry;
        *oi = prod as u64;
        carry = prod >> 64;
    }
    if let Some(last) = out.last_mut() {
        *last = carry as u64;
    }
    out
}

fn div_u320_by_u64_to_u320_le(n: [u64; 5], d: u64) -> [u64; 5] {
    // Caller ensures d != 0 in all consensus paths.
    if d == 0 {
        return [0u64; 5];
    }
    let mut q = [0u64; 5];
    let mut rem: u128 = 0;
    for (ni, qi) in n.iter().rev().zip(q.iter_mut().rev()) {
        let cur = (rem << 64) | (*ni as u128);
        *qi = (cur / (d as u128)) as u64;
        rem = cur % (d as u128);
    }
    q
}

fn is_zero_hash(h: &Hash32) -> bool {
    h.iter().all(|b| *b == 0)
}

fn candidate_record_key_cmp(a: &CandidateRecordV1, b: &CandidateRecordV1) -> Ordering {
    cmp_hash_be_u256(&a.pow_hash, &b.pow_hash)
        .then_with(|| a.mint_id.as_slice().cmp(b.mint_id.as_slice()))
        .then_with(|| a.candidate_id.as_slice().cmp(b.candidate_id.as_slice()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorDecisionV1 {
    None,
    Mint(Hash32),
    Null,
}

fn decode_payload_decision(payload: &AnchorPayloadV3) -> Result<AnchorDecisionV1, MintCensorError> {
    if payload.version != 3 {
        return Err(MintCensorError::ConsensusInvalid(
            "anchorpayloadv3 requires version=3",
        ));
    }
    if payload.mints.len() > 1 {
        return Err(MintCensorError::ConsensusInvalid(
            "anchorpayloadv3 allows at most one mint",
        ));
    }
    if payload.null_mint && payload.mints.len() == 1 {
        return Err(MintCensorError::ConsensusInvalid(
            "null_mint xor mint decision violated",
        ));
    }
    if payload.null_mint {
        return Ok(AnchorDecisionV1::Null);
    }
    if let Some(m) = payload.mints.first() {
        return Ok(AnchorDecisionV1::Mint(mint_id_v1(m)));
    }
    Ok(AnchorDecisionV1::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_types::{AnchorId, LockCommitment, MintEvent, MintPoWCertV1, TxOut};

    fn sample_params() -> MintCensorParamsV1 {
        MintCensorParamsV1 {
            network_id: [0x11; 32],
            windows_start_anchor: 100,
            w: 10,
            k: 3,
            n: 4,
            e: 8,
            min_target: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ],
            max_target: [0xFF; 32],
            initial_target: [0x7F; 32],
            candidate_feature_bits: 0,
        }
    }

    fn sample_candidate(
        network_id: Hash32,
        prev_mint_id: Hash32,
        window_id: u64,
        open_id: Hash32,
    ) -> MintCandidateEvent {
        MintCandidateEvent {
            version: 1,
            network_id,
            prev_mint_id,
            window_id,
            window_open_anchor_id: open_id,
            mint_commitment: [0x22; 32],
            nonce: 1,
            miner_pubkey: None,
            recipient_lock: None,
        }
    }

    fn sample_pow_cert(
        network_id: Hash32,
        prev_mint_id: Hash32,
        window_id: u64,
        open_id: Hash32,
    ) -> MintPoWCertV1 {
        MintPoWCertV1 {
            version: 1,
            network_id,
            prev_mint_id,
            window_id,
            window_open_anchor_id: open_id,
            mint_commitment: [0x22; 32],
            nonce: 1,
        }
    }

    fn sample_payload_with_mint(mint_id_seed: u8) -> AnchorPayloadV3 {
        let mint = MintEvent {
            version: 1,
            prev_mint_id: [0x44; 32],
            outputs: vec![TxOut {
                amount: 1,
                lock: LockCommitment([mint_id_seed; 32]),
            }],
            pow_seed: [0x55; 32],
            pow_nonce: 7,
            minted_at: 99,
        };
        AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![mint],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        }
    }

    #[test]
    fn window_bounds_are_anchor_index_based() {
        let p = sample_params();
        let b = p.window_bounds_for_anchor(112).unwrap();
        assert_eq!(b.window_id, 1);
        assert_eq!(b.window_open_anchor, 110);
        assert_eq!(b.close_anchor, 119);
        assert_eq!(b.deadline_anchor, 122);
    }

    #[test]
    fn params_reject_top_n_above_u32_for_root_encoding() {
        let mut p = sample_params();
        p.n = (u32::MAX as usize).saturating_add(1);
        let err = p.validate().unwrap_err();
        assert_eq!(
            err,
            MintCensorError::InvalidParams("N must be <= u32::MAX for candidate_root encoding")
        );
    }

    #[test]
    fn params_validate_rejects_invalid_configuration() {
        let mut p = sample_params();
        p.w = 0;
        assert!(p.validate().is_err());

        let mut p = sample_params();
        p.n = 0;
        assert!(p.validate().is_err());

        let mut p = sample_params();
        p.e = 0;
        assert!(p.validate().is_err());

        let mut p = sample_params();
        p.min_target = [0u8; 32];
        assert!(p.validate().is_err());

        let mut p = sample_params();
        p.min_target = [0xFF; 32];
        p.max_target = [0x00; 32];
        p.max_target[31] = 1;
        assert!(p.validate().is_err());

        let mut p = sample_params();
        p.min_target = {
            let mut v = [0u8; 32];
            v[31] = 5;
            v
        };
        p.max_target = [0xFF; 32];
        p.initial_target = {
            let mut v = [0u8; 32];
            v[31] = 1;
            v
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn target_update_clamps_and_obs_zero_rule() {
        let min_target = [0u8; 32];
        let mut min_target_mut = min_target;
        min_target_mut[31] = 1;
        let prev = {
            let mut v = [0u8; 32];
            v[31] = 8;
            v
        };
        let next_zero = next_candidate_target_v1(prev, 0, 4, min_target_mut, [0xFF; 32]);
        assert_eq!(next_zero[31], 16);

        let next_down = next_candidate_target_v1(prev, 16, 4, min_target_mut, [0xFF; 32]);
        assert_eq!(next_down[31], 2);
    }

    #[test]
    fn dedupe_and_top_n_are_deterministic() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);

        let mut c1 = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        c1.mint_commitment = [0x01; 32];
        c1.nonce = 1;
        let mut c2 = c1.clone();
        c2.nonce = 2; // same mint_commitment -> dedupe winner chosen by key
        let mut c3 = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        c3.mint_commitment = [0x02; 32];

        w.apply_finalized_candidate(bounds.window_open_anchor, &c1, &[0xAA; 32], &params)
            .unwrap();
        w.apply_finalized_candidate(bounds.window_open_anchor, &c2, &[0xAA; 32], &params)
            .unwrap();
        w.apply_finalized_candidate(bounds.window_open_anchor, &c3, &[0xAA; 32], &params)
            .unwrap();

        assert_eq!(w.top_n.len(), 2);
        assert!(w.winner_exists());
    }

    #[test]
    fn freeze_uses_top_n_frozen_for_root_and_winner() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let c = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        w.apply_finalized_candidate(bounds.close_anchor, &c, &[0xAA; 32], &params)
            .unwrap();
        w.maybe_freeze(bounds.close_anchor + 1);
        assert!(w.is_frozen());
        assert!(w.winner_exists());
        assert_ne!(w.candidate_root, [0u8; 32]);
    }

    #[test]
    fn freeze_is_allowed_when_observed_after_close_plus_one() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let c = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        w.apply_finalized_candidate(bounds.close_anchor, &c, &[0xAA; 32], &params)
            .unwrap();
        // Simulate delayed observation (restart/backfill): still must freeze deterministically.
        w.maybe_freeze(bounds.close_anchor + 3);
        assert!(w.is_frozen());
        assert_eq!(w.obs_prev_window, 1);
    }

    #[test]
    fn deterministic_apply_order_anchor_then_candidate_id() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let c1 = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        let mut c2 = c1.clone();
        c2.nonce = 999;
        let mut ts = vec![
            FinalizedCandidateTransition {
                anchor_index: 102,
                candidate: c2,
            },
            FinalizedCandidateTransition {
                anchor_index: 101,
                candidate: c1,
            },
        ];
        sort_candidate_transitions_deterministic(&mut ts);
        assert!(ts[0].anchor_index <= ts[1].anchor_index);
    }

    #[test]
    fn deterministic_apply_order_within_same_anchor_uses_candidate_id_only() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut c1 = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        let mut c2 = c1.clone();
        c1.nonce = 1;
        c2.nonce = 2;

        let id1 = candidate_id_v1(&c1);
        let id2 = candidate_id_v1(&c2);

        // Deliberately reverse input order for identical anchor_index.
        let mut ts = vec![
            FinalizedCandidateTransition {
                anchor_index: 111,
                candidate: c2,
            },
            FinalizedCandidateTransition {
                anchor_index: 111,
                candidate: c1,
            },
        ];
        sort_candidate_transitions_deterministic(&mut ts);

        let got0 = candidate_id_v1(&ts[0].candidate);
        let got1 = candidate_id_v1(&ts[1].candidate);
        assert!(got0.as_slice() <= got1.as_slice());
        if id1.as_slice() <= id2.as_slice() {
            assert_eq!(got0, id1);
            assert_eq!(got1, id2);
        } else {
            assert_eq!(got0, id2);
            assert_eq!(got1, id1);
        }
    }

    #[test]
    fn deterministic_pow_cert_order_anchor_then_cert_id() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let c1 = sample_pow_cert(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        let mut c2 = c1.clone();
        c2.nonce = 999;
        let mut ts = vec![
            FinalizedPowCertTransition {
                anchor_index: 102,
                cert: c2,
            },
            FinalizedPowCertTransition {
                anchor_index: 101,
                cert: c1,
            },
        ];
        sort_pow_cert_transitions_deterministic(&mut ts);
        assert!(ts[0].anchor_index <= ts[1].anchor_index);
    }

    #[test]
    fn payload_phase_rules_enforced() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let mut c = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        let payload = sample_payload_with_mint(9);

        // Build candidate using payload mint commitment so winner check can pass.
        if let Some(m) = payload.mints.first() {
            c.mint_commitment = mint_id_v1(m);
        }
        w.apply_finalized_candidate(bounds.close_anchor, &c, &[0xAA; 32], &params)
            .unwrap();
        w.maybe_freeze(bounds.close_anchor + 1);

        let no_decision = AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        };
        assert!(w
            .validate_anchor_payload_v3(bounds.deadline_anchor, &no_decision)
            .is_err());
        assert!(w
            .validate_anchor_payload_v3(bounds.deadline_anchor, &payload)
            .is_ok());
    }

    #[test]
    fn payload_decision_rejects_non_v3_version() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let mut payload = sample_payload_with_mint(9);
        payload.version = 2;
        assert!(w
            .validate_anchor_payload_v3(bounds.window_open_anchor, &payload)
            .is_err());
    }

    #[test]
    fn finalized_at_anchor_index_after_close_is_state_irrelevant() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let c = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        let out = w
            .apply_finalized_candidate(bounds.close_anchor + 1, &c, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out, ApplyOutcome::StateIrrelevantNoOp);
        assert!(w.top_n.is_empty());
    }

    #[test]
    fn stale_prev_is_noop_only_when_otherwise_bound_correctly() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);

        let stale_ok =
            sample_candidate(params.network_id, [0xEE; 32], bounds.window_id, [0xBB; 32]);
        let out = w
            .apply_finalized_candidate(bounds.window_open_anchor, &stale_ok, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out, ApplyOutcome::StateIrrelevantNoOp);

        let stale_bad_binding =
            sample_candidate(params.network_id, [0xEE; 32], bounds.window_id, [0xCC; 32]);
        let err = w
            .apply_finalized_candidate(
                bounds.window_open_anchor,
                &stale_bad_binding,
                &[0xAA; 32],
                &params,
            )
            .unwrap_err();
        assert_eq!(
            err,
            MintCensorError::ConsensusInvalid("candidate window_open_anchor_id mismatch")
        );
    }

    #[test]
    fn duplicate_candidate_id_is_idempotent_noop() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let c = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);

        let out1 = w
            .apply_finalized_candidate(bounds.window_open_anchor, &c, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out1, ApplyOutcome::Applied);

        let out2 = w
            .apply_finalized_candidate(bounds.window_open_anchor, &c, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out2, ApplyOutcome::DuplicateNoOp);
        assert_eq!(w.top_n.len(), 1);
        assert_eq!(w.obs_prev_window, 0);
    }

    #[test]
    fn pow_cert_import_uses_same_consensus_rules_as_candidate() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let cert = sample_pow_cert(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);

        let out1 = w
            .apply_finalized_pow_cert(bounds.window_open_anchor, &cert, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out1, ApplyOutcome::Applied);

        let out2 = w
            .apply_finalized_pow_cert(bounds.window_open_anchor, &cert, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out2, ApplyOutcome::DuplicateNoOp);
        assert_eq!(w.top_n.len(), 1);
    }

    #[test]
    fn pow_cert_import_records_cert_binding_for_missing_import() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let cert = sample_pow_cert(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);

        let out = w
            .apply_finalized_pow_cert(bounds.window_open_anchor, &cert, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out, ApplyOutcome::Applied);

        let cert_id = pow_cert_id_v1(&cert);
        let candidate_id = candidate_id_v1(&mint_candidate_from_pow_cert_v1(&cert));
        assert_eq!(
            w.pow_cert_to_candidate_id.get(&cert_id),
            Some(&candidate_id)
        );
    }

    #[test]
    fn obs_prev_window_counts_deduped_state_relevant_candidates_only() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);

        // Stale prev_mint_id: state-irrelevant and must not contribute to obs.
        let stale = sample_candidate(params.network_id, [0xEE; 32], bounds.window_id, [0xBB; 32]);
        let out = w
            .apply_finalized_candidate(bounds.window_open_anchor, &stale, &[0xAA; 32], &params)
            .unwrap();
        assert_eq!(out, ApplyOutcome::StateIrrelevantNoOp);

        // Two candidates with same mint_commitment -> one dedupe winner.
        let mut c1 = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        c1.mint_commitment = [0x01; 32];
        c1.nonce = 1;
        let mut c2 = c1.clone();
        c2.nonce = 2;

        // One additional distinct commitment.
        let mut c3 = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        c3.mint_commitment = [0x02; 32];
        c3.nonce = 3;

        w.apply_finalized_candidate(bounds.window_open_anchor, &c1, &[0xAA; 32], &params)
            .unwrap();
        w.apply_finalized_candidate(bounds.window_open_anchor, &c2, &[0xAA; 32], &params)
            .unwrap();
        w.apply_finalized_candidate(bounds.window_open_anchor, &c3, &[0xAA; 32], &params)
            .unwrap();

        assert_eq!(w.dedupe_by_commitment.len(), 2);
        w.maybe_freeze(bounds.close_anchor + 1);
        assert_eq!(w.obs_prev_window, 2);
        assert_eq!(w.top_n_ref().len(), 2);
    }

    #[test]
    fn censorship_evidence_checks_offending_payload() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let mut c = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        let good_payload = sample_payload_with_mint(5);
        if let Some(m) = good_payload.mints.first() {
            c.mint_commitment = mint_id_v1(m);
        }
        w.apply_finalized_candidate(bounds.close_anchor, &c, &[0xAA; 32], &params)
            .unwrap();
        w.maybe_freeze(bounds.close_anchor + 1);

        let winner_id = w.winner_ref().unwrap().candidate_id;
        let ev = EvidenceKind::MintCensorshipV1 {
            prev_mint_id: [0xAA; 32],
            window_id: bounds.window_id,
            expected_winner_candidate_id: winner_id,
            offending_anchor_id: AnchorId([0xEF; 32]),
        };
        let bad_payload = AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        };
        assert!(w
            .verify_mint_censorship_evidence(
                &ev,
                AnchorId([0xEF; 32]),
                bounds.deadline_anchor,
                &bad_payload,
            )
            .is_ok());

        let bad_anchor_binding = w.verify_mint_censorship_evidence(
            &ev,
            AnchorId([0xEE; 32]),
            bounds.deadline_anchor,
            &bad_payload,
        );
        assert!(bad_anchor_binding.is_err());
    }

    #[test]
    fn missing_import_evidence_checks_required_pow_cert_binding() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let mut w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let good_payload = sample_payload_with_mint(7);

        let mut cert = sample_pow_cert(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
        if let Some(m) = good_payload.mints.first() {
            cert.mint_commitment = mint_id_v1(m);
        }
        w.apply_finalized_pow_cert(bounds.close_anchor, &cert, &[0xAA; 32], &params)
            .unwrap();
        w.maybe_freeze(bounds.close_anchor + 1);

        let winner_id = w.winner_ref().unwrap().candidate_id;
        let cert_id = pow_cert_id_v1(&cert);
        let ev = EvidenceKind::MintMissingImportV1 {
            prev_mint_id: [0xAA; 32],
            window_id: bounds.window_id,
            expected_winner_candidate_id: winner_id,
            required_pow_cert_id: cert_id,
            offending_anchor_id: AnchorId([0xE1; 32]),
        };

        let bad_payload = AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        };

        assert!(w
            .verify_mint_missing_import_evidence(
                &ev,
                AnchorId([0xE1; 32]),
                bounds.deadline_anchor,
                &bad_payload,
            )
            .is_ok());

        let wrong_cert_ev = EvidenceKind::MintMissingImportV1 {
            prev_mint_id: [0xAA; 32],
            window_id: bounds.window_id,
            expected_winner_candidate_id: winner_id,
            required_pow_cert_id: [0x01; 32],
            offending_anchor_id: AnchorId([0xE1; 32]),
        };
        assert!(w
            .verify_mint_missing_import_evidence(
                &wrong_cert_ev,
                AnchorId([0xE1; 32]),
                bounds.deadline_anchor,
                &bad_payload,
            )
            .is_err());
    }

    #[test]
    fn candidate_root_hashes_exact_candidate_ids_without_extra_transform() {
        let rec1 = CandidateRecordV1 {
            candidate_id: [0x11; 32],
            mint_id: [0x22; 32],
            mint_commitment: [0x22; 32],
            pow_hash: [0x33; 32],
            finalized_at_anchor_index: 1,
        };
        let rec2 = CandidateRecordV1 {
            candidate_id: [0xAA; 32],
            mint_id: [0x44; 32],
            mint_commitment: [0x44; 32],
            pow_hash: [0x55; 32],
            finalized_at_anchor_index: 1,
        };
        let got = compute_candidate_root_v1(7, &[rec1.clone(), rec2.clone()]);

        let mut expect = Vec::new();
        expect.extend_from_slice(MINT_CANDROOT_DOMAIN_V1);
        expect.extend_from_slice(&7u64.to_le_bytes());
        expect.extend_from_slice(&2u32.to_le_bytes());
        expect.extend_from_slice(&rec1.candidate_id);
        expect.extend_from_slice(&rec2.candidate_id);
        assert_eq!(got, blake3_32(&expect));
    }

    #[test]
    fn candidate_root_empty_window_uses_same_formula_without_special_case() {
        let got = compute_candidate_root_v1(9, &[]);
        let mut expect = Vec::new();
        expect.extend_from_slice(MINT_CANDROOT_DOMAIN_V1);
        expect.extend_from_slice(&9u64.to_le_bytes());
        expect.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(got, blake3_32(&expect));
    }

    #[test]
    fn censorship_evidence_before_deadline_is_invalid() {
        let params = sample_params();
        let bounds = params.window_bounds_for_anchor(100).unwrap();
        let w = WindowStateV1::new([0xAA; 32], [0xBB; 32], bounds, [0xFF; 32]);
        let ev = EvidenceKind::MintCensorshipV1 {
            prev_mint_id: [0xAA; 32],
            window_id: bounds.window_id,
            expected_winner_candidate_id: [0x00; 32],
            offending_anchor_id: AnchorId([0xEF; 32]),
        };
        let offending_payload = AnchorPayloadV3 {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        };
        let err = w.verify_mint_censorship_evidence(
            &ev,
            AnchorId([0xEF; 32]),
            bounds.deadline_anchor.saturating_sub(1),
            &offending_payload,
        );
        assert!(err.is_err());
    }

    #[test]
    fn winner_key_uses_be_u256_then_mint_id_then_candidate_id() {
        let mut a = CandidateRecordV1 {
            candidate_id: [0x10; 32],
            mint_id: [0x20; 32],
            mint_commitment: [0x20; 32],
            pow_hash: [0x7F; 32],
            finalized_at_anchor_index: 1,
        };
        let mut b = a.clone();
        // Equal pow_hash, lower mint_id wins.
        b.mint_id = [0x01; 32];
        assert!(candidate_record_key_cmp(&b, &a).is_lt());

        // Equal pow_hash and mint_id, lower candidate_id wins.
        a.mint_id = [0x55; 32];
        b.mint_id = [0x55; 32];
        b.candidate_id = [0x00; 32];
        assert!(candidate_record_key_cmp(&b, &a).is_lt());
    }
}
