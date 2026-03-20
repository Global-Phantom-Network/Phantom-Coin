use crate::consts::{
    MINT_CENSOR_RETARGET_REL_MAX_DEN, MINT_CENSOR_RETARGET_REL_MAX_NUM,
    MINT_CENSOR_RETARGET_REL_MIN_DEN, MINT_CENSOR_RETARGET_REL_MIN_NUM,
};
use crate::mint_censor_math::{
    cmp_u320_le, div_u320_by_u64_to_u320_le, is_zero_hash, mul_u256_by_u64_to_u320_le,
    u256_words_le_from_be_bytes, u320_to_u256_be_bytes,
};
use crate::mint_censor_v1::{ApplyOutcome, MintCensorError};
use pc_crypto::blake3_32;
use pc_types::{
    candidate_pow_hash_v2, candidate_slot_id_v2, candidate_submission_id_v2, cmp_hash_be_u256,
    mint_id_v1, pow_cert_id_v2, pow_cert_slot_id_v2, pow_cert_submission_id_v2,
    validate_mint_candidate_v2, validate_mint_pow_cert_v2, AnchorPayloadV3, EvidenceKind,
    MintCandidateEventV2, MintPoWCertV2,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];

const MINT_CANDROOT_DOMAIN_V2: &[u8] = b"PHANTOM:MINT:CANDROOT:v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowBoundsV2 {
    pub window_id: u64,
    pub window_open_anchor: u64,
    pub close_anchor: u64,
    pub deadline_anchor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintCensorParamsV2 {
    pub network_id: Hash32,
    pub windows_start_anchor: u64,
    pub w: u64,
    pub k: u64,
    pub n: usize,
    pub e: u64,
    pub min_target: Hash32,
    pub max_target: Hash32,
    pub initial_target: Hash32,
}

impl MintCensorParamsV2 {
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

    pub fn window_bounds_for_anchor(&self, anchor_index: u64) -> Option<WindowBoundsV2> {
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
        Some(WindowBoundsV2 {
            window_id,
            window_open_anchor,
            close_anchor,
            deadline_anchor,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRecordV2 {
    pub submission_id: Hash32,
    pub slot_id: Hash32,
    pub pow_hash: Hash32,
    pub mint_commitment: Hash32,
    pub finalized_at_anchor_index: u64,
    pub pow_cert_id: Option<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowStateV2 {
    pub prev_mint_id: Hash32,
    pub window_id: u64,
    pub window_open_anchor_id: Hash32,
    pub close_anchor: u64,
    pub deadline_anchor: u64,
    pub candidate_target: Hash32,
    pub dedupe_by_slot_id: BTreeMap<Hash32, CandidateRecordV2>,
    pub seen_submission_ids: BTreeSet<Hash32>,
    pub pow_cert_to_submission_id: BTreeMap<Hash32, Hash32>,
    pub top_n: Vec<CandidateRecordV2>,
    pub winner: Option<CandidateRecordV2>,
    pub candidate_root: Hash32,
    pub obs_prev_window: u64,
    frozen: bool,
}

impl WindowStateV2 {
    pub fn new(
        prev_mint_id: Hash32,
        window_open_anchor_id: Hash32,
        bounds: WindowBoundsV2,
        candidate_target: Hash32,
    ) -> Self {
        let top_n = Vec::new();
        let candidate_root = compute_candidate_root_v2(bounds.window_id, &top_n);
        Self {
            prev_mint_id,
            window_id: bounds.window_id,
            window_open_anchor_id,
            close_anchor: bounds.close_anchor,
            deadline_anchor: bounds.deadline_anchor,
            candidate_target,
            dedupe_by_slot_id: BTreeMap::new(),
            seen_submission_ids: BTreeSet::new(),
            pow_cert_to_submission_id: BTreeMap::new(),
            top_n,
            winner: None,
            candidate_root,
            obs_prev_window: 0,
            frozen: false,
        }
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    pub fn top_n_ref(&self) -> &[CandidateRecordV2] {
        self.top_n.as_slice()
    }

    pub fn maybe_freeze(&mut self, anchor_index: u64) {
        if self.frozen || anchor_index < self.close_anchor.saturating_add(1) {
            return;
        }
        self.obs_prev_window = self.dedupe_by_slot_id.len() as u64;
        self.candidate_root = compute_candidate_root_v2(self.window_id, &self.top_n);
        self.winner = self.top_n.first().cloned();
        self.frozen = true;
    }

    pub fn apply_finalized_candidate_v2(
        &mut self,
        finalized_at_anchor_index: u64,
        candidate: &MintCandidateEventV2,
        state_last_mint_id: &Hash32,
        params: &MintCensorParamsV2,
    ) -> Result<ApplyOutcome, MintCensorError> {
        if finalized_at_anchor_index > self.close_anchor {
            return Ok(ApplyOutcome::StateIrrelevantNoOp);
        }
        if self.frozen {
            return Ok(ApplyOutcome::StateIrrelevantNoOp);
        }

        validate_mint_candidate_v2(candidate).map_err(MintCensorError::ConsensusInvalid)?;

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

        let pow_hash = candidate_pow_hash_v2(candidate);
        if cmp_hash_be_u256(&pow_hash, &self.candidate_target).is_gt() {
            return Err(MintCensorError::ConsensusInvalid(
                "candidate pow hash does not meet target",
            ));
        }

        let submission_id = candidate_submission_id_v2(candidate);
        if self.seen_submission_ids.contains(&submission_id) {
            return Ok(ApplyOutcome::DuplicateNoOp);
        }

        let rec = CandidateRecordV2 {
            submission_id,
            slot_id: candidate_slot_id_v2(candidate),
            pow_hash,
            mint_commitment: candidate.mint_commitment,
            finalized_at_anchor_index,
            pow_cert_id: None,
        };

        self.seen_submission_ids.insert(rec.submission_id);
        match self.dedupe_by_slot_id.get_mut(&rec.slot_id) {
            Some(existing) => {
                if candidate_record_key_cmp(&rec, existing).is_lt() {
                    *existing = rec;
                }
            }
            None => {
                self.dedupe_by_slot_id.insert(rec.slot_id, rec);
            }
        }

        self.recompute_top_n(params.n);
        Ok(ApplyOutcome::Applied)
    }

    pub fn apply_finalized_pow_cert_v2(
        &mut self,
        finalized_at_anchor_index: u64,
        cert: &MintPoWCertV2,
        state_last_mint_id: &Hash32,
        params: &MintCensorParamsV2,
    ) -> Result<ApplyOutcome, MintCensorError> {
        validate_mint_pow_cert_v2(cert).map_err(MintCensorError::ConsensusInvalid)?;

        let cert_id = pow_cert_id_v2(cert);
        let submission_id = pow_cert_submission_id_v2(cert);
        if let Some(existing) = self.pow_cert_to_submission_id.get(&cert_id) {
            if *existing == submission_id {
                return Ok(ApplyOutcome::DuplicateNoOp);
            }
            return Err(MintCensorError::ConsensusInvalid(
                "pow-cert id maps to conflicting submission_id",
            ));
        }

        let candidate = mint_candidate_from_pow_cert_v2(cert);
        let out = self.apply_finalized_candidate_v2(
            finalized_at_anchor_index,
            &candidate,
            state_last_mint_id,
            params,
        )?;
        if matches!(out, ApplyOutcome::Applied | ApplyOutcome::DuplicateNoOp) {
            self.pow_cert_to_submission_id
                .insert(cert_id, submission_id);
            if let Some(existing) = self.dedupe_by_slot_id.get_mut(&pow_cert_slot_id_v2(cert)) {
                if existing.submission_id == submission_id {
                    existing.pow_cert_id = Some(cert_id);
                }
            }
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
            if matches!(decision, AnchorDecisionV2::None) {
                return Ok(());
            }
            return Err(MintCensorError::ConsensusInvalid(
                "mint decision not allowed before close_anchor",
            ));
        }

        if anchor_index < self.deadline_anchor {
            return match decision {
                AnchorDecisionV2::None => Ok(()),
                AnchorDecisionV2::Mint(mint_id) => match winner {
                    Some(w) if mint_id == w.mint_commitment => Ok(()),
                    _ => Err(MintCensorError::ConsensusInvalid(
                        "mint decision does not match winner",
                    )),
                },
                AnchorDecisionV2::Null => {
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

        match winner {
            Some(w) => match decision {
                AnchorDecisionV2::Mint(mint_id) if mint_id == w.mint_commitment => Ok(()),
                _ => Err(MintCensorError::ConsensusInvalid(
                    "deadline violation: winner must be minted",
                )),
            },
            None => match decision {
                AnchorDecisionV2::Null => Ok(()),
                _ => Err(MintCensorError::ConsensusInvalid(
                    "deadline violation: null decision required for empty window",
                )),
            },
        }
    }

    pub fn verify_mint_censorship_evidence_v2(
        &self,
        evidence: &EvidenceKind,
        offending_anchor_id: pc_types::AnchorId,
        offending_anchor_index: u64,
        offending_payload: &AnchorPayloadV3,
    ) -> Result<(), MintCensorError> {
        let (
            prev_mint_id,
            window_id,
            expected_winner_submission_id,
            offending_anchor_id_in_evidence,
        ) = match evidence {
            EvidenceKind::MintCensorshipV2 {
                prev_mint_id,
                window_id,
                expected_winner_submission_id,
                offending_anchor_id,
            } => (
                prev_mint_id,
                *window_id,
                expected_winner_submission_id,
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
        if *expected_winner_submission_id != winner.submission_id {
            return Err(MintCensorError::ConsensusInvalid(
                "expected_winner_submission_id mismatch",
            ));
        }

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

    pub fn verify_mint_missing_import_evidence_v2(
        &self,
        evidence: &EvidenceKind,
        offending_anchor_id: pc_types::AnchorId,
        offending_anchor_index: u64,
        offending_payload: &AnchorPayloadV3,
    ) -> Result<(), MintCensorError> {
        let (
            prev_mint_id,
            window_id,
            expected_winner_submission_id,
            required_pow_cert_id,
            offending_anchor_id_in_evidence,
        ) = match evidence {
            EvidenceKind::MintMissingImportV2 {
                prev_mint_id,
                window_id,
                expected_winner_submission_id,
                required_pow_cert_id,
                offending_anchor_id,
            } => (
                prev_mint_id,
                *window_id,
                expected_winner_submission_id,
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
        if *expected_winner_submission_id != winner.submission_id {
            return Err(MintCensorError::ConsensusInvalid(
                "expected_winner_submission_id mismatch",
            ));
        }
        let mapped_submission = self
            .pow_cert_to_submission_id
            .get(required_pow_cert_id)
            .ok_or(MintCensorError::ConsensusInvalid(
                "required_pow_cert_id not found in finalized window",
            ))?;
        if *mapped_submission != winner.submission_id {
            return Err(MintCensorError::ConsensusInvalid(
                "required_pow_cert_id does not map to winner submission",
            ));
        }

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

    fn winner_ref(&self) -> Option<&CandidateRecordV2> {
        self.top_n.first()
    }

    fn recompute_top_n(&mut self, n: usize) {
        let mut winners: Vec<CandidateRecordV2> =
            self.dedupe_by_slot_id.values().cloned().collect();
        winners.sort_by(candidate_record_key_cmp);
        if winners.len() > n {
            winners.truncate(n);
        }
        self.top_n = winners.clone();
        self.winner = winners.first().cloned();
        self.candidate_root = compute_candidate_root_v2(self.window_id, &winners);
    }
}

pub fn compute_candidate_root_v2(
    window_id: u64,
    candidates_sorted: &[CandidateRecordV2],
) -> Hash32 {
    let mut buf =
        Vec::with_capacity(MINT_CANDROOT_DOMAIN_V2.len() + 8 + 4 + candidates_sorted.len() * 32);
    buf.extend_from_slice(MINT_CANDROOT_DOMAIN_V2);
    buf.extend_from_slice(&window_id.to_le_bytes());
    let m_u32 = u32::try_from(candidates_sorted.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&m_u32.to_le_bytes());
    for c in candidates_sorted {
        buf.extend_from_slice(&c.submission_id);
    }
    blake3_32(&buf)
}

pub fn next_candidate_target_v2(
    prev_target: Hash32,
    obs_prev_window: u64,
    expected_candidates_per_window: u64,
    min_target: Hash32,
    max_target: Hash32,
) -> Hash32 {
    let prev_le = u256_words_le_from_be_bytes(&prev_target);

    let raw_u320_le = if obs_prev_window == 0 {
        div_u320_by_u64_to_u320_le(
            mul_u256_by_u64_to_u320_le(prev_le, MINT_CENSOR_RETARGET_REL_MAX_NUM),
            MINT_CENSOR_RETARGET_REL_MAX_DEN,
        )
    } else {
        let num = mul_u256_by_u64_to_u320_le(prev_le, expected_candidates_per_window);
        div_u320_by_u64_to_u320_le(num, obs_prev_window)
    };

    let rel_min_u320 = div_u320_by_u64_to_u320_le(
        mul_u256_by_u64_to_u320_le(prev_le, MINT_CENSOR_RETARGET_REL_MIN_NUM),
        MINT_CENSOR_RETARGET_REL_MIN_DEN,
    );
    let rel_max_u320 = div_u320_by_u64_to_u320_le(
        mul_u256_by_u64_to_u320_le(prev_le, MINT_CENSOR_RETARGET_REL_MAX_NUM),
        MINT_CENSOR_RETARGET_REL_MAX_DEN,
    );

    let rel_clamped = if cmp_u320_le(&raw_u320_le, &rel_min_u320).is_lt() {
        rel_min_u320
    } else if cmp_u320_le(&raw_u320_le, &rel_max_u320).is_gt() {
        rel_max_u320
    } else {
        raw_u320_le
    };

    let Some(rel_be) = u320_to_u256_be_bytes(rel_clamped) else {
        return max_target;
    };

    if cmp_hash_be_u256(&rel_be, &min_target).is_lt() {
        return min_target;
    }
    if cmp_hash_be_u256(&rel_be, &max_target).is_gt() {
        return max_target;
    }
    rel_be
}

fn mint_candidate_from_pow_cert_v2(c: &MintPoWCertV2) -> MintCandidateEventV2 {
    MintCandidateEventV2 {
        version: 2,
        network_id: c.network_id,
        prev_mint_id: c.prev_mint_id,
        window_id: c.window_id,
        window_open_anchor_id: c.window_open_anchor_id,
        mint_commitment: c.mint_commitment,
        nonce: c.nonce,
        miner_pubkey: None,
        recipient_lock: None,
    }
}

fn candidate_record_key_cmp(a: &CandidateRecordV2, b: &CandidateRecordV2) -> Ordering {
    cmp_hash_be_u256(&a.pow_hash, &b.pow_hash)
        .then_with(|| {
            a.mint_commitment
                .as_slice()
                .cmp(b.mint_commitment.as_slice())
        })
        .then_with(|| a.submission_id.as_slice().cmp(b.submission_id.as_slice()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorDecisionV2 {
    None,
    Mint(Hash32),
    Null,
}

fn decode_payload_decision(payload: &AnchorPayloadV3) -> Result<AnchorDecisionV2, MintCensorError> {
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
        return Ok(AnchorDecisionV2::Null);
    }
    if let Some(m) = payload.mints.first() {
        return Ok(AnchorDecisionV2::Mint(mint_id_v1(m)));
    }
    Ok(AnchorDecisionV2::None)
}
