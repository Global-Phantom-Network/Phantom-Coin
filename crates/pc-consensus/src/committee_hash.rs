// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! On-chain verifiable committee selection (no off-chain VRF inputs).
//!
//! The selection is deterministic based on:
//! - `network_id`
//! - `last_payload_root` (the last finalized payload root)
//! - `epoch`
//! - the on-chain validator registry + stake (derived from staked UTXOs)
//!
//! This deliberately avoids off-chain JSON inputs (stake_registry.json / vrf_committee.json).

use crate::consts::MIN_ATTESTOR_STAKE;
use pc_crypto::{blake3_32, bls_pop_verify, BlsPublicKey, Hash32};

pub const COMMITTEE_SEED_DOMAIN_V1: &[u8] = b"pc:committee:seed:v1\x01";
pub const COMMITTEE_SCORE_DOMAIN_V1: &[u8] = b"pc:committee:score:v1\x01";

#[derive(Clone, Debug)]
pub struct CommitteeCandidate {
    pub recipient_id: [u8; 32],
    pub operator_id: [u8; 32],
    pub bls_pk: BlsPublicKey,
    pub bls_pop: [u8; 96],
    pub stake: u64,
}

#[derive(Clone, Debug)]
pub struct CommitteeSeat {
    pub recipient_id: [u8; 32],
    pub operator_id: [u8; 32],
    pub bls_pk: BlsPublicKey,
    pub score: Hash32,
}

/// Deterministic seed: H(domain || network_id || last_payload_root || epoch_le).
pub fn derive_committee_seed(network_id: Hash32, last_payload_root: Hash32, epoch: u64) -> Hash32 {
    let mut buf = Vec::with_capacity(COMMITTEE_SEED_DOMAIN_V1.len() + 32 + 32 + 8);
    buf.extend_from_slice(COMMITTEE_SEED_DOMAIN_V1);
    buf.extend_from_slice(&network_id);
    buf.extend_from_slice(&last_payload_root);
    buf.extend_from_slice(&epoch.to_le_bytes());
    blake3_32(&buf)
}

fn score(seed: &Hash32, recipient_id: &[u8; 32], operator_id: &[u8; 32]) -> Hash32 {
    let mut buf = Vec::with_capacity(COMMITTEE_SCORE_DOMAIN_V1.len() + 32 + 32 + 32);
    buf.extend_from_slice(COMMITTEE_SCORE_DOMAIN_V1);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(recipient_id);
    buf.extend_from_slice(operator_id);
    blake3_32(&buf)
}

/// Selects up to `k` committee seats deterministically.
/// Rules:
/// - `stake >= MIN_ATTESTOR_STAKE`
/// - BLS PoP must verify
/// - anti-collocation: at most 1 seat per `operator_id`
pub fn select_committee_hash(
    k: u8,
    seed: Hash32,
    candidates: &[CommitteeCandidate],
) -> Vec<CommitteeSeat> {
    if k == 0 || candidates.is_empty() {
        return Vec::new();
    }

    let mut scored: Vec<(Hash32, &CommitteeCandidate)> = Vec::with_capacity(candidates.len());
    for c in candidates {
        if c.stake < MIN_ATTESTOR_STAKE {
            continue;
        }
        if !bls_pop_verify(&c.bls_pk, &c.bls_pop) {
            continue;
        }
        let s = score(&seed, &c.recipient_id, &c.operator_id);
        scored.push((s, c));
    }
    if scored.is_empty() {
        return Vec::new();
    }

    // Deterministic sort: score asc, then recipient_id asc.
    scored.sort_by(|(sa, ca), (sb, cb)| match sa.cmp(sb) {
        core::cmp::Ordering::Equal => ca.recipient_id.cmp(&cb.recipient_id),
        other => other,
    });

    let mut used_ops: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut out: Vec<CommitteeSeat> = Vec::with_capacity(k as usize);
    for (s, c) in scored.into_iter() {
        if used_ops.contains(&c.operator_id) {
            continue;
        }
        used_ops.insert(c.operator_id);
        out.push(CommitteeSeat {
            recipient_id: c.recipient_id,
            operator_id: c.operator_id,
            bls_pk: c.bls_pk.clone(),
            score: s,
        });
        if out.len() >= k as usize {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_crypto::{bls_keygen_from_ikm, bls_pop_prove};

    fn mk_candidate(recipient_byte: u8, operator_byte: u8, stake: u64) -> CommitteeCandidate {
        let ikm = [recipient_byte; 32];
        let kp = bls_keygen_from_ikm(&ikm).expect("bls keygen");
        let pop = bls_pop_prove(&kp.sk);
        CommitteeCandidate {
            recipient_id: [recipient_byte; 32],
            operator_id: [operator_byte; 32],
            bls_pk: kp.pk,
            bls_pop: pop,
            stake,
        }
    }

    fn mk_candidate_with_bad_pop(
        recipient_byte: u8,
        operator_byte: u8,
        stake: u64,
    ) -> CommitteeCandidate {
        let ikm = [recipient_byte; 32];
        let kp = bls_keygen_from_ikm(&ikm).expect("bls keygen");

        // Wrong PoP: proof for a different keypair.
        let other = bls_keygen_from_ikm(&[recipient_byte.wrapping_add(1); 32]).expect("bls keygen");
        let bad_pop = bls_pop_prove(&other.sk);

        CommitteeCandidate {
            recipient_id: [recipient_byte; 32],
            operator_id: [operator_byte; 32],
            bls_pk: kp.pk,
            bls_pop: bad_pop,
            stake,
        }
    }

    #[test]
    fn committee_empty_candidates_yields_empty_committee() {
        let seed: Hash32 = [7u8; 32];
        let out = select_committee_hash(3, seed, &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn committee_filters_by_min_stake_and_rejects_invalid_pop() {
        let seed: Hash32 = [9u8; 32];
        let below = MIN_ATTESTOR_STAKE.saturating_sub(1);
        assert!(
            below < MIN_ATTESTOR_STAKE,
            "MIN_ATTESTOR_STAKE must be > 0 for this test"
        );

        let c_below = mk_candidate(1, 1, below);
        let c_ok = mk_candidate(2, 2, MIN_ATTESTOR_STAKE);
        let c_bad_pop = mk_candidate_with_bad_pop(3, 3, MIN_ATTESTOR_STAKE);

        let out = select_committee_hash(10, seed, &[c_below, c_ok, c_bad_pop]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].operator_id, [2u8; 32]);
    }

    #[test]
    fn committee_enforces_one_seat_per_operator_id() {
        let seed: Hash32 = [0x42u8; 32];
        let stake = MIN_ATTESTOR_STAKE.max(1);

        let a1 = mk_candidate(1, 9, stake);
        let a2 = mk_candidate(2, 9, stake);
        let b1 = mk_candidate(3, 8, stake);

        let out = select_committee_hash(10, seed, &[a1, a2, b1]);
        assert_eq!(out.len(), 2, "one seat per operator_id");
        assert_ne!(out[0].operator_id, out[1].operator_id);
    }

    #[test]
    fn committee_selection_is_deterministic() {
        let seed: Hash32 = [0x99u8; 32];
        let stake = MIN_ATTESTOR_STAKE.max(1);

        let c1 = mk_candidate(1, 1, stake);
        let c2 = mk_candidate(2, 2, stake);
        let c3 = mk_candidate(3, 3, stake);

        let a = select_committee_hash(2, seed, &[c1.clone(), c2.clone(), c3.clone()]);
        let b = select_committee_hash(2, seed, &[c1, c2, c3]);

        assert_eq!(a.len(), b.len());
        for (sa, sb) in a.iter().zip(b.iter()) {
            assert_eq!(sa.recipient_id, sb.recipient_id);
            assert_eq!(sa.operator_id, sb.operator_id);
            assert_eq!(sa.score, sb.score);
        }
    }
}
