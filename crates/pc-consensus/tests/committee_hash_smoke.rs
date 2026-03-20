// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use pc_consensus::committee_hash::{
    derive_committee_seed, select_committee_hash, CommitteeCandidate,
};
use pc_consensus::consts::MIN_ATTESTOR_STAKE;
use pc_crypto::{attestor_recipient_id_from_bls, blake3_32, bls_keygen_from_ikm, bls_pop_prove};

fn mk_candidate(
    seed: &[u8],
    operator_tag: &[u8],
    stake: u64,
    valid_pop: bool,
) -> CommitteeCandidate {
    let ikm = blake3_32(seed);
    let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
    let mut pop = bls_pop_prove(&kp.sk);
    if !valid_pop {
        pop[0] ^= 0xFF;
    }
    CommitteeCandidate {
        recipient_id: attestor_recipient_id_from_bls(&kp.pk),
        operator_id: blake3_32(operator_tag),
        bls_pk: kp.pk,
        bls_pop: pop,
        stake,
    }
}

#[test]
fn committee_seed_is_deterministic() {
    let nid = blake3_32(b"nid");
    let last = blake3_32(b"last");
    let a = derive_committee_seed(nid, last, 42);
    let b = derive_committee_seed(nid, last, 42);
    assert_eq!(a, b);
}

#[test]
fn committee_hash_selection_is_deterministic() {
    let nid = blake3_32(b"nid");
    let last = blake3_32(b"last");
    let seed = derive_committee_seed(nid, last, 3);
    let candidates = vec![
        mk_candidate(b"cand-1", b"op-a", MIN_ATTESTOR_STAKE, true),
        mk_candidate(b"cand-2", b"op-b", MIN_ATTESTOR_STAKE, true),
        mk_candidate(b"cand-3", b"op-c", MIN_ATTESTOR_STAKE, true),
    ];
    let a = select_committee_hash(2, seed, &candidates);
    let b = select_committee_hash(2, seed, &candidates);
    let a_ids: Vec<_> = a.iter().map(|s| (s.recipient_id, s.operator_id)).collect();
    let b_ids: Vec<_> = b.iter().map(|s| (s.recipient_id, s.operator_id)).collect();
    assert_eq!(a_ids, b_ids);
}

#[test]
fn committee_hash_filters_below_min_stake() {
    let seed = derive_committee_seed(blake3_32(b"nid"), blake3_32(b"last"), 0);
    let low = mk_candidate(
        b"cand-low",
        b"op-low",
        MIN_ATTESTOR_STAKE.saturating_sub(1),
        true,
    );
    let high = mk_candidate(b"cand-high", b"op-high", MIN_ATTESTOR_STAKE, true);
    let selected = select_committee_hash(2, seed, &[low.clone(), high.clone()]);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].recipient_id, high.recipient_id);
}

#[test]
fn committee_hash_enforces_operator_dedup() {
    let seed = derive_committee_seed(blake3_32(b"nid"), blake3_32(b"last"), 1);
    let same_op_a = mk_candidate(b"cand-a1", b"same-op", MIN_ATTESTOR_STAKE, true);
    let same_op_b = mk_candidate(b"cand-a2", b"same-op", MIN_ATTESTOR_STAKE, true);
    let other_op = mk_candidate(b"cand-b", b"other-op", MIN_ATTESTOR_STAKE, true);
    let selected = select_committee_hash(
        3,
        seed,
        &[same_op_a.clone(), same_op_b.clone(), other_op.clone()],
    );
    assert_eq!(
        selected
            .iter()
            .filter(|s| s.operator_id == same_op_a.operator_id)
            .count(),
        1
    );
}

#[test]
fn committee_hash_rejects_invalid_bls_pop() {
    let seed = derive_committee_seed(blake3_32(b"nid"), blake3_32(b"last"), 2);
    let invalid = mk_candidate(b"cand-invalid", b"op-invalid", MIN_ATTESTOR_STAKE, false);
    let valid = mk_candidate(b"cand-valid", b"op-valid", MIN_ATTESTOR_STAKE, true);
    let selected = select_committee_hash(2, seed, &[invalid.clone(), valid.clone()]);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].recipient_id, valid.recipient_id);
}

#[test]
fn committee_hash_empty_candidates_returns_empty() {
    let seed = derive_committee_seed(blake3_32(b"nid"), blake3_32(b"last"), 9);
    let selected = select_committee_hash(4, seed, &[]);
    assert!(selected.is_empty());
}
