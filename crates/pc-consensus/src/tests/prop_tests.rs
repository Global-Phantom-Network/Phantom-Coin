use super::*;
use proptest::prelude::*;

fn mk_recipients(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0] = (i & 0xFF) as u8;
            id
        })
        .collect()
}

proptest! {
    #[test]
    fn prop_equivocation_uses_full_pot(bond in 1u64..1_000_000, n in 2usize..33) {
        let params = SlashingParams::recommended_equivocation();
        let recipients = mk_recipients(n);
        // set offender as first
        let offender = recipients[0];
        let ev = pc_types::EvidenceKind::Equivocation { seat_id: offender, epoch_id: 1, a: pc_types::AnchorHeader::default(), b: Box::new(pc_types::AnchorHeader::default()) };
        let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).unwrap();
        // offender excluded
        prop_assert!(!set.entries.iter().any(|e| e.recipient_id == offender));
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        // 100% des Bonds
        prop_assert_eq!(sum, bond);
    }

    #[test]
    fn prop_vote_invalid_within_bounds(bond in 1u64..1_000_000, n in 2usize..33, bp in consts::SLASH_VOTE_INVALID_MIN_BP..=consts::SLASH_VOTE_INVALID_MAX_BP) {
        let params = SlashingParams::recommended_vote_invalid(bp).unwrap();
        let recipients = mk_recipients(n);
        let offender = recipients[0];
        let ev = pc_types::EvidenceKind::VoteInvalid { seat_id: offender, anchor: pc_types::AnchorHeader::default(), reason_code: 1 };
        let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).unwrap();
        // offender excluded
        prop_assert!(!set.entries.iter().any(|e| e.recipient_id == offender));
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        let pot = super::split_bp(bond, bp);
        prop_assert_eq!(sum, pot);
    }

    #[test]
    fn prop_conflicting_da_within_bounds(
        bond in 1u64..1_000_000,
        n in 2usize..33,
        bp in prop_oneof![
            Just(consts::SLASH_DA_25_BP),
            Just(consts::SLASH_DA_50_BP),
            Just(consts::SLASH_DA_100_BP)
        ]
    ) {
        let params = SlashingParams::recommended_conflicting_da(bp).unwrap();
        let recipients = mk_recipients(n);
        let offender = recipients[0];
        let ev = pc_types::EvidenceKind::ConflictingDAAttest {
            seat_id: offender,
            anchor_id: pc_types::AnchorId([1u8;32]),
            attest_a: vec![1,2,3],
            attest_b: vec![4,5,6],
        };
        let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).unwrap();
        // offender excluded
        prop_assert!(!set.entries.iter().any(|e| e.recipient_id == offender));
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        let pot = super::split_bp(bond, bp);
        prop_assert_eq!(sum, pot);
    }

    #[test]
    fn prop_finality_threshold_matches(pop in 0u8..=64u8, k in 1u8..=64u8) {
        // Popcount-basierter Check: konstruiere eine Maske mit exakt "pop" Bits gesetzt
        let mut mask: u64 = 0;
        for i in 0..(pop as u64).min(64) { mask |= 1u64 << i; }
        let eng = ConsensusEngine::new(ConsensusConfig{ k, fee_params: FeeSplitParams::recommended(), bootstrap_k1: false});
        let expect = super::is_final(pop, k);
        prop_assert_eq!(eng.is_final_mask(mask), expect);
    }
}
