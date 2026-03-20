use super::*;
use pc_crypto::blake3_32;
use pc_crypto::{attestor_recipient_id_from_bls, bls_keygen_from_ikm};
use pc_types::{LockCommitment, MintEvent, TxOut};

#[test]
fn threshold() {
    assert_eq!(finality_threshold(21), 15);
    assert!(is_final(15, 21));
    assert!(!is_final(14, 21));
}

#[test]
fn mask_ops() {
    let m = set_bit(0, 5).unwrap();
    assert_eq!(popcount_u64(m), 1);
    assert!(set_bit(0, 64).is_err());
}

#[test]
fn attestor_payout_from_bls_matches_direct_ids() {
    let params = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 1,
        perf_weights: vec![10_000],
    };
    params.validate().unwrap();

    let ikm1 = blake3_32(b"ikm-att-1");
    let ikm2 = blake3_32(b"ikm-att-2");
    let k1 = bls_keygen_from_ikm(&ikm1).unwrap();
    let k2 = bls_keygen_from_ikm(&ikm2).unwrap();
    let pks = [k1.pk.clone(), k2.pk.clone()];
    let ids = [
        attestor_recipient_id_from_bls(&k1.pk),
        attestor_recipient_id_from_bls(&k2.pk),
    ];
    let fees = 12_345u64;

    let from_pks = compute_attestor_payout_from_bls(fees, &params, &pks).unwrap();
    let from_ids = compute_attestor_payout(fees, &params, &ids).unwrap();
    assert_eq!(from_pks.payout_root(), from_ids.payout_root());
}

#[test]
fn attestor_payout_from_bls_empty_ok() {
    let params = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 1,
        perf_weights: vec![10_000],
    };
    params.validate().unwrap();
    let fees = 9_999u64;
    let set = compute_attestor_payout_from_bls(fees, &params, &[]).unwrap();
    assert!(set.entries.is_empty());
    assert_eq!(set.payout_root(), [0u8; 32]);
}

#[test]
fn pow_meets_boundaries() {
    // 0 Bits: immer erfüllt
    let h = [0xFFu8; 32];
    assert!(pow_meets(0, &h));
    // 4 führende Nullbits: 0x0F...
    let mut h2 = [0xFFu8; 32];
    h2[0] = 0x0F; // 0000 1111
    assert!(pow_meets(4, &h2));
    assert!(!pow_meets(5, &h2));
    // Volle Bytes = 8 Bits: 0x00..
    let mut h3 = [0xFFu8; 32];
    h3[0] = 0x00;
    assert!(pow_meets(8, &h3));
    // 9 Bits → erstes Byte 0x00, zweites MSB=0
    h3[1] = 0x7F; // 0111 1111
    assert!(pow_meets(9, &h3));
    h3[1] = 0xFF; // 1111 1111
    assert!(!pow_meets(9, &h3));
}

#[test]
fn fee_split_committee() {
    let params = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 4,
        perf_weights: vec![10000, 6000, 3600, 2160],
    };
    params.validate().unwrap();
    let _k = 3usize;
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let dists = [Some(1u8), Some(2u8), None];
    let fees = 1000u64;
    let set = compute_committee_payout(fees, &params, &recipients, 1, &dists).unwrap();
    // Summe prüfen
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(
        sum,
        split_bp(fees, 6500) + split_bp(fees, 1000) + split_bp(fees, 1500)
    );
}

#[test]
fn fee_split_committee_with_eligibility_all_ineligible() {
    let params = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 4,
        perf_weights: vec![10000, 6000, 3600, 2160],
    };
    params.validate().unwrap();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let dists = [Some(1u8), Some(2u8), None];
    let fees = 1000u64;
    let fee_eligible = [false, false, false];
    let set = compute_committee_payout_with_eligibility(
        fees,
        &params,
        &recipients,
        1,
        &dists,
        &fee_eligible,
    )
    .unwrap();
    assert!(set.entries.is_empty());
    assert_eq!(set.payout_root(), [0u8; 32]);
}

#[test]
fn fee_split_committee_with_eligibility_proposer_ineligible_gets_no_prop_pot() {
    let params = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 4,
        perf_weights: vec![10000, 6000, 3600, 2160],
    };
    params.validate().unwrap();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let dists = [Some(1u8), Some(2u8), None];
    let fees = 1000u64;
    // proposer_index=1 is not fee-eligible.
    let fee_eligible = [true, false, true];
    let set = compute_committee_payout_with_eligibility(
        fees,
        &params,
        &recipients,
        1,
        &dists,
        &fee_eligible,
    )
    .unwrap();
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    // proposer pot is burned/undistributed when proposer is ineligible
    let expected = split_bp(fees, 6500) + split_bp(fees, 1500);
    assert_eq!(sum, expected);
}

#[test]
fn fee_split_attestors() {
    let params = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 1,
        perf_weights: vec![10000],
    };
    params.validate().unwrap();
    let att = [blake3_32(b"x"), blake3_32(b"y")];
    let fees = 1000u64;
    let set = compute_attestor_payout(fees, &params, &att).unwrap();
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, split_bp(fees, 1000));
}

#[test]
fn anchor_graph_ack_distance_basic() {
    // A <- B <- C (C ist ack_id); Seats: A:0, B:1, C:2
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let mut g = AnchorGraph::new();
    let id_a_ins = g.insert(a);
    let _ = g.insert(b);
    let _ = g.insert(c);
    assert!(g.contains(&pc_types::AnchorId(id_a_ins.0)));

    let res = g.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
    assert_eq!(res[0], Some(2));
    assert_eq!(res[1], Some(1));
    assert_eq!(res[2], None);
}

#[test]
fn anchor_graph_cache_basic() {
    // A <- B <- C (C ist ack_id)
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let mut cache = AnchorGraphCache::new();
    cache.insert(a);
    cache.insert(b);
    cache.insert(c);
    let res1 = cache.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
    assert_eq!(res1[0], Some(2));
    assert_eq!(res1[1], Some(1));
    assert_eq!(res1[2], None);
    // Nochmals abrufen (aus Cache)
    let res2 = cache.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
    assert_eq!(res1, res2);
}

#[test]
fn anchor_graph_capacity_evicts_oldest() {
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };

    let id_a = pc_types::AnchorId(a.id_digest());
    let id_b = pc_types::AnchorId(b.id_digest());
    let id_c = pc_types::AnchorId(c.id_digest());

    let mut g = AnchorGraph::with_max_capacity(2);
    g.insert(a);
    g.insert(b);
    g.insert(c);

    assert_eq!(g.len(), 2);
    assert_eq!(g.evict_total(), 1);
    assert!(!g.contains(&id_a));
    assert!(g.contains(&id_b));
    assert!(g.contains(&id_c));
}

#[test]
fn anchor_graph_cache_orphan_pool_unblocks() {
    // A <- B <- C, but insert out-of-order: B first, then A, then C.
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let mut cache = AnchorGraphCache::with_limits(16, 16, 16);
    cache.insert(b);
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.orphans_len(), 1);

    cache.insert(a);
    assert_eq!(cache.orphans_len(), 0);
    assert_eq!(cache.len(), 2);

    cache.insert(c);
    assert_eq!(cache.len(), 3);

    let res = cache.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
    assert_eq!(res[0], Some(2));
    assert_eq!(res[1], Some(1));
    assert_eq!(res[2], None);
}

#[test]
fn anchor_graph_cache_clears_ack_cache_on_evict() {
    // A <- B <- C, with a tiny graph cap. We compute distances for C, then evict A and ensure
    // the cached result does not survive the eviction.
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let mut cache = AnchorGraphCache::with_limits(3, 0, 16);
    cache.insert(a);
    cache.insert(b);
    cache.insert(c);

    let res1 = cache.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
    assert_eq!(res1[0], Some(2));
    assert_eq!(res1[1], Some(1));

    // Evict the oldest node (A) and ensure ack cache is cleared.
    cache.set_graph_max_capacity(2);
    let res2 = cache.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
    assert_eq!(res2[0], None);
    assert_eq!(res2[1], Some(1));
}

#[test]
fn engine_finality_and_ack_distances() {
    // Graph: A <- B <- C (C ist ack_id)
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let cfg = ConsensusConfig::recommended(3);
    let mut eng = ConsensusEngine::new(cfg);
    eng.insert_header(a);
    eng.insert_header(b);
    eng.insert_header(c);

    let d = eng.ack_distances(pc_types::AnchorId(id_c));
    assert_eq!(d.len(), 3);
    assert_eq!(d[0], Some(2));
    assert_eq!(d[1], Some(1));
    assert_eq!(d[2], None);

    // Finalität: k=3 → T=floor(2*3/3)+1 = 3
    // Mask mit 2 Stimmen ist NICHT final, mit 3 Stimmen schon
    let m2 = set_bit(set_bit(0, 0).unwrap(), 1).unwrap();
    assert!(!eng.is_final_mask(m2));
    let m3 = set_bit(m2, 2).unwrap();
    assert!(eng.is_final_mask(m3));
}

#[test]
fn engine_payout_root_matches_direct() {
    // gleicher Graph wie oben
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
    eng.insert_header(a.clone());
    eng.insert_header(b.clone());
    eng.insert_header(c.clone());

    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let fees = 10_000u64;

    let root_engine = eng
        .committee_payout_root_for_ack(fees, &recipients, 1, pc_types::AnchorId(id_c))
        .expect("engine payout root");

    let headers = vec![a, b, c];
    let params = FeeSplitParams::recommended();
    let root_direct = compute_committee_payout_from_headers(
        fees,
        &params,
        &recipients,
        1,
        pc_types::AnchorId(id_c),
        &headers,
        3,
    )
    .map(|s| s.payout_root())
    .expect("direct payout root");

    assert_eq!(root_engine, root_direct);
}

#[test]
fn auto_proposer_uses_creator_index() {
    // Graph: A <- B <- C, C.creator_index = 2
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2, // This should become the proposer
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };

    let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
    eng.insert_header(a);
    eng.insert_header(b);
    eng.insert_header(c.clone());

    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let fees = 10_000u64;

    // Auto-proposer should use c.creator_index (= 2)
    let root_auto = eng
        .committee_payout_root_for_ack_auto_proposer(fees, &recipients, &c)
        .expect("auto proposer root");

    // Manual call with proposer_index = 2 should match
    let root_manual = eng
        .committee_payout_root_for_ack(fees, &recipients, 2, pc_types::AnchorId(c.id_digest()))
        .expect("manual proposer root");

    assert_eq!(root_auto, root_manual);

    // Different proposer_index should give different result
    let root_different = eng
        .committee_payout_root_for_ack(fees, &recipients, 0, pc_types::AnchorId(c.id_digest()))
        .expect("different proposer root");

    assert_ne!(root_auto, root_different);
}

#[test]
fn distribute_equal_invariants() {
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let total = 1001u64;
    let shares = distribute_equal(total, &recipients);
    assert_eq!(shares.len(), recipients.len());
    // Summe stimmt
    let sum: u64 = shares.iter().copied().sum();
    assert_eq!(sum, total);
    // Jeder Anteil ist base oder base+1
    let base = total / (recipients.len() as u64);
    let rem = total % (recipients.len() as u64);
    let mut cnt_base = 0usize;
    let mut cnt_plus = 0usize;
    for &s in &shares {
        assert!(s == base || s == base + 1);
        if s == base {
            cnt_base += 1;
        } else {
            cnt_plus += 1;
        }
    }
    assert_eq!(cnt_plus as u64, rem);
    assert_eq!(cnt_base + cnt_plus, recipients.len());
    // Deterministisch bei erneutem Aufruf
    let shares2 = distribute_equal(total, &recipients);
    assert_eq!(shares, shares2);
}

#[test]
fn distribute_by_weights_invariants() {
    let recipients = [blake3_32(b"x"), blake3_32(b"y"), blake3_32(b"z")];
    let total = 10_000u64;
    let weights = [5u64, 0u64, 5u64]; // Summe 10
    let shares = distribute_by_weights(total, &recipients, &weights);
    assert_eq!(shares.len(), recipients.len());
    // Summe stimmt
    let sum: u64 = shares.iter().copied().sum();
    assert_eq!(sum, total);
    // Jeder Anteil liegt in der Nähe des proportionalen Anteils (floor/ceil)
    let sum_w = 10u64;
    for (i, &w) in weights.iter().enumerate() {
        let base = (total as u128) * (w as u128) / (sum_w as u128);
        let s = shares[i] as u128;
        assert!(s == base || s == base + 1 || (base > 0 && s + 1 == base));
    }
    // Deterministisch bei erneutem Aufruf
    let shares2 = distribute_by_weights(total, &recipients, &weights);
    assert_eq!(shares, shares2);
}

#[test]
fn distribute_by_weights_zero_sum_falls_back_to_equal() {
    // L1-Fix: Bei sum_w==0 jetzt Fallback auf Gleichverteilung statt Nullen
    // L1-Fix: With sum_w==0, now falls back to equal distribution instead of zeros
    let recipients = [blake3_32(b"p"), blake3_32(b"q")];
    let total = 123u64;
    let weights = [0u64, 0u64];
    let shares = distribute_by_weights(total, &recipients, &weights);
    // Gleichverteilung: 123 / 2 = 61 Rest 1 → [61, 62] oder [62, 61] je nach Sortierung
    let sum: u64 = shares.iter().sum();
    assert_eq!(sum, total); // Keine Coins verloren!
    assert!(shares.iter().all(|&s| s == 61 || s == 62));
}

#[test]
fn recommended_params_invariants() {
    let p = FeeSplitParams::recommended();
    // validate prüft Summe==10_000, Länge==d_max und monotone Gewichte
    p.validate().expect("recommended params invalid");
    // redundante Checks (explizit)
    let sum =
        (p.p_base_bp as u32) + (p.p_prop_bp as u32) + (p.p_perf_bp as u32) + (p.p_att_bp as u32);
    assert_eq!(sum, 10_000);
    assert_eq!(p.perf_weights.len(), p.d_max as usize);
    for w in p.perf_weights.windows(2) {
        if let [a, b] = w {
            assert!(a >= b);
        }
    }
}

#[test]
fn split_sums_match_total() {
    let params = FeeSplitParams::recommended();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let att = [blake3_32(b"x"), blake3_32(b"y")];
    let fees = 123_456_789u64;
    let dists = [Some(1u8), Some(2u8), None];
    let committee = compute_committee_payout(fees, &params, &recipients, 1, &dists).unwrap();
    let attestors = compute_attestor_payout(fees, &params, &att).unwrap();
    let sum_comm: u64 = committee.entries.iter().map(|e| e.amount).sum();
    let sum_att: u64 = attestors.entries.iter().map(|e| e.amount).sum();
    // Summe der ausgezahlten Beträge entspricht exakt der Summe der Topf-Splits (base/prop/perf/att)
    let base_pot = split_bp(fees, params.p_base_bp);
    let prop_pot = split_bp(fees, params.p_prop_bp);
    let perf_pot = split_bp(fees, params.p_perf_bp);
    let att_pot = split_bp(fees, params.p_att_bp);
    let sum_pots = base_pot + prop_pot + perf_pot + att_pot;
    assert_eq!(sum_comm + sum_att, sum_pots);
    // Rundungsverlust über alle Töpfe ist klein und deterministisch (< Anzahl Töpfe)
    assert!(sum_pots <= fees);
    assert!((fees - sum_pots) < 4);
}

#[test]
fn ack_distances_fn_matches_graph() {
    // A <- B <- C (C ack)
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    // compute via helper fn on slice
    let headers = vec![a.clone(), b.clone(), c.clone()];
    let via_fn = compute_ack_distances_for_seats(
        pc_types::AnchorId(id_c),
        &headers,
        3,
        FeeSplitParams::recommended().d_max,
    );

    // compute via engine
    let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
    eng.insert_header(a);
    eng.insert_header(b);
    eng.insert_header(c);
    let via_eng = eng.ack_distances(pc_types::AnchorId(id_c));

    assert_eq!(via_fn, via_eng);
}

#[test]
fn maturity_thresholds_boundaries() {
    let m0: AnchorIndex = 1_000_000;
    // Unter L1
    assert!(!maturity_reached(
        m0 + consts::MATURITY_L1 - 1,
        m0,
        consts::MATURITY_L1
    ));
    // Genau L1
    assert!(maturity_reached(
        m0 + consts::MATURITY_L1,
        m0,
        consts::MATURITY_L1
    ));
    // L2 und L3
    assert!(maturity_reached(
        m0 + consts::MATURITY_L2,
        m0,
        consts::MATURITY_L2
    ));
    assert!(maturity_reached(
        m0 + consts::MATURITY_L3,
        m0,
        consts::MATURITY_L3
    ));
}

#[test]
fn maturity_level_increments() {
    let m0: AnchorIndex = 10_000;
    assert_eq!(maturity_level(m0, m0), 0);
    assert_eq!(maturity_level(m0 + consts::MATURITY_L1 - 1, m0), 0);
    assert_eq!(maturity_level(m0 + consts::MATURITY_L1, m0), 1);
    assert_eq!(maturity_level(m0 + consts::MATURITY_L2, m0), 2);
    assert_eq!(maturity_level(m0 + consts::MATURITY_L3, m0), 3);
}

#[test]
fn stake_maturity_validation() {
    let m0: AnchorIndex = 100_000;
    // Unreifer Mint: Stake sollte fehlschlagen
    assert!(validate_stake_maturity(m0 + consts::MATURITY_L1 - 1, m0).is_err());
    // Genau L1 erreicht: Stake erlaubt
    assert!(validate_stake_maturity(m0 + consts::MATURITY_L1, m0).is_ok());
    // Weit über L1: Stake erlaubt
    assert!(validate_stake_maturity(m0 + consts::MATURITY_L2, m0).is_ok());
}

#[test]
fn unbond_maturity_validation() {
    let bonded_at: AnchorIndex = 200_000;
    // Zu früh für Unbond (unter L2)
    assert!(validate_unbond_maturity(bonded_at + consts::MATURITY_L1, bonded_at).is_err());
    assert!(validate_unbond_maturity(bonded_at + consts::MATURITY_L2 - 1, bonded_at).is_err());
    // Genau L2: Unbond erlaubt
    assert!(validate_unbond_maturity(bonded_at + consts::MATURITY_L2, bonded_at).is_ok());
    // Über L2: Unbond erlaubt
    assert!(validate_unbond_maturity(bonded_at + consts::MATURITY_L3, bonded_at).is_ok());
}

#[test]
fn bond_lock_maturity_validation() {
    let m0: AnchorIndex = 50_000;
    // Unreifer Mint: Bond-Lock verboten
    assert!(validate_bond_lock_maturity(m0 + consts::MATURITY_L1 - 1, m0).is_err());
    // L1 erreicht: Bond-Lock erlaubt
    assert!(validate_bond_lock_maturity(m0 + consts::MATURITY_L1, m0).is_ok());
    // Höhere Maturity: Bond-Lock erlaubt
    assert!(validate_bond_lock_maturity(m0 + consts::MATURITY_L2, m0).is_ok());
}

#[test]
fn invalid_params_sum_or_weights_len_fail() {
    // Summe != 10_000
    let bad_sum = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1600, // Summe 10_100
        p_att_bp: 1000,
        d_max: 2,
        perf_weights: vec![10000, 6000],
    };
    assert!(bad_sum.validate().is_err());

    // d_max != perf_weights.len()
    let bad_len = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 3,
        perf_weights: vec![10000, 6000], // Länge 2
    };
    assert!(bad_len.validate().is_err());
}

#[test]
fn slashing_equivocation_100pct() {
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let offender = recipients[1];
    let ev = pc_types::EvidenceKind::Equivocation {
        seat_id: offender,
        epoch_id: 1,
        a: AnchorHeader::default(),
        b: Box::new(AnchorHeader::default()),
    };
    let params = SlashingParams::recommended_equivocation();
    let bond = 1_000u64;
    let set =
        compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).expect("slash eq");
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, bond); // 100%
                           // Täter nicht begünstigt
    for e in &set.entries {
        assert_ne!(e.recipient_id, offender);
    }
    // Gleichverteilung auf 2 recipients
    let amounts: Vec<u64> = set.normalized_entries().iter().map(|e| e.amount).collect();
    assert_eq!(amounts.len(), 2);
    assert!(amounts[0] + amounts[1] == bond);
}

#[test]
fn slashing_vote_invalid_50pct() {
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let offender = recipients[0];
    let ev = pc_types::EvidenceKind::VoteInvalid {
        seat_id: offender,
        anchor: AnchorHeader::default(),
        reason_code: 42,
    };
    let params = SlashingParams::recommended_vote_invalid(consts::SLASH_VOTE_INVALID_MIN_BP)
        .expect("vi params");
    let bond = 2_000u64;
    let set =
        compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).expect("slash vi");
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, bond / 2); // 50%
    for e in &set.entries {
        assert_ne!(e.recipient_id, offender);
    }
}

#[test]
fn slashing_conflicting_da_25pct() {
    let recipients = [
        blake3_32(b"a"),
        blake3_32(b"b"),
        blake3_32(b"c"),
        blake3_32(b"d"),
    ];
    let offender = recipients[2];
    let ev = pc_types::EvidenceKind::ConflictingDAAttest {
        seat_id: offender,
        anchor_id: AnchorId([0u8; 32]),
        attest_a: vec![1, 2],
        attest_b: vec![3, 4],
    };
    let params =
        SlashingParams::recommended_conflicting_da(consts::SLASH_DA_25_BP).expect("da params");
    let bond = 1_000u64;
    let set =
        compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).expect("slash da");
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, 250);
    for e in &set.entries {
        assert_ne!(e.recipient_id, offender);
    }
}

#[test]
fn slashing_params_validation() {
    // Equivocation muss 100% sein
    let bad_eq = SlashingParams {
        equivocation_bp: 9_000,
        vote_invalid_bp: 5_000,
        conflicting_da_bp: 2_500,
    };
    assert!(bad_eq.validate().is_err());

    // Vote-invalid unter 50%
    let bad_vi_low = SlashingParams {
        equivocation_bp: 10_000,
        vote_invalid_bp: 4_999,
        conflicting_da_bp: 2_500,
    };
    assert!(bad_vi_low.validate().is_err());

    // Vote-invalid über 100%
    let bad_vi_high = SlashingParams {
        equivocation_bp: 10_000,
        vote_invalid_bp: 10_001,
        conflicting_da_bp: 2_500,
    };
    assert!(bad_vi_high.validate().is_err());

    // Conflicting-DA ungültiger Wert (nicht 25/50/100%)
    let bad_da = SlashingParams {
        equivocation_bp: 10_000,
        vote_invalid_bp: 5_000,
        conflicting_da_bp: 3_000,
    };
    assert!(bad_da.validate().is_err());

    // Gültige Params
    assert!(SlashingParams::recommended_strict().validate().is_ok());
    assert!(SlashingParams::recommended_moderate().validate().is_ok());
}

#[test]
fn slashing_vote_invalid_100pct() {
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let offender = recipients[1];
    let ev = pc_types::EvidenceKind::VoteInvalid {
        seat_id: offender,
        anchor: AnchorHeader::default(),
        reason_code: 99,
    };
    let params = SlashingParams::recommended_vote_invalid(consts::SLASH_VOTE_INVALID_MAX_BP)
        .expect("vi 100% params");
    let bond = 1_000u64;
    let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev)
        .expect("slash vi 100%");
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, bond); // 100%
    for e in &set.entries {
        assert_ne!(e.recipient_id, offender);
    }
}

#[test]
fn slashing_conflicting_da_50_and_100pct() {
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let offender = recipients[0];
    let ev = pc_types::EvidenceKind::ConflictingDAAttest {
        seat_id: offender,
        anchor_id: AnchorId([1u8; 32]),
        attest_a: vec![0xAA],
        attest_b: vec![0xBB],
    };

    // 50%
    let params_50 =
        SlashingParams::recommended_conflicting_da(consts::SLASH_DA_50_BP).expect("da 50%");
    let bond = 2_000u64;
    let set_50 = compute_slashing_payout_for_evidence(bond, &params_50, &recipients, &ev)
        .expect("slash da 50%");
    let sum_50: u64 = set_50.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum_50, 1_000); // 50%

    // 100%
    let params_100 =
        SlashingParams::recommended_conflicting_da(consts::SLASH_DA_100_BP).expect("da 100%");
    let set_100 = compute_slashing_payout_for_evidence(bond, &params_100, &recipients, &ev)
        .expect("slash da 100%");
    let sum_100: u64 = set_100.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum_100, 2_000); // 100%
}

#[test]
fn slashing_payout_deterministic() {
    // Gleiche Inputs müssen gleiche Outputs ergeben
    let recipients = [blake3_32(b"x"), blake3_32(b"y"), blake3_32(b"z")];
    let offender = recipients[1];
    let ev = pc_types::EvidenceKind::Equivocation {
        seat_id: offender,
        epoch_id: 42,
        a: AnchorHeader::default(),
        b: Box::new(AnchorHeader::default()),
    };
    let params = SlashingParams::recommended_equivocation();
    let bond = 999u64;

    let set1 =
        compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).expect("slash 1");
    let set2 =
        compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).expect("slash 2");

    assert_eq!(set1.entries, set2.entries);

    // Sortierung garantiert
    let ids: Vec<[u8; 32]> = set1.entries.iter().map(|e| e.recipient_id).collect();
    let mut sorted_ids = ids.clone();
    sorted_ids.sort_unstable();
    assert_eq!(ids, sorted_ids);
}

#[test]
fn slashing_excludes_slasher_always() {
    let recipients = [
        blake3_32(b"alice"),
        blake3_32(b"bob"),
        blake3_32(b"carol"),
        blake3_32(b"dave"),
    ];
    let offender = recipients[2]; // carol

    let ev_eq = pc_types::EvidenceKind::Equivocation {
        seat_id: offender,
        epoch_id: 1,
        a: AnchorHeader::default(),
        b: Box::new(AnchorHeader::default()),
    };
    let ev_vi = pc_types::EvidenceKind::VoteInvalid {
        seat_id: offender,
        anchor: AnchorHeader::default(),
        reason_code: 1,
    };
    let ev_da = pc_types::EvidenceKind::ConflictingDAAttest {
        seat_id: offender,
        anchor_id: AnchorId([0u8; 32]),
        attest_a: vec![],
        attest_b: vec![],
    };

    let params = SlashingParams::recommended_strict();
    let bond = 1_000u64;

    for ev in [ev_eq, ev_vi, ev_da] {
        let set =
            compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).expect("slash");
        for e in &set.entries {
            assert_ne!(e.recipient_id, offender, "Slasher must be excluded");
        }
        // Alle anderen vorhanden
        assert_eq!(set.entries.len(), recipients.len() - 1);
    }
}

#[test]
fn slashing_rejects_non_slashing_mint_evidences() {
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let params = SlashingParams::recommended_strict();
    let bond = 1_000u64;

    let censor_ev = pc_types::EvidenceKind::MintCensorshipV1 {
        prev_mint_id: [0x11; 32],
        window_id: 0,
        expected_winner_candidate_id: [0x22; 32],
        offending_anchor_id: AnchorId([0x33; 32]),
    };
    assert!(compute_slashing_payout_for_evidence(bond, &params, &recipients, &censor_ev).is_err());

    let candidate_ev = pc_types::EvidenceKind::MintCandidateV1 {
        candidate: pc_types::MintCandidateEvent {
            version: 1,
            network_id: [0x44; 32],
            prev_mint_id: [0x55; 32],
            window_id: 1,
            window_open_anchor_id: [0x66; 32],
            mint_commitment: [0x77; 32],
            nonce: 9,
            work_id: None,
            miner_pubkey: None,
            recipient_lock: None,
        },
    };
    assert!(
        compute_slashing_payout_for_evidence(bond, &params, &recipients, &candidate_ev).is_err()
    );
}

#[test]
fn committee_payout_mismatch_lengths_and_proposer_index_fail() {
    let params = FeeSplitParams::recommended();
    let recipients = [blake3_32(b"a"), blake3_32(b"b")];
    // Längen-Mismatch: 2 vs 3
    let dists = [Some(1u8), Some(2u8), None];
    let fees = 1000u64;
    assert!(compute_committee_payout(fees, &params, &recipients, 0, &dists).is_err());

    // Proposer-Index außerhalb
    let dists_ok = [Some(1u8), None];
    assert!(compute_committee_payout(fees, &params, &recipients, 2, &dists_ok).is_err());
}

#[test]
fn committee_payout_from_headers_k_mismatch_recipients_len_fail() {
    // A <- B <- C (C ack), k=3 aber recipients nur 2
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let headers = vec![a, b, c];
    let recipients = [blake3_32(b"a"), blake3_32(b"b")];
    let fees = 10_000u64;
    let params = FeeSplitParams::recommended();
    let res = compute_committee_payout_from_headers(
        fees,
        &params,
        &recipients,
        0,
        pc_types::AnchorId(id_c),
        &headers,
        3,
    );
    assert!(res.is_err());
}

#[test]
fn engine_committee_payout_root_for_ack_recipients_len_mismatch_fails() {
    // gleicher Graph wie oben
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();

    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();

    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
    eng.insert_header(a);
    eng.insert_header(b);
    eng.insert_header(c);

    let recipients = [blake3_32(b"a"), blake3_32(b"b")]; // len 2, k=3
    let fees = 10_000u64;
    let res = eng.committee_payout_root_for_ack(fees, &recipients, 0, pc_types::AnchorId(id_c));
    assert!(res.is_err());
}

#[test]
fn total_payout_root_matches_manual_merge() {
    let params = FeeSplitParams::recommended();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let att = [blake3_32(b"x"), blake3_32(b"y")];
    let fees = 123_456u64;
    let dists = [Some(1u8), None, Some(2u8)];
    let proposer_index = 1usize;

    let committee =
        compute_committee_payout(fees, &params, &recipients, proposer_index, &dists).unwrap();
    let attestors = compute_attestor_payout(fees, &params, &att).unwrap();
    let mut entries = committee.entries;
    entries.extend_from_slice(&attestors.entries);
    let expected_root = pc_types::PayoutSet { entries }.payout_root();

    let got = compute_total_payout_root(fees, &params, &recipients, proposer_index, &dists, &att)
        .unwrap();
    assert_eq!(expected_root, got);
}

#[test]
fn total_payout_root_len_mismatch_fails() {
    let params = FeeSplitParams::recommended();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let att = [blake3_32(b"x")];
    let fees = 1000u64;
    // ack_distances len != recipients len
    let dists = [Some(1u8), None];
    let res = compute_total_payout_root(fees, &params, &recipients, 0, &dists, &att);
    assert!(res.is_err());
}

#[test]
fn engine_committee_payout_root_for_ack_invalid_proposer_index_fails() {
    // baue einfachen Graph A<-B<-C
    let parents_a = pc_types::ParentList::default();
    let a = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_a,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_a = a.id_digest();
    let mut parents_b = pc_types::ParentList::default();
    parents_b.push(pc_types::AnchorId(id_a)).unwrap();
    let b = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_b,
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_b = b.id_digest();
    let mut parents_c = pc_types::ParentList::default();
    parents_c.push(pc_types::AnchorId(id_b)).unwrap();
    let c = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: parents_c,
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_c = c.id_digest();

    let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
    eng.insert_header(a);
    eng.insert_header(b);
    eng.insert_header(c);

    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let fees = 10_000u64;
    // proposer_index=3 ist out-of-range
    let res = eng.committee_payout_root_for_ack(fees, &recipients, 3, pc_types::AnchorId(id_c));
    assert!(res.is_err());
}

#[test]
fn ack_distances_empty_returns_none_vec() {
    let ack = pc_types::AnchorId([0u8; 32]);
    let headers: Vec<pc_types::AnchorHeader> = Vec::new();
    let k = 5u8;
    let d_max = 4u8;
    let v = compute_ack_distances_for_seats(ack, &headers, k, d_max);
    assert_eq!(v.len(), k as usize);
    assert!(v.iter().all(|x| x.is_none()));
}

#[test]
fn ack_distances_ack_not_in_headers_yields_none() {
    // ack_id nicht in headers -> keine Distanzen
    let ack = pc_types::AnchorId([9u8; 32]);
    let parents = pc_types::ParentList::default();
    let h = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let headers = vec![h];
    let v = compute_ack_distances_for_seats(ack, &headers, 3, 4);
    assert_eq!(v, vec![None, None, None]);
}

#[test]
fn ack_distances_multi_parents_and_dmax() {
    // Konstruiere ack mit zwei Parents (Seat1, Seat2); je ein Grandparent (Seat0, Seat3)
    // d_max=1: nur Parents (Distanz=1) werden gezählt, Grandparents nicht.
    // d_max=2: Parents (1) und Grandparents (2) werden gezählt.
    let p0 = pc_types::ParentList::default();
    let h0 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: p0.clone(),
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id0 = h0.id_digest();

    let h1 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: p0.clone(),
        payload_hash: [1u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id1 = h1.id_digest();

    let mut p2 = pc_types::ParentList::default();
    p2.push(pc_types::AnchorId(id0)).unwrap();
    let h2 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: p2.clone(),
        payload_hash: [2u8; 32],
        creator_index: 2,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id2 = h2.id_digest();

    let mut p3 = pc_types::ParentList::default();
    p3.push(pc_types::AnchorId(id1)).unwrap();
    let h3 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: p3.clone(),
        payload_hash: [3u8; 32],
        creator_index: 3,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id3 = h3.id_digest();

    let mut pa = pc_types::ParentList::default();
    pa.push(pc_types::AnchorId(id2)).unwrap();
    pa.push(pc_types::AnchorId(id3)).unwrap();
    let ack_h = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pa,
        payload_hash: [4u8; 32],
        creator_index: 4,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let ack_id = pc_types::AnchorId(ack_h.id_digest());

    let headers = vec![h0, h1, h2, h3, ack_h.clone()];
    let k = 5u8; // seats 0..4

    // d_max=1 → nur Seats der direkten Parents (2,3) mit Distanz 1
    let v1 = compute_ack_distances_for_seats(ack_id, &headers, k, 1);
    assert_eq!(v1.len(), k as usize);
    assert_eq!(v1[2], Some(1));
    assert_eq!(v1[3], Some(1));
    assert!(v1[0].is_none() && v1[1].is_none() && v1[4].is_none());

    // d_max=2 → zusätzlich Grandparents (0 via h2, 1 via h3) mit Distanz 2
    let v2 = compute_ack_distances_for_seats(ack_id, &headers, k, 2);
    assert_eq!(v2[0], Some(2));
    assert_eq!(v2[1], Some(2));
    assert_eq!(v2[2], Some(1));
    assert_eq!(v2[3], Some(1));
    assert!(v2[4].is_none());
}

#[test]
fn ack_distances_unknown_parent_ignored() {
    // ack referenziert einen Parent, der nicht in headers existiert → wird ignoriert
    let parents = pc_types::ParentList::default();
    let h0 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id0 = h0.id_digest();
    let fake = pc_types::AnchorId([0xFF; 32]);
    let mut pa = pc_types::ParentList::default();
    pa.push(pc_types::AnchorId(id0)).unwrap();
    pa.push(fake).unwrap();
    let ack_h = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pa,
        payload_hash: [1u8; 32],
        creator_index: 4,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let ack_id = pc_types::AnchorId(ack_h.id_digest());
    let headers = vec![h0, ack_h];
    let v = compute_ack_distances_for_seats(ack_id, &headers, 5, 2);
    // seat 0 erreicht mit Distanz 1; der unbekannte Parent bewirkt keine weiteren Einträge
    assert_eq!(v[0], Some(1));
}

#[test]
fn committee_payout_zero_fees_yields_empty() {
    let params = FeeSplitParams {
        p_base_bp: 6500,
        p_prop_bp: 1000,
        p_perf_bp: 1500,
        p_att_bp: 1000,
        d_max: 1,
        perf_weights: vec![10_000],
    };
    params.validate().unwrap();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let dists = [Some(1u8), None, Some(2u8)];
    let set = compute_committee_payout(0, &params, &recipients, 1, &dists).unwrap();
    assert!(set.entries.is_empty());
}

#[test]
fn committee_payout_base_only_k64_remainder_distribution() {
    // Nur base_pot=10000bp → 100% Basis, k=64, remainder deterministisch nach recipient_id
    let params = FeeSplitParams {
        p_base_bp: 10_000,
        p_prop_bp: 0,
        p_perf_bp: 0,
        p_att_bp: 0,
        d_max: 1,
        perf_weights: vec![10_000],
    };
    params.validate().unwrap();
    let mut recipients: Vec<[u8; 32]> = Vec::with_capacity(64);
    for i in 0u8..64u8 {
        recipients.push([i; 32]);
    }
    let fees = 1000u64;
    let dists: [Option<u8>; 64] = [None; 64];
    let set = compute_committee_payout(fees, &params, &recipients, 0, &dists).unwrap();
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, fees);
    // erwartete Gleichverteilung: 1000 / 64 = 15 Rest 40 → 40 Empfänger mit 16, 24 mit 15
    let mut c15 = 0;
    let mut c16 = 0;
    for e in &set.entries {
        if e.amount == 15 {
            c15 += 1;
        } else if e.amount == 16 {
            c16 += 1;
        }
    }
    assert_eq!(c15, 24);
    assert_eq!(c16, 40);
}

#[test]
fn slashing_payout_offender_only_recipient_fails() {
    let params = SlashingParams::recommended_equivocation();
    let offender = [0xAA; 32];
    let recipients = [offender];
    let ev = EvidenceKind::Equivocation {
        seat_id: offender,
        epoch_id: 1,
        a: pc_types::AnchorHeader::default(),
        b: Box::new(pc_types::AnchorHeader::default()),
    };
    let res = compute_slashing_payout_for_evidence(1000, &params, &recipients, &ev);
    assert!(res.is_err());
}

#[test]
fn slashing_payout_vote_invalid_min_max() {
    // min 50% (5000 bp)
    let params_min =
        SlashingParams::recommended_vote_invalid(consts::SLASH_VOTE_INVALID_MIN_BP).unwrap();
    let offender = [0xBB; 32];
    let recipients = [[0x10; 32], offender];
    let ev = EvidenceKind::VoteInvalid {
        seat_id: offender,
        anchor: pc_types::AnchorHeader::default(),
        reason_code: 1,
    };
    let pot_min = split_bp(1000, consts::SLASH_VOTE_INVALID_MIN_BP);
    let set_min =
        compute_slashing_payout_for_evidence(1000, &params_min, &recipients, &ev).unwrap();
    let sum_min: u64 = set_min.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum_min, pot_min);
    assert_eq!(set_min.entries.len(), 1); // nur der nicht-Täter

    // max 100% (10000 bp)
    let params_max =
        SlashingParams::recommended_vote_invalid(consts::SLASH_VOTE_INVALID_MAX_BP).unwrap();
    let pot_max = split_bp(1000, consts::SLASH_VOTE_INVALID_MAX_BP);
    let set_max =
        compute_slashing_payout_for_evidence(1000, &params_max, &recipients, &ev).unwrap();
    let sum_max: u64 = set_max.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum_max, pot_max);
}

#[test]
fn slashing_payout_large_bond_no_overflow() {
    let params = SlashingParams::recommended_equivocation();
    let offender = [0xCC; 32];
    let recipients = [[0x01; 32], [0x02; 32], offender, [0x03; 32]];
    let ev = EvidenceKind::Equivocation {
        seat_id: offender,
        epoch_id: 1,
        a: pc_types::AnchorHeader::default(),
        b: Box::new(pc_types::AnchorHeader::default()),
    };
    let bond: u64 = u64::MAX / 3;
    let pot = split_bp(bond, consts::SLASH_EQUIVOCATION_BP);
    let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).unwrap();
    let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, pot);
}

#[test]
#[ignore]
fn dump_total_payout_root_spec_example() {
    // Beispiel für SPEC_FEES.md
    let params = FeeSplitParams::recommended();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let att = [blake3_32(b"x"), blake3_32(b"y")];
    let fees = 42_000u64;
    let dists = [Some(1u8), Some(2u8), None];
    let root = compute_total_payout_root(fees, &params, &recipients, 1, &dists, &att).unwrap();
    println!("TOTAL_PAYOUT_ROOT_SPEC={}", hex::encode(root));
}

#[test]
#[ignore]
fn dump_total_payout_root_spec_example_case2() {
    // Zweites Beispiel für weiteren Golden-Test
    let params = FeeSplitParams::recommended();
    let recipients = [
        blake3_32(b"r1"),
        blake3_32(b"r2"),
        blake3_32(b"r3"),
        blake3_32(b"r4"),
    ];
    let att = [blake3_32(b"a1"), blake3_32(b"a2"), blake3_32(b"a3")];
    let fees = 123_456_789u64;
    let dists = [Some(2u8), None, Some(1u8), Some(8u8)];
    let root = compute_total_payout_root(fees, &params, &recipients, 2, &dists, &att).unwrap();
    println!("TOTAL_PAYOUT_ROOT_SPEC2={}", hex::encode(root));
}

#[test]
fn total_payout_root_golden() {
    // Golden-Test basierend auf SPEC_FEES-Beispiel (dump_total_payout_root_spec_example)
    let params = FeeSplitParams::recommended();
    let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
    let att = [blake3_32(b"x"), blake3_32(b"y")];
    let fees = 42_000u64;
    let dists = [Some(1u8), Some(2u8), None];
    let root = compute_total_payout_root(fees, &params, &recipients, 1, &dists, &att).unwrap();
    let hex_root = hex::encode(root);
    assert_eq!(
        hex_root,
        "668f75fc7225e3270bc17cdf864e11c4448a2066142621f926a3903cae7deb14"
    );
}

#[test]
fn total_payout_root_golden_case2() {
    // Golden-Test basierend auf dump_total_payout_root_spec_example_case2
    let params = FeeSplitParams::recommended();
    let recipients = [
        blake3_32(b"r1"),
        blake3_32(b"r2"),
        blake3_32(b"r3"),
        blake3_32(b"r4"),
    ];
    let att = [blake3_32(b"a1"), blake3_32(b"a2"), blake3_32(b"a3")];
    let fees = 123_456_789u64;
    let dists = [Some(2u8), None, Some(1u8), Some(8u8)];
    let root = compute_total_payout_root(fees, &params, &recipients, 2, &dists, &att).unwrap();
    let hex_root = hex::encode(root);
    // Wert wird nach Dump ermittelt und hier fixiert
    assert_eq!(
        hex_root,
        "873f050b731e01fb6e5acf78978dd6ac838f45ac48de53b29a171a213944545a"
    );
}

// ========================================================================
// PoW & Emission Tests
// ========================================================================

#[test]
fn compute_mint_reward_halving_schedule() {
    // Genesis (height 0) → 0
    assert_eq!(consts::compute_mint_reward(0), 0);
    // Erste Mint (height 1) → INITIAL_MINT_REWARD
    assert_eq!(consts::compute_mint_reward(1), consts::INITIAL_MINT_REWARD);
    // Vor erstem Halving
    assert_eq!(
        consts::compute_mint_reward(consts::HALVING_INTERVAL - 1),
        consts::INITIAL_MINT_REWARD
    );
    // Erstes Halving (height = HALVING_INTERVAL)
    assert_eq!(
        consts::compute_mint_reward(consts::HALVING_INTERVAL),
        consts::INITIAL_MINT_REWARD / 2
    );
    // Zweites Halving
    assert_eq!(
        consts::compute_mint_reward(2 * consts::HALVING_INTERVAL),
        consts::INITIAL_MINT_REWARD / 4
    );
    // Nach MAX_HALVINGS → 0
    assert_eq!(
        consts::compute_mint_reward((consts::MAX_HALVINGS as u64) * consts::HALVING_INTERVAL),
        0
    );
}

#[test]
fn compute_mint_reward_hardcap_compliance() {
    // Summiere alle Rewards über alle möglichen Halvings
    let mut total: u128 = 0;
    for height in 1..=((consts::MAX_HALVINGS as u64) * consts::HALVING_INTERVAL) {
        total += consts::compute_mint_reward(height) as u128;
    }
    // Total sollte <= HARD_CAP_UNITS sein
    assert!(
        total <= consts::HARD_CAP_UNITS,
        "total emission {} exceeds hardcap {}",
        total,
        consts::HARD_CAP_UNITS
    );
    // Für Info: Wie nah kommen wir dem Hardcap?
    let ratio = (total as f64) / (consts::HARD_CAP_UNITS as f64);
    println!(
        "Total emission via halving: {} ({}% of hardcap)",
        total,
        ratio * 100.0
    );
}

#[test]
fn supply_state_genesis() {
    let state = SupplyState::new();
    assert_eq!(state.total_supply, 0);
    assert_eq!(state.mint_height, 0);
    assert_eq!(state.last_mint_id, [0u8; 32]);
    assert!(state.can_mint());
    assert_eq!(state.next_reward(), consts::INITIAL_MINT_REWARD);
}

#[test]
fn supply_state_process_first_mint() {
    let mut state = SupplyState::new();
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32], // Genesis
        outputs: vec![TxOut {
            amount: consts::INITIAL_MINT_REWARD,
            lock: LockCommitment([1u8; 32]),
        }],
        pow_seed: [2u8; 32],
        pow_nonce: 12345,
        minted_at: 1,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    assert!(state.process_mint(&mint, 1).is_ok());
    assert_eq!(state.mint_height, 1);
    assert_eq!(state.total_supply, consts::INITIAL_MINT_REWARD as u128);
    assert_eq!(state.last_mint_id, pc_types::digest_mint(&mint));
}

#[test]
fn supply_state_rejects_wrong_prev_mint_id() {
    let mut state = SupplyState::new();
    // Mint mit falschem prev_mint_id
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0xFFu8; 32], // Falsch!
        outputs: vec![TxOut {
            amount: consts::INITIAL_MINT_REWARD,
            lock: LockCommitment([1u8; 32]),
        }],
        pow_seed: [2u8; 32],
        pow_nonce: 12345,
        minted_at: 1,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    assert!(state.process_mint(&mint, 1).is_err());
    // State sollte unverändert sein
    assert_eq!(state.mint_height, 0);
    assert_eq!(state.total_supply, 0);
}

#[test]
fn supply_state_rejects_overemission() {
    let mut state = SupplyState::new();
    // Mint versucht mehr als erlaubt auszugeben
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32],
        outputs: vec![TxOut {
            amount: consts::INITIAL_MINT_REWARD + 1, // Zu viel!
            lock: LockCommitment([1u8; 32]),
        }],
        pow_seed: [2u8; 32],
        pow_nonce: 12345,
        minted_at: 1,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    assert!(state.process_mint(&mint, 1).is_err());
}

#[test]
fn supply_state_hardcap_enforcement() {
    let mut state = SupplyState::new();
    // Setze Supply nahe Hardcap
    state.total_supply = consts::HARD_CAP_UNITS - 100;
    state.mint_height = 1_000_000;
    state.last_mint_id = [0xABu8; 32];

    // Versuche Mint der mehr als verbleibende Supply hinzufügt
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0xABu8; 32],
        outputs: vec![TxOut {
            amount: 101, // Würde Hardcap überschreiten
            lock: LockCommitment([1u8; 32]),
        }],
        pow_seed: [2u8; 32],
        pow_nonce: 12345,
        minted_at: 1_000_001,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    assert!(state.process_mint(&mint, 1_000_001).is_err());

    // Aber 100 sollte funktionieren
    let mint_ok = MintEvent {
        version: 1,
        prev_mint_id: [0xABu8; 32],
        outputs: vec![TxOut {
            amount: 100,
            lock: LockCommitment([1u8; 32]),
        }],
        pow_seed: [3u8; 32],
        pow_nonce: 54321,
        minted_at: 1_000_001,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    assert!(state.process_mint(&mint_ok, 1_000_002).is_ok());
    assert_eq!(state.total_supply, consts::HARD_CAP_UNITS);
    assert!(!state.can_mint()); // Hardcap erreicht
}

#[test]
fn supply_state_prev_mint_id_chain() {
    let mut state = SupplyState::new();

    // Erste Mint
    let mint1 = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32],
        outputs: vec![TxOut {
            amount: 1000,
            lock: LockCommitment([1u8; 32]),
        }],
        pow_seed: [2u8; 32],
        pow_nonce: 100,
        minted_at: 1,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    state.process_mint(&mint1, 1).unwrap();
    let id1 = state.last_mint_id;

    // Zweite Mint muss id1 referenzieren
    let mint2 = MintEvent {
        version: 1,
        prev_mint_id: id1,
        outputs: vec![TxOut {
            amount: 2000,
            lock: LockCommitment([2u8; 32]),
        }],
        pow_seed: [3u8; 32],
        pow_nonce: 200,
        minted_at: 2,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    state.process_mint(&mint2, 2).unwrap();
    let id2 = state.last_mint_id;

    // Dritte Mint muss id2 referenzieren (nicht id1!)
    let mint3_wrong = MintEvent {
        version: 1,
        prev_mint_id: id1, // Falsch! Sollte id2 sein
        outputs: vec![TxOut {
            amount: 3000,
            lock: LockCommitment([3u8; 32]),
        }],
        pow_seed: [4u8; 32],
        pow_nonce: 300,
        minted_at: 3,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    assert!(state.process_mint(&mint3_wrong, 3).is_err());

    // Mit korrektem prev_mint_id sollte es funktionieren
    let mint3_ok = MintEvent {
        version: 1,
        prev_mint_id: id2,
        outputs: vec![TxOut {
            amount: 3000,
            lock: LockCommitment([3u8; 32]),
        }],
        pow_seed: [5u8; 32],
        pow_nonce: 400,
        minted_at: 3,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    assert!(state.process_mint(&mint3_ok, 3).is_ok());
    assert_eq!(state.mint_height, 3);
}

#[test]
fn bootstrap_state_genesis_defaults() {
    let bs = BootstrapState::new_genesis();
    assert!(bs.active);
    assert_eq!(bs.genesis_height, 0);
    assert!(!bs.rotation_activated);
    assert_eq!(bs.epochs_since_genesis, 0);
}

#[test]
fn bootstrap_state_effective_k_returns_1_during_bootstrap() {
    let bs = BootstrapState::new_genesis();
    assert_eq!(bs.effective_committee_k(21), 1); // Bootstrap-Exception
}

#[test]
fn bootstrap_state_effective_k_returns_configured_after_rotation() {
    let mut bs = BootstrapState::new_genesis();
    bs.activate_rotation();
    assert_eq!(bs.effective_committee_k(21), 21); // Normal k
}

#[test]
fn bootstrap_state_is_bootstrap_vote() {
    let mut bs = BootstrapState::new_genesis();
    assert!(bs.is_bootstrap_vote());

    bs.activate_rotation();
    assert!(!bs.is_bootstrap_vote());
}

#[test]
fn bootstrap_state_advance_epoch_deactivates_after_rotation() {
    let mut bs = BootstrapState::new_genesis();
    assert!(bs.active);

    bs.activate_rotation();
    bs.advance_epoch();

    assert!(!bs.active); // Bootstrap automatisch beendet
    assert_eq!(bs.epochs_since_genesis, 1);
}

#[test]
fn bootstrap_state_validates_bounds_rejects_height_mismatch() {
    let bs = BootstrapState::new_genesis();
    assert!(bs.validate_bootstrap_bounds(0).is_ok());
    assert!(bs.validate_bootstrap_bounds(1).is_err()); // height > 0 verboten
}

#[test]
fn bootstrap_state_validates_bounds_rejects_excessive_epochs() {
    let mut bs = BootstrapState::new_genesis();

    // Simuliere zu viele Epochen ohne Rotation
    for _ in 0..12 {
        bs.advance_epoch();
    }

    assert!(bs.validate_bootstrap_bounds(0).is_err()); // > MAX_BOOTSTRAP_EPOCHS
}

#[test]
fn supply_state_remaining_supply() {
    let mut state = SupplyState::new();
    assert_eq!(state.remaining_supply(), consts::HARD_CAP_UNITS);

    state.total_supply = 1_000_000;
    assert_eq!(state.remaining_supply(), consts::HARD_CAP_UNITS - 1_000_000);
}

#[test]
fn cross_link_single_parent_always_valid() {
    let g = AnchorGraph::new();
    let h = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pc_types::ParentList::default(), // len=0
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    assert!(validate_cross_link(&h, &g), "0 parents → always valid");

    let mut p1 = pc_types::ParentList::default();
    p1.push(pc_types::AnchorId([1u8; 32])).unwrap();
    let h1 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: p1,
        payload_hash: [0u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    assert!(
        validate_cross_link(&h1, &g),
        "1 parent → always valid (k=1 bootstrap)"
    );
}

#[test]
fn cross_link_valid_with_other_shard_parent() {
    let mut g = AnchorGraph::new();
    let parent_same = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: [1u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let parent_other = pc_types::AnchorHeader {
        version: 1,
        shard_id: 1,
        parents: pc_types::ParentList::default(),
        payload_hash: [2u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id_same = g.insert(parent_same);
    let id_other = g.insert(parent_other);

    let mut parents = pc_types::ParentList::default();
    parents.push(id_same).unwrap();
    parents.push(id_other).unwrap();
    let h = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents,
        payload_hash: [3u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    assert!(
        validate_cross_link(&h, &g),
        "one parent from shard 1 → cross-link valid"
    );
}

#[test]
fn cross_link_invalid_all_same_shard() {
    let mut g = AnchorGraph::new();
    let p1 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: [1u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let p2 = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: [2u8; 32],
        creator_index: 1,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    let id1 = g.insert(p1);
    let id2 = g.insert(p2);

    let mut parents = pc_types::ParentList::default();
    parents.push(id1).unwrap();
    parents.push(id2).unwrap();
    let h = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents,
        payload_hash: [3u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    assert!(
        !validate_cross_link(&h, &g),
        "all parents same shard → cross-link invalid"
    );
}

#[test]
fn cross_link_parent_not_in_graph_not_counted() {
    let g = AnchorGraph::new();
    let mut parents = pc_types::ParentList::default();
    parents.push(pc_types::AnchorId([0xAAu8; 32])).unwrap();
    parents.push(pc_types::AnchorId([0xBBu8; 32])).unwrap();
    let h = pc_types::AnchorHeader {
        version: 1,
        shard_id: 0,
        parents,
        payload_hash: [3u8; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
    };
    assert!(
        !validate_cross_link(&h, &g),
        "parents not in graph → cannot confirm cross-link"
    );
}
