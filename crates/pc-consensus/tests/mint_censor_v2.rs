use pc_consensus::mint_censor_v2::{
    compute_candidate_root_v2, next_candidate_target_v2, CandidateRecordV2, MintCensorParamsV2,
    WindowStateV2,
};
use pc_crypto::blake3_32;
use pc_types::{
    candidate_pow_hash_v2, candidate_slot_id_v2, candidate_submission_id_v2, cmp_hash_be_u256,
    mint_id_v1, pow_cert_id_v2, pow_cert_slot_id_v2, pow_cert_submission_id_v2, AnchorId,
    AnchorPayloadV3, LockCommitment, MintCandidateEventV2, MintEvent, MintPoWCertV2, TxOut,
};

fn sample_params() -> MintCensorParamsV2 {
    MintCensorParamsV2 {
        network_id: [0x11; 32],
        windows_start_anchor: 100,
        w: 10,
        k: 3,
        n: 4,
        e: 8,
        min_target: {
            let mut v = [0u8; 32];
            v[31] = 1;
            v
        },
        max_target: [0xFF; 32],
        initial_target: [0xFF; 32],
    }
}

fn sample_candidate(
    network_id: [u8; 32],
    prev_mint_id: [u8; 32],
    window_id: u64,
    open_id: [u8; 32],
) -> MintCandidateEventV2 {
    MintCandidateEventV2 {
        version: 2,
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
    network_id: [u8; 32],
    prev_mint_id: [u8; 32],
    window_id: u64,
    open_id: [u8; 32],
) -> MintPoWCertV2 {
    MintPoWCertV2 {
        version: 2,
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
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
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

fn empty_payload() -> AnchorPayloadV3 {
    AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
        null_mint: false,
    }
}

fn sample_window() -> (
    MintCensorParamsV2,
    pc_consensus::mint_censor_v2::WindowBoundsV2,
    WindowStateV2,
) {
    let params = sample_params();
    params.validate().unwrap();
    let bounds = params.window_bounds_for_anchor(100).unwrap();
    let window = WindowStateV2::new([0xAA; 32], [0xBB; 32], bounds, params.initial_target);
    (params, bounds, window)
}

#[test]
fn same_slot_other_legacy_work_id_is_impossible_in_v2_types() {
    let candidate = sample_candidate([0x11; 32], [0xAA; 32], 0, [0xBB; 32]);
    let MintCandidateEventV2 {
        version,
        network_id,
        prev_mint_id,
        window_id,
        window_open_anchor_id,
        mint_commitment,
        nonce,
        miner_pubkey,
        recipient_lock,
    } = candidate;
    assert_eq!(version, 2);
    assert_eq!(network_id, [0x11; 32]);
    assert_eq!(prev_mint_id, [0xAA; 32]);
    assert_eq!(window_id, 0);
    assert_eq!(window_open_anchor_id, [0xBB; 32]);
    assert_eq!(mint_commitment, [0x22; 32]);
    assert_eq!(nonce, 1);
    assert!(miner_pubkey.is_none());
    assert!(recipient_lock.is_none());

    let cert = sample_pow_cert([0x11; 32], [0xAA; 32], 0, [0xBB; 32]);
    let MintPoWCertV2 {
        version: cert_version,
        network_id: cert_network_id,
        prev_mint_id: cert_prev_mint_id,
        window_id: cert_window_id,
        window_open_anchor_id: cert_window_open_anchor_id,
        mint_commitment: cert_mint_commitment,
        nonce: cert_nonce,
    } = cert;
    assert_eq!(cert_version, 2);
    assert_eq!(cert_network_id, [0x11; 32]);
    assert_eq!(cert_prev_mint_id, [0xAA; 32]);
    assert_eq!(cert_window_id, 0);
    assert_eq!(cert_window_open_anchor_id, [0xBB; 32]);
    assert_eq!(cert_mint_commitment, [0x22; 32]);
    assert_eq!(cert_nonce, 1);
}

#[test]
fn same_work_different_optional_fields_keep_submission_id_v2() {
    let mut a = sample_candidate([0x11; 32], [0xAA; 32], 0, [0xBB; 32]);
    a.miner_pubkey = Some([0x66; 32]);
    a.recipient_lock = Some(LockCommitment([0x77; 32]));

    let mut b = a.clone();
    b.miner_pubkey = Some([0x88; 32]);
    b.recipient_lock = None;

    assert_eq!(
        candidate_submission_id_v2(&a),
        candidate_submission_id_v2(&b)
    );
    assert_eq!(candidate_slot_id_v2(&a), candidate_slot_id_v2(&b));
}

#[test]
fn same_slot_two_nonces_better_hash_wins() {
    let (params, bounds, mut window) = sample_window();

    let mut a = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    a.mint_commitment = [0x33; 32];
    a.nonce = 1;
    let mut b = a.clone();
    b.nonce = 2;

    window
        .apply_finalized_candidate_v2(bounds.window_open_anchor, &a, &[0xAA; 32], &params)
        .unwrap();
    window
        .apply_finalized_candidate_v2(bounds.window_open_anchor, &b, &[0xAA; 32], &params)
        .unwrap();

    let expected =
        if cmp_hash_be_u256(&candidate_pow_hash_v2(&a), &candidate_pow_hash_v2(&b)).is_lt() {
            candidate_submission_id_v2(&a)
        } else if cmp_hash_be_u256(&candidate_pow_hash_v2(&a), &candidate_pow_hash_v2(&b)).is_gt() {
            candidate_submission_id_v2(&b)
        } else {
            candidate_submission_id_v2(&a).min(candidate_submission_id_v2(&b))
        };

    assert_eq!(window.dedupe_by_slot_id.len(), 1);
    assert_eq!(window.winner.as_ref().unwrap().submission_id, expected);
}

#[test]
fn two_different_slots_yield_obs_two() {
    let (params, bounds, mut window) = sample_window();

    let mut a = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    a.mint_commitment = [0x01; 32];
    let mut b = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    b.mint_commitment = [0x02; 32];

    window
        .apply_finalized_candidate_v2(bounds.window_open_anchor, &a, &[0xAA; 32], &params)
        .unwrap();
    window
        .apply_finalized_candidate_v2(bounds.window_open_anchor, &b, &[0xAA; 32], &params)
        .unwrap();

    window.maybe_freeze(bounds.close_anchor + 1);

    assert_eq!(window.dedupe_by_slot_id.len(), 2);
    assert_eq!(window.obs_prev_window, 2);
}

#[test]
fn obs_zero_only_makes_controlled_lighter() {
    let mut prev = [0u8; 32];
    prev[31] = 8;
    let mut min = [0u8; 32];
    min[31] = 1;

    let next = next_candidate_target_v2(prev, 0, 4, min, [0xFF; 32]);
    assert_eq!(next[31], 16);
}

#[test]
fn obs_much_greater_than_e_only_makes_controlled_harder() {
    let mut prev = [0u8; 32];
    prev[31] = 8;
    let mut min = [0u8; 32];
    min[31] = 1;

    let next = next_candidate_target_v2(prev, 10_000, 4, min, [0xFF; 32]);
    assert_eq!(next[31], 4);
}

#[test]
fn freeze_is_deterministic() {
    let (params, bounds, mut left) = sample_window();
    let (_, _, mut right) = sample_window();

    let mut a = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    a.mint_commitment = [0x01; 32];
    a.nonce = 1;
    let mut b = a.clone();
    b.nonce = 2;
    let mut c = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    c.mint_commitment = [0x02; 32];
    c.nonce = 3;

    for candidate in [&a, &b, &c] {
        left.apply_finalized_candidate_v2(
            bounds.window_open_anchor,
            candidate,
            &[0xAA; 32],
            &params,
        )
        .unwrap();
    }
    for candidate in [&c, &b, &a] {
        right
            .apply_finalized_candidate_v2(
                bounds.window_open_anchor,
                candidate,
                &[0xAA; 32],
                &params,
            )
            .unwrap();
    }

    left.maybe_freeze(bounds.close_anchor + 1);
    right.maybe_freeze(bounds.close_anchor + 1);

    assert_eq!(left.obs_prev_window, right.obs_prev_window);
    assert_eq!(left.top_n, right.top_n);
    assert_eq!(left.candidate_root, right.candidate_root);
    assert_eq!(left.winner, right.winner);
}

#[test]
fn root_is_deterministic() {
    let rec1 = CandidateRecordV2 {
        submission_id: [0x11; 32],
        slot_id: [0x10; 32],
        pow_hash: [0x33; 32],
        mint_commitment: [0x22; 32],
        finalized_at_anchor_index: 1,
        pow_cert_id: None,
    };
    let rec2 = CandidateRecordV2 {
        submission_id: [0xAA; 32],
        slot_id: [0x40; 32],
        pow_hash: [0x55; 32],
        mint_commitment: [0x44; 32],
        finalized_at_anchor_index: 1,
        pow_cert_id: None,
    };

    let got = compute_candidate_root_v2(7, &[rec1.clone(), rec2.clone()]);
    let mut expect = Vec::new();
    expect.extend_from_slice(b"PHANTOM:MINT:CANDROOT:v2");
    expect.extend_from_slice(&7u64.to_le_bytes());
    expect.extend_from_slice(&2u32.to_le_bytes());
    expect.extend_from_slice(&rec1.submission_id);
    expect.extend_from_slice(&rec2.submission_id);

    assert_eq!(got, blake3_32(&expect));
    assert_eq!(got, compute_candidate_root_v2(7, &[rec1, rec2]));
}

#[test]
fn winner_is_deterministic() {
    let (params, bounds, mut left) = sample_window();
    let (_, _, mut right) = sample_window();

    let mut a = sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    a.mint_commitment = [0x04; 32];
    a.nonce = 1;
    let mut b = a.clone();
    b.nonce = 2;

    left.apply_finalized_candidate_v2(bounds.window_open_anchor, &a, &[0xAA; 32], &params)
        .unwrap();
    left.apply_finalized_candidate_v2(bounds.window_open_anchor, &b, &[0xAA; 32], &params)
        .unwrap();

    right
        .apply_finalized_candidate_v2(bounds.window_open_anchor, &b, &[0xAA; 32], &params)
        .unwrap();
    right
        .apply_finalized_candidate_v2(bounds.window_open_anchor, &a, &[0xAA; 32], &params)
        .unwrap();

    assert_eq!(left.winner, right.winner);
}

#[test]
fn candidate_and_pow_cert_import_share_submission_id() {
    let (params, bounds, mut candidate_window) = sample_window();
    let (_, _, mut cert_window) = sample_window();

    let mut candidate =
        sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    candidate.miner_pubkey = Some([0x66; 32]);
    candidate.recipient_lock = Some(LockCommitment([0x77; 32]));

    let cert = sample_pow_cert(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);

    candidate_window
        .apply_finalized_candidate_v2(bounds.window_open_anchor, &candidate, &[0xAA; 32], &params)
        .unwrap();
    cert_window
        .apply_finalized_pow_cert_v2(bounds.window_open_anchor, &cert, &[0xAA; 32], &params)
        .unwrap();

    assert_eq!(
        candidate_submission_id_v2(&candidate),
        pow_cert_submission_id_v2(&cert)
    );
    assert_eq!(
        candidate_window.top_n[0].submission_id,
        cert_window.top_n[0].submission_id
    );
    assert_eq!(candidate_slot_id_v2(&candidate), pow_cert_slot_id_v2(&cert));
    assert_eq!(
        cert_window
            .pow_cert_to_submission_id
            .get(&pow_cert_id_v2(&cert))
            .copied(),
        Some(candidate_submission_id_v2(&candidate))
    );
}

#[test]
fn censorship_evidence_uses_expected_winner_submission_id() {
    let (params, bounds, mut window) = sample_window();
    let payload = sample_payload_with_mint(5);
    let mut candidate =
        sample_candidate(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    candidate.mint_commitment = mint_id_v1(payload.mints.first().unwrap());

    window
        .apply_finalized_candidate_v2(bounds.close_anchor, &candidate, &[0xAA; 32], &params)
        .unwrap();
    window.maybe_freeze(bounds.close_anchor + 1);

    let winner_submission_id = window.winner.as_ref().unwrap().submission_id;
    let evidence = pc_types::EvidenceKind::MintCensorshipV2 {
        prev_mint_id: [0xAA; 32],
        window_id: bounds.window_id,
        expected_winner_submission_id: winner_submission_id,
        offending_anchor_id: AnchorId([0xEF; 32]),
    };

    assert!(window
        .verify_mint_censorship_evidence_v2(
            &evidence,
            AnchorId([0xEF; 32]),
            bounds.deadline_anchor,
            &empty_payload(),
        )
        .is_ok());

    let wrong = pc_types::EvidenceKind::MintCensorshipV2 {
        prev_mint_id: [0xAA; 32],
        window_id: bounds.window_id,
        expected_winner_submission_id: [0x01; 32],
        offending_anchor_id: AnchorId([0xEF; 32]),
    };
    assert!(window
        .verify_mint_censorship_evidence_v2(
            &wrong,
            AnchorId([0xEF; 32]),
            bounds.deadline_anchor,
            &empty_payload(),
        )
        .is_err());
}

#[test]
fn missing_import_evidence_uses_pow_cert_to_submission_id() {
    let (params, bounds, mut window) = sample_window();
    let payload = sample_payload_with_mint(7);
    let mut cert = sample_pow_cert(params.network_id, [0xAA; 32], bounds.window_id, [0xBB; 32]);
    cert.mint_commitment = mint_id_v1(payload.mints.first().unwrap());

    window
        .apply_finalized_pow_cert_v2(bounds.close_anchor, &cert, &[0xAA; 32], &params)
        .unwrap();
    window.maybe_freeze(bounds.close_anchor + 1);

    let winner_submission_id = window.winner.as_ref().unwrap().submission_id;
    let cert_id = pow_cert_id_v2(&cert);
    let evidence = pc_types::EvidenceKind::MintMissingImportV2 {
        prev_mint_id: [0xAA; 32],
        window_id: bounds.window_id,
        expected_winner_submission_id: winner_submission_id,
        required_pow_cert_id: cert_id,
        offending_anchor_id: AnchorId([0xE1; 32]),
    };

    assert!(window
        .verify_mint_missing_import_evidence_v2(
            &evidence,
            AnchorId([0xE1; 32]),
            bounds.deadline_anchor,
            &empty_payload(),
        )
        .is_ok());

    let wrong = pc_types::EvidenceKind::MintMissingImportV2 {
        prev_mint_id: [0xAA; 32],
        window_id: bounds.window_id,
        expected_winner_submission_id: winner_submission_id,
        required_pow_cert_id: [0x01; 32],
        offending_anchor_id: AnchorId([0xE1; 32]),
    };
    assert!(window
        .verify_mint_missing_import_evidence_v2(
            &wrong,
            AnchorId([0xE1; 32]),
            bounds.deadline_anchor,
            &empty_payload(),
        )
        .is_err());
}
