use super::*;

fn legacy_mint(prev_mint_id: [u8; 32], amount: u64, lock: [u8; 32]) -> MintEvent {
    MintEvent {
        version: pc_types::MINT_VERSION_V1,
        prev_mint_id,
        outputs: vec![pc_types::TxOut {
            amount,
            lock: pc_types::LockCommitment(lock),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    }
}

#[test]
fn validate_mint_pow_bound_v1_accepts_correct_seed_when_bits_zero() {
    let network_id = [7u8; 32];
    let mut m = legacy_mint([3u8; 32], 1, [9u8; 32]);
    m.pow_seed = mint_pow_seed_v1(&network_id, &m);
    assert!(validate_mint_pow_bound_v1(&network_id, &m, 0).is_ok());
}

#[test]
fn validate_mint_pow_bound_v1_rejects_wrong_seed_even_if_pow_meets() {
    let network_id = [7u8; 32];
    let mut m = legacy_mint([3u8; 32], 1, [9u8; 32]);
    m.pow_seed = [1u8; 32];
    assert!(validate_mint_pow_bound_v1(&network_id, &m, 0).is_err());
}

#[test]
fn mint_pow_reuse_must_fail_same_prev_mint_id() {
    // PoW-Reuse Test: Zwei Mints mit gleichem prev_mint_id müssen im State abgelehnt werden.
    // PoW-Reuse Test: Two mints with same prev_mint_id must be rejected in state.
    use pc_state::{InMemoryBackend, UtxoState};
    let network_id = [7u8; 32];
    let mut st = UtxoState::new(InMemoryBackend::new());

    let mut m1 = legacy_mint([0xAAu8; 32], 100, [1u8; 32]);
    m1.pow_seed = mint_pow_seed_v1(&network_id, &m1);

    let mut m2 = legacy_mint([0xAAu8; 32], 200, [2u8; 32]);
    m2.pow_nonce = 1;
    m2.pow_seed = mint_pow_seed_v1(&network_id, &m2);

    // First mint: check not used, apply, mark used
    assert!(!st.is_prev_mint_used(&m1.prev_mint_id));
    st.apply_mint_with_index(&m1, 0);

    // Second mint with same prev_mint_id must be detected as reused
    assert!(
        st.is_prev_mint_used(&m2.prev_mint_id),
        "PoW reuse (same prev_mint_id) must be detected"
    );
}

#[test]
fn mint_pow_different_prev_mint_id_ok() {
    // Zwei Mints mit unterschiedlichem prev_mint_id müssen funktionieren.
    // Two mints with different prev_mint_id must work.
    use pc_state::{InMemoryBackend, UtxoState};
    let network_id = [7u8; 32];
    let mut st = UtxoState::new(InMemoryBackend::new());

    let mut m1 = legacy_mint([0xAAu8; 32], 100, [1u8; 32]);
    m1.pow_seed = mint_pow_seed_v1(&network_id, &m1);

    let mut m2 = legacy_mint([0xBBu8; 32], 200, [2u8; 32]);
    m2.pow_nonce = 1;
    m2.pow_seed = mint_pow_seed_v1(&network_id, &m2);

    assert!(!st.is_prev_mint_used(&m1.prev_mint_id));
    st.apply_mint_with_index(&m1, 0);
    assert!(
        !st.is_prev_mint_used(&m2.prev_mint_id),
        "Different prev_mint_id must not be marked as used"
    );
    st.apply_mint_with_index(&m2, 1);
}

#[test]
fn mint_round_id_and_pow_seed_v2_bind_emission_context() {
    let network_id = [0x77; 32];
    let prev_mint_id = [0x11; 32];
    let round_id = mint_round_id_v1(&prev_mint_id, 9);
    let mut mint = MintEvent {
        version: pc_types::MINT_VERSION_V2,
        prev_mint_id,
        outputs: vec![pc_types::TxOut {
            amount: 1,
            lock: pc_types::LockCommitment([0x22; 32]),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id,
        hit_bucket: 42,
        bits_used: 0,
    };
    let seed = mint_pow_seed_v2(&network_id, &mint);
    mint.pow_seed = seed;

    let mut changed_round = mint.clone();
    changed_round.round_id = mint_round_id_v1(&prev_mint_id, 10);
    let mut changed_bucket = mint.clone();
    changed_bucket.hit_bucket = 43;
    let mut changed_bits = mint.clone();
    changed_bits.bits_used = 1;

    assert_ne!(seed, mint_pow_seed_v2(&network_id, &changed_round));
    assert_ne!(seed, mint_pow_seed_v2(&network_id, &changed_bucket));
    assert_ne!(seed, mint_pow_seed_v2(&network_id, &changed_bits));
}

#[test]
fn validate_mint_pow_and_emission_v2_rejects_wrong_round_id() {
    let network_id = [0x55; 32];
    let mut supply = SupplyState::new();
    supply.pow_bits = 0;
    supply.pow_bits_min = 0;
    supply.pow_asert_ref_bucket = 0;
    let hit_bucket = 100;
    let mut mint = MintEvent {
        version: pc_types::MINT_VERSION_V2,
        prev_mint_id: supply.last_mint_id,
        outputs: vec![pc_types::TxOut {
            amount: 1,
            lock: pc_types::LockCommitment([0x33; 32]),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: mint_round_id_v1(&supply.last_mint_id, supply.mint_height + 1),
        hit_bucket,
        bits_used: supply.expected_bits_for_bucket(hit_bucket),
    };
    mint.pow_seed = mint_pow_seed_v2(&network_id, &mint);

    assert!(validate_mint_pow_and_emission_v2(&network_id, &supply, &mint).is_ok());
    mint.round_id = [0x77; 32];
    mint.pow_seed = mint_pow_seed_v2(&network_id, &mint);
    assert!(validate_mint_pow_and_emission_v2(&network_id, &supply, &mint).is_err());
}

#[test]
fn validate_mint_timing_window_v2_enforces_collect_and_grace_window() {
    let mut supply = SupplyState::new();
    supply.pow_bits = 0;
    supply.pow_bits_min = 0;
    supply.pow_asert_ref_bucket = 0;
    let hit_bucket = 100;
    let mint = MintEvent {
        version: pc_types::MINT_VERSION_V2,
        prev_mint_id: supply.last_mint_id,
        outputs: vec![pc_types::TxOut {
            amount: 1,
            lock: pc_types::LockCommitment([0x33; 32]),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: mint_round_id_v1(&supply.last_mint_id, supply.mint_height + 1),
        hit_bucket,
        bits_used: supply.expected_bits_for_bucket(hit_bucket),
    };

    assert!(validate_mint_timing_window_v2(
        &mint,
        consts::emission_collect_deadline_bucket(hit_bucket),
    )
    .is_ok());
    assert!(validate_mint_timing_window_v2(
        &mint,
        consts::emission_collect_deadline_bucket(hit_bucket) - 1,
    )
    .is_err());
    assert!(validate_mint_timing_window_v2(
        &mint,
        consts::emission_finalize_deadline_bucket(hit_bucket) + 1,
    )
    .is_err());
}

#[test]
fn process_mint_v2_updates_emission_reference_without_changing_maturity_index_logic() {
    let mut state = SupplyState::new();
    state.pow_bits = 12;
    state.pow_bits_min = 4;
    let hit_bucket = 77;
    let mint = MintEvent {
        version: pc_types::MINT_VERSION_V2,
        prev_mint_id: [0u8; 32],
        outputs: vec![pc_types::TxOut {
            amount: consts::INITIAL_MINT_REWARD,
            lock: pc_types::LockCommitment([0x44; 32]),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 999,
        round_id: mint_round_id_v1(&[0u8; 32], 1),
        hit_bucket,
        bits_used: 9,
    };

    state.process_mint(&mint, 123).unwrap();

    assert_eq!(state.last_minted_at_index, 123);
    assert_eq!(state.last_final_emission_bucket, hit_bucket);
    assert_eq!(state.pow_asert_ref_bucket, hit_bucket);
    assert_eq!(state.pow_bits, 9);
}
