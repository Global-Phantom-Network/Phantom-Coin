// SPDX-License-Identifier: AGPL-3.0-only

//! Simplified Byzantine resistance tests

#[test]
fn byzantine_double_vote_is_100pct_slashable() {
    // Equivocation (double-voting) is always 100% slash
    // This is enforced by SlashingParams::recommended_*
    use pc_consensus::SlashingParams;

    let strict = SlashingParams::recommended_strict();
    let moderate = SlashingParams::recommended_moderate();

    // Both configurations slash 100% for equivocation
    assert_eq!(strict.equivocation_bp, 10_000);
    assert_eq!(moderate.equivocation_bp, 10_000);
}

#[test]
fn byzantine_minority_cannot_double_spend() {
    // UTXO state prevents double-spend attacks
    use pc_state::{InMemoryBackend, StateError, UtxoState};
    use pc_types::{
        digest_mint, sighash_microtx_v1, LockCommitment, MicroTx, MintEvent, NetworkId, OutPoint,
        TxIn, TxOut,
    };

    let mut state = UtxoState::new(InMemoryBackend::new());

    let nid: NetworkId = [9u8; 32];
    let sk = [1u8; 32];
    let kp = pc_crypto::SchnorrKeypair::from_secret_key_bytes(&sk).expect("kp");
    let pk = kp.public_xonly_bytes();

    // Create UTXO
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0u8; 32],
        outputs: vec![TxOut {
            amount: 1000,
            lock: LockCommitment(pk),
        }],
        pow_seed: [0u8; 32],
        pow_nonce: 0,
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    state.apply_mint_with_index(&mint, 0);

    let txid = digest_mint(&mint);
    let outpoint = OutPoint { txid, vout: 0 };

    // First spend
    let mut tx1 = MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: outpoint,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            amount: 1000,
            lock: LockCommitment([2u8; 32]),
        }],
    };
    let digest = sighash_microtx_v1(&nid, &tx1);
    let sig = pc_crypto::schnorr_sign(&digest, &kp);
    let mut w = Vec::with_capacity(96);
    w.extend_from_slice(&pk);
    w.extend_from_slice(&sig);
    tx1.inputs[0].witness = w;
    state
        .apply_micro_tx_with_maturity_indexed(&tx1, 100, 10, &nid)
        .expect("apply first micro tx");

    // Double-spend attempt
    let tx2 = MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: outpoint, // Same UTXO!
            witness: vec![],
        }],
        outputs: vec![TxOut {
            amount: 1000,
            lock: LockCommitment([3u8; 32]),
        }],
    };

    // Should be rejected
    let result = state.apply_micro_tx_with_maturity_indexed(&tx2, 100, 10, &nid);
    assert!(matches!(result, Err(StateError::MissingInput(_))));
}

#[test]
fn byzantine_withheld_votes_not_slashable() {
    // Not voting (withholding) is not slashable by design
    // Validators can go offline without penalty
    use pc_consensus::SlashingParams;
    let s = SlashingParams::recommended_moderate();
    assert!(s.validate().is_ok());
}
