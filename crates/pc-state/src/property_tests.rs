use super::*;
use pc_types::{TxIn, TxOut};
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_can_apply_micro_ok_when_mature(amt in 1u64..1_000_000, idx in 1000u64..2000u64, threshold in 1u64..100u64) {
        let mut st = UtxoState::new(InMemoryBackend::new());
        let nid: NetworkId = [9u8; 32];
        let sk = [1u8; 32];
        let kp = pc_crypto::SchnorrKeypair::from_secret_key_bytes(&sk).expect("kp");
        let pk = kp.public_xonly_bytes();
        let out = TxOut { amount: amt, lock: LockCommitment(pk) };
        let mint = MintEvent { version: 1, prev_mint_id: [0; 32], outputs: vec![out], pow_seed: [0; 32], pow_nonce: 0, minted_at: 0 };
        st.apply_mint_with_index(&mint, idx);
        let txid = digest_mint(&mint);
        let mut tx = MicroTx { version: 1, inputs: vec![TxIn { prev_out: OutPoint { txid, vout: 0 }, witness: vec![] }], outputs: vec![TxOut { amount: amt, lock: LockCommitment(pk) }] };
        let digest = pc_types::sighash_microtx_v1(&nid, &tx);
        let sig = pc_crypto::schnorr_sign(&digest, &kp);
        let mut w = Vec::with_capacity(96);
        w.extend_from_slice(&pk);
        w.extend_from_slice(&sig);
        tx.inputs[0].witness = w;
        let current = idx + threshold;
        prop_assert!(st.can_apply_micro_tx_with_maturity_indexed(&tx, current, threshold, &nid).is_ok());
    }

    #[test]
    fn prop_double_spend_rejected(amt in 1u64..1_000_000) {
        let mut st = UtxoState::new(InMemoryBackend::new());
        let nid: NetworkId = [9u8; 32];
        let out = TxOut { amount: amt, lock: LockCommitment([3u8; 32]) };
        let mint = MintEvent { version: 1, prev_mint_id: [0; 32], outputs: vec![out], pow_seed: [0; 32], pow_nonce: 1, minted_at: 0 };
        st.apply_mint(&mint);
        let txid = digest_mint(&mint);
        let in1 = TxIn { prev_out: OutPoint { txid, vout: 0 }, witness: vec![] };
        let tx = MicroTx { version: 1, inputs: vec![in1.clone(), in1], outputs: vec![TxOut { amount: amt, lock: LockCommitment([4u8; 32]) }] };
        prop_assert!(matches!(st.can_apply_micro_tx(&tx, &nid), Err(StateError::DoubleSpend(_))));
    }

    #[test]
    fn prop_balance_conserved_on_apply(a in 1u64..1_000_000, b in 1u64..1_000_000) {
        let mut st = UtxoState::new(InMemoryBackend::new());
        let nid: NetworkId = [9u8; 32];
        let sk = [2u8; 32];
        let kp = pc_crypto::SchnorrKeypair::from_secret_key_bytes(&sk).expect("kp");
        let pk = kp.public_xonly_bytes();
        let mint = MintEvent { version: 1, prev_mint_id: [0; 32], outputs: vec![
            TxOut { amount: a, lock: LockCommitment(pk) },
            TxOut { amount: b, lock: LockCommitment(pk) },
        ], pow_seed: [0; 32], pow_nonce: 2, minted_at: 0 };
        st.apply_mint(&mint);
        let txid = digest_mint(&mint);
        let mut tx = MicroTx { version: 1, inputs: vec![
            TxIn { prev_out: OutPoint { txid, vout: 0 }, witness: vec![] },
            TxIn { prev_out: OutPoint { txid, vout: 1 }, witness: vec![] },
        ], outputs: vec![ TxOut { amount: a + b, lock: LockCommitment([7u8; 32]) } ] };
        let digest = pc_types::sighash_microtx_v1(&nid, &tx);
        let sig = pc_crypto::schnorr_sign(&digest, &kp);
        for tin in tx.inputs.iter_mut() {
            let mut w = Vec::with_capacity(96);
            w.extend_from_slice(&pk);
            w.extend_from_slice(&sig);
            tin.witness = w;
        }
        prop_assert!(st.can_apply_micro_tx(&tx, &nid).is_ok());
        let r1 = st.root();
        prop_assert!(st.apply_micro_tx(&tx, &nid).is_ok());
        let r2 = st.root();
        prop_assert_ne!(r1, r2);
    }
}
