use super::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_payload_merkle_root_invariant_under_order(
        version in any::<u8>(),
        txs in proptest::collection::vec(
            (
                any::<u8>(),
                proptest::collection::vec((any::<[u8;32]>(), any::<u32>(), proptest::collection::vec(any::<u8>(), 0..32)), 0..3),
                proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..3)
            ), 0..5
        ),
        payout in any::<[u8;32]>()
    ) {
        // Baue MicroTx-Liste aus generierten Rohdaten
        let mut a: Vec<MicroTx> = Vec::with_capacity(txs.len());
        for (ver, ins_raw, outs_raw) in &txs {
            let inputs: Vec<TxIn> = ins_raw.iter()
                .map(|(txid, vout, wit)| TxIn { prev_out: OutPoint { txid: *txid, vout: *vout }, witness: wit.clone() })
                .collect();
            let outputs: Vec<TxOut> = outs_raw.iter()
                .map(|(amt, lock)| TxOut { amount: *amt, lock: LockCommitment(*lock) })
                .collect();
            a.push(MicroTx { version: *ver, inputs, outputs });
        }
        let mut b = a.clone();
        b.reverse(); // Permutiere Reihenfolge

        let p1 = AnchorPayload { version, micro_txs: a, mints: vec![], claims: vec![], evidences: vec![], payout_root: payout };
        let p2 = AnchorPayload { version, micro_txs: b, mints: vec![], claims: vec![], evidences: vec![], payout_root: payout };

        let r1 = payload_merkle_root(&p1);
        let r2 = payload_merkle_root(&p2);
        if p1.micro_txs != p2.micro_txs {
            prop_assert_ne!(r1, r2);
        } else {
            prop_assert_eq!(r1, r2);
        }
    }
}

#[test]
fn payload_merkle_root_v2_uses_genesis_note_when_present() {
    let note = GenesisNote {
        version: 0,
        network_name: b"testnet".to_vec(),
        seed: [1u8; 32],
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 3,
            txs_per_payload: 16,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let p = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: genesis_payload_root(&note),
        genesis_note: Some(note.clone()),
    };
    let got = payload_merkle_root_v2(&p);
    let want = genesis_payload_root(&note);
    assert_eq!(got, want);

    let p2 = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
        }],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: genesis_payload_root(&note),
        genesis_note: Some(note.clone()),
    };
    let got2 = payload_merkle_root_v2(&p2);
    assert_ne!(got2, want);
}
