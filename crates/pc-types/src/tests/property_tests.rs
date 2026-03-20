use super::*;
use proptest::prelude::*;

fn rt<T: pc_codec::Encodable + pc_codec::Decodable + core::fmt::Debug + PartialEq>(v: &T) -> T {
    let mut buf = Vec::new();
    v.encode(&mut buf).expect("encode");
    let mut s = &buf[..];
    T::decode(&mut s).expect("decode")
}

proptest! {
    #[test]
    fn prop_roundtrip_anchor_payload_empty_lists(payout in any::<[u8;32]>()) {
        let pl = AnchorPayload { version: 1, micro_txs: vec![], mints: vec![], claims: vec![], evidences: vec![], payout_root: payout };
        let got = rt(&pl);
        prop_assert_eq!(pl, got);
    }

    #[test]
    fn prop_roundtrip_anchor_header_basic(
        payload_hash in any::<[u8;32]>(),
        creator in any::<u8>(),
        vote in any::<u64>(),
        ack in any::<[u8;32]>(),
        ack_present in any::<bool>(),
    ) {
        let parents = ParentList::default();
        let ack_id = if ack_present { AnchorId(ack) } else { AnchorId([0u8;32]) };
        let hdr = AnchorHeader { version: 1, shard_id: 0, parents, payload_hash, creator_index: creator, vote_mask: vote, ack_present, ack_id };
        let got = rt(&hdr);
        prop_assert_eq!(hdr, got);
    }

    #[test]
    fn prop_roundtrip_microtx_random(
        version in 1u8..=2u8,
        ins in proptest::collection::vec((any::<[u8;32]>(), any::<u32>(), proptest::collection::vec(any::<u8>(), 0..64)), 0..4),
        outs in proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..4),
    ) {
        let inputs: Vec<TxIn> = ins.into_iter()
            .map(|(txid, vout, wit)| TxIn { prev_out: OutPoint { txid, vout }, witness: wit })
            .collect();
        let outputs: Vec<TxOut> = outs.into_iter()
            .map(|(amt, lock)| TxOut { amount: amt, lock: LockCommitment(lock) })
            .collect();
        let tx = MicroTx { version, inputs, outputs };
        let got = rt(&tx);
        prop_assert_eq!(tx, got);
    }

    #[test]
    fn prop_roundtrip_mint_random(
        version in prop_oneof![Just(MINT_VERSION_V1), Just(MINT_VERSION_V2)],
        prev_mint_id in any::<[u8;32]>(),
        outs in proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..4),
        pow_seed in any::<[u8;32]>(),
        pow_nonce in any::<u64>(),
    ) {
        let outputs: Vec<TxOut> = outs.into_iter()
            .map(|(amt, lock)| TxOut { amount: amt, lock: LockCommitment(lock) })
            .collect();
        let m = MintEvent {
            version,
            prev_mint_id,
            outputs,
            pow_seed,
            pow_nonce,
            minted_at: 0,
            round_id: [0u8; 32],
            hit_bucket: 0,
            bits_used: 0,
        };
        let got = rt(&m);
        prop_assert_eq!(m, got);
    }

    #[test]
    fn prop_roundtrip_claim_event(
        version in prop_oneof![Just(MINT_VERSION_V1), Just(MINT_VERSION_V2)],
        anchor_id in any::<[u8;32]>(),
        recipient_id in any::<[u8;32]>(),
        amount in any::<u64>(),
        proof in proptest::collection::vec(any::<[u8;32]>(), 0..8),
        payout_lock in any::<[u8;32]>(),
    ) {
        let c = ClaimEvent {
            version,
            anchor_id: AnchorId(anchor_id),
            recipient_id,
            amount,
            merkle_proof: proof,
            payout_lock: LockCommitment(payout_lock),
        };
        let got = rt(&c);
        prop_assert_eq!(c, got);
    }

    #[test]
    fn prop_digest_stable_microtx(
        version in prop_oneof![Just(MINT_VERSION_V1), Just(MINT_VERSION_V2)],
        ins in proptest::collection::vec((any::<[u8;32]>(), any::<u32>(), proptest::collection::vec(any::<u8>(), 0..32)), 0..3),
        outs in proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..3),
    ) {
        let inputs: Vec<TxIn> = ins.into_iter()
            .map(|(txid, vout, wit)| TxIn { prev_out: OutPoint { txid, vout }, witness: wit })
            .collect();
        let outputs: Vec<TxOut> = outs.into_iter()
            .map(|(amt, lock)| TxOut { amount: amt, lock: LockCommitment(lock) })
            .collect();
        let tx = MicroTx { version, inputs, outputs };

        let digest1 = digest_microtx(&tx);
        let tx_rt = rt(&tx);
        let digest2 = digest_microtx(&tx_rt);

        prop_assert_eq!(digest1, digest2, "Digest must be stable after roundtrip");
    }

    #[test]
    fn prop_digest_stable_mint(
        version in prop_oneof![Just(MINT_VERSION_V1), Just(MINT_VERSION_V2)],
        prev_mint_id in any::<[u8;32]>(),
        outs in proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..3),
        pow_seed in any::<[u8;32]>(),
        pow_nonce in any::<u64>(),
    ) {
        let outputs: Vec<TxOut> = outs.into_iter()
            .map(|(amt, lock)| TxOut { amount: amt, lock: LockCommitment(lock) })
            .collect();
        let m = MintEvent {
            version,
            prev_mint_id,
            outputs,
            pow_seed,
            pow_nonce,
            minted_at: 0,
            round_id: [0u8; 32],
            hit_bucket: 0,
            bits_used: 0,
        };

        let digest1 = digest_mint(&m);
        let m_rt = rt(&m);
        let digest2 = digest_mint(&m_rt);

        prop_assert_eq!(digest1, digest2, "Digest must be stable after roundtrip");
    }

    #[test]
    fn prop_encoded_len_matches_actual(
        version in any::<u8>(),
        ins in proptest::collection::vec((any::<[u8;32]>(), any::<u32>(), proptest::collection::vec(any::<u8>(), 0..32)), 0..4),
        outs in proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..4),
    ) {
        let inputs: Vec<TxIn> = ins.into_iter()
            .map(|(txid, vout, wit)| TxIn { prev_out: OutPoint { txid, vout }, witness: wit })
            .collect();
        let outputs: Vec<TxOut> = outs.into_iter()
            .map(|(amt, lock)| TxOut { amount: amt, lock: LockCommitment(lock) })
            .collect();
        let tx = MicroTx { version, inputs, outputs };

        let expected_len = tx.encoded_len();
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();

        prop_assert_eq!(expected_len, buf.len(), "encoded_len() must match actual encoded size");
    }
}
