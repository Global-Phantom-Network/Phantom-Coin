use super::*;
#[test]
fn validate_genesis_anchor_ok() {
    let note = GenesisNote {
        version: 0,
        network_name: b"phantom-dev".to_vec(),
        seed: [0x42; 32],
        params: pc_types::GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let pl = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: genesis_payload_root(&note),
        genesis_note: Some(note.clone()),
    };
    let h = AnchorHeaderV2 {
        version: 2,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: genesis_payload_root(&note),
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
        network_id: digest_genesis_note(&note),
        vote_epoch: 0,
        vote_round: 0,
        attest_sig: None,
        state_root: None,
    };
    let nid = validate_genesis_anchor(&h, &pl).expect("valid");
    assert_eq!(nid, digest_genesis_note(&note));
}

#[test]
fn validate_genesis_anchor_fails_on_nonempty_payload_lists() {
    let note = GenesisNote {
        version: 0,
        network_name: b"phantom-dev".to_vec(),
        seed: [0x42; 32],
        params: pc_types::GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let pl = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![pc_types::MicroTx {
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
    let h = AnchorHeaderV2 {
        version: 2,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: genesis_payload_root(&note),
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
        network_id: digest_genesis_note(&note),
        vote_epoch: 0,
        vote_round: 0,
        attest_sig: None,
        state_root: None,
    };
    assert!(validate_genesis_anchor(&h, &pl).is_err());
}

#[test]
fn validate_genesis_anchor_fails_on_payout_root_mismatch() {
    let note = GenesisNote {
        version: 0,
        network_name: b"phantom-dev".to_vec(),
        seed: [0x42; 32],
        params: pc_types::GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let pl = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: Some(note.clone()),
    };
    let h = AnchorHeaderV2 {
        version: 2,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: genesis_payload_root(&note),
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
        network_id: digest_genesis_note(&note),
        vote_epoch: 0,
        vote_round: 0,
        attest_sig: None,
        state_root: None,
    };
    assert!(validate_genesis_anchor(&h, &pl).is_err());
}
#[test]
fn validate_genesis_anchor_fails_on_params() {
    let bad = GenesisNote {
        version: 0,
        network_name: b"x".to_vec(),
        seed: [0; 32],
        params: pc_types::GenesisParams {
            shards_initial: 0,
            committee_k: 0,
            txs_per_payload: 0,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let pl = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: genesis_payload_root(&bad),
        genesis_note: Some(bad.clone()),
    };
    let h = AnchorHeaderV2 {
        version: 2,
        shard_id: 0,
        parents: pc_types::ParentList::default(),
        payload_hash: genesis_payload_root(&bad),
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: pc_types::AnchorId([0u8; 32]),
        network_id: digest_genesis_note(&bad),
        vote_epoch: 0,
        vote_round: 0,
        attest_sig: None,
        state_root: None,
    };
    assert!(validate_genesis_anchor(&h, &pl).is_err());
}
