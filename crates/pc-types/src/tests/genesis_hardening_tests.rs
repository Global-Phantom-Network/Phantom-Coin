use super::*;
use pc_codec::{decode_exact, Encodable};

#[test]
fn genesis_note_trailing_bytes_must_fail() {
    // Genesis mit trailing bytes muss bei decode_exact failen.
    // Genesis with trailing bytes must fail with decode_exact.
    let note = GenesisNote {
        version: 0,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    note.encode(&mut buf).unwrap();
    buf.push(0xFF); // trailing byte
    let err = decode_exact::<GenesisNote>(&buf);
    assert!(
        err.is_err(),
        "Genesis with trailing bytes must fail decode_exact"
    );
}

#[test]
fn genesis_note_network_name_oversize_must_fail() {
    let note = GenesisNote {
        version: 0,
        network_name: vec![b'a'; MAX_GENESIS_NETWORK_NAME_BYTES + 1],
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    assert!(
        note.encode(&mut buf).is_err(),
        "Genesis network_name > MAX_GENESIS_NETWORK_NAME_BYTES must fail encode"
    );
}

#[test]
fn genesis_note_network_name_at_limit_is_ok() {
    let note = GenesisNote {
        version: 0,
        network_name: vec![b'a'; MAX_GENESIS_NETWORK_NAME_BYTES],
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    note.encode(&mut buf).unwrap();
    let got = decode_exact::<GenesisNote>(&buf).expect("genesis decode at limit");
    assert_eq!(got.network_name.len(), MAX_GENESIS_NETWORK_NAME_BYTES);
}

#[test]
fn genesis_note_encode_rejects_version_above_v3() {
    let note = GenesisNote {
        version: 4,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    assert!(note.encode(&mut buf).is_err());
}

#[test]
fn genesis_note_encode_rejects_v0_with_validators() {
    let note = GenesisNote {
        version: 0,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![GenesisValidatorV1 {
            operator_id: [0x11; 32],
            bls_pk: [0x22; 48],
            bls_pop: [0x33; 96],
        }],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    assert!(note.encode(&mut buf).is_err());
}

#[test]
fn genesis_note_decode_rejects_version_above_v3() {
    // Manual wire payload:
    // version=4, network_name_len=0, seed=[0;32], params(shards=0, k=0, txs=0, features=0)
    let mut buf = Vec::new();
    buf.push(4u8);
    pc_codec::write_varu64(&mut buf, 0).unwrap(); // network_name len
    buf.extend_from_slice(&[0u8; 32]); // seed
    buf.extend_from_slice(&0u16.to_le_bytes()); // shards_initial
    buf.push(0u8); // committee_k
    buf.extend_from_slice(&0u16.to_le_bytes()); // txs_per_payload
    buf.extend_from_slice(&0u64.to_le_bytes()); // features
                                                // version>=1 path would decode genesis_validators vec len:
    pc_codec::write_varu64(&mut buf, 0).unwrap();
    assert!(decode_exact::<GenesisNote>(&buf).is_err());
}

#[test]
fn genesis_note_encode_rejects_pre_v3_bootstrap_bucket() {
    let note = GenesisNote {
        version: 2,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: b"hello".to_vec(),
        emission_bootstrap_bucket: 123,
    };
    let mut buf = Vec::new();
    assert!(note.encode(&mut buf).is_err());
}

#[test]
fn genesis_note_encode_rejects_v1_with_message() {
    let note = GenesisNote {
        version: 1,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: b"hello".to_vec(),
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    assert!(note.encode(&mut buf).is_err());
}

#[test]
fn genesis_note_message_roundtrip_v2() {
    let note = GenesisNote {
        version: 2,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![GenesisValidatorV1 {
            operator_id: [0x11; 32],
            bls_pk: [0x22; 48],
            bls_pop: [0x33; 96],
        }],
        genesis_message: b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
            .to_vec(),
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    note.encode(&mut buf).unwrap();
    let got = decode_exact::<GenesisNote>(&buf).expect("decode v2 genesis");
    assert_eq!(got, note);
}

#[test]
fn genesis_note_roundtrip_v3_with_emission_bootstrap_bucket() {
    let note = GenesisNote {
        version: 3,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![GenesisValidatorV1 {
            operator_id: [0x11; 32],
            bls_pk: [0x22; 48],
            bls_pop: [0x33; 96],
        }],
        genesis_message: b"bootstrap-bucket".to_vec(),
        emission_bootstrap_bucket: 1_773_964_800,
    };
    let mut buf = Vec::new();
    note.encode(&mut buf).unwrap();
    let got = decode_exact::<GenesisNote>(&buf).expect("decode v3 genesis");
    assert_eq!(got, note);
}

#[test]
fn genesis_note_message_oversize_must_fail() {
    let note = GenesisNote {
        version: 2,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![0xAA; MAX_GENESIS_MESSAGE_BYTES + 1],
        emission_bootstrap_bucket: 0,
    };
    let mut buf = Vec::new();
    assert!(note.encode(&mut buf).is_err());
}

#[test]
fn genesis_payload_v2_trailing_bytes_must_fail() {
    // AnchorPayloadV2 mit trailing bytes muss bei decode_exact failen.
    let note = GenesisNote {
        version: 0,
        network_name: b"testnet".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: GENESIS_FEATURE_MINT_POW_BIND_V1,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };
    let payload = AnchorPayloadV2 {
        version: 2,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: genesis_payload_root(&note),
        genesis_note: Some(note),
    };
    let mut buf = Vec::new();
    payload.encode(&mut buf).unwrap();
    buf.push(0xDE); // trailing byte
    buf.push(0xAD); // another trailing byte
    let err = decode_exact::<AnchorPayloadV2>(&buf);
    assert!(
        err.is_err(),
        "Payload with trailing bytes must fail decode_exact"
    );
}

#[test]
fn genesis_header_v2_trailing_bytes_must_fail() {
    // AnchorHeaderV2 mit trailing bytes muss bei decode_exact failen.
    let header = AnchorHeaderV2 {
        version: 2,
        shard_id: 0,
        parents: ParentList::default(),
        payload_hash: [0x11; 32],
        creator_index: 0,
        vote_mask: 0,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
        network_id: [0x22; 32],
        vote_epoch: 0,
        vote_round: 0,
        attest_sig: None,
        state_root: None,
    };
    let mut buf = Vec::new();
    header.encode(&mut buf).unwrap();
    buf.push(0xBE); // trailing byte
    buf.push(0xEF); // another trailing byte
    let err = decode_exact::<AnchorHeaderV2>(&buf);
    assert!(
        err.is_err(),
        "Header with trailing bytes must fail decode_exact"
    );
}
