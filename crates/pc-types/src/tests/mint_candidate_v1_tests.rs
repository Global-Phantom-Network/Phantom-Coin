use super::*;
use pc_codec::decode_exact;

fn sample_mint() -> MintEvent {
    MintEvent {
        version: 1,
        prev_mint_id: [0x11; 32],
        outputs: vec![TxOut {
            amount: 42,
            lock: LockCommitment([0x22; 32]),
        }],
        pow_seed: [0x33; 32],
        pow_nonce: 7,
        minted_at: 9,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    }
}

fn sample_candidate() -> MintCandidateEvent {
    MintCandidateEvent {
        version: 1,
        network_id: [0x44; 32],
        prev_mint_id: [0x55; 32],
        window_id: 12,
        window_open_anchor_id: [0x66; 32],
        mint_commitment: [0x77; 32],
        nonce: 999,
        work_id: Some([0xAB; 32]),
        miner_pubkey: Some([0x88; 32]),
        recipient_lock: Some(LockCommitment([0x99; 32])),
    }
}

fn sample_pow_cert() -> MintPoWCertV1 {
    MintPoWCertV1 {
        version: 1,
        network_id: [0x44; 32],
        prev_mint_id: [0x55; 32],
        window_id: 12,
        window_open_anchor_id: [0x66; 32],
        mint_commitment: [0x77; 32],
        nonce: 999,
        work_id: Some([0xAB; 32]),
    }
}

#[test]
fn mint_id_aliases_mint_commitment_v1() {
    let m = sample_mint();
    assert_eq!(mint_id_v1(&m), mint_commitment_v1(&m));
}

#[test]
fn mint_commitment_hashes_exact_domain_and_canonical_bytes() {
    let m = sample_mint();
    let mut expect_in = Vec::new();
    expect_in.extend_from_slice(MINT_COMMITMENT_DOMAIN_V1);
    expect_in.extend_from_slice(&canonical_mint_bytes_v1(&m));
    assert_eq!(mint_commitment_v1(&m), blake3_32(&expect_in));
}

#[test]
fn candidate_id_hashes_exact_domain_and_canonical_bytes() {
    let c = sample_candidate();
    let mut expect_in = Vec::new();
    expect_in.extend_from_slice(MINT_CANDIDATE_DOMAIN_V1);
    expect_in.extend_from_slice(&canonical_candidate_bytes_v1(&c));
    assert_eq!(candidate_id_v1(&c), blake3_32(&expect_in));
}

#[test]
fn candidate_pow_hash_hashes_exact_bound_fields() {
    let c = sample_candidate();
    let mut expect_in = Vec::new();
    expect_in.extend_from_slice(MINT_POW_DOMAIN_V1);
    expect_in.extend_from_slice(&c.network_id);
    expect_in.extend_from_slice(&c.prev_mint_id);
    expect_in.extend_from_slice(&c.window_id.to_le_bytes());
    expect_in.extend_from_slice(&c.window_open_anchor_id);
    expect_in.extend_from_slice(&c.mint_commitment);
    expect_in.extend_from_slice(&c.nonce.to_le_bytes());
    assert_eq!(candidate_pow_hash_v1(&c), blake3_32(&expect_in));
}

#[test]
fn pow_cert_hashes_exact_bound_fields() {
    let c = sample_pow_cert();
    let mut expect_in = Vec::new();
    expect_in.extend_from_slice(MINT_POW_DOMAIN_V1);
    expect_in.extend_from_slice(&c.network_id);
    expect_in.extend_from_slice(&c.prev_mint_id);
    expect_in.extend_from_slice(&c.window_id.to_le_bytes());
    expect_in.extend_from_slice(&c.window_open_anchor_id);
    expect_in.extend_from_slice(&c.mint_commitment);
    expect_in.extend_from_slice(&c.nonce.to_le_bytes());
    assert_eq!(pow_cert_pow_hash_v1(&c), blake3_32(&expect_in));
}

#[test]
fn mint_decode_exact_rejects_trailing_bytes() {
    let m = sample_mint();
    let mut buf = Vec::new();
    m.encode(&mut buf).unwrap();
    buf.push(0xAB);
    assert!(decode_exact::<MintEvent>(&buf).is_err());
}

#[test]
fn mint_decode_rejects_too_many_outputs() {
    let mut buf = Vec::new();
    1u8.encode(&mut buf).unwrap();
    [0x11u8; 32].encode(&mut buf).unwrap();
    pc_codec::write_varu64(&mut buf, (MAX_MINT_OUTPUTS as u64) + 1).unwrap();
    [0x33u8; 32].encode(&mut buf).unwrap();
    7u64.encode(&mut buf).unwrap();
    9u64.encode(&mut buf).unwrap();
    assert!(decode_exact::<MintEvent>(&buf).is_err());
}

#[test]
fn candidate_roundtrip_decode_exact() {
    let c = sample_candidate();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    let got = decode_exact::<MintCandidateEvent>(&buf).unwrap();
    assert_eq!(got, c);
}

#[test]
fn candidate_encode_rejects_non_v1_version() {
    let mut c = sample_candidate();
    c.version = 2;
    let mut buf = Vec::new();
    assert!(c.encode(&mut buf).is_err());
}

#[test]
fn candidate_decode_rejects_non_v1_version() {
    let mut c = sample_candidate();
    c.version = 2;
    let mut buf = Vec::new();
    // Encode manually to bypass encode-side guard and exercise decode path.
    2u8.encode(&mut buf).unwrap();
    c.network_id.encode(&mut buf).unwrap();
    c.prev_mint_id.encode(&mut buf).unwrap();
    c.window_id.encode(&mut buf).unwrap();
    c.window_open_anchor_id.encode(&mut buf).unwrap();
    c.mint_commitment.encode(&mut buf).unwrap();
    c.nonce.encode(&mut buf).unwrap();
    c.work_id.is_some().encode(&mut buf).unwrap();
    if let Some(work_id) = c.work_id {
        work_id.encode(&mut buf).unwrap();
    }
    c.miner_pubkey.is_some().encode(&mut buf).unwrap();
    if let Some(pk) = c.miner_pubkey {
        buf.extend_from_slice(&pk);
    }
    c.recipient_lock.is_some().encode(&mut buf).unwrap();
    if let Some(lock) = c.recipient_lock {
        lock.encode(&mut buf).unwrap();
    }
    assert!(decode_exact::<MintCandidateEvent>(&buf).is_err());
}

#[test]
fn candidate_decode_exact_rejects_trailing_bytes() {
    let c = sample_candidate();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    buf.push(0xAB);
    assert!(decode_exact::<MintCandidateEvent>(&buf).is_err());
}

#[test]
fn pow_cert_roundtrip_decode_exact() {
    let c = sample_pow_cert();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    let got = decode_exact::<MintPoWCertV1>(&buf).unwrap();
    assert_eq!(got, c);
}

#[test]
fn pow_cert_decode_exact_rejects_trailing_bytes() {
    let c = sample_pow_cert();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    buf.push(0xAB);
    assert!(decode_exact::<MintPoWCertV1>(&buf).is_err());
}

#[test]
fn candidate_features_rejected_when_disabled() {
    let mut c = sample_candidate();
    c.miner_pubkey = None;
    c.recipient_lock = None;
    let err = validate_mint_candidate_features_v1(&c, 0).unwrap_err();
    assert_eq!(err, "work_id feature disabled");
}

#[test]
fn candidate_features_accept_enabled_bits() {
    let c = sample_candidate();
    let bits = MINT_CANDIDATE_FEATURE_WORK_ID_V1
        | MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V1
        | MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V1;
    validate_mint_candidate_features_v1(&c, bits).unwrap();
}

#[test]
fn anchor_payload_v3_xor_sanity() {
    let p = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![sample_mint()],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
        null_mint: true,
    };
    assert!(validate_payload_sanity_v3(&p).is_err());
}

#[test]
fn anchor_payload_v3_rejects_null_mint_without_mints() {
    let p = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
        null_mint: true,
    };
    assert!(validate_payload_sanity_v3(&p).is_err());
}

#[test]
fn anchor_payload_v3_rejects_wrong_version() {
    let p = AnchorPayloadV3 {
        version: 2,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
        null_mint: false,
    };
    assert!(validate_payload_sanity_v3(&p).is_err());
}

#[test]
fn anchor_payload_v3_rejects_oversized_encoded_payload() {
    let fat_tx = MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0x11; 32],
                vout: 0,
            },
            witness: vec![0u8; MAX_WITNESS_BYTES],
        }],
        outputs: vec![],
    };
    let micro_txs: Vec<MicroTx> = (0..1300).map(|_| fat_tx.clone()).collect();
    let p = AnchorPayloadV3 {
        version: 3,
        micro_txs,
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
        null_mint: false,
    };
    assert!(
        p.encoded_len() > MAX_PAYLOAD_BYTES,
        "test payload must exceed MAX_PAYLOAD_BYTES"
    );
    assert!(validate_payload_sanity_v3(&p).is_err());
}

#[test]
fn anchor_payload_v2_rejects_oversized_encoded_payload() {
    let fat_tx = MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0x22; 32],
                vout: 0,
            },
            witness: vec![0u8; MAX_WITNESS_BYTES],
        }],
        outputs: vec![],
    };
    let micro_txs: Vec<MicroTx> = (0..1300).map(|_| fat_tx.clone()).collect();
    let p = AnchorPayloadV2 {
        version: 2,
        micro_txs,
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
    };
    assert!(
        p.encoded_len() > MAX_PAYLOAD_BYTES,
        "test payload must exceed MAX_PAYLOAD_BYTES"
    );
    assert!(validate_payload_sanity_v2(&p).is_err());
}

#[test]
fn mint_censorship_evidence_roundtrip() {
    let ev = EvidenceKind::MintCensorshipV1 {
        prev_mint_id: [0xAA; 32],
        window_id: 7,
        expected_winner_candidate_id: [0xBB; 32],
        offending_anchor_id: AnchorId([0xCC; 32]),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
}

#[test]
fn mint_candidate_evidence_roundtrip() {
    let ev = EvidenceKind::MintCandidateV1 {
        candidate: sample_candidate(),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
}

#[test]
fn mint_pow_cert_evidence_roundtrip() {
    let ev = EvidenceKind::MintPoWCertV1 {
        cert: sample_pow_cert(),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
}

#[test]
fn mint_missing_import_evidence_roundtrip() {
    let ev = EvidenceKind::MintMissingImportV1 {
        prev_mint_id: [0xA1; 32],
        window_id: 7,
        expected_winner_candidate_id: [0xA2; 32],
        required_pow_cert_id: [0xA3; 32],
        offending_anchor_id: AnchorId([0xA4; 32]),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
}

#[test]
fn mint_domains_are_exact_ascii_bytes() {
    assert_eq!(MINT_COMMITMENT_DOMAIN_V1, b"PHANTOM:MINT:COMMIT:v1");
    assert_eq!(MINT_CANDIDATE_DOMAIN_V1, b"PHANTOM:MINT:CANDIDATE:v1");
    assert_eq!(MINT_POW_DOMAIN_V1, b"PHANTOM:MINT:POW:v1");
    assert_eq!(MINT_CANDROOT_DOMAIN_V1, b"PHANTOM:MINT:CANDROOT:v1");
    assert_eq!(MINT_POW_CERT_DOMAIN_V1, b"PHANTOM:MINT:POWCERT:v1");
    for d in [
        MINT_COMMITMENT_DOMAIN_V1,
        MINT_CANDIDATE_DOMAIN_V1,
        MINT_POW_DOMAIN_V1,
        MINT_CANDROOT_DOMAIN_V1,
        MINT_POW_CERT_DOMAIN_V1,
    ] {
        assert!(
            d.iter().all(u8::is_ascii),
            "domain tags must be exact US-ASCII bytes"
        );
    }
}

#[test]
fn pow_cert_id_hashes_exact_domain_and_canonical_bytes() {
    let c = sample_pow_cert();
    let mut expect_in = Vec::new();
    expect_in.extend_from_slice(MINT_POW_CERT_DOMAIN_V1);
    expect_in.extend_from_slice(&canonical_pow_cert_bytes_v1(&c));
    assert_eq!(pow_cert_id_v1(&c), blake3_32(&expect_in));
}

#[test]
fn candidate_from_pow_cert_is_canonical_v1_no_optional_fields() {
    let cert = sample_pow_cert();
    let c = mint_candidate_from_pow_cert_v1(&cert);
    assert_eq!(c.version, 1);
    assert_eq!(c.network_id, cert.network_id);
    assert_eq!(c.prev_mint_id, cert.prev_mint_id);
    assert_eq!(c.window_id, cert.window_id);
    assert_eq!(c.window_open_anchor_id, cert.window_open_anchor_id);
    assert_eq!(c.mint_commitment, cert.mint_commitment);
    assert_eq!(c.nonce, cert.nonce);
    assert_eq!(c.work_id, cert.work_id);
    assert!(c.miner_pubkey.is_none());
    assert!(c.recipient_lock.is_none());
}

#[test]
fn candidate_feature_bits_are_derived_from_genesis_feature_flags() {
    let none = mint_candidate_feature_bits_v1_from_genesis_features(0);
    assert_eq!(none, 0);

    let miner_only = mint_candidate_feature_bits_v1_from_genesis_features(
        GENESIS_FEATURE_MINT_CANDIDATE_MINER_PUBKEY_V1,
    );
    assert_eq!(miner_only, MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V1);

    let lock_only = mint_candidate_feature_bits_v1_from_genesis_features(
        GENESIS_FEATURE_MINT_CANDIDATE_RECIPIENT_LOCK_V1,
    );
    assert_eq!(lock_only, MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V1);

    let work_only = mint_candidate_feature_bits_v1_from_genesis_features(
        GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1,
    );
    assert_eq!(work_only, MINT_CANDIDATE_FEATURE_WORK_ID_V1);

    let both = mint_candidate_feature_bits_v1_from_genesis_features(
        GENESIS_FEATURE_MINT_CANDIDATE_MINER_PUBKEY_V1
            | GENESIS_FEATURE_MINT_CANDIDATE_RECIPIENT_LOCK_V1
            | GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1,
    );
    assert_eq!(
        both,
        MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V1
            | MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V1
            | MINT_CANDIDATE_FEATURE_WORK_ID_V1
    );
}

#[test]
fn candidate_work_id_falls_back_to_mint_commitment_for_legacy_objects() {
    let mut c = sample_candidate();
    c.work_id = None;
    assert_eq!(candidate_work_id_v1(&c), c.mint_commitment);

    let mut cert = sample_pow_cert();
    cert.work_id = None;
    assert_eq!(pow_cert_work_id_v1(&cert), cert.mint_commitment);
}
