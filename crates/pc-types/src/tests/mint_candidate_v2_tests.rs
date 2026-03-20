use super::*;
use pc_codec::decode_exact;
use serde::Deserialize;

fn sample_candidate_v2() -> MintCandidateEventV2 {
    MintCandidateEventV2 {
        version: 2,
        network_id: [0x44; 32],
        prev_mint_id: [0x55; 32],
        window_id: 12,
        window_open_anchor_id: [0x66; 32],
        mint_commitment: [0x77; 32],
        nonce: 999,
        miner_pubkey: Some([0x88; 32]),
        recipient_lock: Some(LockCommitment([0x99; 32])),
    }
}

fn sample_candidate_v2_without_optionals() -> MintCandidateEventV2 {
    let mut candidate = sample_candidate_v2();
    candidate.miner_pubkey = None;
    candidate.recipient_lock = None;
    candidate
}

fn sample_pow_cert_v2() -> MintPoWCertV2 {
    MintPoWCertV2 {
        version: 2,
        network_id: [0x44; 32],
        prev_mint_id: [0x55; 32],
        window_id: 12,
        window_open_anchor_id: [0x66; 32],
        mint_commitment: [0x77; 32],
        nonce: 999,
    }
}

fn parse_hex32(s: &str) -> [u8; 32] {
    let raw = hex::decode(s).expect("hex decode (32 bytes)");
    assert_eq!(raw.len(), 32, "expected 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

fn parse_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex decode")
}

fn encode_candidate_v2_manual(candidate: &MintCandidateEventV2, version: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    version.encode(&mut buf).unwrap();
    candidate.network_id.encode(&mut buf).unwrap();
    candidate.prev_mint_id.encode(&mut buf).unwrap();
    candidate.window_id.encode(&mut buf).unwrap();
    candidate.window_open_anchor_id.encode(&mut buf).unwrap();
    candidate.mint_commitment.encode(&mut buf).unwrap();
    candidate.nonce.encode(&mut buf).unwrap();
    candidate.miner_pubkey.is_some().encode(&mut buf).unwrap();
    if let Some(pk) = &candidate.miner_pubkey {
        buf.extend_from_slice(pk);
    }
    candidate.recipient_lock.is_some().encode(&mut buf).unwrap();
    if let Some(lock) = &candidate.recipient_lock {
        lock.encode(&mut buf).unwrap();
    }
    buf
}

fn encode_pow_cert_v2_manual(cert: &MintPoWCertV2, version: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    version.encode(&mut buf).unwrap();
    cert.network_id.encode(&mut buf).unwrap();
    cert.prev_mint_id.encode(&mut buf).unwrap();
    cert.window_id.encode(&mut buf).unwrap();
    cert.window_open_anchor_id.encode(&mut buf).unwrap();
    cert.mint_commitment.encode(&mut buf).unwrap();
    cert.nonce.encode(&mut buf).unwrap();
    buf
}

fn evidence_event(evidence: EvidenceKind) -> EvidenceEvent {
    EvidenceEvent {
        version: 1,
        evidence,
    }
}

fn reference_pow_retarget_bits(
    old_bits: u8,
    min_bits: u8,
    expected_window_anchors: u64,
    actual_window_anchors: u64,
) -> u8 {
    if old_bits == 0 {
        return 0;
    }
    let expected = expected_window_anchors.max(1);
    let mut actual = actual_window_anchors.max(1);
    let min_actual = (expected / 4).max(1);
    let max_actual = expected.saturating_mul(4).max(min_actual);
    if actual < min_actual {
        actual = min_actual;
    } else if actual > max_actual {
        actual = max_actual;
    }

    let ratio_q32: u64 = (((expected as u128) << 32) / (actual as u128)) as u64;
    const SQRT2_Q32: u64 = 6_074_001_000;
    const INV_SQRT2_Q32: u64 = 3_037_000_500;
    const TWO_SQRT2_Q32: u64 = 12_148_002_000;
    const INV_TWO_SQRT2_Q32: u64 = 1_518_500_250;

    let delta_bits: i16 = if ratio_q32 >= TWO_SQRT2_Q32 {
        2
    } else if ratio_q32 >= SQRT2_Q32 {
        1
    } else if ratio_q32 >= INV_SQRT2_Q32 {
        0
    } else if ratio_q32 >= INV_TWO_SQRT2_Q32 {
        -1
    } else {
        -2
    };

    let mut next = (old_bits as i16).saturating_add(delta_bits);
    if next < min_bits as i16 {
        next = min_bits as i16;
    }
    next.clamp(0, 255) as u8
}

#[derive(Debug, Deserialize)]
struct Vectors {
    candidate: VectorMintWindowV2,
    cert: VectorMintWindowV2,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct VectorMintWindowV2 {
    version: u8,
    network_id: String,
    prev_mint_id: String,
    window_id: u64,
    window_open_anchor_id: String,
    mint_commitment: String,
    nonce: u64,
    miner_pubkey: Option<String>,
    recipient_lock: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Expected {
    candidate_bytes: String,
    pow_cert_bytes: String,
    slot_id_v2: String,
    submission_id_v2: String,
    pow_hash_v2: String,
    pow_cert_id_v2: String,
}

#[derive(Debug, Deserialize)]
struct RetargetVectors {
    cases: Vec<RetargetCase>,
}

#[derive(Debug, Deserialize)]
struct RetargetCase {
    name: String,
    old_bits: u8,
    min_bits: u8,
    expected_window_anchors: u64,
    actual_window_anchors: u64,
    next_bits: u8,
}

fn mk_candidate(v: &VectorMintWindowV2) -> MintCandidateEventV2 {
    MintCandidateEventV2 {
        version: v.version,
        network_id: parse_hex32(&v.network_id),
        prev_mint_id: parse_hex32(&v.prev_mint_id),
        window_id: v.window_id,
        window_open_anchor_id: parse_hex32(&v.window_open_anchor_id),
        mint_commitment: parse_hex32(&v.mint_commitment),
        nonce: v.nonce,
        miner_pubkey: v.miner_pubkey.as_deref().map(parse_hex32),
        recipient_lock: v
            .recipient_lock
            .as_deref()
            .map(|lock| LockCommitment(parse_hex32(lock))),
    }
}

fn mk_pow_cert(v: &VectorMintWindowV2) -> MintPoWCertV2 {
    MintPoWCertV2 {
        version: v.version,
        network_id: parse_hex32(&v.network_id),
        prev_mint_id: parse_hex32(&v.prev_mint_id),
        window_id: v.window_id,
        window_open_anchor_id: parse_hex32(&v.window_open_anchor_id),
        mint_commitment: parse_hex32(&v.mint_commitment),
        nonce: v.nonce,
    }
}

#[test]
fn candidate_v2_roundtrip_decode_exact() {
    let c = sample_candidate_v2();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    let got = decode_exact::<MintCandidateEventV2>(&buf).unwrap();
    assert_eq!(got, c);
}

#[test]
fn candidate_v2_encode_rejects_non_v2_version() {
    let mut c = sample_candidate_v2();
    c.version = 1;
    let mut buf = Vec::new();
    assert!(c.encode(&mut buf).is_err());
}

#[test]
fn candidate_v2_decode_rejects_non_v2_version() {
    let c = sample_candidate_v2();
    let buf = encode_candidate_v2_manual(&c, 1);
    assert!(decode_exact::<MintCandidateEventV2>(&buf).is_err());
}

#[test]
fn candidate_v2_decode_exact_rejects_trailing_bytes() {
    let c = sample_candidate_v2();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    buf.push(0xAB);
    assert!(decode_exact::<MintCandidateEventV2>(&buf).is_err());
}

#[test]
fn pow_cert_v2_roundtrip_decode_exact() {
    let c = sample_pow_cert_v2();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    let got = decode_exact::<MintPoWCertV2>(&buf).unwrap();
    assert_eq!(got, c);
}

#[test]
fn pow_cert_v2_encode_rejects_non_v2_version() {
    let mut c = sample_pow_cert_v2();
    c.version = 1;
    let mut buf = Vec::new();
    assert!(c.encode(&mut buf).is_err());
}

#[test]
fn pow_cert_v2_decode_rejects_non_v2_version() {
    let c = sample_pow_cert_v2();
    let buf = encode_pow_cert_v2_manual(&c, 1);
    assert!(decode_exact::<MintPoWCertV2>(&buf).is_err());
}

#[test]
fn pow_cert_v2_decode_exact_rejects_trailing_bytes() {
    let c = sample_pow_cert_v2();
    let mut buf = Vec::new();
    c.encode(&mut buf).unwrap();
    buf.push(0xAB);
    assert!(decode_exact::<MintPoWCertV2>(&buf).is_err());
}

#[test]
fn v2_codec_layout_keeps_candidate_optionals_but_cert_stays_minimal() {
    let candidate = sample_candidate_v2();
    let cert = sample_pow_cert_v2();

    let candidate_manual = encode_candidate_v2_manual(&candidate, 2);
    let cert_manual = encode_pow_cert_v2_manual(&cert, 2);

    let mut candidate_encoded = Vec::new();
    candidate.encode(&mut candidate_encoded).unwrap();
    let mut cert_encoded = Vec::new();
    cert.encode(&mut cert_encoded).unwrap();

    assert_eq!(candidate_encoded, candidate_manual);
    assert_eq!(cert_encoded, cert_manual);
    assert_ne!(candidate_encoded, cert_encoded);
}

#[test]
fn v2_optional_candidate_fields_do_not_change_slot_submission_or_pow_hash() {
    let candidate_with_optionals = sample_candidate_v2();
    let candidate_without_optionals = sample_candidate_v2_without_optionals();
    let cert = sample_pow_cert_v2();

    assert_eq!(
        candidate_slot_id_v2(&candidate_with_optionals),
        candidate_slot_id_v2(&candidate_without_optionals)
    );
    assert_eq!(
        candidate_submission_id_v2(&candidate_with_optionals),
        candidate_submission_id_v2(&candidate_without_optionals)
    );
    assert_eq!(
        candidate_pow_hash_v2(&candidate_with_optionals),
        candidate_pow_hash_v2(&candidate_without_optionals)
    );
    assert_eq!(
        candidate_slot_id_v2(&candidate_with_optionals),
        pow_cert_slot_id_v2(&cert)
    );
    assert_eq!(
        candidate_submission_id_v2(&candidate_with_optionals),
        pow_cert_submission_id_v2(&cert)
    );
    assert_eq!(
        candidate_pow_hash_v2(&candidate_with_optionals),
        pow_cert_pow_hash_v2(&cert)
    );
    assert_ne!(
        canonical_candidate_bytes_v2(&candidate_with_optionals),
        canonical_candidate_bytes_v2(&candidate_without_optionals)
    );
}

#[test]
fn v2_hashes_and_ids_match_manual_preimages() {
    let candidate = sample_candidate_v2();
    let cert = sample_pow_cert_v2();

    let mut slot_preimage = Vec::new();
    slot_preimage.extend_from_slice(MINT_SLOT_DOMAIN_V2);
    slot_preimage.extend_from_slice(&candidate.network_id);
    slot_preimage.extend_from_slice(&candidate.prev_mint_id);
    slot_preimage.extend_from_slice(&candidate.window_id.to_le_bytes());
    slot_preimage.extend_from_slice(&candidate.window_open_anchor_id);
    slot_preimage.extend_from_slice(&candidate.mint_commitment);
    let slot_id = blake3_32(&slot_preimage);

    let mut submission_preimage = Vec::new();
    submission_preimage.extend_from_slice(MINT_SUBMISSION_DOMAIN_V2);
    submission_preimage.extend_from_slice(&candidate.network_id);
    submission_preimage.extend_from_slice(&candidate.prev_mint_id);
    submission_preimage.extend_from_slice(&candidate.window_id.to_le_bytes());
    submission_preimage.extend_from_slice(&candidate.window_open_anchor_id);
    submission_preimage.extend_from_slice(&candidate.mint_commitment);
    submission_preimage.extend_from_slice(&candidate.nonce.to_le_bytes());
    let submission_id = blake3_32(&submission_preimage);

    let mut pow_preimage = Vec::new();
    pow_preimage.extend_from_slice(MINT_POW_DOMAIN_V1);
    pow_preimage.extend_from_slice(&candidate.network_id);
    pow_preimage.extend_from_slice(&candidate.prev_mint_id);
    pow_preimage.extend_from_slice(&candidate.window_id.to_le_bytes());
    pow_preimage.extend_from_slice(&candidate.window_open_anchor_id);
    pow_preimage.extend_from_slice(&candidate.mint_commitment);
    pow_preimage.extend_from_slice(&candidate.nonce.to_le_bytes());
    let pow_hash = blake3_32(&pow_preimage);

    let mut cert_id_preimage = Vec::new();
    cert_id_preimage.extend_from_slice(MINT_POW_CERT_DOMAIN_V2);
    cert_id_preimage.extend_from_slice(&canonical_pow_cert_bytes_v2(&cert));
    let pow_cert_id = blake3_32(&cert_id_preimage);

    assert_eq!(
        slot_id_v2(
            &candidate.network_id,
            &candidate.prev_mint_id,
            candidate.window_id,
            &candidate.window_open_anchor_id,
            &candidate.mint_commitment
        ),
        slot_id
    );
    assert_eq!(candidate_slot_id_v2(&candidate), slot_id);
    assert_eq!(pow_cert_slot_id_v2(&cert), slot_id);

    assert_eq!(
        submission_id_v2(
            &candidate.network_id,
            &candidate.prev_mint_id,
            candidate.window_id,
            &candidate.window_open_anchor_id,
            &candidate.mint_commitment,
            candidate.nonce
        ),
        submission_id
    );
    assert_eq!(candidate_submission_id_v2(&candidate), submission_id);
    assert_eq!(pow_cert_submission_id_v2(&cert), submission_id);

    assert_eq!(
        pow_hash_v2(
            &candidate.network_id,
            &candidate.prev_mint_id,
            candidate.window_id,
            &candidate.window_open_anchor_id,
            &candidate.mint_commitment,
            candidate.nonce
        ),
        pow_hash
    );
    assert_eq!(candidate_pow_hash_v2(&candidate), pow_hash);
    assert_eq!(pow_cert_pow_hash_v2(&cert), pow_hash);

    assert_eq!(pow_cert_id_v2(&cert), pow_cert_id);
    assert_ne!(pow_cert_id_v2(&cert), pow_cert_submission_id_v2(&cert));
}

#[test]
fn v2_feature_bits_are_separated_from_v1() {
    assert_eq!(mint_candidate_feature_bits_v2_from_genesis_features(0), 0);
    assert_eq!(
        mint_candidate_feature_bits_v2_from_genesis_features(
            GENESIS_FEATURE_MINT_CANDIDATE_MINER_PUBKEY_V1
                | GENESIS_FEATURE_MINT_CANDIDATE_RECIPIENT_LOCK_V1
                | GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1
        ),
        0
    );
    assert_eq!(
        mint_candidate_feature_bits_v2_from_genesis_features(GENESIS_FEATURE_MINT_WINDOW_V2),
        MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V2 | MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V2
    );
    assert_eq!(
        mint_candidate_feature_bits_v1_from_genesis_features(GENESIS_FEATURE_MINT_WINDOW_V2),
        0
    );
    assert_eq!(
        mint_candidate_feature_bits_v1_from_genesis_features(
            GENESIS_FEATURE_MINT_CANDIDATE_MINER_PUBKEY_V1
                | GENESIS_FEATURE_MINT_CANDIDATE_RECIPIENT_LOCK_V1
                | GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1
        ),
        MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V1
            | MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V1
            | MINT_CANDIDATE_FEATURE_WORK_ID_V1
    );
}

#[test]
fn v2_feature_validator_gates_candidate_optionals() {
    let candidate = sample_candidate_v2();

    assert_eq!(
        validate_mint_candidate_features_v2(&candidate, 0).unwrap_err(),
        "miner_pubkey feature disabled"
    );
    assert_eq!(
        validate_mint_candidate_features_v2(&candidate, MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V2)
            .unwrap_err(),
        "recipient_lock feature disabled"
    );
    validate_mint_candidate_features_v2(
        &candidate,
        MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V2 | MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V2,
    )
    .unwrap();
    validate_mint_candidate_v2(&candidate).unwrap();
}

#[test]
fn v2_validators_reject_wrong_versions() {
    let mut candidate = sample_candidate_v2();
    candidate.version = 1;
    assert_eq!(
        validate_mint_candidate_v2(&candidate).unwrap_err(),
        "invalid candidate version"
    );

    let mut cert = sample_pow_cert_v2();
    cert.version = 1;
    assert_eq!(
        validate_mint_pow_cert_v2(&cert).unwrap_err(),
        "invalid mint pow cert version"
    );
}

#[test]
fn mint_censorship_v2_evidence_roundtrip() {
    let ev = EvidenceKind::MintCensorshipV2 {
        prev_mint_id: [0xA1; 32],
        window_id: 7,
        expected_winner_submission_id: [0xA2; 32],
        offending_anchor_id: AnchorId([0xA3; 32]),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    assert_eq!(buf[0], 10);
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
    validate_evidence_sanity(&evidence_event(got)).unwrap();
}

#[test]
fn mint_candidate_v2_evidence_roundtrip() {
    let ev = EvidenceKind::MintCandidateV2 {
        candidate: sample_candidate_v2(),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    assert_eq!(buf[0], 11);
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
    validate_evidence_sanity(&evidence_event(got)).unwrap();
}

#[test]
fn mint_pow_cert_v2_evidence_roundtrip() {
    let ev = EvidenceKind::MintPoWCertV2 {
        cert: sample_pow_cert_v2(),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    assert_eq!(buf[0], 12);
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
    validate_evidence_sanity(&evidence_event(got)).unwrap();
}

#[test]
fn mint_missing_import_v2_evidence_roundtrip() {
    let ev = EvidenceKind::MintMissingImportV2 {
        prev_mint_id: [0xA1; 32],
        window_id: 7,
        expected_winner_submission_id: [0xA2; 32],
        required_pow_cert_id: [0xA3; 32],
        offending_anchor_id: AnchorId([0xA4; 32]),
    };
    let mut buf = Vec::new();
    ev.encode(&mut buf).unwrap();
    assert_eq!(buf[0], 13);
    let got = decode_exact::<EvidenceKind>(&buf).unwrap();
    assert_eq!(got, ev);
    validate_evidence_sanity(&evidence_event(got)).unwrap();
}

#[test]
fn v1_decode_remains_intact_for_candidate_and_pow_cert() {
    let candidate_v1 = MintCandidateEvent {
        version: 1,
        network_id: [0x10; 32],
        prev_mint_id: [0x11; 32],
        window_id: 9,
        window_open_anchor_id: [0x12; 32],
        mint_commitment: [0x13; 32],
        nonce: 42,
        work_id: Some([0x14; 32]),
        miner_pubkey: Some([0x15; 32]),
        recipient_lock: Some(LockCommitment([0x16; 32])),
    };
    let pow_cert_v1 = MintPoWCertV1 {
        version: 1,
        network_id: [0x10; 32],
        prev_mint_id: [0x11; 32],
        window_id: 9,
        window_open_anchor_id: [0x12; 32],
        mint_commitment: [0x13; 32],
        nonce: 42,
        work_id: Some([0x14; 32]),
    };

    let mut candidate_buf = Vec::new();
    candidate_v1.encode(&mut candidate_buf).unwrap();
    assert_eq!(
        decode_exact::<MintCandidateEvent>(&candidate_buf).unwrap(),
        candidate_v1
    );

    let mut cert_buf = Vec::new();
    pow_cert_v1.encode(&mut cert_buf).unwrap();
    assert_eq!(
        decode_exact::<MintPoWCertV1>(&cert_buf).unwrap(),
        pow_cert_v1
    );
}

#[test]
fn mint_pow_v2_vectors_json() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_vectors/mint_pow_v2.json");
    let raw = std::fs::read_to_string(&path).expect("read mint_pow_v2.json");
    assert!(!raw.contains("\"work_id\""));
    let vectors: Vectors = serde_json::from_str(&raw).expect("parse mint_pow_v2.json");

    let candidate = mk_candidate(&vectors.candidate);
    let cert = mk_pow_cert(&vectors.cert);

    assert_eq!(
        hex::encode(canonical_candidate_bytes_v2(&candidate)),
        vectors.expected.candidate_bytes
    );
    assert_eq!(
        hex::encode(canonical_pow_cert_bytes_v2(&cert)),
        vectors.expected.pow_cert_bytes
    );
    assert_eq!(
        hex::encode(candidate_slot_id_v2(&candidate)),
        vectors.expected.slot_id_v2
    );
    assert_eq!(
        hex::encode(pow_cert_slot_id_v2(&cert)),
        vectors.expected.slot_id_v2
    );
    assert_eq!(
        hex::encode(candidate_submission_id_v2(&candidate)),
        vectors.expected.submission_id_v2
    );
    assert_eq!(
        hex::encode(pow_cert_submission_id_v2(&cert)),
        vectors.expected.submission_id_v2
    );
    assert_eq!(
        hex::encode(candidate_pow_hash_v2(&candidate)),
        vectors.expected.pow_hash_v2
    );
    assert_eq!(
        hex::encode(pow_cert_pow_hash_v2(&cert)),
        vectors.expected.pow_hash_v2
    );
    assert_eq!(
        hex::encode(pow_cert_id_v2(&cert)),
        vectors.expected.pow_cert_id_v2
    );

    assert_eq!(
        parse_hex(&vectors.expected.candidate_bytes),
        canonical_candidate_bytes_v2(&candidate)
    );
    assert_eq!(
        parse_hex(&vectors.expected.pow_cert_bytes),
        canonical_pow_cert_bytes_v2(&cert)
    );
}

#[test]
fn mint_pow_retarget_v2_vectors_json() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_vectors/mint_pow_retarget_v2.json");
    let raw = std::fs::read_to_string(&path).expect("read mint_pow_retarget_v2.json");
    let vectors: RetargetVectors =
        serde_json::from_str(&raw).expect("parse mint_pow_retarget_v2.json");

    for case in vectors.cases.iter() {
        let got = reference_pow_retarget_bits(
            case.old_bits,
            case.min_bits,
            case.expected_window_anchors,
            case.actual_window_anchors,
        );
        assert_eq!(got, case.next_bits, "{}", case.name);
    }
}
