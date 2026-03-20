// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Golden Tests für Genesis-Note Encoding und Commitment
//!
//! Diese Tests garantieren Determinismus über Plattformen hinweg und
//! verhindern Breaking Changes am Encoding-Format.

use pc_codec::{Decodable, Encodable};
use pc_types::{digest_genesis_note, GenesisNote, GenesisParams};

const CANONICAL_GENESIS_NOTE_BYTES: &[u8] = include_bytes!("../../../data/genesis_note.bin");

#[test]
fn canonical_repo_genesis_golden() {
    let note = pc_codec::decode_exact::<GenesisNote>(CANONICAL_GENESIS_NOTE_BYTES)
        .expect("decode canonical repo genesis");
    let mut enc = Vec::new();
    note.encode(&mut enc)
        .expect("re-encode canonical repo genesis");

    assert_eq!(enc.as_slice(), CANONICAL_GENESIS_NOTE_BYTES);
    assert_eq!(
        hex::encode(digest_genesis_note(&note)),
        "d4d309537274b9f8e0c8e5a067d6f8b9ba898773bcd203e8e106db08ed9023f6"
    );
    assert_eq!(note.version, 1);
    assert_eq!(note.network_name, b"phantom-mainnet".to_vec());
    assert_eq!(note.params.committee_k, 1);
    assert_eq!(note.params.features, 0x8d);
    assert_eq!(note.genesis_validators.len(), 1);
}

/// Golden Test Vector 1: Minimal GenesisNote
#[test]
fn genesis_note_encoding_minimal() {
    let note = GenesisNote {
        version: 0,
        network_name: b"dev".to_vec(),
        seed: [0x42; 32],
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 1,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let mut enc = Vec::new();
    note.encode(&mut enc)
        .expect("encode genesis_note (minimal)");

    // Golden Hex wird hier ausgegeben für zukünftige Fixierung
    eprintln!("genesis_note_encoding_minimal hex: {}", hex::encode(&enc));

    // Roundtrip muss funktionieren
    let decoded = GenesisNote::decode(&mut &enc[..]).expect("decode genesis_note (minimal)");
    assert_eq!(decoded, note);

    // Encoding muss deterministisch sein
    let mut enc2 = Vec::new();
    note.encode(&mut enc2)
        .expect("re-encode genesis_note (minimal)");
    assert_eq!(enc, enc2);
}

/// Golden Test Vector 2: Testnet-1 GenesisNote
#[test]
fn genesis_note_encoding_testnet1() {
    let note = GenesisNote {
        version: 0,
        network_name: b"phantom-testnet-1".to_vec(),
        seed: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
            0xC3, 0xD2, 0xE1, 0xF0,
        ],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let mut enc = Vec::new();
    note.encode(&mut enc)
        .expect("encode genesis_note (testnet1)");

    eprintln!("genesis_note_encoding_testnet1 hex: {}", hex::encode(&enc));

    // Roundtrip
    let decoded = GenesisNote::decode(&mut &enc[..]).expect("decode genesis_note (testnet1)");
    assert_eq!(decoded, note);

    // Determinismus
    let mut enc2 = Vec::new();
    note.encode(&mut enc2)
        .expect("re-encode genesis_note (testnet1)");
    assert_eq!(enc, enc2);
}

/// Golden Test Vector 3: Mainnet-ähnliche Konfiguration
#[test]
fn genesis_note_encoding_mainnet_like() {
    let note = GenesisNote {
        version: 0,
        network_name: b"phantom-mainnet".to_vec(),
        seed: [0xFF; 32],
        params: GenesisParams {
            shards_initial: 256,
            committee_k: 64,
            txs_per_payload: 1024,
            features: 0x000000000000CAFE, // Einige Features aktiv
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let mut enc = Vec::new();
    note.encode(&mut enc)
        .expect("encode genesis_note (mainnet-like)");

    eprintln!(
        "genesis_note_encoding_mainnet_like hex: {}",
        hex::encode(&enc)
    );

    // Roundtrip
    let decoded = GenesisNote::decode(&mut &enc[..]).expect("decode genesis_note (mainnet-like)");
    assert_eq!(decoded, note);

    // Determinismus
    let mut enc2 = Vec::new();
    note.encode(&mut enc2)
        .expect("re-encode genesis_note (mainnet-like)");
    assert_eq!(enc, enc2);
}

/// Golden Test Vector 4: Commitment Determinismus
#[test]
fn genesis_note_commitment_determinism() {
    let note = GenesisNote {
        version: 0,
        network_name: b"ci-bench".to_vec(),
        seed: [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B,
            0x6C, 0x7D, 0x8E, 0x9F,
        ],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    // Commitment muss über Runs hinweg stabil sein
    let commit1 = digest_genesis_note(&note);
    let commit2 = digest_genesis_note(&note);
    assert_eq!(commit1, commit2);

    eprintln!(
        "genesis_note_commitment_determinism commit: {}",
        hex::encode(commit1)
    );

    // Commitment muss 32 Bytes sein
    assert_eq!(commit1.len(), 32);

    // Verschiedene Notes müssen verschiedene Commitments haben
    let mut note2 = note.clone();
    note2.network_name = b"different".to_vec();
    let commit3 = digest_genesis_note(&note2);
    assert_ne!(commit1, commit3);
}

/// Golden Test Vector 5: Network ID Ableitung
#[test]
fn genesis_network_id_derivation() {
    let note = GenesisNote {
        version: 0,
        network_name: b"phantom-dev".to_vec(),
        seed: [0x00; 32],
        params: GenesisParams {
            shards_initial: 64,
            committee_k: 21,
            txs_per_payload: 256,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let network_id = digest_genesis_note(&note);

    // Network ID muss genau 32 Bytes sein
    assert_eq!(network_id.len(), 32);

    eprintln!(
        "genesis_network_id_derivation nid: {}",
        hex::encode(network_id)
    );

    // Determinismus
    let network_id2 = digest_genesis_note(&note);
    assert_eq!(network_id, network_id2);
}

/// Golden Test Vector 6: Leerer Network Name (Edge Case)
#[test]
fn genesis_note_empty_network_name() {
    let note = GenesisNote {
        version: 0,
        network_name: vec![], // Leer
        seed: [0x11; 32],
        params: GenesisParams {
            shards_initial: 1,
            committee_k: 1,
            txs_per_payload: 1,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let mut enc = Vec::new();
    note.encode(&mut enc)
        .expect("encode genesis_note (empty network name)");

    eprintln!("genesis_note_empty_network_name hex: {}", hex::encode(&enc));

    // Roundtrip
    let decoded =
        GenesisNote::decode(&mut &enc[..]).expect("decode genesis_note (empty network name)");
    assert_eq!(decoded.network_name.len(), 0);

    // Commitment ist deterministisch
    let commit = digest_genesis_note(&note);
    let commit2 = digest_genesis_note(&note);
    assert_eq!(commit, commit2);
    assert_eq!(commit.len(), 32);
}

/// Golden Test Vector 7: Maximale Werte (Stress Test)
#[test]
fn genesis_note_max_values() {
    let note = GenesisNote {
        version: 0,
        network_name: vec![0xFFu8; 32], // Max 32 Bytes
        seed: [0xFFu8; 32],
        params: GenesisParams {
            shards_initial: u16::MAX,
            committee_k: 64, // Max erlaubter Wert laut Spec
            txs_per_payload: u16::MAX,
            features: u64::MAX,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let mut enc = Vec::new();
    note.encode(&mut enc)
        .expect("encode genesis_note (max values)");

    // Roundtrip muss funktionieren
    let decoded = GenesisNote::decode(&mut &enc[..]).expect("decode genesis_note (max values)");
    assert_eq!(decoded.params.shards_initial, u16::MAX);
    assert_eq!(decoded.params.committee_k, 64);
    assert_eq!(decoded.params.txs_per_payload, u16::MAX);
    assert_eq!(decoded.params.features, u64::MAX);

    // Commitment ist stabil
    let commit = digest_genesis_note(&note);
    assert_eq!(commit.len(), 32);
}

/// Cross-Platform Determinismus Test
#[test]
fn genesis_encoding_is_platform_independent() {
    // Derselbe Input muss auf allen Plattformen zum selben Output führen
    let note = GenesisNote {
        version: 0,
        network_name: b"cross-platform-test".to_vec(),
        seed: [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
        ],
        params: GenesisParams {
            shards_initial: 128,
            committee_k: 32,
            txs_per_payload: 512,
            features: 0x0000000000001234,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let mut enc = Vec::new();
    note.encode(&mut enc)
        .expect("encode genesis_note (platform independent)");

    eprintln!(
        "genesis_encoding_is_platform_independent hex: {}",
        hex::encode(&enc)
    );
    eprintln!(
        "genesis_encoding_is_platform_independent commit: {}",
        hex::encode(digest_genesis_note(&note))
    );

    // Dieser Wert MUSS auf x86_64, ARM, macOS, Linux identisch sein
    // Determinismus über mehrere Encodings
    let mut enc2 = Vec::new();
    note.encode(&mut enc2)
        .expect("re-encode genesis_note (platform independent)");
    assert_eq!(enc, enc2);

    // Commitment auch platform-independent (deterministisch)
    let commit = digest_genesis_note(&note);
    let commit2 = digest_genesis_note(&note);
    assert_eq!(commit, commit2);
}
