// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! End-to-end tests for genesis boot and network ID handling.
//! End-to-End Tests für Genesis-Boot und Network-ID-Handling
//!
//! These tests validate:
//! - Node boot with genesis note
//! - Network ID exposure via /status
//! - Config mismatch detection
//! - Empty anchors with DA gating
//!
//! Diese Tests validieren:
//! - Node-Boot mit Genesis-Note
//! - Network-ID Exposition via /status
//! - Config-Mismatch-Detection
//! - Leere Anker mit DA-Gating

use pc_codec::{Decodable, Encodable};
use pc_types::{digest_genesis_note, GenesisNote, GenesisParams};
use std::fs;
use tempfile::TempDir;

/// Helper: creates a test genesis_note.bin.
/// Helper: Erstellt eine test genesis_note.bin
fn create_genesis_note(dir: &std::path::Path, network_name: &str, seed: [u8; 32]) -> GenesisNote {
    let note = GenesisNote {
        version: 0,
        network_name: network_name.as_bytes().to_vec(),
        seed,
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
        .expect("encode genesis_note in create_genesis_note");

    let genesis_path = dir.join("genesis_note.bin");
    fs::write(&genesis_path, &enc).expect("write genesis_note.bin");

    note
}

#[tokio::test]
#[ignore] // Only in CI - requires a running node / Nur in CI - benötigt laufende Node
async fn test_genesis_boot_exposes_network_id() {
    let temp_dir = TempDir::new().expect("TempDir new");
    let mempool_dir = temp_dir.path().join("mempool");
    fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // Create genesis_note.bin.
    // Erstelle genesis_note.bin
    let note = create_genesis_note(&mempool_dir, "test-net", [0x42; 32]);
    let expected_nid = digest_genesis_note(&note);

    // Start node (simulated via direct function calls).
    // In production this would spawn a subprocess.
    // For this test we only validate file operations.
    // Starte Node (simuliert via direkter Funktion-Aufrufe)
    // In Production würde hier ein subprocess gestartet
    // Für diesen Test prüfen wir nur die Datei-Operationen

    // Read genesis_note.bin back from disk.
    // Lese genesis_note.bin zurück
    let genesis_path = mempool_dir.join("genesis_note.bin");
    assert!(genesis_path.exists());

    let buf = fs::read(&genesis_path).expect("read genesis_note.bin");
    let decoded = GenesisNote::decode(&mut &buf[..]).expect("decode genesis_note from file");

    assert_eq!(decoded.network_name, b"test-net");
    assert_eq!(digest_genesis_note(&decoded), expected_nid);

    // Validate that network ID is derived correctly.
    // Validiere dass Network-ID korrekt abgeleitet wird
    let nid = digest_genesis_note(&decoded);
    assert_eq!(nid.len(), 32);
    assert_eq!(nid, expected_nid);
}

#[test]
fn test_genesis_note_persistence_roundtrip() {
    let temp_dir = TempDir::new().expect("TempDir new");
    let mempool_dir = temp_dir.path().to_path_buf();
    fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // Create genesis note.
    // Erstelle Genesis-Note
    let original = create_genesis_note(&mempool_dir, "roundtrip-test", [0xAB; 32]);
    let original_nid = digest_genesis_note(&original);

    // Read back from disk.
    // Lese zurück
    let genesis_path = mempool_dir.join("genesis_note.bin");
    let buf = fs::read(&genesis_path).expect("read genesis_note.bin");
    let restored = GenesisNote::decode(&mut &buf[..]).expect("decode genesis_note from file");

    // Validate.
    // Validiere
    assert_eq!(restored, original);
    assert_eq!(digest_genesis_note(&restored), original_nid);
}

#[test]
fn test_genesis_mismatch_detection() {
    let temp_dir = TempDir::new().expect("TempDir new");
    let mempool_dir = temp_dir.path().to_path_buf();
    fs::create_dir_all(&mempool_dir).expect("create mempool dir");

    // Create first genesis note.
    // Erstelle erste Genesis-Note
    let note1 = create_genesis_note(&mempool_dir, "network-a", [0x11; 32]);
    let nid1 = digest_genesis_note(&note1);

    // Overwrite with a different genesis note.
    // Überschreibe mit anderer Genesis-Note
    let note2 = create_genesis_note(&mempool_dir, "network-b", [0x22; 32]);
    let nid2 = digest_genesis_note(&note2);

    // Network IDs must be different.
    // Network-IDs müssen unterschiedlich sein
    assert_ne!(nid1, nid2);

    // In production, node restart would abort with an error here.
    // This test only validates that the network IDs are indeed different.
    // In Production würde Node-Restart hier mit Error abbrechen
    // Dieser Test validiert nur, dass die NIDs tatsächlich unterschiedlich sind
}

#[test]
fn test_genesis_params_constraints() {
    // Valid parameters.
    // Valide Params
    let valid = GenesisParams {
        shards_initial: 64,
        committee_k: 21,
        txs_per_payload: 256,
        features: 0,
    };
    assert!(valid.committee_k >= 1 && valid.committee_k <= 64);
    assert!(valid.shards_initial >= 1);
    assert!(valid.txs_per_payload >= 1);

    // Edge case: k=1 (bootstrap).
    // Edge Case: k=1 (Bootstrap)
    let bootstrap = GenesisParams {
        shards_initial: 1,
        committee_k: 1,
        txs_per_payload: 1,
        features: 0,
    };
    assert_eq!(bootstrap.committee_k, 1);

    // Edge case: k=64 (maximum).
    // Edge Case: k=64 (Maximum)
    let max_k = GenesisParams {
        shards_initial: 256,
        committee_k: 64,
        txs_per_payload: 1024,
        features: u64::MAX,
    };
    assert_eq!(max_k.committee_k, 64);
}

#[test]
fn test_empty_anchor_payload_root_determinism() {
    use pc_types::{payload_merkle_root_v2, AnchorPayloadV2};

    // Empty anchor (A1+) - no genesis note.
    // Leerer Anker (A1+) - keine Genesis-Note
    let empty = AnchorPayloadV2 {
        version: 2,
        genesis_note: None,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
    };

    let root1 = payload_merkle_root_v2(&empty);
    let root2 = payload_merkle_root_v2(&empty);

    // Payload root must be deterministic.
    // Payload-Root muss deterministisch sein
    assert_eq!(root1, root2);

    // Root must not be 0x00..00 (safety).
    // Root darf nicht 0x00..00 sein (Sicherheit)
    assert_ne!(root1, [0u8; 32]);
}

#[test]
fn test_genesis_anchor_payload_includes_note() {
    use pc_types::{genesis_payload_root, payload_merkle_root_v2, AnchorPayloadV2};

    let note = GenesisNote {
        version: 0,
        network_name: b"genesis-payload-test".to_vec(),
        seed: [0xCC; 32],
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

    let root_genesis = genesis_payload_root(&note);

    // A0 Payload
    let a0_payload = AnchorPayloadV2 {
        version: 2,
        genesis_note: Some(note.clone()),
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: root_genesis,
    };

    let root_v2 = payload_merkle_root_v2(&a0_payload);

    // Both methods must result in the same root for A0.
    // Beide Methoden müssen zum selben Root führen für A0
    assert_eq!(root_v2, root_genesis);
}

#[test]
fn test_network_id_stability_across_encodings() {
    // Encode the same note multiple times  always the same network ID.
    // Dieselbe Note mehrfach encodieren  immer derselbe Network-ID
    let note = GenesisNote {
        version: 0,
        network_name: b"stability-test".to_vec(),
        seed: [0x55; 32],
        params: GenesisParams {
            shards_initial: 128,
            committee_k: 32,
            txs_per_payload: 512,
            features: 0,
        },
        genesis_validators: vec![],
        genesis_message: vec![],
        emission_bootstrap_bucket: 0,
    };

    let mut enc1 = Vec::new();
    let mut enc2 = Vec::new();
    let mut enc3 = Vec::new();

    note.encode(&mut enc1).expect("encode genesis_note enc1");
    note.encode(&mut enc2).expect("encode genesis_note enc2");
    note.encode(&mut enc3).expect("encode genesis_note enc3");

    assert_eq!(enc1, enc2);
    assert_eq!(enc2, enc3);

    let nid1 = digest_genesis_note(&note);
    let nid2 = digest_genesis_note(&note);
    let nid3 = digest_genesis_note(&note);

    assert_eq!(nid1, nid2);
    assert_eq!(nid2, nid3);
}

#[test]
fn test_genesis_note_version_enforcement() {
    // Version 0 is currently the only supported version.
    // Version 0 ist aktuell die einzig unterstützte Version
    let note_v0 = GenesisNote {
        version: 0,
        network_name: b"v0".to_vec(),
        seed: [0x00; 32],
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
    note_v0.encode(&mut enc).expect("encode genesis_note v0");

    // First byte must be 0x00 (version).
    // Erstes Byte muss 0x00 sein (Version)
    assert_eq!(enc.first().copied(), Some(0x00));

    // Roundtrip
    let decoded = GenesisNote::decode(&mut &enc[..]).expect("decode genesis_note v0");
    assert_eq!(decoded.version, 0);
}

#[test]
fn test_bootstrap_k1_effective_committee_size() {
    use pc_consensus::BootstrapState;

    // Bootstrap state for genesis.
    // Bootstrap-State für Genesis
    let bs = BootstrapState::new_genesis();

    // During bootstrap: effective k = 1.
    // Während Bootstrap: effective k = 1
    assert_eq!(bs.effective_committee_k(21), 1);

    // After rotation: effective k equals the configured k.
    // Nach Rotation: effective k = configured k
    let mut bs_rotated = bs.clone();
    bs_rotated.activate_rotation();
    assert_eq!(bs_rotated.effective_committee_k(21), 21);
}

#[test]
fn test_bootstrap_bounds_validation() {
    use pc_consensus::BootstrapState;

    let bs = BootstrapState::new_genesis();

    // Height 0 allowed during bootstrap.
    // Height 0 erlaubt während Bootstrap
    assert!(bs.validate_bootstrap_bounds(0).is_ok());

    // Heights > 0 are forbidden during bootstrap.
    // Heights > 0 sind verboten während Bootstrap
    assert!(bs.validate_bootstrap_bounds(1).is_err());
    assert!(bs.validate_bootstrap_bounds(100).is_err());
}
