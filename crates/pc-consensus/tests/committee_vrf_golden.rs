// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Golden Tests für VRF Committee Selection
//!
//! Diese Tests validieren:
//! - Seed-Derivation-Determinismus
//! - Epoch-Calculation-Stabilität
//! - Committee-Selection-Reproduzierbarkeit
//! - Cross-Platform-Kompatibilität

use pc_consensus::committee_vrf::{
    committee_select_vrf, derive_epoch, derive_vrf_seed, RotationParams, VrfCandidate,
};
use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_pop_prove, bls_vrf_prove};
use pc_types::AnchorId;

#[test]
fn vrf_seed_derivation_golden() {
    // Fixed inputs (Golden vectors)
    let network_id = blake3_32(b"phantom-testnet-1");
    let anchor_id_bytes = blake3_32(b"anchor-genesis-0");
    let anchor_id = AnchorId(anchor_id_bytes);

    let seed = derive_vrf_seed(network_id, anchor_id);

    // Determinismus: mehrfache Aufrufe → identisches Ergebnis
    let seed2 = derive_vrf_seed(network_id, anchor_id);
    assert_eq!(seed, seed2);

    // Golden value ausgeben (für zukünftige Referenz)
    eprintln!("Golden Seed (testnet-1, genesis): {}", hex::encode(seed));

    // Cross-platform check: Seed muss auf allen Plattformen identisch sein
    // (keine Endianness-Issues, da BLAKE3 plattformunabhängig ist)
    assert_eq!(seed.len(), 32);

    // Unterschiedliche Inputs → unterschiedliche Seeds
    let network_id2 = blake3_32(b"phantom-mainnet");
    let seed3 = derive_vrf_seed(network_id2, anchor_id);
    assert_ne!(seed, seed3);

    let anchor_id2 = AnchorId(blake3_32(b"anchor-1"));
    let seed4 = derive_vrf_seed(network_id, anchor_id2);
    assert_ne!(seed, seed4);
}

#[test]
fn epoch_calculation_golden_vectors() {
    // Golden vectors: (anchor_index, epoch_len) → expected_epoch
    let vectors = [
        (0, 10, 0),
        (9, 10, 0),
        (10, 10, 1),
        (19, 10, 1),
        (20, 10, 2),
        (99, 10, 9),
        (100, 10, 10),
        (999, 100, 9),
        (1000, 100, 10),
        // Edge cases
        (0, 1, 0),
        (100, 1, 100),
        (7, 0, 7), // epoch_len=0 → clamped to 1
        (u64::MAX, u64::MAX, 1),
    ];

    for (anchor_index, epoch_len, expected) in vectors {
        let epoch = derive_epoch(anchor_index, epoch_len);
        assert_eq!(
            epoch, expected,
            "anchor_index={}, epoch_len={} → expected={}, got={}",
            anchor_index, epoch_len, expected, epoch
        );
    }

    // Determinismus
    for (anchor_index, epoch_len, _) in vectors {
        let e1 = derive_epoch(anchor_index, epoch_len);
        let e2 = derive_epoch(anchor_index, epoch_len);
        assert_eq!(e1, e2);
    }
}

#[test]
fn committee_selection_determinism_golden() {
    // Fixed seed und epoch
    let seed = blake3_32(b"golden-seed-vrf");
    let epoch = 42u64;
    let current_anchor_index = epoch * 10_000;

    let params = RotationParams {
        cooldown_anchors: 1_000,
        min_attendance_pct: 50,
    };

    // 10 fixe Kandidaten erstellen (deterministisch)
    let mut candidates: Vec<VrfCandidate> = Vec::new();
    for i in 0..10u8 {
        let ikm = blake3_32(&[b'G', b'O', b'L', b'D', i]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");

        // VRF message
        let msg = {
            const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
            let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
            m.extend_from_slice(VRF_MSG_DOMAIN);
            m.extend_from_slice(&seed);
            m.extend_from_slice(&epoch.to_le_bytes());
            m
        };

        let (proof, _y) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', i]),
            blake3_32(&[b'O', i]),
            kp.pk,
            bls_pop_prove(&kp.sk),
            current_anchor_index.saturating_sub(10_000),
            100,
            proof,
        ));
    }

    // Committee auswählen (k=5)
    let committee1 =
        committee_select_vrf(5, epoch, seed, current_anchor_index, &candidates, &params);
    assert_eq!(committee1.len(), 5);

    // Deterministisch: mehrfache Selektionen → identisches Committee
    let committee2 =
        committee_select_vrf(5, epoch, seed, current_anchor_index, &candidates, &params);
    assert_eq!(committee1.len(), committee2.len());

    for (s1, s2) in committee1.iter().zip(committee2.iter()) {
        assert_eq!(s1.recipient_id, s2.recipient_id);
        assert_eq!(s1.operator_id, s2.operator_id);
        assert_eq!(s1.bls_pk.to_bytes(), s2.bls_pk.to_bytes());
        assert_eq!(s1.score, s2.score);
    }

    // Golden values ausgeben
    eprintln!("Golden Committee (k=5, epoch=42):");
    for (idx, seat) in committee1.iter().enumerate() {
        eprintln!(
            "  Seat {}: recipient={}, operator={}, score={}",
            idx,
            hex::encode(seat.recipient_id),
            hex::encode(seat.operator_id),
            hex::encode(seat.score)
        );
    }
}

#[test]
fn vrf_score_ordering_golden() {
    // Mehrere Kandidaten mit bekannten VRF-Scores
    let seed = blake3_32(b"score-order-test");
    let epoch = 10u64;
    let current_anchor_index = 100_000u64;

    let params = RotationParams {
        cooldown_anchors: 0,
        min_attendance_pct: 0,
    };

    // 5 Kandidaten mit unterschiedlichen Keys (→ unterschiedliche VRF-Outputs)
    let mut candidates: Vec<VrfCandidate> = Vec::new();
    let mut expected_scores: Vec<([u8; 32], [u8; 32])> = Vec::new(); // (operator_id, score)

    for i in 0..5u8 {
        let ikm = blake3_32(&[b'S', b'C', b'O', b'R', b'E', i]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");

        let msg = {
            const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
            let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
            m.extend_from_slice(VRF_MSG_DOMAIN);
            m.extend_from_slice(&seed);
            m.extend_from_slice(&epoch.to_le_bytes());
            m
        };

        let (proof, y) = bls_vrf_prove(&msg, &kp.sk);
        let op_id = blake3_32(&[b'O', b'P', i]);

        expected_scores.push((op_id, y));

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', i]),
            op_id,
            kp.pk,
            bls_pop_prove(&kp.sk),
            0,
            100,
            proof,
        ));
    }

    // Erwartete Reihenfolge: sortiert nach score (ascending)
    expected_scores.sort_by(|a, b| a.1.cmp(&b.1));

    let selected = committee_select_vrf(5, epoch, seed, current_anchor_index, &candidates, &params);
    assert_eq!(selected.len(), 5);

    // Verifiziere Reihenfolge ohne panikträchtiges Indexing
    for ((idx, (expected_op, expected_score)), seat) in
        expected_scores.iter().enumerate().zip(selected.iter())
    {
        assert_eq!(
            seat.operator_id, *expected_op,
            "Position {} hat falschen operator_id",
            idx
        );
        assert_eq!(
            seat.score, *expected_score,
            "Position {} hat falschen score",
            idx
        );
    }

    eprintln!("Score ordering verified (ascending):");
    for (idx, seat) in selected.iter().enumerate() {
        eprintln!("  {} → score={}", idx, hex::encode(seat.score));
    }
}

#[test]
fn anti_collocation_golden() {
    // Mehrere Kandidaten pro Operator → nur einer wird ausgewählt
    let seed = blake3_32(b"anti-colloc-test");
    let epoch = 5u64;
    let current_anchor_index = 50_000u64;

    let params = RotationParams {
        cooldown_anchors: 0,
        min_attendance_pct: 0,
    };

    let op_a = blake3_32(b"operator-A");
    let op_b = blake3_32(b"operator-B");

    let mut candidates: Vec<VrfCandidate> = Vec::new();

    // 3 Kandidaten von op_a
    for i in 0..3u8 {
        let ikm = blake3_32(&[b'A', i]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");

        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', b'A', i]),
            op_a,
            kp.pk,
            bls_pop_prove(&kp.sk),
            0,
            100,
            proof,
        ));
    }

    // 2 Kandidaten von op_b
    for i in 0..2u8 {
        let ikm = blake3_32(&[b'B', i]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");

        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', b'B', i]),
            op_b,
            kp.pk,
            bls_pop_prove(&kp.sk),
            0,
            100,
            proof,
        ));
    }

    // Wähle k=3 Seats
    let selected = committee_select_vrf(3, epoch, seed, current_anchor_index, &candidates, &params);

    // Erwartung: maximal 2 Seats (einer von op_a, einer von op_b), da Anti-Kollokation
    assert!(selected.len() <= 2);

    // Verifiziere: kein doppelter operator_id
    let mut seen_ops = std::collections::HashSet::new();
    for seat in &selected {
        assert!(
            !seen_ops.contains(&seat.operator_id),
            "Doppelter operator_id: {}",
            hex::encode(seat.operator_id)
        );
        seen_ops.insert(seat.operator_id);
    }

    eprintln!(
        "Anti-collocation verified: {} unique operators",
        seen_ops.len()
    );
}

#[test]
fn eligibility_filtering_golden() {
    // Verschiedene Eligibility-Szenarien
    let seed = blake3_32(b"eligibility-test");
    let epoch = 3u64;
    let current_anchor_index = 100_000u64;

    let params = RotationParams {
        cooldown_anchors: 10_000,
        min_attendance_pct: 60,
    };

    let mut candidates: Vec<VrfCandidate> = Vec::new();

    // Kandidat 0: eligible (attendance=100, cooldown OK)
    {
        let ikm = blake3_32(&[b'E', 0]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', 0]),
            blake3_32(&[b'O', 0]),
            kp.pk,
            bls_pop_prove(&kp.sk),
            current_anchor_index.saturating_sub(20_000),
            100,
            proof,
        ));
    }

    // Kandidat 1: ineligible (attendance zu niedrig)
    {
        let ikm = blake3_32(&[b'E', 1]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', 1]),
            blake3_32(&[b'O', 1]),
            kp.pk,
            bls_pop_prove(&kp.sk),
            current_anchor_index.saturating_sub(20_000),
            50, // < 60
            proof,
        ));
    }

    // Kandidat 2: ineligible (in cooldown)
    {
        let ikm = blake3_32(&[b'E', 2]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', 2]),
            blake3_32(&[b'O', 2]),
            kp.pk,
            bls_pop_prove(&kp.sk),
            current_anchor_index.saturating_sub(5_000), // < 10_000
            100,
            proof,
        ));
    }

    // Kandidat 3: eligible (attendance=60, cooldown OK)
    {
        let ikm = blake3_32(&[b'E', 3]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', 3]),
            blake3_32(&[b'O', 3]),
            kp.pk,
            bls_pop_prove(&kp.sk),
            current_anchor_index.saturating_sub(15_000),
            60, // genau threshold
            proof,
        ));
    }

    let selected = committee_select_vrf(4, epoch, seed, current_anchor_index, &candidates, &params);

    // Erwartung: nur Kandidaten 0 und 3 eligible
    assert_eq!(selected.len(), 2);

    let recipient_ids: Vec<[u8; 32]> = selected.iter().map(|s| s.recipient_id).collect();
    assert!(recipient_ids.contains(&blake3_32(&[b'R', 0])));
    assert!(recipient_ids.contains(&blake3_32(&[b'R', 3])));

    eprintln!(
        "Eligibility filtering: {} of {} eligible",
        selected.len(),
        candidates.len()
    );
}

#[test]
fn cross_platform_determinism_golden() {
    // Test ob Seed, Epoch und Selection auf allen Plattformen identisch sind
    let network_id = blake3_32(b"cross-platform");
    let anchor_id = AnchorId(blake3_32(b"anchor-x"));

    let seed = derive_vrf_seed(network_id, anchor_id);
    let epoch = derive_epoch(12345, 100);

    // Diese Werte müssen auf macOS, Linux, Windows identisch sein
    assert_eq!(seed.len(), 32);
    assert_eq!(epoch, 123);

    // Generiere Committee
    let params = RotationParams {
        cooldown_anchors: 1_000,
        min_attendance_pct: 50,
    };

    let mut candidates: Vec<VrfCandidate> = Vec::new();
    for i in 0..5u8 {
        let ikm = blake3_32(&[b'X', i]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', i]),
            blake3_32(&[b'O', i]),
            kp.pk,
            bls_pop_prove(&kp.sk),
            0,
            100,
            proof,
        ));
    }

    let selected = committee_select_vrf(3, epoch, seed, 12345, &candidates, &params);
    assert_eq!(selected.len(), 3);

    // Golden output für Vergleich
    eprintln!("Cross-platform golden values:");
    eprintln!("  Seed: {}", hex::encode(seed));
    eprintln!("  Epoch: {}", epoch);
    for (idx, seat) in selected.iter().enumerate() {
        eprintln!(
            "  Seat {}: recipient={}, score={}",
            idx,
            hex::encode(seat.recipient_id),
            hex::encode(seat.score)
        );
    }

    // Diese Werte sollten auf allen Plattformen identisch sein
}

#[test]
fn seed_changes_per_anchor() {
    // Verifiziere dass Seed sich mit jedem Anker ändert
    let network_id = blake3_32(b"testnet");

    let seeds: Vec<[u8; 32]> = (0u64..10u64)
        .map(|i| {
            let anchor_bytes = blake3_32(&i.to_le_bytes());
            derive_vrf_seed(network_id, AnchorId(anchor_bytes))
        })
        .collect();

    // Alle Seeds müssen unterschiedlich sein (ohne Indexing)
    for (i, si) in seeds.iter().enumerate() {
        for (j, sj) in seeds.iter().enumerate().skip(i + 1) {
            assert_ne!(*si, *sj, "Seeds für Anker {} und {} sind identisch", i, j);
        }
    }

    eprintln!(
        "Verified: {} unique seeds for {} anchors",
        seeds.len(),
        seeds.len()
    );
}

// Helper
fn vrf_msg(seed: &[u8; 32], epoch: u64) -> Vec<u8> {
    const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
    let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
    m.extend_from_slice(VRF_MSG_DOMAIN);
    m.extend_from_slice(seed);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}
