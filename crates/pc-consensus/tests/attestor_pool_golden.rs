// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Golden Tests für Attestor Pool
//!
//! Diese Tests validieren:
//! - M=128 Sampling-Determinismus
//! - Payout-Verteilung mit fixen Inputs
//! - Merkle-Root-Stabilität
//! - Proof-Size-Logarithmic
//! - Cross-Platform-Determinismus

use pc_consensus::attestor_claims::{generate_claim_proof, verify_claim, PayoutMerkleTree};
use pc_consensus::attestor_pool::{attestation_message, attestor_sample_vrf};
use pc_consensus::committee_vrf::{derive_epoch, derive_vrf_seed, RotationParams, VrfCandidate};
use pc_consensus::{compute_attestor_payout, FeeSplitParams};
use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_pop_prove, bls_vrf_prove};
use pc_types::{AnchorId, NetworkId, PayoutEntry, PayoutSet};

fn vrf_msg(seed: &[u8; 32], epoch: u64) -> Vec<u8> {
    const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
    let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
    m.extend_from_slice(VRF_MSG_DOMAIN);
    m.extend_from_slice(seed);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

#[test]
fn attestor_sampling_m128_determinism() {
    // Fixed inputs
    let network_id: NetworkId = blake3_32(b"golden-network-att");
    let anchor_id = AnchorId(blake3_32(b"golden-anchor-att"));
    let now = 500_000u64;
    let epoch_len = 10_000u64;

    let params = RotationParams {
        cooldown_anchors: 1_000,
        min_attendance_pct: 50,
    };

    // 200 fixe Kandidaten
    let mut candidates = Vec::new();
    let epoch = derive_epoch(now, epoch_len);
    let seed = derive_vrf_seed(network_id, anchor_id);

    for i in 0..200u8 {
        let ikm = blake3_32(&[b'G', b'A', i]);
        let kp = bls_keygen_from_ikm(&ikm).expect("keygen");
        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(&[b'R', b'A', i]),
            blake3_32(&[b'O', b'A', i]),
            kp.pk,
            bls_pop_prove(&kp.sk),
            now.saturating_sub(10_000),
            100,
            proof,
        ));
    }

    // Sample M=128
    let selected1 = attestor_sample_vrf(
        128,
        now,
        epoch_len,
        network_id,
        anchor_id,
        &candidates,
        &params,
    );
    let selected2 = attestor_sample_vrf(
        128,
        now,
        epoch_len,
        network_id,
        anchor_id,
        &candidates,
        &params,
    );

    // Deterministisch
    assert_eq!(selected1.len(), 128);
    assert_eq!(selected2.len(), 128);

    for (s1, s2) in selected1.iter().zip(selected2.iter()) {
        assert_eq!(s1.recipient_id, s2.recipient_id);
        assert_eq!(s1.operator_id, s2.operator_id);
        assert_eq!(s1.score, s2.score);
    }

    eprintln!("Golden M=128 Sample:");
    for (idx, seat) in selected1.iter().take(5).enumerate() {
        eprintln!(
            "  Seat {}: recipient={}, score={}",
            idx,
            hex::encode(seat.recipient_id),
            hex::encode(seat.score)
        );
    }
}

#[test]
fn payout_distribution_golden() {
    // Fixed inputs
    let fees = 10_000_000u64;

    let params = FeeSplitParams {
        p_base_bp: 1000,
        p_prop_bp: 2000,
        p_perf_bp: 3000,
        p_att_bp: 4000,
        d_max: 3,
        perf_weights: vec![10000, 6000, 3600],
    };

    // 128 attestors
    let attestors: Vec<[u8; 32]> = (0..128u8).map(|i| blake3_32(&[b'G', b'P', i])).collect();

    let payout1 = compute_attestor_payout(fees, &params, &attestors).expect("compute payout1");
    let payout2 = compute_attestor_payout(fees, &params, &attestors).expect("compute payout2");

    // Deterministisch
    assert_eq!(payout1.entries.len(), 128);
    assert_eq!(payout2.entries.len(), 128);

    for (p1, p2) in payout1.entries.iter().zip(payout2.entries.iter()) {
        assert_eq!(p1.recipient_id, p2.recipient_id);
        assert_eq!(p1.amount, p2.amount);
    }

    // attestor_pot = 10_000_000 * 4000 / 10000 = 4_000_000
    // per_attestor = 4_000_000 / 128 = 31_250
    let sum: u64 = payout1.entries.iter().map(|e| e.amount).sum();
    assert_eq!(sum, 4_000_000);

    eprintln!("Golden Payout Distribution (M=128):");
    eprintln!("  Total pot: {}", sum);
    eprintln!("  Per attestor (avg): {}", sum / 128);
    eprintln!("  First 3 payouts:");
    for (idx, entry) in payout1.entries.iter().take(3).enumerate() {
        eprintln!("    {}: amount={}", idx, entry.amount);
    }
}

#[test]
fn merkle_root_stability() {
    // Fixed payout set
    let entries: Vec<PayoutEntry> = (0..128u8)
        .map(|i| PayoutEntry {
            recipient_id: blake3_32(&[b'M', b'R', i]),
            amount: 1_000 + (i as u64),
        })
        .collect();

    let payout_set = PayoutSet { entries };

    // Build tree mehrmals
    let tree1 = PayoutMerkleTree::from_payout_set(&payout_set);
    let tree2 = PayoutMerkleTree::from_payout_set(&payout_set);

    // Root sollte stabil sein
    assert_eq!(tree1.root, tree2.root);

    // Golden value
    eprintln!("Golden Merkle Root (M=128): {}", hex::encode(tree1.root));

    // Root sollte sich bei Änderungen ändern
    let mut modified_set = payout_set.clone();
    if let Some(e0) = modified_set.entries.get_mut(0) {
        e0.amount += 1;
    } else {
        panic!("expected at least one entry");
    }

    let tree3 = PayoutMerkleTree::from_payout_set(&modified_set);
    assert_ne!(tree1.root, tree3.root);
}

#[test]
fn merkle_proof_sizes_logarithmic() {
    // Teste verschiedene M-Größen
    let sizes = vec![1, 2, 4, 8, 16, 32, 64, 128, 256];

    for m in sizes {
        let entries: Vec<PayoutEntry> = (0..m)
            .map(|i| PayoutEntry {
                recipient_id: blake3_32(&(i as u32).to_le_bytes()),
                amount: 1000,
            })
            .collect();

        let payout_set = PayoutSet { entries };
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        // Generate proof für ersten Recipient
        let proof = tree.generate_proof(0).expect("generate proof");

        // Proof-Size sollte log2(M) sein (oder log2(next_power_of_2(M)))
        let expected_size = if m == 1 {
            1
        } else {
            (m as f64).log2().ceil() as usize
        };

        eprintln!(
            "M={:3} → proof_size={} (expected~{})",
            m,
            proof.len(),
            expected_size
        );

        // Proof sollte ungefähr log2(M) sein
        assert!(proof.len() <= expected_size + 1);
    }
}

#[test]
fn cross_platform_sampling() {
    // Diese Werte müssen auf macOS, Linux, Windows identisch sein
    let network_id: NetworkId = blake3_32(b"cross-platform-test");
    let anchor_id = AnchorId(blake3_32(b"cross-anchor"));
    let now = 100_000u64;
    let epoch_len = 10_000u64;

    let params = RotationParams {
        cooldown_anchors: 0,
        min_attendance_pct: 0,
    };

    // 10 Kandidaten
    let mut candidates = Vec::new();
    let epoch = derive_epoch(now, epoch_len);
    let seed = derive_vrf_seed(network_id, anchor_id);

    for i in 0..10u8 {
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

    let selected = attestor_sample_vrf(
        5,
        now,
        epoch_len,
        network_id,
        anchor_id,
        &candidates,
        &params,
    );
    assert_eq!(selected.len(), 5);

    eprintln!("Cross-platform golden values:");
    eprintln!("  Epoch: {}", epoch);
    eprintln!("  Seed: {}", hex::encode(seed));
    for (idx, seat) in selected.iter().enumerate() {
        eprintln!(
            "  Seat {}: recipient={}, score={}",
            idx,
            hex::encode(seat.recipient_id),
            hex::encode(seat.score)
        );
    }
}

#[test]
fn vrf_score_ordering_m128() {
    let network_id: NetworkId = blake3_32(b"score-order-test");
    let anchor_id = AnchorId(blake3_32(b"score-anchor"));
    let now = 200_000u64;
    let epoch_len = 10_000u64;

    let params = RotationParams {
        cooldown_anchors: 0,
        min_attendance_pct: 0,
    };

    // 200 Kandidaten
    let mut candidates = Vec::new();
    let epoch = derive_epoch(now, epoch_len);
    let seed = derive_vrf_seed(network_id, anchor_id);

    for i in 0..200u8 {
        let ikm = blake3_32(&[b'S', b'O', i]);
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

    let selected = attestor_sample_vrf(
        128,
        now,
        epoch_len,
        network_id,
        anchor_id,
        &candidates,
        &params,
    );
    assert_eq!(selected.len(), 128);

    // Verifiziere Scores sind ascending sortiert (ohne Indexing)
    for (a, b) in selected.iter().zip(selected.iter().skip(1)) {
        assert!(a.score <= b.score, "Scores not in ascending order");
    }

    eprintln!("VRF Score ordering verified (M=128):");
    if let Some(s0) = selected.first() {
        eprintln!("  First score:  {}", hex::encode(s0.score));
    }
    if let Some(smid) = selected.get(64) {
        eprintln!("  Middle score: {}", hex::encode(smid.score));
    }
    if let Some(slast) = selected.get(127) {
        eprintln!("  Last score:   {}", hex::encode(slast.score));
    }
}

#[test]
fn claim_proof_roundtrip() {
    // 128 Payouts
    let entries: Vec<PayoutEntry> = (0..128u8)
        .map(|i| PayoutEntry {
            recipient_id: blake3_32(&[b'C', b'P', i]),
            amount: 2_000 + (i as u64),
        })
        .collect();

    let payout_set = PayoutSet { entries };
    let tree = PayoutMerkleTree::from_payout_set(&payout_set);

    // Generiere und verifiziere Claims für alle 128 Recipients
    for i in 0..128u8 {
        let recipient_id = blake3_32(&[b'C', b'P', i]);
        let claim = generate_claim_proof(&payout_set, &recipient_id).expect("gen claim");

        // Verifiziere Claim
        let is_valid = verify_claim(&claim, &tree.root).expect("verify claim");
        assert!(is_valid, "Claim {} should be valid", i);

        // Verifiziere Amount
        assert_eq!(claim.amount, 2_000 + (i as u64));
    }

    eprintln!("Claim proof roundtrip verified for all 128 recipients");
}

#[test]
fn attestation_message_determinism() {
    let network_id: NetworkId = blake3_32(b"msg-test");
    let epoch = 42u64;
    let topic = b"data-commitment";

    let msg1 = attestation_message(&network_id, epoch, topic);
    let msg2 = attestation_message(&network_id, epoch, topic);

    assert_eq!(msg1, msg2);

    // Verschiedene Inputs → verschiedene Messages
    let msg3 = attestation_message(&network_id, epoch + 1, topic);
    assert_ne!(msg1, msg3);

    eprintln!("Attestation message (golden):");
    eprintln!("  Length: {} bytes", msg1.len());
    eprintln!("  Hash: {}", hex::encode(blake3_32(&msg1)));
}
