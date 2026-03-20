// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use crate::consts::MIN_ATTESTOR_STAKE;
use pc_crypto::{blake3_32, bls_pop_verify, bls_vrf_verify, BlsPublicKey, Hash32};
use pc_types::{AnchorId, NetworkId};

const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";

#[derive(Clone, Debug)]
pub struct RotationParams {
    pub cooldown_anchors: u64,
    pub min_attendance_pct: u8, // 0..=100
}

/// Leitet deterministischen VRF-Seed aus NetworkId und letztem AnchorId ab.
/// seed = blake3_32("pc:vrf:seed:v1" || network_id(32) || last_anchor_id(32))
pub fn derive_vrf_seed(network_id: NetworkId, last_anchor_id: AnchorId) -> Hash32 {
    const SEED_DOMAIN: &[u8] = b"pc:vrf:seed:v1\x01";
    let mut buf = Vec::with_capacity(SEED_DOMAIN.len() + 32 + 32);
    buf.extend_from_slice(SEED_DOMAIN);
    buf.extend_from_slice(&network_id);
    buf.extend_from_slice(&last_anchor_id.0);
    blake3_32(&buf)
}

/// Leitet Shard-spezifischen VRF-Seed aus dem globalen Seed ab.
/// shard_seed = blake3_32("pc:vrf:shard_seed:v1\x01" || global_seed(32) || shard_id.to_le_bytes())
/// Verschiedene Shards erhalten verschiedene Committees bei gleichem Global-Seed.
/// Bei num_shards <= 1 gibt die Funktion den globalen Seed unverändert zurück.
pub fn derive_shard_vrf_seed(global_seed: Hash32, shard_id: u16, num_shards: u16) -> Hash32 {
    if num_shards <= 1 {
        return global_seed;
    }
    const SHARD_SEED_DOMAIN: &[u8] = b"pc:vrf:shard_seed:v1\x01";
    let mut buf = Vec::with_capacity(SHARD_SEED_DOMAIN.len() + 32 + 2);
    buf.extend_from_slice(SHARD_SEED_DOMAIN);
    buf.extend_from_slice(&global_seed);
    buf.extend_from_slice(&shard_id.to_le_bytes());
    blake3_32(&buf)
}

/// Epoch-Ableitung über festen Epochenlängen-Parameter (>=1): epoch = floor(current_anchor_index / epoch_len)
pub fn derive_epoch(current_anchor_index: u64, epoch_len: u64) -> u64 {
    let el = core::cmp::max(1u64, epoch_len);
    current_anchor_index / el
}

#[derive(Clone, Debug)]
pub struct VrfCandidate {
    pub recipient_id: [u8; 32],
    pub operator_id: [u8; 32],
    pub bls_pk: BlsPublicKey,
    pub bls_pop: [u8; 96],
    pub last_selected_at: u64,
    pub attendance_recent_pct: u8,
    pub vrf_proof: [u8; 96],
    /// M3-Fix: Aktueller Stake des Kandidaten in Basis-Einheiten.
    /// M3-Fix: Current stake of the candidate in base units.
    /// Default: MIN_ATTESTOR_STAKE für Abwärtskompatibilität.
    /// Default: MIN_ATTESTOR_STAKE for backwards compatibility.
    #[cfg_attr(test, allow(dead_code))]
    pub stake: u64,
}

impl VrfCandidate {
    /// Erstellt VrfCandidate mit Default-Stake (für Abwärtskompatibilität).
    /// Creates VrfCandidate with default stake (for backwards compatibility).
    pub fn new(
        recipient_id: [u8; 32],
        operator_id: [u8; 32],
        bls_pk: BlsPublicKey,
        bls_pop: [u8; 96],
        last_selected_at: u64,
        attendance_recent_pct: u8,
        vrf_proof: [u8; 96],
    ) -> Self {
        Self {
            recipient_id,
            operator_id,
            bls_pk,
            bls_pop,
            last_selected_at,
            attendance_recent_pct,
            vrf_proof,
            stake: MIN_ATTESTOR_STAKE,
        }
    }

    /// Erstellt VrfCandidate mit explizitem Stake.
    /// Creates VrfCandidate with explicit stake.
    #[allow(clippy::too_many_arguments)]
    pub fn with_stake(
        recipient_id: [u8; 32],
        operator_id: [u8; 32],
        bls_pk: BlsPublicKey,
        bls_pop: [u8; 96],
        last_selected_at: u64,
        attendance_recent_pct: u8,
        vrf_proof: [u8; 96],
        stake: u64,
    ) -> Self {
        Self {
            recipient_id,
            operator_id,
            bls_pk,
            bls_pop,
            last_selected_at,
            attendance_recent_pct,
            vrf_proof,
            stake,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SelectedSeat {
    pub recipient_id: [u8; 32],
    pub operator_id: [u8; 32],
    pub bls_pk: BlsPublicKey,
    pub score: Hash32,
}

fn vrf_msg(seed: &Hash32, epoch: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
    m.extend_from_slice(VRF_MSG_DOMAIN);
    m.extend_from_slice(seed);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

/// Wählt deterministisch k Seats aus, basierend auf VRF-Scores (niedrigere Hashes bevorzugt),
/// unter Beachtung von Anti‑Kollokation (ein Seat pro operator_id), Eligibility (Attendance, Cooldown).
pub fn committee_select_vrf(
    k: u8,
    epoch: u64,
    seed: Hash32,
    current_anchor_index: u64,
    candidates: &[VrfCandidate],
    params: &RotationParams,
) -> Vec<SelectedSeat> {
    if k == 0 || candidates.is_empty() {
        return Vec::new();
    }
    // 1) Vorfilter: Eligibility
    let msg = vrf_msg(&seed, epoch);
    let mut scored: Vec<(Hash32, &VrfCandidate)> = Vec::with_capacity(candidates.len());
    for c in candidates {
        // M3-Fix: Stake-Minimum prüfen
        // M3-Fix: Check minimum stake requirement
        if c.stake < MIN_ATTESTOR_STAKE {
            continue;
        }
        // Attendance
        if c.attendance_recent_pct < params.min_attendance_pct {
            continue;
        }
        // Cooldown
        if current_anchor_index.saturating_sub(c.last_selected_at) < params.cooldown_anchors {
            continue;
        }
        // BLS PoP Verify (rogue-key mitigation)
        if !bls_pop_verify(&c.bls_pk, &c.bls_pop) {
            continue;
        }
        // VRF Verify + Score
        if let Some(y) = bls_vrf_verify(&msg, &c.vrf_proof, &c.bls_pk) {
            scored.push((y, c));
        }
    }
    if scored.is_empty() {
        return Vec::new();
    }

    // 2) Sortiere deterministisch nach Score (lexikografisch aufsteigend) + Tiebreaker recipient_id
    scored.sort_by(|(a, _), (b, _)| match a.cmp(b) {
        core::cmp::Ordering::Equal => core::cmp::Ordering::Equal,
        o => o,
    });

    // 3) Greedy-Auswahl mit Anti‑Kollokation (ein operator_id)
    let mut out: Vec<SelectedSeat> = Vec::with_capacity(k as usize);
    let mut used_ops: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for (score, c) in scored.into_iter() {
        if used_ops.contains(&c.operator_id) {
            continue;
        }
        used_ops.insert(c.operator_id);
        out.push(SelectedSeat {
            recipient_id: c.recipient_id,
            operator_id: c.operator_id,
            bls_pk: c.bls_pk.clone(),
            score,
        });
        if out.len() >= k as usize {
            break;
        }
    }
    out
}

/// Verteilt verifizierte Kandidaten auf `num_shards` Committees (je k Seats).
///
/// Ablauf:
/// 1. VRF-Verifikation + Eligibility-Filter mit dem **globalen** Seed (einmal).
/// 2. Pro Shard: Score re-hashen mit `derive_shard_vrf_seed` → deterministisch
///    verschiedene Sortierungen → verschiedene Top-K pro Shard.
///
/// Gibt eine Map shard_id → Vec<SelectedSeat> zurück.
pub fn committee_select_vrf_sharded(
    k: u8,
    epoch: u64,
    global_seed: Hash32,
    current_anchor_index: u64,
    candidates: &[VrfCandidate],
    params: &RotationParams,
    num_shards: u16,
) -> std::collections::HashMap<u16, Vec<SelectedSeat>> {
    let mut result = std::collections::HashMap::new();
    if k == 0 || candidates.is_empty() || num_shards == 0 {
        return result;
    }

    // 1) Globale VRF-Verifikation + Eligibility (einmalig)
    let msg = vrf_msg(&global_seed, epoch);
    let mut verified: Vec<(Hash32, &VrfCandidate)> = Vec::with_capacity(candidates.len());
    for c in candidates {
        if c.stake < MIN_ATTESTOR_STAKE {
            continue;
        }
        if c.attendance_recent_pct < params.min_attendance_pct {
            continue;
        }
        if current_anchor_index.saturating_sub(c.last_selected_at) < params.cooldown_anchors {
            continue;
        }
        if !bls_pop_verify(&c.bls_pk, &c.bls_pop) {
            continue;
        }
        if let Some(y) = bls_vrf_verify(&msg, &c.vrf_proof, &c.bls_pk) {
            verified.push((y, c));
        }
    }

    // 2) Pro Shard: Re-Hash der Scores → shard-spezifische Sortierung → Top-K
    for shard_id in 0..num_shards {
        let shard_seed = derive_shard_vrf_seed(global_seed, shard_id, num_shards);
        let mut shard_scored: Vec<(Hash32, &VrfCandidate)> = verified
            .iter()
            .map(|(vrf_score, c)| {
                // Deterministischer Re-Hash: blake3(shard_seed || vrf_score)
                let mut buf = Vec::with_capacity(32 + 32);
                buf.extend_from_slice(&shard_seed);
                buf.extend_from_slice(vrf_score);
                let shard_score = blake3_32(&buf);
                (shard_score, *c)
            })
            .collect();

        shard_scored.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut seats: Vec<SelectedSeat> = Vec::with_capacity(k as usize);
        let mut used_ops: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for (score, c) in shard_scored {
            if used_ops.contains(&c.operator_id) {
                continue;
            }
            used_ops.insert(c.operator_id);
            seats.push(SelectedSeat {
                recipient_id: c.recipient_id,
                operator_id: c.operator_id,
                bls_pk: c.bls_pk.clone(),
                score,
            });
            if seats.len() >= k as usize {
                break;
            }
        }
        result.insert(shard_id, seats);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_pop_prove, bls_vrf_prove};
    use pc_types::AnchorId as TAnchorId;

    #[test]
    fn select_basic_topk_unique_ops() {
        let seed = blake3_32(b"seed-vrf");
        let epoch = 7u64;
        let params = RotationParams {
            cooldown_anchors: 100,
            min_attendance_pct: 50,
        };
        let now = 10_000u64;

        // 8 Kandidaten, unterschiedliche operator_id
        let mut cands: Vec<VrfCandidate> = Vec::new();
        for i in 0..8u8 {
            let ikm = blake3_32(&[b'k', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _y) = bls_vrf_prove(&msg, &kp.sk);
            let op = blake3_32(&[b'o', i]);
            let rcpt = blake3_32(&[b'r', i]);
            cands.push(VrfCandidate {
                recipient_id: rcpt,
                operator_id: op,
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: now.saturating_sub(1_000),
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }
        let sel = committee_select_vrf(5, epoch, seed, now, &cands, &params);
        assert_eq!(sel.len(), 5);
        // Stabilität: wiederholt gleicher Output
        let sel2 = committee_select_vrf(5, epoch, seed, now, &cands, &params);
        assert_eq!(
            sel.iter().map(|s| s.recipient_id).collect::<Vec<_>>(),
            sel2.iter().map(|s| s.recipient_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn exclude_cooldown_and_attendance_and_collocation() {
        let seed = blake3_32(b"seed-vrf-2");
        let epoch = 9u64;
        let now = 50_000u64;
        let params = RotationParams {
            cooldown_anchors: 10_000,
            min_attendance_pct: 60,
        };

        // Erzeuge 4 Kandidaten, aber einer mit gleicher operator_id, einer mit schlechter Attendance, einer in Cooldown
        let ikm1 = blake3_32(b"k1");
        let kp1 = bls_keygen_from_ikm(&ikm1).unwrap();
        let ikm2 = blake3_32(b"k2");
        let kp2 = bls_keygen_from_ikm(&ikm2).unwrap();
        let ikm3 = blake3_32(b"k3");
        let kp3 = bls_keygen_from_ikm(&ikm3).unwrap();
        let ikm4 = blake3_32(b"k4");
        let kp4 = bls_keygen_from_ikm(&ikm4).unwrap();
        let msg = super::vrf_msg(&seed, epoch);
        let (p1, _) = bls_vrf_prove(&msg, &kp1.sk);
        let (p2, _) = bls_vrf_prove(&msg, &kp2.sk);
        let (p3, _) = bls_vrf_prove(&msg, &kp3.sk);
        let (p4, _) = bls_vrf_prove(&msg, &kp4.sk);

        let op_a = blake3_32(b"op-a");
        let op_b = blake3_32(b"op-b");

        let cands = vec![
            VrfCandidate {
                recipient_id: blake3_32(b"r1"),
                operator_id: op_a,
                bls_pk: kp1.pk,
                bls_pop: bls_pop_prove(&kp1.sk),
                last_selected_at: now.saturating_sub(20_000),
                attendance_recent_pct: 100,
                vrf_proof: p1,
                stake: MIN_ATTESTOR_STAKE,
            },
            VrfCandidate {
                recipient_id: blake3_32(b"r2"),
                operator_id: op_a,
                bls_pk: kp2.pk,
                bls_pop: bls_pop_prove(&kp2.sk),
                last_selected_at: now.saturating_sub(20_000),
                attendance_recent_pct: 100,
                vrf_proof: p2,
                stake: MIN_ATTESTOR_STAKE,
            }, // gleiche operator_id -> anti-collocation
            VrfCandidate {
                recipient_id: blake3_32(b"r3"),
                operator_id: op_b,
                bls_pk: kp3.pk,
                bls_pop: bls_pop_prove(&kp3.sk),
                last_selected_at: now.saturating_sub(5_000),
                attendance_recent_pct: 100,
                vrf_proof: p3,
                stake: MIN_ATTESTOR_STAKE,
            }, // cooldown -> raus
            VrfCandidate {
                recipient_id: blake3_32(b"r4"),
                operator_id: blake3_32(b"op-c"),
                bls_pk: kp4.pk,
                bls_pop: bls_pop_prove(&kp4.sk),
                last_selected_at: now.saturating_sub(20_000),
                attendance_recent_pct: 30,
                vrf_proof: p4,
                stake: MIN_ATTESTOR_STAKE,
            }, // attendance zu gering
        ];

        let sel = committee_select_vrf(2, epoch, seed, now, &cands, &params);
        // Erwartung: nur 1 Seat (von op_a einer, op_b raus wegen cooldown, op-c wegen attendance)
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].operator_id, op_a);
    }

    #[test]
    fn seed_and_epoch_derivation_deterministic() {
        let nid = blake3_32(b"nid");
        let aid = blake3_32(b"aid");
        let s1 = derive_vrf_seed(nid, TAnchorId(aid));
        let s2 = derive_vrf_seed(nid, TAnchorId(aid));
        assert_eq!(s1, s2);
        // epoch derivation
        assert_eq!(derive_epoch(0, 10), 0);
        assert_eq!(derive_epoch(9, 10), 0);
        assert_eq!(derive_epoch(10, 10), 1);
        assert_eq!(derive_epoch(25, 10), 2);
        // epoch_len clamp to >=1
        assert_eq!(derive_epoch(7, 0), 7);
    }

    #[test]
    fn select_k_zero_returns_empty() {
        let seed = blake3_32(b"k-zero");
        let epoch = 1u64;
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 0,
        };
        let ikm = blake3_32(b"k0");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let msg = super::vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        let cands = vec![VrfCandidate {
            recipient_id: blake3_32(b"r0"),
            operator_id: blake3_32(b"o0"),
            bls_pk: kp.pk,
            bls_pop: bls_pop_prove(&kp.sk),
            last_selected_at: 0,
            attendance_recent_pct: 100,
            vrf_proof: proof,
            stake: MIN_ATTESTOR_STAKE,
        }];

        let sel = committee_select_vrf(0, epoch, seed, 1000, &cands, &params);
        assert_eq!(sel.len(), 0);
    }

    #[test]
    fn select_empty_candidates_returns_empty() {
        let seed = blake3_32(b"empty-cands");
        let epoch = 1u64;
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 0,
        };

        let sel = committee_select_vrf(5, epoch, seed, 1000, &[], &params);
        assert_eq!(sel.len(), 0);
    }

    #[test]
    fn select_all_in_cooldown_returns_empty() {
        let seed = blake3_32(b"all-cooldown");
        let epoch = 10u64;
        let now = 10_000u64;
        let params = RotationParams {
            cooldown_anchors: 5_000,
            min_attendance_pct: 0,
        };

        let mut cands = Vec::new();
        for i in 0..5u8 {
            let ikm = blake3_32(&[b'c', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(&[b'r', i]),
                operator_id: blake3_32(&[b'o', i]),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: now.saturating_sub(1_000), // in cooldown
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let sel = committee_select_vrf(3, epoch, seed, now, &cands, &params);
        assert_eq!(sel.len(), 0);
    }

    #[test]
    fn select_all_under_attendance_threshold() {
        let seed = blake3_32(b"low-att");
        let epoch = 5u64;
        let now = 50_000u64;
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 80,
        };

        let mut cands = Vec::new();
        for i in 0..5u8 {
            let ikm = blake3_32(&[b'a', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(&[b'r', i]),
                operator_id: blake3_32(&[b'o', i]),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 50, // unter threshold
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let sel = committee_select_vrf(3, epoch, seed, now, &cands, &params);
        assert_eq!(sel.len(), 0);
    }

    #[test]
    fn epoch_transition_changes_selection() {
        let seed = blake3_32(b"epoch-trans");
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 0,
        };

        let mut cands = Vec::new();
        for i in 0..5u8 {
            let ikm = blake3_32(&[b'e', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();

            // Für epoch 1
            let msg1 = super::vrf_msg(&seed, 1);
            let (proof1, _) = bls_vrf_prove(&msg1, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(&[b'r', i]),
                operator_id: blake3_32(&[b'o', i]),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 100,
                vrf_proof: proof1,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let sel1 = committee_select_vrf(3, 1, seed, 10_000, &cands, &params);

        // Für epoch 2: neue Proofs benötigt
        let mut cands2 = Vec::new();
        for i in 0..5u8 {
            let ikm = blake3_32(&[b'e', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg2 = super::vrf_msg(&seed, 2);
            let (proof2, _) = bls_vrf_prove(&msg2, &kp.sk);

            cands2.push(VrfCandidate {
                recipient_id: blake3_32(&[b'r', i]),
                operator_id: blake3_32(&[b'o', i]),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 100,
                vrf_proof: proof2,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let sel2 = committee_select_vrf(3, 2, seed, 20_000, &cands2, &params);

        // Committees sollten unterschiedlich sein (VRF-Output ändert sich mit Epoch)
        assert_eq!(sel1.len(), 3);
        assert_eq!(sel2.len(), 3);

        // Mindestens ein Seat sollte sich unterscheiden
        let recipients1: Vec<_> = sel1.iter().map(|s| s.recipient_id).collect();
        let recipients2: Vec<_> = sel2.iter().map(|s| s.recipient_id).collect();

        let different = recipients1
            .iter()
            .zip(recipients2.iter())
            .any(|(a, b)| a != b);
        assert!(different, "Committees should differ between epochs");
    }

    #[test]
    fn large_candidate_pool_performance() {
        // Test mit vielen Kandidaten (Skalierbarkeitstest)
        let seed = blake3_32(b"large-pool");
        let epoch = 7u64;
        let now = 70_000u64;
        let params = RotationParams {
            cooldown_anchors: 1_000,
            min_attendance_pct: 50,
        };

        let mut cands = Vec::new();
        for i in 0..100u16 {
            let ikm = blake3_32(&i.to_le_bytes());
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(&[b'R', (i % 256) as u8]),
                operator_id: blake3_32(&[b'O', (i % 256) as u8]),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: now.saturating_sub(10_000),
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let start = std::time::Instant::now();
        let sel = committee_select_vrf(21, epoch, seed, now, &cands, &params);
        let elapsed = start.elapsed();

        assert!(sel.len() <= 21);
        let budget_ms: u128 = if cfg!(debug_assertions) { 5_000 } else { 1_500 };
        assert!(
            elapsed.as_millis() < budget_ms,
            "Should complete within {}ms (elapsed={}ms)",
            budget_ms,
            elapsed.as_millis()
        );

        // Deterministisch: wiederhole und erwarte gleiches Ergebnis
        let sel2 = committee_select_vrf(21, epoch, seed, now, &cands, &params);
        assert_eq!(sel.len(), sel2.len());
        for (a, b) in sel.iter().zip(sel2.iter()) {
            assert_eq!(a.recipient_id, b.recipient_id);
        }
    }

    #[test]
    fn operator_id_many_collisions() {
        // Viele Kandidaten, aber nur 2 unique operator_ids
        let seed = blake3_32(b"collisions");
        let epoch = 3u64;
        let now = 30_000u64;
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 0,
        };

        let op_a = blake3_32(b"op-A");
        let op_b = blake3_32(b"op-B");

        let mut cands = Vec::new();
        for i in 0..10u8 {
            let ikm = blake3_32(&[b'x', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            let op = if i < 7 { op_a } else { op_b };

            cands.push(VrfCandidate {
                recipient_id: blake3_32(&[b'r', i]),
                operator_id: op,
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let sel = committee_select_vrf(5, epoch, seed, now, &cands, &params);

        // Anti-Kollokation: maximal 2 Seats (einer von op_a, einer von op_b)
        assert!(sel.len() <= 2);

        let mut seen_ops = std::collections::HashSet::new();
        for s in &sel {
            seen_ops.insert(s.operator_id);
        }
        assert_eq!(seen_ops.len(), sel.len());
    }

    #[test]
    fn invalid_vrf_proof_rejected() {
        let seed = blake3_32(b"invalid-proof");
        let epoch = 1u64;
        let now = 10_000u64;
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 0,
        };

        let ikm = blake3_32(b"inv");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();

        // Erstelle FALSCHEN Proof (für falsches Message)
        let wrong_msg = b"wrong-message";
        let (wrong_proof, _) = bls_vrf_prove(wrong_msg, &kp.sk);

        let cands = vec![VrfCandidate {
            recipient_id: blake3_32(b"r-inv"),
            operator_id: blake3_32(b"o-inv"),
            bls_pk: kp.pk,
            bls_pop: bls_pop_prove(&kp.sk),
            last_selected_at: 0,
            attendance_recent_pct: 100,
            vrf_proof: wrong_proof, // falscher Proof
            stake: MIN_ATTESTOR_STAKE,
        }];

        let sel = committee_select_vrf(1, epoch, seed, now, &cands, &params);
        // Falscher Proof wird abgelehnt
        assert_eq!(sel.len(), 0);
    }

    #[test]
    fn attendance_boundary_cases() {
        let seed = blake3_32(b"att-bound");
        let epoch = 2u64;
        let now = 20_000u64;
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 60,
        };

        let mut cands = Vec::new();

        // Kandidat mit attendance = 59 (unter threshold)
        {
            let ikm = blake3_32(b"a59");
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(b"r59"),
                operator_id: blake3_32(b"o59"),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 59,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        // Kandidat mit attendance = 60 (genau threshold)
        {
            let ikm = blake3_32(b"a60");
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(b"r60"),
                operator_id: blake3_32(b"o60"),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 60,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        // Kandidat mit attendance = 61 (über threshold)
        {
            let ikm = blake3_32(b"a61");
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(b"r61"),
                operator_id: blake3_32(b"o61"),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 61,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let sel = committee_select_vrf(3, epoch, seed, now, &cands, &params);

        // Nur die mit attendance >= 60 sollten ausgewählt werden
        assert_eq!(sel.len(), 2);

        let recipients: Vec<_> = sel.iter().map(|s| s.recipient_id).collect();
        assert!(recipients.contains(&blake3_32(b"r60")));
        assert!(recipients.contains(&blake3_32(b"r61")));
        assert!(!recipients.contains(&blake3_32(b"r59")));
    }

    #[test]
    fn cooldown_zero_no_filtering() {
        let seed = blake3_32(b"cool-zero");
        let epoch = 1u64;
        let now = 100_000u64;
        let params = RotationParams {
            cooldown_anchors: 0, // kein cooldown
            min_attendance_pct: 0,
        };

        let mut cands = Vec::new();
        for i in 0..5u8 {
            let ikm = blake3_32(&[b'z', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(&[b'r', i]),
                operator_id: blake3_32(&[b'o', i]),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: now.saturating_sub(1), // gerade erst selected
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE,
            });
        }

        let sel = committee_select_vrf(3, epoch, seed, now, &cands, &params);
        // Alle eligible trotz last_selected_at = now-1
        assert_eq!(sel.len(), 3);
    }

    #[test]
    fn shard_seed_single_shard_passthrough() {
        let global = blake3_32(b"global-seed");
        assert_eq!(
            derive_shard_vrf_seed(global, 0, 0),
            global,
            "num_shards=0 must return global seed unchanged"
        );
        assert_eq!(
            derive_shard_vrf_seed(global, 0, 1),
            global,
            "num_shards=1 must return global seed unchanged"
        );
    }

    #[test]
    fn shard_seed_different_shards_diverge() {
        let global = blake3_32(b"multi-seed");
        let s0 = derive_shard_vrf_seed(global, 0, 4);
        let s1 = derive_shard_vrf_seed(global, 1, 4);
        let s2 = derive_shard_vrf_seed(global, 2, 4);
        let s3 = derive_shard_vrf_seed(global, 3, 4);
        assert_ne!(s0, s1);
        assert_ne!(s0, s2);
        assert_ne!(s0, s3);
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s2, s3);
    }

    #[test]
    fn shard_seed_deterministic() {
        let global = blake3_32(b"det-seed");
        let a = derive_shard_vrf_seed(global, 2, 8);
        let b = derive_shard_vrf_seed(global, 2, 8);
        assert_eq!(a, b, "same inputs must produce same shard seed");
    }

    #[test]
    fn m3_insufficient_stake_rejected() {
        // M3-Fix Test: Kandidaten ohne ausreichend Stake werden abgelehnt.
        // M3-Fix Test: Candidates without sufficient stake are rejected.
        let seed = blake3_32(b"stake-test");
        let epoch = 5u64;
        let now = 50_000u64;
        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 0,
        };

        let mut cands = Vec::new();

        // Kandidat mit ausreichend Stake
        {
            let ikm = blake3_32(b"good-stake");
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(b"r-good"),
                operator_id: blake3_32(b"o-good"),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE, // genau Minimum
            });
        }

        // Kandidat mit zu wenig Stake
        {
            let ikm = blake3_32(b"bad-stake");
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(b"r-bad"),
                operator_id: blake3_32(b"o-bad"),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: MIN_ATTESTOR_STAKE - 1, // unter Minimum
            });
        }

        // Kandidat mit 0 Stake
        {
            let ikm = blake3_32(b"zero-stake");
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = super::vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

            cands.push(VrfCandidate {
                recipient_id: blake3_32(b"r-zero"),
                operator_id: blake3_32(b"o-zero"),
                bls_pk: kp.pk,
                bls_pop: bls_pop_prove(&kp.sk),
                last_selected_at: 0,
                attendance_recent_pct: 100,
                vrf_proof: proof,
                stake: 0, // kein Stake
            });
        }

        let sel = committee_select_vrf(3, epoch, seed, now, &cands, &params);

        // Nur der Kandidat mit ausreichend Stake sollte ausgewählt werden
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].recipient_id, blake3_32(b"r-good"));
    }
}
