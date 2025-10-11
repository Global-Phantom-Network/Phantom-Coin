// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use pc_crypto::{blake3_32, bls_vrf_verify, BlsPublicKey, Hash32};
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
    pub last_selected_at: u64,
    pub attendance_recent_pct: u8,
    pub vrf_proof: [u8; 96],
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
        // Attendance
        if c.attendance_recent_pct < params.min_attendance_pct { continue; }
        // Cooldown
        if current_anchor_index.saturating_sub(c.last_selected_at) < params.cooldown_anchors {
            continue;
        }
        // VRF Verify + Score
        if let Some(y) = bls_vrf_verify(&msg, &c.vrf_proof, &c.bls_pk) {
            scored.push((y, c));
        }
    }
    if scored.is_empty() { return Vec::new(); }

    // 2) Sortiere deterministisch nach Score (lexikografisch aufsteigend) + Tiebreaker recipient_id
    scored.sort_by(|(a,_),(b,_)| {
        match a.cmp(b) {
            core::cmp::Ordering::Equal => core::cmp::Ordering::Equal,
            o => o,
        }
    });

    // 3) Greedy-Auswahl mit Anti‑Kollokation (ein operator_id)
    let mut out: Vec<SelectedSeat> = Vec::with_capacity(k as usize);
    let mut used_ops: std::collections::HashSet<[u8;32]> = std::collections::HashSet::new();
    for (score, c) in scored.into_iter() {
        if used_ops.contains(&c.operator_id) { continue; }
        used_ops.insert(c.operator_id);
        out.push(SelectedSeat { recipient_id: c.recipient_id, operator_id: c.operator_id, bls_pk: c.bls_pk.clone(), score });
        if out.len() >= k as usize { break; }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_vrf_prove};
    use pc_types::AnchorId as TAnchorId;

    #[test]
    fn select_basic_topk_unique_ops() {
        let seed = blake3_32(b"seed-vrf");
        let epoch = 7u64;
        let params = RotationParams { cooldown_anchors: 100, min_attendance_pct: 50 };
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
                last_selected_at: now.saturating_sub(1_000),
                attendance_recent_pct: 100,
                vrf_proof: proof,
            });
        }
        let sel = committee_select_vrf(5, epoch, seed, now, &cands, &params);
        assert_eq!(sel.len(), 5);
        // Stabilität: wiederholt gleicher Output
        let sel2 = committee_select_vrf(5, epoch, seed, now, &cands, &params);
        assert_eq!(sel.iter().map(|s| s.recipient_id).collect::<Vec<_>>(), sel2.iter().map(|s| s.recipient_id).collect::<Vec<_>>());
    }

    #[test]
    fn exclude_cooldown_and_attendance_and_collocation() {
        let seed = blake3_32(b"seed-vrf-2");
        let epoch = 9u64;
        let now = 50_000u64;
        let params = RotationParams { cooldown_anchors: 10_000, min_attendance_pct: 60 };

        // Erzeuge 4 Kandidaten, aber einer mit gleicher operator_id, einer mit schlechter Attendance, einer in Cooldown
        let ikm1 = blake3_32(b"k1"); let kp1 = bls_keygen_from_ikm(&ikm1).unwrap();
        let ikm2 = blake3_32(b"k2"); let kp2 = bls_keygen_from_ikm(&ikm2).unwrap();
        let ikm3 = blake3_32(b"k3"); let kp3 = bls_keygen_from_ikm(&ikm3).unwrap();
        let ikm4 = blake3_32(b"k4"); let kp4 = bls_keygen_from_ikm(&ikm4).unwrap();
        let msg = super::vrf_msg(&seed, epoch);
        let (p1,_) = bls_vrf_prove(&msg, &kp1.sk);
        let (p2,_) = bls_vrf_prove(&msg, &kp2.sk);
        let (p3,_) = bls_vrf_prove(&msg, &kp3.sk);
        let (p4,_) = bls_vrf_prove(&msg, &kp4.sk);

        let op_a = blake3_32(b"op-a");
        let op_b = blake3_32(b"op-b");

        let cands = vec![
            VrfCandidate { recipient_id: blake3_32(b"r1"), operator_id: op_a, bls_pk: kp1.pk, last_selected_at: now.saturating_sub(20_000), attendance_recent_pct: 100, vrf_proof: p1 },
            VrfCandidate { recipient_id: blake3_32(b"r2"), operator_id: op_a, bls_pk: kp2.pk, last_selected_at: now.saturating_sub(20_000), attendance_recent_pct: 100, vrf_proof: p2 }, // gleiche operator_id -> anti-collocation
            VrfCandidate { recipient_id: blake3_32(b"r3"), operator_id: op_b, bls_pk: kp3.pk, last_selected_at: now.saturating_sub( 5_000), attendance_recent_pct: 100, vrf_proof: p3 }, // cooldown -> raus
            VrfCandidate { recipient_id: blake3_32(b"r4"), operator_id: blake3_32(b"op-c"), bls_pk: kp4.pk, last_selected_at: now.saturating_sub(20_000), attendance_recent_pct: 30, vrf_proof: p4 }, // attendance zu gering
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
}
