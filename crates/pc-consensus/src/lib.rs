// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

use pc_types::{
    Amount, AnchorHeader, AnchorId, AnchorIndex, EvidenceKind, MintEvent, PayoutEntry, PayoutSet,
};
use pc_types::{AnchorHeaderV2, AnchorPayloadV2, GenesisNote};
use pc_types::{genesis_payload_root, digest_genesis_note, payload_merkle_root_v2, NetworkId};
pub mod consts;
pub mod committee_vrf;
pub mod attestor_pool;

#[derive(Debug)]
pub enum ConsensusError {
    IndexOutOfRange,
    InvalidParams,
}

// ============================
// Leere Anker (V2, i>0)
// ============================
/// Ein V2‑Payload gilt als "leer", wenn keine Transaktionen/Mints/Claims/Evidences enthalten sind
/// und keine Genesis‑Note eingebettet ist. Der `payout_root` darf 0x00..00 sein.
#[inline]
pub fn is_empty_anchor_v2(p: &AnchorPayloadV2) -> bool {
    p.genesis_note.is_none()
        && p.micro_txs.is_empty()
        && p.mints.is_empty()
        && p.claims.is_empty()
        && p.evidences.is_empty()
}

/// Validiert einen leeren V2‑Anker gegen den berechneten Payload‑Merkle‑Root.
/// Für i>0 muss `is_empty_anchor_v2(payload)` gelten und `header.payload_hash`
/// muss `payload_merkle_root_v2(payload)` entsprechen.
pub fn validate_empty_anchor_v2(h: &AnchorHeaderV2, p: &AnchorPayloadV2) -> Result<(), ConsensusError> {
    if !is_empty_anchor_v2(p) {
        return Err(ConsensusError::InvalidParams);
    }
    let root = payload_merkle_root_v2(p);
    if h.payload_hash != root {
        return Err(ConsensusError::InvalidParams);
    }
    Ok(())
}

// ============================
// Genesis A0 Validierung (V2)
// ============================
/// Prüft A0 gemäß Spezifikation und liefert die abgeleitete NetworkId zurück.
/// Regeln:
/// - parents.len == 0 (Genesis hat keinen Vorgänger)
/// - payload_root == genesis_payload_root(genesis_note)
/// - header.network_id == digest_genesis_note(genesis_note)
/// - Parameter-Constraints (committee_k in 1..=64, shards_initial>=1, txs_per_payload>=1)
pub fn validate_genesis_anchor(h: &AnchorHeaderV2, p: &AnchorPayloadV2) -> Result<NetworkId, ConsensusError> {
    // Versionen prüfen
    if h.version != 2 || p.version != 2 {
        return Err(ConsensusError::InvalidParams);
    }
    // Keine Parents
    if (h.parents.len as usize) != 0 {
        return Err(ConsensusError::InvalidParams);
    }
    // Genesis-Note muss vorhanden sein
    let note: &GenesisNote = match p.genesis_note.as_ref() {
        Some(n) => n,
        None => return Err(ConsensusError::InvalidParams),
    };
    // Param-Constraints
    if !(note.params.committee_k >= 1 && note.params.committee_k <= 64) {
        return Err(ConsensusError::InvalidParams);
    }
    if note.params.shards_initial < 1 { return Err(ConsensusError::InvalidParams); }
    if note.params.txs_per_payload < 1 { return Err(ConsensusError::InvalidParams); }

    let pl_root = genesis_payload_root(note);
    if h.payload_hash != pl_root { return Err(ConsensusError::InvalidParams); }
    let nid = digest_genesis_note(note);
    if h.network_id != nid { return Err(ConsensusError::InvalidParams); }
    Ok(nid)
}

#[cfg(test)]
mod genesis_tests {
    use super::*;
    #[test]
    fn validate_genesis_anchor_ok() {
        let note = GenesisNote { version:0, network_name:b"phantom-dev".to_vec(), seed:[0x42;32], params: pc_types::GenesisParams{ shards_initial:64, committee_k:21, txs_per_payload:256, features:0 } };
        let pl = AnchorPayloadV2 { version:2, micro_txs:vec![], mints:vec![], claims:vec![], evidences:vec![], payout_root: genesis_payload_root(&note), genesis_note: Some(note.clone()) };
        let h = AnchorHeaderV2 { version:2, shard_id:0, parents: pc_types::ParentList::default(), payload_hash: genesis_payload_root(&note), creator_index:0, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]), network_id: digest_genesis_note(&note) };
        let nid = validate_genesis_anchor(&h, &pl).expect("valid");
        assert_eq!(nid, digest_genesis_note(&note));
    }
    #[test]
    fn validate_genesis_anchor_fails_on_params() {
        let bad = GenesisNote { version:0, network_name:b"x".to_vec(), seed:[0;32], params: pc_types::GenesisParams{ shards_initial:0, committee_k:0, txs_per_payload:0, features:0 } };
        let pl = AnchorPayloadV2 { version:2, micro_txs:vec![], mints:vec![], claims:vec![], evidences:vec![], payout_root: genesis_payload_root(&bad), genesis_note: Some(bad.clone()) };
        let h = AnchorHeaderV2 { version:2, shard_id:0, parents: pc_types::ParentList::default(), payload_hash: genesis_payload_root(&bad), creator_index:0, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]), network_id: digest_genesis_note(&bad) };
        assert!(validate_genesis_anchor(&h, &pl).is_err());
    }
}

/// Komfort: Erzeugt Attestor-Payout direkt aus BLS-Public-Keys (IDs via Domain-Hash)
pub fn compute_attestor_payout_from_bls(
    fees_total: Amount,
    params: &FeeSplitParams,
    bls_pks: &[pc_crypto::BlsPublicKey],
) -> Result<PayoutSet, ConsensusError> {
    let ids: Vec<[u8; 32]> = bls_pks
        .iter()
        .map(|pk| pc_crypto::attestor_recipient_id_from_bls(pk))
        .collect();
    compute_attestor_payout(fees_total, params, &ids)
}

#[inline]
pub fn finality_threshold(k: u8) -> u8 {
    ((2 * k) / 3) + 1
}

#[inline]
pub fn is_final(popcount: u8, k: u8) -> bool {
    popcount >= finality_threshold(k)
}

#[inline]
pub fn popcount_u64(x: u64) -> u8 {
    x.count_ones() as u8
}

impl core::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IndexOutOfRange => write!(f, "index out of range"),
            Self::InvalidParams => write!(f, "invalid fee split params"),
        }
    }
}

impl std::error::Error for ConsensusError {}

#[inline]
pub fn set_bit(mask: u64, index: u8) -> Result<u64, ConsensusError> {
    if index >= 64 {
        return Err(ConsensusError::IndexOutOfRange);
    }
    let bit = 1u64 << (index as u64);
    Ok(mask | bit)
}

/// Prüft uhrfrei, ob zwischen `minted_at` und `current` mindestens `threshold` Anker vergangen sind.
#[inline]
pub fn maturity_reached(current: AnchorIndex, minted_at: AnchorIndex, threshold: u64) -> bool {
    current.saturating_sub(minted_at) >= threshold
}

/// Liefert die Maturity-Stufe (0..=3) relativ zu L1/L2/L3 Schwellen.
/// 0 = < L1, 1 = ≥L1, 2 = ≥L2, 3 = ≥L3
#[inline]
pub fn maturity_level(current: AnchorIndex, minted_at: AnchorIndex) -> u8 {
    let d = current.saturating_sub(minted_at);
    if d >= consts::MATURITY_L3 {
        3
    } else if d >= consts::MATURITY_L2 {
        2
    } else if d >= consts::MATURITY_L1 {
        1
    } else {
        0
    }
}

/// Fee-Split Parameter in Basispunkten (Summe = 10_000)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSplitParams {
    pub p_base_bp: u16,
    pub p_prop_bp: u16,
    pub p_perf_bp: u16,
    pub p_att_bp: u16,
    pub d_max: u8,
    /// Gewichte für d=1..=d_max (streng monoton fallend, z. B. [10000, 6000, 3600, 2160, ...])
    pub perf_weights: Vec<u32>,
}

impl FeeSplitParams {
    pub fn validate(&self) -> Result<(), ConsensusError> {
        let sum = (self.p_base_bp as u32)
            + (self.p_prop_bp as u32)
            + (self.p_perf_bp as u32)
            + (self.p_att_bp as u32);
        if sum != 10_000 {
            return Err(ConsensusError::InvalidParams);
        }
        if self.d_max as usize != self.perf_weights.len() {
            return Err(ConsensusError::InvalidParams);
        }
        if self.perf_weights.is_empty() {
            return Err(ConsensusError::InvalidParams);
        }
        // Monoton fallend (sicher ohne Indexing)
        for w in self.perf_weights.windows(2) {
            if let [a, b] = w {
                if a < b {
                    return Err(ConsensusError::InvalidParams);
                }
            }
        }
        Ok(())
    }

    /// Empfohlene Startwerte: p_base=65%, p_prop=10%, p_perf=15%, p_att=10%, α=0.6, D_max=8
    pub fn recommended() -> Self {
        let p_base_bp = consts::P_BASE_BP;
        let p_prop_bp = consts::P_PROP_BP;
        let p_perf_bp = consts::P_PERF_BP;
        let p_att_bp = consts::P_ATT_BP;
        let d_max = consts::D_MAX;
        let w = consts::perf_weights_recommended();
        Self {
            p_base_bp,
            p_prop_bp,
            p_perf_bp,
            p_att_bp,
            d_max,
            perf_weights: w,
        }
    }
}

fn split_bp(total: Amount, bp: u16) -> Amount {
    // floor(total * bp / 10_000)
    (total / 10_000) * (bp as u64) + ((total % 10_000) * (bp as u64)) / 10_000
}

fn distribute_equal(total: Amount, recipients: &[[u8; 32]]) -> Vec<Amount> {
    let n = recipients.len() as u64;
    if n == 0 {
        return Vec::new();
    }
    let base = total / n;
    let mut rem = total % n;
    // deterministisch nach recipient_id verteilen (aufsteigend)
    let mut idxs: Vec<(usize, &[u8; 32])> = recipients.iter().enumerate().collect();
    idxs.sort_by(|a, b| a.1.cmp(b.1));
    let mut out = vec![base; recipients.len()];
    for (i, _) in idxs {
        if rem == 0 {
            break;
        }
        if let Some(slot) = out.get_mut(i) {
            *slot = slot.saturating_add(1);
        }
        rem -= 1;
    }
    out
}

fn distribute_by_weights(total: Amount, recipients: &[[u8; 32]], weights: &[u64]) -> Vec<Amount> {
    let n = recipients.len();
    if n == 0 {
        return Vec::new();
    }
    let mut sum_w: u128 = 0;
    for &w in weights {
        sum_w += w as u128;
    }
    if sum_w == 0 {
        return vec![0u64; n];
    }
    let mut shares: Vec<Amount> = Vec::with_capacity(n);
    let mut acc: u128 = 0;
    for &w in weights {
        let part = (total as u128) * (w as u128) / sum_w;
        shares.push(part as u64);
        acc += part;
    }
    let mut rem = (total as u128).saturating_sub(acc) as u64;
    // remainder deterministisch nach recipient_id verteilen
    let mut idxs: Vec<(usize, &[u8; 32])> = recipients.iter().enumerate().collect();
    idxs.sort_by(|a, b| a.1.cmp(b.1));
    for (i, _) in idxs {
        if rem == 0 {
            break;
        }
        if let Some(slot) = shares.get_mut(i) {
            *slot = slot.saturating_add(1);
        }
        rem -= 1;
    }
    shares
}

/// Berechnet Payouts für das Committee (Basis/Proposer/Performance). Attestoren separat verteilen.
/// recipients: Empfänger-IDs der k Seats (z. B. seat_pk-Commitments), proposer_index in 0..k
/// ack_distances: Option<d> je Seat (1..=Dmax); None → kein Beitrag im Perf-Topf
pub fn compute_committee_payout(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    proposer_index: usize,
    ack_distances: &[Option<u8>],
) -> Result<PayoutSet, ConsensusError> {
    params.validate()?;
    if recipients.len() != ack_distances.len() {
        return Err(ConsensusError::InvalidParams);
    }
    if proposer_index >= recipients.len() {
        return Err(ConsensusError::InvalidParams);
    }

    let base_pot = split_bp(fees_total, params.p_base_bp);
    let prop_pot = split_bp(fees_total, params.p_prop_bp);
    let perf_pot = split_bp(fees_total, params.p_perf_bp);

    // Basis gleichmäßig
    let base_shares = distribute_equal(base_pot, recipients);

    // Proposer voll
    let mut entries: Vec<PayoutEntry> = Vec::new();
    if prop_pot > 0 {
        if let Some(rcpt) = recipients.get(proposer_index) {
            entries.push(PayoutEntry {
                recipient_id: *rcpt,
                amount: prop_pot,
            });
        } else {
            return Err(ConsensusError::InvalidParams);
        }
    }

    // Performance nach Gewichten
    if perf_pot > 0 {
        let mut w: Vec<u64> = Vec::with_capacity(recipients.len());
        for d in ack_distances.iter() {
            let weight = match d {
                Some(dist) if *dist >= 1 && *dist <= params.d_max => {
                    let idx = (*dist as usize) - 1;
                    params.perf_weights.get(idx).copied().unwrap_or(0) as u64
                }
                _ => 0u64,
            };
            w.push(weight);
        }
        let perf_shares = distribute_by_weights(perf_pot, recipients, &w);
        for (amt, rcpt) in perf_shares.iter().zip(recipients.iter()) {
            if *amt > 0 {
                entries.push(PayoutEntry {
                    recipient_id: *rcpt,
                    amount: *amt,
                });
            }
        }
    }

    // Basis hinzulegen
    for (amt, rcpt) in base_shares.iter().zip(recipients.iter()) {
        if *amt > 0 {
            entries.push(PayoutEntry {
                recipient_id: *rcpt,
                amount: *amt,
            });
        }
    }

    Ok(PayoutSet { entries })
}

/// Slashing-Parameter für unterschiedliche Evidence-Kategorien.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingParams {
    pub equivocation_bp: u16,   // erwartet 10_000 (100%)
    pub vote_invalid_bp: u16,   // 5_000..=10_000
    pub conflicting_da_bp: u16, // {2_500, 5_000, 10_000}
}

impl SlashingParams {
    pub fn validate(&self) -> Result<(), ConsensusError> {
        // Equivocation strikt 100%
        if self.equivocation_bp != consts::SLASH_EQUIVOCATION_BP {
            return Err(ConsensusError::InvalidParams);
        }
        // Vote-invalid im Intervall [50%, 100%]
        if self.vote_invalid_bp < consts::SLASH_VOTE_INVALID_MIN_BP
            || self.vote_invalid_bp > consts::SLASH_VOTE_INVALID_MAX_BP
        {
            return Err(ConsensusError::InvalidParams);
        }
        // Conflicting-DA aus diskretem Set
        match self.conflicting_da_bp {
            x if x == consts::SLASH_DA_25_BP => {}
            x if x == consts::SLASH_DA_50_BP => {}
            x if x == consts::SLASH_DA_100_BP => {}
            _ => return Err(ConsensusError::InvalidParams),
        }
        Ok(())
    }

    pub fn recommended_equivocation() -> Self {
        Self {
            equivocation_bp: consts::SLASH_EQUIVOCATION_BP,
            vote_invalid_bp: consts::SLASH_VOTE_INVALID_MAX_BP,
            conflicting_da_bp: consts::SLASH_DA_100_BP,
        }
    }
    pub fn recommended_vote_invalid(bp: u16) -> Result<Self, ConsensusError> {
        let s = Self {
            equivocation_bp: consts::SLASH_EQUIVOCATION_BP,
            vote_invalid_bp: bp,
            conflicting_da_bp: consts::SLASH_DA_50_BP,
        };
        s.validate()?;
        Ok(s)
    }
    pub fn recommended_conflicting_da(bp: u16) -> Result<Self, ConsensusError> {
        let s = Self {
            equivocation_bp: consts::SLASH_EQUIVOCATION_BP,
            vote_invalid_bp: consts::SLASH_VOTE_INVALID_MAX_BP,
            conflicting_da_bp: bp,
        };
        s.validate()?;
        Ok(s)
    }
}

/// Berechnet Slashing-Payout auf Basis eines Evidence-Events.
/// - slashed_bond: Betrag des Bonds des Täters
/// - recipients: payout_id der k Seats (eligible Seats)
/// Verteilung: 100% des Slashing-Topfs auf alle eligible Seats EXKL. Täter, deterministisch gleichmäßig
pub fn compute_slashing_payout_for_evidence(
    slashed_bond: Amount,
    params: &SlashingParams,
    recipients: &[[u8; 32]],
    ev: &EvidenceKind,
) -> Result<PayoutSet, ConsensusError> {
    params.validate()?;
    // Täter-ID aus Evidence extrahieren
    let offender: [u8; 32] = match ev {
        EvidenceKind::Equivocation { seat_id, .. } => *seat_id,
        EvidenceKind::VoteInvalid { seat_id, .. } => *seat_id,
        EvidenceKind::ConflictingDAAttest { seat_id, .. } => *seat_id,
    };
    // Basisprozente je Kategorie
    let bp: u16 = match ev {
        EvidenceKind::Equivocation { .. } => params.equivocation_bp,
        EvidenceKind::VoteInvalid { .. } => params.vote_invalid_bp,
        EvidenceKind::ConflictingDAAttest { .. } => params.conflicting_da_bp,
    };
    let pot = split_bp(slashed_bond, bp);
    if pot == 0 {
        return Ok(PayoutSet { entries: vec![] });
    }
    // Eligible: alle außer Täter
    let elig: Vec<[u8; 32]> = recipients
        .iter()
        .copied()
        .filter(|id| *id != offender)
        .collect();
    if elig.is_empty() {
        return Err(ConsensusError::InvalidParams);
    }
    let shares = distribute_equal(pot, &elig);
    let mut entries = Vec::new();
    for (amt, rcpt) in shares.iter().zip(elig.iter()) {
        if *amt > 0 {
            entries.push(PayoutEntry {
                recipient_id: *rcpt,
                amount: *amt,
            });
        }
    }
    Ok(PayoutSet { entries })
}

/// Verteilt den Attestor-Topf gleichmäßig auf eine Stichprobe von Attestoren
pub fn compute_attestor_payout(
    fees_total: Amount,
    params: &FeeSplitParams,
    attestors: &[[u8; 32]],
) -> Result<PayoutSet, ConsensusError> {
    params.validate()?;
    let att_pot = split_bp(fees_total, params.p_att_bp);
    let shares = distribute_equal(att_pot, attestors);
    let mut entries = Vec::new();
    for (amt, &rcpt) in shares.iter().zip(attestors.iter()) {
        if *amt > 0 {
            entries.push(PayoutEntry {
                recipient_id: rcpt,
                amount: *amt,
            });
        }
    }
    Ok(PayoutSet { entries })
}

/// Vereint Committee- und Attestor-Payouts und gibt die finale Payout-Root zurück.
pub fn compute_total_payout_root(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    proposer_index: usize,
    ack_distances: &[Option<u8>],
    attestors: &[[u8; 32]],
) -> Result<pc_crypto::Hash32, ConsensusError> {
    let committee = compute_committee_payout(
        fees_total,
        params,
        recipients,
        proposer_index,
        ack_distances,
    )?;
    let att = compute_attestor_payout(fees_total, params, attestors)?;
    let mut entries = committee.entries;
    entries.extend_from_slice(&att.entries);
    let set = PayoutSet { entries };
    Ok(set.payout_root())
}

/// Liefert pro Seat (0..k-1) die minimale Ack-Distanz (in Kanten) vom gegebenen ack_id
/// zu irgendeinem Anker dieses Seats innerhalb der übergebenen Header-Menge.
/// Distanz 1 entspricht direktem Parent; Distanz 0 (ack selbst) wird nicht gewertet.
pub fn compute_ack_distances_for_seats(
    ack_id: AnchorId,
    headers: &[AnchorHeader],
    k: u8,
    d_max: u8,
) -> Vec<Option<u8>> {
    use std::collections::{HashMap, HashSet, VecDeque};
    let mut out: Vec<Option<u8>> = vec![None; k as usize];
    if k == 0 || headers.is_empty() {
        return out;
    }
    let mut id_to_idx: HashMap<AnchorId, usize> = HashMap::with_capacity(headers.len());
    for (i, h) in headers.iter().enumerate() {
        let hid = AnchorId(h.id_digest());
        id_to_idx.insert(hid, i);
    }
    let mut visited: HashSet<AnchorId> = HashSet::new();
    let mut dist: HashMap<AnchorId, u8> = HashMap::new();
    let mut q: VecDeque<AnchorId> = VecDeque::new();
    q.push_back(ack_id);
    visited.insert(ack_id);
    dist.insert(ack_id, 0);
    while let Some(cur) = q.pop_front() {
        let cur_d = *dist.get(&cur).unwrap_or(&0);
        if let Some(&idx) = id_to_idx.get(&cur) {
            if let Some(h) = headers.get(idx) {
                if cur_d >= 1 {
                    let seat = h.creator_index as usize;
                    if seat < (k as usize) {
                        if let Some(slot) = out.get_mut(seat) {
                            match slot {
                                None => *slot = Some(cur_d),
                                Some(prev) => {
                                    if cur_d < *prev {
                                        *slot = Some(cur_d);
                                    }
                                }
                            }
                        }
                    }
                }
                if cur_d < d_max {
                    let plen = h.parents.len as usize;
                    for pid in h.parents.ids.iter().take(plen) {
                        let pid = *pid;
                        if !visited.contains(&pid) {
                            visited.insert(pid);
                            dist.insert(pid, cur_d.saturating_add(1));
                            q.push_back(pid);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Wrapper: berechnet Ack-Distanzen aus Headern und erzeugt daraus das Committee-Payout
pub fn compute_committee_payout_from_headers(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    proposer_index: usize,
    ack_id: AnchorId,
    headers: &[AnchorHeader],
    k: u8,
) -> Result<PayoutSet, ConsensusError> {
    if recipients.len() != k as usize {
        return Err(ConsensusError::InvalidParams);
    }
    let dists = compute_ack_distances_for_seats(ack_id, headers, k, params.d_max);
    compute_committee_payout(fees_total, params, recipients, proposer_index, &dists)
}

/// Convenience: Liefert direkt die Merkle-Root des Committee-Payouts
pub fn committee_payout_root(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    proposer_index: usize,
    ack_distances: &[Option<u8>],
) -> Result<pc_crypto::Hash32, ConsensusError> {
    let set = compute_committee_payout(
        fees_total,
        params,
        recipients,
        proposer_index,
        ack_distances,
    )?;
    Ok(set.payout_root())
}

// ============================
// Proof-of-Work (Emission)
// ============================

/// BLAKE3-Hash über (POW_DOMAIN || pow_seed(32) || pow_nonce_le(8))
#[inline]
pub fn pow_hash(seed: &[u8; 32], nonce: u64) -> pc_crypto::Hash32 {
    let mut buf = Vec::with_capacity(consts::POW_DOMAIN.len() + 32 + 8);
    buf.extend_from_slice(consts::POW_DOMAIN);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&nonce.to_le_bytes());
    pc_crypto::blake3_32(&buf)
}

/// Prüft, ob der Hash mindestens `bits` führende Nullbits besitzt (MSB-first pro Byte).
#[inline]
pub fn pow_meets(bits: u8, h: &pc_crypto::Hash32) -> bool {
    if bits == 0 {
        return true;
    }
    if (bits as u16) > 256 {
        return false;
    }
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    for i in 0..full {
        if h.get(i).copied().unwrap_or(0) != 0 {
            return false;
        }
    }
    if rem == 0 {
        return true;
    }
    if let Some(&b) = h.get(full) {
        let mask: u8 = 0xFFu8 << (8 - rem);
        return (b & mask) == 0;
    }
    false
}

/// Convenience: Prüft PoW für ein MintEvent gegen `bits`.
#[inline]
pub fn check_mint_pow(m: &MintEvent, bits: u8) -> bool {
    let h = pow_hash(&m.pow_seed, m.pow_nonce);
    pow_meets(bits, &h)
}

/// Einfache in-memory Anker-Graph Struktur für Insert/Lookup und Ack-Distanzen
pub struct AnchorGraph {
    map: std::collections::HashMap<AnchorId, AnchorHeader>,
}

impl AnchorGraph {
    pub fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Fügt einen Header ein und gibt dessen berechnete AnchorId zurück
    pub fn insert(&mut self, header: AnchorHeader) -> AnchorId {
        let id = AnchorId(header.id_digest());
        let _prev = self.map.insert(id, header);
        id
    }

    pub fn contains(&self, id: &AnchorId) -> bool {
        self.map.contains_key(id)
    }
    pub fn get(&self, id: &AnchorId) -> Option<&AnchorHeader> {
        self.map.get(id)
    }

    /// Berechnet Ack-Distanzen über Eltern-Kanten (BFS), Distanz 1 = direkter Parent, 0=ack selbst (nicht gewertet)
    pub fn compute_ack_distances(&self, ack_id: AnchorId, k: u8, d_max: u8) -> Vec<Option<u8>> {
        let mut out: Vec<Option<u8>> = vec![None; k as usize];
        if k == 0 {
            return out;
        }
        if !self.map.contains_key(&ack_id) {
            return out;
        }
        use std::collections::{HashSet, VecDeque};
        let mut visited: HashSet<AnchorId> = HashSet::new();
        let mut dist: std::collections::HashMap<AnchorId, u8> = std::collections::HashMap::new();
        let mut q: VecDeque<AnchorId> = VecDeque::new();
        q.push_back(ack_id);
        visited.insert(ack_id);
        dist.insert(ack_id, 0);
        while let Some(cur) = q.pop_front() {
            let cur_d = *dist.get(&cur).unwrap_or(&0);
            if let Some(h) = self.map.get(&cur) {
                if cur_d >= 1 {
                    let seat = h.creator_index as usize;
                    if seat < (k as usize) {
                        if let Some(slot) = out.get_mut(seat) {
                            match slot {
                                None => *slot = Some(cur_d),
                                Some(prev) => {
                                    if cur_d < *prev {
                                        *slot = Some(cur_d);
                                    }
                                }
                            }
                        }
                    }
                }
                if cur_d < d_max {
                    let plen = h.parents.len as usize;
                    for pid in h.parents.ids.iter().take(plen) {
                        let pid = *pid;
                        if !visited.contains(&pid) && self.map.contains_key(&pid) {
                            visited.insert(pid);
                            dist.insert(pid, cur_d.saturating_add(1));
                            q.push_back(pid);
                        }
                    }
                }
            }
        }
        out
    }
}

/// In-Memory Graph mit einfachem Ack-Distanz-Cache (invalidiert bei Insert)
pub struct AnchorGraphCache {
    graph: AnchorGraph,
    ack_cache: std::collections::HashMap<(AnchorId, u8, u8), Vec<Option<u8>>>,
}

impl Default for AnchorGraphCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AnchorGraphCache {
    pub fn new() -> Self {
        Self {
            graph: AnchorGraph::new(),
            ack_cache: std::collections::HashMap::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.graph.len()
    }
    pub fn is_empty(&self) -> bool {
        self.graph.is_empty()
    }
    pub fn insert(&mut self, header: AnchorHeader) -> AnchorId {
        let id = self.graph.insert(header);
        // Graph hat sich geändert → Cache invalidieren
        self.ack_cache.clear();
        id
    }
    pub fn contains(&self, id: &AnchorId) -> bool {
        self.graph.contains(id)
    }
    pub fn compute_ack_distances(&mut self, ack_id: AnchorId, k: u8, d_max: u8) -> Vec<Option<u8>> {
        let key = (ack_id, k, d_max);
        if let Some(v) = self.ack_cache.get(&key) {
            return v.clone();
        }
        let d = self.graph.compute_ack_distances(ack_id, k, d_max);
        self.ack_cache.insert(key, d.clone());
        d
    }
}

/// Konfiguration für den Konsens-Engine (Single-Shard v0)
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    /// Committee-Größe k (Seats pro Shard)
    pub k: u8,
    /// Fee-Split-Parameter (Basispunkte etc.)
    pub fee_params: FeeSplitParams,
    /// Bootstrap-Fenster: effektives k=1 bis zur ersten Rotation
    pub bootstrap_k1: bool,
}

impl ConsensusConfig {
    /// Empfohlene Startkonfiguration mit gegebenem k
    pub fn recommended(k: u8) -> Self {
        Self {
            k,
            fee_params: FeeSplitParams::recommended(),
            bootstrap_k1: false,
        }
    }

    /// Setzt das Bootstrap-Fenster (effektives k=1) explizit.
    pub fn with_bootstrap_k1(mut self, flag: bool) -> Self {
        self.bootstrap_k1 = flag;
        self
    }

    /// Liefert das wirksame k (1, falls Bootstrap aktiv; sonst konfiguriertes k).
    #[inline]
    pub fn effective_k(&self) -> u8 {
        if self.bootstrap_k1 { 1 } else { self.k }
    }
}

pub struct ConsensusEngine {
    cfg: ConsensusConfig,
    cache: AnchorGraphCache,
}

impl ConsensusEngine {
    pub fn new(cfg: ConsensusConfig) -> Self {
        Self {
            cfg,
            cache: AnchorGraphCache::new(),
        }
    }

    /// Fügt einen Header ein und invalidiert intern den Ack-Cache
    pub fn insert_header(&mut self, header: AnchorHeader) -> AnchorId {
        self.cache.insert(header)
    }

    /// Berechne Ack-Distanzen für gegebenes ack_id gemäß Engine-Parametern (k,d_max)
    pub fn ack_distances(&mut self, ack_id: AnchorId) -> Vec<Option<u8>> {
        let k = self.cfg.effective_k();
        let d_max = self.cfg.fee_params.d_max;
        self.cache.compute_ack_distances(ack_id, k, d_max)
    }

    /// Prüfe Finalität über vote_mask-Popcount gegen Threshold T=floor(2k/3)+1
    /// Erwartet, dass das übergebene vote_mask die Stimmen der k Seats kodiert (u64 reicht k<=64)
    pub fn is_final_mask(&self, vote_mask: u64) -> bool {
        is_final(popcount_u64(vote_mask), self.cfg.effective_k())
    }

    /// Bootstrap‑Modus ein/aus (wirksames k=1, wenn aktiv)
    pub fn set_bootstrap_k1(&mut self, flag: bool) {
        self.cfg.bootstrap_k1 = flag;
    }

    /// Gibt zurück, ob Bootstrap‑Modus aktiv ist
    pub fn bootstrap_k1(&self) -> bool {
        self.cfg.bootstrap_k1
    }

    /// Erzeugt die Committee-Payout-Root für ein gegebenes Ack (aus Graph) und Seats
    pub fn committee_payout_root_for_ack(
        &mut self,
        fees_total: Amount,
        recipients: &[[u8; 32]],
        proposer_index: usize,
        ack_id: AnchorId,
    ) -> Result<pc_crypto::Hash32, ConsensusError> {
        let dists = self.ack_distances(ack_id);
        committee_payout_root(
            fees_total,
            &self.cfg.fee_params,
            recipients,
            proposer_index,
            &dists,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_crypto::blake3_32;
    use pc_crypto::{bls_keygen_from_ikm, attestor_recipient_id_from_bls};

    #[test]
    fn threshold() {
        assert_eq!(finality_threshold(21), 15);
        assert!(is_final(15, 21));
        assert!(!is_final(14, 21));
    }

    #[test]
    fn mask_ops() {
        let m = set_bit(0, 5).unwrap();
        assert_eq!(popcount_u64(m), 1);
        assert!(set_bit(0, 64).is_err());
    }

    #[test]
    fn attestor_payout_from_bls_matches_direct_ids() {
        let params = FeeSplitParams {
            p_base_bp: 6500,
            p_prop_bp: 1000,
            p_perf_bp: 1500,
            p_att_bp: 1000,
            d_max: 1,
            perf_weights: vec![10_000],
        };
        params.validate().unwrap();

        let ikm1 = blake3_32(b"ikm-att-1");
        let ikm2 = blake3_32(b"ikm-att-2");
        let k1 = bls_keygen_from_ikm(&ikm1).unwrap();
        let k2 = bls_keygen_from_ikm(&ikm2).unwrap();
        let pks = [k1.pk.clone(), k2.pk.clone()];
        let ids = [attestor_recipient_id_from_bls(&k1.pk), attestor_recipient_id_from_bls(&k2.pk)];
        let fees = 12_345u64;

        let from_pks = compute_attestor_payout_from_bls(fees, &params, &pks).unwrap();
        let from_ids = compute_attestor_payout(fees, &params, &ids).unwrap();
        assert_eq!(from_pks.payout_root(), from_ids.payout_root());
    }

    #[test]
    fn attestor_payout_from_bls_empty_ok() {
        let params = FeeSplitParams {
            p_base_bp: 6500,
            p_prop_bp: 1000,
            p_perf_bp: 1500,
            p_att_bp: 1000,
            d_max: 1,
            perf_weights: vec![10_000],
        };
        params.validate().unwrap();
        let fees = 9_999u64;
        let set = compute_attestor_payout_from_bls(fees, &params, &[]).unwrap();
        assert!(set.entries.is_empty());
        assert_eq!(set.payout_root(), [0u8; 32]);
    }

    #[test]
    fn pow_meets_boundaries() {
        // 0 Bits: immer erfüllt
        let h = [0xFFu8; 32];
        assert!(pow_meets(0, &h));
        // 4 führende Nullbits: 0x0F...
        let mut h2 = [0xFFu8; 32];
        h2[0] = 0x0F; // 0000 1111
        assert!(pow_meets(4, &h2));
        assert!(!pow_meets(5, &h2));
        // Volle Bytes = 8 Bits: 0x00..
        let mut h3 = [0xFFu8; 32];
        h3[0] = 0x00;
        assert!(pow_meets(8, &h3));
        // 9 Bits → erstes Byte 0x00, zweites MSB=0
        h3[1] = 0x7F; // 0111 1111
        assert!(pow_meets(9, &h3));
        h3[1] = 0xFF; // 1111 1111
        assert!(!pow_meets(9, &h3));
    }

    #[test]
    fn fee_split_committee() {
        let params = FeeSplitParams {
            p_base_bp: 6500,
            p_prop_bp: 1000,
            p_perf_bp: 1500,
            p_att_bp: 1000,
            d_max: 4,
            perf_weights: vec![10000, 6000, 3600, 2160],
        };
        params.validate().unwrap();
        let _k = 3usize;
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let dists = [Some(1u8), Some(2u8), None];
        let fees = 1000u64;
        let set = compute_committee_payout(fees, &params, &recipients, 1, &dists).unwrap();
        // Summe prüfen
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        assert_eq!(
            sum,
            split_bp(fees, 6500) + split_bp(fees, 1000) + split_bp(fees, 1500)
        );
    }

    #[test]
    fn fee_split_attestors() {
        let params = FeeSplitParams {
            p_base_bp: 6500,
            p_prop_bp: 1000,
            p_perf_bp: 1500,
            p_att_bp: 1000,
            d_max: 1,
            perf_weights: vec![10000],
        };
        params.validate().unwrap();
        let att = [blake3_32(b"x"), blake3_32(b"y")];
        let fees = 1000u64;
        let set = compute_attestor_payout(fees, &params, &att).unwrap();
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum, split_bp(fees, 1000));
    }

    #[test]
    fn anchor_graph_ack_distance_basic() {
        // A <- B <- C (C ist ack_id); Seats: A:0, B:1, C:2
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_a,
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_a = a.id_digest();

        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_b,
            payload_hash: [1u8; 32],
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_b = b.id_digest();

        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_c,
            payload_hash: [2u8; 32],
            creator_index: 2,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_c = c.id_digest();

        let mut g = AnchorGraph::new();
        let id_a_ins = g.insert(a);
        let _ = g.insert(b);
        let _ = g.insert(c);
        assert!(g.contains(&pc_types::AnchorId(id_a_ins.0)));

        let res = g.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
        assert_eq!(res[0], Some(2));
        assert_eq!(res[1], Some(1));
        assert_eq!(res[2], None);
    }

    #[test]
    fn anchor_graph_cache_basic() {
        // A <- B <- C (C ist ack_id)
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_a,
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_a = a.id_digest();

        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_b,
            payload_hash: [1u8; 32],
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_b = b.id_digest();

        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_c,
            payload_hash: [2u8; 32],
            creator_index: 2,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_c = c.id_digest();

        let mut cache = AnchorGraphCache::new();
        cache.insert(a);
        cache.insert(b);
        cache.insert(c);
        let res1 = cache.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
        assert_eq!(res1[0], Some(2));
        assert_eq!(res1[1], Some(1));
        assert_eq!(res1[2], None);
        // Nochmals abrufen (aus Cache)
        let res2 = cache.compute_ack_distances(pc_types::AnchorId(id_c), 3, 8);
        assert_eq!(res1, res2);
    }

    #[test]
    fn engine_finality_and_ack_distances() {
        // Graph: A <- B <- C (C ist ack_id)
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_a,
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_a = a.id_digest();

        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_b,
            payload_hash: [1u8; 32],
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_b = b.id_digest();

        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_c,
            payload_hash: [2u8; 32],
            creator_index: 2,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_c = c.id_digest();

        let cfg = ConsensusConfig::recommended(3);
        let mut eng = ConsensusEngine::new(cfg);
        eng.insert_header(a);
        eng.insert_header(b);
        eng.insert_header(c);

        let d = eng.ack_distances(pc_types::AnchorId(id_c));
        assert_eq!(d.len(), 3);
        assert_eq!(d[0], Some(2));
        assert_eq!(d[1], Some(1));
        assert_eq!(d[2], None);

        // Finalität: k=3 → T=floor(2*3/3)+1 = 3
        // Mask mit 2 Stimmen ist NICHT final, mit 3 Stimmen schon
        let m2 = set_bit(set_bit(0, 0).unwrap(), 1).unwrap();
        assert!(!eng.is_final_mask(m2));
        let m3 = set_bit(m2, 2).unwrap();
        assert!(eng.is_final_mask(m3));
    }

    #[test]
    fn engine_payout_root_matches_direct() {
        // gleicher Graph wie oben
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_a,
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_a = a.id_digest();

        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_b,
            payload_hash: [1u8; 32],
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_b = b.id_digest();

        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_c,
            payload_hash: [2u8; 32],
            creator_index: 2,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_c = c.id_digest();

        let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
        eng.insert_header(a.clone());
        eng.insert_header(b.clone());
        eng.insert_header(c.clone());

        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let fees = 10_000u64;

        let root_engine = eng
            .committee_payout_root_for_ack(fees, &recipients, 1, pc_types::AnchorId(id_c))
            .expect("engine payout root");

        let headers = vec![a, b, c];
        let params = FeeSplitParams::recommended();
        let root_direct = compute_committee_payout_from_headers(
            fees,
            &params,
            &recipients,
            1,
            pc_types::AnchorId(id_c),
            &headers,
            3,
        )
        .map(|s| s.payout_root())
        .expect("direct payout root");

        assert_eq!(root_engine, root_direct);
    }

    #[test]
    fn distribute_equal_invariants() {
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let total = 1001u64;
        let shares = distribute_equal(total, &recipients);
        assert_eq!(shares.len(), recipients.len());
        // Summe stimmt
        let sum: u64 = shares.iter().copied().sum();
        assert_eq!(sum, total);
        // Jeder Anteil ist base oder base+1
        let base = total / (recipients.len() as u64);
        let rem = total % (recipients.len() as u64);
        let mut cnt_base = 0usize;
        let mut cnt_plus = 0usize;
        for &s in &shares {
            assert!(s == base || s == base + 1);
            if s == base {
                cnt_base += 1;
            } else {
                cnt_plus += 1;
            }
        }
        assert_eq!(cnt_plus as u64, rem);
        assert_eq!(cnt_base + cnt_plus, recipients.len());
        // Deterministisch bei erneutem Aufruf
        let shares2 = distribute_equal(total, &recipients);
        assert_eq!(shares, shares2);
    }

    #[test]
    fn distribute_by_weights_invariants() {
        let recipients = [blake3_32(b"x"), blake3_32(b"y"), blake3_32(b"z")];
        let total = 10_000u64;
        let weights = [5u64, 0u64, 5u64]; // Summe 10
        let shares = distribute_by_weights(total, &recipients, &weights);
        assert_eq!(shares.len(), recipients.len());
        // Summe stimmt
        let sum: u64 = shares.iter().copied().sum();
        assert_eq!(sum, total);
        // Jeder Anteil liegt in der Nähe des proportionalen Anteils (floor/ceil)
        let sum_w = 10u64;
        for (i, &w) in weights.iter().enumerate() {
            let base = (total as u128) * (w as u128) / (sum_w as u128);
            let s = shares[i] as u128;
            assert!(s == base || s == base + 1 || (base > 0 && s + 1 == base));
        }
        // Deterministisch bei erneutem Aufruf
        let shares2 = distribute_by_weights(total, &recipients, &weights);
        assert_eq!(shares, shares2);
    }

    #[test]
    fn distribute_by_weights_zero_sum() {
        let recipients = [blake3_32(b"p"), blake3_32(b"q")];
        let total = 123u64;
        let weights = [0u64, 0u64];
        let shares = distribute_by_weights(total, &recipients, &weights);
        assert_eq!(shares, vec![0, 0]);
    }

    #[test]
    fn recommended_params_invariants() {
        let p = FeeSplitParams::recommended();
        // validate prüft Summe==10_000, Länge==d_max und monotone Gewichte
        p.validate().expect("recommended params invalid");
        // redundante Checks (explizit)
        let sum = (p.p_base_bp as u32)
            + (p.p_prop_bp as u32)
            + (p.p_perf_bp as u32)
            + (p.p_att_bp as u32);
        assert_eq!(sum, 10_000);
        assert_eq!(p.perf_weights.len(), p.d_max as usize);
        for w in p.perf_weights.windows(2) {
            if let [a, b] = w {
                assert!(a >= b);
            }
        }
    }

    #[test]
    fn split_sums_match_total() {
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let att = [blake3_32(b"x"), blake3_32(b"y")];
        let fees = 123_456_789u64;
        let dists = [Some(1u8), Some(2u8), None];
        let committee = compute_committee_payout(fees, &params, &recipients, 1, &dists).unwrap();
        let attestors = compute_attestor_payout(fees, &params, &att).unwrap();
        let sum_comm: u64 = committee.entries.iter().map(|e| e.amount).sum();
        let sum_att: u64 = attestors.entries.iter().map(|e| e.amount).sum();
        // Summe der ausgezahlten Beträge entspricht exakt der Summe der Topf-Splits (base/prop/perf/att)
        let base_pot = split_bp(fees, params.p_base_bp);
        let prop_pot = split_bp(fees, params.p_prop_bp);
        let perf_pot = split_bp(fees, params.p_perf_bp);
        let att_pot = split_bp(fees, params.p_att_bp);
        let sum_pots = base_pot + prop_pot + perf_pot + att_pot;
        assert_eq!(sum_comm + sum_att, sum_pots);
        // Rundungsverlust über alle Töpfe ist klein und deterministisch (< Anzahl Töpfe)
        assert!(sum_pots <= fees);
        assert!((fees - sum_pots) < 4);
    }

    #[test]
    fn ack_distances_fn_matches_graph() {
        // A <- B <- C (C ack)
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_a,
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_a = a.id_digest();

        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_b,
            payload_hash: [1u8; 32],
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_b = b.id_digest();

        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_c,
            payload_hash: [2u8; 32],
            creator_index: 2,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_c = c.id_digest();

        // compute via helper fn on slice
        let headers = vec![a.clone(), b.clone(), c.clone()];
        let via_fn = compute_ack_distances_for_seats(
            pc_types::AnchorId(id_c),
            &headers,
            3,
            FeeSplitParams::recommended().d_max,
        );

        // compute via engine
        let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
        eng.insert_header(a);
        eng.insert_header(b);
        eng.insert_header(c);
        let via_eng = eng.ack_distances(pc_types::AnchorId(id_c));

        assert_eq!(via_fn, via_eng);
    }

    #[test]
    fn maturity_thresholds_boundaries() {
        let m0: AnchorIndex = 1_000_000;
        // Unter L1
        assert!(!maturity_reached(
            m0 + consts::MATURITY_L1 - 1,
            m0,
            consts::MATURITY_L1
        ));
        // Genau L1
        assert!(maturity_reached(
            m0 + consts::MATURITY_L1,
            m0,
            consts::MATURITY_L1
        ));
        // L2 und L3
        assert!(maturity_reached(
            m0 + consts::MATURITY_L2,
            m0,
            consts::MATURITY_L2
        ));
        assert!(maturity_reached(
            m0 + consts::MATURITY_L3,
            m0,
            consts::MATURITY_L3
        ));
    }

    #[test]
    fn maturity_level_increments() {
        let m0: AnchorIndex = 10_000;
        assert_eq!(maturity_level(m0, m0), 0);
        assert_eq!(maturity_level(m0 + consts::MATURITY_L1 - 1, m0), 0);
        assert_eq!(maturity_level(m0 + consts::MATURITY_L1, m0), 1);
        assert_eq!(maturity_level(m0 + consts::MATURITY_L2, m0), 2);
        assert_eq!(maturity_level(m0 + consts::MATURITY_L3, m0), 3);
    }

    #[test]
    fn invalid_params_sum_or_weights_len_fail() {
        // Summe != 10_000
        let bad_sum = FeeSplitParams {
            p_base_bp: 6500,
            p_prop_bp: 1000,
            p_perf_bp: 1600, // Summe 10_100
            p_att_bp: 1000,
            d_max: 2,
            perf_weights: vec![10000, 6000],
        };
        assert!(bad_sum.validate().is_err());

        // d_max != perf_weights.len()
        let bad_len = FeeSplitParams {
            p_base_bp: 6500,
            p_prop_bp: 1000,
            p_perf_bp: 1500,
            p_att_bp: 1000,
            d_max: 3,
            perf_weights: vec![10000, 6000], // Länge 2
        };
        assert!(bad_len.validate().is_err());
    }

    #[test]
    fn slashing_equivocation_100pct() {
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let offender = recipients[1];
        let ev = pc_types::EvidenceKind::Equivocation {
            seat_id: offender,
            epoch_id: 1,
            a: AnchorHeader::default(),
            b: Box::new(AnchorHeader::default()),
        };
        let params = SlashingParams::recommended_equivocation();
        let bond = 1_000u64;
        let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev)
            .expect("slash eq");
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum, bond); // 100%
                               // Täter nicht begünstigt
        for e in &set.entries {
            assert_ne!(e.recipient_id, offender);
        }
        // Gleichverteilung auf 2 recipients
        let amounts: Vec<u64> = set.normalized_entries().iter().map(|e| e.amount).collect();
        assert_eq!(amounts.len(), 2);
        assert!(amounts[0] + amounts[1] == bond);
    }

    #[test]
    fn slashing_vote_invalid_50pct() {
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let offender = recipients[0];
        let ev = pc_types::EvidenceKind::VoteInvalid {
            seat_id: offender,
            anchor: AnchorHeader::default(),
            reason_code: 42,
        };
        let params = SlashingParams::recommended_vote_invalid(consts::SLASH_VOTE_INVALID_MIN_BP)
            .expect("vi params");
        let bond = 2_000u64;
        let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev)
            .expect("slash vi");
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum, bond / 2); // 50%
        for e in &set.entries {
            assert_ne!(e.recipient_id, offender);
        }
    }

    #[test]
    fn slashing_conflicting_da_25pct() {
        let recipients = [
            blake3_32(b"a"),
            blake3_32(b"b"),
            blake3_32(b"c"),
            blake3_32(b"d"),
        ];
        let offender = recipients[2];
        let ev = pc_types::EvidenceKind::ConflictingDAAttest {
            seat_id: offender,
            anchor_id: AnchorId([0u8; 32]),
            attest_a: vec![1, 2],
            attest_b: vec![3, 4],
        };
        let params =
            SlashingParams::recommended_conflicting_da(consts::SLASH_DA_25_BP).expect("da params");
        let bond = 1_000u64;
        let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev)
            .expect("slash da");
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum, 250);
        for e in &set.entries {
            assert_ne!(e.recipient_id, offender);
        }
    }

    #[test]
    fn committee_payout_mismatch_lengths_and_proposer_index_fail() {
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"a"), blake3_32(b"b")];
        // Längen-Mismatch: 2 vs 3
        let dists = [Some(1u8), Some(2u8), None];
        let fees = 1000u64;
        assert!(compute_committee_payout(fees, &params, &recipients, 0, &dists).is_err());

        // Proposer-Index außerhalb
        let dists_ok = [Some(1u8), None];
        assert!(compute_committee_payout(fees, &params, &recipients, 2, &dists_ok).is_err());
    }

    #[test]
    fn committee_payout_from_headers_k_mismatch_recipients_len_fail() {
        // A <- B <- C (C ack), k=3 aber recipients nur 2
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_a,
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_a = a.id_digest();

        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_b,
            payload_hash: [1u8; 32],
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_b = b.id_digest();

        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_c,
            payload_hash: [2u8; 32],
            creator_index: 2,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_c = c.id_digest();

        let headers = vec![a, b, c];
        let recipients = [blake3_32(b"a"), blake3_32(b"b")];
        let fees = 10_000u64;
        let params = FeeSplitParams::recommended();
        let res = compute_committee_payout_from_headers(
            fees,
            &params,
            &recipients,
            0,
            pc_types::AnchorId(id_c),
            &headers,
            3,
        );
        assert!(res.is_err());
    }

    #[test]
    fn engine_committee_payout_root_for_ack_recipients_len_mismatch_fails() {
        // gleicher Graph wie oben
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_a,
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_a = a.id_digest();

        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_b,
            payload_hash: [1u8; 32],
            creator_index: 1,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_b = b.id_digest();

        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader {
            version: 1,
            shard_id: 0,
            parents: parents_c,
            payload_hash: [2u8; 32],
            creator_index: 2,
            vote_mask: 0,
            ack_present: false,
            ack_id: pc_types::AnchorId([0u8; 32]),
        };
        let id_c = c.id_digest();

        let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
        eng.insert_header(a);
        eng.insert_header(b);
        eng.insert_header(c);

        let recipients = [blake3_32(b"a"), blake3_32(b"b")]; // len 2, k=3
        let fees = 10_000u64;
        let res = eng.committee_payout_root_for_ack(fees, &recipients, 0, pc_types::AnchorId(id_c));
        assert!(res.is_err());
    }

    #[test]
    fn total_payout_root_matches_manual_merge() {
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let att = [blake3_32(b"x"), blake3_32(b"y")];
        let fees = 123_456u64;
        let dists = [Some(1u8), None, Some(2u8)];
        let proposer_index = 1usize;

        let committee = compute_committee_payout(fees, &params, &recipients, proposer_index, &dists).unwrap();
        let attestors = compute_attestor_payout(fees, &params, &att).unwrap();
        let mut entries = committee.entries;
        entries.extend_from_slice(&attestors.entries);
        let expected_root = pc_types::PayoutSet { entries }.payout_root();

        let got = compute_total_payout_root(fees, &params, &recipients, proposer_index, &dists, &att).unwrap();
        assert_eq!(expected_root, got);
    }

    #[test]
    fn total_payout_root_len_mismatch_fails() {
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let att = [blake3_32(b"x")];
        let fees = 1000u64;
        // ack_distances len != recipients len
        let dists = [Some(1u8), None];
        let res = compute_total_payout_root(fees, &params, &recipients, 0, &dists, &att);
        assert!(res.is_err());
    }

    #[test]
    fn engine_committee_payout_root_for_ack_invalid_proposer_index_fails() {
        // baue einfachen Graph A<-B<-C
        let parents_a = pc_types::ParentList::default();
        let a = pc_types::AnchorHeader { version:1, shard_id:0, parents: parents_a, payload_hash:[0u8;32], creator_index:0, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id_a = a.id_digest();
        let mut parents_b = pc_types::ParentList::default();
        parents_b.push(pc_types::AnchorId(id_a)).unwrap();
        let b = pc_types::AnchorHeader { version:1, shard_id:0, parents: parents_b, payload_hash:[1u8;32], creator_index:1, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id_b = b.id_digest();
        let mut parents_c = pc_types::ParentList::default();
        parents_c.push(pc_types::AnchorId(id_b)).unwrap();
        let c = pc_types::AnchorHeader { version:1, shard_id:0, parents: parents_c, payload_hash:[2u8;32], creator_index:2, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id_c = c.id_digest();

        let mut eng = ConsensusEngine::new(ConsensusConfig::recommended(3));
        eng.insert_header(a); eng.insert_header(b); eng.insert_header(c);

        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let fees = 10_000u64;
        // proposer_index=3 ist out-of-range
        let res = eng.committee_payout_root_for_ack(fees, &recipients, 3, pc_types::AnchorId(id_c));
        assert!(res.is_err());
    }

    #[test]
    fn ack_distances_empty_returns_none_vec() {
        let ack = pc_types::AnchorId([0u8;32]);
        let headers: Vec<pc_types::AnchorHeader> = Vec::new();
        let k = 5u8;
        let d_max = 4u8;
        let v = compute_ack_distances_for_seats(ack, &headers, k, d_max);
        assert_eq!(v.len(), k as usize);
        assert!(v.iter().all(|x| x.is_none()));
    }

    #[test]
    fn ack_distances_ack_not_in_headers_yields_none() {
        // ack_id nicht in headers -> keine Distanzen
        let ack = pc_types::AnchorId([9u8;32]);
        let parents = pc_types::ParentList::default();
        let h = pc_types::AnchorHeader { version:1, shard_id:0, parents, payload_hash:[0u8;32], creator_index:0, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let headers = vec![h];
        let v = compute_ack_distances_for_seats(ack, &headers, 3, 4);
        assert_eq!(v, vec![None, None, None]);
    }

    #[test]
    fn ack_distances_multi_parents_and_dmax() {
        // Konstruiere ack mit zwei Parents (Seat1, Seat2); je ein Grandparent (Seat0, Seat3)
        // d_max=1: nur Parents (Distanz=1) werden gezählt, Grandparents nicht.
        // d_max=2: Parents (1) und Grandparents (2) werden gezählt.
        let p0 = pc_types::ParentList::default();
        let h0 = pc_types::AnchorHeader { version:1, shard_id:0, parents: p0.clone(), payload_hash:[0u8;32], creator_index:0, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id0 = h0.id_digest();

        let h1 = pc_types::AnchorHeader { version:1, shard_id:0, parents: p0.clone(), payload_hash:[1u8;32], creator_index:1, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id1 = h1.id_digest();

        let mut p2 = pc_types::ParentList::default();
        p2.push(pc_types::AnchorId(id0)).unwrap();
        let h2 = pc_types::AnchorHeader { version:1, shard_id:0, parents: p2.clone(), payload_hash:[2u8;32], creator_index:2, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id2 = h2.id_digest();

        let mut p3 = pc_types::ParentList::default();
        p3.push(pc_types::AnchorId(id1)).unwrap();
        let h3 = pc_types::AnchorHeader { version:1, shard_id:0, parents: p3.clone(), payload_hash:[3u8;32], creator_index:3, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id3 = h3.id_digest();

        let mut pa = pc_types::ParentList::default();
        pa.push(pc_types::AnchorId(id2)).unwrap();
        pa.push(pc_types::AnchorId(id3)).unwrap();
        let ack_h = pc_types::AnchorHeader { version:1, shard_id:0, parents: pa, payload_hash:[4u8;32], creator_index:4, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let ack_id = pc_types::AnchorId(ack_h.id_digest());

        let headers = vec![h0, h1, h2, h3, ack_h.clone()];
        let k = 5u8; // seats 0..4

        // d_max=1 → nur Seats der direkten Parents (2,3) mit Distanz 1
        let v1 = compute_ack_distances_for_seats(ack_id, &headers, k, 1);
        assert_eq!(v1.len(), k as usize);
        assert_eq!(v1[2], Some(1));
        assert_eq!(v1[3], Some(1));
        assert!(v1[0].is_none() && v1[1].is_none() && v1[4].is_none());

        // d_max=2 → zusätzlich Grandparents (0 via h2, 1 via h3) mit Distanz 2
        let v2 = compute_ack_distances_for_seats(ack_id, &headers, k, 2);
        assert_eq!(v2[0], Some(2));
        assert_eq!(v2[1], Some(2));
        assert_eq!(v2[2], Some(1));
        assert_eq!(v2[3], Some(1));
        assert!(v2[4].is_none());
    }

    #[test]
    fn ack_distances_unknown_parent_ignored() {
        // ack referenziert einen Parent, der nicht in headers existiert → wird ignoriert
        let parents = pc_types::ParentList::default();
        let h0 = pc_types::AnchorHeader { version:1, shard_id:0, parents, payload_hash:[0u8;32], creator_index:0, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let id0 = h0.id_digest();
        let fake = pc_types::AnchorId([0xFF;32]);
        let mut pa = pc_types::ParentList::default();
        pa.push(pc_types::AnchorId(id0)).unwrap();
        pa.push(fake).unwrap();
        let ack_h = pc_types::AnchorHeader { version:1, shard_id:0, parents: pa, payload_hash:[1u8;32], creator_index:4, vote_mask:0, ack_present:false, ack_id: pc_types::AnchorId([0u8;32]) };
        let ack_id = pc_types::AnchorId(ack_h.id_digest());
        let headers = vec![h0, ack_h];
        let v = compute_ack_distances_for_seats(ack_id, &headers, 5, 2);
        // seat 0 erreicht mit Distanz 1; der unbekannte Parent bewirkt keine weiteren Einträge
        assert_eq!(v[0], Some(1));
    }

    #[test]
    fn committee_payout_zero_fees_yields_empty() {
        let params = FeeSplitParams { p_base_bp:6500, p_prop_bp:1000, p_perf_bp:1500, p_att_bp:1000, d_max:1, perf_weights: vec![10_000] };
        params.validate().unwrap();
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let dists = [Some(1u8), None, Some(2u8)];
        let set = compute_committee_payout(0, &params, &recipients, 1, &dists).unwrap();
        assert!(set.entries.is_empty());
    }

    #[test]
    fn committee_payout_base_only_k64_remainder_distribution() {
        // Nur base_pot=10000bp → 100% Basis, k=64, remainder deterministisch nach recipient_id
        let params = FeeSplitParams { p_base_bp:10_000, p_prop_bp:0, p_perf_bp:0, p_att_bp:0, d_max:1, perf_weights: vec![10_000] };
        params.validate().unwrap();
        let mut recipients: Vec<[u8;32]> = Vec::with_capacity(64);
        for i in 0u8..64u8 { recipients.push([i;32]); }
        let fees = 1000u64;
        let set = compute_committee_payout(fees, &params, &recipients, 0, &vec![None;64]).unwrap();
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum, fees);
        // erwartete Gleichverteilung: 1000 / 64 = 15 Rest 40 → 40 Empfänger mit 16, 24 mit 15
        let mut c15 = 0; let mut c16 = 0;
        for e in &set.entries { if e.amount == 15 { c15 += 1; } else if e.amount == 16 { c16 += 1; } }
        assert_eq!(c15, 24);
        assert_eq!(c16, 40);
    }

    #[test]
    fn slashing_payout_offender_only_recipient_fails() {
        let params = SlashingParams::recommended_equivocation();
        let offender = [0xAA;32];
        let recipients = [offender];
        let ev = EvidenceKind::Equivocation { seat_id: offender, epoch_id: 1, a: pc_types::AnchorHeader::default(), b: Box::new(pc_types::AnchorHeader::default()) };
        let res = compute_slashing_payout_for_evidence(1000, &params, &recipients, &ev);
        assert!(res.is_err());
    }

    #[test]
    fn slashing_payout_vote_invalid_min_max() {
        // min 50% (5000 bp)
        let params_min = SlashingParams::recommended_vote_invalid(consts::SLASH_VOTE_INVALID_MIN_BP).unwrap();
        let offender = [0xBB;32];
        let recipients = [[0x10;32], offender];
        let ev = EvidenceKind::VoteInvalid { seat_id: offender, anchor: pc_types::AnchorHeader::default(), reason_code: 1 };
        let pot_min = split_bp(1000, consts::SLASH_VOTE_INVALID_MIN_BP);
        let set_min = compute_slashing_payout_for_evidence(1000, &params_min, &recipients, &ev).unwrap();
        let sum_min: u64 = set_min.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum_min, pot_min);
        assert_eq!(set_min.entries.len(), 1); // nur der nicht-Täter

        // max 100% (10000 bp)
        let params_max = SlashingParams::recommended_vote_invalid(consts::SLASH_VOTE_INVALID_MAX_BP).unwrap();
        let pot_max = split_bp(1000, consts::SLASH_VOTE_INVALID_MAX_BP);
        let set_max = compute_slashing_payout_for_evidence(1000, &params_max, &recipients, &ev).unwrap();
        let sum_max: u64 = set_max.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum_max, pot_max);
    }

    #[test]
    fn slashing_payout_large_bond_no_overflow() {
        let params = SlashingParams::recommended_equivocation();
        let offender = [0xCC;32];
        let recipients = [[0x01;32], [0x02;32], offender, [0x03;32]];
        let ev = EvidenceKind::Equivocation { seat_id: offender, epoch_id: 1, a: pc_types::AnchorHeader::default(), b: Box::new(pc_types::AnchorHeader::default()) };
        let bond: u64 = u64::MAX / 3;
        let pot = split_bp(bond, consts::SLASH_EQUIVOCATION_BP);
        let set = compute_slashing_payout_for_evidence(bond, &params, &recipients, &ev).unwrap();
        let sum: u64 = set.entries.iter().map(|e| e.amount).sum();
        assert_eq!(sum, pot);
    }

    #[test]
    #[ignore]
    fn dump_total_payout_root_spec_example() {
        // Beispiel für SPEC_FEES.md
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let att = [blake3_32(b"x"), blake3_32(b"y")];
        let fees = 42_000u64;
        let dists = [Some(1u8), Some(2u8), None];
        let root = compute_total_payout_root(fees, &params, &recipients, 1, &dists, &att).unwrap();
        println!("TOTAL_PAYOUT_ROOT_SPEC={}", hex::encode(root));
    }

    #[test]
    #[ignore]
    fn dump_total_payout_root_spec_example_case2() {
        // Zweites Beispiel für weiteren Golden-Test
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"r1"), blake3_32(b"r2"), blake3_32(b"r3"), blake3_32(b"r4")];
        let att = [blake3_32(b"a1"), blake3_32(b"a2"), blake3_32(b"a3")];
        let fees = 123_456_789u64;
        let dists = [Some(2u8), None, Some(1u8), Some(8u8)];
        let root = compute_total_payout_root(fees, &params, &recipients, 2, &dists, &att).unwrap();
        println!("TOTAL_PAYOUT_ROOT_SPEC2={}", hex::encode(root));
    }

    #[test]
    fn total_payout_root_golden() {
        // Golden-Test basierend auf SPEC_FEES-Beispiel (dump_total_payout_root_spec_example)
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"a"), blake3_32(b"b"), blake3_32(b"c")];
        let att = [blake3_32(b"x"), blake3_32(b"y")];
        let fees = 42_000u64;
        let dists = [Some(1u8), Some(2u8), None];
        let root = compute_total_payout_root(fees, &params, &recipients, 1, &dists, &att).unwrap();
        let hex_root = hex::encode(root);
        assert_eq!(hex_root, "668f75fc7225e3270bc17cdf864e11c4448a2066142621f926a3903cae7deb14");
    }

    #[test]
    fn total_payout_root_golden_case2() {
        // Golden-Test basierend auf dump_total_payout_root_spec_example_case2
        let params = FeeSplitParams::recommended();
        let recipients = [blake3_32(b"r1"), blake3_32(b"r2"), blake3_32(b"r3"), blake3_32(b"r4")];
        let att = [blake3_32(b"a1"), blake3_32(b"a2"), blake3_32(b"a3")];
        let fees = 123_456_789u64;
        let dists = [Some(2u8), None, Some(1u8), Some(8u8)];
        let root = compute_total_payout_root(fees, &params, &recipients, 2, &dists, &att).unwrap();
        let hex_root = hex::encode(root);
        // Wert wird nach Dump ermittelt und hier fixiert
        assert_eq!(hex_root, "873f050b731e01fb6e5acf78978dd6ac838f45ac48de53b29a171a213944545a");
    }
}
