// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

use pc_types::{Amount, AnchorHeader, AnchorId, PayoutEntry, PayoutSet};
pub mod consts;

#[derive(Debug)]
pub enum ConsensusError {
    IndexOutOfRange,
    InvalidParams,
}

impl Default for AnchorGraph {
    fn default() -> Self {
        Self::new()
    }
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
pub fn finality_threshold(k: u8) -> u8 {
    // T = floor(2k/3) + 1
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

#[inline]
pub fn set_bit(mask: u64, index: u8) -> Result<u64, ConsensusError> {
    if index >= 64 {
        return Err(ConsensusError::IndexOutOfRange);
    }
    let bit = 1u64 << (index as u64);
    Ok(mask | bit)
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
}

impl ConsensusConfig {
    /// Empfohlene Startkonfiguration mit gegebenem k
    pub fn recommended(k: u8) -> Self {
        Self {
            k,
            fee_params: FeeSplitParams::recommended(),
        }
    }
}

/// Konsens-Engine kapselt Graph/Cache und stellt API für Ack-Distanzen,
/// Finalitätsprüfung sowie (Committee-)Payout bereit.
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
        let k = self.cfg.k;
        let d_max = self.cfg.fee_params.d_max;
        self.cache.compute_ack_distances(ack_id, k, d_max)
    }

    /// Prüfe Finalität über vote_mask-Popcount gegen Threshold T=floor(2k/3)+1
    /// Erwartet, dass das übergebene vote_mask die Stimmen der k Seats kodiert (u64 reicht k<=64)
    pub fn is_final_mask(&self, vote_mask: u64) -> bool {
        is_final(popcount_u64(vote_mask), self.cfg.k)
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
}
