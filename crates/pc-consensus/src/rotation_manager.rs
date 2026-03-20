// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Rotation State Management für Committee und Attestor Pools
//!
//! Verwaltet:
//! - Current Committee/Attestors
//! - Attendance Tracking
//! - Selection History
//! - Epoch-basierte Rotation Trigger

use crate::committee_vrf::{
    derive_epoch, derive_vrf_seed, RotationParams, SelectedSeat, VrfCandidate,
};
use pc_types::{AnchorId, NetworkId};
use std::collections::HashMap;

/// Netzwerk-Skalierung: dynamische Shard-Anzahl und Committee-Größe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkScale {
    pub num_shards: u16,
    pub k: u8,
}

/// Berechnet die Netzwerk-Skalierung basierend auf der Pool-Größe.
///
/// - `k` wächst von 1 bis `MAX_K` (21), proportional zur Validator-Anzahl.
/// - `num_shards` wächst erst, wenn `k == MAX_K`, dann `floor(pool_size / MAX_K)` bis `MAX_SHARDS` (64).
///
/// Ergebnis: 1 Validator → (1 Shard, K=1), 1344 Validatoren → (64 Shards, K=21).
pub fn compute_network_scale(pool_size: usize) -> NetworkScale {
    const MAX_K: usize = 21;
    const MAX_SHARDS: usize = 64;

    let k = std::cmp::max(1, std::cmp::min(MAX_K, pool_size)) as u8;

    let num_shards = if pool_size >= MAX_K {
        std::cmp::max(1, std::cmp::min(MAX_SHARDS, pool_size / MAX_K)) as u16
    } else {
        1
    };

    NetworkScale { num_shards, k }
}

/// Attendance-Record für einen Validator
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttendanceRecord {
    pub total_rounds: u32,
    pub attended_rounds: u32,
    pub recent_pct: u8, // cached percentage
}

impl AttendanceRecord {
    pub fn new() -> Self {
        Self {
            total_rounds: 0,
            attended_rounds: 0,
            recent_pct: 100, // optimistischer Start
        }
    }

    /// Update attendance nach einer Round
    pub fn record_attendance(&mut self, attended: bool) {
        self.total_rounds = self.total_rounds.saturating_add(1);
        if attended {
            self.attended_rounds = self.attended_rounds.saturating_add(1);
        }

        // Berechne Prozentsatz (über letzten N Rounds)
        // Für Simplicity: verwende alle rounds (könnte auf sliding window optimiert werden)
        if self.total_rounds > 0 {
            let pct = (self.attended_rounds as u64 * 100) / self.total_rounds as u64;
            self.recent_pct = pct.min(100) as u8;
        }
    }

    /// Reset für neuen Validator (oder Sliding Window)
    pub fn reset(&mut self) {
        self.total_rounds = 0;
        self.attended_rounds = 0;
        self.recent_pct = 100;
    }
}

impl Default for AttendanceRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Rotation-History-Eintrag
#[derive(Clone, Debug)]
pub struct RotationRecord {
    pub epoch: u64,
    pub anchor_index: u64,
    pub selected_seats: Vec<SelectedSeat>,
    /// Dynamische Anzahl der Shards für diese Epoche
    pub num_shards: u16,
    /// Dynamische Committee-Größe (k) für diese Epoche
    pub k: u8,
    /// Committees pro Shard (shard_id → seats). Leer bei num_shards <= 1.
    pub shard_committees: HashMap<u16, Vec<SelectedSeat>>,
}

/// Rotation Manager
pub struct RotationManager {
    /// Aktuelles Committee (globales Flat-Committee, Vereinigung aller Shards)
    pub current_committee: Vec<SelectedSeat>,

    /// Committees pro Shard (shard_id → seats). Bei num_shards <= 1 enthält nur Key 0.
    pub current_shard_committees: HashMap<u16, Vec<SelectedSeat>>,

    /// Aktuelle Attestoren
    pub current_attestors: Vec<SelectedSeat>,

    /// Letzte Rotation-Epoch
    pub last_rotation_epoch: u64,

    /// Attendance-Records (recipient_id → record)
    pub attendance_records: HashMap<[u8; 32], AttendanceRecord>,

    /// Selection-History (begrenzt auf letzten N Einträge)
    pub selection_history: Vec<RotationRecord>,

    /// Max history entries
    pub max_history: usize,

    /// Operator selection counts (operator_id → count in recent history)
    pub recent_op_selection_count: HashMap<[u8; 32], u32>,
}

impl RotationManager {
    /// Berechnet die Netzwerk-Skalierung basierend auf der Pool-Größe.
    /// Delegiert an die freistehende `compute_network_scale`-Funktion.
    pub fn compute_network_scale(pool_size: usize) -> NetworkScale {
        compute_network_scale(pool_size)
    }

    /// Erstellt einen neuen RotationManager
    pub fn new(max_history: usize) -> Self {
        Self {
            current_committee: Vec::new(),
            current_shard_committees: HashMap::new(),
            current_attestors: Vec::new(),
            last_rotation_epoch: 0,
            attendance_records: HashMap::new(),
            selection_history: Vec::new(),
            max_history,
            recent_op_selection_count: HashMap::new(),
        }
    }

    /// Prüft ob Rotation nötig ist
    pub fn should_rotate(&self, current_anchor_index: u64, epoch_len: u64) -> bool {
        let current_epoch = derive_epoch(current_anchor_index, epoch_len);
        current_epoch > self.last_rotation_epoch
    }

    /// Führt Committee-Rotation durch
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_committee(
        &mut self,
        current_anchor_index: u64,
        epoch_len: u64,
        network_id: NetworkId,
        last_anchor_id: AnchorId,
        candidates: &[VrfCandidate],
        params: &RotationParams,
    ) -> Result<(), String> {
        let epoch = derive_epoch(current_anchor_index, epoch_len);
        let seed = derive_vrf_seed(network_id, last_anchor_id);

        // Netzwerk-Skalierung berechnen
        let scale = Self::compute_network_scale(candidates.len());
        let current_shards = scale.num_shards;
        let current_k = scale.k;

        // VRF-Verifikation mit globalem Seed, dann deterministische Shard-Aufteilung
        let shard_committees = crate::committee_vrf::committee_select_vrf_sharded(
            current_k,
            epoch,
            seed,
            current_anchor_index,
            candidates,
            params,
            current_shards,
        );

        // Flat-Liste aller Seats (Vereinigung)
        let mut all_seats: Vec<SelectedSeat> = Vec::new();
        for shard_id in 0..current_shards {
            if let Some(seats) = shard_committees.get(&shard_id) {
                all_seats.extend(seats.iter().cloned());
            }
        }

        // Prüfe ob mindestens ein Shard ein Committee hat
        let any_selected = shard_committees.values().any(|v| !v.is_empty());
        if !any_selected && current_k > 0 {
            return Err("No eligible candidates for committee selection".to_string());
        }

        // Update State
        self.current_committee = all_seats.clone();
        self.current_shard_committees = shard_committees.clone();
        self.last_rotation_epoch = epoch;

        // Update operator selection counts
        for seat in &all_seats {
            *self
                .recent_op_selection_count
                .entry(seat.operator_id)
                .or_insert(0) += 1;
        }

        // History speichern
        self.add_rotation_record(RotationRecord {
            epoch,
            anchor_index: current_anchor_index,
            selected_seats: all_seats,
            num_shards: current_shards,
            k: current_k,
            shard_committees,
        });

        Ok(())
    }

    /// Führt Attestor-Rotation durch
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_attestors(
        &mut self,
        m: u16,
        current_anchor_index: u64,
        epoch_len: u64,
        network_id: NetworkId,
        last_anchor_id: AnchorId,
        candidates: &[VrfCandidate],
        params: &RotationParams,
    ) -> Result<(), String> {
        // Wähle Attestoren
        let selected = crate::attestor_pool::attestor_sample_vrf(
            m,
            current_anchor_index,
            epoch_len,
            network_id,
            last_anchor_id,
            candidates,
            params,
        );

        if selected.is_empty() && m > 0 {
            return Err("No eligible candidates for attestor selection".to_string());
        }

        // Update State
        self.current_attestors = selected.clone();

        // Update operator selection counts
        for seat in &selected {
            *self
                .recent_op_selection_count
                .entry(seat.operator_id)
                .or_insert(0) += 1;
        }

        Ok(())
    }

    /// Rotiere Attestoren mit Fairness-Features
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_attestors_fair(
        &mut self,
        m: u16,
        current_anchor_index: u64,
        epoch_len: u64,
        network_id: NetworkId,
        last_anchor_id: AnchorId,
        candidates: &[VrfCandidate],
        params: &RotationParams,
        cap_limit_per_op: u32,
        perf_index: &HashMap<[u8; 32], u32>,
    ) -> Result<(), String> {
        let selected = crate::attestor_pool::attestor_sample_vrf_fair(
            m,
            current_anchor_index,
            epoch_len,
            network_id,
            last_anchor_id,
            candidates,
            params,
            &self.recent_op_selection_count,
            cap_limit_per_op,
            perf_index,
        );

        if selected.is_empty() && m > 0 {
            return Err("No eligible candidates for fair attestor selection".to_string());
        }

        self.current_attestors = selected;
        Ok(())
    }

    /// Update Attendance für einen Validator
    pub fn update_attendance(&mut self, recipient_id: [u8; 32], attended: bool) {
        let record = self.attendance_records.entry(recipient_id).or_default();
        record.record_attendance(attended);
    }

    /// Hole Attendance-Prozentsatz
    pub fn get_attendance_pct(&self, recipient_id: &[u8; 32]) -> u8 {
        self.attendance_records
            .get(recipient_id)
            .map(|r| r.recent_pct)
            .unwrap_or(100) // Optimistischer Default für neue Validatoren
    }

    /// Reset operator selection counts (z.B. alle N Epochen)
    pub fn reset_operator_counts(&mut self) {
        self.recent_op_selection_count.clear();
    }

    /// Füge Rotation-Record hinzu
    fn add_rotation_record(&mut self, record: RotationRecord) {
        self.selection_history.push(record);

        // Begrenze History-Größe
        if self.selection_history.len() > self.max_history {
            self.selection_history.remove(0);
        }
    }

    /// Hole aktuelles Committee (Vereinigung aller Shards)
    pub fn current_committee(&self) -> &[SelectedSeat] {
        &self.current_committee
    }

    /// Hole Committee für einen bestimmten Shard
    pub fn committee_for_shard(&self, shard_id: u16) -> &[SelectedSeat] {
        self.current_shard_committees
            .get(&shard_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Bestimmt alle Shards, in denen ein Validator (recipient_id) aktuell als Committee-Member sitzt.
    pub fn get_active_shards_for_validator(&self, recipient_id: &[u8; 32]) -> Vec<u16> {
        let mut shards: Vec<u16> = self
            .current_shard_committees
            .iter()
            .filter(|(_, seats)| seats.iter().any(|s| &s.recipient_id == recipient_id))
            .map(|(&shard_id, _)| shard_id)
            .collect();
        shards.sort_unstable();
        shards
    }

    /// Hole aktuelle Attestoren
    pub fn current_attestors(&self) -> &[SelectedSeat] {
        &self.current_attestors
    }

    /// Hole Rotation-History
    pub fn rotation_history(&self) -> &[RotationRecord] {
        &self.selection_history
    }

    /// Export State für Persistierung
    pub fn export_state(&self) -> RotationManagerState {
        RotationManagerState {
            current_committee: self.current_committee.clone(),
            current_attestors: self.current_attestors.clone(),
            last_rotation_epoch: self.last_rotation_epoch,
            attendance_records: self.attendance_records.clone(),
            recent_op_selection_count: self.recent_op_selection_count.clone(),
        }
    }

    /// Import State von Persistierung
    pub fn import_state(&mut self, state: RotationManagerState) {
        self.current_committee = state.current_committee;
        self.current_attestors = state.current_attestors;
        self.last_rotation_epoch = state.last_rotation_epoch;
        self.attendance_records = state.attendance_records;
        self.recent_op_selection_count = state.recent_op_selection_count;
    }
}

/// Serializable State für Persistierung
#[derive(Clone, Debug)]
pub struct RotationManagerState {
    pub current_committee: Vec<SelectedSeat>,
    pub current_attestors: Vec<SelectedSeat>,
    pub last_rotation_epoch: u64,
    pub attendance_records: HashMap<[u8; 32], AttendanceRecord>,
    pub recent_op_selection_count: HashMap<[u8; 32], u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_pop_prove, bls_vrf_prove};

    fn vrf_msg(seed: &[u8; 32], epoch: u64) -> Vec<u8> {
        const VRF_MSG_DOMAIN: &[u8] = b"pc:vrf:committee:v1\x01";
        let mut m = Vec::with_capacity(VRF_MSG_DOMAIN.len() + 32 + 8);
        m.extend_from_slice(VRF_MSG_DOMAIN);
        m.extend_from_slice(seed);
        m.extend_from_slice(&epoch.to_le_bytes());
        m
    }

    #[test]
    fn rotation_manager_init() {
        let mgr = RotationManager::new(100);
        assert_eq!(mgr.current_committee.len(), 0);
        assert_eq!(mgr.current_attestors.len(), 0);
        assert_eq!(mgr.last_rotation_epoch, 0);
        assert_eq!(mgr.selection_history.len(), 0);
    }

    #[test]
    fn should_rotate_triggers_on_epoch_change() {
        let mut mgr = RotationManager::new(100);
        mgr.last_rotation_epoch = 5;

        // Gleiche Epoch → keine Rotation
        assert!(!mgr.should_rotate(50_000, 10_000)); // epoch = 5

        // Nächste Epoch → Rotation
        assert!(mgr.should_rotate(60_000, 10_000)); // epoch = 6
    }

    #[test]
    fn rotate_committee_success() {
        let mut mgr = RotationManager::new(10);
        let network_id = blake3_32(b"test-net");
        let anchor_id = AnchorId(blake3_32(b"anchor-0"));
        let current_anchor_index = 10_000u64;
        let epoch_len = 10_000u64;
        let epoch = derive_epoch(current_anchor_index, epoch_len);
        let seed = derive_vrf_seed(network_id, anchor_id);

        let mut candidates = Vec::new();
        for i in 0..5u8 {
            let ikm = blake3_32(&[b'C', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
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

        let result = mgr.rotate_committee(
            current_anchor_index,
            epoch_len,
            network_id,
            anchor_id,
            &candidates,
            &RotationParams {
                cooldown_anchors: 0,
                min_attendance_pct: 0,
            },
        );

        assert!(result.is_ok());
        assert_eq!(mgr.selection_history.len(), 1);
        assert_eq!(mgr.selection_history[0].num_shards, 1); // 5 < 21 → 1 Shard
        assert_eq!(mgr.selection_history[0].k, 5);
        // Bei 1 Shard: genau ein Shard-Committee (Key 0)
        assert_eq!(mgr.current_shard_committees.len(), 1);
        assert!(mgr.current_shard_committees.contains_key(&0));
        assert_eq!(
            mgr.committee_for_shard(0).len(),
            mgr.current_committee.len()
        );
    }

    #[test]
    fn rotate_committee_no_eligible_fails() {
        let mut mgr = RotationManager::new(10);
        let network_id = blake3_32(b"test-net");
        let anchor_id = AnchorId(blake3_32(b"anchor-1"));
        let current_anchor_index = 10_000u64;
        let epoch_len = 10_000u64;
        let epoch = derive_epoch(current_anchor_index, epoch_len);
        let seed = derive_vrf_seed(network_id, anchor_id);

        // Alle Kandidaten mit niedriger Attendance
        let mut candidates = Vec::new();
        for i in 0..3u8 {
            let ikm = blake3_32(&[b'N', i]);
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = vrf_msg(&seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);
            candidates.push(VrfCandidate::new(
                blake3_32(&[b'R', i]),
                blake3_32(&[b'O', i]),
                kp.pk,
                bls_pop_prove(&kp.sk),
                0,
                50, // unter threshold
                proof,
            ));
        }

        let result = mgr.rotate_committee(
            current_anchor_index,
            epoch_len,
            network_id,
            anchor_id,
            &candidates,
            &RotationParams {
                cooldown_anchors: 0,
                min_attendance_pct: 90, // sehr hoch
            },
        );

        assert!(result.is_err());
        assert!(mgr.current_committee.is_empty());
    }

    #[test]
    fn attendance_tracking_works() {
        let mut mgr = RotationManager::new(10);
        let recipient_id = blake3_32(b"validator-1");

        // Initial: optimistic 100%
        assert_eq!(mgr.get_attendance_pct(&recipient_id), 100);

        // 10 Rounds: 8 attended
        for i in 0..10 {
            mgr.update_attendance(recipient_id, i < 8);
        }

        let pct = mgr.get_attendance_pct(&recipient_id);
        assert_eq!(pct, 80); // 8/10 = 80%
    }

    #[test]
    fn operator_selection_counts_tracked() {
        let mut mgr = RotationManager::new(10);
        let network_id = blake3_32(b"test-net");
        let anchor_id = AnchorId(blake3_32(b"anchor-2"));

        let params = RotationParams {
            cooldown_anchors: 0,
            min_attendance_pct: 0,
        };

        let op_id = blake3_32(b"operator-A");

        let mut candidates = Vec::new();
        let current_anchor_index = 20_000u64;
        let epoch_len = 10_000u64;
        let epoch = derive_epoch(current_anchor_index, epoch_len);
        let seed = derive_vrf_seed(network_id, anchor_id);

        // Kandidat mit op_id
        let ikm = blake3_32(b"K1");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let msg = vrf_msg(&seed, epoch);
        let (proof, _) = bls_vrf_prove(&msg, &kp.sk);

        candidates.push(VrfCandidate::new(
            blake3_32(b"R1"),
            op_id,
            kp.pk,
            bls_pop_prove(&kp.sk),
            0,
            100,
            proof,
        ));

        mgr.rotate_committee(
            current_anchor_index,
            epoch_len,
            network_id,
            anchor_id,
            &candidates,
            &params,
        )
        .unwrap();

        assert_eq!(mgr.recent_op_selection_count.get(&op_id), Some(&1));
    }

    #[test]
    fn history_limited_to_max() {
        let mut mgr = RotationManager::new(3); // max 3 entries

        for i in 0..5 {
            mgr.add_rotation_record(RotationRecord {
                epoch: i,
                anchor_index: i * 1000,
                selected_seats: vec![],
                num_shards: 1,
                k: 1,
                shard_committees: HashMap::new(),
            });
        }

        assert_eq!(mgr.selection_history.len(), 3);
        assert_eq!(mgr.selection_history[0].epoch, 2); // oldest = 2
        assert_eq!(mgr.selection_history[2].epoch, 4); // newest = 4
    }

    #[test]
    fn state_export_import_roundtrip() {
        let mut mgr1 = RotationManager::new(10);
        let recipient_id = blake3_32(b"val-1");
        mgr1.update_attendance(recipient_id, true);
        mgr1.last_rotation_epoch = 42;

        let state = mgr1.export_state();

        let mut mgr2 = RotationManager::new(10);
        mgr2.import_state(state);

        assert_eq!(mgr2.last_rotation_epoch, 42);
        assert_eq!(mgr2.get_attendance_pct(&recipient_id), 100);
    }

    /// Helper: Erzeugt N gültige VrfCandidates mit eindeutigen operator_ids.
    fn make_candidates(n: usize, seed: &[u8; 32], epoch: u64) -> Vec<VrfCandidate> {
        let mut candidates = Vec::with_capacity(n);
        for i in 0..n {
            let idx = i as u16;
            let ikm = blake3_32(&[&[b'G'][..], &idx.to_le_bytes()].concat());
            let kp = bls_keygen_from_ikm(&ikm).unwrap();
            let msg = vrf_msg(seed, epoch);
            let (proof, _) = bls_vrf_prove(&msg, &kp.sk);
            candidates.push(VrfCandidate::new(
                blake3_32(&[&[b'R'][..], &idx.to_le_bytes()].concat()),
                blake3_32(&[&[b'O'][..], &idx.to_le_bytes()].concat()),
                kp.pk,
                bls_pop_prove(&kp.sk),
                0,
                100,
                proof,
            ));
        }
        candidates
    }

    #[test]
    fn multi_shard_committees_distinct_seeds() {
        let mut mgr = RotationManager::new(10);
        let network_id = blake3_32(b"test-net-multi");
        let anchor_id = AnchorId(blake3_32(b"anchor-ms"));
        let current_anchor_index = 10_000u64;
        let epoch_len = 10_000u64;
        let epoch = derive_epoch(current_anchor_index, epoch_len);
        let seed = derive_vrf_seed(network_id, anchor_id);

        // 42 Kandidaten → compute_network_scale(42) = num_shards=2, k=21
        let candidates = make_candidates(42, &seed, epoch);

        let result = mgr.rotate_committee(
            current_anchor_index,
            epoch_len,
            network_id,
            anchor_id,
            &candidates,
            &RotationParams {
                cooldown_anchors: 0,
                min_attendance_pct: 0,
            },
        );

        assert!(result.is_ok());
        let record = &mgr.selection_history[0];
        assert_eq!(record.num_shards, 2);
        assert_eq!(record.k, 21);
        assert_eq!(mgr.current_shard_committees.len(), 2);
        // Jeder Shard hat ein Committee
        assert!(!mgr.committee_for_shard(0).is_empty());
        assert!(!mgr.committee_for_shard(1).is_empty());
        // Nicht-existenter Shard → leer
        assert!(mgr.committee_for_shard(99).is_empty());
    }

    #[test]
    fn get_active_shards_for_validator_works() {
        let mut mgr = RotationManager::new(10);
        let network_id = blake3_32(b"test-net-shards");
        let anchor_id = AnchorId(blake3_32(b"anchor-sh"));
        let current_anchor_index = 10_000u64;
        let epoch_len = 10_000u64;
        let epoch = derive_epoch(current_anchor_index, epoch_len);
        let seed = derive_vrf_seed(network_id, anchor_id);

        // 42 Kandidaten → 2 Shards
        let candidates = make_candidates(42, &seed, epoch);

        mgr.rotate_committee(
            current_anchor_index,
            epoch_len,
            network_id,
            anchor_id,
            &candidates,
            &RotationParams {
                cooldown_anchors: 0,
                min_attendance_pct: 0,
            },
        )
        .unwrap();

        // Mindestens ein Validator sollte in mindestens einem Shard sein
        let mut found_any = false;
        for c in &candidates {
            let shards = mgr.get_active_shards_for_validator(&c.recipient_id);
            if !shards.is_empty() {
                found_any = true;
                // Shards müssen sortiert und im gültigen Bereich sein
                for &s in &shards {
                    assert!(s < 2);
                }
            }
        }
        assert!(
            found_any,
            "mindestens ein Validator muss in einem Shard sitzen"
        );

        // Unbekannter Validator → keine Shards
        let unknown = blake3_32(b"unknown-validator");
        assert!(mgr.get_active_shards_for_validator(&unknown).is_empty());
    }
}
