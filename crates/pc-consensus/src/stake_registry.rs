// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Stake Registry: Verbindet gestakte UTXOs mit Validator-Kandidaten.
//!
//! Verantwortlich für:
//! - Tracking welche UTXOs für welchen Validator gestakt sind
//! - Berechnung des Gesamt-Stakes pro Validator
//! - Generierung von VrfCandidates aus gestakten UTXOs
//! - Persistierung in store_dir/stake_registry.json

use crate::committee_vrf::VrfCandidate;
use crate::consts::MIN_ATTESTOR_STAKE;
use pc_crypto::{bls_pop_verify, BlsPublicKey};
use pc_types::OutPoint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Ein gestakter UTXO-Eintrag
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakedUtxo {
    pub outpoint: OutPoint,
    pub amount: u64,
    pub staked_at_index: u64,
}

/// Validator-Registrierung mit gestakten UTXOs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    /// Eindeutige ID des Validators (z.B. Hash des BLS Public Key)
    pub validator_id: [u8; 32],
    /// Operator-ID (für Anti-Kollokation)
    pub operator_id: [u8; 32],
    /// BLS Public Key (48 Bytes, hex-encoded für JSON)
    pub bls_pk_hex: String,
    /// BLS Proof-of-Possession (96 Bytes, hex-encoded)
    pub bls_pop_hex: Option<String>,
    /// Alle gestakten UTXOs dieses Validators
    pub staked_utxos: Vec<StakedUtxo>,
    /// Letzter VRF-Proof (96 Bytes, hex-encoded)
    pub vrf_proof_hex: Option<String>,
    /// Wann zuletzt ins Committee gewählt
    pub last_selected_at: u64,
    /// Attendance-Prozentsatz (0-100)
    pub attendance_pct: u8,
}

impl ValidatorRegistration {
    /// Berechnet den Gesamt-Stake dieses Validators
    pub fn total_stake(&self) -> u64 {
        self.staked_utxos.iter().map(|u| u.amount).sum()
    }

    /// Prüft ob der gespeicherte BLS PoP zum BLS Public Key passt
    pub fn bls_pop_valid(&self) -> bool {
        let bls_pk = match hex_to_bls_pk(&self.bls_pk_hex) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let bls_pop_hex = match self.bls_pop_hex.as_ref() {
            Some(v) => v,
            None => return false,
        };
        let bls_pop = match hex_to_96(bls_pop_hex) {
            Ok(v) => v,
            Err(_) => return false,
        };
        bls_pop_verify(&bls_pk, &bls_pop)
    }

    /// Prüft ob der Validator das Minimum-Stake erfüllt
    pub fn meets_minimum(&self) -> bool {
        self.total_stake() >= MIN_ATTESTOR_STAKE
    }

    /// Konvertiert zu VrfCandidate (wenn VRF-Proof vorhanden)
    pub fn to_vrf_candidate(&self) -> Option<VrfCandidate> {
        let vrf_proof_hex = self.vrf_proof_hex.as_ref()?;
        let vrf_proof = hex_to_96(vrf_proof_hex).ok()?;
        let bls_pk = hex_to_bls_pk(&self.bls_pk_hex).ok()?;
        let bls_pop_hex = self.bls_pop_hex.as_ref()?;
        let bls_pop = hex_to_96(bls_pop_hex).ok()?;
        if !bls_pop_verify(&bls_pk, &bls_pop) {
            return None;
        }

        Some(VrfCandidate::with_stake(
            self.validator_id,
            self.operator_id,
            bls_pk,
            bls_pop,
            self.last_selected_at,
            self.attendance_pct,
            vrf_proof,
            self.total_stake(),
        ))
    }
}

/// Stake Registry: Verwaltet alle Validator-Registrierungen
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakeRegistry {
    /// Alle registrierten Validators (key = validator_id)
    pub validators: HashMap<[u8; 32], ValidatorRegistration>,
    /// Mapping: OutPoint -> validator_id (für schnelle Lookup)
    #[serde(skip)]
    outpoint_to_validator: HashMap<OutPoint, [u8; 32]>,
}

impl StakeRegistry {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            outpoint_to_validator: HashMap::new(),
        }
    }

    pub fn from_json_str(data: &str) -> Result<Self, String> {
        let mut reg: StakeRegistry =
            serde_json::from_str(data).map_err(|e| format!("parse stake_registry.json: {e}"))?;
        reg.rebuild_index();
        Ok(reg)
    }

    pub fn to_json_pretty(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize stake_registry: {e}"))
    }

    fn rebuild_index(&mut self) {
        self.outpoint_to_validator.clear();
        for (vid, v) in &self.validators {
            for utxo in &v.staked_utxos {
                self.outpoint_to_validator.insert(utxo.outpoint, *vid);
            }
        }
    }

    /// Registriert einen neuen Validator oder fügt UTXOs zu bestehendem hinzu
    pub fn register_validator(
        &mut self,
        validator_id: [u8; 32],
        operator_id: [u8; 32],
        bls_pk_hex: String,
        bls_pop_hex: String,
        utxos: Vec<StakedUtxo>,
    ) -> Result<(), String> {
        let bls_pk = hex_to_bls_pk(&bls_pk_hex)?;
        let bls_pop = hex_to_96(&bls_pop_hex)?;
        if !bls_pop_verify(&bls_pk, &bls_pop) {
            return Err("invalid BLS PoP for provided BLS public key".to_string());
        }

        // Prüfe ob UTXOs bereits anderweitig gestakt sind
        for utxo in &utxos {
            if let Some(existing_vid) = self.outpoint_to_validator.get(&utxo.outpoint) {
                if *existing_vid != validator_id {
                    return Err(format!(
                        "UTXO {:?} bereits für anderen Validator gestakt",
                        utxo.outpoint
                    ));
                }
            }
        }

        // Registriere oder update Validator
        let entry = self.validators.entry(validator_id).or_insert_with(|| {
            ValidatorRegistration {
                validator_id,
                operator_id,
                bls_pk_hex: bls_pk_hex.clone(),
                bls_pop_hex: Some(bls_pop_hex.clone()),
                staked_utxos: Vec::new(),
                vrf_proof_hex: None,
                last_selected_at: 0,
                attendance_pct: 100, // Optimistischer Start
            }
        });
        if entry.bls_pop_hex.is_none() {
            entry.bls_pop_hex = Some(bls_pop_hex.clone());
        }

        // Füge neue UTXOs hinzu
        for utxo in utxos {
            if !entry
                .staked_utxos
                .iter()
                .any(|u| u.outpoint == utxo.outpoint)
            {
                self.outpoint_to_validator
                    .insert(utxo.outpoint, validator_id);
                entry.staked_utxos.push(utxo);
            }
        }

        Ok(())
    }

    /// Setzt/aktualisiert BLS PoP für einen bestehenden Validator
    pub fn set_validator_pop(
        &mut self,
        validator_id: &[u8; 32],
        bls_pop_hex: String,
    ) -> Result<(), String> {
        let entry = self
            .validators
            .get_mut(validator_id)
            .ok_or_else(|| "Validator nicht gefunden".to_string())?;
        let bls_pk = hex_to_bls_pk(&entry.bls_pk_hex)?;
        let bls_pop = hex_to_96(&bls_pop_hex)?;
        if !bls_pop_verify(&bls_pk, &bls_pop) {
            return Err("invalid BLS PoP for stored BLS public key".to_string());
        }
        entry.bls_pop_hex = Some(bls_pop_hex);
        Ok(())
    }

    /// Entfernt UTXOs von einem Validator (Unstake)
    pub fn remove_utxos(
        &mut self,
        validator_id: &[u8; 32],
        outpoints: &[OutPoint],
    ) -> Result<(), String> {
        let entry = self
            .validators
            .get_mut(validator_id)
            .ok_or_else(|| "Validator nicht gefunden".to_string())?;

        for op in outpoints {
            entry.staked_utxos.retain(|u| u.outpoint != *op);
            self.outpoint_to_validator.remove(op);
        }

        // Entferne Validator wenn keine UTXOs mehr
        if entry.staked_utxos.is_empty() {
            self.validators.remove(validator_id);
        }

        Ok(())
    }

    /// Aktualisiert den VRF-Proof eines Validators
    pub fn update_vrf_proof(
        &mut self,
        validator_id: &[u8; 32],
        vrf_proof_hex: String,
    ) -> Result<(), String> {
        let entry = self
            .validators
            .get_mut(validator_id)
            .ok_or_else(|| "Validator nicht gefunden".to_string())?;
        entry.vrf_proof_hex = Some(vrf_proof_hex);
        Ok(())
    }

    /// Aktualisiert last_selected_at nach Committee-Wahl
    pub fn mark_selected(&mut self, validator_id: &[u8; 32], anchor_index: u64) {
        if let Some(entry) = self.validators.get_mut(validator_id) {
            entry.last_selected_at = anchor_index;
        }
    }

    /// Aktualisiert Attendance
    pub fn update_attendance(&mut self, validator_id: &[u8; 32], attended: bool) {
        if let Some(entry) = self.validators.get_mut(validator_id) {
            // Simple EMA mit alpha=0.1
            let new_val = if attended { 100u8 } else { 0u8 };
            entry.attendance_pct = ((entry.attendance_pct as u16 * 9 + new_val as u16) / 10) as u8;
        }
    }

    /// Generiert Liste aller VrfCandidates die das Minimum erfüllen
    pub fn eligible_candidates(&self) -> Vec<VrfCandidate> {
        self.validators
            .values()
            .filter(|v| v.meets_minimum())
            .filter_map(|v| v.to_vrf_candidate())
            .collect()
    }

    /// Gibt den Gesamt-Stake eines Validators zurück
    pub fn get_stake(&self, validator_id: &[u8; 32]) -> u64 {
        self.validators
            .get(validator_id)
            .map(|v| v.total_stake())
            .unwrap_or(0)
    }

    /// Prüft ob ein UTXO bereits gestakt ist
    pub fn is_utxo_staked(&self, outpoint: &OutPoint) -> bool {
        self.outpoint_to_validator.contains_key(outpoint)
    }

    /// Anzahl der registrierten Validators
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Anzahl der Validators die das Minimum erfüllen
    pub fn eligible_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.meets_minimum())
            .count()
    }

    /// Wendet Slashing auf einen Validator an.
    /// Reduziert den Stake proportional von allen UTXOs.
    /// Entfernt Validator automatisch wenn Stake unter MIN_ATTESTOR_STAKE fällt.
    ///
    /// Returns: SlashResult mit Details zur Aktion
    pub fn apply_slash(
        &mut self,
        validator_id: &[u8; 32],
        slash_amount: u64,
    ) -> Result<SlashResult, String> {
        let entry = self
            .validators
            .get_mut(validator_id)
            .ok_or_else(|| "Validator nicht gefunden".to_string())?;

        let stake_before = entry.total_stake();
        if stake_before == 0 {
            return Ok(SlashResult {
                slashed_amount: 0,
                stake_before,
                stake_after: 0,
                removed: false,
            });
        }

        // Proportionale Reduktion aller UTXOs
        let actual_slash = slash_amount.min(stake_before);
        if actual_slash > 0 && !entry.staked_utxos.is_empty() {
            // Berechne Reduktionsfaktor (in Basispunkten für Präzision)
            let reduction_bp = (actual_slash as u128 * 10_000) / stake_before as u128;

            for utxo in entry.staked_utxos.iter_mut() {
                let reduction = (utxo.amount as u128 * reduction_bp / 10_000) as u64;
                utxo.amount = utxo.amount.saturating_sub(reduction);
            }

            // Entferne UTXOs mit 0 Betrag
            let outpoints_to_remove: Vec<_> = entry
                .staked_utxos
                .iter()
                .filter(|u| u.amount == 0)
                .map(|u| u.outpoint)
                .collect();
            for op in &outpoints_to_remove {
                self.outpoint_to_validator.remove(op);
            }
            entry.staked_utxos.retain(|u| u.amount > 0);
        }

        let stake_after = entry.total_stake();
        let removed = stake_after < MIN_ATTESTOR_STAKE || entry.staked_utxos.is_empty();

        // Entferne Validator wenn unter Minimum oder keine UTXOs mehr
        if removed {
            // Cleanup outpoint mappings
            for utxo in &entry.staked_utxos {
                self.outpoint_to_validator.remove(&utxo.outpoint);
            }
            self.validators.remove(validator_id);
        }

        Ok(SlashResult {
            slashed_amount: actual_slash,
            stake_before,
            stake_after,
            removed,
        })
    }

    /// Prüft ob ein Validator noch eligible ist (existiert und meets_minimum)
    pub fn is_eligible(&self, validator_id: &[u8; 32]) -> bool {
        self.validators
            .get(validator_id)
            .map(|v| v.meets_minimum())
            .unwrap_or(false)
    }
}

/// Ergebnis einer Slashing-Operation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashResult {
    /// Tatsächlich geslashter Betrag
    pub slashed_amount: u64,
    /// Stake vor dem Slashing
    pub stake_before: u64,
    /// Stake nach dem Slashing
    pub stake_after: u64,
    /// Wurde der Validator entfernt (unter Minimum oder keine UTXOs)
    pub removed: bool,
}

// Helper functions
fn hex_to_96(hex: &str) -> Result<[u8; 96], String> {
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 96 {
        return Err(format!("expected 96 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn hex_to_bls_pk(hex: &str) -> Result<BlsPublicKey, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 48 {
        return Err(format!("expected 48 bytes for BLS PK, got {}", bytes.len()));
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    BlsPublicKey::from_bytes(&arr).ok_or_else(|| "invalid BLS public key".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_crypto::{blake3_32, bls_keygen_from_ikm, bls_pop_prove};

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: [txid_byte; 32],
            vout,
        }
    }

    #[test]
    fn register_and_total_stake() {
        let mut reg = StakeRegistry::new();
        let ikm = blake3_32(b"reg-1");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let vid = blake3_32(&kp.pk.to_bytes());
        let oid = [2u8; 32];
        let bls_hex = hex::encode(kp.pk.to_bytes());
        let bls_pop_hex = hex::encode(bls_pop_prove(&kp.sk));

        let min = crate::consts::MIN_ATTESTOR_STAKE;
        // Minimum Stake (Summe der UTXOs)
        let utxos = vec![
            StakedUtxo {
                outpoint: make_outpoint(1, 0),
                amount: min / 2,
                staked_at_index: 100,
            },
            StakedUtxo {
                outpoint: make_outpoint(2, 0),
                amount: min / 2,
                staked_at_index: 100,
            },
        ];

        reg.register_validator(vid, oid, bls_hex, bls_pop_hex, utxos)
            .unwrap();

        assert_eq!(reg.validator_count(), 1);
        assert_eq!(reg.get_stake(&vid), min);
        assert!(reg.validators.get(&vid).unwrap().meets_minimum());
    }

    #[test]
    fn remove_utxos_works() {
        let mut reg = StakeRegistry::new();
        let ikm = blake3_32(b"reg-2");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let vid = blake3_32(&kp.pk.to_bytes());
        let oid = [2u8; 32];
        let bls_hex = hex::encode(kp.pk.to_bytes());
        let bls_pop_hex = hex::encode(bls_pop_prove(&kp.sk));

        let op1 = make_outpoint(1, 0);
        let op2 = make_outpoint(2, 0);

        let utxos = vec![
            StakedUtxo {
                outpoint: op1,
                amount: 5_000_000_000,
                staked_at_index: 100,
            },
            StakedUtxo {
                outpoint: op2,
                amount: 5_000_000_000,
                staked_at_index: 100,
            },
        ];

        reg.register_validator(vid, oid, bls_hex, bls_pop_hex, utxos)
            .unwrap();
        assert_eq!(reg.get_stake(&vid), 10_000_000_000);

        reg.remove_utxos(&vid, &[op1]).unwrap();
        assert_eq!(reg.get_stake(&vid), 5_000_000_000);
        assert!(!reg.is_utxo_staked(&op1));
        assert!(reg.is_utxo_staked(&op2));
    }

    #[test]
    fn double_stake_rejected() {
        let mut reg = StakeRegistry::new();
        let ikm = blake3_32(b"reg-3");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let vid1 = blake3_32(&kp.pk.to_bytes());
        let vid2 = [2u8; 32];
        let oid = [3u8; 32];
        let bls_hex = hex::encode(kp.pk.to_bytes());
        let bls_pop_hex = hex::encode(bls_pop_prove(&kp.sk));

        let op = make_outpoint(1, 0);
        let utxo = StakedUtxo {
            outpoint: op,
            amount: 10_000_000_000,
            staked_at_index: 100,
        };

        reg.register_validator(
            vid1,
            oid,
            bls_hex.clone(),
            bls_pop_hex.clone(),
            vec![utxo.clone()],
        )
        .unwrap();

        // Versuch denselben UTXO für anderen Validator zu staken
        let result = reg.register_validator(vid2, oid, bls_hex, bls_pop_hex, vec![utxo]);
        assert!(result.is_err());
    }

    #[test]
    fn apply_slash_reduces_stake() {
        let mut reg = StakeRegistry::new();
        let ikm = blake3_32(b"slash-1");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let vid = blake3_32(&kp.pk.to_bytes());
        let oid = [2u8; 32];
        let bls_hex = hex::encode(kp.pk.to_bytes());
        let bls_pop_hex = hex::encode(bls_pop_prove(&kp.sk));

        let min = crate::consts::MIN_ATTESTOR_STAKE;
        // 2x Minimum Stake
        let utxos = vec![
            StakedUtxo {
                outpoint: make_outpoint(1, 0),
                amount: min,
                staked_at_index: 100,
            },
            StakedUtxo {
                outpoint: make_outpoint(2, 0),
                amount: min,
                staked_at_index: 100,
            },
        ];

        reg.register_validator(vid, oid, bls_hex, bls_pop_hex, utxos)
            .unwrap();
        assert_eq!(reg.get_stake(&vid), min * 2);

        // Slash 25%
        let slash_amount = (min * 2) / 4;
        let result = reg.apply_slash(&vid, slash_amount).unwrap();
        assert_eq!(result.slashed_amount, slash_amount);
        assert_eq!(result.stake_before, min * 2);
        assert!(!result.removed); // Noch über Minimum
        assert!(reg.is_eligible(&vid));
    }

    #[test]
    fn apply_slash_removes_below_minimum() {
        let mut reg = StakeRegistry::new();
        let ikm = blake3_32(b"slash-2");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let vid = blake3_32(&kp.pk.to_bytes());
        let oid = [2u8; 32];
        let bls_hex = hex::encode(kp.pk.to_bytes());
        let bls_pop_hex = hex::encode(bls_pop_prove(&kp.sk));

        let min = crate::consts::MIN_ATTESTOR_STAKE;
        // Exakt Minimum
        let utxos = vec![StakedUtxo {
            outpoint: make_outpoint(1, 0),
            amount: min,
            staked_at_index: 100,
        }];

        reg.register_validator(vid, oid, bls_hex, bls_pop_hex, utxos)
            .unwrap();
        assert!(reg.is_eligible(&vid));

        // Slash 2 PC (>= 1bp) -> unter Minimum
        let slash_amount = min / 10_000;
        let result = reg.apply_slash(&vid, slash_amount).unwrap();
        assert!(result.removed);
        assert!(!reg.is_eligible(&vid));
        assert_eq!(reg.validator_count(), 0);
    }

    #[test]
    fn apply_slash_100pct_removes_validator() {
        let mut reg = StakeRegistry::new();
        let ikm = blake3_32(b"slash-3");
        let kp = bls_keygen_from_ikm(&ikm).unwrap();
        let vid = blake3_32(&kp.pk.to_bytes());
        let oid = [2u8; 32];
        let bls_hex = hex::encode(kp.pk.to_bytes());
        let bls_pop_hex = hex::encode(bls_pop_prove(&kp.sk));

        let min = crate::consts::MIN_ATTESTOR_STAKE;
        let utxos = vec![StakedUtxo {
            outpoint: make_outpoint(1, 0),
            amount: min,
            staked_at_index: 100,
        }];

        reg.register_validator(vid, oid, bls_hex, bls_pop_hex, utxos)
            .unwrap();

        // Slash 100%
        let result = reg.apply_slash(&vid, min).unwrap();
        assert!(result.removed);
        assert_eq!(result.stake_after, 0);
        assert_eq!(reg.validator_count(), 0);
    }
}
