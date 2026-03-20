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
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::useless_vec
    )
)]

use pc_crypto::{
    attestor_recipient_id_from_bls, blake3_32, bls_pk_from_bytes, bls_pop_verify,
    merkle_root_hashes, schnorr_verify_xonly_bytes, Hash32,
};
use pc_types::{digest_microtx, digest_mint};
use pc_types::{
    sighash_microtx_v1, Amount, LockCommitment, MicroTx, MintEvent, NetworkId, OutPoint,
    TX_VERSION_STAKE_BOND_V1, TX_VERSION_STAKE_UNBOND_V1, TX_VERSION_TRANSFER_V1,
    TX_VERSION_VALIDATOR_REGISTER_V1, VALIDATOR_REGISTER_WITNESS_BYTES_V1,
};
use rayon::prelude::*;
#[cfg(feature = "rocksdb")]
use rocksdb::{IteratorMode, Options, DB};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
mod property_tests;
#[cfg(test)]
mod pruning_tests;
#[cfg(test)]
mod state_tests;

#[derive(Debug)]
pub enum StateError {
    MissingInput(OutPoint),
    DoubleSpend(OutPoint),
    AmountMismatch,
    InvalidWitness(OutPoint),
    /// Unbond authorization nonce does not match the expected value (anti-replay).
    /// Unbond-Nonce stimmt nicht mit erwartetem Wert überein (Anti-Replay).
    UnbondBadNonce,
    UnsupportedTxVersion(u8),
    NotMature(OutPoint, u64), // required_at (minted_at + threshold)
    AlreadyStaked(OutPoint),
    NotStaked(OutPoint),
    Locked(OutPoint),
    /// Replay-protection: slash_id already applied.
    /// Replay-Schutz: slash_id wurde bereits angewandt.
    SlashReplay([u8; 32]),
    /// Slash bp is invalid (must be 1..=10_000).
    /// Slash bp ist ungültig (muss 1..=10_000 sein).
    SlashInvalidBp(u16),
    /// Offender validator id is not registered on-chain.
    /// Täter-Validator-ID ist nicht on-chain registriert.
    SlashUnknownValidator([u8; 32]),
    /// Offender has no staked bond at the time of applying the slash.
    /// Täter hat zum Slash-Zeitpunkt keinen gestakten Bond.
    SlashNoStake([u8; 32]),
    /// Computed slash amount is zero (no-op), rejected to prevent DoS.
    /// Berechneter Slash-Betrag ist 0 (No-Op), wird zur DoS-Vermeidung abgelehnt.
    SlashAmountZero([u8; 32]),
    SnapshotIntegrityError,
    /// K3-Fix: minted_at is in the future (invalid).
    /// K3-Fix: minted_at liegt in der Zukunft (ungültig).
    MintedAtFuture(u64, u64), // (minted_at, current_index)
    /// M1-Fix: Amount overflow during calculation.
    /// M1-Fix: Betrags-Overflow bei Berechnung.
    AmountOverflow,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingInput(op) => write!(f, "missing input: {:?}", op),
            Self::DoubleSpend(op) => write!(f, "double spend: {:?}", op),
            Self::AmountMismatch => write!(f, "amounts in != out"),
            Self::InvalidWitness(op) => write!(f, "invalid witness for input: {:?}", op),
            Self::UnbondBadNonce => write!(f, "unbond bad nonce"),
            Self::UnsupportedTxVersion(v) => write!(f, "unsupported tx version: {}", v),
            Self::NotMature(op, req) => {
                write!(f, "outpoint not mature: {:?}, required_at={}", op, req)
            }
            Self::AlreadyStaked(op) => write!(f, "outpoint already staked: {:?}", op),
            Self::NotStaked(op) => write!(f, "outpoint not staked: {:?}", op),
            Self::Locked(op) => write!(f, "outpoint is staked/locked: {:?}", op),
            Self::SlashReplay(id) => {
                write!(f, "slash replay: ")?;
                for b in id {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Self::SlashInvalidBp(bp) => write!(f, "slash invalid bp: {}", bp),
            Self::SlashUnknownValidator(id) => {
                write!(f, "slash unknown validator: ")?;
                for b in id {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Self::SlashNoStake(id) => {
                write!(f, "slash no stake for validator: ")?;
                for b in id {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Self::SlashAmountZero(id) => {
                write!(f, "slash amount zero for validator: ")?;
                for b in id {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Self::SnapshotIntegrityError => write!(f, "snapshot integrity check failed"),
            Self::MintedAtFuture(minted, current) => {
                write!(
                    f,
                    "minted_at {} is in the future (current={})",
                    minted, current
                )
            }
            Self::AmountOverflow => write!(f, "amount overflow during calculation"),
        }
    }
}
impl std::error::Error for StateError {}

// Simple backend trait for UTXO storage.
// Einfache Backend-Trait für UTXO-Storage.
/// Full UTXO entry with all consensus-critical attributes.
/// Vollständiger UTXO-Eintrag mit allen konsens-kritischen Attributen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub amount: Amount,
    pub lock: LockCommitment,
    pub minted_at: u64,
    pub staked: bool,
}

/// Consensus operation: apply a slash to a validator's staked bond.
///
/// The slashing authorization (committee signature) is verified outside of `pc-state`;
/// `pc-state` only applies the deterministic stake reduction and enforces replay protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashOpV1 {
    pub slash_id: [u8; 32],
    pub offender_id: [u8; 32],
    pub slash_bp: u16,
    pub reporter_lock: LockCommitment,
    pub reporter_reward_bp: u16,
}

pub trait StateBackend {
    fn get(&self, key: &OutPoint) -> Option<(Amount, LockCommitment)>;
    fn put(&mut self, key: OutPoint, val: (Amount, LockCommitment));
    fn del(&mut self, key: &OutPoint) -> bool;
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (OutPoint, (Amount, LockCommitment))> + 'a>;

    /// Full iterator including minted_at and staked (P1-3 hardening).
    /// Vollständiger Iterator inkl. minted_at und staked (P1-3 Härtung).
    fn iter_full<'a>(&'a self) -> Box<dyn Iterator<Item = (OutPoint, UtxoEntry)> + 'a> {
        // Default implementation uses the basic iter + lookups.
        // Standard-Implementierung nutzt basic iter + Lookups.
        let items: Vec<_> = self.iter().collect();
        let mut result = Vec::with_capacity(items.len());
        for (op, (amount, lock)) in items {
            let minted_at = self.get_minted_at(&op).unwrap_or(0);
            let staked = self.is_staked(&op);
            result.push((
                op,
                UtxoEntry {
                    amount,
                    lock,
                    minted_at,
                    staked,
                },
            ));
        }
        Box::new(result.into_iter())
    }

    // Optional meta persistence: `minted_at` index.
    // optionale Meta-Persistenz: minted_at Index.
    fn get_minted_at(&self, _key: &OutPoint) -> Option<u64> {
        None
    }
    fn set_minted_at(&mut self, _key: OutPoint, _idx: u64) {}
    fn del_minted_at(&mut self, _key: &OutPoint) {}

    // Optional meta persistence: stake flag.
    // optionale Meta-Persistenz: Stake-Flag.
    fn is_staked(&self, _key: &OutPoint) -> bool {
        false
    }
    fn set_staked(&mut self, _key: OutPoint) {}
    fn unset_staked(&mut self, _key: &OutPoint) {}

    // Optional meta persistence: unbond auth sequence (anti-replay).
    // optionale Meta-Persistenz: Unbond-Auth Sequenz (Anti-Replay).
    fn get_unbond_seq(&self, _lock: &LockCommitment) -> Option<u64> {
        None
    }
    fn set_unbond_seq(&mut self, _lock: LockCommitment, _seq: u64) {}
    fn del_unbond_seq(&mut self, _lock: &LockCommitment) {}
    fn iter_unbond_seq<'a>(&'a self) -> Box<dyn Iterator<Item = (LockCommitment, u64)> + 'a> {
        Box::new(std::iter::empty())
    }

    // Optional meta persistence: used prev_mint_id tracking.
    // optionale Meta-Persistenz: verwendete prev_mint_id Tracking.
    fn is_prev_mint_used(&self, _prev_mint_id: &[u8; 32]) -> bool {
        false
    }
    fn mark_prev_mint_used(&mut self, _prev_mint_id: [u8; 32]) {}
    fn unmark_prev_mint_used(&mut self, _prev_mint_id: &[u8; 32]) {}
    fn iter_prev_mint_used<'a>(&'a self) -> Box<dyn Iterator<Item = [u8; 32]> + 'a> {
        Box::new(std::iter::empty())
    }

    // Optional meta persistence: slash-id replay protection.
    // optionale Meta-Persistenz: slash-id Replay-Schutz.
    fn is_slash_id_used(&self, _slash_id: &[u8; 32]) -> bool {
        false
    }
    fn mark_slash_id_used(&mut self, _slash_id: [u8; 32]) {}
    fn unmark_slash_id_used(&mut self, _slash_id: &[u8; 32]) {}
    fn iter_slash_id_used<'a>(&'a self) -> Box<dyn Iterator<Item = [u8; 32]> + 'a> {
        Box::new(std::iter::empty())
    }

    // Optional meta persistence: on-chain validator registry.
    // optionale Meta-Persistenz: On-Chain Validator-Registry.
    fn get_validator_record(
        &self,
        _validator_id: &[u8; 32],
    ) -> Option<pc_types::ValidatorRecordV1> {
        None
    }
    fn put_validator_record(&mut self, _validator_id: [u8; 32], _rec: pc_types::ValidatorRecordV1) {
    }
    fn del_validator_record(&mut self, _validator_id: &[u8; 32]) {}
    fn get_validator_id_by_stake_lock(&self, stake_lock: &LockCommitment) -> Option<[u8; 32]> {
        for (validator_id, rec) in self.iter_validator_records() {
            if rec.stake_lock == *stake_lock {
                return Some(validator_id);
            }
        }
        None
    }
    fn iter_validator_records<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = ([u8; 32], pc_types::ValidatorRecordV1)> + 'a> {
        Box::new(std::iter::empty())
    }
}

pub struct OverlayBackend<'a, B: StateBackend> {
    base: &'a mut B,
    map: HashMap<OutPoint, Option<(Amount, LockCommitment)>>,
    minted_at: HashMap<OutPoint, Option<u64>>,
    staked: HashMap<OutPoint, bool>,
    unbond_seq: HashMap<[u8; 32], u64>,
    unbond_seq_deleted: HashSet<[u8; 32]>,
    used_prev_mints: HashSet<[u8; 32]>,
    used_prev_mints_deleted: HashSet<[u8; 32]>,
    used_slash_ids: HashSet<[u8; 32]>,
    used_slash_ids_deleted: HashSet<[u8; 32]>,
    validators: HashMap<[u8; 32], Option<pc_types::ValidatorRecordV1>>,
}

impl<'a, B: StateBackend> OverlayBackend<'a, B> {
    pub fn new(base: &'a mut B) -> Self {
        Self {
            base,
            map: HashMap::new(),
            minted_at: HashMap::new(),
            staked: HashMap::new(),
            unbond_seq: HashMap::new(),
            unbond_seq_deleted: HashSet::new(),
            used_prev_mints: HashSet::new(),
            used_prev_mints_deleted: HashSet::new(),
            used_slash_ids: HashSet::new(),
            used_slash_ids_deleted: HashSet::new(),
            validators: HashMap::new(),
        }
    }

    pub fn commit(&mut self) {
        for id in self.used_prev_mints_deleted.drain() {
            self.base.unmark_prev_mint_used(&id);
        }
        for id in self.used_prev_mints.drain() {
            self.base.mark_prev_mint_used(id);
        }
        for id in self.used_slash_ids_deleted.drain() {
            self.base.unmark_slash_id_used(&id);
        }
        for id in self.used_slash_ids.drain() {
            self.base.mark_slash_id_used(id);
        }
        for (op, v) in self.map.drain() {
            match v {
                Some(val) => self.base.put(op, val),
                None => {
                    let _ = self.base.del(&op);
                }
            }
        }
        for (op, v) in self.minted_at.drain() {
            match v {
                Some(idx) => self.base.set_minted_at(op, idx),
                None => self.base.del_minted_at(&op),
            }
        }
        for (op, v) in self.staked.drain() {
            if v {
                self.base.set_staked(op);
            } else {
                self.base.unset_staked(&op);
            }
        }
        for lock in self.unbond_seq_deleted.drain() {
            self.base.del_unbond_seq(&LockCommitment(lock));
        }
        for (lock, seq) in self.unbond_seq.drain() {
            self.base.set_unbond_seq(LockCommitment(lock), seq);
        }
        for (vid, v) in self.validators.drain() {
            match v {
                Some(rec) => self.base.put_validator_record(vid, rec),
                None => self.base.del_validator_record(&vid),
            }
        }
    }
}

impl<'a, B: StateBackend> StateBackend for OverlayBackend<'a, B> {
    fn get(&self, key: &OutPoint) -> Option<(Amount, LockCommitment)> {
        match self.map.get(key) {
            Some(Some(v)) => Some(*v),
            Some(None) => None,
            None => self.base.get(key),
        }
    }

    fn put(&mut self, key: OutPoint, val: (Amount, LockCommitment)) {
        let _ = self.map.insert(key, Some(val));
    }

    fn del(&mut self, key: &OutPoint) -> bool {
        let existed = match self.map.get(key) {
            Some(Some(_)) => true,
            Some(None) => false,
            None => self.base.get(key).is_some(),
        };
        let _ = self.map.insert(*key, None);
        existed
    }

    fn iter<'b>(&'b self) -> Box<dyn Iterator<Item = (OutPoint, (Amount, LockCommitment))> + 'b> {
        let mut out: HashMap<OutPoint, (Amount, LockCommitment)> = HashMap::new();
        for (op, v) in self.base.iter() {
            let _ = out.insert(op, v);
        }
        for (op, v) in self.map.iter() {
            match v {
                Some(val) => {
                    let _ = out.insert(*op, *val);
                }
                None => {
                    let _ = out.remove(op);
                }
            }
        }
        let vec: Vec<(OutPoint, (Amount, LockCommitment))> = out.into_iter().collect();
        Box::new(vec.into_iter())
    }

    fn get_minted_at(&self, key: &OutPoint) -> Option<u64> {
        match self.minted_at.get(key) {
            Some(Some(v)) => Some(*v),
            Some(None) => None,
            None => self.base.get_minted_at(key),
        }
    }

    fn set_minted_at(&mut self, key: OutPoint, idx: u64) {
        let _ = self.minted_at.insert(key, Some(idx));
    }

    fn del_minted_at(&mut self, key: &OutPoint) {
        let _ = self.minted_at.insert(*key, None);
    }

    fn is_staked(&self, key: &OutPoint) -> bool {
        self.staked
            .get(key)
            .copied()
            .unwrap_or_else(|| self.base.is_staked(key))
    }

    fn set_staked(&mut self, key: OutPoint) {
        let _ = self.staked.insert(key, true);
    }

    fn unset_staked(&mut self, key: &OutPoint) {
        let _ = self.staked.insert(*key, false);
    }

    fn get_unbond_seq(&self, lock: &LockCommitment) -> Option<u64> {
        if self.unbond_seq_deleted.contains(&lock.0) {
            return None;
        }
        match self.unbond_seq.get(&lock.0) {
            Some(v) => Some(*v),
            None => self.base.get_unbond_seq(lock),
        }
    }

    fn set_unbond_seq(&mut self, lock: LockCommitment, seq: u64) {
        let _ = self.unbond_seq_deleted.remove(&lock.0);
        let _ = self.unbond_seq.insert(lock.0, seq);
    }

    fn del_unbond_seq(&mut self, lock: &LockCommitment) {
        let _ = self.unbond_seq.remove(&lock.0);
        let _ = self.unbond_seq_deleted.insert(lock.0);
    }

    fn iter_unbond_seq<'b>(&'b self) -> Box<dyn Iterator<Item = (LockCommitment, u64)> + 'b> {
        let mut out: HashMap<[u8; 32], u64> = HashMap::new();
        for (lock, seq) in self.base.iter_unbond_seq() {
            if !self.unbond_seq_deleted.contains(&lock.0) {
                let _ = out.insert(lock.0, seq);
            }
        }
        for (k, v) in self.unbond_seq.iter() {
            let _ = out.insert(*k, *v);
        }
        let vec: Vec<(LockCommitment, u64)> = out
            .into_iter()
            .map(|(k, v)| (LockCommitment(k), v))
            .collect();
        Box::new(vec.into_iter())
    }

    fn is_prev_mint_used(&self, prev_mint_id: &[u8; 32]) -> bool {
        if self.used_prev_mints_deleted.contains(prev_mint_id) {
            return false;
        }
        self.used_prev_mints.contains(prev_mint_id) || self.base.is_prev_mint_used(prev_mint_id)
    }

    fn mark_prev_mint_used(&mut self, prev_mint_id: [u8; 32]) {
        let _ = self.used_prev_mints_deleted.remove(&prev_mint_id);
        let _ = self.used_prev_mints.insert(prev_mint_id);
    }

    fn unmark_prev_mint_used(&mut self, prev_mint_id: &[u8; 32]) {
        let _ = self.used_prev_mints.remove(prev_mint_id);
        let _ = self.used_prev_mints_deleted.insert(*prev_mint_id);
    }

    fn iter_prev_mint_used<'b>(&'b self) -> Box<dyn Iterator<Item = [u8; 32]> + 'b> {
        let mut out: HashSet<[u8; 32]> = HashSet::new();
        for id in self.base.iter_prev_mint_used() {
            if !self.used_prev_mints_deleted.contains(&id) {
                let _ = out.insert(id);
            }
        }
        for id in self.used_prev_mints.iter() {
            let _ = out.insert(*id);
        }
        let vec: Vec<[u8; 32]> = out.into_iter().collect();
        Box::new(vec.into_iter())
    }

    fn is_slash_id_used(&self, slash_id: &[u8; 32]) -> bool {
        if self.used_slash_ids_deleted.contains(slash_id) {
            return false;
        }
        self.used_slash_ids.contains(slash_id) || self.base.is_slash_id_used(slash_id)
    }

    fn mark_slash_id_used(&mut self, slash_id: [u8; 32]) {
        let _ = self.used_slash_ids_deleted.remove(&slash_id);
        let _ = self.used_slash_ids.insert(slash_id);
    }

    fn unmark_slash_id_used(&mut self, slash_id: &[u8; 32]) {
        let _ = self.used_slash_ids.remove(slash_id);
        let _ = self.used_slash_ids_deleted.insert(*slash_id);
    }

    fn iter_slash_id_used<'b>(&'b self) -> Box<dyn Iterator<Item = [u8; 32]> + 'b> {
        let mut out: HashSet<[u8; 32]> = HashSet::new();
        for id in self.base.iter_slash_id_used() {
            if !self.used_slash_ids_deleted.contains(&id) {
                let _ = out.insert(id);
            }
        }
        for id in self.used_slash_ids.iter() {
            let _ = out.insert(*id);
        }
        let vec: Vec<[u8; 32]> = out.into_iter().collect();
        Box::new(vec.into_iter())
    }

    fn get_validator_record(&self, validator_id: &[u8; 32]) -> Option<pc_types::ValidatorRecordV1> {
        match self.validators.get(validator_id) {
            Some(Some(v)) => Some(v.clone()),
            Some(None) => None,
            None => self.base.get_validator_record(validator_id),
        }
    }

    fn put_validator_record(&mut self, validator_id: [u8; 32], rec: pc_types::ValidatorRecordV1) {
        let _ = self.validators.insert(validator_id, Some(rec));
    }

    fn del_validator_record(&mut self, validator_id: &[u8; 32]) {
        let _ = self.validators.insert(*validator_id, None);
    }

    fn get_validator_id_by_stake_lock(&self, stake_lock: &LockCommitment) -> Option<[u8; 32]> {
        for (validator_id, rec) in self.validators.iter() {
            if let Some(rec) = rec {
                if rec.stake_lock == *stake_lock {
                    return Some(*validator_id);
                }
            }
        }
        let base_id = self.base.get_validator_id_by_stake_lock(stake_lock)?;
        match self.validators.get(&base_id) {
            Some(Some(rec)) if rec.stake_lock != *stake_lock => None,
            Some(None) => None,
            _ => Some(base_id),
        }
    }

    fn iter_validator_records<'b>(
        &'b self,
    ) -> Box<dyn Iterator<Item = ([u8; 32], pc_types::ValidatorRecordV1)> + 'b> {
        let mut out: HashMap<[u8; 32], pc_types::ValidatorRecordV1> = HashMap::new();
        for (vid, v) in self.base.iter_validator_records() {
            let _ = out.insert(vid, v);
        }
        for (vid, v) in self.validators.iter() {
            match v {
                Some(rec) => {
                    let _ = out.insert(*vid, rec.clone());
                }
                None => {
                    let _ = out.remove(vid);
                }
            }
        }
        let vec: Vec<([u8; 32], pc_types::ValidatorRecordV1)> = out.into_iter().collect();
        Box::new(vec.into_iter())
    }
}

pub struct InMemoryBackend {
    map: HashMap<OutPoint, (Amount, LockCommitment)>,
    minted_at: HashMap<OutPoint, u64>,
    stakes: HashSet<OutPoint>,
    unbond_seq: HashMap<[u8; 32], u64>,
    used_prev_mints: HashSet<[u8; 32]>,
    used_slash_ids: HashSet<[u8; 32]>,
    validators: HashMap<[u8; 32], pc_types::ValidatorRecordV1>,
    validator_by_stake_lock: HashMap<[u8; 32], [u8; 32]>,
}
impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            minted_at: HashMap::new(),
            stakes: HashSet::new(),
            unbond_seq: HashMap::new(),
            used_prev_mints: HashSet::new(),
            used_slash_ids: HashSet::new(),
            validators: HashMap::new(),
            validator_by_stake_lock: HashMap::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl StateBackend for InMemoryBackend {
    fn get(&self, key: &OutPoint) -> Option<(Amount, LockCommitment)> {
        self.map.get(key).copied()
    }
    fn put(&mut self, key: OutPoint, val: (Amount, LockCommitment)) {
        let _ = self.map.insert(key, val);
    }
    fn del(&mut self, key: &OutPoint) -> bool {
        self.map.remove(key).is_some()
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (OutPoint, (Amount, LockCommitment))> + 'a> {
        Box::new(self.map.iter().map(|(k, v)| (*k, *v)))
    }

    fn get_minted_at(&self, key: &OutPoint) -> Option<u64> {
        self.minted_at.get(key).copied()
    }
    fn set_minted_at(&mut self, key: OutPoint, idx: u64) {
        let _ = self.minted_at.insert(key, idx);
    }
    fn del_minted_at(&mut self, key: &OutPoint) {
        let _ = self.minted_at.remove(key);
    }

    fn is_staked(&self, key: &OutPoint) -> bool {
        self.stakes.contains(key)
    }
    fn set_staked(&mut self, key: OutPoint) {
        let _ = self.stakes.insert(key);
    }
    fn unset_staked(&mut self, key: &OutPoint) {
        let _ = self.stakes.remove(key);
    }

    fn get_unbond_seq(&self, lock: &LockCommitment) -> Option<u64> {
        self.unbond_seq.get(&lock.0).copied()
    }

    fn set_unbond_seq(&mut self, lock: LockCommitment, seq: u64) {
        let _ = self.unbond_seq.insert(lock.0, seq);
    }

    fn del_unbond_seq(&mut self, lock: &LockCommitment) {
        let _ = self.unbond_seq.remove(&lock.0);
    }

    fn iter_unbond_seq<'a>(&'a self) -> Box<dyn Iterator<Item = (LockCommitment, u64)> + 'a> {
        Box::new(
            self.unbond_seq
                .iter()
                .map(|(k, v)| (LockCommitment(*k), *v)),
        )
    }

    fn is_prev_mint_used(&self, prev_mint_id: &[u8; 32]) -> bool {
        self.used_prev_mints.contains(prev_mint_id)
    }
    fn mark_prev_mint_used(&mut self, prev_mint_id: [u8; 32]) {
        let _ = self.used_prev_mints.insert(prev_mint_id);
    }
    fn unmark_prev_mint_used(&mut self, prev_mint_id: &[u8; 32]) {
        let _ = self.used_prev_mints.remove(prev_mint_id);
    }
    fn iter_prev_mint_used<'a>(&'a self) -> Box<dyn Iterator<Item = [u8; 32]> + 'a> {
        Box::new(self.used_prev_mints.iter().copied())
    }

    fn is_slash_id_used(&self, slash_id: &[u8; 32]) -> bool {
        self.used_slash_ids.contains(slash_id)
    }
    fn mark_slash_id_used(&mut self, slash_id: [u8; 32]) {
        let _ = self.used_slash_ids.insert(slash_id);
    }
    fn unmark_slash_id_used(&mut self, slash_id: &[u8; 32]) {
        let _ = self.used_slash_ids.remove(slash_id);
    }
    fn iter_slash_id_used<'a>(&'a self) -> Box<dyn Iterator<Item = [u8; 32]> + 'a> {
        Box::new(self.used_slash_ids.iter().copied())
    }

    fn get_validator_record(&self, validator_id: &[u8; 32]) -> Option<pc_types::ValidatorRecordV1> {
        self.validators.get(validator_id).cloned()
    }

    fn put_validator_record(&mut self, validator_id: [u8; 32], rec: pc_types::ValidatorRecordV1) {
        if let Some(prev) = self.validators.insert(validator_id, rec.clone()) {
            if prev.stake_lock.0 != rec.stake_lock.0
                && self
                    .validator_by_stake_lock
                    .get(&prev.stake_lock.0)
                    .copied()
                    == Some(validator_id)
            {
                let _ = self.validator_by_stake_lock.remove(&prev.stake_lock.0);
            }
        }
        let _ = self
            .validator_by_stake_lock
            .insert(rec.stake_lock.0, validator_id);
    }

    fn del_validator_record(&mut self, validator_id: &[u8; 32]) {
        if let Some(prev) = self.validators.remove(validator_id) {
            if self
                .validator_by_stake_lock
                .get(&prev.stake_lock.0)
                .copied()
                == Some(*validator_id)
            {
                let _ = self.validator_by_stake_lock.remove(&prev.stake_lock.0);
            }
        }
    }

    fn get_validator_id_by_stake_lock(&self, stake_lock: &LockCommitment) -> Option<[u8; 32]> {
        self.validator_by_stake_lock.get(&stake_lock.0).copied()
    }

    fn iter_validator_records<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = ([u8; 32], pc_types::ValidatorRecordV1)> + 'a> {
        Box::new(self.validators.iter().map(|(k, v)| (*k, v.clone())))
    }
}

#[cfg(feature = "rocksdb")]
pub struct RocksDbBackend {
    db: DB,
    read_only: bool,
}

#[cfg(feature = "rocksdb")]
impl RocksDbBackend {
    pub fn open(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Self {
            db,
            read_only: false,
        })
    }

    /// Attempts to repair a corrupted RocksDB at `path` (best-effort).
    ///
    /// This is intended for operator-initiated recovery or automatic "try repair, then reopen"
    /// flows. Repair can drop corrupt data; callers should treat it as a last resort.
    pub fn repair(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = Options::default();
        // We only repair existing DBs. If the directory is missing, `open()` will create it.
        opts.create_if_missing(false);
        DB::repair(&opts, path)?;
        Ok(())
    }

    pub fn open_read_only(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        let db = DB::open_for_read_only(&opts, path, false)?;
        Ok(Self {
            db,
            read_only: true,
        })
    }

    pub fn open_secondary(
        path: &str,
        secondary_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        let db = DB::open_as_secondary(&opts, path, secondary_path)?;
        Ok(Self {
            db,
            read_only: true,
        })
    }

    /// For secondary instances: try to catch up with the primary (best-effort).
    /// Für Secondary-Instanzen: versuche mit Primary aufzuholen (best-effort).
    pub fn try_catch_up_with_primary(&self) -> bool {
        if !self.read_only {
            return true;
        }
        self.db.try_catch_up_with_primary().is_ok()
    }

    fn enc_key(op: &OutPoint) -> [u8; 36] {
        let mut k = [0u8; 36];
        k[0..32].copy_from_slice(&op.txid);
        k[32..36].copy_from_slice(&op.vout.to_be_bytes());
        k
    }
    fn dec_key(k: &[u8]) -> Option<OutPoint> {
        if k.len() != 36 {
            return None;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(k.get(0..32)?);
        let mut vout_b = [0u8; 4];
        vout_b.copy_from_slice(k.get(32..36)?);
        Some(OutPoint {
            txid,
            vout: u32::from_be_bytes(vout_b),
        })
    }
    fn enc_val(v: &(Amount, LockCommitment)) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..8].copy_from_slice(&v.0.to_be_bytes());
        out[8..40].copy_from_slice(&v.1 .0);
        out
    }
    fn dec_val(b: &[u8]) -> Option<(Amount, LockCommitment)> {
        if b.len() != 40 {
            return None;
        }
        let mut amt_b = [0u8; 8];
        amt_b.copy_from_slice(b.get(0..8)?);
        let mut lock = [0u8; 32];
        lock.copy_from_slice(b.get(8..40)?);
        Some((u64::from_be_bytes(amt_b), LockCommitment(lock)))
    }

    fn minted_key(op: &OutPoint) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + 36);
        k.extend_from_slice(b"ma");
        k.extend_from_slice(&Self::enc_key(op));
        k
    }
    fn staked_key(op: &OutPoint) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + 36);
        k.extend_from_slice(b"st");
        k.extend_from_slice(&Self::enc_key(op));
        k
    }
    fn unbond_seq_key(lock: &LockCommitment) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + 32);
        k.extend_from_slice(b"ub");
        k.extend_from_slice(&lock.0);
        k
    }
    fn prev_mint_key(prev_mint_id: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + 32);
        k.extend_from_slice(b"pm");
        k.extend_from_slice(prev_mint_id);
        k
    }

    fn slash_id_key(slash_id: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + 32);
        k.extend_from_slice(b"si");
        k.extend_from_slice(slash_id);
        k
    }

    fn validator_key(validator_id: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + 32);
        k.extend_from_slice(b"vr");
        k.extend_from_slice(validator_id);
        k
    }

    fn validator_by_stake_lock_key(stake_lock: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + 32);
        k.extend_from_slice(b"vs");
        k.extend_from_slice(stake_lock);
        k
    }
}

#[cfg(feature = "rocksdb")]
impl StateBackend for RocksDbBackend {
    fn get(&self, key: &OutPoint) -> Option<(Amount, LockCommitment)> {
        let k = Self::enc_key(key);
        match self.db.get(k) {
            Ok(Some(v)) => Self::dec_val(&v),
            _ => None,
        }
    }
    fn put(&mut self, key: OutPoint, val: (Amount, LockCommitment)) {
        if self.read_only {
            return;
        }
        let k = Self::enc_key(&key);
        let v = Self::enc_val(&val);
        let _ = self.db.put(k, v);
    }
    fn del(&mut self, key: &OutPoint) -> bool {
        if self.read_only {
            return false;
        }
        let k = Self::enc_key(key);
        self.db.delete(k).is_ok()
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (OutPoint, (Amount, LockCommitment))> + 'a> {
        let it = self
            .db
            .iterator(IteratorMode::Start)
            .filter_map(|kv| match kv {
                Ok((k, v)) => {
                    let key = Self::dec_key(&k)?;
                    let val = Self::dec_val(&v)?;
                    Some((key, val))
                }
                _ => None,
            });
        Box::new(it)
    }

    // `minted_at` index.
    // minted_at Index.
    fn get_minted_at(&self, key: &OutPoint) -> Option<u64> {
        let k = Self::minted_key(key);
        match self.db.get(k) {
            Ok(Some(v)) if v.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v);
                Some(u64::from_be_bytes(b))
            }
            _ => None,
        }
    }
    fn set_minted_at(&mut self, key: OutPoint, idx: u64) {
        if self.read_only {
            return;
        }
        let k = Self::minted_key(&key);
        let v = idx.to_be_bytes();
        let _ = self.db.put(k, v);
    }
    fn del_minted_at(&mut self, key: &OutPoint) {
        if self.read_only {
            return;
        }
        let k = Self::minted_key(key);
        let _ = self.db.delete(k);
    }

    // Stake flag.
    // Stake-Flag.
    fn is_staked(&self, key: &OutPoint) -> bool {
        let k = Self::staked_key(key);
        matches!(self.db.get(k), Ok(Some(_)))
    }
    fn set_staked(&mut self, key: OutPoint) {
        if self.read_only {
            return;
        }
        let k = Self::staked_key(&key);
        let _ = self.db.put(k, [1u8]);
    }
    fn unset_staked(&mut self, key: &OutPoint) {
        if self.read_only {
            return;
        }
        let k = Self::staked_key(key);
        let _ = self.db.delete(k);
    }

    fn get_unbond_seq(&self, lock: &LockCommitment) -> Option<u64> {
        let k = Self::unbond_seq_key(lock);
        match self.db.get(k) {
            Ok(Some(v)) if v.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v);
                Some(u64::from_be_bytes(b))
            }
            _ => None,
        }
    }

    fn set_unbond_seq(&mut self, lock: LockCommitment, seq: u64) {
        if self.read_only {
            return;
        }
        let k = Self::unbond_seq_key(&lock);
        let v = seq.to_be_bytes();
        let _ = self.db.put(k, v);
    }

    fn del_unbond_seq(&mut self, lock: &LockCommitment) {
        if self.read_only {
            return;
        }
        let k = Self::unbond_seq_key(lock);
        let _ = self.db.delete(k);
    }

    fn iter_unbond_seq<'a>(&'a self) -> Box<dyn Iterator<Item = (LockCommitment, u64)> + 'a> {
        let it = self
            .db
            .iterator(IteratorMode::Start)
            .filter_map(|kv| match kv {
                Ok((k, v)) => {
                    if k.len() != 34 || !k.starts_with(b"ub") || v.len() != 8 {
                        return None;
                    }
                    let slice = k.get(2..34)?;
                    let mut lock = [0u8; 32];
                    lock.copy_from_slice(slice);
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&v);
                    Some((LockCommitment(lock), u64::from_be_bytes(b)))
                }
                _ => None,
            });
        Box::new(it)
    }

    fn is_prev_mint_used(&self, prev_mint_id: &[u8; 32]) -> bool {
        let k = Self::prev_mint_key(prev_mint_id);
        matches!(self.db.get(k), Ok(Some(_)))
    }
    fn mark_prev_mint_used(&mut self, prev_mint_id: [u8; 32]) {
        if self.read_only {
            return;
        }
        let k = Self::prev_mint_key(&prev_mint_id);
        let _ = self.db.put(k, [1u8]);
    }
    fn unmark_prev_mint_used(&mut self, prev_mint_id: &[u8; 32]) {
        if self.read_only {
            return;
        }
        let k = Self::prev_mint_key(prev_mint_id);
        let _ = self.db.delete(k);
    }
    fn iter_prev_mint_used<'a>(&'a self) -> Box<dyn Iterator<Item = [u8; 32]> + 'a> {
        let it = self
            .db
            .iterator(IteratorMode::Start)
            .filter_map(|kv| match kv {
                Ok((k, _v)) => {
                    if k.len() != 34 || !k.starts_with(b"pm") {
                        return None;
                    }
                    let slice = k.get(2..34)?;
                    let mut id = [0u8; 32];
                    id.copy_from_slice(slice);
                    Some(id)
                }
                _ => None,
            });
        Box::new(it)
    }

    fn is_slash_id_used(&self, slash_id: &[u8; 32]) -> bool {
        let k = Self::slash_id_key(slash_id);
        matches!(self.db.get(k), Ok(Some(_)))
    }
    fn mark_slash_id_used(&mut self, slash_id: [u8; 32]) {
        if self.read_only {
            return;
        }
        let k = Self::slash_id_key(&slash_id);
        let _ = self.db.put(k, [1u8]);
    }
    fn unmark_slash_id_used(&mut self, slash_id: &[u8; 32]) {
        if self.read_only {
            return;
        }
        let k = Self::slash_id_key(slash_id);
        let _ = self.db.delete(k);
    }
    fn iter_slash_id_used<'a>(&'a self) -> Box<dyn Iterator<Item = [u8; 32]> + 'a> {
        let it = self
            .db
            .iterator(IteratorMode::Start)
            .filter_map(|kv| match kv {
                Ok((k, _v)) => {
                    if k.len() != 34 || !k.starts_with(b"si") {
                        return None;
                    }
                    let slice = k.get(2..34)?;
                    let mut id = [0u8; 32];
                    id.copy_from_slice(slice);
                    Some(id)
                }
                _ => None,
            });
        Box::new(it)
    }

    fn get_validator_record(&self, validator_id: &[u8; 32]) -> Option<pc_types::ValidatorRecordV1> {
        use pc_codec::Decodable;
        let k = Self::validator_key(validator_id);
        let raw = match self.db.get(k) {
            Ok(Some(v)) => v,
            _ => return None,
        };
        let mut s = &raw[..];
        pc_types::ValidatorRecordV1::decode(&mut s).ok()
    }

    fn put_validator_record(&mut self, validator_id: [u8; 32], rec: pc_types::ValidatorRecordV1) {
        use pc_codec::Encodable;
        if self.read_only {
            return;
        }
        if let Some(prev) = self.get_validator_record(&validator_id) {
            if prev.stake_lock.0 != rec.stake_lock.0 {
                let old_idx_key = Self::validator_by_stake_lock_key(&prev.stake_lock.0);
                let _ = self.db.delete(old_idx_key);
            }
        }
        let k = Self::validator_key(&validator_id);
        let mut buf = Vec::with_capacity(rec.encoded_len());
        if rec.encode(&mut buf).is_ok() {
            let _ = self.db.put(k, buf);
            let idx_key = Self::validator_by_stake_lock_key(&rec.stake_lock.0);
            let _ = self.db.put(idx_key, validator_id);
        }
    }

    fn del_validator_record(&mut self, validator_id: &[u8; 32]) {
        if self.read_only {
            return;
        }
        if let Some(prev) = self.get_validator_record(validator_id) {
            let idx_key = Self::validator_by_stake_lock_key(&prev.stake_lock.0);
            let _ = self.db.delete(idx_key);
        }
        let k = Self::validator_key(validator_id);
        let _ = self.db.delete(k);
    }

    fn get_validator_id_by_stake_lock(&self, stake_lock: &LockCommitment) -> Option<[u8; 32]> {
        let key = Self::validator_by_stake_lock_key(&stake_lock.0);
        let raw = match self.db.get(key) {
            Ok(Some(v)) => v,
            _ => return None,
        };
        if raw.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Some(out)
    }

    fn iter_validator_records<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = ([u8; 32], pc_types::ValidatorRecordV1)> + 'a> {
        use pc_codec::Decodable;
        let it = self
            .db
            .iterator(IteratorMode::Start)
            .filter_map(|kv| match kv {
                Ok((k, v)) => {
                    if k.len() != 34 || !k.starts_with(b"vr") {
                        return None;
                    }
                    let slice = k.get(2..34)?;
                    let mut vid = [0u8; 32];
                    vid.copy_from_slice(slice);
                    let mut s = &v[..];
                    let rec = pc_types::ValidatorRecordV1::decode(&mut s).ok()?;
                    Some((vid, rec))
                }
                _ => None,
            });
        Box::new(it)
    }
}

// UTXO state with deterministic root.
// UTXO-State mit deterministischem Root.
pub struct UtxoState<B: StateBackend> {
    backend: B,
}
impl<B: StateBackend> UtxoState<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn apply_mint(&mut self, m: &MintEvent) {
        let txid = digest_mint(m);
        for (i, out) in m.outputs.iter().enumerate() {
            let op = OutPoint {
                txid,
                vout: i as u32,
            };
            self.backend.put(op, (out.amount, out.lock));
        }
    }

    /// Checks stateful (without mutation) whether a `MicroTx` would be applicable.
    /// Prüft stateful (ohne Mutation), ob eine MicroTx anwendbar wäre.
    pub fn can_apply_micro_tx(
        &self,
        tx: &MicroTx,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        // Non-indexed API: delegate to the indexed validator with "no maturity".
        // Non-Indexed API: delegiere an Indexed-Validator mit "ohne Maturity".
        self.can_apply_micro_tx_with_maturity_indexed(tx, u64::MAX, 0, network_id)
    }

    pub fn apply_micro_tx(
        &mut self,
        tx: &MicroTx,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        self.can_apply_micro_tx(tx, network_id)?;
        match tx.version {
            TX_VERSION_TRANSFER_V1 | TX_VERSION_STAKE_BOND_V1 | TX_VERSION_STAKE_UNBOND_V1 => {
                // Delete inputs, insert outputs (atomic enough for the in-memory backend).
                // Delete inputs, insert outputs (atomar genug im InMemory-Backend).
                for tin in &tx.inputs {
                    let _ = self.backend.del(&tin.prev_out);
                    self.backend.del_minted_at(&tin.prev_out);
                    self.backend.unset_staked(&tin.prev_out);
                }
                let txid = digest_microtx(tx);
                for (i, out) in tx.outputs.iter().enumerate() {
                    let op = OutPoint {
                        txid,
                        vout: i as u32,
                    };
                    self.backend.put(op, (out.amount, out.lock));
                    if tx.version == TX_VERSION_STAKE_BOND_V1 {
                        self.backend.set_staked(op);
                    }
                }
                Ok(())
            }
            TX_VERSION_VALIDATOR_REGISTER_V1 => {
                // Meta-tx: update validator registry, no UTXO mutations.
                // Meta-Tx: Validator-Registry updaten, keine UTXO-Mutationen.
                let tin = tx
                    .inputs
                    .first()
                    .ok_or(StateError::InvalidWitness(OutPoint {
                        txid: [0u8; 32],
                        vout: 0,
                    }))?;
                let op = tin.prev_out;

                let mut pk32 = [0u8; 32];
                let pk_slice = tin
                    .witness
                    .get(0..32)
                    .ok_or(StateError::InvalidWitness(op))?;
                pk32.copy_from_slice(pk_slice);
                let mut seq_b = [0u8; 8];
                let seq_slice = tin
                    .witness
                    .get(96..104)
                    .ok_or(StateError::InvalidWitness(op))?;
                seq_b.copy_from_slice(seq_slice);
                let sequence = u64::from_le_bytes(seq_b);
                let mut operator_id = [0u8; 32];
                let op_slice = tin
                    .witness
                    .get(104..136)
                    .ok_or(StateError::InvalidWitness(op))?;
                operator_id.copy_from_slice(op_slice);
                let mut bls_pk_bytes = [0u8; 48];
                let pkb_slice = tin
                    .witness
                    .get(136..184)
                    .ok_or(StateError::InvalidWitness(op))?;
                bls_pk_bytes.copy_from_slice(pkb_slice);
                let mut bls_pop = [0u8; 96];
                let pop_slice = tin
                    .witness
                    .get(184..280)
                    .ok_or(StateError::InvalidWitness(op))?;
                bls_pop.copy_from_slice(pop_slice);

                let bls_pk =
                    bls_pk_from_bytes(&bls_pk_bytes).ok_or(StateError::InvalidWitness(op))?;
                let validator_id = attestor_recipient_id_from_bls(&bls_pk);

                let rec = pc_types::ValidatorRecordV1 {
                    version: 1,
                    stake_lock: LockCommitment(pk32),
                    sequence,
                    operator_id,
                    bls_pk: bls_pk_bytes,
                    bls_pop,
                };
                self.backend.put_validator_record(validator_id, rec);
                Ok(())
            }
            _ => Err(StateError::UnsupportedTxVersion(tx.version)),
        }
    }

    pub fn root(&self) -> Hash32 {
        // Deterministic order: sort by (txid, vout).
        // deterministische Reihenfolge: nach (txid,vout) sortieren.
        let mut items: Vec<(OutPoint, UtxoEntry)> = self.backend.iter_full().collect();
        items.sort_by(|a, b| {
            let (ka, _va) = a;
            let (kb, _vb) = b;
            match ka.txid.cmp(&kb.txid) {
                core::cmp::Ordering::Equal => ka.vout.cmp(&kb.vout),
                o => o,
            }
        });
        // Leaves with domain: H("pc:utxo:leaf:v2\x01" || txid(32) || vout(4) || amount(8) || lock(32) || minted_at(8) || staked(1)).
        // Leaves mit Domain: H("pc:utxo:leaf:v2\x01" || txid(32) || vout(4) || amount(8) || lock(32) || minted_at(8) || staked(1)).
        // P1-3: All consensus-critical attributes are now committed.
        // P1-3: Alle konsens-kritischen Attribute werden jetzt committet.
        const UTXO_LEAF_DOMAIN: &[u8] = b"pc:utxo:leaf:v2\x01";
        let mut leaves: Vec<Hash32> = Vec::with_capacity(items.len());
        for (op, entry) in items.into_iter() {
            let mut buf = Vec::with_capacity(UTXO_LEAF_DOMAIN.len() + 32 + 4 + 8 + 32 + 8 + 1);
            buf.extend_from_slice(UTXO_LEAF_DOMAIN);
            buf.extend_from_slice(&op.txid);
            buf.extend_from_slice(&op.vout.to_le_bytes());
            buf.extend_from_slice(&entry.amount.to_le_bytes());
            buf.extend_from_slice(&entry.lock.0);
            buf.extend_from_slice(&entry.minted_at.to_le_bytes());
            buf.push(if entry.staked { 1u8 } else { 0u8 });
            leaves.push(blake3_32(&buf));
        }

        // Validator registry leaves.
        // Validator-Registry Leaves.
        // Leaf hash: H("pc:validator:leaf:v1\x01" || validator_id(32) || stake_lock(32) || sequence_le(8) || operator_id(32) || bls_pk(48) || bls_pop(96))
        const VAL_LEAF_DOMAIN: &[u8] = b"pc:validator:leaf:v1\x01";
        let mut regs: Vec<([u8; 32], pc_types::ValidatorRecordV1)> =
            self.backend.iter_validator_records().collect();
        regs.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (vid, rec) in regs.into_iter() {
            let mut buf = Vec::with_capacity(VAL_LEAF_DOMAIN.len() + 32 + 32 + 8 + 32 + 48 + 96);
            buf.extend_from_slice(VAL_LEAF_DOMAIN);
            buf.extend_from_slice(&vid);
            buf.extend_from_slice(&rec.stake_lock.0);
            buf.extend_from_slice(&rec.sequence.to_le_bytes());
            buf.extend_from_slice(&rec.operator_id);
            buf.extend_from_slice(&rec.bls_pk);
            buf.extend_from_slice(&rec.bls_pop);
            leaves.push(blake3_32(&buf));
        }

        // Used prev_mint_id leaves (consensus-critical anti-reuse state).
        // Used prev_mint_id Leaves (konsens-kritischer Anti-Reuse-State).
        // Leaf hash: H("pc:prev_mint:used:v1\x01" || prev_mint_id(32))
        const PM_LEAF_DOMAIN: &[u8] = b"pc:prev_mint:used:v1\x01";
        let mut used_pm: Vec<[u8; 32]> = self.backend.iter_prev_mint_used().collect();
        used_pm.sort();
        for id in used_pm.into_iter() {
            let mut buf = Vec::with_capacity(PM_LEAF_DOMAIN.len() + 32);
            buf.extend_from_slice(PM_LEAF_DOMAIN);
            buf.extend_from_slice(&id);
            leaves.push(blake3_32(&buf));
        }

        // Used slash_id leaves (replay protection).
        // Used slash_id Leaves (Replay-Schutz).
        // Leaf hash: H("pc:slash:id:v1\x01" || slash_id(32))
        const SLASH_LEAF_DOMAIN: &[u8] = b"pc:slash:id:v1\x01";
        let mut used_slash: Vec<[u8; 32]> = self.backend.iter_slash_id_used().collect();
        used_slash.sort();
        for id in used_slash.into_iter() {
            let mut buf = Vec::with_capacity(SLASH_LEAF_DOMAIN.len() + 32);
            buf.extend_from_slice(SLASH_LEAF_DOMAIN);
            buf.extend_from_slice(&id);
            leaves.push(blake3_32(&buf));
        }

        // Unbond auth sequence leaves (anti-replay).
        // Unbond-Auth Sequenz Leaves (Anti-Replay).
        // Leaf hash: H("pc:unbond:seq:v1\x01" || lock(32) || seq_le(8))
        const UNBOND_SEQ_DOMAIN: &[u8] = b"pc:unbond:seq:v1\x01";
        let mut unbond_seqs: Vec<(LockCommitment, u64)> = self.backend.iter_unbond_seq().collect();
        unbond_seqs.sort_by(|(a, _), (b, _)| a.0.cmp(&b.0));
        for (lock, seq) in unbond_seqs.into_iter() {
            let mut buf = Vec::with_capacity(UNBOND_SEQ_DOMAIN.len() + 32 + 8);
            buf.extend_from_slice(UNBOND_SEQ_DOMAIN);
            buf.extend_from_slice(&lock.0);
            buf.extend_from_slice(&seq.to_le_bytes());
            leaves.push(blake3_32(&buf));
        }
        merkle_root_hashes(&leaves)
    }
}

impl<B: StateBackend> UtxoState<B> {
    /// Read-only check including maturity/stake handling.
    /// Read-only Check inkl. Maturity/Stake.
    pub fn can_apply_micro_tx_with_maturity_indexed(
        &self,
        tx: &MicroTx,
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        match tx.version {
            TX_VERSION_TRANSFER_V1 | TX_VERSION_STAKE_BOND_V1 | TX_VERSION_STAKE_UNBOND_V1 => {
                let require_inputs_staked = tx.version == TX_VERSION_STAKE_UNBOND_V1;

                let mut seen: HashSet<OutPoint> = HashSet::new();
                let mut amt_in: u128 = 0;
                let mut locks: Vec<(OutPoint, LockCommitment)> =
                    Vec::with_capacity(tx.inputs.len());
                for tin in &tx.inputs {
                    let op = tin.prev_out;
                    if !seen.insert(op) {
                        return Err(StateError::DoubleSpend(op));
                    }
                    let is_staked = self.backend.is_staked(&op);
                    if require_inputs_staked {
                        if !is_staked {
                            return Err(StateError::NotStaked(op));
                        }
                    } else if is_staked {
                        return Err(StateError::Locked(op));
                    }
                    let (amt, lock) = self.backend.get(&op).ok_or(StateError::MissingInput(op))?;
                    let minted = self.backend.get_minted_at(&op).unwrap_or(0);
                    // K3-Fix: minted_at must not be in the future.
                    // K3-Fix: minted_at darf nicht in der Zukunft liegen.
                    if minted > current {
                        return Err(StateError::MintedAtFuture(minted, current));
                    }
                    let required_at = minted.saturating_add(threshold);
                    if current < required_at {
                        return Err(StateError::NotMature(op, required_at));
                    }
                    // M1-Fix: Use checked_add to detect overflow.
                    // M1-Fix: Verwende checked_add um Overflow zu erkennen.
                    amt_in = amt_in
                        .checked_add(amt as u128)
                        .ok_or(StateError::AmountOverflow)?;
                    locks.push((op, lock));
                }
                let mut amt_out: u128 = 0;
                for tout in &tx.outputs {
                    // M1-Fix: Use checked_add to detect overflow.
                    // M1-Fix: Verwende checked_add um Overflow zu erkennen.
                    amt_out = amt_out
                        .checked_add(tout.amount as u128)
                        .ok_or(StateError::AmountOverflow)?;
                }
                if amt_in != amt_out {
                    return Err(StateError::AmountMismatch);
                }
                let digest = sighash_microtx_v1(network_id, tx);
                for (tin, (op, lock)) in tx.inputs.iter().zip(locks.iter()) {
                    if tin.witness.len() != 96 {
                        return Err(StateError::InvalidWitness(*op));
                    }
                    let mut pk32 = [0u8; 32];
                    let pk_slice = tin
                        .witness
                        .get(0..32)
                        .ok_or(StateError::InvalidWitness(*op))?;
                    pk32.copy_from_slice(pk_slice);
                    if LockCommitment(pk32) != *lock {
                        return Err(StateError::InvalidWitness(*op));
                    }
                    let mut sig64 = [0u8; 64];
                    let sig_slice = tin
                        .witness
                        .get(32..96)
                        .ok_or(StateError::InvalidWitness(*op))?;
                    sig64.copy_from_slice(sig_slice);
                    if !schnorr_verify_xonly_bytes(&digest, &sig64, &pk32) {
                        return Err(StateError::InvalidWitness(*op));
                    }
                }
                Ok(())
            }
            TX_VERSION_VALIDATOR_REGISTER_V1 => {
                let op = tx.inputs.first().map(|i| i.prev_out).unwrap_or(OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                });

                // Strict shape.
                // Strikte Form.
                if tx.inputs.len() != 1 {
                    return Err(StateError::InvalidWitness(op));
                }
                if !tx.outputs.is_empty() {
                    return Err(StateError::InvalidWitness(op));
                }
                let tin = tx.inputs.first().ok_or(StateError::InvalidWitness(op))?;
                if tin.witness.len() != VALIDATOR_REGISTER_WITNESS_BYTES_V1 {
                    return Err(StateError::InvalidWitness(op));
                }
                // Require a staked UTXO as anchor for registration (prevents free spam).
                // Fordere einen gestakten UTXO als Anker für die Registrierung (verhindert gratis Spam).
                if !self.backend.is_staked(&op) {
                    return Err(StateError::NotStaked(op));
                }
                let (_amt, lock) = self.backend.get(&op).ok_or(StateError::MissingInput(op))?;
                let minted = self.backend.get_minted_at(&op).unwrap_or(0);
                if minted > current {
                    return Err(StateError::MintedAtFuture(minted, current));
                }
                // Consensus change: validator registration is a meta-tx and does not spend the UTXO,
                // so it must not be blocked by coin maturity rules. This enables the natural flow:
                // stake-bond -> (finalize) -> validator-register.
                //
                // Konsens-Änderung: Validator-Register ist eine Meta-Tx und gibt den UTXO nicht aus,
                // daher darf sie nicht an den Maturity-Regeln für Spends hängen. Das ermöglicht den
                // natürlichen Ablauf: stake-bond -> (finalisieren) -> validator-register.

                // Parse witness fields.
                let mut pk32 = [0u8; 32];
                let pk_slice = tin
                    .witness
                    .get(0..32)
                    .ok_or(StateError::InvalidWitness(op))?;
                pk32.copy_from_slice(pk_slice);
                if LockCommitment(pk32) != lock {
                    return Err(StateError::InvalidWitness(op));
                }
                let mut sig64 = [0u8; 64];
                let sig_slice = tin
                    .witness
                    .get(32..96)
                    .ok_or(StateError::InvalidWitness(op))?;
                sig64.copy_from_slice(sig_slice);

                let mut seq_b = [0u8; 8];
                let seq_slice = tin
                    .witness
                    .get(96..104)
                    .ok_or(StateError::InvalidWitness(op))?;
                seq_b.copy_from_slice(seq_slice);
                let sequence = u64::from_le_bytes(seq_b);

                let mut operator_id = [0u8; 32];
                let op_slice = tin
                    .witness
                    .get(104..136)
                    .ok_or(StateError::InvalidWitness(op))?;
                operator_id.copy_from_slice(op_slice);

                let mut bls_pk_bytes = [0u8; 48];
                let pkb_slice = tin
                    .witness
                    .get(136..184)
                    .ok_or(StateError::InvalidWitness(op))?;
                bls_pk_bytes.copy_from_slice(pkb_slice);

                let mut bls_pop = [0u8; 96];
                let pop_slice = tin
                    .witness
                    .get(184..280)
                    .ok_or(StateError::InvalidWitness(op))?;
                bls_pop.copy_from_slice(pop_slice);

                let bls_pk =
                    bls_pk_from_bytes(&bls_pk_bytes).ok_or(StateError::InvalidWitness(op))?;
                if !bls_pop_verify(&bls_pk, &bls_pop) {
                    return Err(StateError::InvalidWitness(op));
                }
                let validator_id = attestor_recipient_id_from_bls(&bls_pk);

                // Verify registration signature over the structured message.
                // Registrierungs-Signatur über strukturierte Nachricht prüfen.
                const REG_DOMAIN: &[u8] = b"pc:validator:register:v1\x01";
                let mut msg =
                    Vec::with_capacity(REG_DOMAIN.len() + 32 + 32 + 4 + 8 + 32 + 48 + 96 + 32);
                msg.extend_from_slice(REG_DOMAIN);
                msg.extend_from_slice(network_id);
                msg.extend_from_slice(&op.txid);
                msg.extend_from_slice(&op.vout.to_le_bytes());
                msg.extend_from_slice(&sequence.to_le_bytes());
                msg.extend_from_slice(&operator_id);
                msg.extend_from_slice(&bls_pk_bytes);
                msg.extend_from_slice(&bls_pop);
                msg.extend_from_slice(&pk32);
                let digest = blake3_32(&msg);
                if !schnorr_verify_xonly_bytes(&digest, &sig64, &pk32) {
                    return Err(StateError::InvalidWitness(op));
                }

                // Sequence and uniqueness checks.
                // Sequence- und Uniqueness-Checks.
                if let Some(existing) = self.backend.get_validator_record(&validator_id) {
                    if existing.stake_lock != LockCommitment(pk32) {
                        return Err(StateError::InvalidWitness(op));
                    }
                    if sequence <= existing.sequence {
                        return Err(StateError::InvalidWitness(op));
                    }
                } else {
                    // One validator per stake_lock (prevents "free" sybil on the same bond key).
                    // Ein Validator pro stake_lock (verhindert "gratis" Sybil über denselben Bond-Key).
                    let stake_lock = LockCommitment(pk32);
                    if let Some(other_id) = self.backend.get_validator_id_by_stake_lock(&stake_lock)
                    {
                        if other_id != validator_id {
                            return Err(StateError::InvalidWitness(op));
                        }
                    }
                }

                Ok(())
            }
            _ => Err(StateError::UnsupportedTxVersion(tx.version)),
        }
    }

    /// Convenience wrapper: stateful check without sig-verify, no maturity.
    /// Convenience-Wrapper: Stateful Check ohne Sig-Verify, ohne Maturity.
    pub fn can_apply_micro_tx_presigned_no_maturity(
        &self,
        tx: &MicroTx,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        self.can_apply_micro_tx_presigned(tx, u64::MAX, 0, network_id)
    }

    /// Stateful UTXO check **without** signature verification.
    /// Use only after signatures have been batch-verified via `verify_microtx_sigs_parallel`.
    ///
    /// Stateful UTXO-Check **ohne** Signaturprüfung.
    /// Nur verwenden, nachdem Signaturen via `verify_microtx_sigs_parallel` geprüft wurden.
    pub fn can_apply_micro_tx_presigned(
        &self,
        tx: &MicroTx,
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        match tx.version {
            TX_VERSION_TRANSFER_V1 | TX_VERSION_STAKE_BOND_V1 | TX_VERSION_STAKE_UNBOND_V1 => {
                let require_inputs_staked = tx.version == TX_VERSION_STAKE_UNBOND_V1;
                let mut seen: HashSet<OutPoint> = HashSet::new();
                let mut amt_in: u128 = 0;
                for tin in &tx.inputs {
                    let op = tin.prev_out;
                    if !seen.insert(op) {
                        return Err(StateError::DoubleSpend(op));
                    }
                    let is_staked = self.backend.is_staked(&op);
                    if require_inputs_staked {
                        if !is_staked {
                            return Err(StateError::NotStaked(op));
                        }
                    } else if is_staked {
                        return Err(StateError::Locked(op));
                    }
                    let (amt, lock) = self.backend.get(&op).ok_or(StateError::MissingInput(op))?;
                    let minted = self.backend.get_minted_at(&op).unwrap_or(0);
                    if minted > current {
                        return Err(StateError::MintedAtFuture(minted, current));
                    }
                    let required_at = minted.saturating_add(threshold);
                    if current < required_at {
                        return Err(StateError::NotMature(op, required_at));
                    }
                    amt_in = amt_in
                        .checked_add(amt as u128)
                        .ok_or(StateError::AmountOverflow)?;
                    // Check pk == lock (binding check, no crypto)
                    if tin.witness.len() < 32 {
                        return Err(StateError::InvalidWitness(op));
                    }
                    let mut pk32 = [0u8; 32];
                    let pk_slice = tin
                        .witness
                        .get(0..32)
                        .ok_or(StateError::InvalidWitness(op))?;
                    pk32.copy_from_slice(pk_slice);
                    if LockCommitment(pk32) != lock {
                        return Err(StateError::InvalidWitness(op));
                    }
                }
                let mut amt_out: u128 = 0;
                for tout in &tx.outputs {
                    amt_out = amt_out
                        .checked_add(tout.amount as u128)
                        .ok_or(StateError::AmountOverflow)?;
                }
                if amt_in != amt_out {
                    return Err(StateError::AmountMismatch);
                }
                Ok(())
            }
            TX_VERSION_VALIDATOR_REGISTER_V1 => {
                self.can_apply_micro_tx_with_maturity_indexed(tx, current, threshold, network_id)
            }
            _ => Err(StateError::UnsupportedTxVersion(tx.version)),
        }
    }

    /// Apply `MicroTx` assuming signatures have already been verified.
    /// MicroTx anwenden – Signaturen wurden bereits verifiziert.
    pub fn apply_micro_tx_presigned(
        &mut self,
        tx: &MicroTx,
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        self.can_apply_micro_tx_presigned(tx, current, threshold, network_id)?;
        match tx.version {
            TX_VERSION_TRANSFER_V1 | TX_VERSION_STAKE_BOND_V1 | TX_VERSION_STAKE_UNBOND_V1 => {
                for tin in &tx.inputs {
                    let _ = self.backend.del(&tin.prev_out);
                    self.backend.del_minted_at(&tin.prev_out);
                    self.backend.unset_staked(&tin.prev_out);
                }
                let txid = digest_microtx(tx);
                for (i, out) in tx.outputs.iter().enumerate() {
                    let op = OutPoint {
                        txid,
                        vout: i as u32,
                    };
                    self.backend.put(op, (out.amount, out.lock));
                    self.backend.set_minted_at(op, current);
                    if tx.version == TX_VERSION_STAKE_BOND_V1 {
                        self.backend.set_staked(op);
                    }
                }
                Ok(())
            }
            TX_VERSION_VALIDATOR_REGISTER_V1 => {
                self.apply_micro_tx_with_maturity_indexed(tx, current, threshold, network_id)
            }
            _ => Err(StateError::UnsupportedTxVersion(tx.version)),
        }
    }

    /// Check if a prev_mint_id has already been used.
    /// Prüft, ob eine prev_mint_id bereits verwendet wurde.
    pub fn is_prev_mint_used(&self, prev_mint_id: &[u8; 32]) -> bool {
        self.backend.is_prev_mint_used(prev_mint_id)
    }

    /// Mark a prev_mint_id as used.
    /// Markiert eine prev_mint_id als verwendet.
    pub fn mark_prev_mint_used(&mut self, prev_mint_id: [u8; 32]) {
        self.backend.mark_prev_mint_used(prev_mint_id);
    }

    /// Apply mint and set the `minted_at` index.
    /// Mint anwenden und minted_at Index setzen.
    pub fn apply_mint_with_index(&mut self, m: &MintEvent, minted_at_idx: u64) {
        let txid = digest_mint(m);
        for (i, out) in m.outputs.iter().enumerate() {
            let op = OutPoint {
                txid,
                vout: i as u32,
            };
            self.backend.put(op, (out.amount, out.lock));
            self.backend.set_minted_at(op, minted_at_idx);
        }
        self.backend.mark_prev_mint_used(m.prev_mint_id);
    }

    /// Apply `MicroTx` with maturity/stake validation and `minted_at` update.
    /// MicroTx anwenden mit Maturity/Stake-Prüfung und minted_at-Update.
    pub fn apply_micro_tx_with_maturity_indexed(
        &mut self,
        tx: &MicroTx,
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        self.can_apply_micro_tx_with_maturity_indexed(tx, current, threshold, network_id)?;

        match tx.version {
            TX_VERSION_TRANSFER_V1 | TX_VERSION_STAKE_BOND_V1 | TX_VERSION_STAKE_UNBOND_V1 => {
                // Spend: delete inputs, insert outputs.
                for tin in &tx.inputs {
                    let _ = self.backend.del(&tin.prev_out);
                    self.backend.del_minted_at(&tin.prev_out);
                    // Important: remove stake-flag for spent outpoints (RocksDB stores it separately).
                    // Wichtig: Stake-Flag für verbrauchte OutPoints entfernen (RocksDB speichert separat).
                    self.backend.unset_staked(&tin.prev_out);
                }
                let txid = digest_microtx(tx);
                for (i, out) in tx.outputs.iter().enumerate() {
                    let op = OutPoint {
                        txid,
                        vout: i as u32,
                    };
                    self.backend.put(op, (out.amount, out.lock));
                    self.backend.set_minted_at(op, current);
                    // Stake bond: outputs become staked/locked.
                    // Stake-Bond: Outputs werden gestakt/gelockt.
                    if tx.version == TX_VERSION_STAKE_BOND_V1 {
                        self.backend.set_staked(op);
                    }
                }
                Ok(())
            }
            TX_VERSION_VALIDATOR_REGISTER_V1 => {
                // Meta-tx: update validator registry, no UTXO mutations.
                // Meta-Tx: Validator-Registry updaten, keine UTXO-Mutationen.
                let tin = tx
                    .inputs
                    .first()
                    .ok_or(StateError::InvalidWitness(OutPoint {
                        txid: [0u8; 32],
                        vout: 0,
                    }))?;
                let op = tin.prev_out;

                // Parse witness fields (already length-checked in can_apply).
                let mut pk32 = [0u8; 32];
                let pk_slice = tin
                    .witness
                    .get(0..32)
                    .ok_or(StateError::InvalidWitness(op))?;
                pk32.copy_from_slice(pk_slice);
                let mut seq_b = [0u8; 8];
                let seq_slice = tin
                    .witness
                    .get(96..104)
                    .ok_or(StateError::InvalidWitness(op))?;
                seq_b.copy_from_slice(seq_slice);
                let sequence = u64::from_le_bytes(seq_b);
                let mut operator_id = [0u8; 32];
                let op_slice = tin
                    .witness
                    .get(104..136)
                    .ok_or(StateError::InvalidWitness(op))?;
                operator_id.copy_from_slice(op_slice);
                let mut bls_pk_bytes = [0u8; 48];
                let pkb_slice = tin
                    .witness
                    .get(136..184)
                    .ok_or(StateError::InvalidWitness(op))?;
                bls_pk_bytes.copy_from_slice(pkb_slice);
                let mut bls_pop = [0u8; 96];
                let pop_slice = tin
                    .witness
                    .get(184..280)
                    .ok_or(StateError::InvalidWitness(op))?;
                bls_pop.copy_from_slice(pop_slice);

                let bls_pk =
                    bls_pk_from_bytes(&bls_pk_bytes).ok_or(StateError::InvalidWitness(op))?;
                let validator_id = attestor_recipient_id_from_bls(&bls_pk);

                let rec = pc_types::ValidatorRecordV1 {
                    version: 1,
                    stake_lock: LockCommitment(pk32),
                    sequence,
                    operator_id,
                    bls_pk: bls_pk_bytes,
                    bls_pop,
                };
                self.backend.put_validator_record(validator_id, rec);
                Ok(())
            }
            _ => Err(StateError::UnsupportedTxVersion(tx.version)),
        }
    }

    /// Preview on-chain slashing operations (stake reductions) without mutating state.
    ///
    /// This is useful for supply accounting (burn/recycle) when validating a payload.
    pub fn preview_slash_ops(
        &self,
        slashes: &[SlashOpV1],
    ) -> Result<(u128, u128, u128), StateError> {
        // Map stake_lock -> total bonded amount.
        let mut bond_by_lock: HashMap<[u8; 32], u128> = HashMap::new();
        for (_outp, entry) in self.backend.iter_full() {
            if !entry.staked {
                continue;
            }
            let key = entry.lock.0;
            let cur = bond_by_lock.get(&key).copied().unwrap_or(0);
            let next = cur
                .checked_add(entry.amount as u128)
                .ok_or(StateError::AmountOverflow)?;
            let _ = bond_by_lock.insert(key, next);
        }

        let mut total_slashed: u128 = 0;
        let mut total_rewarded: u128 = 0;
        let mut total_burned: u128 = 0;

        for op in slashes {
            if self.backend.is_slash_id_used(&op.slash_id) {
                continue; // idempotent
            }
            if op.slash_bp == 0 || op.slash_bp > 10_000 {
                return Err(StateError::SlashInvalidBp(op.slash_bp));
            }
            if op.reporter_reward_bp > 10_000 {
                return Err(StateError::SlashInvalidBp(op.reporter_reward_bp));
            }
            let rec = self
                .backend
                .get_validator_record(&op.offender_id)
                .ok_or(StateError::SlashUnknownValidator(op.offender_id))?;
            let key = rec.stake_lock.0;
            let bond_u128 = bond_by_lock.get(&key).copied().unwrap_or(0);
            if bond_u128 == 0 {
                return Err(StateError::SlashNoStake(op.offender_id));
            }
            if bond_u128 > (u64::MAX as u128) {
                return Err(StateError::AmountOverflow);
            }
            let slash_amount_u128: u128 = (bond_u128 * (op.slash_bp as u128)) / 10_000u128;
            if slash_amount_u128 == 0 {
                return Err(StateError::SlashAmountZero(op.offender_id));
            }
            let reward_amount_u128: u128 =
                (slash_amount_u128 * (op.reporter_reward_bp as u128)) / 10_000u128;
            let burned_u128: u128 = slash_amount_u128.saturating_sub(reward_amount_u128);

            total_slashed = total_slashed
                .checked_add(slash_amount_u128)
                .ok_or(StateError::AmountOverflow)?;
            total_rewarded = total_rewarded
                .checked_add(reward_amount_u128)
                .ok_or(StateError::AmountOverflow)?;
            total_burned = total_burned
                .checked_add(burned_u128)
                .ok_or(StateError::AmountOverflow)?;

            // Sequential semantics: update bond for the lock so multiple slashes in one payload
            // preview correctly compound.
            let next_bond = bond_u128.saturating_sub(slash_amount_u128);
            let _ = bond_by_lock.insert(key, next_bond);
        }

        Ok((total_slashed, total_rewarded, total_burned))
    }

    /// Apply on-chain slashing operations (stake reductions) deterministically.
    ///
    /// Slashes are idempotent via `slash_id` replay protection and also create a
    /// deterministic reporter reward output.
    pub fn apply_slash_ops(
        &mut self,
        slashes: &[SlashOpV1],
        current: u64,
    ) -> Result<(), StateError> {
        use pc_crypto::blake3_32;
        const REWARD_TXID_DOMAIN_V1: &[u8] = b"pc:slash:reward_outpoint:v1\x01";

        // Build initial view of staked UTXOs (stake_lock -> outpoints).
        let mut by_lock: HashMap<[u8; 32], Vec<(OutPoint, Amount, LockCommitment)>> =
            HashMap::new();
        let mut bond_by_lock: HashMap<[u8; 32], u128> = HashMap::new();
        for (outp, entry) in self.backend.iter_full() {
            if !entry.staked {
                continue;
            }
            let key = entry.lock.0;
            by_lock
                .entry(key)
                .or_default()
                .push((outp, entry.amount, entry.lock));
            let cur = bond_by_lock.get(&key).copied().unwrap_or(0);
            let next = cur
                .checked_add(entry.amount as u128)
                .ok_or(StateError::AmountOverflow)?;
            let _ = bond_by_lock.insert(key, next);
        }

        for op in slashes {
            if self.backend.is_slash_id_used(&op.slash_id) {
                continue; // idempotent
            }
            if op.slash_bp == 0 || op.slash_bp > 10_000 {
                return Err(StateError::SlashInvalidBp(op.slash_bp));
            }
            if op.reporter_reward_bp > 10_000 {
                return Err(StateError::SlashInvalidBp(op.reporter_reward_bp));
            }
            let rec = self
                .backend
                .get_validator_record(&op.offender_id)
                .ok_or(StateError::SlashUnknownValidator(op.offender_id))?;
            let key = rec.stake_lock.0;

            let bond_u128 = bond_by_lock.get(&key).copied().unwrap_or(0);
            if bond_u128 == 0 {
                return Err(StateError::SlashNoStake(op.offender_id));
            }
            if bond_u128 > (u64::MAX as u128) {
                return Err(StateError::AmountOverflow);
            }
            let bond: u64 = bond_u128 as u64;

            // slash_amount = floor(bond * bp / 10_000).
            let slash_amount_u128: u128 = (bond_u128 * (op.slash_bp as u128)) / 10_000u128;
            if slash_amount_u128 == 0 {
                return Err(StateError::SlashAmountZero(op.offender_id));
            }
            let slash_amount: u64 = (slash_amount_u128 as u64).min(bond);
            let mut remaining: u64 = slash_amount;

            let targets = by_lock
                .get_mut(&key)
                .ok_or(StateError::SlashNoStake(op.offender_id))?;
            if targets.is_empty() {
                return Err(StateError::SlashNoStake(op.offender_id));
            }
            // Deterministic order: (txid, vout).
            targets.sort_by(|(a, _, _), (b, _, _)| match a.txid.cmp(&b.txid) {
                core::cmp::Ordering::Equal => a.vout.cmp(&b.vout),
                o => o,
            });

            for (outp, amt, lock) in targets.iter_mut() {
                if remaining == 0 {
                    break;
                }
                let take = (*amt).min(remaining);
                let new_amt = amt.saturating_sub(take);
                if new_amt == 0 {
                    let _ = self.backend.del(outp);
                    self.backend.del_minted_at(outp);
                    self.backend.unset_staked(outp);
                    *amt = 0;
                } else {
                    self.backend.put(*outp, (new_amt, *lock));
                    *amt = new_amt;
                }
                remaining = remaining.saturating_sub(take);
                // Update bond view for sequential slashes in the same payload.
                let cur_bond = bond_by_lock.get(&key).copied().unwrap_or(0);
                let next_bond = cur_bond.saturating_sub(take as u128);
                let _ = bond_by_lock.insert(key, next_bond);
            }

            // Reporter reward: floor(slash_amount * reporter_bp / 10_000).
            let reward_amount_u64: u64 =
                ((slash_amount as u128) * (op.reporter_reward_bp as u128) / 10_000u128) as u64;
            if reward_amount_u64 > 0 {
                // Deterministic outpoint derived from slash_id.
                let mut tmp = Vec::with_capacity(REWARD_TXID_DOMAIN_V1.len() + 32);
                tmp.extend_from_slice(REWARD_TXID_DOMAIN_V1);
                tmp.extend_from_slice(&op.slash_id);
                let reward_txid = blake3_32(&tmp);
                let reward_op = OutPoint {
                    txid: reward_txid,
                    vout: 0,
                };
                if self.backend.get(&reward_op).is_some() {
                    // Should be impossible unless there is a collision or inconsistent replay handling.
                    return Err(StateError::SnapshotIntegrityError);
                }
                self.backend
                    .put(reward_op, (reward_amount_u64, op.reporter_lock));
                self.backend.set_minted_at(reward_op, current);
            }

            // Mark as applied (replay protection).
            self.backend.mark_slash_id_used(op.slash_id);
        }
        Ok(())
    }

    pub fn apply_payload_v2_atomic(
        &mut self,
        mints: &[MintEvent],
        micro_txs: &[MicroTx],
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        self.apply_payload_v2_atomic_with_slashes(
            mints,
            micro_txs,
            &[] as &[SlashOpV1],
            current,
            threshold,
            network_id,
        )
    }

    pub fn apply_payload_v2_atomic_with_slashes(
        &mut self,
        mints: &[MintEvent],
        micro_txs: &[MicroTx],
        slashes: &[SlashOpV1],
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<(), StateError> {
        let overlay = OverlayBackend::new(&mut self.backend);
        let mut tmp = UtxoState::new(overlay);
        for m in mints {
            tmp.apply_mint_with_index(m, current);
        }
        // Slashing must run before micro-txs so unbond cannot escape penalties in the same payload.
        // Slashing muss vor Micro-Txs laufen, damit Unbond im selben Payload nicht ausweichen kann.
        tmp.apply_slash_ops(slashes, current)?;
        for tx in micro_txs {
            tmp.apply_micro_tx_with_maturity_indexed(tx, current, threshold, network_id)?;
        }
        tmp.backend_mut().commit();
        Ok(())
    }

    /// Tolerant payload application: mints and slashes are applied atomically (must succeed),
    /// but individual micro-txs that fail are skipped instead of aborting the entire payload.
    /// Returns the indices of skipped micro-txs for deterministic consensus.
    ///
    /// Tolerante Payload-Anwendung: Mints und Slashes werden atomar angewandt (müssen gelingen),
    /// aber einzelne MicroTxs, die fehlschlagen, werden übersprungen statt den gesamten Payload
    /// abzubrechen. Gibt die Indizes der übersprungenen MicroTxs zurück (für deterministischen Konsens).
    pub fn apply_payload_v2_tolerant(
        &mut self,
        mints: &[MintEvent],
        micro_txs: &[MicroTx],
        slashes: &[SlashOpV1],
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<Vec<usize>, StateError> {
        let overlay = OverlayBackend::new(&mut self.backend);
        let mut tmp = UtxoState::new(overlay);
        for m in mints {
            tmp.apply_mint_with_index(m, current);
        }
        tmp.apply_slash_ops(slashes, current)?;
        let mut skipped: Vec<usize> = Vec::new();
        for (i, tx) in micro_txs.iter().enumerate() {
            if tmp
                .apply_micro_tx_with_maturity_indexed(tx, current, threshold, network_id)
                .is_err()
            {
                skipped.push(i);
            }
        }
        tmp.backend_mut().commit();
        Ok(skipped)
    }

    /// Like `apply_payload_v2_tolerant`, but assumes all `MicroTx` signatures have
    /// already been verified (e.g. via `verify_microtx_sigs_parallel`).
    /// Skips the expensive `schnorr_verify_xonly_bytes` call during apply.
    ///
    /// Wie `apply_payload_v2_tolerant`, aber setzt voraus, dass alle MicroTx-Signaturen
    /// bereits geprüft wurden (z.B. via `verify_microtx_sigs_parallel`).
    pub fn apply_payload_v2_tolerant_presigned(
        &mut self,
        mints: &[MintEvent],
        micro_txs: &[MicroTx],
        slashes: &[SlashOpV1],
        current: u64,
        threshold: u64,
        network_id: &NetworkId,
    ) -> Result<Vec<usize>, StateError> {
        let overlay = OverlayBackend::new(&mut self.backend);
        let mut tmp = UtxoState::new(overlay);
        for m in mints {
            tmp.apply_mint_with_index(m, current);
        }
        tmp.apply_slash_ops(slashes, current)?;
        let mut skipped: Vec<usize> = Vec::new();
        for (i, tx) in micro_txs.iter().enumerate() {
            if tmp
                .apply_micro_tx_presigned(tx, current, threshold, network_id)
                .is_err()
            {
                skipped.push(i);
            }
        }
        tmp.backend_mut().commit();
        Ok(skipped)
    }

    /// Stake: bind outpoints (optionally allowing only mature UTXOs).
    /// Stake: OutPoints binden (optional nur reife UTXOs zulassen).
    pub fn bond_outpoints(
        &mut self,
        ops: &[OutPoint],
        current: u64,
        threshold: u64,
        allow_unripe: bool,
    ) -> Result<(), StateError> {
        for op in ops {
            if self.backend.get(op).is_none() {
                return Err(StateError::MissingInput(*op));
            }
            if self.backend.is_staked(op) {
                return Err(StateError::AlreadyStaked(*op));
            }
            if !allow_unripe {
                let minted = self.backend.get_minted_at(op).unwrap_or(0);
                let required_at = minted.saturating_add(threshold);
                if current < required_at {
                    return Err(StateError::NotMature(*op, required_at));
                }
            }
        }
        for op in ops {
            self.backend.set_staked(*op);
        }
        Ok(())
    }

    /// Stake: release outpoints.
    /// Stake: OutPoints lösen.
    /// S3-Fix: UNSICHER - Diese Funktion prüft NICHT den Eigentümer!
    /// S3-Fix: UNSAFE - This function does NOT verify ownership!
    /// Verwende unbond_outpoints_with_auth für sichere Unbonds.
    /// Use unbond_outpoints_with_auth for secure unbonds.
    #[deprecated(note = "Use unbond_outpoints_with_auth for secure unbonds")]
    pub fn unbond_outpoints(
        &mut self,
        ops: &[OutPoint],
        _current: u64,
        _threshold: u64,
    ) -> Result<(), StateError> {
        for op in ops {
            if !self.backend.is_staked(op) {
                return Err(StateError::NotStaked(*op));
            }
            self.backend.unset_staked(op);
        }
        Ok(())
    }

    /// S3-Fix: Sichere Unbond-Funktion mit Signaturprüfung.
    /// S3-Fix: Secure unbond function with signature verification.
    /// Prüft für jedes UTXO, dass die Signatur vom Eigentümer (LockCommitment) stammt.
    /// Verifies for each UTXO that the signature is from the owner (LockCommitment).
    /// S4-Fix: Anti-Replay - Nonce ist **state-derived** (lock + monotone seq) und wird im State getrackt.
    /// S4-Fix: Anti-Replay - Nonce is **state-derived** (lock + monotonic seq) and tracked in state.
    pub fn unbond_outpoints_with_auth(
        &mut self,
        ops: &[OutPoint],
        signatures: &[[u8; 64]],
        public_keys: &[[u8; 32]],
        nonce: &[u8; 32],
    ) -> Result<(), StateError> {
        use pc_crypto::schnorr_verify_xonly_bytes;

        if ops.is_empty() || ops.len() != signatures.len() || ops.len() != public_keys.len() {
            return Err(StateError::InvalidWitness(ops.first().copied().unwrap_or(
                OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
            )));
        }

        const UNBOND_DOMAIN: &[u8] = b"pc:unbond:v1\x01";
        const UNBOND_NONCE_DOMAIN: &[u8] = b"pc:unbond:nonce:v1\x01";

        // 1) Determine the stake lock and expected nonce from state.
        //    We require a single lock for the whole request, because the API carries a single nonce.
        // 1) Stake-Lock und erwarteten Nonce aus dem State bestimmen.
        //    Wir verlangen einen einzigen Lock pro Request, weil die API nur einen Nonce trägt.
        let first_op = *ops.first().ok_or(StateError::InvalidWitness(OutPoint {
            txid: [0u8; 32],
            vout: 0,
        }))?;
        let first_pk = *public_keys
            .first()
            .ok_or(StateError::InvalidWitness(first_op))?;
        if !self.backend.is_staked(&first_op) {
            return Err(StateError::NotStaked(first_op));
        }
        let (_amt0, lock0) = self
            .backend
            .get(&first_op)
            .ok_or(StateError::MissingInput(first_op))?;
        if LockCommitment(first_pk) != lock0 {
            return Err(StateError::InvalidWitness(first_op));
        }
        let seq = self.backend.get_unbond_seq(&lock0).unwrap_or(0);
        let mut nonce_buf = Vec::with_capacity(UNBOND_NONCE_DOMAIN.len() + 32 + 8);
        nonce_buf.extend_from_slice(UNBOND_NONCE_DOMAIN);
        nonce_buf.extend_from_slice(&lock0.0);
        nonce_buf.extend_from_slice(&seq.to_le_bytes());
        let expected_nonce = blake3_32(&nonce_buf);
        if nonce != &expected_nonce {
            return Err(StateError::UnbondBadNonce);
        }

        // 2) Verify signatures + ownership for all outpoints.
        // 2) Prüfe alle Signaturen + Eigentümerschaft.
        for ((op, sig), pk) in ops.iter().zip(signatures.iter()).zip(public_keys.iter()) {
            // Prüfe ob gestakt
            if !self.backend.is_staked(op) {
                return Err(StateError::NotStaked(*op));
            }
            // Prüfe ob UTXO existiert und hole LockCommitment
            let (_amt, lock) = self.backend.get(op).ok_or(StateError::MissingInput(*op))?;
            // Prüfe ob Public Key zum Lock passt
            if LockCommitment(*pk) != lock {
                return Err(StateError::InvalidWitness(*op));
            }
            if lock != lock0 {
                return Err(StateError::InvalidWitness(*op));
            }
            // Message = H(domain || txid || vout || state_nonce(lock,seq)).
            // Message = H(domain || txid || vout || state_nonce(lock,seq)).
            let mut buf = Vec::with_capacity(UNBOND_DOMAIN.len() + 32 + 4 + 32);
            buf.extend_from_slice(UNBOND_DOMAIN);
            buf.extend_from_slice(&op.txid);
            buf.extend_from_slice(&op.vout.to_le_bytes());
            buf.extend_from_slice(&expected_nonce);
            let msg = blake3_32(&buf);
            // Prüfe Signatur
            if !schnorr_verify_xonly_bytes(&msg, sig, pk) {
                return Err(StateError::InvalidWitness(*op));
            }
        }

        // 3) All checks passed: unbond + advance seq (anti-replay).
        // 3) Alle Prüfungen bestanden: unbonden + Sequenz erhöhen (Anti-Replay).
        for op in ops {
            self.backend.unset_staked(op);
        }
        self.backend.set_unbond_seq(lock0, seq.saturating_add(1));
        Ok(())
    }

    pub fn unbond_sequence_for_lock(&self, lock: &LockCommitment) -> u64 {
        self.backend.get_unbond_seq(lock).unwrap_or(0)
    }

    pub fn unbond_nonce_for_lock(&self, lock: &LockCommitment) -> [u8; 32] {
        const UNBOND_NONCE_DOMAIN: &[u8] = b"pc:unbond:nonce:v1\x01";
        let seq = self.unbond_sequence_for_lock(lock);
        let mut buf = Vec::with_capacity(UNBOND_NONCE_DOMAIN.len() + 32 + 8);
        buf.extend_from_slice(UNBOND_NONCE_DOMAIN);
        buf.extend_from_slice(&lock.0);
        buf.extend_from_slice(&seq.to_le_bytes());
        blake3_32(&buf)
    }

    /// S2-Fix: Berechnet den Gesamtstake für eine bestimmte LockCommitment.
    /// S2-Fix: Calculates total staked amount for a specific LockCommitment.
    /// Iteriert über alle gestakten UTXOs und summiert die Beträge, die zu diesem Lock gehören.
    /// Iterates over all staked UTXOs and sums amounts belonging to this lock.
    pub fn staked_amount_for_lock(&self, lock: &LockCommitment) -> u64 {
        let mut total: u64 = 0;
        for (_op, entry) in self.backend.iter_full() {
            if entry.staked && &entry.lock == lock {
                total = total.saturating_add(entry.amount);
            }
        }
        total
    }

    /// S2-Fix: Prüft ob ein bestimmter Stake für einen Lock ausreichend gedeckt ist.
    /// S2-Fix: Checks if a specific stake amount is covered for a lock.
    pub fn verify_stake_for_lock(&self, lock: &LockCommitment, claimed_stake: u64) -> bool {
        self.staked_amount_for_lock(lock) >= claimed_stake
    }

    pub fn utxos_for_lock_detailed(
        &self,
        lock: &LockCommitment,
    ) -> Vec<(OutPoint, Amount, u64, bool)> {
        let mut out: Vec<(OutPoint, Amount, u64, bool)> = Vec::new();
        for (op, entry) in self.backend.iter_full() {
            if &entry.lock == lock {
                out.push((op, entry.amount, entry.minted_at, entry.staked));
            }
        }
        out
    }

    /// Prune old UTXOs based on minted_at threshold
    pub fn prune_old_utxos(&mut self, current: u64, retain_anchors: u64) -> usize {
        let cutoff = current.saturating_sub(retain_anchors);
        let mut to_remove: Vec<OutPoint> = Vec::new();

        for (op, _val) in self.backend.iter() {
            // Legacy entries may not have minted_at indexed; treat them as oldest (0).
            let minted = self.backend.get_minted_at(&op).unwrap_or(0);
            if minted < cutoff && !self.backend.is_staked(&op) {
                to_remove.push(op);
            }
        }

        let count = to_remove.len();
        for op in to_remove {
            let _ = self.backend.del(&op);
            self.backend.del_minted_at(&op);
        }
        count
    }

    /// Create snapshot of current state
    pub fn create_snapshot(&self, height: u64) -> StateSnapshot {
        let mut utxos = Vec::new();
        let mut stakes = Vec::new();
        let mut validators: Vec<([u8; 32], pc_types::ValidatorRecordV1)> =
            self.backend.iter_validator_records().collect();
        validators.sort_by(|(a, _), (b, _)| a.cmp(b));
        let mut used_prev_mints: Vec<[u8; 32]> = self.backend.iter_prev_mint_used().collect();
        used_prev_mints.sort();
        let mut used_slash_ids: Vec<[u8; 32]> = self.backend.iter_slash_id_used().collect();
        used_slash_ids.sort();
        let mut unbond_sequences: Vec<(LockCommitment, u64)> =
            self.backend.iter_unbond_seq().collect();
        unbond_sequences.sort_by(|(a, _), (b, _)| a.0.cmp(&b.0));
        let mut total_value = 0u64;

        for (op, (amt, lock)) in self.backend.iter() {
            let minted_at = self.backend.get_minted_at(&op).unwrap_or(0);
            utxos.push((op, amt, lock, minted_at));
            total_value = total_value.saturating_add(amt);

            if self.backend.is_staked(&op) {
                stakes.push(op);
            }
        }

        StateSnapshot {
            metadata: SnapshotMetadata {
                height,
                state_root: self.root(),
                utxo_count: utxos.len() as u64,
                total_value,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                version: 1,
            },
            utxos,
            stakes,
            validators,
            used_prev_mints,
            used_slash_ids,
            unbond_sequences,
        }
    }

    /// Restore state from snapshot
    pub fn restore_snapshot(&mut self, snapshot: StateSnapshot) -> Result<(), StateError> {
        // Clear existing state first to avoid "union restore" on non-empty backends.
        let existing_utxos: Vec<OutPoint> = self.backend.iter().map(|(op, _)| op).collect();
        for op in existing_utxos {
            let _ = self.backend.del(&op);
            self.backend.del_minted_at(&op);
            self.backend.unset_staked(&op);
        }

        let existing_validators: Vec<[u8; 32]> = self
            .backend
            .iter_validator_records()
            .map(|(vid, _)| vid)
            .collect();
        for vid in existing_validators {
            self.backend.del_validator_record(&vid);
        }

        let existing_prev_mints: Vec<[u8; 32]> = self.backend.iter_prev_mint_used().collect();
        for id in existing_prev_mints {
            self.backend.unmark_prev_mint_used(&id);
        }

        let existing_slash_ids: Vec<[u8; 32]> = self.backend.iter_slash_id_used().collect();
        for id in existing_slash_ids {
            self.backend.unmark_slash_id_used(&id);
        }

        let existing_unbond_seqs: Vec<LockCommitment> = self
            .backend
            .iter_unbond_seq()
            .map(|(lock, _)| lock)
            .collect();
        for lock in existing_unbond_seqs {
            self.backend.del_unbond_seq(&lock);
        }

        // Apply all UTXOs from snapshot
        for (op, amt, lock, minted_at) in snapshot.utxos {
            self.backend.put(op, (amt, lock));
            self.backend.set_minted_at(op, minted_at);
        }

        // Apply all stakes
        for op in snapshot.stakes {
            self.backend.set_staked(op);
        }

        // Restore validator registry.
        for (vid, rec) in snapshot.validators {
            self.backend.put_validator_record(vid, rec);
        }

        // Restore used prev_mint_id set.
        for id in snapshot.used_prev_mints {
            self.backend.mark_prev_mint_used(id);
        }

        // Restore used slash_id set.
        for id in snapshot.used_slash_ids {
            self.backend.mark_slash_id_used(id);
        }

        // Restore unbond auth sequences.
        for (lock, seq) in snapshot.unbond_sequences {
            self.backend.set_unbond_seq(lock, seq);
        }

        // Verify root matches
        let computed_root = self.root();
        if computed_root != snapshot.metadata.state_root {
            return Err(StateError::SnapshotIntegrityError);
        }

        Ok(())
    }
}

/// Verify all Schnorr signatures in a batch of `MicroTx` in parallel via rayon.
/// Returns `true` if every signature is valid.
/// Only checks Transfer/StakeBond/StakeUnbond versions (v1 sighash).
/// ValidatorRegister txs are skipped (verified later in the stateful check).
///
/// Prüft alle Schnorr-Signaturen eines MicroTx-Batches parallel via rayon.
/// Gibt `true` zurück, wenn alle Signaturen gültig sind.
pub fn verify_microtx_sigs_parallel(txs: &[MicroTx], network_id: &NetworkId) -> bool {
    txs.par_iter().all(|tx| match tx.version {
        TX_VERSION_TRANSFER_V1 | TX_VERSION_STAKE_BOND_V1 | TX_VERSION_STAKE_UNBOND_V1 => {
            let digest = sighash_microtx_v1(network_id, tx);
            for tin in &tx.inputs {
                if tin.witness.len() != 96 {
                    return false;
                }
                let mut pk32 = [0u8; 32];
                let Some(pk_slice) = tin.witness.get(0..32) else {
                    return false;
                };
                pk32.copy_from_slice(pk_slice);
                let mut sig64 = [0u8; 64];
                let Some(sig_slice) = tin.witness.get(32..96) else {
                    return false;
                };
                sig64.copy_from_slice(sig_slice);
                if !schnorr_verify_xonly_bytes(&digest, &sig64, &pk32) {
                    return false;
                }
            }
            true
        }
        TX_VERSION_VALIDATOR_REGISTER_V1 => true,
        _ => false,
    })
}

/// Like `verify_microtx_sigs_parallel`, but returns a `Vec<bool>` per tx
/// so callers can filter out individually invalid txs.
///
/// Wie `verify_microtx_sigs_parallel`, aber gibt pro Tx ein `bool` zurück.
pub fn verify_microtx_sigs_parallel_each(txs: &[MicroTx], network_id: &NetworkId) -> Vec<bool> {
    txs.par_iter()
        .map(|tx| match tx.version {
            TX_VERSION_TRANSFER_V1 | TX_VERSION_STAKE_BOND_V1 | TX_VERSION_STAKE_UNBOND_V1 => {
                let digest = sighash_microtx_v1(network_id, tx);
                for tin in &tx.inputs {
                    if tin.witness.len() != 96 {
                        return false;
                    }
                    let mut pk32 = [0u8; 32];
                    let Some(pk_slice) = tin.witness.get(0..32) else {
                        return false;
                    };
                    pk32.copy_from_slice(pk_slice);
                    let mut sig64 = [0u8; 64];
                    let Some(sig_slice) = tin.witness.get(32..96) else {
                        return false;
                    };
                    sig64.copy_from_slice(sig_slice);
                    if !schnorr_verify_xonly_bytes(&digest, &sig64, &pk32) {
                        return false;
                    }
                }
                true
            }
            TX_VERSION_VALIDATOR_REGISTER_V1 => true,
            _ => false,
        })
        .collect()
}

/// Snapshot metadata
#[derive(Debug, Clone)]
pub struct SnapshotMetadata {
    pub height: u64,
    pub state_root: Hash32,
    pub utxo_count: u64,
    pub total_value: u64,
    pub created_at: u64,
    pub version: u8,
}

/// State snapshot
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    pub metadata: SnapshotMetadata,
    pub utxos: Vec<(OutPoint, Amount, LockCommitment, u64)>,
    pub stakes: Vec<OutPoint>,
    pub validators: Vec<([u8; 32], pc_types::ValidatorRecordV1)>,
    pub used_prev_mints: Vec<[u8; 32]>,
    pub used_slash_ids: Vec<[u8; 32]>,
    pub unbond_sequences: Vec<(LockCommitment, u64)>,
}

#[cfg(all(test, feature = "rocksdb"))]
mod rocks_tests {
    use super::*;
    use pc_types::{TxIn, TxOut};

    fn unique_tmp_path(suffix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("pc_state_rocksdb_{}_{}", nanos, suffix));
        p.to_string_lossy().to_string()
    }

    #[test]
    fn rocksdb_backend_basic_ops() {
        let path = unique_tmp_path("basic");
        let mut be = RocksDbBackend::open(&path).expect("open rocksdb");
        let op = OutPoint {
            txid: [7u8; 32],
            vout: 1,
        };
        let val = (123u64, LockCommitment([9u8; 32]));
        // put/get
        be.put(op, val);
        assert_eq!(
            be.get(&OutPoint {
                txid: [7u8; 32],
                vout: 1
            }),
            Some(val)
        );
        // del
        assert!(be.del(&OutPoint {
            txid: [7u8; 32],
            vout: 1
        }));
        assert!(be
            .get(&OutPoint {
                txid: [7u8; 32],
                vout: 1
            })
            .is_none());
        // iter (should be empty)
        assert_eq!(be.iter().count(), 0);
    }

    #[test]
    fn rocksdb_state_root_changes() {
        let path = unique_tmp_path("root");
        let be = RocksDbBackend::open(&path).expect("open rocksdb");
        let mut st = UtxoState::new(be);
        let nid: NetworkId = [9u8; 32];
        let sk = [3u8; 32];
        let kp = pc_crypto::SchnorrKeypair::from_secret_key_bytes(&sk).expect("kp");
        let pk = kp.public_xonly_bytes();

        // Mint 2 Outputs
        let m_out0 = TxOut {
            amount: 50,
            lock: LockCommitment(pk),
        };
        let m_out1 = TxOut {
            amount: 30,
            lock: LockCommitment(pk),
        };
        let mint = MintEvent {
            version: 1,
            prev_mint_id: [0u8; 32],
            outputs: vec![m_out0, m_out1],
            pow_seed: [3u8; 32],
            pow_nonce: 11,
            minted_at: 0,
        };
        st.apply_mint(&mint);
        let r1 = st.root();
        assert_ne!(r1, [0u8; 32]);

        // Spend 50 -> 20 + 30
        let txid_m = digest_mint(&mint);
        let txin = TxIn {
            prev_out: OutPoint {
                txid: txid_m,
                vout: 0,
            },
            witness: vec![],
        };
        let t_out0 = TxOut {
            amount: 20,
            lock: LockCommitment([3u8; 32]),
        };
        let t_out1 = TxOut {
            amount: 30,
            lock: LockCommitment([4u8; 32]),
        };
        let mut mtx = MicroTx {
            version: 1,
            inputs: vec![txin],
            outputs: vec![t_out0, t_out1],
        };
        let digest = pc_types::sighash_microtx_v1(&nid, &mtx);
        let sig = pc_crypto::schnorr_sign(&digest, &kp);
        let mut w = Vec::with_capacity(96);
        w.extend_from_slice(&pk);
        w.extend_from_slice(&sig);
        mtx.inputs[0].witness = w;
        assert!(st.apply_micro_tx(&mtx, &nid).is_ok());
        let r2 = st.root();
        assert_ne!(r1, r2);
    }
}
