use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Result};
use pc_consensus::committee_hash::{
    derive_committee_seed, select_committee_hash, CommitteeCandidate, CommitteeSeat,
};
use pc_consensus::role_policy::RolePolicy;
use pc_crypto::{attestor_recipient_id_from_bls, bls_pk_from_bytes};
use pc_state::StateBackend;
use pc_types::{
    GenesisNote, GENESIS_FEATURE_GENESIS_VALIDATORS_V1, GENESIS_FEATURE_ROLE_POLICY_V1,
};
use phantom_config as pcfg;

#[derive(Clone, Debug)]
pub(crate) struct CommitteeSelection {
    pub(crate) seats: Vec<CommitteeSeat>,
    pub(crate) bootstrap_mode: bool,
    pub(crate) fee_eligible: Vec<bool>,
}

pub(crate) fn aggregate_stake_by_lock<B: StateBackend>(backend: &B) -> HashMap<[u8; 32], u64> {
    let mut stake_by_lock: HashMap<[u8; 32], u64> = HashMap::new();
    for (_op, entry) in backend.iter_full() {
        if !entry.staked {
            continue;
        }
        let next = stake_by_lock
            .get(&entry.lock.0)
            .copied()
            .unwrap_or(0)
            .saturating_add(entry.amount);
        let _ = stake_by_lock.insert(entry.lock.0, next);
    }
    stake_by_lock
}

#[allow(dead_code)]
pub(crate) fn load_role_policy_from_mempool_dir(
    mempool_dir: &Path,
    note: &GenesisNote,
) -> Result<Option<RolePolicy>> {
    let policy_path = mempool_dir.join(pcfg::ROLE_POLICY_FILENAME);
    if (note.params.features & GENESIS_FEATURE_ROLE_POLICY_V1) == 0 {
        return Ok(None);
    }
    if !policy_path.exists() {
        bail!(
            "role_policy.json required (GENESIS_FEATURE_ROLE_POLICY_V1 set) at {}",
            policy_path.display()
        );
    }
    let policy = pcfg::load_role_policy_from_file(&policy_path)
        .map_err(|e| anyhow::anyhow!("role_policy load failed: {e}"))?;
    let got = policy.commitment();
    let want = note.seed;
    if got != want {
        bail!(
            "role_policy commitment mismatch: computed={}, genesis_note.seed={}",
            hex::encode(got),
            hex::encode(want)
        );
    }
    Ok(Some(policy))
}

pub(crate) fn select_effective_committee_from_backend<B: StateBackend>(
    backend: &B,
    note: &GenesisNote,
    stake_by_lock: &HashMap<[u8; 32], u64>,
    k: u8,
    epoch: u64,
    seed_anchor: [u8; 32],
    network_id: [u8; 32],
    role_policy: Option<&RolePolicy>,
) -> CommitteeSelection {
    if k == 0 || k > 64 {
        return CommitteeSelection {
            seats: Vec::new(),
            bootstrap_mode: false,
            fee_eligible: Vec::new(),
        };
    }

    let mut staked_candidates: Vec<CommitteeCandidate> = Vec::new();
    for (validator_id, rec) in backend.iter_validator_records() {
        if let Some(policy) = role_policy {
            if !policy.allows_validator_id(&validator_id) {
                continue;
            }
        }
        let pk = match bls_pk_from_bytes(&rec.bls_pk) {
            Some(p) => p,
            None => continue,
        };
        let derived = attestor_recipient_id_from_bls(&pk);
        if derived != validator_id {
            continue;
        }
        let stake = stake_by_lock.get(&rec.stake_lock.0).copied().unwrap_or(0);
        staked_candidates.push(CommitteeCandidate {
            recipient_id: validator_id,
            operator_id: rec.operator_id,
            bls_pk: pk,
            bls_pop: rec.bls_pop,
            stake,
        });
    }

    let mut bootstrap_candidates: Vec<CommitteeCandidate> = Vec::new();
    if note.version >= 1 && (note.params.features & GENESIS_FEATURE_GENESIS_VALIDATORS_V1) != 0 {
        bootstrap_candidates.reserve(note.genesis_validators.len());
        for gv in note.genesis_validators.iter() {
            let pk = match bls_pk_from_bytes(&gv.bls_pk) {
                Some(p) => p,
                None => continue,
            };
            let rid = attestor_recipient_id_from_bls(&pk);
            if let Some(policy) = role_policy {
                if !policy.allows_validator_id(&rid) {
                    continue;
                }
            }
            bootstrap_candidates.push(CommitteeCandidate {
                recipient_id: rid,
                operator_id: gv.operator_id,
                bls_pk: pk,
                bls_pop: gv.bls_pop,
                stake: pc_consensus::consts::MIN_ATTESTOR_STAKE,
            });
        }
    }

    let seed = derive_committee_seed(network_id, seed_anchor, epoch);
    let staked_selected: Vec<CommitteeSeat> = select_committee_hash(k, seed, &staked_candidates);
    if staked_selected.len() == k as usize && !staked_selected.is_empty() {
        return CommitteeSelection {
            fee_eligible: vec![true; staked_selected.len()],
            seats: staked_selected,
            bootstrap_mode: false,
        };
    }

    let bootstrap_selected: Vec<CommitteeSeat> =
        select_committee_hash(k, seed, &bootstrap_candidates);
    if !bootstrap_selected.is_empty() {
        return CommitteeSelection {
            fee_eligible: vec![false; bootstrap_selected.len()],
            seats: bootstrap_selected,
            bootstrap_mode: true,
        };
    }

    if !staked_selected.is_empty() {
        return CommitteeSelection {
            fee_eligible: vec![true; staked_selected.len()],
            seats: staked_selected,
            bootstrap_mode: false,
        };
    }

    CommitteeSelection {
        seats: Vec::new(),
        bootstrap_mode: false,
        fee_eligible: Vec::new(),
    }
}
