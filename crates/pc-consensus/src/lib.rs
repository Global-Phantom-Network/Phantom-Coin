// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
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

use pc_types::{
    digest_genesis_note, genesis_payload_root, payload_merkle_root_v2, NetworkId,
    GENESIS_FEATURE_MINT_POW_BIND_V1,
};
use pc_types::{
    Amount, AnchorHeader, AnchorId, AnchorIndex, EvidenceKind, MintEvent, PayoutEntry, PayoutSet,
};
use pc_types::{AnchorHeaderV2, AnchorPayloadV2, GenesisNote};
use std::time::{SystemTime, UNIX_EPOCH};
pub mod attestation;
pub mod attestor_claims;
pub mod attestor_pool;
pub mod committee_hash;
pub mod committee_vrf;
pub mod consts;
pub mod finalized_queue;
pub mod mint_censor_math;
pub mod mint_censor_v1;
pub mod mint_censor_v2;
pub mod role_policy;
pub mod rotation_manager;
pub mod stake_registry;
pub mod validator_control;

#[derive(Debug)]
pub enum ConsensusError {
    IndexOutOfRange,
    InvalidParams,
    BootstrapViolation,
}

/// Bootstrap state for k=1 exception handling.
/// Bootstrap-State für k=1 Ausnahme-Behandlung.
///
/// During the bootstrap phase (height == 0 until the first successful rotation),
/// Während der Bootstrap-Phase (height == 0 bis zur ersten erfolgreichen Rotation)
/// the effective committee size can temporarily be k=1 to allow starting the network
/// kann die effektive Committee-Größe temporär k=1 sein, um den Netzwerk-Start
/// with a single validator.
/// mit einem einzelnen Validator zu ermöglichen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BootstrapState {
    /// Is bootstrap mode active? (only for height == 0).
    /// Ist Bootstrap-Modus aktiv? (nur für height == 0).
    pub active: bool,
    /// Genesis height (always 0 for A0).
    /// Genesis-Height (immer 0 für A0).
    pub genesis_height: u64,
    /// Was the first rotation successfully completed?
    /// Wurde die erste Rotation erfolgreich abgeschlossen?
    pub rotation_activated: bool,
    /// Epoch counter since genesis (0 = genesis epoch).
    /// Epochen-Counter seit Genesis (0 = Genesis-Epoche).
    pub epochs_since_genesis: u64,
}

impl BootstrapState {
    /// Creates an active bootstrap state for genesis (A0).
    /// Erstellt einen aktiven Bootstrap-State für Genesis (A0).
    pub fn new_genesis() -> Self {
        Self {
            active: true,
            genesis_height: 0,
            rotation_activated: false,
            epochs_since_genesis: 0,
        }
    }

    /// Computes the effective committee size taking bootstrap exceptions into account.
    /// Berechnet die effektive Committee-Größe unter Berücksichtigung von Bootstrap-Ausnahmen.
    ///
    /// # Returns
    /// - `1` during the bootstrap phase (k=1 exception).
    /// - `1` während Bootstrap-Phase (k=1 Exception).
    /// - `configured_k` after rotation activation.
    /// - `configured_k` nach Rotation-Aktivierung.
    pub fn effective_committee_k(&self, configured_k: u8) -> u8 {
        if self.active && !self.rotation_activated {
            1 // Bootstrap-Exception
        } else {
            configured_k
        }
    }

    /// Checks whether a vote/attestation was emitted under bootstrap conditions.
    /// Prüft ob ein Vote/Attestation unter Bootstrap-Bedingungen emittiert wurde.
    pub fn is_bootstrap_vote(&self) -> bool {
        self.active && !self.rotation_activated
    }

    /// Activates rotation (ends the k=1 exception phase).
    /// Aktiviert Rotation (beendet k=1 Exception-Phase).
    pub fn activate_rotation(&mut self) {
        self.rotation_activated = true;
    }

    /// Increments the epoch counter and deactivates bootstrap when conditions are met.
    /// Inkrementiert Epochen-Counter und deaktiviert Bootstrap nach bestimmten Bedingungen.
    pub fn advance_epoch(&mut self) {
        self.epochs_since_genesis += 1;

        // Bootstrap is automatically disabled after a successful rotation.
        // Bootstrap wird nach erfolgreicher Rotation automatisch beendet.
        if self.rotation_activated {
            self.active = false;
        }
    }

    /// Validates that the bootstrap phase is not abused.
    /// Validiert dass Bootstrap-Phase nicht missbraucht wird.
    pub fn validate_bootstrap_bounds(&self, current_height: u64) -> Result<(), ConsensusError> {
        if self.active && current_height > 0 {
            return Err(ConsensusError::BootstrapViolation);
        }

        // Bootstrap must stay within reasonable epoch bounds.
        // Bootstrap muss innerhalb vernünftiger Epochen-Grenzen bleiben.
        const MAX_BOOTSTRAP_EPOCHS: u64 = 10;
        if self.active && self.epochs_since_genesis > MAX_BOOTSTRAP_EPOCHS {
            return Err(ConsensusError::BootstrapViolation);
        }

        Ok(())
    }
}

impl Default for AnchorGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ============================
// Empty anchors (V2, i>0).
// Leere Anker (V2, i>0).
// ============================
/// A V2 payload is considered "empty" if it contains no transactions, mints, claims or evidences
/// and no genesis note is embedded. The `payout_root` is allowed to be 0x00..00.
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

/// Validates an empty V2 anchor against the computed payload Merkle root.
/// For i>0, `is_empty_anchor_v2(payload)` must hold and `header.payload_hash`
/// must equal `payload_merkle_root_v2(payload)`.
/// Validiert einen leeren V2‑Anker gegen den berechneten Payload‑Merkle‑Root.
/// Für i>0 muss `is_empty_anchor_v2(payload)` gelten und `header.payload_hash`
/// muss `payload_merkle_root_v2(payload)` entsprechen.
pub fn validate_empty_anchor_v2(
    h: &AnchorHeaderV2,
    p: &AnchorPayloadV2,
) -> Result<(), ConsensusError> {
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
// Genesis A0 validation (V2).
// Genesis A0 Validierung (V2).
// ============================
/// Verifies A0 according to the specification and returns the derived `NetworkId`.
/// Prüft A0 gemäß Spezifikation und liefert die abgeleitete `NetworkId` zurück.
/// Rules:
/// Regeln:
/// - `parents.len == 0` (genesis has no predecessor).
/// - `parents.len == 0` (Genesis hat keinen Vorgänger).
/// - `payload_root == genesis_payload_root(genesis_note)`.
/// - `payload_root == genesis_payload_root(genesis_note)`.
/// - `header.network_id == digest_genesis_note(genesis_note)`.
/// - `header.network_id == digest_genesis_note(genesis_note)`.
/// - Parameter constraints (`committee_k` in 1..=64, `shards_initial >= 1`, `txs_per_payload >= 1`).
/// - Parameter-Constraints (`committee_k` in 1..=64, `shards_initial>=1`, `txs_per_payload>=1`).
pub fn validate_genesis_anchor(
    h: &AnchorHeaderV2,
    p: &AnchorPayloadV2,
) -> Result<NetworkId, ConsensusError> {
    // Check versions.
    // Versionen prüfen.
    if h.version != 2 || p.version != 2 {
        return Err(ConsensusError::InvalidParams);
    }
    // No parents.
    // Keine Parents.
    if (h.parents.len as usize) != 0 {
        return Err(ConsensusError::InvalidParams);
    }
    // Genesis note must be present.
    // Genesis-Note muss vorhanden sein.
    let note: &GenesisNote = match p.genesis_note.as_ref() {
        Some(n) => n,
        None => return Err(ConsensusError::InvalidParams),
    };

    if !p.micro_txs.is_empty()
        || !p.mints.is_empty()
        || !p.claims.is_empty()
        || !p.evidences.is_empty()
    {
        return Err(ConsensusError::InvalidParams);
    }
    // Parameter constraints.
    // Param-Constraints.
    if !(note.params.committee_k >= 1 && note.params.committee_k <= 64) {
        return Err(ConsensusError::InvalidParams);
    }
    if note.params.shards_initial < 1 {
        return Err(ConsensusError::InvalidParams);
    }
    if note.params.txs_per_payload < 1 {
        return Err(ConsensusError::InvalidParams);
    }
    if (note.params.features & GENESIS_FEATURE_MINT_POW_BIND_V1) == 0 {
        return Err(ConsensusError::InvalidParams);
    }

    let pl_root = genesis_payload_root(note);
    if p.payout_root != pl_root {
        return Err(ConsensusError::InvalidParams);
    }
    if h.payload_hash != pl_root {
        return Err(ConsensusError::InvalidParams);
    }
    let nid = digest_genesis_note(note);
    if h.network_id != nid {
        return Err(ConsensusError::InvalidParams);
    }
    Ok(nid)
}

/// Komfort: Erzeugt Attestor-Payout direkt aus BLS-Public-Keys (IDs via Domain-Hash)
pub fn compute_attestor_payout_from_bls(
    fees_total: Amount,
    params: &FeeSplitParams,
    bls_pks: &[pc_crypto::BlsPublicKey],
) -> Result<PayoutSet, ConsensusError> {
    let ids: Vec<[u8; 32]> = bls_pks
        .iter()
        .map(pc_crypto::attestor_recipient_id_from_bls)
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
            // Used by many validation paths (PoW binding, supply checks, etc). Keep message generic.
            Self::InvalidParams => write!(f, "invalid params"),
            Self::BootstrapViolation => write!(f, "bootstrap phase violation"),
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

/// Checks in a clock-free way whether at least `threshold` anchors have elapsed
/// between `minted_at` and `current`.
/// Prüft uhrfrei, ob zwischen `minted_at` und `current` mindestens `threshold` Anker vergangen sind.
#[inline]
pub fn maturity_reached(current: AnchorIndex, minted_at: AnchorIndex, threshold: u64) -> bool {
    current.saturating_sub(minted_at) >= threshold
}

/// Returns the maturity level (0..=3) relative to the L1/L2/L3 thresholds.
/// 0 = < L1, 1 = ≥L1, 2 = ≥L2, 3 = ≥L3.
/// Liefert die Maturity-Stufe (0..=3) relativ zu L1/L2/L3 Schwellen.
/// 0 = < L1, 1 = ≥L1, 2 = ≥L2, 3 = ≥L3.
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

/// Validates whether a mint is old enough for staking (at least L1 maturity).
/// Returns `Ok(())` if staking is allowed, otherwise `Err(ConsensusError::IndexOutOfRange)`.
/// Validiert ob ein Mint alt genug ist für Staking (mind. L1 Maturity).
/// Returns Ok(()) wenn Stake erlaubt, sonst Err(ConsensusError::IndexOutOfRange).
pub fn validate_stake_maturity(
    current: AnchorIndex,
    minted_at: AnchorIndex,
) -> Result<(), ConsensusError> {
    if !maturity_reached(current, minted_at, consts::MATURITY_L1) {
        return Err(ConsensusError::IndexOutOfRange);
    }
    Ok(())
}

/// Validates whether a bond is old enough for unbonding (at least L2 maturity).
/// Returns `Ok(())` if unbonding is allowed, otherwise `Err(ConsensusError::IndexOutOfRange)`.
/// Validiert ob ein Bond alt genug ist für Unbonding (mind. L2 Maturity).
/// Returns Ok(()) wenn Unbond erlaubt, sonst Err(ConsensusError::IndexOutOfRange).
pub fn validate_unbond_maturity(
    current: AnchorIndex,
    bonded_at: AnchorIndex,
) -> Result<(), ConsensusError> {
    if !maturity_reached(current, bonded_at, consts::MATURITY_L2) {
        return Err(ConsensusError::IndexOutOfRange);
    }
    Ok(())
}

/// Checks whether a mint output is mature enough for bond lock (at least L1).
/// Bond locking from immature mints is forbidden, but funds may already be locked
/// (only their use is allowed after maturity).
/// Prüft ob ein Mint-Output reif genug ist für Bond-Lock (mind. L1).
/// Bond-Lock aus unreifen Mints ist verboten, aber Funds können bereits gebunden werden
/// (nur die Nutzung ist erst nach Maturity erlaubt).
pub fn validate_bond_lock_maturity(
    current: AnchorIndex,
    minted_at: AnchorIndex,
) -> Result<(), ConsensusError> {
    if !maturity_reached(current, minted_at, consts::MATURITY_L1) {
        return Err(ConsensusError::IndexOutOfRange);
    }
    Ok(())
}

/// Fee split parameters in basis points (sum = 10_000).
/// Fee-Split Parameter in Basispunkten (Summe = 10_000).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSplitParams {
    pub p_base_bp: u16,
    pub p_prop_bp: u16,
    pub p_perf_bp: u16,
    pub p_att_bp: u16,
    pub d_max: u8,
    /// Weights for d=1..=d_max (strictly monotonically decreasing, e.g. [10000, 6000, 3600, 2160, ...]).
    /// Gewichte für d=1..=d_max (streng monoton fallend, z. B. [10000, 6000, 3600, 2160, ...]).
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
        // Strictly monotonically decreasing (implemented safely without indexing).
        // Monoton fallend (sicher ohne Indexing).
        for w in self.perf_weights.windows(2) {
            if let [a, b] = w {
                if a < b {
                    return Err(ConsensusError::InvalidParams);
                }
            }
        }
        Ok(())
    }

    /// Recommended defaults: p_base=65%, p_prop=10%, p_perf=15%, p_att=10%, α=0.6, D_max=8.
    /// Empfohlene Startwerte: p_base=65%, p_prop=10%, p_perf=15%, p_att=10%, α=0.6, D_max=8.
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

/// Distributes total by weights. If all weights are zero, falls back to equal distribution.
/// Verteilt total nach Gewichten. Falls alle Gewichte 0, Fallback auf Gleichverteilung.
/// L1-Fix: Prevents loss of funds when no one contributed (sum_w == 0).
/// L1-Fix: Verhindert Verlust wenn niemand beigetragen hat (sum_w == 0).
fn distribute_by_weights(total: Amount, recipients: &[[u8; 32]], weights: &[u64]) -> Vec<Amount> {
    let n = recipients.len();
    if n == 0 {
        return Vec::new();
    }
    let mut sum_w: u128 = 0;
    for &w in weights {
        sum_w += w as u128;
    }
    // L1-Fix: If all weights are zero, fall back to equal distribution instead of returning zeros.
    // L1-Fix: Falls alle Gewichte 0, Fallback auf Gleichverteilung statt Nullen.
    if sum_w == 0 {
        return distribute_equal(total, recipients);
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

/// Computes payouts for the committee (base/proposer/performance). Attestors are handled separately.
/// recipients: recipient IDs of the k seats (e.g. seat_pk commitments), `proposer_index` in 0..k.
/// ack_distances: `Option<d>` per seat (1..=Dmax); `None` → no contribution to the performance pool.
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
    let fee_eligible = vec![true; recipients.len()];
    compute_committee_payout_with_eligibility(
        fees_total,
        params,
        recipients,
        proposer_index,
        ack_distances,
        &fee_eligible,
    )
}

/// Computes payouts for the committee with explicit fee eligibility per seat.
/// Nicht fee-eligible Seats erhalten keinen Anteil aus base/proposer/perf.
pub fn compute_committee_payout_with_eligibility(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    proposer_index: usize,
    ack_distances: &[Option<u8>],
    fee_eligible: &[bool],
) -> Result<PayoutSet, ConsensusError> {
    params.validate()?;
    if recipients.len() != ack_distances.len() || recipients.len() != fee_eligible.len() {
        return Err(ConsensusError::InvalidParams);
    }
    if proposer_index >= recipients.len() {
        return Err(ConsensusError::InvalidParams);
    }

    let base_pot = split_bp(fees_total, params.p_base_bp);
    let prop_pot = split_bp(fees_total, params.p_prop_bp);
    let perf_pot = split_bp(fees_total, params.p_perf_bp);

    // Base payout distributed equally among fee-eligible seats.
    // Basis gleichmäßig unter fee-eligible Seats.
    let mut eligible_recipients: Vec<[u8; 32]> = Vec::new();
    for (i, rcpt) in recipients.iter().enumerate() {
        if fee_eligible.get(i).copied().unwrap_or(false) {
            eligible_recipients.push(*rcpt);
        }
    }
    let base_shares = distribute_equal(base_pot, &eligible_recipients);

    // Proposer receives the full proposer pot.
    // Proposer voll.
    let mut entries: Vec<PayoutEntry> = Vec::new();
    if prop_pot > 0 && fee_eligible.get(proposer_index).copied().unwrap_or(false) {
        if let Some(rcpt) = recipients.get(proposer_index) {
            entries.push(PayoutEntry {
                recipient_id: *rcpt,
                amount: prop_pot,
            });
        } else {
            return Err(ConsensusError::InvalidParams);
        }
    }

    // Performance component distributed according to weights.
    // Performance nach Gewichten.
    if perf_pot > 0 {
        let mut perf_recipients: Vec<[u8; 32]> = Vec::new();
        let mut perf_weights: Vec<u64> = Vec::new();
        for (seat_idx, d) in ack_distances.iter().enumerate() {
            if !fee_eligible.get(seat_idx).copied().unwrap_or(false) {
                continue;
            }
            let weight = match d {
                Some(dist) if *dist >= 1 && *dist <= params.d_max => {
                    let idx = (*dist as usize) - 1;
                    params.perf_weights.get(idx).copied().unwrap_or(0) as u64
                }
                _ => 0u64,
            };
            if let Some(rcpt) = recipients.get(seat_idx) {
                perf_recipients.push(*rcpt);
                perf_weights.push(weight);
            }
        }
        let perf_shares = distribute_by_weights(perf_pot, &perf_recipients, &perf_weights);
        for (amt, rcpt) in perf_shares.iter().zip(perf_recipients.iter()) {
            if *amt > 0 {
                entries.push(PayoutEntry {
                    recipient_id: *rcpt,
                    amount: *amt,
                });
            }
        }
    }

    // Add base component.
    // Basis hinzulegen.
    for (amt, rcpt) in base_shares.iter().zip(eligible_recipients.iter()) {
        if *amt > 0 {
            entries.push(PayoutEntry {
                recipient_id: *rcpt,
                amount: *amt,
            });
        }
    }

    Ok(PayoutSet { entries })
}

/// Slashing parameters for different evidence categories.
/// Slashing-Parameter für unterschiedliche Evidence-Kategorien.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingParams {
    pub equivocation_bp: u16, // Expected 10_000 (100%). erwartet 10_000 (100%).
    pub vote_invalid_bp: u16, // 5_000..=10_000
    pub conflicting_da_bp: u16, // {2_500, 5_000, 10_000}
}

impl SlashingParams {
    pub fn validate(&self) -> Result<(), ConsensusError> {
        // Equivocation strictly 100%.
        // Equivocation strikt 100%.
        if self.equivocation_bp != consts::SLASH_EQUIVOCATION_BP {
            return Err(ConsensusError::InvalidParams);
        }
        // Vote-invalid in the interval [50%, 100%].
        // Vote-invalid im Intervall [50%, 100%].
        if self.vote_invalid_bp < consts::SLASH_VOTE_INVALID_MIN_BP
            || self.vote_invalid_bp > consts::SLASH_VOTE_INVALID_MAX_BP
        {
            return Err(ConsensusError::InvalidParams);
        }
        // Conflicting-DA from a discrete set of allowed values.
        // Conflicting-DA aus diskretem Set.
        match self.conflicting_da_bp {
            x if x == consts::SLASH_DA_25_BP => {}
            x if x == consts::SLASH_DA_50_BP => {}
            x if x == consts::SLASH_DA_100_BP => {}
            _ => return Err(ConsensusError::InvalidParams),
        }
        Ok(())
    }

    /// Strict configuration: Equivocation=100%, vote-invalid=100%, DA=100%.
    /// Strikte Parametrierung: Equivocation=100%, Vote-invalid=100%, DA=100%.
    pub fn recommended_strict() -> Self {
        Self {
            equivocation_bp: consts::SLASH_EQUIVOCATION_BP,
            vote_invalid_bp: consts::SLASH_VOTE_INVALID_MAX_BP,
            conflicting_da_bp: consts::SLASH_DA_100_BP,
        }
    }

    /// Moderate configuration: Equivocation=100%, vote-invalid=50%, DA=25%.
    /// Moderate Parametrierung: Equivocation=100%, Vote-invalid=50%, DA=25%.
    pub fn recommended_moderate() -> Self {
        Self {
            equivocation_bp: consts::SLASH_EQUIVOCATION_BP,
            vote_invalid_bp: consts::SLASH_VOTE_INVALID_MIN_BP,
            conflicting_da_bp: consts::SLASH_DA_25_BP,
        }
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

/// Computes the slashing payout based on an evidence event.
/// - `slashed_bond`: amount of the offender's bond.
/// - `recipients`: payout IDs of the k seats (eligible seats).
///   Distribution: 100% of the slashing pool across all eligible seats excluding the offender,
///   deterministically and evenly.
///
/// NOTE: This only computes the payout (distribution).
/// The actual on-chain stake reduction is applied in `pc-state` (via `SlashOpV1`).
///
/// Berechnet Slashing-Payout auf Basis eines Evidence-Events.
/// - slashed_bond: Betrag des Bonds des Täters
/// - recipients: payout_id der k Seats (eligible Seats)
///   Verteilung: 100% des Slashing-Topfs auf alle eligible Seats EXKL. Täter, deterministisch gleichmäßig
///
/// HINWEIS: Berechnet nur Payout (Verteilung).
/// Die eigentliche on-chain Stake-Reduktion passiert in `pc-state` (via `SlashOpV1`).
pub fn compute_slashing_payout_for_evidence(
    slashed_bond: Amount,
    params: &SlashingParams,
    recipients: &[[u8; 32]],
    ev: &EvidenceKind,
) -> Result<PayoutSet, ConsensusError> {
    params.validate()?;
    if matches!(
        ev,
        EvidenceKind::MintCensorshipV1 { .. }
            | EvidenceKind::MintCandidateV1 { .. }
            | EvidenceKind::MintPoWCertV1 { .. }
            | EvidenceKind::MintMissingImportV1 { .. }
            | EvidenceKind::MintCensorshipV2 { .. }
            | EvidenceKind::MintCandidateV2 { .. }
            | EvidenceKind::MintPoWCertV2 { .. }
            | EvidenceKind::MintMissingImportV2 { .. }
    ) {
        // Mint-censorship evidence is consensus-validity evidence, not a bond-slashing category.
        return Err(ConsensusError::InvalidParams);
    }
    // Extract offender ID from evidence.
    // Täter-ID aus Evidence extrahieren.
    let offender: [u8; 32] = match ev {
        EvidenceKind::Equivocation { seat_id, .. } => *seat_id,
        EvidenceKind::EquivocationBftV1 { offender_id, .. } => *offender_id,
        EvidenceKind::VoteInvalid { seat_id, .. } => *seat_id,
        EvidenceKind::ConflictingDAAttest { seat_id, .. } => *seat_id,
        EvidenceKind::SlashTicketV1 { offender_id, .. } => *offender_id,
        EvidenceKind::MintCensorshipV1 { .. } => unreachable!(),
        EvidenceKind::MintCandidateV1 { .. } => unreachable!(),
        EvidenceKind::MintPoWCertV1 { .. } => unreachable!(),
        EvidenceKind::MintMissingImportV1 { .. } => unreachable!(),
        EvidenceKind::MintCensorshipV2 { .. } => unreachable!(),
        EvidenceKind::MintCandidateV2 { .. } => unreachable!(),
        EvidenceKind::MintPoWCertV2 { .. } => unreachable!(),
        EvidenceKind::MintMissingImportV2 { .. } => unreachable!(),
    };
    // Basisprozente je Kategorie
    let bp: u16 = match ev {
        EvidenceKind::Equivocation { .. } => params.equivocation_bp,
        EvidenceKind::EquivocationBftV1 { .. } => params.equivocation_bp,
        EvidenceKind::VoteInvalid { .. } => params.vote_invalid_bp,
        EvidenceKind::ConflictingDAAttest { .. } => params.conflicting_da_bp,
        EvidenceKind::SlashTicketV1 { slash_bp, .. } => *slash_bp,
        EvidenceKind::MintCensorshipV1 { .. } => unreachable!(),
        EvidenceKind::MintCandidateV1 { .. } => unreachable!(),
        EvidenceKind::MintPoWCertV1 { .. } => unreachable!(),
        EvidenceKind::MintMissingImportV1 { .. } => unreachable!(),
        EvidenceKind::MintCensorshipV2 { .. } => unreachable!(),
        EvidenceKind::MintCandidateV2 { .. } => unreachable!(),
        EvidenceKind::MintPoWCertV2 { .. } => unreachable!(),
        EvidenceKind::MintMissingImportV2 { .. } => unreachable!(),
    };
    if bp == 0 || bp > 10_000 {
        return Err(ConsensusError::InvalidParams);
    }
    let pot = split_bp(slashed_bond, bp);
    if pot == 0 {
        return Ok(PayoutSet { entries: vec![] });
    }
    // Eligible: all recipients except the offender, deterministically sorted.
    // Eligible: alle außer Täter, deterministisch sortiert.
    let mut elig: Vec<[u8; 32]> = recipients
        .iter()
        .copied()
        .filter(|id| *id != offender)
        .collect();
    if elig.is_empty() {
        return Err(ConsensusError::InvalidParams);
    }
    elig.sort_unstable(); // deterministisch sortieren
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

/// Distributes the attestor pot evenly across a sample of attestors.
/// Verteilt den Attestor-Topf gleichmäßig auf eine Stichprobe von Attestoren.
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

/// Combines committee and attestor payouts and returns the final payout root.
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

/// Returns, for each seat (0..k-1), the minimal ack distance (in edges) from the given `ack_id`
/// to any anchor of that seat within the provided header set.
/// Distance 1 corresponds to a direct parent; distance 0 (the ack itself) is not counted.
/// Liefert pro Seat (0..k-1) die minimale Ack-Distanz (in Kanten) vom gegebenen `ack_id`
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
// Auto-Proposer Functions (proposer = creator)
// ============================

/// Computes committee payout using anchor's creator_index as proposer.
/// Berechnet Committee-Payout mit creator_index des Anchors als Proposer.
pub fn compute_committee_payout_auto_proposer(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    anchor: &AnchorHeader,
    ack_distances: &[Option<u8>],
) -> Result<PayoutSet, ConsensusError> {
    compute_committee_payout(
        fees_total,
        params,
        recipients,
        anchor.creator_index as usize,
        ack_distances,
    )
}

/// Computes committee payout root using anchor's creator_index as proposer.
/// Berechnet Committee-Payout-Root mit creator_index des Anchors als Proposer.
pub fn committee_payout_root_auto_proposer(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    anchor: &AnchorHeader,
    ack_distances: &[Option<u8>],
) -> Result<pc_crypto::Hash32, ConsensusError> {
    committee_payout_root(
        fees_total,
        params,
        recipients,
        anchor.creator_index as usize,
        ack_distances,
    )
}

/// Computes total payout root (committee + attestors) using anchor's creator_index as proposer.
/// Berechnet Gesamt-Payout-Root (Committee + Attestoren) mit creator_index als Proposer.
pub fn compute_total_payout_root_auto_proposer(
    fees_total: Amount,
    params: &FeeSplitParams,
    recipients: &[[u8; 32]],
    anchor: &AnchorHeader,
    ack_distances: &[Option<u8>],
    attestors: &[[u8; 32]],
) -> Result<pc_crypto::Hash32, ConsensusError> {
    compute_total_payout_root(
        fees_total,
        params,
        recipients,
        anchor.creator_index as usize,
        ack_distances,
        attestors,
    )
}

// ============================
// Proof-of-Work (Emission)
// ============================

const MINT_POW_SEED_DOMAIN_V1: &[u8] = b"pc:mint:pow:seed:v1\x01";
const MINT_POW_SEED_DOMAIN_V2: &[u8] = b"pc:mint:pow:seed:v2\x01";
const MINT_ROUND_ID_DOMAIN_V1: &[u8] = b"pc:mint:round:v1\x01";

#[inline]
fn push_varu64(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

#[inline]
pub fn mint_pow_seed_v1(network_id: &NetworkId, template: &MintEvent) -> pc_crypto::Hash32 {
    let mut buf = Vec::with_capacity(MINT_POW_SEED_DOMAIN_V1.len() + 32 + 1 + 32 + 64);
    buf.extend_from_slice(MINT_POW_SEED_DOMAIN_V1);
    buf.extend_from_slice(network_id);
    buf.push(template.version);
    buf.extend_from_slice(&template.prev_mint_id);
    push_varu64(&mut buf, template.outputs.len() as u64);
    for o in template.outputs.iter() {
        push_varu64(&mut buf, o.amount);
        buf.extend_from_slice(&o.lock.0);
    }
    pc_crypto::blake3_32(&buf)
}

#[inline]
pub fn mint_round_id_v1(prev_mint_id: &[u8; 32], next_mint_height: u64) -> pc_crypto::Hash32 {
    let mut buf = Vec::with_capacity(MINT_ROUND_ID_DOMAIN_V1.len() + 32 + 8);
    buf.extend_from_slice(MINT_ROUND_ID_DOMAIN_V1);
    buf.extend_from_slice(prev_mint_id);
    push_varu64(&mut buf, next_mint_height);
    pc_crypto::blake3_32(&buf)
}

#[inline]
pub fn mint_pow_seed_v2(network_id: &NetworkId, template: &MintEvent) -> pc_crypto::Hash32 {
    let mut buf = Vec::with_capacity(MINT_POW_SEED_DOMAIN_V2.len() + 32 + 1 + 32 + 64 + 32 + 8 + 1);
    buf.extend_from_slice(MINT_POW_SEED_DOMAIN_V2);
    buf.extend_from_slice(network_id);
    buf.push(template.version);
    buf.extend_from_slice(&template.prev_mint_id);
    push_varu64(&mut buf, template.outputs.len() as u64);
    for o in template.outputs.iter() {
        push_varu64(&mut buf, o.amount);
        buf.extend_from_slice(&o.lock.0);
    }
    buf.extend_from_slice(&template.round_id);
    push_varu64(&mut buf, template.hit_bucket);
    buf.push(template.bits_used);
    pc_crypto::blake3_32(&buf)
}

#[inline]
pub fn current_emission_bucket() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => consts::emission_bucket_from_unix_millis(dur.as_millis()),
        Err(_) => 0,
    }
}

const POW_HASH_INPUT_LEN: usize = consts::POW_DOMAIN.len() + 32 + 8;

/// BLAKE3 hash over `(POW_DOMAIN || pow_seed(32) || pow_nonce_le(8))`.
/// BLAKE3-Hash über (POW_DOMAIN || pow_seed(32) || pow_nonce_le(8)).
#[inline]
pub fn pow_hash(seed: &[u8; 32], nonce: u64) -> pc_crypto::Hash32 {
    let domain_len = consts::POW_DOMAIN.len();
    let nonce_bytes = nonce.to_le_bytes();
    let mut buf = [0u8; POW_HASH_INPUT_LEN];
    buf[..domain_len].copy_from_slice(consts::POW_DOMAIN);
    buf[domain_len..domain_len + 32].copy_from_slice(seed);
    buf[domain_len + 32..].copy_from_slice(&nonce_bytes);
    pc_crypto::blake3_32(&buf)
}

/// Checks whether the hash has at least `bits` leading zero bits (MSB-first per byte).
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

/// Convenience: checks the PoW of a `MintEvent` against `bits`.
/// Convenience: Prüft PoW für ein MintEvent gegen `bits`.
#[inline]
pub fn check_mint_pow(m: &MintEvent, bits: u8) -> bool {
    let h = pow_hash(&m.pow_seed, m.pow_nonce);
    pow_meets(bits, &h)
}

#[inline]
pub fn validate_mint_pow_bound_v1(
    network_id: &NetworkId,
    m: &MintEvent,
    bits: u8,
) -> Result<(), ConsensusError> {
    let expected_seed = if m.uses_emission_rounds() {
        mint_pow_seed_v2(network_id, m)
    } else {
        mint_pow_seed_v1(network_id, m)
    };
    if expected_seed != m.pow_seed {
        return Err(ConsensusError::InvalidParams);
    }
    if !check_mint_pow(m, bits) {
        return Err(ConsensusError::InvalidParams);
    }
    Ok(())
}

#[inline]
pub fn validate_mint_pow_and_emission_v2(
    network_id: &NetworkId,
    supply: &SupplyState,
    m: &MintEvent,
) -> Result<(), ConsensusError> {
    if !m.uses_emission_rounds() {
        return Err(ConsensusError::InvalidParams);
    }
    let expected_round_id =
        mint_round_id_v1(&supply.last_mint_id, supply.mint_height.saturating_add(1));
    if m.round_id == [0u8; 32] || m.round_id != expected_round_id {
        return Err(ConsensusError::InvalidParams);
    }
    if m.hit_bucket < supply.last_final_emission_bucket {
        return Err(ConsensusError::InvalidParams);
    }
    let expected_bits = supply.expected_bits_for_bucket(m.hit_bucket);
    if m.bits_used != expected_bits {
        return Err(ConsensusError::InvalidParams);
    }
    validate_mint_pow_bound_v1(network_id, m, m.bits_used)?;
    Ok(())
}

#[inline]
pub fn validate_mint_timing_window_v2(
    m: &MintEvent,
    current_bucket: u64,
) -> Result<(), ConsensusError> {
    if !m.uses_emission_rounds() {
        return Err(ConsensusError::InvalidParams);
    }
    if m.hit_bucket > current_bucket.saturating_add(consts::EMISSION_MAX_FUTURE_SKEW_BUCKETS) {
        return Err(ConsensusError::InvalidParams);
    }
    let collect_deadline = consts::emission_collect_deadline_bucket(m.hit_bucket);
    let finalize_deadline = consts::emission_finalize_deadline_bucket(m.hit_bucket);
    if current_bucket < collect_deadline || current_bucket > finalize_deadline {
        return Err(ConsensusError::InvalidParams);
    }
    Ok(())
}

/// Supply tracking state: tracks total emission and the `prev_mint_id` chain.
/// Supply Tracking State: Verfolgt die Gesamtemission und prev_mint_id-Kette.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SupplyState {
    pub total_supply: u128, // Current total supply in units. Aktueller Gesamt-Supply in Einheiten.
    pub mint_height: u64, // Number of processed mints (height of the mint chain). Anzahl der verarbeiteten Mints (Höhe der Mint-Kette).
    pub last_mint_id: [u8; 32], // Hash of the last processed mint. Hash des letzten verarbeiteten Mints.
    pub pow_bits: u8,
    pub last_minted_at_index: u64, // Anchor-Index des letzten Mints (uhrfrei)
    #[serde(default)]
    pub last_final_emission_bucket: u64,
    #[serde(default)]
    pub pow_asert_ref_bucket: u64,
    /// Minimum PoW difficulty ("powLimit") in leading-zero bits.
    /// Minimale PoW-Schwierigkeit ("powLimit") in führenden Nullbits.
    #[serde(default)]
    pub pow_bits_min: u8,
    /// Retarget window start (first mint of the current window).
    /// Startpunkt des Retarget-Windows (erste Mint im aktuellen Window).
    #[serde(default)]
    pub pow_retarget_start_mint_height: u64,
    #[serde(default)]
    pub pow_retarget_start_anchor_index: u64,
}

impl SupplyState {
    pub fn new() -> Self {
        let init_bits = consts::pow_bits_for_mint_height(consts::POW_DEFAULT_BITS, 1);
        Self {
            total_supply: 0,
            mint_height: 0,
            last_mint_id: [0u8; 32],
            pow_bits: init_bits,
            last_minted_at_index: 0,
            last_final_emission_bucket: 0,
            pow_asert_ref_bucket: 0,
            pow_bits_min: init_bits,
            pow_retarget_start_mint_height: 0,
            pow_retarget_start_anchor_index: 0,
        }
    }

    #[inline]
    pub fn expected_bits_for_bucket(&self, hit_bucket: u64) -> u8 {
        if self.pow_bits == 0 {
            return 0;
        }
        let ref_bucket = if self.pow_asert_ref_bucket == 0 {
            hit_bucket
        } else {
            self.pow_asert_ref_bucket
        };
        consts::pow_asert_bits(self.pow_bits, self.pow_bits_min, ref_bucket, hit_bucket)
    }

    /// Validates a mint against the current supply state without mutating state.
    ///
    /// This is the consensus rule set that must hold before a mint can be included in a payload.
    /// The caller is responsible for PoW checks and role-policy checks.
    pub fn validate_mint(&self, mint: &MintEvent) -> Result<(), ConsensusError> {
        // 1. Check the `prev_mint_id` chain.
        if mint.prev_mint_id != self.last_mint_id {
            return Err(ConsensusError::InvalidParams);
        }

        // 2. Compute expected reward based on height.
        let expected_reward = consts::compute_mint_reward(self.mint_height + 1);

        // 3. Sum actual mint outputs.
        let mut mint_total: u64 = 0;
        for out in &mint.outputs {
            mint_total = mint_total.saturating_add(out.amount);
        }

        // 4. Validate: mint may not spend more than the reward.
        if mint_total > expected_reward {
            return Err(ConsensusError::InvalidParams);
        }

        // 5. Check hard cap.
        let new_supply = self.total_supply.saturating_add(mint_total as u128);
        if new_supply > consts::HARD_CAP_UNITS {
            return Err(ConsensusError::InvalidParams);
        }

        Ok(())
    }

    /// Validates and processes a new mint.
    /// Validiert und verarbeitet einen neuen Mint.
    /// `current_anchor_index` wird von der Node gesetzt (nicht vom Miner).
    pub fn process_mint(
        &mut self,
        mint: &MintEvent,
        current_anchor_index: u64,
    ) -> Result<(), ConsensusError> {
        if current_anchor_index < self.last_minted_at_index {
            return Err(ConsensusError::InvalidParams);
        }

        // Validate consensus rules that must hold before state transition.
        self.validate_mint(mint)?;

        // Recompute totals for the state transition (kept explicit for clarity).
        let mut mint_total: u64 = 0;
        for out in &mint.outputs {
            mint_total = mint_total.saturating_add(out.amount);
        }
        let new_supply = self.total_supply.saturating_add(mint_total as u128);

        // 6. Update state.
        // 6. Update State.
        self.total_supply = new_supply;
        self.mint_height += 1;
        self.last_mint_id = pc_types::digest_mint(mint);

        self.last_minted_at_index = current_anchor_index;
        if mint.uses_emission_rounds() {
            self.last_final_emission_bucket = mint.hit_bucket;
            self.pow_asert_ref_bucket = mint.hit_bucket;
            self.pow_bits = mint.bits_used.max(self.pow_bits_min);
            return Ok(());
        }

        // Ensure powLimit is initialized even when loading older `supply_state.json` files
        // that predate `pow_bits_min`.
        if self.pow_bits_min == 0 && self.pow_bits != 0 {
            self.pow_bits_min = self.pow_bits;
        }
        // Enforce powLimit.
        if self.pow_bits < self.pow_bits_min {
            self.pow_bits = self.pow_bits_min;
        }

        // Bitcoin-like difficulty retarget (clock-free).
        //
        // We retarget only based on the finalized global anchor index to keep the rule deterministic
        // without relying on Unix timestamps.
        if self.pow_bits != 0 {
            // Start a new window on the first mint of each period.
            if self.pow_retarget_start_mint_height == 0
                || (self.mint_height % consts::POW_RETARGET_WINDOW_MINTS) == 1
            {
                self.pow_retarget_start_mint_height = self.mint_height;
                self.pow_retarget_start_anchor_index = current_anchor_index;
            }

            // Retarget for the next mint when the current height closes the window.
            if self.pow_retarget_start_mint_height != 0
                && self
                    .mint_height
                    .is_multiple_of(consts::POW_RETARGET_WINDOW_MINTS)
            {
                let expected = consts::POW_TARGET_ANCHORS_PER_MINT
                    .saturating_mul(consts::POW_RETARGET_WINDOW_MINTS);
                let actual =
                    current_anchor_index.saturating_sub(self.pow_retarget_start_anchor_index);
                self.pow_bits =
                    consts::pow_retarget_bits(self.pow_bits, self.pow_bits_min, expected, actual);

                // Next window will start at the next mint.
                self.pow_retarget_start_mint_height = 0;
                self.pow_retarget_start_anchor_index = 0;
            }
        }

        Ok(())
    }

    /// Checks whether further minting is possible.
    /// Prüft ob weiteres Minting möglich ist.
    pub fn can_mint(&self) -> bool {
        self.total_supply < consts::HARD_CAP_UNITS
    }

    /// Returns the expected reward for the next mint.
    /// Gibt den erwarteten Reward für den nächsten Mint zurück.
    pub fn next_reward(&self) -> u64 {
        consts::compute_mint_reward(self.mint_height + 1)
    }

    /// Remaining supply until hard cap.
    /// Verbleibende Supply bis Hardcap.
    pub fn remaining_supply(&self) -> u128 {
        consts::HARD_CAP_UNITS.saturating_sub(self.total_supply)
    }
}

impl Default for SupplyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple in-memory anchor graph structure for insert/lookup and ack distances.
/// Einfache in-memory Anker-Graph Struktur für Insert/Lookup und Ack-Distanzen.
pub struct AnchorGraph {
    map: std::collections::HashMap<AnchorId, AnchorHeader>,
    insert_order: std::collections::VecDeque<AnchorId>,
    max_capacity: usize,
    evict_total: u64,
}

impl AnchorGraph {
    /// Default max number of headers kept in memory.
    ///
    /// This is a DoS hardening measure. The graph is a local cache and not suitable
    /// as a consensus-critical source of truth (nodes may see different header sets).
    pub const DEFAULT_MAX_CAPACITY: usize = 16_384;

    pub fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            insert_order: std::collections::VecDeque::new(),
            max_capacity: Self::DEFAULT_MAX_CAPACITY,
            evict_total: 0,
        }
    }

    pub fn with_max_capacity(max_capacity: usize) -> Self {
        let cap = core::cmp::max(1, max_capacity);
        Self {
            map: std::collections::HashMap::new(),
            insert_order: std::collections::VecDeque::new(),
            max_capacity: cap,
            evict_total: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Updates the max capacity and prunes immediately if the graph is larger.
    pub fn set_max_capacity(&mut self, max_capacity: usize) {
        self.max_capacity = core::cmp::max(1, max_capacity);
        self.prune_to_capacity();
    }

    pub fn evict_total(&self) -> u64 {
        self.evict_total
    }

    fn prune_to_capacity(&mut self) {
        while self.map.len() > self.max_capacity {
            if let Some(old) = self.insert_order.pop_front() {
                if self.map.remove(&old).is_some() {
                    self.evict_total = self.evict_total.saturating_add(1);
                }
            } else {
                break;
            }
        }
    }

    /// Fügt einen Header ein und gibt dessen berechnete AnchorId zurück
    pub fn insert(&mut self, header: AnchorHeader) -> AnchorId {
        let id = AnchorId(header.id_digest());
        self.insert_with_id(id, header)
    }

    /// Fügt einen Header mit expliziter AnchorId ein.
    ///
    /// Useful when IDs are computed in a different digest domain than `AnchorHeader::id_digest`
    /// (e.g. V2 header IDs while storing V1-compatible projection in the graph).
    pub fn insert_with_id(&mut self, id: AnchorId, header: AnchorHeader) -> AnchorId {
        let is_new = !self.map.contains_key(&id);
        let _prev = self.map.insert(id, header);
        if is_new {
            self.insert_order.push_back(id);
            self.prune_to_capacity();
        }
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

/// Cross-Link-Validierung: Bei >= 2 Parents muss mindestens ein Parent aus einem
/// anderen Shard stammen, damit Shards nicht isoliert divergieren.
/// Bei < 2 Parents (k=1 Bootstrap) wird true zurückgegeben.
/// Wenn ein Parent im Graph nicht gefunden wird, wird er ignoriert (nicht als Cross-Link gezählt).
pub fn validate_cross_link(header: &AnchorHeader, graph: &AnchorGraph) -> bool {
    if header.parents.len < 2 {
        return true;
    }
    header
        .parents
        .ids
        .iter()
        .take(header.parents.len as usize)
        .any(|pid| {
            graph
                .get(pid)
                .map(|ph| ph.shard_id != header.shard_id)
                .unwrap_or(false)
        })
}

/// In-Memory Graph mit einfachem Ack-Distanz-Cache (invalidiert bei Insert)
pub struct AnchorGraphCache {
    graph: AnchorGraph,
    ack_cache: std::collections::HashMap<(AnchorId, u8, u8), Vec<Option<u8>>>,
    ack_order: std::collections::VecDeque<(AnchorId, u8, u8)>,
    ack_cache_max_entries: usize,
    orphans: std::collections::HashMap<AnchorId, OrphanEntry>,
    orphan_order: std::collections::VecDeque<AnchorId>,
    orphan_wait: std::collections::HashMap<AnchorId, Vec<AnchorId>>,
    orphan_max_entries: usize,
    orphan_dropped_total: u64,
}

#[derive(Clone, Debug)]
struct OrphanEntry {
    header: AnchorHeader,
    missing: Vec<AnchorId>,
}

impl Default for AnchorGraphCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AnchorGraphCache {
    pub const DEFAULT_MAX_ORPHANS: usize = 1024;
    pub const DEFAULT_MAX_ACK_CACHE_ENTRIES: usize = 1024;

    pub fn new() -> Self {
        Self::with_limits(
            AnchorGraph::DEFAULT_MAX_CAPACITY,
            Self::DEFAULT_MAX_ORPHANS,
            Self::DEFAULT_MAX_ACK_CACHE_ENTRIES,
        )
    }

    pub fn with_limits(graph_max: usize, orphan_max: usize, ack_cache_max: usize) -> Self {
        Self {
            graph: AnchorGraph::with_max_capacity(graph_max),
            ack_cache: std::collections::HashMap::new(),
            ack_order: std::collections::VecDeque::new(),
            ack_cache_max_entries: ack_cache_max,
            orphans: std::collections::HashMap::new(),
            orphan_order: std::collections::VecDeque::new(),
            orphan_wait: std::collections::HashMap::new(),
            orphan_max_entries: orphan_max,
            orphan_dropped_total: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.graph.len()
    }
    pub fn is_empty(&self) -> bool {
        self.graph.is_empty()
    }
    pub fn orphans_len(&self) -> usize {
        self.orphans.len()
    }
    pub fn orphan_dropped_total(&self) -> u64 {
        self.orphan_dropped_total
    }
    pub fn evict_total(&self) -> u64 {
        self.graph.evict_total()
    }
    pub fn set_graph_max_capacity(&mut self, cap: usize) {
        let prev = self.graph.evict_total();
        self.graph.set_max_capacity(cap);
        if self.graph.evict_total() != prev {
            self.clear_ack_cache();
        }
    }

    pub fn insert(&mut self, header: AnchorHeader) -> AnchorId {
        let id = AnchorId(header.id_digest());
        self.insert_with_id(header, id)
    }

    pub fn insert_with_id(&mut self, header: AnchorHeader, id: AnchorId) -> AnchorId {
        if self.graph.contains(&id) {
            return id;
        }

        if self.parents_known(&header) {
            self.insert_ready(header, id);
        } else {
            self.insert_orphan(header, id);
        }
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
        // Only cache lookups for known nodes, and cap the cache size. This prevents
        // unbounded memory usage from repeated queries for random/unknown ack ids.
        if self.graph.contains(&ack_id) && self.ack_cache_max_entries > 0 {
            self.ack_cache_insert(key, d.clone());
        }
        d
    }

    fn clear_ack_cache(&mut self) {
        self.ack_cache.clear();
        self.ack_order.clear();
    }

    fn ack_cache_insert(&mut self, key: (AnchorId, u8, u8), val: Vec<Option<u8>>) {
        let key_copy = key;
        match self.ack_cache.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(val);
                return;
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                let _ = e.insert(val);
            }
        }
        self.ack_order.push_back(key_copy);
        while self.ack_cache.len() > self.ack_cache_max_entries {
            if let Some(old) = self.ack_order.pop_front() {
                let _ = self.ack_cache.remove(&old);
            } else {
                break;
            }
        }
    }

    fn parents_known(&self, header: &AnchorHeader) -> bool {
        let plen = header.parents.len as usize;
        for pid in header.parents.ids.iter().take(plen) {
            if !self.graph.contains(pid) {
                return false;
            }
        }
        true
    }

    fn missing_parents(&self, header: &AnchorHeader) -> Vec<AnchorId> {
        let plen = header.parents.len as usize;
        let mut missing: Vec<AnchorId> = Vec::new();
        for pid in header.parents.ids.iter().take(plen) {
            if !self.graph.contains(pid) {
                missing.push(*pid);
            }
        }
        missing
    }

    fn remove_orphan_from_wait_index(&mut self, oid: AnchorId, missing: &[AnchorId]) {
        for pid in missing {
            if let Some(list) = self.orphan_wait.get_mut(pid) {
                list.retain(|x| x != &oid);
                if list.is_empty() {
                    self.orphan_wait.remove(pid);
                }
            }
        }
    }

    fn prune_orphans_to_capacity(&mut self) {
        while self.orphans.len() > self.orphan_max_entries {
            if let Some(old) = self.orphan_order.pop_front() {
                if let Some(entry) = self.orphans.remove(&old) {
                    self.orphan_dropped_total = self.orphan_dropped_total.saturating_add(1);
                    self.remove_orphan_from_wait_index(old, &entry.missing);
                }
            } else {
                break;
            }
        }
    }

    fn insert_orphan(&mut self, header: AnchorHeader, id: AnchorId) {
        if self.orphan_max_entries == 0 {
            self.orphan_dropped_total = self.orphan_dropped_total.saturating_add(1);
            return;
        }
        if self.orphans.contains_key(&id) {
            return;
        }
        let missing = self.missing_parents(&header);
        let entry = OrphanEntry {
            header,
            missing: missing.clone(),
        };
        self.orphans.insert(id, entry);
        self.orphan_order.push_back(id);
        for pid in missing {
            self.orphan_wait.entry(pid).or_default().push(id);
        }
        self.prune_orphans_to_capacity();
    }

    fn insert_ready(&mut self, header: AnchorHeader, id: AnchorId) {
        let prev_evict = self.graph.evict_total();
        let inserted = self.graph.insert_with_id(id, header);
        debug_assert_eq!(inserted, id);
        if self.graph.evict_total() != prev_evict {
            self.clear_ack_cache();
        }

        // Orphan processing: any new node may unblock orphans that were waiting on it.
        let mut q: std::collections::VecDeque<AnchorId> = std::collections::VecDeque::new();
        q.push_back(id);
        while let Some(parent) = q.pop_front() {
            let waiters = match self.orphan_wait.remove(&parent) {
                Some(v) => v,
                None => continue,
            };
            for oid in waiters {
                let ready = self
                    .orphans
                    .get(&oid)
                    .map(|e| self.parents_known(&e.header))
                    .unwrap_or(false);
                if !ready {
                    continue;
                }
                let entry = match self.orphans.remove(&oid) {
                    Some(e) => e,
                    None => continue,
                };
                self.remove_orphan_from_wait_index(oid, &entry.missing);
                let prev_evict2 = self.graph.evict_total();
                let nid = self.graph.insert_with_id(oid, entry.header);
                if self.graph.evict_total() != prev_evict2 {
                    self.clear_ack_cache();
                }
                q.push_back(nid);
            }
        }
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
        if self.bootstrap_k1 {
            1
        } else {
            self.k
        }
    }
}

pub struct ConsensusEngine {
    cfg: ConsensusConfig,
    cache: AnchorGraphCache,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnchorGraphStats {
    pub headers: usize,
    pub orphans: usize,
    pub evict_total: u64,
    pub orphan_dropped_total: u64,
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

    /// Fügt einen Header mit expliziter ID ein.
    pub fn insert_header_with_id(&mut self, id: AnchorId, header: AnchorHeader) -> AnchorId {
        self.cache.insert_with_id(header, id)
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

    /// Erzeugt die Committee-Payout-Root mit automatischem Proposer (creator_index).
    /// Creates Committee-Payout-Root with automatic proposer (creator_index).
    pub fn committee_payout_root_for_ack_auto_proposer(
        &mut self,
        fees_total: Amount,
        recipients: &[[u8; 32]],
        anchor: &AnchorHeader,
    ) -> Result<pc_crypto::Hash32, ConsensusError> {
        let ack_id = AnchorId(anchor.id_digest());
        let dists = self.ack_distances(ack_id);
        committee_payout_root(
            fees_total,
            &self.cfg.fee_params,
            recipients,
            anchor.creator_index as usize,
            &dists,
        )
    }

    /// Read-only visibility into the in-memory AnchorGraph cache state. Useful for runtime metrics.
    pub fn anchor_graph_stats(&self) -> AnchorGraphStats {
        AnchorGraphStats {
            headers: self.cache.len(),
            orphans: self.cache.orphans_len(),
            evict_total: self.cache.evict_total(),
            orphan_dropped_total: self.cache.orphan_dropped_total(),
        }
    }
}

#[cfg(test)]
mod tests;
