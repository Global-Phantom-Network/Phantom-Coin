// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Attestor Claim Path mit Merkle-Proofs
//!
//! Ermöglicht Attestoren, ihre Payouts via Merkle-Proof zu claimen.
//! Proof-Größe: O(log M) für M Attestoren.

use pc_crypto::{blake3_32, Hash32};
use pc_types::{Amount, PayoutSet};
use std::collections::HashSet;

/// Domain-Tags für Merkle-Tree-Hashing
const LEAF_DOMAIN: &[u8] = b"pc:payout:leaf:v1\x01";
const NODE_DOMAIN: &[u8] = b"pc:payout:node:v1\x01";

/// L2-Fix: Maximum claim window in anchors (e.g. ~7 days at 1 anchor/10s = 60480).
/// L2-Fix: Maximales Claim-Fenster in Anchors (z.B. ~7 Tage bei 1 Anchor/10s = 60480).
/// Claims older than this are considered expired and cannot be processed.
/// Claims älter als dieses Fenster gelten als abgelaufen und werden nicht verarbeitet.
pub const CLAIM_WINDOW_ANCHORS: u64 = 60_480;
pub const MAX_TRACKED_CLAIMS: usize = 100_000;

/// Attestor Claim mit Merkle-Proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestorClaim {
    pub recipient_id: [u8; 32],
    pub amount: Amount,
    pub payout_root: Hash32,
    pub merkle_proof: Vec<Hash32>,
    pub leaf_index: u32,
}

/// Merkle-Tree für Payout-Set
#[derive(Clone, Debug)]
pub struct PayoutMerkleTree {
    pub leaves: Vec<Hash32>,
    pub nodes: Vec<Vec<Hash32>>, // nodes[0] = leaves, nodes[height] = root
    pub root: Hash32,
}

impl PayoutMerkleTree {
    /// Erstellt einen Merkle-Tree aus einem PayoutSet
    pub fn from_payout_set(payout_set: &PayoutSet) -> Self {
        if payout_set.entries.is_empty() {
            return Self {
                leaves: vec![],
                nodes: vec![],
                root: [0u8; 32],
            };
        }

        // 1. Hash alle Payout-Entries zu Leaves
        let mut leaves: Vec<Hash32> = payout_set
            .entries
            .iter()
            .map(|entry| hash_payout_leaf(&entry.recipient_id, entry.amount))
            .collect();

        // 2. Wenn ungerade Anzahl, dupliziere letztes Leaf
        if leaves.len() % 2 == 1 {
            if let Some(last) = leaves.last().copied() {
                leaves.push(last);
            }
        }

        // 3. Build Tree bottom-up
        let mut nodes = vec![leaves.clone()];

        while nodes.last().map(|lvl| lvl.len()).unwrap_or(0) > 1 {
            let mut next_level = Vec::new();
            if let Some(current_level) = nodes.last() {
                for pair in current_level.chunks(2) {
                    if let Some((&left, rest)) = pair.split_first() {
                        let right = rest.first().copied().unwrap_or(left);
                        let parent = hash_internal_node(&left, &right);
                        next_level.push(parent);
                    }
                }
            }
            nodes.push(next_level);
        }

        let root = nodes
            .last()
            .and_then(|lvl| lvl.first())
            .copied()
            .unwrap_or([0u8; 32]);

        Self {
            leaves,
            nodes,
            root,
        }
    }

    /// Generiert einen Merkle-Proof für einen bestimmten recipient_id
    pub fn generate_proof(&self, leaf_index: u32) -> Result<Vec<Hash32>, String> {
        let idx = leaf_index as usize;

        if idx >= self.leaves.len() {
            return Err(format!(
                "leaf_index {} out of bounds (leaves: {})",
                idx,
                self.leaves.len()
            ));
        }

        let mut proof = Vec::new();
        let mut current_idx = idx;

        // Traverse von Leaf zu Root
        for current_level in self.nodes.iter().take(self.nodes.len().saturating_sub(1)) {
            // Sibling-Index berechnen
            let sibling_idx = if (current_idx & 1) == 0 {
                current_idx + 1
            } else {
                current_idx - 1
            };

            // Sibling hinzufügen (wenn vorhanden)
            if let Some(sib) = current_level.get(sibling_idx) {
                proof.push(*sib);
            } else if let Some(cur) = current_level.get(current_idx) {
                // Wenn kein Sibling existiert (ungerader Level), dupliziere aktuelles Element
                proof.push(*cur);
            }

            // Index für nächstes Level
            current_idx /= 2;
        }

        Ok(proof)
    }
}

/// Hasht einen Payout-Entry als Leaf
pub fn hash_payout_leaf(recipient_id: &[u8; 32], amount: Amount) -> Hash32 {
    let mut buf = Vec::with_capacity(LEAF_DOMAIN.len() + 32 + 8);
    buf.extend_from_slice(LEAF_DOMAIN);
    buf.extend_from_slice(recipient_id);
    buf.extend_from_slice(&amount.to_le_bytes());
    blake3_32(&buf)
}

/// Hasht zwei Child-Nodes zu einem Internal-Node
pub fn hash_internal_node(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = Vec::with_capacity(NODE_DOMAIN.len() + 32 + 32);
    buf.extend_from_slice(NODE_DOMAIN);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    blake3_32(&buf)
}

/// Generiert einen Attestor-Claim mit Merkle-Proof
pub fn generate_claim_proof(
    payout_set: &PayoutSet,
    recipient_id: &[u8; 32],
) -> Result<AttestorClaim, String> {
    // Finde Index des recipient_id in PayoutSet
    let leaf_index = payout_set
        .entries
        .iter()
        .position(|e| &e.recipient_id == recipient_id)
        .ok_or_else(|| "recipient_id not found in payout set".to_string())?;

    let amount = payout_set
        .entries
        .get(leaf_index)
        .map(|e| e.amount)
        .ok_or_else(|| "leaf index out of bounds".to_string())?;

    // Build Merkle-Tree
    let tree = PayoutMerkleTree::from_payout_set(payout_set);

    // Generiere Proof
    let merkle_proof = tree.generate_proof(leaf_index as u32)?;

    Ok(AttestorClaim {
        recipient_id: *recipient_id,
        amount,
        payout_root: tree.root,
        merkle_proof,
        leaf_index: leaf_index as u32,
    })
}

/// Verifiziert einen Attestor-Claim gegen einen erwarteten Payout-Root
pub fn verify_claim(claim: &AttestorClaim, expected_root: &Hash32) -> Result<bool, String> {
    // 1. Compute Leaf-Hash
    let mut current_hash = hash_payout_leaf(&claim.recipient_id, claim.amount);
    let mut current_idx = claim.leaf_index;

    // 2. Traverse Merkle-Proof
    for sibling in &claim.merkle_proof {
        if (current_idx & 1) == 0 {
            // current ist linkes Child
            current_hash = hash_internal_node(&current_hash, sibling);
        } else {
            // current ist rechtes Child
            current_hash = hash_internal_node(sibling, &current_hash);
        }
        current_idx /= 2;
    }

    // 3. Verifiziere Root
    if &current_hash != expected_root {
        return Ok(false);
    }

    // 4. Zusätzliche Validierung: Payout-Root in Claim muss matchen
    if &claim.payout_root != expected_root {
        return Ok(false);
    }

    Ok(true)
}

/// L2-Fix: Verifiziert Claim mit Timeout-Prüfung.
/// L2-Fix: Verifies claim with timeout check.
/// Returns Err if claim is expired, Ok(false) if invalid, Ok(true) if valid.
/// Gibt Err zurück wenn abgelaufen, Ok(false) wenn ungültig, Ok(true) wenn gültig.
pub fn verify_claim_with_timeout(
    claim: &AttestorClaim,
    expected_root: &Hash32,
    claim_anchor_index: u64,
    current_anchor_index: u64,
) -> Result<bool, String> {
    // L2-Fix: Check claim window expiry
    // L2-Fix: Prüfe Claim-Fenster-Ablauf
    if current_anchor_index.saturating_sub(claim_anchor_index) > CLAIM_WINDOW_ANCHORS {
        return Err(format!(
            "Claim expired: anchor {} is older than {} anchors from current {}",
            claim_anchor_index, CLAIM_WINDOW_ANCHORS, current_anchor_index
        ));
    }
    verify_claim(claim, expected_root)
}

/// Claim-Tracker für Double-Claim-Prevention
pub struct ClaimTracker {
    claimed: HashSet<([u8; 32], u64)>, // (recipient_id, anchor_index)
}

impl ClaimTracker {
    pub fn new() -> Self {
        Self {
            claimed: HashSet::new(),
        }
    }

    /// Markiert einen Claim als claimed
    pub fn mark_claimed(&mut self, recipient_id: [u8; 32], anchor_index: u64) -> bool {
        if self.claimed.len() >= MAX_TRACKED_CLAIMS
            && !self.claimed.contains(&(recipient_id, anchor_index))
        {
            return false;
        }
        self.claimed.insert((recipient_id, anchor_index))
    }

    /// Prüft ob bereits claimed
    pub fn is_claimed(&self, recipient_id: &[u8; 32], anchor_index: u64) -> bool {
        self.claimed.contains(&(*recipient_id, anchor_index))
    }

    /// L2-Fix: Prüft ob Claim noch im gültigen Fenster liegt
    /// L2-Fix: Checks if claim is still within valid window
    pub fn is_within_claim_window(&self, anchor_index: u64, current_anchor_index: u64) -> bool {
        current_anchor_index.saturating_sub(anchor_index) <= CLAIM_WINDOW_ANCHORS
    }

    /// L2-Fix: Versucht Claim zu markieren, gibt Fehler zurück wenn abgelaufen oder bereits claimed
    /// L2-Fix: Attempts to mark claim, returns error if expired or already claimed
    pub fn try_mark_claimed(
        &mut self,
        recipient_id: [u8; 32],
        anchor_index: u64,
        current_anchor_index: u64,
    ) -> Result<(), &'static str> {
        // L2-Fix: Prüfe ob Claim-Fenster abgelaufen
        if !self.is_within_claim_window(anchor_index, current_anchor_index) {
            return Err("Claim expired: outside claim window");
        }
        // Enforce bounded memory even if caller forgets explicit cleanup.
        self.cleanup_expired(current_anchor_index);
        // Prüfe Double-Claim
        if self.is_claimed(&recipient_id, anchor_index) {
            return Err("Claim already processed");
        }
        if !self.mark_claimed(recipient_id, anchor_index) {
            return Err("Claim tracker capacity exceeded");
        }
        Ok(())
    }

    /// Räumt alte Claims auf (nutzt jetzt CLAIM_WINDOW_ANCHORS als Default)
    /// Cleans up old claims (now uses CLAIM_WINDOW_ANCHORS as default)
    pub fn cleanup(&mut self, current_anchor_index: u64, timeout: u64) {
        self.claimed
            .retain(|(_, idx)| current_anchor_index.saturating_sub(*idx) < timeout);
    }

    /// L2-Fix: Cleanup mit Standard-Fenster
    /// L2-Fix: Cleanup with standard window
    pub fn cleanup_expired(&mut self, current_anchor_index: u64) {
        self.cleanup(current_anchor_index, CLAIM_WINDOW_ANCHORS);
    }

    pub fn len(&self) -> usize {
        self.claimed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claimed.is_empty()
    }
}

impl Default for ClaimTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_payout_set(count: usize) -> PayoutSet {
        use pc_types::PayoutEntry;

        let entries: Vec<PayoutEntry> = (0..count)
            .map(|i| PayoutEntry {
                recipient_id: blake3_32(&[b'r', i as u8]),
                amount: 1000 + i as u64,
            })
            .collect();

        PayoutSet { entries }
    }

    #[test]
    fn merkle_tree_empty_payout_set() {
        let payout_set = PayoutSet { entries: vec![] };
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);
        assert_eq!(tree.leaves.len(), 0);
        assert_eq!(tree.root, [0u8; 32]);
    }

    #[test]
    fn merkle_tree_single_entry() {
        let payout_set = create_test_payout_set(1);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        // Single entry → dupliziert zu 2 leaves
        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(tree.leaves[0], tree.leaves[1]);

        // Root sollte Hash von (leaf, leaf) sein
        let expected_root = hash_internal_node(&tree.leaves[0], &tree.leaves[1]);
        assert_eq!(tree.root, expected_root);
    }

    #[test]
    fn merkle_tree_power_of_two() {
        let payout_set = create_test_payout_set(4);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        // 4 entries → 4 leaves
        assert_eq!(tree.leaves.len(), 4);

        // Height sollte log2(4) + 1 = 3 sein (leaves, level1, root)
        assert_eq!(tree.nodes.len(), 3);
    }

    #[test]
    fn merkle_tree_odd_count() {
        let payout_set = create_test_payout_set(5);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        // 5 entries → 6 leaves (letztes dupliziert)
        assert_eq!(tree.leaves.len(), 6);
        assert_eq!(tree.leaves[4], tree.leaves[5]);
    }

    #[test]
    fn merkle_tree_m128() {
        let payout_set = create_test_payout_set(128);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        assert_eq!(tree.leaves.len(), 128);

        // Height = log2(128) + 1 = 8 (leaves + 7 internal levels + root)
        assert_eq!(tree.nodes.len(), 8);
    }

    #[test]
    fn generate_claim_proof_valid() {
        let payout_set = create_test_payout_set(8);
        let recipient_id = blake3_32(&[b'r', 2]);

        let claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        assert_eq!(claim.recipient_id, recipient_id);
        assert_eq!(claim.amount, 1002);
        assert_eq!(claim.leaf_index, 2);

        // Proof size für 8 leaves = log2(8) = 3
        assert_eq!(claim.merkle_proof.len(), 3);
    }

    #[test]
    fn generate_claim_proof_m128() {
        let payout_set = create_test_payout_set(128);
        let recipient_id = blake3_32(&[b'r', 64]);

        let claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        // Proof size für 128 leaves = log2(128) = 7
        assert_eq!(claim.merkle_proof.len(), 7);
    }

    #[test]
    fn generate_claim_proof_recipient_not_found() {
        let payout_set = create_test_payout_set(4);
        let unknown_id = blake3_32(b"unknown");

        let result = generate_claim_proof(&payout_set, &unknown_id);
        assert!(result.is_err());
    }

    #[test]
    fn verify_claim_valid() {
        let payout_set = create_test_payout_set(8);
        let recipient_id = blake3_32(&[b'r', 3]);

        let claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        let tree = PayoutMerkleTree::from_payout_set(&payout_set);
        let is_valid = verify_claim(&claim, &tree.root).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn verify_claim_all_recipients_m128() {
        let payout_set = create_test_payout_set(128);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        // Alle 128 Claims sollten valide sein
        for i in 0..128 {
            let recipient_id = blake3_32(&[b'r', i as u8]);
            let claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();
            let is_valid = verify_claim(&claim, &tree.root).unwrap();
            assert!(is_valid, "Claim {} should be valid", i);
        }
    }

    #[test]
    fn verify_claim_wrong_root() {
        let payout_set = create_test_payout_set(4);
        let recipient_id = blake3_32(&[b'r', 1]);

        let claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        let wrong_root = blake3_32(b"wrong-root");
        let is_valid = verify_claim(&claim, &wrong_root).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn verify_claim_tampered_amount() {
        let payout_set = create_test_payout_set(4);
        let recipient_id = blake3_32(&[b'r', 1]);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        let mut claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        // Tamper amount
        claim.amount += 1;

        let is_valid = verify_claim(&claim, &tree.root).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn verify_claim_tampered_proof() {
        let payout_set = create_test_payout_set(8);
        let recipient_id = blake3_32(&[b'r', 2]);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);

        let mut claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        // Tamper proof
        claim.merkle_proof[0] = blake3_32(b"tampered");

        let is_valid = verify_claim(&claim, &tree.root).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn claim_tracker_double_claim_prevention() {
        let mut tracker = ClaimTracker::new();

        let recipient_id = blake3_32(b"attestor-1");
        let anchor_index = 1000u64;

        // First claim sollte erfolgreich sein
        assert!(tracker.mark_claimed(recipient_id, anchor_index));

        // Second claim sollte False zurückgeben (schon claimed)
        assert!(!tracker.mark_claimed(recipient_id, anchor_index));

        // Prüfen ob claimed
        assert!(tracker.is_claimed(&recipient_id, anchor_index));
    }

    #[test]
    fn claim_tracker_different_anchors() {
        let mut tracker = ClaimTracker::new();

        let recipient_id = blake3_32(b"attestor-1");

        tracker.mark_claimed(recipient_id, 1000);
        tracker.mark_claimed(recipient_id, 2000);

        assert!(tracker.is_claimed(&recipient_id, 1000));
        assert!(tracker.is_claimed(&recipient_id, 2000));
    }

    #[test]
    fn claim_tracker_cleanup() {
        let mut tracker = ClaimTracker::new();

        let recipient_id = blake3_32(b"attestor-1");

        tracker.mark_claimed(recipient_id, 100);
        tracker.mark_claimed(recipient_id, 900);
        tracker.mark_claimed(recipient_id, 1500);

        // Cleanup: current=2000, timeout=1000 → Claims < 1000 werden entfernt
        tracker.cleanup(2000, 1000);

        assert!(!tracker.is_claimed(&recipient_id, 100)); // removed
        assert!(!tracker.is_claimed(&recipient_id, 900)); // removed
        assert!(tracker.is_claimed(&recipient_id, 1500)); // kept
    }

    #[test]
    fn f85_claim_tracker_capacity_limit_is_enforced() {
        let mut tracker = ClaimTracker::new();
        let anchor_index = 1_000u64;
        let current_anchor_index = anchor_index;

        for i in 0..MAX_TRACKED_CLAIMS {
            let mut recipient_id = [0u8; 32];
            recipient_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(
                tracker
                    .try_mark_claimed(recipient_id, anchor_index, current_anchor_index)
                    .is_ok(),
                "claim {} should fit into tracker capacity",
                i
            );
        }
        assert_eq!(tracker.len(), MAX_TRACKED_CLAIMS);

        let overflow_id = [0xFFu8; 32];
        let err = tracker
            .try_mark_claimed(overflow_id, anchor_index, current_anchor_index)
            .expect_err("claim beyond MAX_TRACKED_CLAIMS must be rejected");
        assert!(err.contains("capacity"));
    }

    #[test]
    fn claim_tracker_try_mark_claimed_auto_cleans_expired_entries() {
        let mut tracker = ClaimTracker::new();
        for i in 0..MAX_TRACKED_CLAIMS {
            let mut recipient_id = [0u8; 32];
            recipient_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            // old/stale entries at anchor 0
            assert!(tracker.mark_claimed(recipient_id, 0));
        }
        assert_eq!(tracker.len(), MAX_TRACKED_CLAIMS);

        let current_anchor_index = CLAIM_WINDOW_ANCHORS + 10;
        let fresh_anchor = current_anchor_index;
        let fresh_id = [0xAAu8; 32];
        let result = tracker.try_mark_claimed(fresh_id, fresh_anchor, current_anchor_index);
        assert!(
            result.is_ok(),
            "expired entries should be cleaned before capacity check"
        );
        assert!(tracker.is_claimed(&fresh_id, fresh_anchor));
    }

    #[test]
    fn merkle_proof_determinism() {
        let payout_set = create_test_payout_set(128);
        let recipient_id = blake3_32(&[b'r', 50]);

        let claim1 = generate_claim_proof(&payout_set, &recipient_id).unwrap();
        let claim2 = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        // Proof sollte deterministisch sein
        assert_eq!(claim1.merkle_proof, claim2.merkle_proof);
        assert_eq!(claim1.payout_root, claim2.payout_root);
    }

    // L2-Fix Tests
    #[test]
    fn claim_window_constant_is_reasonable() {
        // ~7 Tage bei 1 Anchor/10s
        assert_eq!(CLAIM_WINDOW_ANCHORS, 60_480);
        // Prüfe dass 7 Tage * 24h * 60min * 6 anchors/min = 60480
        assert_eq!(7 * 24 * 60 * 6, 60_480);
    }

    #[test]
    fn verify_claim_with_timeout_valid() {
        let payout_set = create_test_payout_set(4);
        let recipient_id = blake3_32(&[b'r', 1]);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);
        let claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        // Claim innerhalb des Fensters
        let result = verify_claim_with_timeout(&claim, &tree.root, 1000, 1000 + 100);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn verify_claim_with_timeout_expired() {
        let payout_set = create_test_payout_set(4);
        let recipient_id = blake3_32(&[b'r', 1]);
        let tree = PayoutMerkleTree::from_payout_set(&payout_set);
        let claim = generate_claim_proof(&payout_set, &recipient_id).unwrap();

        // Claim außerhalb des Fensters (zu alt)
        let result =
            verify_claim_with_timeout(&claim, &tree.root, 1000, 1000 + CLAIM_WINDOW_ANCHORS + 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn claim_tracker_try_mark_claimed_within_window() {
        let mut tracker = ClaimTracker::new();
        let recipient_id = blake3_32(b"attestor-1");

        // Claim innerhalb des Fensters sollte erfolgreich sein
        let result = tracker.try_mark_claimed(recipient_id, 1000, 1000 + 100);
        assert!(result.is_ok());

        // Double-Claim sollte Fehler geben
        let result2 = tracker.try_mark_claimed(recipient_id, 1000, 1000 + 100);
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("already"));
    }

    #[test]
    fn claim_tracker_try_mark_claimed_expired() {
        let mut tracker = ClaimTracker::new();
        let recipient_id = blake3_32(b"attestor-1");

        // Claim außerhalb des Fensters sollte Fehler geben
        let result = tracker.try_mark_claimed(recipient_id, 1000, 1000 + CLAIM_WINDOW_ANCHORS + 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn claim_tracker_cleanup_expired() {
        let mut tracker = ClaimTracker::new();
        let recipient_id = blake3_32(b"attestor-1");

        tracker.mark_claimed(recipient_id, 100);
        tracker.mark_claimed(recipient_id, CLAIM_WINDOW_ANCHORS + 50);

        // Cleanup mit Standard-Fenster
        tracker.cleanup_expired(CLAIM_WINDOW_ANCHORS + 200);

        assert!(!tracker.is_claimed(&recipient_id, 100)); // removed (expired)
        assert!(tracker.is_claimed(&recipient_id, CLAIM_WINDOW_ANCHORS + 50)); // kept
    }

    #[test]
    fn is_within_claim_window_boundary() {
        let tracker = ClaimTracker::new();

        // Exakt an der Grenze
        assert!(tracker.is_within_claim_window(0, CLAIM_WINDOW_ANCHORS));
        // Einen drüber
        assert!(!tracker.is_within_claim_window(0, CLAIM_WINDOW_ANCHORS + 1));
        // Weit innerhalb
        assert!(tracker.is_within_claim_window(1000, 1500));
    }
}
