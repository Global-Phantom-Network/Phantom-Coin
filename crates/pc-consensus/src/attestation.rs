// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

//! Consensus message formats used for committee/attestor signatures.

pub use crate::attestor_pool::{
    attestation_message, attestor_aggregate_sigs, committee_precommit_message,
    committee_vote_message,
};

/// Domain-separated slash-ticket message.
///
/// This binds all replay-relevant fields (network, seed anchor, epoch, offender, category, bp, id,
/// reporter) into a single byte string for BLS signing/verification.
#[allow(clippy::too_many_arguments)]
pub fn slash_ticket_message(
    network_id: &pc_types::NetworkId,
    seed_anchor: &[u8; 32],
    vote_epoch: u64,
    offender_id: &[u8; 32],
    category: u8,
    slash_bp: u16,
    slash_id: &[u8; 32],
    reporter_lock: &[u8; 32],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"pc:slash:ticket:v1\x01";
    let mut m = Vec::with_capacity(DOMAIN.len() + 32 + 32 + 8 + 32 + 1 + 2 + 32 + 32);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(network_id);
    m.extend_from_slice(seed_anchor);
    m.extend_from_slice(&vote_epoch.to_le_bytes());
    m.extend_from_slice(offender_id);
    m.push(category);
    m.extend_from_slice(&slash_bp.to_le_bytes());
    m.extend_from_slice(slash_id);
    m.extend_from_slice(reporter_lock);
    m
}
