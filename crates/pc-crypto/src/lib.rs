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

pub type Hash32 = [u8; 32];

pub mod schnorr;
pub use schnorr::{schnorr_sign, schnorr_verify, SchnorrKeypair};
pub mod bls;
pub use bls::*;

/// Compute BLAKE3-256 (32 bytes) digest
pub fn blake3_32(data: &[u8]) -> Hash32 {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

// Attestor-Recipient-ID aus BLS-Public-Key (Domain-separiert)
const ATTESTOR_PK_DOMAIN: &[u8] = b"pc:attest:pk:v1\x01";

pub fn attestor_recipient_id_from_bls(pk: &BlsPublicKey) -> Hash32 {
    let pkb = pk.to_bytes();
    let mut buf = Vec::with_capacity(ATTESTOR_PK_DOMAIN.len() + pkb.len());
    buf.extend_from_slice(ATTESTOR_PK_DOMAIN);
    buf.extend_from_slice(&pkb);
    blake3_32(&buf)
}

pub fn bls_pk_from_bytes(b: &[u8; 48]) -> Option<BlsPublicKey> {
    BlsPublicKey::from_bytes(b)
}

/// Hash für einen Payout-Leaf: H(domain || recipient_id(32) || amount_le(8))
pub fn payout_leaf_hash(recipient_id: &[u8; 32], amount: u64) -> Hash32 {
    let mut data = [0u8; PAYOUT_LEAF_DOMAIN.len() + 32 + 8];
    // domain
    for (dst, src) in data.iter_mut().zip(PAYOUT_LEAF_DOMAIN.iter()) {
        *dst = *src;
    }
    // recipient_id (32)
    for (dst, src) in data
        .iter_mut()
        .skip(PAYOUT_LEAF_DOMAIN.len())
        .take(32)
        .zip(recipient_id.iter())
    {
        *dst = *src;
    }
    // amount (LE 8)
    let amt = amount.to_le_bytes();
    for (dst, src) in data
        .iter_mut()
        .skip(PAYOUT_LEAF_DOMAIN.len() + 32)
        .zip(amt.iter())
    {
        *dst = *src;
    }
    blake3_32(&data)
}

const MRKL_PAIR_DOMAIN: &[u8] = b"pc:mrkl:pair:v1\x01";
const PAYOUT_LEAF_DOMAIN: &[u8] = b"pc:payout:leaf:v1\x01";

/// Merkle-Root über bereits 32-Byte-Leaves (Dupliziere letztes Leaf bei ungerader Anzahl).
/// Leerer Baum → 32 Byte Null (definiert: Merkle-Root(empty)=0x00..00)
pub fn merkle_root_hashes(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        if let Some(&first) = leaves.first() {
            return first;
        }
    }
    // Arbeits-Puffer kopieren
    let mut level: Vec<Hash32> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Hash32> = Vec::with_capacity(level.len().div_ceil(2));
        let mut it = level.iter();
        while let Some(left_ref) = it.next() {
            let left = *left_ref;
            let right = match it.next() {
                Some(r) => *r,
                None => left,
            };
            // Paar-Hash mit Domain-Trennung
            let mut data = [0u8; MRKL_PAIR_DOMAIN.len() + 64];
            // domain
            for (dst, src) in data.iter_mut().zip(MRKL_PAIR_DOMAIN.iter()) {
                *dst = *src;
            }
            // left
            for (dst, src) in data
                .iter_mut()
                .skip(MRKL_PAIR_DOMAIN.len())
                .take(32)
                .zip(left.iter())
            {
                *dst = *src;
            }
            // right
            for (dst, src) in data
                .iter_mut()
                .skip(MRKL_PAIR_DOMAIN.len() + 32)
                .zip(right.iter())
            {
                *dst = *src;
            }
            next.push(blake3_32(&data));
        }
        level = next;
    }
    level.pop().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_len() {
        let h = blake3_32(b"test");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn merkle_basic() {
        let a = blake3_32(b"a");
        let b = blake3_32(b"b");
        let r = merkle_root_hashes(&[a, b]);
        let r2 = merkle_root_hashes(&[a, b]);
        assert_eq!(r, r2);
        let single = merkle_root_hashes(&[a]);
        assert_eq!(single, a);
        let empty = merkle_root_hashes(&[]);
        assert_eq!(empty, [0u8; 32]);
    }

    #[test]
    fn attestor_recipient_id_derivation_unique_and_stable() {
        // zwei unterschiedliche Schlüssel → unterschiedliche IDs; gleiche PK → gleiche ID
        let ikm1 = blake3_32(b"ikm-attestor-1");
        let ikm2 = blake3_32(b"ikm-attestor-2");
        let kp1 = bls::bls_keygen_from_ikm(&ikm1).expect("keygen1");
        let kp2 = bls::bls_keygen_from_ikm(&ikm2).expect("keygen2");
        let id1 = attestor_recipient_id_from_bls(&kp1.pk);
        let id1b = attestor_recipient_id_from_bls(&kp1.pk);
        let id2 = attestor_recipient_id_from_bls(&kp2.pk);
        assert_eq!(id1, id1b);
        assert_ne!(id1, id2);

        // PoP Verifikation für beide
        let pop1 = bls::bls_pop_prove(&kp1.sk);
        let pop2 = bls::bls_pop_prove(&kp2.sk);
        assert!(bls::bls_pop_verify(&kp1.pk, &pop1));
        assert!(bls::bls_pop_verify(&kp2.pk, &pop2));
    }
}
