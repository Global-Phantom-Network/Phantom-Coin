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
        clippy::vec_init_then_push
    )
)]

use pc_codec::{CodecError, Decodable, Encodable};
use pc_crypto::{blake3_32, merkle_root_hashes, payout_leaf_hash, Hash32};
use std::io::{Read, Write};

pub const MAX_PARENTS: usize = 4;
// Stateless Limits (v0 – konservativ)
pub const MAX_TX_INPUTS: usize = 16;
pub const MAX_TX_OUTPUTS: usize = 16;
pub const MAX_WITNESS_BYTES: usize = 2048;
pub const MAX_MINT_OUTPUTS: usize = 256;
pub const MAX_PAYLOAD_MICROTX: usize = 4096;
pub const MAX_PAYLOAD_MINTS: usize = 1024;
pub const MAX_PAYLOAD_CLAIMS: usize = 1024;
pub const MAX_PAYLOAD_EVIDENCES: usize = 256;
pub const MAX_PAYOUT_ENTRIES: usize = 4096;
pub const MAX_GENESIS_NETWORK_NAME_BYTES: usize = 256;
pub const MAX_GENESIS_MESSAGE_BYTES: usize = 4096;
// Claim/Evidence field limits (P1-2 hardening).
// Merkle proof depth: 64 levels supports 2^64 leaves (more than enough).
// Merkle-Proof-Tiefe: 64 Ebenen unterstützen 2^64 Blätter (mehr als genug).
pub const MAX_CLAIM_MERKLE_PROOF_DEPTH: usize = 64;
// DA attestation max size: 4KB per attestation (covers BLS sig + metadata).
// DA-Attestation max Größe: 4KB pro Attestation (deckt BLS-Sig + Metadaten).
pub const MAX_EVIDENCE_ATTEST_BYTES: usize = 4 * 1024;
// Encoded size limits (bytes).
pub const MAX_HEADER_BYTES: usize = 2 * 1024;
pub const MAX_TX_BYTES: usize = 64 * 1024;
// Consensus-critical upper bound for encoded payload size.
// Konsens-kritische Obergrenze für die kodierte Payload-Größe.
//
// Keep this tight to reduce bandwidth/memory DoS surface.
pub const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

// MicroTx versions (consensus-critical).
// MicroTx-Versionen (konsens-kritisch).
pub const TX_VERSION_TRANSFER_V1: u8 = 1;
pub const TX_VERSION_STAKE_BOND_V1: u8 = 2;
pub const TX_VERSION_STAKE_UNBOND_V1: u8 = 3;
pub const TX_VERSION_VALIDATOR_REGISTER_V1: u8 = 4;
pub const MINT_VERSION_V1: u8 = 1;
pub const MINT_VERSION_V2: u8 = 2;

// Validator register witness layout (version=4).
// Layout: pk32 || sig64 || seq_u64_le || operator_id32 || bls_pk48 || bls_pop96
pub const VALIDATOR_REGISTER_WITNESS_BYTES_V1: usize = 32 + 64 + 8 + 32 + 48 + 96;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct AnchorId(pub Hash32);

impl Encodable for AnchorId {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.0.encode(w)
    }
    fn encoded_len(&self) -> usize {
        32
    }
}
// ============================
// V2: Header/Payload mit Genesis-Bindung
// ============================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorHeaderV2 {
    pub version: u8,
    pub shard_id: u16,
    pub parents: ParentList,
    pub payload_hash: Hash32,
    pub creator_index: u8,
    pub vote_mask: u64,
    pub ack_present: bool,
    pub ack_id: AnchorId,
    pub network_id: Hash32,
    pub vote_epoch: u64,
    pub vote_round: u64,
    pub attest_sig: Option<[u8; 96]>,
    pub state_root: Option<[u8; 32]>,
}
impl Default for AnchorHeaderV2 {
    fn default() -> Self {
        Self {
            version: 2,
            shard_id: 0,
            parents: ParentList::default(),
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
            network_id: [0u8; 32],
            vote_epoch: 0,
            vote_round: 0,
            attest_sig: None,
            state_root: None,
        }
    }
}
impl Encodable for AnchorHeaderV2 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.encode_core(w)?;
        if self.version >= 3 {
            match self.attest_sig {
                Some(sig) => {
                    true.encode(w)?;
                    w.write_all(&sig).map_err(CodecError::Io)?;
                }
                None => {
                    false.encode(w)?;
                }
            }
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        n += self.core_len();
        if self.version >= 3 {
            n += bool::default().encoded_len();
            if self.attest_sig.is_some() {
                n += 96;
            }
        }
        n
    }
}
impl Decodable for AnchorHeaderV2 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        let shard_id = u16::decode(r)?;
        let parents = ParentList::decode(r)?;
        let payload_hash = <[u8; 32]>::decode(r)?;
        let creator_index = u8::decode(r)?;
        let vote_mask = u64::decode(r)?;
        let ack_present = bool::decode(r)?;
        let ack_id = if ack_present {
            AnchorId::decode(r)?
        } else {
            AnchorId([0u8; 32])
        };
        let network_id = <[u8; 32]>::decode(r)?;
        let (vote_epoch, vote_round, attest_sig, state_root) = if version >= 3 {
            let epoch = u64::decode(r)?;
            let round = if version >= 4 { u64::decode(r)? } else { 0u64 };
            let state_root = if version >= 5 {
                let has = bool::decode(r)?;
                if has {
                    let mut sr = [0u8; 32];
                    r.read_exact(&mut sr)?;
                    Some(sr)
                } else {
                    None
                }
            } else {
                None
            };
            let has = bool::decode(r)?;
            if has {
                let mut sig = [0u8; 96];
                r.read_exact(&mut sig)?;
                (epoch, round, Some(sig), state_root)
            } else {
                (epoch, round, None, state_root)
            }
        } else {
            (0u64, 0u64, None, None)
        };
        Ok(Self {
            version,
            shard_id,
            parents,
            payload_hash,
            creator_index,
            vote_mask,
            ack_present,
            ack_id,
            network_id,
            vote_epoch,
            vote_round,
            attest_sig,
            state_root,
        })
    }
}

impl AnchorHeaderV2 {
    fn encode_core<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.shard_id.encode(w)?;
        self.parents.encode(w)?;
        self.payload_hash.encode(w)?;
        self.creator_index.encode(w)?;
        self.vote_mask.encode(w)?;
        self.ack_present.encode(w)?;
        if self.ack_present {
            self.ack_id.encode(w)?;
        }
        self.network_id.encode(w)?;
        if self.version >= 3 {
            self.vote_epoch.encode(w)?;
            if self.version >= 4 {
                self.vote_round.encode(w)?;
            }
            if self.version >= 5 {
                match self.state_root {
                    Some(sr) => {
                        true.encode(w)?;
                        w.write_all(&sr).map_err(CodecError::Io)?;
                    }
                    None => {
                        false.encode(w)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn core_len(&self) -> usize {
        let mut n = 0usize;
        n += self.version.encoded_len();
        n += self.shard_id.encoded_len();
        n += self.parents.encoded_len();
        n += self.payload_hash.encoded_len();
        n += self.creator_index.encoded_len();
        n += self.vote_mask.encoded_len();
        n += self.ack_present.encoded_len();
        if self.ack_present {
            n += self.ack_id.encoded_len();
        }
        n += self.network_id.encoded_len();
        if self.version >= 3 {
            n += self.vote_epoch.encoded_len();
            if self.version >= 4 {
                n += self.vote_round.encoded_len();
            }
            if self.version >= 5 {
                n += bool::default().encoded_len();
                if self.state_root.is_some() {
                    n += 32;
                }
            }
        }
        n
    }

    pub fn id_digest(&self) -> Hash32 {
        let mut buf = Vec::with_capacity(self.encoded_len());
        let _ = self.encode_core(&mut buf);
        blake3_32(&buf)
    }

    /// Hash der signierbaren Header-Felder (ohne Attestations-Signatur).
    pub fn signing_hash(&self) -> Hash32 {
        let mut buf = Vec::with_capacity(self.encoded_len());
        let _ = self.encode_core(&mut buf);
        blake3_32(&buf)
    }

    /// Hash of the fields that committee members sign (vote target).
    ///
    /// `vote_mask` is excluded so that signers do not need to know the final signer set.
    pub fn vote_target_hash(&self) -> Hash32 {
        let mut h = self.clone();
        h.vote_mask = 0;
        h.signing_hash()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorPayloadV2 {
    pub version: u8,
    pub micro_txs: Vec<MicroTx>,
    pub mints: Vec<MintEvent>,
    pub claims: Vec<ClaimEvent>,
    pub evidences: Vec<EvidenceEvent>,
    pub payout_root: Hash32,
    pub genesis_note: Option<GenesisNote>,
}
impl Encodable for AnchorPayloadV2 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.micro_txs.encode(w)?;
        self.mints.encode(w)?;
        self.claims.encode(w)?;
        self.evidences.encode(w)?;
        self.payout_root.encode(w)?;
        match &self.genesis_note {
            Some(note) => {
                true.encode(w)?;
                note.encode(w)?;
            }
            None => {
                false.encode(w)?;
            }
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        n += self.version.encoded_len();
        n += self.micro_txs.encoded_len();
        n += self.mints.encoded_len();
        n += self.claims.encoded_len();
        n += self.evidences.encoded_len();
        n += self.payout_root.encoded_len();
        n += bool::default().encoded_len();
        if let Some(note) = &self.genesis_note {
            n += note.encoded_len();
        }
        n
    }
}
impl Decodable for AnchorPayloadV2 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        // Bounded decode for all Vec fields (P1-2 hardening).
        // Gebundener Decode für alle Vec-Felder (P1-2 Härtung).
        let micro_txs = decode_bounded_vec::<MicroTx, _>(r, MAX_PAYLOAD_MICROTX)?;
        let mints = decode_bounded_vec::<MintEvent, _>(r, MAX_PAYLOAD_MINTS)?;
        let claims = decode_bounded_vec::<ClaimEvent, _>(r, MAX_PAYLOAD_CLAIMS)?;
        let evidences = decode_bounded_vec::<EvidenceEvent, _>(r, MAX_PAYLOAD_EVIDENCES)?;
        let payout_root = <[u8; 32]>::decode(r)?;
        let has_note = bool::decode(r)?;
        let genesis_note = if has_note {
            Some(GenesisNote::decode(r)?)
        } else {
            None
        };
        Ok(Self {
            version,
            micro_txs,
            mints,
            claims,
            evidences,
            payout_root,
            genesis_note,
        })
    }
}

/// V3 payload extends V2 with explicit null-mint decision semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorPayloadV3 {
    pub version: u8,
    pub micro_txs: Vec<MicroTx>,
    pub mints: Vec<MintEvent>,
    pub claims: Vec<ClaimEvent>,
    pub evidences: Vec<EvidenceEvent>,
    pub payout_root: Hash32,
    pub genesis_note: Option<GenesisNote>,
    pub null_mint: bool,
}

impl AnchorPayloadV3 {
    pub fn is_empty(&self) -> bool {
        self.micro_txs.is_empty()
            && self.mints.is_empty()
            && self.claims.is_empty()
            && self.evidences.is_empty()
            && self.genesis_note.is_none()
            && self.payout_root == [0u8; 32]
            && !self.null_mint
    }
}

impl Encodable for AnchorPayloadV3 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.micro_txs.encode(w)?;
        self.mints.encode(w)?;
        self.claims.encode(w)?;
        self.evidences.encode(w)?;
        self.payout_root.encode(w)?;
        match &self.genesis_note {
            Some(note) => {
                true.encode(w)?;
                note.encode(w)?;
            }
            None => false.encode(w)?,
        }
        self.null_mint.encode(w)?;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        n += self.version.encoded_len();
        n += self.micro_txs.encoded_len();
        n += self.mints.encoded_len();
        n += self.claims.encoded_len();
        n += self.evidences.encoded_len();
        n += self.payout_root.encoded_len();
        n += bool::default().encoded_len();
        if let Some(note) = &self.genesis_note {
            n += note.encoded_len();
        }
        n += self.null_mint.encoded_len();
        n
    }
}

impl Decodable for AnchorPayloadV3 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        let micro_txs = decode_bounded_vec::<MicroTx, _>(r, MAX_PAYLOAD_MICROTX)?;
        let mints = decode_bounded_vec::<MintEvent, _>(r, MAX_PAYLOAD_MINTS)?;
        let claims = decode_bounded_vec::<ClaimEvent, _>(r, MAX_PAYLOAD_CLAIMS)?;
        let evidences = decode_bounded_vec::<EvidenceEvent, _>(r, MAX_PAYLOAD_EVIDENCES)?;
        let payout_root = <[u8; 32]>::decode(r)?;
        let has_note = bool::decode(r)?;
        let genesis_note = if has_note {
            Some(GenesisNote::decode(r)?)
        } else {
            None
        };
        let null_mint = bool::decode(r)?;
        Ok(Self {
            version,
            micro_txs,
            mints,
            claims,
            evidences,
            payout_root,
            genesis_note,
            null_mint,
        })
    }
}

/// Computes the payload Merkle root for V2.
/// Berechne den Payload‑Merkle‑Root für V2.
/// Genesis special case: if `genesis_note` is present and the payload is canonical genesis, use `genesis_payload_root(note)`.
/// Genesis-Sonderfall: Wenn `genesis_note` vorhanden ist und der Payload kanonische Genesis ist, verwende `genesis_payload_root(note)`.
/// Otherwise, behave like V1 over all categories and the payout root.
/// Andernfalls analog V1 über alle Kategorien und den payout_root.
pub fn payload_merkle_root_v2(payload: &AnchorPayloadV2) -> Hash32 {
    if let Some(note) = &payload.genesis_note {
        let pl_root = genesis_payload_root(note);
        if payload.micro_txs.is_empty()
            && payload.mints.is_empty()
            && payload.claims.is_empty()
            && payload.evidences.is_empty()
            && payload.payout_root == pl_root
        {
            return pl_root;
        }
    }
    let mut leaves: Vec<Hash32> = Vec::new();
    for tx in &payload.micro_txs {
        leaves.push(digest_microtx(tx));
    }
    for m in &payload.mints {
        leaves.push(digest_mint(m));
    }
    for c in &payload.claims {
        leaves.push(digest_claim(c));
    }
    for e in &payload.evidences {
        leaves.push(digest_evidence(e));
    }
    if let Some(note) = &payload.genesis_note {
        leaves.push(digest_genesis_leaf(note));
    }
    leaves.push(digest_payout_root(&payload.payout_root));
    merkle_root_hashes(&leaves)
}

/// Lossless mapping from payload-v2 to payload-v3 with `null_mint=false`.
pub fn payload_v2_to_v3(payload: &AnchorPayloadV2) -> AnchorPayloadV3 {
    AnchorPayloadV3 {
        version: 3,
        micro_txs: payload.micro_txs.clone(),
        mints: payload.mints.clone(),
        claims: payload.claims.clone(),
        evidences: payload.evidences.clone(),
        payout_root: payload.payout_root,
        genesis_note: payload.genesis_note.clone(),
        null_mint: false,
    }
}

/// Computes the payload root for V3.
///
/// Compatibility note:
/// - if `null_mint == false`, this is exactly `payload_merkle_root_v2` over the shared fields.
/// - if `null_mint == true`, we domain-separate by hashing an extra null-mint leaf on top.
pub fn payload_merkle_root_v3(payload: &AnchorPayloadV3) -> Hash32 {
    let base = payload_merkle_root_v2(&AnchorPayloadV2 {
        version: 2,
        micro_txs: payload.micro_txs.clone(),
        mints: payload.mints.clone(),
        claims: payload.claims.clone(),
        evidences: payload.evidences.clone(),
        payout_root: payload.payout_root,
        genesis_note: payload.genesis_note.clone(),
    });
    if !payload.null_mint {
        return base;
    }
    let mut leaves = vec![base];
    leaves.push(digest_null_mint_decision(true));
    merkle_root_hashes(&leaves)
}

// Domain tags for leaf digests (module level).
// Domain‑Tags für Leaf‑Digests (Modulebene).
const LEAF_MICROTX: &[u8] = b"pc:leaf:microtx:v1\x01";
const LEAF_MINT: &[u8] = b"pc:leaf:mint:v1\x01";
const LEAF_CLAIM: &[u8] = b"pc:leaf:claim:v1\x01";
const LEAF_EVID: &[u8] = b"pc:leaf:evidence:v1\x01";
const LEAF_PAYOUT_ROOT: &[u8] = b"pc:leaf:payout_root:v1\x01";
const LEAF_GENESIS: &[u8] = b"pc:leaf:genesis_note:v1\x01";
const LEAF_NULL_MINT: &[u8] = b"pc:leaf:null_mint:v1\x01";

const SLASH_ID_EQUIVOCATION_BFT_V1: &[u8] = b"pc:slash:id:equivocation_bft:v1\x01";
const SLASH_REPORTER_CLAIM_SIGHASH_V1: &[u8] = b"pc:slash:reporter_claim:v1\x01";

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(domain.len() + bytes.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(bytes);
    blake3_32(&buf)
}

/// Genesis leaf digest (for the A0 special case): domain-separated hash over the encoded `GenesisNote`.
/// Genesis-Leaf-Digest (für A0-Sonderfall): Domain-separierter Hash über kodierte GenesisNote.
pub fn digest_genesis_leaf(note: &GenesisNote) -> Hash32 {
    let mut enc = Vec::with_capacity(note.encoded_len());
    let _ = note.encode(&mut enc);
    digest_with_domain(LEAF_GENESIS, &enc)
}

/// A0 payload root: Merkle root over exactly one leaf (the genesis leaf).
/// A0-Payload-Root: Merkle-Root über genau 1 Leaf (Genesis-Leaf).
pub fn genesis_payload_root(note: &GenesisNote) -> Hash32 {
    let leaf = digest_genesis_leaf(note);
    merkle_root_hashes(&[leaf])
}
// ============================
// Genesis Note (A0)
// ============================
// Domain tag for the genesis note commitment.
// Domain-Tag für Genesis-Note-Commitment.
const GENESIS_NOTE_V1: &[u8] = b"pc:genesis:note:v1\x01";

/// Network ID is represented as a 32-byte hash.
/// Netzwerk-ID wird als 32-Byte-Hash geführt.
pub type NetworkId = Hash32;

pub const GENESIS_FEATURE_MINT_POW_BIND_V1: u64 = 1u64 << 0;
pub const GENESIS_FEATURE_ROLE_POLICY_V1: u64 = 1u64 << 1;
pub const GENESIS_FEATURE_GENESIS_VALIDATORS_V1: u64 = 1u64 << 2;
pub const GENESIS_FEATURE_MINT_CENSOR_PROOF_V1: u64 = 1u64 << 3;
pub const GENESIS_FEATURE_MINT_CANDIDATE_MINER_PUBKEY_V1: u64 = 1u64 << 4;
pub const GENESIS_FEATURE_MINT_CANDIDATE_RECIPIENT_LOCK_V1: u64 = 1u64 << 5;
pub const GENESIS_FEATURE_MINT_FORCED_INCLUSION_V2: u64 = 1u64 << 6;
pub const GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1: u64 = 1u64 << 7;
pub const GENESIS_FEATURE_MINT_WINDOW_V2: u64 = 1u64 << 8;

// Mint candidate optional-field feature bits (consensus-checked).
pub const MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V1: u64 = 1u64 << 0;
pub const MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V1: u64 = 1u64 << 1;
pub const MINT_CANDIDATE_FEATURE_WORK_ID_V1: u64 = 1u64 << 2;
pub const MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V2: u64 = 1u64 << 0;
pub const MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V2: u64 = 1u64 << 1;

#[inline]
pub fn mint_candidate_feature_bits_v1_from_genesis_features(genesis_features: u64) -> u64 {
    let mut bits = 0u64;
    if (genesis_features & GENESIS_FEATURE_MINT_CANDIDATE_MINER_PUBKEY_V1) != 0 {
        bits |= MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V1;
    }
    if (genesis_features & GENESIS_FEATURE_MINT_CANDIDATE_RECIPIENT_LOCK_V1) != 0 {
        bits |= MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V1;
    }
    if (genesis_features & GENESIS_FEATURE_MINT_CANDIDATE_WORK_ID_V1) != 0 {
        bits |= MINT_CANDIDATE_FEATURE_WORK_ID_V1;
    }
    bits
}

#[inline]
pub fn mint_candidate_feature_bits_v2_from_genesis_features(genesis_features: u64) -> u64 {
    let mut bits = 0u64;
    if (genesis_features & GENESIS_FEATURE_MINT_WINDOW_V2) != 0 {
        bits |= MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V2;
        bits |= MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V2;
    }
    bits
}

// Strictly domain-separated mint/candidate hashes (ASCII bytes, no normalization).
pub const MINT_COMMITMENT_DOMAIN_V1: &[u8] = b"PHANTOM:MINT:COMMIT:v1";
pub const MINT_CANDIDATE_DOMAIN_V1: &[u8] = b"PHANTOM:MINT:CANDIDATE:v1";
pub const MINT_POW_DOMAIN_V1: &[u8] = b"PHANTOM:MINT:POW:v1";
pub const MINT_CANDROOT_DOMAIN_V1: &[u8] = b"PHANTOM:MINT:CANDROOT:v1";
pub const MINT_POW_CERT_DOMAIN_V1: &[u8] = b"PHANTOM:MINT:POWCERT:v1";
pub const MINT_SLOT_DOMAIN_V2: &[u8] = b"PHANTOM:MINT:SLOT:v2";
pub const MINT_SUBMISSION_DOMAIN_V2: &[u8] = b"PHANTOM:MINT:SUBMIT:v2";
pub const MINT_POW_CERT_DOMAIN_V2: &[u8] = b"PHANTOM:MINT:POWCERT:v2";

// Hard cap to keep genesis note bounded.
// Harter Cap, damit die Genesis-Note klein bleibt.
pub const MAX_GENESIS_VALIDATORS: usize = 256;

/// Genesis validators list entry (version=1).
/// Genesis-Validatoren Listen-Eintrag (Version=1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisValidatorV1 {
    pub operator_id: [u8; 32],
    pub bls_pk: [u8; 48],
    pub bls_pop: [u8; 96],
}

impl Encodable for GenesisValidatorV1 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.operator_id.encode(w)?;
        w.write_all(&self.bls_pk).map_err(CodecError::Io)?;
        w.write_all(&self.bls_pop).map_err(CodecError::Io)?;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        32 + 48 + 96
    }
}

impl Decodable for GenesisValidatorV1 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let operator_id = <[u8; 32]>::decode(r)?;
        let mut bls_pk = [0u8; 48];
        r.read_exact(&mut bls_pk)?;
        let mut bls_pop = [0u8; 96];
        r.read_exact(&mut bls_pop)?;
        Ok(Self {
            operator_id,
            bls_pk,
            bls_pop,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisParams {
    pub shards_initial: u16,
    pub committee_k: u8,
    pub txs_per_payload: u16,
    pub features: u64,
}
impl Encodable for GenesisParams {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.shards_initial.encode(w)?;
        self.committee_k.encode(w)?;
        self.txs_per_payload.encode(w)?;
        self.features.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.shards_initial.encoded_len()
            + self.committee_k.encoded_len()
            + self.txs_per_payload.encoded_len()
            + self.features.encoded_len()
    }
}
impl Decodable for GenesisParams {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            shards_initial: u16::decode(r)?,
            committee_k: u8::decode(r)?,
            txs_per_payload: u16::decode(r)?,
            features: u64::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisNote {
    pub version: u8, // 0x00 (v1), 0x01 (v2 w/ genesis validators), 0x02 (v3 + genesis message), 0x03 (v4 + emission bootstrap bucket / current)
    pub network_name: Vec<u8>, // UTF-8, <=32 bytes recommended. UTF-8, <=32 Bytes empfohlen.
    pub seed: [u8; 32],
    pub params: GenesisParams,
    // Only present for `version >= 1`.
    pub genesis_validators: Vec<GenesisValidatorV1>,
    // Only present for `version >= 2`.
    // Arbitrary byte message (e.g. genesis inscription), bounded by MAX_GENESIS_MESSAGE_BYTES.
    pub genesis_message: Vec<u8>,
    // Only present for `version >= 3`.
    // Consensus-committed emission bootstrap bucket for first-round ASERT difficulty.
    pub emission_bootstrap_bucket: u64,
}
impl Encodable for GenesisNote {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        if self.version > 3 {
            return Err(CodecError::InvalidTag(self.version));
        }
        if self.network_name.len() > MAX_GENESIS_NETWORK_NAME_BYTES {
            return Err(CodecError::InvalidLength(self.network_name.len()));
        }
        if self.genesis_message.len() > MAX_GENESIS_MESSAGE_BYTES {
            return Err(CodecError::InvalidLength(self.genesis_message.len()));
        }
        if self.version == 0
            && (!self.genesis_validators.is_empty() || !self.genesis_message.is_empty())
        {
            return Err(CodecError::InvalidLength(self.genesis_validators.len()));
        }
        if self.version == 1 && !self.genesis_message.is_empty() {
            return Err(CodecError::InvalidLength(self.genesis_message.len()));
        }
        if self.version < 3 && self.emission_bootstrap_bucket != 0 {
            return Err(CodecError::InvalidLength(
                self.emission_bootstrap_bucket as usize,
            ));
        }
        self.version.encode(w)?;
        self.network_name.encode(w)?; // Vec<u8>
        self.seed.encode(w)?;
        self.params.encode(w)?;
        if self.version >= 1 {
            self.genesis_validators.encode(w)?;
        }
        if self.version >= 2 {
            self.genesis_message.encode(w)?;
        }
        if self.version >= 3 {
            self.emission_bootstrap_bucket.encode(w)?;
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        let mut n = self.version.encoded_len()
            + self.network_name.encoded_len()
            + 32
            + self.params.encoded_len();
        if self.version >= 1 {
            n += self.genesis_validators.encoded_len();
        }
        if self.version >= 2 {
            n += self.genesis_message.encoded_len();
        }
        if self.version >= 3 {
            n += self.emission_bootstrap_bucket.encoded_len();
        }
        n
    }
}
impl Decodable for GenesisNote {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        if version > 3 {
            return Err(CodecError::InvalidTag(version));
        }
        let network_name = decode_bounded_bytes(r, MAX_GENESIS_NETWORK_NAME_BYTES)?;
        let seed = <[u8; 32]>::decode(r)?;
        let params = GenesisParams::decode(r)?;

        // Optional genesis validators (version >= 1).
        let genesis_validators = if version >= 1 {
            // Bounded decode (defense-in-depth).
            let n = pc_codec::read_varu64(r)? as usize;
            if n > MAX_GENESIS_VALIDATORS {
                return Err(CodecError::InvalidLength(n));
            }
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(GenesisValidatorV1::decode(r)?);
            }
            out
        } else {
            Vec::new()
        };
        let genesis_message = if version >= 2 {
            decode_bounded_bytes(r, MAX_GENESIS_MESSAGE_BYTES)?
        } else {
            Vec::new()
        };
        let emission_bootstrap_bucket = if version >= 3 { u64::decode(r)? } else { 0 };

        Ok(Self {
            version,
            network_name,
            seed,
            params,
            genesis_validators,
            genesis_message,
            emission_bootstrap_bucket,
        })
    }
}

pub fn digest_genesis_note(note: &GenesisNote) -> Hash32 {
    let mut enc = Vec::with_capacity(note.encoded_len());
    let _ = note.encode(&mut enc);
    digest_with_domain(GENESIS_NOTE_V1, &enc)
}
impl Decodable for AnchorId {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self(<[u8; 32]>::decode(r)?))
    }
}

pub fn digest_microtx(tx: &MicroTx) -> Hash32 {
    let mut enc = Vec::with_capacity(tx.encoded_len());
    let _ = tx.encode(&mut enc);
    digest_with_domain(LEAF_MICROTX, &enc)
}
pub fn digest_mint(m: &MintEvent) -> Hash32 {
    let mut enc = Vec::with_capacity(m.encoded_len());
    let _ = m.encode(&mut enc);
    digest_with_domain(LEAF_MINT, &enc)
}
pub fn digest_claim(c: &ClaimEvent) -> Hash32 {
    let mut enc = Vec::with_capacity(c.encoded_len());
    let _ = c.encode(&mut enc);
    digest_with_domain(LEAF_CLAIM, &enc)
}
pub fn digest_evidence(e: &EvidenceEvent) -> Hash32 {
    let mut enc = Vec::with_capacity(e.encoded_len());
    let _ = e.encode(&mut enc);
    digest_with_domain(LEAF_EVID, &enc)
}

/// Deterministic slash id for BFT equivocation evidence.
///
/// The id is reporter-independent (prevents multi-claiming) and symmetric in (a,b).
#[allow(clippy::too_many_arguments)]
pub fn slash_id_equivocation_bft_v1(
    network_id: &NetworkId,
    seed_anchor: &[u8; 32],
    epoch: u64,
    shard_id: u16,
    round: u64,
    offender_id: &[u8; 32],
    vote_target_a: &[u8; 32],
    vote_target_b: &[u8; 32],
) -> Hash32 {
    let (lo, hi) = if vote_target_a <= vote_target_b {
        (vote_target_a, vote_target_b)
    } else {
        (vote_target_b, vote_target_a)
    };
    let mut buf =
        Vec::with_capacity(SLASH_ID_EQUIVOCATION_BFT_V1.len() + 32 + 32 + 8 + 2 + 8 + 32 + 32 + 32);
    buf.extend_from_slice(SLASH_ID_EQUIVOCATION_BFT_V1);
    buf.extend_from_slice(network_id);
    buf.extend_from_slice(seed_anchor);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&shard_id.to_le_bytes());
    buf.extend_from_slice(&round.to_le_bytes());
    buf.extend_from_slice(offender_id);
    buf.extend_from_slice(lo);
    buf.extend_from_slice(hi);
    blake3_32(&buf)
}

/// Message hash that the reporter signs to bind the slashing reward to their lock.
pub fn reporter_slash_claim_sighash_v1(network_id: &NetworkId, slash_id: &[u8; 32]) -> Hash32 {
    let mut buf = Vec::with_capacity(SLASH_REPORTER_CLAIM_SIGHASH_V1.len() + 32 + 32);
    buf.extend_from_slice(SLASH_REPORTER_CLAIM_SIGHASH_V1);
    buf.extend_from_slice(network_id);
    buf.extend_from_slice(slash_id);
    blake3_32(&buf)
}

pub fn digest_payout_root(root: &Hash32) -> Hash32 {
    let mut data = Vec::with_capacity(LEAF_PAYOUT_ROOT.len() + 32);
    data.extend_from_slice(LEAF_PAYOUT_ROOT);
    data.extend_from_slice(root);
    blake3_32(&data)
}

pub fn digest_null_mint_decision(null_mint: bool) -> Hash32 {
    let mut data = Vec::with_capacity(LEAF_NULL_MINT.len() + 1);
    data.extend_from_slice(LEAF_NULL_MINT);
    data.push(if null_mint { 1 } else { 0 });
    blake3_32(&data)
}

pub fn lock_commitment_schnorr_xonly_v1(pub_xonly: &[u8; 32]) -> LockCommitment {
    LockCommitment(*pub_xonly)
}

pub fn sighash_microtx_v1(network_id: &NetworkId, tx: &MicroTx) -> Hash32 {
    const SIGHASH_DOMAIN_V1: &[u8] = b"pc:tx:sighash:v1\x01";
    let mut txc = tx.clone();
    for tin in &mut txc.inputs {
        tin.witness.clear();
    }
    let mut buf = Vec::with_capacity(SIGHASH_DOMAIN_V1.len() + 32 + txc.encoded_len());
    buf.extend_from_slice(SIGHASH_DOMAIN_V1);
    buf.extend_from_slice(network_id);
    let _ = txc.encode(&mut buf);
    blake3_32(&buf)
}

/// Computes the payload Merkle root deterministically (order-dependent within the categories).
/// Berechne den Payload‑Merkle‑Root deterministisch (ordnungsabhängig innerhalb der Kategorien).
pub fn payload_merkle_root(payload: &AnchorPayload) -> Hash32 {
    let mut leaves: Vec<Hash32> = Vec::new();
    for tx in &payload.micro_txs {
        leaves.push(digest_microtx(tx));
    }
    for m in &payload.mints {
        leaves.push(digest_mint(m));
    }
    for c in &payload.claims {
        leaves.push(digest_claim(c));
    }
    for e in &payload.evidences {
        leaves.push(digest_evidence(e));
    }
    leaves.push(digest_payout_root(&payload.payout_root));
    merkle_root_hashes(&leaves)
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AnchorPayload {
    pub version: u8,
    pub micro_txs: Vec<MicroTx>,
    pub mints: Vec<MintEvent>,
    pub claims: Vec<ClaimEvent>,
    pub evidences: Vec<EvidenceEvent>,
    pub payout_root: Hash32,
}
impl Encodable for AnchorPayload {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.micro_txs.encode(w)?;
        self.mints.encode(w)?;
        self.claims.encode(w)?;
        self.evidences.encode(w)?;
        self.payout_root.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.micro_txs.encoded_len()
            + self.mints.encoded_len()
            + self.claims.encoded_len()
            + self.evidences.encoded_len()
            + self.payout_root.encoded_len()
    }
}
impl Decodable for AnchorPayload {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        // Bounded decode for all Vec fields (P1-2 hardening).
        // Gebundener Decode für alle Vec-Felder (P1-2 Härtung).
        let micro_txs = decode_bounded_vec::<MicroTx, _>(r, MAX_PAYLOAD_MICROTX)?;
        let mints = decode_bounded_vec::<MintEvent, _>(r, MAX_PAYLOAD_MINTS)?;
        let claims = decode_bounded_vec::<ClaimEvent, _>(r, MAX_PAYLOAD_CLAIMS)?;
        let evidences = decode_bounded_vec::<EvidenceEvent, _>(r, MAX_PAYLOAD_EVIDENCES)?;
        let payout_root = <[u8; 32]>::decode(r)?;
        Ok(Self {
            version,
            micro_txs,
            mints,
            claims,
            evidences,
            payout_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentList {
    pub len: u8,
    pub ids: [AnchorId; MAX_PARENTS],
}
impl Default for ParentList {
    fn default() -> Self {
        Self {
            len: 0,
            ids: [AnchorId([0u8; 32]); MAX_PARENTS],
        }
    }
}
impl ParentList {
    pub fn push(&mut self, id: AnchorId) -> Result<(), CodecError> {
        if (self.len as usize) >= MAX_PARENTS {
            return Err(CodecError::InvalidLength(self.len as usize));
        }
        let idx = self.len as usize;
        if let Some(slot) = self.ids.get_mut(idx) {
            *slot = id;
            self.len = self.len.saturating_add(1);
            Ok(())
        } else {
            Err(CodecError::InvalidLength(idx))
        }
    }
}

// ============================
// Payout-Commitment (Merkle)
// ============================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutEntry {
    pub recipient_id: [u8; 32],
    pub amount: Amount,
}
impl Encodable for PayoutEntry {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.recipient_id.encode(w)?;
        self.amount.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        32 + self.amount.encoded_len()
    }
}
impl Decodable for PayoutEntry {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            recipient_id: <[u8; 32]>::decode(r)?,
            amount: u64::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PayoutSet {
    pub entries: Vec<PayoutEntry>,
}

impl PayoutSet {
    /// Returns a normalized, deterministically sorted list: ascending by `recipient_id`, with duplicates merged (summed).
    /// Liefert eine normalisierte, deterministisch sortierte Liste: nach recipient_id aufsteigend, Duplikate zusammengefasst (summiert).
    pub fn normalized_entries(&self) -> Vec<PayoutEntry> {
        let mut v = self.entries.clone();
        // Sort by recipient_id (ascending).
        // sortiere nach recipient_id.
        v.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
        // Merge entries with the same recipient.
        // merge gleiche Empfänger.
        let mut merged: Vec<PayoutEntry> = Vec::with_capacity(v.len());
        for e in v.into_iter() {
            if let Some(last) = merged.last_mut() {
                if last.recipient_id == e.recipient_id {
                    // Sum with overflow protection.
                    // Summe mit Overflow‑Schutz.
                    let (sum, of) = last.amount.overflowing_add(e.amount);
                    if !of {
                        last.amount = sum;
                    } else {
                        // On overflow: saturate (a more production-ready variant would return an error).
                        // Bei Overflow: saturieren (produktionsreifere Variante wäre ein Fehler).
                        last.amount = u64::MAX;
                    }
                    continue;
                }
            }
            merged.push(e);
        }
        merged
    }

    /// Merkle root over payout leaves (with domain separation). Empty set → 0x00..00.
    /// Merkle‑Root über payout leaves (domain‑getrennt). Leere Menge → 0x00..00.
    pub fn payout_root(&self) -> Hash32 {
        let norm = self.normalized_entries();
        let leaves: Vec<Hash32> = norm
            .iter()
            .map(|e| payout_leaf_hash(&e.recipient_id, e.amount))
            .collect();
        merkle_root_hashes(&leaves)
    }
}

impl Encodable for PayoutSet {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.entries.encode(w)
    }
    fn encoded_len(&self) -> usize {
        self.entries.encoded_len()
    }
}
impl Decodable for PayoutSet {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        // Bounded decode for entries (P1-2 hardening).
        // Gebundener Decode für entries (P1-2 Härtung).
        let entries = decode_bounded_vec::<PayoutEntry, _>(r, MAX_PAYOUT_ENTRIES)?;
        Ok(Self { entries })
    }
}
impl Encodable for ParentList {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.len.encode(w)?;
        for it in self.ids.iter().take(self.len as usize) {
            it.encode(w)?;
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        1 + (self.len as usize) * 32
    }
}
impl Decodable for ParentList {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let len = u8::decode(r)?;
        if (len as usize) > MAX_PARENTS {
            return Err(CodecError::InvalidLength(len as usize));
        }
        let mut ids = [AnchorId([0u8; 32]); MAX_PARENTS];
        let mut i = 0usize;
        while i < (len as usize) {
            if let Some(slot) = ids.get_mut(i) {
                *slot = AnchorId::decode(r)?;
            } else {
                return Err(CodecError::InvalidLength(i));
            }
            i += 1;
        }
        Ok(Self { len, ids })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorHeader {
    pub version: u8,
    pub shard_id: u16,
    pub parents: ParentList,
    pub payload_hash: Hash32,
    pub creator_index: u8, // 0..k-1
    pub vote_mask: u64,    // u64 bitset (k<=64)
    pub ack_present: bool,
    pub ack_id: AnchorId, // only valid if ack_present
}

impl Default for AnchorHeader {
    fn default() -> Self {
        Self {
            version: 1,
            shard_id: 0,
            parents: ParentList::default(),
            payload_hash: [0u8; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
        }
    }
}

impl Encodable for AnchorHeader {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.shard_id.encode(w)?;
        self.parents.encode(w)?;
        self.payload_hash.encode(w)?;
        self.creator_index.encode(w)?;
        self.vote_mask.encode(w)?;
        self.ack_present.encode(w)?;
        if self.ack_present {
            self.ack_id.encode(w)?;
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        n += self.version.encoded_len();
        n += self.shard_id.encoded_len();
        n += self.parents.encoded_len();
        n += self.payload_hash.encoded_len();
        n += self.creator_index.encoded_len();
        n += self.vote_mask.encoded_len();
        n += self.ack_present.encoded_len();
        if self.ack_present {
            n += self.ack_id.encoded_len();
        }
        n
    }
}
impl Decodable for AnchorHeader {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        let shard_id = u16::decode(r)?;
        let parents = ParentList::decode(r)?;
        let payload_hash = <[u8; 32]>::decode(r)?;
        let creator_index = u8::decode(r)?;
        let vote_mask = u64::decode(r)?;
        let ack_present = bool::decode(r)?;
        let ack_id = if ack_present {
            AnchorId::decode(r)?
        } else {
            AnchorId([0u8; 32])
        };
        Ok(Self {
            version,
            shard_id,
            parents,
            payload_hash,
            creator_index,
            vote_mask,
            ack_present,
            ack_id,
        })
    }
}

impl AnchorHeader {
    pub fn id_digest(&self) -> Hash32 {
        let mut buf = Vec::with_capacity(self.encoded_len());
        // Encode deterministically; writing into a Vec<u8> cannot fail.
        // encode deterministisch; Schreiben in Vec<u8> kann nicht fehlschlagen.
        // We avoid unwrap/expect according to policy and guard in debug builds.
        // Wir vermeiden unwrap/expect gemäß Policy und sichern in Debug-Builds ab.
        if let Err(_e) = self.encode(&mut buf) {
            debug_assert!(false, "encode to Vec<u8> should not fail");
        }
        blake3_32(&buf)
    }
}

// ============================
// UTXO / TX / EVENTS
// ============================

pub type Amount = u64; // Smallest unit (e.g. 1e-8 PC). kleinste Einheit (z. B. 1e-8 PC).
/// Global, monotonic anchor index (clock-free). Used, among other things, for maturity levels.
/// Globaler, monotoner Anchor-Index (uhrfrei). Dient u. a. für Maturity-Stufen.
pub type AnchorIndex = u64;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub struct OutPoint {
    pub txid: Hash32,
    pub vout: u32,
}
impl Encodable for OutPoint {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.txid.encode(w)?;
        self.vout.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        32 + 4
    }
}
impl Decodable for OutPoint {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            txid: <[u8; 32]>::decode(r)?,
            vout: u32::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prev_out: OutPoint,
    pub witness: Vec<u8>,
}
impl Encodable for TxIn {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.prev_out.encode(w)?;
        self.witness.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.prev_out.encoded_len() + self.witness.encoded_len()
    }
}
impl Decodable for TxIn {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let prev_out = OutPoint::decode(r)?;
        // Bounded decode for witness (P1-2 hardening).
        // Gebundener Decode für witness (P1-2 Härtung).
        let witness = decode_bounded_bytes(r, MAX_WITNESS_BYTES)?;
        Ok(Self { prev_out, witness })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LockCommitment(pub [u8; 32]); // 32‑Byte Commitment auf Script/Key/Policy
impl Encodable for LockCommitment {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.0.encode(w)
    }
    fn encoded_len(&self) -> usize {
        32
    }
}
impl Decodable for LockCommitment {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self(<[u8; 32]>::decode(r)?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub amount: Amount,
    pub lock: LockCommitment,
}
impl Encodable for TxOut {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.amount.encode(w)?;
        self.lock.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.amount.encoded_len() + self.lock.encoded_len()
    }
}
impl Decodable for TxOut {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            amount: u64::decode(r)?,
            lock: LockCommitment::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MicroTx {
    pub version: u8,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}
impl Encodable for MicroTx {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.inputs.encode(w)?;
        self.outputs.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.version.encoded_len() + self.inputs.encoded_len() + self.outputs.encoded_len()
    }
}
impl Decodable for MicroTx {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        // Bounded decode for inputs (P1-2 hardening).
        // Gebundener Decode für inputs (P1-2 Härtung).
        let inputs_len = pc_codec::read_varu64(r)? as usize;
        if inputs_len > MAX_TX_INPUTS {
            return Err(CodecError::InvalidLength(inputs_len));
        }
        let mut inputs = Vec::with_capacity(inputs_len);
        for _ in 0..inputs_len {
            inputs.push(TxIn::decode(r)?);
        }
        // Bounded decode for outputs (P1-2 hardening).
        // Gebundener Decode für outputs (P1-2 Härtung).
        let outputs_len = pc_codec::read_varu64(r)? as usize;
        if outputs_len > MAX_TX_OUTPUTS {
            return Err(CodecError::InvalidLength(outputs_len));
        }
        let mut outputs = Vec::with_capacity(outputs_len);
        for _ in 0..outputs_len {
            outputs.push(TxOut::decode(r)?);
        }
        Ok(Self {
            version,
            inputs,
            outputs,
        })
    }
}

/// Deterministic shard assignment for a transaction.
///
/// The shard is derived from the first input's `OutPoint` using a domain-separated
/// BLAKE3 hash. This ensures a UTXO can never appear in two different shards.
/// Transactions without inputs (coinbase-like) are assigned to shard 0.
pub fn shard_for_tx(tx: &MicroTx, num_shards: u16) -> u16 {
    if num_shards <= 1 {
        return 0;
    }
    let Some(first_in) = tx.inputs.first() else {
        return 0;
    };
    const DOMAIN: &[u8] = b"pc:shard_assign:v1\0";
    let mut buf = Vec::with_capacity(DOMAIN.len() + 32 + 4);
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(&first_in.prev_out.txid);
    buf.extend_from_slice(&first_in.prev_out.vout.to_le_bytes());
    let hash = blake3_32(&buf);
    u16::from_le_bytes([hash[0], hash[1]]) % num_shards
}

/// On-chain validator registry record (stored in state DB).
/// On-Chain Validator-Registry Eintrag (im State-DB gespeichert).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRecordV1 {
    pub version: u8,
    pub stake_lock: LockCommitment,
    pub sequence: u64,
    pub operator_id: [u8; 32],
    pub bls_pk: [u8; 48],
    pub bls_pop: [u8; 96],
}

impl Encodable for ValidatorRecordV1 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.stake_lock.encode(w)?;
        self.sequence.encode(w)?;
        self.operator_id.encode(w)?;
        w.write_all(&self.bls_pk).map_err(CodecError::Io)?;
        w.write_all(&self.bls_pop).map_err(CodecError::Io)?;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.stake_lock.encoded_len()
            + self.sequence.encoded_len()
            + 32
            + 48
            + 96
    }
}

impl Decodable for ValidatorRecordV1 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        let stake_lock = LockCommitment::decode(r)?;
        let sequence = u64::decode(r)?;
        let operator_id = <[u8; 32]>::decode(r)?;
        let mut bls_pk = [0u8; 48];
        r.read_exact(&mut bls_pk)?;
        let mut bls_pop = [0u8; 96];
        r.read_exact(&mut bls_pop)?;
        Ok(Self {
            version,
            stake_lock,
            sequence,
            operator_id,
            bls_pk,
            bls_pop,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintEvent {
    pub version: u8,
    pub prev_mint_id: Hash32,
    pub outputs: Vec<TxOut>,
    pub pow_seed: Hash32,
    pub pow_nonce: u64,
    pub minted_at: AnchorIndex, // Global anchor index at the time of the mint (for maturity). Globaler Anchor-Index zum Zeitpunkt des Mints (für Maturity).
    pub round_id: Hash32,
    pub hit_bucket: u64,
    pub bits_used: u8,
}
impl Encodable for MintEvent {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        if self.version != MINT_VERSION_V1 && self.version != MINT_VERSION_V2 {
            return Err(CodecError::InvalidTag(self.version));
        }
        self.version.encode(w)?;
        self.prev_mint_id.encode(w)?;
        self.outputs.encode(w)?;
        self.pow_seed.encode(w)?;
        self.pow_nonce.encode(w)?;
        self.minted_at.encode(w)?;
        if self.version >= MINT_VERSION_V2 {
            self.round_id.encode(w)?;
            self.hit_bucket.encode(w)?;
            self.bits_used.encode(w)?;
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        let mut n = self.version.encoded_len()
            + 32
            + self.outputs.encoded_len()
            + 32
            + self.pow_nonce.encoded_len()
            + self.minted_at.encoded_len();
        if self.version >= MINT_VERSION_V2 {
            n += self.round_id.encoded_len();
            n += self.hit_bucket.encoded_len();
            n += self.bits_used.encoded_len();
        }
        n
    }
}
impl Decodable for MintEvent {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        if version != MINT_VERSION_V1 && version != MINT_VERSION_V2 {
            return Err(CodecError::InvalidTag(version));
        }
        let prev_mint_id = <[u8; 32]>::decode(r)?;
        // Bounded decode for outputs (P1-2 hardening).
        // Gebundener Decode für outputs (P1-2 Härtung).
        let outputs_len = pc_codec::read_varu64(r)? as usize;
        if outputs_len > MAX_MINT_OUTPUTS {
            return Err(CodecError::InvalidLength(outputs_len));
        }
        let mut outputs = Vec::with_capacity(outputs_len);
        for _ in 0..outputs_len {
            outputs.push(TxOut::decode(r)?);
        }
        let pow_seed = <[u8; 32]>::decode(r)?;
        let pow_nonce = u64::decode(r)?;
        let minted_at = AnchorIndex::decode(r)?;
        let (round_id, hit_bucket, bits_used) = if version >= MINT_VERSION_V2 {
            (<[u8; 32]>::decode(r)?, u64::decode(r)?, u8::decode(r)?)
        } else {
            ([0u8; 32], 0, 0)
        };
        Ok(Self {
            version,
            prev_mint_id,
            outputs,
            pow_seed,
            pow_nonce,
            minted_at,
            round_id,
            hit_bucket,
            bits_used,
        })
    }
}

impl MintEvent {
    #[inline]
    pub fn uses_emission_rounds(&self) -> bool {
        self.version >= MINT_VERSION_V2
    }
}

/// Canonical MintCandidate consensus object used by censorship-proof windows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintCandidateEvent {
    pub version: u8,
    pub network_id: Hash32,
    pub prev_mint_id: Hash32,
    pub window_id: u64,
    pub window_open_anchor_id: Hash32,
    pub mint_commitment: Hash32,
    pub nonce: u64,
    // Optional fields are encoded at fixed positions via canonical presence bits.
    pub work_id: Option<Hash32>,
    pub miner_pubkey: Option<[u8; 32]>,
    pub recipient_lock: Option<LockCommitment>,
}

/// Forced-inclusion PoW certificate (v2 extension).
///
/// This object carries the canonical PoW binding fields and is imported into the
/// same candidate window pipeline as `MintCandidateEvent` once finalized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintPoWCertV1 {
    pub version: u8,
    pub network_id: Hash32,
    pub prev_mint_id: Hash32,
    pub window_id: u64,
    pub window_open_anchor_id: Hash32,
    pub mint_commitment: Hash32,
    pub nonce: u64,
    pub work_id: Option<Hash32>,
}

impl Encodable for MintPoWCertV1 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        if self.version != 1 {
            return Err(CodecError::InvalidTag(self.version));
        }
        self.version.encode(w)?;
        self.network_id.encode(w)?;
        self.prev_mint_id.encode(w)?;
        self.window_id.encode(w)?;
        self.window_open_anchor_id.encode(w)?;
        self.mint_commitment.encode(w)?;
        self.nonce.encode(w)?;
        self.work_id.is_some().encode(w)?;
        if let Some(work_id) = self.work_id {
            work_id.encode(w)?;
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.network_id.encoded_len()
            + self.prev_mint_id.encoded_len()
            + self.window_id.encoded_len()
            + self.window_open_anchor_id.encoded_len()
            + self.mint_commitment.encoded_len()
            + self.nonce.encoded_len()
            + bool::default().encoded_len()
            + if self.work_id.is_some() { 32 } else { 0 }
    }
}

impl Decodable for MintPoWCertV1 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        if version != 1 {
            return Err(CodecError::InvalidTag(version));
        }
        Ok(Self {
            version,
            network_id: <[u8; 32]>::decode(r)?,
            prev_mint_id: <[u8; 32]>::decode(r)?,
            window_id: u64::decode(r)?,
            window_open_anchor_id: <[u8; 32]>::decode(r)?,
            mint_commitment: <[u8; 32]>::decode(r)?,
            nonce: u64::decode(r)?,
            work_id: if bool::decode(r)? {
                Some(<[u8; 32]>::decode(r)?)
            } else {
                None
            },
        })
    }
}

impl Encodable for MintCandidateEvent {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        if self.version != 1 {
            return Err(CodecError::InvalidTag(self.version));
        }
        self.version.encode(w)?;
        self.network_id.encode(w)?;
        self.prev_mint_id.encode(w)?;
        self.window_id.encode(w)?;
        self.window_open_anchor_id.encode(w)?;
        self.mint_commitment.encode(w)?;
        self.nonce.encode(w)?;
        self.work_id.is_some().encode(w)?;
        if let Some(work_id) = self.work_id {
            work_id.encode(w)?;
        }
        self.miner_pubkey.is_some().encode(w)?;
        if let Some(pk) = self.miner_pubkey {
            w.write_all(&pk).map_err(CodecError::Io)?;
        }
        self.recipient_lock.is_some().encode(w)?;
        if let Some(lock) = self.recipient_lock {
            lock.encode(w)?;
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        n += self.version.encoded_len();
        n += self.network_id.encoded_len();
        n += self.prev_mint_id.encoded_len();
        n += self.window_id.encoded_len();
        n += self.window_open_anchor_id.encoded_len();
        n += self.mint_commitment.encoded_len();
        n += self.nonce.encoded_len();
        n += bool::default().encoded_len();
        if self.work_id.is_some() {
            n += 32;
        }
        n += bool::default().encoded_len();
        if self.miner_pubkey.is_some() {
            n += 32;
        }
        n += bool::default().encoded_len();
        if self.recipient_lock.is_some() {
            n += LockCommitment([0u8; 32]).encoded_len();
        }
        n
    }
}

impl Decodable for MintCandidateEvent {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        if version != 1 {
            return Err(CodecError::InvalidTag(version));
        }
        let network_id = <[u8; 32]>::decode(r)?;
        let prev_mint_id = <[u8; 32]>::decode(r)?;
        let window_id = u64::decode(r)?;
        let window_open_anchor_id = <[u8; 32]>::decode(r)?;
        let mint_commitment = <[u8; 32]>::decode(r)?;
        let nonce = u64::decode(r)?;
        let work_id = if bool::decode(r)? {
            Some(<[u8; 32]>::decode(r)?)
        } else {
            None
        };

        let has_miner_pubkey = bool::decode(r)?;
        let miner_pubkey = if has_miner_pubkey {
            let mut pk = [0u8; 32];
            r.read_exact(&mut pk)?;
            Some(pk)
        } else {
            None
        };

        let has_recipient_lock = bool::decode(r)?;
        let recipient_lock = if has_recipient_lock {
            Some(LockCommitment::decode(r)?)
        } else {
            None
        };

        Ok(Self {
            version,
            network_id,
            prev_mint_id,
            window_id,
            window_open_anchor_id,
            mint_commitment,
            nonce,
            work_id,
            miner_pubkey,
            recipient_lock,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintCandidateEventV2 {
    pub version: u8,
    pub network_id: Hash32,
    pub prev_mint_id: Hash32,
    pub window_id: u64,
    pub window_open_anchor_id: Hash32,
    pub mint_commitment: Hash32,
    pub nonce: u64,
    pub miner_pubkey: Option<[u8; 32]>,
    pub recipient_lock: Option<LockCommitment>,
}

impl Encodable for MintCandidateEventV2 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        if self.version != 2 {
            return Err(CodecError::InvalidTag(self.version));
        }
        self.version.encode(w)?;
        self.network_id.encode(w)?;
        self.prev_mint_id.encode(w)?;
        self.window_id.encode(w)?;
        self.window_open_anchor_id.encode(w)?;
        self.mint_commitment.encode(w)?;
        self.nonce.encode(w)?;
        self.miner_pubkey.is_some().encode(w)?;
        if let Some(pk) = self.miner_pubkey {
            w.write_all(&pk).map_err(CodecError::Io)?;
        }
        self.recipient_lock.is_some().encode(w)?;
        if let Some(lock) = self.recipient_lock {
            lock.encode(w)?;
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        n += self.version.encoded_len();
        n += self.network_id.encoded_len();
        n += self.prev_mint_id.encoded_len();
        n += self.window_id.encoded_len();
        n += self.window_open_anchor_id.encoded_len();
        n += self.mint_commitment.encoded_len();
        n += self.nonce.encoded_len();
        n += bool::default().encoded_len();
        if self.miner_pubkey.is_some() {
            n += 32;
        }
        n += bool::default().encoded_len();
        if self.recipient_lock.is_some() {
            n += LockCommitment([0u8; 32]).encoded_len();
        }
        n
    }
}

impl Decodable for MintCandidateEventV2 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        if version != 2 {
            return Err(CodecError::InvalidTag(version));
        }
        let network_id = <[u8; 32]>::decode(r)?;
        let prev_mint_id = <[u8; 32]>::decode(r)?;
        let window_id = u64::decode(r)?;
        let window_open_anchor_id = <[u8; 32]>::decode(r)?;
        let mint_commitment = <[u8; 32]>::decode(r)?;
        let nonce = u64::decode(r)?;
        let miner_pubkey = if bool::decode(r)? {
            let mut pk = [0u8; 32];
            r.read_exact(&mut pk)?;
            Some(pk)
        } else {
            None
        };
        let recipient_lock = if bool::decode(r)? {
            Some(LockCommitment::decode(r)?)
        } else {
            None
        };
        Ok(Self {
            version,
            network_id,
            prev_mint_id,
            window_id,
            window_open_anchor_id,
            mint_commitment,
            nonce,
            miner_pubkey,
            recipient_lock,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintPoWCertV2 {
    pub version: u8,
    pub network_id: Hash32,
    pub prev_mint_id: Hash32,
    pub window_id: u64,
    pub window_open_anchor_id: Hash32,
    pub mint_commitment: Hash32,
    pub nonce: u64,
}

impl Encodable for MintPoWCertV2 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        if self.version != 2 {
            return Err(CodecError::InvalidTag(self.version));
        }
        self.version.encode(w)?;
        self.network_id.encode(w)?;
        self.prev_mint_id.encode(w)?;
        self.window_id.encode(w)?;
        self.window_open_anchor_id.encode(w)?;
        self.mint_commitment.encode(w)?;
        self.nonce.encode(w)?;
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.network_id.encoded_len()
            + self.prev_mint_id.encoded_len()
            + self.window_id.encoded_len()
            + self.window_open_anchor_id.encoded_len()
            + self.mint_commitment.encoded_len()
            + self.nonce.encoded_len()
    }
}

impl Decodable for MintPoWCertV2 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        if version != 2 {
            return Err(CodecError::InvalidTag(version));
        }
        Ok(Self {
            version,
            network_id: <[u8; 32]>::decode(r)?,
            prev_mint_id: <[u8; 32]>::decode(r)?,
            window_id: u64::decode(r)?,
            window_open_anchor_id: <[u8; 32]>::decode(r)?,
            mint_commitment: <[u8; 32]>::decode(r)?,
            nonce: u64::decode(r)?,
        })
    }
}

/// Canonical bytes used for mint commitment/mint id hashing.
pub fn canonical_mint_bytes_v1(m: &MintEvent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(m.encoded_len());
    let _ = m.encode(&mut buf);
    buf
}

/// `mint_commitment = BLAKE3("PHANTOM:MINT:COMMIT:v1" || canonical_mint_bytes)`.
pub fn mint_commitment_v1(m: &MintEvent) -> Hash32 {
    let bytes = canonical_mint_bytes_v1(m);
    digest_with_domain(MINT_COMMITMENT_DOMAIN_V1, &bytes)
}

/// Normative alias: `mint_id == mint_commitment`.
pub fn mint_id_v1(m: &MintEvent) -> Hash32 {
    mint_commitment_v1(m)
}

#[inline]
pub fn candidate_work_id_v1(c: &MintCandidateEvent) -> Hash32 {
    c.work_id.unwrap_or(c.mint_commitment)
}

#[inline]
pub fn pow_cert_work_id_v1(c: &MintPoWCertV1) -> Hash32 {
    c.work_id.unwrap_or(c.mint_commitment)
}

/// Canonical bytes used for candidate-id hashing.
pub fn canonical_candidate_bytes_v1(c: &MintCandidateEvent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(c.encoded_len());
    let _ = c.encode(&mut buf);
    buf
}

/// `candidate_id = BLAKE3("PHANTOM:MINT:CANDIDATE:v1" || canonical_candidate_bytes)`.
pub fn candidate_id_v1(c: &MintCandidateEvent) -> Hash32 {
    let bytes = canonical_candidate_bytes_v1(c);
    digest_with_domain(MINT_CANDIDATE_DOMAIN_V1, &bytes)
}

pub fn canonical_candidate_bytes_v2(c: &MintCandidateEventV2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(c.encoded_len());
    let _ = c.encode(&mut buf);
    buf
}

/// Canonical bytes used for V2 PoW-certificate id hashing.
pub fn canonical_pow_cert_bytes_v1(c: &MintPoWCertV1) -> Vec<u8> {
    let mut buf = Vec::with_capacity(c.encoded_len());
    let _ = c.encode(&mut buf);
    buf
}

/// `pow_cert_id = BLAKE3("PHANTOM:MINT:POWCERT:v1" || canonical_pow_cert_bytes)`.
pub fn pow_cert_id_v1(c: &MintPoWCertV1) -> Hash32 {
    let bytes = canonical_pow_cert_bytes_v1(c);
    digest_with_domain(MINT_POW_CERT_DOMAIN_V1, &bytes)
}

pub fn canonical_pow_cert_bytes_v2(c: &MintPoWCertV2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(c.encoded_len());
    let _ = c.encode(&mut buf);
    buf
}

pub fn slot_id_v2(
    network_id: &Hash32,
    prev_mint_id: &Hash32,
    window_id: u64,
    window_open_anchor_id: &Hash32,
    mint_commitment: &Hash32,
) -> Hash32 {
    let mut buf = Vec::with_capacity(MINT_SLOT_DOMAIN_V2.len() + (32 * 4) + 8);
    buf.extend_from_slice(MINT_SLOT_DOMAIN_V2);
    buf.extend_from_slice(network_id);
    buf.extend_from_slice(prev_mint_id);
    buf.extend_from_slice(&window_id.to_le_bytes());
    buf.extend_from_slice(window_open_anchor_id);
    buf.extend_from_slice(mint_commitment);
    blake3_32(&buf)
}

pub fn submission_id_v2(
    network_id: &Hash32,
    prev_mint_id: &Hash32,
    window_id: u64,
    window_open_anchor_id: &Hash32,
    mint_commitment: &Hash32,
    nonce: u64,
) -> Hash32 {
    let mut buf = Vec::with_capacity(MINT_SUBMISSION_DOMAIN_V2.len() + (32 * 4) + 16);
    buf.extend_from_slice(MINT_SUBMISSION_DOMAIN_V2);
    buf.extend_from_slice(network_id);
    buf.extend_from_slice(prev_mint_id);
    buf.extend_from_slice(&window_id.to_le_bytes());
    buf.extend_from_slice(window_open_anchor_id);
    buf.extend_from_slice(mint_commitment);
    buf.extend_from_slice(&nonce.to_le_bytes());
    blake3_32(&buf)
}

pub fn pow_hash_v2(
    network_id: &Hash32,
    prev_mint_id: &Hash32,
    window_id: u64,
    window_open_anchor_id: &Hash32,
    mint_commitment: &Hash32,
    nonce: u64,
) -> Hash32 {
    let mut buf = Vec::with_capacity(MINT_POW_DOMAIN_V1.len() + (32 * 4) + 16);
    buf.extend_from_slice(MINT_POW_DOMAIN_V1);
    buf.extend_from_slice(network_id);
    buf.extend_from_slice(prev_mint_id);
    buf.extend_from_slice(&window_id.to_le_bytes());
    buf.extend_from_slice(window_open_anchor_id);
    buf.extend_from_slice(mint_commitment);
    buf.extend_from_slice(&nonce.to_le_bytes());
    blake3_32(&buf)
}

#[inline]
pub fn candidate_slot_id_v2(c: &MintCandidateEventV2) -> Hash32 {
    slot_id_v2(
        &c.network_id,
        &c.prev_mint_id,
        c.window_id,
        &c.window_open_anchor_id,
        &c.mint_commitment,
    )
}

#[inline]
pub fn pow_cert_slot_id_v2(c: &MintPoWCertV2) -> Hash32 {
    slot_id_v2(
        &c.network_id,
        &c.prev_mint_id,
        c.window_id,
        &c.window_open_anchor_id,
        &c.mint_commitment,
    )
}

#[inline]
pub fn candidate_submission_id_v2(c: &MintCandidateEventV2) -> Hash32 {
    submission_id_v2(
        &c.network_id,
        &c.prev_mint_id,
        c.window_id,
        &c.window_open_anchor_id,
        &c.mint_commitment,
        c.nonce,
    )
}

#[inline]
pub fn pow_cert_submission_id_v2(c: &MintPoWCertV2) -> Hash32 {
    submission_id_v2(
        &c.network_id,
        &c.prev_mint_id,
        c.window_id,
        &c.window_open_anchor_id,
        &c.mint_commitment,
        c.nonce,
    )
}

pub fn pow_cert_id_v2(c: &MintPoWCertV2) -> Hash32 {
    let bytes = canonical_pow_cert_bytes_v2(c);
    digest_with_domain(MINT_POW_CERT_DOMAIN_V2, &bytes)
}

/// Canonical PoW hash bound to window/mint commitment.
pub fn candidate_pow_hash_v1(c: &MintCandidateEvent) -> Hash32 {
    let mut buf = Vec::with_capacity(MINT_POW_DOMAIN_V1.len() + (32 * 4) + 16);
    buf.extend_from_slice(MINT_POW_DOMAIN_V1);
    buf.extend_from_slice(&c.network_id);
    buf.extend_from_slice(&c.prev_mint_id);
    buf.extend_from_slice(&c.window_id.to_le_bytes());
    buf.extend_from_slice(&c.window_open_anchor_id);
    buf.extend_from_slice(&c.mint_commitment);
    buf.extend_from_slice(&c.nonce.to_le_bytes());
    blake3_32(&buf)
}

/// Canonical PoW hash for a forced-inclusion certificate.
pub fn pow_cert_pow_hash_v1(c: &MintPoWCertV1) -> Hash32 {
    let mut buf = Vec::with_capacity(MINT_POW_DOMAIN_V1.len() + (32 * 4) + 16);
    buf.extend_from_slice(MINT_POW_DOMAIN_V1);
    buf.extend_from_slice(&c.network_id);
    buf.extend_from_slice(&c.prev_mint_id);
    buf.extend_from_slice(&c.window_id.to_le_bytes());
    buf.extend_from_slice(&c.window_open_anchor_id);
    buf.extend_from_slice(&c.mint_commitment);
    buf.extend_from_slice(&c.nonce.to_le_bytes());
    blake3_32(&buf)
}

#[inline]
pub fn candidate_pow_hash_v2(c: &MintCandidateEventV2) -> Hash32 {
    pow_hash_v2(
        &c.network_id,
        &c.prev_mint_id,
        c.window_id,
        &c.window_open_anchor_id,
        &c.mint_commitment,
        c.nonce,
    )
}

#[inline]
pub fn pow_cert_pow_hash_v2(c: &MintPoWCertV2) -> Hash32 {
    pow_hash_v2(
        &c.network_id,
        &c.prev_mint_id,
        c.window_id,
        &c.window_open_anchor_id,
        &c.mint_commitment,
        c.nonce,
    )
}

/// Deterministic conversion: a PoW cert imports into the candidate pipeline with
/// empty optional candidate fields.
pub fn mint_candidate_from_pow_cert_v1(c: &MintPoWCertV1) -> MintCandidateEvent {
    MintCandidateEvent {
        version: 1,
        network_id: c.network_id,
        prev_mint_id: c.prev_mint_id,
        window_id: c.window_id,
        window_open_anchor_id: c.window_open_anchor_id,
        mint_commitment: c.mint_commitment,
        nonce: c.nonce,
        work_id: c.work_id,
        miner_pubkey: None,
        recipient_lock: None,
    }
}

/// BE-u256 comparison helper for consensus-sort keys.
#[inline]
pub fn cmp_hash_be_u256(a: &Hash32, b: &Hash32) -> core::cmp::Ordering {
    a.as_slice().cmp(b.as_slice())
}

/// Enforces fixed-position optional fields under feature-gated policy.
pub fn validate_mint_candidate_features_v1(
    c: &MintCandidateEvent,
    active_feature_bits: u64,
) -> Result<(), &'static str> {
    if c.version != 1 {
        return Err("invalid candidate version");
    }
    if c.miner_pubkey.is_some()
        && (active_feature_bits & MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V1 == 0)
    {
        return Err("miner_pubkey feature disabled");
    }
    if c.recipient_lock.is_some()
        && (active_feature_bits & MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V1 == 0)
    {
        return Err("recipient_lock feature disabled");
    }
    if c.work_id.is_some() && (active_feature_bits & MINT_CANDIDATE_FEATURE_WORK_ID_V1 == 0) {
        return Err("work_id feature disabled");
    }
    if c.work_id == Some([0u8; 32]) {
        return Err("invalid work_id");
    }
    Ok(())
}

pub fn validate_mint_pow_cert_features_v1(
    c: &MintPoWCertV1,
    active_feature_bits: u64,
) -> Result<(), &'static str> {
    if c.version != 1 {
        return Err("invalid mint pow cert version");
    }
    if c.work_id.is_some() && (active_feature_bits & MINT_CANDIDATE_FEATURE_WORK_ID_V1 == 0) {
        return Err("work_id feature disabled");
    }
    if c.work_id == Some([0u8; 32]) {
        return Err("invalid work_id");
    }
    Ok(())
}

pub fn validate_mint_candidate_features_v2(
    c: &MintCandidateEventV2,
    active_feature_bits: u64,
) -> Result<(), &'static str> {
    if c.version != 2 {
        return Err("invalid candidate version");
    }
    if c.miner_pubkey.is_some()
        && (active_feature_bits & MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V2 == 0)
    {
        return Err("miner_pubkey feature disabled");
    }
    if c.recipient_lock.is_some()
        && (active_feature_bits & MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V2 == 0)
    {
        return Err("recipient_lock feature disabled");
    }
    Ok(())
}

pub fn validate_mint_candidate_v2(c: &MintCandidateEventV2) -> Result<(), &'static str> {
    validate_mint_candidate_features_v2(
        c,
        MINT_CANDIDATE_FEATURE_MINER_PUBKEY_V2 | MINT_CANDIDATE_FEATURE_RECIPIENT_LOCK_V2,
    )
}

pub fn validate_mint_pow_cert_v2(c: &MintPoWCertV2) -> Result<(), &'static str> {
    if c.version != 2 {
        return Err("invalid mint pow cert version");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimEvent {
    pub version: u8,
    pub anchor_id: AnchorId,
    pub recipient_id: [u8; 32], // z. B. Commitment auf seat_pk
    pub amount: Amount,
    pub merkle_proof: Vec<Hash32>,
    pub payout_lock: LockCommitment,
}
impl Encodable for ClaimEvent {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.anchor_id.encode(w)?;
        self.recipient_id.encode(w)?;
        self.amount.encode(w)?;
        self.merkle_proof.encode(w)?;
        self.payout_lock.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.anchor_id.encoded_len()
            + 32
            + self.amount.encoded_len()
            + self.merkle_proof.encoded_len()
            + self.payout_lock.encoded_len()
    }
}
impl Decodable for ClaimEvent {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        let anchor_id = AnchorId::decode(r)?;
        let recipient_id = <[u8; 32]>::decode(r)?;
        let amount = u64::decode(r)?;
        // Bounded decode for merkle_proof (P1-2 hardening).
        // Gebundener Decode für merkle_proof (P1-2 Härtung).
        let proof_len = pc_codec::read_varu64(r)? as usize;
        if proof_len > MAX_CLAIM_MERKLE_PROOF_DEPTH {
            return Err(CodecError::InvalidLength(proof_len));
        }
        let mut merkle_proof = Vec::with_capacity(proof_len);
        for _ in 0..proof_len {
            merkle_proof.push(<[u8; 32]>::decode(r)?);
        }
        let payout_lock = LockCommitment::decode(r)?;
        Ok(Self {
            version,
            anchor_id,
            recipient_id,
            amount,
            merkle_proof,
            payout_lock,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Equivocation {
        seat_id: [u8; 32],
        epoch_id: u64,
        a: AnchorHeader,
        b: Box<AnchorHeader>,
    },
    VoteInvalid {
        seat_id: [u8; 32],
        anchor: AnchorHeader,
        reason_code: u16,
    },
    ConflictingDAAttest {
        seat_id: [u8; 32],
        anchor_id: AnchorId,
        attest_a: Vec<u8>,
        attest_b: Vec<u8>,
    },
    /// On-chain verifiable slashing authorization (committee-signed).
    ///
    /// This is intentionally *not* the raw evidence itself; it is a compact,
    /// replay-protected ticket carrying a BLS aggregate signature from the
    /// committee derived from on-chain state.
    ///
    /// `category` values:
    /// - 1 = equivocation
    /// - 2 = vote_invalid
    /// - 3 = conflicting_da
    SlashTicketV1 {
        offender_id: [u8; 32],
        category: u8,
        slash_bp: u16,
        vote_epoch: u64,
        seed_anchor: [u8; 32],
        slash_id: [u8; 32],
        vote_mask: u64,
        reporter_lock: LockCommitment,
        agg_sig: [u8; 96],
    },
    /// On-chain verifiable BFT equivocation evidence (ticketless).
    ///
    /// Proves that `offender_id` participated in signing two conflicting finalized headers
    /// for the same (epoch, shard, round) under the same seed anchor.
    ///
    /// Reward is bound to the reporter via `reporter_sig` over a deterministic `slash_id`.
    EquivocationBftV1 {
        offender_id: [u8; 32],
        seed_anchor: [u8; 32],
        a: Box<AnchorHeaderV2>,
        b: Box<AnchorHeaderV2>,
        reporter_lock: LockCommitment,
        reporter_sig: [u8; 64],
    },
    /// Evidence that an anchor violated winner/null-mint rules for a finalized window.
    MintCensorshipV1 {
        prev_mint_id: [u8; 32],
        window_id: u64,
        expected_winner_candidate_id: [u8; 32],
        offending_anchor_id: AnchorId,
    },
    /// Finalized mint-candidate consensus object carried in the finalized graph/payload path.
    MintCandidateV1 {
        candidate: MintCandidateEvent,
    },
    /// Forced-inclusion PoW certificate (v2 extension).
    MintPoWCertV1 {
        cert: MintPoWCertV1,
    },
    /// Evidence that a finalized V2 PoW cert exists for the winner but an offending
    /// deadline anchor omitted the required winner decision.
    MintMissingImportV1 {
        prev_mint_id: [u8; 32],
        window_id: u64,
        expected_winner_candidate_id: [u8; 32],
        required_pow_cert_id: [u8; 32],
        offending_anchor_id: AnchorId,
    },
    MintCensorshipV2 {
        prev_mint_id: [u8; 32],
        window_id: u64,
        expected_winner_submission_id: [u8; 32],
        offending_anchor_id: AnchorId,
    },
    MintCandidateV2 {
        candidate: MintCandidateEventV2,
    },
    MintPoWCertV2 {
        cert: MintPoWCertV2,
    },
    MintMissingImportV2 {
        prev_mint_id: [u8; 32],
        window_id: u64,
        expected_winner_submission_id: [u8; 32],
        required_pow_cert_id: [u8; 32],
        offending_anchor_id: AnchorId,
    },
}

impl Encodable for EvidenceKind {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            EvidenceKind::Equivocation {
                seat_id,
                epoch_id,
                a,
                b,
            } => {
                1u8.encode(w)?;
                seat_id.encode(w)?;
                epoch_id.encode(w)?;
                a.encode(w)?;
                b.encode(w)?;
                Ok(())
            }
            EvidenceKind::VoteInvalid {
                seat_id,
                anchor,
                reason_code,
            } => {
                2u8.encode(w)?;
                seat_id.encode(w)?;
                anchor.encode(w)?;
                reason_code.encode(w)?;
                Ok(())
            }
            EvidenceKind::ConflictingDAAttest {
                seat_id,
                anchor_id,
                attest_a,
                attest_b,
            } => {
                3u8.encode(w)?;
                seat_id.encode(w)?;
                anchor_id.encode(w)?;
                attest_a.encode(w)?;
                attest_b.encode(w)?;
                Ok(())
            }
            EvidenceKind::SlashTicketV1 {
                offender_id,
                category,
                slash_bp,
                vote_epoch,
                seed_anchor,
                slash_id,
                vote_mask,
                reporter_lock,
                agg_sig,
            } => {
                4u8.encode(w)?;
                offender_id.encode(w)?;
                category.encode(w)?;
                slash_bp.encode(w)?;
                vote_epoch.encode(w)?;
                seed_anchor.encode(w)?;
                slash_id.encode(w)?;
                vote_mask.encode(w)?;
                reporter_lock.encode(w)?;
                w.write_all(agg_sig).map_err(CodecError::Io)?;
                Ok(())
            }
            EvidenceKind::EquivocationBftV1 {
                offender_id,
                seed_anchor,
                a,
                b,
                reporter_lock,
                reporter_sig,
            } => {
                5u8.encode(w)?;
                offender_id.encode(w)?;
                seed_anchor.encode(w)?;
                a.as_ref().encode(w)?;
                b.encode(w)?;
                reporter_lock.encode(w)?;
                w.write_all(reporter_sig).map_err(CodecError::Io)?;
                Ok(())
            }
            EvidenceKind::MintCensorshipV1 {
                prev_mint_id,
                window_id,
                expected_winner_candidate_id,
                offending_anchor_id,
            } => {
                6u8.encode(w)?;
                prev_mint_id.encode(w)?;
                window_id.encode(w)?;
                expected_winner_candidate_id.encode(w)?;
                offending_anchor_id.encode(w)?;
                Ok(())
            }
            EvidenceKind::MintCandidateV1 { candidate } => {
                7u8.encode(w)?;
                candidate.encode(w)?;
                Ok(())
            }
            EvidenceKind::MintPoWCertV1 { cert } => {
                8u8.encode(w)?;
                cert.encode(w)?;
                Ok(())
            }
            EvidenceKind::MintMissingImportV1 {
                prev_mint_id,
                window_id,
                expected_winner_candidate_id,
                required_pow_cert_id,
                offending_anchor_id,
            } => {
                9u8.encode(w)?;
                prev_mint_id.encode(w)?;
                window_id.encode(w)?;
                expected_winner_candidate_id.encode(w)?;
                required_pow_cert_id.encode(w)?;
                offending_anchor_id.encode(w)?;
                Ok(())
            }
            EvidenceKind::MintCensorshipV2 {
                prev_mint_id,
                window_id,
                expected_winner_submission_id,
                offending_anchor_id,
            } => {
                10u8.encode(w)?;
                prev_mint_id.encode(w)?;
                window_id.encode(w)?;
                expected_winner_submission_id.encode(w)?;
                offending_anchor_id.encode(w)?;
                Ok(())
            }
            EvidenceKind::MintCandidateV2 { candidate } => {
                11u8.encode(w)?;
                candidate.encode(w)?;
                Ok(())
            }
            EvidenceKind::MintPoWCertV2 { cert } => {
                12u8.encode(w)?;
                cert.encode(w)?;
                Ok(())
            }
            EvidenceKind::MintMissingImportV2 {
                prev_mint_id,
                window_id,
                expected_winner_submission_id,
                required_pow_cert_id,
                offending_anchor_id,
            } => {
                13u8.encode(w)?;
                prev_mint_id.encode(w)?;
                window_id.encode(w)?;
                expected_winner_submission_id.encode(w)?;
                required_pow_cert_id.encode(w)?;
                offending_anchor_id.encode(w)?;
                Ok(())
            }
        }
    }
    fn encoded_len(&self) -> usize {
        match self {
            EvidenceKind::Equivocation {
                seat_id: _,
                epoch_id,
                a,
                b,
            } => 1 + 32 + epoch_id.encoded_len() + a.encoded_len() + b.encoded_len(),
            EvidenceKind::VoteInvalid {
                seat_id: _,
                anchor,
                reason_code,
            } => 1 + 32 + anchor.encoded_len() + reason_code.encoded_len(),
            EvidenceKind::ConflictingDAAttest {
                seat_id: _,
                anchor_id,
                attest_a,
                attest_b,
            } => 1 + 32 + anchor_id.encoded_len() + attest_a.encoded_len() + attest_b.encoded_len(),
            EvidenceKind::SlashTicketV1 {
                offender_id: _,
                category,
                slash_bp,
                vote_epoch,
                seed_anchor: _,
                slash_id: _,
                vote_mask,
                reporter_lock,
                agg_sig: _,
            } => {
                1 + 32
                    + category.encoded_len()
                    + slash_bp.encoded_len()
                    + vote_epoch.encoded_len()
                    + 32
                    + 32
                    + vote_mask.encoded_len()
                    + reporter_lock.encoded_len()
                    + 96
            }
            EvidenceKind::EquivocationBftV1 {
                offender_id: _,
                seed_anchor: _,
                a,
                b,
                reporter_lock,
                reporter_sig: _,
            } => 1 + 32 + 32 + a.encoded_len() + b.encoded_len() + reporter_lock.encoded_len() + 64,
            EvidenceKind::MintCensorshipV1 {
                prev_mint_id: _,
                window_id,
                expected_winner_candidate_id: _,
                offending_anchor_id,
            } => 1 + 32 + window_id.encoded_len() + 32 + offending_anchor_id.encoded_len(),
            EvidenceKind::MintCandidateV1 { candidate } => 1 + candidate.encoded_len(),
            EvidenceKind::MintPoWCertV1 { cert } => 1 + cert.encoded_len(),
            EvidenceKind::MintMissingImportV1 {
                prev_mint_id: _,
                window_id,
                expected_winner_candidate_id: _,
                required_pow_cert_id: _,
                offending_anchor_id,
            } => 1 + 32 + window_id.encoded_len() + 32 + 32 + offending_anchor_id.encoded_len(),
            EvidenceKind::MintCensorshipV2 {
                prev_mint_id: _,
                window_id,
                expected_winner_submission_id: _,
                offending_anchor_id,
            } => 1 + 32 + window_id.encoded_len() + 32 + offending_anchor_id.encoded_len(),
            EvidenceKind::MintCandidateV2 { candidate } => 1 + candidate.encoded_len(),
            EvidenceKind::MintPoWCertV2 { cert } => 1 + cert.encoded_len(),
            EvidenceKind::MintMissingImportV2 {
                prev_mint_id: _,
                window_id,
                expected_winner_submission_id: _,
                required_pow_cert_id: _,
                offending_anchor_id,
            } => 1 + 32 + window_id.encoded_len() + 32 + 32 + offending_anchor_id.encoded_len(),
        }
    }
}
/// Bounded decode for Vec<T> with max count limit (P1-2 hardening).
/// Gebundener Decode für Vec<T> mit max Anzahllimit (P1-2 Härtung).
fn decode_bounded_vec<T: Decodable, R: Read>(
    r: &mut R,
    max_len: usize,
) -> Result<Vec<T>, CodecError> {
    let len = pc_codec::read_varu64(r)? as usize;
    if len > max_len {
        return Err(CodecError::InvalidLength(len));
    }
    let mut vec = Vec::with_capacity(len);
    for _ in 0..len {
        vec.push(T::decode(r)?);
    }
    Ok(vec)
}

/// Bounded decode for Vec<u8> with max size limit (P1-2 hardening).
/// Gebundener Decode für Vec<u8> mit max Größenlimit (P1-2 Härtung).
fn decode_bounded_bytes<R: Read>(r: &mut R, max_len: usize) -> Result<Vec<u8>, CodecError> {
    let len = pc_codec::read_varu64(r)? as usize;
    if len > max_len {
        return Err(CodecError::InvalidLength(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

impl Decodable for EvidenceKind {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let tag = u8::decode(r)?;
        match tag {
            1 => Ok(EvidenceKind::Equivocation {
                seat_id: <[u8; 32]>::decode(r)?,
                epoch_id: u64::decode(r)?,
                a: AnchorHeader::decode(r)?,
                b: Box::new(AnchorHeader::decode(r)?),
            }),
            2 => Ok(EvidenceKind::VoteInvalid {
                seat_id: <[u8; 32]>::decode(r)?,
                anchor: AnchorHeader::decode(r)?,
                reason_code: u16::decode(r)?,
            }),
            3 => {
                // Bounded decode for attest_a/b (P1-2 hardening).
                // Gebundener Decode für attest_a/b (P1-2 Härtung).
                let seat_id = <[u8; 32]>::decode(r)?;
                let anchor_id = AnchorId::decode(r)?;
                let attest_a = decode_bounded_bytes(r, MAX_EVIDENCE_ATTEST_BYTES)?;
                let attest_b = decode_bounded_bytes(r, MAX_EVIDENCE_ATTEST_BYTES)?;
                Ok(EvidenceKind::ConflictingDAAttest {
                    seat_id,
                    anchor_id,
                    attest_a,
                    attest_b,
                })
            }
            4 => {
                let offender_id = <[u8; 32]>::decode(r)?;
                let category = u8::decode(r)?;
                let slash_bp = u16::decode(r)?;
                let vote_epoch = u64::decode(r)?;
                let seed_anchor = <[u8; 32]>::decode(r)?;
                let slash_id = <[u8; 32]>::decode(r)?;
                let vote_mask = u64::decode(r)?;
                let reporter_lock = LockCommitment::decode(r)?;
                let mut agg_sig = [0u8; 96];
                r.read_exact(&mut agg_sig)?;
                Ok(EvidenceKind::SlashTicketV1 {
                    offender_id,
                    category,
                    slash_bp,
                    vote_epoch,
                    seed_anchor,
                    slash_id,
                    vote_mask,
                    reporter_lock,
                    agg_sig,
                })
            }
            5 => {
                let offender_id = <[u8; 32]>::decode(r)?;
                let seed_anchor = <[u8; 32]>::decode(r)?;
                let a = Box::new(AnchorHeaderV2::decode(r)?);
                let b = Box::new(AnchorHeaderV2::decode(r)?);
                let reporter_lock = LockCommitment::decode(r)?;
                let mut reporter_sig = [0u8; 64];
                r.read_exact(&mut reporter_sig)?;
                Ok(EvidenceKind::EquivocationBftV1 {
                    offender_id,
                    seed_anchor,
                    a,
                    b,
                    reporter_lock,
                    reporter_sig,
                })
            }
            6 => {
                let prev_mint_id = <[u8; 32]>::decode(r)?;
                let window_id = u64::decode(r)?;
                let expected_winner_candidate_id = <[u8; 32]>::decode(r)?;
                let offending_anchor_id = AnchorId::decode(r)?;
                Ok(EvidenceKind::MintCensorshipV1 {
                    prev_mint_id,
                    window_id,
                    expected_winner_candidate_id,
                    offending_anchor_id,
                })
            }
            7 => {
                let candidate = MintCandidateEvent::decode(r)?;
                Ok(EvidenceKind::MintCandidateV1 { candidate })
            }
            8 => {
                let cert = MintPoWCertV1::decode(r)?;
                Ok(EvidenceKind::MintPoWCertV1 { cert })
            }
            9 => {
                let prev_mint_id = <[u8; 32]>::decode(r)?;
                let window_id = u64::decode(r)?;
                let expected_winner_candidate_id = <[u8; 32]>::decode(r)?;
                let required_pow_cert_id = <[u8; 32]>::decode(r)?;
                let offending_anchor_id = AnchorId::decode(r)?;
                Ok(EvidenceKind::MintMissingImportV1 {
                    prev_mint_id,
                    window_id,
                    expected_winner_candidate_id,
                    required_pow_cert_id,
                    offending_anchor_id,
                })
            }
            10 => {
                let prev_mint_id = <[u8; 32]>::decode(r)?;
                let window_id = u64::decode(r)?;
                let expected_winner_submission_id = <[u8; 32]>::decode(r)?;
                let offending_anchor_id = AnchorId::decode(r)?;
                Ok(EvidenceKind::MintCensorshipV2 {
                    prev_mint_id,
                    window_id,
                    expected_winner_submission_id,
                    offending_anchor_id,
                })
            }
            11 => {
                let candidate = MintCandidateEventV2::decode(r)?;
                Ok(EvidenceKind::MintCandidateV2 { candidate })
            }
            12 => {
                let cert = MintPoWCertV2::decode(r)?;
                Ok(EvidenceKind::MintPoWCertV2 { cert })
            }
            13 => {
                let prev_mint_id = <[u8; 32]>::decode(r)?;
                let window_id = u64::decode(r)?;
                let expected_winner_submission_id = <[u8; 32]>::decode(r)?;
                let required_pow_cert_id = <[u8; 32]>::decode(r)?;
                let offending_anchor_id = AnchorId::decode(r)?;
                Ok(EvidenceKind::MintMissingImportV2 {
                    prev_mint_id,
                    window_id,
                    expected_winner_submission_id,
                    required_pow_cert_id,
                    offending_anchor_id,
                })
            }
            _ => Err(CodecError::InvalidTag(tag)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceEvent {
    pub version: u8,
    pub evidence: EvidenceKind,
}
impl Encodable for EvidenceEvent {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.evidence.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.version.encoded_len() + self.evidence.encoded_len()
    }
}
impl Decodable for EvidenceEvent {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            version: u8::decode(r)?,
            evidence: EvidenceKind::decode(r)?,
        })
    }
}

// ============================
// Stateless Validation (v0)
// ============================
pub fn validate_microtx_sanity(tx: &MicroTx) -> Result<(), &'static str> {
    // Validate supported versions early.
    // Unterstützte Versionen früh prüfen.
    match tx.version {
        TX_VERSION_TRANSFER_V1
        | TX_VERSION_STAKE_BOND_V1
        | TX_VERSION_STAKE_UNBOND_V1
        | TX_VERSION_VALIDATOR_REGISTER_V1 => {}
        _ => return Err("unsupported tx version"),
    }
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err("too many inputs");
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err("too many outputs");
    }

    // Validator register tx is a special "meta" tx: it does not spend value and has no outputs.
    // Validator-Register-Tx ist eine spezielle "Meta"-Tx: sie transferiert keinen Wert und hat keine Outputs.
    if tx.version == TX_VERSION_VALIDATOR_REGISTER_V1 {
        if tx.inputs.len() != 1 {
            return Err("validator register requires exactly 1 input");
        }
        if !tx.outputs.is_empty() {
            return Err("validator register must have 0 outputs");
        }
        let tin = tx
            .inputs
            .first()
            .ok_or("validator register requires exactly 1 input")?;
        if tin.witness.len() != VALIDATOR_REGISTER_WITNESS_BYTES_V1 {
            return Err("validator register witness bad length");
        }
        return Ok(());
    }

    // S6-Fix: Mindestens ein Input erforderlich.
    // S6-Fix: At least one input required.
    if tx.inputs.is_empty() {
        return Err("no inputs");
    }
    // S6-Fix: Mindestens ein Output erforderlich.
    // S6-Fix: At least one output required.
    if tx.outputs.is_empty() {
        return Err("no outputs");
    }
    for tin in &tx.inputs {
        if tin.witness.len() > MAX_WITNESS_BYTES {
            return Err("witness too large");
        }
    }
    // S6-Fix: Zero-Amount-Outputs verbieten (DoS-Schutz).
    // S6-Fix: Reject zero-amount outputs (DoS protection).
    for tout in &tx.outputs {
        if tout.amount == 0 {
            return Err("zero amount output");
        }
    }
    Ok(())
}

pub fn validate_mint_sanity(m: &MintEvent) -> Result<(), &'static str> {
    if m.outputs.len() > MAX_MINT_OUTPUTS {
        return Err("too many mint outputs");
    }
    // S6-Fix: Mindestens ein Output erforderlich.
    // S6-Fix: At least one output required.
    if m.outputs.is_empty() {
        return Err("no mint outputs");
    }
    // S6-Fix: Zero-Amount-Outputs verbieten (DoS-Schutz).
    // S6-Fix: Reject zero-amount outputs (DoS protection).
    for out in &m.outputs {
        if out.amount == 0 {
            return Err("zero amount mint output");
        }
    }
    Ok(())
}

/// Sanity checks for `ClaimEvent` (P1-2 hardening).
/// Sanity-Checks für ClaimEvent (P1-2 Härtung).
pub fn validate_claim_sanity(c: &ClaimEvent) -> Result<(), &'static str> {
    if c.merkle_proof.len() > MAX_CLAIM_MERKLE_PROOF_DEPTH {
        return Err("merkle proof too deep");
    }
    Ok(())
}

/// Sanity checks for `EvidenceEvent` (P1-2 hardening).
/// Sanity-Checks für EvidenceEvent (P1-2 Härtung).
pub fn validate_evidence_sanity(e: &EvidenceEvent) -> Result<(), &'static str> {
    match &e.evidence {
        EvidenceKind::ConflictingDAAttest {
            attest_a, attest_b, ..
        } => {
            if attest_a.len() > MAX_EVIDENCE_ATTEST_BYTES {
                return Err("attest_a too large");
            }
            if attest_b.len() > MAX_EVIDENCE_ATTEST_BYTES {
                return Err("attest_b too large");
            }
        }
        EvidenceKind::SlashTicketV1 {
            category,
            slash_bp,
            reporter_lock,
            ..
        } => {
            if !matches!(*category, 1..=3) {
                return Err("invalid slash category");
            }
            if *slash_bp == 0 || *slash_bp > 10_000 {
                return Err("invalid slash_bp");
            }
            if reporter_lock.0 == [0u8; 32] {
                return Err("invalid reporter_lock");
            }
        }
        EvidenceKind::EquivocationBftV1 {
            offender_id,
            seed_anchor,
            a,
            b,
            reporter_lock,
            reporter_sig: _,
        } => {
            if *offender_id == [0u8; 32] {
                return Err("invalid offender_id");
            }
            if *seed_anchor == [0u8; 32] {
                return Err("invalid seed_anchor");
            }
            if reporter_lock.0 == [0u8; 32] {
                return Err("invalid reporter_lock");
            }
            // Basic structure checks (full verification happens in the node).
            if a.version < 3 || b.version < 3 {
                return Err("equivocation headers must be v3+");
            }
            if a.vote_epoch != b.vote_epoch
                || a.vote_round != b.vote_round
                || a.shard_id != b.shard_id
            {
                return Err("equivocation slot mismatch");
            }
            if a.vote_target_hash() == b.vote_target_hash() {
                return Err("equivocation targets equal");
            }
        }
        EvidenceKind::MintCensorshipV1 {
            prev_mint_id,
            window_id: _,
            expected_winner_candidate_id,
            offending_anchor_id,
        } => {
            if *prev_mint_id == [0u8; 32] {
                return Err("invalid prev_mint_id");
            }
            if *expected_winner_candidate_id == [0u8; 32] {
                return Err("invalid expected_winner_candidate_id");
            }
            if offending_anchor_id.0 == [0u8; 32] {
                return Err("invalid offending_anchor_id");
            }
        }
        EvidenceKind::MintCandidateV1 { candidate } => {
            validate_mint_candidate_features_v1(candidate, u64::MAX)
                .map_err(|_| "invalid mint candidate")?;
        }
        EvidenceKind::MintPoWCertV1 { cert } => {
            validate_mint_pow_cert_features_v1(cert, u64::MAX)
                .map_err(|_| "invalid mint pow cert")?;
            if cert.mint_commitment == [0u8; 32] {
                return Err("invalid mint_commitment");
            }
        }
        EvidenceKind::MintMissingImportV1 {
            prev_mint_id,
            window_id: _,
            expected_winner_candidate_id,
            required_pow_cert_id,
            offending_anchor_id,
        } => {
            if *prev_mint_id == [0u8; 32] {
                return Err("invalid prev_mint_id");
            }
            if *expected_winner_candidate_id == [0u8; 32] {
                return Err("invalid expected_winner_candidate_id");
            }
            if *required_pow_cert_id == [0u8; 32] {
                return Err("invalid required_pow_cert_id");
            }
            if offending_anchor_id.0 == [0u8; 32] {
                return Err("invalid offending_anchor_id");
            }
        }
        EvidenceKind::MintCensorshipV2 {
            prev_mint_id,
            window_id: _,
            expected_winner_submission_id,
            offending_anchor_id,
        } => {
            if *prev_mint_id == [0u8; 32] {
                return Err("invalid prev_mint_id");
            }
            if *expected_winner_submission_id == [0u8; 32] {
                return Err("invalid expected_winner_submission_id");
            }
            if offending_anchor_id.0 == [0u8; 32] {
                return Err("invalid offending_anchor_id");
            }
        }
        EvidenceKind::MintCandidateV2 { candidate } => {
            validate_mint_candidate_v2(candidate).map_err(|_| "invalid mint candidate")?;
        }
        EvidenceKind::MintPoWCertV2 { cert } => {
            validate_mint_pow_cert_v2(cert).map_err(|_| "invalid mint pow cert")?;
            if cert.mint_commitment == [0u8; 32] {
                return Err("invalid mint_commitment");
            }
        }
        EvidenceKind::MintMissingImportV2 {
            prev_mint_id,
            window_id: _,
            expected_winner_submission_id,
            required_pow_cert_id,
            offending_anchor_id,
        } => {
            if *prev_mint_id == [0u8; 32] {
                return Err("invalid prev_mint_id");
            }
            if *expected_winner_submission_id == [0u8; 32] {
                return Err("invalid expected_winner_submission_id");
            }
            if *required_pow_cert_id == [0u8; 32] {
                return Err("invalid required_pow_cert_id");
            }
            if offending_anchor_id.0 == [0u8; 32] {
                return Err("invalid offending_anchor_id");
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_payload_sanity(p: &AnchorPayload) -> Result<(), &'static str> {
    if p.encoded_len() > MAX_PAYLOAD_BYTES {
        return Err("payload exceeds MAX_PAYLOAD_BYTES");
    }
    if p.micro_txs.len() > MAX_PAYLOAD_MICROTX {
        return Err("too many micro_txs");
    }
    if p.mints.len() > MAX_PAYLOAD_MINTS {
        return Err("too many mints");
    }
    if p.claims.len() > MAX_PAYLOAD_CLAIMS {
        return Err("too many claims");
    }
    if p.evidences.len() > MAX_PAYLOAD_EVIDENCES {
        return Err("too many evidences");
    }
    for tx in &p.micro_txs {
        validate_microtx_sanity(tx)?;
    }
    for m in &p.mints {
        validate_mint_sanity(m)?;
    }
    for c in &p.claims {
        validate_claim_sanity(c)?;
    }
    for e in &p.evidences {
        validate_evidence_sanity(e)?;
    }
    Ok(())
}

/// Sanity checks for `AnchorPayloadV2` (analogous to V1; `genesis_note` is not validated).
/// Sanity-Checks für AnchorPayloadV2 (analog V1; genesis_note wird nicht validiert).
pub fn validate_payload_sanity_v2(p: &AnchorPayloadV2) -> Result<(), &'static str> {
    if p.encoded_len() > MAX_PAYLOAD_BYTES {
        return Err("payload exceeds MAX_PAYLOAD_BYTES");
    }
    if p.micro_txs.len() > MAX_PAYLOAD_MICROTX {
        return Err("too many micro_txs");
    }
    if p.mints.len() > MAX_PAYLOAD_MINTS {
        return Err("too many mints");
    }
    if p.claims.len() > MAX_PAYLOAD_CLAIMS {
        return Err("too many claims");
    }
    if p.evidences.len() > MAX_PAYLOAD_EVIDENCES {
        return Err("too many evidences");
    }
    for tx in &p.micro_txs {
        validate_microtx_sanity(tx)?;
    }
    for m in &p.mints {
        validate_mint_sanity(m)?;
    }
    for c in &p.claims {
        validate_claim_sanity(c)?;
    }
    for e in &p.evidences {
        validate_evidence_sanity(e)?;
    }
    Ok(())
}

/// Sanity checks for `AnchorPayloadV3` (V2 checks + null-mint XOR semantics).
pub fn validate_payload_sanity_v3(p: &AnchorPayloadV3) -> Result<(), &'static str> {
    if p.version != 3 {
        return Err("anchorpayloadv3 requires version=3");
    }
    if p.encoded_len() > MAX_PAYLOAD_BYTES {
        return Err("payload exceeds MAX_PAYLOAD_BYTES");
    }
    if p.micro_txs.len() > MAX_PAYLOAD_MICROTX {
        return Err("too many micro_txs");
    }
    if p.mints.len() > MAX_PAYLOAD_MINTS {
        return Err("too many mints");
    }
    if p.claims.len() > MAX_PAYLOAD_CLAIMS {
        return Err("too many claims");
    }
    if p.evidences.len() > MAX_PAYLOAD_EVIDENCES {
        return Err("too many evidences");
    }
    if p.mints.len() > 1 {
        return Err("anchorpayloadv3 allows at most one mint");
    }
    if p.null_mint {
        return Err("null_mint not supported on active payload v3 path");
    }
    for tx in &p.micro_txs {
        validate_microtx_sanity(tx)?;
    }
    for m in &p.mints {
        validate_mint_sanity(m)?;
    }
    for c in &p.claims {
        validate_claim_sanity(c)?;
    }
    for e in &p.evidences {
        validate_evidence_sanity(e)?;
    }
    Ok(())
}

/// The seed is deterministically bound to the canonical mint context.
/// Random or arbitrary seeds will be rejected by consensus validation.
///
/// **WICHTIG**: Bei Emissionsrunden (`MintEvent.version >= 2`) MUSS der Miner den PoW-Seed mit
/// `mint_pow_seed_v2(network_id, mint_event)` berechnen.
/// Der Seed ist deterministisch an `network_id + version + prev_mint_id + outputs + round_id + hit_bucket + bits_used` gebunden.
/// Zufällige oder beliebige Seeds werden von der Konsens-Validierung abgelehnt.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MintTemplate {
    /// Previous mint hash (`prev_mint_id` for the next mint).
    /// Vorheriger Mint-Hash (prev_mint_id für den nächsten Mint).
    pub prev_mint_id: String, // Hex-String
    /// Target Difficulty (Bits)
    pub target_bits: u8,
    /// Expected reward in units.
    /// Erwarteter Reward in Einheiten.
    pub reward: u64,
    /// Current mint height (chain position).
    /// Aktuelle Mint-Höhe (Chain-Position).
    pub mint_height: u64,
    /// Current total supply in units.
    /// Aktueller Total Supply in Einheiten.
    pub total_supply: String, // String wegen u128
    /// Remaining supply until hard cap.
    /// Verbleibende Supply bis Hardcap.
    pub remaining_supply: String, // String wegen u128
    /// Network ID (genesis hash) - required for PoW seed computation via mint_pow_seed_v2 on active emission rounds.
    /// Network-ID (Genesis-Hash) - erforderlich für die PoW-Seed-Berechnung via mint_pow_seed_v2 auf aktiven Emissionsrunden.
    pub network_id: String, // Hex-String (32 bytes)
    /// Active local mint round phase.
    pub phase: MintRoundPhase,
    /// Deterministic mint round id for the currently open emission round.
    pub round_id: String,
    /// Frozen hit bucket once the round entered collecting.
    pub hit_bucket: Option<u64>,
    /// Difficulty committed into a collecting round.
    pub bits_used: Option<u8>,
    /// Bucket when the 5s collection window closes.
    pub collect_deadline_bucket: Option<u64>,
    /// Hard deadline after which the collecting round expires.
    pub finalize_deadline_bucket: Option<u64>,
}

/// Mint status response: provides information about the current mint status.
/// Mint Status Response: Gibt Auskunft über aktuellen Mint-Status.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MintStatus {
    /// Last known mint hash.
    /// Letzter bekannter Mint-Hash.
    pub last_mint_id: String, // Hex-String
    /// Current mint height.
    /// Aktuelle Mint-Höhe.
    pub mint_height: u64,
    /// Current total supply in units.
    /// Aktueller Total Supply in Einheiten.
    pub total_supply: String, // String wegen u128
    /// Remaining supply until hard cap.
    /// Verbleibende Supply bis Hardcap.
    pub remaining_supply: String, // String wegen u128
    /// Hard cap in units.
    /// Hardcap in Einheiten.
    pub hard_cap: String, // String wegen u128
    /// Next expected reward.
    /// Nächster erwarteter Reward.
    pub next_reward: u64,
    /// Whether further minting can take place.
    /// Kann weiteres Minting stattfinden?
    pub can_mint: bool,
    /// Current target difficulty.
    /// Aktuelle Target-Difficulty.
    pub target_bits: u8,
    /// Active local mint round phase.
    pub phase: MintRoundPhase,
    /// Deterministic mint round id for the currently open emission round.
    pub round_id: String,
    /// Current final emission bucket reference.
    pub last_final_emission_bucket: u64,
    /// Frozen hit bucket once the round entered collecting.
    pub hit_bucket: Option<u64>,
    /// Difficulty committed into a collecting round.
    pub bits_used: Option<u8>,
    /// Bucket when the 5s collection window closes.
    pub collect_deadline_bucket: Option<u64>,
    /// Hard deadline after which the collecting round expires.
    pub finalize_deadline_bucket: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintRoundPhase {
    Searching,
    Collecting,
}

/// Submit mint solution request.
/// Submit Mint Solution Request.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SubmitMintRequest {
    /// Full `MintEvent` to submit.
    /// Vollständiges MintEvent zum Einreichen.
    pub mint: MintEventJson,
}

/// JSON-friendly `MintEvent` representation.
/// JSON-freundliche MintEvent Repräsentation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MintEventJson {
    pub version: u8,
    pub prev_mint_id: String, // Hex
    pub outputs: Vec<TxOutJson>,
    pub pow_seed: String, // Hex
    pub pow_nonce: u64,
    pub minted_at: u64,
    pub round_id: Option<String>,
    pub hit_bucket: Option<u64>,
    pub bits_used: Option<u8>,
}

/// JSON-friendly `TxOut` representation.
/// JSON-freundliche TxOut Repräsentation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxOutJson {
    pub amount: u64,
    pub lock: String, // Hex (32 Bytes)
}

/// Submit mint solution response.
/// Submit Mint Solution Response.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SubmitMintResponse {
    /// Success?
    /// Erfolg?
    pub ok: bool,
    /// Mint hash (if successful).
    /// Mint-Hash (falls erfolgreich).
    pub mint_id: Option<String>,
    /// Error message (if not successful).
    /// Fehlermeldung (falls nicht erfolgreich).
    pub error: Option<String>,
}

#[cfg(test)]
mod tests;
