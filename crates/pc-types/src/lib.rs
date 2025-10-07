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
        }
    }
}
impl Encodable for AnchorHeaderV2 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.shard_id.encode(w)?;
        self.parents.encode(w)?;
        self.payload_hash.encode(w)?;
        self.creator_index.encode(w)?;
        self.vote_mask.encode(w)?;
        self.ack_present.encode(w)?;
        if self.ack_present { self.ack_id.encode(w)?; }
        self.network_id.encode(w)?;
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
        if self.ack_present { n += self.ack_id.encoded_len(); }
        n += self.network_id.encoded_len();
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
        let ack_id = if ack_present { AnchorId::decode(r)? } else { AnchorId([0u8; 32]) };
        let network_id = <[u8; 32]>::decode(r)?;
        Ok(Self { version, shard_id, parents, payload_hash, creator_index, vote_mask, ack_present, ack_id, network_id })
    }
}

impl AnchorHeaderV2 {
    pub fn id_digest(&self) -> Hash32 {
        let mut buf = Vec::with_capacity(self.encoded_len());
        let _ = self.encode(&mut buf);
        blake3_32(&buf)
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
            Some(note) => { true.encode(w)?; note.encode(w)?; }
            None => { false.encode(w)?; }
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
        if let Some(note) = &self.genesis_note { n += note.encoded_len(); }
        n
    }
}
impl Decodable for AnchorPayloadV2 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let version = u8::decode(r)?;
        let micro_txs = Vec::<MicroTx>::decode(r)?;
        let mints = Vec::<MintEvent>::decode(r)?;
        let claims = Vec::<ClaimEvent>::decode(r)?;
        let evidences = Vec::<EvidenceEvent>::decode(r)?;
        let payout_root = <[u8; 32]>::decode(r)?;
        let has_note = bool::decode(r)?;
        let genesis_note = if has_note { Some(GenesisNote::decode(r)?) } else { None };
        Ok(Self { version, micro_txs, mints, claims, evidences, payout_root, genesis_note })
    }
}

/// Berechne den Payload‑Merkle‑Root für V2.
/// Genesis-Sonderfall: Wenn `genesis_note` vorhanden ist, verwende `genesis_payload_root(note)`.
/// Andernfalls analog V1 über alle Kategorien und den payout_root.
pub fn payload_merkle_root_v2(payload: &AnchorPayloadV2) -> Hash32 {
    if let Some(note) = &payload.genesis_note {
        return genesis_payload_root(note);
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
    leaves.push(digest_payout_root(&payload.payout_root));
    leaves.sort_unstable();
    merkle_root_hashes(&leaves)
}


/// Genesis-Leaf-Digest (für A0-Sonderfall): Domain-separierter Hash über kodierte GenesisNote
pub fn digest_genesis_leaf(note: &GenesisNote) -> Hash32 {
    let mut enc = Vec::with_capacity(note.encoded_len());
    let _ = note.encode(&mut enc);
    digest_with_domain(LEAF_GENESIS, &enc)
}

/// A0-Payload-Root: Merkle-Root über genau 1 Leaf (Genesis-Leaf)
pub fn genesis_payload_root(note: &GenesisNote) -> Hash32 {
    let leaf = digest_genesis_leaf(note);
    merkle_root_hashes(&[leaf])
}
// ============================
// Genesis Note (A0)
// ============================
// Domain-Tag für Genesis-Note-Commitment
const GENESIS_NOTE_V1: &[u8] = b"pc:genesis:note:v1\x01";

/// Netzwerk-ID wird als 32-Byte-Hash geführt
pub type NetworkId = Hash32;

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
    pub version: u8,              // 0x00 (v1)
    pub network_name: Vec<u8>,    // UTF-8, <=32 Bytes empfohlen
    pub seed: [u8; 32],
    pub params: GenesisParams,
}
impl Encodable for GenesisNote {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.network_name.encode(w)?; // Vec<u8>
        self.seed.encode(w)?;
        self.params.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + self.network_name.encoded_len()
            + 32
            + self.params.encoded_len()
    }
}
impl Decodable for GenesisNote {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            version: u8::decode(r)?,
            network_name: Vec::<u8>::decode(r)?,
            seed: <[u8; 32]>::decode(r)?,
            params: GenesisParams::decode(r)?,
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

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn rt<T: pc_codec::Encodable + pc_codec::Decodable + core::fmt::Debug + PartialEq>(v: &T) -> T {
        let mut buf = Vec::new();
        v.encode(&mut buf).expect("encode");
        let mut s = &buf[..];
        T::decode(&mut s).expect("decode")
    }

    proptest! {
        #[test]
        fn prop_roundtrip_anchor_payload_empty_lists(payout in any::<[u8;32]>()) {
            let pl = AnchorPayload { version: 1, micro_txs: vec![], mints: vec![], claims: vec![], evidences: vec![], payout_root: payout };
            let got = rt(&pl);
            prop_assert_eq!(pl, got);
        }

        #[test]
        fn prop_roundtrip_anchor_header_basic(
            payload_hash in any::<[u8;32]>(),
            creator in any::<u8>(),
            vote in any::<u64>(),
            ack in any::<[u8;32]>(),
            ack_present in any::<bool>(),
        ) {
            let parents = ParentList::default();
            let ack_id = if ack_present { AnchorId(ack) } else { AnchorId([0u8;32]) };
            let hdr = AnchorHeader { version: 1, shard_id: 0, parents, payload_hash, creator_index: creator, vote_mask: vote, ack_present, ack_id };
            let got = rt(&hdr);
            prop_assert_eq!(hdr, got);
        }

        #[test]
        fn prop_roundtrip_microtx_random(
            version in any::<u8>(),
            ins in proptest::collection::vec((any::<[u8;32]>(), any::<u32>(), proptest::collection::vec(any::<u8>(), 0..64)), 0..4),
            outs in proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..4),
        ) {
            let inputs: Vec<TxIn> = ins.into_iter()
                .map(|(txid, vout, wit)| TxIn { prev_out: OutPoint { txid, vout }, witness: wit })
                .collect();
            let outputs: Vec<TxOut> = outs.into_iter()
                .map(|(amt, lock)| TxOut { amount: amt, lock: LockCommitment(lock) })
                .collect();
            let tx = MicroTx { version, inputs, outputs };
            let got = rt(&tx);
            prop_assert_eq!(tx, got);
        }

        #[test]
        fn prop_roundtrip_mint_random(
            version in any::<u8>(),
            prev_mint_id in any::<[u8;32]>(),
            outs in proptest::collection::vec((any::<u64>(), any::<[u8;32]>()), 0..4),
            pow_seed in any::<[u8;32]>(),
            pow_nonce in any::<u64>(),
        ) {
            let outputs: Vec<TxOut> = outs.into_iter()
                .map(|(amt, lock)| TxOut { amount: amt, lock: LockCommitment(lock) })
                .collect();
            let m = MintEvent { version, prev_mint_id, outputs, pow_seed, pow_nonce };
            let got = rt(&m);
            prop_assert_eq!(m, got);
        }
    }
}
// Domain‑Tags für Leaf‑Digests (Modulebene)
const LEAF_MICROTX: &[u8] = b"pc:leaf:microtx:v1\x01";
const LEAF_MINT: &[u8] = b"pc:leaf:mint:v1\x01";
const LEAF_CLAIM: &[u8] = b"pc:leaf:claim:v1\x01";
const LEAF_EVID: &[u8] = b"pc:leaf:evidence:v1\x01";
const LEAF_PAYOUT_ROOT: &[u8] = b"pc:leaf:payout_root:v1\x01";
const LEAF_GENESIS: &[u8] = b"pc:leaf:genesis_note:v1\x01";

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(domain.len() + bytes.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(bytes);
    blake3_32(&buf)
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

pub fn digest_payout_root(root: &Hash32) -> Hash32 {
    let mut data = Vec::with_capacity(LEAF_PAYOUT_ROOT.len() + 32);
    data.extend_from_slice(LEAF_PAYOUT_ROOT);
    data.extend_from_slice(root);
    blake3_32(&data)
}

/// Berechne den Payload‑Merkle‑Root deterministisch (ordnungunabhängig innerhalb der Kategorien)
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
    leaves.sort_unstable();
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
        Ok(Self {
            version: u8::decode(r)?,
            micro_txs: Vec::<MicroTx>::decode(r)?,
            mints: Vec::<MintEvent>::decode(r)?,
            claims: Vec::<ClaimEvent>::decode(r)?,
            evidences: Vec::<EvidenceEvent>::decode(r)?,
            payout_root: <[u8; 32]>::decode(r)?,
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
    /// Liefert eine normalisierte, deterministisch sortierte Liste: nach recipient_id aufsteigend, Duplikate zusammengefasst (summiert).
    pub fn normalized_entries(&self) -> Vec<PayoutEntry> {
        let mut v = self.entries.clone();
        // sortiere nach recipient_id
        v.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
        // merge gleiche Empfänger
        let mut merged: Vec<PayoutEntry> = Vec::with_capacity(v.len());
        for e in v.into_iter() {
            if let Some(last) = merged.last_mut() {
                if last.recipient_id == e.recipient_id {
                    // Summe mit Overflow‑Schutz
                    let (sum, of) = last.amount.overflowing_add(e.amount);
                    if !of {
                        last.amount = sum;
                    } else {
                        // Bei Overflow: saturieren (produktionsreifere Variante wäre ein Fehler)
                        last.amount = u64::MAX;
                    }
                    continue;
                }
            }
            merged.push(e);
        }
        merged
    }

    /// Merkle‑Root über payout leaves (domain‑getrennt). Leere Menge → 0x00..00
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
        Ok(Self {
            entries: Vec::<PayoutEntry>::decode(r)?,
        })
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
        // encode deterministisch; Schreiben in Vec<u8> kann nicht fehlschlagen.
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

pub type Amount = u64; // kleinste Einheit (z. B. 1e-8 PC)
/// Globaler, monotoner Anchor-Index (uhrfrei). Dient u. a. für Maturity-Stufen.
pub type AnchorIndex = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
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
        Ok(Self {
            prev_out: OutPoint::decode(r)?,
            witness: Vec::<u8>::decode(r)?,
        })
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
        Ok(Self {
            version: u8::decode(r)?,
            inputs: Vec::<TxIn>::decode(r)?,
            outputs: Vec::<TxOut>::decode(r)?,
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
}
impl Encodable for MintEvent {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.prev_mint_id.encode(w)?;
        self.outputs.encode(w)?;
        self.pow_seed.encode(w)?;
        self.pow_nonce.encode(w)?;
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.version.encoded_len()
            + 32
            + self.outputs.encoded_len()
            + 32
            + self.pow_nonce.encoded_len()
    }
}
impl Decodable for MintEvent {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            version: u8::decode(r)?,
            prev_mint_id: <[u8; 32]>::decode(r)?,
            outputs: Vec::<TxOut>::decode(r)?,
            pow_seed: <[u8; 32]>::decode(r)?,
            pow_nonce: u64::decode(r)?,
        })
    }
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
        Ok(Self {
            version: u8::decode(r)?,
            anchor_id: AnchorId::decode(r)?,
            recipient_id: <[u8; 32]>::decode(r)?,
            amount: u64::decode(r)?,
            merkle_proof: Vec::<[u8; 32]>::decode(r)?,
            payout_lock: LockCommitment::decode(r)?,
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
        }
    }
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
            3 => Ok(EvidenceKind::ConflictingDAAttest {
                seat_id: <[u8; 32]>::decode(r)?,
                anchor_id: AnchorId::decode(r)?,
                attest_a: Vec::<u8>::decode(r)?,
                attest_b: Vec::<u8>::decode(r)?,
            }),
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
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err("too many inputs");
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err("too many outputs");
    }
    for tin in &tx.inputs {
        if tin.witness.len() > MAX_WITNESS_BYTES {
            return Err("witness too large");
        }
    }
    Ok(())
}

pub fn validate_mint_sanity(m: &MintEvent) -> Result<(), &'static str> {
    if m.outputs.len() > MAX_MINT_OUTPUTS {
        return Err("too many mint outputs");
    }
    Ok(())
}

pub fn validate_payload_sanity(p: &AnchorPayload) -> Result<(), &'static str> {
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
    Ok(())
}

/// Sanity-Checks für AnchorPayloadV2 (analog V1; genesis_note wird nicht validiert)
pub fn validate_payload_sanity_v2(p: &AnchorPayloadV2) -> Result<(), &'static str> {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut parents = ParentList::default();
        parents.push(AnchorId([1u8; 32])).unwrap();
        let h = AnchorHeader {
            version: 1,
            shard_id: 7,
            parents,
            payload_hash: [2u8; 32],
            creator_index: 5,
            vote_mask: 0xABCD,
            ack_present: true,
            ack_id: AnchorId([3u8; 32]),
        };
        let mut buf = Vec::new();
        h.encode(&mut buf).unwrap();
        let got = AnchorHeader::decode(&mut &buf[..]).unwrap();
        assert_eq!(h, got);
        let id = h.id_digest();
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn tx_roundtrip() {
        let op = OutPoint {
            txid: [9u8; 32],
            vout: 1,
        };
        let txin = TxIn {
            prev_out: op,
            witness: vec![1, 2, 3],
        };
        let txout = TxOut {
            amount: 123,
            lock: LockCommitment([7u8; 32]),
        };
        let tx = MicroTx {
            version: 1,
            inputs: vec![txin],
            outputs: vec![txout],
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).unwrap();
        let got = MicroTx::decode(&mut &buf[..]).unwrap();
        assert_eq!(tx, got);
    }

    #[test]
    fn mint_roundtrip() {
        let txout = TxOut {
            amount: 42,
            lock: LockCommitment([1u8; 32]),
        };
        let m = MintEvent {
            version: 1,
            prev_mint_id: [0u8; 32],
            outputs: vec![txout],
            pow_seed: [2u8; 32],
            pow_nonce: 12345,
        };
        let mut buf = Vec::new();
        m.encode(&mut buf).unwrap();
        let got = MintEvent::decode(&mut &buf[..]).unwrap();
        assert_eq!(m, got);
    }

    #[test]
    fn claim_roundtrip() {
        let c = ClaimEvent {
            version: 1,
            anchor_id: AnchorId([3u8; 32]),
            recipient_id: [4u8; 32],
            amount: 999,
            merkle_proof: vec![[5u8; 32], [6u8; 32]],
            payout_lock: LockCommitment([7u8; 32]),
        };
        let mut buf = Vec::new();
        c.encode(&mut buf).unwrap();
        let got = ClaimEvent::decode(&mut &buf[..]).unwrap();
        assert_eq!(c, got);
    }

    #[test]
    fn evidence_roundtrip() {
        let mut parents = ParentList::default();
        parents.push(AnchorId([8u8; 32])).unwrap();
        let h1 = AnchorHeader {
            version: 1,
            shard_id: 1,
            parents: parents.clone(),
            payload_hash: [1u8; 32],
            creator_index: 0,
            vote_mask: 1,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
        };
        let h2 = AnchorHeader {
            version: 1,
            shard_id: 1,
            parents,
            payload_hash: [2u8; 32],
            creator_index: 0,
            vote_mask: 2,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
        };
        let ev = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::Equivocation {
                seat_id: [9u8; 32],
                epoch_id: 10,
                a: h1,
                b: Box::new(h2),
            },
        };
        let mut buf = Vec::new();
        ev.encode(&mut buf).unwrap();
        let got = EvidenceEvent::decode(&mut &buf[..]).unwrap();
        assert_eq!(format!("{:?}", ev), format!("{:?}", got));
    }

    #[test]
    fn payout_merkle() {
        let set = PayoutSet {
            entries: vec![
                PayoutEntry {
                    recipient_id: [2u8; 32],
                    amount: 10,
                },
                PayoutEntry {
                    recipient_id: [1u8; 32],
                    amount: 1,
                },
                PayoutEntry {
                    recipient_id: [2u8; 32],
                    amount: 5,
                }, // wird zusammengeführt
            ],
        };
        // Root ist deterministisch unabhängig von Eingabereihenfolge
        let r1 = set.payout_root();
        // Neu sortierte/vereinheitlichte Entries manuell prüfen
        let entries_sorted = set.normalized_entries();
        assert_eq!(entries_sorted.len(), 2);
        assert_eq!(entries_sorted[0].recipient_id, [1u8; 32]);
        assert_eq!(entries_sorted[0].amount, 1);
        assert_eq!(entries_sorted[1].recipient_id, [2u8; 32]);
        assert_eq!(entries_sorted[1].amount, 15);
        // Rebuild root aus normalized_entries
        let leaves: Vec<Hash32> = entries_sorted
            .iter()
            .map(|e| payout_leaf_hash(&e.recipient_id, e.amount))
            .collect();
        let r2 = merkle_root_hashes(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn payload_roundtrip() {
        let txin = TxIn {
            prev_out: OutPoint {
                txid: [1u8; 32],
                vout: 0,
            },
            witness: vec![7, 8],
        };
        let txout = TxOut {
            amount: 12345,
            lock: LockCommitment([9u8; 32]),
        };
        let tx = MicroTx {
            version: 1,
            inputs: vec![txin],
            outputs: vec![txout],
        };

        let mint_out = TxOut {
            amount: 5,
            lock: LockCommitment([3u8; 32]),
        };
        let mint = MintEvent {
            version: 1,
            prev_mint_id: [2u8; 32],
            outputs: vec![mint_out],
            pow_seed: [4u8; 32],
            pow_nonce: 42,
        };

        let claim = ClaimEvent {
            version: 1,
            anchor_id: AnchorId([5u8; 32]),
            recipient_id: [6u8; 32],
            amount: 77,
            merkle_proof: vec![[7u8; 32]],
            payout_lock: LockCommitment([8u8; 32]),
        };

        let ev = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::VoteInvalid {
                seat_id: [10u8; 32],
                anchor: AnchorHeader::default(),
                reason_code: 13,
            },
        };

        let set = PayoutSet {
            entries: vec![
                PayoutEntry {
                    recipient_id: [11u8; 32],
                    amount: 1,
                },
                PayoutEntry {
                    recipient_id: [12u8; 32],
                    amount: 2,
                },
            ],
        };
        let pr = set.payout_root();

        let p = AnchorPayload {
            version: 1,
            micro_txs: vec![tx],
            mints: vec![mint],
            claims: vec![claim],
            evidences: vec![ev],
            payout_root: pr,
        };

        let mut buf = Vec::new();
        p.encode(&mut buf).unwrap();
        let got = AnchorPayload::decode(&mut &buf[..]).unwrap();
        assert_eq!(p, got);
    }

    #[test]
    fn payload_merkle_root_order_invariance_full() {
        // Baue Elemente in bestimmter Reihenfolge
        let mk_tx = |n: u8| MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut { amount: n as u64, lock: LockCommitment([n; 32]) }],
        };
        let mk_mint = |n: u8| MintEvent {
            version: 1,
            prev_mint_id: [n; 32],
            outputs: vec![TxOut { amount: (n as u64) * 10, lock: LockCommitment([n.wrapping_add(1); 32]) }],
            pow_seed: [n.wrapping_add(2); 32],
            pow_nonce: (n as u64) * 100,
        };
        let mk_claim = |n: u8| ClaimEvent {
            version: 1,
            anchor_id: AnchorId([n; 32]),
            recipient_id: [n.wrapping_add(1); 32],
            amount: (n as u64) * 3,
            merkle_proof: vec![[n.wrapping_add(2); 32]],
            payout_lock: LockCommitment([n.wrapping_add(3); 32]),
        };
        let mk_evid = |n: u8| EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::VoteInvalid { seat_id: [n; 32], anchor: AnchorHeader::default(), reason_code: n as u16 },
        };

        let pr = PayoutSet { entries: vec![ PayoutEntry{ recipient_id: [0x21;32], amount: 1000 }, PayoutEntry{ recipient_id: [0x10;32], amount: 500 } ] }.payout_root();

        let p1 = AnchorPayload {
            version: 1,
            micro_txs: vec![mk_tx(3), mk_tx(1)],
            mints: vec![mk_mint(7), mk_mint(5)],
            claims: vec![mk_claim(9), mk_claim(2)],
            evidences: vec![mk_evid(4), mk_evid(8)],
            payout_root: pr,
        };
        // Permutiere die Reihenfolge in jeder Kategorie
        let p2 = AnchorPayload {
            version: 1,
            micro_txs: vec![p1.micro_txs[1].clone(), p1.micro_txs[0].clone()],
            mints: vec![p1.mints[1].clone(), p1.mints[0].clone()],
            claims: vec![p1.claims[1].clone(), p1.claims[0].clone()],
            evidences: vec![p1.evidences[1].clone(), p1.evidences[0].clone()],
            payout_root: p1.payout_root,
        };
        assert_eq!(payload_merkle_root(&p1), payload_merkle_root(&p2));
    }

    #[test]
    #[ignore]
    fn dump_stable_hash_vectors() {
        // Mikro‑Tx
        let tx = MicroTx { version:1, inputs: vec![], outputs: vec![TxOut{ amount: 12345, lock: LockCommitment([9u8;32]) }] };
        let tx_h = digest_microtx(&tx);
        println!("MICROTX_DIGEST={}", hex::encode(tx_h));

        // Mint
        let mint = MintEvent { version:1, prev_mint_id: [0xAA;32], outputs: vec![TxOut{ amount: 42, lock: LockCommitment([0x55;32]) }], pow_seed: [0x11;32], pow_nonce: 987654321 };
        let mint_h = digest_mint(&mint);
        println!("MINT_DIGEST={}", hex::encode(mint_h));

        // Claim
        let claim = ClaimEvent { version:1, anchor_id: AnchorId([0x01;32]), recipient_id: [0x02;32], amount: 777, merkle_proof: vec![[0x03;32],[0x04;32]], payout_lock: LockCommitment([0x05;32]) };
        let claim_h = digest_claim(&claim);
        println!("CLAIM_DIGEST={}", hex::encode(claim_h));

        // Evidence (VoteInvalid)
        let header = AnchorHeader { version:1, shard_id: 2, parents: ParentList::default(), payload_hash: [0x10;32], creator_index: 3, vote_mask: 0xABCDEF, ack_present: false, ack_id: AnchorId([0u8;32]) };
        let evid = EvidenceEvent { version:1, evidence: EvidenceKind::VoteInvalid { seat_id: [0x07;32], anchor: header, reason_code: 0x99 } };
        let evid_h = digest_evidence(&evid);
        println!("EVIDENCE_DIGEST={}", hex::encode(evid_h));

        // Payload Root (mit deterministischer PayoutRoot)
        let payout = PayoutSet { entries: vec![ PayoutEntry{ recipient_id: [0x21;32], amount: 1000 }, PayoutEntry{ recipient_id: [0x10;32], amount: 500 } ] };
        let payload = AnchorPayload { version:1, micro_txs: vec![tx.clone()], mints: vec![mint.clone()], claims: vec![claim.clone()], evidences: vec![evid.clone()], payout_root: payout.payout_root() };
        let pl_root = payload_merkle_root(&payload);
        println!("PAYLOAD_ROOT={}", hex::encode(pl_root));

        // Header ID
        let mut parents = ParentList::default();
        parents.push(AnchorId([0x22;32])).unwrap();
        let hdr = AnchorHeader { version:1, shard_id: 9, parents, payload_hash: pl_root, creator_index: 4, vote_mask: 0x55AA, ack_present: true, ack_id: AnchorId([0x77;32]) };
        let hid = hdr.id_digest();
        println!("HEADER_ID={}", hex::encode(hid));
    }

    #[test]
    fn stable_hash_vectors_golden() {
        // Repliziere dieselben Objekte wie im Dump-Test und verifiziere die erwarteten Hashes
        let tx = MicroTx { version:1, inputs: vec![], outputs: vec![TxOut{ amount: 12345, lock: LockCommitment([9u8;32]) }] };
        let tx_h = digest_microtx(&tx);
        assert_eq!(hex::encode(tx_h), "1f701e879ce87e53d835dbf6ac42a51e2204135f664152749a51db4172872e73");

        let mint = MintEvent { version:1, prev_mint_id: [0xAA;32], outputs: vec![TxOut{ amount: 42, lock: LockCommitment([0x55;32]) }], pow_seed: [0x11;32], pow_nonce: 987654321 };
        let mint_h = digest_mint(&mint);
        assert_eq!(hex::encode(mint_h), "08d15620dc06558b18c7a175ed7613ebabe2b79329fc05ffa6860386137861f2");

        let claim = ClaimEvent { version:1, anchor_id: AnchorId([0x01;32]), recipient_id: [0x02;32], amount: 777, merkle_proof: vec![[0x03;32],[0x04;32]], payout_lock: LockCommitment([0x05;32]) };
        let claim_h = digest_claim(&claim);
        assert_eq!(hex::encode(claim_h), "ff1d41d529269c7aeea43b664ec7b674eae08ab97f7cc65976853d5b5aa3aea8");

        let header = AnchorHeader { version:1, shard_id: 2, parents: ParentList::default(), payload_hash: [0x10;32], creator_index: 3, vote_mask: 0xABCDEF, ack_present: false, ack_id: AnchorId([0u8;32]) };
        let evid = EvidenceEvent { version:1, evidence: EvidenceKind::VoteInvalid { seat_id: [0x07;32], anchor: header, reason_code: 0x99 } };
        let evid_h = digest_evidence(&evid);
        assert_eq!(hex::encode(evid_h), "78221b1ec5446d85ce9c7046d77033e4c9d9e6078cf8bd6fdf27c16b676db9e6");

        let payout = PayoutSet { entries: vec![ PayoutEntry{ recipient_id: [0x21;32], amount: 1000 }, PayoutEntry{ recipient_id: [0x10;32], amount: 500 } ] };
        let payload = AnchorPayload { version:1, micro_txs: vec![tx.clone()], mints: vec![mint.clone()], claims: vec![claim.clone()], evidences: vec![evid.clone()], payout_root: payout.payout_root() };
        let pl_root = payload_merkle_root(&payload);
        assert_eq!(hex::encode(pl_root), "2b6cdafd1cba1ecf772c93135af43d5e6d8b0efde30be0a2504a9b85f769d0ba");

        let mut parents = ParentList::default();
        parents.push(AnchorId([0x22;32])).unwrap();
        let hdr = AnchorHeader { version:1, shard_id: 9, parents, payload_hash: pl_root, creator_index: 4, vote_mask: 0x55AA, ack_present: true, ack_id: AnchorId([0x77;32]) };
        let hid = hdr.id_digest();
        assert_eq!(hex::encode(hid), "43e6762a4560e36c7528e6e85def46d5e1aa068eb44362b21e36691628cf7d91");
    }

    #[test]
    fn parent_list_decode_len_overflow_fails() {
        // Baue Buffer mit len=MAX_PARENTS+1 und prüfe, dass decode fehlschlägt
        let mut buf = Vec::new();
        let over_len = (MAX_PARENTS as u8).saturating_add(1);
        buf.push(over_len); // len
        // keine ids anhängen, sollte bereits an len scheitern
        let res = ParentList::decode(&mut &buf[..]);
        assert!(res.is_err());
    }

    #[test]
    fn evidence_invalid_tag_fails_decode() {
        // Tag=99 (ungültig), danach keine weiteren Felder
        let mut buf = Vec::new();
        buf.push(99u8);
        let res = EvidenceKind::decode(&mut &buf[..]);
        assert!(res.is_err());
    }

    #[test]
    fn encoded_len_matches_buffer_sizes() {
        // MicroTx
        let tx = MicroTx { version:1, inputs: vec![], outputs: vec![TxOut{ amount: 1, lock: LockCommitment([0x01;32]) }] };
        let mut buf_tx = Vec::new();
        tx.encode(&mut buf_tx).unwrap();
        assert_eq!(tx.encoded_len(), buf_tx.len());

        // AnchorHeader mit ack_present=false
        let hdr = AnchorHeader { version:1, shard_id: 1, parents: ParentList::default(), payload_hash: [0x99;32], creator_index: 2, vote_mask: 3, ack_present: false, ack_id: AnchorId([0u8;32]) };
        let mut buf_h = Vec::new();
        hdr.encode(&mut buf_h).unwrap();
        assert_eq!(hdr.encoded_len(), buf_h.len());

        // AnchorHeader mit ack_present=true (inkl. ack_id)
        let mut parents = ParentList::default();
        parents.push(AnchorId([0x22;32])).unwrap();
        let hdr2 = AnchorHeader { version:1, shard_id: 7, parents, payload_hash: [0x10;32], creator_index: 4, vote_mask: 0x55AA, ack_present: true, ack_id: AnchorId([0x77;32]) };
        let mut buf_h2 = Vec::new();
        hdr2.encode(&mut buf_h2).unwrap();
        assert_eq!(hdr2.encoded_len(), buf_h2.len());
    }

    #[test]
    #[ignore]
    fn header_encode_example_bytes() {
        // Beispiel-Header für SPEC_CODEC.md
        // version=1, shard_id=0x1234, parents: len=2 ([AA..AA], [BB..BB]),
        // payload_hash=[11..11], creator_index=5, vote_mask=300 (varint AC 02),
        // ack_present=true, ack_id=[CC..CC]
        let mut parents = ParentList::default();
        parents.push(AnchorId([0xAA; 32])).unwrap();
        parents.push(AnchorId([0xBB; 32])).unwrap();
        let hdr = AnchorHeader {
            version: 1,
            shard_id: 0x1234,
            parents,
            payload_hash: [0x11; 32],
            creator_index: 5,
            vote_mask: 300,
            ack_present: true,
            ack_id: AnchorId([0xCC; 32]),
        };
        let mut buf = Vec::new();
        hdr.encode(&mut buf).unwrap();
        println!("HEADER_EXAMPLE_BYTES={}", hex::encode(buf));
    }

    #[test]
    #[ignore]
    fn anchor_payload_encode_example_bytes() {
        // Beispiel-Payload mit je 1 Element pro Kategorie und fixem payout_root
        let tx = MicroTx {
            version: 1,
            inputs: vec![TxIn { prev_out: OutPoint { txid: [0x10;32], vout: 1 }, witness: vec![0xAA, 0xBB] }],
            outputs: vec![TxOut { amount: 1234, lock: LockCommitment([0x20;32]) }],
        };
        let mint = MintEvent {
            version: 1,
            prev_mint_id: [0x30;32],
            outputs: vec![TxOut { amount: 55, lock: LockCommitment([0x40;32]) }],
            pow_seed: [0x50;32],
            pow_nonce: 777,
        };
        let claim = ClaimEvent {
            version: 1,
            anchor_id: AnchorId([0x60;32]),
            recipient_id: [0x61;32],
            amount: 222,
            merkle_proof: vec![[0x62;32], [0x63;32]],
            payout_lock: LockCommitment([0x64;32]),
        };
        let evid = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::VoteInvalid { seat_id: [0x70;32], anchor: AnchorHeader::default(), reason_code: 0x1234 },
        };
        let payout = PayoutSet { entries: vec![ PayoutEntry { recipient_id: [0x80;32], amount: 1 } ] };
        let p = AnchorPayload { version:1, micro_txs: vec![tx], mints: vec![mint], claims: vec![claim], evidences: vec![evid], payout_root: payout.payout_root() };
        let mut buf = Vec::new();
        p.encode(&mut buf).unwrap();
        println!("ANCHOR_PAYLOAD_EXAMPLE_BYTES={}", hex::encode(buf));
    }

    #[test]
    #[ignore]
    fn evidence_kinds_encode_example_bytes() {
        // Equivocation
        let ev_eq = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::Equivocation {
                seat_id: [0xA0; 32],
                epoch_id: 42,
                a: AnchorHeader::default(),
                b: Box::new(AnchorHeader::default()),
            },
        };
        let mut buf = Vec::new();
        ev_eq.encode(&mut buf).unwrap();
        println!("EVIDENCE_EQUIVOCATION_BYTES={}", hex::encode(&buf));

        // VoteInvalid
        let ev_vi = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::VoteInvalid {
                seat_id: [0xB0; 32],
                anchor: AnchorHeader::default(),
                reason_code: 0xCAFE,
            },
        };
        buf.clear();
        ev_vi.encode(&mut buf).unwrap();
        println!("EVIDENCE_VOTE_INVALID_BYTES={}", hex::encode(&buf));

        // ConflictingDAAttest
        let ev_da = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::ConflictingDAAttest {
                seat_id: [0xC0; 32],
                anchor_id: AnchorId([0xC1;32]),
                attest_a: vec![0x01, 0x02, 0x03],
                attest_b: vec![0xFF, 0xEE],
            },
        };
        buf.clear();
        ev_da.encode(&mut buf).unwrap();
        println!("EVIDENCE_CONFLICTING_DA_BYTES={}", hex::encode(&buf));
    }
}
