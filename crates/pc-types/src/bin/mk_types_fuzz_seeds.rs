// SPDX-License-Identifier: AGPL-3.0-only
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;

use pc_codec::Encodable;
use pc_types::{
    AnchorHeader as AnchorHeaderV1, AnchorHeaderV2, AnchorId, AnchorPayloadV2 as AnchorPayload,
    EvidenceEvent, EvidenceKind, GenesisNote, GenesisParams, ParentList,
};

fn write_seed(path: PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut f = File::create(&path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // AnchorHeaderV2 seeds
    let hdr_dir = base.join("fuzz/corpus/types_anchor_header_v2");
    {
        // ack_present=false
        let mut buf = Vec::new();
        let h = AnchorHeaderV2::default();
        h.encode(&mut buf)?;
        write_seed(hdr_dir.join("hdr_v2_ack0.bin"), &buf)?;
    }
    {
        // ack_present=true, 1 parent
        let mut parents = ParentList::default();
        let _ = parents.push(AnchorId([0x11; 32]));
        let h = AnchorHeaderV2 {
            version: 2,
            shard_id: 1,
            parents,
            payload_hash: [0x22; 32],
            creator_index: 0,
            vote_mask: 0,
            ack_present: true,
            ack_id: AnchorId([0x33; 32]),
            network_id: [0x44; 32],
            vote_epoch: 0,
            vote_round: 0,
            attest_sig: None,
            state_root: None,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf)?;
        write_seed(hdr_dir.join("hdr_v2_ack1_parent1.bin"), &buf)?;
    }

    // AnchorPayloadV2 seeds
    let pl_dir = base.join("fuzz/corpus/types_anchor_payload_v2");
    {
        // genesis_note=None
        let p = AnchorPayload {
            version: 2,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
        };
        let mut buf = Vec::new();
        p.encode(&mut buf)?;
        write_seed(pl_dir.join("payload_v2_none.bin"), &buf)?;
    }
    {
        // genesis_note=Some(...)
        let note = GenesisNote {
            version: 0,
            network_name: b"fuzznet".to_vec(),
            seed: [1u8; 32],
            params: GenesisParams {
                shards_initial: 1,
                committee_k: 3,
                txs_per_payload: 8,
                features: 0,
            },
            genesis_validators: vec![],
            genesis_message: vec![],
            emission_bootstrap_bucket: 0,
        };
        let p = AnchorPayload {
            version: 2,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [9u8; 32],
            genesis_note: Some(note),
        };
        let mut buf = Vec::new();
        p.encode(&mut buf)?;
        write_seed(pl_dir.join("payload_v2_with_genesis_note.bin"), &buf)?;
    }

    // EvidenceEvent seeds
    let evid_dir = base.join("fuzz/corpus/types_evidence_event");
    {
        // Equivocation
        let mut parents = ParentList::default();
        let _ = parents.push(AnchorId([0x22; 32]));
        let h1 = AnchorHeaderV1 {
            version: 1,
            shard_id: 1,
            parents: parents.clone(),
            payload_hash: [1u8; 32],
            creator_index: 0,
            vote_mask: 1,
            ack_present: false,
            ack_id: AnchorId([0u8; 32]),
        };
        let h2 = AnchorHeaderV1 {
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
        ev.encode(&mut buf)?;
        write_seed(evid_dir.join("evidence_equivocation.bin"), &buf)?;
    }
    {
        // VoteInvalid
        let h = AnchorHeaderV1::default();
        let ev = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::VoteInvalid {
                seat_id: [0x70; 32],
                anchor: h,
                reason_code: 0x1234,
            },
        };
        let mut buf = Vec::new();
        ev.encode(&mut buf)?;
        write_seed(evid_dir.join("evidence_vote_invalid.bin"), &buf)?;
    }
    {
        // ConflictingDAAttest
        let ev = EvidenceEvent {
            version: 1,
            evidence: EvidenceKind::ConflictingDAAttest {
                seat_id: [0xC0; 32],
                anchor_id: AnchorId([0xC1; 32]),
                attest_a: vec![0x01, 0x02, 0x03],
                attest_b: vec![0xFF, 0xEE],
            },
        };
        let mut buf = Vec::new();
        ev.encode(&mut buf)?;
        write_seed(evid_dir.join("evidence_conflicting_da.bin"), &buf)?;
    }
    Ok(())
}
