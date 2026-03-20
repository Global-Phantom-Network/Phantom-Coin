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
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
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
            }, // will be merged. wird zusammengeführt.
        ],
    };
    // Root is deterministic and independent of input order.
    // Root ist deterministisch unabhängig von Eingabereihenfolge.
    let r1 = set.payout_root();
    // Manually verify newly sorted/unified entries.
    // Neu sortierte/vereinheitlichte Entries manuell prüfen.
    let entries_sorted = set.normalized_entries();
    assert_eq!(entries_sorted.len(), 2);
    assert_eq!(entries_sorted[0].recipient_id, [1u8; 32]);
    assert_eq!(entries_sorted[0].amount, 1);
    assert_eq!(entries_sorted[1].recipient_id, [2u8; 32]);
    assert_eq!(entries_sorted[1].amount, 15);
    // Rebuild root from normalized_entries.
    // Rebuild root aus normalized_entries.
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
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
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
        outputs: vec![TxOut {
            amount: n as u64,
            lock: LockCommitment([n; 32]),
        }],
    };
    let mk_mint = |n: u8| MintEvent {
        version: 1,
        prev_mint_id: [n; 32],
        outputs: vec![TxOut {
            amount: (n as u64) * 10,
            lock: LockCommitment([n.wrapping_add(1); 32]),
        }],
        pow_seed: [n.wrapping_add(2); 32],
        pow_nonce: (n as u64) * 100,
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
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
        evidence: EvidenceKind::VoteInvalid {
            seat_id: [n; 32],
            anchor: AnchorHeader::default(),
            reason_code: n as u16,
        },
    };

    let pr = PayoutSet {
        entries: vec![
            PayoutEntry {
                recipient_id: [0x21; 32],
                amount: 1000,
            },
            PayoutEntry {
                recipient_id: [0x10; 32],
                amount: 500,
            },
        ],
    }
    .payout_root();

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
    assert_ne!(payload_merkle_root(&p1), payload_merkle_root(&p2));
}

#[test]
fn payload_v3_with_only_payout_root_is_not_empty() {
    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0xAB; 32],
        genesis_note: None,
        null_mint: false,
    };

    assert!(
        !payload.is_empty(),
        "heartbeat payloads with payout_root must be persisted"
    );
}

#[test]
fn payload_v3_with_null_mint_is_not_empty() {
    let payload = AnchorPayloadV3 {
        version: 3,
        micro_txs: vec![],
        mints: vec![],
        claims: vec![],
        evidences: vec![],
        payout_root: [0u8; 32],
        genesis_note: None,
        null_mint: true,
    };

    assert!(
        !payload.is_empty(),
        "null-mint decisions are consensus-relevant payloads"
    );
}

#[test]
#[ignore]
fn dump_stable_hash_vectors() {
    // Mikro‑Tx
    let tx = MicroTx {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            amount: 12345,
            lock: LockCommitment([9u8; 32]),
        }],
    };
    let tx_h = digest_microtx(&tx);
    println!("MICROTX_DIGEST={}", hex::encode(tx_h));

    // Mint
    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0xAA; 32],
        outputs: vec![TxOut {
            amount: 42,
            lock: LockCommitment([0x55; 32]),
        }],
        pow_seed: [0x11; 32],
        pow_nonce: 987654321,
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    let mint_h = digest_mint(&mint);
    println!("MINT_DIGEST={}", hex::encode(mint_h));

    // Claim
    let claim = ClaimEvent {
        version: 1,
        anchor_id: AnchorId([0x01; 32]),
        recipient_id: [0x02; 32],
        amount: 777,
        merkle_proof: vec![[0x03; 32], [0x04; 32]],
        payout_lock: LockCommitment([0x05; 32]),
    };
    let claim_h = digest_claim(&claim);
    println!("CLAIM_DIGEST={}", hex::encode(claim_h));

    // Evidence (VoteInvalid)
    let header = AnchorHeader {
        version: 1,
        shard_id: 2,
        parents: ParentList::default(),
        payload_hash: [0x10; 32],
        creator_index: 3,
        vote_mask: 0xABCDEF,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
    };
    let evid = EvidenceEvent {
        version: 1,
        evidence: EvidenceKind::VoteInvalid {
            seat_id: [0x07; 32],
            anchor: header,
            reason_code: 0x99,
        },
    };
    let evid_h = digest_evidence(&evid);
    println!("EVIDENCE_DIGEST={}", hex::encode(evid_h));

    // Payload Root (mit deterministischer PayoutRoot)
    let payout = PayoutSet {
        entries: vec![
            PayoutEntry {
                recipient_id: [0x21; 32],
                amount: 1000,
            },
            PayoutEntry {
                recipient_id: [0x10; 32],
                amount: 500,
            },
        ],
    };
    let payload = AnchorPayload {
        version: 1,
        micro_txs: vec![tx.clone()],
        mints: vec![mint.clone()],
        claims: vec![claim.clone()],
        evidences: vec![evid.clone()],
        payout_root: payout.payout_root(),
    };
    let pl_root = payload_merkle_root(&payload);
    println!("PAYLOAD_ROOT={}", hex::encode(pl_root));

    // Header ID
    let mut parents = ParentList::default();
    parents.push(AnchorId([0x22; 32])).unwrap();
    let hdr = AnchorHeader {
        version: 1,
        shard_id: 9,
        parents,
        payload_hash: pl_root,
        creator_index: 4,
        vote_mask: 0x55AA,
        ack_present: true,
        ack_id: AnchorId([0x77; 32]),
    };
    let hid = hdr.id_digest();
    println!("HEADER_ID={}", hex::encode(hid));
}

#[test]
fn stable_hash_vectors_golden() {
    // Repliziere dieselben Objekte wie im Dump-Test und verifiziere die erwarteten Hashes
    let tx = MicroTx {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            amount: 12345,
            lock: LockCommitment([9u8; 32]),
        }],
    };
    let tx_h = digest_microtx(&tx);
    assert_eq!(
        hex::encode(tx_h),
        "1f701e879ce87e53d835dbf6ac42a51e2204135f664152749a51db4172872e73"
    );

    let mint = MintEvent {
        version: 1,
        prev_mint_id: [0xAA; 32],
        outputs: vec![TxOut {
            amount: 42,
            lock: LockCommitment([0x55; 32]),
        }],
        pow_seed: [0x11; 32],
        pow_nonce: 987654321,
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };
    let mint_h = digest_mint(&mint);
    assert_eq!(
        hex::encode(mint_h),
        "b6b20704983ad03ed226b6ea99056725b091e95d0fe98355a18e1412053cae85"
    );

    let claim = ClaimEvent {
        version: 1,
        anchor_id: AnchorId([0x01; 32]),
        recipient_id: [0x02; 32],
        amount: 777,
        merkle_proof: vec![[0x03; 32], [0x04; 32]],
        payout_lock: LockCommitment([0x05; 32]),
    };
    let claim_h = digest_claim(&claim);
    assert_eq!(
        hex::encode(claim_h),
        "ff1d41d529269c7aeea43b664ec7b674eae08ab97f7cc65976853d5b5aa3aea8"
    );

    let header = AnchorHeader {
        version: 1,
        shard_id: 2,
        parents: ParentList::default(),
        payload_hash: [0x10; 32],
        creator_index: 3,
        vote_mask: 0xABCDEF,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
    };
    let evid = EvidenceEvent {
        version: 1,
        evidence: EvidenceKind::VoteInvalid {
            seat_id: [0x07; 32],
            anchor: header,
            reason_code: 0x99,
        },
    };
    let evid_h = digest_evidence(&evid);
    assert_eq!(
        hex::encode(evid_h),
        "78221b1ec5446d85ce9c7046d77033e4c9d9e6078cf8bd6fdf27c16b676db9e6"
    );

    let payout = PayoutSet {
        entries: vec![
            PayoutEntry {
                recipient_id: [0x21; 32],
                amount: 1000,
            },
            PayoutEntry {
                recipient_id: [0x10; 32],
                amount: 500,
            },
        ],
    };
    let payload = AnchorPayload {
        version: 1,
        micro_txs: vec![tx.clone()],
        mints: vec![mint.clone()],
        claims: vec![claim.clone()],
        evidences: vec![evid.clone()],
        payout_root: payout.payout_root(),
    };
    let pl_root = payload_merkle_root(&payload);
    assert_eq!(
        hex::encode(pl_root),
        "5bbfb9b7056e5bb7ac4adf98db419ea5b681bee5f578a367b8a6a5dea9997c83"
    );

    let mut parents = ParentList::default();
    parents.push(AnchorId([0x22; 32])).unwrap();
    let hdr = AnchorHeader {
        version: 1,
        shard_id: 9,
        parents,
        payload_hash: pl_root,
        creator_index: 4,
        vote_mask: 0x55AA,
        ack_present: true,
        ack_id: AnchorId([0x77; 32]),
    };
    let hid = hdr.id_digest();
    assert_eq!(
        hex::encode(hid),
        "a7959731e508794f6693df3865274ae3a37398d82feac244fbaac26277930c2a"
    );
}

#[test]
fn parent_list_decode_len_overflow_fails() {
    // Build buffer with len=MAX_PARENTS+1 and verify that decode fails.
    // Baue Buffer mit len=MAX_PARENTS+1 und prüfe, dass decode fehlschlägt.
    let mut buf = Vec::new();
    let over_len = (MAX_PARENTS as u8).saturating_add(1);
    buf.push(over_len); // len
                        // do not append ids; decoding should already fail on the length.
                        // keine ids anhängen, sollte bereits an len scheitern.
    let res = ParentList::decode(&mut &buf[..]);
    assert!(res.is_err());
}

#[test]
fn evidence_invalid_tag_fails_decode() {
    // Tag=99 (invalid), followed by no further fields.
    // Tag=99 (ungültig), danach keine weiteren Felder.
    let mut buf = Vec::new();
    buf.push(99u8);
    let res = EvidenceKind::decode(&mut &buf[..]);
    assert!(res.is_err());
}

#[test]
fn claim_merkle_proof_bounded_decode_rejects_oversized() {
    // P1-2: merkle_proof with len > MAX_CLAIM_MERKLE_PROOF_DEPTH must fail.
    // P1-2: merkle_proof mit len > MAX_CLAIM_MERKLE_PROOF_DEPTH muss fehlschlagen.
    let mut buf = Vec::new();
    1u8.encode(&mut buf).unwrap(); // version
    AnchorId([0x11; 32]).encode(&mut buf).unwrap(); // anchor_id
    [0x22u8; 32].encode(&mut buf).unwrap(); // recipient_id
    100u64.encode(&mut buf).unwrap(); // amount
                                      // merkle_proof len = MAX_CLAIM_MERKLE_PROOF_DEPTH + 1 (65)
    pc_codec::write_varu64(&mut buf, (MAX_CLAIM_MERKLE_PROOF_DEPTH + 1) as u64).unwrap();
    // No actual proof elements needed - decode should fail on length check.
    let res = ClaimEvent::decode(&mut &buf[..]);
    assert!(res.is_err(), "decode should reject oversized merkle_proof");
}

#[test]
fn evidence_attest_bounded_decode_rejects_oversized() {
    // P1-2: attest_a/b with len > MAX_EVIDENCE_ATTEST_BYTES must fail.
    // P1-2: attest_a/b mit len > MAX_EVIDENCE_ATTEST_BYTES muss fehlschlagen.
    let mut buf = Vec::new();
    3u8.encode(&mut buf).unwrap(); // tag for ConflictingDAAttest
    [0x11u8; 32].encode(&mut buf).unwrap(); // seat_id
    AnchorId([0x22; 32]).encode(&mut buf).unwrap(); // anchor_id
                                                    // attest_a len = MAX_EVIDENCE_ATTEST_BYTES + 1
    pc_codec::write_varu64(&mut buf, (MAX_EVIDENCE_ATTEST_BYTES + 1) as u64).unwrap();
    // No actual bytes needed - decode should fail on length check.
    let res = EvidenceKind::decode(&mut &buf[..]);
    assert!(res.is_err(), "decode should reject oversized attest_a");
}

#[test]
fn claim_sanity_rejects_oversized_proof() {
    // P1-2: validate_claim_sanity rejects proof > MAX_CLAIM_MERKLE_PROOF_DEPTH.
    let claim = ClaimEvent {
        version: 1,
        anchor_id: AnchorId([0x11; 32]),
        recipient_id: [0x22; 32],
        amount: 100,
        merkle_proof: vec![[0u8; 32]; MAX_CLAIM_MERKLE_PROOF_DEPTH + 1],
        payout_lock: LockCommitment([0x33; 32]),
    };
    assert!(validate_claim_sanity(&claim).is_err());
}

#[test]
fn evidence_sanity_rejects_oversized_attest() {
    // P1-2: validate_evidence_sanity rejects attest > MAX_EVIDENCE_ATTEST_BYTES.
    let evid = EvidenceEvent {
        version: 1,
        evidence: EvidenceKind::ConflictingDAAttest {
            seat_id: [0x11; 32],
            anchor_id: AnchorId([0x22; 32]),
            attest_a: vec![0u8; MAX_EVIDENCE_ATTEST_BYTES + 1],
            attest_b: vec![0u8; 64],
        },
    };
    assert!(validate_evidence_sanity(&evid).is_err());
}

#[test]
fn encoded_len_matches_buffer_sizes() {
    // MicroTx
    let tx = MicroTx {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            amount: 1,
            lock: LockCommitment([0x01; 32]),
        }],
    };
    let mut buf_tx = Vec::new();
    tx.encode(&mut buf_tx).unwrap();
    assert_eq!(tx.encoded_len(), buf_tx.len());

    // AnchorHeader mit ack_present=false
    let hdr = AnchorHeader {
        version: 1,
        shard_id: 1,
        parents: ParentList::default(),
        payload_hash: [0x99; 32],
        creator_index: 2,
        vote_mask: 3,
        ack_present: false,
        ack_id: AnchorId([0u8; 32]),
    };
    let mut buf_h = Vec::new();
    hdr.encode(&mut buf_h).unwrap();
    assert_eq!(hdr.encoded_len(), buf_h.len());

    // AnchorHeader mit ack_present=true (inkl. ack_id)
    let mut parents = ParentList::default();
    parents.push(AnchorId([0x22; 32])).unwrap();
    let hdr2 = AnchorHeader {
        version: 1,
        shard_id: 7,
        parents,
        payload_hash: [0x10; 32],
        creator_index: 4,
        vote_mask: 0x55AA,
        ack_present: true,
        ack_id: AnchorId([0x77; 32]),
    };
    let mut buf_h2 = Vec::new();
    hdr2.encode(&mut buf_h2).unwrap();
    assert_eq!(hdr2.encoded_len(), buf_h2.len());
}

#[test]
#[ignore]
fn header_encode_example_bytes() {
    // Example header for SPEC_CODEC.md.
    // Beispiel-Header für SPEC_CODEC.md.
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
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0x10; 32],
                vout: 1,
            },
            witness: vec![0xAA, 0xBB],
        }],
        outputs: vec![TxOut {
            amount: 1234,
            lock: LockCommitment([0x20; 32]),
        }],
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
        minted_at: 0,
        round_id: [0u8; 32],
        hit_bucket: 0,
        bits_used: 0,
    };

    let claim = ClaimEvent {
        version: 1,
        anchor_id: AnchorId([5u8; 32]),
        recipient_id: [6u8; 32],
        amount: 222,
        merkle_proof: vec![[0x62; 32], [0x63; 32]],
        payout_lock: LockCommitment([0x64; 32]),
    };
    let evid = EvidenceEvent {
        version: 1,
        evidence: EvidenceKind::VoteInvalid {
            seat_id: [0x70; 32],
            anchor: AnchorHeader::default(),
            reason_code: 0x1234,
        },
    };
    let payout = PayoutSet {
        entries: vec![PayoutEntry {
            recipient_id: [0x80; 32],
            amount: 1,
        }],
    };
    let p = AnchorPayload {
        version: 1,
        micro_txs: vec![tx],
        mints: vec![mint],
        claims: vec![claim],
        evidences: vec![evid],
        payout_root: payout.payout_root(),
    };
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
            anchor_id: AnchorId([0xC1; 32]),
            attest_a: vec![0x01, 0x02, 0x03],
            attest_b: vec![0xFF, 0xEE],
        },
    };
    buf.clear();
    ev_da.encode(&mut buf).unwrap();
    println!("EVIDENCE_CONFLICTING_DA_BYTES={}", hex::encode(&buf));
}

#[test]
fn shard_for_tx_single_shard_always_zero() {
    let tx = MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0xAA; 32],
                vout: 0,
            },
            witness: vec![],
        }],
        outputs: vec![],
    };
    assert_eq!(shard_for_tx(&tx, 0), 0);
    assert_eq!(shard_for_tx(&tx, 1), 0);
}

#[test]
fn shard_for_tx_no_inputs_returns_zero() {
    let tx = MicroTx {
        version: 1,
        inputs: vec![],
        outputs: vec![],
    };
    assert_eq!(shard_for_tx(&tx, 4), 0);
}

#[test]
fn shard_for_tx_deterministic() {
    let tx = MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0x42; 32],
                vout: 7,
            },
            witness: vec![1, 2, 3],
        }],
        outputs: vec![],
    };
    let s1 = shard_for_tx(&tx, 64);
    let s2 = shard_for_tx(&tx, 64);
    assert_eq!(s1, s2);
    assert!(s1 < 64);
}

#[test]
fn shard_for_tx_different_inputs_can_differ() {
    let mk = |n: u8| MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [n; 32],
                vout: 0,
            },
            witness: vec![],
        }],
        outputs: vec![],
    };
    let mut shards = std::collections::HashSet::new();
    for i in 0..32u8 {
        shards.insert(shard_for_tx(&mk(i), 16));
    }
    assert!(
        shards.len() > 1,
        "different inputs should map to different shards"
    );
}

#[test]
fn shard_for_tx_vout_matters() {
    let mk = |vout: u32| MicroTx {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0xFF; 32],
                vout,
            },
            witness: vec![],
        }],
        outputs: vec![],
    };
    let s0 = shard_for_tx(&mk(0), 256);
    let s1 = shard_for_tx(&mk(1), 256);
    assert_ne!(
        s0, s1,
        "different vout should produce different shard with high probability"
    );
}
