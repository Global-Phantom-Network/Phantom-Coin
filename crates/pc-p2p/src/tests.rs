use crate::messages::{P2pMessage, ReqMsg, RespMsg};
use pc_codec::{Decodable, Encodable};
use pc_types::{
    AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV3 as AnchorPayload, MicroTx,
};
use proptest::prelude::*;

// Roundtrip-Helfer ohne unwrap/expect
fn rt<T: Encodable + Decodable + core::fmt::Debug + PartialEq>(
    v: &T,
) -> Result<T, pc_codec::CodecError> {
    let mut buf = Vec::new();
    v.encode(&mut buf)?;
    let mut s = &buf[..];
    T::decode(&mut s)
}

fn arb_hash32() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_anchor_id() -> impl Strategy<Value = AnchorId> {
    arb_hash32().prop_map(AnchorId)
}

fn arb_header() -> impl Strategy<Value = AnchorHeader> {
    (
        any::<u8>(),                                                           // version
        any::<u16>(),                                                          // shard_id
        arb_hash32(),                                                          // payload_hash
        any::<u8>(),                                                           // creator_index
        any::<u64>(),                                                          // vote_mask
        any::<bool>(),                                                         // ack_present
        arb_hash32(),                                                          // ack_id as bytes
        arb_hash32(),                                                          // network_id
        proptest::collection::vec(arb_anchor_id(), 0..=pc_types::MAX_PARENTS), // parents ids
    )
        .prop_map(
            |(
                version,
                shard_id,
                payload_hash,
                creator_index,
                vote_mask,
                ack_present,
                ack_id_b,
                network_id,
                p_ids,
            )| {
                let mut parents = pc_types::ParentList::default();
                for id in p_ids.into_iter() {
                    let _ = parents.push(id);
                }
                AnchorHeader {
                    version,
                    shard_id,
                    parents,
                    payload_hash,
                    creator_index,
                    vote_mask,
                    ack_present,
                    ack_id: if ack_present {
                        AnchorId(ack_id_b)
                    } else {
                        AnchorId([0u8; 32])
                    },
                    network_id,
                    vote_epoch: 0,
                    vote_round: 0,
                    state_root: None,
                    attest_sig: None,
                }
            },
        )
}

fn arb_microtx() -> impl Strategy<Value = MicroTx> {
    any::<u8>().prop_map(|version| MicroTx {
        version,
        inputs: vec![],
        outputs: vec![],
    })
}

fn arb_payload() -> impl Strategy<Value = AnchorPayload> {
    (
        any::<u8>(),
        proptest::collection::vec(arb_microtx(), 0..3),
        arb_hash32(),
        any::<bool>(),
    )
        .prop_map(
            |(version, micro_txs, payout_root, null_mint)| AnchorPayload {
                version,
                micro_txs,
                mints: vec![],
                claims: vec![],
                evidences: vec![],
                payout_root,
                genesis_note: None,
                null_mint,
            },
        )
}

fn arb_req() -> impl Strategy<Value = ReqMsg> {
    prop_oneof![
        proptest::collection::vec(arb_anchor_id(), 0..4).prop_map(|ids| ReqMsg::GetHeaders { ids }),
        proptest::collection::vec(arb_hash32(), 0..4)
            .prop_map(|roots| ReqMsg::GetPayloads { roots }),
        proptest::collection::vec(arb_hash32(), 0..4).prop_map(|ids| ReqMsg::GetTx { ids }),
    ]
}

fn arb_resp() -> impl Strategy<Value = RespMsg> {
    prop_oneof![
        proptest::collection::vec(
            arb_header().prop_filter("prevote header", |h| h.state_root.is_none()),
            0..3,
        )
        .prop_map(|headers| RespMsg::PrevoteHeaders { headers }),
        proptest::collection::vec(
            arb_header().prop_map(|mut h| {
                h.version = 5;
                h.state_root.get_or_insert([0x11; 32]);
                h
            }),
            0..3,
        )
        .prop_map(|headers| RespMsg::PrecommitHeaders { headers }),
        (
            proptest::collection::vec(
                arb_header().prop_filter("prevote header", |h| h.state_root.is_none()),
                1..3,
            ),
            proptest::collection::vec(
                arb_header().prop_map(|mut h| {
                    h.version = 5;
                    h.state_root.get_or_insert([0x22; 32]);
                    h
                }),
                1..3,
            ),
        )
            .prop_map(
                |(prevote_headers, precommit_headers)| RespMsg::StagedHeaders {
                    prevote_headers,
                    precommit_headers,
                }
            ),
        proptest::collection::vec(arb_payload(), 0..3)
            .prop_map(|payloads| RespMsg::Payloads { payloads }),
        proptest::collection::vec(any::<[u8; 32]>(), 0..3)
            .prop_map(|ids| RespMsg::NotFound { ty: 2, ids }),
        proptest::collection::vec(arb_microtx(), 0..3).prop_map(|txs| RespMsg::Txs { txs }),
    ]
}

fn arb_message() -> impl Strategy<Value = P2pMessage> {
    prop_oneof![
        arb_header()
            .prop_filter("prevote announce", |h| h.state_root.is_none())
            .prop_map(P2pMessage::PrevoteAnnounce),
        arb_header()
            .prop_map(|mut h| {
                h.version = 5;
                h.state_root.get_or_insert([0x22; 32]);
                h
            })
            .prop_map(P2pMessage::PrecommitAnnounce),
        proptest::collection::vec(arb_anchor_id(), 0..4)
            .prop_map(|ids| P2pMessage::HeadersInv { ids }),
        proptest::collection::vec(arb_hash32(), 0..4)
            .prop_map(|roots| P2pMessage::PayloadInv { roots }),
        proptest::collection::vec(arb_hash32(), 0..4).prop_map(|ids| P2pMessage::TxInv { ids }),
        arb_req().prop_map(P2pMessage::Req),
        arb_resp().prop_map(P2pMessage::Resp),
    ]
}

proptest! {
    #[test]
    fn prop_p2p_message_roundtrip(msg in arb_message()) {
        let dec = rt(&msg);
        prop_assert_eq!(dec.ok(), Some(msg.clone()));
    }

    #[test]
    fn prop_p2p_message_encoded_len_matches(msg in arb_message()) {
        let mut buf = Vec::new();
        prop_assert!(msg.encode(&mut buf).is_ok());
        let enc_len = msg.encoded_len();
        prop_assert_eq!(enc_len, buf.len());
    }

    #[test]
    fn prop_req_roundtrip(req in arb_req()) {
        let dec = rt(&req);
        prop_assert_eq!(dec.ok(), Some(req.clone()));
    }
}

proptest! {
    #[test]
    fn prop_resp_roundtrip(resp in arb_resp()) {
        let dec = rt(&resp);
        prop_assert_eq!(dec.ok(), Some(resp.clone()));
    }
}
