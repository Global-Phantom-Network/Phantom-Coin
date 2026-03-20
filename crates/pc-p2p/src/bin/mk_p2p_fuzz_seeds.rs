use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;

use pc_codec::Encodable;
use pc_p2p::messages::{P2pMessage, ReqMsg, RespMsg};
use pc_types::{
    AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV3 as AnchorPayload, GenesisNote,
    GenesisParams, MicroTx,
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

    // P2pMessage seeds
    let p2p_dir = base.join("fuzz/corpus/p2p_message_decode");
    {
        // PrevoteAnnounce
        let mut buf = Vec::new();
        let m = P2pMessage::PrevoteAnnounce(AnchorHeader::default());
        m.encode(&mut buf)?;
        write_seed(p2p_dir.join("prevote_announce.bin"), &buf)?;
    }
    {
        // PrecommitAnnounce
        let mut buf = Vec::new();
        let mut h = AnchorHeader::default();
        h.version = 5;
        h.state_root = Some([0x44; 32]);
        let m = P2pMessage::PrecommitAnnounce(h);
        m.encode(&mut buf)?;
        write_seed(p2p_dir.join("precommit_announce.bin"), &buf)?;
    }
    {
        // HeadersInv (empty)
        let mut buf = Vec::new();
        let m = P2pMessage::HeadersInv { ids: vec![] };
        m.encode(&mut buf)?;
        write_seed(p2p_dir.join("headers_inv_empty.bin"), &buf)?;
    }
    {
        // PayloadInv (one root)
        let mut buf = Vec::new();
        let m = P2pMessage::PayloadInv {
            roots: vec![[0u8; 32]],
        };
        m.encode(&mut buf)?;
        write_seed(p2p_dir.join("payload_inv_one.bin"), &buf)?;
    }
    {
        // TxInv (two ids)
        let mut buf = Vec::new();
        let m = P2pMessage::TxInv {
            ids: vec![[1u8; 32], [2u8; 32]],
        };
        m.encode(&mut buf)?;
        write_seed(p2p_dir.join("tx_inv_two.bin"), &buf)?;
    }
    {
        // Req GetHeaders
        let mut buf = Vec::new();
        let r = ReqMsg::GetHeaders {
            ids: vec![AnchorId([3u8; 32])],
        };
        let m = P2pMessage::Req(r);
        m.encode(&mut buf)?;
        write_seed(p2p_dir.join("req_get_headers.bin"), &buf)?;
    }
    {
        // Resp NotFound payloads
        let mut buf = Vec::new();
        let r = RespMsg::NotFound {
            ty: 2,
            ids: vec![[9u8; 32]],
        };
        let m = P2pMessage::Resp(r);
        m.encode(&mut buf)?;
        write_seed(p2p_dir.join("resp_notfound_payloads.bin"), &buf)?;
    }

    // ReqMsg seeds
    let req_dir = base.join("fuzz/corpus/reqmsg_decode");
    {
        let mut buf = Vec::new();
        let r = ReqMsg::GetPayloads {
            roots: vec![[0xABu8; 32]],
        };
        r.encode(&mut buf)?;
        write_seed(req_dir.join("req_get_payloads.bin"), &buf)?;
    }
    {
        let mut buf = Vec::new();
        let r = ReqMsg::GetTx { ids: vec![] };
        r.encode(&mut buf)?;
        write_seed(req_dir.join("req_get_tx_empty.bin"), &buf)?;
    }

    // RespMsg seeds
    let resp_dir = base.join("fuzz/corpus/respmsg_decode");
    {
        let mut buf = Vec::new();
        let pl = AnchorPayload {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [0u8; 32],
            genesis_note: None,
            null_mint: false,
        };
        let r = RespMsg::Payloads { payloads: vec![pl] };
        r.encode(&mut buf)?;
        write_seed(resp_dir.join("resp_payloads_one.bin"), &buf)?;
    }
    {
        // Payloads mit genesis_note = Some(...)
        let mut buf = Vec::new();
        let note = GenesisNote {
            version: 0,
            network_name: b"fuzznet".to_vec(),
            seed: [2u8; 32],
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
        let pl = AnchorPayload {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [1u8; 32],
            genesis_note: Some(note),
            null_mint: false,
        };
        let r = RespMsg::Payloads { payloads: vec![pl] };
        r.encode(&mut buf)?;
        write_seed(resp_dir.join("resp_payloads_with_note.bin"), &buf)?;
    }
    {
        let mut buf = Vec::new();
        let r = RespMsg::PrevoteHeaders {
            headers: vec![AnchorHeader::default()],
        };
        r.encode(&mut buf)?;
        write_seed(resp_dir.join("resp_prevote_headers_one.bin"), &buf)?;
    }
    {
        let mut buf = Vec::new();
        let mut h = AnchorHeader::default();
        h.version = 5;
        h.state_root = Some([0x22; 32]);
        let r = RespMsg::PrecommitHeaders { headers: vec![h] };
        r.encode(&mut buf)?;
        write_seed(resp_dir.join("resp_precommit_headers_one.bin"), &buf)?;
    }
    {
        let mut buf = Vec::new();
        let mut precommit = AnchorHeader::default();
        precommit.version = 5;
        precommit.state_root = Some([0x33; 32]);
        let r = RespMsg::StagedHeaders {
            prevote_headers: vec![AnchorHeader::default()],
            precommit_headers: vec![precommit],
        };
        r.encode(&mut buf)?;
        write_seed(resp_dir.join("resp_staged_headers_mixed.bin"), &buf)?;
    }

    // Seeds for payloads_vec_decode (Vec<AnchorPayloadV3>).
    // Seeds für payloads_vec_decode (Vec<AnchorPayloadV3>)
    let plv_dir = base.join("fuzz/corpus/payloads_vec_decode");
    {
        let mut buf = Vec::new();
        let v: Vec<AnchorPayload> = vec![];
        v.encode(&mut buf)?;
        write_seed(plv_dir.join("vec_empty.bin"), &buf)?;
    }
    {
        let mut buf = Vec::new();
        let p = AnchorPayload {
            version: 3,
            micro_txs: vec![],
            mints: vec![],
            claims: vec![],
            evidences: vec![],
            payout_root: [3u8; 32],
            genesis_note: None,
            null_mint: false,
        };
        let v: Vec<AnchorPayload> = vec![p];
        v.encode(&mut buf)?;
        write_seed(plv_dir.join("vec_one.bin"), &buf)?;
    }

    // Seeds for headers_vec_decode (Vec<AnchorHeaderV2>).
    // Seeds für headers_vec_decode (Vec<AnchorHeaderV2>)
    let hv_dir = base.join("fuzz/corpus/headers_vec_decode");
    {
        let mut buf = Vec::new();
        let v: Vec<AnchorHeader> = vec![];
        v.encode(&mut buf)?;
        write_seed(hv_dir.join("vec_empty.bin"), &buf)?;
    }
    {
        let mut buf = Vec::new();
        let v: Vec<AnchorHeader> = vec![AnchorHeader::default()];
        v.encode(&mut buf)?;
        write_seed(hv_dir.join("vec_one.bin"), &buf)?;
    }

    // Seeds for txs_vec_decode (Vec<MicroTx>).
    // Seeds für txs_vec_decode (Vec<MicroTx>)
    let tv_dir = base.join("fuzz/corpus/txs_vec_decode");
    {
        let mut buf = Vec::new();
        let v: Vec<MicroTx> = vec![];
        v.encode(&mut buf)?;
        write_seed(tv_dir.join("vec_empty.bin"), &buf)?;
    }
    {
        let mut buf = Vec::new();
        let v: Vec<MicroTx> = vec![MicroTx {
            version: 1,
            inputs: vec![],
            outputs: vec![],
        }];
        v.encode(&mut buf)?;
        write_seed(tv_dir.join("vec_one.bin"), &buf)?;
    }
    Ok(())
}
