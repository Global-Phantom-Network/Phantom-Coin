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
        clippy::useless_vec
    )
)]

/// P2P skeleton: placeholder types and functions. No network I/O here; pure API sketch.
/// P2P-Skelett: Platzhaltertypen und -funktionen. Keine Netzwerk-IO hier; reine API-Skizze.
/// Later implementation uses async (tokio) and QUIC/TCP, VRF sampling, gossip with backpressure control.
/// Spätere Implementierung nutzt async (tokio) und QUIC/TCP, VRF-Sampling, Gossip mit Backpressure-Steuerung.
#[cfg(all(feature = "async", feature = "libp2p"))]
mod libp2p_node;
pub mod peer_store;
#[cfg(all(feature = "async", feature = "persistent"))]
pub mod rocksdb_store;

use pc_types::AnchorHeaderV2 as AnchorHeader;

#[derive(Debug)]
pub enum P2pError {
    InvalidConfig,
    ChannelClosed,
    StoreError,
}

#[cfg(all(feature = "async", feature = "libp2p"))]
pub use libp2p_node::node::Libp2pConfig;

/// Starts the internal P2P service and attaches it to a libp2p gossipsub node.
/// Startet den internen P2P-Service und koppelt ihn an einen libp2p-Gossipsub-Knoten.
/// Returns: (service, handle of service loop, handle of libp2p swarm).
/// Rückgabe: (Service, Handle Service-Loop, Handle libp2p-Swarm)
#[cfg(all(feature = "async", feature = "libp2p"))]
#[allow(clippy::type_complexity)]
pub fn spawn_with_libp2p(
    cfg: P2pConfig,
    lp2p_cfg: Libp2pConfig,
) -> Result<
    (
        async_svc::P2pService,
        tokio::task::JoinHandle<Result<(), P2pError>>,
        tokio::task::JoinHandle<()>,
    ),
    P2pError,
> {
    use async_svc::spawn as svc_spawn;
    let network_id = cfg.network_id;
    let max_peers = cfg.max_peers as usize;
    let enable_peer_exchange = cfg.enable_peer_exchange;
    let (svc, out_rx, svc_handle) = svc_spawn(cfg);
    let swarm_handle = libp2p_node::node::start(
        svc.clone(),
        out_rx,
        lp2p_cfg,
        network_id,
        max_peers,
        enable_peer_exchange,
    )?;
    Ok((svc, svc_handle, swarm_handle))
}

impl core::fmt::Display for P2pError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            P2pError::InvalidConfig => f.write_str("invalid P2P config"),
            P2pError::ChannelClosed => f.write_str("channel closed"),
            P2pError::StoreError => f.write_str("store error"),
        }
    }
}

impl std::error::Error for P2pError {}

#[derive(Clone, Debug, Default)]
pub struct P2pConfig {
    pub max_peers: u16,
    pub rate: Option<RateLimitConfig>,
    pub peers_json_path: Option<std::path::PathBuf>,
    pub enable_peer_exchange: bool,
    pub network_id: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub struct RateLimitConfig {
    pub hdr_capacity: u32,
    pub hdr_refill_per_sec: u32,
    pub inv_capacity: u32,
    pub inv_refill_per_sec: u32,
    pub req_capacity: u32,
    pub req_refill_per_sec: u32,
    pub resp_capacity: u32,
    pub resp_refill_per_sec: u32,
    /// Byte budget capacity (burst). 0 = default.
    pub bytes_capacity: u32,
    /// Byte budget refill per second. 0 = default.
    pub bytes_refill_per_sec: u32,
    pub per_peer: bool,
    pub peer_ttl_secs: u64,
}

/// Message formats and codec implementations for P2P.
/// Nachrichtenformate und Codec-Implementierungen für P2P
pub mod messages {
    use pc_codec::{CodecError, Decodable, Encodable};
    use pc_types::{
        AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV3 as AnchorPayload, EvidenceEvent,
    };

    // Message-level bounds (P1-02 hardening). These are defensive limits for decode/allocation
    // and are not meant to be tuned frequently.
    const MAX_PEER_IP_BYTES: usize = 16; // 4 (IPv4) or 16 (IPv6)
    const MAX_PEER_CERT_DER_BYTES: usize = 8 * 1024;

    pub const MAX_INV_IDS: usize = 2048;
    pub const MAX_PEERS_IN_MSG: usize = 256;
    pub const MAX_HEADERS_IN_MSG: usize = 256;
    pub const MAX_PAYLOADS_IN_MSG: usize = 8;
    pub const MAX_TXS_IN_MSG: usize = 1024;
    pub const MAX_EVIDENCES_IN_MSG: usize = 1024;

    // Wire-size caps by message type (bytes, includes the tag byte).
    pub const MAX_MSG_HEADER_ANNOUNCE_BYTES: usize = pc_types::MAX_HEADER_BYTES + 256;
    pub const MAX_MSG_INV_BYTES: usize = 64 * 1024;
    pub const MAX_MSG_PEERS_BYTES: usize = 64 * 1024;
    pub const MAX_MSG_PING_PONG_BYTES: usize = 1024;
    pub const MAX_MSG_RPC_REQ_BYTES: usize = 128 * 1024;
    pub const MAX_MSG_RPC_RESP_BYTES: usize = pc_types::MAX_PAYLOAD_BYTES + 256 * 1024;

    // Hard maximum across all message types.
    pub const MAX_WIRE_MESSAGE_BYTES: usize = MAX_MSG_RPC_RESP_BYTES;

    /// Returns the maximum allowed wire size (bytes) for a given top-level tag.
    /// `None` means "unknown tag" and should be rejected by transports.
    pub fn max_wire_bytes_for_tag(tag: u8) -> Option<usize> {
        match tag {
            TAG_PREVOTE_ANN | TAG_PRECOMMIT_ANN => Some(MAX_MSG_HEADER_ANNOUNCE_BYTES),
            TAG_HEADERS_INV | TAG_PAYLOAD_INV | TAG_TX_INV | TAG_EVIDENCE_INV => {
                Some(MAX_MSG_INV_BYTES)
            }
            TAG_PEERS => Some(MAX_MSG_PEERS_BYTES),
            TAG_PING | TAG_PONG => Some(MAX_MSG_PING_PONG_BYTES),
            TAG_REQ => Some(MAX_MSG_RPC_REQ_BYTES),
            TAG_RESP => Some(MAX_MSG_RPC_RESP_BYTES),
            _ => None,
        }
    }

    /// Bounded decode for Vec<T> with max count limit (P1-02 hardening).
    fn decode_bounded_vec<T: Decodable, R: std::io::Read>(
        r: &mut R,
        max_len: usize,
    ) -> Result<Vec<T>, CodecError> {
        let len = pc_codec::read_varu64(r)? as usize;
        if len > max_len {
            return Err(CodecError::InvalidLength(len));
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(T::decode(r)?);
        }
        Ok(out)
    }

    /// Bounded decode for Vec<u8> with max byte length (P1-02 hardening).
    fn decode_bounded_bytes<R: std::io::Read>(
        r: &mut R,
        max_len: usize,
    ) -> Result<Vec<u8>, CodecError> {
        let len = pc_codec::read_varu64(r)? as usize;
        if len > max_len {
            return Err(CodecError::InvalidLength(len));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(buf)
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PeerInfo {
        pub ip: Vec<u8>,
        pub port: u16,
        pub cert_der: Vec<u8>,
        pub last_seen: u64,
        pub role_flags: u8,
    }

    pub const ROLE_FULLNODE: u8 = 0;
    pub const ROLE_VALIDATOR: u8 = 1;
    pub const ROLE_MINER: u8 = 2;

    impl Encodable for PeerInfo {
        fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
            self.ip.encode(w)?;
            self.port.encode(w)?;
            self.cert_der.encode(w)?;
            self.last_seen.encode(w)?;
            self.role_flags.encode(w)
        }
        fn encoded_len(&self) -> usize {
            self.ip.encoded_len()
                + self.port.encoded_len()
                + self.cert_der.encoded_len()
                + self.last_seen.encoded_len()
                + self.role_flags.encoded_len()
        }
    }

    impl Decodable for PeerInfo {
        fn decode<R: std::io::Read>(r: &mut R) -> Result<Self, CodecError> {
            let ip = decode_bounded_bytes(r, MAX_PEER_IP_BYTES)?;
            if ip.len() != 4 && ip.len() != 16 {
                return Err(CodecError::InvalidLength(ip.len()));
            }
            let port = u16::decode(r)?;
            let cert_der = decode_bounded_bytes(r, MAX_PEER_CERT_DER_BYTES)?;
            let last_seen = u64::decode(r)?;
            let role_flags = u8::decode(r)?;
            Ok(Self {
                ip,
                port,
                cert_der,
                last_seen,
                role_flags,
            })
        }
    }

    // Top-level message types.
    // Top-Level Nachrichtentypen
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[allow(clippy::large_enum_variant)]
    pub enum P2pMessage {
        PrevoteAnnounce(AnchorHeader),
        PrecommitAnnounce(AnchorHeader),
        HeadersInv { ids: Vec<AnchorId> },
        PayloadInv { roots: Vec<[u8; 32]> },
        TxInv { ids: Vec<[u8; 32]> },
        EvidenceInv { ids: Vec<[u8; 32]> },
        Peers { peers: Vec<PeerInfo> },
        Ping,
        Pong,
        Req(ReqMsg),
        Resp(RespMsg),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum HeaderAnnounceStage {
        Prevote,
        Precommit,
    }

    impl HeaderAnnounceStage {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Prevote => "prevote",
                Self::Precommit => "precommit",
            }
        }
    }

    pub fn announced_header(msg: &P2pMessage) -> Option<&AnchorHeader> {
        match msg {
            P2pMessage::PrevoteAnnounce(h) | P2pMessage::PrecommitAnnounce(h) => Some(h),
            _ => None,
        }
    }

    pub fn announced_header_stage(msg: &P2pMessage) -> Option<HeaderAnnounceStage> {
        match msg {
            P2pMessage::PrevoteAnnounce(_) => Some(HeaderAnnounceStage::Prevote),
            P2pMessage::PrecommitAnnounce(_) => Some(HeaderAnnounceStage::Precommit),
            _ => None,
        }
    }

    pub fn explicit_announce_for_header(header: AnchorHeader) -> P2pMessage {
        if header.state_root.is_some() {
            P2pMessage::PrecommitAnnounce(header)
        } else {
            P2pMessage::PrevoteAnnounce(header)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ReqMsg {
        GetHeaders { ids: Vec<AnchorId> },
        GetPayloads { roots: Vec<[u8; 32]> },
        GetTx { ids: Vec<[u8; 32]> },
        GetEvidences { ids: Vec<[u8; 32]> },
        GetPeers { max_count: u16 },
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RespMsg {
        PrevoteHeaders {
            headers: Vec<AnchorHeader>,
        },
        PrecommitHeaders {
            headers: Vec<AnchorHeader>,
        },
        StagedHeaders {
            prevote_headers: Vec<AnchorHeader>,
            precommit_headers: Vec<AnchorHeader>,
        },
        Payloads {
            payloads: Vec<AnchorPayload>,
        },
        Txs {
            txs: Vec<pc_types::MicroTx>,
        },
        Evidences {
            evidences: Vec<EvidenceEvent>,
        },
        NotFound {
            ty: u8,
            ids: Vec<[u8; 32]>,
        }, // ty: 1=headers, 2=payloads, 3=txs, 4=evidences
        Peers {
            peers: Vec<PeerInfo>,
        },
    }

    fn split_headers_by_stage(
        headers: Vec<AnchorHeader>,
    ) -> (Vec<AnchorHeader>, Vec<AnchorHeader>) {
        let mut prevote_headers = Vec::new();
        let mut precommit_headers = Vec::new();
        for header in headers {
            if header.state_root.is_some() {
                precommit_headers.push(header);
            } else {
                prevote_headers.push(header);
            }
        }
        (prevote_headers, precommit_headers)
    }

    pub fn header_response_headers(resp: &RespMsg) -> Option<Vec<AnchorHeader>> {
        match resp {
            RespMsg::PrevoteHeaders { headers } | RespMsg::PrecommitHeaders { headers } => {
                Some(headers.clone())
            }
            RespMsg::StagedHeaders {
                prevote_headers,
                precommit_headers,
            } => {
                let mut headers =
                    Vec::with_capacity(prevote_headers.len() + precommit_headers.len());
                headers.extend(prevote_headers.iter().cloned());
                headers.extend(precommit_headers.iter().cloned());
                Some(headers)
            }
            _ => None,
        }
    }

    pub fn explicit_header_response_for_headers(headers: Vec<AnchorHeader>) -> RespMsg {
        let (prevote_headers, precommit_headers) = split_headers_by_stage(headers);
        if precommit_headers.is_empty() {
            RespMsg::PrevoteHeaders {
                headers: prevote_headers,
            }
        } else if prevote_headers.is_empty() {
            RespMsg::PrecommitHeaders {
                headers: precommit_headers,
            }
        } else {
            RespMsg::StagedHeaders {
                prevote_headers,
                precommit_headers,
            }
        }
    }

    pub fn normalize_header_response(resp: RespMsg) -> Result<RespMsg, &'static str> {
        match resp {
            RespMsg::PrevoteHeaders { headers } => {
                if headers.iter().all(|h| h.state_root.is_none()) {
                    Ok(RespMsg::PrevoteHeaders { headers })
                } else {
                    Err("prevote_headers_state_root_present")
                }
            }
            RespMsg::PrecommitHeaders { headers } => {
                if headers.iter().all(|h| h.state_root.is_some()) {
                    Ok(RespMsg::PrecommitHeaders { headers })
                } else {
                    Err("precommit_headers_state_root_missing")
                }
            }
            RespMsg::StagedHeaders {
                prevote_headers,
                precommit_headers,
            } => {
                if prevote_headers.iter().any(|h| h.state_root.is_some()) {
                    Err("staged_prevote_headers_state_root_present")
                } else if precommit_headers.iter().any(|h| h.state_root.is_none()) {
                    Err("staged_precommit_headers_state_root_missing")
                } else if prevote_headers.len() + precommit_headers.len() > MAX_HEADERS_IN_MSG {
                    Err("staged_headers_too_many")
                } else if precommit_headers.is_empty() {
                    Ok(RespMsg::PrevoteHeaders {
                        headers: prevote_headers,
                    })
                } else if prevote_headers.is_empty() {
                    Ok(RespMsg::PrecommitHeaders {
                        headers: precommit_headers,
                    })
                } else {
                    Ok(RespMsg::StagedHeaders {
                        prevote_headers,
                        precommit_headers,
                    })
                }
            }
            other => Ok(other),
        }
    }

    // Tags
    const TAG_PAYLOAD_INV: u8 = 2;
    const TAG_REQ: u8 = 3;
    const TAG_RESP: u8 = 4;
    const TAG_HEADERS_INV: u8 = 5;
    const TAG_TX_INV: u8 = 6;
    const TAG_PEERS: u8 = 7;
    const TAG_PING: u8 = 8;
    const TAG_PONG: u8 = 9;
    const TAG_EVIDENCE_INV: u8 = 10;
    const TAG_PREVOTE_ANN: u8 = 11;
    const TAG_PRECOMMIT_ANN: u8 = 12;

    const REQ_GET_HEADERS: u8 = 1;
    const REQ_GET_PAYLOADS: u8 = 2;
    const REQ_GET_TX: u8 = 3;
    const REQ_GET_PEERS: u8 = 4;
    const REQ_GET_EVIDENCES: u8 = 5;

    const RESP_PAYLOADS: u8 = 2;
    const RESP_NOTFOUND: u8 = 3;
    const RESP_TXS: u8 = 4;
    const RESP_PEERS: u8 = 5;
    const RESP_EVIDENCES: u8 = 6;
    const RESP_PREVOTE_HEADERS: u8 = 7;
    const RESP_PRECOMMIT_HEADERS: u8 = 8;
    const RESP_STAGED_HEADERS: u8 = 9;

    impl Encodable for P2pMessage {
        fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
            match self {
                P2pMessage::PrevoteAnnounce(h) => {
                    TAG_PREVOTE_ANN.encode(w)?;
                    h.encode(w)
                }
                P2pMessage::PrecommitAnnounce(h) => {
                    TAG_PRECOMMIT_ANN.encode(w)?;
                    h.encode(w)
                }
                P2pMessage::HeadersInv { ids } => {
                    TAG_HEADERS_INV.encode(w)?;
                    ids.encode(w)
                }
                P2pMessage::PayloadInv { roots } => {
                    TAG_PAYLOAD_INV.encode(w)?;
                    roots.encode(w)
                }
                P2pMessage::TxInv { ids } => {
                    TAG_TX_INV.encode(w)?;
                    ids.encode(w)
                }
                P2pMessage::EvidenceInv { ids } => {
                    TAG_EVIDENCE_INV.encode(w)?;
                    ids.encode(w)
                }
                P2pMessage::Peers { peers } => {
                    TAG_PEERS.encode(w)?;
                    peers.encode(w)
                }
                P2pMessage::Ping => TAG_PING.encode(w),
                P2pMessage::Pong => TAG_PONG.encode(w),
                P2pMessage::Req(r) => {
                    TAG_REQ.encode(w)?;
                    r.encode(w)
                }
                P2pMessage::Resp(r) => {
                    TAG_RESP.encode(w)?;
                    r.encode(w)
                }
            }
        }
        fn encoded_len(&self) -> usize {
            1 + match self {
                P2pMessage::PrevoteAnnounce(h) => h.encoded_len(),
                P2pMessage::PrecommitAnnounce(h) => h.encoded_len(),
                P2pMessage::HeadersInv { ids } => ids.encoded_len(),
                P2pMessage::PayloadInv { roots } => roots.encoded_len(),
                P2pMessage::TxInv { ids } => ids.encoded_len(),
                P2pMessage::EvidenceInv { ids } => ids.encoded_len(),
                P2pMessage::Peers { peers } => peers.encoded_len(),
                P2pMessage::Ping => 0,
                P2pMessage::Pong => 0,
                P2pMessage::Req(r) => r.encoded_len(),
                P2pMessage::Resp(r) => r.encoded_len(),
            }
        }
    }

    impl Decodable for P2pMessage {
        fn decode<R: std::io::Read>(r: &mut R) -> Result<Self, CodecError> {
            let tag = u8::decode(r)?;
            match tag {
                TAG_PREVOTE_ANN => Ok(P2pMessage::PrevoteAnnounce(AnchorHeader::decode(r)?)),
                TAG_PRECOMMIT_ANN => Ok(P2pMessage::PrecommitAnnounce(AnchorHeader::decode(r)?)),
                TAG_HEADERS_INV => Ok(P2pMessage::HeadersInv {
                    ids: decode_bounded_vec::<AnchorId, _>(r, MAX_INV_IDS)?,
                }),
                TAG_PAYLOAD_INV => Ok(P2pMessage::PayloadInv {
                    roots: decode_bounded_vec::<[u8; 32], _>(r, MAX_INV_IDS)?,
                }),
                TAG_TX_INV => Ok(P2pMessage::TxInv {
                    ids: decode_bounded_vec::<[u8; 32], _>(r, MAX_INV_IDS)?,
                }),
                TAG_EVIDENCE_INV => Ok(P2pMessage::EvidenceInv {
                    ids: decode_bounded_vec::<[u8; 32], _>(r, MAX_INV_IDS)?,
                }),
                TAG_PEERS => Ok(P2pMessage::Peers {
                    peers: decode_bounded_vec::<PeerInfo, _>(r, MAX_PEERS_IN_MSG)?,
                }),
                TAG_PING => Ok(P2pMessage::Ping),
                TAG_PONG => Ok(P2pMessage::Pong),
                TAG_REQ => Ok(P2pMessage::Req(ReqMsg::decode(r)?)),
                TAG_RESP => Ok(P2pMessage::Resp(RespMsg::decode(r)?)),
                _ => Err(CodecError::InvalidTag(tag)),
            }
        }
    }

    impl Encodable for ReqMsg {
        fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
            match self {
                ReqMsg::GetHeaders { ids } => {
                    REQ_GET_HEADERS.encode(w)?;
                    ids.encode(w)
                }
                ReqMsg::GetPayloads { roots } => {
                    REQ_GET_PAYLOADS.encode(w)?;
                    roots.encode(w)
                }
                ReqMsg::GetTx { ids } => {
                    REQ_GET_TX.encode(w)?;
                    ids.encode(w)
                }
                ReqMsg::GetEvidences { ids } => {
                    REQ_GET_EVIDENCES.encode(w)?;
                    ids.encode(w)
                }
                ReqMsg::GetPeers { max_count } => {
                    REQ_GET_PEERS.encode(w)?;
                    max_count.encode(w)
                }
            }
        }
        fn encoded_len(&self) -> usize {
            1 + match self {
                ReqMsg::GetHeaders { ids } => ids.encoded_len(),
                ReqMsg::GetPayloads { roots } => roots.encoded_len(),
                ReqMsg::GetTx { ids } => ids.encoded_len(),
                ReqMsg::GetEvidences { ids } => ids.encoded_len(),
                ReqMsg::GetPeers { max_count } => max_count.encoded_len(),
            }
        }
    }

    impl Decodable for ReqMsg {
        fn decode<R: std::io::Read>(r: &mut R) -> Result<Self, CodecError> {
            let tag = u8::decode(r)?;
            match tag {
                REQ_GET_HEADERS => Ok(ReqMsg::GetHeaders {
                    ids: decode_bounded_vec::<AnchorId, _>(r, MAX_INV_IDS)?,
                }),
                REQ_GET_PAYLOADS => Ok(ReqMsg::GetPayloads {
                    roots: decode_bounded_vec::<[u8; 32], _>(r, MAX_INV_IDS)?,
                }),
                REQ_GET_TX => Ok(ReqMsg::GetTx {
                    ids: decode_bounded_vec::<[u8; 32], _>(r, MAX_INV_IDS)?,
                }),
                REQ_GET_EVIDENCES => Ok(ReqMsg::GetEvidences {
                    ids: decode_bounded_vec::<[u8; 32], _>(r, MAX_INV_IDS)?,
                }),
                REQ_GET_PEERS => Ok(ReqMsg::GetPeers {
                    max_count: u16::decode(r)?,
                }),
                _ => Err(CodecError::InvalidTag(tag)),
            }
        }
    }

    impl Encodable for RespMsg {
        fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
            match self {
                RespMsg::PrevoteHeaders { headers } => {
                    RESP_PREVOTE_HEADERS.encode(w)?;
                    headers.encode(w)
                }
                RespMsg::PrecommitHeaders { headers } => {
                    RESP_PRECOMMIT_HEADERS.encode(w)?;
                    headers.encode(w)
                }
                RespMsg::StagedHeaders {
                    prevote_headers,
                    precommit_headers,
                } => {
                    RESP_STAGED_HEADERS.encode(w)?;
                    prevote_headers.encode(w)?;
                    precommit_headers.encode(w)
                }
                RespMsg::Payloads { payloads } => {
                    RESP_PAYLOADS.encode(w)?;
                    payloads.encode(w)
                }
                RespMsg::Txs { txs } => {
                    RESP_TXS.encode(w)?;
                    txs.encode(w)
                }
                RespMsg::Evidences { evidences } => {
                    RESP_EVIDENCES.encode(w)?;
                    evidences.encode(w)
                }
                RespMsg::NotFound { ty, ids } => {
                    RESP_NOTFOUND.encode(w)?;
                    ty.encode(w)?;
                    ids.encode(w)
                }
                RespMsg::Peers { peers } => {
                    RESP_PEERS.encode(w)?;
                    peers.encode(w)
                }
            }
        }
        fn encoded_len(&self) -> usize {
            1 + match self {
                RespMsg::PrevoteHeaders { headers } => headers.encoded_len(),
                RespMsg::PrecommitHeaders { headers } => headers.encoded_len(),
                RespMsg::StagedHeaders {
                    prevote_headers,
                    precommit_headers,
                } => prevote_headers.encoded_len() + precommit_headers.encoded_len(),
                RespMsg::Payloads { payloads } => payloads.encoded_len(),
                RespMsg::Txs { txs } => txs.encoded_len(),
                RespMsg::Evidences { evidences } => evidences.encoded_len(),
                RespMsg::NotFound { ty: _, ids } => 1 + ids.encoded_len(),
                RespMsg::Peers { peers } => peers.encoded_len(),
            }
        }
    }

    impl Decodable for RespMsg {
        fn decode<R: std::io::Read>(r: &mut R) -> Result<Self, CodecError> {
            let tag = u8::decode(r)?;
            match tag {
                RESP_PREVOTE_HEADERS => Ok(RespMsg::PrevoteHeaders {
                    headers: decode_bounded_vec::<AnchorHeader, _>(r, MAX_HEADERS_IN_MSG)?,
                }),
                RESP_PRECOMMIT_HEADERS => Ok(RespMsg::PrecommitHeaders {
                    headers: decode_bounded_vec::<AnchorHeader, _>(r, MAX_HEADERS_IN_MSG)?,
                }),
                RESP_STAGED_HEADERS => Ok(RespMsg::StagedHeaders {
                    prevote_headers: decode_bounded_vec::<AnchorHeader, _>(r, MAX_HEADERS_IN_MSG)?,
                    precommit_headers: decode_bounded_vec::<AnchorHeader, _>(
                        r,
                        MAX_HEADERS_IN_MSG,
                    )?,
                }),
                RESP_PAYLOADS => Ok(RespMsg::Payloads {
                    payloads: decode_bounded_vec::<AnchorPayload, _>(r, MAX_PAYLOADS_IN_MSG)?,
                }),
                RESP_TXS => Ok(RespMsg::Txs {
                    txs: decode_bounded_vec::<pc_types::MicroTx, _>(r, MAX_TXS_IN_MSG)?,
                }),
                RESP_EVIDENCES => Ok(RespMsg::Evidences {
                    evidences: decode_bounded_vec::<EvidenceEvent, _>(r, MAX_EVIDENCES_IN_MSG)?,
                }),
                RESP_NOTFOUND => {
                    let ty = u8::decode(r)?;
                    if ty != 1 && ty != 2 && ty != 3 && ty != 4 {
                        return Err(CodecError::InvalidTag(ty));
                    }
                    let ids = decode_bounded_vec::<[u8; 32], _>(r, MAX_INV_IDS)?;
                    Ok(RespMsg::NotFound { ty, ids })
                }
                RESP_PEERS => Ok(RespMsg::Peers {
                    peers: decode_bounded_vec::<PeerInfo, _>(r, MAX_PEERS_IN_MSG)?,
                }),
                _ => Err(CodecError::InvalidTag(tag)),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pc_types::ParentList;

        fn rt<T: Encodable + Decodable + core::fmt::Debug + PartialEq>(
            v: &T,
        ) -> Result<T, CodecError> {
            let mut buf = Vec::new();
            v.encode(&mut buf)?;
            let mut slice = &buf[..];
            T::decode(&mut slice)
        }

        #[test]
        fn roundtrip_staged_header_announces() {
            let parents = ParentList::default();
            let prevote = AnchorHeader {
                version: 5,
                shard_id: 0,
                parents: parents.clone(),
                payload_hash: [1u8; 32],
                creator_index: 7,
                vote_mask: 1,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 2,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };
            let precommit = AnchorHeader {
                state_root: Some([9u8; 32]),
                ..prevote.clone()
            };
            let prevote_msg = P2pMessage::PrevoteAnnounce(prevote);
            let precommit_msg = P2pMessage::PrecommitAnnounce(precommit);
            assert_eq!(rt(&prevote_msg).ok(), Some(prevote_msg));
            assert_eq!(rt(&precommit_msg).ok(), Some(precommit_msg));
        }

        #[test]
        fn roundtrip_payload_inv() {
            let msg = P2pMessage::PayloadInv {
                roots: vec![[1u8; 32], [2u8; 32]],
            };
            assert_eq!(rt(&msg).ok(), Some(msg));
        }

        #[test]
        fn roundtrip_headers_inv() {
            let msg = P2pMessage::HeadersInv {
                ids: vec![AnchorId([1u8; 32]), AnchorId([2u8; 32])],
            };
            assert_eq!(rt(&msg).ok(), Some(msg));
        }

        #[test]
        fn roundtrip_tx_inv() {
            let msg = P2pMessage::TxInv {
                ids: vec![[7u8; 32], [8u8; 32]],
            };
            assert_eq!(rt(&msg).ok(), Some(msg));
        }

        #[test]
        fn roundtrip_req_resp() {
            let r1 = ReqMsg::GetHeaders {
                ids: vec![AnchorId([9u8; 32]), AnchorId([7u8; 32])],
            };
            assert_eq!(rt(&r1).ok(), Some(r1.clone()));

            let r2 = ReqMsg::GetPayloads {
                roots: vec![[3u8; 32]],
            };
            assert_eq!(rt(&r2).ok(), Some(r2.clone()));

            let r3 = ReqMsg::GetTx {
                ids: vec![[4u8; 32]],
            };
            assert_eq!(rt(&r3).ok(), Some(r3.clone()));

            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 1,
                shard_id: 0,
                parents,
                payload_hash: [0u8; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };
            let prevote_hdr = hdr;
            let prevote_resp = RespMsg::PrevoteHeaders {
                headers: vec![prevote_hdr.clone()],
            };
            assert_eq!(rt(&prevote_resp).ok(), Some(prevote_resp.clone()));

            let precommit_resp = RespMsg::PrecommitHeaders {
                headers: vec![AnchorHeader {
                    version: 5,
                    state_root: Some([1u8; 32]),
                    ..prevote_hdr.clone()
                }],
            };
            assert_eq!(rt(&precommit_resp).ok(), Some(precommit_resp.clone()));

            let mixed_resp = RespMsg::StagedHeaders {
                prevote_headers: vec![AnchorHeader {
                    version: 2,
                    state_root: None,
                    ..prevote_hdr.clone()
                }],
                precommit_headers: vec![AnchorHeader {
                    version: 5,
                    state_root: Some([2u8; 32]),
                    ..prevote_hdr.clone()
                }],
            };
            assert_eq!(rt(&mixed_resp).ok(), Some(mixed_resp.clone()));

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
            let resp2 = RespMsg::Payloads { payloads: vec![pl] };
            assert_eq!(rt(&resp2).ok(), Some(resp2.clone()));

            let resp3 = RespMsg::NotFound {
                ty: 2,
                ids: vec![[4u8; 32], [5u8; 32]],
            };
            assert_eq!(rt(&resp3).ok(), Some(resp3));

            let tx = pc_types::MicroTx {
                version: 1,
                inputs: vec![],
                outputs: vec![],
            };
            let resp4 = RespMsg::Txs { txs: vec![tx] };
            assert_eq!(rt(&resp4).ok(), Some(resp4));
        }

        #[test]
        fn decode_legacy_header_announce_tag_errors() {
            use pc_codec::{Decodable, Encodable};

            let mut buf = Vec::new();
            assert!(1u8.encode(&mut buf).is_ok());
            assert!(AnchorHeader::default().encode(&mut buf).is_ok());

            let res = P2pMessage::decode(&mut &buf[..]);
            assert!(matches!(res, Err(pc_codec::CodecError::InvalidTag(1))));
        }

        #[test]
        fn decode_legacy_headers_response_tag_errors() {
            use pc_codec::{Decodable, Encodable};

            let mut buf = Vec::new();
            assert!(1u8.encode(&mut buf).is_ok());
            let headers = vec![AnchorHeader::default()];
            assert!(headers.encode(&mut buf).is_ok());

            let res = RespMsg::decode(&mut &buf[..]);
            assert!(matches!(res, Err(pc_codec::CodecError::InvalidTag(1))));
        }

        #[test]
        fn malformed_staged_header_response_is_rejected() {
            let parents = pc_types::ParentList::default();
            let invalid_prevote = AnchorHeader {
                version: 5,
                shard_id: 0,
                parents,
                payload_hash: [0x44; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: Some([0x55; 32]),
                attest_sig: None,
            };

            assert_eq!(
                normalize_header_response(RespMsg::StagedHeaders {
                    prevote_headers: vec![invalid_prevote],
                    precommit_headers: Vec::new(),
                }),
                Err("staged_prevote_headers_state_root_present")
            );
        }

        #[test]
        fn decode_resp_notfound_invalid_ty_errors() {
            use pc_codec::{Decodable, Encodable};
            // Build buffer: RESP_NOTFOUND tag, then ty=99, then empty ids vec
            const RESP_NOTFOUND: u8 = 3;
            let mut inner = Vec::new();
            assert!(RESP_NOTFOUND.encode(&mut inner).is_ok());
            assert!(99u8.encode(&mut inner).is_ok());
            let empty_ids: Vec<[u8; 32]> = vec![];
            assert!(empty_ids.encode(&mut inner).is_ok());
            let res = RespMsg::decode(&mut &inner[..]);
            assert!(matches!(res, Err(pc_codec::CodecError::InvalidTag(99))));

            // Allowed ty=1 should decode
            let mut ok1 = Vec::new();
            assert!(RESP_NOTFOUND.encode(&mut ok1).is_ok());
            assert!(1u8.encode(&mut ok1).is_ok());
            let empty: Vec<[u8; 32]> = vec![];
            assert!(empty.encode(&mut ok1).is_ok());
            let dec1 = RespMsg::decode(&mut &ok1[..]);
            assert!(matches!(dec1, Ok(RespMsg::NotFound { ty: 1, .. })));
        }
    }
}

#[derive(Clone, Debug)]
pub struct P2pNode {
    _cfg: P2pConfig,
}

impl P2pNode {
    pub fn new(cfg: P2pConfig) -> Result<Self, P2pError> {
        if cfg.max_peers == 0 {
            return Err(P2pError::InvalidConfig);
        }
        Ok(Self { _cfg: cfg })
    }

    pub fn announce_header(&self, _hdr: &AnchorHeader) -> Result<(), P2pError> {
        Ok(())
    }
}

#[cfg(all(feature = "async", feature = "quic"))]
pub mod quic_transport {
    use super::async_svc::P2pService;
    use super::messages::P2pMessage;
    use super::P2pError;
    use pc_codec::{Decodable, Encodable};
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::RootCertStore;
    use std::net::SocketAddr;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::sync::{mpsc, Semaphore};
    use tokio::time::timeout;

    const MAX_QUIC_MESSAGE_BYTES: usize = super::messages::MAX_WIRE_MESSAGE_BYTES;
    // Limit concurrent handshakes so a peer cannot stall the accept loop by opening many half-open
    // connections. Handshakes are awaited in spawned tasks with a timeout.
    const MAX_QUIC_HANDSHAKES_IN_FLIGHT: usize = 64;
    const MAX_QUIC_CONCURRENT_UNI_STREAMS: u32 = 64;
    // Transport-level byte budget (per QUIC connection). This is a pre-allocation guard against
    // bandwidth/memory DoS via large messages.
    const DEFAULT_QUIC_IN_BYTES_PER_SEC: usize = 2 * 1024 * 1024; // 2 MiB/s
    const DEFAULT_QUIC_IN_BYTES_BURST: usize = MAX_QUIC_MESSAGE_BYTES; // allow at least one max-sized msg

    const QUIC_READ_LEN_TIMEOUT: Duration = Duration::from_secs(5);
    const QUIC_READ_TAG_TIMEOUT: Duration = Duration::from_secs(5);
    const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

    fn quic_read_body_timeout(len: usize) -> Duration {
        // Base + per MiB, so large payloads have a fair window while still preventing slowloris.
        let mb = (len as u64).div_ceil(1024 * 1024);
        Duration::from_secs(5 + 5 * std::cmp::max(1, mb))
    }

    fn encode_msg(msg: &P2pMessage) -> Result<Vec<u8>, P2pError> {
        let mut body = Vec::new();
        msg.encode(&mut body).map_err(|_| P2pError::InvalidConfig)?;
        let tag = body.first().copied().unwrap_or(0);
        let cap = super::messages::max_wire_bytes_for_tag(tag).unwrap_or(0);
        if cap == 0 || body.len() > cap || body.len() > MAX_QUIC_MESSAGE_BYTES {
            return Err(P2pError::InvalidConfig);
        }
        let mut out = Vec::with_capacity(4 + body.len());
        let len = body.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        crate::async_svc::record_outbound_bytes(out.len());
        Ok(out)
    }

    struct ByteBudget {
        capacity: f64,
        tokens: f64,
        refill_per_sec: f64,
        last: Instant,
    }

    impl ByteBudget {
        fn new(capacity: usize, refill_per_sec: usize) -> Self {
            let cap = capacity as f64;
            Self {
                capacity: cap,
                tokens: cap,
                refill_per_sec: refill_per_sec as f64,
                last: Instant::now(),
            }
        }

        fn allow(&mut self, n: usize) -> bool {
            let now = Instant::now();
            let dt = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
            let want = n as f64;
            if self.tokens >= want {
                self.tokens -= want;
                true
            } else {
                false
            }
        }
    }

    async fn read_one(
        mut r: quinn::RecvStream,
        budget: &mut ByteBudget,
    ) -> Result<Option<P2pMessage>, P2pError> {
        let mut len_buf = [0u8; 4];
        let len_res = timeout(QUIC_READ_LEN_TIMEOUT, r.read_exact(&mut len_buf)).await;
        if !matches!(len_res, Ok(Ok(()))) {
            return Ok(None);
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_QUIC_MESSAGE_BYTES {
            let _ = r.stop(VarInt::from_u32(0));
            return Ok(None);
        }
        // Read the tag byte first so we can apply per-type caps without allocating the full body.
        let mut tag_buf = [0u8; 1];
        let tag_res = timeout(QUIC_READ_TAG_TIMEOUT, r.read_exact(&mut tag_buf)).await;
        if !matches!(tag_res, Ok(Ok(()))) {
            let _ = r.stop(VarInt::from_u32(0));
            return Ok(None);
        }
        let tag = tag_buf[0];
        let cap = match super::messages::max_wire_bytes_for_tag(tag) {
            Some(c) => c,
            None => {
                let _ = r.stop(VarInt::from_u32(0));
                return Ok(None);
            }
        };
        if len > cap {
            let _ = r.stop(VarInt::from_u32(0));
            return Ok(None);
        }
        let total = 4usize.saturating_add(len);
        if !budget.allow(total) {
            let _ = r.stop(VarInt::from_u32(0));
            return Ok(None);
        }
        let mut data = vec![0u8; len];
        if let Some(first) = data.first_mut() {
            *first = tag;
        } else {
            // Defensive: should be unreachable because `len==0` is rejected above.
            let _ = r.stop(VarInt::from_u32(0));
            return Ok(None);
        }
        if len > 1 {
            let body_to = quic_read_body_timeout(len);
            let Some(body) = data.get_mut(1..) else {
                let _ = r.stop(VarInt::from_u32(0));
                return Ok(None);
            };
            let body_res = timeout(body_to, r.read_exact(body)).await;
            if !matches!(body_res, Ok(Ok(()))) {
                let _ = r.stop(VarInt::from_u32(0));
                return Ok(None);
            }
        }
        // Record raw bytes received (length prefix + body).
        crate::async_svc::record_inbound_bytes(total);
        let mut slice = &data[..];
        match P2pMessage::decode(&mut slice) {
            Ok(m) if slice.is_empty() => Ok(Some(m)),
            Ok(_) => Ok(None), // trailing bytes → reject
            Err(_e) => Ok(None),
        }
    }

    /// mTLS configuration for production QUIC usage.
    /// mTLS-Konfiguration für produktiven QUIC-Einsatz
    #[derive(Clone, Debug)]
    pub struct TlsConfig {
        /// Path to the certificate file (PEM or DER).
        /// Pfad zur Zertifikat-Datei (PEM oder DER)
        pub cert_path: String,
        /// Path to the private key file (PEM or DER).
        /// Pfad zur Private-Key-Datei (PEM oder DER)
        pub key_path: String,
        /// Optional path to a CA certificate for client verification.
        /// Optionaler CA-Cert-Pfad für Client-Verifikation
        pub ca_cert_path: Option<String>,
    }

    /// Loads mTLS configuration from files (for production).
    /// Lädt mTLS-Konfiguration aus Dateien (für Produktion)
    pub fn make_server_config_from_files(
        tls_cfg: &TlsConfig,
    ) -> Result<(ServerConfig, Vec<u8>), P2pError> {
        use rustls::pki_types::pem::{Error as PemError, PemObject};
        use std::fs;

        let _ = rustls::crypto::ring::default_provider().install_default();

        // Load certificate.
        // Lade Zertifikat
        let cert_pem = fs::read(&tls_cfg.cert_path).map_err(|_| P2pError::InvalidConfig)?;
        let certs: Vec<CertificateDer> = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| P2pError::InvalidConfig)?;
        let certs: Vec<CertificateDer> = if certs.is_empty() {
            vec![CertificateDer::from(cert_pem)]
        } else {
            certs
        };

        // Load private key.
        // Lade Private Key
        let key_pem = fs::read(&tls_cfg.key_path).map_err(|_| P2pError::InvalidConfig)?;
        let key = match PrivateKeyDer::from_pem_slice(&key_pem) {
            Ok(k) => k,
            Err(PemError::NoItemsFound) => PrivateKeyDer::try_from(key_pem.as_slice())
                .map(|k| k.clone_key())
                .map_err(|_| P2pError::InvalidConfig)?,
            Err(_) => return Err(P2pError::InvalidConfig),
        };

        let cert_der = certs
            .first()
            .map(|c| c.to_vec())
            .ok_or(P2pError::InvalidConfig)?;

        let mut tls = if let Some(ca_path) = &tls_cfg.ca_cert_path {
            let roots = load_roots_from_path(ca_path)?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|_| P2pError::InvalidConfig)?;
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|_| P2pError::InvalidConfig)?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|_| P2pError::InvalidConfig)?
        };
        tls.alpn_protocols = vec![b"hq-29".to_vec()];
        let quic_tls = QuicServerConfig::try_from(std::sync::Arc::new(tls))
            .map_err(|_| P2pError::InvalidConfig)?;
        let mut cfg = ServerConfig::with_crypto(std::sync::Arc::new(quic_tls));

        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        transport.max_concurrent_uni_streams(VarInt::from_u32(MAX_QUIC_CONCURRENT_UNI_STREAMS));
        transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
        cfg.transport = std::sync::Arc::new(transport);

        Ok((cfg, cert_der))
    }

    /// Generates a self-signed certificate (tests/dev only).
    /// Generiert self-signed Zertifikat (nur für Tests/Dev)
    fn make_server_config() -> Result<(ServerConfig, Vec<u8>), P2pError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = match rcgen::generate_simple_self_signed(vec!["localhost".to_string()]) {
            Ok(c) => c,
            Err(_e) => return Err(P2pError::InvalidConfig),
        };
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let cert_chain = vec![CertificateDer::from(cert_der.clone())];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|_| P2pError::InvalidConfig)?;
        tls.alpn_protocols = vec![b"hq-29".to_vec()];
        let quic_tls = QuicServerConfig::try_from(std::sync::Arc::new(tls))
            .map_err(|_| P2pError::InvalidConfig)?;
        let mut cfg = ServerConfig::with_crypto(std::sync::Arc::new(quic_tls));
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        transport.max_concurrent_uni_streams(VarInt::from_u32(MAX_QUIC_CONCURRENT_UNI_STREAMS));
        transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
        cfg.transport = std::sync::Arc::new(transport);
        Ok((cfg, cert_der))
    }

    fn load_roots_from_path(path: &str) -> Result<RootCertStore, P2pError> {
        use rustls::pki_types::pem::PemObject;
        let ca = std::fs::read(path).map_err(|_| P2pError::InvalidConfig)?;
        let mut store = RootCertStore::empty();
        let certs: Vec<CertificateDer> = CertificateDer::pem_slice_iter(&ca)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| P2pError::InvalidConfig)?;
        if certs.is_empty() {
            store
                .add(CertificateDer::from(ca))
                .map_err(|_| P2pError::InvalidConfig)?;
            return Ok(store);
        }
        for c in certs {
            store.add(c).map_err(|_| P2pError::InvalidConfig)?;
        }
        Ok(store)
    }

    pub async fn start_server_with_tls(
        addr: SocketAddr,
        svc: P2pService,
        tls_cfg: &TlsConfig,
        max_connections: usize,
    ) -> Result<
        (
            Endpoint,
            Vec<u8>,
            tokio::task::JoinHandle<()>,
            mpsc::Sender<crate::async_svc::OutboundEnvelope>,
        ),
        P2pError,
    > {
        let (server_cfg, cert_der) = make_server_config_from_files(tls_cfg)?;
        let endpoint = match Endpoint::server(server_cfg, addr) {
            Ok(ep) => ep,
            Err(_e) => return Err(P2pError::InvalidConfig),
        };
        let (tx, mut rx) = mpsc::channel::<crate::async_svc::OutboundEnvelope>(1024);
        let connections: Arc<Mutex<Vec<quinn::Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let handshake_sem = Arc::new(Semaphore::new(MAX_QUIC_HANDSHAKES_IN_FLIGHT));
        let ep_clone = endpoint.clone();
        let svc_clone = svc.clone();
        let conns_for_accept = connections.clone();
        let sem_for_accept = handshake_sem.clone();
        let handle = tokio::spawn(async move {
            while let Some(connecting) = ep_clone.accept().await {
                let permit = match sem_for_accept.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // Too many in-flight handshakes: drop the incoming connection attempt early.
                        continue;
                    }
                };
                let conns_for_accept = conns_for_accept.clone();
                let svc2 = svc_clone.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let new_conn = match timeout(QUIC_HANDSHAKE_TIMEOUT, connecting).await {
                        Ok(Ok(c)) => c,
                        Ok(Err(_e)) => return,
                        Err(_elapsed) => return,
                    };
                    if let Ok(mut guard) = conns_for_accept.lock() {
                        guard.retain(|c| c.close_reason().is_none());
                        if guard.len() >= max_connections.max(1) {
                            new_conn.close(VarInt::from_u32(0), b"too many connections");
                            return;
                        }
                        guard.push(new_conn.clone());
                    }
                    let peer = new_conn.remote_address();
                    tokio::spawn(async move {
                        let mut budget = ByteBudget::new(
                            DEFAULT_QUIC_IN_BYTES_BURST,
                            DEFAULT_QUIC_IN_BYTES_PER_SEC,
                        );
                        while let Ok(recv) = new_conn.accept_uni().await {
                            if let Ok(Some(m)) = read_one(recv, &mut budget).await {
                                let _ = svc2.send_message_from(peer, m).await;
                            }
                        }
                    });
                });
            }
        });
        let conns_for_broadcast = connections.clone();
        tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                let (target_peer, msg) = env.into_parts();
                let buf = match encode_msg(&msg) {
                    Ok(b) => Arc::new(b),
                    Err(_) => continue,
                };
                if let Ok(mut guard) = conns_for_broadcast.lock() {
                    guard.retain(|c| c.close_reason().is_none());
                    for conn in guard.iter() {
                        if let Some(peer) = target_peer {
                            if conn.remote_address() != peer {
                                continue;
                            }
                        }
                        let buf = buf.clone();
                        let c = conn.clone();
                        tokio::spawn(async move {
                            match c.open_uni().await {
                                Ok(mut s) => {
                                    if let Err(_e) = s.write_all(&buf[..]).await {
                                        super::async_svc::out_error_inc();
                                        return;
                                    }
                                    if let Err(_e) = s.finish() {
                                        super::async_svc::out_error_inc();
                                    }
                                }
                                Err(_e) => {
                                    super::async_svc::out_error_inc();
                                }
                            }
                        });
                    }
                }
            }
        });
        Ok((endpoint, cert_der, handle, tx))
    }

    pub async fn start_server(
        addr: SocketAddr,
        svc: P2pService,
        max_connections: usize,
    ) -> Result<
        (
            Endpoint,
            Vec<u8>,
            tokio::task::JoinHandle<()>,
            mpsc::Sender<crate::async_svc::OutboundEnvelope>,
        ),
        P2pError,
    > {
        let (server_cfg, cert_der) = make_server_config()?;
        let endpoint = match Endpoint::server(server_cfg, addr) {
            Ok(ep) => ep,
            Err(_e) => return Err(P2pError::InvalidConfig),
        };
        let (tx, mut rx) = mpsc::channel::<crate::async_svc::OutboundEnvelope>(1024);
        let connections: Arc<Mutex<Vec<quinn::Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let handshake_sem = Arc::new(Semaphore::new(MAX_QUIC_HANDSHAKES_IN_FLIGHT));
        let ep_clone = endpoint.clone();
        let svc_clone = svc.clone();
        let conns_for_accept = connections.clone();
        let sem_for_accept = handshake_sem.clone();
        let handle = tokio::spawn(async move {
            while let Some(connecting) = ep_clone.accept().await {
                let permit = match sem_for_accept.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // Too many in-flight handshakes: drop the incoming connection attempt early.
                        continue;
                    }
                };
                let conns_for_accept = conns_for_accept.clone();
                let svc2 = svc_clone.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let new_conn = match timeout(QUIC_HANDSHAKE_TIMEOUT, connecting).await {
                        Ok(Ok(c)) => c,
                        Ok(Err(_e)) => return,
                        Err(_elapsed) => return,
                    };
                    if let Ok(mut guard) = conns_for_accept.lock() {
                        guard.retain(|c| c.close_reason().is_none());
                        if guard.len() >= max_connections.max(1) {
                            new_conn.close(VarInt::from_u32(0), b"too many connections");
                            return;
                        }
                        guard.push(new_conn.clone());
                    }
                    let peer = new_conn.remote_address();
                    tokio::spawn(async move {
                        let mut budget = ByteBudget::new(
                            DEFAULT_QUIC_IN_BYTES_BURST,
                            DEFAULT_QUIC_IN_BYTES_PER_SEC,
                        );
                        while let Ok(recv) = new_conn.accept_uni().await {
                            if let Ok(Some(m)) = read_one(recv, &mut budget).await {
                                let _ = svc2.send_message_from(peer, m).await;
                            }
                        }
                    });
                });
            }
        });
        let conns_for_broadcast = connections.clone();
        tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                let (target_peer, msg) = env.into_parts();
                let buf = match encode_msg(&msg) {
                    Ok(b) => Arc::new(b),
                    Err(_) => continue,
                };
                if let Ok(mut guard) = conns_for_broadcast.lock() {
                    guard.retain(|c| c.close_reason().is_none());
                    for conn in guard.iter() {
                        if let Some(peer) = target_peer {
                            if conn.remote_address() != peer {
                                continue;
                            }
                        }
                        let buf = buf.clone();
                        let c = conn.clone();
                        tokio::spawn(async move {
                            match c.open_uni().await {
                                Ok(mut s) => {
                                    if let Err(_e) = s.write_all(&buf[..]).await {
                                        super::async_svc::out_error_inc();
                                        return;
                                    }
                                    if let Err(_e) = s.finish() {
                                        super::async_svc::out_error_inc();
                                    }
                                }
                                Err(_e) => {
                                    super::async_svc::out_error_inc();
                                }
                            }
                        });
                    }
                }
            }
        });
        Ok((endpoint, cert_der, handle, tx))
    }

    pub fn client_config_from_cert(cert_der: &[u8]) -> Result<ClientConfig, P2pError> {
        // Ensure a CryptoProvider is installed (rustls 0.23+). This avoids a runtime panic
        // if no default provider has been set by crate features at this point.
        #[cfg(feature = "quic")]
        {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let mut roots = RootCertStore::empty();
        if roots.add(CertificateDer::from(cert_der.to_vec())).is_err() {
            return Err(P2pError::InvalidConfig);
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"hq-29".to_vec()];
        let quic_tls = QuicClientConfig::try_from(std::sync::Arc::new(tls))
            .map_err(|_| P2pError::InvalidConfig)?;
        Ok(ClientConfig::new(std::sync::Arc::new(quic_tls)))
    }

    pub fn client_config_from_cert_with_client_auth(
        cert_der: &[u8],
        client_cert_path: &str,
        client_key_path: &str,
    ) -> Result<ClientConfig, P2pError> {
        use rustls::pki_types::pem::{Error as PemError, PemObject};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = RootCertStore::empty();
        if roots.add(CertificateDer::from(cert_der.to_vec())).is_err() {
            return Err(P2pError::InvalidConfig);
        }
        let cert_bytes = std::fs::read(client_cert_path).map_err(|_| P2pError::InvalidConfig)?;
        let certs: Vec<CertificateDer> = CertificateDer::pem_slice_iter(&cert_bytes)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| P2pError::InvalidConfig)?;
        let certs: Vec<CertificateDer> = if certs.is_empty() {
            vec![CertificateDer::from(cert_bytes)]
        } else {
            certs
        };

        let key_bytes = std::fs::read(client_key_path).map_err(|_| P2pError::InvalidConfig)?;
        let key = match PrivateKeyDer::from_pem_slice(&key_bytes) {
            Ok(k) => k,
            Err(PemError::NoItemsFound) => PrivateKeyDer::try_from(key_bytes.as_slice())
                .map(|k| k.clone_key())
                .map_err(|_| P2pError::InvalidConfig)?,
            Err(_) => return Err(P2pError::InvalidConfig),
        };

        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|_| P2pError::InvalidConfig)?;
        tls.alpn_protocols = vec![b"hq-29".to_vec()];
        let quic_tls = QuicClientConfig::try_from(std::sync::Arc::new(tls))
            .map_err(|_| P2pError::InvalidConfig)?;
        Ok(ClientConfig::new(std::sync::Arc::new(quic_tls)))
    }

    pub async fn connect(
        addr: SocketAddr,
        cfg: ClientConfig,
    ) -> Result<quinn::Connection, P2pError> {
        let bind_addr: std::net::SocketAddr = match "0.0.0.0:0".parse() {
            Ok(a) => a,
            Err(_e) => return Err(P2pError::InvalidConfig),
        };
        let mut endpoint = match Endpoint::client(bind_addr) {
            Ok(ep) => ep,
            Err(_e) => return Err(P2pError::InvalidConfig),
        };
        endpoint.set_default_client_config(cfg);
        let connecting = match endpoint.connect(addr, "localhost") {
            Ok(c) => c,
            Err(_e) => return Err(P2pError::InvalidConfig),
        };
        match connecting.await {
            Ok(c) => Ok(c),
            Err(_e) => Err(P2pError::InvalidConfig),
        }
    }

    pub struct QuicClientSink {
        conn: quinn::Connection,
    }
    impl QuicClientSink {
        pub fn new(conn: quinn::Connection) -> Self {
            Self { conn }
        }

        /// Best-effort reliable delivery for short-lived CLI tools.
        ///
        /// `deliver()` intentionally does not wait for the peer to acknowledge receipt; this keeps
        /// the hot path fast. For one-shot commands that exit immediately after sending (like
        /// `p2p-inject-*`), that can cause message loss under load. This helper waits briefly after
        /// finishing the stream so the QUIC stack can flush and (usually) receive an ACK.
        pub async fn deliver_wait(&self, msg: P2pMessage) -> Result<(), P2pError> {
            let buf = encode_msg(&msg)?;
            let mut s = match self.conn.open_uni().await {
                Ok(st) => st,
                Err(_e) => {
                    super::async_svc::out_error_inc();
                    return Err(P2pError::ChannelClosed);
                }
            };
            if let Err(_e) = s.write_all(&buf).await {
                super::async_svc::out_error_inc();
                return Err(P2pError::ChannelClosed);
            }
            if let Err(_e) = s.finish() {
                super::async_svc::out_error_inc();
                return Err(P2pError::ChannelClosed);
            }

            // Wait a bit for the peer to ACK the stream data; ignore timeouts to avoid hanging CLIs.
            // `SendStream::stopped()` completes once all data is acknowledged (or the peer stops it).
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.stopped()).await;
            Ok(())
        }
    }

    async fn send_on_connection(
        conn: &quinn::Connection,
        msg: &P2pMessage,
    ) -> Result<(), P2pError> {
        let buf = encode_msg(msg)?;
        let mut s = conn.open_uni().await.map_err(|_| P2pError::ChannelClosed)?;
        s.write_all(&buf)
            .await
            .map_err(|_| P2pError::ChannelClosed)?;
        s.finish().map_err(|_| P2pError::ChannelClosed)?;
        Ok(())
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[async_trait::async_trait]
    impl super::async_svc::OutboundSink for QuicClientSink {
        async fn deliver(&self, msg: P2pMessage) -> Result<(), P2pError> {
            let buf = match encode_msg(&msg) {
                Ok(b) => b,
                Err(e) => {
                    super::async_svc::out_error_inc();
                    return Err(e);
                }
            };
            let mut s = match self.conn.open_uni().await {
                Ok(st) => st,
                Err(_e) => {
                    super::async_svc::out_error_inc();
                    return Err(P2pError::ChannelClosed);
                }
            };
            if let Err(_e) = s.write_all(&buf).await {
                super::async_svc::out_error_inc();
                return Err(P2pError::ChannelClosed);
            }
            if let Err(_e) = s.finish() {
                super::async_svc::out_error_inc();
                return Err(P2pError::ChannelClosed);
            }
            Ok(())
        }
    }

    pub fn spawn_client_reader(
        conn: quinn::Connection,
        svc: P2pService,
        last_pong_ms: Option<Arc<AtomicU64>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut budget =
                ByteBudget::new(DEFAULT_QUIC_IN_BYTES_BURST, DEFAULT_QUIC_IN_BYTES_PER_SEC);
            while let Ok(recv) = conn.accept_uni().await {
                if let Ok(Some(m)) = read_one(recv, &mut budget).await {
                    match m {
                        P2pMessage::Ping => {
                            let _ = send_on_connection(&conn, &P2pMessage::Pong).await;
                        }
                        P2pMessage::Pong => {
                            if let Some(ts) = &last_pong_ms {
                                ts.store(now_millis(), Ordering::Relaxed);
                            }
                        }
                        _ => {}
                    }
                    let _ = svc.send_message_from(conn.remote_address(), m).await;
                }
            }
        })
    }
}

#[cfg(feature = "async")]
pub mod async_svc {
    use super::messages::{self, P2pMessage, ReqMsg, RespMsg};
    use super::*;
    use crate::peer_store::PeerStore;
    use pc_codec::Encodable;
    use pc_types::payload_merkle_root_v3 as payload_merkle_root;
    use pc_types::{digest_evidence, digest_microtx};
    use pc_types::{
        AnchorHeaderV2 as AnchorHeader, AnchorId, AnchorPayloadV3 as AnchorPayload, EvidenceEvent,
        MicroTx,
    };
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::hash::{Hash, Hasher};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Instant;
    use tokio::sync::broadcast;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{interval, sleep, Duration};
    use tracing::{debug, info, warn};

    // Optional store backend delegate (e.g. disk store). Thread-safe and async-capable.
    // Optionales Store-Backend-Delegate (z. B. Diskstore). Threadsicher und async-fähig.
    #[async_trait::async_trait]
    pub trait StoreDelegate: Send + Sync {
        /// Admission check for remote headers before they are persisted / trigger DA-gating.
        ///
        /// Default: accept everything (backward compatible).
        async fn admit_header(&self, _h: &AnchorHeader) -> bool {
            true
        }
        async fn insert_header(&self, h: AnchorHeader);
        async fn insert_payload(&self, p: AnchorPayload);
        async fn has_payload(&self, root: &[u8; 32]) -> bool;
        async fn get_headers(&self, ids: &[AnchorId]) -> (Vec<AnchorHeader>, Vec<[u8; 32]>);
        async fn get_payloads(&self, roots: &[[u8; 32]]) -> (Vec<AnchorPayload>, Vec<[u8; 32]>);
        async fn insert_tx(&self, tx: MicroTx);
        async fn has_tx(&self, id: &[u8; 32]) -> bool;
        async fn get_txs(&self, ids: &[[u8; 32]]) -> (Vec<MicroTx>, Vec<[u8; 32]>);

        // Optional: evidence propagation. Default impls keep backward compatibility for
        // store delegates that don't persist evidence.
        async fn insert_evidence(&self, _e: EvidenceEvent) {}
        async fn has_evidence(&self, _id: &[u8; 32]) -> bool {
            false
        }
        async fn get_evidences(&self, ids: &[[u8; 32]]) -> (Vec<EvidenceEvent>, Vec<[u8; 32]>) {
            (Vec::new(), ids.to_vec())
        }
    }

    #[derive(Debug)]
    pub enum P2pCmd {
        AnnounceHeader(AnchorHeader),
        PutHeader(AnchorHeader),
        PutPayload(AnchorPayload),
        PutTx(MicroTx),
        PutEvidence(EvidenceEvent),
        Incoming(P2pMessage),
        IncomingFrom(SocketAddr, P2pMessage),
        Rpc(ReqMsg, oneshot::Sender<RespMsg>),
        // New outbound RPC command: sends a ReqMsg via the outbox (libp2p request_response).
        // Neuer Outbound-RPC-Befehl: sendet ReqMsg über die Outbox (libp2p request_response)
        SendReq(ReqMsg),
        // New outbound INV commands: publish INV via the outbox (libp2p gossipsub).
        // Neue Outbound-INV-Befehle: publizieren INV über die Outbox (libp2p gossipsub)
        SendHeadersInv(Vec<AnchorId>),
        SendPayloadInv(Vec<[u8; 32]>),
        // PEX: Aktualisiert den aktuellen AnchorIndex für PeerStore-Operationen
        SetAnchor(u64),
        Shutdown,
    }

    #[derive(Clone)]
    pub struct P2pService {
        tx: mpsc::Sender<P2pCmd>,
    }

    impl P2pService {
        pub async fn put_header(&self, hdr: AnchorHeader) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::PutHeader(hdr))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn announce_header(&self, hdr: AnchorHeader) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::AnnounceHeader(hdr))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn put_payload(&self, pl: AnchorPayload) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::PutPayload(pl))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn put_tx(&self, tx: MicroTx) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::PutTx(tx))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn put_evidence(&self, evid: EvidenceEvent) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::PutEvidence(evid))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn send_message(&self, msg: P2pMessage) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::Incoming(msg))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        /// Outbound RPC: sends a ReqMsg via the outbox (libp2p request_response).
        /// Outbound-RPC: sendet eine ReqMsg über die Outbox (libp2p request_response)
        pub async fn send_req(&self, req: ReqMsg) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::SendReq(req))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        /// Outbound gossip: publishes HEADERS_INV via the outbox (libp2p gossipsub).
        /// Outbound-Gossip: publiziert HEADERS_INV über die Outbox (libp2p gossipsub)
        pub async fn publish_headers_inv(&self, ids: Vec<AnchorId>) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::SendHeadersInv(ids))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        /// Outbound gossip: publishes PAYLOAD_INV via the outbox (libp2p gossipsub).
        /// Outbound-Gossip: publiziert PAYLOAD_INV über die Outbox (libp2p gossipsub)
        pub async fn publish_payload_inv(&self, roots: Vec<[u8; 32]>) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::SendPayloadInv(roots))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn send_message_from(
            &self,
            peer: SocketAddr,
            msg: P2pMessage,
        ) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::IncomingFrom(peer, msg))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn shutdown(&self) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::Shutdown)
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        /// PEX: Setzt den aktuellen AnchorIndex für PeerStore-Operationen
        pub async fn set_anchor(&self, anchor: u64) -> Result<(), P2pError> {
            self.tx
                .send(P2pCmd::SetAnchor(anchor))
                .await
                .map_err(|_| P2pError::ChannelClosed)
        }
        /// Synchronous RPC bridge: processes a ReqMsg locally and returns a RespMsg.
        /// Synchrone RPC-Brücke: verarbeitet ReqMsg lokal und liefert eine RespMsg.
        pub async fn rpc_call(&self, req: ReqMsg) -> Result<RespMsg, P2pError> {
            let (tx, rx) = oneshot::channel();
            self.tx
                .send(P2pCmd::Rpc(req, tx))
                .await
                .map_err(|_| P2pError::ChannelClosed)?;
            rx.await.map_err(|_| P2pError::ChannelClosed)
        }
    }

    // Global metrics (process-wide).
    // Globale Metriken (prozessweit)
    static INBOUND_TOTAL: AtomicU64 = AtomicU64::new(0);
    static INBOUND_DROPPED_RATE: AtomicU64 = AtomicU64::new(0);
    static OUTBOUND_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Approx. bytes seen on the wire (encoded message size). Updated by transport backends.
    // Ungefähre Bytes auf dem Wire (encoded message size). Wird von Transport-Backends aktualisiert.
    static INBOUND_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUTBOUND_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
    static PEER_RL_PURGED_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Per-message type (inbound).
    // Per-Message-Typ (Inbound)
    static IN_HDR_TOTAL: AtomicU64 = AtomicU64::new(0);
    static IN_INV_TOTAL: AtomicU64 = AtomicU64::new(0);
    static IN_REQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    static IN_RESP_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Per-message type (outbound).
    // Per-Message-Typ (Outbound)
    static OUT_HDR_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUT_INV_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUT_REQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUT_RESP_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Outbound errors (network/QUIC).
    // Outbound-Fehler (Netz/QUIC)
    static OUT_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Outbox queue (mpsc).
    // Outbox-Queue (mpsc)
    static OUTBOX_ENQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUTBOX_DEQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUTBOX_DROP_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Best-effort current depth of the outbox channel.
    // Best-Effort aktuelle Tiefe des Outbox-Channels.
    static OUTBOX_DEPTH: AtomicU64 = AtomicU64::new(0);
    static IN_DEDUP_TOTAL: AtomicU64 = AtomicU64::new(0);
    // PeerStore role counts (updated periodically by P2P loop)
    // PeerStore Rollen-Zähler (werden periodisch vom P2P-Loop aktualisiert)
    static PEERS_KNOWN_TOTAL: AtomicU64 = AtomicU64::new(0);
    static PEERS_MINER_TOTAL: AtomicU64 = AtomicU64::new(0);
    static PEERS_VALIDATOR_TOTAL: AtomicU64 = AtomicU64::new(0);
    static PEERS_BANNED_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Latency histogram (inbound handling) – buckets in seconds: 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, +Inf.
    // Latenz-Histogramm (Inbound-Handling) – Buckets in Sekunden: 1ms,5ms,10ms,50ms,100ms,500ms,+Inf
    static IN_HIST_LE_1MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_5MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_10MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_50MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_100MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_500MS: AtomicU64 = AtomicU64::new(0);
    static IN_HANDLE_COUNT: AtomicU64 = AtomicU64::new(0);
    static IN_HANDLE_SUM_MICROS: AtomicU64 = AtomicU64::new(0);

    // Inbound observer (broadcast): allows external subscribers to observe incoming P2P messages.
    // Inbound-Observer (Broadcast): ermöglicht externen Abonnenten, eingehende P2P-Messages zu beobachten
    static INBOUND_OBS: OnceLock<broadcast::Sender<P2pMessage>> = OnceLock::new();

    // Bench mode: disable periodic anti-entropy.
    // Bench-Mode: periodic anti-entropy ausschalten
    static BENCH_MODE: AtomicBool = AtomicBool::new(false);
    pub fn set_bench_mode(on: bool) {
        BENCH_MODE.store(on, Ordering::Relaxed);
    }
    pub fn is_bench_mode() -> bool {
        BENCH_MODE.load(Ordering::Relaxed)
    }

    // One-shot RPC watcher: per requested object (header ID or payload root).
    // OneShot-RPC Watcher: pro angefragtem Objekt (Header-ID oder Payload-Root)
    #[derive(Clone, Debug, Eq)]
    enum WatchKey {
        Header([u8; 32]),
        Payload([u8; 32]),
    }
    impl PartialEq for WatchKey {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (WatchKey::Header(a), WatchKey::Header(b)) => a == b,
                (WatchKey::Payload(a), WatchKey::Payload(b)) => a == b,
                _ => false,
            }
        }
    }
    impl Hash for WatchKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            match self {
                WatchKey::Header(x) => {
                    1u8.hash(state);
                    x.hash(state);
                }
                WatchKey::Payload(x) => {
                    2u8.hash(state);
                    x.hash(state);
                }
            }
        }
    }
    type WatchMap = std::collections::HashMap<WatchKey, Vec<oneshot::Sender<RespMsg>>>;
    static WATCHERS: OnceLock<std::sync::Mutex<WatchMap>> = OnceLock::new();
    fn watchers() -> &'static std::sync::Mutex<WatchMap> {
        WATCHERS.get_or_init(|| std::sync::Mutex::new(WatchMap::new()))
    }

    pub fn watch_header(id: AnchorId) -> oneshot::Receiver<RespMsg> {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut map) = watchers().lock() {
            map.entry(WatchKey::Header(id.0)).or_default().push(tx);
        }
        rx
    }
    pub fn watch_payload(root: [u8; 32]) -> oneshot::Receiver<RespMsg> {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut map) = watchers().lock() {
            map.entry(WatchKey::Payload(root)).or_default().push(tx);
        }
        rx
    }

    fn dispatch_watchers(resp: &RespMsg) {
        use RespMsg::*;
        match resp {
            PrevoteHeaders { .. } | PrecommitHeaders { .. } | StagedHeaders { .. } => {
                if let Ok(mut map) = watchers().lock() {
                    for h in messages::header_response_headers(resp).unwrap_or_default() {
                        let key = WatchKey::Header(h.id_digest());
                        if let Some(list) = map.get_mut(&key) {
                            if let Some(tx) = list.pop() {
                                let _ = tx
                                    .send(messages::explicit_header_response_for_headers(vec![h]));
                            }
                            if list.is_empty() {
                                let _ = map.remove(&key);
                            }
                        }
                    }
                }
            }
            Payloads { payloads } => {
                if let Ok(mut map) = watchers().lock() {
                    for p in payloads.iter() {
                        let root = payload_merkle_root(p);
                        let key = WatchKey::Payload(root);
                        if let Some(list) = map.get_mut(&key) {
                            if let Some(tx) = list.pop() {
                                let _ = tx.send(RespMsg::Payloads {
                                    payloads: vec![p.clone()],
                                });
                            }
                            if list.is_empty() {
                                let _ = map.remove(&key);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn notify_inbound(msg: &P2pMessage) {
        if let Some(tx) = INBOUND_OBS.get() {
            let _ = tx.send(msg.clone());
        }
    }

    fn normalize_announced_header_message(
        msg: P2pMessage,
    ) -> Result<(AnchorHeader, P2pMessage), &'static str> {
        match msg {
            P2pMessage::PrevoteAnnounce(header) => {
                if header.state_root.is_some() {
                    Err("prevote_state_root_present")
                } else {
                    Ok((header.clone(), P2pMessage::PrevoteAnnounce(header)))
                }
            }
            P2pMessage::PrecommitAnnounce(header) => {
                if header.state_root.is_none() {
                    Err("precommit_state_root_missing")
                } else {
                    Ok((header.clone(), P2pMessage::PrecommitAnnounce(header)))
                }
            }
            _ => Err("not_a_header_announce"),
        }
    }

    const DEFAULT_INBOUND_OBS_CAPACITY: usize = 4096;
    const MAX_INBOUND_OBS_CAPACITY: usize = 100_000;

    fn parse_inbound_obs_capacity(s: &str) -> Option<usize> {
        s.parse::<usize>()
            .ok()
            .filter(|&n| (1..=MAX_INBOUND_OBS_CAPACITY).contains(&n))
    }

    /// Subscribe to inbound P2P messages (PrevoteAnnounce/PrecommitAnnounce/Inv/Req/Resp)
    /// processed by the service.
    /// Abonniere eingehende P2P-Messages (PrevoteAnnounce/PrecommitAnnounce/Inv/Req/Resp), die
    /// der Service verarbeitet.
    pub fn inbound_subscribe() -> broadcast::Receiver<P2pMessage> {
        let tx = INBOUND_OBS.get_or_init(|| {
            // Configurable via env var to avoid hardcoding for operators.
            // Note: this is process-global and must be set before the first subscribe call.
            let cap = std::env::var("PC_P2P_INBOUND_OBS_CAP")
                .ok()
                .as_deref()
                .and_then(parse_inbound_obs_capacity)
                .unwrap_or(DEFAULT_INBOUND_OBS_CAPACITY);
            let (tx, _rx) = broadcast::channel(cap);
            tx
        });
        tx.subscribe()
    }

    #[cfg(test)]
    mod inbound_obs_tests {
        use super::*;

        #[test]
        fn parse_inbound_obs_capacity_bounds() {
            assert_eq!(parse_inbound_obs_capacity("0"), None);
            assert_eq!(parse_inbound_obs_capacity("1"), Some(1));
            assert_eq!(
                parse_inbound_obs_capacity(&(MAX_INBOUND_OBS_CAPACITY + 1).to_string()),
                None
            );
        }
    }

    // Public increment helpers for other modules.
    // Öffentliche Inkrement-Helfer für andere Module
    pub fn out_error_inc() {
        OUT_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    pub fn outbox_deq_inc() {
        OUTBOX_DEQ_TOTAL.fetch_add(1, Ordering::Relaxed);
        // Keep gauge non-negative.
        // Gauge nie negativ werden lassen.
        loop {
            let cur = OUTBOX_DEPTH.load(Ordering::Relaxed);
            if cur == 0 {
                break;
            }
            if OUTBOX_DEPTH
                .compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
    pub fn record_inbound_bytes(n: usize) {
        let v = u64::try_from(n).unwrap_or(u64::MAX);
        INBOUND_BYTES_TOTAL.fetch_add(v, Ordering::Relaxed);
    }
    pub fn record_outbound_bytes(n: usize) {
        let v = u64::try_from(n).unwrap_or(u64::MAX);
        OUTBOUND_BYTES_TOTAL.fetch_add(v, Ordering::Relaxed);
    }

    #[derive(Debug, Clone, Copy)]
    pub struct MetricsSnapshot {
        pub inbound_total: u64,
        pub inbound_dropped_rate: u64,
        pub outbound_total: u64,
        pub inbound_bytes_total: u64,
        pub outbound_bytes_total: u64,
        pub peer_rl_purged_total: u64,
        // inbound per-Message-Typ
        pub in_hdr_total: u64,
        pub in_inv_total: u64,
        pub in_req_total: u64,
        pub in_resp_total: u64,
        // outbound per-Message-Typ
        pub out_hdr_total: u64,
        pub out_inv_total: u64,
        pub out_req_total: u64,
        pub out_resp_total: u64,
        // outbound Fehler und Outbox-Queue
        pub out_errors_total: u64,
        pub outbox_enq_total: u64,
        pub outbox_deq_total: u64,
        pub outbox_drop_total: u64,
        pub outbox_depth: u64,
        pub in_dedup_total: u64,
        pub in_handle_count: u64,
        pub in_handle_sum_micros: u64,
        pub in_bucket_le_1ms: u64,
        pub in_bucket_le_5ms: u64,
        pub in_bucket_le_10ms: u64,
        pub in_bucket_le_50ms: u64,
        pub in_bucket_le_100ms: u64,
        pub in_bucket_le_500ms: u64,
        // PeerStore role counts
        pub peers_known_total: u64,
        pub peers_miner_total: u64,
        pub peers_validator_total: u64,
        pub peers_banned_total: u64,
    }

    /// Aktualisiert die globalen PeerStore-Metriken basierend auf PeerRoleCounts
    pub fn update_peer_metrics(counts: crate::peer_store::PeerRoleCounts) {
        PEERS_KNOWN_TOTAL.store(counts.total, Ordering::Relaxed);
        PEERS_MINER_TOTAL.store(counts.miner, Ordering::Relaxed);
        PEERS_VALIDATOR_TOTAL.store(counts.validator, Ordering::Relaxed);
    }

    pub fn metrics_snapshot() -> MetricsSnapshot {
        MetricsSnapshot {
            inbound_total: INBOUND_TOTAL.load(Ordering::Relaxed),
            inbound_dropped_rate: INBOUND_DROPPED_RATE.load(Ordering::Relaxed),
            outbound_total: OUTBOUND_TOTAL.load(Ordering::Relaxed),
            inbound_bytes_total: INBOUND_BYTES_TOTAL.load(Ordering::Relaxed),
            outbound_bytes_total: OUTBOUND_BYTES_TOTAL.load(Ordering::Relaxed),
            peer_rl_purged_total: PEER_RL_PURGED_TOTAL.load(Ordering::Relaxed),
            in_hdr_total: IN_HDR_TOTAL.load(Ordering::Relaxed),
            in_inv_total: IN_INV_TOTAL.load(Ordering::Relaxed),
            in_req_total: IN_REQ_TOTAL.load(Ordering::Relaxed),
            in_resp_total: IN_RESP_TOTAL.load(Ordering::Relaxed),
            out_hdr_total: OUT_HDR_TOTAL.load(Ordering::Relaxed),
            out_inv_total: OUT_INV_TOTAL.load(Ordering::Relaxed),
            out_req_total: OUT_REQ_TOTAL.load(Ordering::Relaxed),
            out_resp_total: OUT_RESP_TOTAL.load(Ordering::Relaxed),
            out_errors_total: OUT_ERRORS_TOTAL.load(Ordering::Relaxed),
            outbox_enq_total: OUTBOX_ENQ_TOTAL.load(Ordering::Relaxed),
            outbox_deq_total: OUTBOX_DEQ_TOTAL.load(Ordering::Relaxed),
            outbox_drop_total: OUTBOX_DROP_TOTAL.load(Ordering::Relaxed),
            outbox_depth: OUTBOX_DEPTH.load(Ordering::Relaxed),
            in_dedup_total: IN_DEDUP_TOTAL.load(Ordering::Relaxed),
            in_handle_count: IN_HANDLE_COUNT.load(Ordering::Relaxed),
            in_handle_sum_micros: IN_HANDLE_SUM_MICROS.load(Ordering::Relaxed),
            in_bucket_le_1ms: IN_HIST_LE_1MS.load(Ordering::Relaxed),
            in_bucket_le_5ms: IN_HIST_LE_5MS.load(Ordering::Relaxed),
            in_bucket_le_10ms: IN_HIST_LE_10MS.load(Ordering::Relaxed),
            in_bucket_le_50ms: IN_HIST_LE_50MS.load(Ordering::Relaxed),
            in_bucket_le_100ms: IN_HIST_LE_100MS.load(Ordering::Relaxed),
            in_bucket_le_500ms: IN_HIST_LE_500MS.load(Ordering::Relaxed),
            peers_known_total: PEERS_KNOWN_TOTAL.load(Ordering::Relaxed),
            peers_miner_total: PEERS_MINER_TOTAL.load(Ordering::Relaxed),
            peers_validator_total: PEERS_VALIDATOR_TOTAL.load(Ordering::Relaxed),
            peers_banned_total: PEERS_BANNED_TOTAL.load(Ordering::Relaxed),
        }
    }

    fn record_in_latency(dur: std::time::Duration) {
        let micros = dur.as_micros() as u64;
        IN_HANDLE_COUNT.fetch_add(1, Ordering::Relaxed);
        IN_HANDLE_SUM_MICROS.fetch_add(micros, Ordering::Relaxed);
        // Buckets in ms thresholds
        let ms = micros as f64 / 1000.0;
        if ms <= 1.0 {
            IN_HIST_LE_1MS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if ms <= 5.0 {
            IN_HIST_LE_5MS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if ms <= 10.0 {
            IN_HIST_LE_10MS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if ms <= 50.0 {
            IN_HIST_LE_50MS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if ms <= 100.0 {
            IN_HIST_LE_100MS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if ms <= 500.0 {
            IN_HIST_LE_500MS.fetch_add(1, Ordering::Relaxed);
        }
        // +Inf: wird in der Exposition über count abgebildet
    }

    // Simple token bucket rate limiter per message type (global).
    // Einfache Token-Bucket-Rate-Limiter pro Nachrichtentyp (global)
    struct Bucket {
        capacity: f64,
        tokens: f64,
        refill_per_sec: f64,
        last: Instant,
    }

    impl Bucket {
        fn new(capacity: u32, refill_per_sec: u32) -> Self {
            Self {
                capacity: capacity as f64,
                tokens: capacity as f64,
                refill_per_sec: refill_per_sec as f64,
                last: Instant::now(),
            }
        }
        fn allow(&mut self) -> bool {
            self.allow_n(1)
        }
        fn allow_n(&mut self, n: usize) -> bool {
            let now = Instant::now();
            let dt = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
            let want = n as f64;
            if self.tokens >= want {
                self.tokens -= want;
                true
            } else {
                false
            }
        }
    }

    struct RateLimiter {
        hdr: Bucket,
        inv: Bucket,
        req: Bucket,
        resp: Bucket,
        bytes: Bucket,
    }

    impl RateLimiter {
        fn from_cfg(cfg: Option<&RateLimitConfig>) -> Self {
            let default_bytes_capacity =
                u32::try_from(pc_types::MAX_PAYLOAD_BYTES.saturating_mul(2)).unwrap_or(u32::MAX);
            let default_bytes_refill_per_sec =
                u32::try_from(pc_types::MAX_PAYLOAD_BYTES).unwrap_or(u32::MAX);
            match cfg {
                Some(c) => Self {
                    hdr: Bucket::new(
                        if c.hdr_capacity == 0 {
                            200
                        } else {
                            c.hdr_capacity
                        },
                        if c.hdr_refill_per_sec == 0 {
                            200
                        } else {
                            c.hdr_refill_per_sec
                        },
                    ),
                    inv: Bucket::new(
                        if c.inv_capacity == 0 {
                            300
                        } else {
                            c.inv_capacity
                        },
                        if c.inv_refill_per_sec == 0 {
                            300
                        } else {
                            c.inv_refill_per_sec
                        },
                    ),
                    req: Bucket::new(
                        if c.req_capacity == 0 {
                            300
                        } else {
                            c.req_capacity
                        },
                        if c.req_refill_per_sec == 0 {
                            300
                        } else {
                            c.req_refill_per_sec
                        },
                    ),
                    resp: Bucket::new(
                        if c.resp_capacity == 0 {
                            300
                        } else {
                            c.resp_capacity
                        },
                        if c.resp_refill_per_sec == 0 {
                            300
                        } else {
                            c.resp_refill_per_sec
                        },
                    ),
                    bytes: Bucket::new(
                        if c.bytes_capacity == 0 {
                            default_bytes_capacity
                        } else {
                            c.bytes_capacity
                        },
                        if c.bytes_refill_per_sec == 0 {
                            default_bytes_refill_per_sec
                        } else {
                            c.bytes_refill_per_sec
                        },
                    ),
                },
                None => Self {
                    hdr: Bucket::new(200, 200),
                    inv: Bucket::new(300, 300),
                    req: Bucket::new(300, 300),
                    resp: Bucket::new(300, 300),
                    bytes: Bucket::new(default_bytes_capacity, default_bytes_refill_per_sec),
                },
            }
        }
        fn allow_msg(&mut self, msg: &P2pMessage) -> bool {
            // Defense in depth: byte-budget in addition to message-budget.
            // Tiefe Verteidigung: Byte-Budget zusätzlich zum Message-Budget.
            let size = msg.encoded_len();
            if !self.bytes.allow_n(size) {
                return false;
            }
            match msg {
                P2pMessage::PrevoteAnnounce(_) | P2pMessage::PrecommitAnnounce(_) => {
                    self.hdr.allow()
                }
                P2pMessage::HeadersInv { .. } => self.inv.allow(),
                P2pMessage::PayloadInv { .. } => self.inv.allow(),
                P2pMessage::TxInv { .. } => self.inv.allow(),
                P2pMessage::EvidenceInv { .. } => self.inv.allow(),
                P2pMessage::Peers { .. } => self.inv.allow(),
                P2pMessage::Ping => self.inv.allow(),
                P2pMessage::Pong => self.inv.allow(),
                P2pMessage::Req(_) => self.req.allow(),
                P2pMessage::Resp(_) => self.resp.allow(),
            }
        }
    }

    #[cfg(test)]
    mod rate_limit_tests {
        use super::*;
        use pc_types::{AnchorHeaderV2 as AnchorHeader, ParentList};

        fn prevote_announce() -> P2pMessage {
            P2pMessage::PrevoteAnnounce(AnchorHeader {
                version: 4,
                shard_id: 0,
                parents: ParentList::default(),
                payload_hash: [0x11; 32],
                creator_index: 0,
                vote_mask: 1,
                ack_present: false,
                ack_id: pc_types::AnchorId([0u8; 32]),
                network_id: [0x22; 32],
                vote_epoch: 1,
                vote_round: 1,
                state_root: None,
                attest_sig: None,
            })
        }

        #[test]
        fn header_burst_is_rate_limited_after_capacity_is_exhausted() {
            let cfg = RateLimitConfig {
                hdr_capacity: 1,
                hdr_refill_per_sec: 0,
                inv_capacity: 10,
                inv_refill_per_sec: 0,
                req_capacity: 10,
                req_refill_per_sec: 0,
                resp_capacity: 10,
                resp_refill_per_sec: 0,
                bytes_capacity: 4096,
                bytes_refill_per_sec: 0,
                per_peer: true,
                peer_ttl_secs: 60,
            };
            let msg = prevote_announce();
            let mut rl = RateLimiter::from_cfg(Some(&cfg));
            assert!(rl.allow_msg(&msg));
            assert!(!rl.allow_msg(&msg));
        }

        #[test]
        fn byte_budget_rejects_oversized_burst_even_when_header_tokens_remain() {
            let msg = prevote_announce();
            let cfg = RateLimitConfig {
                hdr_capacity: 10,
                hdr_refill_per_sec: 0,
                inv_capacity: 10,
                inv_refill_per_sec: 0,
                req_capacity: 10,
                req_refill_per_sec: 0,
                resp_capacity: 10,
                resp_refill_per_sec: 0,
                bytes_capacity: (msg.encoded_len() as u32).saturating_sub(1),
                bytes_refill_per_sec: 0,
                per_peer: true,
                peer_ttl_secs: 60,
            };
            let mut rl = RateLimiter::from_cfg(Some(&cfg));
            assert!(!rl.allow_msg(&msg));
        }
    }

    struct InMemoryStore {
        headers: HashMap<AnchorId, AnchorHeader>,
        payloads: HashMap<[u8; 32], AnchorPayload>,
        txs: HashMap<[u8; 32], MicroTx>,
        evidences: HashMap<[u8; 32], EvidenceEvent>,
        recent_hdrs: VecDeque<AnchorId>,
        recent_payload_roots: VecDeque<[u8; 32]>,
        recent_evidence_ids: VecDeque<[u8; 32]>,
    }

    const MAX_INMEM_HEADERS: usize = 200_000;
    const MAX_INMEM_PAYLOADS: usize = 50_000;
    const MAX_INMEM_TXS: usize = 200_000;
    const MAX_INMEM_EVIDENCES: usize = 200_000;

    impl InMemoryStore {
        fn new() -> Self {
            Self {
                headers: HashMap::new(),
                payloads: HashMap::new(),
                txs: HashMap::new(),
                evidences: HashMap::new(),
                recent_hdrs: VecDeque::with_capacity(1024),
                recent_payload_roots: VecDeque::with_capacity(1024),
                recent_evidence_ids: VecDeque::with_capacity(1024),
            }
        }
        fn note_header_id(&mut self, id: AnchorId) {
            self.recent_hdrs.push_back(id);
            if self.recent_hdrs.len() > 1024 {
                let _ = self.recent_hdrs.pop_front();
            }
        }
        fn note_payload_root(&mut self, root: [u8; 32]) {
            self.recent_payload_roots.push_back(root);
            if self.recent_payload_roots.len() > 1024 {
                let _ = self.recent_payload_roots.pop_front();
            }
        }
        fn note_evidence_id(&mut self, id: [u8; 32]) {
            self.recent_evidence_ids.push_back(id);
            if self.recent_evidence_ids.len() > 1024 {
                let _ = self.recent_evidence_ids.pop_front();
            }
        }
        fn insert_header(&mut self, h: AnchorHeader) {
            let id = AnchorId(h.id_digest());
            if !self.headers.contains_key(&id) && self.headers.len() >= MAX_INMEM_HEADERS {
                if let Some(drop_id) = self.headers.keys().copied().find(|k| *k != id) {
                    let _ = self.headers.remove(&drop_id);
                }
            }
            let _ = self.headers.insert(id, h);
            self.note_header_id(id);
        }
        fn insert_payload(&mut self, p: AnchorPayload) {
            let root = payload_merkle_root(&p);
            if !self.payloads.contains_key(&root) && self.payloads.len() >= MAX_INMEM_PAYLOADS {
                if let Some(drop_root) = self.payloads.keys().copied().find(|k| *k != root) {
                    let _ = self.payloads.remove(&drop_root);
                }
            }
            let _ = self.payloads.insert(root, p);
            self.note_payload_root(root);
        }
        fn has_payload(&self, root: &[u8; 32]) -> bool {
            self.payloads.contains_key(root)
        }
        fn get_headers(&self, ids: &[AnchorId]) -> (Vec<AnchorHeader>, Vec<[u8; 32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                if let Some(h) = self.headers.get(id) {
                    found.push(h.clone());
                } else {
                    missing.push(id.0);
                }
            }
            (found, missing)
        }
        fn get_payloads(&self, roots: &[[u8; 32]]) -> (Vec<AnchorPayload>, Vec<[u8; 32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for r in roots {
                if let Some(p) = self.payloads.get(r) {
                    found.push(p.clone());
                } else {
                    missing.push(*r);
                }
            }
            (found, missing)
        }
        fn insert_tx(&mut self, tx: MicroTx) {
            let id = digest_microtx(&tx);
            if !self.txs.contains_key(&id) && self.txs.len() >= MAX_INMEM_TXS {
                if let Some(drop_id) = self.txs.keys().copied().find(|k| *k != id) {
                    let _ = self.txs.remove(&drop_id);
                }
            }
            let _ = self.txs.insert(id, tx);
        }
        fn insert_evidence(&mut self, evid: EvidenceEvent) {
            let id = digest_evidence(&evid);
            if !self.evidences.contains_key(&id) && self.evidences.len() >= MAX_INMEM_EVIDENCES {
                if let Some(drop_id) = self.evidences.keys().copied().find(|k| *k != id) {
                    let _ = self.evidences.remove(&drop_id);
                }
            }
            let _ = self.evidences.insert(id, evid);
            self.note_evidence_id(id);
        }
        fn has_tx(&self, id: &[u8; 32]) -> bool {
            self.txs.contains_key(id)
        }
        #[allow(dead_code)]
        fn has_evidence(&self, id: &[u8; 32]) -> bool {
            self.evidences.contains_key(id)
        }
        fn get_txs(&self, ids: &[[u8; 32]]) -> (Vec<MicroTx>, Vec<[u8; 32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                if let Some(tx) = self.txs.get(id) {
                    found.push(tx.clone());
                } else {
                    missing.push(*id);
                }
            }
            (found, missing)
        }
        fn get_evidences(&self, ids: &[[u8; 32]]) -> (Vec<EvidenceEvent>, Vec<[u8; 32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                if let Some(e) = self.evidences.get(id) {
                    found.push(e.clone());
                } else {
                    missing.push(*id);
                }
            }
            (found, missing)
        }
        fn recent_headers_sample(&self, n: usize) -> Vec<AnchorId> {
            let len = self.recent_hdrs.len();
            let take = n.min(len);
            self.recent_hdrs.iter().rev().take(take).cloned().collect()
        }
        fn recent_payload_roots_sample(&self, n: usize) -> Vec<[u8; 32]> {
            let len = self.recent_payload_roots.len();
            let take = n.min(len);
            self.recent_payload_roots
                .iter()
                .rev()
                .take(take)
                .cloned()
                .collect()
        }
        fn recent_evidence_ids_sample(&self, n: usize) -> Vec<[u8; 32]> {
            let len = self.recent_evidence_ids.len();
            let take = n.min(len);
            self.recent_evidence_ids
                .iter()
                .rev()
                .take(take)
                .cloned()
                .collect()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum OutboundEnvelope {
        Broadcast(P2pMessage),
        Direct { peer: SocketAddr, msg: P2pMessage },
    }

    impl OutboundEnvelope {
        pub fn message(&self) -> &P2pMessage {
            match self {
                Self::Broadcast(msg) | Self::Direct { msg, .. } => msg,
            }
        }

        pub fn into_parts(self) -> (Option<SocketAddr>, P2pMessage) {
            match self {
                Self::Broadcast(msg) => (None, msg),
                Self::Direct { peer, msg } => (Some(peer), msg),
            }
        }
    }

    #[derive(Clone)]
    struct Outbox {
        tx: mpsc::Sender<OutboundEnvelope>,
    }
    impl Outbox {
        async fn enqueue(&self, msg: P2pMessage, direct_peer: Option<SocketAddr>) {
            // Count outbox enqueue + outbound per message type.
            // Outbox Enqueue + Outbound per-Message-Typ zählen
            OUTBOX_ENQ_TOTAL.fetch_add(1, Ordering::Relaxed);
            OUTBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
            match &msg {
                P2pMessage::PrevoteAnnounce(_) | P2pMessage::PrecommitAnnounce(_) => {
                    OUT_HDR_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::HeadersInv { .. } => {
                    OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::PayloadInv { .. } => {
                    OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::TxInv { .. } => {
                    OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::EvidenceInv { .. } => {
                    OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::Peers { .. } => {
                    OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::Ping => {
                    OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::Pong => {
                    OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::Req(_) => {
                    OUT_REQ_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::Resp(_) => {
                    OUT_RESP_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Backpressure: drop low-priority messages (Announce/Inv) when the channel is full.
            // Backpressure: niedrige Priorität (Announce/Inv) droppen bei vollem Kanal
            let low_prio = matches!(
                msg,
                P2pMessage::PrevoteAnnounce(_)
                    | P2pMessage::PrecommitAnnounce(_)
                    | P2pMessage::HeadersInv { .. }
                    | P2pMessage::PayloadInv { .. }
                    | P2pMessage::TxInv { .. }
                    | P2pMessage::EvidenceInv { .. }
                    | P2pMessage::Peers { .. }
                    | P2pMessage::Ping
                    | P2pMessage::Pong
            );
            // Depth should track "in-flight" messages submitted to the outbox. We increment early
            // to avoid races where the receiver dequeues before we update the gauge.
            // Depth soll "in-flight" Messages tracken. Wir inkrementieren früh, um Races zu vermeiden
            // (Receiver dequeued bevor Gauge aktualisiert ist).
            OUTBOX_DEPTH.fetch_add(1, Ordering::Relaxed);
            let envelope = match direct_peer {
                Some(peer) => OutboundEnvelope::Direct { peer, msg },
                None => OutboundEnvelope::Broadcast(msg),
            };
            let enqueued = if low_prio {
                match self.tx.try_send(envelope) {
                    Ok(()) => true,
                    Err(_e) => {
                        OUTBOX_DROP_TOTAL.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
            } else {
                match self.tx.send(envelope).await {
                    Ok(()) => true,
                    Err(_e) => {
                        OUTBOX_DROP_TOTAL.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
            };
            if !enqueued {
                // Not enqueued: revert depth increment.
                loop {
                    let cur = OUTBOX_DEPTH.load(Ordering::Relaxed);
                    if cur == 0 {
                        break;
                    }
                    if OUTBOX_DEPTH
                        .compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        break;
                    }
                }
            }
        }

        async fn send(&self, msg: P2pMessage) {
            self.enqueue(msg, None).await;
        }

        async fn send_to(&self, peer: SocketAddr, msg: P2pMessage) {
            self.enqueue(msg, Some(peer)).await;
        }
    }

    // Dedupe maps with TTL for INV.
    // Dedupe-Maps mit TTL für INV
    const MAX_DEDUPE_ENTRIES: usize = 200_000;
    const DEDUPE_EVICT_SAMPLE: usize = 16;
    fn dedupe_insert_capped(map: &mut HashMap<[u8; 32], Instant>, key: [u8; 32], now: Instant) {
        map.insert(key, now);
        if map.len() <= MAX_DEDUPE_ENTRIES {
            return;
        }
        // Bound memory under adversarial INV spam: best-effort eviction of an old-ish entry.
        // Speicherbegrenzung unter adversarial INV-Spam: best-effort Eviction eines eher alten Eintrags.
        let mut drop_key: Option<[u8; 32]> = None;
        let mut drop_t: Option<Instant> = None;
        for (k, t) in map.iter().take(DEDUPE_EVICT_SAMPLE) {
            if *k == key {
                continue;
            }
            match drop_t {
                None => {
                    drop_key = Some(*k);
                    drop_t = Some(*t);
                }
                Some(cur) if *t < cur => {
                    drop_key = Some(*k);
                    drop_t = Some(*t);
                }
                _ => {}
            }
        }
        // Never evict the just-inserted key by fallback; otherwise dedupe can be bypassed.
        // Nie den gerade eingefügten Key per Fallback entfernen; sonst ist Dedupe umgehbar.
        if let Some(k) = drop_key.or_else(|| map.keys().copied().find(|k| *k != key)) {
            let _ = map.remove(&k);
        }
    }

    #[cfg(test)]
    mod dedupe_tests {
        use super::*;

        #[test]
        fn f60_dedupe_insert_capped_keeps_new_key_and_caps_len() {
            let base = Instant::now();
            let mut map: HashMap<[u8; 32], Instant> = HashMap::with_capacity(MAX_DEDUPE_ENTRIES);
            for i in 0..MAX_DEDUPE_ENTRIES {
                let mut k = [0u8; 32];
                k[..8].copy_from_slice(&(i as u64).to_le_bytes());
                map.insert(k, base);
            }
            assert_eq!(map.len(), MAX_DEDUPE_ENTRIES);

            let new_key = [0xAAu8; 32];
            dedupe_insert_capped(&mut map, new_key, base + Duration::from_millis(1));

            // Must never evict the just-inserted key (regression for adversarial bypass).
            assert!(map.contains_key(&new_key));
            // Dedupe must stay bounded by MAX_DEDUPE_ENTRIES under steady-state inserts.
            assert_eq!(map.len(), MAX_DEDUPE_ENTRIES);
        }
    }

    #[cfg(test)]
    mod store_tests {
        use super::*;

        #[test]
        fn f66_inmemory_store_caps_headers_len() {
            let mut store = InMemoryStore::new();
            let parents = pc_types::ParentList::default();

            // Insert more than the cap; store must stay bounded.
            for i in 0..(MAX_INMEM_HEADERS + 128) {
                let mut payload_hash = [0u8; 32];
                payload_hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let hdr = AnchorHeader {
                    version: 2,
                    shard_id: 0,
                    parents: parents.clone(),
                    payload_hash,
                    creator_index: 1,
                    vote_mask: 0,
                    ack_present: false,
                    ack_id: AnchorId([0u8; 32]),
                    network_id: [0u8; 32],
                    vote_epoch: 0,
                    vote_round: 0,
                    state_root: None,
                    attest_sig: None,
                };
                store.insert_header(hdr);
            }

            assert!(
                store.headers.len() <= MAX_INMEM_HEADERS,
                "headers map must be capped"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_inbound_message(
        peer: Option<SocketAddr>,
        msg: P2pMessage,
        rl: &mut RateLimiter,
        store: &mut InMemoryStore,
        store_delegate: Option<&Arc<dyn StoreDelegate>>,
        out: &Outbox,
        dedupe_hdr: &mut HashMap<[u8; 32], Instant>,
        dedupe_pl: &mut HashMap<[u8; 32], Instant>,
        dedupe_tx: &mut HashMap<[u8; 32], Instant>,
        dedupe_evid: &mut HashMap<[u8; 32], Instant>,
        dedupe_ttl: Duration,
        peer_store: &mut PeerStore,
        current_anchor: u64,
        last_get_peers: Option<Instant>,
        peers_req_ttl: Duration,
        allow_peer_exchange: bool,
    ) {
        let start = Instant::now();
        if is_bench_mode() || rl.allow_msg(&msg) {
            match msg {
                msg @ (P2pMessage::PrevoteAnnounce(_) | P2pMessage::PrecommitAnnounce(_)) => {
                    let (h, canonical_msg) = match normalize_announced_header_message(msg) {
                        Ok(v) => v,
                        Err(reason) => {
                            debug!(target: "pc_p2p.svc", event = "drop_header_announce", reason, "malformed staged header announce");
                            INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                            record_in_latency(start.elapsed());
                            return;
                        }
                    };
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_HDR_TOTAL.fetch_add(1, Ordering::Relaxed);
                    let h_clone = h.clone();
                    let admitted = if let Some(d) = store_delegate {
                        d.admit_header(&h_clone).await
                    } else {
                        true
                    };
                    if admitted {
                        let id = AnchorId(h_clone.id_digest());
                        if store_delegate.is_some() {
                            store.note_header_id(id);
                        }
                        if let Some(d) = store_delegate {
                            d.insert_header(h).await;
                        } else {
                            store.insert_header(h);
                        }

                        // DA-Gating: fehlende Payloads proaktiv anfordern (pull-then-vote).
                        let root = h_clone.payload_hash;
                        let present = if let Some(d) = store_delegate {
                            d.has_payload(&root).await
                        } else {
                            store.has_payload(&root)
                        };
                        if !present {
                            if is_bench_mode() {
                                out.send(P2pMessage::Req(ReqMsg::GetPayloads {
                                    roots: vec![root],
                                }))
                                .await;
                            } else {
                                let now = Instant::now();
                                match dedupe_pl.get(&root) {
                                    Some(&t) if now.duration_since(t) < dedupe_ttl => {
                                        IN_DEDUP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                    }
                                    _ => {
                                        dedupe_insert_capped(dedupe_pl, root, now);
                                        out.send(P2pMessage::Req(ReqMsg::GetPayloads {
                                            roots: vec![root],
                                        }))
                                        .await;
                                    }
                                }
                            }
                        }
                        notify_inbound(&canonical_msg);
                    } else {
                        INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                    }
                }
                P2pMessage::PayloadInv { roots } => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                    // Security hardening: treat PayloadInv as a hint only.
                    //
                    // Requesting/persisting payloads solely based on remote INV allows attackers
                    // to trigger unbounded disk/memory growth (storage DoS). We only fetch payloads
                    // when they are needed (e.g. referenced by admitted headers) or explicitly
                    // requested by local logic (SendReq / DA-gating).
                    notify_inbound(&P2pMessage::PayloadInv {
                        roots: roots.clone(),
                    });
                }
                P2pMessage::TxInv { ids } => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                    let mut missing: Vec<[u8; 32]> = Vec::new();
                    if is_bench_mode() {
                        for id in ids.iter() {
                            let present = if let Some(d) = store_delegate {
                                d.has_tx(id).await
                            } else {
                                store.has_tx(id)
                            };
                            if !present {
                                missing.push(*id);
                            }
                        }
                    } else {
                        let now = Instant::now();
                        for id in ids.iter() {
                            let present = if let Some(d) = store_delegate {
                                d.has_tx(id).await
                            } else {
                                store.has_tx(id)
                            };
                            if !present {
                                match dedupe_tx.get(id) {
                                    Some(&t) if now.duration_since(t) < dedupe_ttl => {
                                        IN_DEDUP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                    }
                                    _ => {
                                        dedupe_insert_capped(dedupe_tx, *id, now);
                                        missing.push(*id);
                                    }
                                }
                            }
                        }
                    }
                    if !missing.is_empty() {
                        for chunk in missing.chunks(super::messages::MAX_TXS_IN_MSG) {
                            out.send(P2pMessage::Req(ReqMsg::GetTx {
                                ids: chunk.to_vec(),
                            }))
                            .await;
                        }
                    }
                    notify_inbound(&P2pMessage::TxInv { ids: ids.clone() });
                }
                P2pMessage::EvidenceInv { ids } => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                    // Security hardening: treat EvidenceInv as a hint only. Similar to PayloadInv,
                    // fetching evidences purely due to remote INV enables storage DoS.
                    notify_inbound(&P2pMessage::EvidenceInv { ids: ids.clone() });
                }
                P2pMessage::Peers { peers } => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);

                    let count = peers.len();
                    let m = P2pMessage::Peers { peers };
                    // PEX hardening: do not accept gossiped peer lists. Only accept peer
                    // exchange via on-request RPC (ReqMsg::GetPeers / RespMsg::Peers).
                    if let Some(peer) = peer {
                        debug!(target: "pc_p2p.svc", event = "drop_peers_gossip", peer = %peer, count = count, "drop gossiped peers (use GetPeers RPC)");
                    } else {
                        debug!(target: "pc_p2p.svc", event = "drop_peers_gossip", count = count, "drop gossiped peers (use GetPeers RPC)");
                    }
                    notify_inbound(&m);
                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                }
                P2pMessage::Ping => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                    let m = P2pMessage::Ping;
                    notify_inbound(&m);
                }
                P2pMessage::Pong => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                    let m = P2pMessage::Pong;
                    notify_inbound(&m);
                }
                P2pMessage::HeadersInv { ids } => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                    let ids_slice: &[AnchorId] = ids
                        .get(..super::messages::MAX_HEADERS_IN_MSG)
                        .unwrap_or(ids.as_slice());
                    debug!(target: "pc_p2p.svc", event = "inv_in", kind = "headers", count = ids.len(), cap = ids_slice.len(), "headers_inv inbound");
                    let (found, missing_raw) = if let Some(d) = store_delegate {
                        d.get_headers(ids_slice).await
                    } else {
                        store.get_headers(ids_slice)
                    };
                    let mut missing: Vec<AnchorId> = Vec::new();
                    if is_bench_mode() {
                        for raw in missing_raw.into_iter() {
                            missing.push(AnchorId(raw));
                        }
                    } else {
                        let now = Instant::now();
                        for raw in missing_raw.into_iter() {
                            match dedupe_hdr.get(&raw) {
                                Some(&t) if now.duration_since(t) < dedupe_ttl => {
                                    IN_DEDUP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                }
                                _ => {
                                    dedupe_insert_capped(dedupe_hdr, raw, now);
                                    missing.push(AnchorId(raw));
                                }
                            }
                        }
                    }
                    debug!(target: "pc_p2p.svc", event = "inv_miss", kind = "headers", missing = missing.len(), "headers_inv missing computed");
                    if !missing.is_empty() {
                        debug!(target: "pc_p2p.svc", event = "rr_enq", kind = "get_headers", count = missing.len(), "enqueue get_headers request");
                        out.send(P2pMessage::Req(ReqMsg::GetHeaders { ids: missing }))
                            .await;
                    } else {
                        debug!(target: "pc_p2p.svc", event = "rr_skip", reason = "no_missing", kind = "get_headers", "skip get_headers");
                    }
                    notify_inbound(&P2pMessage::HeadersInv { ids: ids.clone() });
                    let _ = found;
                }
                P2pMessage::Req(req) => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_REQ_TOTAL.fetch_add(1, Ordering::Relaxed);
                    match req {
                        ReqMsg::GetHeaders { ref ids } => {
                            let ids_slice: &[AnchorId] = ids
                                .get(..super::messages::MAX_HEADERS_IN_MSG)
                                .unwrap_or(ids.as_slice());
                            let (found, missing) = if let Some(d) = store_delegate {
                                d.get_headers(ids_slice).await
                            } else {
                                store.get_headers(ids_slice)
                            };
                            debug!(target: "pc_p2p.svc", event = "rr_in", kind = "get_headers", count = ids.len(), cap = ids_slice.len(), found = found.len(), missing = missing.len(), "rpc inbound get_headers");
                            if !found.is_empty() {
                                let resp = P2pMessage::Resp(
                                    super::messages::explicit_header_response_for_headers(found),
                                );
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                            if !missing.is_empty() {
                                let resp = P2pMessage::Resp(RespMsg::NotFound {
                                    ty: 1,
                                    ids: missing,
                                });
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                        }
                        ReqMsg::GetPayloads { ref roots } => {
                            let roots_slice: &[[u8; 32]] = roots
                                .get(..super::messages::MAX_PAYLOADS_IN_MSG)
                                .unwrap_or(roots.as_slice());
                            let (found, missing) = if let Some(d) = store_delegate {
                                d.get_payloads(roots_slice).await
                            } else {
                                store.get_payloads(roots_slice)
                            };
                            if !found.is_empty() {
                                let resp = P2pMessage::Resp(RespMsg::Payloads { payloads: found });
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                            if !missing.is_empty() {
                                let resp = P2pMessage::Resp(RespMsg::NotFound {
                                    ty: 2,
                                    ids: missing,
                                });
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                        }
                        ReqMsg::GetTx { ref ids } => {
                            let ids_slice: &[[u8; 32]] = ids
                                .get(..super::messages::MAX_TXS_IN_MSG)
                                .unwrap_or(ids.as_slice());
                            let (found, missing) = if let Some(d) = store_delegate {
                                d.get_txs(ids_slice).await
                            } else {
                                store.get_txs(ids_slice)
                            };
                            if !found.is_empty() {
                                let resp = P2pMessage::Resp(RespMsg::Txs { txs: found });
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                            if !missing.is_empty() {
                                let resp = P2pMessage::Resp(RespMsg::NotFound {
                                    ty: 3,
                                    ids: missing,
                                });
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                        }
                        ReqMsg::GetEvidences { ref ids } => {
                            let ids_slice: &[[u8; 32]] = ids
                                .get(..super::messages::MAX_EVIDENCES_IN_MSG)
                                .unwrap_or(ids.as_slice());
                            let (found, missing) = if let Some(d) = store_delegate {
                                d.get_evidences(ids_slice).await
                            } else {
                                store.get_evidences(ids_slice)
                            };
                            if !found.is_empty() {
                                let resp =
                                    P2pMessage::Resp(RespMsg::Evidences { evidences: found });
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                            if !missing.is_empty() {
                                let resp = P2pMessage::Resp(RespMsg::NotFound {
                                    ty: 4,
                                    ids: missing,
                                });
                                if let Some(peer) = peer {
                                    out.send_to(peer, resp).await;
                                } else {
                                    out.send(resp).await;
                                }
                            }
                        }
                        ReqMsg::GetPeers { max_count } => {
                            if !allow_peer_exchange {
                                debug!(target: "pc_p2p.svc", event = "rr_drop_req", kind = "get_peers", reason = "peer_exchange_disabled", "drop inbound get_peers request");
                                notify_inbound(&P2pMessage::Req(req.clone()));
                                record_in_latency(start.elapsed());
                                return;
                            }
                            let mut peers = peer_store.to_peer_infos();
                            peers.truncate(
                                (max_count as usize).min(super::messages::MAX_PEERS_IN_MSG),
                            );
                            debug!(target: "pc_p2p.svc", event = "rr_in", kind = "get_peers", count = peers.len(), "rpc inbound get_peers");
                            let resp = P2pMessage::Resp(RespMsg::Peers { peers });
                            if let Some(peer) = peer {
                                out.send_to(peer, resp).await;
                            } else {
                                out.send(resp).await;
                            }
                        }
                    }
                    notify_inbound(&P2pMessage::Req(req.clone()));
                }
                P2pMessage::Resp(resp) => {
                    INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                    IN_RESP_TOTAL.fetch_add(1, Ordering::Relaxed);
                    let resp = match super::messages::normalize_header_response(resp) {
                        Ok(v) => v,
                        Err(reason) => {
                            debug!(target: "pc_p2p.svc", event = "drop_header_resp", reason, "malformed staged header response");
                            INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                            record_in_latency(start.elapsed());
                            return;
                        }
                    };
                    match &resp {
                        RespMsg::PrevoteHeaders { .. }
                        | RespMsg::PrecommitHeaders { .. }
                        | RespMsg::StagedHeaders { .. } => {
                            let headers =
                                super::messages::header_response_headers(&resp).unwrap_or_default();
                            let kind = match &resp {
                                RespMsg::PrevoteHeaders { .. } => "prevote_headers",
                                RespMsg::PrecommitHeaders { .. } => "precommit_headers",
                                RespMsg::StagedHeaders { .. } => "staged_headers",
                                _ => unreachable!("non-header responses handled in separate arms"),
                            };
                            debug!(target: "pc_p2p.svc", event = "rr_resp_in", kind, count = headers.len(), "rpc response staged headers inbound");
                            let mut admitted: Vec<AnchorHeader> = Vec::new();
                            for h in headers {
                                if !is_bench_mode() {
                                    let id_raw = h.id_digest();
                                    if !dedupe_hdr.contains_key(&id_raw) {
                                        // Drop unsolicited header responses.
                                        INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                }
                                let ok = if let Some(d) = store_delegate {
                                    d.admit_header(&h).await
                                } else {
                                    true
                                };
                                if !ok {
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                admitted.push(h.clone());
                                let id = AnchorId(h.id_digest());
                                if store_delegate.is_some() {
                                    store.note_header_id(id);
                                }
                                if let Some(d) = store_delegate {
                                    d.insert_header(h).await;
                                } else {
                                    store.insert_header(h);
                                }
                            }
                            // DA-Gating: nach Insert fehlende Payloads ermitteln und anfordern (nur admitted)
                            let mut missing: Vec<[u8; 32]> = Vec::new();
                            if is_bench_mode() {
                                for h in admitted.iter() {
                                    let root = h.payload_hash;
                                    let present = if let Some(d) = store_delegate {
                                        d.has_payload(&root).await
                                    } else {
                                        store.has_payload(&root)
                                    };
                                    if !present {
                                        missing.push(root);
                                    }
                                }
                            } else {
                                let now = Instant::now();
                                for h in admitted.iter() {
                                    let root = h.payload_hash;
                                    let present = if let Some(d) = store_delegate {
                                        d.has_payload(&root).await
                                    } else {
                                        store.has_payload(&root)
                                    };
                                    if !present {
                                        match dedupe_pl.get(&root) {
                                            Some(&t) if now.duration_since(t) < dedupe_ttl => {
                                                IN_DEDUP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            }
                                            _ => {
                                                dedupe_insert_capped(dedupe_pl, root, now);
                                                missing.push(root);
                                            }
                                        }
                                    }
                                }
                            }
                            if !missing.is_empty() {
                                for chunk in missing.chunks(super::messages::MAX_PAYLOADS_IN_MSG) {
                                    out.send(P2pMessage::Req(ReqMsg::GetPayloads {
                                        roots: chunk.to_vec(),
                                    }))
                                    .await;
                                }
                            }
                        }
                        RespMsg::Payloads { payloads } => {
                            for p in payloads.iter().cloned() {
                                let root = payload_merkle_root(&p);
                                if !is_bench_mode() && !dedupe_pl.contains_key(&root) {
                                    // Drop unsolicited payload responses to avoid disk fill.
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                if let Err(e) = pc_types::validate_payload_sanity_v3(&p) {
                                    debug!(target: "pc_p2p.svc", event = "drop_payload", reason = %e, root = ?root, "payload failed sanity checks");
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                if store_delegate.is_some() {
                                    store.note_payload_root(root);
                                }
                                if let Some(d) = store_delegate {
                                    d.insert_payload(p).await;
                                } else {
                                    store.insert_payload(p);
                                }
                            }
                        }
                        RespMsg::Txs { txs } => {
                            for tx in txs.iter().cloned() {
                                let id = digest_microtx(&tx);
                                if !is_bench_mode() && !dedupe_tx.contains_key(&id) {
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                if let Err(e) = pc_types::validate_microtx_sanity(&tx) {
                                    debug!(target: "pc_p2p.svc", event = "drop_tx", reason = %e, id = ?id, "tx failed sanity checks");
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                if let Some(d) = store_delegate {
                                    d.insert_tx(tx).await;
                                } else {
                                    store.insert_tx(tx);
                                }
                            }
                        }
                        RespMsg::Evidences { evidences } => {
                            for evid in evidences.iter().cloned() {
                                let id = digest_evidence(&evid);
                                if !is_bench_mode() && !dedupe_evid.contains_key(&id) {
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                if let Err(e) = pc_types::validate_evidence_sanity(&evid) {
                                    debug!(target: "pc_p2p.svc", event = "drop_evidence", reason = %e, id = ?id, "evidence failed sanity checks");
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                if let Some(d) = store_delegate {
                                    d.insert_evidence(evid).await;
                                } else {
                                    store.insert_evidence(evid);
                                }
                                if store_delegate.is_some() {
                                    store.note_evidence_id(id);
                                }
                            }
                        }
                        RespMsg::NotFound { .. } => {}
                        RespMsg::Peers { peers } => {
                            if !allow_peer_exchange {
                                INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                record_in_latency(start.elapsed());
                                return;
                            }
                            if !is_bench_mode() {
                                let ok = last_get_peers
                                    .map(|t| t.elapsed() <= peers_req_ttl)
                                    .unwrap_or(false);
                                if !ok {
                                    INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
                                    // Drop unsolicited peer responses.
                                    record_in_latency(start.elapsed());
                                    return;
                                }
                            }
                            debug!(target: "pc_p2p.svc", event = "rr_resp_in", kind = "peers", count = peers.len(), "rpc response peers inbound");
                            let incoming = PeerStore::from_peer_infos(peers, current_anchor);
                            peer_store.merge(&incoming, current_anchor);
                        }
                    }
                    notify_inbound(&P2pMessage::Resp(resp.clone()));
                    dispatch_watchers(&resp);
                }
            }
        } else {
            INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed);
        }
        record_in_latency(start.elapsed());
    }

    async fn run_p2p_loop(
        cfg: P2pConfig,
        mut rx: mpsc::Receiver<P2pCmd>,
        out: Outbox,
        store_delegate: Option<Arc<dyn StoreDelegate>>,
    ) -> Result<(), P2pError> {
        if cfg.max_peers == 0 {
            return Err(P2pError::InvalidConfig);
        }
        let mut store = InMemoryStore::new();
        let mut rl = RateLimiter::from_cfg(cfg.rate.as_ref());
        struct PeerRate {
            rl: RateLimiter,
            last_seen: Instant,
        }
        let mut per_peer_rl: HashMap<SocketAddr, PeerRate> = HashMap::new();
        let ttl_secs = cfg
            .rate
            .as_ref()
            .map(|r| {
                if r.peer_ttl_secs == 0 {
                    600
                } else {
                    r.peer_ttl_secs
                }
            })
            .unwrap_or(600);

        // PeerStore für PEX laden
        let peers_path = cfg.peers_json_path.clone();
        let mut peer_store = match &peers_path {
            Some(p) => PeerStore::load(p),
            None => PeerStore::default(),
        };
        let mut peer_store_save_interval = interval(Duration::from_secs(60));
        let mut peer_exchange = interval(Duration::from_secs(12 * 60 * 60));
        let mut current_anchor: u64 = 0;

        let mut anti_entropy = interval(Duration::from_secs(3));
        let mut dedupe_hdr: HashMap<[u8; 32], Instant> = HashMap::new();
        let mut dedupe_pl: HashMap<[u8; 32], Instant> = HashMap::new();
        let mut dedupe_tx: HashMap<[u8; 32], Instant> = HashMap::new();
        let mut dedupe_evid: HashMap<[u8; 32], Instant> = HashMap::new();
        let dedupe_ttl = Duration::from_secs(30);
        // Track whether we recently requested peers, so we can drop unsolicited peer lists.
        // (No request IDs in the wire format; use a short TTL for defense in depth.)
        let mut last_get_peers: Option<Instant> = None;
        let peers_req_ttl = Duration::from_secs(30);
        loop {
            tokio::select! {
                                cmd = rx.recv() => {
                                    match cmd {
                                    Some(P2pCmd::AnnounceHeader(h)) => {
                                        out.send(messages::explicit_announce_for_header(h)).await;
                                    }
                                    Some(P2pCmd::PutHeader(h)) => {
                                        // Header lokal einspielen (ohne Broadcast)
                                        let id = AnchorId(h.id_digest());
                                        if store_delegate.is_some() {
                                            store.note_header_id(id);
                                        }
                                        if let Some(d) = &store_delegate {
                                            d.insert_header(h).await;
                                        } else {
                                            store.insert_header(h);
                                        }
                                    }
                                    Some(P2pCmd::PutPayload(pl)) => {
                                        let root = payload_merkle_root(&pl);
                                        if store_delegate.is_some() {
                                            store.note_payload_root(root);
                                        }
                                        if let Some(d) = &store_delegate {
                                            d.insert_payload(pl).await;
                                        } else {
                                            store.insert_payload(pl);
                                        }
                                    }
                                            Some(P2pCmd::PutTx(tx)) => {
                                                if let Err(e) = pc_types::validate_microtx_sanity(&tx) {
                                                    // Defensive: never persist/broadcast an invalid local tx.
                                                    debug!(target: "pc_p2p.svc", event = "drop_tx_local", reason = %e, "local tx failed sanity checks");
                                                    continue;
                                                }
                                                let id = digest_microtx(&tx);
                                                if let Some(d) = &store_delegate { d.insert_tx(tx).await; } else { store.insert_tx(tx); }
                                                out.send(P2pMessage::TxInv { ids: vec![id] }).await;
                                            }
                                        Some(P2pCmd::PutEvidence(evid)) => {
                                            let id = digest_evidence(&evid);
                                            if let Some(d) = &store_delegate {
                                                d.insert_evidence(evid).await;
                                            } else {
                                                store.insert_evidence(evid);
                                            }
                                            if store_delegate.is_some() {
                                                store.note_evidence_id(id);
                                            }
                                            out.send(P2pMessage::EvidenceInv { ids: vec![id] }).await;
                                        }
                                    Some(P2pCmd::SendHeadersInv(ids)) => {
                                        out.send(P2pMessage::HeadersInv { ids }).await;
                                    }
                                    Some(P2pCmd::SendPayloadInv(roots)) => {
                                        out.send(P2pMessage::PayloadInv { roots }).await;
                                    }
                                            Some(P2pCmd::SendReq(req)) => {
                                                // Outbound RPC an Peers via libp2p request_response
                                                // Track requested objects so we can drop unsolicited responses.
                                                let now = Instant::now();
                                                if !is_bench_mode() {
                                                        match &req {
                                                            ReqMsg::GetHeaders { ids } => {
                                                                for id in ids.iter() {
                                                                    dedupe_insert_capped(&mut dedupe_hdr, id.0, now);
                                                                }
                                                            }
                                                            ReqMsg::GetPayloads { roots } => {
                                                                for r in roots.iter() {
                                                                    dedupe_insert_capped(&mut dedupe_pl, *r, now);
                                                                }
                                                            }
                                                            ReqMsg::GetTx { ids } => {
                                                                for id in ids.iter() {
                                                                    dedupe_insert_capped(&mut dedupe_tx, *id, now);
                                                                }
                                                            }
                                                        ReqMsg::GetEvidences { ids } => {
                                                            for id in ids.iter() {
                                                                dedupe_insert_capped(&mut dedupe_evid, *id, now);
                                                            }
                                                        }
                                                        ReqMsg::GetPeers { .. } => {
                                                            if cfg.enable_peer_exchange {
                                                                last_get_peers = Some(now);
                                                            } else {
                                                                continue;
                                                            }
                                                        }
                                                    }
                                                }
                                                // Wire-compatible chunking: don't send requests peers cannot answer in a single message.
                                                // Wire-kompatibles Chunking: keine Requests senden, die Peers nicht in einer Message beantworten können.
                                                match req {
                                                    ReqMsg::GetHeaders { ids } => {
                                                        for chunk in ids.chunks(super::messages::MAX_HEADERS_IN_MSG) {
                                                            out.send(P2pMessage::Req(ReqMsg::GetHeaders { ids: chunk.to_vec() })).await;
                                                        }
                                                    }
                                                    ReqMsg::GetPayloads { roots } => {
                                                        for chunk in roots.chunks(super::messages::MAX_PAYLOADS_IN_MSG) {
                                                            out.send(P2pMessage::Req(ReqMsg::GetPayloads { roots: chunk.to_vec() })).await;
                                                        }
                                                    }
                                                    ReqMsg::GetTx { ids } => {
                                                        for chunk in ids.chunks(super::messages::MAX_TXS_IN_MSG) {
                                                            out.send(P2pMessage::Req(ReqMsg::GetTx { ids: chunk.to_vec() })).await;
                                                        }
                                                    }
                                                    ReqMsg::GetEvidences { ids } => {
                                                        for chunk in ids.chunks(super::messages::MAX_EVIDENCES_IN_MSG) {
                                                            out.send(P2pMessage::Req(ReqMsg::GetEvidences { ids: chunk.to_vec() })).await;
                                                        }
                                                    }
                                                    ReqMsg::GetPeers { max_count } => {
                                                        if !cfg.enable_peer_exchange {
                                                            continue;
                                                        }
                                                        let max = super::messages::MAX_PEERS_IN_MSG as u16;
                                                        out.send(P2pMessage::Req(ReqMsg::GetPeers { max_count: max_count.min(max) })).await;
                                                    }
                                                }
                                            }
                                    Some(P2pCmd::SetAnchor(anchor)) => {
                                        current_anchor = anchor;
                                        peer_store.prune(current_anchor);
                                    }
                                        Some(P2pCmd::Incoming(msg)) => {
                                            handle_inbound_message(
                                                None,
                                            msg,
                                            &mut rl,
                                            &mut store,
                                            store_delegate.as_ref(),
                                            &out,
                                            &mut dedupe_hdr,
                                            &mut dedupe_pl,
                                            &mut dedupe_tx,
                                            &mut dedupe_evid,
                                            dedupe_ttl,
                                            &mut peer_store,
                                            current_anchor,
                                            last_get_peers,
                                            peers_req_ttl,
                                            cfg.enable_peer_exchange,
                                        )
                                        .await;
                                        }
                Some(P2pCmd::Rpc(req, reply_tx)) => {
                                                // Lokale synchrone RPC-Verarbeitung
                                                let resp = match req {
                                                    ReqMsg::GetHeaders { ref ids } => {
                                                        let ids_slice: &[AnchorId] = ids
                                                            .get(..super::messages::MAX_HEADERS_IN_MSG)
                                                            .unwrap_or(ids.as_slice());
                                                        let (found, missing) = if let Some(d) = &store_delegate { d.get_headers(ids_slice).await } else { store.get_headers(ids_slice) };
                                                        if !found.is_empty() { super::messages::explicit_header_response_for_headers(found) } else { RespMsg::NotFound { ty: 1, ids: missing } }
                                                    }
                                                    ReqMsg::GetPayloads { ref roots } => {
                                                        let roots_slice: &[[u8; 32]] = roots
                                                            .get(..super::messages::MAX_PAYLOADS_IN_MSG)
                                                            .unwrap_or(roots.as_slice());
                                                        let (found, missing) = if let Some(d) = &store_delegate { d.get_payloads(roots_slice).await } else { store.get_payloads(roots_slice) };
                                                        if !found.is_empty() { RespMsg::Payloads { payloads: found } } else { RespMsg::NotFound { ty: 2, ids: missing } }
                                                    }
                                                        ReqMsg::GetTx { ref ids } => {
                                                            let ids_slice: &[[u8; 32]] = ids
                                                                .get(..super::messages::MAX_TXS_IN_MSG)
                                                                .unwrap_or(ids.as_slice());
                                                            let (found, missing) = if let Some(d) = &store_delegate { d.get_txs(ids_slice).await } else { store.get_txs(ids_slice) };
                                                            if !found.is_empty() { RespMsg::Txs { txs: found } } else { RespMsg::NotFound { ty: 3, ids: missing } }
                                                        }
                                                        ReqMsg::GetEvidences { ref ids } => {
                                                            let ids_slice: &[[u8; 32]] = ids
                                                                .get(..super::messages::MAX_EVIDENCES_IN_MSG)
                                                                .unwrap_or(ids.as_slice());
                                                            let (found, missing) = if let Some(d) = &store_delegate {
                                                                d.get_evidences(ids_slice).await
                                                            } else {
                                                                store.get_evidences(ids_slice)
                                                        };
                                                        if !found.is_empty() {
                                                            RespMsg::Evidences { evidences: found }
                                                        } else {
                                                            RespMsg::NotFound { ty: 4, ids: missing }
                                                        }
                                                    }
                                                    ReqMsg::GetPeers { max_count } => {
                                                        let mut peers = peer_store.to_peer_infos();
                                                        peers.truncate((max_count as usize).min(super::messages::MAX_PEERS_IN_MSG));
                                                        RespMsg::Peers { peers }
                                                    }
                                            };
                                            let _ = reply_tx.send(resp);
                                        }
            Some(P2pCmd::IncomingFrom(peer, msg)) => {
                let use_per_peer = cfg.rate.as_ref().map(|r| r.per_peer).unwrap_or(true);
                let now = Instant::now();
                if use_per_peer {
                    let entry = per_peer_rl.entry(peer).or_insert_with(|| PeerRate {
                        rl: RateLimiter::from_cfg(cfg.rate.as_ref()),
                        last_seen: now,
                    });
                    entry.last_seen = now;
                    handle_inbound_message(
                        Some(peer),
                        msg,
                        &mut entry.rl,
                        &mut store,
                        store_delegate.as_ref(),
                        &out,
                        &mut dedupe_hdr,
                        &mut dedupe_pl,
                        &mut dedupe_tx,
                        &mut dedupe_evid,
                        dedupe_ttl,
                        &mut peer_store,
                        current_anchor,
                        last_get_peers,
                        peers_req_ttl,
                        cfg.enable_peer_exchange,
                    )
                    .await;
                } else {
                    handle_inbound_message(
                        Some(peer),
                        msg,
                        &mut rl,
                        &mut store,
                        store_delegate.as_ref(),
                        &out,
                        &mut dedupe_hdr,
                        &mut dedupe_pl,
                        &mut dedupe_tx,
                        &mut dedupe_evid,
                        dedupe_ttl,
                        &mut peer_store,
                        current_anchor,
                        last_get_peers,
                        peers_req_ttl,
                        cfg.enable_peer_exchange,
                    )
                    .await;
                }
            }
            Some(P2pCmd::Shutdown) => { info!("p2p shutdown received"); break; }
                                    None => { warn!("p2p command channel closed"); break; }
                                }
                            },
                            _ = anti_entropy.tick() => {
                                if !BENCH_MODE.load(Ordering::Relaxed) {
                                    // Periodischer Anti-Entropy Abgleich: sende letzte bekannten Inventare
                                    let hdr_sample = store.recent_headers_sample(16);
                                    if !hdr_sample.is_empty() {
                                        out.send(P2pMessage::HeadersInv { ids: hdr_sample }).await;
                                    }
                                    let pl_sample = store.recent_payload_roots_sample(16);
                                    if !pl_sample.is_empty() {
                                        out.send(P2pMessage::PayloadInv { roots: pl_sample }).await;
                                    }
                                    let ev_sample = store.recent_evidence_ids_sample(16);
                                    if !ev_sample.is_empty() {
                                        out.send(P2pMessage::EvidenceInv { ids: ev_sample }).await;
                                    }
                                }
                            },
                                _ = peer_exchange.tick() => {
                                if !BENCH_MODE.load(Ordering::Relaxed) {
                                    if !cfg.enable_peer_exchange {
                                        continue;
                                    }
                                        // Periodischer Peer-Exchange: bitte Peers-Liste anfordern
                                        last_get_peers = Some(Instant::now());
                                        out.send(P2pMessage::Req(ReqMsg::GetPeers { max_count: 16 })).await;
                                    }
                                },
                            _ = peer_store_save_interval.tick() => {
                                if let Some(ref p) = peers_path {
                                    let _ = peer_store.save(p);
                                    debug!(target: "pc_p2p.svc", event = "peer_store_saved", count = peer_store.peers.len(), "peer store saved to disk");
                                }
                                // Aktualisiere PeerStore-Metriken
                                update_peer_metrics(peer_store.count_by_role());
                            }
                            _ = sleep(Duration::from_secs(60)) => {
                                let use_per_peer = cfg.rate.as_ref().map(|r| r.per_peer).unwrap_or(true);
                                if use_per_peer && ttl_secs > 0 {
                                    let now = Instant::now();
                                    let mut purged = 0u64;
                                    per_peer_rl.retain(|_, v| {
                                        let alive = now.duration_since(v.last_seen).as_secs() <= ttl_secs;
                                        if !alive { purged += 1; }
                                        alive
                                    });
                                    if purged > 0 { PEER_RL_PURGED_TOTAL.fetch_add(purged, Ordering::Relaxed); }
                                }
                                // Clean up dedupe maps.
                                // Dedupe-Maps säubern
                                    {
                                        let now = Instant::now();
                                        dedupe_hdr.retain(|_, t| now.duration_since(*t) < dedupe_ttl);
                                        dedupe_pl.retain(|_, t| now.duration_since(*t) < dedupe_ttl);
                                        dedupe_tx.retain(|_, t| now.duration_since(*t) < dedupe_ttl);
                                        dedupe_evid.retain(|_, t| now.duration_since(*t) < dedupe_ttl);
                                    }
                                }
                        }
        }
        Ok(())
    }

    pub fn spawn(
        cfg: P2pConfig,
    ) -> (
        P2pService,
        mpsc::Receiver<OutboundEnvelope>,
        tokio::task::JoinHandle<Result<(), P2pError>>,
    ) {
        let (tx, rx) = mpsc::channel(1024);
        let (out_tx, out_rx) = mpsc::channel(1024);
        let out = Outbox { tx: out_tx };
        let handle = tokio::spawn(run_p2p_loop(cfg, rx, out, None));
        (P2pService { tx }, out_rx, handle)
    }

    /// Spawn with an optional persistent store backend (e.g. DiskStore). If provided, all store operations
    /// are delegated to it; otherwise the service uses an in-memory store.
    /// Spawn mit optionalem persistentem Store-Backend (z. B. DiskStore). Wenn übergeben, werden alle Store-Operationen
    /// über das Delegate geleitet; ansonsten nutzt der Service ein InMemoryStore.
    pub fn spawn_with_store(
        cfg: P2pConfig,
        store: Arc<dyn StoreDelegate>,
    ) -> (
        P2pService,
        mpsc::Receiver<OutboundEnvelope>,
        tokio::task::JoinHandle<Result<(), P2pError>>,
    ) {
        let (tx, rx) = mpsc::channel(1024);
        let (out_tx, out_rx) = mpsc::channel(1024);
        let out = Outbox { tx: out_tx };
        let handle = tokio::spawn(run_p2p_loop(cfg, rx, out, Some(store)));
        (P2pService { tx }, out_rx, handle)
    }

    // Outbound peer abstraction.
    // Outbound Peer Abstraktion
    #[async_trait::async_trait]
    pub trait OutboundSink: Send + Sync {
        async fn deliver(&self, msg: P2pMessage) -> Result<(), P2pError>;
    }

    pub struct InProcessSink {
        remote: P2pService,
    }
    impl InProcessSink {
        pub fn new(remote: P2pService) -> Self {
            Self { remote }
        }
    }

    #[async_trait::async_trait]
    impl OutboundSink for InProcessSink {
        async fn deliver(&self, msg: P2pMessage) -> Result<(), P2pError> {
            self.remote.send_message(msg).await
        }
    }

    #[cfg(test)]
    #[cfg(feature = "async")]
    mod itests {
        use super::super::messages::{
            explicit_announce_for_header, explicit_header_response_for_headers,
            header_response_headers, P2pMessage, ReqMsg, RespMsg,
        };
        use super::*;
        use pc_types::{
            payload_merkle_root_v3 as payload_merkle_root, AnchorPayloadV3 as AnchorPayload,
        };
        use pc_types::{AnchorHeaderV2 as AnchorHeader, AnchorId};
        use tokio::time::{timeout, Duration};

        fn test_cfg() -> P2pConfig {
            P2pConfig {
                max_peers: 8,
                rate: None,
                peers_json_path: None,
                enable_peer_exchange: false,
                network_id: None,
            }
        }

        // End-to-end: HeaderAnnounce -> GET_PAYLOADS -> PAYLOADS between two loops.
        // End-to-End: HeaderAnnounce -> GET_PAYLOADS -> PAYLOADS zwischen zwei Loops
        #[tokio::test]
        async fn header_getpayloads_flow() {
            let cfg = test_cfg();
            let (svc_a, mut out_a, handle_a) = spawn(cfg.clone());
            let (svc_b, mut out_b, handle_b) = spawn(cfg.clone());

            // Create payload on A.
            // Erzeuge Payload auf A
            let payload = AnchorPayload {
                version: 3,
                micro_txs: vec![],
                mints: vec![],
                claims: vec![],
                evidences: vec![],
                payout_root: [9u8; 32],
                genesis_note: None,
                null_mint: false,
            };
            let root = payload_merkle_root(&payload);
            let _ = svc_a.put_payload(payload).await; // ok if ChannelClosed? here it should be ok

            // Send header announce to B which references the payload root.
            // Sende HeaderAnnounce an B, der den Payload-Root referenziert.
            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: root,
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };
            let _ = svc_b.send_message(explicit_announce_for_header(hdr)).await;

            // B should create GET_PAYLOADS (on out_b).
            // B soll GET_PAYLOADS erzeugen (auf out_b)
            let req = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                            return Some(roots.clone());
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            assert_eq!(req, vec![root]);

            // Forward GET_PAYLOADS from B to A (simulated network).
            // Leite GET_PAYLOADS von B an A (simuliert Netzwerk)
            let _ = svc_a
                .send_message(P2pMessage::Req(ReqMsg::GetPayloads { roots: req.clone() }))
                .await;

            // Expect the PAYLOADS response on out_a.
            // Erwarte auf out_a die PAYLOADS-Response
            let resp_from_a = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_a.recv().await {
                        if let P2pMessage::Resp(RespMsg::Payloads { payloads }) = msg.message() {
                            return Some(payloads.clone());
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            assert!(!resp_from_a.is_empty());

            // Forward the response from A to B (B now stores the payload).
            // Forwarde die Response von A an B (B speichert nun Payload)
            let _ = svc_b
                .send_message(P2pMessage::Resp(RespMsg::Payloads {
                    payloads: resp_from_a.clone(),
                }))
                .await;

            // Check: send GET_PAYLOADS to B and expect PAYLOADS as response on out_b.
            // Prüfe: Stelle GET_PAYLOADS an B und erwarte PAYLOADS als Antwort auf out_b
            let _ = svc_b
                .send_message(P2pMessage::Req(ReqMsg::GetPayloads { roots: vec![root] }))
                .await;
            let got = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Resp(RespMsg::Payloads { payloads }) = msg.message() {
                            return Some(payloads.clone());
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten();
            assert!(got.map(|v| !v.is_empty()).unwrap_or(false));

            // Clean shutdown.
            // Shutdown sauber
            let _ = svc_a.shutdown().await;
            let _ = svc_b.shutdown().await;
            let _ = handle_a.await;
            let _ = handle_b.await;
        }

        // Security hardening: PAYLOAD_INV must not trigger GET_PAYLOADS (storage-DoS mitigation).
        #[tokio::test]
        async fn payload_inv_does_not_trigger_getpayloads() {
            let cfg = test_cfg();
            let (svc, mut out, handle) = spawn(cfg.clone());

            let root = [42u8; 32];
            let _ = svc
                .send_message(P2pMessage::PayloadInv { roots: vec![root] })
                .await;

            // Ensure we don't emit GetPayloads in response to INV alone.
            let got = timeout(Duration::from_millis(200), async {
                loop {
                    if let Some(msg) = out.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetPayloads { .. }) = msg.message() {
                            return true;
                        }
                    } else {
                        return false;
                    }
                }
            })
            .await
            .unwrap_or(false);
            assert!(!got);

            let _ = svc.shutdown().await;
            let _ = handle.await;
        }

        // End-to-end: HEADERS_INV -> GET_HEADERS -> HEADERS between two loops.
        // End-to-End: HEADERS_INV -> GET_HEADERS -> HEADERS zwischen zwei Loops
        #[tokio::test]
        async fn headers_inv_getheaders_flow() {
            let cfg = test_cfg();
            let (svc_a, mut out_a, handle_a) = spawn(cfg.clone());
            let (svc_b, mut out_b, handle_b) = spawn(cfg.clone());

            // Create header on A.
            // Erzeuge Header auf A
            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [0u8; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };
            let id = pc_types::AnchorId(hdr.id_digest());
            // Insert in A-Store durch Incoming-Message
            let _ = svc_a
                .send_message(explicit_announce_for_header(hdr.clone()))
                .await;

            // Sende HEADERS_INV an B (simuliert Netzwerk)
            let _ = svc_b
                .send_message(P2pMessage::HeadersInv { ids: vec![id] })
                .await;

            // B soll GET_HEADERS erzeugen (auf out_b)
            let req_ids = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetHeaders { ids }) = msg.message() {
                            return Some(ids.clone());
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            assert_eq!(req_ids, vec![id]);

            // Leite GET_HEADERS von B an A (simuliert Netzwerk)
            let _ = svc_a
                .send_message(P2pMessage::Req(ReqMsg::GetHeaders {
                    ids: req_ids.clone(),
                }))
                .await;

            // Erwarte auf out_a die HEADERS-Response
            let resp_from_a = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_a.recv().await {
                        if let P2pMessage::Resp(resp) = msg.message() {
                            if let Some(headers) = header_response_headers(resp) {
                                return Some(headers);
                            }
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            assert_eq!(resp_from_a.len(), 1);

            // Forwarde die Response von A an B (B speichert nun Header)
            let _ = svc_b
                .send_message(P2pMessage::Resp(explicit_header_response_for_headers(
                    resp_from_a.clone(),
                )))
                .await;

            // Prüfe: Stelle GET_HEADERS an B und erwarte HEADERS als Antwort auf out_b
            let _ = svc_b
                .send_message(P2pMessage::Req(ReqMsg::GetHeaders { ids: vec![id] }))
                .await;
            let got = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Resp(resp) = msg.message() {
                            if let Some(headers) = header_response_headers(resp) {
                                return Some(headers);
                            }
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            assert_eq!(got.len(), 1);

            // Shutdown sauber
            let _ = svc_a.shutdown().await;
            let _ = svc_b.shutdown().await;
            let _ = handle_a.await;
            let _ = handle_b.await;
        }

        // DA-Gating: HeaderAnnounce mit fehlendem Payload löst GetPayloads aus
        #[tokio::test]
        async fn header_announce_triggers_getpayloads() {
            let cfg = test_cfg();
            let (_svc_a, _out_a, handle_a) = spawn(cfg.clone());
            let (svc_b, mut out_b, handle_b) = spawn(cfg.clone());

            // Header mit unbekanntem payload_hash
            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [5u8; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };

            // Sende Announce an B
            let _ = svc_b.send_message(explicit_announce_for_header(hdr)).await;

            // Erwartung: GetPayloads auf out_b
            let req = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                            return Some(roots.clone());
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            assert_eq!(req, vec![[5u8; 32]]);

            // Shutdown
            let _ = _svc_a.shutdown().await;
            let _ = svc_b.shutdown().await;
            let _ = handle_a.await;
            let _ = handle_b.await;
        }

        // DA-Gating: Dedupe verhindert mehrfaches GetPayloads für selben Root in kurzer Zeit
        #[tokio::test]
        async fn header_announce_dedupe_only_once() {
            let cfg = test_cfg();
            let (svc_b, mut out_b, handle_b) = spawn(cfg.clone());

            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [7u8; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };

            // Zwei Announce kurz hintereinander
            let _ = svc_b
                .send_message(explicit_announce_for_header(hdr.clone()))
                .await;
            let _ = svc_b
                .send_message(explicit_announce_for_header(hdr.clone()))
                .await;

            // Sammle kurzzeitig alle Outbox-Messages und zähle GetPayloads
            let mut got_roots: Vec<[u8; 32]> = Vec::new();
            let _ = timeout(Duration::from_millis(500), async {
                while let Some(msg) = out_b.recv().await {
                    if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                        got_roots.extend(roots);
                    }
                }
            })
            .await; // Timeout erwartet -> ignorieren

            // Es darf nur ein GetPayloads für den Root geben
            let count = got_roots.iter().filter(|r| **r == [7u8; 32]).count();
            assert!(count >= 1);
            assert_eq!(count, 1);

            let _ = svc_b.shutdown().await;
            let _ = handle_b.await;
        }

        // Watcher: watch_payload(root) löst aus, wenn PAYLOADS-Resp ankommt
        #[tokio::test]
        async fn watch_payload_resolves_on_payloads_resp() {
            let cfg = test_cfg();
            let (svc, _out, handle) = spawn(cfg.clone());

            // Baue Payload und Root
            let payload = AnchorPayload {
                version: 2,
                micro_txs: vec![],
                mints: vec![],
                claims: vec![],
                evidences: vec![],
                payout_root: [1u8; 32],
                genesis_note: None,
                null_mint: false,
            };
            let root = payload_merkle_root(&payload);

            // Starte Watcher
            let rx = super::watch_payload(root);

            // Sende PAYLOADS-Resp
            let _ = svc
                .send_message(P2pMessage::Resp(RespMsg::Payloads {
                    payloads: vec![payload],
                }))
                .await;

            // Erwartung: Watcher liefert innerhalb Timeout
            let got = tokio::time::timeout(Duration::from_secs(1), rx)
                .await
                .ok()
                .and_then(|r| r.ok());
            let r2_opt = got.and_then(|m| match m {
                RespMsg::Payloads { payloads } => payloads.first().map(payload_merkle_root),
                _ => None,
            });
            assert_eq!(r2_opt, Some(root));

            let _ = svc.shutdown().await;
            let _ = handle.await;
        }

        // Watcher: Timeout wenn keine Lieferung erfolgt (Nichtlieferung)
        #[tokio::test]
        async fn watch_payload_times_out_on_non_delivery() {
            let _cfg = test_cfg();
            // Kein Service nötig, wir nutzen nur den Watcher ohne Response
            let root = [2u8; 32];
            let rx = super::watch_payload(root);
            // Erwartung: Timeout tritt ein (keine Lieferung)
            let res = tokio::time::timeout(Duration::from_millis(150), rx).await;
            assert!(res.is_err());
        }

        // Watcher: Spätlieferung (erst nach kurzer Verzögerung geliefert)
        #[tokio::test]
        async fn watch_payload_resolves_on_late_delivery() {
            let cfg = test_cfg();
            let (svc, _out, handle) = spawn(cfg.clone());

            let payload = AnchorPayload {
                version: 2,
                micro_txs: vec![],
                mints: vec![],
                claims: vec![],
                evidences: vec![],
                payout_root: [3u8; 32],
                genesis_note: None,
                null_mint: false,
            };
            let root = payload_merkle_root(&payload);
            let rx = super::watch_payload(root);

            // Verzögerte Lieferung
            tokio::spawn({
                let svc2 = svc.clone();
                let p = payload.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let _ = svc2
                        .send_message(P2pMessage::Resp(RespMsg::Payloads { payloads: vec![p] }))
                        .await;
                }
            });

            let got = tokio::time::timeout(Duration::from_secs(1), rx)
                .await
                .ok()
                .and_then(|r| r.ok());
            let r2_opt = got.and_then(|m| match m {
                RespMsg::Payloads { payloads } => payloads.first().map(payload_merkle_root),
                _ => None,
            });
            assert_eq!(r2_opt, Some(root));

            let _ = svc.shutdown().await;
            let _ = handle.await;
        }

        // DA-Gating: HEADERS-Response mit fehlenden Payloads löst GetPayloads aus
        #[tokio::test]
        async fn headers_resp_triggers_getpayloads() {
            let cfg = test_cfg();
            let (svc_b, mut out_b, handle_b) = spawn(cfg.clone());

            // Header mit unbekanntem payload_hash
            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [11u8; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };

            // Markiere den Header als "requested", damit die requested-only RESP-Härtung
            // (Drop unsolicited HEADERS) im Test nicht greift.
            let id = pc_types::AnchorId(hdr.id_digest());
            let _ = svc_b.send_req(ReqMsg::GetHeaders { ids: vec![id] }).await;

            // Simuliere eingehende HEADERS-Resp
            let _ = svc_b
                .send_message(P2pMessage::Resp(explicit_header_response_for_headers(
                    vec![hdr],
                )))
                .await;

            // Erwartung: GetPayloads auf out_b
            let req = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg.message() {
                            return Some(roots.clone());
                        }
                    } else {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            assert_eq!(req, vec![[11u8; 32]]);

            let _ = svc_b.shutdown().await;
            let _ = handle_b.await;
        }

        // Backpressure/Loss: viele HeaderAnnounce (low prio) führen zu Drops (Outbox try_send)
        #[tokio::test]
        async fn backpressure_drops_low_priority_header_announce() {
            let cfg = test_cfg();
            let (svc, mut out_rx, handle) = spawn(cfg.clone());

            // Einfacher Header
            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [0u8; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };

            // Sende deutlich mehr low-prio Events als die Outbox-Kanalgröße (1024)
            let sent: usize = 3000;
            for _ in 0..sent {
                let _ = svc.announce_header(hdr.clone()).await;
            }

            // Jetzt drainen wir schnell alle Outbox-Nachrichten (ein Teil sollte gedroppt sein)
            let mut received = 0usize;
            let _ = tokio::time::timeout(Duration::from_millis(500), async {
                while let Some(msg) = out_rx.recv().await {
                    if super::messages::announced_header(msg.message()).is_some() {
                        received += 1;
                    }
                }
            })
            .await; // Timeout erwartbar

            // Erwartung: es wurden Nachrichten gedroppt (received < sent), aber einige kamen an (>0)
            assert!(received > 0, "keine Header-Announce empfangen");
            assert!(
                received < sent,
                "es wurden keine Nachrichten gedroppt (received={received}, sent={sent})"
            );

            let _ = svc.shutdown().await;
            let _ = handle.await;
        }

        #[tokio::test]
        async fn malformed_precommit_announce_without_state_root_is_dropped() {
            let cfg = test_cfg();
            let (svc, mut out_rx, handle) = spawn(cfg);
            let hdr = AnchorHeader {
                version: 5,
                shard_id: 0,
                parents: pc_types::ParentList::default(),
                payload_hash: [0xAB; 32],
                creator_index: 1,
                vote_mask: 1,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 7,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };

            let _ = svc.send_message(P2pMessage::PrecommitAnnounce(hdr)).await;
            let saw_invalid_side_effect = tokio::time::timeout(Duration::from_millis(150), async {
                while let Some(msg) = out_rx.recv().await {
                    if matches!(msg.message(), P2pMessage::Req(ReqMsg::GetPayloads { .. }))
                        || super::messages::announced_header(msg.message()).is_some()
                    {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false);
            assert!(
                !saw_invalid_side_effect,
                "malformed precommit announce must not trigger DA-gating or header rebroadcast"
            );

            let _ = svc.shutdown().await;
            let _ = handle.await;
        }

        // F58 regression: Incoming and IncomingFrom must share the exact same inbound handler.
        #[tokio::test]
        async fn inbound_incoming_and_incomingfrom_are_equivalent() {
            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader {
                version: 2,
                shard_id: 0,
                parents,
                payload_hash: [9u8; 32],
                creator_index: 1,
                vote_mask: 0,
                ack_present: false,
                ack_id: AnchorId([0u8; 32]),
                network_id: [0u8; 32],
                vote_epoch: 0,
                vote_round: 0,
                state_root: None,
                attest_sig: None,
            };
            let id = AnchorId(hdr.id_digest());
            let msg = explicit_announce_for_header(hdr);

            let mut store_a = InMemoryStore::new();
            let mut store_b = InMemoryStore::new();
            let mut rl_a = RateLimiter::from_cfg(None);
            let mut rl_b = RateLimiter::from_cfg(None);
            let mut dedupe_hdr_a: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_pl_a: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_tx_a: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_evid_a: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_hdr_b: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_pl_b: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_tx_b: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_evid_b: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut peer_store_a = PeerStore::default();
            let mut peer_store_b = PeerStore::default();

            let (tx_a, mut rx_a) = mpsc::channel::<OutboundEnvelope>(8);
            let (tx_b, mut rx_b) = mpsc::channel::<OutboundEnvelope>(8);
            let out_a = Outbox { tx: tx_a };
            let out_b = Outbox { tx: tx_b };

            let dedupe_ttl = Duration::from_secs(30);
            let peers_req_ttl = Duration::from_secs(30);
            let last_get_peers: Option<Instant> = None;
            let current_anchor = 0u64;

            handle_inbound_message(
                None,
                msg.clone(),
                &mut rl_a,
                &mut store_a,
                None,
                &out_a,
                &mut dedupe_hdr_a,
                &mut dedupe_pl_a,
                &mut dedupe_tx_a,
                &mut dedupe_evid_a,
                dedupe_ttl,
                &mut peer_store_a,
                current_anchor,
                last_get_peers,
                peers_req_ttl,
                true,
            )
            .await;

            let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
            handle_inbound_message(
                Some(peer),
                msg,
                &mut rl_b,
                &mut store_b,
                None,
                &out_b,
                &mut dedupe_hdr_b,
                &mut dedupe_pl_b,
                &mut dedupe_tx_b,
                &mut dedupe_evid_b,
                dedupe_ttl,
                &mut peer_store_b,
                current_anchor,
                last_get_peers,
                peers_req_ttl,
                true,
            )
            .await;

            assert!(store_a.headers.contains_key(&id));
            assert!(store_b.headers.contains_key(&id));

            let mut out_msgs_a: Vec<P2pMessage> = Vec::new();
            while let Ok(m) = rx_a.try_recv() {
                out_msgs_a.push(m.message().clone());
            }
            let mut out_msgs_b: Vec<P2pMessage> = Vec::new();
            while let Ok(m) = rx_b.try_recv() {
                out_msgs_b.push(m.message().clone());
            }
            assert_eq!(out_msgs_a, out_msgs_b);
        }

        #[tokio::test]
        async fn inbound_payload_response_is_directed_to_requesting_peer() {
            let payload = AnchorPayload {
                version: 3,
                micro_txs: vec![],
                mints: vec![],
                claims: vec![],
                evidences: vec![],
                payout_root: [0xAA; 32],
                genesis_note: None,
                null_mint: false,
            };
            let root = payload_merkle_root(&payload);
            let mut store = InMemoryStore::new();
            store.payloads.insert(root, payload.clone());
            let mut rl = RateLimiter::from_cfg(None);
            let mut dedupe_hdr: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_pl: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_tx: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_evid: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut peer_store = PeerStore::default();
            let (tx, mut rx) = mpsc::channel::<OutboundEnvelope>(8);
            let out = Outbox { tx };
            let peer: SocketAddr = "127.0.0.1:32123".parse().unwrap();

            handle_inbound_message(
                Some(peer),
                P2pMessage::Req(ReqMsg::GetPayloads { roots: vec![root] }),
                &mut rl,
                &mut store,
                None,
                &out,
                &mut dedupe_hdr,
                &mut dedupe_pl,
                &mut dedupe_tx,
                &mut dedupe_evid,
                Duration::from_secs(30),
                &mut peer_store,
                0,
                None,
                Duration::from_secs(30),
                true,
            )
            .await;

            let env = rx.recv().await.expect("direct payload response expected");
            match env {
                OutboundEnvelope::Direct {
                    peer: got_peer,
                    msg,
                } => {
                    assert_eq!(got_peer, peer);
                    match msg {
                        P2pMessage::Resp(RespMsg::Payloads { payloads }) => {
                            assert_eq!(payloads.len(), 1);
                            assert_eq!(payload_merkle_root(&payloads[0]), root);
                        }
                        other => panic!("unexpected outbound response: {:?}", other),
                    }
                }
                other => panic!("expected directed response, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn inbound_getpeers_is_dropped_when_peer_exchange_is_disabled() {
            let mut store = InMemoryStore::new();
            let mut rl = RateLimiter::from_cfg(None);
            let mut dedupe_hdr: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_pl: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_tx: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut dedupe_evid: HashMap<[u8; 32], Instant> = HashMap::new();
            let mut peer_store = PeerStore::default();
            let (tx, mut rx) = mpsc::channel::<OutboundEnvelope>(8);
            let out = Outbox { tx };
            let peer: SocketAddr = "127.0.0.1:32124".parse().unwrap();

            handle_inbound_message(
                Some(peer),
                P2pMessage::Req(ReqMsg::GetPeers { max_count: 8 }),
                &mut rl,
                &mut store,
                None,
                &out,
                &mut dedupe_hdr,
                &mut dedupe_pl,
                &mut dedupe_tx,
                &mut dedupe_evid,
                Duration::from_secs(30),
                &mut peer_store,
                0,
                None,
                Duration::from_secs(30),
                false,
            )
            .await;

            let got = timeout(Duration::from_millis(50), rx.recv()).await;
            assert!(got.is_err(), "peer exchange must stay silent when disabled");
        }
    }
}

#[cfg(test)]
mod tests;
