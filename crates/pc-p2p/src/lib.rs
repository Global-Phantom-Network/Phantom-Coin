#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

/// P2P-Skelett: Platzhaltertypen und -funktionen. Keine Netzwerk-IO hier; reine API-Skizze.
/// Spätere Implementierung nutzt async (tokio) und QUIC/TCP, VRF-Sampling, Gossip mit Backpressure-Steuerung.
use pc_types::AnchorHeader;

#[derive(Debug)]
pub enum P2pError {
    InvalidConfig,
    ChannelClosed,
    StoreError,
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
    pub per_peer: bool,
    pub peer_ttl_secs: u64,
}

/// Nachrichtenformate und Codec-Implementierungen für P2P
pub mod messages {
    use pc_codec::{Encodable, Decodable, CodecError};
    use pc_types::{AnchorHeader, AnchorPayload, AnchorId};

    // Top-Level Nachrichtentypen
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum P2pMessage {
        HeaderAnnounce(AnchorHeader),
        HeadersInv { ids: Vec<AnchorId> },
        PayloadInv { roots: Vec<[u8;32]> },
        TxInv { ids: Vec<[u8;32]> },
        Req(ReqMsg),
        Resp(RespMsg),
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ReqMsg {
        GetHeaders { ids: Vec<AnchorId> },
        GetPayloads { roots: Vec<[u8;32]> },
        GetTx { ids: Vec<[u8;32]> },
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RespMsg {
        Headers { headers: Vec<AnchorHeader> },
        Payloads { payloads: Vec<AnchorPayload> },
        Txs { txs: Vec<pc_types::MicroTx> },
        NotFound { ty: u8, ids: Vec<[u8;32]> }, // ty: 1=headers, 2=payloads
    }

    // Tags
    const TAG_HEADER_ANN: u8 = 1;
    const TAG_PAYLOAD_INV: u8 = 2;
    const TAG_REQ: u8 = 3;
    const TAG_RESP: u8 = 4;
    const TAG_HEADERS_INV: u8 = 5;
    const TAG_TX_INV: u8 = 6;

    const REQ_GET_HEADERS: u8 = 1;
    const REQ_GET_PAYLOADS: u8 = 2;
    const REQ_GET_TX: u8 = 3;

    const RESP_HEADERS: u8 = 1;
    const RESP_PAYLOADS: u8 = 2;
    const RESP_NOTFOUND: u8 = 3;
    const RESP_TXS: u8 = 4;

    impl Encodable for P2pMessage {
        fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
            match self {
                P2pMessage::HeaderAnnounce(h) => { TAG_HEADER_ANN.encode(w)?; h.encode(w) }
                P2pMessage::HeadersInv { ids } => { TAG_HEADERS_INV.encode(w)?; ids.encode(w) }
                P2pMessage::PayloadInv { roots } => { TAG_PAYLOAD_INV.encode(w)?; roots.encode(w) }
                P2pMessage::TxInv { ids } => { TAG_TX_INV.encode(w)?; ids.encode(w) }
                P2pMessage::Req(r) => { TAG_REQ.encode(w)?; r.encode(w) }
                P2pMessage::Resp(r) => { TAG_RESP.encode(w)?; r.encode(w) }
            }
        }
        fn encoded_len(&self) -> usize {
            1 + match self {
                P2pMessage::HeaderAnnounce(h) => h.encoded_len(),
                P2pMessage::HeadersInv { ids } => ids.encoded_len(),
                P2pMessage::PayloadInv { roots } => roots.encoded_len(),
                P2pMessage::TxInv { ids } => ids.encoded_len(),
                P2pMessage::Req(r) => r.encoded_len(),
                P2pMessage::Resp(r) => r.encoded_len(),
            }
        }
    }

    impl Decodable for P2pMessage {
        fn decode<R: std::io::Read>(r: &mut R) -> Result<Self, CodecError> {
            let tag = u8::decode(r)?;
            match tag {
                TAG_HEADER_ANN => Ok(P2pMessage::HeaderAnnounce(AnchorHeader::decode(r)?)),
                TAG_HEADERS_INV => Ok(P2pMessage::HeadersInv { ids: Vec::<AnchorId>::decode(r)? }),
                TAG_PAYLOAD_INV => Ok(P2pMessage::PayloadInv { roots: Vec::<[u8;32]>::decode(r)? }),
                TAG_TX_INV => Ok(P2pMessage::TxInv { ids: Vec::<[u8;32]>::decode(r)? }),
                TAG_REQ => Ok(P2pMessage::Req(ReqMsg::decode(r)?)),
                TAG_RESP => Ok(P2pMessage::Resp(RespMsg::decode(r)?)),
                _ => Err(CodecError::InvalidTag(tag)),
            }
        }
    }

    impl Encodable for ReqMsg {
        fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
            match self {
                ReqMsg::GetHeaders { ids } => { REQ_GET_HEADERS.encode(w)?; ids.encode(w) }
                ReqMsg::GetPayloads { roots } => { REQ_GET_PAYLOADS.encode(w)?; roots.encode(w) }
                ReqMsg::GetTx { ids } => { REQ_GET_TX.encode(w)?; ids.encode(w) }
            }
        }
        fn encoded_len(&self) -> usize {
            1 + match self {
                ReqMsg::GetHeaders { ids } => ids.encoded_len(),
                ReqMsg::GetPayloads { roots } => roots.encoded_len(),
                ReqMsg::GetTx { ids } => ids.encoded_len(),
            }
        }
    }

    impl Decodable for ReqMsg {
        fn decode<R: std::io::Read>(r: &mut R) -> Result<Self, CodecError> {
            let tag = u8::decode(r)?;
            match tag {
                REQ_GET_HEADERS => Ok(ReqMsg::GetHeaders { ids: Vec::<AnchorId>::decode(r)? }),
                REQ_GET_PAYLOADS => Ok(ReqMsg::GetPayloads { roots: Vec::<[u8;32]>::decode(r)? }),
                REQ_GET_TX => Ok(ReqMsg::GetTx { ids: Vec::<[u8;32]>::decode(r)? }),
                _ => Err(CodecError::InvalidTag(tag)),
            }
        }
    }

    impl Encodable for RespMsg {
        fn encode<W: std::io::Write>(&self, w: &mut W) -> Result<(), CodecError> {
            match self {
                RespMsg::Headers { headers } => { RESP_HEADERS.encode(w)?; headers.encode(w) }
                RespMsg::Payloads { payloads } => { RESP_PAYLOADS.encode(w)?; payloads.encode(w) }
                RespMsg::Txs { txs } => { RESP_TXS.encode(w)?; txs.encode(w) }
                RespMsg::NotFound { ty, ids } => { RESP_NOTFOUND.encode(w)?; ty.encode(w)?; ids.encode(w) }
            }
        }
        fn encoded_len(&self) -> usize {
            1 + match self {
                RespMsg::Headers { headers } => headers.encoded_len(),
                RespMsg::Payloads { payloads } => payloads.encoded_len(),
                RespMsg::Txs { txs } => txs.encoded_len(),
                RespMsg::NotFound { ty: _, ids } => 1 + ids.encoded_len(),
            }
        }
    }

    impl Decodable for RespMsg {
        fn decode<R: std::io::Read>(r: &mut R) -> Result<Self, CodecError> {
            let tag = u8::decode(r)?;
            match tag {
                RESP_HEADERS => Ok(RespMsg::Headers { headers: Vec::<AnchorHeader>::decode(r)? }),
                RESP_PAYLOADS => Ok(RespMsg::Payloads { payloads: Vec::<AnchorPayload>::decode(r)? }),
                RESP_TXS => Ok(RespMsg::Txs { txs: Vec::<pc_types::MicroTx>::decode(r)? }),
                RESP_NOTFOUND => {
                    let ty = u8::decode(r)?;
                    let ids = Vec::<[u8;32]>::decode(r)?;
                    Ok(RespMsg::NotFound { ty, ids })
                }
                _ => Err(CodecError::InvalidTag(tag)),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pc_types::ParentList;

        fn rt<T: Encodable + Decodable + core::fmt::Debug + PartialEq>(v: &T) -> Result<T, CodecError> {
            let mut buf = Vec::new();
            v.encode(&mut buf)?;
            let mut slice = &buf[..];
            T::decode(&mut slice)
        }

        #[test]
        fn roundtrip_header_announce() {
            let parents = ParentList::default();
            let hdr = AnchorHeader { version:1, shard_id:0, parents, payload_hash:[0u8;32], creator_index:7, vote_mask:0, ack_present:false, ack_id: AnchorId([0u8;32]) };
            let msg = P2pMessage::HeaderAnnounce(hdr);
            assert_eq!(rt(&msg).ok(), Some(msg));
        }

        #[test]
        fn roundtrip_payload_inv() {
            let msg = P2pMessage::PayloadInv { roots: vec![[1u8;32], [2u8;32]] };
            assert_eq!(rt(&msg).ok(), Some(msg));
        }

        #[test]
        fn roundtrip_headers_inv() {
            let msg = P2pMessage::HeadersInv { ids: vec![AnchorId([1u8;32]), AnchorId([2u8;32])] };
            assert_eq!(rt(&msg).ok(), Some(msg));
        }

        #[test]
        fn roundtrip_tx_inv() {
            let msg = P2pMessage::TxInv { ids: vec![[7u8;32], [8u8;32]] };
            assert_eq!(rt(&msg).ok(), Some(msg));
        }

        #[test]
        fn roundtrip_req_resp() {
            let r1 = ReqMsg::GetHeaders { ids: vec![AnchorId([9u8;32]), AnchorId([7u8;32])] };
            assert_eq!(rt(&r1).ok(), Some(r1.clone()));

            let r2 = ReqMsg::GetPayloads { roots: vec![[3u8;32]] };
            assert_eq!(rt(&r2).ok(), Some(r2.clone()));

            let r3 = ReqMsg::GetTx { ids: vec![[4u8;32]] };
            assert_eq!(rt(&r3).ok(), Some(r3.clone()));

            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader { version:1, shard_id:0, parents, payload_hash:[0u8;32], creator_index:1, vote_mask:0, ack_present:false, ack_id: AnchorId([0u8;32]) };
            let resp1 = RespMsg::Headers { headers: vec![hdr] };
            assert_eq!(rt(&resp1).ok(), Some(resp1.clone()));

            let pl = AnchorPayload { version:1, micro_txs: vec![], mints: vec![], claims: vec![], evidences: vec![], payout_root: [0u8;32] };
            let resp2 = RespMsg::Payloads { payloads: vec![pl] };
            assert_eq!(rt(&resp2).ok(), Some(resp2.clone()));

            let resp3 = RespMsg::NotFound { ty: 2, ids: vec![[4u8;32], [5u8;32]] };
            assert_eq!(rt(&resp3).ok(), Some(resp3));

            let tx = pc_types::MicroTx { version:1, inputs: vec![], outputs: vec![] };
            let resp4 = RespMsg::Txs { txs: vec![tx] };
            assert_eq!(rt(&resp4).ok(), Some(resp4));
        }
    }
}


#[derive(Clone, Debug)]
pub struct P2pNode {
    _cfg: P2pConfig,
}

impl P2pNode {
    pub fn new(cfg: P2pConfig) -> Result<Self, P2pError> {
        if cfg.max_peers == 0 { return Err(P2pError::InvalidConfig); }
        Ok(Self { _cfg: cfg })
    }

    pub fn announce_header(&self, _hdr: &AnchorHeader) -> Result<(), P2pError> {
        Ok(())
    }
}

#[cfg(all(feature = "async", feature = "quic"))]
pub mod quic_transport {
    use super::messages::P2pMessage;
    use super::async_svc::P2pService;
    use super::P2pError;
    use pc_codec::{Encodable, Decodable};
    use quinn::{Endpoint, ServerConfig, ClientConfig, TransportConfig};
    use rustls::{Certificate, PrivateKey, RootCertStore};
    use std::net::SocketAddr;
    use tokio::sync::mpsc;
    use std::sync::{Arc, Mutex};
    

    fn encode_msg(msg: &P2pMessage) -> Result<Vec<u8>, P2pError> {
        let mut body = Vec::new();
        msg.encode(&mut body).map_err(|_| P2pError::InvalidConfig)?;
        let mut out = Vec::with_capacity(4 + body.len());
        let len = body.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub(crate) async fn read_one(mut r: quinn::RecvStream) -> Result<Option<P2pMessage>, P2pError> {
        let mut len_buf = [0u8; 4];
        if let Err(_e) = r.read_exact(&mut len_buf).await { return Ok(None); }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        if let Err(_e) = r.read_exact(&mut data).await { return Ok(None); }
        let mut slice = &data[..];
        match P2pMessage::decode(&mut slice) { Ok(m) => Ok(Some(m)), Err(_e) => Ok(None) }
    }

    fn make_server_config() -> Result<(ServerConfig, Vec<u8>), P2pError> {
        let cert = match rcgen::generate_simple_self_signed(vec!["localhost".to_string()]) { Ok(c) => c, Err(_e) => return Err(P2pError::InvalidConfig) };
        let cert_der = match cert.serialize_der() { Ok(c) => c, Err(_e) => return Err(P2pError::InvalidConfig) };
        let key_der = cert.serialize_private_key_der();
        let cert_chain = vec![Certificate(cert_der.clone())];
        let key = PrivateKey(key_der);
        let mut cfg = match ServerConfig::with_single_cert(cert_chain, key) { Ok(c) => c, Err(_e) => return Err(P2pError::InvalidConfig) };
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        cfg.transport = std::sync::Arc::new(transport);
        Ok((cfg, cert_der))
    }

    pub async fn start_server(addr: SocketAddr, svc: P2pService) -> Result<(Endpoint, Vec<u8>, tokio::task::JoinHandle<()>, mpsc::Sender<P2pMessage>), P2pError> {
        let (server_cfg, cert_der) = make_server_config()?;
        let endpoint = match Endpoint::server(server_cfg, addr) { Ok(ep) => ep, Err(_e) => return Err(P2pError::InvalidConfig) };
        let (tx, mut rx) = mpsc::channel::<P2pMessage>(1024);
        let connections: Arc<Mutex<Vec<quinn::Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let ep_clone = endpoint.clone();
        let svc_clone = svc.clone();
        let conns_for_accept = connections.clone();
        let handle = tokio::spawn(async move {
            while let Some(connecting) = ep_clone.accept().await {
                if let Ok(new_conn) = connecting.await {
                    if let Ok(mut guard) = conns_for_accept.lock() { guard.push(new_conn.clone()); }
                    let svc2 = svc_clone.clone();
                    let peer = new_conn.remote_address();
                    tokio::spawn(async move {
                        while let Ok(recv) = new_conn.accept_uni().await {
                            if let Ok(Some(m)) = read_one(recv).await {
                                let _ = svc2.send_message_from(peer, m).await;
                            }
                        }
                    });
                }
            }
        });
        let conns_for_broadcast = connections.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let buf = match encode_msg(&msg) { Ok(b) => b, Err(_)=> continue };
                if let Ok(mut guard) = conns_for_broadcast.lock() {
                    guard.retain(|conn| {
                        let buf_vec = buf.clone();
                        let c = conn.clone();
                        tokio::spawn(async move {
                            match c.open_uni().await {
                                Ok(mut s) => {
                                    if let Err(_e) = s.write_all(&buf_vec).await { super::async_svc::out_error_inc(); return; }
                                    if let Err(_e) = s.finish().await { super::async_svc::out_error_inc(); }
                                }
                                Err(_e) => { super::async_svc::out_error_inc(); }
                            }
                        });
                        true
                    });
                }
            }
        });
        Ok((endpoint, cert_der, handle, tx))
    }

    pub fn client_config_from_cert(cert_der: &[u8]) -> Result<ClientConfig, P2pError> {
        let mut roots = RootCertStore::empty();
        if roots.add(&Certificate(cert_der.to_vec())).is_err() { return Err(P2pError::InvalidConfig); }
        let tls = rustls::ClientConfig::builder().with_safe_defaults().with_root_certificates(roots).with_no_client_auth();
        Ok(ClientConfig::new(std::sync::Arc::new(tls)))
    }

    pub async fn connect(addr: SocketAddr, cfg: ClientConfig) -> Result<quinn::Connection, P2pError> {
        let bind_addr: std::net::SocketAddr = match "0.0.0.0:0".parse() { Ok(a) => a, Err(_e) => return Err(P2pError::InvalidConfig) };
        let mut endpoint = match Endpoint::client(bind_addr) { Ok(ep) => ep, Err(_e) => return Err(P2pError::InvalidConfig) };
        endpoint.set_default_client_config(cfg);
        let connecting = match endpoint.connect(addr, "localhost") { Ok(c) => c, Err(_e) => return Err(P2pError::InvalidConfig) };
        match connecting.await { Ok(c) => Ok(c), Err(_e) => Err(P2pError::InvalidConfig) }
    }

    pub struct QuicClientSink { conn: quinn::Connection }
    impl QuicClientSink { pub fn new(conn: quinn::Connection) -> Self { Self { conn } } }

    #[async_trait::async_trait]
    impl super::async_svc::OutboundSink for QuicClientSink {
        async fn deliver(&self, msg: P2pMessage) -> Result<(), P2pError> {
            let buf = match encode_msg(&msg) { Ok(b) => b, Err(e) => { super::async_svc::out_error_inc(); return Err(e); } };
            let mut s = match self.conn.open_uni().await { Ok(st) => st, Err(_e) => { super::async_svc::out_error_inc(); return Err(P2pError::ChannelClosed); } };
            if let Err(_e) = s.write_all(&buf).await { super::async_svc::out_error_inc(); return Err(P2pError::ChannelClosed); }
            if let Err(_e) = s.finish().await { super::async_svc::out_error_inc(); return Err(P2pError::ChannelClosed); }
            Ok(())
        }
    }

    pub fn spawn_client_reader(conn: quinn::Connection, svc: P2pService) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Ok(recv) = conn.accept_uni().await {
                if let Ok(Some(m)) = read_one(recv).await {
                    let _ = svc.send_message_from(conn.remote_address(), m).await;
                }
            }
        })
    }
}

#[cfg(feature = "async")]
pub mod async_svc {
    use super::*;
    use super::messages::{P2pMessage, ReqMsg, RespMsg};
    use tokio::sync::mpsc;
    use tokio::sync::broadcast;
    use tokio::time::{sleep, Duration};
    use tracing::{info, warn};
    use std::collections::HashMap;
    use pc_types::{AnchorId, AnchorPayload, MicroTx};
    use pc_types::digest_microtx;
    use pc_types::payload_merkle_root;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{OnceLock, Arc};
    use std::time::Instant;
    use std::net::SocketAddr;

    // Optionales Store-Backend-Delegate (z. B. Diskstore). Threadsicher und async-fähig.
    #[async_trait::async_trait]
    pub trait StoreDelegate: Send + Sync {
        async fn insert_header(&self, h: AnchorHeader);
        async fn insert_payload(&self, p: AnchorPayload);
        async fn has_payload(&self, root: &[u8;32]) -> bool;
        async fn get_headers(&self, ids: &[AnchorId]) -> (Vec<AnchorHeader>, Vec<[u8;32]>);
        async fn get_payloads(&self, roots: &[[u8;32]]) -> (Vec<AnchorPayload>, Vec<[u8;32]>);
        async fn insert_tx(&self, tx: MicroTx);
        async fn has_tx(&self, id: &[u8;32]) -> bool;
        async fn get_txs(&self, ids: &[[u8;32]]) -> (Vec<MicroTx>, Vec<[u8;32]>);
    }

    #[derive(Debug)]
    pub enum P2pCmd {
        AnnounceHeader(AnchorHeader),
        PutPayload(AnchorPayload),
        PutTx(MicroTx),
        Incoming(P2pMessage),
        IncomingFrom(SocketAddr, P2pMessage),
        Shutdown,
    }

    #[derive(Clone)]
    pub struct P2pService { tx: mpsc::Sender<P2pCmd> }

    impl P2pService {
        pub async fn announce_header(&self, hdr: AnchorHeader) -> Result<(), P2pError> {
            self.tx.send(P2pCmd::AnnounceHeader(hdr)).await.map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn put_payload(&self, pl: AnchorPayload) -> Result<(), P2pError> {
            self.tx.send(P2pCmd::PutPayload(pl)).await.map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn put_tx(&self, tx: MicroTx) -> Result<(), P2pError> {
            self.tx.send(P2pCmd::PutTx(tx)).await.map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn send_message(&self, msg: P2pMessage) -> Result<(), P2pError> {
            self.tx.send(P2pCmd::Incoming(msg)).await.map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn send_message_from(&self, peer: SocketAddr, msg: P2pMessage) -> Result<(), P2pError> {
            self.tx.send(P2pCmd::IncomingFrom(peer, msg)).await.map_err(|_| P2pError::ChannelClosed)
        }
        pub async fn shutdown(&self) -> Result<(), P2pError> {
            self.tx.send(P2pCmd::Shutdown).await.map_err(|_| P2pError::ChannelClosed)
        }
    }

    // Globale Metriken (prozessweit)
    static INBOUND_TOTAL: AtomicU64 = AtomicU64::new(0);
    static INBOUND_DROPPED_RATE: AtomicU64 = AtomicU64::new(0);
    static OUTBOUND_TOTAL: AtomicU64 = AtomicU64::new(0);
    static PEER_RL_PURGED_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Per-Message-Typ (Inbound)
    static IN_HDR_TOTAL: AtomicU64 = AtomicU64::new(0);
    static IN_INV_TOTAL: AtomicU64 = AtomicU64::new(0);
    static IN_REQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    static IN_RESP_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Per-Message-Typ (Outbound)
    static OUT_HDR_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUT_INV_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUT_REQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUT_RESP_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Outbound-Fehler (Netz/QUIC)
    static OUT_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Outbox-Queue (mpsc)
    static OUTBOX_ENQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    static OUTBOX_DEQ_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Latenz-Histogramm (Inbound-Handling) – Buckets in Sekunden: 1ms,5ms,10ms,50ms,100ms,500ms,+Inf
    static IN_HIST_LE_1MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_5MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_10MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_50MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_100MS: AtomicU64 = AtomicU64::new(0);
    static IN_HIST_LE_500MS: AtomicU64 = AtomicU64::new(0);
    static IN_HANDLE_COUNT: AtomicU64 = AtomicU64::new(0);
    static IN_HANDLE_SUM_MICROS: AtomicU64 = AtomicU64::new(0);

    // Inbound-Observer (Broadcast): ermöglicht externen Abonnenten, eingehende P2P-Messages zu beobachten
    static INBOUND_OBS: OnceLock<broadcast::Sender<P2pMessage>> = OnceLock::new();

    fn notify_inbound(msg: &P2pMessage) {
        if let Some(tx) = INBOUND_OBS.get() {
            let _ = tx.send(msg.clone());
        }
    }

    /// Abonniere eingehende P2P-Messages (HeaderAnnounce/Inv/Req/Resp), die der Service verarbeitet
    pub fn inbound_subscribe() -> broadcast::Receiver<P2pMessage> {
        let tx = INBOUND_OBS.get_or_init(|| {
            let (tx, _rx) = broadcast::channel(1024);
            tx
        });
        tx.subscribe()
    }

    // Öffentliche Inkrement-Helfer für andere Module
    pub fn out_error_inc() { OUT_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed); }
    pub fn outbox_deq_inc() { OUTBOX_DEQ_TOTAL.fetch_add(1, Ordering::Relaxed); }

    #[derive(Debug, Clone, Copy)]
    pub struct MetricsSnapshot {
        pub inbound_total: u64,
        pub inbound_dropped_rate: u64,
        pub outbound_total: u64,
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
        pub in_handle_count: u64,
        pub in_handle_sum_micros: u64,
        pub in_bucket_le_1ms: u64,
        pub in_bucket_le_5ms: u64,
        pub in_bucket_le_10ms: u64,
        pub in_bucket_le_50ms: u64,
        pub in_bucket_le_100ms: u64,
        pub in_bucket_le_500ms: u64,
    }

    pub fn metrics_snapshot() -> MetricsSnapshot {
        MetricsSnapshot {
            inbound_total: INBOUND_TOTAL.load(Ordering::Relaxed),
            inbound_dropped_rate: INBOUND_DROPPED_RATE.load(Ordering::Relaxed),
            outbound_total: OUTBOUND_TOTAL.load(Ordering::Relaxed),
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
            in_handle_count: IN_HANDLE_COUNT.load(Ordering::Relaxed),
            in_handle_sum_micros: IN_HANDLE_SUM_MICROS.load(Ordering::Relaxed),
            in_bucket_le_1ms: IN_HIST_LE_1MS.load(Ordering::Relaxed),
            in_bucket_le_5ms: IN_HIST_LE_5MS.load(Ordering::Relaxed),
            in_bucket_le_10ms: IN_HIST_LE_10MS.load(Ordering::Relaxed),
            in_bucket_le_50ms: IN_HIST_LE_50MS.load(Ordering::Relaxed),
            in_bucket_le_100ms: IN_HIST_LE_100MS.load(Ordering::Relaxed),
            in_bucket_le_500ms: IN_HIST_LE_500MS.load(Ordering::Relaxed),
        }
    }

    fn record_in_latency(dur: std::time::Duration) {
        let micros = dur.as_micros() as u64;
        IN_HANDLE_COUNT.fetch_add(1, Ordering::Relaxed);
        IN_HANDLE_SUM_MICROS.fetch_add(micros, Ordering::Relaxed);
        // Buckets in ms thresholds
        let ms = micros as f64 / 1000.0;
        if ms <= 1.0 { IN_HIST_LE_1MS.fetch_add(1, Ordering::Relaxed); return; }
        if ms <= 5.0 { IN_HIST_LE_5MS.fetch_add(1, Ordering::Relaxed); return; }
        if ms <= 10.0 { IN_HIST_LE_10MS.fetch_add(1, Ordering::Relaxed); return; }
        if ms <= 50.0 { IN_HIST_LE_50MS.fetch_add(1, Ordering::Relaxed); return; }
        if ms <= 100.0 { IN_HIST_LE_100MS.fetch_add(1, Ordering::Relaxed); return; }
        if ms <= 500.0 { IN_HIST_LE_500MS.fetch_add(1, Ordering::Relaxed); }
        // +Inf: wird in der Exposition über count abgebildet
    }

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
            let now = Instant::now();
            let dt = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
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
    }

    impl RateLimiter {
        fn from_cfg(cfg: Option<&RateLimitConfig>) -> Self {
            match cfg {
                Some(c) => Self {
                    hdr: Bucket::new(
                        if c.hdr_capacity == 0 { 2000 } else { c.hdr_capacity },
                        if c.hdr_refill_per_sec == 0 { 2000 } else { c.hdr_refill_per_sec },
                    ),
                    inv: Bucket::new(
                        if c.inv_capacity == 0 { 500 } else { c.inv_capacity },
                        if c.inv_refill_per_sec == 0 { 500 } else { c.inv_refill_per_sec },
                    ),
                    req: Bucket::new(
                        if c.req_capacity == 0 { 1000 } else { c.req_capacity },
                        if c.req_refill_per_sec == 0 { 1000 } else { c.req_refill_per_sec },
                    ),
                    resp: Bucket::new(
                        if c.resp_capacity == 0 { 1000 } else { c.resp_capacity },
                        if c.resp_refill_per_sec == 0 { 1000 } else { c.resp_refill_per_sec },
                    ),
                },
                None => Self {
                    hdr: Bucket::new(2000, 2000),
                    inv: Bucket::new(500, 500),
                    req: Bucket::new(1000, 1000),
                    resp: Bucket::new(1000, 1000),
                },
            }
        }
        fn allow_msg(&mut self, msg: &P2pMessage) -> bool {
            match msg {
                P2pMessage::HeaderAnnounce(_) => self.hdr.allow(),
                P2pMessage::HeadersInv { .. } => self.inv.allow(),
                P2pMessage::PayloadInv { .. } => self.inv.allow(),
                P2pMessage::TxInv { .. } => self.inv.allow(),
                P2pMessage::Req(_) => self.req.allow(),
                P2pMessage::Resp(_) => self.resp.allow(),
            }
        }
    }

    struct InMemoryStore {
        headers: HashMap<AnchorId, AnchorHeader>,
        payloads: HashMap<[u8;32], AnchorPayload>,
        txs: HashMap<[u8;32], MicroTx>,
    }

    impl InMemoryStore {
        fn new() -> Self { Self { headers: HashMap::new(), payloads: HashMap::new(), txs: HashMap::new() } }
        fn insert_header(&mut self, h: AnchorHeader) {
            let id = AnchorId(h.id_digest());
            let _ = self.headers.insert(id, h);
        }
        fn insert_payload(&mut self, p: AnchorPayload) {
            let root = payload_merkle_root(&p);
            let _ = self.payloads.insert(root, p);
        }
        fn has_payload(&self, root: &[u8;32]) -> bool { self.payloads.contains_key(root) }
        fn get_headers(&self, ids: &[AnchorId]) -> (Vec<AnchorHeader>, Vec<[u8;32]>) {
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
        fn get_payloads(&self, roots: &[[u8;32]]) -> (Vec<AnchorPayload>, Vec<[u8;32]>) {
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
            let _ = self.txs.insert(id, tx);
        }
        fn has_tx(&self, id: &[u8;32]) -> bool { self.txs.contains_key(id) }
        fn get_txs(&self, ids: &[[u8;32]]) -> (Vec<MicroTx>, Vec<[u8;32]>) {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                if let Some(tx) = self.txs.get(id) { found.push(tx.clone()); } else { missing.push(*id); }
            }
            (found, missing)
        }
    }

    #[derive(Clone)]
    struct Outbox { tx: mpsc::Sender<P2pMessage> }
    impl Outbox {
        async fn send(&self, msg: P2pMessage) {
            // Outbox Enqueue + Outbound per-Message-Typ zählen
            OUTBOX_ENQ_TOTAL.fetch_add(1, Ordering::Relaxed);
            OUTBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
            match &msg {
                P2pMessage::HeaderAnnounce(_) => { OUT_HDR_TOTAL.fetch_add(1, Ordering::Relaxed); }
                P2pMessage::HeadersInv { .. } => { OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed); }
                P2pMessage::PayloadInv { .. } => { OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed); }
                P2pMessage::TxInv { .. } => { OUT_INV_TOTAL.fetch_add(1, Ordering::Relaxed); }
                P2pMessage::Req(_) => { OUT_REQ_TOTAL.fetch_add(1, Ordering::Relaxed); }
                P2pMessage::Resp(_) => { OUT_RESP_TOTAL.fetch_add(1, Ordering::Relaxed); }
            }
            let _ = self.tx.send(msg).await;
        }
    }

    async fn run_p2p_loop(
        cfg: P2pConfig,
        mut rx: mpsc::Receiver<P2pCmd>,
        out: Outbox,
        store_delegate: Option<Arc<dyn StoreDelegate>>,
    ) -> Result<(), P2pError> {
        if cfg.max_peers == 0 { return Err(P2pError::InvalidConfig); }
        let mut store = InMemoryStore::new();
        let mut rl = RateLimiter::from_cfg(cfg.rate.as_ref());
        struct PeerRate { rl: RateLimiter, last_seen: Instant }
        let mut per_peer_rl: HashMap<SocketAddr, PeerRate> = HashMap::new();
        let ttl_secs = cfg.rate.as_ref().map(|r| if r.peer_ttl_secs == 0 { 600 } else { r.peer_ttl_secs }).unwrap_or(600);

        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    match cmd {
                        Some(P2pCmd::AnnounceHeader(h)) => {
                            out.send(P2pMessage::HeaderAnnounce(h)).await;
                        }
                        Some(P2pCmd::PutPayload(pl)) => {
                            if let Some(d) = &store_delegate { d.insert_payload(pl).await; } else { store.insert_payload(pl); }
                        }
                        Some(P2pCmd::PutTx(tx)) => {
                            let id = digest_microtx(&tx);
                            if let Some(d) = &store_delegate { d.insert_tx(tx).await; } else { store.insert_tx(tx); }
                            out.send(P2pMessage::TxInv { ids: vec![id] }).await;
                        }
                        Some(P2pCmd::Incoming(P2pMessage::HeaderAnnounce(h))) => {
                            let start = Instant::now();
                            if rl.allow_msg(&P2pMessage::HeaderAnnounce(h.clone())) {
                                INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                IN_HDR_TOTAL.fetch_add(1, Ordering::Relaxed);
                                let h_clone = h.clone();
                                if let Some(d) = &store_delegate { d.insert_header(h).await; } else { store.insert_header(h); }
                                notify_inbound(&P2pMessage::HeaderAnnounce(h_clone));
                            } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                            record_in_latency(start.elapsed());
                        }
                        Some(P2pCmd::Incoming(P2pMessage::PayloadInv { roots })) => {
                            let start = Instant::now();
                            if rl.allow_msg(&P2pMessage::PayloadInv { roots: roots.clone() }) {
                                INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                let mut missing: Vec<[u8;32]> = Vec::new();
                                for r in roots.iter() {
                                    let present = if let Some(d) = &store_delegate { d.has_payload(r).await } else { store.has_payload(r) };
                                    if !present { missing.push(*r); }
                                }
                                if !missing.is_empty() {
                                    out.send(P2pMessage::Req(ReqMsg::GetPayloads { roots: missing })).await;
                                }
                                notify_inbound(&P2pMessage::PayloadInv { roots: roots.clone() });
                            } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                            record_in_latency(start.elapsed());
                        }
                        Some(P2pCmd::Incoming(P2pMessage::TxInv { ids })) => {
                            let start = Instant::now();
                            if rl.allow_msg(&P2pMessage::TxInv { ids: ids.clone() }) {
                                INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                let mut missing: Vec<[u8;32]> = Vec::new();
                                for id in ids.iter() {
                                    let present = if let Some(d) = &store_delegate { d.has_tx(id).await } else { store.has_tx(id) };
                                    if !present { missing.push(*id); }
                                }
                                if !missing.is_empty() { out.send(P2pMessage::Req(ReqMsg::GetTx { ids: missing })).await; }
                                notify_inbound(&P2pMessage::TxInv { ids: ids.clone() });
                            } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                            record_in_latency(start.elapsed());
                        }
                        Some(P2pCmd::Incoming(P2pMessage::HeadersInv { ids })) => {
                            let start = Instant::now();
                            if rl.allow_msg(&P2pMessage::HeadersInv { ids: ids.clone() }) {
                                INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                let (found, missing_raw) = if let Some(d) = &store_delegate { d.get_headers(&ids).await } else { store.get_headers(&ids) };
                                // found werden ignoriert; bei missing holen wir nach
                                let missing: Vec<AnchorId> = missing_raw.into_iter().map(AnchorId).collect();
                                if !missing.is_empty() {
                                    out.send(P2pMessage::Req(ReqMsg::GetHeaders { ids: missing })).await;
                                }
                                notify_inbound(&P2pMessage::HeadersInv { ids: ids.clone() });
                                let _ = found; // suppress unused warning if any
                            } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                            record_in_latency(start.elapsed());
                        }
                        Some(P2pCmd::Incoming(P2pMessage::Req(req))) => {
                            let start = Instant::now();
                            if rl.allow_msg(&P2pMessage::Req(req.clone())) {
                                INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                IN_REQ_TOTAL.fetch_add(1, Ordering::Relaxed);
                                match req {
                                    ReqMsg::GetHeaders { ref ids } => {
                                        let (found, missing) = if let Some(d) = &store_delegate { d.get_headers(ids).await } else { store.get_headers(ids) };
                                        if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Headers { headers: found })).await; }
                                        if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 1, ids: missing })).await; }
                                    }
                                    ReqMsg::GetPayloads { ref roots } => {
                                        let (found, missing) = if let Some(d) = &store_delegate { d.get_payloads(roots).await } else { store.get_payloads(roots) };
                                        if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Payloads { payloads: found })).await; }
                                        if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 2, ids: missing })).await; }
                                    }
                                    ReqMsg::GetTx { ref ids } => {
                                        let (found, missing) = if let Some(d) = &store_delegate { d.get_txs(ids).await } else { store.get_txs(ids) };
                                        if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Txs { txs: found })).await; }
                                        if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 3, ids: missing })).await; }
                                    }
                                }
                                notify_inbound(&P2pMessage::Req(req.clone()));
                            } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                            record_in_latency(start.elapsed());
                        }
                        Some(P2pCmd::Incoming(P2pMessage::Resp(resp))) => {
                            let start = Instant::now();
                            if rl.allow_msg(&P2pMessage::Resp(resp.clone())) {
                                INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                IN_RESP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                match resp { 
                                    RespMsg::Headers { ref headers } => {
                                        for h in headers.iter().cloned() {
                                            if let Some(d) = &store_delegate { d.insert_header(h).await; } else { store.insert_header(h); }
                                        }
                                    },
                                    RespMsg::Payloads { ref payloads } => {
                                        for p in payloads.iter().cloned() {
                                            if let Some(d) = &store_delegate { d.insert_payload(p).await; } else { store.insert_payload(p); }
                                        }
                                    },
                                    RespMsg::Txs { ref txs } => {
                                        for tx in txs.iter().cloned() {
                                            if let Some(d) = &store_delegate { d.insert_tx(tx).await; } else { store.insert_tx(tx); }
                                        }
                                    },
                                    RespMsg::NotFound { .. } => { } 
                                }
                                notify_inbound(&P2pMessage::Resp(resp.clone()));
                            } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                            record_in_latency(start.elapsed());
                        }
                        Some(P2pCmd::IncomingFrom(peer, msg)) => {
                            let use_per_peer = cfg.rate.as_ref().map(|r| r.per_peer).unwrap_or(true);
                            if use_per_peer {
                                let entry = per_peer_rl.entry(peer).or_insert_with(|| PeerRate { rl: RateLimiter::from_cfg(cfg.rate.as_ref()), last_seen: Instant::now() });
                                entry.last_seen = Instant::now();
                                match msg {
                                    P2pMessage::HeaderAnnounce(h) => {
                                        let start = Instant::now();
                                        if entry.rl.allow_msg(&P2pMessage::HeaderAnnounce(h.clone())) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed); IN_HDR_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            if let Some(d) = &store_delegate { d.insert_header(h).await; } else { store.insert_header(h); }
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::PayloadInv { roots } => {
                                        let start = Instant::now();
                                        if entry.rl.allow_msg(&P2pMessage::PayloadInv { roots: roots.clone() }) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            let mut missing: Vec<[u8;32]> = Vec::new();
                                            for r in roots.iter() {
                                                let present = if let Some(d) = &store_delegate { d.has_payload(r).await } else { store.has_payload(r) };
                                                if !present { missing.push(*r); }
                                            }
                                            if !missing.is_empty() { out.send(P2pMessage::Req(ReqMsg::GetPayloads { roots: missing })).await; }
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::TxInv { ids } => {
                                        let start = Instant::now();
                                        if entry.rl.allow_msg(&P2pMessage::TxInv { ids: ids.clone() }) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            let mut missing: Vec<[u8;32]> = Vec::new();
                                            for id in ids.iter() {
                                                let present = if let Some(d) = &store_delegate { d.has_tx(id).await } else { store.has_tx(id) };
                                                if !present { missing.push(*id); }
                                            }
                                            if !missing.is_empty() { out.send(P2pMessage::Req(ReqMsg::GetTx { ids: missing })).await; }
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::HeadersInv { ids } => {
                                        let start = Instant::now();
                                        if entry.rl.allow_msg(&P2pMessage::HeadersInv { ids: ids.clone() }) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            let (_found, missing_raw) = if let Some(d) = &store_delegate { d.get_headers(&ids).await } else { store.get_headers(&ids) };
                                            let missing: Vec<AnchorId> = missing_raw.into_iter().map(AnchorId).collect();
                                            if !missing.is_empty() { out.send(P2pMessage::Req(ReqMsg::GetHeaders { ids: missing })).await; }
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::Req(req) => {
                                        let start = Instant::now();
                                        if entry.rl.allow_msg(&P2pMessage::Req(req.clone())) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_REQ_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            match req {
                                                ReqMsg::GetHeaders { ref ids } => {
                                                    let (found, missing) = if let Some(d) = &store_delegate { d.get_headers(ids).await } else { store.get_headers(ids) };
                                                    if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Headers { headers: found })).await; }
                                                    if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 1, ids: missing })).await; }
                                                }
                                                ReqMsg::GetPayloads { ref roots } => {
                                                    let (found, missing) = if let Some(d) = &store_delegate { d.get_payloads(roots).await } else { store.get_payloads(roots) };
                                                    if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Payloads { payloads: found })).await; }
                                                    if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 2, ids: missing })).await; }
                                                }
                                                ReqMsg::GetTx { ref ids } => {
                                                    let (found, missing) = if let Some(d) = &store_delegate { d.get_txs(ids).await } else { store.get_txs(ids) };
                                                    if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Txs { txs: found })).await; }
                                                    if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 3, ids: missing })).await; }
                                                }
                                            }
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::Resp(resp) => {
                                        let start = Instant::now();
                                        if entry.rl.allow_msg(&P2pMessage::Resp(resp.clone())) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_RESP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            match resp {
                                                RespMsg::Headers { ref headers } => {
                                                    for h in headers.iter().cloned() {
                                                        if let Some(d) = &store_delegate { d.insert_header(h).await; } else { store.insert_header(h); }
                                                    }
                                                },
                                                RespMsg::Payloads { ref payloads } => {
                                                    for p in payloads.iter().cloned() {
                                                        if let Some(d) = &store_delegate { d.insert_payload(p).await; } else { store.insert_payload(p); }
                                                    }
                                                },
                                                RespMsg::Txs { ref txs } => {
                                                    for tx in txs.iter().cloned() {
                                                        if let Some(d) = &store_delegate { d.insert_tx(tx).await; } else { store.insert_tx(tx); }
                                                    }
                                                },
                                                RespMsg::NotFound { .. } => { }
                                            }
                                            notify_inbound(&P2pMessage::Resp(resp.clone())); 
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                }
                            } else {
                                match msg {
                                    P2pMessage::HeaderAnnounce(h) => {
                                        let start = Instant::now();
                                        if rl.allow_msg(&P2pMessage::HeaderAnnounce(h.clone())) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed); IN_HDR_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            let h_clone = h.clone();
                                            if let Some(d) = &store_delegate { d.insert_header(h).await; } else { store.insert_header(h); }
                                            notify_inbound(&P2pMessage::HeaderAnnounce(h_clone));
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::PayloadInv { roots } => {
                                        let start = Instant::now();
                                        if rl.allow_msg(&P2pMessage::PayloadInv { roots: roots.clone() }) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            let mut missing: Vec<[u8;32]> = Vec::new();
                                            for r in roots.iter() {
                                                let present = if let Some(d) = &store_delegate { d.has_payload(r).await } else { store.has_payload(r) };
                                                if !present { missing.push(*r); }
                                            }
                                            if !missing.is_empty() { out.send(P2pMessage::Req(ReqMsg::GetPayloads { roots: missing })).await; }
                                            notify_inbound(&P2pMessage::PayloadInv { roots: roots.clone() });
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::TxInv { ids } => {
                                        let start = Instant::now();
                                        if rl.allow_msg(&P2pMessage::TxInv { ids: ids.clone() }) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            let mut missing: Vec<[u8;32]> = Vec::new();
                                            for id in ids.iter() {
                                                let present = if let Some(d) = &store_delegate { d.has_tx(id).await } else { store.has_tx(id) };
                                                if !present { missing.push(*id); }
                                            }
                                            if !missing.is_empty() { out.send(P2pMessage::Req(ReqMsg::GetTx { ids: missing })).await; }
                                            notify_inbound(&P2pMessage::TxInv { ids: ids.clone() });
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::HeadersInv { ids } => {
                                        let start = Instant::now();
                                        if rl.allow_msg(&P2pMessage::HeadersInv { ids: ids.clone() }) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_INV_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            let (_found, missing_raw) = if let Some(d) = &store_delegate { d.get_headers(&ids).await } else { store.get_headers(&ids) };
                                            let missing: Vec<AnchorId> = missing_raw.into_iter().map(AnchorId).collect();
                                            if !missing.is_empty() { out.send(P2pMessage::Req(ReqMsg::GetHeaders { ids: missing })).await; }
                                            notify_inbound(&P2pMessage::HeadersInv { ids: ids.clone() });
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::Req(req) => {
                                        let start = Instant::now();
                                        if rl.allow_msg(&P2pMessage::Req(req.clone())) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_REQ_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            match req {
                                                ReqMsg::GetHeaders { ref ids } => {
                                                    let (found, missing) = if let Some(d) = &store_delegate { d.get_headers(ids).await } else { store.get_headers(ids) };
                                                    if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Headers { headers: found })).await; }
                                                    if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 1, ids: missing })).await; }
                                                }
                                                ReqMsg::GetPayloads { ref roots } => {
                                                    let (found, missing) = if let Some(d) = &store_delegate { d.get_payloads(roots).await } else { store.get_payloads(roots) };
                                                    if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Payloads { payloads: found })).await; }
                                                    if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 2, ids: missing })).await; }
                                                }
                                                ReqMsg::GetTx { ref ids } => {
                                                    let (found, missing) = if let Some(d) = &store_delegate { d.get_txs(ids).await } else { store.get_txs(ids) };
                                                    if !found.is_empty() { out.send(P2pMessage::Resp(RespMsg::Txs { txs: found })).await; }
                                                    if !missing.is_empty() { out.send(P2pMessage::Resp(RespMsg::NotFound { ty: 3, ids: missing })).await; }
                                                }
                                            }
                                            notify_inbound(&P2pMessage::Req(req.clone()));
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                    P2pMessage::Resp(resp) => {
                                        let start = Instant::now();
                                        if rl.allow_msg(&P2pMessage::Resp(resp.clone())) {
                                            INBOUND_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            IN_RESP_TOTAL.fetch_add(1, Ordering::Relaxed);
                                            match resp {
                                                RespMsg::Headers { ref headers } => {
                                                    for h in headers.iter().cloned() {
                                                        if let Some(d) = &store_delegate { d.insert_header(h).await; } else { store.insert_header(h); }
                                                    }
                                                },
                                                RespMsg::Payloads { ref payloads } => {
                                                    for p in payloads.iter().cloned() {
                                                        if let Some(d) = &store_delegate { d.insert_payload(p).await; } else { store.insert_payload(p); }
                                                    }
                                                },
                                                RespMsg::Txs { ref txs } => {
                                                    for tx in txs.iter().cloned() {
                                                        if let Some(d) = &store_delegate { d.insert_tx(tx).await; } else { store.insert_tx(tx); }
                                                    }
                                                },
                                                RespMsg::NotFound { .. } => { } 
                                            }
                                            notify_inbound(&P2pMessage::Resp(resp.clone())); 
                                        } else { INBOUND_DROPPED_RATE.fetch_add(1, Ordering::Relaxed); }
                                        record_in_latency(start.elapsed());
                                    }
                                }
                            }
                        }
                        Some(P2pCmd::Shutdown) => { info!("p2p shutdown received"); break; }
                        None => { warn!("p2p command channel closed"); break; }
                    }
                },
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
                }
            }
        }
        Ok(())
    }

    pub fn spawn(cfg: P2pConfig) -> (P2pService, mpsc::Receiver<P2pMessage>, tokio::task::JoinHandle<Result<(), P2pError>>) {
        let (tx, rx) = mpsc::channel(1024);
        let (out_tx, out_rx) = mpsc::channel(1024);
        let out = Outbox { tx: out_tx };
        let handle = tokio::spawn(run_p2p_loop(cfg, rx, out, None));
        (P2pService { tx }, out_rx, handle)
    }

    /// Spawn mit optionalem persistentem Store-Backend (z. B. DiskStore). Wenn übergeben, werden alle Store-Operationen
    /// über das Delegate geleitet; ansonsten nutzt der Service ein InMemoryStore.
    pub fn spawn_with_store(
        cfg: P2pConfig,
        store: Arc<dyn StoreDelegate>,
    ) -> (P2pService, mpsc::Receiver<P2pMessage>, tokio::task::JoinHandle<Result<(), P2pError>>) {
        let (tx, rx) = mpsc::channel(1024);
        let (out_tx, out_rx) = mpsc::channel(1024);
        let out = Outbox { tx: out_tx };
        let handle = tokio::spawn(run_p2p_loop(cfg, rx, out, Some(store)));
        (P2pService { tx }, out_rx, handle)
    }

    // Outbound Peer Abstraktion
    #[async_trait::async_trait]
    pub trait OutboundSink: Send + Sync {
        async fn deliver(&self, msg: P2pMessage) -> Result<(), P2pError>;
    }

    pub struct InProcessSink { remote: P2pService }
    impl InProcessSink { pub fn new(remote: P2pService) -> Self { Self { remote } } }

    #[async_trait::async_trait]
    impl OutboundSink for InProcessSink {
        async fn deliver(&self, msg: P2pMessage) -> Result<(), P2pError> {
            self.remote.send_message(msg).await
        }
    }

    #[cfg(test)]
    #[cfg(feature = "async")]
    mod itests {
        use super::*;
        use super::super::messages::{P2pMessage, ReqMsg, RespMsg};
        use pc_types::{AnchorPayload, payload_merkle_root};
        use pc_types::{AnchorHeader, AnchorId};
        use tokio::time::{timeout, Duration};

        // End-to-End: INV -> GET_PAYLOADS -> PAYLOADS zwischen zwei Loops
        #[tokio::test]
        async fn inv_getpayloads_flow() {
            let cfg = P2pConfig { max_peers: 8, rate: None };
            let (svc_a, mut out_a, handle_a) = spawn(cfg.clone());
            let (svc_b, mut out_b, handle_b) = spawn(cfg.clone());

            // Erzeuge Payload auf A
            let payload = AnchorPayload { version:1, micro_txs: vec![], mints: vec![], claims: vec![], evidences: vec![], payout_root: [9u8;32] };
            let root = payload_merkle_root(&payload);
            let _ = svc_a.put_payload(payload).await; // ok if ChannelClosed? here it should be ok

            // Sende INV an B (Simuliert Netzwerk)
            let _ = svc_b.send_message(P2pMessage::PayloadInv { roots: vec![root] }).await;

            // B soll GET_PAYLOADS erzeugen (auf out_b)
            let req = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetPayloads { roots }) = msg { return Some(roots); }
                    } else { return None; }
                }
            }).await.ok().flatten().unwrap_or_default();
            assert_eq!(req, vec![root]);

            // Leite GET_PAYLOADS von B an A (simuliert Netzwerk)
            let _ = svc_a.send_message(P2pMessage::Req(ReqMsg::GetPayloads { roots: req.clone() })).await;

            // Erwarte auf out_a die PAYLOADS-Response
            let resp_from_a = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_a.recv().await {
                        if let P2pMessage::Resp(RespMsg::Payloads { payloads }) = msg { return Some(payloads); }
                    } else { return None; }
                }
            }).await.ok().flatten().unwrap_or_default();
            assert!(!resp_from_a.is_empty());

            // Forwarde die Response von A an B (B speichert nun Payload)
            let _ = svc_b.send_message(P2pMessage::Resp(RespMsg::Payloads { payloads: resp_from_a.clone() })).await;

            // Prüfe: Stelle GET_PAYLOADS an B und erwarte PAYLOADS als Antwort auf out_b
            let _ = svc_b.send_message(P2pMessage::Req(ReqMsg::GetPayloads { roots: vec![root] })).await;
            let got = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Resp(RespMsg::Payloads { payloads }) = msg { return Some(payloads); }
                    } else { return None; }
                }
            }).await.ok().flatten();
            assert!(got.map(|v| !v.is_empty()).unwrap_or(false));

            // Shutdown sauber
            let _ = svc_a.shutdown().await;
            let _ = svc_b.shutdown().await;
            let _ = handle_a.await;
            let _ = handle_b.await;
        }

        // End-to-End: HEADERS_INV -> GET_HEADERS -> HEADERS zwischen zwei Loops
        #[tokio::test]
        async fn headers_inv_getheaders_flow() {
            let cfg = P2pConfig { max_peers: 8, rate: None };
            let (svc_a, mut out_a, handle_a) = spawn(cfg.clone());
            let (svc_b, mut out_b, handle_b) = spawn(cfg.clone());

            // Erzeuge Header auf A
            let parents = pc_types::ParentList::default();
            let hdr = AnchorHeader { version:1, shard_id:0, parents, payload_hash:[0u8;32], creator_index:1, vote_mask:0, ack_present:false, ack_id: AnchorId([0u8;32]) };
            let id = pc_types::AnchorId(hdr.id_digest());
            // Insert in A-Store durch Incoming-Message
            let _ = svc_a.send_message(P2pMessage::HeaderAnnounce(hdr.clone())).await;

            // Sende HEADERS_INV an B (simuliert Netzwerk)
            let _ = svc_b.send_message(P2pMessage::HeadersInv { ids: vec![id] }).await;

            // B soll GET_HEADERS erzeugen (auf out_b)
            let req_ids = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Req(ReqMsg::GetHeaders { ids }) = msg { return Some(ids); }
                    } else { return None; }
                }
            }).await.ok().flatten().unwrap_or_default();
            assert_eq!(req_ids, vec![id]);

            // Leite GET_HEADERS von B an A (simuliert Netzwerk)
            let _ = svc_a.send_message(P2pMessage::Req(ReqMsg::GetHeaders { ids: req_ids.clone() })).await;

            // Erwarte auf out_a die HEADERS-Response
            let resp_from_a = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_a.recv().await {
                        if let P2pMessage::Resp(RespMsg::Headers { headers }) = msg { return Some(headers); }
                    } else { return None; }
                }
            }).await.ok().flatten().unwrap_or_default();
            assert_eq!(resp_from_a.len(), 1);

            // Forwarde die Response von A an B (B speichert nun Header)
            let _ = svc_b.send_message(P2pMessage::Resp(RespMsg::Headers { headers: resp_from_a.clone() })).await;

            // Prüfe: Stelle GET_HEADERS an B und erwarte HEADERS als Antwort auf out_b
            let _ = svc_b.send_message(P2pMessage::Req(ReqMsg::GetHeaders { ids: vec![id] })).await;
            let got = timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(msg) = out_b.recv().await {
                        if let P2pMessage::Resp(RespMsg::Headers { headers }) = msg { return Some(headers); }
                    } else { return None; }
                }
            }).await.ok().flatten().unwrap_or_default();
            assert_eq!(got.len(), 1);

            // Shutdown sauber
            let _ = svc_a.shutdown().await;
            let _ = svc_b.shutdown().await;
            let _ = handle_a.await;
            let _ = handle_b.await;
        }
    }
}
