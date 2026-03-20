// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::result_large_err)]

#[cfg(all(feature = "async", feature = "libp2p"))]
pub mod node {
    #![allow(clippy::vec_init_then_push)]
    use crate::async_svc::{OutboundEnvelope, P2pService};
    use crate::messages::{self, P2pMessage, ReqMsg};
    use crate::P2pError;
    use libp2p::core::connection::ConnectedPoint;
    use libp2p::futures::StreamExt;
    use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
    use libp2p::kad::{self, store::MemoryStore};
    use libp2p::request_response as rr;
    use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
    use libp2p::Transport;
    use libp2p::{identity, multiaddr::Protocol, noise, tcp, yamux, Multiaddr, PeerId, Swarm};
    use pc_codec::{Decodable, Encodable};
    use serde::{Deserialize, Serialize};
    use tracing::debug;

    use async_trait::async_trait;
    use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::select;
    use tokio::sync::{mpsc, Semaphore};
    use tokio::time::interval;

    const BLOCKED_PEERS_TTL_SECS: u64 = 60 * 60; // 1h
    const MAX_BLOCKED_PEERS: usize = 1024;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct BlockedPeerEntry {
        peer_id: String,
        expires_at: u64,
    }

    fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn blocked_peers_path(cfg: &Libp2pConfig) -> Option<PathBuf> {
        let p = cfg.identity_key_file.as_ref()?;
        let mut pb = PathBuf::from(p);
        pb.set_extension("blocked_peers.json");
        Some(pb)
    }

    fn prune_blocked_peers(blocked: &mut HashMap<PeerId, u64>, now: u64) -> bool {
        let before = blocked.len();
        blocked.retain(|_, exp| *exp > now);
        let mut changed = blocked.len() != before;

        if blocked.len() > MAX_BLOCKED_PEERS {
            let mut entries: Vec<_> = blocked.iter().map(|(k, v)| (*k, *v)).collect();
            entries.sort_by_key(|(_, exp)| std::cmp::Reverse(*exp));
            entries.truncate(MAX_BLOCKED_PEERS);
            blocked.clear();
            for (k, v) in entries {
                blocked.insert(k, v);
            }
            changed = true;
        }

        changed
    }

    fn load_blocked_peers(path: &Path) -> HashMap<PeerId, u64> {
        let now = now_epoch_secs();
        let mut out: HashMap<PeerId, u64> = HashMap::new();
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return out,
        };
        let entries: Vec<BlockedPeerEntry> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return out,
        };
        for e in entries {
            if e.expires_at <= now {
                continue;
            }
            if let Ok(pid) = e.peer_id.parse::<PeerId>() {
                out.insert(pid, e.expires_at);
            }
        }
        let _ = prune_blocked_peers(&mut out, now);
        out
    }

    fn save_blocked_peers(path: &Path, blocked: &HashMap<PeerId, u64>) {
        let mut entries: Vec<BlockedPeerEntry> = blocked
            .iter()
            .map(|(pid, exp)| BlockedPeerEntry {
                peer_id: pid.to_string(),
                expires_at: *exp,
            })
            .collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.expires_at));
        entries.truncate(MAX_BLOCKED_PEERS);

        if let Ok(data) = serde_json::to_string_pretty(&entries) {
            let _ = std::fs::write(path, data);
        }
    }

    fn peer_is_blocked(blocked: &mut HashMap<PeerId, u64>, peer: &PeerId, now: u64) -> bool {
        match blocked.get(peer).copied() {
            Some(exp) if exp > now => true,
            Some(_) => {
                blocked.remove(peer);
                false
            }
            None => false,
        }
    }

    #[derive(Clone, Debug)]
    pub struct Libp2pConfig {
        /// Optional: listen multiaddr, e.g. "/ip4/0.0.0.0/tcp/0".
        /// Optional: Listen-Multiaddr, z. B. "/ip4/0.0.0.0/tcp/0"
        pub listen_on: Option<String>,
        /// Shards to subscribe to explicitly. `None` => subscribe to all topics.
        /// Shards, die gezielt abonniert werden. None => alle Topics
        pub shards: Option<Vec<u8>>,
        /// Gossipsub validation mode (Strict/Permissive).
        /// Gossipsub-Validation Strict/Permissive
        pub strict_validation: bool,
        /// Optional: target multiaddr for actively dialing a peer.
        /// Optional: Ziel-Multiaddr zum aktiven Verbindungsaufbau
        pub dial: Option<String>,
        /// Enable peer scoring (default: true).
        /// Peer-Scoring aktivieren (Standard: true)
        pub enable_peer_scoring: bool,
        /// Optional: load a persistent identity keypair from a protobuf file.
        /// Optional: lade eine feste Identity (Protobuf-Datei)
        pub identity_key_file: Option<String>,
        /// Optional: creator_index -> expected PeerId mapping (JSON).
        /// Optional: creator_index -> erwarteter PeerId (JSON)
        pub creator_peer_map_file: Option<String>,
        /// Optional: maximale Anzahl gleichzeitiger Verbindungen pro IP.
        /// Optional: max simultaneous connections per IP
        pub max_peers_per_ip: Option<usize>,
        /// Bootstrap-Peers für Kademlia (Multiaddr inkl. /p2p/PeerId)
        pub bootstrap_peers: Vec<String>,
        /// Kademlia-Bootstrap-Intervall in Sekunden (0 = deaktiviert)
        pub kad_bootstrap_interval_secs: u64,
    }

    impl Default for Libp2pConfig {
        fn default() -> Self {
            Self {
                // Safer default: local-only; explicit config can bind publicly if needed.
                listen_on: Some("/ip4/127.0.0.1/tcp/0".to_string()),
                shards: None,
                strict_validation: true,
                dial: None,
                enable_peer_scoring: true,
                identity_key_file: None,
                creator_peer_map_file: None,
                max_peers_per_ip: None,
                bootstrap_peers: Vec::new(),
                kad_bootstrap_interval_secs: 60,
            }
        }
    }

    fn ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
        for p in addr.iter() {
            match p {
                Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
                Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
                _ => {}
            }
        }
        None
    }

    fn strip_p2p(mut addr: Multiaddr) -> Multiaddr {
        if let Some(Protocol::P2p(_)) = addr.iter().last() {
            let _ = addr.pop();
        }
        addr
    }

    fn peer_id_to_sockaddr(peer: &PeerId) -> SocketAddr {
        // libp2p does not expose a stable SocketAddr for peers (can have multiple addrs, NAT, etc.).
        // We derive a deterministic pseudo-address from PeerId so the service can apply per-peer RL.
        let pid = peer.to_bytes();
        let h = pc_crypto::blake3_32(&pid);
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&h[0..16]);
        // Force into unique-local range to avoid confusing logs.
        ip[0] = 0xfd;
        let port = u16::from_be_bytes([h[16], h[17]]);
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(ip)),
            if port == 0 { 1 } else { port },
        )
    }

    fn parse_bootstrap_peer(s: &str) -> Option<(PeerId, Multiaddr, Multiaddr)> {
        let addr: Multiaddr = s.parse().ok()?;
        let mut addr_no_peer = addr.clone();
        match addr_no_peer.pop() {
            Some(Protocol::P2p(peer_id)) => Some((peer_id, addr, addr_no_peer)),
            _ => None,
        }
    }

    fn load_identity_keypair(path: &str) -> Result<identity::Keypair, P2pError> {
        let bytes = std::fs::read(path).map_err(|_| P2pError::InvalidConfig)?;
        identity::Keypair::from_protobuf_encoding(&bytes).map_err(|_| P2pError::InvalidConfig)
    }

    fn load_creator_peer_map(path: &str) -> Result<HashMap<u8, PeerId>, P2pError> {
        let raw = std::fs::read_to_string(path).map_err(|_| P2pError::InvalidConfig)?;
        let map: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| P2pError::InvalidConfig)?;
        let obj = map.as_object().ok_or(P2pError::InvalidConfig)?;
        let mut out: HashMap<u8, PeerId> = HashMap::new();
        for (k, v) in obj.iter() {
            let idx: u8 = k.parse().map_err(|_| P2pError::InvalidConfig)?;
            let s = v.as_str().ok_or(P2pError::InvalidConfig)?;
            let pid: PeerId = s.parse().map_err(|_| P2pError::InvalidConfig)?;
            out.insert(idx, pid);
        }
        Ok(out)
    }

    // Default number of shards (S=64) for subscriptions if no specific shard list is provided.
    // Standardanzahl Shards (S=64) für Default-Subscription, falls keine spezifische Shardliste angegeben wurde
    const SHARDS_DEFAULT: u16 = 64;

    // RPC protocol and codec.
    // RPC-Protokoll & Codec
    #[derive(Clone, Default)]
    struct PcCodec;

    const MAX_LIBP2P_RPC_REQUEST_BYTES: usize = crate::messages::MAX_MSG_RPC_REQ_BYTES;
    const MAX_LIBP2P_RPC_RESPONSE_BYTES: usize = crate::messages::MAX_MSG_RPC_RESP_BYTES;

    #[derive(Clone, Debug)]
    struct TokenBucket {
        capacity: f64,
        tokens: f64,
        refill_per_sec: f64,
        last: Instant,
    }

    impl TokenBucket {
        fn new(capacity: u32, refill_per_sec: u32) -> Self {
            let cap = capacity.max(1) as f64;
            let refill = refill_per_sec.max(1) as f64;
            Self {
                capacity: cap,
                tokens: cap,
                refill_per_sec: refill,
                last: Instant::now(),
            }
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

    #[derive(Clone, Debug)]
    struct RpcPeerBudget {
        reqs: TokenBucket,
        bytes: TokenBucket,
        last_seen: Instant,
    }

    impl RpcPeerBudget {
        fn new(
            req_cap: u32,
            req_refill_per_sec: u32,
            bytes_cap: u32,
            bytes_refill_per_sec: u32,
        ) -> Self {
            Self {
                reqs: TokenBucket::new(req_cap, req_refill_per_sec),
                bytes: TokenBucket::new(bytes_cap, bytes_refill_per_sec),
                last_seen: Instant::now(),
            }
        }

        fn allow(&mut self, req_bytes: usize) -> bool {
            self.last_seen = Instant::now();
            self.reqs.allow_n(1) && self.bytes.allow_n(req_bytes)
        }
    }

    fn clamp_req(req: crate::messages::ReqMsg) -> crate::messages::ReqMsg {
        match req {
            crate::messages::ReqMsg::GetHeaders { mut ids } => {
                ids.truncate(crate::messages::MAX_HEADERS_IN_MSG);
                crate::messages::ReqMsg::GetHeaders { ids }
            }
            crate::messages::ReqMsg::GetPayloads { mut roots } => {
                roots.truncate(crate::messages::MAX_PAYLOADS_IN_MSG);
                crate::messages::ReqMsg::GetPayloads { roots }
            }
            crate::messages::ReqMsg::GetTx { mut ids } => {
                ids.truncate(crate::messages::MAX_TXS_IN_MSG);
                crate::messages::ReqMsg::GetTx { ids }
            }
            crate::messages::ReqMsg::GetEvidences { mut ids } => {
                ids.truncate(crate::messages::MAX_EVIDENCES_IN_MSG);
                crate::messages::ReqMsg::GetEvidences { ids }
            }
            crate::messages::ReqMsg::GetPeers { max_count } => crate::messages::ReqMsg::GetPeers {
                max_count: max_count.min(crate::messages::MAX_PEERS_IN_MSG as u16),
            },
        }
    }

    async fn read_limited<T>(io: &mut T, max_bytes: usize) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        const READ_CHUNK_TIMEOUT: Duration = Duration::from_secs(10);
        const READ_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let mut total: usize = 0;
        let start = Instant::now();
        loop {
            if start.elapsed() > READ_TOTAL_TIMEOUT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "rpc message read timeout",
                ));
            }
            let n = match tokio::time::timeout(READ_CHUNK_TIMEOUT, io.read(&mut tmp)).await {
                Ok(res) => res?,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc message read timeout",
                    ))
                }
            };
            if n == 0 {
                break;
            }
            total = total.saturating_add(n);
            if total > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rpc message too large",
                ));
            }
            if let Some(slice) = tmp.get(..n) {
                buf.extend_from_slice(slice);
            }
        }
        Ok(buf)
    }

    #[async_trait]
    impl rr::Codec for PcCodec {
        type Protocol = String;
        type Request = Vec<u8>;
        type Response = Vec<u8>;

        async fn read_request<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
        ) -> std::io::Result<Self::Request>
        where
            T: AsyncRead + Unpin + Send,
        {
            read_limited(io, MAX_LIBP2P_RPC_REQUEST_BYTES).await
        }

        async fn read_response<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
        ) -> std::io::Result<Self::Response>
        where
            T: AsyncRead + Unpin + Send,
        {
            read_limited(io, MAX_LIBP2P_RPC_RESPONSE_BYTES).await
        }

        async fn write_request<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
            req: Self::Request,
        ) -> std::io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            if req.len() > MAX_LIBP2P_RPC_REQUEST_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rpc request too large",
                ));
            }
            io.write_all(&req).await?;
            io.close().await
        }

        async fn write_response<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
            resp: Self::Response,
        ) -> std::io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            if resp.len() > MAX_LIBP2P_RPC_RESPONSE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rpc response too large",
                ));
            }
            io.write_all(&resp).await?;
            io.close().await
        }
    }

    #[derive(NetworkBehaviour)]
    struct Behaviour {
        gossipsub: gossipsub::Behaviour,
        rpc: rr::Behaviour<PcCodec>,
        kademlia: kad::Behaviour<MemoryStore>,
    }

    fn network_namespace(network_id: Option<[u8; 32]>) -> String {
        network_id
            .map(hex::encode)
            .unwrap_or_else(|| "default".to_string())
    }

    fn topic_for(namespace: &str, msg: &P2pMessage) -> gossipsub::IdentTopic {
        match msg {
            P2pMessage::PrevoteAnnounce(h) => {
                gossipsub::IdentTopic::new(format!("pc/{namespace}/shard/{}/prevote", h.shard_id))
            }
            P2pMessage::PrecommitAnnounce(h) => {
                gossipsub::IdentTopic::new(format!("pc/{namespace}/shard/{}/precommit", h.shard_id))
            }
            P2pMessage::HeadersInv { .. } => {
                gossipsub::IdentTopic::new(format!("pc/{namespace}/inv/headers"))
            }
            P2pMessage::PayloadInv { .. } => {
                gossipsub::IdentTopic::new(format!("pc/{namespace}/inv/payloads"))
            }
            P2pMessage::TxInv { .. } => {
                gossipsub::IdentTopic::new(format!("pc/{namespace}/inv/txs"))
            }
            P2pMessage::EvidenceInv { .. } => {
                gossipsub::IdentTopic::new(format!("pc/{namespace}/inv/evidences"))
            }
            // Legacy: peer gossip topic. We do not subscribe/publish peers lists anymore; peer
            // exchange is done via on-request RPC (ReqMsg::GetPeers / RespMsg::Peers).
            P2pMessage::Peers { .. } => gossipsub::IdentTopic::new(format!("pc/{namespace}/peers")),
            P2pMessage::Ping => gossipsub::IdentTopic::new(format!("pc/{namespace}/ping")),
            P2pMessage::Pong => gossipsub::IdentTopic::new(format!("pc/{namespace}/pong")),
            P2pMessage::Req(_) => gossipsub::IdentTopic::new(format!("pc/{namespace}/rpc/req")),
            P2pMessage::Resp(_) => gossipsub::IdentTopic::new(format!("pc/{namespace}/rpc/resp")),
        }
    }

    fn encode_msg(msg: &P2pMessage) -> Result<Vec<u8>, P2pError> {
        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf).map_err(|_| P2pError::InvalidConfig)?;
        crate::async_svc::record_outbound_bytes(buf.len());
        Ok(buf)
    }

    fn decode_msg(data: &[u8]) -> Option<P2pMessage> {
        crate::async_svc::record_inbound_bytes(data.len());
        let tag = *data.first()?;
        let cap = crate::messages::max_wire_bytes_for_tag(tag)?;
        if data.len() > cap {
            return None;
        }
        let mut slice = data;
        match P2pMessage::decode(&mut slice) {
            Ok(m) if slice.is_empty() => Some(m),
            _ => None, // decode error or trailing bytes → reject
        }
    }

    fn build_gossipsub(
        local_key: &identity::Keypair,
        strict: bool,
        enable_scoring: bool,
    ) -> Result<gossipsub::Behaviour, P2pError> {
        // Dedupe via stable message_id (hash of payload)
        let id_fn = |m: &gossipsub::Message| {
            let h = pc_crypto::blake3_32(&m.data);
            gossipsub::MessageId::from(hex::encode(h))
        };
        let hb = if crate::async_svc::is_bench_mode() {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        };
        let cfg = gossipsub::ConfigBuilder::default()
            .message_id_fn(id_fn)
            .validation_mode(if strict {
                ValidationMode::Strict
            } else {
                ValidationMode::Permissive
            })
            .heartbeat_interval(hb)
            .build()
            .map_err(|_e| P2pError::InvalidConfig)?;

        let mut behaviour =
            gossipsub::Behaviour::new(MessageAuthenticity::Signed(local_key.clone()), cfg)
                .map_err(|_e| P2pError::InvalidConfig)?;

        // Enable peer scoring when desired.
        // Peer-Scoring aktivieren wenn gewünscht
        if enable_scoring {
            let peer_score_params = gossipsub::PeerScoreParams {
                app_specific_weight: 1.0,
                behaviour_penalty_weight: -10.0,
                behaviour_penalty_threshold: 6.0,
                behaviour_penalty_decay: 0.99,
                ..gossipsub::PeerScoreParams::default()
            };

            let peer_score_thresholds = gossipsub::PeerScoreThresholds {
                gossip_threshold: -4000.0,
                publish_threshold: -8000.0,
                graylist_threshold: -16000.0,
                accept_px_threshold: 100.0,
                opportunistic_graft_threshold: 5.0,
            };

            behaviour
                .with_peer_score(peer_score_params, peer_score_thresholds)
                .map_err(|_e| P2pError::InvalidConfig)?;
        }

        Ok(behaviour)
    }

    pub fn start(
        svc: P2pService,
        mut out_rx: mpsc::Receiver<OutboundEnvelope>,
        cfg: Libp2pConfig,
        network_id: Option<[u8; 32]>,
        max_peers: usize,
        allow_peer_exchange: bool,
    ) -> Result<tokio::task::JoinHandle<()>, P2pError> {
        // Keys
        let id_keys = if let Some(path) = cfg.identity_key_file.as_deref() {
            load_identity_keypair(path)?
        } else {
            identity::Keypair::generate_ed25519()
        };
        let peer_id = PeerId::from(id_keys.public());

        let creator_peer_map: Option<HashMap<u8, PeerId>> =
            if let Some(p) = cfg.creator_peer_map_file.as_deref() {
                Some(load_creator_peer_map(p)?)
            } else {
                None
            };

        let namespace = network_namespace(network_id);

        // Transport: TCP + Noise + Yamux
        let noise_keys = noise::Config::new(&id_keys).map_err(|_e| P2pError::InvalidConfig)?;
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(libp2p::core::upgrade::Version::V1Lazy)
            .authenticate(noise_keys)
            .multiplex(yamux::Config::default())
            .boxed();

        // Behaviour
        let gossipsub = build_gossipsub(&id_keys, cfg.strict_validation, cfg.enable_peer_scoring)?;
        let mut kad_cfg = kad::Config::default();
        kad_cfg.set_query_timeout(Duration::from_secs(30));
        let store = MemoryStore::new(peer_id);
        let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_cfg);
        kademlia.set_mode(Some(kad::Mode::Server));
        let rr_cfg = rr::Config::default().with_request_timeout(Duration::from_secs(2));
        let rpc_protocol = format!("/pc/{namespace}/1/rpc");
        let rpc = rr::Behaviour::<PcCodec>::new(
            std::iter::once((rpc_protocol, rr::ProtocolSupport::Full)),
            rr_cfg,
        );
        let behaviour = Behaviour {
            gossipsub,
            rpc,
            kademlia,
        };
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        // Subscribe topics.
        let mut topics: Vec<gossipsub::IdentTopic> = Vec::new();
        // Base topics (INV/RPC).
        // Grundthemen (INV/RPC)
        topics.push(gossipsub::IdentTopic::new(format!(
            "pc/{namespace}/inv/headers"
        )));
        topics.push(gossipsub::IdentTopic::new(format!(
            "pc/{namespace}/inv/payloads"
        )));
        topics.push(gossipsub::IdentTopic::new(format!(
            "pc/{namespace}/inv/txs"
        )));
        topics.push(gossipsub::IdentTopic::new(format!(
            "pc/{namespace}/inv/evidences"
        )));
        topics.push(gossipsub::IdentTopic::new(format!("pc/{namespace}/ping")));
        topics.push(gossipsub::IdentTopic::new(format!("pc/{namespace}/pong")));
        // Shard-specific header announce topics.
        // Shard-spezifische Header-Announce-Themen
        match &cfg.shards {
            Some(v) => {
                for sid in v {
                    for suffix in ["prevote", "precommit"] {
                        topics.push(gossipsub::IdentTopic::new(format!(
                            "pc/{namespace}/shard/{}/{}",
                            sid, suffix
                        )));
                    }
                }
            }
            None => {
                // Default: subscribe to header announce topics for all shards (0..S-1).
                // Standard: explizite Prevotе-/Precommit-Themen für alle Shards (0..S-1) abonnieren
                // S=64 corresponds to the initial configuration (see consensus constants); kept here locally to avoid dependencies.
                // S=64 entspricht der Startkonfiguration (siehe Konsens-Konstanten); hier lokal gehalten, um Abhängigkeiten zu vermeiden.
                for sid in 0..SHARDS_DEFAULT {
                    for suffix in ["prevote", "precommit"] {
                        topics.push(gossipsub::IdentTopic::new(format!(
                            "pc/{namespace}/shard/{}/{}",
                            sid, suffix
                        )));
                    }
                }
            }
        }
        for t in topics {
            let _ = swarm.behaviour_mut().gossipsub.subscribe(&t);
        }

        // Listen.
        if let Some(ma) = cfg.listen_on.as_deref() {
            let addr: Multiaddr = ma.parse().map_err(|_| P2pError::InvalidConfig)?;
            Swarm::listen_on(&mut swarm, addr).map_err(|_| P2pError::InvalidConfig)?;
        }
        // Optional: actively dial a peer.
        // Optional: aktiv wählen
        if let Some(ma) = cfg.dial.as_deref() {
            if let Ok(addr) = ma.parse::<Multiaddr>() {
                debug!(target: "pc_p2p.lp2p", event = "dial", addr = %addr, "libp2p dial initiated");
                let _ = Swarm::dial(&mut swarm, addr);
            }
        }

        let mut bootstrap_addrs: Vec<Multiaddr> = Vec::new();
        for raw in cfg.bootstrap_peers.iter() {
            match parse_bootstrap_peer(raw) {
                Some((peer_id, addr, addr_no_peer)) => {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr_no_peer);
                    bootstrap_addrs.push(addr);
                }
                None => {
                    debug!(target: "pc_p2p.lp2p", event = "kad_bootstrap_invalid", peer = %raw, "invalid bootstrap multiaddr");
                }
            }
        }
        if !bootstrap_addrs.is_empty() {
            for addr in bootstrap_addrs {
                let _ = Swarm::dial(&mut swarm, addr);
            }
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        // Peer management and RPC retry state.
        // Peer-Verwaltung & RPC-Retry State
        let mut peers: Vec<PeerId> = Vec::new();
        let max_peers_per_ip = cfg.max_peers_per_ip;
        let mut peers_per_ip: HashMap<IpAddr, usize> = HashMap::new();
        let mut peer_ip: HashMap<PeerId, IpAddr> = HashMap::new();
        let mut peer_conn_counts: HashMap<PeerId, usize> = HashMap::new();
        let blocked_peers_path = blocked_peers_path(&cfg);
        let mut blocked_peers: HashMap<PeerId, u64> = blocked_peers_path
            .as_deref()
            .map(load_blocked_peers)
            .unwrap_or_default();
        let mut rr_rr_idx: usize = 0;
        let mut pending: HashMap<rr::OutboundRequestId, (Vec<u8>, u8, Instant)> = HashMap::new(); // (req_bytes, attempts, start)
        let mut pending_no_peer: Vec<(Vec<u8>, Instant)> = Vec::new(); // (req_bytes, start)
        const PENDING_REQ_TTL: Duration = Duration::from_secs(30);
        let mut pending_gc = interval(Duration::from_secs(5));
        let mut blocked_peers_gc = interval(Duration::from_secs(60));
        let kad_bootstrap_enabled = cfg.kad_bootstrap_interval_secs > 0;
        let mut kad_bootstrap =
            interval(Duration::from_secs(cfg.kad_bootstrap_interval_secs.max(1)));

        // Inbound RPC hardening: bound concurrency and apply lightweight rate limits.
        // Inbound-RPC Härtung: Concurrency begrenzen + leichte Rate-Limits.
        const INBOUND_RPC_MAX_IN_FLIGHT: usize = 64;
        const INBOUND_RPC_PEER_MAP_MAX: usize = 4096;
        const INBOUND_RPC_GLOBAL_REQ_CAP: u32 = 200;
        const INBOUND_RPC_GLOBAL_REQ_REFILL_PER_SEC: u32 = 200;
        const INBOUND_RPC_GLOBAL_BYTES_CAP: u32 =
            (crate::messages::MAX_MSG_RPC_REQ_BYTES as u32) * 32; // ~4MB burst
        const INBOUND_RPC_GLOBAL_BYTES_REFILL_PER_SEC: u32 = INBOUND_RPC_GLOBAL_BYTES_CAP;
        const INBOUND_RPC_PEER_REQ_CAP: u32 = 25;
        const INBOUND_RPC_PEER_REQ_REFILL_PER_SEC: u32 = 25;
        const INBOUND_RPC_PEER_BYTES_CAP: u32 = (crate::messages::MAX_MSG_RPC_REQ_BYTES as u32) * 2; // ~256KB burst
        const INBOUND_RPC_PEER_BYTES_REFILL_PER_SEC: u32 = INBOUND_RPC_PEER_BYTES_CAP;
        let inbound_rpc_sema = Arc::new(Semaphore::new(INBOUND_RPC_MAX_IN_FLIGHT));
        let (inbound_rpc_resp_tx, mut inbound_rpc_resp_rx) =
            mpsc::channel::<(rr::ResponseChannel<Vec<u8>>, Vec<u8>)>(INBOUND_RPC_MAX_IN_FLIGHT);

        let handle = tokio::spawn(async move {
            let mut inbound_rpc_global_req = TokenBucket::new(
                INBOUND_RPC_GLOBAL_REQ_CAP,
                INBOUND_RPC_GLOBAL_REQ_REFILL_PER_SEC,
            );
            let mut inbound_rpc_global_bytes = TokenBucket::new(
                INBOUND_RPC_GLOBAL_BYTES_CAP,
                INBOUND_RPC_GLOBAL_BYTES_REFILL_PER_SEC,
            );
            let mut inbound_rpc_per_peer: HashMap<PeerId, RpcPeerBudget> = HashMap::new();
            loop {
                select! {
                        // RPC responses from worker tasks → send via request_response.
                        maybe_rpc_resp = inbound_rpc_resp_rx.recv() => {
                            match maybe_rpc_resp {
                                Some((channel, buf)) => {
                                    crate::async_svc::record_outbound_bytes(buf.len());
                                    let _ = swarm.behaviour_mut().rpc.send_response(channel, buf);
                                }
                                None => break,
                            }
                        }
                        // Outgoing from service → publish / request.
                        maybe_msg = out_rx.recv() => {
                            if let Some(env) = maybe_msg {
                                crate::async_svc::outbox_deq_inc();
                            let (target_peer, msg) = env.into_parts();
                            if target_peer.is_some() {
                                debug!(target: "pc_p2p.lp2p", event = "drop_direct_outbound", "direct outbound envelope is not supported on libp2p transport");
                                continue;
                            }
                            match msg {
                                P2pMessage::Req(req) => {
                                    // Nur ReqMsg encodieren (nicht P2pMessage::Req)
                                    let mut buf = Vec::new();
                                    if req.encode(&mut buf).is_ok() {
                                        if peers.is_empty() {
                                            let start = Instant::now();
                                            debug!(target: "pc_p2p.lp2p", event = "rr_queue", reason = "no_peer", req_bytes = buf.len(), kind = %match &req { crate::messages::ReqMsg::GetHeaders{..} => "get_headers", crate::messages::ReqMsg::GetPayloads{..} => "get_payloads", crate::messages::ReqMsg::GetTx{..} => "get_tx", crate::messages::ReqMsg::GetPeers{..} => "get_peers", crate::messages::ReqMsg::GetEvidences{..} => "get_evidences" }, "queue request until peer available");
                                            pending_no_peer.push((buf, start));
                                        } else {
                                            rr_rr_idx = rr_rr_idx.wrapping_add(1);
                                            let idx = rr_rr_idx % peers.len();
                                            if let Some(peer) = peers.get(idx).cloned() {
                                                crate::async_svc::record_outbound_bytes(buf.len());
                                                let id = swarm.behaviour_mut().rpc.send_request(&peer, buf.clone());
                                                let start = Instant::now();
                                                let kind = match &req { crate::messages::ReqMsg::GetHeaders { ids } => { ids.len() as u64 }, _ => 0 };
                                                debug!(target: "pc_p2p.lp2p", event = "rr_send", peer = %peer, req_bytes = buf.len(), kind = %match &req { crate::messages::ReqMsg::GetHeaders{..} => "get_headers", crate::messages::ReqMsg::GetPayloads{..} => "get_payloads", crate::messages::ReqMsg::GetTx{..} => "get_tx", crate::messages::ReqMsg::GetPeers{..} => "get_peers", crate::messages::ReqMsg::GetEvidences{..} => "get_evidences" }, count = kind, "request_response send_request issued");
                                                pending.insert(id, (buf, 1, start));
                                            }
                                        }
                                    }
                                }
                                P2pMessage::Resp(_) => {
                                    // Responses are not sent via gossip; handled by request-response.
                                    // Responses werden nicht via Gossip gesendet; handled durch Request-Response
                                }
                                    P2pMessage::Peers { .. } => {
                                        // On-request PEX only: do not gossip peers lists.
                                    }
                                    other => {
                                        let topic = topic_for(&namespace, &other);
                                        if let Ok(data) = encode_msg(&other) {
                                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
                                            match &other {
                                            P2pMessage::HeadersInv { ids } => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "headers_inv", count = ids.len(), "published headers_inv");
                                            }
                                            P2pMessage::PayloadInv { roots } => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "payload_inv", count = roots.len(), "published payload_inv");
                                            }
                                                P2pMessage::EvidenceInv { ids } => {
                                                    debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "evidence_inv", count = ids.len(), "published evidence_inv");
                                                }
                                                P2pMessage::PrevoteAnnounce(h) => {
                                                    debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "prevote_announce", shard = h.shard_id, "published prevote_announce");
                                                }
                                                P2pMessage::PrecommitAnnounce(h) => {
                                                    debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "precommit_announce", shard = h.shard_id, "published precommit_announce");
                                                }
                                                _ => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "other", "published other message");
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    // Kademlia periodic bootstrap
                    _ = kad_bootstrap.tick(), if kad_bootstrap_enabled => {
                        if let Ok(qid) = swarm.behaviour_mut().kademlia.bootstrap() {
                            debug!(target: "pc_p2p.lp2p", event = "kad_bootstrap", query_id = ?qid, "kademlia bootstrap");
                        }
                    }
                    _ = pending_gc.tick() => {
                        let before_pending = pending.len();
                        pending.retain(|_, (_, _, start)| start.elapsed() < PENDING_REQ_TTL);
                        let before_no_peer = pending_no_peer.len();
                        pending_no_peer.retain(|(_, start)| start.elapsed() < PENDING_REQ_TTL);
                        let dropped_pending = before_pending.saturating_sub(pending.len());
                        let dropped_no_peer = before_no_peer.saturating_sub(pending_no_peer.len());
                        if dropped_pending > 0 || dropped_no_peer > 0 {
                            debug!(
                                target: "pc_p2p.lp2p",
                                event = "rr_pending_gc",
                                dropped_pending,
                                dropped_no_peer,
                                "dropped expired pending rpc requests"
                            );
                        }
                    }
                    _ = blocked_peers_gc.tick() => {
                        let now = now_epoch_secs();
                        if prune_blocked_peers(&mut blocked_peers, now) {
                            if let Some(path) = blocked_peers_path.as_deref() {
                                save_blocked_peers(path, &blocked_peers);
                            }
                        }
                    }
                    // Inbound from swarm → forward to service
                    ev = swarm.select_next_some() => {
                        match ev {
                            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message{ propagation_source, message, .. })) => {
                                let now = now_epoch_secs();
                                if peer_is_blocked(&mut blocked_peers, &propagation_source, now) {
                                    debug!(target: "pc_p2p.lp2p", event = "a8_drop_msg", peer = %propagation_source, "drop message from blocked peer");
                                    continue;
                                }
                                    if let Some(decoded) = decode_msg(&message.data) {
                                        if let (Some(map), Some(h)) = (creator_peer_map.as_ref(), messages::announced_header(&decoded)) {
                                            if let Some(expected) = map.get(&h.creator_index) {
                                                if expected != &propagation_source {
                                                    debug!(target: "pc_p2p.lp2p", event = "a9_drop_header", creator_index = h.creator_index, expected = %expected, got = %propagation_source, "drop spoofed header announce");
                                                    continue;
                                                }
                                            } else {
                                                debug!(target: "pc_p2p.lp2p", event = "a9_drop_header", creator_index = h.creator_index, got = %propagation_source, "drop header announce: creator_index not in map");
                                                continue;
                                            }
                                        }
                                        if let P2pMessage::Peers { peers } = &decoded {
                                            // On-request PEX only: drop gossiped peer lists at the edge.
                                            debug!(target: "pc_p2p.lp2p", event = "drop_peers_gossip", peer = %propagation_source, count = peers.len(), "drop gossipsub peers (use GetPeers RPC)");
                                            continue;
                                        }
                                        if matches!(&decoded, P2pMessage::Req(_) | P2pMessage::Resp(_)) {
                                            debug!(target: "pc_p2p.lp2p", event = "drop_rpc_gossip", peer = %propagation_source, "drop gossiped rpc message");
                                            continue;
                                        }
                                        match &decoded {
                                            P2pMessage::HeadersInv { ids } => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "headers_inv", count = ids.len(), "gossipsub inbound headers_inv");
                                            }
                                        P2pMessage::PayloadInv { roots } => {
                                            debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "payload_inv", count = roots.len(), "gossipsub inbound payload_inv");
                                        }
                                            P2pMessage::EvidenceInv { ids } => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "evidence_inv", count = ids.len(), "gossipsub inbound evidence_inv");
                                            }
                                            P2pMessage::PrevoteAnnounce(h) => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "prevote_announce", shard = h.shard_id, "gossipsub inbound prevote_announce");
                                            }
                                            P2pMessage::PrecommitAnnounce(h) => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "precommit_announce", shard = h.shard_id, "gossipsub inbound precommit_announce");
                                            }
                                            _ => {}
                                    }
                                    // Peer-SocketAddr ist hier nicht verfügbar → generisch einspeisen
                                    let peer_addr = peer_id_to_sockaddr(&propagation_source);
                                    let _ = svc.send_message_from(peer_addr, decoded).await;
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Rpc(ev)) => {
                                match ev {
                                    rr::Event::Message { peer, message, .. } => {
                                        let now = now_epoch_secs();
                                        if peer_is_blocked(&mut blocked_peers, &peer, now) {
                                            debug!(target: "pc_p2p.lp2p", event = "a8_drop_rpc", peer = %peer, "drop rpc from blocked peer");
                                            continue;
                                        }
                                            match message {
                                                rr::Message::Request { request, channel, .. } => {
                                                    let req_bytes = request.len();
                                                    crate::async_svc::record_inbound_bytes(req_bytes);

                                                    // Apply cheap limits in the swarm loop; do decode/DB work off-thread.
                                                    if !inbound_rpc_global_req.allow_n(1)
                                                        || !inbound_rpc_global_bytes.allow_n(req_bytes)
                                                    {
                                                        debug!(target: "pc_p2p.lp2p", event = "rr_drop_req", peer = %peer, reason = "global_rate", req_bytes = req_bytes, "drop inbound rpc request (global rate limit)");
                                                        continue;
                                                    }

                                                    if inbound_rpc_per_peer.len() >= INBOUND_RPC_PEER_MAP_MAX
                                                        && !inbound_rpc_per_peer.contains_key(&peer)
                                                    {
                                                        debug!(target: "pc_p2p.lp2p", event = "rr_drop_req", peer = %peer, reason = "peer_map_full", req_bytes = req_bytes, "drop inbound rpc request (peer limiter map full)");
                                                        continue;
                                                    }
                                                    let budget = inbound_rpc_per_peer.entry(peer).or_insert_with(|| {
                                                        RpcPeerBudget::new(
                                                            INBOUND_RPC_PEER_REQ_CAP,
                                                            INBOUND_RPC_PEER_REQ_REFILL_PER_SEC,
                                                            INBOUND_RPC_PEER_BYTES_CAP,
                                                            INBOUND_RPC_PEER_BYTES_REFILL_PER_SEC,
                                                        )
                                                    });
                                                    if !budget.allow(req_bytes) {
                                                        debug!(target: "pc_p2p.lp2p", event = "rr_drop_req", peer = %peer, reason = "peer_rate", req_bytes = req_bytes, "drop inbound rpc request (per-peer rate limit)");
                                                        continue;
                                                    }

                                                    let permit = match inbound_rpc_sema.clone().try_acquire_owned() {
                                                        Ok(p) => p,
                                                        Err(_) => {
                                                            debug!(target: "pc_p2p.lp2p", event = "rr_drop_req", peer = %peer, reason = "in_flight", req_bytes = req_bytes, "drop inbound rpc request (too many in flight)");
                                                            continue;
                                                        }
                                                    };
                                                    let svc2 = svc.clone();
                                                    let tx2 = inbound_rpc_resp_tx.clone();
                                                    tokio::spawn(async move {
                                                        let _permit = permit;
                                                        let mut slice = &request[..];
                                                        let req_opt = match crate::messages::ReqMsg::decode(&mut slice) {
                                                            Ok(r) if slice.is_empty() => Some(r),
                                                            _ => None, // decode error or trailing bytes → reject
                                                        };
                                                        let Some(req) = req_opt else {
                                                            return;
                                                        };
                                                        let req = clamp_req(req);
                                                        if !allow_peer_exchange && matches!(&req, ReqMsg::GetPeers { .. }) {
                                                            return;
                                                        }
                                                        if let Ok(resp) = tokio::time::timeout(Duration::from_secs(2), svc2.rpc_call(req))
                                                            .await
                                                            .unwrap_or(Err(crate::P2pError::ChannelClosed))
                                                        {
                                                            let mut buf = Vec::new();
                                                            if resp.encode(&mut buf).is_ok() {
                                                                let _ = tx2.send((channel, buf)).await;
                                                            }
                                                        }
                                                    });
                                                }
                                            rr::Message::Response { request_id, response } => {
                                                crate::async_svc::record_inbound_bytes(response.len());
                                                // Response to our outbound RPC request.
                                                // Antwort auf unsere ausgehende RPC-Anfrage
                                                if let Some((_bytes, _att, start)) = pending.remove(&request_id) {
                                                    let rtt = start.elapsed();
                                                    debug!(target: "pc_p2p.lp2p", event = "rr_resp", rtt_ms = %format!("{:.3}", rtt.as_secs_f64()*1000.0), "rpc response received");
                                                }
                                                let mut slice = &response[..];
                                                let resp_opt = match crate::messages::RespMsg::decode(&mut slice) {
                                                    Ok(r) if slice.is_empty() => Some(r),
                                                    _ => None, // decode error or trailing bytes → reject
                                                };
                                                if let Some(resp) = resp_opt {
                                                    let peer_addr = peer_id_to_sockaddr(&peer);
                                                    let _ = svc
                                                        .send_message_from(peer_addr, crate::messages::P2pMessage::Resp(resp))
                                                        .await;
                                                }
                                            }
                                        }
                                    }
                                    rr::Event::OutboundFailure { request_id, .. } => {
                                        // Metrics: record outbound error.
                                        // Metriken: Outbound-Fehler registrieren
                                        crate::async_svc::out_error_inc();
                                        // Simple retry on another peer (max 2 attempts).
                                        // Einfacher Retry auf anderen Peer (max 2 Versuche)
                                        if let Some((bytes, att, _start_old)) = pending.remove(&request_id) {
                                            if (att as u32) < 2 && !peers.is_empty() {
                                                rr_rr_idx = rr_rr_idx.wrapping_add(1);
                                                let idx = rr_rr_idx % peers.len();
                                                if let Some(peer2) = peers.get(idx).cloned() {
                                                    crate::async_svc::record_outbound_bytes(bytes.len());
                                                    let id2 = swarm.behaviour_mut().rpc.send_request(&peer2, bytes.clone());
                                                    let start = Instant::now();
                                                    debug!(target: "pc_p2p.lp2p", event = "rr_retry", peer = %peer2, attempts = att + 1, "rpc outbound retry");
                                                    pending.insert(id2, (bytes, att + 1, start));
                                                }
                                            }
                                        }
                                    }
                                    rr::Event::InboundFailure { .. } => { /* ignore */ }
                                    rr::Event::ResponseSent { .. } => { /* ignore */ }
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(ev)) => {
                                debug!(target: "pc_p2p.lp2p", event = "kad", ?ev, "kademlia event");
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                                let now = now_epoch_secs();
                                if peer_is_blocked(&mut blocked_peers, &peer_id, now) {
                                    debug!(target: "pc_p2p.lp2p", event = "a8_drop_peer", peer = %peer_id, "peer is blocked; disconnect");
                                    let _ = swarm.disconnect_peer_id(peer_id);
                                    continue;
                                }

                                let cnt = peer_conn_counts.entry(peer_id).or_insert(0);
                                *cnt = cnt.saturating_add(1);

                                if *cnt == 1 {
                                    if peers.len() >= max_peers.max(1) {
                                        debug!(target: "pc_p2p.lp2p", event = "drop_peer_max_peers", peer = %peer_id, max_peers = max_peers as u64, "peer limit reached; disconnect");
                                        let _ = swarm.disconnect_peer_id(peer_id);
                                        continue;
                                    }
                                    if let (Some(limit), Some(ip)) = (max_peers_per_ip, match &endpoint {
                                        ConnectedPoint::Dialer { address, .. } => ip_from_multiaddr(address),
                                        ConnectedPoint::Listener { send_back_addr, .. } => ip_from_multiaddr(send_back_addr),
                                    }) {
                                        let cur = *peers_per_ip.get(&ip).unwrap_or(&0);
                                        if cur >= limit {
                                            let now = now_epoch_secs();
                                            let _ = prune_blocked_peers(&mut blocked_peers, now);
                                            blocked_peers.insert(peer_id, now.saturating_add(BLOCKED_PEERS_TTL_SECS));
                                            if let Some(path) = blocked_peers_path.as_deref() {
                                                save_blocked_peers(path, &blocked_peers);
                                            }
                                            debug!(target: "pc_p2p.lp2p", event = "a8_drop_peer", peer = %peer_id, ip = %ip, limit = limit as u64, "too many peers from same ip; disconnect");
                                            let _ = swarm.disconnect_peer_id(peer_id);
                                            continue;
                                        }
                                        peers_per_ip.insert(ip, cur + 1);
                                        peer_ip.insert(peer_id, ip);
                                    }

                                    let addr_for_kad = match &endpoint {
                                        ConnectedPoint::Dialer { address, .. } => Some(address.clone()),
                                        ConnectedPoint::Listener { send_back_addr, .. } => Some(send_back_addr.clone()),
                                    };
                                    if let Some(addr) = addr_for_kad {
                                        let addr = strip_p2p(addr);
                                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                    }

                                    if !peers.contains(&peer_id) {
                                        debug!(target: "pc_p2p.lp2p", event = "peer_up", peer = %peer_id, "peer connected");
                                        peers.push(peer_id);
                                        // Flush queued requests, falls vorhanden
                                        if !pending_no_peer.is_empty() {
                                            let queued = pending_no_peer.len();
                                            for (buf, _start_old) in pending_no_peer.drain(..) {
                                                let id = swarm.behaviour_mut().rpc.send_request(&peer_id, buf.clone());
                                                let start = Instant::now();
                                                debug!(target: "pc_p2p.lp2p", event = "rr_send_queued", peer = %peer_id, req_bytes = buf.len(), queued = queued, "flushed queued request after connect");
                                                pending.insert(id, (buf, 1, start));
                                            }
                                        }
                                    }
                                }
                            }
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                let remove_peer_fully = match peer_conn_counts.get_mut(&peer_id) {
                                    Some(v) => {
                                        *v = v.saturating_sub(1);
                                        *v == 0
                                    }
                                    None => true,
                                };
                                    if remove_peer_fully {
                                        peer_conn_counts.remove(&peer_id);

                                        if let Some(ip) = peer_ip.remove(&peer_id) {
                                            if let Some(v) = peers_per_ip.get_mut(&ip) {
                                            *v = v.saturating_sub(1);
                                            if *v == 0 {
                                                peers_per_ip.remove(&ip);
                                            }
                                            }
                                        }
                                        inbound_rpc_per_peer.remove(&peer_id);
                                        if let Some(pos) = peers.iter().position(|p| *p == peer_id) {
                                            debug!(target: "pc_p2p.lp2p", event = "peer_down", peer = %peer_id, "peer disconnected");
                                            peers.remove(pos);
                                        }
                                    }
                            }
                            SwarmEvent::NewListenAddr { .. } => { /* ignore */ }
                            _ => { /* ignore others */ }
                        }
                    }
                }
            }
        });
        Ok(handle)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use libp2p::PeerId;
        use std::collections::HashMap;

        #[test]
        fn f61_pending_requests_have_ttl_cleanup() -> std::io::Result<()> {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("libp2p_node.rs");
            let src = std::fs::read_to_string(&path)?;
            assert!(
                src.contains("const PENDING_REQ_TTL: Duration = Duration::from_secs(30);"),
                "expected a normative pending TTL constant"
            );
            assert!(
                src.contains(
                    "pending.retain(|_, (_, _, start)| start.elapsed() < PENDING_REQ_TTL);"
                ),
                "expected pending.retain TTL cleanup"
            );
            assert!(
                src.contains(
                    "pending_no_peer.retain(|(_, start)| start.elapsed() < PENDING_REQ_TTL);"
                ),
                "expected pending_no_peer.retain TTL cleanup"
            );
            Ok(())
        }

        #[test]
        fn blocked_peers_persist_roundtrip_and_expiry() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("blocked_peers.json");

            let peer_ok = PeerId::random();
            let peer_expired = PeerId::random();
            let now = now_epoch_secs();

            let mut m: HashMap<PeerId, u64> = HashMap::new();
            m.insert(peer_ok, now.saturating_add(60));
            m.insert(peer_expired, now.saturating_sub(1));

            save_blocked_peers(&path, &m);
            let loaded = load_blocked_peers(&path);

            assert!(loaded.get(&peer_ok).copied().unwrap_or(0) > now);
            assert!(!loaded.contains_key(&peer_expired));
        }
    }
}
