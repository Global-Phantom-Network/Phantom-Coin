// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::result_large_err)]

#[cfg(all(feature = "async", feature = "libp2p"))]
pub mod node {
    use crate::async_svc::P2pService;
    use crate::messages::P2pMessage;
    use crate::P2pError;
    use libp2p::futures::StreamExt;
    use libp2p::Transport;
    use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
    use libp2p::request_response as rr;
    use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
    use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, Swarm};
    use pc_codec::{Decodable, Encodable};
    use tracing::debug;

    use std::time::{Duration, Instant};
    use tokio::select;
    use tokio::sync::mpsc;
    use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use std::collections::HashMap;
    use async_trait::async_trait;


    #[derive(Clone, Debug)]
    pub struct Libp2pConfig {
        /// Optional: Listen-Multiaddr, z. B. "/ip4/0.0.0.0/tcp/0"
        pub listen_on: Option<String>,
        /// Shards, die gezielt abonniert werden. None => alle Topics
        pub shards: Option<Vec<u8>>,
        /// Gossipsub-Validation Strict/Permissive
        pub strict_validation: bool,
        /// Optional: Ziel-Multiaddr zum aktiven Verbindungsaufbau
        pub dial: Option<String>,
    }

    impl Default for Libp2pConfig {
        fn default() -> Self {
            Self {
                listen_on: Some("/ip4/0.0.0.0/tcp/0".to_string()),
                shards: None,
                strict_validation: true,
                dial: None,
            }
        }
    }

    // Standardanzahl Shards (S=64) für Default-Subscription, falls keine spezifische Shardliste angegeben wurde
    const SHARDS_DEFAULT: u16 = 64;

    // RPC-Protokoll & Codec
    #[derive(Clone, Default)]
    struct PcCodec;
    #[async_trait]
    impl rr::Codec for PcCodec {
        type Protocol = String;
        type Request = Vec<u8>;
        type Response = Vec<u8>;

        async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Request>
        where T: AsyncRead + Unpin + Send {
            let mut buf = Vec::new();
            io.read_to_end(&mut buf).await?;
            Ok(buf)
        }

        async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> std::io::Result<Self::Response>
        where T: AsyncRead + Unpin + Send {
            let mut buf = Vec::new();
            io.read_to_end(&mut buf).await?;
            Ok(buf)
        }

        async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
        where T: AsyncWrite + Unpin + Send {
            io.write_all(&req).await?;
            io.close().await
        }

        async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, resp: Self::Response) -> std::io::Result<()>
        where T: AsyncWrite + Unpin + Send {
            io.write_all(&resp).await?;
            io.close().await
        }
    }

    #[derive(NetworkBehaviour)]
    struct Behaviour {
        gossipsub: gossipsub::Behaviour,
        rpc: rr::Behaviour<PcCodec>,
    }

    fn topic_for(msg: &P2pMessage) -> gossipsub::IdentTopic {
        match msg {
            P2pMessage::HeaderAnnounce(h) => {
                gossipsub::IdentTopic::new(format!("pc/shard/{}/header", h.shard_id))
            }
            P2pMessage::HeadersInv { .. } => gossipsub::IdentTopic::new("pc/inv/headers"),
            P2pMessage::PayloadInv { .. } => gossipsub::IdentTopic::new("pc/inv/payloads"),
            P2pMessage::TxInv { .. } => gossipsub::IdentTopic::new("pc/inv/txs"),
            P2pMessage::Req(_) => gossipsub::IdentTopic::new("pc/rpc/req"),
            P2pMessage::Resp(_) => gossipsub::IdentTopic::new("pc/rpc/resp"),
        }
    }

    fn encode_msg(msg: &P2pMessage) -> Result<Vec<u8>, P2pError> {
        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf).map_err(|_| P2pError::InvalidConfig)?;
        Ok(buf)
    }

    fn decode_msg(data: &[u8]) -> Option<P2pMessage> {
        let mut slice = data;
        P2pMessage::decode(&mut slice).ok()
    }

    fn build_gossipsub(local_key: &identity::Keypair, strict: bool) -> gossipsub::Behaviour {
        // Dedupe via stable message_id (hash of payload)
        let id_fn = |m: &gossipsub::Message| {
            let h = pc_crypto::blake3_32(&m.data);
            gossipsub::MessageId::from(hex::encode(h))
        };
        let hb = if crate::async_svc::is_bench_mode() { Duration::from_millis(100) } else { Duration::from_secs(1) };
        let cfg = gossipsub::ConfigBuilder::default()
            .message_id_fn(id_fn)
            .validation_mode(if strict {
                ValidationMode::Strict
            } else {
                ValidationMode::Permissive
            })
            .heartbeat_interval(hb)
            .build()
            .expect("valid gossipsub config");
        // Backpressure-Hinweis: geringe max_transmit_size belassen, Heartbeat 1s
        gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key.clone()),
            cfg,
        )
        .expect("gossipsub")
    }

    pub fn start(
        svc: P2pService,
        mut out_rx: mpsc::Receiver<P2pMessage>,
        cfg: Libp2pConfig,
    ) -> Result<tokio::task::JoinHandle<()>, P2pError> {
        // Keys
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(id_keys.public());

        // Transport: TCP + Noise + Yamux
        let noise_keys = noise::Config::new(&id_keys).expect("noise");
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(libp2p::core::upgrade::Version::V1Lazy)
            .authenticate(noise_keys)
            .multiplex(yamux::Config::default())
            .boxed();

        // Behaviour
        let gossipsub = build_gossipsub(&id_keys, cfg.strict_validation);
        let rr_cfg = rr::Config::default().with_request_timeout(Duration::from_secs(2));
        let rpc = rr::Behaviour::<PcCodec>::new(
            std::iter::once(("/pc/1/rpc".to_string(), rr::ProtocolSupport::Full)),
            rr_cfg,
        );
        let behaviour = Behaviour { gossipsub, rpc };
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        // Subscribe topics
        let mut topics: Vec<gossipsub::IdentTopic> = Vec::new();
        // Grundthemen (INV/RPC)
        topics.push(gossipsub::IdentTopic::new("pc/inv/headers"));
        topics.push(gossipsub::IdentTopic::new("pc/inv/payloads"));
        topics.push(gossipsub::IdentTopic::new("pc/inv/txs"));
        topics.push(gossipsub::IdentTopic::new("pc/rpc/req"));
        topics.push(gossipsub::IdentTopic::new("pc/rpc/resp"));
        // Shard-spezifische Header-Announce-Themen
        match &cfg.shards {
            Some(v) => {
                for sid in v {
                    topics.push(gossipsub::IdentTopic::new(format!(
                        "pc/shard/{}/header",
                        sid
                    )));
                }
            }
            None => {
                // Standard: Header-Announce-Themen für alle Shards (0..S-1) abonnieren
                // S=64 entspricht der Startkonfiguration (siehe Konsens-Konstanten); hier lokal gehalten, um Abhängigkeiten zu vermeiden.
                for sid in 0..SHARDS_DEFAULT {
                    topics.push(gossipsub::IdentTopic::new(format!("pc/shard/{}/header", sid)));
                }
            }
        }
        for t in topics {
            let _ = swarm.behaviour_mut().gossipsub.subscribe(&t);
        }

        // Listen
        if let Some(ma) = cfg.listen_on.as_deref() {
            let addr: Multiaddr = ma.parse().map_err(|_| P2pError::InvalidConfig)?;
            Swarm::listen_on(&mut swarm, addr).map_err(|_| P2pError::InvalidConfig)?;
        }
        // Optional: aktiv wählen
        if let Some(ma) = cfg.dial.as_deref() {
            if let Ok(addr) = ma.parse::<Multiaddr>() {
                debug!(target: "pc_p2p.lp2p", event = "dial", addr = %addr, "libp2p dial initiated");
                let _ = Swarm::dial(&mut swarm, addr);
            }
        }

        // Peer-Verwaltung & RPC-Retry State
        let mut peers: Vec<PeerId> = Vec::new();
        let mut rr_rr_idx: usize = 0;
        let mut pending: HashMap<rr::OutboundRequestId, (Vec<u8>, u8, Instant)> = HashMap::new(); // (req_bytes, attempts, start)
        let mut pending_no_peer: Vec<(Vec<u8>, Instant)> = Vec::new(); // (req_bytes, start)

        let handle = tokio::spawn(async move {
            loop {
                select! {
                    // Outgoing from service → publish / request
                    maybe_msg = out_rx.recv() => {
                        if let Some(msg) = maybe_msg {
                            crate::async_svc::outbox_deq_inc();
                            match msg {
                                P2pMessage::Req(req) => {
                                    // Nur ReqMsg encodieren (nicht P2pMessage::Req)
                                    let mut buf = Vec::new();
                                    if req.encode(&mut buf).is_ok() {
                                        if peers.is_empty() {
                                            let start = Instant::now();
                                            debug!(target: "pc_p2p.lp2p", event = "rr_queue", reason = "no_peer", req_bytes = buf.len(), kind = %match &req { crate::messages::ReqMsg::GetHeaders{..} => "get_headers", crate::messages::ReqMsg::GetPayloads{..} => "get_payloads", crate::messages::ReqMsg::GetTx{..} => "get_tx" }, "queue request until peer available");
                                            pending_no_peer.push((buf, start));
                                        } else {
                                            rr_rr_idx = rr_rr_idx.wrapping_add(1);
                                            let idx = rr_rr_idx % peers.len();
                                            let peer = peers[idx];
                                            let id = swarm.behaviour_mut().rpc.send_request(&peer, buf.clone());
                                            let start = Instant::now();
                                            let kind = match &req { crate::messages::ReqMsg::GetHeaders { ids } => { ids.len() as u64 }, _ => 0 };
                                            debug!(target: "pc_p2p.lp2p", event = "rr_send", peer = %peer, req_bytes = buf.len(), kind = %match &req { crate::messages::ReqMsg::GetHeaders{..} => "get_headers", crate::messages::ReqMsg::GetPayloads{..} => "get_payloads", crate::messages::ReqMsg::GetTx{..} => "get_tx" }, count = kind, "request_response send_request issued");
                                            pending.insert(id, (buf, 1, start));
                                        }
                                    }
                                }
                                P2pMessage::Resp(_) => {
                                    // Responses werden nicht via Gossip gesendet; handled durch Request-Response
                                }
                                other => {
                                    let topic = topic_for(&other);
                                    if let Ok(data) = encode_msg(&other) {
                                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
                                        match &other {
                                            P2pMessage::HeadersInv { ids } => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "headers_inv", count = ids.len(), "published headers_inv");
                                            }
                                            P2pMessage::PayloadInv { roots } => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "payload_inv", count = roots.len(), "published payload_inv");
                                            }
                                            P2pMessage::HeaderAnnounce(h) => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "header_announce", shard = h.shard_id, "published header_announce");
                                            }
                                            _ => {
                                                debug!(target: "pc_p2p.lp2p", event = "gossip_publish", kind = "other", "published other message");
                                            }
                                        }
                                        if let P2pMessage::HeaderAnnounce(h) = &other {
                                            let aux = gossipsub::IdentTopic::new(format!("pc/shard/{}/header", h.shard_id));
                                            let _ = swarm.behaviour_mut().gossipsub.publish(aux, encode_msg(&other).unwrap_or_default());
                                        }
                                    }
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    // Inbound from swarm → forward to service
                    ev = swarm.select_next_some() => {
                        match ev {
                            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message{ message, .. })) => {
                                if let Some(decoded) = decode_msg(&message.data) {
                                    match &decoded {
                                        P2pMessage::HeadersInv { ids } => {
                                            debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "headers_inv", count = ids.len(), "gossipsub inbound headers_inv");
                                        }
                                        P2pMessage::PayloadInv { roots } => {
                                            debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "payload_inv", count = roots.len(), "gossipsub inbound payload_inv");
                                        }
                                        P2pMessage::HeaderAnnounce(h) => {
                                            debug!(target: "pc_p2p.lp2p", event = "gossip_in", kind = "header_announce", shard = h.shard_id, "gossipsub inbound header_announce");
                                        }
                                        _ => {}
                                    }
                                    // Peer-SocketAddr ist hier nicht verfügbar → generisch einspeisen
                                    let _ = svc.send_message(decoded).await;
                                }
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::Rpc(ev)) => {
                                match ev {
                                    rr::Event::Message { peer: _, message } => {
                                        match message {
                                            rr::Message::Request { request, channel, .. } => {
                                                // Eingehende RPC-Request → ReqMsg decodieren, Service rpc_call, Antwort senden
                                                let mut slice = &request[..];
                                                if let Ok(req) = crate::messages::ReqMsg::decode(&mut slice) {
                                                    debug!(target: "pc_p2p.lp2p", event = "rr_in_req", kind = %match &req { crate::messages::ReqMsg::GetHeaders{..} => "get_headers", crate::messages::ReqMsg::GetPayloads{..} => "get_payloads", crate::messages::ReqMsg::GetTx{..} => "get_tx" }, "rpc inbound request");
                                                    if let Ok(resp) = tokio::time::timeout(Duration::from_secs(2), svc.rpc_call(req)).await.unwrap_or(Err(crate::P2pError::ChannelClosed)) {
                                                        let mut buf = Vec::new();
                                                        if resp.encode(&mut buf).is_ok() {
                                                            let _ = swarm.behaviour_mut().rpc.send_response(channel, buf);
                                                        }
                                                    }
                                                }
                                            }
                                            rr::Message::Response { request_id, response } => {
                                                // Antwort auf unsere ausgehende RPC-Anfrage
                                                if let Some((_bytes, _att, start)) = pending.remove(&request_id) {
                                                    let rtt = start.elapsed();
                                                    debug!(target: "pc_p2p.lp2p", event = "rr_resp", rtt_ms = %format!("{:.3}", rtt.as_secs_f64()*1000.0), "rpc response received");
                                                }
                                                let mut slice = &response[..];
                                                if let Ok(resp) = crate::messages::RespMsg::decode(&mut slice) {
                                                    let _ = svc.send_message(crate::messages::P2pMessage::Resp(resp)).await;
                                                }
                                            }
                                        }
                                    }
                                    rr::Event::OutboundFailure { request_id, .. } => {
                                        // Metriken: Outbound-Fehler registrieren
                                        crate::async_svc::out_error_inc();
                                        // Einfacher Retry auf anderen Peer (max 2 Versuche)
                                        if let Some((bytes, att, _start_old)) = pending.remove(&request_id) {
                                            if (att as u32) < 2 && !peers.is_empty() {
                                                rr_rr_idx = rr_rr_idx.wrapping_add(1);
                                                let idx = rr_rr_idx % peers.len();
                                                let peer2 = peers[idx];
                                                let id2 = swarm.behaviour_mut().rpc.send_request(&peer2, bytes.clone());
                                                let start = Instant::now();
                                                debug!(target: "pc_p2p.lp2p", event = "rr_retry", peer = %peer2, attempts = att + 1, "rpc outbound retry");
                                                pending.insert(id2, (bytes, att + 1, start));
                                            }
                                        }
                                    }
                                    rr::Event::InboundFailure { .. } => { /* ignore */ }
                                    rr::Event::ResponseSent { .. } => { /* ignore */ }
                                }
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
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
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                if let Some(pos) = peers.iter().position(|p| *p == peer_id) {
                                    debug!(target: "pc_p2p.lp2p", event = "peer_down", peer = %peer_id, "peer disconnected");
                                    peers.remove(pos);
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
}
