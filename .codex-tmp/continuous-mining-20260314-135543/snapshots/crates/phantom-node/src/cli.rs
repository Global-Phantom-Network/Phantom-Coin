use super::*;

pub(crate) fn run_consensus_ack_dists(args: &ConsensusAckDistsArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let headers: Vec<AnchorHeader> = load_vec_decodable(&args.headers_file)?;
    // k aus Genesis (falls vorhanden) oder CLI ableiten; Genesis hat Vorrang
    let k_eff = if let Some(ref gpath) = args.genesis {
        let g = load_genesis(gpath)?;
        let k = g.consensus.k;
        if k == 0 || k > 64 {
            bail!("invalid k in genesis: {} (must be 1..=64)", k);
        }
        println!(
            "{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}",
            k, g.commitment
        );
        k
    } else {
        if args.k == 0 || args.k > 64 {
            bail!("invalid k: {} (must be 1..=64)", args.k);
        }
        println!(
            "{{\"type\":\"k_selected\",\"k\":{},\"source\":\"cli\"}}",
            args.k
        );
        args.k
    };
    let mut cfg = ConsensusConfig::recommended(k_eff);
    if let Some(dm) = args.d_max {
        cfg.fee_params.d_max = dm;
    }
    let dmax_out = cfg.fee_params.d_max;
    let mut eng = ConsensusEngine::new(cfg);
    for h in headers {
        let _ = eng.insert_header(h);
    }
    let dists = eng.ack_distances(AnchorId(ack));
    // Baue JSON deterministisch ohne Format-String-Brace-Escapes
    let mut out = String::new();
    out.push_str("{\"k\":");
    out.push_str(&args.k.to_string());
    out.push_str(",\"d_max\":");
    out.push_str(&dmax_out.to_string());
    out.push_str(",\"distances\":[");
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match d {
            Some(v) => out.push_str(&v.to_string()),
            None => out.push_str("null"),
        }
    }
    out.push_str("]}");
    println!("{}", out);
    Ok(())
}

pub(crate) fn run_consensus_payout_root(args: &ConsensusPayoutRootArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let headers: Vec<AnchorHeader> = load_vec_decodable(&args.headers_file)?;
    let recipients = parse_hex32_list(&args.recipients)?;
    // k aus Genesis (falls vorhanden) oder CLI ableiten; Genesis hat Vorrang
    let k_eff = if let Some(ref gpath) = args.genesis {
        let g = load_genesis(gpath)?;
        let k = g.consensus.k;
        if k == 0 || k > 64 {
            bail!("invalid k in genesis: {} (must be 1..=64)", k);
        }
        println!(
            "{{\"type\":\"genesis_loaded\",\"k\":{},\"commitment\":\"{}\"}}",
            k, g.commitment
        );
        k
    } else {
        if args.k == 0 || args.k > 64 {
            bail!("invalid k: {} (must be 1..=64)", args.k);
        }
        println!(
            "{{\"type\":\"k_selected\",\"k\":{},\"source\":\"cli\"}}",
            args.k
        );
        args.k
    };
    if recipients.len() != k_eff as usize {
        bail!(
            "recipients length ({}) must equal k ({})",
            recipients.len(),
            k_eff
        );
    }
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let mut cfg = ConsensusConfig::recommended(k_eff);
    if let Some(dm) = args.d_max {
        cfg.fee_params.d_max = dm;
    }
    let mut eng = ConsensusEngine::new(cfg);
    for h in headers {
        let _ = eng.insert_header(h);
    }
    let root = eng.committee_payout_root_for_ack(
        args.fees,
        &recipients,
        args.proposer_index,
        AnchorId(ack),
    )?;
    println!("{}", hex::encode(root));
    Ok(())
}

#[derive(Debug, Clone, Args)]
pub(crate) struct ConsensusAckDistsArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    pub ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    pub headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    pub k: u8,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    pub genesis: Option<String>,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    pub d_max: Option<u8>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct ConsensusPayoutRootArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    pub ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    pub headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    pub k: u8,
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    pub fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert) – muss Länge k haben
    #[arg(long, value_delimiter = ',')]
    pub recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    pub proposer_index: usize,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    pub genesis: Option<String>,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    pub d_max: Option<u8>,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct RateArgs {
    /// HeaderAnnounce Bucket-Kapazität
    #[arg(long)]
    pub hdr_capacity: Option<u32>,
    /// HeaderAnnounce Tokens pro Sekunde
    #[arg(long)]
    pub hdr_refill_per_sec: Option<u32>,
    /// PayloadInv Bucket-Kapazität
    #[arg(long)]
    pub inv_capacity: Option<u32>,
    /// PayloadInv Tokens pro Sekunde
    #[arg(long)]
    pub inv_refill_per_sec: Option<u32>,
    /// Req Bucket-Kapazität
    #[arg(long)]
    pub req_capacity: Option<u32>,
    /// Req Tokens pro Sekunde
    #[arg(long)]
    pub req_refill_per_sec: Option<u32>,
    /// Resp Bucket-Kapazität
    #[arg(long)]
    pub resp_capacity: Option<u32>,
    /// Resp Tokens pro Sekunde
    #[arg(long)]
    pub resp_refill_per_sec: Option<u32>,
    /// Byte-Budget Bucket-Kapazität (Burst). 0/leer = Default
    #[arg(long)]
    pub bytes_capacity: Option<u32>,
    /// Byte-Budget Tokens (Bytes) pro Sekunde. 0/leer = Default
    #[arg(long)]
    pub bytes_refill_per_sec: Option<u32>,
    /// Per-Peer-Limits aktivieren (true/false)
    #[arg(long)]
    pub per_peer: Option<bool>,
    /// TTL für per-Peer Rate-Limiter in Sekunden (Cleanup), 0 = Default
    #[arg(long)]
    pub peer_ttl_secs: Option<u64>,
}

fn rate_cfg_from_parts(
    hdr_capacity: Option<u32>,
    hdr_refill_per_sec: Option<u32>,
    inv_capacity: Option<u32>,
    inv_refill_per_sec: Option<u32>,
    req_capacity: Option<u32>,
    req_refill_per_sec: Option<u32>,
    resp_capacity: Option<u32>,
    resp_refill_per_sec: Option<u32>,
    bytes_capacity: Option<u32>,
    bytes_refill_per_sec: Option<u32>,
    per_peer: Option<bool>,
    peer_ttl_secs: Option<u64>,
) -> Option<RateLimitConfig> {
    let any = hdr_capacity.is_some()
        || hdr_refill_per_sec.is_some()
        || inv_capacity.is_some()
        || inv_refill_per_sec.is_some()
        || req_capacity.is_some()
        || req_refill_per_sec.is_some()
        || resp_capacity.is_some()
        || resp_refill_per_sec.is_some()
        || bytes_capacity.is_some()
        || bytes_refill_per_sec.is_some()
        || per_peer.is_some()
        || peer_ttl_secs.is_some();
    if !any {
        return None;
    }
    Some(RateLimitConfig {
        hdr_capacity: hdr_capacity.unwrap_or(0),
        hdr_refill_per_sec: hdr_refill_per_sec.unwrap_or(0),
        inv_capacity: inv_capacity.unwrap_or(0),
        inv_refill_per_sec: inv_refill_per_sec.unwrap_or(0),
        req_capacity: req_capacity.unwrap_or(0),
        req_refill_per_sec: req_refill_per_sec.unwrap_or(0),
        resp_capacity: resp_capacity.unwrap_or(0),
        resp_refill_per_sec: resp_refill_per_sec.unwrap_or(0),
        bytes_capacity: bytes_capacity.unwrap_or(0),
        bytes_refill_per_sec: bytes_refill_per_sec.unwrap_or(0),
        per_peer: per_peer.unwrap_or(true),
        peer_ttl_secs: peer_ttl_secs.unwrap_or(0),
    })
}

pub(crate) fn rate_cfg_opt(r: &RateArgs) -> Option<RateLimitConfig> {
    rate_cfg_from_parts(
        r.hdr_capacity,
        r.hdr_refill_per_sec,
        r.inv_capacity,
        r.inv_refill_per_sec,
        r.req_capacity,
        r.req_refill_per_sec,
        r.resp_capacity,
        r.resp_refill_per_sec,
        r.bytes_capacity,
        r.bytes_refill_per_sec,
        r.per_peer,
        r.peer_ttl_secs,
    )
}

#[derive(Debug, Clone, Args)]
pub(crate) struct P2pInjectHeadersArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    pub addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    pub cert_file: String,
    /// Datei mit Vec<AnchorHeader> (pc-codec)
    #[arg(long)]
    pub headers_file: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct P2pInjectPayloadsArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    pub addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    pub cert_file: String,
    /// Datei mit Vec<AnchorPayload> (pc-codec)
    #[arg(long)]
    pub payloads_file: String,
    /// Zusätzlich zur Inventory die Payloads direkt mitsenden (RespMsg::Payloads)
    #[arg(long, default_value_t = false)]
    pub with_payloads: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct P2pQuicListenArgs {
    /// QUIC Listen-Adresse, z. B. 127.0.0.1:9000
    #[arg(long)]
    pub addr: String,
    #[arg(long, default_value_t = false)]
    pub unsafe_confirm: bool,
    /// Optional: schreibe Zertifikat (DER) in Datei
    #[arg(long)]
    pub cert_out: Option<String>,
    /// Pfad zu einer TOML-Konfigurationsdatei (optional)
    #[arg(long)]
    pub config: Option<String>,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    pub genesis: Option<String>,
    /// Persistenz-Verzeichnis für Headers/Payloads (wird angelegt)
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    pub store_dir: String,
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true)
    #[arg(long, default_value_t = true)]
    pub fsync: bool,
    /// Committee-Größe k (1..=64) für ConsensusEngine
    #[arg(long, default_value_t = 21)]
    pub k: u8,
    /// Header-Cache-Kapazität (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    pub cache_hdr_cap: Option<usize>,
    /// Payload-Cache-Budget in MB (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    pub cache_pl_mb: Option<usize>,
    /// Rate-Limits (optional)
    #[command(flatten)]
    pub rate: RateArgs,
    /// Aktiviere einfachen PoW-Miner für Mint-Emission (Dev)
    #[arg(long, default_value_t = false)]
    pub pow_miner: bool,
    /// Mint-Amount (kleinste Einheit). Wenn nicht gesetzt: auto aus Mint-Hoehe.
    #[arg(long)]
    pub mint_amount: Option<u64>,
    /// Payout-Lock (32-Byte Hex Commitment)
    #[arg(long)]
    pub mint_lock: Option<String>,
    /// Aktiviere Tx-Proposer: baut periodisch Payloads aus Mempool-TXs und announced sie
    #[arg(long, default_value_t = false)]
    pub tx_proposer: bool,
    /// Intervall für Tx-Proposer in Millisekunden
    #[arg(long, default_value_t = 500)]
    pub tx_proposer_interval_ms: u64,
    /// Max. Anzahl MicroTxs pro Payload (Default: aus genesis_note.params.txs_per_payload; Fallback: DEFAULT_TXS_PER_PAYLOAD)
    #[arg(long)]
    pub txs_per_payload: Option<usize>,
    /// Optionales Payload-Größenbudget (Bytes, encoded_len Summe); übersteigt Auswahl nicht diesen Wert
    #[arg(long)]
    pub payload_budget_bytes: Option<usize>,
    /// Validator-ID (64 Hex = 32 Bytes) für dynamischen Rollenwechsel.
    /// Wenn gesetzt und on-chain genug Stake (staked UTXOs) + gültiger Validator-Record vorhanden ist → automatisch Validator-Rolle.
    #[arg(long)]
    pub validator_id: Option<String>,
    /// BLS Public Key (96 Hex = 48 Bytes) als Alternative zu validator_id.
    /// validator_id wird automatisch als Hash des BLS-PK berechnet.
    #[arg(long)]
    pub bls_pk: Option<String>,
    /// Importiere Peers aus JSON (peers.json oder bootstrap_peers.json), mehrfach nutzbar
    #[arg(long, value_name = "FILE", action = ArgAction::Append)]
    pub peers_import: Vec<String>,
    /// Optional: HTTP Listen-Adresse für Prometheus /metrics (nur loopback), z. B. 127.0.0.1:9100
    #[arg(long)]
    pub metrics_addr: Option<String>,
    /// DA-Gating: Payload wait timeout (Sekunden). Wird aktuell als Konfig-Gauge in /metrics exportiert.
    #[arg(long)]
    pub da_payload_wait_timeout_secs: Option<u64>,
    /// DA-Gating: Retry initial delay (Millisekunden). Wird aktuell als Konfig-Gauge in /metrics exportiert.
    #[arg(long)]
    pub da_retry_initial_delay_ms: Option<u64>,
    /// DA-Gating: Retry max delay (Millisekunden). Wird aktuell als Konfig-Gauge in /metrics exportiert.
    #[arg(long)]
    pub da_retry_max_delay_ms: Option<u64>,
    /// DA-Gating: Retry max retries. Wird aktuell als Konfig-Gauge in /metrics exportiert.
    #[arg(long)]
    pub da_retry_max_retries: Option<u32>,
    /// DA-Gating: Retry jitter (Prozent 0..=100). Wird aktuell als Konfig-Gauge in /metrics exportiert.
    #[arg(long)]
    pub da_retry_jitter_pct: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NodeConfig {
    pub consensus: Option<ConsensusCfg>,
    pub node: Option<NodeSection>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsensusCfg {
    pub k: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NodeSection {
    pub cache: Option<CacheCfg>,
    pub rate: Option<RateCfg>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CacheCfg {
    pub header_cap: Option<usize>,
    pub payload_mb: Option<usize>,
}

#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub(crate) struct RateCfg {
    pub hdr_capacity: Option<u32>,
    pub hdr_refill_per_sec: Option<u32>,
    pub inv_capacity: Option<u32>,
    pub inv_refill_per_sec: Option<u32>,
    pub req_capacity: Option<u32>,
    pub req_refill_per_sec: Option<u32>,
    pub resp_capacity: Option<u32>,
    pub resp_refill_per_sec: Option<u32>,
    pub bytes_capacity: Option<u32>,
    pub bytes_refill_per_sec: Option<u32>,
    pub per_peer: Option<bool>,
    pub peer_ttl_secs: Option<u64>,
}

pub(crate) fn effective_rate_cfg(cli: &RateArgs, cfg: Option<&RateCfg>) -> Option<RateLimitConfig> {
    rate_cfg_from_parts(
        cli.hdr_capacity.or(cfg.and_then(|c| c.hdr_capacity)),
        cli.hdr_refill_per_sec
            .or(cfg.and_then(|c| c.hdr_refill_per_sec)),
        cli.inv_capacity.or(cfg.and_then(|c| c.inv_capacity)),
        cli.inv_refill_per_sec
            .or(cfg.and_then(|c| c.inv_refill_per_sec)),
        cli.req_capacity.or(cfg.and_then(|c| c.req_capacity)),
        cli.req_refill_per_sec
            .or(cfg.and_then(|c| c.req_refill_per_sec)),
        cli.resp_capacity.or(cfg.and_then(|c| c.resp_capacity)),
        cli.resp_refill_per_sec
            .or(cfg.and_then(|c| c.resp_refill_per_sec)),
        cli.bytes_capacity.or(cfg.and_then(|c| c.bytes_capacity)),
        cli.bytes_refill_per_sec
            .or(cfg.and_then(|c| c.bytes_refill_per_sec)),
        cli.per_peer.or(cfg.and_then(|c| c.per_peer)),
        cli.peer_ttl_secs.or(cfg.and_then(|c| c.peer_ttl_secs)),
    )
}

pub(crate) fn load_node_config(path: &str) -> Result<NodeConfig> {
    let s = std::fs::read_to_string(path).map_err(|e| anyhow!("read config '{}': {}", path, e))?;
    let cfg: NodeConfig =
        toml::from_str(&s).map_err(|e| anyhow!("parse toml '{}': {}", path, e))?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_config_parses_rate_section() {
        let cfg: NodeConfig = toml::from_str(
            r#"
[consensus]
k = 21

[node.rate]
hdr_capacity = 200
hdr_refill_per_sec = 200
inv_capacity = 300
inv_refill_per_sec = 300
req_capacity = 300
req_refill_per_sec = 300
resp_capacity = 300
resp_refill_per_sec = 300
bytes_capacity = 4194304
bytes_refill_per_sec = 2097152
per_peer = true
peer_ttl_secs = 600
"#,
        )
        .expect("parse node config");

        let rate = cfg.node.and_then(|n| n.rate).expect("node.rate present");
        assert_eq!(rate.hdr_capacity, Some(200));
        assert_eq!(rate.bytes_capacity, Some(4_194_304));
        assert_eq!(rate.bytes_refill_per_sec, Some(2_097_152));
        assert_eq!(rate.per_peer, Some(true));
        assert_eq!(rate.peer_ttl_secs, Some(600));
    }

    #[test]
    fn effective_rate_cfg_prefers_cli_over_config_and_falls_back() {
        let cli = RateArgs {
            hdr_capacity: Some(111),
            per_peer: Some(false),
            ..RateArgs::default()
        };
        let cfg = RateCfg {
            hdr_capacity: Some(200),
            hdr_refill_per_sec: Some(200),
            peer_ttl_secs: Some(600),
            per_peer: Some(true),
            ..RateCfg::default()
        };

        let effective = effective_rate_cfg(&cli, Some(&cfg)).expect("effective rate cfg");
        assert_eq!(effective.hdr_capacity, 111);
        assert_eq!(effective.hdr_refill_per_sec, 200);
        assert!(!effective.per_peer);
        assert_eq!(effective.peer_ttl_secs, 600);
    }

    #[test]
    fn effective_rate_cfg_none_when_cli_and_config_absent() {
        assert!(effective_rate_cfg(&RateArgs::default(), None).is_none());
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Genesis {
    pub consensus: GenesisConsensus,
    pub genesis_note: String,
    pub commitment: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GenesisConsensus {
    pub k: u8,
    // Optional: PoW-Difficulty in führenden Nullbits für Mint-PoW
    pub pow_bits: Option<u8>,
}

pub(crate) fn load_genesis(path: &str) -> Result<Genesis> {
    let s = std::fs::read_to_string(path).map_err(|e| anyhow!("read genesis '{}': {}", path, e))?;
    let g: Genesis = toml::from_str(&s).map_err(|e| anyhow!("parse toml '{}': {}", path, e))?;
    // Validierung: commitment == blake3_32(genesis_note)
    let note = parse_hex32(&g.genesis_note)?;
    let got = blake3_32(&note);
    let want = parse_hex32(&g.commitment)?;
    if got != want {
        bail!(
            "genesis commitment mismatch: computed={}, expected={}",
            hex::encode(got),
            g.commitment
        );
    }
    Ok(g)
}

#[derive(Debug, Clone, Args)]
pub(crate) struct P2pQuicConnectArgs {
    /// QUIC Ziel-Adresse, z. B. 127.0.0.1:9000, host:port oder Multiaddr (/ip4/.../udp/.../quic-v1[/p2p/...])
    #[arg(long)]
    pub addr: String,
    /// Pfad zur Server-Zertifikatsdatei (DER), wie von p2p-quic-listen ausgegeben
    #[arg(long)]
    pub cert_file: String,
    /// Rate-Limits (optional)
    #[command(flatten)]
    pub rate: RateArgs,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BootstrapPeersFile {
    pub peers: Vec<BootstrapPeerEntry>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BootstrapPeerEntry {
    pub addr: String,
    pub cert_file: String,
}

pub(crate) const MAX_BOOTSTRAP_TARGETS: usize = 64;
pub(crate) const MAX_OUTBOUND_PEERS: usize = 16;
pub(crate) const MAX_CERT_DER_LEN: usize = 8192;
pub(crate) const MAX_CONNECT_FAILS: u32 = 3;
pub(crate) const DNS_FALLBACK_INTERVAL_SECS: u64 = 300;
pub(crate) const PEER_REQUEST_MIN_OUTBOUND: usize = 4;
pub(crate) const PEER_REQUEST_BASE_SECS: u64 = 900;
pub(crate) const PEER_REQUEST_JITTER_SECS: u64 = 300;
pub(crate) const PEER_REQUEST_SAMPLE: u16 = 16;
pub(crate) const PING_INTERVAL_SECS: u64 = 120;
pub(crate) const PING_TIMEOUT_SECS: u64 = 360;

pub(crate) fn parse_quic_multiaddr(input: &str) -> Result<SocketAddr> {
    let parts: Vec<&str> = input.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() < 4 {
        bail!("Multiaddr unvollständig: {}", input);
    }
    let proto = parts
        .first()
        .copied()
        .ok_or_else(|| anyhow!("Multiaddr unvollständig: {}", input))?;
    let ip_str = parts
        .get(1)
        .copied()
        .ok_or_else(|| anyhow!("Multiaddr unvollständig: {}", input))?;
    let ip: IpAddr = match proto {
        "ip4" => ip_str
            .parse()
            .map_err(|e| anyhow!("Ungültige ip4 in Multiaddr '{}': {}", input, e))?,
        "ip6" => ip_str
            .parse()
            .map_err(|e| anyhow!("Ungültige ip6 in Multiaddr '{}': {}", input, e))?,
        _ => bail!("Multiaddr-Protokoll nicht unterstützt: {}", proto),
    };
    let udp_tag = parts
        .get(2)
        .copied()
        .ok_or_else(|| anyhow!("Multiaddr unvollständig: {}", input))?;
    if udp_tag != "udp" {
        bail!("Multiaddr muss /udp/ verwenden (bekommen: {})", udp_tag);
    }
    let port_str = parts
        .get(3)
        .copied()
        .ok_or_else(|| anyhow!("Multiaddr unvollständig: {}", input))?;
    let port: u16 = port_str
        .parse()
        .map_err(|e| anyhow!("Ungültiger UDP-Port in Multiaddr '{}': {}", input, e))?;

    let mut idx = 4;
    if let Some(tag) = parts.get(idx) {
        if *tag == "quic-v1" || *tag == "quic" {
            idx += 1;
        }
    }
    if parts.get(idx).copied() == Some("p2p") {
        if parts.get(idx + 1).is_none() {
            bail!("Multiaddr enthält /p2p ohne PeerId: {}", input);
        }
        idx += 2;
    }
    if idx != parts.len() {
        bail!("Multiaddr enthält unbekannte Teile: {}", input);
    }

    Ok(SocketAddr::new(ip, port))
}

pub(crate) fn parse_quic_addr(input: &str) -> Result<SocketAddr> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("addr ist leer");
    }
    if trimmed.starts_with('/') {
        return parse_quic_multiaddr(trimmed);
    }
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let mut resolved = trimmed
        .to_socket_addrs()
        .map_err(|e| anyhow!("DNS-Auflösung fehlgeschlagen für '{}': {}", trimmed, e))?;
    resolved
        .next()
        .ok_or_else(|| anyhow!("DNS-Auflösung ergab keine Adresse für '{}'", trimmed))
}

fn resolve_cert_path(store_dir: &str, cert_file: &str) -> Option<PathBuf> {
    let raw = cert_file.trim();
    if raw.is_empty() {
        return None;
    }
    let p = PathBuf::from(raw);
    if p.is_absolute() && p.exists() {
        return Some(p);
    }
    if p.exists() {
        return Some(p);
    }
    let candidate = PathBuf::from(store_dir).join(raw);
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

pub(crate) fn load_bootstrap_targets(store_dir: &str) -> Vec<(SocketAddr, Vec<u8>)> {
    let path = PathBuf::from(store_dir).join("bootstrap_peers.json");
    if !path.exists() {
        return Vec::new();
    }
    let data = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let parsed: BootstrapPeersFile = match serde_json::from_str(&data) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for peer in parsed.peers.into_iter() {
        if out.len() >= MAX_BOOTSTRAP_TARGETS {
            break;
        }
        let addr = match parse_quic_addr(&peer.addr) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let cert_path = match resolve_cert_path(store_dir, &peer.cert_file) {
            Some(p) => p,
            None => continue,
        };
        let cert_der = match std::fs::read(&cert_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if cert_der.is_empty() || cert_der.len() > MAX_CERT_DER_LEN {
            continue;
        }
        out.push((addr, cert_der));
    }
    out
}

pub(crate) fn load_dynamic_targets(store_dir: &str, max: usize) -> Vec<(SocketAddr, Vec<u8>)> {
    let path = PathBuf::from(store_dir).join("peers.json");
    let store = PeerStore::load(&path);
    store.connect_targets(max)
}

pub(crate) fn remove_peer_from_store(store_dir: &str, addr: SocketAddr) {
    let path = PathBuf::from(store_dir).join("peers.json");
    let mut store = PeerStore::load(&path);
    if store.peers.remove(&addr.to_string()).is_some() {
        let _ = store.save(&path);
    }
}

pub(crate) fn resolve_cert_path_with_base(
    store_dir: &str,
    base_dir: &Path,
    cert_file: &str,
) -> Option<PathBuf> {
    let raw = cert_file.trim();
    if raw.is_empty() {
        return None;
    }
    let p = PathBuf::from(raw);
    if p.is_absolute() && p.exists() {
        return Some(p);
    }
    let candidate = base_dir.join(raw);
    if candidate.exists() {
        return Some(candidate);
    }
    resolve_cert_path(store_dir, cert_file)
}

pub(crate) fn import_peer_lists(store_dir: &str, paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let peers_path = PathBuf::from(store_dir).join("peers.json");
    let mut store = PeerStore::load(&peers_path);
    let mut imported = 0usize;

    for raw_path in paths {
        let path = PathBuf::from(raw_path);
        let data = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "{{\"type\":\"peers_import\",\"status\":\"read_failed\",\"path\":\"{}\",\"err\":\"{}\"}}",
                    path.display(),
                    e
                );
                continue;
            }
        };

        if let Ok(other) = serde_json::from_str::<PeerStore>(&data) {
            let before = store.peers.len();
            store.merge(&other, 0);
            let after = store.peers.len();
            imported += after.saturating_sub(before);
            continue;
        }

        if let Ok(parsed) = serde_json::from_str::<BootstrapPeersFile>(&data) {
            let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
            for peer in parsed.peers {
                let addr = match parse_quic_addr(&peer.addr) {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let cert_path =
                    match resolve_cert_path_with_base(store_dir, base_dir, &peer.cert_file) {
                        Some(p) => p,
                        None => continue,
                    };
                let cert_der = match std::fs::read(&cert_path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if cert_der.is_empty() || cert_der.len() > MAX_CERT_DER_LEN {
                    continue;
                }
                let before = store.peers.len();
                store.add_peer(addr, &cert_der, ROLE_FULLNODE, 0);
                let after = store.peers.len();
                if after > before {
                    imported += 1;
                }
            }
            continue;
        }

        println!(
            "{{\"type\":\"peers_import\",\"status\":\"invalid_json\",\"path\":\"{}\"}}",
            path.display()
        );
    }

    let _ = store.save(&peers_path);
    println!(
        "{{\"type\":\"peers_import\",\"status\":\"ok\",\"count\":{}}}",
        imported
    );
    Ok(())
}

pub(crate) fn socket_addr_to_peer_info(
    addr: SocketAddr,
    cert_der: Vec<u8>,
    role_flags: u8,
) -> PeerInfo {
    let ip_bytes = match addr.ip() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    PeerInfo {
        ip: ip_bytes,
        port: addr.port(),
        cert_der,
        last_seen: 0,
        role_flags,
    }
}

pub(crate) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_connect_targets(
    targets: Vec<(SocketAddr, Vec<u8>)>,
    using_dynamic: bool,
    listen_addr: SocketAddr,
    outbound_active: &Arc<Mutex<HashSet<SocketAddr>>>,
    last_attempt: &mut HashMap<SocketAddr, Instant>,
    fail_counts: &mut HashMap<SocketAddr, u32>,
    store_dir: &str,
    svc: &pc_p2p::async_svc::P2pService,
    out_tx: &tokio::sync::broadcast::Sender<P2pMessage>,
    _own_role_flags: u8,
) -> usize {
    let mut made = 0usize;
    for (addr, cert_der) in targets {
        if addr == listen_addr {
            continue;
        }
        {
            let guard = outbound_active.lock().await;
            if guard.contains(&addr) || guard.len() >= MAX_OUTBOUND_PEERS {
                continue;
            }
        }
        if let Some(last) = last_attempt.get(&addr) {
            if last.elapsed() < Duration::from_secs(30) {
                continue;
            }
        }
        last_attempt.insert(addr, Instant::now());
        let cfg = match client_config_from_cert(&cert_der) {
            Ok(c) => c,
            Err(_) => {
                let count = fail_counts.entry(addr).and_modify(|c| *c += 1).or_insert(1);
                if using_dynamic && *count >= MAX_CONNECT_FAILS {
                    remove_peer_from_store(store_dir, addr);
                    fail_counts.remove(&addr);
                }
                continue;
            }
        };
        let conn = match connect(addr, cfg).await {
            Ok(c) => c,
            Err(_) => {
                let count = fail_counts.entry(addr).and_modify(|c| *c += 1).or_insert(1);
                if using_dynamic && *count >= MAX_CONNECT_FAILS {
                    remove_peer_from_store(store_dir, addr);
                    fail_counts.remove(&addr);
                }
                continue;
            }
        };
        {
            let mut guard = outbound_active.lock().await;
            if guard.len() >= MAX_OUTBOUND_PEERS || guard.contains(&addr) {
                continue;
            }
            guard.insert(addr);
        }
        fail_counts.remove(&addr);

        let svc_peer = svc.clone();
        let outbound_active_peer = outbound_active.clone();
        let mut rx = out_tx.subscribe();
        let cert_copy = cert_der.clone();
        let last_pong_ms = Arc::new(AtomicU64::new(now_millis()));
        let last_pong_for_reader = last_pong_ms.clone();
        tokio::spawn(async move {
            let _reader =
                spawn_client_reader(conn.clone(), svc_peer.clone(), Some(last_pong_for_reader));
            let sink = QuicClientSink::new(conn.clone());
            let mut ping_tick = interval(Duration::from_secs(PING_INTERVAL_SECS));
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Ok(msg) => {
                                if sink.deliver(msg).await.is_err() {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = ping_tick.tick() => {
                        if sink.deliver(P2pMessage::Ping).await.is_err() {
                            break;
                        }
                        let last = last_pong_ms.load(Ordering::Relaxed);
                        if last > 0 && now_millis().saturating_sub(last) > (PING_TIMEOUT_SECS * 1000) {
                            break;
                        }
                    }
                }
            }
            let mut guard = outbound_active_peer.lock().await;
            guard.remove(&addr);
        });

        // We don't know the remote's role flags here; treat as fullnode (safe default).
        let info = socket_addr_to_peer_info(addr, cert_copy, ROLE_FULLNODE);
        let _ = svc
            .send_message(P2pMessage::Peers { peers: vec![info] })
            .await;

        made += 1;
        if made >= MAX_OUTBOUND_PEERS {
            break;
        }
    }
    made
}

pub(crate) fn run_p2p_run(args: &P2pRunArgs) -> Result<()> {
    // Runtime erstellen
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::P2pConfig;
        let cfg = P2pConfig {
            max_peers: args.max_peers,
            rate: rate_cfg_opt(&args.rate),
            peers_json_path: None,
        };
        // Libp2p-Swarm + interner Service starten
        let lp2p_cfg = pc_p2p::Libp2pConfig {
            bootstrap_peers: args.bootstrap_peer.clone(),
            kad_bootstrap_interval_secs: args.kad_bootstrap_interval_secs,
            ..pc_p2p::Libp2pConfig::default()
        };
        let (svc, svc_handle, swarm_handle) = pc_p2p::spawn_with_libp2p(cfg, lp2p_cfg)
            .map_err(|e| anyhow!("spawn_with_libp2p failed: {e:?}"))?;

        // Inbound-Observer für Ausgabe nutzen
        let mut rx_in = inbound_subscribe();
        let print_task = tokio::spawn(async move {
            loop {
                match rx_in.recv().await {
                    Ok(msg) => {
                        print_p2p_json(&msg);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        // Warte auf Ctrl-C und stoppe dann
        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = print_task.await;
        let res = svc_handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))?;
        let _ = swarm_handle.await;
        Ok(())
    })
}

pub(crate) fn read_hex32_files_in(dir: &std::path::Path, max_n: usize) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if let Some(name) = p.file_stem().and_then(|s| s.to_str()) {
            if name.len() == 64 {
                // 32 bytes hex
                if let Ok(bytes) = hex::decode(name) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        out.push(arr);
                        if out.len() >= max_n {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

pub(crate) fn run_cache_bench(args: &CacheBenchArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let store = FileStore::open(&args.store_dir, args.fsync)?;
        let delegate =
            NodeDiskStore::new(store, &args.store_dir, args.fsync, args.cache_hdr_cap, args.cache_pl_mb, None, None);
        let start_hits_hdr = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
        let start_miss_hdr = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
        let start_hits_pl = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
        let start_miss_pl = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
        let t0 = Instant::now();
        match args.mode.as_str() {
            "headers" => {
                let ids = read_hex32_files_in(&std::path::Path::new(&args.store_dir).join("headers"), args.sample)?
                    .into_iter().map(AnchorId).collect::<Vec<_>>();
                if ids.is_empty() { bail!("no headers found in store_dir"); }
                for _ in 0..args.iterations {
                    let _ = delegate.get_headers(&ids).await;
                }
            }
            "payloads" => {
                let roots = read_hex32_files_in(&std::path::Path::new(&args.store_dir).join("payloads"), args.sample)?;
                if roots.is_empty() { bail!("no payloads found in store_dir"); }
                for _ in 0..args.iterations {
                    let _ = delegate.get_payloads(&roots).await;
                }
            }
            other => { bail!("invalid mode: {} (use 'headers' or 'payloads')", other); }
        }
        let elapsed = t0.elapsed();
        let end_hits_hdr = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
        let end_miss_hdr = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
        let end_hits_pl = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
        let end_miss_pl = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
        let dh_hdr = end_hits_hdr.saturating_sub(start_hits_hdr);
        let dm_hdr = end_miss_hdr.saturating_sub(start_miss_hdr);
        let dh_pl = end_hits_pl.saturating_sub(start_hits_pl);
        let dm_pl = end_miss_pl.saturating_sub(start_miss_pl);
        println!(
            "{{\"type\":\"cache_bench\",\"mode\":\"{}\",\"sample\":{},\"iterations\":{},\"hdr_hits\":{},\"hdr_misses\":{},\"pl_hits\":{},\"pl_misses\":{},\"elapsed_ms\":{}}}",
            args.mode, args.sample, args.iterations, dh_hdr, dm_hdr, dh_pl, dm_pl, elapsed.as_millis()
        );
        Ok::<(), anyhow::Error>(())
    })
}

pub(crate) fn run_p2p_metrics() -> Result<()> {
    let m = metrics_snapshot();
    let n_hdr = NODE_PERSIST_HEADERS_TOTAL.load(Ordering::Relaxed);
    let n_hdr_err = NODE_PERSIST_HEADERS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_pl = NODE_PERSIST_PAYLOADS_TOTAL.load(Ordering::Relaxed);
    let n_pl_err = NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_lag = NODE_INBOUND_OBS_LAGGED_TOTAL.load(Ordering::Relaxed);
    println!(
        "{{\"inbound_total\":{},\"inbound_dropped_rate\":{},\"outbound_total\":{},\"peer_rl_purged_total\":{},\"in_hdr_total\":{},\"in_inv_total\":{},\"in_req_total\":{},\"in_resp_total\":{},\"out_hdr_total\":{},\"out_inv_total\":{},\"out_req_total\":{},\"out_resp_total\":{},\"out_errors_total\":{},\"outbox_enq_total\":{},\"outbox_deq_total\":{},\"in_handle_count\":{},\"in_handle_sum_micros\":{},\"in_bucket_le_1ms\":{},\"in_bucket_le_5ms\":{},\"in_bucket_le_10ms\":{},\"in_bucket_le_50ms\":{},\"in_bucket_le_100ms\":{},\"in_bucket_le_500ms\":{},\"node_persist_headers_total\":{},\"node_persist_headers_errors_total\":{},\"node_persist_payloads_total\":{},\"node_persist_payloads_errors_total\":{},\"node_inbound_obs_lagged_total\":{}}}",
        m.inbound_total,
        m.inbound_dropped_rate,
        m.outbound_total,
        m.peer_rl_purged_total,
        m.in_hdr_total,
        m.in_inv_total,
        m.in_req_total,
        m.in_resp_total,
        m.out_hdr_total,
        m.out_inv_total,
        m.out_req_total,
        m.out_resp_total,
        m.out_errors_total,
        m.outbox_enq_total,
        m.outbox_deq_total,
        m.in_handle_count,
        m.in_handle_sum_micros,
        m.in_bucket_le_1ms,
        m.in_bucket_le_5ms,
        m.in_bucket_le_10ms,
        m.in_bucket_le_50ms,
        m.in_bucket_le_100ms,
        m.in_bucket_le_500ms,
        n_hdr,
        n_hdr_err,
        n_pl,
        n_pl_err,
        n_lag,
    );
    Ok(())
}

pub(crate) fn render_p2p_metrics_prometheus_text() -> String {
    let m = metrics_snapshot();
    let sum_sec = (m.in_handle_sum_micros as f64) / 1_000_000.0;
    let c1 = m.in_bucket_le_1ms;
    let c5 = c1 + m.in_bucket_le_5ms;
    let c10 = c5 + m.in_bucket_le_10ms;
    let c50 = c10 + m.in_bucket_le_50ms;
    let c100 = c50 + m.in_bucket_le_100ms;
    let c500 = c100 + m.in_bucket_le_500ms;
    let count = m.in_handle_count;
    let n_hdr = NODE_PERSIST_HEADERS_TOTAL.load(Ordering::Relaxed);
    let n_hdr_err = NODE_PERSIST_HEADERS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_pl = NODE_PERSIST_PAYLOADS_TOTAL.load(Ordering::Relaxed);
    let n_pl_err = NODE_PERSIST_PAYLOADS_ERRORS_TOTAL.load(Ordering::Relaxed);
    let n_lag = NODE_INBOUND_OBS_LAGGED_TOTAL.load(Ordering::Relaxed);
    // Node-Store Read Latenzen
    let hdr_cnt = NODE_STORE_HDR_READ_COUNT.load(Ordering::Relaxed);
    let hdr_sum_sec = (NODE_STORE_HDR_READ_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
    let h1 = NODE_STORE_HDR_BUCKET_LE_1MS.load(Ordering::Relaxed);
    let h5 = h1 + NODE_STORE_HDR_BUCKET_LE_5MS.load(Ordering::Relaxed);
    let h10 = h5 + NODE_STORE_HDR_BUCKET_LE_10MS.load(Ordering::Relaxed);
    let h50 = h10 + NODE_STORE_HDR_BUCKET_LE_50MS.load(Ordering::Relaxed);
    let h100 = h50 + NODE_STORE_HDR_BUCKET_LE_100MS.load(Ordering::Relaxed);
    let h500 = h100 + NODE_STORE_HDR_BUCKET_LE_500MS.load(Ordering::Relaxed);

    let pl_cnt = NODE_STORE_PL_READ_COUNT.load(Ordering::Relaxed);
    let pl_sum_sec = (NODE_STORE_PL_READ_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
    let p1 = NODE_STORE_PL_BUCKET_LE_1MS.load(Ordering::Relaxed);
    let p5 = p1 + NODE_STORE_PL_BUCKET_LE_5MS.load(Ordering::Relaxed);
    let p10 = p5 + NODE_STORE_PL_BUCKET_LE_10MS.load(Ordering::Relaxed);
    let p50 = p10 + NODE_STORE_PL_BUCKET_LE_50MS.load(Ordering::Relaxed);
    let p100 = p50 + NODE_STORE_PL_BUCKET_LE_100MS.load(Ordering::Relaxed);
    let p500 = p100 + NODE_STORE_PL_BUCKET_LE_500MS.load(Ordering::Relaxed);
    let cache_hdr_hit = NODE_CACHE_HEADERS_HITS_TOTAL.load(Ordering::Relaxed);
    let cache_hdr_miss = NODE_CACHE_HEADERS_MISSES_TOTAL.load(Ordering::Relaxed);
    let cache_pl_hit = NODE_CACHE_PAYLOADS_HITS_TOTAL.load(Ordering::Relaxed);
    let cache_pl_miss = NODE_CACHE_PAYLOADS_MISSES_TOTAL.load(Ordering::Relaxed);
    // Mempool-Kennzahlen
    let mp_size = NODE_MEMPOOL_SIZE.load(Ordering::Relaxed);
    let mp_acc = NODE_MEMPOOL_ACCEPTED_TOTAL.load(Ordering::Relaxed);
    let mp_rej = NODE_MEMPOOL_REJECTED_TOTAL.load(Ordering::Relaxed);
    let mp_dup = NODE_MEMPOOL_DUPLICATE_TOTAL.load(Ordering::Relaxed);
    let mp_conf = NODE_MEMPOOL_CONFLICT_TOTAL.load(Ordering::Relaxed);
    let mp_ttl = NODE_MEMPOOL_TTL_EVICT_TOTAL.load(Ordering::Relaxed);
    let mp_cap = NODE_MEMPOOL_CAP_EVICT_TOTAL.load(Ordering::Relaxed);
    let mp_invld = NODE_MEMPOOL_INVALIDATED_TOTAL.load(Ordering::Relaxed);
    let mp_shard_rej = NODE_MEMPOOL_SHARD_REJECT_TOTAL.load(Ordering::Relaxed);
    let prop_built = NODE_PROPOSER_BUILT_TOTAL.load(Ordering::Relaxed);
    let prop_last = NODE_PROPOSER_LAST_SIZE.load(Ordering::Relaxed);
    let prop_err = NODE_PROPOSER_ERRORS_TOTAL.load(Ordering::Relaxed);
    let prop_pending = NODE_PROPOSER_PENDING.load(Ordering::Relaxed);
    // Persist latency histogram (kumulative Buckets).
    let persist_cnt = NODE_PERSIST_COUNT.load(Ordering::Relaxed);
    let persist_sum_sec = (NODE_PERSIST_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
    let pb1 = NODE_PERSIST_BUCKET_LE_1MS.load(Ordering::Relaxed);
    let pb5 = pb1 + NODE_PERSIST_BUCKET_LE_5MS.load(Ordering::Relaxed);
    let pb10 = pb5 + NODE_PERSIST_BUCKET_LE_10MS.load(Ordering::Relaxed);
    let pb50 = pb10 + NODE_PERSIST_BUCKET_LE_50MS.load(Ordering::Relaxed);
    let pb100 = pb50 + NODE_PERSIST_BUCKET_LE_100MS.load(Ordering::Relaxed);
    let pb500 = pb100 + NODE_PERSIST_BUCKET_LE_500MS.load(Ordering::Relaxed);
    // Prozess-Metriken.
    let cpu_pct = (NODE_PROCESS_CPU_PCT_MICRO.load(Ordering::Relaxed) as f64) / 1_000_000.0;
    let rss_bytes = NODE_PROCESS_RSS_BYTES.load(Ordering::Relaxed);
    // Rolle/Validator (lokal).
    let role_flags = NODE_ROLE_FLAGS_GAUGE.load(Ordering::Relaxed);
    let vid_cfg = NODE_VALIDATOR_ID_CONFIGURED.load(Ordering::Relaxed);
    let v_stake = NODE_VALIDATOR_STAKE.load(Ordering::Relaxed);
    let v_min = NODE_VALIDATOR_MIN_STAKE.load(Ordering::Relaxed);
    let v_pop_ok = NODE_VALIDATOR_POP_OK.load(Ordering::Relaxed);
    let v_policy_ok = NODE_VALIDATOR_POLICY_OK.load(Ordering::Relaxed);
    let v_eligible = NODE_VALIDATOR_ELIGIBLE.load(Ordering::Relaxed);
    let v_conditions_ok = NODE_VALIDATOR_CONDITIONS_OK.load(Ordering::Relaxed);
    let v_enabled = NODE_VALIDATOR_VOTING_ENABLED.load(Ordering::Relaxed);
    let vc_kill = NODE_VALIDATOR_CONTROL_KILL_SWITCH.load(Ordering::Relaxed);
    let vc_maint = NODE_VALIDATOR_CONTROL_MAINTENANCE.load(Ordering::Relaxed);
    let vc_manual = NODE_VALIDATOR_CONTROL_MANUAL_DISABLE.load(Ordering::Relaxed);
    let vc_auto = NODE_VALIDATOR_CONTROL_AUTO_REENABLE.load(Ordering::Relaxed);
    let vc_cooldown = NODE_VALIDATOR_CONTROL_COOLDOWN_UNTIL_EPOCH.load(Ordering::Relaxed);
    let vc_updated = NODE_VALIDATOR_CONTROL_UPDATED_AT_EPOCH.load(Ordering::Relaxed);
    let body = format!(
        "# HELP pc_p2p_inbound_total Total inbound messages\n# TYPE pc_p2p_inbound_total counter\npc_p2p_inbound_total {}\n\
# HELP pc_p2p_inbound_bytes_total Total inbound bytes (encoded message size)\n# TYPE pc_p2p_inbound_bytes_total counter\npc_p2p_inbound_bytes_total {}\n\
# HELP pc_p2p_inbound_dropped_rate Dropped inbound messages due to rate limiting\n# TYPE pc_p2p_inbound_dropped_rate counter\npc_p2p_inbound_dropped_rate {}\n\
# HELP pc_p2p_outbound_total Total outbound messages\n# TYPE pc_p2p_outbound_total counter\npc_p2p_outbound_total {}\n\
# HELP pc_p2p_outbound_bytes_total Total outbound bytes (encoded message size)\n# TYPE pc_p2p_outbound_bytes_total counter\npc_p2p_outbound_bytes_total {}\n\
# HELP pc_p2p_peer_rl_purged_total Purged per-peer rate limiters due to TTL\n# TYPE pc_p2p_peer_rl_purged_total counter\npc_p2p_peer_rl_purged_total {}\n\
# HELP pc_p2p_in_hdr_total Total inbound HeaderAnnounce\n# TYPE pc_p2p_in_hdr_total counter\npc_p2p_in_hdr_total {}\n\
# HELP pc_p2p_in_inv_total Total inbound PayloadInv\n# TYPE pc_p2p_in_inv_total counter\npc_p2p_in_inv_total {}\n\
# HELP pc_p2p_in_req_total Total inbound Req\n# TYPE pc_p2p_in_req_total counter\npc_p2p_in_req_total {}\n\
# HELP pc_p2p_in_resp_total Total inbound Resp\n# TYPE pc_p2p_in_resp_total counter\npc_p2p_in_resp_total {}\n\
# HELP pc_p2p_out_hdr_total Total outbound HeaderAnnounce\n# TYPE pc_p2p_out_hdr_total counter\npc_p2p_out_hdr_total {}\n\
# HELP pc_p2p_out_inv_total Total outbound PayloadInv\n# TYPE pc_p2p_out_inv_total counter\npc_p2p_out_inv_total {}\n\
# HELP pc_p2p_out_req_total Total outbound Req\n# TYPE pc_p2p_out_req_total counter\npc_p2p_out_req_total {}\n\
# HELP pc_p2p_out_resp_total Total outbound Resp\n# TYPE pc_p2p_out_resp_total counter\npc_p2p_out_resp_total {}\n\
# HELP pc_p2p_out_errors_total Total outbound transport errors (QUIC/network)\n# TYPE pc_p2p_out_errors_total counter\npc_p2p_out_errors_total {}\n\
# HELP pc_p2p_outbox_enq_total Total enqueued messages to outbox\n# TYPE pc_p2p_outbox_enq_total counter\npc_p2p_outbox_enq_total {}\n\
# HELP pc_p2p_outbox_deq_total Total dequeued messages from outbox\n# TYPE pc_p2p_outbox_deq_total counter\npc_p2p_outbox_deq_total {}\n\
# HELP pc_p2p_outbox_drop_total Total dropped messages due to backpressure\n# TYPE pc_p2p_outbox_drop_total counter\npc_p2p_outbox_drop_total {}\n\
# HELP pc_p2p_outbox_depth Current outbox depth\n# TYPE pc_p2p_outbox_depth gauge\npc_p2p_outbox_depth {}\n\
# HELP pc_p2p_in_dedup_total Total dropped inbound messages due to deduplication\n# TYPE pc_p2p_in_dedup_total counter\npc_p2p_in_dedup_total {}\n\
# HELP pc_p2p_peers_known_total Total known peers in PeerStore\n# TYPE pc_p2p_peers_known_total gauge\npc_p2p_peers_known_total {}\n\
# HELP pc_p2p_peers_miner_total Known miner peers\n# TYPE pc_p2p_peers_miner_total gauge\npc_p2p_peers_miner_total {}\n\
# HELP pc_p2p_peers_validator_total Known validator peers\n# TYPE pc_p2p_peers_validator_total gauge\npc_p2p_peers_validator_total {}\n\
# HELP pc_p2p_peers_banned_total Banned peers\n# TYPE pc_p2p_peers_banned_total gauge\npc_p2p_peers_banned_total {}\n\
# HELP pc_p2p_in_handle_seconds Inbound message handling latency\n# TYPE pc_p2p_in_handle_seconds histogram\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_p2p_in_handle_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_p2p_in_handle_seconds_sum {}\n\
pc_p2p_in_handle_seconds_count {}\n",
        m.inbound_total,
        m.inbound_bytes_total,
        m.inbound_dropped_rate,
        m.outbound_total,
        m.outbound_bytes_total,
        m.peer_rl_purged_total,
        m.in_hdr_total,
        m.in_inv_total,
        m.in_req_total,
        m.in_resp_total,
        m.out_hdr_total,
        m.out_inv_total,
        m.out_req_total,
        m.out_resp_total,
        m.out_errors_total,
        m.outbox_enq_total,
        m.outbox_deq_total,
        m.outbox_drop_total,
        m.outbox_depth,
        m.in_dedup_total,
        m.peers_known_total,
        m.peers_miner_total,
        m.peers_validator_total,
        m.peers_banned_total,
        c1,
        c5,
        c10,
        c50,
        c100,
        c500,
        count,
        sum_sec,
        count,
    );
    // Node-Metriken (Persistenz/Observer-Lag/Cache) anhängen
    let node_metrics = format!(
        "# HELP pc_node_persist_headers_total Total persisted headers\n# TYPE pc_node_persist_headers_total counter\npc_node_persist_headers_total {}\n\
# HELP pc_node_persist_headers_errors_total Total errors persisting headers\n# TYPE pc_node_persist_headers_errors_total counter\npc_node_persist_headers_errors_total {}\n\
# HELP pc_node_persist_payloads_total Total persisted payloads\n# TYPE pc_node_persist_payloads_total counter\npc_node_persist_payloads_total {}\n\
# HELP pc_node_persist_payloads_errors_total Total errors persisting payloads\n# TYPE pc_node_persist_payloads_errors_total counter\npc_node_persist_payloads_errors_total {}\n\
# HELP pc_node_inbound_obs_lagged_total Total dropped messages in node inbound observer due to lag\n# TYPE pc_node_inbound_obs_lagged_total counter\npc_node_inbound_obs_lagged_total {}\n\
# HELP pc_node_cache_headers_hits_total Cache hits for headers\n# TYPE pc_node_cache_headers_hits_total counter\npc_node_cache_headers_hits_total {}\n\
# HELP pc_node_cache_headers_misses_total Cache misses for headers\n# TYPE pc_node_cache_headers_misses_total counter\npc_node_cache_headers_misses_total {}\n\
# HELP pc_node_cache_payloads_hits_total Cache hits for payloads\n# TYPE pc_node_cache_payloads_hits_total counter\npc_node_cache_payloads_hits_total {}\n\
# HELP pc_node_cache_payloads_misses_total Cache misses for payloads\n# TYPE pc_node_cache_payloads_misses_total counter\npc_node_cache_payloads_misses_total {}\n\
# HELP pc_node_store_header_read_seconds Node store header read latency\n# TYPE pc_node_store_header_read_seconds histogram\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_store_header_read_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_store_header_read_seconds_sum {}\n\
pc_node_store_header_read_seconds_count {}\n\
# HELP pc_node_store_payload_read_seconds Node store payload read latency\n# TYPE pc_node_store_payload_read_seconds histogram\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_store_payload_read_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_store_payload_read_seconds_sum {}\n\
pc_node_store_payload_read_seconds_count {}\n\
# HELP pc_node_mempool_size Current mempool size\n# TYPE pc_node_mempool_size gauge\npc_node_mempool_size {}\n\
# HELP pc_node_mempool_accepted_total Total accepted txs into mempool\n# TYPE pc_node_mempool_accepted_total counter\npc_node_mempool_accepted_total {}\n\
# HELP pc_node_mempool_rejected_total Total rejected txs (stateless invalid)\n# TYPE pc_node_mempool_rejected_total counter\npc_node_mempool_rejected_total {}\n\
# HELP pc_node_mempool_duplicate_total Total duplicate txs ignored\n# TYPE pc_node_mempool_duplicate_total counter\npc_node_mempool_duplicate_total {}\n\
# HELP pc_node_mempool_conflict_total Total txs rejected due to mempool input conflicts\n# TYPE pc_node_mempool_conflict_total counter\npc_node_mempool_conflict_total {}\n\
# HELP pc_node_mempool_ttl_evict_total Total mempool evictions due to TTL\n# TYPE pc_node_mempool_ttl_evict_total counter\npc_node_mempool_ttl_evict_total {}\n\
# HELP pc_node_mempool_cap_evict_total Total mempool evictions due to cap limit\n# TYPE pc_node_mempool_cap_evict_total counter\npc_node_mempool_cap_evict_total {}\n\
# HELP pc_node_mempool_invalidated_total Total mempool txs invalidated by finalized state\n# TYPE pc_node_mempool_invalidated_total counter\npc_node_mempool_invalidated_total {}\n\
# HELP pc_node_mempool_shard_reject_total Total txs rejected due to wrong shard\n# TYPE pc_node_mempool_shard_reject_total counter\npc_node_mempool_shard_reject_total {}\n\
# HELP pc_node_proposer_built_total Total payloads built by proposer\n# TYPE pc_node_proposer_built_total counter\npc_node_proposer_built_total {}\n\
# HELP pc_node_proposer_last_size Last built payload micro_txs count\n# TYPE pc_node_proposer_last_size gauge\npc_node_proposer_last_size {}\n\
# HELP pc_node_proposer_errors_total Total proposer errors\n# TYPE pc_node_proposer_errors_total counter\npc_node_proposer_errors_total {}\n\
# HELP pc_node_proposer_pending Current pending payloads awaiting finalization\n# TYPE pc_node_proposer_pending gauge\npc_node_proposer_pending {}\n",
        n_hdr,
        n_hdr_err,
        n_pl,
        n_pl_err,
        n_lag,
        cache_hdr_hit,
        cache_hdr_miss,
        cache_pl_hit,
        cache_pl_miss,
        h1,
        h5,
        h10,
        h50,
        h100,
        h500,
        hdr_cnt,
        hdr_sum_sec,
        hdr_cnt,
        p1,
        p5,
        p10,
        p50,
        p100,
        p500,
        pl_cnt,
        pl_sum_sec,
        pl_cnt,
        mp_size,
        mp_acc,
        mp_rej,
        mp_dup,
        mp_conf,
        mp_ttl,
        mp_cap,
        mp_invld,
        mp_shard_rej,
        prop_built,
        prop_last,
        prop_err,
        prop_pending,
    );
    let persist_latency_metrics = format!(
        "# HELP pc_node_persist_seconds Node persist latency\n# TYPE pc_node_persist_seconds histogram\n\
pc_node_persist_seconds_bucket{{le=\"0.001\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.005\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.01\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.05\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.1\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"0.5\"}} {}\n\
pc_node_persist_seconds_bucket{{le=\"+Inf\"}} {}\n\
pc_node_persist_seconds_sum {}\n\
pc_node_persist_seconds_count {}\n",
        pb1, pb5, pb10, pb50, pb100, pb500, persist_cnt, persist_sum_sec, persist_cnt
    );
    let process_metrics = format!(
        "# HELP pc_node_process_cpu_percent Process CPU usage percent\n# TYPE pc_node_process_cpu_percent gauge\npc_node_process_cpu_percent {}\n\
# HELP pc_node_process_rss_bytes Process resident memory (RSS) in bytes\n# TYPE pc_node_process_rss_bytes gauge\npc_node_process_rss_bytes {}\n",
        cpu_pct, rss_bytes
    );
    let validator_metrics = format!(
        "# HELP pc_node_role_flags Configured role flags (0=fullnode, 1=validator, 2=miner)\n# TYPE pc_node_role_flags gauge\npc_node_role_flags {}\n\
# HELP pc_node_validator_id_configured Validator id/BLS key configured locally\n# TYPE pc_node_validator_id_configured gauge\npc_node_validator_id_configured {}\n\
# HELP pc_node_validator_stake Local validator stake (on-chain: staked UTXOs for validator record)\n# TYPE pc_node_validator_stake gauge\npc_node_validator_stake {}\n\
# HELP pc_node_validator_min_stake Minimum required stake\n# TYPE pc_node_validator_min_stake gauge\npc_node_validator_min_stake {}\n\
# HELP pc_node_validator_pop_ok Local BLS proof-of-possession OK\n# TYPE pc_node_validator_pop_ok gauge\npc_node_validator_pop_ok {}\n\
# HELP pc_node_validator_policy_ok Role policy allows this validator id\n# TYPE pc_node_validator_policy_ok gauge\npc_node_validator_policy_ok {}\n\
# HELP pc_node_validator_eligible Local eligibility (stake>=min && pop_ok && policy_ok)\n# TYPE pc_node_validator_eligible gauge\npc_node_validator_eligible {}\n\
# HELP pc_node_validator_conditions_ok Local conditions_ok used by validator_control\n# TYPE pc_node_validator_conditions_ok gauge\npc_node_validator_conditions_ok {}\n\
# HELP pc_node_validator_voting_enabled Effective voting/proposer enabled after controls\n# TYPE pc_node_validator_voting_enabled gauge\npc_node_validator_voting_enabled {}\n\
# HELP pc_node_validator_control_kill_switch Hard kill switch forces voting off\n# TYPE pc_node_validator_control_kill_switch gauge\npc_node_validator_control_kill_switch {}\n\
# HELP pc_node_validator_control_maintenance Maintenance mode forces voting off\n# TYPE pc_node_validator_control_maintenance gauge\npc_node_validator_control_maintenance {}\n\
# HELP pc_node_validator_control_manual_disable Manual disable flag\n# TYPE pc_node_validator_control_manual_disable gauge\npc_node_validator_control_manual_disable {}\n\
# HELP pc_node_validator_control_auto_reenable Auto re-enable when conditions ok\n# TYPE pc_node_validator_control_auto_reenable gauge\npc_node_validator_control_auto_reenable {}\n\
# HELP pc_node_validator_control_cooldown_until_epoch Cooldown end time (epoch seconds)\n# TYPE pc_node_validator_control_cooldown_until_epoch gauge\npc_node_validator_control_cooldown_until_epoch {}\n\
# HELP pc_node_validator_control_updated_at_epoch Last control update time (epoch seconds)\n# TYPE pc_node_validator_control_updated_at_epoch gauge\npc_node_validator_control_updated_at_epoch {}\n",
        role_flags,
        vid_cfg,
        v_stake,
        v_min,
        v_pop_ok,
        v_policy_ok,
        v_eligible,
        v_conditions_ok,
        v_enabled,
        vc_kill,
        vc_maint,
        vc_manual,
        vc_auto,
        vc_cooldown,
        vc_updated
    );
    let f_count = NODE_FINALITY_COUNT.load(Ordering::Relaxed);
    let f_sum_sec = (NODE_FINALITY_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
    let f50 = NODE_FINALITY_BUCKET_LE_50MS.load(Ordering::Relaxed);
    let f100 = f50 + NODE_FINALITY_BUCKET_LE_100MS.load(Ordering::Relaxed);
    let f500 = f100 + NODE_FINALITY_BUCKET_LE_500MS.load(Ordering::Relaxed);
    let f1s = f500 + NODE_FINALITY_BUCKET_LE_1S.load(Ordering::Relaxed);
    let f2s = f1s + NODE_FINALITY_BUCKET_LE_2S.load(Ordering::Relaxed);
    let f5s = f2s + NODE_FINALITY_BUCKET_LE_5S.load(Ordering::Relaxed);
    let finality_metrics = format!(
        "# HELP pc_node_finality_seconds End-to-end finality since mint\n# TYPE pc_node_finality_seconds histogram\npc_node_finality_seconds_bucket{{le=\"0.05\"}} {}\npc_node_finality_seconds_bucket{{le=\"0.1\"}} {}\npc_node_finality_seconds_bucket{{le=\"0.5\"}} {}\npc_node_finality_seconds_bucket{{le=\"1\"}} {}\npc_node_finality_seconds_bucket{{le=\"2\"}} {}\npc_node_finality_seconds_bucket{{le=\"5\"}} {}\npc_node_finality_seconds_bucket{{le=\"+Inf\"}} {}\npc_node_finality_seconds_sum {}\npc_node_finality_seconds_count {}\n# HELP pc_node_finality_events_total Finalization events observed\n# TYPE pc_node_finality_events_total counter\npc_node_finality_events_total {}\n# HELP pc_node_finality_mint_events_total Finalization events that contained at least one mint\n# TYPE pc_node_finality_mint_events_total counter\npc_node_finality_mint_events_total {}\n",
        f50, f100, f500, f1s, f2s, f5s, f_count, f_sum_sec, f_count, f_count, NODE_FINALITY_MINT_EVENTS.load(Ordering::Relaxed),
    );
    let v_count = NODE_VERIFY_COUNT.load(Ordering::Relaxed);
    let v_sum_sec = (NODE_VERIFY_SUM_MICROS.load(Ordering::Relaxed) as f64) / 1_000_000.0;
    let v1 = NODE_VERIFY_BUCKET_LE_1MS.load(Ordering::Relaxed);
    let v5 = v1 + NODE_VERIFY_BUCKET_LE_5MS.load(Ordering::Relaxed);
    let v10 = v5 + NODE_VERIFY_BUCKET_LE_10MS.load(Ordering::Relaxed);
    let v50 = v10 + NODE_VERIFY_BUCKET_LE_50MS.load(Ordering::Relaxed);
    let v100 = v50 + NODE_VERIFY_BUCKET_LE_100MS.load(Ordering::Relaxed);
    let v500 = v100 + NODE_VERIFY_BUCKET_LE_500MS.load(Ordering::Relaxed);
    let verify_metrics = format!(
        "# HELP pc_node_verify_seconds BLS fast aggregate verify latency\n# TYPE pc_node_verify_seconds histogram\npc_node_verify_seconds_bucket{{le=\"0.001\"}} {}\npc_node_verify_seconds_bucket{{le=\"0.005\"}} {}\npc_node_verify_seconds_bucket{{le=\"0.01\"}} {}\npc_node_verify_seconds_bucket{{le=\"0.05\"}} {}\npc_node_verify_seconds_bucket{{le=\"0.1\"}} {}\npc_node_verify_seconds_bucket{{le=\"0.5\"}} {}\npc_node_verify_seconds_bucket{{le=\"+Inf\"}} {}\npc_node_verify_seconds_sum {}\npc_node_verify_seconds_count {}\n",
        v1, v5, v10, v50, v100, v500, v_count, v_sum_sec, v_count,
    );
    let vote_metrics = format!(
        "# HELP pc_node_votes_sent_total Votes (attestations) observed for finality verification\n# TYPE pc_node_votes_sent_total counter\npc_node_votes_sent_total {}\n# HELP pc_node_votes_accepted_total Votes accepted by finality verification\n# TYPE pc_node_votes_accepted_total counter\npc_node_votes_accepted_total {}\n# HELP pc_node_votes_rejected_total Votes rejected by finality verification\n# TYPE pc_node_votes_rejected_total counter\npc_node_votes_rejected_total {}\n# HELP pc_node_votes_rate_limited_total Votes dropped by global finality-verify rate limit\n# TYPE pc_node_votes_rate_limited_total counter\npc_node_votes_rate_limited_total {}\n# HELP pc_node_committee_active_seats Current effective committee size used for finality verification\n# TYPE pc_node_committee_active_seats gauge\npc_node_committee_active_seats {}\n# HELP pc_node_committee_fee_eligible_seats Current number of fee-eligible committee seats\n# TYPE pc_node_committee_fee_eligible_seats gauge\npc_node_committee_fee_eligible_seats {}\n# HELP pc_node_committee_bootstrap_mode 1 if committee currently runs in bootstrap/emergency mode\n# TYPE pc_node_committee_bootstrap_mode gauge\npc_node_committee_bootstrap_mode {}\n",
        NODE_VOTE_SENT_TOTAL.load(Ordering::Relaxed),
        NODE_VOTE_ACCEPTED_TOTAL.load(Ordering::Relaxed),
        NODE_VOTE_REJECTED_TOTAL.load(Ordering::Relaxed),
        NODE_VOTE_RATE_LIMITED_TOTAL.load(Ordering::Relaxed),
        NODE_COMMITTEE_ACTIVE_SEATS.load(Ordering::Relaxed),
        NODE_COMMITTEE_FEE_ELIGIBLE_SEATS.load(Ordering::Relaxed),
        NODE_COMMITTEE_BOOTSTRAP_MODE.load(Ordering::Relaxed),
    );
    let anchor_graph_metrics = format!(
        "# HELP pc_node_anchor_graph_headers Anchor headers in the in-memory AnchorGraph cache\n# TYPE pc_node_anchor_graph_headers gauge\npc_node_anchor_graph_headers {}\n\
# HELP pc_node_anchor_graph_orphans Anchor headers currently held in the orphan pool\n# TYPE pc_node_anchor_graph_orphans gauge\npc_node_anchor_graph_orphans {}\n\
# HELP pc_node_anchor_graph_evict_total Total evicted headers due to AnchorGraph capacity limits\n# TYPE pc_node_anchor_graph_evict_total counter\npc_node_anchor_graph_evict_total {}\n\
# HELP pc_node_anchor_graph_orphan_dropped_total Total dropped orphans due to orphan pool capacity limits\n# TYPE pc_node_anchor_graph_orphan_dropped_total counter\npc_node_anchor_graph_orphan_dropped_total {}\n",
        NODE_ANCHOR_GRAPH_HEADERS.load(Ordering::Relaxed),
        NODE_ANCHOR_GRAPH_ORPHANS.load(Ordering::Relaxed),
        NODE_ANCHOR_GRAPH_EVICT_TOTAL.load(Ordering::Relaxed),
        NODE_ANCHOR_GRAPH_ORPHAN_DROPPED_TOTAL.load(Ordering::Relaxed),
    );
    let da_cfg_metrics = format!(
        "# HELP pc_node_da_gating_cfg_payload_wait_timeout_secs DA-gating payload wait timeout in seconds\n# TYPE pc_node_da_gating_cfg_payload_wait_timeout_secs gauge\npc_node_da_gating_cfg_payload_wait_timeout_secs {}\n\
# HELP pc_node_da_gating_cfg_retry_initial_delay_ms DA-gating retry initial delay in milliseconds\n# TYPE pc_node_da_gating_cfg_retry_initial_delay_ms gauge\npc_node_da_gating_cfg_retry_initial_delay_ms {}\n\
# HELP pc_node_da_gating_cfg_retry_max_delay_ms DA-gating retry max delay in milliseconds\n# TYPE pc_node_da_gating_cfg_retry_max_delay_ms gauge\npc_node_da_gating_cfg_retry_max_delay_ms {}\n\
# HELP pc_node_da_gating_cfg_retry_max_retries DA-gating retry max retries\n# TYPE pc_node_da_gating_cfg_retry_max_retries gauge\npc_node_da_gating_cfg_retry_max_retries {}\n\
# HELP pc_node_da_gating_cfg_retry_jitter_pct DA-gating retry jitter percent\n# TYPE pc_node_da_gating_cfg_retry_jitter_pct gauge\npc_node_da_gating_cfg_retry_jitter_pct {}\n",
        NODE_DA_GATING_CFG_PAYLOAD_WAIT_TIMEOUT_SECS.load(Ordering::Relaxed),
        NODE_DA_GATING_CFG_RETRY_INITIAL_DELAY_MS.load(Ordering::Relaxed),
        NODE_DA_GATING_CFG_RETRY_MAX_DELAY_MS.load(Ordering::Relaxed),
        NODE_DA_GATING_CFG_RETRY_MAX_RETRIES.load(Ordering::Relaxed),
        NODE_DA_GATING_CFG_RETRY_JITTER_PCT.load(Ordering::Relaxed),
    );
    let pow_miner_metrics = format!(
        "# HELP pc_node_pow_mining_active Whether the internal PoW miner is actively mining (1=yes, 0=no)\n# TYPE pc_node_pow_mining_active gauge\npc_node_pow_mining_active {}\n\
# HELP pc_node_pow_hashes_total Total hashes computed by internal PoW miner\n# TYPE pc_node_pow_hashes_total counter\npc_node_pow_hashes_total {}\n\
# HELP pc_node_pow_blocks_found_total Blocks (mints) found by internal PoW miner\n# TYPE pc_node_pow_blocks_found_total counter\npc_node_pow_blocks_found_total {}\n\
# HELP pc_node_pow_submit_ok_total Successful payload submissions by internal PoW miner\n# TYPE pc_node_pow_submit_ok_total counter\npc_node_pow_submit_ok_total {}\n\
# HELP pc_node_pow_submit_stale_total Stale submissions (chain tip changed) by internal PoW miner\n# TYPE pc_node_pow_submit_stale_total counter\npc_node_pow_submit_stale_total {}\n\
# HELP pc_node_pow_submit_err_total Failed payload submissions by internal PoW miner\n# TYPE pc_node_pow_submit_err_total counter\npc_node_pow_submit_err_total {}\n",
        NODE_POW_MINING_ACTIVE.load(Ordering::Relaxed),
        NODE_POW_HASHES_TOTAL.load(Ordering::Relaxed),
        NODE_POW_BLOCKS_FOUND_TOTAL.load(Ordering::Relaxed),
        NODE_POW_SUBMIT_OK_TOTAL.load(Ordering::Relaxed),
        NODE_POW_SUBMIT_STALE_TOTAL.load(Ordering::Relaxed),
        NODE_POW_SUBMIT_ERR_TOTAL.load(Ordering::Relaxed),
    );
    format!(
        "{}{}{}{}{}{}{}{}{}{}{}",
        body,
        node_metrics,
        persist_latency_metrics,
        process_metrics,
        validator_metrics,
        da_cfg_metrics,
        finality_metrics,
        verify_metrics,
        vote_metrics,
        anchor_graph_metrics,
        pow_miner_metrics
    )
}

pub(crate) fn run_p2p_metrics_serve(args: &MetricsServeArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = parse_quic_addr(&args.addr)?;
        if !addr.ip().is_loopback() {
            bail!("metrics addr darf nur auf 127.0.0.1/::1 binden (nicht öffentlich)");
        }

        // Use TcpListener to support ":0" and report the actual bound port.
        let listener = std::net::TcpListener::bind(addr)
            .map_err(|e| anyhow!("bind metrics addr '{}': {e}", &args.addr))?;
        let actual = listener
            .local_addr()
            .map_err(|e| anyhow!("metrics listener local_addr: {e}"))?;

        let make_svc = make_service_fn(|_conn| async move {
            Ok::<_, Infallible>(service_fn(|req: Request<Body>| async move {
                if req.uri().path() != "/metrics" {
                    let mut resp = Response::new(Body::from("Not Found"));
                    *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
                    resp.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("text/plain"),
                    );
                    return Ok::<_, Infallible>(resp);
                }
                let body = render_p2p_metrics_prometheus_text();
                let mut resp = Response::new(Body::from(body));
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"),
                );
                Ok::<_, Infallible>(resp)
            }))
        });

        let server = Server::from_tcp(listener)
            .map_err(|e| anyhow!("metrics server from_tcp: {e}"))?
            .serve(make_svc);
        println!("{{\"type\":\"metrics_serve\",\"addr\":\"{}\"}}", actual);

        let graceful = server.with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        graceful
            .await
            .map_err(|e| anyhow!("metrics server error: {e}"))
    })
}

pub(crate) fn run_da_run(args: &DaRunArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_da::async_svc as da_async;
        use pc_da::DaConfig;
        let cfg = DaConfig {
            max_chunks: args.max_chunks,
        };
        let (svc, handle) = da_async::spawn(cfg);
        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let res = handle
            .await
            .map_err(|e| anyhow!("da task join error: {e}"))?;
        res.map_err(|e| anyhow!("da loop error: {e}"))
    })
}

pub(crate) fn run_graph_insert_and_ack(args: &GraphInsertAndAckArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    // Datei laden
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let headers: Vec<AnchorHeader> = pc_codec::decode_exact(&buf)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;

    let d_max = args
        .d_max
        .unwrap_or_else(|| FeeSplitParams::recommended().d_max);

    let mut cache = AnchorGraphCache::new();
    for h in headers {
        let _ = cache.insert(h);
    }
    let dists = cache.compute_ack_distances(AnchorId(ack), args.k, d_max);

    // Optional Committee-Payout-Root
    let mut payout_root_hex: Option<String> = None;
    if let (Some(fees), Some(prop_idx)) = (args.fees, args.proposer_index) {
        if !args.recipients.is_empty() {
            let recipients = parse_hex32_list(&args.recipients)?;
            if recipients.len() != args.k as usize {
                bail!(
                    "recipients length ({}) must equal k ({})",
                    recipients.len(),
                    args.k
                );
            }
            if prop_idx >= recipients.len() {
                bail!(
                    "proposer_index {} out of range (k={})",
                    prop_idx,
                    recipients.len()
                );
            }
            let params = FeeSplitParams::recommended();
            let set = compute_committee_payout(fees, &params, &recipients, prop_idx, &dists)
                .map_err(|e| anyhow!("committee payout failed: {e}"))?;
            payout_root_hex = Some(hex::encode(set.payout_root()));
        }
    }

    // JSON-Ausgabe
    print!("{{\"k\":{},\"d_max\":{},\"distances\":[", args.k, d_max);
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        match d {
            Some(v) => print!("{}", v),
            None => print!("null"),
        }
    }
    if let Some(root) = payout_root_hex {
        println!("],\"committee_payout_root\":\"{}\"}}", root);
    } else {
        println!("]}}");
    }
    Ok(())
}

#[derive(Debug, Clone, Args)]
pub(crate) struct GraphInsertAndAckArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    pub ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    pub headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    pub k: u8,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    pub d_max: Option<u8>,
    /// Optional: Gesamt-Gebühren (wenn gesetzt, wird Committee-Payout-Root berechnet)
    #[arg(long)]
    pub fees: Option<u64>,
    /// Optional: Recipients (32-Byte Hex, komma-separiert) – muss Länge k haben
    #[arg(long, value_delimiter = ',')]
    pub recipients: Vec<String>,
    /// Optional: Proposer-Index (0-basiert)
    #[arg(long)]
    pub proposer_index: Option<usize>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct GraphAckArgs {
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    pub ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    pub headers_file: String,
    /// Committee-Größe k (Anzahl Seats)
    #[arg(long)]
    pub k: u8,
    /// Optional: d_max Kappung (Default: FeeSplitParams::recommended().d_max)
    #[arg(long)]
    pub d_max: Option<u8>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct P2pRunArgs {
    /// Maximale Anzahl Peers
    #[arg(long, default_value_t = 128)]
    pub max_peers: u16,
    /// Kademlia-Bootstrap-Peers (Multiaddr inkl. /p2p/PeerId), wiederholbar
    #[arg(long, value_delimiter = ',')]
    pub bootstrap_peer: Vec<String>,
    /// Kademlia-Bootstrap-Intervall in Sekunden (0 = deaktiviert)
    #[arg(long, default_value_t = 60)]
    pub kad_bootstrap_interval_secs: u64,
    /// Rate-Limits (optional)
    #[command(flatten)]
    pub rate: RateArgs,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct DaRunArgs {
    /// Maximale Anzahl Chunks im DA-Service
    #[arg(long, default_value_t = 4096)]
    pub max_chunks: u32,
}

pub(crate) fn load_vec_decodable<T: pc_codec::Decodable>(path: &str) -> Result<Vec<T>> {
    let mut f =
        std::fs::File::open(path).map_err(|e| anyhow!("cannot open file '{}': {e}", path))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read file '{}': {e}", path))?;
    let v: Vec<T> =
        pc_codec::decode_exact(&buf).map_err(|e| anyhow!("failed to decode Vec: {e}"))?;
    Ok(v)
}

pub(crate) fn load_header_files_for_consensus_rehydrate(
    store_dir: &str,
) -> (Vec<AnchorHeaderV2>, usize, usize, usize) {
    let headers_dir = Path::new(store_dir).join("headers");
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&headers_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => return (Vec::new(), 0, 0, 0),
    };
    files.sort();

    let mut loaded: Vec<AnchorHeaderV2> = Vec::with_capacity(files.len());
    let mut read_errors = 0usize;
    let mut decode_errors = 0usize;
    let mut digest_mismatch = 0usize;

    for path in files {
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".bin") else {
            continue;
        };
        let expected_id = match parse_hex32(stem) {
            Ok(id) => id,
            Err(_) => continue,
        };
        let buf = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                read_errors = read_errors.saturating_add(1);
                continue;
            }
        };
        let hdr = match pc_codec::decode_exact::<AnchorHeaderV2>(&buf) {
            Ok(h) => h,
            Err(_) => {
                decode_errors = decode_errors.saturating_add(1);
                continue;
            }
        };
        if hdr.id_digest() != expected_id {
            digest_mismatch = digest_mismatch.saturating_add(1);
            continue;
        }
        loaded.push(hdr);
    }

    (loaded, read_errors, decode_errors, digest_mismatch)
}

pub(crate) fn run_build_payload(args: &BuildPayloadArgs) -> Result<()> {
    // Events ggf. laden
    let mut micro_txs: Vec<MicroTx> = if let Some(p) = &args.microtx_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    // Optional: Mempool lesen und anhängen (deterministisch sortieren, deduplizieren, cap)
    if args.from_mempool {
        let base = match args.store_dir.as_deref() {
            Some(raw) => crate::store_path::resolve_store_dir_legacy(raw)?,
            None => crate::store_path::default_runtime_store_dir()?
                .to_string_lossy()
                .to_string(),
        };
        let mp_dir = std::path::Path::new(&base).join("mempool");
        if let Ok(rd) = std::fs::read_dir(&mp_dir) {
            for ent in rd.flatten() {
                if let Ok(meta) = ent.metadata() {
                    if !meta.is_file() {
                        continue;
                    }
                }
                if let Ok(mut f) = std::fs::File::open(ent.path()) {
                    let mut buf = Vec::new();
                    use std::io::Read as _;
                    if f.read_to_end(&mut buf).is_ok() {
                        if let Ok(tx) = pc_codec::decode_exact::<MicroTx>(&buf) {
                            if validate_microtx_sanity(&tx).is_ok() {
                                micro_txs.push(tx);
                            }
                        }
                    }
                }
            }
        }
        // Dedupe + Sort + Cap
        use std::collections::HashSet;
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut uniq: Vec<MicroTx> = Vec::with_capacity(micro_txs.len());
        for tx in micro_txs.into_iter() {
            let id = digest_microtx(&tx);
            if seen.insert(id) {
                uniq.push(tx);
            }
        }
        uniq.sort_unstable_by_key(digest_microtx);
        if uniq.len() > MAX_PAYLOAD_MICROTX {
            uniq.truncate(MAX_PAYLOAD_MICROTX);
        }
        micro_txs = uniq;
    }
    let mints: Vec<MintEvent> = if let Some(p) = &args.mints_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    let claims: Vec<ClaimEvent> = if let Some(p) = &args.claims_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };
    let evidences: Vec<EvidenceEvent> = if let Some(p) = &args.evidences_file {
        load_vec_decodable(p)?
    } else {
        Vec::new()
    };

    // Payout-Root bestimmen
    let payout_root = if let Some(payout_path) = &args.payout_file {
        let entries: Vec<PayoutEntry> = load_vec_decodable(payout_path)?;
        let set = PayoutSet { entries };
        set.payout_root()
    } else {
        // via Fees/Recipients/Acks/Attestors
        let fees = args
            .fees
            .ok_or_else(|| anyhow!("missing --fees when --payout-file is not provided"))?;
        let proposer_index = args.proposer_index.ok_or_else(|| {
            anyhow!("missing --proposer-index when --payout-file is not provided")
        })?;
        let recipients = parse_hex32_list(&args.recipients)?;
        let acks = parse_acks(&args.acks)?;
        let attestors = parse_hex32_list(&args.attestors)?;
        if recipients.len() != acks.len() {
            bail!(
                "recipients ({}) and acks ({}) length mismatch",
                recipients.len(),
                acks.len()
            );
        }
        if proposer_index >= recipients.len() {
            bail!(
                "proposer_index {} out of range (k={})",
                proposer_index,
                recipients.len()
            );
        }
        let params = FeeSplitParams::recommended();
        compute_total_payout_root(
            fees,
            &params,
            &recipients,
            proposer_index,
            &acks,
            &attestors,
        )?
    };

    let payload = AnchorPayload {
        version: 1,
        micro_txs,
        mints,
        claims,
        evidences,
        payout_root,
    };
    let root = compute_payload_hash(&payload);
    println!("{}", hex::encode(root));
    if let Some(out) = &args.out_file {
        let mut buf = Vec::with_capacity(payload.encoded_len());
        payload
            .encode(&mut buf)
            .map_err(|e| anyhow!("encode payload failed: {e}"))?;
        std::fs::write(out, &buf).map_err(|e| anyhow!("write out_file failed: {e}"))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Args)]
pub(crate) struct BuildPayloadArgs {
    /// Datei mit Vec<MicroTx> (pc-codec)
    #[arg(long)]
    pub microtx_file: Option<String>,
    /// Optional: auch aus dem Mempool lesen (store_dir/mempool)
    #[arg(long, default_value_t = false)]
    pub from_mempool: bool,
    /// Basisverzeichnis für Mempool/UTXO/Store
    #[arg(long)]
    pub store_dir: Option<String>,
    /// Datei mit Vec<MintEvent> (pc-codec)
    #[arg(long)]
    pub mints_file: Option<String>,
    /// Datei mit Vec<ClaimEvent> (pc-codec)
    #[arg(long)]
    pub claims_file: Option<String>,
    /// Datei mit Vec<EvidenceEvent> (pc-codec)
    #[arg(long)]
    pub evidences_file: Option<String>,
    /// Datei mit Vec<PayoutEntry> (pc-codec); alternativ fees/recipients/acks/attestors verwenden
    #[arg(long)]
    pub payout_file: Option<String>,

    /// Falls keine payout_file: Gebühren (in kleinster Einheit)
    #[arg(long)]
    pub fees: Option<u64>,
    /// Falls keine payout_file: Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    pub recipients: Vec<String>,
    /// Falls keine payout_file: Proposer-Index (0-basiert)
    #[arg(long)]
    pub proposer_index: Option<usize>,
    /// Falls keine payout_file: Ack-Distanzen (z. B. "1,2,none,4"; gleiche Länge wie recipients)
    #[arg(long, value_delimiter = ',')]
    pub acks: Vec<String>,
    /// Falls keine payout_file: Attestors (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    pub attestors: Vec<String>,

    /// Optional: schreibe AnchorPayload (pc-codec) in Datei
    #[arg(long)]
    pub out_file: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub(crate) enum Role {
    #[default]
    Fullnode,
    Validator,
    Miner,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct NodeRunArgs {
    /// Node-Rolle
    #[arg(long, value_enum)]
    pub role: Role,
    /// QUIC Listen-Adresse, z. B. 0.0.0.0:9000 (öffentlich) oder 127.0.0.1:9000 (nur lokal)
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub addr: String,
    #[arg(long, default_value_t = false)]
    pub unsafe_confirm: bool,
    /// Optional: schreibe Zertifikat (DER) in Datei
    #[arg(long)]
    pub cert_out: Option<String>,
    /// Pfad zu einer TOML-Konfigurationsdatei (optional)
    #[arg(long)]
    pub config: Option<String>,
    /// Pfad zur Genesis TOML (wenn gesetzt, hat Vorrang und bestimmt k strikt)
    #[arg(long)]
    pub genesis: Option<String>,
    /// Persistenz-Verzeichnis für Headers/Payloads (wird angelegt)
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    pub store_dir: String,
    /// Führe fsync() für Datei- und Verzeichnis-Operationen aus (Default: true)
    #[arg(long, default_value_t = true)]
    pub fsync: bool,
    /// Committee-Größe k (1..=64) für ConsensusEngine
    #[arg(long, default_value_t = 21)]
    pub k: u8,
    /// Header-Cache-Kapazität (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    pub cache_hdr_cap: Option<usize>,
    /// Payload-Cache-Budget in MB (0=aus). CLI-Override; wenn nicht gesetzt, aus Config gelesen
    #[arg(long)]
    pub cache_pl_mb: Option<usize>,
    /// Rate-Limits (optional)
    #[command(flatten)]
    pub rate: RateArgs,
    /// Mint-Amount (kleinste Einheit) (nur Rolle miner). Wenn nicht gesetzt: auto aus Mint-Hoehe.
    #[arg(long)]
    pub mint_amount: Option<u64>,
    /// Payout-Lock (32-Byte Hex Commitment) (nur Rolle miner)
    #[arg(long)]
    pub mint_lock: Option<String>,
    /// Intervall für Tx-Proposer in Millisekunden (nur Rolle validator)
    #[arg(long, default_value_t = 500)]
    pub tx_proposer_interval_ms: u64,
    /// Max. Anzahl MicroTxs pro Payload (Default: MAX_PAYLOAD_MICROTX)
    #[arg(long)]
    pub txs_per_payload: Option<usize>,
    /// Optionales Payload-Größenbudget (Bytes, encoded_len Summe); übersteigt Auswahl nicht diesen Wert
    #[arg(long)]
    pub payload_budget_bytes: Option<usize>,
    /// Validator-ID (64 Hex = 32 Bytes) für dynamischen Rollenwechsel
    #[arg(long)]
    pub validator_id: Option<String>,
    /// BLS Public Key (96 Hex = 48 Bytes) als Alternative zu validator_id
    #[arg(long)]
    pub bls_pk: Option<String>,
    /// Optional: HTTP Listen-Adresse für Prometheus /metrics (nur loopback), z. B. 127.0.0.1:9100
    #[arg(long)]
    pub metrics_addr: Option<String>,
}

impl Default for NodeRunArgs {
    fn default() -> Self {
        Self {
            role: Role::Fullnode,
            addr: "127.0.0.1:9000".to_string(),
            unsafe_confirm: false,
            cert_out: None,
            config: None,
            genesis: None,
            store_dir: crate::store_path::default_runtime_store_dir_string(),
            fsync: true,
            k: 21,
            cache_hdr_cap: None,
            cache_pl_mb: None,
            rate: RateArgs::default(),
            mint_amount: None,
            mint_lock: None,
            tx_proposer_interval_ms: 500,
            txs_per_payload: None,
            payload_budget_bytes: None,
            validator_id: None,
            bls_pk: None,
            metrics_addr: None,
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "phantom-node",
    version,
    about = "PhantomCoin Node Runtime",
    disable_help_subcommand = true
)]
pub(crate) struct NodeOpts {
    /// Dienstprogramme
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum Command {
    /// Starte die Node-Runtime (Default-Modus)
    Run(NodeRunArgs),
    /// Berechne die finale Payout-Merkle-Root (Committee + Attestors)
    PayoutRoot(PayoutArgs),
    /// Berechne die Committee-Payout-Root aus Header-Datei und ack_id
    CommitteePayoutFromHeaders(CommitteePayoutHeadersArgs),
    /// Baue einen AnchorPayload aus Event-Dateien oder Parametern
    BuildPayload(BuildPayloadArgs),
    /// Berechne Ack-Distanzen aus einer Header-Datei für eine gegebene ack_id
    GraphAck(GraphAckArgs),
    /// Füge Header in einen In-Memory DAG (AnchorGraphCache) ein und berechne Ack-Distanzen; optional Committee-Payout-Root
    GraphInsertAndAck(GraphInsertAndAckArgs),
    /// Starte den P2P-Service (Tokio-basiert); beendet mit Ctrl-C
    P2pRun(P2pRunArgs),
    /// Starte den DA-Service (Tokio-basiert); beendet mit Ctrl-C
    DaRun(DaRunArgs),
    /// Starte QUIC-Listener, gibt cert_der (Hex) aus und broadcastet P2P-Messages an Clients; beendet mit Ctrl-C
    P2pQuicListen(P2pQuicListenArgs),
    /// Verbinde zu QUIC-Server, forwarde lokale P2P-Outbox an Remote und verarbeite eingehende Nachrichten; beendet mit Ctrl-C
    P2pQuicConnect(P2pQuicConnectArgs),
    /// Injiziere Header-Announce-Messages über QUIC in einen Remote-Knoten
    P2pInjectHeaders(P2pInjectHeadersArgs),
    /// Injiziere Payload-Inventory (und optional Payloads) über QUIC in einen Remote-Knoten
    P2pInjectPayloads(P2pInjectPayloadsArgs),
    /// Gib aktuelle P2P-Metriken als JSON auf stdout aus
    P2pMetrics,
    /// Starte einen HTTP-Server, der Prometheus-kompatible Metriken liefert (Default: 127.0.0.1:9100)
    P2pMetricsServe(MetricsServeArgs),
    /// Starte einen einfachen Status-HTTP-Server (GET /status)
    StatusServe(StatusServeArgs),
    /// Konsens: Ack-Distanzen via ConsensusEngine aus Header-Datei berechnen
    ConsensusAckDists(ConsensusAckDistsArgs),
    /// Konsens: Committee-Payout-Root via ConsensusEngine berechnen
    ConsensusPayoutRoot(ConsensusPayoutRootArgs),
    /// Cache-Benchmark: misst Cache-Hits/Misses und Laufzeit gegen FileStore
    CacheBench(CacheBenchArgs),
    /// Datenbank-Wartung (RocksDB): Repair/Reset für lokale State-DBs
    #[command(subcommand)]
    Db(DbCmd),
    /// Validator: Control (Kill-Switch/Maintenance/Auto-Reenable)
    #[command(subcommand)]
    ValidatorControl(ValidatorControlCmd),
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum DbCmd {
    /// Versuche RocksDB-Reparatur für lokale State-DBs (best-effort).
    Repair(DbRepairArgs),
    /// Backup + Reset der lokalen State-DBs (legt neue leere DBs an).
    Reset(DbResetArgs),
}

#[derive(Debug, Clone, Args)]
pub(crate) struct DbRepairArgs {
    /// Store-Verzeichnis
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    pub store_dir: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct DbResetArgs {
    /// Store-Verzeichnis
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    pub store_dir: String,
    /// Confirm destructive reset (deletes/renames existing DB dirs).
    /// Destruktiven Reset bestaetigen (loescht/verschiebt bestehende DB-Verzeichnisse).
    #[arg(long, default_value_t = false)]
    pub yes: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ValidatorControlCmd {
    /// Zeige aktuelle Validator-Control Konfiguration
    Get(ValidatorControlGetArgs),
    /// Zeige Validator-Control Status (read-only Preview)
    Status(ValidatorControlStatusArgs),
    /// Setze Validator-Control Konfiguration
    Set(ValidatorControlSetArgs),
}

#[derive(Debug, Clone, Args)]
pub(crate) struct ValidatorControlGetArgs {
    /// Store-Verzeichnis
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    pub store_dir: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct ValidatorControlStatusArgs {
    /// Store-Verzeichnis
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    pub store_dir: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct ValidatorControlSetArgs {
    /// Store-Verzeichnis
    #[arg(long, default_value_t = crate::store_path::default_runtime_store_dir_string())]
    pub store_dir: String,
    /// Kill-Switch (true/false)
    #[arg(long)]
    pub kill_switch: Option<bool>,
    /// Maintenance Mode (true/false)
    #[arg(long)]
    pub maintenance: Option<bool>,
    /// Manual Disable (true/false)
    #[arg(long)]
    pub manual_disable: Option<bool>,
    /// Auto-Reenable (true/false)
    #[arg(long)]
    pub auto_reenable: Option<bool>,
    /// Optionaler Grund
    #[arg(long)]
    pub reason: Option<String>,
    /// Bestätigung für kritische Actions (erforderlich bei Kill/Maintenance/ManualDisable)
    #[arg(long)]
    pub confirm: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct MetricsServeArgs {
    /// HTTP Listen-Adresse, z. B. 127.0.0.1:9100
    #[arg(long, default_value = "127.0.0.1:9100")]
    pub addr: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct PayoutArgs {
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    pub fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    pub recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    pub proposer_index: usize,
    /// Ack-Distanzen (z. B. "1,2,none,4"; muss gleiche Länge wie recipients haben)
    #[arg(long, value_delimiter = ',')]
    pub acks: Vec<String>,
    /// Attestors (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    pub attestors: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct CommitteePayoutHeadersArgs {
    /// Gesamt-Gebühren (in kleinster Einheit)
    #[arg(long)]
    pub fees: u64,
    /// Recipients (32-Byte Hex, komma-separiert)
    #[arg(long, value_delimiter = ',')]
    pub recipients: Vec<String>,
    /// Proposer-Index (0-basiert)
    #[arg(long)]
    pub proposer_index: usize,
    /// ack_id (32-Byte Hex)
    #[arg(long)]
    pub ack_id: String,
    /// Pfad zur Binärdatei mit Vec<AnchorHeader> im pc-codec-Format
    #[arg(long)]
    pub headers_file: String,
}

pub(crate) fn compute_payload_hash(payload: &AnchorPayload) -> pc_crypto::Hash32 {
    payload_merkle_root(payload)
}

pub(crate) fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex for 32-byte id: {e}"))?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub(crate) fn parse_hex32_list(v: &[String]) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::with_capacity(v.len());
    for s in v {
        out.push(parse_hex32(s)?);
    }
    Ok(out)
}

pub(crate) fn parse_acks(v: &[String]) -> Result<Vec<Option<u8>>> {
    let mut out = Vec::with_capacity(v.len());
    for s in v {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("none") || t == "-" {
            out.push(None);
        } else {
            out.push(Some(
                t.parse::<u8>()
                    .map_err(|e| anyhow!("invalid ack distance '{t}': {e}"))?,
            ));
        }
    }
    Ok(out)
}

pub(crate) fn run_payout_root(args: &PayoutArgs) -> Result<()> {
    let recipients = parse_hex32_list(&args.recipients)?;
    let acks = parse_acks(&args.acks)?;
    let attestors = parse_hex32_list(&args.attestors)?;
    if recipients.len() != acks.len() {
        bail!(
            "recipients ({}) and acks ({}) length mismatch",
            recipients.len(),
            acks.len()
        );
    }
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let params = FeeSplitParams::recommended();
    let root = compute_total_payout_root(
        args.fees,
        &params,
        &recipients,
        args.proposer_index,
        &acks,
        &attestors,
    )?;
    println!("{}", hex::encode(root));
    Ok(())
}

pub(crate) fn run_committee_payout_from_headers(args: &CommitteePayoutHeadersArgs) -> Result<()> {
    let recipients = parse_hex32_list(&args.recipients)?;
    if args.proposer_index >= recipients.len() {
        bail!(
            "proposer_index {} out of range (k={})",
            args.proposer_index,
            recipients.len()
        );
    }
    let ack = parse_hex32(&args.ack_id)?;
    // Datei laden
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let headers: Vec<AnchorHeader> = pc_codec::decode_exact(&buf)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;
    let params = FeeSplitParams::recommended();
    let set = compute_committee_payout_from_headers(
        args.fees,
        &params,
        &recipients,
        args.proposer_index,
        AnchorId(ack),
        &headers,
        recipients.len() as u8,
    )?;
    println!("{}", hex::encode(set.payout_root()));
    Ok(())
}

pub(crate) fn run_graph_ack(args: &GraphAckArgs) -> Result<()> {
    let ack = parse_hex32(&args.ack_id)?;
    let mut f = std::fs::File::open(&args.headers_file)
        .map_err(|e| anyhow!("cannot open headers_file '{}': {e}", &args.headers_file))?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read headers_file '{}': {e}", &args.headers_file))?;
    let headers: Vec<AnchorHeader> = pc_codec::decode_exact(&buf)
        .map_err(|e| anyhow!("failed to decode Vec<AnchorHeader>: {e}"))?;
    let d_max = args
        .d_max
        .unwrap_or_else(|| FeeSplitParams::recommended().d_max);
    let dists = compute_ack_distances_for_seats(AnchorId(ack), &headers, args.k, d_max);
    // JSON Ausgabe minimal, ohne externe Abhängigkeit
    print!("{{\"k\":{},\"d_max\":{},\"distances\":[", args.k, d_max);
    for (i, d) in dists.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        match d {
            Some(v) => print!("{}", v),
            None => print!("null"),
        }
    }
    println!("]}}");
    Ok(())
}

pub(crate) fn print_p2p_json(msg: &P2pMessage) {
    match msg {
        P2pMessage::PrevoteAnnounce(h) => {
            println!(
                "{{\"type\":\"prevote_announce\",\"creator\":{},\"id\":\"{}\"}}",
                h.creator_index,
                hex::encode(h.id_digest())
            );
        }
        P2pMessage::PrecommitAnnounce(h) => {
            println!(
                "{{\"type\":\"precommit_announce\",\"creator\":{},\"id\":\"{}\"}}",
                h.creator_index,
                hex::encode(h.id_digest())
            );
        }
        P2pMessage::HeadersInv { ids } => {
            let mut out = String::from("{\"type\":\"headers_inv\",\"ids\":[");
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(id.0));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::PayloadInv { roots } => {
            let mut out = String::from("{\"type\":\"payload_inv\",\"roots\":[");
            for (i, r) in roots.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(r));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::TxInv { ids } => {
            let mut out = String::from("{\"type\":\"tx_inv\",\"ids\":[");
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(id));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::EvidenceInv { ids } => {
            let mut out = String::from("{\"type\":\"evidence_inv\",\"ids\":[");
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&hex::encode(id));
                out.push('"');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::Peers { peers } => {
            let mut out = String::from("{\"type\":\"peers\",\"peers\":[");
            for (i, p) in peers.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str("{\"ip\":\"");
                out.push_str(&hex::encode(&p.ip));
                out.push_str("\",\"port\":");
                out.push_str(&p.port.to_string());
                out.push('}');
            }
            out.push_str("]}");
            println!("{}", out);
        }
        P2pMessage::Ping => {
            println!("{{\"type\":\"ping\"}}");
        }
        P2pMessage::Pong => {
            println!("{{\"type\":\"pong\"}}");
        }
        P2pMessage::Req(_) => {
            println!("{{\"type\":\"req\"}}");
        }
        P2pMessage::Resp(_) => {
            println!("{{\"type\":\"resp\"}}");
        }
    }
}

pub(crate) fn run_p2p_quic_connect(args: &P2pQuicConnectArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        use pc_p2p::async_svc as p2p_async;
        use pc_p2p::P2pConfig;
        let cfg = P2pConfig {
            max_peers: 256,
            rate: None,
            peers_json_path: None,
        };
        let (svc, mut out_rx, handle) = p2p_async::spawn(cfg);
        let addr: SocketAddr = parse_quic_addr(&args.addr)?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let _reader = spawn_client_reader(conn.clone(), svc.clone(), None);
        let sink = QuicClientSink::new(conn);

        let forward_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                outbox_deq_inc();
                print_p2p_json(&msg);
                let _ = sink.deliver(msg).await;
            }
            Ok::<(), anyhow::Error>(())
        });

        if let Err(e) = tokio::signal::ctrl_c().await {
            return Err(anyhow!("failed to listen for ctrl_c: {e}"));
        }
        svc.shutdown().await?;
        let _ = forward_task.await;
        let res = handle
            .await
            .map_err(|e| anyhow!("p2p task join error: {e}"))?;
        res.map_err(|e| anyhow!("p2p loop error: {e}"))
    })
}

pub(crate) fn run_p2p_inject_headers(args: &P2pInjectHeadersArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = parse_quic_addr(&args.addr)?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let sink = QuicClientSink::new(conn);
        let headers: Vec<pc_types::AnchorHeaderV2> = load_vec_decodable(&args.headers_file)?;
        let mut sent = 0usize;
        for h in headers.into_iter() {
            sink.deliver_wait(pc_p2p::messages::explicit_announce_for_header(h))
                .await
                .map_err(|e| anyhow!("deliver header_announce failed: {e}"))?;
            sent += 1;
        }
        println!(
            "{{\"type\":\"inject\",\"kind\":\"headers\",\"count\":{}}}",
            sent
        );
        Ok(())
    })
}

pub(crate) fn run_p2p_inject_payloads(args: &P2pInjectPayloadsArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to build tokio runtime: {e}"))?;
    rt.block_on(async move {
        let addr: SocketAddr = parse_quic_addr(&args.addr)?;
        let cert_der = std::fs::read(&args.cert_file)
            .map_err(|e| anyhow!("read cert_file '{}': {e}", &args.cert_file))?;
        let client_cfg = client_config_from_cert(&cert_der)
            .map_err(|e| anyhow!("client config from cert failed: {e}"))?;
        let conn = connect(addr, client_cfg)
            .await
            .map_err(|e| anyhow!("quic connect failed: {e}"))?;
        let sink = QuicClientSink::new(conn);
        let payloads: Vec<pc_types::AnchorPayloadV3> =
            match load_vec_decodable::<pc_types::AnchorPayloadV3>(&args.payloads_file) {
                Ok(v3) => v3,
                Err(v3_err) => {
                    // Backward-compatibility for test/tool payload fixtures still encoded as V2.
                    match load_vec_decodable::<pc_types::AnchorPayloadV2>(&args.payloads_file) {
                        Ok(v2) => v2.iter().map(pc_types::payload_v2_to_v3).collect(),
                        Err(v2_err) => {
                            return Err(anyhow!(
                                "failed to decode payload vec as v3 ({v3_err}); also failed as v2 ({v2_err})"
                            ));
                        }
                    }
                }
            };
        let mut roots = Vec::with_capacity(payloads.len());
        for p in &payloads {
            roots.push(pc_types::payload_merkle_root_v3(p));
        }
        sink.deliver_wait(P2pMessage::PayloadInv {
            roots: roots.clone(),
        })
        .await
        .map_err(|e| anyhow!("deliver payload_inv failed: {e}"))?;
        if args.with_payloads {
            sink.deliver_wait(P2pMessage::Resp(RespMsg::Payloads { payloads }))
                .await
                .map_err(|e| anyhow!("deliver payloads failed: {e}"))?;
        }
        println!(
            "{{\"type\":\"inject\",\"kind\":\"payloads\",\"roots\":{}}}",
            roots.len()
        );
        Ok(())
    })
}

pub(crate) fn run_node_run(args: &NodeRunArgs) -> Result<()> {
    let (pow_miner, tx_proposer) = match args.role {
        Role::Fullnode => (false, false),
        Role::Validator => (false, true),
        Role::Miner => (true, false),
    };
    if pow_miner {
        if matches!(args.mint_amount, Some(0)) {
            bail!("--mint-amount muss > 0 sein");
        }
        if args.mint_lock.is_none() {
            bail!("--mint-lock ist für role=miner erforderlich");
        }
    }

    let listen_args = P2pQuicListenArgs {
        addr: args.addr.clone(),
        unsafe_confirm: args.unsafe_confirm,
        cert_out: args.cert_out.clone(),
        config: args.config.clone(),
        genesis: args.genesis.clone(),
        store_dir: args.store_dir.clone(),
        fsync: args.fsync,
        k: args.k,
        cache_hdr_cap: args.cache_hdr_cap,
        cache_pl_mb: args.cache_pl_mb,
        rate: args.rate.clone(),
        pow_miner,
        mint_amount: args.mint_amount,
        mint_lock: args.mint_lock.clone(),
        tx_proposer,
        tx_proposer_interval_ms: args.tx_proposer_interval_ms,
        txs_per_payload: args.txs_per_payload,
        payload_budget_bytes: args.payload_budget_bytes,
        validator_id: args.validator_id.clone(),
        bls_pk: args.bls_pk.clone(),
        peers_import: Vec::new(),
        metrics_addr: args.metrics_addr.clone(),
        da_payload_wait_timeout_secs: None,
        da_retry_initial_delay_ms: None,
        da_retry_max_delay_ms: None,
        da_retry_max_retries: None,
        da_retry_jitter_pct: None,
    };
    run_p2p_quic_listen(&listen_args)
}

pub(crate) fn resolve_store_dir(store_dir: &str) -> Result<String> {
    crate::store_path::resolve_store_dir_legacy(store_dir)
}

pub(crate) fn backup_path_unique(src: &Path, tag: &str) -> Result<PathBuf> {
    let ts = pcfg::now_secs().map_err(|e| anyhow!("now_secs failed: {e}"))?;
    let base = src.to_string_lossy().to_string();
    let mut dst = PathBuf::from(format!("{base}.{tag}.{ts}"));
    let mut i: u32 = 0;
    while dst.exists() {
        i = i.saturating_add(1);
        dst = PathBuf::from(format!("{base}.{tag}.{ts}.{i}"));
    }
    Ok(dst)
}

pub(crate) fn backup_dir(src: &Path, tag: &str) -> Result<Option<PathBuf>> {
    if !src.exists() {
        return Ok(None);
    }
    let dst = backup_path_unique(src, tag)?;
    std::fs::rename(src, &dst).map_err(|e| {
        anyhow!(
            "failed to backup '{}' -> '{}': {e}",
            src.display(),
            dst.display()
        )
    })?;
    Ok(Some(dst))
}

pub(crate) fn run_db_repair(args: &DbRepairArgs) -> Result<()> {
    let store_dir = resolve_store_dir(&args.store_dir)?;
    #[cfg(not(feature = "rocksdb"))]
    {
        let _ = store_dir;
        bail!("rocksdb feature not enabled");
    }
    #[cfg(feature = "rocksdb")]
    {
        let utxo = Path::new(&store_dir).join("utxo");
        let utxo_secondary = Path::new(&store_dir).join("utxo.secondary");
        let state = Path::new(&store_dir).join("mempool").join("state.rocks");

        let mut repaired: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        if utxo.exists() {
            match pc_state::RocksDbBackend::repair(&utxo.to_string_lossy()) {
                Ok(()) => repaired.push(utxo.to_string_lossy().to_string()),
                Err(e) => errors.push(format!("utxo repair failed: {e}")),
            }
        }
        if state.exists() {
            match pc_state::RocksDbBackend::repair(&state.to_string_lossy()) {
                Ok(()) => repaired.push(state.to_string_lossy().to_string()),
                Err(e) => errors.push(format!("state.rocks repair failed: {e}")),
            }
        }

        // Secondary view can always be deleted and recreated.
        let _ = std::fs::remove_dir_all(&utxo_secondary);
        let _ = std::fs::create_dir_all(&utxo_secondary);

        let body = serde_json::json!({
            "ok": errors.is_empty(),
            "store_dir": store_dir,
            "repaired": repaired,
            "errors": errors,
        })
        .to_string();
        println!("{body}");
        Ok(())
    }
}

pub(crate) fn run_db_reset(args: &DbResetArgs) -> Result<()> {
    let store_dir = resolve_store_dir(&args.store_dir)?;
    if !args.yes {
        bail!(
            "db reset ist destruktiv (lokale DBs werden zurueckgesetzt). Fuehre erneut mit --yes aus, um zu bestaetigen."
        );
    }
    #[cfg(not(feature = "rocksdb"))]
    {
        let _ = store_dir;
        bail!("rocksdb feature not enabled");
    }
    #[cfg(feature = "rocksdb")]
    {
        let utxo = Path::new(&store_dir).join("utxo");
        let utxo_secondary = Path::new(&store_dir).join("utxo.secondary");
        let state = Path::new(&store_dir).join("mempool").join("state.rocks");

        let utxo_backup = backup_dir(&utxo, "corrupt")?;
        let secondary_backup = backup_dir(&utxo_secondary, "corrupt")?;
        let state_backup = backup_dir(&state, "corrupt")?;

        // Recreate empty dirs to make subsequent opens more predictable.
        let _ = std::fs::create_dir_all(&utxo);
        let _ = std::fs::create_dir_all(&utxo_secondary);
        let _ = std::fs::create_dir_all(Path::new(&store_dir).join("mempool"));

        let body = serde_json::json!({
            "ok": true,
            "store_dir": store_dir,
            "backups": {
                "utxo": utxo_backup.as_ref().map(|p| p.to_string_lossy().to_string()),
                "utxo_secondary": secondary_backup.as_ref().map(|p| p.to_string_lossy().to_string()),
                "state_rocks": state_backup.as_ref().map(|p| p.to_string_lossy().to_string()),
            }
        })
        .to_string();
        println!("{body}");
        Ok(())
    }
}

pub(crate) fn run_validator_control_get(args: &ValidatorControlGetArgs) -> Result<()> {
    let store_dir = resolve_store_dir(&args.store_dir)?;
    let path = validator_control_path(&store_dir);
    let control = if path.exists() {
        load_validator_control(&path)
    } else {
        pcfg::default_validator_control_fail_closed()
            .map_err(|e| anyhow!("now_secs failed: {e}"))?
    };
    let out = serde_json::to_string_pretty(&control)
        .map_err(|e| anyhow!("serialize validator_control: {e}"))?;
    println!("{out}");
    Ok(())
}

pub(crate) fn run_validator_control_status(args: &ValidatorControlStatusArgs) -> Result<()> {
    let store_dir = resolve_store_dir(&args.store_dir)?;
    let path = validator_control_path(&store_dir);
    let (control, source) = if path.exists() {
        (load_validator_control(&path), "file")
    } else {
        (
            pcfg::default_validator_control_fail_closed()
                .map_err(|e| anyhow!("now_secs failed: {e}"))?,
            "default",
        )
    };
    let now = pcfg::now_secs().map_err(|e| anyhow!("now_secs failed: {e}"))?;
    let disabled = control.kill_switch
        || control.maintenance
        || control.manual_disable
        || control.cooldown_until > now;
    let status = if disabled { "DISABLED" } else { "ENABLED" };
    println!("Validator Control Status ({source})");
    println!("status: {status}");
    println!("kill_switch: {}", control.kill_switch);
    println!("maintenance: {}", control.maintenance);
    println!("manual_disable: {}", control.manual_disable);
    println!("auto_reenable: {}", control.auto_reenable);
    println!("cooldown_until: {}", control.cooldown_until);
    println!("updated_at: {}", control.updated_at);
    println!(
        "last_changed_by: {}",
        if control.last_changed_by.is_empty() {
            "-"
        } else {
            &control.last_changed_by
        }
    );
    println!(
        "reason: {}",
        if control.reason.is_empty() {
            "-"
        } else {
            &control.reason
        }
    );
    Ok(())
}

pub(crate) fn run_validator_control_set(args: &ValidatorControlSetArgs) -> Result<()> {
    let store_dir = resolve_store_dir(&args.store_dir)?;
    let path = validator_control_path(&store_dir);
    let mut current = if path.exists() {
        load_validator_control(&path)
    } else {
        pcfg::default_validator_control_fail_closed()
            .map_err(|e| anyhow!("now_secs failed: {e}"))?
    };
    let before = current.clone();

    if let Some(v) = args.kill_switch {
        current.kill_switch = v;
    }
    if let Some(v) = args.maintenance {
        current.maintenance = v;
    }
    if let Some(v) = args.manual_disable {
        current.manual_disable = v;
    }
    if let Some(v) = args.auto_reenable {
        current.auto_reenable = v;
    }
    if let Some(ref r) = args.reason {
        current.reason = r.clone();
    }

    let critical_changed = before.kill_switch != current.kill_switch
        || before.maintenance != current.maintenance
        || before.manual_disable != current.manual_disable;
    if critical_changed {
        let ok = args
            .confirm
            .as_deref()
            .map(|s| s == "I_UNDERSTAND")
            .unwrap_or(false);
        if !ok {
            bail!("critical change requires --confirm I_UNDERSTAND");
        }
    }

    current.updated_at = pcfg::now_secs().map_err(|e| anyhow!("now_secs failed: {e}"))?;
    current.last_changed_by = "cli".to_string();
    pcfg::save_validator_control_to_file(&current, &path)
        .map_err(|e| anyhow!("validator_control save failed: {e}"))?;
    println!(
        "{{\"type\":\"validator_control_set\",\"path\":\"{}\"}}",
        path.display()
    );
    Ok(())
}
