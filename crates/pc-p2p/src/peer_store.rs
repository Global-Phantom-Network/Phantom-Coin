use crate::messages::PeerInfo;
use pc_crypto::blake3_32;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

const MAX_PEERS: usize = 256;
const MAX_NEW_PEERS_PER_MERGE: usize = 32;
const TTL_ANCHORS: u64 = 100_800; // ~7 Tage bei 6s Anchor-Zeit
const MAX_CERT_DER_LEN: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPeer {
    pub addr: String,
    pub cert_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_der_hex: Option<String>,
    pub last_seen_anchor: u64,
    pub role_flags: u8,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PeerStore {
    pub peers: HashMap<String, StoredPeer>,
}

impl PeerStore {
    pub fn load(path: &Path) -> Self {
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(path) {
                if let Ok(store) = serde_json::from_str(&data) {
                    return store;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)
    }

    pub fn add_peer(
        &mut self,
        addr: SocketAddr,
        cert_der: &[u8],
        role_flags: u8,
        anchor_index: u64,
    ) {
        // Only store peers we can actually dial via QUIC: must have a certificate and a real port.
        // This prevents PeerStore poisoning with undialable entries (empty cert / port 0).
        if cert_der.is_empty() || cert_der.len() > MAX_CERT_DER_LEN || addr.port() == 0 {
            return;
        }
        // Defensive: reject obviously invalid destination IPs (never dialable).
        let ip = addr.ip();
        if ip.is_unspecified() || ip.is_multicast() {
            return;
        }
        if let std::net::IpAddr::V4(v4) = ip {
            if v4.is_broadcast() {
                return;
            }
        }

        // Cryptographic fingerprint over the (bounded) DER bytes.
        // Kryptografischer Fingerprint über die (gebundenen) DER-Bytes.
        let cert_bytes = cert_der.get(..MAX_CERT_DER_LEN).unwrap_or(cert_der);
        let fp = blake3_32(cert_bytes);
        let fingerprint = bytes_to_hex(&fp);
        let cert_der_hex = if cert_der.len() <= MAX_CERT_DER_LEN && !cert_der.is_empty() {
            Some(bytes_to_hex(cert_der))
        } else {
            None
        };
        let key = addr.to_string();

        self.peers.insert(
            key.clone(),
            StoredPeer {
                addr: key,
                cert_fingerprint: fingerprint,
                cert_der_hex,
                last_seen_anchor: anchor_index,
                role_flags,
            },
        );

        self.prune(anchor_index);
    }

    pub fn prune(&mut self, current_anchor: u64) {
        self.peers
            .retain(|_, p| current_anchor.saturating_sub(p.last_seen_anchor) < TTL_ANCHORS);

        if self.peers.len() > MAX_PEERS {
            let mut entries: Vec<_> = self.peers.iter().collect();
            entries.sort_by_key(|(_, p)| std::cmp::Reverse(p.last_seen_anchor));
            let to_keep: std::collections::HashSet<_> = entries
                .into_iter()
                .take(MAX_PEERS)
                .map(|(k, _)| k.clone())
                .collect();
            self.peers.retain(|k, _| to_keep.contains(k));
        }
    }

    pub fn to_peer_infos(&self) -> Vec<PeerInfo> {
        self.peers
            .values()
            .filter_map(|p| {
                let addr: SocketAddr = p.addr.parse().ok()?;
                let ip = addr.ip();
                let ip_bytes = match ip {
                    std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                    std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                let cert_der = p
                    .cert_der_hex
                    .as_ref()
                    .and_then(|hex| hex_to_bytes(hex))
                    .filter(|b| b.len() <= MAX_CERT_DER_LEN)
                    .unwrap_or_default();
                Some(PeerInfo {
                    ip: ip_bytes,
                    port: addr.port(),
                    cert_der,
                    last_seen: p.last_seen_anchor,
                    role_flags: p.role_flags,
                })
            })
            .collect()
    }

    pub fn connect_targets(&self, max: usize) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        for p in self.peers.values() {
            if out.len() >= max {
                break;
            }
            let addr: SocketAddr = match p.addr.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let cert_hex = match p.cert_der_hex.as_ref() {
                Some(h) => h,
                None => continue,
            };
            let cert = match hex_to_bytes(cert_hex) {
                Some(b) if !b.is_empty() && b.len() <= MAX_CERT_DER_LEN => b,
                _ => continue,
            };
            out.push((addr, cert));
        }
        out
    }

    pub fn from_peer_infos(peers: &[PeerInfo], current_anchor: u64) -> Self {
        let mut store = Self::default();
        for p in peers {
            // Reject undialable peers early (empty/oversized certs, port 0).
            if p.cert_der.is_empty() || p.cert_der.len() > MAX_CERT_DER_LEN || p.port == 0 {
                continue;
            }
            let ip = if p.ip.len() == 4 {
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    p.ip.first().copied().unwrap_or(0),
                    p.ip.get(1).copied().unwrap_or(0),
                    p.ip.get(2).copied().unwrap_or(0),
                    p.ip.get(3).copied().unwrap_or(0),
                ))
            } else if p.ip.len() == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&p.ip);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            } else {
                continue;
            };
            // Defensive: never dial unspecified/multicast/broadcast addrs from PEX.
            if ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            if let std::net::IpAddr::V4(v4) = ip {
                if v4.is_broadcast() {
                    continue;
                }
            }
            let addr = SocketAddr::new(ip, p.port);
            store.add_peer(addr, &p.cert_der, p.role_flags, current_anchor);
        }
        store
    }

    pub fn merge(&mut self, other: &PeerStore, current_anchor: u64) {
        let mut newly_added = 0usize;
        for (key, peer) in &other.peers {
            match self.peers.get(key) {
                Some(existing) if existing.last_seen_anchor >= peer.last_seen_anchor => {}
                _ => {
                    if !self.peers.contains_key(key) {
                        if newly_added >= MAX_NEW_PEERS_PER_MERGE {
                            continue;
                        }
                        newly_added = newly_added.saturating_add(1);
                    }
                    self.peers.insert(key.clone(), peer.clone());
                }
            }
        }
        self.prune(current_anchor);
    }

    /// Zählt Peers nach role_flags: (total, fullnode, validator, miner)
    pub fn count_by_role(&self) -> PeerRoleCounts {
        use crate::messages::{ROLE_FULLNODE, ROLE_MINER, ROLE_VALIDATOR};
        let mut counts = PeerRoleCounts::default();
        for p in self.peers.values() {
            counts.total += 1;
            match p.role_flags {
                ROLE_FULLNODE => counts.fullnode += 1,
                ROLE_VALIDATOR => counts.validator += 1,
                ROLE_MINER => counts.miner += 1,
                _ => counts.fullnode += 1, // unknown → treat as fullnode
            }
        }
        counts
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PeerRoleCounts {
    pub total: u64,
    pub fullnode: u64,
    pub validator: u64,
    pub miner: u64,
}

impl From<&PeerInfo> for Option<StoredPeer> {
    fn from(p: &PeerInfo) -> Self {
        if p.cert_der.is_empty() || p.cert_der.len() > MAX_CERT_DER_LEN || p.port == 0 {
            return None;
        }
        let ip = if p.ip.len() == 4 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                p.ip.first().copied().unwrap_or(0),
                p.ip.get(1).copied().unwrap_or(0),
                p.ip.get(2).copied().unwrap_or(0),
                p.ip.get(3).copied().unwrap_or(0),
            ))
        } else if p.ip.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&p.ip);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        } else {
            return None;
        };
        if ip.is_unspecified() || ip.is_multicast() {
            return None;
        }
        if let std::net::IpAddr::V4(v4) = ip {
            if v4.is_broadcast() {
                return None;
            }
        }
        let addr = SocketAddr::new(ip, p.port);
        let cert_der: &[u8] = &p.cert_der;
        let fp = blake3_32(cert_der);
        let fingerprint = bytes_to_hex(&fp);
        let cert_der_hex = if !cert_der.is_empty() {
            Some(bytes_to_hex(cert_der))
        } else {
            None
        };
        Some(StoredPeer {
            addr: addr.to_string(),
            cert_fingerprint: fingerprint,
            cert_der_hex,
            last_seen_anchor: p.last_seen,
            role_flags: p.role_flags,
        })
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex_digit(bytes.get(i).copied()?)?;
        let lo = from_hex_digit(bytes.get(i + 1).copied()?)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ROLE_FULLNODE;

    #[test]
    fn add_and_prune() {
        let mut store = PeerStore::default();
        let anchor = 1000u64;
        for i in 0..300u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 9000 + i).parse().unwrap();
            store.add_peer(addr, &[i as u8; 32], ROLE_FULLNODE, anchor);
        }
        assert!(store.peers.len() <= MAX_PEERS);
    }

    #[test]
    fn roundtrip_json() {
        let mut store = PeerStore::default();
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        store.add_peer(addr, &[1u8; 32], ROLE_FULLNODE, 100);

        let json = serde_json::to_string(&store).unwrap();
        let loaded: PeerStore = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.peers.len(), 1);
    }

    #[test]
    fn merge_limits_new_peers_per_call() {
        let mut base = PeerStore::default();
        let mut incoming = PeerStore::default();
        let anchor = 1_000u64;

        for i in 0..200u16 {
            let addr: SocketAddr = format!("10.0.0.{}:{}", (i % 250) + 1, 9_000 + i)
                .parse()
                .unwrap();
            incoming.add_peer(addr, &[i as u8; 32], ROLE_FULLNODE, anchor);
        }

        base.merge(&incoming, anchor);
        assert!(
            base.peers.len() <= MAX_NEW_PEERS_PER_MERGE,
            "new peers added in one merge must be capped"
        );
    }
}
