# Network Bootstrap Guide

Anleitung zum Starten eines Phantom-Coin Netzwerks mit 3 Nodes (1 Validator, 2 Fullnodes) und 1 Miner.

## Voraussetzungen

- Kompilierte Binaries: `phantom-node`, `phantom-miner`
- Gemeinsames Datenverzeichnis pro Node, z. B. `/var/lib/phantom-coin/validator`, `/var/lib/phantom-coin/fullnode1`, `/var/lib/phantom-coin/fullnode2`
- Genesis-Datei (`genesis_note.bin`) für alle Nodes identisch

## 1. Genesis-Datei erstellen

Erstelle eine deterministische Genesis-Datei für das Netzwerk:

```bash
cargo run --bin genesis_bootstrap -- \
  --mempool-dir /var/lib/phantom-coin/validator/mempool \
  --network-name "phantom-testnet" \
  --shards-initial 1 \
  --committee-k 3 \
  --txs-per-payload 100 \
  --features 1
```

Ausgabe (JSON):
```json
{"type":"genesis_note_written","file":"/var/lib/phantom-coin/validator/mempool/genesis_note.bin","network_name":"phantom-testnet","network_id":"<hex>"}
```

Kopiere `genesis_note.bin` in alle Node-Verzeichnisse:
```bash
cp /var/lib/phantom-coin/validator/mempool/genesis_note.bin /var/lib/phantom-coin/fullnode1/mempool/
cp /var/lib/phantom-coin/validator/mempool/genesis_note.bin /var/lib/phantom-coin/fullnode2/mempool/
```

### Optional: Role-Policy (Genesis-Whitelist)
Wenn du Miner/Validatoren einschränken willst, erstelle eine `role_policy.json` und binde sie an die Genesis:

```json
{
  "version": 1,
  "mint_locks": ["<32-byte-hex-lock>"],
  "validator_ids": ["<32-byte-hex-validator-id>"]
}
```

Dann Genesis mit Policy erzeugen:
```bash
cargo run --bin genesis_bootstrap -- \
  --mempool-dir /var/lib/phantom-coin/validator/mempool \
  --network-name "phantom-testnet" \
  --shards-initial 1 \
  --committee-k 3 \
  --txs-per-payload 100 \
  --features 1 \
  --role-policy /var/lib/phantom-coin/validator/mempool/role_policy.json
```

Wichtig:
- `role_policy.json` muss identisch in **allen** Node-Mempool-Verzeichnissen liegen.
- Leere Listen bedeuten **keine Einschränkung** (Policy ist dann nur ein Commitment).

## 2. TLS-Zertifikate

Jeder Node generiert beim Start ein selbstsigniertes TLS-Zertifikat für QUIC-Verbindungen.

Mit `--cert-out` wird das Zertifikat in eine Datei geschrieben:
```bash
phantom-node p2p-quic-listen --addr 127.0.0.1:9000 --store-dir /var/lib/phantom-coin/validator --cert-out /var/lib/phantom-coin/validator/p2p_quic_cert.der
```

Andere Nodes verwenden dieses Zertifikat mit `--cert-file` um sich zu verbinden.

## 3. Bootstrap Peers JSON

Erstelle `bootstrap_peers.json` im Store-Verzeichnis:

```json
{
  "peers": [
    {
      "addr": "seed1.phantom.local:9000",
      "cert_file": "/var/lib/phantom-coin/validator/p2p_quic_cert.der"
    }
  ]
}
```

**Format:**
- `addr`: `IP:Port`, `Host:Port` (DNS-Seed) **oder** Multiaddr `/ip4|ip6/.../udp/.../quic-v1[/p2p/<peerId>]`
- `cert_file`: Pfad zum TLS-Zertifikat des Peers (Pinning)

**DNS-Seed (Variante A, sicher):**
- DNS wird nur für die Auflösung genutzt (A/AAAA).
- Die Verbindung klappt **nur** mit dem passenden Zertifikat (`cert_file`).
- DNS liefert also nur Ziele, Authentizität bleibt am Zertifikat.
> Hinweis: DNS‑Multiaddr (`/dns4/...`) wird nicht geparst – nutze dafür `Host:Port`.

**Peer-Exchange (automatisch):**
- Der Node sammelt bekannte Peers und speichert sie in `<store-dir>/peers.json`.
- Beim Neustart werden zuerst diese Peers genutzt; nur wenn leer, greift er auf `bootstrap_peers.json` (DNS) zurück.
- Health‑Check: Peers, die nach mehreren Verbindungsversuchen nicht erreichbar sind, werden automatisch aus `peers.json` entfernt.
- Periodisch: Peer‑Exchange läuft **alle 12 Stunden** (kleine Stichprobe).
- On‑Demand: Wenn zu wenige Outbound‑Peers aktiv sind, wird zusätzlich **stichprobenartig** nach Peers gefragt (mit Jitter).

**Ping/Pong (Liveness):**
- Ping/Pong ist **minimal**: nur der Message‑Tag (Payload = **1 Byte**).
- Identitätsprüfung findet **im QUIC/TLS‑Handshake** statt (Zertifikat‑Pinning / optional mTLS), **nicht** im Ping selbst.
- Vorteil: sehr geringe Netzlast, Sicherheit bleibt über die bestehende Verbindung.

**Peer‑Liste manuell importieren:**
```bash
phantom-node p2p-quic-listen \
  --addr 127.0.0.1:9000 \
  --store-dir /var/lib/phantom-coin/validator \
  --peers-import ./peers.json \
  --peers-import ./bootstrap_peers.json
```
Unterstützte Formate:
- `peers.json` (dynamische Peer‑Liste inkl. Zertifikate)
- `bootstrap_peers.json` (addr + cert_file)

## 4. Netzwerk starten

### Validator (Node 1)
```bash
phantom-node p2p-quic-listen \
  --addr 127.0.0.1:9000 \
  --store-dir /var/lib/phantom-coin/validator \
  --cert-out /var/lib/phantom-coin/validator/p2p_quic_cert.der
```

### Fullnode 1 (Node 2)
```bash
phantom-node p2p-quic-listen \
  --addr 127.0.0.1:9001 \
  --store-dir /var/lib/phantom-coin/fullnode1 \
  --cert-out /var/lib/phantom-coin/fullnode1/p2p_quic_cert.der
```

### Fullnode 2 (Node 3)
```bash
phantom-node p2p-quic-listen \
  --addr 127.0.0.1:9002 \
  --store-dir /var/lib/phantom-coin/fullnode2 \
  --cert-out /var/lib/phantom-coin/fullnode2/p2p_quic_cert.der
```

### Bootstrap-Verbindungen herstellen
- **Wallet GUI**: Im Node-Tab `P2P Start (Auto-Connect)` nutzt die Einträge aus `bootstrap_peers.json`.
- **CLI**: Für jeden Peer:
```bash
phantom-node p2p-quic-connect \
  --addr 127.0.0.1:9000 \
  --cert-file /var/lib/phantom-coin/validator/p2p_quic_cert.der \
  --network-id <32-byte-hex-network-id>
```

## 5. Mint RPC Server starten

Auf dem Validator-Node:
```bash
phantom-node mint-rpc \
  --addr 127.0.0.1:9090 \
  --store-dir /var/lib/phantom-coin/validator \
  --pow-bits 20
```
Hinweis: `mint-rpc` verwendet standardmäßig `--store-dir/mempool`. Ein abweichendes `--mempool-dir` oder `--store-dir` ist im Live-Betrieb nicht unterstützt; der Node behandelt einen Marker-Mismatch fail-closed und beendet sich, statt fremde Mint-Dateien zu ingestieren.

## 6. Miner starten

```bash
phantom-miner mine \
  --rpc-url http://127.0.0.1:9090 \
  --lock <deine-lock-adresse> \
  --threads 4 \
  --progress-secs 10
```

Der Miner:
1. Holt ein Mint-Template von `/mint/template`
2. Führt Proof-of-Work durch (findet Nonce mit ausreichender Difficulty)
3. Sendet das fertige Mint an `/mint/submit`

## 7. Payload/Header Injection (optional)

Für Tests oder manuelle Synchronisation:

### Headers injizieren
```bash
phantom-node p2p-inject-headers \
  --addr 127.0.0.1:9000 \
  --cert-file /var/lib/phantom-coin/validator/p2p_quic_cert.der \
  --headers-file ./headers.bin
```

### Payloads injizieren
```bash
phantom-node p2p-inject-payloads \
  --addr 127.0.0.1:9000 \
  --cert-file /var/lib/phantom-coin/validator/p2p_quic_cert.der \
  --payloads-file ./payloads.bin \
  --with-payloads
```

## 8. Verifizierung

Nach einem erfolgreichen Mint prüfen:

1. **SupplyState** in `/var/lib/phantom-coin/*/mempool/supply_state.json`:
   ```json
   {"mint_height":1,"total_supply":5000000000,"last_mint_id":"<hex>"}
   ```

2. **Konsistenz**: `supply_state.json` muss auf allen Nodes identisch sein.

3. **UTXO**: Genau ein Mint-UTXO existiert im UTXO-Set.

4. **Validierung**:
   - Double-Mints werden abgelehnt (prev_mint_id muss korrekt sein)
   - Ungültige PoW-Difficulty wird abgelehnt

## CLI-Referenz

| Befehl | Beschreibung |
|--------|--------------|
| `p2p-quic-listen` | QUIC-Server starten |
| `p2p-quic-connect` | Zu einem QUIC-Peer verbinden |
| `p2p-inject-headers` | Headers an einen Node senden |
| `p2p-inject-payloads` | Payloads an einen Node senden |
| `mint-rpc` | Mint RPC Server starten |
| `genesis_bootstrap` | Genesis-Datei generieren |

## Wichtige Pfade

| Datei | Beschreibung |
|-------|--------------|
| `<store-dir>/mempool/genesis_note.bin` | Genesis-Konfiguration |
| `<store-dir>/mempool/supply_state.json` | Aktueller Supply-Stand |
| `<store-dir>/bootstrap_peers.json` | Bootstrap-Peer-Liste |
| `<store-dir>/peers.json` | Entdeckte Peers (PEX) |
| `<store-dir>/p2p_quic_cert.der` | TLS-Zertifikat für QUIC |

## Peer Exchange (PEX)

Das Netzwerk unterstützt automatischen Peer-Austausch:

- **ReqMsg::GetPeers**: Anfrage für bekannte Peers
- **RespMsg::Peers**: Antwort mit Peer-Liste
- **PeerStore**: Persistiert entdeckte Peers in `peers.json`

### PeerInfo Struktur

```rust
pub struct PeerInfo {
    pub ip: Vec<u8>,        // IPv4 (4 Bytes) oder IPv6 (16 Bytes)
    pub port: u16,
    pub cert_der: Vec<u8>,  // TLS-Zertifikat
    pub last_seen: u64,     // AnchorIndex (uhrfrei, monoton)
    pub role_flags: u8,     // 0=Fullnode, 1=Validator, 2=Miner
}
```

### Limits

- **MAX_PEERS**: 256 Peers pro Node
- **TTL_ANCHORS**: 100.800 Anchors (~7 Tage bei 6s Anchor-Zeit)

## Fehlerbehandlung

- **Mint abgelehnt**: Prüfe `prev_mint_id` und PoW-Difficulty
- **Verbindung fehlgeschlagen**: Prüfe Zertifikatspfad und Multiaddr
- **Genesis mismatch**: Alle Nodes müssen dieselbe `genesis_note.bin` verwenden
