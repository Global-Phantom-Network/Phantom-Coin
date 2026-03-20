# Multi-Node Local Setup – Runbook

Minimaler Proof-of-Concept für ein lokales 3-Node-Cluster. Alle Nodes teilen sich dieselbe Genesis, laufen aber auf unterschiedlichen Ports.

## Voraussetzungen
- Rust toolchain (stable), Cargo
- Ports 18081-18083 frei
- Workspace-Root: Repository-Wurzel

## Quick Start

### 1. Nodes starten
```bash
bash scripts/testnets/multi_node_local.sh
```

Erwartet:
- Genesis wird generiert (`${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/shared/genesis_note.bin`)
- 3 Nodes starten auf Ports 18081, 18082, 18083
- Health-Checks laufen automatisch
- Logs: `${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/node{1,2,3}.log`

### 2. Status prüfen

**Health-Checks:**
```bash
curl -sf http://127.0.0.1:18081/healthz && echo "Node 1 OK"
curl -sf http://127.0.0.1:18082/healthz && echo "Node 2 OK"
curl -sf http://127.0.0.1:18083/healthz && echo "Node 3 OK"
```

**Status-Details:**
```bash
curl -s http://127.0.0.1:18081/status | jq .
curl -s http://127.0.0.1:18082/status | jq .
curl -s http://127.0.0.1:18083/status | jq .
```

**Metriken:**
```bash
curl -s http://127.0.0.1:18081/metrics | grep pc_network_id
curl -s http://127.0.0.1:18082/metrics | grep pc_genesis_height
```

### 3. Logs ansehen

**Live-Logs:**
```bash
tail -f "${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/node1.log"
```

**Alle Logs:**
```bash
tail -f "${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}"/node{1,2,3}.log
```

### 4. Nodes stoppen

**Sauber herunterfahren:**
```bash
bash scripts/testnets/stop_multi_node.sh
```

**Manuell:**
```bash
kill "$(cat "${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/node1.pid")"
kill "$(cat "${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/node2.pid")"
kill "$(cat "${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/node3.pid")"
```

**Oder:**
```bash
pkill -f "phantom-node.*status-serve"
```

## Erweiterte Nutzung

### Clean-Start (alte Daten löschen)
```bash
CLEAN=1 bash scripts/testnets/multi_node_local.sh
```

### Custom Genesis-Parameter
```bash
# Edit scripts/testnets/multi_node_local.sh und ändere:
NETWORK_NAME=custom-net SHARDS_INITIAL=4 COMMITTEE_K=21 \
  PHANTOM_TESTNET_STATE_DIR="${TMPDIR:-/tmp}/phantom-coin/custom-multi-node" \
  bash scripts/testnets/genesis_tn0.sh
```

## Architektur

```
${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/
├── shared/
│   └── genesis_note.bin        # Gemeinsame Genesis für alle Nodes
├── node1/
│   └── genesis_note.bin        # Kopie
├── node2/
│   └── genesis_note.bin        # Kopie
├── node3/
│   └── genesis_note.bin        # Kopie
├── node1.log                   # Node 1 Logs
├── node2.log                   # Node 2 Logs
├── node3.log                   # Node 3 Logs
├── node1.pid                   # Process ID von Node 1
├── node2.pid                   # Process ID von Node 2
└── node3.pid                   # Process ID von Node 3
```

## Limitierungen

- **Kein P2P:** Nodes kommunizieren nicht untereinander (nur `status-serve`)
- **Shared Genesis:** Alle Nodes nutzen dieselbe Genesis (Single-Shard)
- **Lokal only:** Keine externen Verbindungen

## Zweck

Dieser Setup ist ein **minimaler Proof-of-Concept** für:
- Multi-Node-Tests (z.B. Load-Balancing über mehrere Endpoints)
- Monitoring-Setup (3 Targets für Prometheus)
- Runbook-Validation (Deployment-Prozesse testen)

**Für Production:** Siehe separate Deployment-Runbooks (Docker, Kubernetes, Terraform).

## Troubleshooting

### Ports belegt
```bash
# Prüfe welcher Prozess den Port nutzt
lsof -i :18081
# Oder ändere Ports im Skript
```

### Genesis-Fehler
```bash
# Lösche alte Genesis und starte neu
rm -rf "${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}"
bash scripts/testnets/multi_node_local.sh
```

### Node startet nicht
```bash
# Prüfe Logs
cat "${PHANTOM_MULTI_NODE_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/multi-node-local}/node1.log"
# oder
RUST_LOG=debug bash scripts/testnets/multi_node_local.sh
```
