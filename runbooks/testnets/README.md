# Testnet Runbooks

## English version

Documentation for different testnet setups.

## Available runbooks

### Single-node setups

- **[testnet-0.md](testnet-0.md)** – single-shard testnet (S=1, k=21)
- **[testnet-1.md](testnet-1.md)** – 64-shard testnet (S=64, k=21, attestors)

### Multi-node setups

- **[multi-node-local.md](multi-node-local.md)** – local 3-node cluster (development/testing)

## Quick start

### Testnet-0 (single shard)

```bash
# Generate genesis
bash scripts/testnets/genesis_tn0.sh

# Start status-serve
PHANTOM_STATUS_AUTH_TOKEN="$(openssl rand -hex 16)" \
cargo run -p phantom-node -- status-serve \
  --addr 127.0.0.1:18080 \
  --mempool-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0/mempool" \
  --store-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0" \
  --fsync

# Check health
curl http://127.0.0.1:18080/healthz
```

### Testnet-1 (64 shards)

```bash
# Generate genesis
bash scripts/testnets/genesis_tn1.sh

# Start status-serve
PHANTOM_STATUS_AUTH_TOKEN="$(openssl rand -hex 16)" \
cargo run -p phantom-node -- status-serve \
  --addr 127.0.0.1:18080 \
  --mempool-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1/mempool" \
  --store-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1" \
  --fsync

# Check health
curl http://127.0.0.1:18080/healthz
```

### Multi-node local cluster

```bash
# Start 3 nodes (ports 18081-18083)
bash scripts/testnets/multi_node_local.sh

# Check all nodes
curl http://127.0.0.1:18081/healthz
curl http://127.0.0.1:18082/healthz
curl http://127.0.0.1:18083/healthz

# Stop all nodes
bash scripts/testnets/stop_multi_node.sh
```

## CI validation

All testnets are validated in CI:

- **Workflow:** `.github/workflows/testnet-smoke.yml`
- **Tests:** genesis generation, status-serve startup, health checks, finality gates, claims gates
- **Status:** ✅ passing

## Monitoring

See [docs/observability.md](../../docs/observability.md) for:

- Prometheus metrics setup
- Health check endpoints
- PromQL queries
- Logging configuration

## Production deployment

**Note:** current runbooks are for development/testing. Production deployment (Docker, Kubernetes, cloud VMs) is deferred and will be documented separately when infrastructure is available.

## Support

- Issues: `docs/issues_en/t19.md` (current status and roadmap)
- Observability: `docs/observability.md`
- Genesis: `docs/GENESIS.md`

## Deutsche Version

Dokumentation für verschiedene Testnet-Setups.

## Verfügbare Runbooks

### Single-Node-Setups

- **[testnet-0.md](testnet-0.md)** – Single-Shard-Testnet (S=1, k=21)
- **[testnet-1.md](testnet-1.md)** – 64-Shard-Testnet (S=64, k=21, Attestors)

### Multi-Node-Setups

- **[multi-node-local.md](multi-node-local.md)** – lokaler 3-Node-Cluster (Development/Testing)

## Quick Start

### Testnet-0 (Single-Shard)

```bash
# Genesis erzeugen
bash scripts/testnets/genesis_tn0.sh

# status-serve starten
PHANTOM_STATUS_AUTH_TOKEN="$(openssl rand -hex 16)" \
cargo run -p phantom-node -- status-serve \
  --addr 127.0.0.1:18080 \
  --mempool-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0/mempool" \
  --store-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn0" \
  --fsync

# Health prüfen
curl http://127.0.0.1:18080/healthz
```

### Testnet-1 (64-Shard)

```bash
# Genesis erzeugen
bash scripts/testnets/genesis_tn1.sh

# status-serve starten
PHANTOM_STATUS_AUTH_TOKEN="$(openssl rand -hex 16)" \
cargo run -p phantom-node -- status-serve \
  --addr 127.0.0.1:18080 \
  --mempool-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1/mempool" \
  --store-dir "${PHANTOM_TESTNET_STATE_DIR:-${TMPDIR:-/tmp}/phantom-coin/testnets}/tn1" \
  --fsync

# Health prüfen
curl http://127.0.0.1:18080/healthz
```

### Multi-Node-Cluster lokal

```bash
# Drei Nodes starten (Ports 18081–18083)
bash scripts/testnets/multi_node_local.sh

# Alle Nodes prüfen
curl http://127.0.0.1:18081/healthz
curl http://127.0.0.1:18082/healthz
curl http://127.0.0.1:18083/healthz

# Alle Nodes stoppen
bash scripts/testnets/stop_multi_node.sh
```

## CI-Validierung

Alle Testnets werden in CI validiert:

- **Workflow:** `.github/workflows/testnet-smoke.yml`
- **Tests:** Genesis-Erzeugung, status-serve-Start, Health-Checks, Finality-Gates, Claims-Gates
- **Status:** ✅ grün

## Monitoring

Siehe [docs/observability.md](../../docs/observability.md) für:

- Prometheus-Metrik-Setup
- Health-Check-Endpunkte
- PromQL-Queries
- Logging-Konfiguration

## Produktiv-Deployment

**Hinweis:** Die aktuellen Runbooks sind für Entwicklung/Tests gedacht. Produktiv-Deployment (Docker, Kubernetes, Cloud-VMs) wird separat dokumentiert, sobald die Infrastruktur verfügbar ist.

## Support

- Issues: `docs/issues_en/t19.md` (aktueller Status und Roadmap)
- Observability: `docs/observability.md`
- Genesis: `docs/GENESIS.md`
