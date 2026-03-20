# Docker Compose - Local Multi-Node Setup

Produktionsreifes Multi-Node-Setup für lokale Entwicklung, Testing und Demos mit Docker Compose.

## Quick Start

```bash
# 1. Clone & Build
git clone https://github.com/Global-Phantom-Network/Phantom-Coin.git
cd Phantom-Coin

# 2. Konfiguration anlegen
cat > .env <<'EOF'
NODE1_STATUS_AUTH_TOKEN=replace-with-long-random-token-1
NODE2_STATUS_AUTH_TOKEN=replace-with-long-random-token-2
NODE3_STATUS_AUTH_TOKEN=replace-with-long-random-token-3
GRAFANA_USER=admin
GRAFANA_PASSWORD=replace-with-long-random-password
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
RUST_LOG=info
EOF

# 3. Starten (nur Nodes)
docker compose up -d

# Optional: mit Observability-Stack
docker compose --profile observability up -d

# 4. Logs anschauen
docker compose logs -f

# 5. Secrets in die Shell laden und Status prüfen
set -a
. ./.env
set +a
curl -H "Authorization: Bearer $NODE1_STATUS_AUTH_TOKEN" http://localhost:18081/status | jq .
curl -H "Authorization: Bearer $NODE2_STATUS_AUTH_TOKEN" http://localhost:18082/status | jq .
curl -H "Authorization: Bearer $NODE3_STATUS_AUTH_TOKEN" http://localhost:18083/status | jq .

# 6. Monitoring öffnen (nur mit `--profile observability`)
open http://localhost:9090  # Prometheus
open http://localhost:3000  # Grafana

# 7. Stoppen
docker compose down

# 8. Mit Datenlöschung stoppen
docker compose down -v
```

## Architektur

### Services

```
┌─────────────────────────────────────────────────────────┐
│                   Docker Network                         │
│                   (172.20.0.0/16)                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  Node 1  │  │  Node 2  │  │  Node 3  │             │
│  │ Validator│  │ Validator│  │ Observer │             │
│  │  + Miner │  │          │  │          │             │
│  │  :18081  │  │  :18082  │  │  :18083  │             │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘             │
│       │             │             │                     │
│       └─────────────┴─────────────┘                     │
│                     │                                   │
│            ┌────────┴────────┐                         │
│            │   Prometheus    │                         │
│            │      :9090      │                         │
│            └────────┬────────┘                         │
│                     │                                   │
│            ┌────────┴────────┐                         │
│            │    Grafana      │                         │
│            │     :3000       │                         │
│            └─────────────────┘                         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Node-Rollen

| Service | Rolle | Port | Beschreibung |
|---------|-------|------|--------------|
| node1 | Validator + Proposer | 18081 | Transaktions-Proposal und Validierung |
| node2 | Validator | 18082 | Nur Validierung |
| node3 | Observer | 18083 | Nur Beobachtung (kein Staking) |

### Volumes

| Volume | Zweck |
|--------|-------|
| `shared-genesis` | Gemeinsames Genesis-File für alle Nodes |
| `node1-data` | Node 1 Blockchain-Daten |
| `node2-data` | Node 2 Blockchain-Daten |
| `node3-data` | Node 3 Blockchain-Daten |
| `prometheus-data` | Prometheus Metriken |
| `grafana-data` | Grafana Dashboards & Config |

## Verwendung

### Logs anschauen

```bash
# Alle Logs
docker compose logs -f

# Nur Node 1
docker compose logs -f node1

# Nur letzte 100 Zeilen
docker compose logs --tail=100 node1
```

### Health Checks

```bash
# Alle Services
docker compose ps

# Einzelner Node
curl http://localhost:18081/healthz

# Status mit Details
set -a
. ./.env
set +a
curl -H "Authorization: Bearer $NODE1_STATUS_AUTH_TOKEN" http://localhost:18081/status | jq .
```

### Einzelne Services neu starten

```bash
# Node 1 neu starten
docker compose restart node1

# Alle Nodes neu starten (Monitoring läuft weiter)
docker compose restart node1 node2 node3
```

### In Container einsteigen

```bash
# Shell in Node 1
docker compose exec node1 sh

# Direkt Command ausführen
docker compose exec node1 phantom-node --version
```

### Daten zurücksetzen

```bash
# Services stoppen
docker compose down

# Daten löschen
docker volume rm phantom-coin_node1-data \
                  phantom-coin_node2-data \
                  phantom-coin_node3-data \
                  phantom-coin_shared-genesis

# Neu starten (Genesis wird neu erstellt)
docker compose up -d
```

## Konfiguration

### Umgebungsvariablen (.env)

Erstelle `.env` manuell im Repo-Root.

Wichtige Variablen:

```env
# Status-API Bearer-Tokens (Pflicht)
NODE1_STATUS_AUTH_TOKEN=replace-with-long-random-token-1
NODE2_STATUS_AUTH_TOKEN=replace-with-long-random-token-2
NODE3_STATUS_AUTH_TOKEN=replace-with-long-random-token-3

# Grafana-Login (Pflicht)
GRAFANA_USER=admin
GRAFANA_PASSWORD=replace-with-long-random-password

# Node Ports anpassen (falls Konflikte)
NODE1_PORT=18081
NODE2_PORT=18082
NODE3_PORT=18083

# Logging-Level erhöhen für Debugging
RUST_LOG=debug

# Monitoring Ports
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
```

Die Status-Services schreiben das Bearer-Token beim Start mit restriktiven Rechten in eine temporäre `auth_token_file` und starten `status-serve` anschließend über eine generierte TOML-Konfiguration. Inline-CLI-Tokens werden in diesem Compose-Setup nicht verwendet.

### Monitoring anpassen

#### Prometheus

Targets und Scrape-Konfiguration in `deploy/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'phantom-nodes'
    static_configs:
      - targets:
        - 'node1:18081'
        - 'node2:18082'
        - 'node3:18083'
```

#### Grafana

Dashboards in `docs/observability/grafana/provisioning/dashboards/`.

Login: über die in `.env` gesetzten Grafana-Zugangsdaten

## Szenarien

### 1. Lokale Entwicklung

Schneller Iteration-Cycle mit Hot-Reload:

```bash
# Node lokal starten (außerhalb Docker)
PHANTOM_STATUS_AUTH_TOKEN="$(openssl rand -hex 16)" \
cargo run -p phantom-node -- status-serve \
  --addr 127.0.0.1:18081 \
  --mempool-dir /var/lib/phantom-coin/data/mempool \
  --store-dir /var/lib/phantom-coin/data \
  --require-auth

# Andere Nodes via Docker für P2P-Tests
docker compose up -d node2 node3 prometheus grafana
```

### 2. Integration Tests

Vollständiges Testnet für E2E-Tests:

```bash
# Alle Services starten
docker compose up -d

# Tests ausführen
cargo test --workspace

# Cleanup
docker compose down -v
```

### 3. Performance Benchmarks

Isoliertes Environment für reproduzierbare Benchmarks:

```bash
# CPU/Memory Limits setzen (docker-compose.override.yml)
cat > docker-compose.override.yml <<EOF
services:
  node1:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
EOF

docker compose up -d
# Run benchmarks...
```

### 4. Demo/Präsentation

Setup für Demos und Vorführungen:

```bash
# Starten mit clean state
docker compose down -v
docker compose up -d

# Grafana Dashboard öffnen
open http://localhost:3000

# Live Transaktionen zeigen
set -a
. ./.env
set +a
watch -n 1 "curl -s -H 'Authorization: Bearer $NODE1_STATUS_AUTH_TOKEN' http://localhost:18081/status | jq '.height'"
```

## Troubleshooting

### Problem: Port bereits belegt

```
Error: bind: address already in use
```

**Lösung:**

```bash
# Port-Konflikte prüfen
lsof -i :18081

# Eigene Ports in .env setzen
echo "NODE1_PORT=28081" >> .env
echo "NODE2_PORT=28082" >> .env
echo "NODE3_PORT=28083" >> .env

docker compose up -d
```

### Problem: Genesis-Fehler

```
Error: genesis_note.bin not found
```

**Lösung:**

```bash
# Genesis-Volume neu erstellen
docker compose down
docker volume rm phantom-coin_shared-genesis
docker compose up -d genesis
docker compose logs genesis
```

### Problem: Node startet nicht

```
Error: connection refused
```

**Lösung:**

```bash
# Logs prüfen
docker compose logs node1

# Health-Check Status
docker compose ps

# Container neu bauen
docker compose build --no-cache node1
docker compose up -d node1
```

### Problem: Keine Metriken in Prometheus

```
Error: no targets up
```

**Lösung:**

```bash
# Netzwerk-Verbindung prüfen
docker compose exec prometheus wget -O- http://node1:18081/metrics

# Prometheus-Config validieren
docker compose exec prometheus promtool check config /etc/prometheus/prometheus.yml

# Prometheus neu starten
docker compose restart prometheus
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Compose Smoke

on: [push, pull_request]

jobs:
  docker-compose-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Start services
        run: docker compose --profile observability up -d
      
      - name: Wait for health
        run: |
          timeout 60 bash -c 'until curl -sf http://localhost:18081/healthz; do sleep 2; done'
      
      - name: Run tests
        run: |
          set -a
          . ./.env
          set +a
          curl -H "Authorization: Bearer $NODE1_STATUS_AUTH_TOKEN" http://localhost:18081/status
          # Add more tests...
      
      - name: Cleanup
        if: always()
        run: docker compose down -v
```

Der produktive Smoke-Workflow im Repo ist [`compose-smoke.yml`](/Users/fuatbayram/Desktop/DEX/Phantom-Coin/.github/workflows/compose-smoke.yml); das Snippet oben ist nur die verkürzte Form.

## Production-Hinweise

⚠️ **Dieses Setup ist für lokale Entwicklung/Testing optimiert!**

Für Production-Deployments beachten:

1. **Secrets Management:** Verwende Docker Secrets oder Vault statt `.env`
2. **Resource Limits:** Setze CPU/Memory Limits via `deploy.resources`
3. **Persistent Volumes:** Verwende externe Volumes oder Cloud-Storage
4. **TLS:** Aktiviere TLS für alle Node-zu-Node-Verbindungen
5. **Firewalls:** Setze Network Policies und Firewall-Rules
6. **Monitoring:** Integriere mit zentralem Monitoring (Datadog, New Relic, etc.)
7. **Backups:** Regelmäßige Backups der Volumes
8. **High Availability:** Multi-Region-Deployment mit Load Balancing

Siehe `docs/devops/production-deployment.md` für Details.

## Weiterführende Links

- [Observability Guide](../observability/README.md)
- [HSM Signing](./hsm-signing.md)
- [Upgrade Procedures](./upgrade-procedures.md)
- [Emergency Procedures](./emergency-procedures.md)

## Support

Bei Problemen oder Fragen:

- GitHub Issues: https://github.com/Global-Phantom-Network/Phantom-Coin/issues
- Dokumentation: https://github.com/Global-Phantom-Network/Phantom-Coin/tree/main/docs
