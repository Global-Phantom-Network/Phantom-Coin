# Upgrade Procedures

Schritt-für-Schritt-Anleitung für sichere Upgrades von Phantom Coin Nodes und Infrastructure.

## Übersicht

- [Pre-Upgrade Checklist](#pre-upgrade-checklist)
- [Node Upgrades](#node-upgrades)
- [Docker Upgrades](#docker-upgrades)
- [Rolling Upgrades](#rolling-upgrades)
- [Rollback Procedures](#rollback-procedures)
- [Post-Upgrade Verification](#post-upgrade-verification)

---

## Pre-Upgrade Checklist

✅ **Vor jedem Upgrade durchführen:**

### 1. Release Notes lesen

```bash
# Aktuelle Version prüfen
phantom-node --version

# Release Notes für neue Version lesen
open https://github.com/Global-Phantom-Network/Phantom-Coin/releases/tag/vX.Y.Z
```

**Prüfen auf:**
- Breaking Changes
- Migration-Scripts erforderlich?
- Neue Dependencies
- Kompatibilität mit bestehenden Nodes

### 2. Backup erstellen

```bash
# Node stoppen
systemctl stop phantom-node

# Backup erstellen
BACKUP_DIR=~/backups/phantom-$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"

# Daten sichern
cp -r /var/lib/phantom-coin/data "$BACKUP_DIR/"
cp -r /etc/phantom-coin "$BACKUP_DIR/"
cp /etc/phantom-coin/genesis_note.bin "$BACKUP_DIR/"

# Optional: Logs archivieren
journalctl -u phantom-node --since "7 days ago" > "$BACKUP_DIR/logs.txt"

# Backup-Größe prüfen
du -sh "$BACKUP_DIR"

echo "Backup created at: $BACKUP_DIR"
```

### 3. Health Check

```bash
# Vor dem Upgrade Status dokumentieren
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq . > pre-upgrade-status.json

# Metriken sichern
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/metrics > pre-upgrade-metrics.txt

# Aktuelle Block-Height notieren
CURRENT_HEIGHT=$(curl -s -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq -r '.height')
echo "Current height: $CURRENT_HEIGHT"
```

### 4. Maintenance Window kommunizieren

```bash
# Wartungsfenster ankündigen (wenn Validator)
# - Discord/Telegram Notification
# - Status Page Update
# - Monitoring Alert Suppression

# Beispiel: Monitoring Alert pausieren
curl -X POST https://monitoring.example.com/api/v1/silence \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [{"name": "instance", "value": "node1"}],
    "startsAt": "2025-11-09T17:00:00Z",
    "endsAt": "2025-11-09T18:00:00Z",
    "comment": "Planned upgrade to v0.0.13"
  }'
```

---

## Node Upgrades

### Binary Upgrade (Standalone Node)

#### 1. Download & Verify neues Binary

```bash
# Version definieren
NEW_VERSION=v0.0.13

# Download von GitHub Releases
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/${NEW_VERSION}/phantomcoin-${NEW_VERSION}-linux-x86_64.tar.gz

# SHA256 prüfen
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/${NEW_VERSION}/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# Cosign Signature verifizieren (optional, empfohlen)
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/${NEW_VERSION}/SHA256SUMS.sig
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/${NEW_VERSION}/SHA256SUMS.pem

cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp "https://github.com/Global-Phantom-Network/Phantom-Coin" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS

echo "✓ Signature verified"
```

#### 2. Binary installieren

```bash
# Entpacken
tar -xzf phantomcoin-${NEW_VERSION}-linux-x86_64.tar.gz

# Altes Binary sichern
sudo mv /usr/local/bin/phantom-node /usr/local/bin/phantom-node.backup

# Neues Binary installieren
sudo cp phantom-node /usr/local/bin/
sudo chmod +x /usr/local/bin/phantom-node

# Version prüfen
phantom-node --version
# Expected: phantom-node v0.0.13
```

#### 3. Upgrade durchführen

```bash
# Node starten
sudo systemctl start phantom-node

# Logs live verfolgen
journalctl -u phantom-node -f

# Health Check (in separatem Terminal)
sleep 10
curl http://localhost:18081/healthz

# Status prüfen
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq .
```

#### 4. Monitoring

```bash
# Block-Height sollte steigen
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
watch -n 5 "curl -s -H 'Authorization: Bearer $STATUS_TOKEN' http://localhost:18081/status | jq '.height'"

# Prometheus Metriken prüfen
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/metrics | grep pc_node_height

# Logs auf Fehler prüfen
journalctl -u phantom-node --since "5 minutes ago" | grep -i error
```

---

## Docker Upgrades

### Docker Compose Upgrade

#### 1. Neue Version pullen

```bash
cd /path/to/Phantom-Coin

# Git pull (wenn from source)
git fetch --tags
git checkout ${NEW_VERSION}

# Oder: docker-compose.yml manuell anpassen
# image: ghcr.io/global-phantom-network/phantom-node:v0.0.13
```

#### 2. Images pullen

```bash
# Neue Images downloaden
docker compose pull

# Verifizieren
docker images | grep phantom-node
```

#### 3. Rolling Upgrade (Zero-Downtime)

```bash
# Node 3 (Observer) zuerst - kein Impact
docker compose up -d node3
docker compose logs -f node3
# Warten bis healthy...

# Node 2 (Validator)
docker compose up -d node2
docker compose logs -f node2
# Warten bis healthy...

# Node 1 (Validator + Proposer) zuletzt
docker compose up -d node1
docker compose logs -f node1
# Warten bis healthy...
```

#### 4. Health Check

```bash
# Alle Nodes prüfen
for port in 18081 18082 18083; do
  echo "Checking node on port $port..."
  curl -f http://localhost:$port/healthz && echo "✓ Healthy" || echo "✗ Unhealthy"
done

# Docker Status
docker compose ps
```

---

## Rolling Upgrades (Multi-Node Production)

### Strategie: Blue-Green Deployment

#### Phase 1: Observer Nodes (kein Impact)

```bash
# Alle Observer Nodes upgraden
for node in observer1 observer2 observer3; do
  echo "Upgrading $node..."
  ssh $node "systemctl stop phantom-node"
  ssh $node "cp /path/to/new/phantom-node /usr/local/bin/"
  ssh $node "systemctl start phantom-node"
  sleep 30  # Wait for sync
done
```

#### Phase 2: Validator Nodes (Rolling)

```bash
# Validator Nodes einzeln upgraden (max 1/3 gleichzeitig)
# Verhindert Loss of Finality

for node in validator1 validator2 validator3; do
  echo "Upgrading $node..."
  
  # Node aus Rotation nehmen (falls Load Balancer)
  # drain_node $node
  
  ssh $node "systemctl stop phantom-node"
  ssh $node "cp /path/to/new/phantom-node /usr/local/bin/"
  ssh $node "systemctl start phantom-node"
  
  # Warten bis gesund und synchronisiert
  until ssh $node "curl -sf http://localhost:18081/healthz"; do
    echo "Waiting for $node to be healthy..."
    sleep 10
  done
  
  # Node zurück in Rotation
  # undrain_node $node
  
  echo "✓ $node upgraded successfully"
  sleep 60  # Safety buffer zwischen Upgrades
done
```

#### Phase 3: Miner Nodes

```bash
# Miner Nodes können parallel upgraden (kein Konsens-Impact)
parallel-ssh -h miner_nodes.txt "systemctl stop phantom-node && \
  cp /path/to/new/phantom-node /usr/local/bin/ && \
  systemctl start phantom-node"
```

---

## Rollback Procedures

### Schnell-Rollback (wenn Upgrade fehlschlägt)

#### 1. Sofortiger Rollback

```bash
# Node stoppen
sudo systemctl stop phantom-node

# Altes Binary wiederherstellen
sudo cp /usr/local/bin/phantom-node.backup /usr/local/bin/phantom-node

# Backup-Daten wiederherstellen (falls DB-Migration fehlschlug)
sudo rm -rf /var/lib/phantom-coin/data
sudo cp -r "$BACKUP_DIR/data" /var/lib/phantom-coin/
sudo install -m 0644 "$BACKUP_DIR/genesis_note.bin" /etc/phantom-coin/genesis_note.bin

# Node starten
sudo systemctl start phantom-node

# Logs prüfen
journalctl -u phantom-node -f
```

#### 2. Docker Rollback

```bash
# Zurück zu vorheriger Version
git checkout ${OLD_VERSION}

# Oder: docker-compose.yml manuell anpassen
# image: ghcr.io/global-phantom-network/phantom-node:v0.0.12

# Container neu starten
docker compose down
docker compose up -d

# Health prüfen
docker compose ps
docker compose logs -f
```

### Rollback-Entscheidungsbaum

```
Upgrade erfolgreich?
├─ Ja → ✓ Continue Monitoring
└─ Nein → Fehlertyp?
    ├─ Binary läuft nicht
    │  └─ → Sofortiger Rollback
    ├─ DB-Migration failed
    │  └─ → Rollback + DB Restore
    ├─ Konsens-Fehler (keine Blocks)
    │  └─ → Rollback + Koordination mit anderen Validators
    └─ Performance-Degradation
       └─ → Monitoring 15min, dann entscheiden
```

---

## Post-Upgrade Verification

### Automated Checks

```bash
#!/bin/bash
# post-upgrade-check.sh

set -euo pipefail

echo "=== Post-Upgrade Verification ==="

# 1. Binary Version
echo "1. Checking binary version..."
VERSION=$(phantom-node --version | awk '{print $2}')
EXPECTED="v0.0.13"
if [ "$VERSION" = "$EXPECTED" ]; then
  echo "✓ Version correct: $VERSION"
else
  echo "✗ Version mismatch: got $VERSION, expected $EXPECTED"
  exit 1
fi

# 2. Service Status
echo "2. Checking service status..."
if systemctl is-active --quiet phantom-node; then
  echo "✓ Service is running"
else
  echo "✗ Service is not running"
  exit 1
fi

# 3. Health Endpoint
echo "3. Checking health endpoint..."
if curl -sf http://localhost:18081/healthz > /dev/null; then
  echo "✓ Health check passed"
else
  echo "✗ Health check failed"
  exit 1
fi

# 4. Block Height Progress
echo "4. Checking block height progress..."
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
HEIGHT1=$(curl -s -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq -r '.height')
sleep 30
HEIGHT2=$(curl -s -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq -r '.height')
if [ "$HEIGHT2" -gt "$HEIGHT1" ]; then
  echo "✓ Block height progressing: $HEIGHT1 → $HEIGHT2"
else
  echo "✗ Block height stuck: $HEIGHT1"
  exit 1
fi

# 5. Error Logs
echo "5. Checking for errors in logs..."
ERROR_COUNT=$(journalctl -u phantom-node --since "10 minutes ago" | grep -ci error || true)
if [ "$ERROR_COUNT" -eq 0 ]; then
  echo "✓ No errors in logs"
else
  echo "⚠ Found $ERROR_COUNT errors in logs (review manually)"
fi

# 6. Peer Connections (wenn P2P aktiviert)
echo "6. Checking peer connections..."
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
PEERS=$(curl -s -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/metrics | grep 'pc_p2p_peers_total{' | awk '{print $2}')
if [ "${PEERS:-0}" -gt 0 ]; then
  echo "✓ Connected to $PEERS peers"
else
  echo "⚠ No peer connections (check if expected)"
fi

echo ""
echo "=== Upgrade Verification Complete ==="
echo "✓ All critical checks passed"
```

### Manual Verification

```bash
# 1. Prometheus Queries
# - Block production rate
# - Memory usage trend
# - Error rate

# 2. Grafana Dashboards
# - Node Overview Dashboard
# - P2P Network Dashboard
# - Consensus Dashboard

# 3. Log Analysis
journalctl -u phantom-node --since "1 hour ago" | grep -E "(WARN|ERROR|CRIT)"

# 4. Performance Comparison
# - Latency P50/P95
# - Throughput
# - Resource usage
```

---

## Emergency Contacts

Bei kritischen Problemen während Upgrades:

- **On-Call Engineer:** [PagerDuty/Opsgenie Link]
- **Slack Channel:** `#phantom-ops-emergency`
- **GitHub Issues:** https://github.com/Global-Phantom-Network/Phantom-Coin/issues
- **Incident Commander:** [Contact Info]

---

## Upgrade Checkliste (Print & Use)

```
[ ] Release Notes gelesen
[ ] Breaking Changes verstanden
[ ] Backup erstellt und verifiziert
[ ] Maintenance Window kommuniziert
[ ] Monitoring Alerts pausiert
[ ] Binary heruntergeladen und verifiziert
[ ] Upgrade durchgeführt
[ ] Service gestartet
[ ] Health Checks passed
[ ] Block Height progressing
[ ] Logs sauber (keine Errors)
[ ] Post-Upgrade Verification Script ausgeführt
[ ] Monitoring für 1h beobachtet
[ ] Alerts wieder aktiviert
[ ] Dokumentation aktualisiert
[ ] Team informiert
```

---

## Siehe auch

- [Emergency Procedures](./emergency-procedures.md)
- [Docker Compose Guide](./docker-compose.md)
- [Monitoring Setup](../observability/README.md)
