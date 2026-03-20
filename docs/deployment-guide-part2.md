# Phantom-Coin Deployment Guide - Teil 2

## Monitoring Setup

### Prometheus Configuration

**File:** `monitoring/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'phantom-mainnet'
    environment: 'production'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

# Load alert rules
rule_files:
  - 'alerts/*.yml'

scrape_configs:
  # Phantom Node Metrics
  - job_name: 'phantom-node'
    static_configs:
      - targets: ['localhost:9101']
        labels:
          instance: 'validator-1'
          network: 'mainnet'
          role: 'validator'

  # Phantom Status API
  - job_name: 'phantom-status'
    metrics_path: '/metrics'
    static_configs:
      - targets: ['localhost:8080']
        labels:
          instance: 'validator-1'

  # System Metrics (Node Exporter)
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:9100']

  # Optional: Additional validators
  # - job_name: 'phantom-node-2'
  #   static_configs:
  #     - targets: ['validator-2.example.com:9101']
  #       labels:
  #         instance: 'validator-2'
```

### Alert Rules

**File:** `monitoring/alerts/phantom-node.yml`

```yaml
groups:
  - name: phantom_node_critical
    interval: 30s
    rules:
      - alert: PhantomNodeDown
        expr: up{job="phantom-node"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Phantom Node ist down (instance {{ $labels.instance }})"
          description: "Phantom Node {{ $labels.instance }} antwortet nicht mehr auf Prometheus-Scrapes."

      - alert: PhantomStatusAPIDown
        expr: up{job="phantom-status"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Status API ist down"
          description: "Status API antwortet nicht mehr."

  - name: phantom_node_warning
    interval: 1m
    rules:
      - alert: HighFinalityLatency
        expr: rate(pc_node_finality_sum_micros[5m]) / rate(pc_node_finality_count[5m]) > 5000000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Hohe Finalisierungs-Latenz (>5s)"
          description: "Durchschnittliche Finalisierungszeit liegt bei {{ $value | humanizeDuration }}."

      - alert: P2POutboxDrops
        expr: rate(pc_p2p_outbox_drop_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "P2P Outbox Drops detektiert"
          description: "Backpressure im P2P-Layer: {{ $value }} drops/sec."

      - alert: LowPeerCount
        expr: pc_p2p_peers_total < 5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Niedrige Peer-Anzahl"
          description: "Nur {{ $value }} Peers verbunden (minimum: 5)."

      - alert: HighTxBroadcastErrors
        expr: rate(phantom_node_tx_broadcast_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Hohe TX-Broadcast-Fehlerrate"
          description: "{{ $value }} TX-Broadcast-Fehler/sec."

  - name: phantom_system
    interval: 1m
    rules:
      - alert: HighCPUUsage
        expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Hohe CPU-Auslastung (>80%)"
          description: "CPU-Auslastung bei {{ $value }}%."

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Hohe RAM-Auslastung (>90%)"
          description: "RAM-Auslastung bei {{ $value }}%."

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) < 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Disk-Space unter 10%"
          description: "Nur noch {{ $value | humanizePercentage }} Speicherplatz frei."

      - alert: HighDiskIOWait
        expr: rate(node_disk_io_time_seconds_total[5m]) > 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Hohe Disk I/O Wait"
          description: "Disk I/O Wait bei {{ $value }}."
```

### Grafana Dashboards

**Datasource:** `monitoring/grafana/datasources/prometheus.yml`

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
```

**Dashboard Provisioning:** `monitoring/grafana/dashboards/phantom-node.json`

*Hinweis: Zu groß für README. Importiere folgende Community-Dashboards:*

1. **Node Exporter Full:** Dashboard ID `1860`
2. **Prometheus 2.0 Overview:** Dashboard ID `3662`

**Custom Metrics für Phantom Dashboard:**

```json
{
  "panels": [
    {
      "title": "Finality Rate",
      "targets": [{
        "expr": "rate(pc_node_finality_events_total[5m])"
      }]
    },
    {
      "title": "Avg Finality Latency",
      "targets": [{
        "expr": "rate(pc_node_finality_sum_micros[5m]) / rate(pc_node_finality_count[5m])"
      }]
    },
    {
      "title": "P2P Inbound/Outbound",
      "targets": [
        {"expr": "rate(pc_p2p_inbound_total[5m])", "legendFormat": "Inbound"},
        {"expr": "rate(pc_p2p_outbound_total[5m])", "legendFormat": "Outbound"}
      ]
    },
    {
      "title": "TX Broadcast Rate",
      "targets": [{
        "expr": "rate(phantom_node_tx_broadcast_total[5m])"
      }]
    }
  ]
}
```

---

## Security Hardening

### 1. TLS/mTLS Configuration

**Generate Self-Signed Certificate (Dev/Test):**

```bash
# Server certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/phantom-coin/certs/server.key \
  -out /etc/phantom-coin/certs/server.crt \
  -days 365 \
  -subj "/CN=phantom-node.local"

# Set permissions
sudo chmod 600 /etc/phantom-coin/certs/server.key
sudo chown phantom:phantom /etc/phantom-coin/certs/*
```

**Production: Let's Encrypt (Recommended):**

```bash
# Install certbot
sudo apt install certbot

# Obtain certificate (HTTP-01 challenge)
sudo certbot certonly --standalone \
  -d validator.yourdomain.com \
  --agree-tos \
  --email admin@yourdomain.com

# Certificates will be in: /etc/letsencrypt/live/validator.yourdomain.com/
# Link to phantom-coin directory
sudo ln -s /etc/letsencrypt/live/validator.yourdomain.com/fullchain.pem /etc/phantom-coin/certs/server.crt
sudo ln -s /etc/letsencrypt/live/validator.yourdomain.com/privkey.pem /etc/phantom-coin/certs/server.key

# Auto-renewal
sudo crontab -e
# Add: 0 3 * * * certbot renew --quiet && systemctl reload phantom-node-status
```

**mTLS (Mutual TLS) für Consensus-Endpoints:**

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/phantom-coin/certs/ca.key \
  -out /etc/phantom-coin/certs/ca.crt \
  -days 3650 \
  -subj "/CN=Phantom-CA"

# Client certificate
openssl req -newkey rsa:4096 -nodes \
  -keyout /etc/phantom-coin/certs/client.key \
  -out /etc/phantom-coin/certs/client.csr \
  -subj "/CN=phantom-client"

# Sign with CA
openssl x509 -req \
  -in /etc/phantom-coin/certs/client.csr \
  -CA /etc/phantom-coin/certs/ca.crt \
  -CAkey /etc/phantom-coin/certs/ca.key \
  -CAcreateserial \
  -out /etc/phantom-coin/certs/client.crt \
  -days 365

# Test mTLS connection
curl --cert /etc/phantom-coin/certs/client.crt \
     --key /etc/phantom-coin/certs/client.key \
     --cacert /etc/phantom-coin/certs/ca.crt \
     https://localhost:8443/consensus/config
```

**status-serve.toml with TLS:**

```toml
config_version = 1
addr = "127.0.0.1:8080"
mempool_dir = "/var/lib/phantom-coin/data/mempool"
store_dir = "/var/lib/phantom-coin/data"
fsync = true
require_auth = true
auth_token_file = "/etc/phantom-coin/status-auth.token"
tls_cert = "/etc/phantom-coin/certs/server.crt"
tls_key = "/etc/phantom-coin/certs/server.key"
tls_client_ca = "/etc/phantom-coin/certs/ca.crt"  # Enables mTLS
```

### 1b. Reverse Proxy Reference

Wenn `status-serve` öffentlich erreichbar sein soll, ist der bevorzugte Produktionspfad:

- `status-serve` bleibt auf `127.0.0.1:8080`
- externer Zugriff läuft über einen Reverse Proxy mit TLS
- `require_auth = true` bleibt am Upstream aktiv
- öffentlich erreichbares Plain-HTTP ohne vorgeschalteten Schutz ist kein empfohlener Produktionsmodus

**Nginx reference:**

```nginx
upstream phantom_status {
    server 127.0.0.1:8080;
    keepalive 16;
}

server {
    listen 443 ssl http2;
    server_name status.example.com;

    ssl_certificate /etc/letsencrypt/live/status.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/status.example.com/privkey.pem;

    location / {
        proxy_pass http://phantom_status;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Authorization $http_authorization;
    }
}
```

**Upstream status-serve.toml for proxy mode:**

```toml
config_version = 1
addr = "127.0.0.1:8080"
mempool_dir = "/var/lib/phantom-coin/data/mempool"
store_dir = "/var/lib/phantom-coin/data"
fsync = true
require_auth = true
auth_token_file = "/etc/phantom-coin/status-auth.token"
```

### 2. Secrets Management

**Option A: systemd Credentials (systemd 250+)**

```bash
# Encrypt auth token
sudo systemd-creds encrypt - /etc/phantom-coin/auth-token.cred <<< "$(openssl rand -hex 32)"

# In systemd service file:
[Service]
LoadCredential=auth_token:/etc/phantom-coin/auth-token.cred
ExecStart=/opt/phantom-coin/bin/phantom-node ... \
  --auth-token-file ${CREDENTIALS_DIRECTORY}/auth_token
```

**Option B: Environment File**

```bash
# Create env file
sudo bash -c 'cat > /etc/phantom-coin/phantom-node.env' << 'EOF'
PHANTOM_STATUS_AUTH_TOKEN=<paste-64-hex-random-token-here>
RUST_LOG=info
EOF

# Set permissions
sudo chmod 600 /etc/phantom-coin/phantom-node.env
sudo chown phantom:phantom /etc/phantom-coin/phantom-node.env

# In systemd service:
[Service]
EnvironmentFile=/etc/phantom-coin/phantom-node.env
ExecStart=/opt/phantom-coin/bin/phantom-node \
  status-serve \
  --config /etc/phantom-coin/status-serve.toml
```

**Option C: HashiCorp Vault (Enterprise)**

```bash
# Retrieve from Vault
export VAULT_ADDR=https://vault.example.com
AUTH_TOKEN=$(vault kv get -field=token secret/phantom-coin/auth)

# Write token file for status-serve
install -m 600 /dev/null /etc/phantom-coin/status-auth.token
printf '%s\n' "$AUTH_TOKEN" > /etc/phantom-coin/status-auth.token
sudo chown phantom:phantom /etc/phantom-coin/status-auth.token

# Pass to service
/opt/phantom-coin/bin/phantom-node ... --auth-token-file /etc/phantom-coin/status-auth.token
```

**Verify token file ownership and mode**

```bash
stat -c '%a %U %G %n' /etc/phantom-coin/status-auth.token
# Expected: 600 phantom phantom /etc/phantom-coin/status-auth.token
```

### 3. SSH Hardening

```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config

# Recommended settings:
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Restart SSH
sudo systemctl restart sshd
```

### 4. Fail2Ban for SSH

```bash
# Install
sudo apt install fail2ban

# Configure
sudo bash -c 'cat > /etc/fail2ban/jail.local' << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
EOF

# Start
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check status
sudo fail2ban-client status sshd
```

### 5. Automatic Security Updates

```bash
# Install unattended-upgrades
sudo apt install unattended-upgrades apt-listchanges

# Configure
sudo dpkg-reconfigure -plow unattended-upgrades

# Enable automatic reboot (optional)
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
# Uncomment: Unattended-Upgrade::Automatic-Reboot "true";
# Set time: Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

---

## Production Checklist

### Pre-Deployment

- [ ] **System vorbereitet:**
  - [ ] Ubuntu 22.04 LTS / Debian 12 installiert
  - [ ] System Updates: `apt update && apt upgrade`
  - [ ] Benötigte Pakete installiert
  - [ ] NTP synchronisiert: `timedatectl status`

- [ ] **User & Directories:**
  - [ ] User `phantom` erstellt
  - [ ] Directories unter `/opt/phantom-coin`, `/var/lib/phantom-coin`, `/etc/phantom-coin` erstellt
  - [ ] Permissions korrekt gesetzt (750/600)

- [ ] **Binaries installiert:**
  - [ ] `phantom-node`, `phantom-miner`, `phantom-signer` nach `/opt/phantom-coin/bin/`
  - [ ] Executable: `chmod +x /opt/phantom-coin/bin/*`
  - [ ] Version geprüft: `phantom-node --version`

- [ ] **Config-Files:**
  - [ ] `genesis.toml` vorhanden und validiert
  - [ ] `genesis_note.bin` aus dem freigegebenen Release nach `/etc/phantom-coin/genesis_note.bin` installiert
  - [ ] `node.toml` erstellt (mit Rotation/DA-Gating/Rate-Limiting)
  - [ ] `status-serve.toml` erstellt (mit Auth/TLS/HTTP-Settings)
  - [ ] `miner.toml` erstellt (optional)
  - [ ] TLS-Zertifikate generiert/installiert

- [ ] **Secrets:**
  - [ ] Auth-Token generiert (mindestens 32 Zeichen, zufällig)
  - [ ] Secrets-Management konfiguriert (systemd credentials / env file / Vault)
  - [ ] Keystore-Backups erstellt (siehe Backup-Guide)

- [ ] **Netzwerk:**
  - [ ] Firewall konfiguriert (UFW/iptables)
  - [ ] Port-Forwarding im Router (9000/UDP, 9100/TCP)
  - [ ] Statische IP konfiguriert (optional, aber empfohlen)

- [ ] **Storage:**
  - [ ] Mindestens 100 GB SSD frei
  - [ ] NVMe-SSD für `/var/lib/phantom-coin/data` (empfohlen)
  - [ ] Filesystem: ext4 oder xfs

- [ ] **Monitoring:**
  - [ ] Prometheus installiert/konfiguriert
  - [ ] Grafana installiert/konfiguriert
  - [ ] Alert-Rules deployed
  - [ ] Node Exporter installiert

- [ ] **Backup:**
  - [ ] Backup-Strategie definiert
  - [ ] Backup-Scripts erstellt
  - [ ] Erste Snapshots gemacht
  - [ ] Restore getestet

### Deployment

- [ ] **Systemd Services:**
  - [ ] Service-Files nach `/etc/systemd/system/` kopiert
  - [ ] `systemctl daemon-reload` ausgeführt
  - [ ] Services enabled: `systemctl enable phantom-node`
  - [ ] Services gestartet: `systemctl start phantom-node`

- [ ] **Health Checks:**
  - [ ] Services laufen: `systemctl status phantom-node`
  - [ ] Logs ohne Errors: `journalctl -u phantom-node --lines=100`
  - [ ] `/healthz` → 200 OK
  - [ ] `/readyz` → 200 OK
  - [ ] `/metrics` liefert Metriken

- [ ] **P2P Connectivity:**
  - [ ] Peer-Count > 0: Check in Metrics oder Logs
  - [ ] Inbound-Connections funktionieren (Port-Forwarding OK)
  - [ ] P2P-Traffic sichtbar: `tc_p2p_inbound_total`, `pc_p2p_outbound_total` steigen

- [ ] **Finality:**
  - [ ] `pc_node_finality_events_total` steigt
  - [ ] Finality-Latenz < 10s
  - [ ] Keine `pc_node_finality_errors_total`

### Post-Deployment

- [ ] **Monitoring aktiv:**
  - [ ] Prometheus scrapet erfolgreich (Targets "UP")
  - [ ] Grafana-Dashboards zeigen Daten
  - [ ] Alerts konfiguriert und getestet
  - [ ] Alert-Routing (Email/Slack/PagerDuty) funktioniert

- [ ] **Automated Backups:**
  - [ ] Backup-Cronjob läuft
  - [ ] Backup-Destination erreichbar
  - [ ] Retention-Policy konfiguriert
  - [ ] Restore-Test durchgeführt

- [ ] **Dokumentation:**
  - [ ] Runbook für Operations erstellt
  - [ ] Incident-Response-Plan dokumentiert
  - [ ] Kontakt-Informationen hinterlegt
  - [ ] Disaster-Recovery-Prozeduren beschrieben

- [ ] **Performance Tuning:**
  - [ ] CPU-Auslastung < 80%
  - [ ] RAM-Auslastung < 80%
  - [ ] Disk I/O-Wait < 50%
  - [ ] Keine Backpressure (pc_p2p_outbox_drop_total = 0)

- [ ] **Security Audit:**
  - [ ] SSH nur mit Key-Auth
  - [ ] Fail2Ban aktiv
  - [ ] Firewall-Rules minimalistisch
  - [ ] Automatic Security Updates enabled
  - [ ] TLS-Zertifikate gültig (Check Expiry)

---

## Troubleshooting

### Node startet nicht

```bash
# Check Service-Status
sudo systemctl status phantom-node

# View Logs
sudo journalctl -u phantom-node -n 100 --no-pager

# Common Issues:
# 1. Port belegt
sudo netstat -tulpn | grep :9000
sudo lsof -i :9000
sudo kill -9 <PID>

# 2. Permission Denied
sudo chown -R phantom:phantom /var/lib/phantom-coin
sudo chmod 750 /var/lib/phantom-coin

# 3. Missing or mismatched Genesis file
ls -l /etc/phantom-coin/genesis_note.bin
ls -l /var/lib/phantom-coin/data/mempool/genesis_note.bin

# Restore the canonical release genesis to both locations
sudo install -m 0644 /backup/genesis_note.bin /etc/phantom-coin/genesis_note.bin
sudo install -m 0644 /backup/genesis_note.bin /var/lib/phantom-coin/data/mempool/genesis_note.bin

# If status-serve refuses to start with:
# "genesis_note passt nicht zu mempool_dir/genesis_note.bin"
# then the canonical file and the store copy differ. Replace both copies
# with the same release artifact before restarting.

# 4. Config Syntax Error
/opt/phantom-coin/bin/phantom-node status-serve --config /etc/phantom-coin/status-serve.toml
# Fix TOML syntax errors
```

### Keine P2P-Verbindungen

```bash
# Check Firewall
sudo ufw status
sudo iptables -L -n -v

# Test Port-Forwarding (from external)
nc -zvu <YOUR_PUBLIC_IP> 9000
nc -zv <YOUR_PUBLIC_IP> 9100

# Check Peers in Logs
sudo journalctl -u phantom-node | grep -i peer

# Manually connect to seed nodes (if configured)
# Add bootstrap nodes in genesis.toml
```

### Hohe CPU/RAM-Auslastung

```bash
# Check Top Processes
top -o %CPU
top -o %MEM

# Phantom-Node-Limits setzen
sudo systemctl edit phantom-node.service
# Add:
[Service]
CPUQuota=300%
MemoryMax=8G
MemoryHigh=6G

# Reload
sudo systemctl daemon-reload
sudo systemctl restart phantom-node
```

### Disk-Space voll

```bash
# Check Usage
df -h
du -sh /var/lib/phantom-coin/*
du -sh /var/log/*

# Clean Old Logs
sudo journalctl --vacuum-time=7d
sudo journalctl --vacuum-size=1G

# Rotate/Compress Logs
sudo apt install logrotate
sudo nano /etc/logrotate.d/phantom-node
```

### TLS-Certificate Errors

```bash
# Check Certificate
openssl x509 -in /etc/phantom-coin/certs/server.crt -text -noout

# Check Expiry
openssl x509 -enddate -noout -in /etc/phantom-coin/certs/server.crt

# Test Connection
curl -vvv https://localhost:8443/healthz

# Verify Chain
openssl verify -CAfile /etc/phantom-coin/certs/ca.crt /etc/phantom-coin/certs/server.crt
```

### Metrics nicht verfügbar

```bash
# Check Metrics Service
sudo systemctl status phantom-node-metrics

# Manual Test
curl http://localhost:9101/metrics

# Check Prometheus Targets
curl http://localhost:9090/api/v1/targets | jq

# Firewall Allow (if needed)
sudo ufw allow from 10.0.0.0/8 to any port 9101
```

---

## Weitere Ressourcen

- **Phantom-Node README:** [crates/phantom-node/README.md](../crates/phantom-node/README.md)
- **Phantom-Miner README:** [crates/phantom-miner/README.md](../crates/phantom-miner/README.md)
- **Phantom-Signer README:** [crates/phantom-signer/README.md](../crates/phantom-signer/README.md)
- **Backup & Recovery Guide:** [backup-recovery-guide.md](./backup-recovery-guide.md)
- **P2P Specification:** [SPEC_P2P.md](./SPEC_P2P.md)
- **Maturity Specification:** [SPEC_MATURITY.md](./SPEC_MATURITY.md)
