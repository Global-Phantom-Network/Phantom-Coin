# Phantom-Coin Production Deployment Guide

**Version:** 1.0  
**Last Updated:** 2025-01-10

## Inhaltsverzeichnis

1. [System-Anforderungen](#system-anforderungen)
2. [Installation](#installation)
3. [Systemd Services](#systemd-services)
4. [Docker Deployment](#docker-deployment)
5. [Netzwerk & Firewall](#netzwerk--firewall)
6. [Monitoring Setup](#monitoring-setup)
7. [Security Hardening](#security-hardening)
8. [Production Checklist](#production-checklist)
9. [Troubleshooting](#troubleshooting)

---

## System-Anforderungen

### Hardware (Minimum)
- **CPU:** 4 cores @ 2.5 GHz (8+ cores @ 3.0+ GHz empfohlen)
- **RAM:** 8 GB (16+ GB empfohlen für Validator)
- **Disk:** 100 GB SSD (NVMe empfohlen, 500+ GB für Archiv-Node)
- **Network:** 100 Mbps symmetrisch (1 Gbps+ empfohlen)

### Hardware (Empfohlen für Produktion)
- **CPU:** 8+ cores (AMD Ryzen 7 / Intel i7 oder besser)
- **RAM:** 32 GB DDR4
- **Disk:** 1 TB NVMe SSD (Samsung 980 PRO o.ä.)
- **Network:** Dedizierte 1 Gbps Leitung, statische IP

### Software
- **OS:** Ubuntu 22.04 LTS / Debian 12 Bookworm (empfohlen)
- **Kernel:** Linux 5.15+ 
- **Rust:** 1.75+ (für Build from Source)
- **Dependencies:** 
  ```bash
  apt install build-essential libssl-dev pkg-config curl git
  ```

### Netzwerk-Ports

| Service | Port | Protokoll | Beschreibung | Öffentlich? |
|---------|------|-----------|--------------|-------------|
| HTTP API | 8080 | TCP | Status/Broadcast/Consensus | Nein (intern) |
| HTTPS API | 8443 | TCP | TLS/mTLS Endpoints | Optional |
| P2P QUIC | 9000 | UDP | Peer-to-Peer Kommunikation | **Ja** |
| libp2p Gossipsub | 9100 | TCP | Gossipsub Transport | **Ja** |
| Prometheus Metrics | 9101 | TCP | Metrics Exporter | Nein (intern) |

---

## Installation

### Option 1: Binary Installation (Empfohlen)

```bash
# Download latest release
wget https://github.com/phantom-coin/phantom-coin/releases/download/v1.0.0/phantom-coin-x86_64-linux.tar.gz

# Extract
tar -xzf phantom-coin-x86_64-linux.tar.gz

# Install system-wide
sudo mkdir -p /opt/phantom-coin/bin
sudo cp phantom-node phantom-miner phantom-signer /opt/phantom-coin/bin/
sudo chmod +x /opt/phantom-coin/bin/*

# Verify
/opt/phantom-coin/bin/phantom-node --version
```

### Option 2: Build from Source

```bash
# Clone repository
git clone https://github.com/phantom-coin/phantom-coin.git
cd phantom-coin

# Build release binaries
cargo build --release \
  -p phantom-node \
  -p phantom-miner \
  -p phantom-signer \
  --features "async,libp2p,quic"

# Install
sudo mkdir -p /opt/phantom-coin/bin
sudo cp target/release/phantom-{node,miner,signer} /opt/phantom-coin/bin/
```

### User & Directories Setup

```bash
# Create dedicated user
sudo useradd -r -m -s /bin/bash -d /opt/phantom-coin phantom

# Create data directories
sudo mkdir -p /var/lib/phantom-coin/{data,mempool}
sudo mkdir -p /etc/phantom-coin/certs
sudo mkdir -p /var/log/phantom-coin

# Set permissions
sudo chown -R phantom:phantom /opt/phantom-coin
sudo chown -R phantom:phantom /var/lib/phantom-coin
sudo chown -R phantom:phantom /var/log/phantom-coin
sudo chmod 750 /var/lib/phantom-coin
sudo chmod 750 /etc/phantom-coin
```

### Canonical Genesis Provisioning

- Verwende die freigegebene `genesis_note.bin` des Releases als einzige autoritative Genesis-Datei.
- Der aktuelle kanonische Release-Stand erwartet `network_id = d4d309537274b9f8e0c8e5a067d6f8b9ba898773bcd203e8e106db08ed9023f6`.
- Bei `systemd`-Deployments wird diese Datei nach `/etc/phantom-coin/genesis_note.bin` installiert.
- `phantom-node.service` kopiert sie vor jedem Start nach `/var/lib/phantom-coin/data/mempool/genesis_note.bin`.
- `phantom-node-status.service` liest dieselbe kanonische Datei über `--genesis-note /etc/phantom-coin/genesis_note.bin`.
- Bei Docker-Compose-Deployments liegt dieselbe freigegebene Genesis-Datei im Image unter `/usr/local/share/phantom-coin/genesis_note.bin`; der `genesis`-Init-Service kopiert sie in das Shared-Volume und jeder Node- oder Status-Container installiert sie vor dem Start nach `/data/mempool/genesis_note.bin`.
- Lokale Genesis-Rewrites sind nicht zulässig; ein Genesis-Wechsel erfolgt ausschließlich durch Austausch der freigegebenen Datei und vollständigen Store-Reset.

---

## Systemd Services

### 1. Main Node Service

**File:** `/etc/systemd/system/phantom-node.service`

```ini
[Unit]
Description=Phantom-Coin Validator Node
Documentation=https://github.com/phantom-coin/phantom-coin
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=phantom
Group=phantom
WorkingDirectory=/opt/phantom-coin

# Environment
Environment="RUST_LOG=info"

# Main command
ExecStartPre=/usr/bin/mkdir -p /var/lib/phantom-coin/data/mempool
ExecStartPre=/usr/bin/install -m 0644 /etc/phantom-coin/genesis_note.bin /var/lib/phantom-coin/data/mempool/genesis_note.bin
ExecStart=/opt/phantom-coin/bin/phantom-node \
  p2p-quic-listen \
  --addr 0.0.0.0:9000 \
  --store-dir /var/lib/phantom-coin/data \
  --fsync \
  --k 21 \
  --genesis /etc/phantom-coin/genesis.toml \
  --tx-proposer \
  --tx-proposer-interval-ms 5000

# Restart policy
Restart=on-failure
RestartSec=10s
StartLimitBurst=5
StartLimitIntervalSec=300

# Timeouts
TimeoutStartSec=60s
TimeoutStopSec=30s
KillMode=mixed
KillSignal=SIGTERM

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096
LimitMEMLOCK=infinity

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/phantom-coin
ReadOnlyPaths=/etc/phantom-coin
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=phantom-node

[Install]
WantedBy=multi-user.target
```

### 2. Status API Service

**File:** `/etc/systemd/system/phantom-node-status.service`

```ini
[Unit]
Description=Phantom-Coin Status API Server
Documentation=https://github.com/phantom-coin/phantom-coin
After=network-online.target phantom-node.service
Wants=network-online.target

[Service]
Type=simple
User=phantom
Group=phantom
WorkingDirectory=/opt/phantom-coin
Environment="RUST_LOG=info"

ExecStart=/opt/phantom-coin/bin/phantom-node \
  status-serve \
  --config /etc/phantom-coin/status-serve.toml \
  --genesis-note /etc/phantom-coin/genesis_note.bin

Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
KillMode=mixed

LimitNOFILE=65535

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/phantom-coin/data
ReadOnlyPaths=/etc/phantom-coin

StandardOutput=journal
StandardError=journal
SyslogIdentifier=phantom-status

[Install]
WantedBy=multi-user.target
```

### 3. Metrics Exporter Service

**File:** `/etc/systemd/system/phantom-node-metrics.service`

```ini
[Unit]
Description=Phantom-Coin Prometheus Metrics Exporter
After=network-online.target phantom-node.service

[Service]
Type=simple
User=phantom
Group=phantom
WorkingDirectory=/opt/phantom-coin

ExecStart=/opt/phantom-coin/bin/phantom-node \
  p2p-metrics-serve \
  --addr 127.0.0.1:9101

Restart=on-failure
RestartSec=5s

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

StandardOutput=journal
StandardError=journal
SyslogIdentifier=phantom-metrics

[Install]
WantedBy=multi-user.target
```

### 4. Miner Service (Optional)

**File:** `/etc/systemd/system/phantom-miner.service`

```ini
[Unit]
Description=Phantom-Coin Miner Client
After=network-online.target phantom-node-status.service
Wants=network-online.target

[Service]
Type=simple
User=phantom
Group=phantom
WorkingDirectory=/opt/phantom-coin

ExecStart=/opt/phantom-coin/bin/phantom-miner \
  run \
  --config /etc/phantom-coin/miner.toml

Restart=on-failure
RestartSec=10s

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

StandardOutput=journal
StandardError=journal
SyslogIdentifier=phantom-miner

[Install]
WantedBy=multi-user.target
```

### Systemd Management

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services (auto-start on boot)
sudo systemctl enable phantom-node.service
sudo systemctl enable phantom-node-status.service
sudo systemctl enable phantom-node-metrics.service
# Optional:
sudo systemctl enable phantom-miner.service

# Start services
sudo systemctl start phantom-node
sudo systemctl start phantom-node-status
sudo systemctl start phantom-node-metrics

# Check status
sudo systemctl status phantom-node
sudo systemctl status phantom-node-status

# View logs (live)
sudo journalctl -u phantom-node -f --lines=100
sudo journalctl -u phantom-node-status -f

# View logs (recent)
sudo journalctl -u phantom-node --since "1 hour ago"

# Restart services
sudo systemctl restart phantom-node

# Stop services
sudo systemctl stop phantom-node
sudo systemctl stop phantom-node-status
```

---

## Docker Deployment

### Dockerfile

**File:** `Dockerfile`

```dockerfile
# Multi-stage build for optimized image size
ARG BASE_RUNTIME=debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421
ARG BASE_BUILDER=rust:1-bookworm@sha256:ca8d52cf3eadfe814328f1cff05e3f0022b4cf696ddc8498ef26b52f71b201ad
FROM ${BASE_BUILDER} AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    libclang-dev \
    llvm-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binaries
RUN cargo build --release \
    -p phantom-node \
    -p phantom-miner \
    -p phantom-signer \
    --features "async,libp2p,quic"

# Runtime stage
FROM ${BASE_RUNTIME}

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create phantom user
RUN useradd -r -m -u 1000 -s /bin/bash phantom

# Copy binaries from builder
COPY --from=builder /build/target/release/phantom-node /usr/local/bin/
COPY --from=builder /build/target/release/phantom-miner /usr/local/bin/
COPY --from=builder /build/target/release/phantom-signer /usr/local/bin/

# Create directories
RUN mkdir -p /var/lib/phantom-coin/data \
             /var/lib/phantom-coin/mempool \
             /etc/phantom-coin \
    && chown -R phantom:phantom /var/lib/phantom-coin /etc/phantom-coin

USER phantom
WORKDIR /home/phantom

# Expose ports
EXPOSE 8080 8443 9000/udp 9100 9101

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/phantom-node"]
CMD ["status-serve", "--addr", "127.0.0.1:8080", "--mempool-dir", "/var/lib/phantom-coin/mempool"]
```

### docker-compose.yml

**File:** `docker-compose.yml`

```yaml
version: '3.8'

services:
  phantom-node:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: phantom-node
    restart: unless-stopped
    ports:
      - "9000:9000/udp"  # P2P QUIC
      - "9100:9100"      # libp2p
    volumes:
      - phantom-data:/var/lib/phantom-coin/data
      - phantom-mempool:/var/lib/phantom-coin/mempool
      - ./configs:/etc/phantom-coin:ro
    environment:
      - RUST_LOG=info
    command: >
      p2p-quic-listen
      --addr 0.0.0.0:9000
      --store-dir /var/lib/phantom-coin/data
      --fsync
      --k 21
      --genesis /etc/phantom-coin/genesis.toml
      --tx-proposer
      --tx-proposer-interval-ms 5000
    networks:
      - phantom-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"

  phantom-status:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: phantom-status
    restart: unless-stopped
    ports:
      - "8080:8080"   # HTTP API
      - "8443:8443"   # HTTPS API
    volumes:
      - phantom-mempool:/var/lib/phantom-coin/mempool
      - ./configs:/etc/phantom-coin:ro
      - ./certs:/etc/phantom-coin/certs:ro
    environment:
      - RUST_LOG=info
    command: >
      status-serve
      --config /etc/phantom-coin/status-serve.toml
      --genesis-note /etc/phantom-coin/genesis_note.bin
    depends_on:
      phantom-node:
        condition: service_healthy
    networks:
      - phantom-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz"]
      interval: 15s
      timeout: 5s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "3"

  phantom-metrics:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: phantom-metrics
    restart: unless-stopped
    environment:
      - RUST_LOG=info
    command: >
      p2p-metrics-serve
      --addr 0.0.0.0:9101
    depends_on:
      - phantom-node
    networks:
      - phantom-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9101/metrics"]
      interval: 30s
      timeout: 5s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "3"

  phantom-miner:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: phantom-miner
    restart: unless-stopped
    volumes:
      - ./configs:/etc/phantom-coin:ro
    environment:
      - RUST_LOG=info
    entrypoint: ["/usr/local/bin/phantom-miner"]
    command: >
      run
      --config /etc/phantom-coin/miner.toml
    depends_on:
      phantom-status:
        condition: service_healthy
    networks:
      - phantom-net
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "3"

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./monitoring/alerts:/etc/prometheus/alerts:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    networks:
      - phantom-net
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "3"

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources:ro
    environment:
      - GF_SECURITY_ADMIN_USER=${GRAFANA_ADMIN_USER:?set-in-env}
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD:?set-in-env}
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SERVER_ROOT_URL=http://localhost:3000
    depends_on:
      - prometheus
    networks:
      - phantom-net
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "3"

volumes:
  phantom-data:
    driver: local
  phantom-mempool:
    driver: local
  prometheus-data:
    driver: local
  grafana-data:
    driver: local

networks:
  phantom-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Docker Commands

```bash
# Build images
docker-compose build

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f phantom-node
docker-compose logs -f phantom-status
docker-compose logs --tail=100 -f

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Restart specific service
docker-compose restart phantom-node

# Check health
docker-compose ps
docker ps

# Execute commands in container
docker-compose exec phantom-node /bin/bash
docker-compose exec phantom-status curl http://localhost:8080/healthz

# View resource usage
docker stats
```

---

## Netzwerk & Firewall

### UFW (Ubuntu/Debian)

```bash
# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH (restrict to trusted IPs in production)
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp

# P2P (public)
sudo ufw allow 9000/udp comment 'Phantom P2P QUIC'
sudo ufw allow 9100/tcp comment 'Phantom libp2p'

# API (internal only - use VPN or private network)
# sudo ufw allow from 10.0.0.0/8 to any port 8080 proto tcp
# sudo ufw allow from 10.0.0.0/8 to any port 8443 proto tcp

# Metrics (internal only)
# sudo ufw allow from 10.0.0.0/8 to any port 9101 proto tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

### iptables (Advanced)

```bash
# Flush existing rules
sudo iptables -F
sudo iptables -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH (rate limit)
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# P2P
sudo iptables -A INPUT -p udp --dport 9000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9100 -j ACCEPT

# Save rules
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### Port Forwarding (Router)

Für Validator-Nodes **müssen** folgende Ports öffentlich erreichbar sein:

1. **9000/UDP** → Ihre Node-IP (P2P QUIC)
2. **9100/TCP** → Ihre Node-IP (libp2p)

**Nicht** öffentlich machen:
- 8080 (HTTP API)
- 8443 (HTTPS API)
- 9101 (Metrics)

---

*(Fortsetzung folgt im nächsten Teil...)*
