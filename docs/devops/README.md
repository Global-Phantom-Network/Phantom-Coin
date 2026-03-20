# DevOps Documentation

## English version

Full operations and deployment documentation for Phantom-Coin.

## 🚀 Quick Start

- **First Time Setup:** [Docker Compose Guide](./docker-compose.md)
- **Production Deployment:** [Release Process](./release-process.md)
- **Upgrade Existing Node:** [Upgrade Procedures](./upgrade-procedures.md)
- **Emergency Response:** [Emergency Procedures](./emergency-procedures.md)

---

## 📚 Documentation Index

### Deployment & Operations

| Document | Description | Audience |
|----------|-------------|----------|
| [Docker Compose Guide](./docker-compose.md) | **⭐ START HERE** - Local multi-node setup | Developers, QA |
| [Upgrade Procedures](./upgrade-procedures.md) | **⭐ OPERATIONS** - Safe upgrade processes | Operators, Validators |
| [Emergency Procedures](./emergency-procedures.md) | **⭐ ON-CALL** - Incident response runbooks | SRE, On-Call |
| [Release Checklist](./release-checklist.md) | **⭐ RELEASES** - Release process checklist | Release Managers |

### Build & Release

| Document | Description |
|----------|-------------|
| [Reproducible Builds](./reproducible-builds.md) | Deterministic build configuration |
| [Perf Builds](./perf-builds.md) | Performance-optimized builds |
| [Docker Digest Pinning](./docker-digest-pinning.md) | Base image pinning for reproducibility |

### Security

| Document | Description |
|----------|-------------|
| [HSM Signing](./hsm-signing.md) | Hardware Security Module signing procedures |
| [HSM Flows](./hsm-flows.md) | HSM integration workflows |

### Legacy/Reference

| Document | Description |
|----------|-------------|
| [Legacy Release Process](./release-process.md) | Previous release documentation |
| [Legacy Upgrades](./upgrades.md) | Previous upgrade documentation |
| [Legacy Emergency](./emergency.md) | Previous emergency documentation |
| [Upgrade Epoch](./upgrade-epoch.md) | Epoch-based upgrade concept |

---

## 🎯 Common Tasks

### Local Development

```bash
# Start 3-node testnet
docker compose up -d

# Watch logs
docker compose logs -f

# Check health
set -a
. ./.env
set +a
curl -H "Authorization: Bearer $NODE1_STATUS_AUTH_TOKEN" http://localhost:18081/status | jq .

# Stop
docker compose down
```

**See:** [Docker Compose Guide](./docker-compose.md)

### Deploying a Release

```bash
# 1. Download verified binary
wget https://github.com/.../phantomcoin-v0.0.13-linux-x86_64.tar.gz
sha256sum -c SHA256SUMS --ignore-missing

# 2. Backup
sudo cp -r /var/lib/phantom-coin/data /backup/
sudo cp /etc/phantom-coin/genesis_note.bin /backup/

# 3. Install
tar -xzf phantomcoin-v0.0.13-linux-x86_64.tar.gz
sudo cp phantom-node /usr/local/bin/

# 4. Restart
sudo systemctl restart phantom-node

# 5. Verify
phantom-node --version
curl http://localhost:18081/healthz
```

**See:** [Upgrade Procedures](./upgrade-procedures.md) | [Release Checklist](./release-checklist.md)

### Responding to Incidents

```bash
# P0: Node Down
systemctl status phantom-node
journalctl -u phantom-node --since "30 minutes ago" | tail -100
systemctl restart phantom-node

# P0: Consensus Halt
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq '{height, finalized_height}'
# Check other validators...

# P1: High Memory
free -h
ps aux --sort=-%mem | head -20
systemctl restart phantom-node
```

**See:** [Emergency Procedures](./emergency-procedures.md)

---

## 🏗️ Architecture

### Local Development Setup (Docker Compose)

```
┌─────────────────────────────────────────────┐
│           Docker Network                     │
├─────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│  │ Node 1  │  │ Node 2  │  │ Node 3  │    │
│  │Validator│  │Validator│  │Observer │    │
│  │ +Miner  │  │         │  │         │    │
│  │  :18081 │  │  :18082 │  │  :18083 │    │
│  └────┬────┘  └────┬────┘  └────┬────┘    │
│       └────────────┴────────────┘          │
│                    │                        │
│         ┌──────────┴─────────┐            │
│         │    Prometheus      │            │
│         │       :9090        │            │
│         └──────────┬─────────┘            │
│                    │                        │
│         ┌──────────┴─────────┐            │
│         │     Grafana        │            │
│         │      :3000         │            │
│         └────────────────────┘            │
└─────────────────────────────────────────────┘
```

### Production Deployment

```
┌────────────────────────────────────────────┐
│              Load Balancer                  │
│            (Cloudflare/AWS ALB)            │
└──────────┬──────────────┬──────────────────┘
           │              │
    ┌──────┴─────┐ ┌─────┴──────┐
    │ Validator  │ │ Validator  │ ...
    │   Region A │ │   Region B │
    └──────┬─────┘ └─────┬──────┘
           │              │
    ┌──────┴──────────────┴──────┐
    │    Distributed Storage      │
    │      (S3/GCS Backup)       │
    └────────────────────────────┘
           │
    ┌──────┴──────────────────────┐
    │   Monitoring & Alerting     │
    │  (Prometheus/Grafana/PD)    │
    └─────────────────────────────┘
```

---

## 🔧 CI/CD Pipeline

### Release Workflow

```
git tag v0.0.13
     │
     ├─ Build Artifacts (6 platforms)
     │   ├─ Linux x86_64
     │   ├─ Linux ARM64
     │   ├─ macOS x86_64
     │   ├─ macOS ARM64
     │   ├─ Perf Linux x86_64 (skylake)
     │   └─ Perf Linux ARM64 (neoverse-n1)
     │
     ├─ Docker Multi-Arch Build
     │   ├─ linux/amd64
     │   └─ linux/arm64
     │
     ├─ Signing & Verification
     │   ├─ SHA256SUMS generation
     │   ├─ Cosign keyless signing
     │   └─ Image signing
     │
     └─ GitHub Release
         ├─ Artifacts upload
         ├─ Release notes
         └─ Docker GHCR publish
```

**Workflow File:** [`.github/workflows/release.yml`](../../.github/workflows/release.yml)

---

## 📊 Monitoring

### Key Metrics

| Metric | Alert Threshold | Dashboard |
|--------|----------------|-----------|
| Node Health | Down > 1min | Node Overview |
| Block Height | Stuck > 5min | Consensus |
| Memory Usage | > 90% | Resources |
| Disk Space | > 85% | Resources |
| P2P Peers | < 3 | Network |
| Finality Time | > 30s | Consensus |

### Dashboards

- **Prometheus:** http://localhost:9090
- **Grafana:** http://localhost:3000 (mit den in `.env` gesetzten Zugangsdaten)
- **Metrics Endpoint:** http://localhost:18081/metrics

**See:** [Observability Guide](../observability/README.md)

---

## 🆘 Support

### Getting Help

1. **Documentation:** Check relevant guide above
2. **GitHub Issues:** [Open an issue](https://github.com/Global-Phantom-Network/Phantom-Coin/issues)
3. **Discord:** `#support` or `#validators`
4. **Emergency:** See [On-Call Contacts](./emergency-procedures.md#emergency-contacts)

### Contributing

Found a bug in documentation? [Submit a PR](https://github.com/Global-Phantom-Network/Phantom-Coin/pulls)!

---

## 📝 Document Status

| Document | Last Updated | Status |
|----------|--------------|--------|
| Docker Compose | 2025-11-09 | ✅ Current |
| Upgrade Procedures | 2025-11-09 | ✅ Current |
| Emergency Procedures | 2025-11-09 | ✅ Current |
| Release Checklist | 2025-11-09 | ✅ Current |
| HSM Signing | 2025-11-09 | ✅ Current |
| Reproducible Builds | 2025-11-08 | ✅ Current |
| Legacy Docs | Various | ⚠️ Reference Only |

---

## 🗺️ Roadmap

### Completed (v0.0.12+)
- ✅ Docker Compose multi-node setup
- ✅ Comprehensive upgrade procedures
- ✅ Emergency response runbooks
- ✅ Release checklist
- ✅ Reproducible builds
- ✅ Multi-arch Docker images
- ✅ Cosign signing

### Planned
- [ ] Kubernetes Helm charts
- [ ] Terraform modules (AWS, GCP, Azure)
- [ ] Ansible playbooks
- [ ] Auto-scaling policies
- [ ] Advanced monitoring (Datadog, New Relic)
- [ ] Performance benchmarking integration
- [ ] Blue-green deployment automation

---

**Last Updated:** 2025-11-09  
**Maintained By:** DevOps Team  
**Version:** 1.0.0

## Deutsche Version

Vollständige Operations- und Deployment-Dokumentation für Phantom-Coin.
