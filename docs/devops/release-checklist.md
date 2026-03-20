# Release Checklist

Standardisierte Checkliste für Phantom Coin Releases. Verwende diese für jeden Release-Prozess.

## Pre-Release (T-7 days)

### Code Freeze & Testing

- [ ] **Code Freeze** - Nur Bugfixes im Release-Branch
- [ ] **CI Pipeline grün** - Alle Tests bestehen
  ```bash
  # Check CI status
  gh run list --branch main --limit 5
  ```
- [ ] **Benchmarks** - Performance-Regression-Tests bestanden
  ```bash
  # Check latest bench results
  gh run view --log-failed
  ```
- [ ] **Security Audit** - Keine kritischen Vulnerabilities
  ```bash
  cargo audit --deny warnings
  ```
- [ ] **Integration Tests** - E2E-Tests auf Testnet erfolgreich
  ```bash
  make test-integration
  ```

### Documentation

- [ ] **Changelog aktualisiert** - `CHANGELOG.md` mit allen Changes
  ```markdown
  ## [v0.0.13] - 2025-11-10
  
  ### Added
  - Feature X
  
  ### Changed
  - Improved Y
  
  ### Fixed
  - Bug Z
  
  ### Breaking Changes
  - Migration required: ...
  ```
- [ ] **Migration Guide** - Falls Breaking Changes existieren
- [ ] **API Docs** - Alle neuen APIs dokumentiert
- [ ] **README aktualisiert** - Installation/Upgrade-Anweisungen aktuell

### Infrastructure Prep

- [ ] **Staging Deployment** - Release auf Staging getestet
  ```bash
  kubectl set image deployment/phantom-node phantom-node=ghcr.io/.../phantom-node:v0.0.13-rc1
  ```
- [ ] **Backup-Plan** - Rollback-Prozedur dokumentiert
- [ ] **Monitoring Dashboards** - Alerts und Dashboards aktualisiert
- [ ] **Capacity Planning** - Ressourcen ausreichend für neuen Release

---

## Release Day (T-0)

### Pre-Release Verification

- [ ] **Final CI Check** - Alle Pipelines grün
  ```bash
  gh run list --workflow=CI --branch main --limit 1
  ```
- [ ] **Git Tag erstellen** - Release-Tag vorbereitet
  ```bash
  git tag -a v0.0.13 -m "Release v0.0.13: [Summary]"
  git push origin v0.0.13
  ```
- [ ] **Release Notes** - Draft fertig auf GitHub
- [ ] **Communication** - Release-Announcement vorbereitet (Discord, Twitter, etc.)

### Release Execution

#### 1. Trigger Release Pipeline

```bash
# Push tag triggers release workflow
git push origin v0.0.13
```

- [ ] **Build Artifacts** - Warten bis alle Artifacts gebaut sind
  - Linux x86_64
  - Linux ARM64
  - macOS x86_64
  - macOS ARM64
  - Perf-tuned variants
- [ ] **Docker Images** - Multi-Arch Image gepusht zu GHCR
- [ ] **Signatures** - Cosign signatures erstellt
- [ ] **SHA256SUMS** - Checksums generiert und signiert

#### 2. Verify Release Artifacts

```bash
# Check release exists
gh release view v0.0.13

# Download and verify
wget https://github.com/.../phantomcoin-v0.0.13-linux-x86_64.tar.gz
wget https://github.com/.../SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# Verify signature
wget https://github.com/.../SHA256SUMS.sig
wget https://github.com/.../SHA256SUMS.pem
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp "https://github.com/Global-Phantom-Network/Phantom-Coin" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

- [ ] **Binary funktioniert** - Smoke test auf clean system
  ```bash
  ./phantom-node --version
  ./phantom-node --help
  ```
- [ ] **Docker Image pullbar** - Image kann heruntergeladen werden
  ```bash
  docker pull ghcr.io/global-phantom-network/phantom-node:v0.0.13
  docker run --rm ghcr.io/.../phantom-node:v0.0.13 --version
  ```

#### 3. Publish Release

- [ ] **GitHub Release** - Publish release (nicht mehr Draft)
  ```bash
  gh release edit v0.0.13 --draft=false
  ```
- [ ] **Release Notes** - Finale Release Notes online
- [ ] **Documentation Site** - Docs aktualisiert (docs.phantom.network)

---

## Post-Release (T+0 to T+7)

### Deployment & Monitoring

#### Observer Nodes (T+0, within 1h)

- [ ] **Observer Nodes upgraden** - Kein Impact auf Konsens
  ```bash
  # Rolling update observers
  for node in observer{1..3}; do
    ssh $node "systemctl stop phantom-node && \
               cp phantom-node-v0.0.13 /usr/local/bin/phantom-node && \
               systemctl start phantom-node"
    sleep 30
  done
  ```
- [ ] **Health Checks** - Alle Observer Nodes healthy

#### Validator Nodes (T+2h, after Observer stable)

- [ ] **Maintenance Window** - Communication gesendet
- [ ] **Rolling Upgrade** - Max 1/3 gleichzeitig
  ```bash
  # Upgrade validator1
  ssh validator1 "systemctl stop phantom-node && \
                  cp phantom-node-v0.0.13 /usr/local/bin/phantom-node && \
                  systemctl start phantom-node"
  # Wait for sync + 10 min buffer
  sleep 600
  
  # Repeat for validator2, validator3...
  ```
- [ ] **Consensus Check** - Finality läuft weiter
  ```bash
  watch -n 5 'curl -s http://validator1:18081/status | jq ".finalized_height"'
  ```

#### Production Monitoring (T+0 to T+24h)

- [ ] **Metrics Dashboard** - Kontinuierlich beobachten
  - Block production rate
  - Finality time
  - Memory/CPU usage
  - Error rates
- [ ] **Logs Review** - Keine unerwarteten Errors
  ```bash
  journalctl -u phantom-node --since "1 hour ago" | grep -i error
  ```
- [ ] **Performance Comparison** - Baseline vs. New Release
  - Latency P50/P95
  - Throughput
  - Resource usage

### Communication

- [ ] **Release Announcement** - Public announcement
  - Discord #announcements
  - Twitter/X
  - Blog post (optional)
- [ ] **Validator Communication** - Notify validators
  - Discord #validators
  - Email list
  - Upgrade instructions
- [ ] **Documentation** - Updated everywhere
  - Website docs
  - GitHub README
  - Docker Hub description

### Post-Release Review (T+7 days)

- [ ] **Incident Review** - Any issues während Release?
- [ ] **Performance Analysis** - Benchmarks Pre vs. Post
- [ ] **User Feedback** - Community feedback gesammelt
- [ ] **Process Improvements** - Lessons Learned dokumentiert
- [ ] **Next Release Planning** - Roadmap aktualisiert

---

## Emergency Rollback

Falls kritische Probleme auftreten:

### Decision Criteria (Rollback wenn)

- [ ] Critical bugs (data loss, security, crash loop)
- [ ] Performance degradation > 50%
- [ ] Consensus halt > 15 minutes
- [ ] > 33% validators unable to run new version

### Rollback Procedure

```bash
# 1. Announce rollback immediately
# Slack #phantom-ops-emergency

# 2. Coordinate with validators
# Discord #validators "URGENT: Rollback to v0.0.12"

# 3. Execute rollback on all nodes
for node in validator{1..3} observer{1..3}; do
  ssh $node "systemctl stop phantom-node && \
             cp /usr/local/bin/phantom-node.backup /usr/local/bin/phantom-node && \
             systemctl start phantom-node"
done

# 4. Monitor recovery
watch -n 5 'curl -s http://validator1:18081/status | jq ".height"'

# 5. Post-mortem
# - Root cause analysis
# - Fix in new release
# - Update this checklist
```

---

## Release Template

```markdown
# Phantom Coin v0.0.13

**Release Date:** 2025-11-10  
**Docker Image:** `ghcr.io/global-phantom-network/phantom-node:v0.0.13`

## Highlights

- 🚀 **Performance:** 20% faster block production
- 🔒 **Security:** Fixed CVE-2025-XXXX
- ✨ **Features:** New RPC endpoint `/v2/status`

## Downloads

| Platform | Binary | SHA256 |
|----------|--------|--------|
| Linux x86_64 | [Download](https://github.com/.../phantomcoin-v0.0.13-linux-x86_64.tar.gz) | `abc123...` |
| Linux ARM64 | [Download](https://github.com/.../phantomcoin-v0.0.13-linux-aarch64.tar.gz) | `def456...` |
| macOS x86_64 | [Download](https://github.com/.../phantomcoin-v0.0.13-macos-x86_64.tar.gz) | `ghi789...` |
| macOS ARM64 | [Download](https://github.com/.../phantomcoin-v0.0.13-macos-arm64.tar.gz) | `jkl012...` |

[See all artifacts →](https://github.com/.../releases/tag/v0.0.13)

## What's Changed

### Added
- New `/v2/status` RPC endpoint with extended metrics
- Support for parallel transaction execution

### Changed
- Improved consensus performance (20% faster)
- Updated base Docker image to Debian Bookworm

### Fixed
- **Security:** Fixed potential DoS in P2P handshake (CVE-2025-XXXX)
- Memory leak in long-running nodes
- Incorrect finality reporting in edge cases

### Breaking Changes
⚠️ **Migration Required:**
```bash
# Backup your data
sudo cp -r /var/lib/phantom/data /backup/

# Upgrade binary
sudo cp phantom-node /usr/local/bin/

# Run migration
phantom-node migrate --data-dir /var/lib/phantom/data

# Restart
sudo systemctl restart phantom-node
```

## Upgrade Instructions

See [Upgrade Procedures](docs/devops/upgrade-procedures.md) for detailed instructions.

### Quick Upgrade (Binary)

```bash
# Download
wget https://github.com/.../phantomcoin-v0.0.13-linux-x86_64.tar.gz

# Verify
wget https://github.com/.../SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# Install
tar -xzf phantomcoin-v0.0.13-linux-x86_64.tar.gz
sudo cp phantom-node /usr/local/bin/

# Restart
sudo systemctl restart phantom-node
```

### Quick Upgrade (Docker)

```bash
# Pull new image
docker pull ghcr.io/global-phantom-network/phantom-node:v0.0.13

# Update docker-compose.yml (change image tag)
# docker compose pull
# docker compose up -d
```

## Verification

```bash
# Check version
phantom-node --version
# Expected: phantom-node v0.0.13

# Verify signature (optional, recommended)
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp "https://github.com/Global-Phantom-Network/Phantom-Coin" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

## Known Issues

- Minor UI glitch in Grafana dashboard (workaround in docs)
- Increased memory usage on ARM64 (investigating)

## Full Changelog

[v0.0.12...v0.0.13](https://github.com/.../compare/v0.0.12...v0.0.13)

---

**Questions?** Ask in [Discord #support](https://discord.gg/...) or [open an issue](https://github.com/.../issues).
```

---

## Tools & Commands Reference

```bash
# List recent releases
gh release list --limit 10

# View release details
gh release view v0.0.13

# Download release artifacts
gh release download v0.0.13

# Create draft release
gh release create v0.0.13 --draft --title "v0.0.13" --notes-file RELEASE_NOTES.md

# Upload additional artifacts
gh release upload v0.0.13 additional-file.tar.gz

# Publish (undraft) release
gh release edit v0.0.13 --draft=false

# Delete release (emergency only!)
gh release delete v0.0.13 --yes
```

---

## Siehe auch

- [Upgrade Procedures](./upgrade-procedures.md)
- [Emergency Procedures](./emergency-procedures.md)
- [Docker Compose Guide](./docker-compose.md)
- [CI/CD Pipeline](../../.github/workflows/release.yml)
