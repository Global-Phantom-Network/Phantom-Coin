# PhantomCoin Emergency Runbook

## Übersicht
Dieses Runbook beschreibt Notfall-Prozeduren für kritische Incidents: Chain-Halt, Konsensus-Bugs, Security-Vulnerabilities, Datenkorruption, Performance-Collapse und Disaster Recovery.

**Prinzipien:**
- Reproduzierbare Artefakte (keine Unix-Timestamps)
- Hash-Verifikation bei jedem Deployment
- Koordinierte Kommunikation (Discord #emergency)
- Post-Mortem nach jedem Incident

---

## 1. Incident Classification & Response Times

### Severity Levels

| Severity | Beschreibung | Response Time | Beispiele |
|----------|--------------|---------------|----------|
| **P0 - Critical** | Chain-Halt, Security-Breach | 15 Min | Konsensus-Fork, Private-Key-Leak |
| **P1 - High** | Partielle Degradation | 1 Std | 50% Validator offline, State-Corruption |
| **P2 - Medium** | Non-Critical Bug | 4 Std | Memory-Leak, Performance-Regression |
| **P3 - Low** | Minor Issue | 24 Std | Metrics-Ausfall, Documentation-Fehler |

### Incident Triage (erste 5 Minuten)

```bash
# 1. Incident-Typ identifizieren
# - Konsensus-Bug: Finality stagniert, Fork detektiert
# - Security: Vulnerability-Report, unautorisierten Zugriff
# - Performance: TPS < 10%, hohe Latenz (>5s)
# - Data-Corruption: State-Mismatches, Header-Verification-Failures

# 2. Impact-Assessment
# - Betroffene Nodes (lokal / testnet / mainnet?)
# - Betroffene Version/Commit
# - Reproduzierbar? (Steps to Reproduce)

# 3. Eskalation
# - P0/P1: Sofort Discord #emergency pingen (@core-team)
# - P2/P3: GitHub Issue, reguläre Kanäle
```

---

## 2. P0: Chain-Halt-Prozeduren

### Anwendungsfall
- **Konsensus-Fork**: >33% Validator auf unterschiedlichen Chains
- **Kritischer Bug**: Node crasht bei bestimmtem Block
- **Security-Exploit**: Aktiver Angriff auf Netzwerk

### Chain-Halt-Flow (koordiniert)

#### 2.1 Freeze-Entscheidung (Incident Commander)
```bash
# 1. Schnell-Analyse (max 5 Min)
# - Logs der letzten 100 Blocks analysieren
sudo journalctl -u phantom-node --since "10 minutes ago" | grep -E "ERROR|PANIC|FORK"

# - Metrics prüfen
curl -s http://localhost:9100/metrics | grep -E "finality|fork|consensus_error"

# 2. Freeze-Signal (Discord #emergency)
# Nachricht: "CHAIN FREEZE INITIATED - All validators STOP immediately"
# Reason: <kurze Beschreibung>
# Affected Block: <Block-Nummer>
```

#### 2.2 Koordinierter Node-Stop (alle Validator)
```bash
# Validators stoppen Nodes SOFORT (innerhalb 2 Min nach Freeze-Signal)
sudo systemctl stop phantom-node

# Bestätigung im Discord: "Node stopped, last block: <N>"

# State-Backup ziehen (vor jeder Änderung)
BACKUP_DIR=/backup/emergency-$(date +%Y%m%d-%H%M%S)
mkdir -p $BACKUP_DIR
cp -r /data/phantom/state $BACKUP_DIR/
cp -r /data/phantom/store $BACKUP_DIR/
cp /var/log/phantom-node.log $BACKUP_DIR/
echo "Backup completed: $BACKUP_DIR"
```

#### 2.3 Root-Cause-Analysis (Core-Team, parallel)
```bash
# 1. Logs aggregieren (alle Validator senden Logs)
# Discord #emergency: Upload phantom-node.log (letzte 1000 Zeilen)
sudo journalctl -u phantom-node -n 1000 > phantom-node-last1000.log

# 2. State-Comparison (Fork-Detection)
# Jeder Validator: aktuellen Anchor-Index und State-Root posten
curl -s http://127.0.0.1:9100/metrics | grep '^pc_node_anchor_index '
curl -s \
  -H "Authorization: Bearer $(cat /etc/phantom-coin/status-auth.token)" \
  http://127.0.0.1:8080/state/root

# 3. Diff-Analyse
# Falls Fork: Identify Fork-Point (Block-Nummer)
# Falls Bug: Stack-Trace, Reproduktions-Steps
```

#### 2.4 Hotfix-Deployment (Express-Track)
```bash
# 1. Hotfix-Branch erstellen (Core-Dev)
git checkout -b hotfix/p0-chain-halt v1.2.3
# Fix implementieren
git commit -m "fix(consensus): P0 hotfix for block <N> panic"
git tag v1.2.4-hotfix
git push origin v1.2.4-hotfix

# 2. Emergency-Release (CI, manuell getriggert)
# GitHub Actions: Run workflow "Release" mit Tag v1.2.4-hotfix
# Reproduzierbare Binaries + Docker-Images werden gebaut

# 3. Hash-Verifikation (CRITICAL)
wget https://github.com/.../releases/download/v1.2.4-hotfix/SHA256SUMS
wget https://github.com/.../releases/download/v1.2.4-hotfix/phantomcoin-v1.2.4-hotfix-linux-x86_64.tar.gz
sha256sum -c SHA256SUMS
# MUSS grün sein, sonst NICHT deployen
```

#### 2.5 Koordinierter Restart (Staggered)
```bash
# Incident Commander gibt Signal: "RESTART in 3 stages"
# Stage 1 (33% Validator): T+0
# Stage 2 (33% Validator): T+5 Min
# Stage 3 (33% Validator): T+10 Min

# Jeder Validator:
# 1. Neue Binary installieren
sudo cp phantomcoin-v1.2.4-hotfix/phantom-node /usr/local/bin/
sudo chmod +x /usr/local/bin/phantom-node

# 2. Version prüfen
/usr/local/bin/phantom-node --version | grep v1.2.4-hotfix

# 3. Node starten (NUR bei eigenem Stage-Signal)
sudo systemctl start phantom-node

# 4. Bestätigung im Discord
echo "Node restarted, syncing from block <N>"
```

#### 2.6 Post-Restart-Validierung
```bash
# 1. Finality-Check (nach 15 Min)
curl -s http://localhost:9100/metrics | grep pc_node_finalized_block
# Erwartung: Block-Nummer steigt

# 2. Fork-Detection
# Alle Validator: finalized Block-Hash vergleichen
# MUSS identisch sein

# 3. Network-Health
curl http://localhost:9000/readyz
# Erwartung: {"ok":true}
```

---

## 3. P1: State-Corruption Recovery

### Symptome
- State-Mismatches zwischen Nodes
- Header-Verification-Failures
- Payload-Root-Mismatches

### Recovery-Prozedur

```bash
# 1. Node stoppen
sudo systemctl stop phantom-node

# 2. State löschen (Headers/Payloads bleiben)
rm -rf /data/phantom/state

# 3. Optional: State-Snapshot von vertrauenswürdigem Node holen
# Trusted-Node-Operator stellt Snapshot bereit
scp trusted-node:/data/phantom/state-snapshot.tar.gz /tmp/
tar -xzf /tmp/state-snapshot.tar.gz -C /data/phantom/

# 4. Lokale State-DBs reparieren
phantom-node db repair --store-dir /data/phantom/store

# 4b. Falls Repair fehlschlägt: lokale State-DBs bewusst resetten (destruktiv)
phantom-node db reset --store-dir /data/phantom/store --yes

# 5. Node starten
sudo systemctl start phantom-node

# 6. Sync-Validierung
# State sollte mit Netzwerk konsistent sein nach 10-30 Min
sudo journalctl -u phantom-node -f
```

---

## 4. P0: Security-Incident (Vulnerability-Exploit)

### Anwendungsfall
- **Private-Key-Leak**: HSM kompromittiert, Validator-Key leaked
- **Remote-Code-Execution**: Exploit in RPC-Handler entdeckt
- **DoS-Attack**: Massive RPC-Floods

### Sonderfall: kontaminierte Workspace-/Release-Artefakte

Wenn ein ZIP, Backup oder Ad-hoc-Artefakt repo-lokale Runtime-Daten enthält, ist das als Security-Incident zu behandeln.

```bash
# 1. Workspace sofort auf repo-lokale Runtime-Artefakte prüfen
bash scripts/security/scan_runtime_artifacts.sh

# 2. Ad-hoc-Artefakt nicht weiter verteilen
# 3. server.key und wiederverwendete Validator-/Payout-Keystores rotieren,
#    falls das Artefakt an Dritte ging oder langfristig wiederverwendet wird

# 4. Repo-lokale Runtime-Artefakte nach Prüfung entfernen
bash scripts/security/clean_runtime_artifacts.sh --force
```

Behandle dabei insbesondere diese Pfade als offengelegt, wenn sie in einem weitergegebenen Artefakt enthalten waren:
- `pc-data/`
- `pc-data-validator/`
- `apps/phantom-dashboard/src-tauri/pc-data/`
- `server.key`, `server.crt`, `status_auth_token.txt`
- Validator-/Payout-Keystores wie `validator_bls.ks.toml`, `seat_bls.toml`, `payout_schnorr.toml`

### Security-Incident-Flow

#### 4.1 Immediate-Isolation
```bash
# 1. Betroffene Nodes vom Netzwerk isolieren
# Firewall-Regel: Block alle eingehenden Verbindungen
sudo iptables -A INPUT -p tcp --dport 9000 -j DROP
sudo iptables -A INPUT -p tcp --dport 9100 -j DROP

# 2. Node stoppen (State-Backup vorher!)
sudo systemctl stop phantom-node

# 3. Forensics-Snapshot ziehen
sudo tar -czf /backup/forensics-$(date +%s).tar.gz /data/phantom /var/log
```

#### 4.2 Key-Rotation (falls HSM kompromittiert)
```bash
# 1. Alten Validator-Key über den release-/netzwerkspezifischen On-Chain-Rotation-Flow widerrufen
# Kein generisches `phantom-node validator-key-revoke`-Subcommand vorhanden.

# 2. Neuen Key auf frischem HSM generieren
yubico-piv-tool -s 9d -a generate -A ECCP384 -o new-emergency-key.pem

# 3. Anschließend den dokumentierten On-Chain-Rotation-Flow der aktuellen Release-Doku ausführen
# Kein generisches `phantom-node validator-key-update`-Subcommand vorhanden.
```

#### 4.3 Patch-Deployment (CVE-Fix)
```bash
# 1. Security-Patch entwickeln (NICHT öffentlich committen)
# Privates Repo für Security-Fixes

# 2. Binaries direkt an Validator-Betreiber senden (verschlüsselt)
# PGP-verschlüsselte .tar.gz per Signal/Telegram

# 3. Koordinierter Rollout (innerhalb 1 Stunde)
# Alle Validator upgraden auf gepatche Version

# 4. Nach 24h: Public-Disclosure
# CVE-Report, GitHub Security Advisory, Patch-Release
```

---

## 5. Disaster Recovery (Datacenter-Ausfall)

### Backup-Strategy

#### 5.1 Daily State-Snapshots
```bash
# Cronjob (täglich 03:00 UTC)
0 3 * * * /opt/scripts/backup-phantom-state.sh

# backup-phantom-state.sh
#!/bin/bash
set -euo pipefail
DATE=$(date +%Y%m%d)
BACKUP_DIR=/backup/phantom-state-$DATE
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/state.tar.gz /data/phantom/state
tar -czf $BACKUP_DIR/store.tar.gz /data/phantom/store
sha256sum $BACKUP_DIR/*.tar.gz > $BACKUP_DIR/SHA256SUMS

# Upload zu S3/Backblaze (verschlüsselt)
rclone copy $BACKUP_DIR remote:phantom-backups/ --crypt-password=$BACKUP_PASSPHRASE
```

#### 5.2 Cross-Region-Restore
```bash
# 1. Neuen Server in anderem Datacenter provisionieren
# Specs: identisch zu ausgefallenen Node

# 2. Latest Snapshot herunterladen
rclone copy remote:phantom-backups/phantom-state-20250108 /tmp/ --crypt-password=$BACKUP_PASSPHRASE

# 3. Snapshot verifizieren
cd /tmp/phantom-state-20250108
sha256sum -c SHA256SUMS

# 4. State/Store wiederherstellen
tar -xzf state.tar.gz -C /data/phantom/
tar -xzf store.tar.gz -C /data/phantom/

# 5. Node starten (sync ab Snapshot-Block)
sudo systemctl start phantom-node

# 6. Sync-Validierung (kann 1-3 Stunden dauern)
sudo journalctl -u phantom-node -f
```

---

## 6. Communication Protocols

### Incident-Channels

| Kanal | Verwendung | Audience |
|-------|------------|----------|
| **Discord #emergency** | P0/P1 Real-Time-Koordination | Core-Team, Validator |
| **GitHub Security Advisory** | CVE-Reports, Patches | Public (nach Disclosure) |
| **Twitter @PhantomCoin** | Status-Updates | Community |
| **validator-emergency@** | Direct-Email (verschlüsselt) | Validator-Betreiber |

### Status-Page-Updates
```bash
# 1. Incident erkannt → "Investigating"
curl -X POST https://status.phantom-coin.org/api/v1/incidents \
  -H "Authorization: Bearer $STATUS_API_KEY" \
  -d '{"status":"investigating","message":"Chain finality delayed, investigating..."}
'
# 2. Hotfix deployed → "Monitoring"
# ...

# 3. Resolved → "Resolved"
# ...
```

---

## 7. Rollback-Prozeduren

### Schneller Rollback (Binary-Swap)
```bash
# 1. Node stoppen
sudo systemctl stop phantom-node

# 2. Alte Binary wiederherstellen (aus Backup)
sudo cp /usr/local/bin/phantom-node.backup.20250108 /usr/local/bin/phantom-node

# 3. Version prüfen
/usr/local/bin/phantom-node --version

# 4. Node starten
sudo systemctl start phantom-node

# 5. Health-Check
curl http://localhost:9000/readyz
```

### Tiefer Rollback (State-Restore)
```bash
# Anwendungsfall: Hotfix hat State korrumpiert
# 1. Node stoppen
sudo systemctl stop phantom-node

# 2. State-Backup wiederherstellen (Pre-Hotfix)
rm -rf /data/phantom/state
tar -xzf /backup/state-pre-hotfix.tar.gz -C /data/phantom/

# 3. Alte Binary
sudo cp /usr/local/bin/phantom-node.pre-hotfix /usr/local/bin/phantom-node

# 4. Node starten
sudo systemctl start phantom-node
```

---

## 8. Post-Mortem Template

```markdown
# Incident Post-Mortem: <Titel>

**Datum:** 2025-01-08
**Severity:** P0
**Duration:** 45 Min (detected → resolved)
**Impact:** Chain-Halt, 100% Validator betroffen

## Timeline (UTC)
- **14:32**: Incident detected (Finality stagniert bei Block 123456)
- **14:35**: Freeze-Signal, Validator stoppen Nodes
- **14:40**: Root-Cause identifiziert (Konsensus-Bug in v1.2.3)
- **14:50**: Hotfix v1.2.4 deployed
- **15:10**: Koordinierter Restart (3 Stages)
- **15:17**: Chain resumed, Finality normal

## Root Cause
- **Bug:** Off-by-one-Error in Ack-Distance-Berechnung
- **Trigger:** Spezifischer Parent-List-Pattern bei Block 123456
- **Code:** `crates/pc-consensus/src/engine.rs:456`

## Fix
- **Patch:** Bounds-Check ergänzt, Unit-Test hinzugefügt
- **PR:** #789
- **Release:** v1.2.4-hotfix

## Prevention
- [ ] Fuzzing für Parent-List-Patterns erweitern
- [ ] Bench-Gate für Ack-Distances hinzufügen
- [ ] Property-Test: Ack-Distance niemals > d_max

## Action Items
- [ ] @dev: Fuzzer erweitern (bis 2025-01-15)
- [ ] @devops: Emergency-Runbook updaten (done)
- [ ] @community: Incident-Report veröffentlichen (bis 2025-01-10)
```

---

## 9. Emergency-Kontakte

| Rolle | Contact | Verfügbarkeit |
|-------|---------|---------------|
| **Incident Commander** | @core-lead (Discord) | 24/7 |
| **Lead-Dev** | dev@phantom-coin.org | 24/7 |
| **DevOps-Lead** | ops@phantom-coin.org | EU-Hours + On-Call |
| **Security-Team** | security@phantom-coin.org | 24/7 (PGP-Key: docs/SECURITY_KEY.asc) |

---

## 10. Checklisten

### Pre-Deployment (Hotfix)
- [ ] SHA256SUMS verifiziert
- [ ] Reproducibility-Check grün (CI)
- [ ] No-Build-Time-Injection-Check grün (CI)
- [ ] Binary auf Testnet getestet (falls Zeit)
- [ ] Rollback-Plan bereit
- [ ] Backup gezogen

### Post-Deployment
- [ ] `/readyz` gibt 200 zurück
- [ ] Finality resumed (Block-Nummer steigt)
- [ ] Keine ERROR-Logs in ersten 5 Min
- [ ] Metrics normal (CPU/RAM/Disk)
- [ ] Peers connected (>5)
- [ ] Validator: Attestations accepted

### Rollback-Trigger
- [ ] Node crasht wiederholt (>3x in 10 Min)
- [ ] Finality stagniert (>10 Min keine neuen Blocks)
- [ ] State-Mismatches zwischen Nodes
- [ ] Performance-Degradation >80% (TPS collapsed)
- [ ] Security-Indicator (unauthorized access, exploit detected)
