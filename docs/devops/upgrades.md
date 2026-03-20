# PhantomCoin Node-Upgrade & Migration-Runbook

## Übersicht
Dieses Runbook beschreibt sichere Node-Upgrades, Breaking-Change-Migrationen, Rollback-Prozeduren und Epochen-Übergänge für PhantomCoin-Fullnodes, Validator und Miner.

---

## 1. Standard-Upgrade (Minor/Patch, keine Breaking Changes)

### Voraussetzungen
- Aktuelles Backup (State, Headers, Payloads)
- Release Notes gelesen
- SHA256SUMS verifiziert

### Upgrade-Schritte

#### 1.1 Binary-Upgrade (systemd)
```bash
# 1. Neue Version herunterladen & verifizieren
cd /tmp
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.2.0/phantomcoin-v1.2.0-linux-x86_64.tar.gz
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v1.2.0/SHA256SUMS
sha256sum -c SHA256SUMS

# 2. Extrahieren
tar -xzf phantomcoin-v1.2.0-linux-x86_64.tar.gz

# 3. Node stoppen
sudo systemctl stop phantom-node

# 4. Backup des aktuellen Binaries
sudo cp /usr/local/bin/phantom-node /usr/local/bin/phantom-node.backup.$(date +%Y%m%d)

# 5. Neue Binary installieren
sudo cp phantom-node /usr/local/bin/phantom-node
sudo chmod +x /usr/local/bin/phantom-node

# 6. Version prüfen
/usr/local/bin/phantom-node --version

# 7. Node starten
sudo systemctl start phantom-node

# 8. Logs prüfen (erste 2 Minuten)
sudo journalctl -u phantom-node -f --since "2 minutes ago"
```

#### 1.2 Docker-Upgrade
```bash
# 1. Aktuelles Image pullen
docker pull ghcr.io/global-phantom-network/phantom-node:v1.2.0

# 2. Container stoppen & backup
docker stop phantom-node
docker commit phantom-node phantom-node-backup-$(date +%Y%m%d)

# 3. Container mit neuem Image starten
docker run -d --name phantom-node \
  -v /data/phantom:/data \
  -p 9000:9000 \
  ghcr.io/global-phantom-network/phantom-node:v1.2.0 \
  phantom-node status-serve --addr 127.0.0.1:9000 --mempool-dir /data

# 4. Logs prüfen
docker logs -f phantom-node
```

#### 1.3 Docker Compose Upgrade
```bash
cd deploy
# Image-Tag in docker-compose.yml anpassen oder :latest verwenden
docker-compose pull
docker-compose up -d
docker-compose logs -f node1
```

---

## 2. Breaking-Change-Migration (Major-Version)

### Erkennungsmerkmale
- **Major-Version-Bump** (v1.x.x → v2.0.0)
- Release Notes mit "BREAKING CHANGE"
- Neue Genesis-Parameter oder Konsensus-Regeln

### Migrations-Schritte

#### 2.1 Pre-Migration-Backup
```bash
# Vollständiges Backup von State, Store, Config
BACKUP_DIR=/backup/phantom-$(date +%Y%m%d-%H%M%S)
mkdir -p $BACKUP_DIR

# State (RocksDB/In-Memory Dump falls vorhanden)
cp -r /data/phantom/state $BACKUP_DIR/

# Store (Headers, Payloads)
cp -r /data/phantom/store $BACKUP_DIR/

# Mempool
cp -r /data/phantom/mempool $BACKUP_DIR/

# Config
cp /etc/phantom/config.toml $BACKUP_DIR/

# Binary (alte Version)
cp /usr/local/bin/phantom-node $BACKUP_DIR/phantom-node.v1

echo "Backup completed: $BACKUP_DIR"
```

#### 2.2 Migration ausführen (Beispiel: v1 → v2)

**Szenario: Neue Genesis-Parameter (k, epoch_len)**

```bash
# 1. Node stoppen
sudo systemctl stop phantom-node

# 2. Neue Binary installieren (siehe 1.1)
# ...

# 3. Config-Migration (falls Breaking Changes in config.toml)
# Beispiel: neue Parameter hinzufügen
cat >> /etc/phantom/config.toml <<EOF

# v2.0.0 neue Parameter
[consensus]
new_fee_model = "dynamic"
min_stake = 1000
EOF

# 4. Optional: release-spezifisches State-Migrations-Script ausführen
# Kein generisches `phantom-node migrate-state`-Subcommand vorhanden.
# Nur dokumentierte Migrations-Skripte aus dem jeweiligen Release verwenden.

# 5. Genesis-Update (falls Chain-Restart erforderlich)
# Bei Epochen-Upgrade ohne Chain-Restart: übersprungen
# Bei Hard-Fork: neues genesis.toml deployen
cp /tmp/genesis-v2.toml /etc/phantom/genesis.toml

# 6. Node mit neuem Binary starten
sudo systemctl start phantom-node

# 7. Validierung
sudo journalctl -u phantom-node -f
# Erwartete Log-Meldung: "migration successful, running v2.0.0"
```

#### 2.3 Rollback (falls Migration fehlschlägt)
```bash
# 1. Node stoppen
sudo systemctl stop phantom-node

# 2. Alte Binary wiederherstellen
sudo cp $BACKUP_DIR/phantom-node.v1 /usr/local/bin/phantom-node

# 3. Alte Config wiederherstellen
sudo cp $BACKUP_DIR/config.toml /etc/phantom/config.toml

# 4. State/Store wiederherstellen (falls migriert)
rm -rf /data/phantom/state /data/phantom/store
cp -r $BACKUP_DIR/state /data/phantom/
cp -r $BACKUP_DIR/store /data/phantom/

# 5. Node starten
sudo systemctl start phantom-node

# 6. Prüfen
sudo journalctl -u phantom-node -f
# Erwartete Log-Meldung: "running v1.x.x"
```

---

## 3. Epochen-Upgrade (koordinierter Netzwerk-Übergang)

### Epochen-Upgrade-Flow

**Beispiel: Neue Konsensus-Regeln ab Epoche 1000**

#### 3.1 Vorbereitung (1 Woche vor Epoche 1000)
```bash
# 1. Release Notes lesen
# - Ab Epoche 1000: neue VRF-Seed-Berechnung
# - Upgrade-Window: Epoche 990-999

# 2. Neue Binary installieren (unterstützt alte + neue Regeln)
# Binary erkennt automatisch, ab Epoche 1000 neue Regeln anzuwenden

# 3. Upgrade auf v2.1.0 (Epoche-aware)
# (siehe Schritte in 1.1)

# 4. Config-Check
# Kein generisches `phantom-node check-config`-Subcommand vorhanden.
# Ziel-Config mit der neuen Binary in Staging starten und die Logs prüfen.
```

#### 3.2 Epochen-Übergang (automatisch)
```bash
# Node erkennt Epoche 1000 automatisch beim Finalisieren von Epoche 999
# Logs prüfen:
sudo journalctl -u phantom-node -f | grep -i "epoch transition"

# Erwartete Meldung:
# {"type":"epoch_transition","from":999,"to":1000,"new_consensus_rules":true}
```

#### 3.3 Post-Upgrade-Validierung
```bash
# 1. Metrics prüfen
curl -s http://localhost:9100/metrics | grep pc_node_epoch
# pc_node_epoch 1000

# 2. Committee-Selection testen
curl -X POST http://localhost:9000/consensus/select-committee \
  -H "Content-Type: application/json" \
  -d '{"epoch":1000,"current_anchor_index":50000,"seed":"...","candidates":[...]}'

# 3. Neue Anchors validieren (mit neuen Regeln)
# Erwartete Finality innerhalb von 2 Epochen
```

---

## 4. Koordinierter Hard-Fork (Chain-Split)

### Anwendungsfall
- Kritischer Konsensus-Bug-Fix
- Nicht-rückwärtskompatible Protokolländerung

### Hard-Fork-Prozedur

#### 4.1 Governance-Approval (Off-Chain)
- **Forum-Diskussion**: 2 Wochen Community-Feedback
- **Validator-Signaling**: 80% Validator müssen zustimmen
- **Fork-Block festlegen**: z. B. Block 500.000

#### 4.2 Deployment (koordiniert)
```bash
# 1. Alle Nodes upgraden auf Fork-Binary (v3.0.0-fork)
# Binary aktiviert Fork-Logik automatisch ab Block 500.000

# 2. Vor Block 500.000: Business as usual
# Ab Block 500.000: neue Konsensus-Regeln aktiv

# 3. Monitoring
# - Alte Nodes (v2.x) forken ab Block 500.000 auf Old-Chain
# - Neue Nodes (v3.x) folgen New-Chain

# 4. Empfehlung: Upgrade bis Block 499.000 abschließen
```

#### 4.3 Chain-Split-Handling
```bash
# Falls versehentlich auf Old-Chain:
# 1. Node stoppen
# 2. State löschen (ab Fork-Point)
# 3. Neusynchro mit Fork-Binary

sudo systemctl stop phantom-node
rm -rf /data/phantom/state
# Headers/Payloads behalten, nur State neu berechnen
sudo systemctl start phantom-node
```

---

## 5. Notfall-Rollback (Netzwerk-weit)

### Anwendungsfall
- Kritischer Bug in neuem Release entdeckt (innerhalb 24h nach Upgrade)
- Netzwerk-Instabilität

### Rollback-Koordination
```bash
# 1. Rollback-Signal im Discord/Telegram
# "EMERGENCY ROLLBACK: Alle Nodes zurück auf v2.5.0"

# 2. Alte Binary wiederherstellen (siehe 2.3)

# 3. State-Rollback auf letzten stabilen Checkpoint
# (falls vorhanden: wöchentliche State-Snapshots)
rm -rf /data/phantom/state
tar -xzf /backup/state-snapshot-20250101.tar.gz -C /data/phantom/

# 4. Node neu starten
sudo systemctl start phantom-node

# 5. Sync-Validierung
# Node synchronisiert ab Snapshot-Block
```

---

## 6. Validator-spezifische Upgrades

### HSM/Signing-Key-Rotation
```bash
# 1. Neuen BLS-Key auf HSM generieren
yubico-piv-tool -s 9d -a generate -A ECCP384 -o new-bls-pubkey.pem

# 2. Dokumentierten On-Chain-Key-Rotation-Flow der aktuellen Release-Doku ausführen
# Kein generisches `phantom-node validator-key-update`-Subcommand vorhanden.

# 3. Nächste Epoche: neuer Key aktiv
# Alter Key bleibt 1 Epoche gültig (Grace Period)
```

### Validator-Node-Migration (Server-Wechsel)
```bash
# Auf altem Server:
# 1. State/Store-Backup ziehen
tar -czf validator-backup.tar.gz /data/phantom

# Auf neuem Server:
# 2. Backup einspielen
tar -xzf validator-backup.tar.gz -C /data

# 3. HSM physisch umstecken oder Remote-HSM konfigurieren

# 4. Node mit gleicher Config starten
# 5. Validierung: gleiches Seat, gleiche Metrics
```

---

## 7. Downtime-Minimierung (Zero-Downtime-Upgrade)

### Blue-Green-Deployment (für kritische Validator)
```bash
# 1. Zweiten Node (Green) mit neuer Binary starten
# (parallel zum bestehenden Blue-Node)

# 2. Green-Node synchronisiert State von Blue (Read-Only-Modus)

# 3. Traffic-Umschaltung (DNS/Load-Balancer)
# Green wird Primary, Blue wird Standby

# 4. Blue-Node upgraden (jetzt ohne Downtime)

# 5. Rollback-Option: Traffic zurück auf Blue
```

### Rolling-Upgrade (Multi-Node-Setup)
```bash
# Bei 3-Node-Cluster (z. B. Multi-Region):
# 1. Node1 upgraden → Testen → Stable
# 2. Node2 upgraden → Testen → Stable
# 3. Node3 upgraden → Testen → Stable
# Zu jedem Zeitpunkt: 2/3 Nodes verfügbar
```

---

## 8. Checklisten

### Pre-Upgrade-Checklist
- [ ] Release Notes vollständig gelesen
- [ ] Breaking Changes identifiziert
- [ ] SHA256SUMS verifiziert (GPG/Cosign)
- [ ] Backup erstellt (State, Store, Config, Binary)
- [ ] Testnet-Upgrade erfolgreich durchgeführt
- [ ] Rollback-Plan bereit
- [ ] Monitoring/Alerting aktiviert

### Post-Upgrade-Checklist
- [ ] Node startet ohne Fehler
- [ ] Logs zeigen korrekte Version
- [ ] Metrics normal (CPU, RAM, Disk I/O)
- [ ] Sync-Status: up-to-date
- [ ] Validator: Attestations werden akzeptiert
- [ ] P2P: Peers verbunden (>5)
- [ ] Backup der neuen Binary gesichert

---

## 9. Troubleshooting

### Problem: Node startet nach Upgrade nicht
```bash
# 1. Binary-Kompatibilität prüfen
file /usr/local/bin/phantom-node
# Erwartung: ELF 64-bit LSB executable, x86-64

# 2. Dependencies prüfen
ldd /usr/local/bin/phantom-node
# Fehlende .so? → System-Update erforderlich

# 3. Logs analysieren
sudo journalctl -u phantom-node --since "10 minutes ago" | tail -50

# 4. Config-Syntax prüfen
# Kein generisches `phantom-node check-config`-Subcommand vorhanden.
# Für Status-HTTP die produktive Konfiguration mit dem echten Startkommando prüfen:
phantom-node status-serve --config /etc/phantom-coin/status-serve.toml --genesis-note /etc/phantom-coin/genesis_note.bin
```

### Problem: State-Corruption nach Upgrade
```bash
# 1. Best-effort RocksDB-Reparatur der lokalen State-DBs
phantom-node db repair --store-dir /data/phantom/store

# 2. Falls Repair fehlschlägt: Snapshot wiederherstellen
tar -xzf /backup/state-snapshot-latest.tar.gz -C /data/phantom/

# 3. Optional: lokale State-DBs bewusst zurücksetzen (destruktiv)
phantom-node db reset --store-dir /data/phantom/store --yes
```

### Problem: Performance-Regression nach Upgrade
```bash
# 1. Metrics vergleichen (vor/nach)
curl http://localhost:9100/metrics > metrics-post-upgrade.txt
diff metrics-pre-upgrade.txt metrics-post-upgrade.txt

# 2. CPU-Profiling über Status-HTTP abrufen
curl -s \
  -H "Authorization: Bearer $(cat /etc/phantom-coin/status-auth.token)" \
  "http://127.0.0.1:8080/debug/pprof/profile?seconds=30" \
  -o /tmp/profile.pb

# 3. Issue mit Profiling-Daten melden
```

---

## 10. Support & Eskalation

### Community-Support
- **Discord**: #node-operations
- **GitHub Discussions**: Upgrade-Issues
- **Docs**: https://docs.phantom-coin.org/upgrades

### Kritische Upgrades (Validator-Support)
- **Emergency-Hotline**: validator-support@phantom-coin.org
- **Incident-Kanal**: Discord #validator-emergency

---

## Referenzen
- [Release Notes](https://github.com/Global-Phantom-Network/Phantom-Coin/releases)
- [Reproducible Builds](./reproducible-builds.md)
- [HSM-Signing](./hsm-signing.md)
- [Emergency Runbook](./emergency.md)
