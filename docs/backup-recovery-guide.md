# Phantom-Coin Backup & Recovery Guide

**Version:** 1.0  
**Last Updated:** 2025-01-10

## Inhaltsverzeichnis

1. [Backup-Strategie](#backup-strategie)
2. [Keystore-Backups](#keystore-backups)
3. [Node-Data-Backups](#node-data-backups)
4. [Disaster Recovery](#disaster-recovery)
5. [Automated Backup-Scripts](#automated-backup-scripts)
6. [Testing & Validation](#testing--validation)

---

## Backup-Strategie

### Was muss gesichert werden?

| Komponente | Priorität | Frequenz | Speicherort |
|------------|-----------|----------|-------------|
| **Keystores** (Seat/Bond/Payout) | KRITISCH | Nach jeder Änderung | Cold Storage, Offline |
| **Slashing-DB** | KRITISCH | Täglich | Encrypted Remote |
| **Node Data** (`/var/lib/phantom-coin/data`) | Hoch | Wöchentlich | NAS/S3 |
| **Mempool** (`/var/lib/phantom-coin/mempool`) | Mittel | Täglich | NAS/S3 |
| **Config-Files** (`/etc/phantom-coin`) | Hoch | Bei Änderung | Git Repo |
| **Genesis File** | Hoch | Einmalig | Git Repo |

### 3-2-1 Backup-Regel

- **3** Kopien der Daten
- **2** verschiedene Speichermedien (z.B. Disk + Cloud)
- **1** Kopie Off-Site (geografisch getrennt)

### Retention-Policy

- **Keystores:** Unbegrenzt (mehrere Generationen)
- **Slashing-DB:** 90 Tage
- **Node Data:** 30 Tage (Weekly Snapshots), 7 Tage (Daily Incrementals)
- **Mempool:** 7 Tage
- **Configs:** Git-History (unbegrenzt)

---

## Keystore-Backups

### 1. Seat-Key (Hot Storage)

**Wichtigkeit:** KRITISCH - Wird für Voting benötigt

**Backup-Methode:**

```bash
# Encrypted Backup mit GPG
cd /path/to/keystores

# Encrypt
gpg --symmetric --cipher-algo AES256 --armor seat.toml
# Ausgabe: seat.toml.asc

# Verify
gpg --decrypt seat.toml.asc > /dev/null
# Sollte: "gpg: encrypted with 1 passphrase"

# Store
# Option A: USB-Stick (offline, mehrere Kopien)
cp seat.toml.asc /media/usb-backup/keystores/

# Option B: Encrypted Cloud Storage
rclone copy seat.toml.asc remote:phantom-backups/keystores/

# NIEMALS unencrypted in Cloud!
```

**Recovery-Test:**

```bash
# Decrypt
gpg --decrypt seat.toml.asc > seat-recovered.toml

# Verify
phantom-signer export-pub --keystore seat-recovered.toml
# Compare public key with original

# Test Sign
echo "test" > test.bin
phantom-signer sign --keystore seat-recovered.toml --msg test.bin --out sig.hex

# Cleanup test files
rm test.bin sig.hex seat-recovered.toml
```

### 2. Bond-Key (Cold Storage)

**Wichtigkeit:** KRITISCH - Kontrolliert Staking-Funds

**Best Practice:** Hardware-Wallet (BitBox02)

```bash
# Backup-Strategie für Hardware-Wallet:

# 1. Seed-Phrase (24 Wörter)
# - Auf Metal-Backup gravieren (Cryptosteel/Billfodl)
# - 3 Kopien an verschiedenen Orten
# - Niemals digital speichern
# - Niemals fotografieren

# 2. SD-Card-Backup (BitBox02)
# - SD-Card in BitBox02 einlegen
# - Backup erstellen über BitBox-App
# - SD-Card sicher aufbewahren (Safe)
# - Mehrere SD-Cards für Redundanz

# 3. XPub exportieren (Watch-Only)
phantom-signer hwi-get-xpub --derivation "m/86'/12345'/0'"
# Output: xpub... (safe to store unencrypted)

phantom-signer import-xpub \
  --algo schnorr \
  --xpub "xpub6..." \
  --derivation "m/86'/12345'/0'" \
  --out bond-xpub.toml \
  --hrp pc

# bond-xpub.toml kann unencrypted gespeichert werden (nur public keys)
```

**Recovery-Test:**

```bash
# Mit Seed-Phrase auf neuem BitBox02
# 1. Factory Reset
# 2. Restore from Seed
# 3. Verify XPub matches

phantom-signer hwi-get-xpub --derivation "m/86'/12345'/0'"
# Compare with recorded XPub

# Generate Test-Address
phantom-signer addr-from-xpub \
  --xpubstore bond-xpub.toml \
  --change 0 \
  --index 0
# Compare with known address
```

### 3. Payout-Key (Cold Storage)

**Wichtigkeit:** HOCH - Empfängt Block-Rewards

**Backup wie Bond-Key:**

```bash
# Hardware-Wallet empfohlen
# Oder encrypted Keystore:

gpg --symmetric --cipher-algo AES256 --armor payout.toml

# Multiple Backups
cp payout.toml.asc /media/usb-backup-1/
cp payout.toml.asc /media/usb-backup-2/
cp payout.toml.asc /media/usb-backup-3/

# Test-Recovery
gpg --decrypt payout.toml.asc > payout-test.toml
phantom-signer export-pub --keystore payout-test.toml
rm payout-test.toml
```

### Key-Separation Best Practices

| Key Type | Storage | Access | Backup Frequency |
|----------|---------|--------|------------------|
| **Seat** | Hot (Server encrypted) | Täglich (Voting) | Nach jeder Rotation |
| **Bond** | Cold (Hardware-Wallet) | Selten (Staking) | Einmalig (Seed) |
| **Payout** | Cold (Hardware-Wallet) | Selten (Withdrawals) | Einmalig (Seed) |

**Niemals:**
- Alle 3 Keys auf demselben System
- Keystores unencrypted in Cloud
- Seed-Phrases digital speichern
- Keystores per Email versenden

---

## Node-Data-Backups

### 1. Full Snapshot

**Wann:** Wöchentlich, vor Major-Updates

```bash
#!/bin/bash
# File: /opt/phantom-coin/scripts/backup-full.sh

BACKUP_DIR="/mnt/backup/phantom-node"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="phantom-node-full-${TIMESTAMP}"

# Stop services (optional, safer)
sudo systemctl stop phantom-node
sudo systemctl stop phantom-node-status

# Create snapshot
sudo tar -czf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" \
  -C /var/lib/phantom-coin \
  data mempool

# Resume services
sudo systemctl start phantom-node
sudo systemctl start phantom-node-status

# Verify archive
tar -tzf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" | head

# Calculate checksum
sha256sum "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" > "${BACKUP_DIR}/${BACKUP_NAME}.sha256"

# Optional: Encrypt
gpg --symmetric --cipher-algo AES256 "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

# Upload to remote
rclone copy "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" remote:phantom-backups/node-data/

# Cleanup old backups (keep last 4 weeks)
find "${BACKUP_DIR}" -name "phantom-node-full-*.tar.gz*" -mtime +28 -delete

echo "Backup completed: ${BACKUP_NAME}.tar.gz"
```

### 2. Incremental Backup (rsync)

**Wann:** Täglich

```bash
#!/bin/bash
# File: /opt/phantom-coin/scripts/backup-incremental.sh

BACKUP_DIR="/mnt/backup/phantom-node/incremental"
DATE=$(date +%Y-%m-%d)

# Incremental backup with rsync
rsync -avz --delete \
  --link-dest="${BACKUP_DIR}/latest" \
  /var/lib/phantom-coin/data/ \
  "${BACKUP_DIR}/${DATE}/"

# Update latest symlink
ln -snf "${DATE}" "${BACKUP_DIR}/latest"

# Cleanup old incrementals (keep 7 days)
find "${BACKUP_DIR}" -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \;

echo "Incremental backup completed: ${DATE}"
```

### 3. Slashing-DB Backup

**Wann:** Täglich (KRITISCH für Validator)

```bash
#!/bin/bash
# File: /opt/phantom-coin/scripts/backup-slashdb.sh

SLASHDB_DIR="/var/lib/phantom-coin/slashdb"  # Adjust to actual path
BACKUP_DIR="/mnt/backup/phantom-node/slashdb"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="slashdb-${TIMESTAMP}"

# RocksDB snapshot (use phantom-signer or direct copy)
# Option A: Direct copy (safe if RocksDB not open)
tar -czf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" -C "${SLASHDB_DIR}" .

# Option B: RocksDB checkpoint (if integrated)
# phantom-signer slash-db-checkpoint --db-dir "${SLASHDB_DIR}" --out "${BACKUP_DIR}/${BACKUP_NAME}"

# Encrypt (IMPORTANT: Contains voting history)
gpg --symmetric --cipher-algo AES256 "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

# Upload
rclone copy "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" remote:phantom-backups/slashdb/

# Verify
gpg --decrypt "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" | tar -tz | head

# Cleanup old backups (keep 90 days)
find "${BACKUP_DIR}" -name "slashdb-*.tar.gz*" -mtime +90 -delete

echo "Slashing-DB backup completed: ${BACKUP_NAME}.tar.gz.gpg"
```

### 4. Config-Files Backup (Git)

**Wann:** Bei jeder Änderung

```bash
# Initialize Git repo
cd /etc/phantom-coin
sudo git init
sudo git config user.name "Phantom Admin"
sudo git config user.email "admin@example.com"

# Add files
sudo git add genesis.toml node.toml status-serve.toml miner.toml

# Commit
sudo git commit -m "Initial config"

# Remote (private repo)
sudo git remote add origin git@github.com:yourorg/phantom-configs-private.git
sudo git push -u origin main

# After changes:
sudo git add -A
sudo git commit -m "Update VRF rotation parameters"
sudo git push
```

---

## Disaster Recovery

### Scenario 1: Keystore verloren

**Recovery-Schritte:**

```bash
# 1. Stop services
sudo systemctl stop phantom-node

# 2. Retrieve encrypted backup
rclone copy remote:phantom-backups/keystores/seat.toml.asc /tmp/

# 3. Decrypt
gpg --decrypt /tmp/seat.toml.asc > /opt/phantom-coin/keystores/seat.toml

# 4. Verify
phantom-signer export-pub --keystore /opt/phantom-coin/keystores/seat.toml
# Compare with known public key

# 5. Set permissions
sudo chown phantom:phantom /opt/phantom-coin/keystores/seat.toml
sudo chmod 600 /opt/phantom-coin/keystores/seat.toml

# 6. Test
echo "test" > /tmp/test.bin
phantom-signer sign --keystore /opt/phantom-coin/keystores/seat.toml --msg /tmp/test.bin

# 7. Resume
sudo systemctl start phantom-node

# 8. Cleanup
rm /tmp/seat.toml.asc /tmp/test.bin
```

### Scenario 2: Node-Data korrupt

**Recovery-Schritte:**

```bash
# 1. Stop services
sudo systemctl stop phantom-node
sudo systemctl stop phantom-node-status

# 2. Backup current (korrupte) Daten
sudo mv /var/lib/phantom-coin/data /var/lib/phantom-coin/data.corrupt

# 3. Download latest backup
rclone copy remote:phantom-backups/node-data/phantom-node-full-latest.tar.gz.gpg /tmp/

# 4. Decrypt & Extract
gpg --decrypt /tmp/phantom-node-full-latest.tar.gz.gpg | \
  sudo tar -xzf - -C /var/lib/phantom-coin/

# 5. Verify checksum
sha256sum /tmp/phantom-node-full-latest.tar.gz
# Compare with .sha256 file

# 6. Set permissions
sudo chown -R phantom:phantom /var/lib/phantom-coin/data
sudo chown -R phantom:phantom /var/lib/phantom-coin/mempool

# 7. Resume
sudo systemctl start phantom-node
sudo systemctl start phantom-node-status

# 8. Monitor logs
sudo journalctl -u phantom-node -f

# 9. Verify finality resumption
curl http://localhost:8080/healthz
curl http://localhost:9101/metrics | grep pc_node_finality_events_total

# 10. Cleanup
rm /tmp/phantom-node-full-latest.tar.gz.gpg
# Keep data.corrupt for 7 days before deleting
```

### Scenario 3: Slashing-DB verloren

**Recovery-Schritte:**

```bash
# CRITICAL: Slashing-DB ist essentiell für Validator-Sicherheit

# 1. STOP VALIDATING IMMEDIATELY
sudo systemctl stop phantom-node

# 2. Retrieve latest backup
rclone copy remote:phantom-backups/slashdb/slashdb-latest.tar.gz.gpg /tmp/

# 3. Decrypt & Extract
mkdir -p /tmp/slashdb-restore
gpg --decrypt /tmp/slashdb-latest.tar.gz.gpg | \
  tar -xzf - -C /tmp/slashdb-restore/

# 4. Verify integrity
phantom-signer slash-db-get \
  --db-dir /tmp/slashdb-restore \
  --epoch 1 --shard 0 --round 1
# Should return last known vote

# 5. Move to production
sudo mv /var/lib/phantom-coin/slashdb /var/lib/phantom-coin/slashdb.old
sudo mv /tmp/slashdb-restore /var/lib/phantom-coin/slashdb
sudo chown -R phantom:phantom /var/lib/phantom-coin/slashdb

# 6. IMPORTANT: Review missed epochs
# DO NOT SIGN for epochs between backup and now without verification
# Risk of slashing if voted differently

# 7. Resume (with caution)
sudo systemctl start phantom-node

# 8. Monitor for slashing risks
sudo journalctl -u phantom-node | grep -i slash
```

### Scenario 4: Server komplett verloren

**Full Recovery:**

```bash
# 1. Provision new server (see Deployment Guide)
# 2. Install phantom-node binaries
# 3. Recover configs
git clone git@github.com:yourorg/phantom-configs-private.git /etc/phantom-coin

# 4. Recover keystores
rclone copy remote:phantom-backups/keystores/ /tmp/keystores/
for f in /tmp/keystores/*.asc; do
  gpg --decrypt "$f" > "/opt/phantom-coin/keystores/$(basename $f .asc)"
done

# 5. Recover slashing-DB (CRITICAL)
rclone copy remote:phantom-backups/slashdb/slashdb-latest.tar.gz.gpg /tmp/
gpg --decrypt /tmp/slashdb-latest.tar.gz.gpg | \
  tar -xzf - -C /var/lib/phantom-coin/slashdb/

# 6. Recover node-data (optional, can resync)
rclone copy remote:phantom-backups/node-data/phantom-node-full-latest.tar.gz.gpg /tmp/
gpg --decrypt /tmp/phantom-node-full-latest.tar.gz.gpg | \
  tar -xzf - -C /var/lib/phantom-coin/

# 7. Set permissions
sudo chown -R phantom:phantom /opt/phantom-coin
sudo chown -R phantom:phantom /var/lib/phantom-coin
sudo chmod 600 /opt/phantom-coin/keystores/*

# 8. Setup systemd services
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable phantom-node
sudo systemctl start phantom-node

# 9. Verify recovery
sudo systemctl status phantom-node
sudo journalctl -u phantom-node -f
curl http://localhost:8080/healthz

# 10. Re-establish monitoring
# Configure Prometheus/Grafana
```

---

## Automated Backup-Scripts

### Cronjob Setup

```bash
# Edit crontab for phantom user
sudo crontab -e -u phantom

# Add backup jobs:
# Daily incremental backup at 2 AM
0 2 * * * /opt/phantom-coin/scripts/backup-incremental.sh >> /var/log/phantom-coin/backup.log 2>&1

# Daily slashing-DB backup at 3 AM
0 3 * * * /opt/phantom-coin/scripts/backup-slashdb.sh >> /var/log/phantom-coin/backup.log 2>&1

# Weekly full backup on Sunday at 4 AM
0 4 * * 0 /opt/phantom-coin/scripts/backup-full.sh >> /var/log/phantom-coin/backup.log 2>&1

# Daily backup verification at 5 AM
0 5 * * * /opt/phantom-coin/scripts/verify-backups.sh >> /var/log/phantom-coin/backup.log 2>&1
```

### Backup Verification Script

```bash
#!/bin/bash
# File: /opt/phantom-coin/scripts/verify-backups.sh

BACKUP_DIR="/mnt/backup/phantom-node"
ERRORS=0

# Check latest full backup exists
LATEST_FULL=$(find "${BACKUP_DIR}" -name "phantom-node-full-*.tar.gz.gpg" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
if [ -z "$LATEST_FULL" ]; then
  echo "ERROR: No full backup found"
  ERRORS=$((ERRORS + 1))
else
  AGE=$(($(date +%s) - $(stat -c %Y "$LATEST_FULL")))
  if [ $AGE -gt 604800 ]; then  # 7 days
    echo "WARNING: Latest full backup older than 7 days"
    ERRORS=$((ERRORS + 1))
  fi
  
  # Verify checksum
  SHA_FILE="${LATEST_FULL%.gpg}.sha256"
  if [ -f "$SHA_FILE" ]; then
    gpg --decrypt "$LATEST_FULL" 2>/dev/null | sha256sum -c "$SHA_FILE"
    if [ $? -ne 0 ]; then
      echo "ERROR: Checksum mismatch for $LATEST_FULL"
      ERRORS=$((ERRORS + 1))
    fi
  fi
fi

# Check slashing-DB backup
LATEST_SLASHDB=$(find "${BACKUP_DIR}/slashdb" -name "slashdb-*.tar.gz.gpg" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
if [ -z "$LATEST_SLASHDB" ]; then
  echo "ERROR: No slashing-DB backup found"
  ERRORS=$((ERRORS + 1))
else
  AGE=$(($(date +%s) - $(stat -c %Y "$LATEST_SLASHDB")))
  if [ $AGE -gt 86400 ]; then  # 1 day
    echo "ERROR: Latest slashing-DB backup older than 1 day"
    ERRORS=$((ERRORS + 1))
  fi
fi

# Check remote backups
rclone ls remote:phantom-backups/ > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "ERROR: Cannot access remote backup storage"
  ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -eq 0 ]; then
  echo "Backup verification passed"
  exit 0
else
  echo "Backup verification failed with $ERRORS errors"
  # Send alert (email/slack)
  exit 1
fi
```

---

## Testing & Validation

### Quarterly Recovery Drill

**Durchführung:** Alle 3 Monate

```bash
# 1. Setup Test Environment
# Use separate VM or Docker container

# 2. Simulate Data Loss
# Delete /var/lib/phantom-coin/data

# 3. Execute Recovery
# Follow "Scenario 2: Node-Data korrupt"

# 4. Validate
# - Services start successfully
# - Health checks pass
# - Finality resumes
# - No data corruption

# 5. Document Results
# - Recovery time
# - Issues encountered
# - Lessons learned

# 6. Update Procedures
# Based on drill findings
```

### Backup Health Checks

```bash
# Check backup sizes (should be consistent)
du -sh /mnt/backup/phantom-node/*

# Check backup age
find /mnt/backup/phantom-node -name "*.tar.gz*" -mtime -1 -ls

# Check remote sync status
rclone check /mnt/backup/phantom-node remote:phantom-backups/

# Test restore (without applying)
LATEST=$(ls -t /mnt/backup/phantom-node/phantom-node-full-*.tar.gz.gpg | head -1)
gpg --decrypt "$LATEST" | tar -tzf - | wc -l
# Should show thousands of files
```

---

## Best Practices Summary

### DO:
✅ Encrypt all backups (especially keystores)  
✅ Test restore procedures regularly  
✅ Keep multiple backup generations  
✅ Store backups off-site (cloud/remote)  
✅ Automate backups with cron  
✅ Monitor backup success/failure  
✅ Document recovery procedures  
✅ Use hardware wallets for Bond/Payout keys  

### DON'T:
❌ Store keystores unencrypted  
❌ Rely on single backup location  
❌ Skip backup verification  
❌ Keep all keys on same system  
❌ Share seed phrases digitally  
❌ Forget to backup slashing-DB  
❌ Ignore backup failures  
❌ Test recovery only in crisis  

---

## Emergency Contacts

**In case of:**
- **Key Compromise:** Immediately rotate keys, notify network
- **Slashing Event:** Contact core team, preserve evidence
- **Data Loss:** Follow recovery procedures, restore from last known good backup

**Support Channels:**
- Discord: https://discord.gg/phantom-coin
- Email: security@phantom-coin.org
- Incident Response: +1-XXX-XXX-XXXX (24/7)
