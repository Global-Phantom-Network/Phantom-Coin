# Phantom-Coin Systemd Services

## English version

Production-ready systemd service files for Phantom-Coin components.

## Installation

```bash
# Copy all service files to systemd directory
sudo cp systemd/*.service /etc/systemd/system/

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
```

## Services

| Service | Description | Port |
|---------|-------------|------|
| `phantom-node.service` | Main validator node (P2P QUIC) | 9000/UDP, 9100/TCP |
| `phantom-node-status.service` | HTTP/HTTPS API server | 8080/TCP, 8443/TCP |
| `phantom-node-metrics.service` | Prometheus metrics exporter | 9101/TCP |
| `phantom-miner.service` | Miner client (optional) | - |

## Management

```bash
# Check status
sudo systemctl status phantom-node
sudo systemctl status phantom-node-status

# View logs (live)
sudo journalctl -u phantom-node -f
sudo journalctl -u phantom-node-status -f

# View logs (recent)
sudo journalctl -u phantom-node --since "1 hour ago"
sudo journalctl -u phantom-node --lines=100

# Restart
sudo systemctl restart phantom-node

# Stop
sudo systemctl stop phantom-node
sudo systemctl stop phantom-node-status

# Disable (prevent auto-start)
sudo systemctl disable phantom-node
```

## Prerequisites

1. **User:** phantom user must exist

   ```bash
   sudo useradd -r -m -s /bin/bash -d /opt/phantom-coin phantom
   ```

2. **Directories:**

   ```bash
   sudo mkdir -p /opt/phantom-coin/bin
   sudo mkdir -p /var/lib/phantom-coin/{data,mempool}
   sudo mkdir -p /etc/phantom-coin
   sudo chown -R phantom:phantom /opt/phantom-coin
   sudo chown -R phantom:phantom /var/lib/phantom-coin
   ```

3. **Binaries:** Install phantom-node, phantom-miner, phantom-signer to `/opt/phantom-coin/bin/`

4. **Config:** Create `/etc/phantom-coin/node.toml`, `/etc/phantom-coin/status-serve.toml`, `/etc/phantom-coin/genesis.toml`, and optionally `/etc/phantom-coin/miner.toml`

5. **Genesis:** Install the canonical release `genesis_note.bin` at `/etc/phantom-coin/genesis_note.bin`. `phantom-node.service` copies it to `/var/lib/phantom-coin/data/mempool/genesis_note.bin` before startup, and `phantom-node-status.service` reads the canonical file via `--genesis-note /etc/phantom-coin/genesis_note.bin`.

## Security features

All services include:

- ✅ Non-privileged user (phantom)
- ✅ NoNewPrivileges
- ✅ PrivateTmp
- ✅ ProtectSystem=strict
- ✅ ProtectHome=true
- ✅ Minimal read/write paths
- ✅ Resource limits (NOFILE, NPROC)
- ✅ Automatic restart on failure

## Troubleshooting

**Service fails to start:**

```bash
# Check detailed error
sudo systemctl status phantom-node -l

# Check logs
sudo journalctl -u phantom-node -n 50

# Verify binary exists
ls -l /opt/phantom-coin/bin/phantom-node

# Check permissions
sudo su - phantom -c "/opt/phantom-coin/bin/phantom-node --version"
```

**Port already in use:**

```bash
sudo netstat -tulpn | grep :9000
sudo lsof -i :9000
# Kill conflicting process
sudo kill -9 <PID>
```

## See also

- [Deployment Guide](../docs/deployment-guide.md)
- [Deployment Guide Part 2](../docs/deployment-guide-part2.md)
- [Backup & Recovery Guide](../docs/backup-recovery-guide.md)

## Deutsche Version

Produktionsreife systemd-Service-Dateien für Phantom-Coin-Komponenten.

## Installation

```bash
# Alle Service-Dateien in das systemd-Verzeichnis kopieren
sudo cp systemd/*.service /etc/systemd/system/

# systemd neu laden
sudo systemctl daemon-reload

# Services aktivieren (Autostart beim Booten)
sudo systemctl enable phantom-node.service
sudo systemctl enable phantom-node-status.service
sudo systemctl enable phantom-node-metrics.service
# Optional:
sudo systemctl enable phantom-miner.service

# Services starten
sudo systemctl start phantom-node
sudo systemctl start phantom-node-status
sudo systemctl start phantom-node-metrics
```

## Services

| Service | Beschreibung | Port |
|---------|--------------|------|
| `phantom-node.service` | Haupt-Validator-Node (P2P QUIC) | 9000/UDP, 9100/TCP |
| `phantom-node-status.service` | HTTP/HTTPS API-Server | 8080/TCP, 8443/TCP |
| `phantom-node-metrics.service` | Prometheus-Metrik-Exporter | 9101/TCP |
| `phantom-miner.service` | Miner-Client (optional) | - |

## Verwaltung

```bash
# Status prüfen
sudo systemctl status phantom-node
sudo systemctl status phantom-node-status

# Logs live ansehen
sudo journalctl -u phantom-node -f
sudo journalctl -u phantom-node-status -f

# Logs der letzten Zeit ansehen
sudo journalctl -u phantom-node --since "1 hour ago"
sudo journalctl -u phantom-node --lines=100

# Neustart
sudo systemctl restart phantom-node

# Stoppen
sudo systemctl stop phantom-node
sudo systemctl stop phantom-node-status

# Deaktivieren (Autostart verhindern)
sudo systemctl disable phantom-node
```

## Voraussetzungen

1. **Benutzer:** Benutzer `phantom` muss existieren

   ```bash
   sudo useradd -r -m -s /bin/bash -d /opt/phantom-coin phantom
   ```

2. **Verzeichnisse:**

   ```bash
   sudo mkdir -p /opt/phantom-coin/bin
   sudo mkdir -p /var/lib/phantom-coin/{data,mempool}
   sudo mkdir -p /etc/phantom-coin
   sudo chown -R phantom:phantom /opt/phantom-coin
   sudo chown -R phantom:phantom /var/lib/phantom-coin
   ```

3. **Binaries:** `phantom-node`, `phantom-miner`, `phantom-signer` nach `/opt/phantom-coin/bin/` installieren

4. **Config:** `/etc/phantom-coin/node.toml`, `/etc/phantom-coin/status-serve.toml`, `/etc/phantom-coin/genesis.toml` und optional `/etc/phantom-coin/miner.toml` anlegen

5. **Genesis:** Die kanonische Release-`genesis_note.bin` unter `/etc/phantom-coin/genesis_note.bin` installieren. `phantom-node.service` kopiert sie vor dem Start nach `/var/lib/phantom-coin/data/mempool/genesis_note.bin`, und `phantom-node-status.service` liest dieselbe kanonische Datei via `--genesis-note /etc/phantom-coin/genesis_note.bin`.

## Sicherheits-Features

Alle Services enthalten:

- ✅ Nicht-privilegierter Benutzer (`phantom`)
- ✅ NoNewPrivileges
- ✅ PrivateTmp
- ✅ ProtectSystem=strict
- ✅ ProtectHome=true
- ✅ Minimale Read/Write-Pfade
- ✅ Ressourcen-Limits (NOFILE, NPROC)
- ✅ Automatischer Neustart bei Fehlern

## Troubleshooting

**Service startet nicht:**

```bash
# Detailfehler prüfen
sudo systemctl status phantom-node -l

# Logs prüfen
sudo journalctl -u phantom-node -n 50

# Prüfen, ob Binary existiert
ls -l /opt/phantom-coin/bin/phantom-node

# Berechtigungen prüfen
sudo su - phantom -c "/opt/phantom-coin/bin/phantom-node --version"
```

**Port bereits belegt:**

```bash
sudo netstat -tulpn | grep :9000
sudo lsof -i :9000
# Konfligierenden Prozess beenden
sudo kill -9 <PID>
```

## Siehe auch

- [Deployment Guide](../docs/deployment-guide.md)
- [Deployment Guide Part 2](../docs/deployment-guide-part2.md)
- [Backup & Recovery Guide](../docs/backup-recovery-guide.md)
