# Epochen‑Upgrades & Rollbacks (deterministisch)

Ziel: Sicheres Upgrade einer Node/Cluster‑Version oder VRF/Epoch‑Parameter ohne Downtime bzw. mit minimaler Unterbrechung. Alle Artefakte sind reproduzierbar (keine Unix‑Zeitstempel).

## Voraussetzungen
- Release‑Artefakte aus GitHub Release (tar.gz) mit `SHA256SUMS` verifiziert
- Docker: Image `ghcr.io/<org>/phantom-node:<version>` oder lokales tar.gz
- Konfigurationsdatei (TOML) für `phantom-node` vorhanden

## Upgrade‑Strategie (Einzelnode)
1. **Verifizieren**
   - Lade `phantomcoin-<tag>-<platform>.tar.gz` und `SHA256SUMS` aus Release
   - `sha256sum -c SHA256SUMS`
2. **Binary vorbereiten**
   - Entpacken nach `/opt/phantom-node/<tag>/phantom-node`
   - Dateirechte setzen: `chmod 0755`
3. **Graceful Stop**
   - Prozess beenden (systemd/docker) und sicherstellen, dass keine Schreibvorgänge offen sind
4. **Konfiguration aktualisieren (optional)**
   - Epoch/VRF‑Overrides: `--vrf_epoch_len`, `--vrf_cooldown_anchors`, `--vrf_min_attendance_pct`
   - Beispiel: `--vrf_epoch_len 8192`
5. **Start**
   - Start mit neuem Binary und identischen Datenverzeichnissen (`--mempool-dir`)
6. **Verifizieren**
   - `GET /readyz` → 200
   - `GET /metrics` → `pc_network_id`, `pc_genesis_height` sichtbar

## Upgrade‑Strategie (Docker Compose)
1. `docker compose pull` (falls GHCR genutzt)
2. `docker compose up -d --no-deps --build node1 node2 node3`
3. Health‑Checks prüfen: `curl node1:18081/healthz` etc.

## Parameter‑Änderungen (Epochen/VRF)
- Overrides via CLI (`status-serve`):
  - `--vrf-epoch-len <u64>`
  - `--vrf-cooldown-anchors <u64>`
  - `--vrf-min-attendance-pct <u8>`
- Empfehlung: In TOML‑Config ablegen und über `--config` referenzieren

## Rollback
1. Binary zurück auf vorherigen Release‑Tag (verifizierter Hash)
2. Neustart mit identischer Konfiguration
3. Verifizieren wie oben

## Zero‑Downtime (staggered restart)
- In Multi‑Node‑Setups Nodes nacheinander neu starten (mind. 1 Node online halten)
- Reihenfolge: Node3 → Node2 → Node1
- Nach jedem Schritt Health‑Checks und Finalität prüfen

## Hinweise
- Build‑Artefakte sind deterministisch; keine Unix‑Zeit in Tar/Gzip (mtime=0), OCI‑Labels `created=1970-01-01T00:00:00Z`
- Pfade im Binary mit `--remap-path-prefix` normalisiert
