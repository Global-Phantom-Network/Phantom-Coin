# Production Readiness Checklist

Konkrete Abarbeitungsliste für den ersten produktiven Rollout von Phantom-Coin.

Diese Checkliste ergänzt die allgemeine `release-checklist.md` um die aktuell audit-relevanten Produktionsblocker und Härtungsmaßnahmen.

## Scope

Geprüfte Flächen:

- `crates/phantom-node`
- `crates/phantom-miner`
- `apps/phantom-dashboard/src-tauri`
- `systemd/`
- `docker-compose.yml`
- `deploy/docker-compose.yml`
- `configs/`
- `Dockerfile`

## Go / No-Go Regel

Ein produktiver Rollout ist erst freigegeben, wenn alle Punkte unter "Blocker vor erstem Prod-Rollout" erledigt und verifiziert sind.

---

## Blocker vor erstem Prod-Rollout

### 1. Deploy-Kommandos an aktuelle CLI anpassen

- [x] Alle `systemd/*.service` Dateien von alten CamelCase-Subcommands auf die aktuelle CLI umstellen.
- [x] Alle alten Snake-Case-Flags in Deploy-Dateien entfernen.
- [x] `docker-compose.yml` und `deploy/docker-compose.yml` auf aktuelle Subcommands und Flags umstellen.
- [x] `systemd/README.md` und relevante Deploy-Dokumentation auf denselben Stand bringen.

Betroffene Punkte:

- `StatusServe` -> `status-serve`
- `P2pQuicListen` -> `p2p-quic-listen`
- `P2pMetricsServe` -> `p2p-metrics-serve`
- `--mempool_dir` -> `--mempool-dir`
- `--store_dir` -> `--store-dir`

Verifikation:

- [x] Jeder dokumentierte Startbefehl läuft lokal mindestens bis zur Argumentvalidierung durch.
- [x] Keine Fehlermeldung `unrecognized subcommand`.
- [x] Keine Fehlermeldung `unexpected argument`.

### 2. Genesis-Provisioning eindeutig und kanonisch festlegen

- [x] Eine einzige autoritative Quelle für `genesis_note.bin` festlegen.
- [x] Für jede produktive Node sicherstellen, dass `genesis_note.bin` unter `<store>/mempool/genesis_note.bin` vorhanden ist.
- [x] Falls `status-serve` mit `--genesis-note` arbeitet: absoluten Pfad und Ausrollmechanik dokumentieren.
- [x] Compose- und systemd-Deploys so umbauen, dass Genesis nicht implizit oder zufällig entsteht.
- [x] Fake-/Platzhalter-Genesis-Schritte in Deploy-Beispielen entfernen.

Verifikation:

- [x] Nach Node-Start existiert `mempool/genesis_note.bin` tatsächlich.
- [x] `/status` liefert die erwartete `network_id`.
- [x] Es erscheint kein Warnpfad, dass Finalitäts-Verifikation wegen fehlender Genesis deaktiviert ist.

### 3. Konfigurationsdateien nach Runtime trennen

- [x] Eine eigene Beispielkonfiguration für `status-serve` anlegen.
- [x] Eine eigene Beispielkonfiguration für den P2P-/Node-Listener anlegen, falls dieser config-basiert ausgerollt werden soll.
- [x] Eine eigene Beispielkonfiguration für `phantom-miner` anlegen.
- [x] `systemd/phantom-node-status.service` auf eine tatsächlich parsebare `status-serve`-Config umstellen.
- [x] Dokumentation so anpassen, dass `configs/node.toml` nicht länger als `status-serve`-Config missverstanden werden kann.

Mindestens nötige Felder für `status-serve`:

- `config_version`
- `addr`
- `mempool_dir`
- optional `store_dir`
- `require_auth`
- `auth_token_file`
- optional `tls_cert`
- optional `tls_key`
- optional `tls_client_ca`

Verifikation:

- [x] `phantom-node status-serve --config <datei>` startet mit der ausgelieferten Beispielkonfiguration.
- [x] Keine Parserfehler wegen fehlender Root-Felder.

### 4. Status-Auth und Secret-Handling verbindlich setzen

- [x] Produktive Status-Instanzen ausschließlich mit `require_auth=true` betreiben.
- [x] Kein Inline-CLI-Token in Produktionsdokumentation oder Service-Dateien verwenden.
- [x] `auth_token_file` oder kontrolliertes Secret-Environment als Standardpfad festlegen.
- [x] Rechte der Token-Datei im Deployment dokumentieren und prüfen.
- [x] Reverse-Proxy- oder Operator-Doku klar von unsicheren Direktstarts trennen.

Verifikation:

- [x] Nicht-öffentliche Endpunkte liefern ohne Bearer-Token `401`.
- [x] Mit korrekt geladenem Token funktionieren geschützte Endpunkte.

### 5. P2P-Rate-Limits verbindlich konfigurieren

- [x] Produktionsdefaults für Header-, Inventory-, Request-, Response- und Byte-Buckets definieren.
- [x] Per-Peer-Limits aktivieren.
- [x] Rate-Limit-Werte in Deploy-Artefakten oder autoritativer Konfig verankern.
- [x] Beobachtbare Metriken oder Logs für Drops/Limit-Events dokumentieren.

Verifikation:

- [x] Flood-/Burst-Test führt zu Limitierung statt ungebremstem Ressourcenanstieg.
- [x] CPU- und Speicherverbrauch bleiben unter Last stabil.

### 6. Monitoring- und Observability-Stack härten

- [x] Standard-Credentials aus Grafana/Monitoring-Beispielen entfernen.
- [x] Starke Secrets als Pflichtvoraussetzung definieren.
- [x] Keine Monitoring-Komponente mit Demo-Credentials produktiv freigeben.
- [x] Dokumentation und Compose-Dateien auf Secret-basierte Initialisierung umstellen.

Verifikation:

- [x] Kein Default-Login wie `admin/admin` oder `changeme` mehr vorhanden.
- [x] Start ohne explizites Admin-Secret schlägt kontrolliert fehl oder ist nicht dokumentiert.

### 7. Metrics-Binds auf Loopback oder abgeschottetes Netz beschränken

- [x] `systemd/phantom-node-metrics.service` nicht auf `0.0.0.0` ausrollen.
- [x] Remote-Scraping nur über Proxy, VPN oder internes Netz erlauben.
- [x] README und Deploy-Beispiele auf denselben Sicherheitsstandard bringen.

Verifikation:

- [x] Metrics sind von außen nicht direkt erreichbar.
- [x] Prometheus-Scraping funktioniert über den vorgesehenen internen Pfad.

### 8. Schreibpfade für Validator-Control unter systemd korrekt freigeben

- [x] Prüfen, wo `validator_control` im Store tatsächlich landet.
- [x] `ReadWritePaths=` so anpassen, dass der Control-Pfad vom Status-Service geschrieben werden darf.
- [x] Keine unnötig breiten Schreibrechte freigeben.

Verifikation:

- [x] `POST /validator/control` funktioniert unter systemd erfolgreich.
- [x] Die Control-Datei wird am erwarteten Pfad persistiert.

Hinweis:

- Der systemd-Nachweis läuft über `scripts/verify_systemd_runtime_ci.sh` im self-hosted Linux/systemd-Job von `.github/workflows/runtime-verification.yml`.

### 9. Miner-TLS für Produktion hart ziehen

- [x] Für produktive HTTPS-Kommunikation des Miners eine vertrauenswürdige CA-Datei verpflichtend machen.
- [x] In Produktionsdoku keinen implizit unsicheren Zertifikatsmodus dokumentieren.
- [x] Unsicheren Zertifikatsmodus nicht als Produktionspfad dokumentieren; ein separater Dev-Unsafe-Modus bleibt optional und ist nicht Standard.

Verifikation:

- [x] Miner lehnt falsche oder nicht vertrauenswürdige Zertifikate im Produktionspfad ab.
- [x] Kommunikation mit korrekt signiertem Node-Zertifikat funktioniert.

---

## Muss vor Mainnet / öffentlichem Rollout erledigt sein

### 10. Docker-Basisimages per Digest pinnen

- [x] Builder- und Runtime-Image im `Dockerfile` per Digest pinnen.
- [x] Dokumentation zum Aktualisieren der Digests ergänzen.

Verifikation:

- [x] Kein unpinned `FROM rust:...` oder `FROM debian:...` mehr im Release-Build.

### 11. Dashboard-/Tauri-Release-Konfiguration härten

- [x] Release-Bundling aktivieren.
- [x] Dev-WebSocket-Origins aus der Release-CSP entfernen.
- [x] Dev- und Prod-Konfiguration sauber trennen.

Verifikation:

- [x] Release-Build enthält keine Dev-Hot-Reload-Origins mehr.

### 12. Produktions-Loghärtung aufräumen

- [x] `RUST_BACKTRACE=1` nicht als Produktionsdefault ausliefern.
- [x] Backtraces nur für Debug-/Incident-Fälle dokumentieren.

Verifikation:

- [x] Standard-Deploy läuft ohne unnötige Debug-Ausgabe.

### 13. `status_http` nicht als stillen Prod-Fallback behandeln

- [x] Falls das Binary produktiv genutzt werden soll, explizite TLS-/Auth-Anforderungen dokumentieren.
- [x] Auto-generierte Zertifikate nicht als Produktionsmodus darstellen.

Verifikation:

- [x] Doku trennt klar zwischen lokalem Helper und produktivem Trust-Modell.

---

## Sollte zusätzlich gehärtet werden

- [x] Reverse-Proxy-Referenzsetup für `status-serve` bereitstellen.
- [x] CI-Smoke-Test für alle dokumentierten `systemd`- und Compose-Kommandos ergänzen.
- [x] CI-Regel für unsichere Defaults wie Demo-Credentials ergänzen.
- [x] CI-Regel für unpinned Docker-Images ergänzen.
- [x] Prod-Readiness-Gate als eigener Release-Check in CI dokumentieren.

---

## Minimale Vorab-Verifikation vor Go-Live

Vor dem ersten produktiven Rollout manuell prüfen:

- [x] `phantom-node status-serve --help`
- [x] `phantom-node p2p-quic-listen --help`
- [x] `phantom-node p2p-metrics-serve --help`
- [x] Beispiel-`systemd`-Units referenzieren nur gültige Subcommands und Flags.
- [x] Jede Node hat dieselbe kanonische `genesis_note.bin`.
- [x] Geschützte Status-Endpunkte sind ohne Token nicht erreichbar.
- [x] Monitoring hat keine Demo-Credentials.
- [x] Metrics sind nicht öffentlich exponiert.
- [x] Miner spricht nur mit vertrauenswürdigem TLS.

---

## Abschlusskriterium

Produktionsfreigabe erst, wenn:

- alle Blocker erledigt sind,
- die zugehörigen Verifikationen dokumentiert wurden,
- und mindestens ein kompletter Staging-Durchlauf mit denselben Artefakten erfolgreich war.
