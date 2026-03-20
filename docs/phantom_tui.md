# Phantom TUI (Unified)

Eine gemeinsame Terminal‑Oberfläche für **Node**, **Wallet**, **Miner**, **Signer** und **Tools**.  
Ziel: alle Funktionen der bestehenden CLIs nativ im TUI abbilden – mit **Standard‑Modus** und **Experten‑Modus**.

## Start

```bash
cargo run -p phantom-tui --
```

Wenn als Binary installiert:

```bash
phantom-tui
```

## Bedienung (Tasten)

- `1..6` → Tab wechseln (Home/Node/Wallet/Miner/Signer/Tools)
- `e` → Expertenmodus an/aus
- `h` oder `?` → Hilfe an/aus
- `Esc` → zurück zu Home
- `q` → Beenden

## Tabs & Funktionsumfang (Mapping zu CLI)

### 1) Node (phantom-node)
**Zweck:** Node‑Runtime, P2P/DA, Metriken, Konsens‑Werkzeuge, Staking.  
**Abzudecken (entspricht CLI‑Commands):**

- `run` → Node starten (Rolle fullnode/validator/miner, Store‑Dir, Netzwerk, Limits)
- `p2p-run` → P2P‑Service starten
- `da-run` → DA‑Service starten
- `p2p-quic-listen` → QUIC‑Listener starten
- `p2p-quic-connect` → QUIC‑Connect zu Remote
- `p2p-inject-headers` → Header‑Messages injizieren
- `p2p-inject-payloads` → Payloads injizieren
- `p2p-metrics` → P2P‑Metriken (JSON)
- `p2p-metrics-serve` → Prometheus‑Metriken (HTTP)
- `status-serve` → Status‑HTTP/API (`GET /status`, `GET /consensus/committee`, `POST /stake/bond`, `POST /stake/unbond`)
- `payout-root` → finale Payout‑Root
- `committee-payout-from-headers` → Committee‑Payout‑Root
- `build-payload` → AnchorPayload bauen
- `graph-ack` → Ack‑Distanzen
- `graph-insert-and-ack` → DAG+Ack Berechnung
- `consensus-ack-dists` → Ack‑Distanzen via ConsensusEngine
- `consensus-payout-root` → Payout‑Root via ConsensusEngine
- `cache-bench` → Cache‑Benchmark

**Aktuell im TUI (nativ integriert):**
- Start/Stop der Node (phantom-node run) mit Basisparametern
- Status‑Abfrage `/status` (Network-ID, Network-Name, Version)
- Live‑Logs (stdout/stderr)
- Expertenmodus: zusätzliche Felder + `extra_args`

### 2) Wallet
**Zweck:** Empfangen, Senden, History, UTXO‑Übersicht.  
**Abzudecken (phantom-signer + WalletDB):**

- Wallet anlegen / wiederherstellen (Seed)
- Wallet sperren/entsperren (Passphrase)
- Adressen anzeigen / auswählen
- Balance / History / UTXOs laden
- Transaktionen senden (inkl. Fee/Change‑Adresse)

### 3) Miner (phantom-miner)
**Zweck:** PoW‑Mining von Mint‑Events.  
**Abzudecken:**

- Mining starten/stoppen
- Hashrate & Shares
- Verbindung zum Node
- Mint‑Erfolg/Fehler
- Parameter: Threads, Difficulty, Mint‑Amount, Mint‑Lock

**Aktuell im TUI (nativ integriert):**
- Mining Start/Stop (`Space`)
- Hashrate, Shares, Node‑Status, Logs
- Optional: External `phantom-miner` Prometheus `/metrics` Monitor (`m`)

### 4) Signer (phantom-signer)
**Zweck:** Schlüssel/Keystore, PSBT, Signaturen, Seat‑Votes, HWI.  
**Abzudecken (CLI‑Mapping):**

- `keygen`, `import`, `export-pub`
- `sign`, `verify`
- `psbt-create`, `psbt-sighash`, `sign-tx-with-keystore`, `psbt-finalize`
- `hwi-enumerate`, `hwi-get-xpub`, `import-xpub`, `addr-from-xpub`
- `seat-vote-sign`, `seat-vote-verify`
- `slash-db-init`, `slash-db-get`, `slash-db-put`, `slash-db-import`, `slash-db-export`, `slash-db-vacuum`, `slash-db-check`

**Hinweis:** Passphrase‑Ableitung für Rollen (validator/miner) wird über `--passphrase-role` unterstützt.
**Hinweis (HWI sign‑tx):** erwartet ein externes Signer‑Binary (Default: `bitbox02-signer`, alternativ `$PHANTOM_BITBOX2_SIGNER`).  
Im Workspace vorhanden: `bitbox02-signer` (Software‑Signer, verschlüsselter Seed‑Store).

### 5) Tools (phantom-node/src/bin)
**Zweck:** Netzwerk‑/Genesis‑Werkzeuge und Hilfs‑Tools.  
**Abzudecken:**

- `genesis_bootstrap` → Genesis + role_policy
- `mint_rpc` → Mint‑RPC Tool
- `status_http` → Status‑HTTP Helper
- `phantom-node p2p-quic-listen --metrics-addr ...` → QUIC + Prometheus /metrics (in-process)
- `mine_mint` → Mint‑Test
- `gen_headers` → Test‑Header generieren
- `gen_payloads` → Test‑Payloads generieren

**Aktuell im TUI (integrierter Tool‑Runner):**
- Tool‑Auswahl mit Vorlagen‑Commandlines
- Ausführen/Stoppen, Logs
- Freie CLI‑Commands möglich (z. B. phantom‑signer/phantom‑node/phantom‑miner)
> Hinweis: Commands werden per Whitespace gesplittet. Pfade mit Leerzeichen ggf. vermeiden.

## Expertenmodus

Im Expertenmodus werden **alle** Flags/Parameter sichtbar (auch seltene/gefährliche).  
Im Standardmodus nur die **sicheren/typischen** Optionen.

## Dokumentations‑Hinweis

Diese Datei beschreibt **Zweck & Mapping**.  
Sobald ein Modul nativ integriert ist, bekommt es eine detaillierte Eingabe‑/Ausgabe‑Sektion mit Beispielen.

## Aktueller Stand (Incremental)

- **Signer‑Tab**: `keygen`, `import`, `export-pub`, `sign`, `verify`, `psbt-create`, `psbt-sighash`, `sign-tx-with-keystore`, `verify-tx-sig`, `psbt-finalize`, `slashdb (init/get/put)`, `seat-vote sign/verify`, `hwi (enumerate/get-xpub/sign-message/sign-tx)`, `payjoin (initiate/respond/finalize/parse-uri)` sind **nativ** integriert.
- **Wallet‑Tab**: Login + Adressen/History/UTXOs + Senden + neue Adresse (TUI‑Funktionen integriert).
- **Miner‑Tab**: Mining‑UI integriert (Status/Hashrate/Logs).
- **Node‑Tab**: Start/Stop/Status/Logs integriert.
- **Tools‑Tab**: Tool‑Runner mit Vorlagen + freie Commands integriert.
- Bedienung: Felder per `Tab` fokussieren, mit Text füllen, `Enter` ausführen. `x` stoppt Prozesse, `c` löscht Logs.
