# Staking & Validator-Rollen

## Übersicht

Das Phantom-Coin Netzwerk verwendet ein Staking-basiertes Validator-System:

- **Fullnode**: Validiert Transaktionen, speichert Blockchain-Daten, reicht keine Blöcke ein
- **Validator**: Fullnode + produziert Payloads, nimmt am Konsens teil
- **Miner**: Separates Binary (`phantom-miner`), nur für PoW-Mining von Mint-Events

Wichtige Ausnahme:

- In der initialen Single-Operator-Bootstrap-Phase darf genau ein Genesis-Node temporaer Miner-, Validator- und Fullnode-Funktion zugleich tragen, damit aus dem Nullzustand ueberhaupt Coins, Finalisierung und erster Stake entstehen koennen.
- Diese Ausnahme ist nicht das Zielmodell. Die saubere Abgrenzung ist in [ROLE_BOOTSTRAP_SPEC.md](./ROLE_BOOTSTRAP_SPEC.md) beschrieben.

## Minimum Stake

Um als Validator teilzunehmen, sind **10.000 PC** (= 1.000.000.000.000 Basis-Einheiten) erforderlich.
Empfehlung: **20.000 PC** staken, um nach einem 50%-Slashing nicht unter das Minimum zu fallen.

## Aktueller Runtime-Stand

Die aktuellen `phantom-node`-Subcommands `stake`, `unstake`, `stake-status` und `stake-set-pop` sind **nicht** Teil der heutigen CLI.

Validator-Eligibility wird heute aus den produktiven Runtime-Daten abgeleitet:

- **On-chain Validator-Record** im State-DB
- **Gestakte UTXOs** im State-DB
- **Gültiger BLS Proof-of-Possession** (`bls_pop`)
- **Optionale `role_policy.json`**

Beim Start mit `--validator-id` oder `--bls-pk` prüft der Node diese Daten und schreibt `role_check`- bzw. `dynamic_role`-Events ins Log.

## Status-API für Staking-Operationen

Staking-Operationen im laufenden System erfolgen über `phantom-node status-serve`.

- **[Auth]** Nicht-öffentliche Endpunkte erfordern Bearer-Auth.
- **[Production]** Im Produktionsbetrieb sollte `status-serve` über `--config /etc/phantom-coin/status-serve.toml` mit `auth_token_file` betrieben werden.

### 1. UTXOs bonden

```bash
curl -s \
  -H "Authorization: Bearer $(cat /etc/phantom-coin/status-auth.token)" \
  -H "Content-Type: application/json" \
  -X POST http://127.0.0.1:8080/stake/bond \
  -d '{
    "ops": [
      {"txid": "<32-byte-hex-txid>", "vout": 0},
      {"txid": "<32-byte-hex-txid>", "vout": 1}
    ],
    "current": 0,
    "threshold": 0,
    "allow_unripe_bond": false
  }'
```

**Request-Felder:**
- `ops`: Liste der zu bindenden UTXOs (`txid`, `vout`)
- `current`: aktueller Anchor-/State-Index für die Maturity-Prüfung
- `threshold`: benötigte Maturity-Schwelle
- `allow_unripe_bond`: optionaler Override für unreife Bonds

**Antwort bei Erfolg:**
```json
{"ok":true}
```

### 2. Unbond vorbereiten

Vor dem Unbond wird eine Challenge aus dem aktuellen State benötigt:

```bash
curl -s \
  -H "Authorization: Bearer $(cat /etc/phantom-coin/status-auth.token)" \
  "http://127.0.0.1:8080/stake/unbond_challenge?lock=<32-byte-hex-lock>"
```

**Antwort bei Erfolg:**
```json
{
  "ok": true,
  "lock": "...",
  "sequence": 7,
  "nonce": "..."
}
```

### 3. UTXOs unbonden

```bash
curl -s \
  -H "Authorization: Bearer $(cat /etc/phantom-coin/status-auth.token)" \
  -H "Content-Type: application/json" \
  -X POST http://127.0.0.1:8080/stake/unbond \
  -d '{
    "ops": [
      {"txid": "<32-byte-hex-txid>", "vout": 0}
    ],
    "signatures": ["<64-byte-schnorr-signature-hex>"],
    "public_keys": ["<32-byte-xonly-pubkey-hex>"],
    "nonce": "<32-byte-hex-nonce>"
  }'
```

**Request-Felder:**
- `ops`: Liste der zu lösenden UTXOs
- `signatures`: Schnorr-Signaturen über die state-derived Unbond-Challenge
- `public_keys`: zugehörige X-only Public Keys
- `nonce`: Challenge-Nonce aus `GET /stake/unbond_challenge`

### 4. Committee-/Validator-Sicht prüfen

Ein dediziertes `stake-status`-CLI gibt es aktuell nicht.
Für operative Prüfungen stehen stattdessen diese Flächen zur Verfügung:

```bash
curl -s \
  -H "Authorization: Bearer $(cat /etc/phantom-coin/status-auth.token)" \
  "http://127.0.0.1:8080/consensus/committee?epoch=1000"
```

Zusätzlich zeigen die Node-Logs beim Start den lokalen Eligibility-Status:

```json
{"type":"role_check","validator_id":"...","stake":1000000000000,"min_stake":1000000000000,"pop_ok":true,"policy_ok":true,"eligible":true}
{"type":"dynamic_role","role":"validator","tx_proposer":true}
```

## Dynamischer Rollenwechsel

### Automatische Validator-Erkennung

Beim Start mit `--validator-id` oder `--bls-pk` prüft der Node den lokalen Validator-Status gegen den produktiven State:

```bash
phantom-node p2p-quic-listen \
  --addr 0.0.0.0:9000 \
  --store-dir /path/to/data \
  --bls-pk <96-hex-zeichen>
```

**Ausgabe bei ausreichend Stake:**
```json
{"type":"role_check","validator_id":"...","stake":1000000000000,"min_stake":1000000000000,"pop_ok":true,"policy_ok":true,"eligible":true}
{"type":"dynamic_role","role":"validator","tx_proposer":true}
```

**Ausgabe bei unzureichend Stake:**
```json
{"type":"role_check","validator_id":"...","stake":500000000000,"min_stake":1000000000000,"pop_ok":true,"policy_ok":true,"eligible":false}
```

**Ausgabe bei fehlendem/ungültigem PoP:**
```json
{"type":"role_check","validator_id":"...","stake":1000000000000,"min_stake":1000000000000,"pop_ok":false,"policy_ok":true,"eligible":false}
```

### Manuelle Validator-Aktivierung

Alternativ kann `--tx-proposer` explizit gesetzt werden:

```bash
phantom-node p2p-quic-listen \
  --addr 0.0.0.0:9000 \
  --store-dir /path/to/data \
  --tx-proposer
```

## Architektur

### Autoritative Eligibility-Daten

Die produktive Validator-Eligibility basiert auf:

- `ValidatorRecordV1` im State-DB
- gestakten UTXOs im State-DB
- lokal verifiziertem `bls_pop`
- optionaler `role_policy.json`

### Legacy/Bootstrap: `stake_registry.json`

`stake_registry.json` kann weiterhin als Bootstrap-/Hilfsartefakt im `store_dir` vorhanden sein.
Der aktuelle Node nutzt diese Datei beim Start höchstens als Fallback für die initiale Netzskalen-Berechnung; die laufende Validator-Eligibility wird jedoch **nicht** aus dieser Datei bestimmt.

Ein mögliches Dateiformat ist:

```json
{
  "validators": {
    "<validator_id_hex>": {
      "validator_id": [1,2,3,...],
      "operator_id": [4,5,6,...],
      "bls_pk_hex": "...",
      "bls_pop_hex": "...",
      "staked_utxos": [
        {"outpoint": {"txid": [...], "vout": 0}, "amount": 500000000000, "staked_at_index": 100}
      ],
      "vrf_proof_hex": null,
      "last_selected_at": 0,
      "attendance_pct": 100
    }
  }
}
```

### On-Chain UTXO-Locking

Gestakte UTXOs werden im UTXO-State als `staked=true` markiert und können nicht ausgegeben werden.

### Committee-Selection

Nur Kandidaten mit ausreichend Stake werden für die Committee-Selection berücksichtigt.

## Workflow: Validator werden

1. **UTXOs sammeln**: Mindestens 10.000 PC in UTXOs (empfohlen: 20.000 PC)
2. **BLS-Keypair generieren**: Für VRF-Proofs und Signierung
2b. **BLS PoP erzeugen**:

```bash
phantom-signer bls-pop --keystore validator_bls.ks.toml
```

3. **Validator-Record on-chain bereitstellen**: Die produktive Eligibility setzt einen gültigen Validator-Record im State-DB voraus.
4. **Zugehörige UTXOs binden**: Über `POST /stake/bond` die Stake-UTXOs binden.
5. **Node starten**: `phantom-node p2p-quic-listen --bls-pk ...`
6. **Automatisch Validator**: Bei genug Stake wird `tx_proposer` aktiviert.

## Sicherheit

- **[Ownership]** Unstake benötigt gültige Signaturen.
- **[Replay-Schutz]** Die Unbond-Nachricht enthält eine state-derived Challenge.
- **[Stake-Locking]** Bereits gestakte UTXOs bleiben im State gesperrt.
