# Phantom-Coin Mining API

Dieses Dokument beschreibt die aktive HTTP-API fuer externe Miner und Pool-Betreiber.
Es gilt fuer den Live-Emissionspfad mit Mint-Runden, `round_id`, `hit_bucket`, `bits_used`
und graph-finalisiertem Winner-Mint.

## 1. Rolle der API

Die Mining-API ist kein eigener Konsenslayer. Sie ist nur die Operator-Schnittstelle fuer:

- Abruf der aktuell offenen Emissionsrunde,
- Abruf der aktuellen Difficulty und Reward-Parameter,
- Einreichen gefundener Mint-Kandidaten,
- Pruefen, ob ein lokaler Mint bereits auf Platte liegt.

Die endgueltige Wahrheit bleibt der Graph:

- Ein eingereichter Mint ist nur lokal persistiert.
- Ein Mint wird erst real, wenn ein Proposer ihn in ein Payload aufnimmt und der Graph ihn finalisiert.

## 2. Wo die API laeuft

Es gibt zwei relevante Deployment-Formen:

### 2.1 Im normalen Node

Der produktive Pfad ist der Status-Server des `phantom-node`.
Dort laufen unter anderem:

- `GET /mint/template`
- `GET /mint/status`
- `GET /mint/status/<hex_id>`
- `POST /mint/submit`

Beispiel:

```bash
cargo run -p phantom-node --bin phantom-node -- \
  status-serve \
  --addr 127.0.0.1:8080 \
  --store-dir /var/lib/phantom-coin/data \
  --mempool-dir /var/lib/phantom-coin/data/mempool
```

### 2.2 Standalone-Testserver

Fuer isolierte Mining-Tests existiert zusaetzlich `phantom-mint-rpc`.
Die Semantik der Endpunkte ist dieselbe, der produktive Referenzpfad bleibt aber der
Status-Server im Haupt-Node.

## 3. Aktive Rundenphasen

Jede offene Runde befindet sich lokal immer in genau einer Phase:

- `searching`
- `collecting`

### 3.1 `searching`

Bedeutung:

- fuer die naechste Mint-Hoehe gibt es noch keinen eingefrorenen Treffer,
- `target_bits` ist ein Momentwert fuer den aktuellen Zeit-Bucket,
- `hit_bucket`, `bits_used` und Deadlines sind noch `null`.

### 3.2 `collecting`

Bedeutung:

- ein erster Treffer wurde akzeptiert,
- `hit_bucket` und `bits_used` sind eingefroren,
- nur Kandidaten mit exakt demselben Rundenkontext sind noch zulaessig,
- nach 5 Buckets darf der beste Kandidat in ein Payload,
- nach insgesamt 20 Buckets verfaellt die Runde.

## 4. Endpoint-Uebersicht

| Endpunkt | Methode | Zweck |
|---|---|---|
| `/mint/template` | `GET` | Template der aktuell offenen Runde abrufen |
| `/mint/status` | `GET` | Status der offenen Runde und Supply-Metadaten abrufen |
| `/mint/status/<hex_id>` | `GET` | Lokale Existenz eines konkreten Mint-Files pruefen |
| `/mint/submit` | `POST` | Gefundenen Mint-Kandidaten einreichen |

Alle Antworten sind JSON.

## 5. `GET /mint/template`

### 5.1 Zweck

Liefert:

- `prev_mint_id`
- die aktuell gueltige Difficulty fuer die offene Runde,
- Reward- und Supply-Metadaten,
- die lokale Rundenphase,
- den aktuellen oder eingefrorenen Emissionskontext.

Wichtig:

- `network_id` wird aus der kanonischen `GenesisNote` abgeleitet.
- Im aktiven Pfad ist diese Genesis `version == 3` und commitet damit auch auf
  `emission_bootstrap_bucket`.

### 5.2 Beispielantwort in `searching`

```json
{
  "prev_mint_id": "742b998018deb2e706fb807878ca43c121d478c1e4eb3ff5370faaf7f5216fa6",
  "target_bits": 20,
  "reward": 5000000000,
  "mint_height": 2183,
  "total_supply": "1091500000000000",
  "remaining_supply": "3908500000000000",
  "network_id": "c931c34f6e9af65140b847e1c8e5eeac34920274d7b5563faca79f004bb20557",
  "phase": "searching",
  "round_id": "1cbb0a0b8f99a1f51fef82ce3a7b7b0af5fd0fe178b4dcbfca0caa6a8bba41a2",
  "hit_bucket": null,
  "bits_used": null,
  "collect_deadline_bucket": null,
  "finalize_deadline_bucket": null
}
```

### 5.3 Beispielantwort in `collecting`

```json
{
  "prev_mint_id": "742b998018deb2e706fb807878ca43c121d478c1e4eb3ff5370faaf7f5216fa6",
  "target_bits": 19,
  "reward": 5000000000,
  "mint_height": 2183,
  "total_supply": "1091500000000000",
  "remaining_supply": "3908500000000000",
  "network_id": "c931c34f6e9af65140b847e1c8e5eeac34920274d7b5563faca79f004bb20557",
  "phase": "collecting",
  "round_id": "1cbb0a0b8f99a1f51fef82ce3a7b7b0af5fd0fe178b4dcbfca0caa6a8bba41a2",
  "hit_bucket": 1700000101,
  "bits_used": 19,
  "collect_deadline_bucket": 1700000106,
  "finalize_deadline_bucket": 1700000121
}
```

### 5.4 Feldbedeutung

| Feld | Typ | Bedeutung |
|---|---|---|
| `prev_mint_id` | Hex-String, 32 Byte | letzter finaler Mint |
| `target_bits` | `u8` | aktive Difficulty fuer den aktuellen lokalen Rundenstatus |
| `reward` | `u64` | maximal zulaessiger Reward fuer den naechsten Mint |
| `mint_height` | `u64` | aktuelle finale Mint-Hoehe vor dem naechsten Mint |
| `total_supply` | String | aktuelle Gesamtemission |
| `remaining_supply` | String | verbleibende Emission bis Hardcap |
| `network_id` | Hex-String, 32 Byte | Eingabe fuer `pow_seed` |
| `phase` | `searching` oder `collecting` | lokale Rundenphase |
| `round_id` | Hex-String, 32 Byte | deterministische ID der offenen Runde |
| `hit_bucket` | `u64?` | eingefrorener Treffer-Bucket in `collecting` |
| `bits_used` | `u8?` | eingefrorene Difficulty in `collecting` |
| `collect_deadline_bucket` | `u64?` | Bucket, ab dem der Winner in einen Payload darf |
| `finalize_deadline_bucket` | `u64?` | Bucket, ab dem die Runde verfaellt |

### 5.5 Wichtiger Unterschied: `target_bits` in `searching`

In `searching` ist `target_bits` nur der aktuelle Bucket-Wert zum Zeitpunkt des Abrufs.

Das ist wichtig:

- Die Difficulty kann mit der Zeit wandern.
- Ein Miner darf `target_bits` nicht als unendlich lange gueltige Zusage interpretieren.
- Wenn sich der lokale Zeit-Bucket veraendert, kann ein spaeterer Treffer andere `bits_used`
  benoetigen als ein frueheres Template noch angezeigt hat.

Empfohlene Operator-Regel:

- in `searching` Template oder Status mindestens einmal pro Sekunde oder pro lokalem Bucketwechsel
  aktualisieren,
- `longpoll` nur als Zusatz fuer Tip-Wechsel verwenden, nicht als Ersatz fuer Bucket-synchrone
  Difficulty-Aktualisierung.

### 5.6 Longpoll

Der Endpoint unterstuetzt:

```text
GET /mint/template?longpoll=true&prev_mint_id=<hex>&timeout_ms=30000
```

Parameter:

| Parameter | Pflicht | Bedeutung |
|---|---|---|
| `longpoll` | nein | `true` aktiviert Longpoll |
| `prev_mint_id` | bei Longpoll ja | zuletzt bekannter finaler Mint |
| `timeout_ms` | nein | Default `25000`, Minimum `1000`, Maximum `120000` |

Wichtig:

- Longpoll wacht auf, wenn sich der effektive Rundenkontext aendert.
- Dazu gehoeren mindestens `prev_mint_id`, `round_id`, `phase`, `hit_bucket`, `bits_used`,
  `collect_deadline_bucket`, `finalize_deadline_bucket` und `target_bits`.
- Longpoll ist damit deutlich staerker als ein reiner Tip-Wechsel-Wakeup, ersetzt aber trotzdem
  kein aktives Polling ueber laengere Mining-Phasen.

## 6. `GET /mint/status`

### 6.1 Zweck

`/mint/status` liefert denselben offenen Emissionskontext wie `/mint/template`, aber mit zusaetzlichen
Supply- und Rundenfeldern fuer Dashboards und Operatoren.

### 6.2 Beispielantwort

```json
{
  "last_mint_id": "742b998018deb2e706fb807878ca43c121d478c1e4eb3ff5370faaf7f5216fa6",
  "mint_height": 2183,
  "total_supply": "1091500000000000",
  "remaining_supply": "3908500000000000",
  "hard_cap": "5000000000000000",
  "next_reward": 5000000000,
  "can_mint": true,
  "target_bits": 19,
  "phase": "collecting",
  "round_id": "1cbb0a0b8f99a1f51fef82ce3a7b7b0af5fd0fe178b4dcbfca0caa6a8bba41a2",
  "last_final_emission_bucket": 1700000000,
  "hit_bucket": 1700000101,
  "bits_used": 19,
  "collect_deadline_bucket": 1700000106,
  "finalize_deadline_bucket": 1700000121
}
```

### 6.3 Zusatzfelder

| Feld | Bedeutung |
|---|---|
| `last_mint_id` | letzter finaler Mint |
| `hard_cap` | absolute Emissionsobergrenze |
| `next_reward` | Reward fuer die offene Runde |
| `can_mint` | `false`, wenn Hardcap erreicht ist |
| `last_final_emission_bucket` | Bucket des letzten finalisierten Mints |

## 7. `GET /mint/status/<hex_id>`

Dieser Endpoint prueft nur, ob unter `mempool/mints/<hex_id>.bin` bereits ein lokales Mint-File liegt.

Beispielantwort:

```json
{
  "ok": true,
  "found": true
}
```

Das ist KEIN Finalitaetsbeweis.
`found = true` bedeutet nur:

- der Mint wurde lokal persistiert,
- nicht, dass er bereits im Graph finalisiert wurde.

## 8. `POST /mint/submit`

### 8.1 Zweck

Reicht einen Mint-Kandidaten ein.
Der Node:

- prueft Format, Rundenkontext, Difficulty und `pow_seed`,
- schreibt den Mint in `mempool/mints/<mint_id>.bin`,
- friert bei Bedarf die Runde ein oder ersetzt den lokalen Bestkandidaten.

### 8.2 Request-Format

```json
{
  "mint": {
    "version": 2,
    "prev_mint_id": "742b998018deb2e706fb807878ca43c121d478c1e4eb3ff5370faaf7f5216fa6",
    "outputs": [
      {
        "amount": 5000000000,
        "lock": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
      }
    ],
    "pow_seed": "e7f8a9b0c1d2e7f8a9b0c1d2e7f8a9b0c1d2e7f8a9b0c1d2e7f8a9b0c1d2e7f8",
    "pow_nonce": 123456789,
    "minted_at": 0,
    "round_id": "1cbb0a0b8f99a1f51fef82ce3a7b7b0af5fd0fe178b4dcbfca0caa6a8bba41a2",
    "hit_bucket": 1700000101,
    "bits_used": 19
  }
}
```

### 8.3 Pflichtregeln

| Feld | Regel |
|---|---|
| `version` | MUSS `2` sein |
| `prev_mint_id` | MUSS dem letzten finalen Mint entsprechen |
| `outputs` | Summe darf Reward nicht ueberschreiten |
| `pow_seed` | MUSS exakt via `mint_pow_seed_v2()` berechnet sein |
| `pow_nonce` | beliebiger `u64`, solange `pow_hash` die Difficulty erfuellt |
| `minted_at` | auf `0` setzen; wird spaeter vom Node gesetzt |
| `round_id` | MUSS zur offenen Runde passen |
| `hit_bucket` | MUSS zum Trefferzeitpunkt passen und darf nicht zu weit in der Zukunft liegen |
| `bits_used` | MUSS der fuer `hit_bucket` erwarteten Difficulty entsprechen |

### 8.4 Verhalten in `searching`

Wenn die Runde `searching` ist:

- `round_id` muss exakt passen,
- `hit_bucket` darf nicht mehr als 1 Bucket in der Zukunft liegen,
- `bits_used` muss `expected_bits_for_bucket(hit_bucket)` entsprechen.

Ist die Submission gueltig, friert der Node die Runde ein und startet `collecting`.

### 8.5 Verhalten in `collecting`

Wenn die Runde `collecting` ist:

- `round_id`, `hit_bucket` und `bits_used` muessen exakt zum eingefrorenen Rundenzustand passen,
- eine Submission mit anderem Kontext wird mit `409` abgelehnt,
- nach Ablauf der `finalize_deadline_bucket` wird die Runde verworfen und wieder zu `searching`.

### 8.6 Erfolg

```json
{
  "ok": true,
  "mint_id": "d4f6a4119aada18dde42b9b999304b1648a3ef5a594060b5bb181b4de387f655",
  "error": null
}
```

### 8.7 Typische Fehlerantworten

```json
{
  "ok": false,
  "mint_id": null,
  "error": "round_id mismatch"
}
```

Haeufige HTTP-Status:

| Status | Ursache |
|---|---|
| `200` | Kandidat lokal akzeptiert |
| `400` | JSON, Feldformat, `pow_seed`, Sanity, Difficulty oder Role-Policy ungueltig |
| `409` | stale `prev_mint_id`, falscher Rundenkontext, verfallene Collecting-Runde |
| `413` | Request-Body groesser als `MAX_HTTP_BODY_BYTES` |
| `500` | Persistenz- oder interner Serverfehler |
| `503` | `network_id` nicht konfiguriert, z. B. fehlende Genesis-Note |

Typische Fehltexte aus dem Live-Node:

- `prev_mint_id does not match chain tip - stale template`
- `mint v2 required for emission rounds`
- `round_id mismatch`
- `hit_bucket too far in future`
- `bits_used mismatch`
- `mint does not match frozen round`
- `collecting round expired`
- `pow validation failed: seed not bound or difficulty not met`
- `seed already used`
- `mint sanity failed`
- `mint rejected by role_policy`

## 9. Wie Miner `pow_seed` V2 berechnen

### 9.1 Eingaben

Ein Miner braucht:

- `network_id`
- `version = 2`
- `prev_mint_id`
- `outputs`
- `round_id`
- `hit_bucket`
- `bits_used`

### 9.2 Formel

```text
pow_seed =
  BLAKE3-256(
    b"pc:mint:pow:seed:v2\x01" ||
    network_id ||
    version ||
    prev_mint_id ||
    varu64(outputs.len) ||
    outputs ||
    round_id ||
    varu64(hit_bucket) ||
    bits_used
  )
```

### 9.3 Praktische Regel

- In `searching` bestimmt der Miner `hit_bucket` zum Trefferzeitpunkt.
- `bits_used` MUSS zu genau diesem `hit_bucket` passen.
- In `collecting` sind `hit_bucket` und `bits_used` bereits eingefroren; weitere Kandidaten
  derselben Runde muessen exakt diesen Kontext verwenden.

## 10. Empfohlener Miner-Ablauf

1. `GET /mint/template` abrufen.
2. Wenn `phase = searching`:
   - mit `prev_mint_id`, `round_id` und aktuellem `target_bits` arbeiten,
   - Template mindestens pro Bucketwechsel aktualisieren.
3. Treffer gefunden:
   - `hit_bucket` auf aktuellen lokalen Bucket setzen,
   - `bits_used` passend zu diesem Bucket setzen,
   - `pow_seed` neu mit `mint_pow_seed_v2()` berechnen,
   - `POST /mint/submit`.
4. Wenn die Runde nun `collecting` ist:
   - optional weitere Kandidaten fuer exakt denselben eingefrorenen Kontext suchen,
   - nach `collect_deadline_bucket` lohnt sich lokales Weiterrechnen fuer dieselbe Runde nur noch,
     wenn der Node die Collecting-Runde noch nicht finalisiert hat.
5. Bei `409` oder neuem `prev_mint_id`:
   - Template verwerfen,
   - neue Runde laden.

## 11. Operator-Hinweise

- `GET /mint/status` ist der beste Endpoint fuer Dashboards.
- `GET /mint/template` ist der beste Endpoint fuer Miner.
- `GET /mint/status/<hex_id>` zeigt nur lokale Persistenz, nicht Finalitaet.
- Ein lokal akzeptierter Mint kann spaeter trotzdem verlieren, wenn waehrend `collecting`
  ein besserer Kandidat eingereicht wurde.
- Die Sammelphase ist fix 5 Sekunden. Sie skaliert NICHT mit der Difficulty.
- Die Difficulty skaliert ueber Buckets. Deshalb muss `searching` aktiver gepollt werden als
  ein klassischer statischer PoW-Job.
