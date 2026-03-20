# Phantom-Coin Emission and PoW Specification

Dieses Dokument ist die kanonische Live-Spezifikation fuer den Emissionspfad von Phantom-Coin.
Es beschreibt ausschliesslich das aktuell aktive Modell aus Emissionsrunden, bucket-basierter
Difficulty und graph-finalisierten Winner-Mints.

Begriffe wie MUST, MUST NOT, SHOULD und MAY sind im RFC-Sinn zu verstehen.

## 1. Ziel und Scope

Phantom-Coin trennt zwei Dinge strikt:

- Der Graph finalisiert Reihenfolge, Besitzwechsel, Transfers, Claims, Slashing und Mints.
- PoW sichert nicht den Graphen, sondern liefert nur das Recht auf Coin-Emission.

Der Emissionspfad ist deshalb kein eigener Finalitaetsmechanismus, sondern eine vorgelagerte
Auswahl- und Difficulty-Logik, deren Ergebnis als normaler Mint im Graph finalisiert wird.

Dieses Dokument normiert:

- die Rollen von Graph und Emission,
- die deterministische Mint-Runden-ID,
- die erlaubte Zeit-Ausnahme fuer Difficulty und Sammelphase,
- das Verhalten von `Searching` und `Collecting`,
- die Bindung von `pow_seed`, `round_id`, `hit_bucket` und `bits_used`,
- die Akzeptanzregeln fuer Miner, Proposer und Validatoren,
- die Fortschreibung von `SupplyState`,
- die Persistenz- und Reset-Semantik des Emissionspfads.

Dieses Dokument normiert nicht:

- P2P-Header-/Vote-/BLS-Details des Graphkonsenses,
- Wallet- oder Address-Formate,
- historische Mint-Window-/Heartbeat-Logik.

## 2. Harte Architekturgrenzen

### 2.1 Graph

Der Graph bleibt vollstaendig zeitfrei fuer:

- Reihenfolge der finalen Kette,
- `anchor_index`,
- UTXO-Maturity,
- normale Transfers,
- Claims,
- Slashing,
- finale State-Root-Bildung.

### 2.2 Einzige erlaubte Zeit-Ausnahme

Lokale Zeit darf ausschliesslich im Emissionspfad verwendet werden fuer:

- `hit_bucket`,
- 5-Sekunden-Sammelphase,
- 15-Sekunden-Finalisierungs-Grace,
- ASERT-artige Difficulty-Anpassung.

Zeit darf NICHT verwendet werden fuer:

- Graph-Finalitaet,
- Header-Verkettung,
- UTXO-Maturity,
- Reihenfolge normaler Payloads,
- Besitzwechsel ausserhalb von Mints.

### 2.3 Determinismusgrenze

Die finale Graphkette bleibt mathematisch deterministisch replaybar.

Die Vorstufe der Emission ist absichtlich weicher:

- lokale Nodes duerfen unterschiedliche Kandidatenmengen sehen,
- lokale Nodes duerfen die Sammelphase zu leicht unterschiedlichen realen Zeitpunkten erleben,
- global bewiesen wird nicht, dass wirklich jeder existierende Kandidat gesehen wurde.

Deterministisch finalisiert wird nur:

- welcher Mint am Ende im Graph gelandet ist,
- mit welchem `round_id`,
- mit welchem `hit_bucket`,
- mit welchem `bits_used`,
- gegen welchen `prev_mint_id`.

## 3. Kernbegriffe

- `SupplyState`: globaler, finalisierter Emissionszustand.
- `MintRoundState`: lokaler, persistierter Rundenzustand fuer die aktuell offene Emissionsrunde.
- `Searching`: Runde ist offen, aber noch kein erster akzeptierter Treffer eingefroren.
- `Collecting`: erster Treffer ist eingefroren; weitere Kandidaten duerfen fuer exakt denselben
  Rundenkontext gesammelt werden.
- `round_id`: deterministische ID der offenen Runde, abgeleitet aus letztem finalen Mint und
  naechster Mint-Hoehe.
- `hit_bucket`: der Bucket des ersten oder eines konkurrierenden Treffers innerhalb derselben Runde.
- `bits_used`: die fuer diesen Treffer gueltige Difficulty.
- `collect_deadline_bucket`: Bucket, ab dem ein Gewinner-Mint in einen Payload aufgenommen werden darf.
- `finalize_deadline_bucket`: Bucket, nach dem eine nicht finalisierte Collecting-Runde verfaellt.
- `minted_at`: finaler `anchor_index`, vom Node beim Anwenden gesetzt. Dieses Feld ist fuer
  Maturity relevant und nicht Teil der Mining-Eingabe.

## 4. Zeitmodell und Konstanten

Aktive Konstanten aus `crates/pc-consensus/src/consts.rs`:

| Konstante | Wert | Bedeutung |
|---|---:|---|
| `EMISSION_BUCKET_MS` | `1000` | Ein Emissions-Bucket entspricht 1 Sekunde |
| `EMISSION_COLLECT_BUCKETS` | `5` | Sammelphase dauert 5 Buckets |
| `EMISSION_FINALIZE_GRACE_BUCKETS` | `15` | Zusaetzliche Finalisierungs-Reserve nach Ende der Sammelphase |
| `EMISSION_MAX_FUTURE_SKEW_BUCKETS` | `1` | Treffer darf hoechstens 1 Bucket in der Zukunft liegen |
| `POW_TARGET_SPACING_BUCKETS` | `600` | ASERT-Zielabstand zwischen zwei finalen Mints |
| `POW_ASERT_HALFLIFE_BUCKETS` | `3600` | Halflife der integer-basierten ASERT-Anpassung |

Ableitungen:

- `collect_deadline_bucket = hit_bucket + 5`
- `finalize_deadline_bucket = hit_bucket + 20`

## 5. Datenmodell

### 5.1 Finaler Emissionszustand: `SupplyState`

Fuer den aktiven Emissionspfad sind diese Felder normativ relevant:

- `last_mint_id`
- `mint_height`
- `total_supply`
- `pow_bits`
- `pow_bits_min`
- `last_final_emission_bucket`
- `pow_asert_ref_bucket`
- `last_minted_at_index`
- `genesis_note.emission_bootstrap_bucket` als Bootstrap-Quelle fuer leeren Zustand

Bedeutung:

- `last_mint_id` und `mint_height` definieren die naechste offene Runde.
- `pow_bits` ist die letzte finalisierte Basis-Difficulty.
- `pow_bits_min` ist die untere Schwierigkeitsschranke.
- `last_final_emission_bucket` ist der Bucket des letzten finalen Mints.
- `pow_asert_ref_bucket` ist der Referenz-Bucket fuer die naechste ASERT-Berechnung.
- Wenn noch kein finaler Mint existiert, MUSS `pow_asert_ref_bucket` aus der kanonischen
  `genesis_note.bin` (`emission_bootstrap_bucket`) initialisiert werden.
- `last_minted_at_index` bleibt fuer Maturity am `anchor_index` haengen und ist absichtlich
  unabhaengig von der Emissionszeit.

### 5.2 Lokaler Rundenzustand: `MintRoundState`

Die aktuell offene Runde wird persistent in `mempool/mint_round_state.json` gehalten und enthaelt:

- `prev_mint_id`
- `next_mint_height`
- `round_id`
- `phase`
- `frozen_hit_bucket`
- `frozen_bits`
- `collection_deadline_bucket`
- `finalize_deadline_bucket`
- `best_candidate_id`
- `best_pow_hash`

Diese Datei ist lokaler Laufzeitzustand, nicht selbst Konsensobjekt.
Sie darf beim Start aus dem finalen `SupplyState` rekonstruiert und bei Inkonsistenz verworfen werden.

### 5.3 Finales Mint-Objekt: `MintEvent` V2

Der Live-Node akzeptiert nur `MintEvent.version == 2`.

Normative Felder:

- `version`
- `prev_mint_id`
- `outputs`
- `pow_seed`
- `pow_nonce`
- `minted_at`
- `round_id`
- `hit_bucket`
- `bits_used`

Semantik:

- `prev_mint_id` bindet die Emission an den letzten finalen Mint.
- `round_id` bindet den Mint an die deterministische Runde.
- `hit_bucket` bindet den Mint an die Difficulty-Zeit.
- `bits_used` bindet den Mint an die konkrete Difficulty dieser Runde.
- `minted_at` wird vom Miner in Requests als `0` geliefert und vom Node spaeter auf den
  finalen `anchor_index` gesetzt.

## 6. Deterministische IDs und Hash-Bindung

### 6.1 `round_id`

`round_id` wird deterministisch berechnet als:

```text
round_id =
  BLAKE3-256(
    b"pc:mint:round:v1\x01" ||
    prev_mint_id ||
    varu64(next_mint_height)
  )
```

Konsequenzen:

- Jede offene Runde ist eindeutig durch letzten finalen Mint plus naechste Hoehe definiert.
- Nach Finalisierung eines Mints oeffnet automatisch genau eine neue Runde.
- Restart oder Rehydration duerfen keine alternative `round_id` erzeugen.

### 6.2 `pow_seed` V2

Fuer `MintEvent.version >= 2` MUSS der Miner `mint_pow_seed_v2()` verwenden:

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

Dadurch ist ein Miner kryptographisch gebunden an:

- das Netzwerk,
- die konkrete Runde,
- den Difficulty-Bucket,
- die verwendete Difficulty,
- die Auszahlungsoutputs.

Ein Mint darf seinen `pow_seed` nicht spaeter auf einen anderen Zeit- oder Difficulty-Kontext
umbiegen.

### 6.3 `pow_hash`

Der eigentliche Proof-of-Work bleibt:

```text
pow_hash = BLAKE3-256(POW_DOMAIN || pow_seed || pow_nonce_le)
```

`POW_DOMAIN = b"pc:mint:pow:v1\x01"`.

## 7. Rundenlebenszyklus

### 7.1 Oeffnen einer Runde

Nach jedem finalen Mint gilt:

- `prev_mint_id = last_mint_id`
- `next_mint_height = mint_height + 1`
- `round_id = H(prev_mint_id, next_mint_height)`
- `phase = Searching`

Diese Runde bleibt offen, bis entweder:

- ein erster gueltiger Treffer sie nach `Collecting` ueberfuehrt,
- oder nach einem verfallenen `Collecting` dieselbe Runde neu in `Searching` geoeffnet wird.

### 7.2 Phase `Searching`

In `Searching` gilt:

- es gibt noch keinen eingefrorenen Treffer,
- die aktive Difficulty ist `expected_bits_for_bucket(now_bucket)`,
- `target_bits` aus `/mint/template` ist nur ein Momentwert fuer den aktuellen Bucket.

Ein Miner-Kandidat darf in `Searching` akzeptiert werden, wenn mindestens Folgendes gilt:

- `version >= 2`
- `prev_mint_id == supply.last_mint_id`
- `round_id == current round_id`
- `hit_bucket <= now_bucket + 1`
- `bits_used == supply.expected_bits_for_bucket(hit_bucket)`
- `pow_seed` ist korrekt an den Mint gebunden
- `pow_hash` erfuellt `bits_used`
- Reward-, Cap- und Role-Policy-Regeln werden eingehalten

Der erste akzeptierte Treffer friert lokal ein:

- `phase = Collecting`
- `frozen_hit_bucket = hit_bucket`
- `frozen_bits = bits_used`
- `collection_deadline_bucket = hit_bucket + 5`
- `finalize_deadline_bucket = hit_bucket + 20`
- `best_candidate_id = mint_id`
- `best_pow_hash = pow_hash`

Wichtig:

- Die Difficulty darf bis zum ersten Treffer mit der Zeit wandern.
- Die erste akzeptierte Submission bestimmt den eingefrorenen Zeit-/Difficulty-Kontext der Runde.
- `first seen` waehlt NICHT automatisch den Gewinner, sondern nur den eingefrorenen Kontext.

### 7.3 Phase `Collecting`

In `Collecting` gilt:

- nur Kandidaten mit exakt demselben eingefrorenen Rundenkontext sind zulaessig,
- also identisches `round_id`,
- identisches `prev_mint_id`,
- identisches `hit_bucket`,
- identisches `bits_used`.

Alle anderen Kandidaten sind fuer diese Runde `context-invalid`.

Der lokale Bestkandidat wird deterministisch ersetzt, wenn sein Key besser ist:

```text
(pow_hash_as_be_u256, mint_id)
```

Praktisch bedeutet das:

- der niedrigere `pow_hash` gewinnt,
- bei Gleichstand gewinnt die kleinere `mint_id`.

### 7.4 Ende der Sammelphase

Ab `current_bucket >= collection_deadline_bucket` darf der Proposer den lokalen Bestkandidaten
in ein Payload aufnehmen.

Vor `collection_deadline_bucket` darf der Winner noch NICHT final werden.
Das ist die harte 5-Sekunden-Sammelphase.

### 7.5 Finalisierungs-Grace

Bis einschliesslich `finalize_deadline_bucket` darf ein eingefrorener Winner noch final werden.

Ab `current_bucket > finalize_deadline_bucket` gilt:

- die Runde ist verfallen,
- der lokale `MintRoundState` wird auf `Searching` fuer dieselbe `prev_mint_id`/Hoehe zurueckgesetzt,
- der Candidate-Pool fuer diese Runde wird verworfen,
- die Difficulty fuer den naechsten Versuch ergibt sich neu aus der aktuellen Zeit.

## 8. ASERT-artige Difficulty

### 8.1 Ziel

Die Difficulty soll sinken koennen, wenn lange kein Mint gefunden wird, ohne dass dafuer
Heartbeats oder leere Graph-Finalisierungen noetig sind.

### 8.2 Eingaben

`expected_bits_for_bucket(hit_bucket)` basiert auf:

- `pow_bits`
- `pow_bits_min`
- `pow_asert_ref_bucket`
- dem angefragten `hit_bucket`

### 8.3 Normative Berechnung

In vereinfachter Form:

```text
if pow_bits == 0:
    return 0

reference_bucket =
    pow_asert_ref_bucket

if current_bucket <= reference_bucket:
    return max(pow_bits, pow_bits_min)

actual = current_bucket - reference_bucket
target = 600
halflife = 3600
error = target - actual
delta = rounded(error / halflife)
next = clamp(pow_bits + delta, pow_bits_min, 255)
```

Interpretation:

- Mint kommt frueher als Zielabstand: Difficulty wird haerter.
- Mint kommt spaeter als Zielabstand: Difficulty wird leichter.
- Unter `pow_bits_min` darf die Difficulty nie fallen.
- Vor dem ersten finalen Mint stammt `pow_asert_ref_bucket` aus `genesis_note.emission_bootstrap_bucket`.

### 8.4 Fortschreibung nach Finalisierung

Wenn ein V2-Mint finalisiert wird, schreibt `process_mint()` fort:

- `last_final_emission_bucket = mint.hit_bucket`
- `pow_asert_ref_bucket = mint.hit_bucket`
- `pow_bits = max(mint.bits_used, pow_bits_min)`
- `last_minted_at_index = current_anchor_index`

Damit gilt:

- Emissions-Difficulty haengt an der finalen Mint-Historie und an Buckets,
- Maturity bleibt weiter am Graph-`anchor_index`,
- Heartbeats sind fuer Difficulty nicht mehr noetig.

## 9. Proposer- und Payload-Regeln

### 9.1 Keine Heartbeats mehr

Der aktive Emissionspfad erzeugt keine Heartbeat- oder Null-Mint-Payloads als Taktgeber.

Der Proposer darf weiterhin ganz normale tx-only Payloads bauen.
Emission blockiert nicht die Graph-Nutzung, und der Graph blockiert nicht die Emission.

### 9.2 Mint-Aufnahme in Payloads

Ein Mint darf nur aufgenommen werden, wenn:

- die Runde `Collecting` ist,
- `current_bucket >= collection_deadline_bucket`,
- der lokale Bestkandidat noch nicht verfallen ist.

`null_mint` in `AnchorPayloadV3` bleibt aus Wire-Kompatibilitaetsgruenden im Typ erhalten,
wird vom Live-Pfad aber immer als `false` geschrieben und ist bei `true` auf dem aktiven
Payload-v3-Pfad ungueltig.

## 10. Validator- und Finality-Regeln

Die Finality-Pipeline bleibt in exakt derselben Reihenfolge wie bisher:

1. `SupplyState`-Snapshot laden und mit Diskzustand synchronisieren.
2. Mint-Sanity pruefen.
3. Emissions-/PoW-Kontext pruefen.
4. Reward-, Cap- und Role-Policy pruefen.
5. `process_mint(m, next_anchor_index)` ausfuehren.
6. Danach erst normale `micro_txs`, Slashing und State-Root-Anwendung.

Validatorische Emissionspruefung fuer V2-Mints:

Deterministischer Konsenspfad:

- `mint.uses_emission_rounds() == true`
- `round_id == mint_round_id_v1(last_mint_id, mint_height + 1)`
- `hit_bucket >= last_final_emission_bucket`
- `bits_used == supply.expected_bits_for_bucket(hit_bucket)`
- `pow_seed` ist korrekt gebunden
- `pow_hash` erfuellt `bits_used`

Lokaler Vorstufen-/Timing-Pfad ausserhalb der finalen Konsensentscheidung:

- `hit_bucket <= current_bucket + 1`
- `current_bucket >= hit_bucket + 5`
- `current_bucket <= hit_bucket + 20`

Diese Zeitregeln steuern die lokale Such-/Collecting-Phase und die Annahme im Vorlauf.
Die finale Mint-Gueltigkeit in der Finality-Pipeline bleibt davon unberuehrt und wertet
keine lokale Wall-Clock neu aus.

## 11. Persistenz, Reset und Rehydration

### 11.1 Persistente Dateien

Wichtige Runtime-Dateien:

- `mempool/supply_state.json`
- `mempool/mint_round_state.json`
- `mempool/mints/<mint_id>.bin`
- `mempool/mint_seeds/<pow_seed_hex>`
- `headers/`
- `payload_segments/`
- `last_final_payload_root`

### 11.2 Startverhalten

Beim Start gilt:

- `SupplyState` wird geladen,
- `MintRoundState` wird geladen,
- wenn `MintRoundState` nicht zu `SupplyState.last_mint_id` oder `mint_height + 1` passt,
  wird er verworfen und aus `SupplyState` neu aufgebaut,
- wenn eine `Collecting`-Runde bereits ueber ihrer Deadline liegt, wird sie auf `Searching`
  zurueckgesetzt.

### 11.3 Kanonischer Reset

Der kanonische Reset purgt alle relevanten Runtime-Artefakte, einschliesslich:

- `headers/`
- `payload_segments/`
- `last_final_payload_root`
- `mempool/mint_round_state.json`
- weitere volatile Runtime-Stores

Damit darf alter Emissionszustand nach Reset nicht wieder rehydriert werden.

## 12. Nicht mehr erlaubte Altannahmen

Folgende Aussagen sind fuer das Live-System falsch:

- der Graph braucht Heartbeats, damit PoW weiterlaeuft
- `anchor_index` steuert die aktuelle Mint-Difficulty
- anchor-basierte Window- oder Deadline-Felder sind aktive Emissionsregeln
- `null_mint` ist auf dem Live-Pfad erlaubt oder eine Fortschrittsmechanik
- Mint-Version 1 ist noch live akzeptiert

## 13. Praktische Folgen fuer Miner und Operatoren

- Miner muessen mit `MintEvent.version = 2` arbeiten.
- Miner muessen `round_id`, `hit_bucket` und `bits_used` korrekt in den Mint uebernehmen.
- Miner muessen `pow_seed` mit `mint_pow_seed_v2()` berechnen.
- Operatoren duerfen `target_bits` aus `GET /mint/template` in `Searching` nur als aktuellen
  Bucket-Wert verstehen, nicht als dauerhafte Zusage.
- In `Collecting` ist die Difficulty eingefroren; dann liefern `hit_bucket` und `bits_used`
  den verbindlichen Kontext.
- Ein hoher Wert bei `pc_node_finality_events_total` bedeutet nicht automatisch viele Mints;
  tx-only Payloads zaehlen ebenfalls als Finality-Events.

## 14. Zusammenfassung

Das Live-Modell lautet:

- genau eine offene Runde pro naechstem Mint,
- erste gueltige Submission friert `hit_bucket` und `bits_used` ein,
- danach 5 Sekunden Sammelphase,
- danach darf der beste lokale Kandidat in den Graph,
- spaetestens nach 20 Sekunden verfällt die Runde,
- Difficulty reagiert auf Emissionszeit,
- Graph-Finalitaet bleibt zeitfrei.
