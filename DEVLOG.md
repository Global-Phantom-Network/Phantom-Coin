# DEVLOG — Phantom-Coin Entwicklungsprotokoll

> Chronologisches Logbuch aller Code-Änderungen mit Kontext, Begründung und Verifikation.
> Ziel: 100% Nachvollziehbarkeit für alle Beteiligten.

---

## Legende

| Kürzel | Bedeutung |
|--------|-----------|
| **BUG** | Fehlerbehebung |
| **FEA** | Neues Feature |
| **REF** | Refactoring (Verhalten unverändert) |
| **TST** | Test-Änderung |
| **CFG** | Konfiguration / Build |

---

## Session 1 — Kompilations- & Semantik-Fehler fixen (Mrz 2026)

### 1.1 — BUG: `compute_payload_payout_root_strict` — Signatur-Korrektur

- **Datei:** `crates/phantom-node/src/main.rs` Zeilen 1188–1245
- **Problem:** Nach dem großen Refactoring (Monolith → Module) war die Funktion
  `compute_payload_payout_root_strict` nicht korrekt verdrahtet. Der letzte Parameter
  war als `u8` (creator_index) definiert, aber die Callsite übergab eine
  `Option<[u8; 32]>` (Validator-ID).
- **Ursache:** Beim Refactoring wurde die interne Logik zur Auflösung der Validator-ID
  zum `creator_index` nicht übernommen.
- **Fix:** Funktion nimmt jetzt `local_validator_id: Option<[u8; 32]>` entgegen und
  löst den `creator_index` intern auf, indem die Validator-ID im Committee gesucht wird
  (Zeilen 1217–1225).
- **Abgleich mit Backup:** Logik entspricht dem Original-Verhalten im Monolith.
- **Risiko:** Gering — reine Signatur-Anpassung, Verhalten identisch.
- **Verifikation:** `cargo check -p phantom-node` + `cargo test -p phantom-node` (43/43 Tests grün).

---

### 1.2 — BUG: `compute_payload_payout_root_strict` — Payout-Root-Berechnung

- **Datei:** `crates/phantom-node/src/main.rs` Zeilen 1231–1244
- **Problem:** Die Payout-Root-Berechnung fehlte komplett — die Funktion gab einen
  leeren Hash zurück statt `compute_total_payout_root` aufzurufen.
- **Fix:** `fees_total = 0` (da `amt_in == amt_out` im UTXO-Modell erzwungen wird),
  dann Berechnung via `compute_total_payout_root` mit `FeeSplitParams::recommended()`.
- **Design-Entscheidung:** Kein explizites Fee-Modell → `fees_total` ist immer 0.
  Die Payout-Root wird trotzdem korrekt berechnet (leerer PayoutSet bei 0 Fees).
- **Verifikation:** Unit-Test `verify_payload_payout_root_rejects_wrong_root_for_finalized_apply_path`.

---

### 1.3 — BUG: `verify_and_extract_slash_ops` — Überflüssiger Parameter

- **Datei:** `crates/phantom-node/src/quic_server.rs` Zeilen 2317–2324 und 2916–2923
- **Problem:** Beide Callsites übergaben einen extra `k_state`-Parameter, den die
  Funktion nicht erwartet (6 statt 7 Argumente).
- **Ursache:** Beim Refactoring wurde ein Parameter aus der Funktions-Signatur entfernt,
  aber die Callsites nicht angepasst.
- **Fix:** Überflüssigen `k_state`-Parameter aus beiden Callsites entfernt.
- **Verifikation:** `cargo check -p phantom-node`.

---

### 1.4 — REF: Ungenutzte Imports entfernt

- **Datei:** `crates/phantom-node/src/main.rs` Zeilen 54–59
- **Entfernt:** `candidate_id_v1`, `mint_candidate_from_pow_cert_v1` (ungenutzt nach Refactoring).
- **Datei:** `crates/phantom-node/src/main.rs` Zeilen 1189, 1248
- **Geändert:** Ungenutzte Parameter mit Unterstrich prefixed (`_st`, `_txs`).
- **Verifikation:** `cargo check -p phantom-node` — 0 Warnungen.

---

### 1.5 — TST: Tests an neue APIs angepasst

- **Datei:** `crates/phantom-node/src/tests.rs`
- **Änderungen:**
  1. **Zeile 350:** Funktionsname `verify_payload_payout_root_strict_by_creator_index`
     → `compute_payload_payout_root_strict_by_creator_index` (Rename im Refactoring).
  2. **Zeile 356:** Parameter `&payload` → `&payload.micro_txs` (Signatur-Änderung).
  3. **Zeilen 230, 252:** `q.pop_next(1)` → `q.pop_next(|_| 1)` (Closure statt
     Integer, da `FinalizedQueue::pop_next` jetzt eine Closure für dynamische
     Shard-Anzahl erwartet).
- **Verifikation:** Alle 43 Unit-Tests in `phantom-node` bestanden.

---

### 1.6 — BUG (kritisch): `MintCensorRuntimeV1::validate_final_payload` — Fehler geschluckt

- **Datei:** `crates/phantom-node/src/main.rs` Zeilen 2154–2162
- **Problem:** Die Funktion gab **immer** `Ok(())` zurück, auch wenn die interne
  Validierung fehlschlug. Fehler wurden geloggt, aber nicht propagiert.
- **Auswirkung:** Ungültige Mint-Payloads wurden akzeptiert statt abgelehnt.
  Consensus-kritischer Bug.
- **Ursache:** Beim Refactoring wurde das Original-Pattern
  ```rust
  if validation.is_err() {
      self.windows = windows_before;
      self.finalized_anchor_ids = finalized_anchor_ids_before;
  }
  validation  // ← Original gibt Fehler weiter
  ```
  ersetzt durch:
  ```rust
  match validation {
      Ok(_) => {}
      Err(e) => {
          // rollback...
          warn!(err = %e, "mint-censor validation failed");
      }
  }
  Ok(())  // ← BUG: Fehler wird geschluckt
  ```
- **Fix:**
  ```rust
  match validation {
      Ok(_) => Ok(()),
      Err(e) => {
          self.windows = windows_before;
          self.finalized_anchor_ids = finalized_anchor_ids_before;
          warn!(err = %e, "mint-censor validation failed");
          Err(e)  // ← Fehler wird jetzt korrekt propagiert
      }
  }
  ```
- **Abgleich mit Backup:** Fix stellt Original-Verhalten wieder her + zusätzliches
  `warn!`-Logging.
- **Risiko:** Fix selbst ist risikoarm. Der *Bug* war hochriskant (Consensus-Break).
- **Verifikation:**
  - `mint_censor_runtime_failed_validation_rolls_back_state` — PASS
  - `mint_censor_runtime_failed_validation_restores_existing_anchor_binding` — PASS
  - `mint_censor_runtime_rejects_candidate_when_open_anchor_not_finalized` — PASS
  - Alle 43 Tests grün nach Fix.

---

## Session 2 — Dynamisches Sharding: Schritt 1 (Mrz 2026)

### 2.1 — CFG: `rotation_manager` Modul exportieren

- **Datei:** `crates/pc-consensus/src/lib.rs` Zeile 37
- **Problem:** `rotation_manager.rs` existierte, war aber nie als `pub mod` in `lib.rs`
  eingetragen → wurde nie kompiliert, Tests nie ausgeführt.
- **Fix:** `pub mod rotation_manager;` hinzugefügt.
- **Verifikation:** `cargo check -p pc-consensus` — 0 Fehler.

---

### 2.2 — FEA: `NetworkScale` Struct + `compute_network_scale` Funktion

- **Datei:** `crates/pc-consensus/src/rotation_manager.rs` Zeilen 18–44
- **Umsetzungsplan:** Schritt 1.1 + 1.2
- **Beschreibung:** Neuer Typ `NetworkScale { num_shards: u16, k: u8 }` und
  freistehende Funktion `compute_network_scale(pool_size: usize) -> NetworkScale`.
- **Logik:**
  - `k = clamp(1, pool_size, 21)` — Committee-Größe wächst mit Validator-Anzahl
  - `num_shards = 1` wenn `pool_size < 21`, sonst `clamp(1, pool_size / 21, 64)`
  - Ergebnis: 1 Val → (1S, K=1), 21 Val → (1S, K=21), 1344 Val → (64S, K=21)
- **Bestehender Code:** `RotationManager::compute_network_scale` delegiert an die neue
  freistehende Funktion (DRY).
- **Design-Entscheidung:** Freistehende Funktion, damit sie auch ohne RotationManager
  nutzbar ist (z.B. im QUIC-Server).

---

### 2.3 — FEA: `RotationRecord` um `num_shards` und `k` erweitert

- **Datei:** `crates/pc-consensus/src/rotation_manager.rs` Zeilen 91–100
- **Umsetzungsplan:** Schritt 1.3
- **Beschreibung:** `RotationRecord` speichert jetzt pro Epoche die dynamisch
  berechneten Werte `num_shards: u16` und `k: u8`.
- **Hinweis:** War bereits im refactored Code vorhanden, fehlte aber im Backup
  (Original). Dies ist eine bewusste Erweiterung.

---

### 2.4 — FEA: `rotate_committee` berechnet `k` intern

- **Datei:** `crates/pc-consensus/src/rotation_manager.rs` Zeilen 152–172
- **Backup-Signatur:** `rotate_committee(&mut self, k: u8, ...)` — `k` explizit.
- **Neue Signatur:** `rotate_committee(&mut self, current_anchor_index, epoch_len, ...)`
  — `k` wird intern via `compute_network_scale(candidates.len())` berechnet.
- **Breaking Change:** Ja — Callsites müssen angepasst werden (kein `k`-Parameter mehr).
- **Begründung:** Dynamisches Sharding erfordert, dass `k` zur Laufzeit aus der
  Pool-Größe berechnet wird, nicht manuell übergeben.

---

### 2.5 — TST: rotation_manager Tests teilweise repariert

- **Datei:** `crates/pc-consensus/src/rotation_manager.rs` Zeilen 397–540
- **Gefixt:**
  - `rotate_committee_success`: Fehlende `current_anchor_index`/`epoch_len` Variablen hinzugefügt.
  - `rotate_committee_no_eligible_fails`: Dummy-BLS-Keys korrigiert.
  - `operator_selection_counts_tracked`: 7 → 6 Argumente (extra `1` entfernt).
- **Noch offen:** 2 Tests rot wegen ungültiger BLS-Dummy-Keys
  (`BlsPublicKey::from_bytes(&[0u8;48])` gibt `None` zurück).
  → Fix: `bls_keygen_from_ikm` verwenden (wie im Backup).

---

### 2.6 — TST: rotation_manager Tests — gültige BLS-Keys (05.03.2026, 13:38)

- **Datei:** `crates/pc-consensus/src/rotation_manager.rs` Zeilen 397–484
- **Problem:** 2 Tests (`rotate_committee_success`, `rotate_committee_no_eligible_fails`)
  stürzten mit `unwrap()` auf `None` ab, weil `BlsPublicKey::from_bytes(&[0u8; 48])`
  keinen gültigen BLS-Key erzeugt (Null-Bytes sind kein Punkt auf der BLS12-381-Kurve).
- **Ursache:** Beim Refactoring wurden Dummy-Keys als Platzhalter eingesetzt, die
  zur Laufzeit ungültig sind.
- **Fix:** Beide Tests nutzen jetzt `bls_keygen_from_ikm` (wie im Backup):
  - Generiert gültige BLS-Keypairs aus deterministischem IKM-Seed
  - VRF-Proofs via `bls_vrf_prove` mit korrekter Seed/Epoch-Message
  - PoP via `bls_pop_prove`
- **Ergebnis:** Alle 8 `rotation_manager`-Tests grün.
- **Verifikation:** `cargo test -p pc-consensus rotation_manager` — 8/8 PASS.

### 2.7 — FEAT: Schritt 2 — FinalizedQueue bereits dynamisch (05.03.2026)

- **Datei:** `crates/pc-consensus/src/finalized_queue.rs`
- **Befund:** `pop_next` akzeptiert bereits eine Closure `Fn(u64) -> u16`,
  die pro Epoche die erwartete Shard-Anzahl liefert.
- **Callsite** in `quic_server.rs:2191` nutzt `|_epoch| num_shards_state`.
- **Ergebnis:** Keine Codeänderung nötig — Architektur steht bereits.

---

### 2.8 — FEAT: Schritt 3 — Hardcoded Sharding in quic_server.rs aufgelöst (05.03.2026)

- **Datei:** `crates/phantom-node/src/quic_server.rs` Zeilen 975–1001
- **Problem:** `let num_shards_state: u16 = 1` und `let my_shard_id: u16 = 0` waren
  hardcoded — keine Skalierung möglich.
- **Fix:**
  - `stake_registry.json` wird aus `store_dir` geladen (falls vorhanden)
  - `eligible_count()` → `compute_network_scale(pool)` → `initial_scale`
  - `num_shards_state` wird aus `initial_scale.num_shards` gesetzt
  - **Fallback:** Ohne Registry → `NetworkScale { num_shards: 1, k: k_state }` (Genesis-Modus)
  - `my_shard_id` bleibt vorerst `0` — dynamische Berechnung kommt in Schritt 4
- **Risiko:** Niedrig. Ohne `stake_registry.json` verhält sich der Code identisch zum Vorzustand.
- **Verifikation:** `cargo check -p phantom-node` — kompiliert warningsfrei (bzgl. dieser Änderung).

---

### 2.9 — FEAT: Schritt 4 — VRF-Committee pro Shard + Validator-Zuständigkeit (06.03.2026)

- **Dateien:**
  - `crates/pc-consensus/src/committee_vrf.rs` — neue Funktion `committee_select_vrf_sharded`
  - `crates/pc-consensus/src/rotation_manager.rs` — `rotate_committee` nutzt Sharded-Selektion,
    neue Felder/Methoden für Shard-Committees
- **Problem:** `rotate_committee` nutzte einen einzigen globalen Seed für die Committee-Wahl.
  Multi-Shard erfordert pro Shard verschiedene Committees.
- **Design-Entscheidung:** VRF-Verifikation mit **globalem Seed** (einmalig), dann
  deterministische Shard-Aufteilung durch Re-Hash: `blake3(shard_seed || vrf_score)`.
  Grund: Kandidaten erstellen nur einen VRF-Proof (mit globalem Seed). Pro-Shard-Verification
  wäre inkompatibel, da der Proof nur gegen den Erstellungs-Seed validierbar ist.
- **Neue API:**
  - `committee_select_vrf_sharded(k, epoch, global_seed, anchor_idx, candidates, params, num_shards)`
    → `HashMap<u16, Vec<SelectedSeat>>`
  - `RotationManager::committee_for_shard(shard_id)` → `&[SelectedSeat]`
  - `RotationManager::get_active_shards_for_validator(recipient_id)` → `Vec<u16>`
  - `RotationRecord::shard_committees` — neues Feld
  - `RotationManager::current_shard_committees` — neues Feld
- **Tests:** 10/10 `rotation_manager`-Tests grün, inkl. 2 neue:
  - `multi_shard_committees_distinct_seeds` — 42 Kandidaten → 2 Shards, verschiedene Committees
  - `get_active_shards_for_validator_works` — Validator-Lookup über Shard-Committees
- **Verifikation:** `cargo test -p pc-consensus --lib rotation_manager` — 10/10 PASS.

---

### 2.10 — FEAT: Schritt 3.2 — my_shard_id dynamisch (06.03.2026)

- **Datei:** `crates/phantom-node/src/quic_server.rs`
- **Problem:** `my_shard_id: u16 = 0` war ein einzelner Wert — bei Multi-Shard kann ein
  Validator in mehreren Shards sitzen.
- **Fix:**
  - `my_shard_id: u16` → `my_shard_ids: HashSet<u16>` (initial: `{0}`)
  - 4 Callsites: `shard_for_tx(&tx, n) != my_shard_id` → `!my_shard_ids.contains(&shard_for_tx(&tx, n))`
  - Bei Epoch-Rotation wird das Set via `get_active_shards_for_validator` aktualisiert (Plumbing steht)
- **Risiko:** Niedrig. Im Genesis-Modus (1 Shard) enthält das Set nur `{0}` — identisch zum Vorzustand.
- **Verifikation:** `cargo check -p phantom-node` — kompiliert warningsfrei.

---

### 2.11 — FEAT: Schritt 5 — Mempool-Kapazität dynamisch (06.03.2026)

- **Datei:** `crates/phantom-node/src/quic_server.rs`
- **Problem:** `mempool_cap_per_shard(1)` war hardcoded — bei mehr Shards muss die Kapazität
  pro Shard reduziert werden (MEMPOOL_GLOBAL_MAX / num_shards).
- **Fix:** `mempool_cap_per_shard(1)` → `mempool_cap_per_shard(num_shards_state)`
- **Risiko:** Niedrig. Bei 1 Shard identisch zum Vorzustand.
- **Verifikation:** `cargo check -p phantom-node` — kompiliert warningsfrei.

---

### 2.12 — FEAT: Schritt 6 — Proposer-Loop nur für eigene Shards (06.03.2026)

- **Datei:** `crates/phantom-node/src/quic_server.rs`
- **Problem:** `for proposer_shard_id in 0..num_shards_state` iterierte über **alle** Shards —
  ein Validator sollte nur für seine zugewiesenen Shards Payloads bauen.
- **Fix:** `0..num_shards_state` → `my_shard_ids.iter()` — iteriert nur über eigene Shards.
- **Risiko:** Niedrig. Bei 1 Shard und `my_shard_ids = {0}` identisch zum Vorzustand.
- **Verifikation:** `cargo check -p phantom-node` — kompiliert warningsfrei.

---

### 2.13 — FEAT: Schritt 7 — verify_header_finality mit dynamischem k (06.03.2026)

- **Datei:** `crates/phantom-node/src/quic_server.rs`
- **Problem:** `let k = k_eff` im Consensus-Task nutzte den statischen Genesis-Wert.
  Bei dynamischem Sharding muss `k` aus der StakeRegistry berechnet werden.
- **Fix:**
  - `initial_scale`-Berechnung (StakeRegistry-Ladung) nach **oben** verschoben (vor `consensus_task`)
  - `let k = k_eff` → `let k = initial_scale.k`
  - Duplizierte `initial_scale`-Berechnung im `state_task` entfernt
- **Risiko:** Niedrig. Ohne StakeRegistry: Fallback auf `k_eff` (Genesis-Wert).
- **Verifikation:** `cargo check --workspace` — kompiliert warningsfrei.

---

### 2.14 — TST: Schritt 8 — Verifikation (06.03.2026)

- `cargo test -p pc-consensus` — alle Tests grün (Unit + Integration)
- `cargo check --workspace` — gesamter Workspace kompiliert warningsfrei
- Nur vorbestehende Warnings (`compute_committee_from_state` unused, `cert` field unused)

---

## Offene Punkte

| # | Beschreibung | Priorität | Status |
|---|---|---|---|
| O1 | 2 rote Tests in `rotation_manager` fixen (BLS-Keys) | Hoch | ✅ Erledigt |
| O2 | Sharding Schritt 2: FinalizedQueue dynamische Shards | Hoch | ✅ Erledigt (bereits implementiert) |
| O3 | Sharding Schritt 3: Hardcoded Werte in quic_server.rs auflösen | Hoch | ✅ Erledigt |
| O4 | Sharding Schritt 4: VRF-Committee pro Shard + Validator-Zuständigkeit | Hoch | ✅ Erledigt |
| O5 | Sharding Schritt 5: Mempool-Kapazität + Tx-Filter dynamisch | Hoch | ✅ Erledigt |
| O6 | Sharding Schritt 6: Proposer-Loop nur für eigene Shards | Hoch | ✅ Erledigt |
| O7 | Sharding Schritt 7: verify_header_finality mit dynamischem k | Hoch | ✅ Erledigt |
| O8 | Sharding Schritt 8: Tests & Verifikation | Hoch | ✅ Erledigt |
| O9 | Weltkarte: Backend/Frontend | Mittel | Ausstehend |
| O10 | Epoch-Rotation: my_shard_ids + num_shards_state zur Laufzeit aktualisieren | Mittel | Ausstehend |

---

## Referenzen

- **Backup (Original):** `/Users/fuatbayram/Desktop/DEX/Phantom-Coin-Genesis-Node/`
- **Umsetzungsplan:** `sharding_umsetzungsplan.txt` im Projekt-Root
- **Test-Kommando:** `cargo test -p phantom-node` (43 Tests), `cargo test -p pc-consensus rotation_manager`
