# Phantom-Coin Security Audit Report

## Kontext-Check

- **Analysierte Dateien**: `crates/phantom-node/src/main.rs`, `crates/phantom-node/src/quic_server.rs`, `crates/pc-p2p/src/lib.rs`, `crates/pc-state/src/lib.rs`, `crates/pc-da/src/da_gating/mod.rs`
- **Noch nicht abschließend verifiziert**: Der aktive lokale Signier-/Vote-Erzeugungspfad wurde für dieses Finding noch nicht vollständig isoliert.

---

## Bestätigte Findings

### P1-F01 — Finalität wird vor vollständiger lokaler Inhalts-/State-Prüfung in den Finalitätspfad übernommen *(DA-Gate + Sanity: behoben; volle State-/Ökonomie-Prüfung: nachgelagert im Apply-Pfad)*

**Datei/Modul + Symbol/Funktion:**

| Datei | Zeilen | Relevanz |
|---|---|---|
| `crates/phantom-node/src/main.rs` | 2166–2324 | `verify_header_finality(...)` prüft nur Header/Committee/Quorum/BLS-Aggregatsignatur |
| `crates/phantom-node/src/quic_server.rs` | 801–845, 872–915 | `final_ok` führt direkt zu `tx_final_cons.send(meta)` |
| `crates/phantom-node/src/quic_server.rs` | 2258–2262 | Fehlender Payload wird erst nach Finality-Signal erkannt |
| `crates/phantom-node/src/quic_server.rs` | 2267–2458 | Sanity/Mint/Slash/Payout/State-Prüfung kommt erst im Apply-Pfad |
| `crates/pc-p2p/src/lib.rs` | 2433–2462 | Payload wird nach admitted Header nur proaktiv angefordert, kein hartes blockierendes DA-Gate |

**Ist-Zustand:**

`verify_header_finality(...)` prüft ausschließlich formale Eigenschaften:
- Header-Version, `attest_sig` vorhanden, `network_id`
- Committee / Seed-Anchor / Epoch
- `creator_index`, `vote_mask`, Threshold
- BLS-Aggregatsignatur

Was dort **nicht** passiert:
- Kein Laden/Ausführen des Payloads
- Kein `validate_payload_sanity_v3`
- Keine Mint-/Slash-/Payout-/Ökonomie-Prüfung
- Keine State-Transition

Ein formal verifizierter Header wird danach **sofort** in den Finalitätspfad übernommen (`tx_final_cons.send(meta)`), obwohl Payload-Verfügbarkeit und Vollprüfung noch ausstehen. Das ist **kein echter Pre-Vote**, sondern ein **zu früh finalitätswirksamer Header-/Committee-Vote mit nachgelagerter Vollprüfung**.

**Risiko/Impact:**

- Falls der Payload fehlt oder spätere Prüfungen fehlschlagen, entsteht ein Zustand „formal final / lokal nicht anwendbar".
- Das ist ein reales Liveness-/Konsensrisiko: Finalitätsschicht sagt „ok", Ausführungsschicht sagt später „nicht anwendbar".
- Die dokumentierte DA-Gating-Architektur (`crates/pc-da/src/da_gating/mod.rs`) ist **nicht** als hartes Vote-Gate im produktiven `phantom-node`-Pfad verdrahtet.

**Impact-Abgrenzung:**

- Es gibt aktuell **keinen harten Beleg**, dass ein komplett ungültiger Payload trotz gescheiterter Vollprüfung in den persistenten State committed wird. Die persistente Finalisierung (`anchor_index`, `last_final_payload_root`, `applied_final_roots`) erfolgt erst nach erfolgreichem Apply.
- Belegt ist aber, dass formal finaler Inhalt **vor** Vollprüfung in den Finalitätspfad geschoben wird.

**Test-Idee:**

- Header mit gültiger Committee-Aggregatsignatur aber fehlendem Payload einspeisen: nach Fix darf kein Finality-Event entstehen.
- Header mit vorhandenem Payload, dessen Mint-/Slash-/Payout-Prüfung fehlschlägt: nach Fix darf kein Finality-Event entstehen.

---

### P2-F01 — Finalisierter Payload kann ungültige Einzel-micro_txs enthalten (toleranter Apply)

**Datei/Modul + Symbol/Funktion:**

| Datei | Zeilen | Relevanz |
|---|---|---|
| `crates/pc-state/src/lib.rs` | 2110–2176 | `apply_payload_v2_tolerant(...)`, `apply_payload_v2_tolerant_presigned(...)` |
| `crates/phantom-node/src/quic_server.rs` | 2439–2458 | Toleranter Apply-Pfad im State-Task |

**Ist-Zustand:**

Einzelne fehlschlagende `micro_txs` aborten den Payload nicht, sondern werden deterministisch übersprungen. Dadurch kann ein finalisierter Payload Transaktionen enthalten, die nicht zustandswirksam sind. Das ist nicht automatisch State-Corruption, aber eine riskante Semantik.

**Fix-Vorschlag:**

- **Option A (strict atomic):** Jede ungültige `micro_tx` verwirft den gesamten Payload.
- **Option B (canonical tolerant):** Skip-Ergebnis wird vor Vote kanonisch festgelegt und mitattestiert, damit Finalität und Ausführung exakt dasselbe Objekt meinen.

**Test-Idee:**

- Payload mit einer gültigen und einer ungültigen `micro_tx` einspielen: erwartetes Verhalten nach Architekturentscheidung ist entweder vollständige Ablehnung oder kanonisch committete Skip-Liste ohne Divergenz.

---

## Umsetzungsplan: Sichere Vote-/Finality-Pipeline

### Ziel-Invariante

**Nichts wird finalitätswirksam bestätigt, das nicht vorher lokal verfügbar, hash-konsistent und vollständig deterministisch validiert wurde.**

### Soll-Pipeline

```
Admission (nicht finalitätswirksam)
  -> DA / Payload lokal verfügbar + hash-verifiziert
  -> Vollprüfung / deterministische Vor-Ausführung
  -> Vote / Attestation
  -> Quorum
  -> Finalisierung / Persistenz
```

### Schritt 1: Admission / Pre-Check (nicht finalitätswirksam)

- Header-Struktur, Version, `network_id`, Epoch, Committee, `vote_mask`, Threshold, Aggregatsignatur prüfen
- Payload **lokal verfügbar** machen (hartes DA-Gate)
- Payload-Hash gegen Header prüfen
- Wenn Payload oder Referenzen fehlen: **kein Vote, kein Finality-Event**

### Schritt 2: Vollprüfung / Deterministische Vor-Ausführung

- `validate_payload_sanity_v3(...)` prüfen
- Double-Spends und Balances prüfen
- Mint-/Slash-/Payout-/Role-Policy-/Maturity-Regeln prüfen
- Vollständige State-/Ökonomie-Validierung auf Overlay-State ausführen
- Ergebnis als kanonische Vor-Ausführung festhalten
- Wenn irgendein konsensrelevanter Check fehlschlägt: **kein Vote** — nicht „später skippen und trotzdem finalisieren", sofern das Protokoll keine explizit kanonische Skip-Semantik committet

### Schritt 3: Vote / Attestation

- Lokale Stimme erst **nach** bestandenem Pre-Check und bestandener Vollprüfung erzeugen
- Attestiertes Objekt muss exakt das widerspiegeln, was lokal validiert wurde
- Falls tolerante Payload-Semantik bestehen bleibt: kanonisches Ausführungsergebnis mitattestieren

### Schritt 4: Finalisierung / Commit

- Erst nach Quorum über dem vollständig validierten Objekt
- Erst dann:
  - `anchor_index` erhöhen
  - `last_final_payload_root` persistieren
  - `applied_final_roots` aktualisieren
  - Mempool/Evidence-Pool bereinigen

### Konkrete Umbauschritte

1. **`verify_header_finality(...)` auf reine Admission-/Authentizitätsprüfung begrenzen.** Keine direkte Einspeisung in den finalen Apply-Pfad.
2. **Hartes DA-Gating in den produktiven `phantom-node`-Pfad ziehen.** Ohne lokal verfügbaren und hash-validierten Payload kein Übergang in Vote/Finality.
3. **Deterministische Vor-Ausführungsfunktion extrahieren**, die dieselben Regeln wie der spätere Commit-Pfad benutzt.
4. **`tx_final_cons.send(meta)` erst nach erfolgreicher Vor-Ausführung und expliziter Freigabe auslösen.**
5. **Entscheidung zur Payload-Semantik treffen:**
   - strict atomic: jede ungültige `micro_tx` verwirft den Payload
   - canonical tolerant: Skip-Ergebnis wird vor Vote kanonisch festgelegt und mitattestiert
6. **Aktiven lokalen Signier-/Vote-Erzeugungspfad gesondert auf dieselbe Invariante umstellen.**

### Verifikation nach dem Umbau

- Fehlender Payload trotz formal gültigem Header erzeugt kein Finality-Event.
- Ungültiger Mint, Slash oder Payout erzeugt kein Finality-Event.
- Restart- und Retry-Pfade persistieren `last_final_payload_root` nur nach erfolgreichem Commit.
- Gemischte Nodes mit spät eintreffenden Payloads divergieren nicht zwischen Finalität und Ausführung.
