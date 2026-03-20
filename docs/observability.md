# Observability and Operations for `phantom-node`

Dieses Dokument ist die kanonische Operator-Dokumentation fuer Status-Endpunkte, Metriken,
Persistenzpfade und die Beobachtung des aktiven Emissionspfads.

## 1. Betriebsmodell

Ein laufender Node besteht operativ aus mindestens zwei HTTP-Sichten:

- Status-Server:
  - `/status`
  - `/healthz`
  - `/readyz`
  - `/metrics`
  - `/mint/template`
  - `/mint/status`
  - `/mint/status/<hex_id>`
  - Verwaltungs- und Konsensendpunkte
- optionaler P2P-Metrikserver:
  - `/metrics` fuer P2P- und Persistenzsignale

## 2. Typische Startkommandos

### 2.1 Status-Server

```bash
PHANTOM_STATUS_AUTH_TOKEN="$(openssl rand -hex 16)" \
cargo run -p phantom-node --bin phantom-node -- \
  status-serve \
  --addr 127.0.0.1:8080 \
  --store-dir /var/lib/phantom-coin/data \
  --mempool-dir /var/lib/phantom-coin/data/mempool \
  --fsync
```

### 2.2 QUIC + P2P-Metriken

```bash
cargo run -p phantom-node --bin phantom-node -- \
  p2p-quic-listen \
  --addr 127.0.0.1:9001 \
  --metrics-addr 127.0.0.1:9101 \
  --store-dir /var/lib/phantom-coin/data \
  --fsync
```

## 3. Security-Defaults

### 3.1 Auth

Wenn `--require-auth` aktiv ist, brauchen geschuetzte Endpunkte:

```text
Authorization: Bearer <TOKEN>
```

### 3.2 TLS und mTLS

Optional:

- `--tls-cert`
- `--tls-key`
- `--tls-client-ca`

Empfohlener Produktionspfad:

- `phantom-node` nur an Loopback oder internes Netz binden,
- externen Zugriff via Reverse Proxy, VPN oder internes LB fuehren,
- Bearer-Auth trotzdem aktiv lassen.

### 3.3 Body-Limits

Der HTTP-Server begrenzt Bodies via `MAX_HTTP_BODY_BYTES`.
Das ist besonders fuer `/mint/submit` relevant.

## 4. Endpoint-Semantik

### 4.1 Status und Readiness

| Endpunkt | Zweck |
|---|---|
| `GET /status` | Basisstatus des Dienstes und Netzkontext |
| `GET /healthz` | Liveness |
| `GET /readyz` | lokale Betriebsbereitschaft, insbesondere Erreichbarkeit von `mempool_dir` |
| `GET /metrics` | Prometheus-Textformat |

### 4.2 Emissionsendpunkte

| Endpunkt | Zweck |
|---|---|
| `GET /mint/template` | Miner-Template der offenen Runde |
| `GET /mint/status` | Operator-Sicht auf offene Runde und Difficulty-Kontext |
| `GET /mint/status/<hex_id>` | lokale Existenz eines konkreten Mint-Files |
| `POST /mint/submit` | Kandidat einreichen |

### 4.3 Entfernte Altpfade

Der fruehere direkte State-Mutationspfad fuer Mints ist entfernt.
Mints muessen ueber Emissionsrunden in den Graph finalisieren.

## 5. Persistenzlayout

Wichtige Pfade unterhalb von `store_dir` bzw. `mempool_dir`:

| Pfad | Bedeutung |
|---|---|
| `headers/` | persistierte Graph-Header |
| `payload_segments/` | segmentierter persistenter Payload-Store |
| `payloads/.latest` | Root des zuletzt vorgeschlagenen Payloads |
| `last_final_payload_root` | Root des zuletzt finalisierten Payloads |
| `mempool/supply_state.json` | finaler Emissionszustand |
| `mempool/mint_round_state.json` | lokaler Zustand der offenen Emissionsrunde |
| `mempool/mints/*.bin` | lokal persistierte Mint-Kandidaten |
| `mempool/mint_seeds/*` | Seed-Reservierungsmarker gegen Replay/Duplikate |
| `mempool/evidences/` | Evidence-Files |

### 5.1 Wichtige Unterscheidung: `.latest` vs. `last_final_payload_root`

Diese beiden Dateien sind nicht dasselbe:

- `payloads/.latest` zeigt den zuletzt vorgeschlagenen Payload-Root.
- `last_final_payload_root` zeigt den zuletzt finalisierten Payload-Root.

Ein Dashboard, das nur `.latest` zeigt, kann deshalb einen leeren oder neueren Payload anzeigen,
obwohl der zuletzt finalisierte Payload ein Mint oder ein anderer Inhalt war.

## 6. Emissionsrunden beobachten

### 6.1 `GET /mint/status`

Die wichtigste Operator-Sicht fuer Emission ist:

```bash
curl -sS http://127.0.0.1:8080/mint/status \
  -H "Authorization: Bearer $PHANTOM_STATUS_AUTH_TOKEN" | jq
```

Relevante Felder:

- `phase`
- `round_id`
- `target_bits`
- `last_final_emission_bucket`
- `hit_bucket`
- `bits_used`
- `collect_deadline_bucket`
- `finalize_deadline_bucket`

### 6.2 Interpretation der Phase

`phase = searching`

- kein eingefrorener Treffer,
- `target_bits` ist der aktuelle Bucket-Wert,
- Difficulty kann weiter mit der Zeit wandern.

`phase = collecting`

- erster Treffer wurde akzeptiert,
- `hit_bucket` und `bits_used` sind eingefroren,
- der Proposer darf erst ab `collect_deadline_bucket` final aufnehmen,
- nach `finalize_deadline_bucket` wird die Runde verworfen.

### 6.3 Praktische Operator-Fragen

Wenn du verstehen willst, warum kein Mint finalisiert:

1. `GET /mint/status`
2. Pruefen:
   - `can_mint`
   - `phase`
   - `target_bits`
   - `hit_bucket`
   - `finalize_deadline_bucket`
3. `mempool/mints/` auf lokale Kandidaten pruefen
4. `last_final_payload_root` und `payloads/.latest` getrennt ansehen
5. Finality- und Candidate-Metriken gegenlesen

## 7. Finalitaet beobachten

### 7.1 Kernmetriken

| Metrik | Typ | Bedeutung |
|---|---|---|
| `pc_node_finality_seconds` | Histogramm | End-to-end-Finalitaetslatenz |
| `pc_node_finality_events_total` | Counter | Anzahl finalisierter Payload-Ereignisse |
| `pc_node_finality_mint_events_total` | Counter | Anzahl finalisierter Payload-Ereignisse mit mindestens einem Mint |

Wichtig:

- `pc_node_finality_events_total` zaehlt alle finalen Payloads.
- `pc_node_finality_mint_events_total` zaehlt nur jene Finalisierungen, die einen Mint enthalten.
- Ein hoher Abstand zwischen beiden Werten ist normal, wenn viele tx-only Payloads finalisiert werden.

### 7.2 PromQL-Beispiele

```promql
histogram_quantile(0.50, sum by (le) (rate(pc_node_finality_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le) (rate(pc_node_finality_seconds_bucket[5m])))
histogram_quantile(0.99, sum by (le) (rate(pc_node_finality_seconds_bucket[5m])))
rate(pc_node_finality_events_total[5m])
rate(pc_node_finality_mint_events_total[5m])
```

## 8. Verify beobachten

### 8.1 Kernmetriken

| Metrik | Typ | Bedeutung |
|---|---|---|
| `pc_node_verify_seconds` | Histogramm | BLS fast aggregate verify Latenz |

PromQL:

```promql
histogram_quantile(0.50, sum by (le) (rate(pc_node_verify_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le) (rate(pc_node_verify_seconds_bucket[5m])))
histogram_quantile(0.99, sum by (le) (rate(pc_node_verify_seconds_bucket[5m])))
rate(pc_node_verify_seconds_count[5m])
```

Wenn ein UI keine Verify-Heatmap zeigt, aber `pc_node_verify_seconds_count` steigt,
liegt das Problem im UI oder in der Visualisierung, nicht automatisch im Verify-Pfad.

## 9. Candidate- und Mining-Metriken

### 9.1 Aktive Kennzahlen

| Metrik | Typ | Bedeutung |
|---|---|---|
| `pc_node_pow_candidate_active_work_slots` | Gauge | aktuell verfolgte Candidate-Slots |
| `pc_node_pow_candidate_queued_total` | Counter | insgesamt eingeordnete Candidate-Ereignisse |
| `pc_node_pow_candidate_replaced_total` | Counter | besserer Kandidat hat frueheren lokalen Bestkandidaten ersetzt |
| `pc_node_pow_candidate_skipped_not_better_total` | Counter | Kandidat war schlechter als der aktuelle Bestkandidat |
| `pc_node_pow_candidate_scope_resets_total` | Counter | Candidate-Scope wurde wegen Kontextwechsel zurueckgesetzt |

### 9.2 Wichtige Operator-Falle

Die Counter mit `_total` sind kumulativ seit Prozessstart.
Sie sind KEINE aktuellen Queue-Laengen.

Beispiel:

- `pc_node_pow_candidate_queued_total = 48`

bedeutet:

- seit Start wurden 48 Kandidaten aufgenommen,
- NICHT, dass gerade 48 Kandidaten in einer aktuellen Warteschlange liegen.

### 9.3 Interpretation

- hohe `replaced_total`: Konkurrenz innerhalb derselben Runde, lokal bessere Kandidaten sind angekommen
- hohe `skipped_not_better_total`: viele Kandidaten waren schlechter als der aktuelle Bestkandidat
- hohe `scope_resets_total`: der gueltige Mining-Kontext hat sich geaendert

## 10. AnchorGraph- und Persistenzmetriken

### 10.1 Graph

| Metrik | Typ | Bedeutung |
|---|---|---|
| `pc_node_anchor_graph_headers` | Gauge | Header im In-Memory-AnchorGraph |
| `pc_node_anchor_graph_orphans` | Gauge | derzeitige Orphans |
| `pc_node_anchor_graph_evict_total` | Counter | Evictions wegen Kapazitaetsgrenzen |

### 10.2 Persistenz

| Metrik | Typ | Bedeutung |
|---|---|---|
| `pc_node_persist_headers_total` | Counter | persistierte Header |
| `pc_node_persist_headers_errors_total` | Counter | Persistenzfehler fuer Header |
| `pc_node_persist_payloads_total` | Counter | persistierte Payloads |
| `pc_node_persist_payloads_errors_total` | Counter | Persistenzfehler fuer Payloads |

Hinweis:

Im aktuellen Layout kommt Speicherwachstum oft eher von vielen kleinen Header-Dateien als von
grossen Payload-Segmenten.

## 11. P2P-Metriken

Typische P2P-Signale:

- `pc_p2p_inbound_total`
- `pc_p2p_outbound_total`
- `pc_p2p_inbound_dropped_rate`
- `pc_p2p_peer_rl_purged_total`

Operator-Hinweis:

- `outbound_total` ist ein Sendepfad-Zaehler.
- Er ist kein harter Beweis dafuer, dass echte Gegenstellen Daten erfolgreich verarbeitet haben.
- In Solo- oder Bootstrap-Betrieb kann `inbound_total` daher plausibel `0` bleiben.

## 12. E2E-Checks fuer Emission

### 12.1 Aktuelle offene Runde sehen

```bash
curl -sS http://127.0.0.1:8080/mint/template \
  -H "Authorization: Bearer $PHANTOM_STATUS_AUTH_TOKEN" \
  | jq '{prev_mint_id, round_id, target_bits, phase, hit_bucket, bits_used}'
```

### 12.2 Vollen Status sehen

```bash
curl -sS http://127.0.0.1:8080/mint/status \
  -H "Authorization: Bearer $PHANTOM_STATUS_AUTH_TOKEN" | jq
```

### 12.3 Letzten finalen Payload getrennt vom letzten Vorschlag pruefen

```bash
cat /var/lib/phantom-coin/data/last_final_payload_root
cat /var/lib/phantom-coin/data/payloads/.latest
```

## 13. Kanonischer Reset

Der kanonische Reset bereinigt unter anderem:

- `headers/`
- `payload_segments/`
- `last_final_payload_root`
- `mempool/mint_round_state.json`

Damit darf alter Emissions- oder Payload-Zustand nach Reset nicht wieder rehydriert werden.

## 14. Troubleshooting

### 14.1 `finality_events_total` hoch, `finality_mint_events_total` niedrig

Bedeutung:

- der Graph finalisiert Payloads,
- aber nur wenige davon enthalten Mints.

Das ist moeglich und kein Beweis fuer kaputte Finalitaet.

### 14.2 `phase = collecting`, aber kein Mint wird final

Pruefen:

- ist `current_bucket` schon hinter `collect_deadline_bucket`?
- ist `finalize_deadline_bucket` schon abgelaufen?
- liegt ein besserer Kandidat lokal vor?
- sieht der Proposer den lokalen Bestkandidaten in `mempool/mints/`?

### 14.3 Dashboard zeigt leeren Payload trotz finalisiertem Mint

Pruefen:

- liest das Dashboard `payloads/.latest` oder `last_final_payload_root`?

Nur der zweite Wert beschreibt den letzten finalisierten Payload.

### 14.4 `queued_total` oder `skipped_not_better_total` wirken astronomisch

Das sind kumulative Counter seit Start, keine Momentaufnahme einer aktuellen Queue.

## 15. Profiling

### 15.1 Tokio Console

- Build mit `--features console`
- Aktivierung via `PHANTOM_CONSOLE=1`

### 15.2 pprof

- Build mit `--features pprof`
- Endpoint:

```text
GET /debug/pprof/profile?seconds=10
```

## 16. Operator-Zusammenfassung

Wenn du nur drei Dinge fuer den Emissionspfad beobachten willst, dann diese:

1. `GET /mint/status`
2. `pc_node_finality_events_total` plus `pc_node_finality_mint_events_total`
3. `last_final_payload_root` getrennt von `payloads/.latest`
