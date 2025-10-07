# PHANTOMCOIN_TODO_PLAN.md
Version: v0.1
Erstellt am: 2025-09-26

## Kontext (fixe Rahmenbedingungen)
- L1: reines UTXO (eUTXO-Predicates v0), PoW nur für Emission (keine Order-Macht).
- Hardcap: 50.000.000 PC. Teilbarkeit: 1 PC = 100.000.000 Einheiten.
- Konsens: leaderloser DAG + aBFT, O(1)-Finalität via u64 vote_mask; Total-Order = (consensus_time aus DAG, dann event_id).
- Zeitregel: keinerlei Unix-Zeit im Konsens-/Protokollpfad (nur DAG-logische Größen).
- Sharding: Start S≈64, Committee je Shard k≈21 (k≤64), Parents P≤4, mind. 1 Cross-Link ab k≥2.
- Maturity (Mint): Stufenmodell (50k/100k/200k finalisierte Anker, globaler Index), beim Mint fixiert; Bond-Lock aus unreifen Mints erlaubt.
- Slashing: Sicherheitsvergehen (insb. Equivocation) 100% Bond; Vote-for-invalid 50%→100%; Conflicting-DA 25%/50%/100%. 100% Ausschüttung an alle eligible Seats via Merkle-Claim (kein Burn).
- Fees: Sender zahlt; Verteilung per Merkle-Payout-Root. Modell: Floor (Basis) + kleiner Proposer-Anteil + gedeckelter Performance-Bonus (Ack-Distanz) + Attestor-Topf (aggregierte DA-Atteste).
- Rollen/Binaries: `phantom-node` (Fullnode/Validator), `phantom-miner` (Worker via RPC), `phantom-signer` (HW/HSM).  
- Genesis: A0 mit genesis_note Hash-Commitment; k=1 Bootstrap-Ausnahmen.


## Meilensteine (High-Level)

| MS | Titel | Inhalt (Tasks) | Deliverable | Akzeptanzkriterien | ETA |
|---|---|---|---|---|---|
| M1 | Protokoll-Spez final | t1,t2,t3,t4,t5,t6,t7,t11,t12,t13,t14 | Spez v1.0 | alle Konstanten/Regeln vollständig & konsistent | 1–2 Wochen |
| M2 | Node Core & Codec | t6,t8,t14,t15 (t15 completed) | lauffähiger Fullnode‑Core | deterministische IDs/Apply; DA pull‑then‑vote | 2–3 Wochen |
| M3 | Wallet/Signer & Mining | t9,t10,t5 | Node/Signer/Miner + RPC | Mint→Maturity→Spend e2e (Single‑Shard) | 1–2 Wochen |
| M4 | Slashing & Fees e2e | t3,t4 | Evidence/Claim/Payout | Equivocation‑Slash 100% → Merkle‑Payout ok | 1–2 Wochen |
| M5 | Observability & Bench | t16,t17,t18 | Metriken/Tests/Bench | Pi‑5 15–20k/s; i9 40–70k/s je Shard | 1–2 Wochen |
| M6 | Testnet‑0 | t19 | Single‑Shard Netz | stabile Finalität, Slash/Fees/Claims ok | 1 Woche |
| M7 | Testnet‑1 | t19 | S=64, k=21, Attestoren | Cross‑Links stabil, Throughput skaliert | 2–3 Wochen |
| M8 | Release/DevOps | t20 | Repro‑Builds/Runbooks | reproduzierbare Builds, HSM/Upgrades | 1 Woche |
---

## Detaillierte Aufgaben (ToDos)

Status-Legende: in_progress, pending, completed

- t1_consensus_consts — Status: in_progress — Prio: hoch  
  Konsens-Konstanten finalisieren: S=64, k=21 (k≤64), P≤4, B≈256, Fee-Split (p_base/p_prop/p_perf/p_att), Ack‑Bonus‑Parameter (α, D_max), globaler Anchor‑Index.  
  Akzeptanz: Konstantenblatt vollständig, referenziert in Spez.

- t2_maturity_spec — Status: pending — Prio: hoch  
  Maturity (Stufenmodell 50k/100k/200k), globaler Anchor‑Index, Stake‑Maturity/Unbonding (uhrenfrei), Bond-Lock aus unreifen Mints, Aktivierungs‑Puffer.  
  Akzeptanz: formale Funktion, Edge‑Cases (Genesis, leere Anker), Testfälle.

- t3_slashing_spec — Status: pending — Prio: hoch  
  Slashing: Equivocation=100%; Vote‑for‑invalid 50%→100%; Conflicting‑DA 25%/50%/100%; Fenster/Cooldowns uhrenfrei; 100% Ausschüttung an alle eligible Seats via Merkle‑Claim.  
  Akzeptanz: Evidence‑Formate, Prüfpfad, Payout‑Root/Claim, Dedupe.

- t4_fees_spec — Status: pending — Prio: hoch  
  Fee‑Verteilung: Floor (Basis), Proposer, Performance‑Bonus (Ack‑Distanz w=α^(d−1), cap D_max), Attestor‑Topf; Anti‑Spam (1 Ack/Ziel, Anchor‑Kredit, kleine Anchor‑Fee); Payout‑Root/Claim.  
  Akzeptanz: deterministische Formel je Anchor, Merkle‑Root reproduzierbar.

- t5_pow_spec — Status: pending — Prio: hoch  
  PoW/Mint: Algorithmus, Template‑RPCs (`get_mint_template`, `submit_mint_solution`, `mint_status`), prev_mint_id‑Kette, Emissionskurve (Hardcap 50 Mio, Halving/Abnahme uhrenfrei).  
  Akzeptanz: e2e Mining‑Flow (lokal) validierbar.

- t6_bin_codec — Status: pending — Prio: hoch  
  Binärformat/Serialisierung: feste Längen/Varints, Domain‑Separation, BLAKE3‑IDs; Event/Micro‑Event‑Layouts kanonisch.  
  Akzeptanz: Property‑Tests, Round‑Trip, stabile Hashes.

- t7_crypto_choice — Status: pending — Prio: hoch  
  Krypto: Schnorr(secp256k1 BIP‑340), MuSig2 (Multisig‑Aggregation); Attest‑Aggregation (BLS12‑381 vs. MuSig2‑Aggregation) Entscheidung + Sicherheitsanalyse.  
  Akzeptanz: Auswahl begründet, Bench‑Zahlen, Implementierungsplan.

- t8_p2p_net — Status: pending — Prio: hoch  
  P2P: libp2p Gossipsub pro Shard; Inventory→Pull; Dedupe/Backpressure; Noise/TLS; Anti‑Entropy.  
  Akzeptanz: Lasttest P50/P95 stabil, kein Flood/Amplification.

- t9_node_arch — Status: pending — Prio: hoch  
  Binaries/Prozessflüsse/CLI: `phantom-node`, `phantom-miner`, `phantom-signer`; Flags/Endpoints; Key‑Trennung (seat/bond/payout).  
  Akzeptanz: Start‑Szenarien (Bootstrap/Validator/Miner) dokumentiert.

- t10_wallet_spec — Status: pending — Prio: mittel  
  Wallet/Signer: Bech32m (HRP „pc“), PSPT‑ähnliche Flows, Stealth/Silent‑Payments, PayJoin‑Default, deterministische Output‑Sortierung.  
  Akzeptanz: End‑to‑End Signier-/Receive‑Flows spezifiziert.
- t11_genesis_spec — Status: pending — Prio: hoch  
  Genesis: A0, genesis_note Hash‑Commitment, Seed/Netz‑ID, k=1‑Bootstrap (Cross‑Link‑Pflicht ausgesetzt), Regeln für leere Anker.  
  Akzeptanz: Konsistenter Start aller Nodes.

- t12_vrf_rotation — Status: pending — Prio: hoch  
  Committee‑Selektion/Rotation: VRF aus finalisiertem Seed; Anti‑Kollokation (max 1 Seat/Shard/Operator); Eligibility via Heartbeat; Attendance/Cooldown.

- t13_attestor_pools — Status: pending — Prio: hoch  
  Attestor‑Pools: VRF‑Sampling (M≈128), Signatur‑Aggregation, optional Performance‑Index (PI) mit Caps; Claim‑Pfad.  
  Akzeptanz: Aggregat‑Signaturen verifizierbar, gerechte Verteilung.

- t14_da_gating — Status: completed — Prio: hoch  
  DA‑Gating: strikt pull‑then‑vote; kein Vote/Ack ohne lokale Daten; Schnittstellen zu Storage/Fetcher.  
  Akzeptanz: Tests für Nichtlieferung/Spätlieferung bestehen.

- t15_utxo_state — Status: completed — Prio: hoch  
  UTXO/State‑Engine: RocksDB/NVMe, deterministische Apply‑Pipeline, Merkle‑Roots, Pruning/Snapshots.  
  Akzeptanz: deterministisches Apply; Snapshot/Restore erfolgreich.
  Done-Notiz: Implementierung in [crates/pc-state/src/lib.rs](../crates/pc-state/src/lib.rs) (InMemory/RocksDB-Backends, `apply_*`, Maturity/Stake), deterministischer `root()`, `snapshot_to_*`/`restore_from_*`; CI prüft RocksDB-Feature in [.github/workflows/ci.yml](../.github/workflows/ci.yml); relevante Tests: `rocksdb_snapshot_roundtrip`, `rocksdb_state_root_changes`.

- t16_observability — Status: pending — Prio: mittel  
  Observability: Metriken (EPS, P50/P95 Finalität, Queue‑Tiefen, Verify‑CPU), strukturierte Logs, Profiling‑Hooks.  
  Akzeptanz: Dashboards/Alerts; Engpässe sichtbar.

- t17_testing — Status: pending — Prio: hoch  
  Teststrategie: Property/Fuzz (Codec/UTXO/Merkle), Konsenstests (Equivocation/Vote‑invalid), Netz‑Sims (Loss/Delay).  
{{ ... }}

- t18_benchmarks — Status: pending — Prio: hoch  
  Benchmarks: Pi‑5 Baseline & i9 Skalierung je Shard; Zielwerte 15–20k/s vs. 40–70k/s; P50/P95 im Ziel.  
  Akzeptanz: Reports mit Parametern, Abweichungen analysiert.

- t19_testnets — Status: pending — Prio: hoch  
  Testnet‑0 (Single‑Shard, k klein) → Testnet‑1 (S=64, k=21, Attestoren an); Monitoring/Runbooks.  
  Akzeptanz: stabile Finalität; Slash/Fees/Claims on‑chain geprüft.

- t20_devops_release — Status: pending — Prio: mittel  
  DevOps/Release: Repro‑Builds, Container/Packages, HSM‑Flows, Upgrade an Epoche, Notfall‑Prozeduren.  
  Akzeptanz: reproduzierbare Artefakte; dokumentierte Upgrades/Recoveries.

- t21_error_policy — Status: completed — Prio: hoch  
  Rust Error Policy: `docs/RUST_ERROR_POLICY.md` (Clippy‑Lints `unwrap_used`/`expect_used` verboten, `panic = "abort"`, konsistente Codebeispiele).  
  Akzeptanz: Datei existiert; Beispiele korrigiert/kompilierbar; Richtlinie verbindlich.

---

## Risiken & Gegenmaßnahmen (kompakt)
- DA‑Gating/Netz: heikler Pfad → strikte Pull‑then‑Vote‑Durchsetzung; Attest‑Aggregation.
- Signatur‑Verify: CPU‑Hotspot → Batch‑Verify, AVX2/BMI2; 1 Sig/Mikro‑Event.
- Fee‑Bonus (Zentralisierung): p_perf ≤ 20%, α≈0,6–0,7, Caps (Ack‑Limits, D_max).
- Ökonomische Sybil: Bond pro Seat (linear), Anti‑Kollokation, Rotation; vollständig ausschließen nicht möglich.
- Keine Unix‑Zeit: alle Fenster in finalisierten Ankern definieren (Maturity, Slash‑Window, Cooldown, Claim‑Verfall).

---

## Tuning‑Guidelines: Node‑Cache & Store‑I/O

- Ziel: Disk‑I/O minimieren und Latenzen senken, insbesondere auf Raspberry Pi 5.

- Konfiguration
  - `[node.cache] header_cap`, `payload_cap` (0=aus). CLI‑Override via `--cache_hdr_cap/--cache_pl_cap`.
  - Sharded LRU: Anzahl Shards ≈ CPU‑Kerne (auto, via `num_cpus`). Reduziert Mutex‑Contention.

- Startwerte (RPi5 Empfehlung)
  - `header_cap ≈ 10_000`
  - `payload_cap ≈ 2_000 .. 5_000`

- Messung
  - Prometheus: `pc_node_cache_*` (Hits/Misses), `pc_node_store_*_read_seconds` (Histogramme Header/Payload).
  - CLI‑Benchmark: `phantom-node CacheBench` (siehe README), z. B.:
    ```bash
    phantom-node CacheBench \
      --store_dir pc-data \
      --mode headers \
      --sample 1000 \
      --iterations 5 \
      --cache_hdr_cap 10000 \
      --cache_pl_cap 0
    ```

- Vorgehen
  1. Mit konservativen Kapazitäten starten, Warmup abwarten.
  2. CacheBench + Metriken beobachten: Miss‑Rate sollte deutlich sinken; Histogramme sollten nach kurzer Zeit <5–10ms dominieren.
  3. Kapazitäten schrittweise erhöhen, bis RAM‑Budget erreicht bzw. Miss‑Rate asymptotisch niedrig.
  4. Bei starker Parallelität: Sharding ist aktiv; bei weiterem Bedarf Kapazität pro Shard anheben (gesamt `*_cap`).

- Trade‑offs
  - Mehr RAM ↔ weniger Disk‑I/O. Payload‑Objekte sind größer als Header; stärkerer RAM‑Impact.
  - Zu kleine Caches führen zu Thrash (viele Misses) → zunächst Header‑Cache erhöhen, dann Payload‑Cache.
