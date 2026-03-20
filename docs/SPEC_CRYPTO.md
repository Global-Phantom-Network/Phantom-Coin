# Phantom-Coin: Krypto-Entscheidung (v1)

Ziel: Klare, praxisnahe Auswahl der Signaturverfahren pro Pfad mit Fokus auf:
- Hardware-Wallet-Kompatibilität
- Verifikations-/Bandbreitenkosten
- Aggregationsfähigkeit (Attestoren)

## Entscheidungen
- MicroTx-User-Signaturen: Schnorr (secp256k1, BIP340-kompatibel, x-only 32B)
  - Gründe: breite Tool-/HWI-Verfügbarkeit (z. B. BitBox02), kompakte 64B Signaturen, etablierte Sicherheit.
  - Adressen: Bech32m (HRP "pc"), Programm = x-only 32B (Version 1). Siehe `docs/wallet-spec.md`.
  - Witness-Layout: `xonly(32) || sig(64)`.
- Attestoren (Committee-/DA-Attests): BLS12-381 (Aggregation)
  - Gründe: Signaturaggregation reduziert Netz-/Speicherlast; deterministische Payout-Berechnung nutzt Empfänger-IDs aus BLS-PKs.
  - Verwendet in `pc-crypto` (BLS Modus) mit Benchmarks.

Alternative: MuSig2 (Schnorr Multi-Key Aggregation)
- Vorteile: ein Kurven-Stack (secp256k1) für alles, Multi-Signaturen möglich.
- Nachteile: Komplexere Interaktion (Rounds), HWI-Support derzeit dünner als BLS, weniger vorteilhaft für große Attestormengen.

## Sicherheits-/Leistungsbewertung
- Schnorr: 64B Signatur, 32B Pubkey (x-only); Verifikation schnell (libsecp256k1), HWI Reife.
- BLS12-381: Aggregation erheblich effizienter bei vielen Attestoren; Einzelverifikation langsamer als Schnorr, aber Aggregation amortisiert.
- Domain-Separation: Alle Hashes/Roots in `pc-types` mit expliziten Domaintags.

## Parameter & Formate
- Schnorr: BIP340 Schemata; Sighash siehe `docs/wallet-spec.md`.
- BLS: Empfänger-ID: `attestor_recipient_id_from_bls(pk)` → 32B ID (für Payouts).

## Implementierungsstand
- `crates/pc-crypto`: Schnorr/BLS Implementierungen, Benches vorhanden (`benches/schnorr_bench.rs`, `benches/bls_bench.rs`).
- `crates/phantom-signer`: HWI- und PSBT-Flows für Schnorr, Broadcast CLI.
- `crates/pc-consensus`: Fee-/Payout-Berechnungen akzeptieren BLS-IDs.

## Fazit
- v1: Schnorr für Endnutzer-Transaktionen, BLS für Attestoren.
- MuSig2 bleibt Option für spätere Version (abhängig von HWI-/Ökosystemreife und Benchmarks).
