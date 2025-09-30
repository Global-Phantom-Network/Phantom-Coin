# Phantom-Coin: Slashing-Spezifikation (v0)

Ziel: Deterministische, uhrfreie Slashing-Regeln, die 100% der Slashing-Einnahmen an alle eligible Seats ausschütten (kein Burn), mit Merkle-Claim. Kategorien gemäß Festlegung v0:
- Equivocation: 100% des Bonds
- Vote-for-invalid: 50% → 100%
- Conflicting-DA: 25% / 50% / 100%

## Evidence-Typen (pc-types)
- `EvidenceKind::Equivocation { seat_id, epoch_id, a, b }`
- `EvidenceKind::VoteInvalid { seat_id, anchor, reason_code }`
- `EvidenceKind::ConflictingDAAttest { seat_id, anchor_id, attest_a, attest_b }`

## Konstanten (pc-consensus/src/consts.rs)
- `SLASH_EQUIVOCATION_BP = 10_000` (100%)
- `SLASH_VOTE_INVALID_MIN_BP = 5_000` (50%), `SLASH_VOTE_INVALID_MAX_BP = 10_000` (100%)
- `SLASH_DA_25_BP = 2_500` (25%), `SLASH_DA_50_BP = 5_000` (50%), `SLASH_DA_100_BP = 10_000` (100%)

## Parameter und Funktion (pc-consensus)
- `SlashingParams { equivocation_bp, vote_invalid_bp, conflicting_da_bp }`
  - `validate()` prüft: Equivocation=100%, Vote-invalid ∈ [50%,100%], Conflicting-DA ∈ {25%,50%,100%}.
  - `recommended_*` Helfer erzeugen valide Parametrierungen.
- `compute_slashing_payout_for_evidence(slashed_bond, params, recipients, evidence) -> PayoutSet`
  - `slashed_bond`: Bond-Betrag des Täters (u64)
  - `recipients`: payout_id der k Seats (alle seats des Shards)
  - `evidence`: eine der Evidence-Kategorien
  - Ermittelt Täter (`seat_id`) aus Evidence, bestimmt Prozentsatz (BP) aus `params`.
  - Berechnet Topf: `floor(slashed_bond * bp / 10_000)`.
  - Verteilt deterministisch gleichmäßig auf alle eligible Seats außer Täter. Remainder-Verteilung deterministisch (sortiert nach recipient_id aufsteigend).
  - Ergibt `PayoutSet`, dessen Merkle-Root in den Anchor-Payload-Root eingeht (via `pc-types::digest_payout_root`).

## Invarianten/Tests
- Equivocation 100%: Summe der Auszahlungen == `slashed_bond`; Täter ist nicht begünstigt.
- Vote-invalid 50%: Summe == `slashed_bond / 2` (bei 5_000 BP); Bereich 5_000..10_000 BP zulässig.
- Conflicting-DA 25%: Summe == `floor(slashed_bond * 0.25)`; alternativ 50%/100% via Params.
- Verteilung deterministisch, unabhängig von Eingabereihenfolge; Täter ausgeschlossen.

## Hinweise
- Ausschüttung an alle eligible Seats (kein Burn), in Einklang mit v0-Festlegung.
- Uhrfrei; keine Unix-Zeit im Konsenspfad. Alle Berechnungen sind deterministisch aus Inputs und BP.
- Die konkrete Einbettung in den Payout-Flow (zusammen mit Gebühren) erfolgt über `PayoutSet`/Merkle-Root und ist kompatibel zu den bestehenden Fee-Split-Mechanismen.
