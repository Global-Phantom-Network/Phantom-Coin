# Phantom-Coin: Slashing-Spezifikation (v0)

Ziel: Deterministische, uhrfreie Slashing-Regeln, die 100% der Slashing-Einnahmen an alle eligible Seats ausschütten (kein Burn), mit Merkle-Claim. Kategorien gemäß Festlegung v0:
- Equivocation: 100% des Bonds
- Vote-for-invalid: 50% → 100%
- Conflicting-DA: 25% / 50% / 100%

## Evidence-Typen (pc-types)
- `EvidenceKind::Equivocation { seat_id, epoch_id, a, b }`
- `EvidenceKind::VoteInvalid { seat_id, anchor, reason_code }`
- `EvidenceKind::ConflictingDAAttest { seat_id, anchor_id, attest_a, attest_b }`

## Konstanten (pc-consensus/src/consts.rs) ✅
- `SLASH_EQUIVOCATION_BP = 10_000` (100%)
- `SLASH_VOTE_INVALID_MIN_BP = 5_000` (50%), `SLASH_VOTE_INVALID_MAX_BP = 10_000` (100%)
- `SLASH_DA_25_BP = 2_500` (25%), `SLASH_DA_50_BP = 5_000` (50%), `SLASH_DA_100_BP = 10_000` (100%)

## Parameter und Funktion (pc-consensus) ✅
- `SlashingParams { equivocation_bp, vote_invalid_bp, conflicting_da_bp }`
  - `validate()` prüft: Equivocation=100%, Vote-invalid ∈ [50%,100%], Conflicting-DA ∈ {25%,50%,100%}.
  - `recommended_strict()` - Equivocation=100%, Vote-invalid=100%, DA=100%
  - `recommended_moderate()` - Equivocation=100%, Vote-invalid=50%, DA=25%
  - `recommended_equivocation()` - Equivocation-fokussierte Parametrierung
  - `recommended_vote_invalid(bp)` - Custom Vote-invalid BP (validiert 50%..100%)
  - `recommended_conflicting_da(bp)` - Custom Conflicting-DA BP (validiert 25/50/100%)
- `compute_slashing_payout_for_evidence(slashed_bond, params, recipients, evidence) -> Result<PayoutSet, ConsensusError>` ✅
  - `slashed_bond`: Bond-Betrag des Täters (u64)
  - `recipients`: payout_id der k Seats (alle seats des Shards, inkl. Täter)
  - `evidence`: eine der Evidence-Kategorien (EvidenceKind)
  - Ermittelt Täter (`seat_id`) aus Evidence, bestimmt Prozentsatz (BP) aus `params`.
  - Berechnet Topf: `floor(slashed_bond * bp / 10_000)` via `split_bp()`.
  - Verteilt deterministisch gleichmäßig auf alle eligible Seats außer Täter (sortiert nach recipient_id aufsteigend).
  - Remainder-Verteilung deterministisch via `distribute_equal()`.
  - Ergibt `PayoutSet`, dessen Merkle-Root via `payout_root()` in den Anchor-Payload-Root eingeht.

## Invarianten/Tests ✅
- ✅ `slashing_equivocation_100pct`: Equivocation 100%, Summe == `slashed_bond`, Täter ausgeschlossen
- ✅ `slashing_vote_invalid_50pct`: Vote-invalid 50%, Summe == `slashed_bond / 2`
- ✅ `slashing_vote_invalid_100pct`: Vote-invalid 100%, Summe == `slashed_bond`
- ✅ `slashing_conflicting_da_25pct`: Conflicting-DA 25%, Summe == `floor(slashed_bond * 0.25)`
- ✅ `slashing_conflicting_da_50_and_100pct`: Conflicting-DA 50% und 100% Varianten
- ✅ `slashing_params_validation`: Parameter-Validierung (ungültige BP-Werte schlagen fehl)
- ✅ `slashing_payout_deterministic`: Gleiche Inputs → gleiche Outputs, sortiert
- ✅ `slashing_excludes_slasher_always`: Täter in allen Evidence-Kategorien ausgeschlossen
- Verteilung deterministisch, unabhängig von Eingabereihenfolge; Täter immer ausgeschlossen.

## Hinweise
- Ausschüttung an alle eligible Seats (kein Burn), in Einklang mit v0-Festlegung.
- Uhrfrei; keine Unix-Zeit im Konsenspfad. Alle Berechnungen sind deterministisch aus Inputs und BP.
- Die konkrete Einbettung in den Payout-Flow (zusammen mit Gebühren) erfolgt über `PayoutSet`/Merkle-Root und ist kompatibel zu den bestehenden Fee-Split-Mechanismen.
