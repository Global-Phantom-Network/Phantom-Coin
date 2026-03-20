# Phantom-Coin: Maturity (uhrfrei)

Ziel: uhrfreie Reifegrade (Maturity) für Mint-UTXOs und Stake-Flows ausschließlich über den globalen, monotonen Anchor-Index. Keine Unix-Zeit im Konsens-/Protokollpfad.

## Definitionen
- Globaler Anchor-Index: `AnchorIndex = u64` (monoton, global; keine Zeitabhängigkeit)
- Maturity-Stufen (Konstanten, siehe `pc-consensus/src/consts.rs`):
  - L1 = 50.000 Anker
  - L2 = 100.000 Anker
  - L3 = 200.000 Anker
- Beim Mint wird der AnchorIndex als `minted_at`-Index im UTXO‑State fixiert (globaler Index des finalisierten Mints).
- Im `MintEvent` bleibt `minted_at` uhrfrei (0); die Reifegrade nutzen den UTXO‑Index.

## Regeln (v0)
- Spend/Stake/Unbonding sind an Reifegrade relativ zu `minted_at` gebunden:
  - Beispiel: ein Stake ist erst zulässig, wenn `maturity_level(current, minted_at) ≥ 1` (≥L1).
  - Unbonding ggf. erst ab `≥L2` oder `≥L3` (netzspezifisch; per Parametrisierung/Policy).
- Bond-Lock aus unreifen Mints ist erlaubt (Funds gebunden, aber Nutzung erst nach erreichter Maturity).
- Maturity ist deterministisch, uhrfrei: `current_index - minted_at >= threshold`.

## API (Hilfsfunktionen)
Implementiert in `pc-consensus/src/lib.rs`:
- `maturity_reached(current: AnchorIndex, minted_at: AnchorIndex, threshold: u64) -> bool`
- `maturity_level(current: AnchorIndex, minted_at: AnchorIndex) -> u8` (0..=3, relativ zu L1/L2/L3)
- `validate_stake_maturity(current: AnchorIndex, minted_at: AnchorIndex) -> Result<(), ConsensusError>` (erfordert L1)
- `validate_unbond_maturity(current: AnchorIndex, bonded_at: AnchorIndex) -> Result<(), ConsensusError>` (erfordert L2)
- `validate_bond_lock_maturity(current: AnchorIndex, minted_at: AnchorIndex) -> Result<(), ConsensusError>` (erfordert L1)

## Validierung & Tests
- Unit-Tests prüfen Schwellenwerte und Level-Inkremente:
  - `maturity_thresholds_boundaries` - Threshold-Grenzen
  - `maturity_level_increments` - Level-Übergänge  
  - `stake_maturity_validation` - Stake-Validierung (L1-Anforderung)
  - `unbond_maturity_validation` - Unbond-Validierung (L2-Anforderung)
  - `bond_lock_maturity_validation` - Bond-Lock-Validierung (L1-Anforderung)
- Keine Unix-Zeit, ausschließlich Index-Differenzen.
- Maturity nutzt den `minted_at`‑Index aus dem UTXO‑State (AnchorIndex).

## Konfiguration/Parametrisierung
- Netzweite Policies (welche Stufe für Stake/Unbond/Spend nötig ist) können in Zukunft per Genesis/Config vorgegeben werden.
- Die Konstanten L1/L2/L3 liegen in `pc-consensus/src/consts.rs` und können in einer künftigen Hardfork angepasst werden.
