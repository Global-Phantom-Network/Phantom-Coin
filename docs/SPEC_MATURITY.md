# Phantom-Coin: Maturity (uhrfrei)

Ziel: uhrfreie Reifegrade (Maturity) für Mint-UTXOs und Stake-Flows ausschließlich über den globalen, monotonen Anchor-Index. Keine Unix-Zeit im Konsens-/Protokollpfad.

## Definitionen
- Globaler Anchor-Index: `AnchorIndex = u64` (monoton, global; keine Zeitabhängigkeit)
- Maturity-Stufen (Konstanten, siehe `pc-consensus/src/consts.rs`):
  - L1 = 50.000 Anker
  - L2 = 100.000 Anker
  - L3 = 200.000 Anker
- Beim Mint wird `minted_at: AnchorIndex` fixiert (der globale Index des finalisierten Mints).

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

## Validierung & Tests
- Unit-Tests prüfen Schwellenwerte und Level-Inkremente (`maturity_thresholds_boundaries`, `maturity_level_increments`).
- Keine Unix-Zeit, ausschließlich Index-Differenzen.

## Konfiguration/Parametrisierung
- Netzweite Policies (welche Stufe für Stake/Unbond/Spend nötig ist) können in Zukunft per Genesis/Config vorgegeben werden.
- Die Konstanten L1/L2/L3 liegen in `pc-consensus/src/consts.rs` und können in einer künftigen Hardfork angepasst werden.
