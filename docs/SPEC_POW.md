# Phantom-Coin: Proof‑of‑Work (Emission) v0

Ziel: Minimales, deterministisches PoW nur für Mint‑Emissionen. Keine Unix‑Zeit im Pfad. PoW ist unabhängig vom Konsens (leaderloser DAG, aBFT) und dient ausschließlich der kontrollierten Ausgabe neuer Coins.

## Grundlagen
- Hardcap: 50.000.000 PC, Teilbarkeit: 1 PC = 100.000.000 Einheiten.
- PoW dient nur für Mints. Normale Transaktionen benötigen kein PoW.
- Mint‑Kette: Jeder `MintEvent` referenziert `prev_mint_id` (Hash der vorherigen Mint), wodurch eine simple, lineare Mint‑Kette entsteht.
- Keine Uhrabhängigkeit (keine Zeitstempel, keine Difficulty‑Retargets an Zeit gebunden).

## Datenstrukturen (pc‑types)
- `MintEvent { version: u8, prev_mint_id: [u8;32], outputs: Vec<TxOut>, pow_seed: [u8;32], pow_nonce: u64 }`
- Digest der Mint als Commitment: `pc_types::digest_mint(&mint)`

## Hash‑Funktion und Difficulty
- Domain‑Trennung: `POW_DOMAIN = b"pc:mint:pow:v1\x01"` (siehe `crates/pc-consensus/src/consts.rs`).
- Hash: `H = blake3_32( POW_DOMAIN || pow_seed || nonce_le )`
- Kriterium: `H` muss mindestens `bits` führende Nullbits haben (MSB‑first pro Byte).
- Default‑Leitwert: `POW_DEFAULT_BITS = 20` (für Tools/Dev; netzwerkspezifische Policy möglich).

Implementierung (pc‑consensus):
- `pow_hash(seed, nonce) -> [u8;32]`
- `pow_meets(bits, &hash) -> bool` (prüft Leading‑Zero‑Bits)
- `check_mint_pow(&MintEvent, bits) -> bool`

Tests (pc‑consensus):
- `pow_meets_boundaries`: Randfälle (0/4/8/9 Bits) werden geprüft.

## Verifikation
- Knoten, die Mints akzeptieren (z. B. Proposer/Builder), verifizieren vor Aufnahme in Payload:
  - `validate_mint_sanity(m)` (Struktur/Größenlimit)
  - `check_mint_pow(m, bits)` (Difficulty‑Policy)
- Die Difficulty‑Policy (`bits`) ist netzwerkspezifisch (Genesis/Config/CLI). In v0 ist die konkrete Policy noch offen und kann per Node‑Config/CLI gesetzt werden.

## Emissions‑Budget und Hardcap
- Monetäre Konstanten (`COIN`, `HARD_CAP_PC`, `HARD_CAP_UNITS`) sind in `pc-consensus/src/consts.rs` hinterlegt.
- Durchsetzung der Emissionskurve (Zeitplan/Rate) ist v0‑offen. Hardcap ist als obere Schranke zu verstehen; die genaue Kurve wird in einer späteren Version festgelegt und state‑seitig validiert.

## Determinismus und Sicherheit
- Keine Unix‑Zeit im PoW‑Pfad.
- Domain‑Trennung verhindert Cross‑Protocol‑Replay.
- Difficulty‑Vergleich ist byteweise MSB‑first, remainder‑Bits per Maske.
- 32‑Byte BLAKE3‑Hash, Konstantzeit‑Vergleich nicht erforderlich (keine Secret‑Keys im Spiel).

## Zusammenfassung
- PoW ist auf Mints beschränkt und definiert über einfache Leading‑Zero‑Bits.
- Implementierung und Tests liegen in `pc-consensus`. `pc-types` liefert die Mint‑Struktur und Digest‑Funktionen.
- Nächste Schritte (außerhalb v0): Netzweite Policy/Parametrisierung (Genesis/Config), optionale Mining‑CLI, Emissionskurve + Hardcap‑Durchsetzung im State.
