# Phantom Wallet/Signer Spezifikation (v1)

Diese Spezifikation definiert Adressen, Signatur- und Transaktionsflüsse für Phantom.
Sie ist auf ed25519/BLS unabhängig, fokussiert hier aber auf Schnorr (secp256k1 xonly, BIP340‑kompatibel),
da dies mit HWI/BitBox02 eingesetzt wird.

## 1. Adressen (Bech32m, HRP "pc")
- Version: 1 (Bech32m, BIP350)
- Programm: 32 Byte xonly‑Public‑Key (BIP340, ohne Y‑Parity)
- HRP: `pc`
- Ableitungspfad (empfohlen, BIP86‑ähnlich):
  - `m/86'/<coin_type>'/<account>'/<change>/<index>`
  - Vorläufiger `coin_type`: `12345'` bis SLIP‑44 reserviert ist.
- Beispiel (Normativ): Die Adresse wird als Bech32m (`Variant::Bech32m`) kodiert,
  wobei `data = [version=1] ++ program(32B xonly)`, siehe `crates/phantom-signer/src/main.rs: bech32m_address_from_xonly()`.

## 2. Phantom‑PSBT (TOML)
Container für signierbare MicroTx‑Vorlagen (watch‑only kompatibel):

```toml
version = 1                # u32
algo = "schnorr"          # string
# tx_b64: pc-codec kodierte MicroTx (inkl. Witness-Felder, die vor Sighash geleert werden)
# derivations: pro Input ein BIP32-Pfad (string), z. B. m/86'/12345'/0'/0/0
```

Struktur (siehe `crates/phantom-signer/src/psbt.rs`):
- `PhantomPsbtToml { version, algo, tx_b64, derivations[] }`
- `algo` muss für diese Spez `"schnorr"` sein.

## 3. Sighash (Phantom‑Schnorr)
- Domain‑Separation: `SIGHASH_DOMAIN = "PHANTOM_SIGHASH_V1"` (ASCII Bytes)
- Bytes für Hash:
  1. `SIGHASH_DOMAIN`
  2. `encode(tx_without_witnesses)`, d. h. alle `TxIn.witness` Felder vor dem Kodieren leeren.
- Hash: `blake3_32` der obigen Bytes.
- Referenz: `sighash_of_tx()` in `crates/phantom-signer/src/psbt.rs`.

## 4. Witness‑Layout (pro Input)
- Layout: `witness = xonly_pubkey(32) || schnorr_sig(64)` (insgesamt 96 Bytes)
- Referenz: `build_witness()` in `crates/phantom-signer/src/psbt.rs`.
- Verifikation: Signatur gegen `sighash_of_tx()` und `xonly_pubkey` (BIP340 Verify) prüfen.

## 5. Deterministische Sortierung
Um deterministische Normalisierung und Privacy‑Konsistenz zu erzielen:
- Inputs (optional, empfohlen wenn neu konstruiert):
  1. aufsteigend nach `prev_out.txid` (lexikografisch, 32B big‑endian)
  2. dann aufsteigend nach `prev_out.vout` (u32)
- Outputs (empfohlen):
  1. aufsteigend nach `amount` (u64)
  2. dann lexikografisch nach `lock` (32B Commitment)

Hinweis: Diese Sortierung ist BIP69‑ähnlich, angepasst für `TxOut.lock` (Commitment statt ScriptPubKey).

## 6. Stealth / Silent Payments (Design v1)
Ziel: Zahlungen, die keine wiederverwendbare Adresse im Klartext offenbaren und vom Empfänger
per Scan ableitbar sind.

- Schlüsselannahmen (Empfänger):
  - `X_s` (Scan‑Key, xonly public, secp256k1)
  - `X_d` (Diversifier/Spend‑Key‑Root, xonly public)
- Sender erzeugt pro Zahlung einen Ephemeral‑Schlüssel `x_e` (secret) und `X_e` (xonly pub).
- DH‑Ableitung (BIP340‑kompatibles ECDH, xonly): `S = DH(X_s, x_e)` und `t = H( "PHANTOM_STEALTH_V1" || X_e || X_s || S )` (32B)
- Tweak der Zieladresse: `Q = X_d + t*G` (Gruppenaddition auf secp256k1, xonly)
- Ziel‑Adresse: Bech32m `pc1...` für `Q` (siehe Abschnitt 1)
- Empfänger‑Scan: Für jede eingehende Zahlung liest der Empfänger `X_e` (vom Sender im Tx‑Hint/Out‑Commitment od. Side‑Channel geliefert),
  berechnet `t` und rekonstruiert `Q`.
- Ableitungspfad (empfohlen): den diversifizierten Spend‑Key pro Zahlung aus `X_d` und `t` intern mappen auf
  Standard‑Pfad `m/86'/12345'/account'/change/index`.
- Sicherheit: `H` = `blake3_32`; `PHANTOM_STEALTH_V1` als Domain trennt diesen Mechanismus klar.
- Integrationspunkt: Der „Hint“ (`X_e`) kann im Lock‑Commitment oder als Side‑Data in der Payload codiert werden (normativ: eigener Commitment‑Slot in zukünftiger Version).

Diese v1‑Definition vermeidet Adresswiederverwendung und erlaubt Empfänger‑seitiges Scannen ohne globale Indizes.

## 7. PayJoin‑Default (Design v1)
Ziel: Standard‑Workflow, bei dem Empfänger zusätzliche Inputs beisteuert, um Heuristiken (z. B. „common input ownership“)
zu erschweren.

- Initiator (Sender) erstellt eine vorbereitete PSBT mit:
  - mindestens einem Sender‑Input und einem Empfänger‑Output (Lock auf Empfänger)
  - optional einem Change‑Output zurück an den Sender
- Responder (Empfänger) ergänzt mindestens einen Empfänger‑Input und ggf. passt Outputs betragswahrend an (keine Gebührenverschiebung zum Nachteil des Initiators)
- Privacy‑Constraints (MUSS):
  - Keine trivialen Betrags‑Anker (z. B. 0‑Change), keine eindeutig linkbaren Kleinstbeträge
  - Output‑Sortierung nach Abschnitt 5
  - Sender darf zurückweisen, wenn Empfänger Inputs/Outputs gegen obige Regeln verstößt
- Transport:
  - `pc:`‑URI mit `pj=https://...` Parameter oder direkter HTTPS‑POST mit Phantom‑PSBT (TOML) als Body (`Content-Type: text/plain; charset=utf-8`)
  - Antwort: Phantom‑PSBT (TOML) mit hinzugefügten Inputs/Outputs; anschließend regulärer Signatur‑Austausch

Diese v1‑Definition priorisiert einfache Integration und klare Ablehnungskriterien.

## 8. Test‑Vektoren (Referenz)
Die folgenden bekannten Vektoren stammen aus den stabilen Tests in `crates/pc-types/src/lib.rs` und dokumentieren Kodierungen/Hashes.

- MicroTx‑Digest (Beispiel):
  - `1f701e879ce87e53d835dbf6ac42a51e2204135f664152749a51db4172872e73`
- Payload‑Merkle‑Root (Beispiel):
  - `2b6cdafd1cba1ecf772c93135af43d5e6d8b0efde30be0a2504a9b85f769d0ba`
- Header‑ID (Beispiel):
  - `43e6762a4560e36c7528e6e85def46d5e1aa068eb44362b21e36691628cf7d91`

Für PSBT‑Sighash gelten die Regeln aus Abschnitt 3. Konkrete Sighash‑Vektoren ergeben sich aus dem
`pc-codec`‑Encoding der MicroTx und können über `PsbtSighash` reproduziert werden.

## 9. Versionierung & Kompatibilität
- Diese Spezifikation ist `v1`. Änderungen an Domain‑Strings oder Formaten erfordern Versionssprünge.
- Abwärtskompatibilität wird über klare `version`‑Felder (PSBT) und getrennte Domains (`SIGHASH_DOMAIN`, `PHANTOM_STEALTH_V1`) gewahrt.

## 10. Sicherheitshinweise
- Private Keys verlassen nie das HWI (BitBox02). PSBT/Signer arbeitet watch‑only und fügt nur Witnesses hinzu.
- Validate‑Pipeline im Node prüft `MicroTx` Größen und Witness‑Längen; weiterführende Konsensregeln bleiben unaffected.
