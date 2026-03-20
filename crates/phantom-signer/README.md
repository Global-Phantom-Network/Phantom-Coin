# phantom-signer

## English version

CLI for keys, HWI/BitBox02, PSBT and broadcast.

## Configuration (optional)

`signer.toml`

```toml
node_url = "http://127.0.0.1:8080"
auth_token_file = "/etc/phantom-coin/signer-auth.token"  # optional
# default_hrp = "pc"                # reserved
```

Run with `--config signer.toml`.

CLI invocation pattern: `phantom-signer <subcommand> [FLAGS] [OPTIONS]`

## Key commands

- Keys/keystore:
  - `phantom-signer keygen --type seat|bond|payout --algo schnorr|bls --out ks.toml [--force] [--passphrase-env VAR | --passphrase-file PATH] [--passphrase-role validator|miner]`
  - `phantom-signer import --type ... --algo ... --secret-hex <32Bhex> --out ks.toml [--passphrase-env VAR | --passphrase-file PATH] [--passphrase-role validator|miner]`
  - `phantom-signer export-pub --keystore ks.toml`
  - `phantom-signer bls-pop --keystore ks.toml [--out pop.hex] [--passphrase-env VAR | --passphrase-file PATH] [--passphrase-role validator|miner]`
  - `phantom-signer sign --keystore ks.toml --msg file.bin --out sig.hex [--passphrase-env VAR | --passphrase-file PATH] [--passphrase-role validator|miner]`
  - `phantom-signer verify --algo schnorr|bls --pub-hex <hex> --msg file.bin --sig-hex <hex>`

- Watch-only/HWI:
  - `phantom-signer hwi-enumerate`
  - `phantom-signer hwi-get-xpub --derivation "m/86'/12345'/0'" [--fingerprint <fp>]`
  - `phantom-signer import-xpub --algo schnorr --xpub ... --derivation ... --out xpub.toml --hrp pc`
  - `phantom-signer addr-from-xpub --xpubstore xpub.toml --change 0 --index 0`

- PSBT/signing:
  - `phantom-signer psbt-create --tx-bin microtx.bin --paths "m/86'/12345'/0'/0/0" --out tx.psbt.toml`
  - `phantom-signer psbt-sighash --psbt tx.psbt.toml`
  - `phantom-signer sign-tx-with-keystore --psbt tx.psbt.toml --keystore ks.toml --out sig.hex [--passphrase-env VAR | --passphrase-file PATH]`
- `phantom-signer psbt-finalize --psbt tx.psbt.toml --pubkeys <xonly,...> --sigs <sig64,...> --out finalized_tx.bin`

- Broadcast:
  - `phantom-signer tx-broadcast --node http://127.0.0.1:8080 --tx finalized_tx.bin [--auth-token-file /etc/phantom-coin/signer-auth.token]`

- Externer Signer (für `hwi-sign-tx`):
  - **Schnittstelle:** `--digest <hex32> --path <derivation> [--fingerprint <fp>]` → JSON `{pub_xonly_hex,sig_hex}`
  - Im Workspace ist ein passendes CLI enthalten: `bitbox02-signer` (Software‑Signer).
  - Setup (verschlüsselter Seed‑Store, BIP39):
    - `bitbox02-signer init` (Mnemonic eingeben, Passphrase setzen)
    - Signieren: `bitbox02-signer sign --digest <hex32> --path "m/86'/12345'/0'/0/0"`
  - Hinweis: Kein offizielles BitBox02‑CLI signiert Phantom‑Sighashes (BLAKE3) direkt.  
    Für Hardware‑Schlüssel empfiehlt sich `phantom-signer sign-pkcs11`.

## Slashing DB and seat vote

- Slashing DB:
  - `slash-db-init --db-dir /path/to/slashdb`
  - `slash-db-get --db-dir /path/to/slashdb --epoch <u64> --shard <u16> --round <u64>`
  - `slash-db-put --db-dir /path/to/slashdb --epoch <u64> --shard <u16> --round <u64> --header-hex <32Bhex>`
  - `slash-db-import --db-dir /path/to/slashdb --file dump.json`
  - `slash-db-export --db-dir /path/to/slashdb --file dump.json`
  - `slash-db-vacuum --db-dir /path/to/slashdb`
  - `slash-db-check --db-dir /path/to/slashdb`

- Seat vote signing (Schnorr, with slashing enforcement):
  - `phantom-signer seat-vote-sign --db-dir /path/to/slashdb --epoch <u64> --shard <u16> --round <u64> --header-hex <32Bhex> --keystore seat.toml [--out sig.hex] [--passphrase-env VAR | --passphrase-file PATH] [--passphrase-role validator|miner]`
  - Idempotent: the same (epoch, shard, round, header_id) can be signed multiple times; a different `header_id` for the same tuple triggers an equivocation error.

- Seat vote verification (Schnorr):
  - `phantom-signer seat-vote-verify --epoch <u64> --shard <u16> --round <u64> --header-hex <32Bhex> --pub-hex <xonly32> --sig-hex <64Bhex>`

### Canonical message (SeatVote)

`DOMAIN || epoch_le(8) || shard_le(2) || round_le(8) || header_id(32)`

With `DOMAIN = b"pc:vote:seat:v1\x01"` and little-endian encoding for `epoch`, `shard`, `round`. The digest is `blake3_32(msg)`.

### Examples

- `phantom-signer slash-db-init --db-dir .slashdb`

- Seat vote signing (Schnorr):
  - `phantom-signer seat-vote-sign --db-dir .slashdb --epoch 1 --shard 0 --round 7 --header-hex <64-hex> --keystore seat.toml --out sig.hex --passphrase-env KS_PASS [--passphrase-role validator|miner]`
  - `phantom-signer seat-vote-sign --db-dir .slashdb --epoch 1 --shard 0 --round 7 --header-hex <64-hex> --keystore seat.toml --out sig.hex --passphrase-file ./pass.txt [--passphrase-role validator|miner]`
  - Repeated calls with identical parameters: OK
  - Different `--header-hex` for the same (epoch, shard, round): equivocation error

- Seat vote verification:
  - `phantom-signer seat-vote-verify --epoch 1 --shard 0 --round 7 --header-hex <64-hex> --pub-hex <xonly32-hex> --sig-hex $(cat sig.hex)`

- Message signing (Schnorr/BLS), non-interactive:
  - `KS_PASS=secret phantom-signer sign --keystore ks.toml --msg msg.bin --out sig.hex --passphrase-env KS_PASS [--passphrase-role validator|miner]`

- PSBT signing with keystore (Schnorr), non-interactive:
  - `KS_PASS=secret phantom-signer sign-tx-with-keystore --psbt tx.psbt.toml --keystore ks.toml --out sig.hex --passphrase-env KS_PASS`
  - `phantom-signer sign-tx-with-keystore --psbt tx.psbt.toml --keystore ks.toml --out sig.hex --passphrase-file ./pass.txt`

#### Non-interactive examples

- Import with ENV: `KS_PASS=secret phantom-signer import --type seat --algo schnorr --secret-hex <32Bhex> --out seat.toml --passphrase-env KS_PASS`
- Import with file: `phantom-signer import --type seat --algo schnorr --secret-hex <32Bhex> --out seat.toml --passphrase-file ./pass.txt`

#### Passphrase behaviour

- Order: `--passphrase-env` (if set) > `--passphrase-file` (if set) > interactive prompt on TTY.
- Import: interactive double entry only if no flags are set; with flags, a single source (no double prompt).
- Files are trimmed for trailing `\n`/`\r` when read (typical for secret files).
- Optional: `--passphrase-role validator|miner` derives the keystore passphrase deterministically from the provided master passphrase (env/file/prompt).

#### Troubleshooting

- `--passphrase-env VAR` fails: check whether the env variable is set (`printenv VAR`) and contains no whitespace.
- `--passphrase-file PATH` fails: check path/permissions. Trailing newlines are removed automatically; content must be exactly the passphrase.
- Wrong algo/key type: `seat-vote-sign` expects a `seat`+`schnorr` keystore; `sign-tx-with-keystore` currently supports only `schnorr`.

## Notes

- Schnorr x-only (32B) & signatures (64B) for MicroTx.
- External BitBox02 signer: expects `--digest <hex32> --path <derivation> [--fingerprint <fp>]` and returns JSON `{pub_xonly_hex,sig_hex}`.
- `TxBroadcast` optionally uses a bearer token.

## Deutsche Version

CLI für Schlüssel, HWI/BitBox02, PSBT und Broadcast.

## Konfiguration (optional)

`signer.toml`

```toml
node_url = "http://127.0.0.1:8080"
auth_token_file = "/etc/phantom-coin/signer-auth.token"  # optional
# default_hrp = "pc"                # reserviert
```

Aufruf mit `--config signer.toml`.

CLI-Aufruf-Schema: `phantom-signer <subcommand> [FLAGS] [OPTIONEN]`

## Wichtige Kommandos

- Key/Keystore:
  - `phantom-signer keygen --type seat|bond|payout --algo schnorr|bls --out ks.toml [--force] [--passphrase-env VAR | --passphrase-file PFAD] [--passphrase-role validator|miner]`
  - `phantom-signer import --type ... --algo ... --secret-hex <32Bhex> --out ks.toml [--passphrase-env VAR | --passphrase-file PFAD] [--passphrase-role validator|miner]`
  - `phantom-signer export-pub --keystore ks.toml`
  - `phantom-signer bls-pop --keystore ks.toml [--out pop.hex] [--passphrase-env VAR | --passphrase-file PFAD] [--passphrase-role validator|miner]`
  - `phantom-signer sign --keystore ks.toml --msg file.bin --out sig.hex [--passphrase-env VAR | --passphrase-file PFAD] [--passphrase-role validator|miner]`
  - `phantom-signer verify --algo schnorr|bls --pub-hex <hex> --msg file.bin --sig-hex <hex>`

- Watch‑Only/HWI:
  - `phantom-signer hwi-enumerate`
  - `phantom-signer hwi-get-xpub --derivation "m/86'/12345'/0'" [--fingerprint <fp>]`
  - `phantom-signer import-xpub --algo schnorr --xpub ... --derivation ... --out xpub.toml --hrp pc`
  - `phantom-signer addr-from-xpub --xpubstore xpub.toml --change 0 --index 0`
  - Optionaler Transport (BitBoxBridge):
    - `PHANTOM_BITBOX_TRANSPORT=bridge` (alternativ `usb` oder `auto`)
    - `PHANTOM_BITBOX_BRIDGE_URL=http://127.0.0.1:8178`

- PSBT/Signieren:
  - `phantom-signer psbt-create --tx-bin microtx.bin --paths "m/86'/12345'/0'/0/0" --out tx.psbt.toml`
  - `phantom-signer psbt-sighash --psbt tx.psbt.toml`
  - `phantom-signer sign-tx-with-keystore --psbt tx.psbt.toml --keystore ks.toml --out sig.hex [--passphrase-env VAR | --passphrase-file PFAD]`
  - `phantom-signer psbt-finalize --psbt tx.psbt.toml --pubkeys <xonly,...> --sigs <sig64,...> --out finalized_tx.bin`

- Broadcast:
  - `phantom-signer tx-broadcast --node http://127.0.0.1:8080 --tx finalized_tx.bin [--auth-token-file /etc/phantom-coin/signer-auth.token]`

## Slashing-DB und Seat-Vote

- Slashing-DB
  - `slash-db-init --db-dir /pfad/zur/slashdb`
  - `slash-db-get --db-dir /pfad/zur/slashdb --epoch <u64> --shard <u16> --round <u64>`
  - `slash-db-put --db-dir /pfad/zur/slashdb --epoch <u64> --shard <u16> --round <u64> --header-hex <32Bhex>`
  - `slash-db-import --db-dir /pfad/zur/slashdb --file dump.json`
  - `slash-db-export --db-dir /pfad/zur/slashdb --file dump.json`
  - `slash-db-vacuum --db-dir /pfad/zur/slashdb`
  - `slash-db-check --db-dir /pfad/zur/slashdb`

- Seat-Vote signieren (Schnorr, mit Slashing-Enforcement):
  - `phantom-signer seat-vote-sign --db-dir /pfad/zur/slashdb --epoch <u64> --shard <u16> --round <u64> --header-hex <32Bhex> --keystore seat.toml [--out sig.hex] [--passphrase-env VAR | --passphrase-file PFAD] [--passphrase-role validator|miner]`
  - idempotent: gleicher (epoch, shard, round, header_id) mehrfach erlaubt; abweichender `header_id` → Equivocation-Fehler

- Seat-Vote verifizieren (Schnorr):
  - `phantom-signer seat-vote-verify --epoch <u64> --shard <u16> --round <u64> --header-hex <32Bhex> --pub-hex <xonly32> --sig-hex <64Bhex>`

### Kanonische Nachricht (SeatVote)

`DOMAIN || epoch_le(8) || shard_le(2) || round_le(8) || header_id(32)`

mit `DOMAIN = b"pc:vote:seat:v1\x01"` und little‑endian Kodierung für `epoch`, `shard`, `round`. Der Digest ist `blake3_32(msg)`.

### Beispiele

- `phantom-signer slash-db-init --db-dir .slashdb`

- Seat‑Vote signieren (Schnorr):
  - `phantom-signer seat-vote-sign --db-dir .slashdb --epoch 1 --shard 0 --round 7 --header-hex <64-hex> --keystore seat.toml --out sig.hex --passphrase-env KS_PASS [--passphrase-role validator|miner]`
  - `phantom-signer seat-vote-sign --db-dir .slashdb --epoch 1 --shard 0 --round 7 --header-hex <64-hex> --keystore seat.toml --out sig.hex --passphrase-file ./pass.txt [--passphrase-role validator|miner]`
  - erneuter Aufruf mit identischen Parametern: OK
  - abweichender `--header-hex` für dieselben (epoch, shard, round): Equivocation‑Fehler

- Seat‑Vote verifizieren:
  - `phantom-signer seat-vote-verify --epoch 1 --shard 0 --round 7 --header-hex <64-hex> --pub-hex <xonly32-hex> --sig-hex $(cat sig.hex)`

- Nachricht signieren (Schnorr/BLS), non-interaktiv:
  - `KS_PASS=geheim phantom-signer sign --keystore ks.toml --msg msg.bin --out sig.hex --passphrase-env KS_PASS [--passphrase-role validator|miner]`

- PSBT mit Keystore signieren (Schnorr), non-interaktiv:
  - `KS_PASS=geheim phantom-signer sign-tx-with-keystore --psbt tx.psbt.toml --keystore ks.toml --out sig.hex --passphrase-env KS_PASS`
  - `phantom-signer sign-tx-with-keystore --psbt tx.psbt.toml --keystore ks.toml --out sig.hex --passphrase-file ./pass.txt`

#### Non-interaktive Beispiele

- Import mit ENV: `KS_PASS=geheim phantom-signer import --type seat --algo schnorr --secret-hex <32Bhex> --out seat.toml --passphrase-env KS_PASS`
- Import mit Datei: `phantom-signer import --type seat --algo schnorr --secret-hex <32Bhex> --out seat.toml --passphrase-file ./pass.txt`

#### Passphrase-Verhalten

- Reihenfolge: `--passphrase-env` (wenn gesetzt) > `--passphrase-file` (wenn gesetzt) > interaktive Abfrage am TTY.
- Import: interaktive Doppelteingabe nur, wenn keine Flags gesetzt sind; bei gesetzten Flags eine einzige Quelle (kein Double-Prompt).
- Dateien werden beim Einlesen am Ende um `\n`/`\r` bereinigt (typisch für Secret-Dateien).
- Optional: `--passphrase-role validator|miner` leitet die Keystore-Passphrase deterministisch aus der Master-Passphrase ab (ENV/Datei/Prompt).

#### Troubleshooting

- `--passphrase-env VAR` liefert Fehler: Prüfe, ob die ENV-Variable gesetzt ist (`printenv VAR`) und keine Whitespaces enthält.
- `--passphrase-file PFAD` liefert Fehler: Prüfe Pfad/Berechtigungen. Trailing Newlines werden automatisch entfernt; Inhalt muss exakt die Passphrase enthalten.
- Falscher Algo/Keytyp: `seat-vote-sign` erwartet `seat`+`schnorr` Keystore; `sign-tx-with-keystore` unterstützt aktuell nur `schnorr`.

## Hinweise

- Schnorr xonly (32B) & Signaturen (64B) für MicroTx.
- Externer BitBox02‑Signer: erwartet `--digest <hex32> --path <derivation> [--fingerprint <fp>]` und liefert JSON `{pub_xonly_hex,sig_hex}`.
- `TxBroadcast` nutzt optional Bearer‑Token.
