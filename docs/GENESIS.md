# Genesis-Datei (genesis.toml): Format, Commitment, Verwendung

## Ziel
Diese Anleitung beschreibt das Format der `genesis.toml`, wie das kryptographische Commitment über die Genesis-Note berechnet wird (BLAKE3-256), wie Feature-Bits in der kanonischen `GenesisNote` aktiviert werden und wie die Datei in den Phantom-Node-Subkommandos verwendet wird. Die Parameter aus der Genesis-Datei haben Vorrang vor CLI/Config und verhindern Konfigurations-Drift.

## Aktuelle kanonische Repo-Genesis

- Die allein autoritative kanonische Genesis liegt im Repository unter `data/genesis_note.bin`.
- Das Dashboard bettet genau diese Datei per `include_bytes!` ein und installiert beim Reset oder beim Erststart exakt diese Bytes in `mempool/genesis_note.bin`.
- Lokale Genesis-Rewrites, Bootstrap-Overrides oder Keystore-basierte Genesis-Neuerzeugung sind im Reset-Pfad nicht mehr vorgesehen.
- Aktueller fester Stand:
  - `genesis_note.version`: `3`
  - `network_id`: `b28e1bdf6d2e7a41cc1c3b3b182136612069fe5e9b5b1e2023edfec02d15cf34`
  - `network_name`: `phantom-mainnet`
  - `seed`: `5068616e746f6d436f696e5f47656e657369735f4d61696e6e65745f76310000`
  - `committee_k`: `1`
  - `features`: `0x8d`
  - `emission_bootstrap_bucket`: `1773964800`
  - `genesis_validators.len()`: `1`

## Dateiformat: genesis.toml
```toml
# 32-Byte Hex (64 Hex-Zeichen). Rohbytes (kein ASCII-Text!)
genesis_note = "<64-hex-bytes>"

# 32-Byte Hex (64 Hex-Zeichen) = BLAKE3-256(genesis_note_raw_bytes)
commitment   = "<64-hex-bytes>"

[consensus]
# Committee-Größe k (Seats pro Shard); muss 1..=64 sein
k = 21
# Optional: PoW-Difficulty (führende Nullbits) für Mint-PoW
# Wenn nicht gesetzt, verwendet Tools/CLI den Default (POW_DEFAULT_BITS)
# pow_bits = 20
```

- `consensus.k`: Konsens-k (Seats). Harte Validierung auf 1..=64.
- `consensus.pow_bits` (optional): Difficulty in führenden Nullbits für Mint‑PoW.
- `genesis_note`: 32 Byte als Hex, z. B. per CSPRNG erzeugt. Wird in Rohbytes interpretiert (die 32 Bytes, auf die das Hex zeigt), nicht als ASCII.
- `commitment`: BLAKE3-256 über genau diese 32 Rohbytes aus `genesis_note`.
- Die konsensrelevante Feature-Maske liegt in der kanonischen `GenesisNote.params.features`, nicht in einer separaten lokalen Side-Config.

Die Node-Implementierung prüft beim Start:
1) `genesis_note` ist gültiger 32-Byte-Hex.
2) `commitment == blake3_32(genesis_note_raw)`.
3) `k` in [1, 64].

Bei Erfolg wird geloggt:
```
{"type":"genesis_loaded","k":<wert>,"commitment":"<hex64>"}
```

## Feature-Bits der kanonischen Genesis-Note

Die kanonische `GenesisNote` enthaelt in `GenesisParams` folgende konsensrelevanten Parameter:

- `shards_initial: u16`
- `committee_k: u8`
- `txs_per_payload: u16`
- `features: u64`

Zusätzlich enthaelt die aktive kanonische `GenesisNote` ab `version == 3` das Feld:

- `emission_bootstrap_bucket: u64`

Alle diese Felder sind Teil der kanonischen `GenesisNote`-Bytes. Dadurch gilt:

- `network_id` commitet implizit auf `features`.
- `network_id` commitet ab `GenesisNote.version == 3` auch auf `emission_bootstrap_bucket`.
- Eine Aenderung von `features` aendert die `network_id`.
- Eine Aenderung von `emission_bootstrap_bucket` aendert ebenfalls die `network_id`.
- Eine Aenderung von `features` nach Netzstart erzeugt effektiv ein anderes Netz und ist daher unzulaessig.
- Eine Aenderung von `emission_bootstrap_bucket` nach Netzstart erzeugt ebenfalls effektiv ein anderes Netz und ist daher unzulaessig.

### Emissions-Bootstrap-Bucket

- `emission_bootstrap_bucket` ist der konsensgebundene Referenz-Bucket fuer die erste ASERT-Berechnung,
  solange noch kein finaler Mint existiert.
- Dadurch kann die Difficulty im Emissionspfad bereits vor dem ersten finalen Mint auf einen
  kanonischen Referenzpunkt zurueckgreifen, ohne dass lokale Reset-Zeitpunkte Teil des Konsenses werden.
- Dieses Feld ist Teil der kanonischen Genesis-Bytes und damit Teil der Netzwerk-Identitaet.

## Erstellung der Genesis-Datei

### 1) 32-Byte `genesis_note` erzeugen
- macOS/Linux (OpenSSL):
```bash
GENESIS_NOTE=$(openssl rand -hex 32)
echo "$GENESIS_NOTE"
```
- Alternativ (Linux):
```bash
GENESIS_NOTE=$(head -c 32 /dev/urandom | xxd -p -c 256)
echo "$GENESIS_NOTE"
```

Wichtig: Es müssen genau 64 Hex-Zeichen sein (32 Byte).

### 2) `commitment` berechnen (BLAKE3-256 über Rohbytes)
Es wird der BLAKE3-Hash über die 32 Rohbytes gebildet, auf die `genesis_note` zeigt. Nicht den ASCII-String hashen.

- Bevorzugt: `b3sum` (BLAKE3 CLI). Installation: `brew install b3sum` (macOS) oder Paketmanager der Distribution.
```bash
COMMITMENT=$(printf "%s" "$GENESIS_NOTE" | xxd -r -p | b3sum --no-names | awk '{print $1}')
echo "$COMMITMENT"
```

- Alternative (Python mit blake3-Modul):
```bash
python3 - <<'PY'
import binascii, sys
try:
    import blake3
except ImportError:
    sys.stderr.write("Installiere zuerst: pip install blake3\n"); sys.exit(1)
note_hex = """$GENESIS_NOTE"""
note = binascii.unhexlify(note_hex)
print(blake3.blake3(note).hexdigest())
PY
```

### 3) `genesis.toml` schreiben
```bash
cat > genesis.toml <<EOF
genesis_note = "$GENESIS_NOTE"
commitment   = "$COMMITMENT"

[consensus]
k = 21
EOF
```

Optional: Datei unveränderlich versionieren und an alle Nodes verteilen. Alle Validatoren eines Netzes/Shard müssen identische `genesis.toml` nutzen.

## Verwendung im Phantom-Node

- QUIC Listener (P2P + Persistenz + Metriken):
```bash
phantom-node p2p-quic-listen \
  --addr 127.0.0.1:9000 \
  --genesis ./genesis.toml \
  --store-dir /var/lib/phantom-coin/data \
  --fsync
```
Bei Erfolg: `{"type":"genesis_loaded",...}` in den Logs. k wird strikt aus Genesis gezogen. CLI/Config-Overrides sind dann wirkungslos.

- Ack-Distanzen:
```bash
phantom-node consensus-ack-dists \
  --ack-id <hex32> \
  --headers-file headers.bin \
  --genesis ./genesis.toml
```

- Payout-Root:
```bash
phantom-node consensus-payout-root \
  --ack-id <hex32> \
  --headers-file headers.bin \
  --fees 1000000 \
  --recipients <hex32>,<hex32>,... \
  --proposer-index 0 \
  --genesis ./genesis.toml
```

- Mint-PoW (Nonce finden):
```bash
phantom-node mine_mint \
  --pow_seed <hex32> \
  --genesis ./genesis.toml \
  --threads 0 \
  --progress_secs 5
# Alternativ ohne Genesis:
phantom-node mine_mint \
  --pow_seed <hex32> \
  --bits 22
```

Hinweis: Ohne `--genesis` fällt das jeweilige Subcommand auf `--k` (CLI) zurück. Das ist ausschließlich für lokale Entwicklung gedacht. Produktion: immer `--genesis` verwenden.

## Fehlermeldungen & Troubleshooting
- `genesis commitment mismatch`: `commitment` passt nicht zu `genesis_note`. Prüfe, ob Du die Rohbytes gehasht hast (siehe Pipe mit `xxd -r -p`).
- `invalid k in genesis`: k außerhalb 1..=64. Korrigiere `consensus.k`.
- `invalid hex for 32-byte id`: `genesis_note`/`commitment` sind nicht exakt 64 Hex-Zeichen.

## Best Practices
- **Einheitlich verteilen**: Dieselbe `genesis.toml` an alle Nodes/Validatoren verteilen.
- **Änderungen vermeiden**: Nach dem Netz-Start darf die Genesis-Datei nicht mehr geändert werden.
- **Feature-Bits und Bootstrap-Bucket vor Launch einfrieren**: `GenesisNote.params.features` und `GenesisNote.emission_bootstrap_bucket` muessen vor Netzstart final sein und duerfen spaeter nicht lokal ersetzt werden.
- **Dokumentation**: `k` (Seats) klar dokumentieren und in Monitoring/Deployment-Pipelines prüfen.
- **Sicherheit**: `genesis_note` kann zufällig sein; das Commitment schützt vor versehentlicher Manipulation. Bewahre die Datei im Repository, aber prüfe Integrität (Commitment) bei Deployments.
