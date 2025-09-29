# Genesis-Datei (genesis.toml): Format, Commitment, Verwendung

## Ziel
Diese Anleitung beschreibt das Format der `genesis.toml`, wie das kryptographische Commitment über die Genesis-Note berechnet wird (BLAKE3-256), und wie die Datei in den Phantom-Node-Subkommandos verwendet wird. Die Parameter aus der Genesis-Datei (insbesondere `consensus.k`) haben Vorrang vor CLI/Config und verhindern Konfigurations-Drift.

## Dateiformat: genesis.toml
```toml
[consensus]
# Committee-Größe k (Seats pro Shard); muss 1..=64 sein
k = 21

# 32-Byte Hex (64 Hex-Zeichen). Rohbytes (kein ASCII-Text!)
genesis_note = "<64-hex-bytes>"

# 32-Byte Hex (64 Hex-Zeichen) = BLAKE3-256(genesis_note_raw_bytes)
commitment   = "<64-hex-bytes>"
```

- `consensus.k`: Konsens-k (Seats). Harte Validierung auf 1..=64.
- `genesis_note`: 32 Byte als Hex, z. B. per CSPRNG erzeugt. Wird in Rohbytes interpretiert (die 32 Bytes, auf die das Hex zeigt), nicht als ASCII.
- `commitment`: BLAKE3-256 über genau diese 32 Rohbytes aus `genesis_note`.

Die Node-Implementierung prüft beim Start:
1) `genesis_note` ist gültiger 32-Byte-Hex.
2) `commitment == blake3_32(genesis_note_raw)`.
3) `k` in [1, 64].

Bei Erfolg wird geloggt:
```
{"type":"genesis_loaded","k":<wert>,"commitment":"<hex64>"}
```

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
[consensus]
k = 21

genesis_note = "$GENESIS_NOTE"
commitment   = "$COMMITMENT"
EOF
```

Optional: Datei unveränderlich versionieren und an alle Nodes verteilen. Alle Validatoren eines Netzes/Shard müssen identische `genesis.toml` nutzen.

## Verwendung im Phantom-Node

- QUIC Listener (P2P + Persistenz + Metriken):
```bash
phantom-node P2pQuicListen \
  --addr 127.0.0.1:9000 \
  --genesis ./genesis.toml \
  --store_dir pc-data \
  --fsync true
```
Bei Erfolg: `{"type":"genesis_loaded",...}` in den Logs. k wird strikt aus Genesis gezogen. CLI/Config-Overrides sind dann wirkungslos.

- Ack-Distanzen:
```bash
phantom-node ConsensusAckDists \
  --ack_id <hex32> \
  --headers_file headers.bin \
  --genesis ./genesis.toml
```

- Payout-Root:
```bash
phantom-node ConsensusPayoutRoot \
  --ack_id <hex32> \
  --headers_file headers.bin \
  --fees 1000000 \
  --recipients <hex32>,<hex32>,... \
  --proposer_index 0 \
  --genesis ./genesis.toml
```

Hinweis: Ohne `--genesis` fällt das jeweilige Subcommand auf `--k` (CLI) zurück. Das ist ausschließlich für lokale Entwicklung gedacht. Produktion: immer `--genesis` verwenden.

## Fehlermeldungen & Troubleshooting
- `genesis commitment mismatch`: `commitment` passt nicht zu `genesis_note`. Prüfe, ob Du die Rohbytes gehasht hast (siehe Pipe mit `xxd -r -p`).
- `invalid k in genesis`: k außerhalb 1..=64. Korrigiere `consensus.k`.
- `invalid hex for 32-byte id`: `genesis_note`/`commitment` sind nicht exakt 64 Hex-Zeichen.

## Best Practices
- **Einheitlich verteilen**: Dieselbe `genesis.toml` an alle Nodes/Validatoren verteilen.
- **Änderungen vermeiden**: Nach dem Netz-Start darf die Genesis-Datei nicht mehr geändert werden.
- **Dokumentation**: `k` (Seats) klar dokumentieren und in Monitoring/Deployment-Pipelines prüfen.
- **Sicherheit**: `genesis_note` kann zufällig sein; das Commitment schützt vor versehentlicher Manipulation. Bewahre die Datei im Repository, aber prüfe Integrität (Commitment) bei Deployments.
