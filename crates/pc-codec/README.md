# pc-codec

## English version

Canonical, deterministic binary serialization format for Phantom-Coin.

### Features

- **Varint u64:** LEB128-like, base-128, max 10 bytes
- **Fixed-length types:** u8, u16, u32 (LE), bool, [u8;32]
- **Vec<T>:** length prefix (varint) + elements
- **Error handling:** `CodecError` without panics
- **Traits:** `Encodable`, `Decodable` for easy extension

### Usage

```rust
use pc_codec::{Encodable, Decodable};

let value = 12345u64;
let mut buf = Vec::new();
value.encode(&mut buf)?;

let mut reader = &buf[..];
let decoded = u64::decode(&mut reader)?;
assert_eq!(value, decoded);
```

### Tests

- Unit tests for roundtrips and error handling
- Property-based tests (proptest) for arbitrary inputs
- Fuzz tests (cargo-fuzz) for varint and Vec

### Specification

See `docs/SPEC_CODEC.md` for the complete wire format specification.

## Deutsche Version

Kanonisches, deterministisches Binär-Serialisierungsformat für Phantom-Coin.

## Features

- **Varint u64:** LEB128-ähnlich, base-128, max. 10 Bytes
- **Fixe Längen:** u8, u16, u32 (LE), bool, [u8;32]
- **Vec<T>:** Length-prefix (varint) + Elemente
- **Fehlerbehandlung:** `CodecError` ohne Panics
- **Traits:** `Encodable`, `Decodable` für einfache Erweiterung

## Verwendung

```rust
use pc_codec::{Encodable, Decodable};

let value = 12345u64;
let mut buf = Vec::new();
value.encode(&mut buf)?;

let mut reader = &buf[..];
let decoded = u64::decode(&mut reader)?;
assert_eq!(value, decoded);
```

## Tests

- Unit-Tests für Roundtrips und Fehlerbehandlung
- Property-Tests (proptest) für beliebige Eingaben
- Fuzz-Tests (cargo-fuzz) für Varint und Vec

```bash
cargo test -p pc-codec
cargo fuzz list  # im fuzz/ Verzeichnis
```

## Spezifikation

Siehe `docs/SPEC_CODEC.md` für die vollständige Wire-Format-Spezifikation.
