# Rust Error Policy (PhantomCoin)
Version: v1.0
Datum: 2025-09-26
Gültig für: alle produktiven Crates (Konsens, P2P, Codec, Wallet, UTXO, Slashing)

## Leitprinzipien
- Keine Panics im Produktionspfad. `unwrap()`, `expect()` sind verboten.
- Fehler werden entweder sauber behandelt (recoverable) oder eindeutig propagiert (non-recoverable) – niemals verschluckt.
- Keine Unix‑Zeit in Fehlerpfaden (keine Timeouts in Sekunden als Konsens‑Kriterium). Alle Fenster/Zähler sind DAG‑logisch.
- Konsens‑kritische Fehlerpfade sind deterministisch, informationsarm (keine Geheimnis‑Leaks), mit klaren Error‑Typen.

## Compiler-/Lint‑Vorgaben
In produktiven Crates (lib/bin‑Roots):

```rust
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]
```

Cargo (Workspace‑weit empfohlen):

```toml
# Cargo.toml (workspace)
[profile.release]
panic = "abort"
lto = "fat"
codegen-units = 1
```

Hinweise:
- `panic = "abort"` erzwingt Prozessabbruch bei verbleibenden Panics (sollten nicht vorkommen). Größe/Speed besser.
- `clippy::indexing_slicing` zwingt bounds‑checks (`get`, `get_mut`) – keine UB‑Muster.
- In Test‑Crates/Modulen dürfen `unwrap/expect` genutzt werden (siehe unten).

## Fehlerklassen
- Recoverable: P2P‑Nachrichtenfehler, DA‑Fetch‑Miss, ungültige Transaktionen/Events, temporäre IO.
  - Aktion: verwerfen, backoff/retry, loggen (Rate‑limitiert), weiterarbeiten.
- Non‑recoverable (prozesslokal): Konsistente Startkonfiguration nicht erfüllbar, Datenbank korrupt (mit Beleg), kryptografische Invarianten verletzt (Bug).
  - Aktion: Sauberer Exit aus `main` (Fehlercode) mit strukturierter Logmeldung. Keine Panics im Business‑Code.

## Patterns (empfohlen)
- Ergebnis propagieren:
```rust
fn parse(buf: &[u8]) -> Result<Foo, CodecError> {
    let len = buf.first().copied().ok_or(CodecError::Truncated)?;
    let payload = buf.get(1..1 + len as usize).ok_or(CodecError::Truncated)?;
    Foo::from_bytes(payload)
}
```

- Option → Result heben:
```rust
let v = opt.ok_or(StateError::MissingField("parents"))?;
```

- Fehler mappen:
```rust
let n = reader.read(&mut buf).map_err(CodecError::Io)?;
```

- Explizite Behandlung (recoverable):
```rust
match decode_message(frame) {
    Ok(msg) => handle(msg),
    Err(e) => {
        metrics::inc("p2p_decode_err");
        tracing::warn!(reason = %e, "drop invalid p2p frame");
        return Ok(());
    }
}
```

- Keine `unwrap`/`expect` im Prod‑Pfad:
```rust
// Verboten:
// let x = opt.unwrap();
// Erlaubt:
let x = match opt {
    Some(x) => x,
    None => return Err(Error::MissingX),
};
```

## Error‑Typen
- Pro Domäne ein präziser Enum (z. B. `CodecError`, `ConsensusError`, `StateError`, `P2pError`).
- Optional `thiserror` für ergonomische Implementierung – nur in Nicht‑Hotpath‑Crates.
- Keine `anyhow` in Libraries (nur in Binaries für CLI/Top‑Level). Libraries liefern typsichere Fehler.

Beispiel:
```rust
use core::fmt;

#[derive(Debug)]
pub enum CodecError {
    Truncated,
    InvalidTag(u8),
    InvalidLength(usize),
    Io(std::io::Error),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated input"),
            Self::InvalidTag(t) => write!(f, "invalid tag: {t}"),
            Self::InvalidLength(n) => write!(f, "invalid length: {n}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl core::error::Error for CodecError {}

impl From<std::io::Error> for CodecError {
    fn from(e: std::io::Error) -> Self { CodecError::Io(e) }
}
```

## Logging & Telemetrie
- Strukturierte Logs (`tracing`), kein `println!` im Prod.
- Rate‑Limit für laute Pfade (z. B. ungültige P2P‑Frames).
- Metriken: Zähler für Fehlerklassen (`codec_err`, `consensus_drop`, `da_miss`, `state_conflict`).

## Konsens‑kritisch (zusätzlich)
- Keine geheimnisverratenden Fehlermeldungen (Keys, Seeds, genaue Prüfreihenfolgen).
- Gleichbleibende Fehlerkosten (Timing‑Seitenkanäle vermeiden, soweit praktikabel in Rust).
- Bei Verifikation immer „fail fast“ mit klarer Error‑Ursache.

## Tests
- In `#[cfg(test)]` sind `unwrap/expect` zulässig, um Testfälle kompakt zu halten.
- Fuzz/Property‑Tests für Codec/UTXO/Konsens‑Transitions.
- Panics in Tests sind erlaubt; im Prod‑Build niemals absichtlich provozieren.

## Binaries (Top‑Level)
- `main() -> anyhow::Result<()>` ist erlaubt. Fehler werden am Programmende sauber geloggt und mit non‑zero Exit beendet.
- Keine Panics im Top‑Level. Keine `unwrap` in CLI‑Parsing/IO.

## CI/Clippy‑Durchsetzung
- Clippy als Pflicht in CI, mit o. g. Lints.
- Zusätzlich sinnvoll: `clippy::result_large_err`, `clippy::redundant_closure_for_method_calls` (Qualität), aber nicht hart.

## Migrationsleitfaden (kurz)
1. Crate‑Roots mit `#![deny(...)]` ausstatten (Prod‑Crates).  
2. `panic = "abort"` in Workspace‑`Cargo.toml` setzen.  
3. `unwrap/expect` eliminieren, Fehler sauber propagieren.  
4. Fehler‑Enums je Domäne erstellen, Mapping vereinheitlichen.  
5. Logs/Metriken ergänzen, Lärm rate‑limitieren.  
6. CI: Clippy‑Gate aktivieren.  
7. Tests/Fuzz: Stark auf Codec/UTXO/Konsens‑Transitions.

## Beispiele: Anti‑Pattern → Korrekt
- Serialisierung
```rust
// Anti‑Pattern
let mut v = Vec::new();
writer.write_all(&v).unwrap();

// Korrekt
writer.write_all(&v).map_err(CodecError::Io)?;
```

- Slice‑Zugriff
```rust
// Anti‑Pattern
let tag = buf[0];

// Korrekt
let tag = *buf.get(0).ok_or(CodecError::Truncated)?;
```

- Thread Join
```rust
// Anti‑Pattern
handle.join().unwrap();

// Korrekt
handle.join().map_err(|_| RuntimeError::WorkerPanicked)?;
```

Beispiel: `RuntimeError`
```rust
#[derive(Debug)]
pub enum RuntimeError {
    WorkerPanicked,
}

impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkerPanicked => write!(f, "worker thread panicked"),
        }
    }
}

impl core::error::Error for RuntimeError {}
```

---

Dieses Dokument ist verbindlich. Abweichungen nur per RFC/Review. Alle neuen Crates/Module müssen die Lints und Profile übernehmen. 
