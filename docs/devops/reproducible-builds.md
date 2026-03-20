# Reproducible Builds (deterministisch, ohne Unix-Time)

Ziel: Aus demselben Commit-Tag immer identische Artefakte (Byte-gleich) erzeugen.

## Anforderungen
- Git-Tag: `vX.Y.Z`
- Rust-Toolchain: exakt `1.81.0`
- `Cargo.lock` committed
- Zeit/Locale fixiert: `TZ=UTC`, `LC_ALL=C`, `SOURCE_DATE_EPOCH=0`
- Keine Build-IDs/Debug-Infos, Pfade normalisiert

## Compiler-/Linker-Flags
- `RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none --remap-path-prefix=$PWD=."`
- Release-Profile bereits gesetzt: `lto = "fat"`, `codegen-units = 1`, `opt-level = 3` in `Cargo.toml`

## Repro-Schritte (Linux/macOS)
```bash
# 1) Clean checkout (genauer Tag)
GIT_TAG=vX.Y.Z
git fetch --tags
git checkout "$GIT_TAG"

# 2) Env für Repro
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=0
export RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none --remap-path-prefix=$PWD=."

# 3) Exakte Toolchain
rustup override set 1.81.0

# 4) Build (locked + frozen)
cargo build --workspace --release --locked --frozen

# 5) Paketierung (repro-tar/gzip)
mkdir -p dist
cp target/release/phantom-node dist/
cp -r docs dist/docs
# GNU tar empfohlen (macOS: `brew install gnu-tar`)
(tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C dist -cf - . | gzip -n) \
  > phantomcoin-${GIT_TAG}-linux-x86_64.tar.gz

# 6) Hash erzeugen
sha256sum phantomcoin-${GIT_TAG}-linux-x86_64.tar.gz > SHA256SUMS
```

## Docker (multi-arch) reproduzierbar bauen
```bash
# Buildx vorbereiten
export DOCKER_BUILDKIT=1
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none"

docker buildx create --use --name repro || true

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --build-arg RUSTFLAGS="$RUSTFLAGS" \
  --provenance=false --sbom=false \
  --label org.opencontainers.image.created=1970-01-01T00:00:00Z \
  -t ghcr.io/<owner>/phantom-node:${GIT_TAG} \
  --load .
```

## Verifikation
- Vergleiche `sha256sum` aus GitHub Release `SHA256SUMS` mit lokal erzeugtem Hash.
- Archiv sollte Byte-gleich sein (identische Größe + Hash).

## Hinweise
- Build ist deterministisch; Runtime nutzt Zeitfunktionen (z. B. Rate-Limiter) – das berührt die Reproduzierbarkeit nicht.
- Keine Unix-Zeitstempel in Archiven (Tar `--mtime=@0`, Gzip `-n`, Owner=0, sortierte Einträge).
- Pfade via `--remap-path-prefix` normalisiert.
