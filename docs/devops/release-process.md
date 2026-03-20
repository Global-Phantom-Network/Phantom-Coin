# Release‑Prozess (deterministisch)

Dieser Leitfaden beschreibt, wie Releases reproduzierbar (ohne Unix‑Zeitstempel) erstellt, verifiziert, signiert und veröffentlicht werden.

## Versionierung & Tags
- Verwende SemVer‑Tags: `vX.Y.Z`
- Jede Änderung am Release‑Prozess erfolgt über PR + Review.

## CI‑Pipelines
- Workflow: `.github/workflows/release.yml`
  - Builds für Linux/macOS (x86_64/arm64)
  - Repro‑Artefakte: tar.gz mit `mtime=0`, sortiert, Owner/GID=0; `SHA256SUMS`
  - GHCR Image: deterministische Labels (`created=1970-01-01T00:00:00Z`), provenance/sbom disabled
  - Cosign (keyless) Signierung des GHCR‑Images
- Repro‑Check: `.github/workflows/repro-check.yml` – baut 2× und vergleicht Hashes
- Build‑Time‑Schutz: `.github/workflows/no-build-time.yml` – verbietet Zeitinjektion in `build.rs` und vergen/built

## Manuelles Release (lokal)
```bash
GIT_TAG=vX.Y.Z
# 1) Checkout
git fetch --tags && git checkout "$GIT_TAG"

# 2) Workspace-Hygiene prüfen
bash scripts/security/scan_runtime_artifacts.sh

# 3) Repro‑Env
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=0
export RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none --remap-path-prefix=$PWD=."
rustup override set 1.81.0

# 4) Build (locked/frozen)
cargo build --workspace --release --locked --frozen

# 5) Package
bash scripts/release/repro_package.sh \
  --bin target/release/phantom-node \
  --docs ./docs \
  --out phantomcoin-${GIT_TAG}-linux-x86_64.tar.gz

# 6) Hash
sha256sum phantomcoin-${GIT_TAG}-linux-x86_64.tar.gz > SHA256SUMS
```

## Verifikation
- Lade Release‑Artefakte herunter und prüfe Hash:
```bash
sha256sum -c SHA256SUMS
```
- Docker: verifiziere Digest aus `IMAGES_DIGESTS.txt`:
```bash
docker pull ghcr.io/<org>/phantom-node@sha256:<digest>
```

## Signierung (Container)
- Cosign keyless via CI (`sign-images` Job)
- Optional: zusätzliche Supply‑Chain Policies (Rekor, Attestations)

## Hinweise
- Keine Buildzeit in Binaries/Archiven.
- Pfade normalisiert (`--remap-path-prefix`).
- Repro‑Artefakte unabhängig von Host‑Zeit und Zeitzone.
- Runtime-Daten, Keystores und `.git/` dürfen nie durch „Ordner zippen“ veröffentlicht werden; offizielle Artefakte entstehen nur über den Staging-Pfad in `scripts/release/repro_package.sh`.
