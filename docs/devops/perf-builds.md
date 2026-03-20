# Performance‑Builds (deterministisch, ohne Unix‑Zeit)

Ziel: Maximale TPS durch CPU‑optimierte Builds – getrennt vom generischen Repro‑Artefakt. Beide Tracks bleiben deterministisch.

## Varianten
- x86_64 (Skylake/AVX2): `-C target-cpu=skylake -C target-feature=+avx2`
- ARM64 (Neoverse‑N1): `-C target-cpu=neoverse-n1`

## CI‑Jobs
- Siehe `.github/workflows/release.yml` → `build-perf-linux-x86_64`, `build-perf-linux-aarch64`
- Artefakte: `phantomcoin-<tag>-linux-x86_64-perf-skylake.tar.gz`, `...-linux-aarch64-perf-neoverse-n1.tar.gz`
- Packaged wie Repro: sortiert, `mtime=0`, `gzip -n`

## Lokal bauen (x86_64 Skylake)
```bash
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=0
export RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none -C target-cpu=skylake -C target-feature=+avx2 --remap-path-prefix=$PWD=."
rustup override set 1.81.0
cargo build --workspace --release --locked --frozen
```

## Lokal bauen (ARM64 Neoverse‑N1)
```bash
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=0
export RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none -C target-cpu=neoverse-n1 --remap-path-prefix=$PWD=."
rustup override set 1.81.0
rustup target add aarch64-unknown-linux-gnu
cargo build --workspace --release --locked --frozen --target aarch64-unknown-linux-gnu
```

## Hinweise
- Zielplattform muss zur Hardware passen (sonst Performanceverlust/Illegal Instruction).
- Für Benchmarking/CI korreliert mit `benches-agg`/`benches-nightly`: gleiche Flags/Toolchain verwenden.
- Repro‑Track und Perf‑Track sind getrennt; beide deterministisch innerhalb je Track.
