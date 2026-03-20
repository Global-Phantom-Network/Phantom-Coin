# SPDX-License-Identifier: AGPL-3.0-only
# Multi-stage build: build Rust binary, then minimal runtime image

# 1) Builder (multi-arch capable)
ARG BASE_RUNTIME=debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421
ARG BASE_BUILDER=rust:1-bookworm@sha256:ca8d52cf3eadfe814328f1cff05e3f0022b4cf696ddc8498ef26b52f71b201ad
FROM ${BASE_BUILDER} AS builder
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang libclang-dev llvm-dev && \
    ln -sf "$(llvm-config --libdir)/libclang.so" /usr/local/lib/libclang.so && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY . .

# Determinism: allow passing SOURCE_DATE_EPOCH and RUSTFLAGS from buildx
ARG SOURCE_DATE_EPOCH=0
ARG RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none"
ENV TZ=UTC \
    LC_ALL=C \
    LIBCLANG_PATH=/usr/local/lib \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    RUSTFLAGS=${RUSTFLAGS}

# Build only phantom-node binary in release mode (locked)
# (buildx sets the container arch according to target platform)
RUN cargo build --release --locked -p phantom-node

# 2) Runtime
FROM ${BASE_RUNTIME} AS runtime
# Deterministic created label may be overridden by buildx labels
ARG IMAGE_CREATED="1970-01-01T00:00:00Z"
LABEL org.opencontainers.image.source="https://github.com/Global-Phantom-Network/Phantom-Coin"
LABEL org.opencontainers.image.description="Phantom Node (multi-arch linux/amd64,linux/arm64)"
LABEL org.opencontainers.image.created=${IMAGE_CREATED}

# Create non-root user (no home directory for reproducibility)
RUN useradd -M -u 10001 -U phantom && \
    install -d -o phantom -g phantom /data /data/mempool && \
    touch -m -d @0 /etc/passwd /etc/group /data /data/mempool

# Copy binary
COPY --from=builder /app/target/release/phantom-node /usr/local/bin/phantom-node
COPY --from=builder /app/data/genesis_note.bin /usr/local/share/phantom-coin/genesis_note.bin
# Normalize mtime for reproducible layers
RUN touch -m -d @0 /usr/local/bin/phantom-node /usr/local/share/phantom-coin/genesis_note.bin

# Optional: Expose metrics port (adjust if needed)
EXPOSE 9100

ENV TZ=UTC LC_ALL=C
USER 10001
ENTRYPOINT ["/usr/local/bin/phantom-node"]
CMD ["--help"]
