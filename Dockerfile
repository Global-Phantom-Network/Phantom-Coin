# SPDX-License-Identifier: AGPL-3.0-only
# Multi-stage build: build Rust binary, then minimal runtime image

# 1) Builder (multi-arch capable)
FROM rust:1-bookworm AS builder
WORKDIR /app

# Copy workspace
COPY . .

# Build only phantom-node binary in release mode
# (buildx will set the container arch according to target platform)
RUN cargo build --release -p phantom-node

# 2) Runtime
FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/Global-Phantom-Network/Phantom-Coin"
LABEL org.opencontainers.image.description="Phantom Node (multi-arch linux/amd64,linux/arm64)"

# Create non-root user
RUN useradd -m -u 10001 phantom

# Copy binary
COPY --from=builder /app/target/release/phantom-node /usr/local/bin/phantom-node

# Optional: Expose metrics port (adjust if needed)
EXPOSE 9100

USER 10001
ENTRYPOINT ["/usr/local/bin/phantom-node"]
CMD ["--help"]
