# ---- Build stage ----
FROM rust:1.82-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

COPY src/ src/
RUN cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/nexusinbox-signer /usr/local/bin/nexusinbox-signer

# Signer Daemon runs as a dedicated UID for SO_PEERCRED isolation
RUN groupadd -r signer && useradd -r -g signer signer
USER signer

WORKDIR /home/signer
VOLUME ["/home/signer/keys"]

ENTRYPOINT ["nexusinbox-signer"]
