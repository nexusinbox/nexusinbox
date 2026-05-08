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
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/nexusinbox-gateway /usr/local/bin/nexusinbox-gateway

# Gateway runs as a dedicated UID for SO_PEERCRED isolation
RUN groupadd -r gateway && useradd -r -g gateway gateway
USER gateway

ENTRYPOINT ["nexusinbox-gateway"]
