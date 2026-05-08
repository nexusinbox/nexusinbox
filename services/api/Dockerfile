# syntax=docker/dockerfile:1.7
#
# NexusInbox API production image.
#
# Targets Fly.io (docs/18 §3.3). Multi-stage build keeps the runtime image
# small by leaving the ~1.5 GB Rust toolchain in the builder stage.
#
# The API reads runtime config from environment variables only — no files
# are baked in — so the same image works in staging and production once
# fly secrets are set.

# ---- Build stage ------------------------------------------------------------
FROM --platform=linux/amd64 rust:1.90-bookworm AS builder
WORKDIR /build

# Copy all sources and do the full build.
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY migrations/ migrations/
RUN cargo build --release --locked --bin nexusinbox-api

# Strip the binary to shave a few MB off the runtime layer.
RUN strip target/release/nexusinbox-api

# ---- Runtime stage ----------------------------------------------------------
FROM --platform=linux/amd64 debian:bookworm-slim AS runtime

# ca-certificates: TLS trust for Supabase + R2.
# libssl3: reqwest/rustls actually uses aws-lc-rs but some transitive deps
#          may still link against libssl — harmless to include.
# curl:    used by the HEALTHCHECK below and for quick container-side debugging.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary and migrations. Migrations are embedded via sqlx::migrate!()
# so they ship as part of the binary, but we also copy them so operators can
# inspect the applied schema from inside the container.
COPY --from=builder /build/target/release/nexusinbox-api /usr/local/bin/nexusinbox-api
COPY --from=builder /build/migrations/ /app/migrations/

WORKDIR /app

# Default port — Fly.io will route its internal_port (see fly.toml) to this.
ENV PORT=8080
EXPOSE 8080

# Drop root. The binary doesn't need any privileged capability.
RUN groupadd --system app \
    && useradd --system --gid app --home /app --shell /usr/sbin/nologin app \
    && chown -R app:app /app
USER app:app

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/health || exit 1

ENTRYPOINT ["nexusinbox-api"]
