# syntax=docker/dockerfile:1.7
#
# NexusInbox MCP relay (docs/33 §11). Passes TLS for <id>.mcp.agent-inbox.ai
# through untouched; ends TLS only for relay.agent-inbox.ai, with its own
# Let's Encrypt certificate kept on the /data volume.

FROM --platform=linux/amd64 rust:1.90-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked --bin nexusinbox-relay \
    && strip target/release/nexusinbox-relay

FROM --platform=linux/amd64 debian:bookworm-slim AS runtime
RUN groupadd --system app \
    && useradd --system --gid app --home /nonexistent --shell /usr/sbin/nologin app
COPY --from=builder /build/target/release/nexusinbox-relay /usr/local/bin/nexusinbox-relay
EXPOSE 8443
# The Fly volume mounts root-owned: hand it to the app user, then drop root.
ENTRYPOINT ["/bin/sh", "-c", "mkdir -p /data/acme && chown -R app:app /data && chmod 700 /data/acme && exec setpriv --reuid=app --regid=app --init-groups /usr/local/bin/nexusinbox-relay"]
