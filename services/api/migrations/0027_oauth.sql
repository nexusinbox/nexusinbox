-- 0027_oauth.sql
--
-- OAuth 2.1 for cloud AIs that reach a person's computer over MCP
-- (docs/33 §10). The API is the authorization server; the computer's
-- gateway is the resource server and checks tokens by introspection.
--
-- mcp_resources: the MCP URL of a person's computer, tied to one agent.
-- oauth_clients: AI apps, registered dynamically (RFC 7591) or known by
--   their client metadata document URL.
-- oauth_grants: who let which app use which agent, with what scope.
-- oauth_codes / oauth_tokens: hashes only, never the values.

CREATE TABLE IF NOT EXISTS mcp_resources (
    resource       TEXT PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    aid            TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    credential_id  UUID REFERENCES agent_credentials(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_resources_credential ON mcp_resources(credential_id);

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id      TEXT PRIMARY KEY,
    client_name    TEXT NOT NULL,
    redirect_uris  TEXT[] NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('registered', 'metadata_document')),
    fetched_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_grants (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    aid            TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    resource       TEXT NOT NULL,
    scope          TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_oauth_grants_user ON oauth_grants(user_id);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash       TEXT PRIMARY KEY,
    grant_id        UUID NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    redirect_uri    TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id            UUID NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    access_hash         TEXT NOT NULL UNIQUE,
    refresh_hash        TEXT NOT NULL UNIQUE,
    access_expires_at   TIMESTAMPTZ NOT NULL,
    refresh_expires_at  TIMESTAMPTZ NOT NULL,
    rotated_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_grant ON oauth_tokens(grant_id);
