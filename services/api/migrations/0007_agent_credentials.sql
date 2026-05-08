-- Agent Credentials & Tokens for non-interactive (AI) access.
-- See docs/15_non_interactive_agent_access_design.md (v2) for full design.

-- One credential = one Signer Daemon deployment.
CREATE TABLE IF NOT EXISTS agent_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aid                 TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label               TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','active','revoked','compromised')),
    enrollment_hash     TEXT,              -- hex(sha256(secret)), NULL after activation
    enrollment_expires  TIMESTAMPTZ,
    signing_public_key  TEXT,              -- set on activation
    allowed_scopes      TEXT[] NOT NULL DEFAULT ARRAY['messages.read','messages.send'],
    policy              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_aid
    ON agent_credentials(aid) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_agent_credentials_user
    ON agent_credentials(user_id);

-- Short-lived tokens issued to Signer Daemons.
-- Only sha256 hashes are stored; plaintext is returned once at issuance.
CREATE TABLE IF NOT EXISTS agent_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id       UUID NOT NULL REFERENCES agent_credentials(id) ON DELETE CASCADE,
    access_hash         TEXT NOT NULL,          -- hex(sha256(agt_...))
    refresh_hash        TEXT,                   -- hex(sha256(agr_...)), rotated
    dpop_jkt            TEXT NOT NULL,          -- RFC 7638 JWK thumbprint
    scopes              TEXT[] NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    access_expires_at   TIMESTAMPTZ NOT NULL,
    refresh_expires_at  TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    flagged_at          TIMESTAMPTZ,
    usage_count         INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_tokens_access_hash
    ON agent_tokens(access_hash);

CREATE INDEX IF NOT EXISTS idx_agent_tokens_credential
    ON agent_tokens(credential_id) WHERE revoked_at IS NULL;
