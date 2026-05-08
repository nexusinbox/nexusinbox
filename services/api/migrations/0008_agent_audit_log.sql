-- Audit log for non-interactive agent access events.
-- See docs/15_non_interactive_agent_access_design.md §10.
-- All logs are structured (no free-text concatenation) to prevent log injection.

CREATE TABLE IF NOT EXISTS agent_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   UUID REFERENCES agent_credentials(id) ON DELETE SET NULL,
    aid             TEXT,
    event           TEXT NOT NULL,
    -- Structured detail fields (no user-input concatenation)
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Query pattern: list events for a user, newest first
CREATE INDEX IF NOT EXISTS idx_agent_audit_log_user
    ON agent_audit_log(user_id, created_at DESC);

-- Query pattern: events for a specific credential
CREATE INDEX IF NOT EXISTS idx_agent_audit_log_credential
    ON agent_audit_log(credential_id, created_at DESC);

-- Query pattern: security-relevant events (compromised, reuse, etc.)
CREATE INDEX IF NOT EXISTS idx_agent_audit_log_event
    ON agent_audit_log(event) WHERE event IN (
        'refresh_reuse_detected',
        'credential_compromised',
        'policy_violation',
        'rate_limit_tripped'
    );
