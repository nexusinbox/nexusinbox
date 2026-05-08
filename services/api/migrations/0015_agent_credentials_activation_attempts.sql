-- 0015_agent_credentials_activation_attempts.sql
--
-- Track failed `POST /agent-credentials/:id/activate` attempts per
-- credential so an attacker who learned a credential UUID can't
-- brute-force the 43-char enrollment secret / forge the enrollment
-- proof indefinitely. Once the counter hits
-- `ACTIVATION_MAX_FAILED_ATTEMPTS` (see services/api/src/lib.rs) the
-- server auto-revokes the credential — the legitimate owner just
-- issues a fresh one.
--
-- Threat model (security-audit P2 #9):
--   - Without this column the only control was the 30-minute TTL on
--     `enrollment_expires` plus the 60 req/min per-IP global budget.
--     With a handful of leaked credential UUIDs (audit log spill,
--     log aggregator exposure) an attacker got 30 minutes of
--     unlimited tries at each.
--   - A per-credential counter is a cheap guardrail against that
--     class of mistake: even if the UUID leaks, the attacker gets
--     at most N attempts before the credential is burned.
--
-- Nullable design:
--   - INT NOT NULL DEFAULT 0 so every row has a counter; the handler
--     can always `UPDATE … SET failed_activation_attempts =
--     failed_activation_attempts + 1 … RETURNING failed_activation_attempts`
--     without needing a COALESCE. Rows already active / revoked keep
--     the default 0 and ignore the field.

ALTER TABLE agent_credentials
    ADD COLUMN IF NOT EXISTS failed_activation_attempts INT NOT NULL DEFAULT 0;
