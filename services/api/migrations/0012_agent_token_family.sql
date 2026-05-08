-- Token family tracking for refresh-rotation reuse detection.
--
-- Refresh rotation issues a new (access_token, refresh_token) pair and
-- marks the old refresh token as revoked. The entire chain — the
-- original RT and every descendant born from a rotation of it — is a
-- "token family". When refresh reuse is detected (a caller replays a
-- refresh_token that was already rotated), every live token in the
-- same family must be revoked in one atomic step, not just the
-- presenting token. This column gives us a grouping key for that.
--
-- Design notes:
--   - DEFAULT gen_random_uuid() means every row INSERTed without an
--     explicit token_family_id is treated as a brand-new family. That
--     matches fresh issuance via POST /agent-auth/token.
--   - Refresh rotation MUST pass the parent row's token_family_id
--     explicitly so descendants share the grouping key.
--   - Existing rows (issued before this migration) each get their own
--     family via the DEFAULT. That's the correct behavior: their
--     provenance is unknown, so we treat every legacy token as its
--     own singleton family.
--   - Index on (credential_id, token_family_id) supports the two hot
--     queries: "revoke every live token in this family" and "show me
--     the family tree for this credential" (future admin UI).

ALTER TABLE agent_tokens
    ADD COLUMN IF NOT EXISTS token_family_id UUID NOT NULL DEFAULT gen_random_uuid();

CREATE INDEX IF NOT EXISTS idx_agent_tokens_family
    ON agent_tokens(token_family_id) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_agent_tokens_credential_family
    ON agent_tokens(credential_id, token_family_id);
