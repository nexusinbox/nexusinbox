-- 0020_user_identities_and_human_limits.sql
--
-- Provider-agnostic identities and per-human limits (docs/30).
--
-- user_identities: one row per (provider, subject) a person has proven.
-- UNIQUE (provider, subject_hash) is the "one proof, one account" rule.
-- subject_hash is base64url(SHA-256(provider-scoped identifier)); the raw
-- identifier is never stored. For World ID it equals the existing
-- users.world_id_hash, so recorded human-level blocks keep matching.

CREATE TABLE IF NOT EXISTS user_identities (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,
    subject_hash     TEXT NOT NULL,
    assurance        TEXT NOT NULL CHECK (assurance IN ('high', 'medium')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, subject_hash)
);

CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities(user_id);

INSERT INTO user_identities (user_id, provider, subject_hash, assurance, created_at, last_verified_at)
SELECT id, 'world_id', world_id_hash, 'high', created_at, created_at
FROM users
WHERE world_id_hash IS NOT NULL
ON CONFLICT (provider, subject_hash) DO NOTHING;

-- Stop keeping raw World ID nullifiers.
ALTER TABLE users ALTER COLUMN nullifier_hash DROP NOT NULL;
UPDATE users SET nullifier_hash = NULL WHERE nullifier_hash IS NOT NULL;

-- A person proven by another provider has no World ID hash.
ALTER TABLE users ALTER COLUMN world_id_hash DROP NOT NULL;

-- Per-person daily send counter, shared by the person's sessions and all
-- of their agents. Incremented atomically; old days are removed by the
-- retention job.
CREATE TABLE IF NOT EXISTS user_send_counters (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day     DATE NOT NULL,
    sent    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
