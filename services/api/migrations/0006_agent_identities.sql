-- Agent Identities: stable logical ID (aid) that survives key rotation.
-- See docs/16_adr_agent_identifier.md for rationale.

CREATE TABLE IF NOT EXISTS agent_identities (
    aid         TEXT PRIMARY KEY,          -- "aid:ai:<ULID>"
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_identities_agent
    ON agent_identities(agent_id);

-- Key history: one aid maps to one or more did:key over time.
CREATE TABLE IF NOT EXISTS agent_identity_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aid                     TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    did                     TEXT NOT NULL UNIQUE,
    signing_public_key      TEXT NOT NULL,
    encryption_public_key   TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','rotating','retired','compromised')),
    external_did            TEXT,              -- reserved for future did:web alias
    activated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at              TIMESTAMPTZ,
    rotation_proof          TEXT               -- JWS: old key signs new key
);

CREATE INDEX IF NOT EXISTS idx_aik_active
    ON agent_identity_keys(aid) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_aik_did
    ON agent_identity_keys(did);

-- Back-fill: create agent_identities + agent_identity_keys rows for every
-- existing agent so that the new tables are immediately consistent.
-- aid is generated as 'aid:ai:' || replace(gen_random_uuid()::text, '-', '')
-- (a deterministic ULID would be ideal but Postgres lacks a built-in; UUID
-- is acceptable for a one-time backfill — new rows created by the app will
-- use proper ULIDs).
INSERT INTO agent_identities (aid, agent_id, user_id, created_at)
SELECT 'aid:ai:' || replace(gen_random_uuid()::text, '-', ''),
       a.id,
       a.user_id,
       a.created_at
FROM agents a
WHERE NOT EXISTS (
    SELECT 1 FROM agent_identities ai WHERE ai.agent_id = a.id
);

INSERT INTO agent_identity_keys (aid, did, signing_public_key, encryption_public_key, status, activated_at)
SELECT ai.aid,
       a.did,
       a.public_key,
       a.encryption_key,
       'active',
       a.created_at
FROM agents a
JOIN agent_identities ai ON ai.agent_id = a.id
WHERE NOT EXISTS (
    SELECT 1 FROM agent_identity_keys aik WHERE aik.did = a.did
);
