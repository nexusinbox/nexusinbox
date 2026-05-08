-- Phase 4.4a: per-agent auto-reply policy storage.
-- See docs/25_auto_reply_engine_design.md §2.2 for the design decision.
--
-- Scope: this migration only adds the storage table. The evaluator
-- (4.4b), executor (4.4c), Calendar integration (4.4d), and LLM
-- integration (4.4e) land in later phases. Until then, inserting
-- a row here records the user's intent without triggering any
-- automated behaviour — `agents.auto_reply` (BOOLEAN) from
-- 0001_init.sql stays the master on/off switch.
--
-- Rollback: DROP TABLE agent_auto_reply_policies CASCADE.

CREATE TABLE IF NOT EXISTS agent_auto_reply_policies (
    agent_id           UUID PRIMARY KEY
                            REFERENCES agents(id) ON DELETE CASCADE,
    -- Matches the policy JSON's top-level `v` field. Per-type
    -- bumps (schema breaking change) are tracked separately from
    -- the row-level optimistic lock below.
    schema_version     INT NOT NULL DEFAULT 1,
    -- Row-level revision for optimistic concurrency. Incremented
    -- on every PUT. Clients submit the value via If-Match / body
    -- and receive 409 on mismatch. See docs/25 §6.
    revision           BIGINT NOT NULL DEFAULT 1,
    -- Declarative policy DSL. Schema enforced client + server
    -- side; the DB only promises JSONB. See docs/25 §5.
    policy             JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by_user_id UUID NOT NULL REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Query patterns:
-- - "who last touched this agent's policy?" (audit cross-ref)
CREATE INDEX IF NOT EXISTS idx_agent_auto_reply_policies_updated_by
    ON agent_auto_reply_policies(updated_by_user_id);

-- - "list recently-updated policies" (future admin / monitoring)
CREATE INDEX IF NOT EXISTS idx_agent_auto_reply_policies_updated_at
    ON agent_auto_reply_policies(updated_at DESC);
