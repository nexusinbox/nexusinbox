-- 0023_agent_credentials_enrollment_hash_index.sql
--
-- Pairing codes (docs/31): POST /agent-pairing/resolve finds a pending
-- credential by the hash of its code instead of by its id. Only pending
-- credentials keep an enrollment hash (activation clears it), so the
-- index stays small.

CREATE INDEX IF NOT EXISTS idx_agent_credentials_enrollment_hash
    ON agent_credentials(enrollment_hash) WHERE enrollment_hash IS NOT NULL;
