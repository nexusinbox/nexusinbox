-- 0028_cloud_access.sql
--
-- Cloud AIs reach a person's computer through the relay only while the
-- person has turned it on for that computer (docs/33 §12). Off by default.
--
-- cloud_access_enabled_at: when the person turned it on (NULL = off). The
--   API issues relay tickets only while it is set.
-- cloud_serving_at: when the computer last said it is reachable through the
--   relay (connected, with its certificate). The page shows "ready" while
--   this is recent.
ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS cloud_access_enabled_at TIMESTAMPTZ;
ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS cloud_serving_at TIMESTAMPTZ;
