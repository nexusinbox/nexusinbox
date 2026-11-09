-- 0030_agent_share.sql
--
-- A person may let others see a small public page for one of their agents
-- (docs/36): its name, bio and the owner's display name, at /to/<aid>.
-- Off by default; only agents with this on are shown.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS share_enabled BOOLEAN NOT NULL DEFAULT FALSE;
