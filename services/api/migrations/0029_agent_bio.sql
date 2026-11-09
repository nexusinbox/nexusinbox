-- 0029_agent_bio.sql
--
-- A one-line description the person writes for their agent, shown on the
-- agent's profile (docs/35 step 3). Plain text; the person's own screens
-- only.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT '';
