-- Drafts signed with envelope signature v2 (docs/40 §14.4). The computer
-- wraps the content key for every device of both agents when it makes the
-- draft and signs the whole envelope, so approving only sends it. Older
-- computers keep sending v1 drafts (signature only, wraps added by the
-- approving browser).

ALTER TABLE agent_drafts ALTER COLUMN signature DROP NOT NULL;
ALTER TABLE agent_drafts ADD COLUMN IF NOT EXISTS signature_v2 JSONB;
ALTER TABLE agent_drafts ADD COLUMN IF NOT EXISTS sender_encrypted_key TEXT;
ALTER TABLE agent_drafts ADD COLUMN IF NOT EXISTS encrypted_keys JSONB;
ALTER TABLE agent_drafts ADD COLUMN IF NOT EXISTS sender_encrypted_keys JSONB;
