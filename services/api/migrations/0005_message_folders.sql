-- Extend message_index with folder/starred state so the inbox UI
-- can route messages into Gmail-style buckets (inbox, sent, drafts,
-- archive, spam, trash, pending_approval) and persist per-message
-- star flags without inventing a separate state table yet.

ALTER TABLE message_index
  ADD COLUMN IF NOT EXISTS folder TEXT NOT NULL DEFAULT 'inbox',
  ADD COLUMN IF NOT EXISTS starred BOOLEAN NOT NULL DEFAULT FALSE;

-- Pre-existing rows were all inbox receipts; leave them in 'inbox'.
-- New outgoing duplicates will be inserted with folder='sent' so that
-- the sender sees their own copy in the 送信済み view.

CREATE INDEX IF NOT EXISTS idx_message_index_owner_folder
  ON message_index(owner_user_id, folder, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_message_index_owner_starred
  ON message_index(owner_user_id, starred)
  WHERE starred = TRUE;
