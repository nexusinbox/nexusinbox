-- Migration 0010: Attachment uploads and message attachments
-- See docs/17_attachment_upload_r2_spec.md
--
-- Design principles:
-- - attachments are stored in R2 as encrypted opaque blobs
-- - server never sees filename, content-type, or plaintext hash
-- - server only tracks lifecycle state, ciphertext size, and ownership

CREATE TABLE IF NOT EXISTS attachment_uploads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_did TEXT,
  draft_id TEXT,
  r2_bucket TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  ciphertext_size_limit BIGINT NOT NULL,
  ciphertext_size_bytes BIGINT,
  status TEXT NOT NULL CHECK (
    status IN ('issued', 'uploaded', 'attached', 'deleted', 'expired', 'quarantined')
  ),
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  upload_expires_at TIMESTAMPTZ NOT NULL,
  uploaded_at TIMESTAMPTZ,
  attached_message_id UUID,
  deleted_at TIMESTAMPTZ,
  last_verified_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_attachment_uploads_owner
  ON attachment_uploads(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_attachment_uploads_status
  ON attachment_uploads(status);
-- For orphan GC: find expired intents quickly
CREATE INDEX IF NOT EXISTS idx_attachment_uploads_expires
  ON attachment_uploads(upload_expires_at) WHERE status IN ('issued', 'uploaded');

CREATE TABLE IF NOT EXISTS message_attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id UUID NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,
  attachment_upload_id UUID NOT NULL REFERENCES attachment_uploads(id) ON DELETE RESTRICT,
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_did TEXT NOT NULL,
  recipient_did TEXT NOT NULL,
  -- Encrypted metadata contains: filename, mime, plaintext_size, cipher_nonce,
  -- attachment_key_wraps (both sender and recipient), sha256_plaintext
  metadata_encrypted TEXT NOT NULL,
  metadata_nonce TEXT NOT NULL,
  ciphertext_size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_message_attachments_message
  ON message_attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_message_attachments_upload
  ON message_attachments(attachment_upload_id);
