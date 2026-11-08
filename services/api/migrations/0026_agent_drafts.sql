-- 0026_agent_drafts.sql
--
-- Drafts that a cloud-hosted AI made through the person's computer, kept
-- until the person approves (sends) or discards them (docs/33 §8, §9).
--
-- review_keys: X25519 public keys of the browsers the person set up to
-- review drafts. The private halves never leave those browsers.
--
-- agent_drafts: a ready-to-send envelope, signed by the agent on the
-- person's computer and encrypted for the recipient, plus the same content
-- key wrapped to each review key (review_wraps). The server cannot read a
-- draft. Rows go when sent or discarded, and expire after 7 days.

CREATE TABLE IF NOT EXISTS review_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key  TEXT NOT NULL,
    label       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, public_key)
);

CREATE TABLE IF NOT EXISTS agent_drafts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    aid               TEXT NOT NULL,
    sender_did        TEXT NOT NULL,
    recipient_did     TEXT NOT NULL,
    thread_id         UUID,
    in_reply_to       UUID,
    subject_encrypted TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    encrypted_key     TEXT NOT NULL,
    nonce             TEXT NOT NULL,
    signature         TEXT NOT NULL,
    content_type      TEXT,
    review_wraps      JSONB NOT NULL,
    via               TEXT,
    sending_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_drafts_owner ON agent_drafts(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_drafts_expires ON agent_drafts(expires_at);
