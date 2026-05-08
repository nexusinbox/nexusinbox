CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  world_id_hash TEXT NOT NULL UNIQUE,
  nullifier_hash TEXT NOT NULL UNIQUE,
  verification_level TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  did TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  public_key TEXT NOT NULL,
  encryption_key TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  auto_reply BOOLEAN NOT NULL DEFAULT FALSE,
  unread_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_user_id ON agents(user_id);

CREATE TABLE IF NOT EXISTS message_index (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_did TEXT NOT NULL,
  recipient_did TEXT NOT NULL,
  thread_id UUID,
  subject_encrypted TEXT NOT NULL,
  storage_ref TEXT NOT NULL,
  status TEXT NOT NULL,
  priority TEXT NOT NULL,
  ai_category TEXT,
  trust_score REAL NOT NULL DEFAULT 0.5,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_message_index_owner_created_at
  ON message_index(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_message_index_owner_recipient
  ON message_index(owner_user_id, recipient_did);

CREATE TABLE IF NOT EXISTS sessions (
  session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  jwt_id TEXT UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS replay_nonces (
  id BIGSERIAL PRIMARY KEY,
  scope TEXT NOT NULL,
  replay_key TEXT NOT NULL,
  seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE(scope, replay_key)
);

CREATE INDEX IF NOT EXISTS idx_replay_nonces_expires_at ON replay_nonces(expires_at);
