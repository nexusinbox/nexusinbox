-- Address book. Each user keeps their own notes about DIDs they
-- talk to: who owns the DID, what role the agent plays, and an
-- optional free-form memo. Used by the UI to replace opaque DID
-- strings with human-friendly names. Recipient lookups still go
-- through the DID itself; contacts only decorate the display.
CREATE TABLE IF NOT EXISTS contacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  did TEXT NOT NULL,
  person_name TEXT NOT NULL,
  agent_label TEXT,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT contacts_owner_did_unique UNIQUE(owner_user_id, did)
);

CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_user_id);
