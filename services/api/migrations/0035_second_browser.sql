-- A second browser that can sign an agent's device list (docs/40 §17.4).
--
-- A browser that can sign shows a pairing link; the new browser makes its
-- own keys for each of the person's agents and sends them here with a MAC
-- under a secret only the two browsers know (the part of the link after
-- `#`, never sent to the server). The keys wait in the pairing until a
-- browser that can sign puts a device list naming them; only then do they
-- become active keys of the agent.

-- Browsers added this way: the server knows them as browsers (signers of a
-- v2 list must be), and shows the name the browser gave itself.
ALTER TABLE agent_identity_keys ADD COLUMN IF NOT EXISTS device_kind TEXT
    CHECK (device_kind IN ('browser'));
ALTER TABLE agent_identity_keys ADD COLUMN IF NOT EXISTS device_label TEXT;

CREATE TABLE IF NOT EXISTS browser_pairings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- sha256 hex of the code part the server sees.
    code_hash   TEXT NOT NULL UNIQUE,
    -- The agents the browser that showed the link will add the new one to.
    aids        TEXT[] NOT NULL,
    -- The new browser's keys and MACs: [{aid, did, signing_public_key,
    -- encryption_public_key, mac}], and its name.
    claimed     JSONB,
    label       TEXT,
    -- The agents' roots, MACed back by the browser that signed: [{aid, mac}].
    root_macs   JSONB,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_browser_pairings_user ON browser_pairings(user_id);

-- The contacts key wrapped to a device's own encryption key, for browsers
-- other than the one each agent was created with (contact_key_wraps holds
-- the wraps to each agent's first key).
CREATE TABLE IF NOT EXISTS contact_key_device_wraps (
    did         TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contact_key_device_wraps_user ON contact_key_device_wraps(user_id);

-- The one browser that runs the agent's automatic replies while its inbox
-- is open (docs/40 §17.6). NULL: the browser the agent was created with.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS auto_reply_device TEXT;
