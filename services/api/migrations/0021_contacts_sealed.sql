-- 0021_contacts_sealed.sql
--
-- Contact names and notes sealed on the person's device (docs/28 P3-8).
--
-- contacts.sealed: AES-GCM ciphertext of {person_name, agent_label, note}
-- under the person's contacts key, bound to the contact's DID. The server
-- keeps only the DID in the clear (the auto-reply policy needs it). The
-- plaintext columns stay until the web has re-sealed existing rows; new
-- writes only set `sealed`.
--
-- contact_key_wraps: the contacts key, wrapped (X25519 with its own HKDF
-- info) to each of the person's agents' encryption keys, so any device
-- that holds one of those agent keys can open the address book.

ALTER TABLE contacts ADD COLUMN IF NOT EXISTS sealed TEXT;
ALTER TABLE contacts ALTER COLUMN person_name DROP NOT NULL;

CREATE TABLE IF NOT EXISTS contact_key_wraps (
    agent_id    UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contact_key_wraps_user ON contact_key_wraps(user_id);
