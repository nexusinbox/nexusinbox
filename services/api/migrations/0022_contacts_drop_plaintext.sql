-- 0022_contacts_drop_plaintext.sql
--
-- Contacts keep only the DID and the fields sealed on the person's device
-- (docs/28 P3-8, migration 0021). Every row has been re-sealed (checked on
-- production on 2026-11-07: no row without `sealed`), so the plaintext
-- columns go, and a row without sealed fields can no longer be written.

ALTER TABLE contacts
    DROP COLUMN IF EXISTS person_name,
    DROP COLUMN IF EXISTS agent_label,
    DROP COLUMN IF EXISTS note;

ALTER TABLE contacts ALTER COLUMN sealed SET NOT NULL;
