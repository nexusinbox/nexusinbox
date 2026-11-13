-- Pairing MACs (docs/40 §13.5). The connect code carries a secret only the
-- browser and the computer know; the server never sees it. When the
-- computer activates it MACs its own keys with the secret, and the root
-- browser MACs the agent's root back for the computer to check. Only the
-- MACs are stored here, and they go with the credential.

ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS pairing_device_mac TEXT;
ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS pairing_root_mac TEXT;
