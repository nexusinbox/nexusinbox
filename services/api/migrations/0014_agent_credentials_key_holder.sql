-- 0014_agent_credentials_key_holder.sql
--
-- Record how each credential's private key material is held, so the
-- Web UI can distinguish Mode B (web_keystore) from Mode A
-- (signer_daemon) credentials and give the user a truthful message
-- visibility UX. Driven by docs/21_message_visibility_ux_for_mcp_modes.md
-- §7 — the browser-only `hasRecipientPrivateKey` heuristic already
-- covers the core UX fix, but `key_holder` lets the server tell the
-- compose screen "this recipient runs daemon-only" without the client
-- having to probe each recipient's keystore, and feeds the per-
-- credential badge in /settings/agents.
--
-- Values (kept in lockstep with the @agent-inbox/core `AgentKeyHolder`
-- enum — both ends must stay frozen):
--
--   - 'web_keystore'   → keys in browser IndexedDB / in-memory keyring
--                        (Mode B, default for credentials created via
--                        the web UI)
--   - 'signer_daemon'  → keys held at rest by a local Signer Daemon
--                        (Mode A, e.g. bootstrap-mode-a.mjs)
--   - 'unknown'        → legacy credential with no recorded hint.
--                        Web UI falls back to Mode-B rendering so
--                        existing rows don't spontaneously flip to
--                        "Daemon-isolated" (see
--                        `deriveMessageState` in @agent-inbox/core).
--
-- Default `'unknown'` is intentional: we can't retroactively tell
-- whether a pre-migration credential was minted in the browser or via
-- a daemon bootstrap. Clients that care ship a fresh value on their
-- next activation.

ALTER TABLE agent_credentials
    ADD COLUMN IF NOT EXISTS key_holder TEXT NOT NULL DEFAULT 'unknown'
        CHECK (key_holder IN ('web_keystore', 'signer_daemon', 'unknown'));
