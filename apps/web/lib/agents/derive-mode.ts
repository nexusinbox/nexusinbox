// Pure helper for the agent mode badge + Bridge-panel gate. Lives
// outside the page component so the priority rules can be unit-tested
// in isolation; both the badge in `<AgentModePanel>` and the gate in
// `<BridgeTokenPanel>` import from here so they cannot drift.
//
// Spec:
//   1. Any active `web_keystore` → "standard"
//      (browser holds a key → user can decrypt locally)
//   2. Any active `signer_daemon` → "daemon_isolated"
//      (key lives only in the daemon → Web UI needs Bridged restore)
//   3. Else (only `unknown` rows or no active rows) → "default"
//      (pre-migration / nothing activated → fall back to Standard UX
//      while signalling the unconfirmed state via a separate hint)
//
// docs/21_message_visibility_ux_for_mcp_modes.md §7 captures the UX
// rationale for the priority ordering.

import type { AgentCredential } from "../api/types";

export type AgentMode = "standard" | "daemon_isolated" | "default";

export function deriveAgentMode(
  aid: string,
  credentials: AgentCredential[],
): AgentMode {
  const active = credentials.filter(
    (cred) => cred.aid === aid && cred.status === "active",
  );
  // Priority 1: any web_keystore wins.
  if (active.some((cred) => cred.key_holder === "web_keystore")) {
    return "standard";
  }
  // Priority 2: any signer_daemon wins. Use `some`, not `every` — the
  // common transition state (one MCP --init credential tagged 'unknown'
  // alongside a freshly bootstrapped Isolated credential) must still
  // resolve to "daemon_isolated" so the Bridge panel surfaces and the
  // user can pair / decrypt. The earlier `every` form silently hid the
  // panel until every legacy credential was revoked, which is the
  // opposite of helpful.
  if (active.some((cred) => cred.key_holder === "signer_daemon")) {
    return "daemon_isolated";
  }
  return "default";
}
