/**
 * Browser-safe visibility-state helpers.
 *
 * Kept isolated from `@nexusinbox/core/src/index.ts` so that Web UI
 * code can `import { deriveMessageState } from "@nexusinbox/core/visibility"`
 * without pulling in the Node-only API client (which imports
 * `node:crypto` + `node:net`) and blowing up webpack during the
 * Next.js browser bundle.
 *
 * Stays 100% pure — no side effects, no runtime imports. MCP runtime
 * (Node) re-exports these through `./index.ts`, so both environments
 * share a single definition.
 */

/**
 * Where the recipient agent's X25519 private key actually lives.
 *
 * - `web_keystore` → browser IndexedDB / in-memory keyring. Default for
 *   credentials activated from the Web UI (Standard mode).
 * - `signer_daemon` → at-rest encrypted file held by the Signer Daemon
 *   process only. Isolated mode credentials activated via
 *   `templates/agent-runtime-node/bootstrap-mode-a.mjs` or equivalent.
 * - `unknown` → pre-existing credential with no recorded hint.
 *   Callers should fall back to Standard mode behaviour for display purposes
 *   (i.e. "assume the browser has the key, try to decrypt, fall back to
 *   `decrypt_failed` if it can't").
 *
 * See docs/21_message_visibility_ux_for_mcp_modes.md §7.
 */
export type AgentKeyHolder = "web_keystore" | "signer_daemon" | "unknown";

/**
 * Visibility state of a single message for the current browser session.
 * Drives the Web UI's state machine in apps/web and (as a trivial
 * always-`readable` case) the Isolated mode MCP runtime.
 *
 * The four states are deliberately distinct — the pre-Phase-1 UI
 * collapsed "still decrypting" and "no key to decrypt with" into one
 * infinite placeholder, which is the exact UX bug
 * docs/21 Phase 1 sets out to fix.
 */
export type MessageVisibilityState =
  | "decrypting"
  | "readable"
  | "unavailable_on_this_device"
  | "decrypt_failed";

export type DeriveMessageStateArgs = {
  /**
   * How this agent is known to hold its private key. When `unknown`,
   * treated like `web_keystore` so existing credentials don't suddenly
   * look Daemon-isolated.
   */
  recipientKeyHolder: AgentKeyHolder;
  /**
   * Whether the current browser / runtime actually has the X25519
   * private half on hand. For the Web UI this comes from
   * `hasRecipientPrivateKey(did)` against IndexedDB. For the MCP Isolated mode
   * runtime this is always `true` because the daemon unwrap replaces
   * local key presence.
   */
  localHasPrivateKey: boolean;
  /**
   * Result of the most recent decrypt attempt, if any.
   *
   * - `pending` → decrypt hasn't returned yet (spinner case)
   * - `ok` → plaintext produced
   * - `error` → decrypt threw or returned placeholder despite the key
   *   being present
   * - `no_key` → decrypt bailed because no private key was reachable
   */
  decryptOutcome: "pending" | "ok" | "error" | "no_key";
};

/**
 * Pure function that projects raw signals into the four-state model
 * docs/21 §2 defines. Kept deliberately small so both the Web UI and
 * the MCP runtime can call it without import-cycle risk.
 *
 * @example decrypting
 *   deriveMessageState({ recipientKeyHolder: "web_keystore",
 *     localHasPrivateKey: true, decryptOutcome: "pending" })
 *   // → "decrypting"
 *
 * @example daemon-isolated message viewed on a device without the key
 *   deriveMessageState({ recipientKeyHolder: "signer_daemon",
 *     localHasPrivateKey: false, decryptOutcome: "no_key" })
 *   // → "unavailable_on_this_device"
 */
export function deriveMessageState(
  args: DeriveMessageStateArgs,
): MessageVisibilityState {
  const { recipientKeyHolder, localHasPrivateKey, decryptOutcome } = args;

  if (decryptOutcome === "pending") return "decrypting";
  if (decryptOutcome === "ok") return "readable";

  // `no_key` is an unambiguous "we don't have the material on this
  // device". That's always `unavailable_on_this_device` regardless of
  // which mode the credential was minted in — Isolated mode would obviously
  // produce this, but a Standard mode user who opens the inbox on a second
  // browser profile would too.
  if (decryptOutcome === "no_key") return "unavailable_on_this_device";

  // At this point decryptOutcome === "error". Distinguish by mode:
  // Isolated mode (signer_daemon) lacking local key ⇒ expected UX, same card
  // as `no_key`; anything else ⇒ genuine decrypt failure the user
  // should see explicitly.
  if (recipientKeyHolder === "signer_daemon" && !localHasPrivateKey) {
    return "unavailable_on_this_device";
  }
  return "decrypt_failed";
}
