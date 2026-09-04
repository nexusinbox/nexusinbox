/**
 * Per-agent bridge token storage (Phase 3b + 3c.5).
 *
 * The bearer token itself rides through an AES-GCM envelope
 * keyed by a non-extractable IndexedDB KEK (see `./at-rest.ts`).
 * A `localStorage` dump from a browser extension / XSS payload
 * therefore yields ciphertext rather than a replayable bearer. See
 * docs/22 §8 Phase 3c.5 for the threat model.
 *
 * Load / save are async because unwrap needs to consult IndexedDB.
 * Callers pass around a `BridgeTokenRecord | null` same as before.
 */

import {
  isWrappedBridgeToken,
  unwrapBridgeToken,
  wrapBridgeToken,
} from "./at-rest";

// Re-export so call sites in `/settings/agents` can branch on
// `err instanceof BridgeSecureStorageUnavailableError` without
// having to reach into the sibling `at-rest` module.
export { BridgeSecureStorageUnavailableError } from "./at-rest";

const STORAGE_PREFIX = "nexusinbox:bridge-token:";

export type BridgeTokenRecord = {
  aid: string;
  base_url: string;
  /** Decrypted bearer. Caller must not persist this to disk — use
   * {@link saveBridgeToken} which re-encrypts before write. */
  token: string;
  /** ISO timestamp so we can invalidate records that look stale. */
  stored_at: string;
};

/** Shape stored in localStorage. `token` is the at-rest envelope
 *  string produced by `wrapBridgeToken`, not the plaintext bearer. */
type BridgeTokenStoredRecord = {
  aid: string;
  base_url: string;
  token: string;
  stored_at: string;
};

function isStorageAvailable(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const probe = "__nexusinbox_probe__";
    window.localStorage.setItem(probe, "1");
    window.localStorage.removeItem(probe);
    return true;
  } catch {
    return false;
  }
}

function storageKey(aid: string): string {
  return STORAGE_PREFIX + aid;
}

export async function loadBridgeToken(
  aid: string,
): Promise<BridgeTokenRecord | null> {
  if (!aid || !isStorageAvailable()) return null;
  const raw = window.localStorage.getItem(storageKey(aid));
  if (!raw) return null;
  let parsed: Partial<BridgeTokenStoredRecord>;
  try {
    parsed = JSON.parse(raw) as Partial<BridgeTokenStoredRecord>;
  } catch {
    // Malformed top-level JSON → remove and pretend nothing's
    // stored; the user re-pairs.
    window.localStorage.removeItem(storageKey(aid));
    return null;
  }
  if (!parsed.aid || !parsed.token) return null;
  const unwrapped = await unwrapBridgeToken(parsed.token);
  if (unwrapped === null) {
    // Envelope present but the KEK couldn't decrypt it (missing
    // IndexedDB, different origin, rotated KEK). Evict and force
    // re-pair rather than silently returning something broken.
    window.localStorage.removeItem(storageKey(aid));
    return null;
  }
  // Legacy-plaintext migration: if the stored token wasn't already
  // wrapped, rewrite it encrypted on the next available tick. Fire
  // and forget — we still return the record immediately so the
  // caller isn't blocked on the upgrade. A KEK failure inside
  // saveBridgeToken now throws rather than silently re-persisting
  // plaintext, so we swallow here (the existing legacy row stays
  // readable until the caller triggers an explicit re-pair).
  if (!isWrappedBridgeToken(parsed.token)) {
    void saveBridgeToken({
      aid: parsed.aid,
      base_url: parsed.base_url ?? "http://127.0.0.1:43417",
      token: unwrapped,
    }).catch(() => {
      // KEK unavailable: we keep the legacy plaintext row in place
      // instead of trying to upgrade it. Forcing re-pair would
      // surprise users whose only failure is a rotated / missing
      // KEK on a device where everything still otherwise works.
    });
  }
  return {
    aid: parsed.aid,
    base_url: parsed.base_url ?? "http://127.0.0.1:43417",
    token: unwrapped,
    stored_at: parsed.stored_at ?? new Date().toISOString(),
  };
}

/**
 * Persist a bridge bearer token at rest.
 *
 * Throws `BridgeSecureStorageUnavailableError` when the AES-GCM KEK
 * cannot be materialised — callers MUST surface this to the user
 * rather than proceeding with an unencrypted bearer. The earlier
 * revision of this function silently fell back to plaintext, which
 * contradicted the Help / Bridge panel copy that tells users "the
 * bearer lives as ciphertext in localStorage".
 *
 * Invalid / missing args and localStorage being unavailable remain
 * silent no-ops (same as before); the fail-closed contract only
 * kicks in when the KEK is unreachable.
 */
export async function saveBridgeToken(record: {
  aid: string;
  base_url?: string;
  token: string;
}): Promise<void> {
  if (!record.aid || !record.token || !isStorageAvailable()) return;
  // May throw BridgeSecureStorageUnavailableError — intentional,
  // propagates to the Pair / Advanced-token submit handlers.
  const wrapped = await wrapBridgeToken(record.token);
  const payload: BridgeTokenStoredRecord = {
    aid: record.aid,
    base_url: record.base_url ?? "http://127.0.0.1:43417",
    token: wrapped,
    stored_at: new Date().toISOString(),
  };
  window.localStorage.setItem(storageKey(record.aid), JSON.stringify(payload));
}

export function clearBridgeToken(aid: string): void {
  if (!aid || !isStorageAvailable()) return;
  window.localStorage.removeItem(storageKey(aid));
}

// ---------------------------------------------------------------------------
// Session nonce (Phase 3c.2 — docs/22 §2 invariant 5 hardening)
// ---------------------------------------------------------------------------
//
// The bearer token lives in localStorage (long-lived), but the nonce
// lives in **sessionStorage** — a hostile extension or XSS payload
// that exfiltrates `localStorage` gets a useless bearer without the
// matching nonce, because sessionStorage is tab-scoped and cross-tab
// reads are blocked by same-origin policy.
//
// The tradeoff: a fresh tab / browser-restart can't use an existing
// pairing until the user re-pairs. That's the intended invariant —
// "one active browser session per pair" — not a bug. The UI explains
// this in the `inbox.bridgedRestoreErrorSessionMissing` copy.

const SESSION_NONCE_PREFIX = "nexusinbox:bridge-session-nonce:";

function isSessionStorageAvailable(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const probe = "__nexusinbox_probe__";
    window.sessionStorage.setItem(probe, "1");
    window.sessionStorage.removeItem(probe);
    return true;
  } catch {
    return false;
  }
}

function nonceKey(aid: string): string {
  return SESSION_NONCE_PREFIX + aid;
}

/**
 * Generate 32 bytes of CSPRNG → base64url. Browsers all have
 * `crypto.getRandomValues` so no need to feature-detect. 32 bytes
 * gives 256 bits of entropy, plenty for what is effectively a
 * secret-sharing handshake with no online guessing pressure.
 */
export function generateBridgeSessionNonce(): string {
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error("crypto.getRandomValues is required for bridge session nonce");
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  // Base64url without padding to keep the header value ASCII.
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function loadBridgeSessionNonce(aid: string): string | null {
  if (!aid || !isSessionStorageAvailable()) return null;
  return window.sessionStorage.getItem(nonceKey(aid));
}

export function saveBridgeSessionNonce(aid: string, nonce: string): void {
  if (!aid || !nonce || !isSessionStorageAvailable()) return;
  window.sessionStorage.setItem(nonceKey(aid), nonce);
}

export function clearBridgeSessionNonce(aid: string): void {
  if (!aid || !isSessionStorageAvailable()) return;
  window.sessionStorage.removeItem(nonceKey(aid));
}

/**
 * Drop every stored bridge token and session nonce, whatever the aid.
 *
 * Called on logout. The bearer is re-obtainable by pairing again, so
 * unlike the E2E private keys in IndexedDB (which this browser may hold
 * the only copy of) it must not outlive the session that created it.
 */
export function clearAllBridgeTokens(): void {
  if (isStorageAvailable()) {
    removeKeysWithPrefix(window.localStorage, STORAGE_PREFIX);
  }
  if (isSessionStorageAvailable()) {
    removeKeysWithPrefix(window.sessionStorage, SESSION_NONCE_PREFIX);
  }
}

function removeKeysWithPrefix(storage: Storage, prefix: string): void {
  // Collect first: removing while iterating shifts the key indices.
  const doomed: string[] = [];
  for (let i = 0; i < storage.length; i += 1) {
    const key = storage.key(i);
    if (key && key.startsWith(prefix)) doomed.push(key);
  }
  for (const key of doomed) storage.removeItem(key);
}
