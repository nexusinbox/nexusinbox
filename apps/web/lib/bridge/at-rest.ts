// At-rest encryption for the bridge bearer token (docs/22 §8 Phase 3c.5).
//
// Before 3c.5 the bearer lived in `localStorage` as plaintext. A
// browser extension or XSS payload that dumped `localStorage` got
// a directly-reusable token. Phase 3c.5 raises the floor: we keep
// only the ciphertext in `localStorage` and stash a
// **non-extractable** AES-GCM 256 key in IndexedDB. Neither
// `crypto.subtle.exportKey` nor an extension's `chrome.storage`
// reader can lift the key out of IndexedDB; an XSS payload running
// inside the origin can still call `decrypt()` — that remains the
// XSS bar, but a passive dump no longer yields the bearer.
//
// Migration: older plaintext records (the pre-3c.5 format) are
// detected and re-encrypted on the next save. Nothing needs to be
// re-paired.
//
// ## Fail-closed contract (post-3c.5 hardening)
//
// The earlier revision of `wrapBridgeToken()` fell back to plaintext
// when the KEK could not be materialised (no IndexedDB, private mode
// quota error, extension sandbox blocking the DB open). That silently
// contradicted the user-visible copy in `/help` and the Bridge panel
// tooltip ("stored ciphertext in localStorage"). Phase 3c.5 now fails
// closed: if the KEK can't be created or loaded, both wrap and save
// throw `BridgeSecureStorageUnavailableError`, and the pair dialog is
// expected to surface a dedicated user-facing error instead of writing
// a plaintext bearer.

import { isKeystoreAvailable, secureLoadKey, secureStoreKey } from "../crypto/keystore";

const KEK_ID = "nexusinbox:bridge-kek";

/**
 * Thrown when the AES-GCM KEK can't be materialised in IndexedDB.
 * Callers in the pair / advanced-token flow translate this into a
 * user-visible "secure bridge token storage is unavailable" error and
 * abort rather than writing an unprotected bearer to localStorage.
 *
 * The name is stable so translations can switch on
 * `err.name === "BridgeSecureStorageUnavailableError"` without leaking
 * the message string into the render.
 */
export class BridgeSecureStorageUnavailableError extends Error {
  constructor(message = "secure bridge token storage is unavailable") {
    super(message);
    this.name = "BridgeSecureStorageUnavailableError";
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function asArrayBuffer(view: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(view.byteLength);
  new Uint8Array(ab).set(view);
  return ab;
}

/**
 * Fetch the per-origin bridge KEK, generating it on first use.
 * Non-extractable ⇒ `crypto.subtle.exportKey` refuses; a hostile
 * dump of IndexedDB sees the wrapped handle only. We still keep
 * the key scoped to one known `id` so rotations could target it
 * later without invalidating the X25519 recipient-keyring under
 * the same store.
 *
 * Throws `BridgeSecureStorageUnavailableError` when the keystore
 * layer is unreachable (SSR, no IndexedDB, private-mode quota
 * miss, WebCrypto generate error). The caller must propagate this
 * up to the UI — falling back to plaintext localStorage silently
 * would contradict the "bearer is stored ciphertext" contract
 * documented in the Help / Bridge tooltip copy (docs/22 §8).
 */
async function loadOrCreateKek(): Promise<CryptoKey> {
  if (!isKeystoreAvailable()) {
    throw new BridgeSecureStorageUnavailableError(
      "IndexedDB keystore is unavailable (SSR or unsupported browser context)",
    );
  }
  const existing = await secureLoadKey(KEK_ID);
  if (existing) return existing;
  try {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false, // non-extractable
      ["encrypt", "decrypt"],
    );
    await secureStoreKey(KEK_ID, key);
    return key;
  } catch (cause) {
    throw new BridgeSecureStorageUnavailableError(
      cause instanceof Error
        ? `failed to materialise bridge KEK: ${cause.message}`
        : "failed to materialise bridge KEK",
    );
  }
}

/**
 * Ciphertext envelope written to localStorage. `v: 1` so we can
 * bump the format without guessing; `iv` + `ct` are base64url so
 * the whole record round-trips through JSON cleanly.
 */
type WrappedToken = {
  v: 1;
  iv: string;
  ct: string;
};

function isWrapped(value: unknown): value is WrappedToken {
  return (
    typeof value === "object" &&
    value !== null &&
    "v" in value &&
    (value as { v: unknown }).v === 1 &&
    "iv" in value &&
    "ct" in value
  );
}

/**
 * Encrypt a bearer token with the per-origin KEK. Returns a JSON
 * envelope safe to drop straight into localStorage.
 *
 * Throws `BridgeSecureStorageUnavailableError` when the KEK cannot
 * be materialised. Callers MUST treat this as a hard failure and
 * not persist the bearer in any other form — the earlier plaintext
 * fallback contradicted the Help / settings copy and is explicitly
 * removed in the Phase 3c.5 hardening pass.
 */
export async function wrapBridgeToken(token: string): Promise<string> {
  const kek = await loadOrCreateKek();
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    kek,
    asArrayBuffer(new TextEncoder().encode(token)),
  );
  const wrapped: WrappedToken = {
    v: 1,
    iv: toBase64Url(iv),
    ct: toBase64Url(new Uint8Array(ct)),
  };
  return JSON.stringify(wrapped);
}

/**
 * Reverse of {@link wrapBridgeToken}. Accepts either the Phase
 * 3c.5 envelope or a legacy plaintext string — returning `null`
 * only when the envelope was present but unwrappable (wrong KEK,
 * corrupted ciphertext, KEK unavailable). That lets callers
 * migrate silently:
 *
 * - "plain string" → use as-is and let the next save re-encrypt.
 *   If the next save can't (KEK unavailable) it will throw from
 *   `saveBridgeToken` so the bearer is not silently re-persisted.
 * - "envelope + unwrap failed" → caller forces a re-pair.
 */
export async function unwrapBridgeToken(stored: string): Promise<string | null> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stored);
  } catch {
    // Not JSON → treat as legacy plaintext bearer.
    return stored;
  }
  if (!isWrapped(parsed)) {
    // Parsed JSON but not our envelope shape → also legacy /
    // unexpected; fall back to the raw string. Caller decides.
    return stored;
  }
  let kek: CryptoKey;
  try {
    kek = await loadOrCreateKek();
  } catch {
    // KEK unreachable: the envelope is real ciphertext we can't
    // decrypt right now. Tell the caller to force a re-pair
    // instead of handing back stale bytes.
    return null;
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: asArrayBuffer(fromBase64Url(parsed.iv)) },
      kek,
      asArrayBuffer(fromBase64Url(parsed.ct)),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    return null;
  }
}

/**
 * Detects whether a stored value is already encrypted. Used by
 * callers that want to decide "do I need to re-write this at
 * rest?" without actually decrypting.
 */
export function isWrappedBridgeToken(stored: string): boolean {
  try {
    const parsed = JSON.parse(stored);
    return isWrapped(parsed);
  } catch {
    return false;
  }
}
