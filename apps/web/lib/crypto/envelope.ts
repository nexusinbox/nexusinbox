import {
  decryptText,
  encryptText,
  parseEncryptedPayload,
  serializeEncryptedPayload,
} from "@nexusinbox/crypto";
import { unwrapContentKeyWithRecipientPrivateKey } from "./keywrap";
import { getRecipientPrivateKey } from "./recipient-keyring";

// Marker string returned when decryption fails or key is unavailable.
// UI components should check for this and show a localized message.
export const ENCRYPTED_PLACEHOLDER = "__ENCRYPTED_PLACEHOLDER__";

function toBase64Url(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function generateContentKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

async function decodeWrappedContentKey(encryptedKey: string, recipientDid?: string): Promise<string | null> {
  if (!encryptedKey.startsWith("x25519v1:")) {
    return null;
  }
  if (!recipientDid) {
    return null;
  }
  const privateKey = await getRecipientPrivateKey(recipientDid);
  if (!privateKey) {
    return null;
  }
  try {
    return await unwrapContentKeyWithRecipientPrivateKey(encryptedKey, privateKey);
  } catch {
    return null;
  }
}

export async function encryptEnvelopeText(plaintext: string): Promise<{
  serialized: string;
  nonce: string;
  encryptedKey: string;
}>;

export async function encryptEnvelopeText(
  plaintext: string,
  options: { contentKey: string },
): Promise<{
  serialized: string;
  nonce: string;
  encryptedKey: string;
}>;

export async function encryptEnvelopeText(
  plaintext: string,
  options?: { contentKey: string },
): Promise<{
  serialized: string;
  nonce: string;
  encryptedKey: string;
}> {
  const contentKey = options?.contentKey ?? generateContentKey();
  const payload = await encryptText(plaintext, contentKey);
  return {
    serialized: serializeEncryptedPayload(payload),
    nonce: payload.iv,
    encryptedKey: "",
  };
}

export async function decryptEnvelopeText(
  maybeEncrypted: string,
  encryptedKey?: string,
  recipientDid?: string,
): Promise<string> {
  const result = await decryptEnvelopeTextWithState(
    maybeEncrypted,
    encryptedKey,
    recipientDid,
  );
  return result.state === "readable" ? result.text : ENCRYPTED_PLACEHOLDER;
}

/**
 * Rich-result variant of {@link decryptEnvelopeText} that splits the
 * two failure modes the legacy API collapsed:
 *
 * - `no_key` → this browser has no X25519 private key for the
 *   recipient DID. For Isolated mode (daemon-isolated) credentials this is the
 *   expected steady state; for Standard mode it means the user opened the
 *   inbox from a second profile / device.
 * - `decrypt_failed` → the key was there and decryption still threw
 *   (ciphertext corruption, wrap-format mismatch, rotation-in-flight).
 *
 * Callers feed the `outcome` into `deriveMessageState` from
 * `@nexusinbox/core` to pick the right UI branch. The legacy
 * `decryptEnvelopeText` keeps working for code paths that only need
 * plaintext-or-placeholder.
 */
export type DecryptEnvelopeOutcome = "ok" | "error" | "no_key";

export type DecryptEnvelopeResult = {
  state: "passthrough" | "readable" | DecryptEnvelopeOutcome;
  text: string;
};

export async function decryptEnvelopeTextWithState(
  maybeEncrypted: string,
  encryptedKey?: string,
  recipientDid?: string,
): Promise<DecryptEnvelopeResult> {
  const parsed = parseEncryptedPayload(maybeEncrypted);
  if (!parsed) {
    // The caller handed us a non-encrypted string (dev / legacy mode).
    // Mirror the old behaviour — return it verbatim — and flag the
    // state so the UI knows no decrypt attempt actually happened.
    return { state: "passthrough", text: maybeEncrypted };
  }

  let resolvedContentKey: string | null = null;
  if (encryptedKey) {
    resolvedContentKey = await decodeWrappedContentKey(encryptedKey, recipientDid);
  }

  if (!resolvedContentKey) {
    return { state: "no_key", text: ENCRYPTED_PLACEHOLDER };
  }

  try {
    const plaintext = await decryptText(parsed, resolvedContentKey);
    return { state: "readable", text: plaintext };
  } catch {
    return { state: "error", text: ENCRYPTED_PLACEHOLDER };
  }
}

/**
 * Decrypt an `enc:v1:...` payload given a pre-resolved `content_key`
 * — skips the X25519 / keyring lookup that the standard path does.
 *
 * Useful when something else already recovered the content key on
 * this device, e.g. the bridged-restore flow (docs/22): the Signer
 * Daemon unwraps `encrypted_key` over its localhost bridge and
 * returns just the `content_key`; the browser then calls this to
 * finish the AES-GCM decrypt locally without the recipient's X25519
 * private key ever entering the page.
 */
export async function decryptEnvelopeTextWithContentKey(
  maybeEncrypted: string,
  contentKey: string,
): Promise<DecryptEnvelopeResult> {
  const parsed = parseEncryptedPayload(maybeEncrypted);
  if (!parsed) {
    return { state: "passthrough", text: maybeEncrypted };
  }
  try {
    const plaintext = await decryptText(parsed, contentKey);
    return { state: "readable", text: plaintext };
  } catch {
    return { state: "error", text: ENCRYPTED_PLACEHOLDER };
  }
}
