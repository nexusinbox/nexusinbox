/**
 * Recipient-side envelope decryption for Standard mode.
 *
 * Given an encrypted envelope (encrypted_content, encrypted_key, nonce,
 * subject_encrypted) and the recipient's X25519 private CryptoKey from
 * the keystore, return `{ subject, body }` in plaintext.
 *
 * Crypto pipeline (mirrors apps/web/lib/crypto/keywrap.ts +
 * packages/crypto/src/index.ts so the server and the web UI stay
 * compatible):
 *
 *   1. Parse `x25519v1:<eph_pub>:<salt>:<iv>:<ct>` → unwrap with the
 *      recipient's X25519 private key → HKDF-SHA256 → AES-GCM-256 →
 *      raw content_key string (b64url 32 bytes used as passphrase).
 *   2. Parse `enc:v1:PBKDF2-SHA256:AES-GCM-256:<iter>:<salt>:<iv>:<ct>`
 *      for both `encrypted_content` and `subject_encrypted` → PBKDF2
 *      over the unwrapped content_key → AES-GCM-256 → UTF-8 text.
 *
 * Nothing here touches disk; the plaintext only ever lives in process
 * memory of the MCP server and the caller-held response.
 */

import { webcrypto } from "node:crypto";
import { decryptText, parseEncryptedPayload } from "@nexusinbox/crypto";

const subtle = webcrypto.subtle;
const WRAP_PREFIX = "x25519v1:";
const encoder = new TextEncoder();

function fromB64Url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function asArrayBuffer(view: Uint8Array): ArrayBuffer {
  // Guarantee a *fresh* ArrayBuffer the Web Crypto API will accept
  // regardless of how the underlying Buffer was allocated.
  const ab = new ArrayBuffer(view.byteLength);
  new Uint8Array(ab).set(view);
  return ab;
}

async function deriveWrapKey(sharedSecret: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await subtle.importKey(
    "raw",
    asArrayBuffer(sharedSecret),
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asArrayBuffer(salt),
      info: asArrayBuffer(encoder.encode("nexusinbox/x25519-wrap/v1")),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

/**
 * Unwrap a `x25519v1:...` encrypted_key using the recipient's X25519
 * private key. Returns the raw content_key string that was wrapped for
 * this recipient at send time.
 */
export async function unwrapContentKey(
  wrappedKey: string,
  recipientPrivateKey: CryptoKey,
): Promise<string> {
  if (!wrappedKey.startsWith(WRAP_PREFIX)) {
    throw new Error("unsupported wrapped key format");
  }
  const raw = wrappedKey.slice(WRAP_PREFIX.length);
  const [ephemeralPublicKeyB64, saltB64, ivB64, ciphertextB64] = raw.split(":");
  if (!ephemeralPublicKeyB64 || !saltB64 || !ivB64 || !ciphertextB64) {
    throw new Error("invalid wrapped key format");
  }

  const ephemeralPublicKey = await subtle.importKey(
    "raw",
    asArrayBuffer(fromB64Url(ephemeralPublicKeyB64)),
    { name: "X25519" },
    false,
    [],
  );
  const sharedBits = await subtle.deriveBits(
    { name: "X25519", public: ephemeralPublicKey },
    recipientPrivateKey,
    256,
  );
  const wrapKey = await deriveWrapKey(new Uint8Array(sharedBits), fromB64Url(saltB64));
  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(fromB64Url(ivB64)) },
    wrapKey,
    asArrayBuffer(fromB64Url(ciphertextB64)),
  );
  return new TextDecoder().decode(plaintext);
}

export type DecryptEnvelopeInput = {
  encrypted_content: string;
  encrypted_key: string;
  nonce: string; // signed into the envelope; not required for this AEAD decryption
  subject_encrypted: string;
  recipientPrivateKey: CryptoKey;
};

/**
 * Decrypt the subject + body for a recipient-held X25519 private key.
 * Gracefully returns placeholder strings for any field that cannot be
 * decoded, so a malformed leg in a batch doesn't crash the whole tool
 * response.
 */
export async function decryptEnvelopeTextForRecipient(
  input: DecryptEnvelopeInput,
): Promise<{ subject: string; body: string }> {
  const contentKey = await unwrapContentKey(input.encrypted_key, input.recipientPrivateKey);
  return decryptEnvelopeTextWithContentKey({
    encrypted_content: input.encrypted_content,
    subject_encrypted: input.subject_encrypted,
    contentKey,
  });
}

/**
 * Same shape as `decryptEnvelopeTextForRecipient` but skips the X25519
 * unwrap step — useful when the `content_key` was already recovered by
 * a daemon `unwrap_content_key` RPC, so the MCP process never has to
 * hold the recipient's X25519 private key itself (Isolated mode, Phase 2.5).
 */
export async function decryptEnvelopeTextWithContentKey(input: {
  encrypted_content: string;
  subject_encrypted: string;
  contentKey: string;
}): Promise<{ subject: string; body: string }> {
  const body = await decryptSafely(input.encrypted_content, input.contentKey);
  const subject = input.subject_encrypted
    ? await decryptSafely(input.subject_encrypted, input.contentKey)
    : "";
  return { subject, body };
}

async function decryptSafely(serialized: string, contentKey: string): Promise<string> {
  const parsed = parseEncryptedPayload(serialized);
  if (!parsed) {
    // Ciphertext wasn't in the expected `enc:v1:...` envelope — assume
    // already-plaintext (dev / mock mode) and pass through untouched.
    return serialized;
  }
  try {
    return await decryptText(parsed, contentKey);
  } catch {
    return "(decryption failed)";
  }
}
