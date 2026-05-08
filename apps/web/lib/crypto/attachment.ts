// Binary-payload AES-GCM helpers for E2E-encrypted attachments.
//
// Rationale: @nexusinbox/crypto wraps AES-GCM in PBKDF2-SHA256 with a string
// passphrase — intentionally slow and not suitable for per-file random-key
// encryption. Attachments use a fresh random 32-byte key per file, directly
// with AES-GCM. The raw key is then wrapped per-recipient via the existing
// keywrap (see keywrap.ts) so both sender and recipient can retrieve it.

const IV_BYTES = 12;
const KEY_BYTES = 32;

function toBase64Url(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * Generate a fresh 256-bit AES-GCM key for a single attachment.
 * Returned as raw bytes; callers may base64url-encode for wrapping.
 */
export function generateAttachmentKey(): Uint8Array {
  const bytes = new Uint8Array(KEY_BYTES);
  crypto.getRandomValues(bytes);
  return bytes;
}

/** Encode raw key bytes as base64url — the form consumed by `wrapContentKeyForRecipient`. */
export function encodeAttachmentKey(key: Uint8Array): string {
  return toBase64Url(key);
}

/** Decode base64url back to raw key bytes. */
export function decodeAttachmentKey(b64url: string): Uint8Array {
  const bytes = fromBase64Url(b64url);
  if (bytes.byteLength !== KEY_BYTES) {
    throw new Error("invalid attachment key length");
  }
  return bytes;
}

async function importAesGcmKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.byteLength !== KEY_BYTES) {
    throw new Error("attachment key must be 32 bytes");
  }
  return crypto.subtle.importKey(
    "raw",
    asArrayBuffer(rawKey),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt a binary payload with AES-GCM using a fresh 96-bit IV.
 * Returns the ciphertext (including GCM auth tag) and the IV as base64url.
 */
export async function encryptAttachment(
  plaintext: ArrayBuffer,
  rawKey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonceB64Url: string }> {
  const key = await importAesGcmKey(rawKey);
  const nonce = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(nonce);
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(nonce) },
    key,
    plaintext,
  );
  return {
    ciphertext: new Uint8Array(ciphertextBuf),
    nonceB64Url: toBase64Url(nonce),
  };
}

/**
 * Decrypt an attachment ciphertext produced by `encryptAttachment`.
 * Throws if the GCM auth tag does not verify — callers should treat this as
 * an integrity failure and surface it to the user.
 */
export async function decryptAttachment(
  ciphertext: ArrayBuffer,
  rawKey: Uint8Array,
  nonceB64Url: string,
): Promise<ArrayBuffer> {
  const key = await importAesGcmKey(rawKey);
  const nonce = fromBase64Url(nonceB64Url);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(nonce) },
    key,
    ciphertext,
  );
}

/**
 * Base64url SHA-256 of the plaintext bytes. Stored inside encrypted metadata
 * so the recipient can independently verify integrity after decryption
 * (defence in depth on top of GCM's built-in auth tag).
 */
export async function sha256OfBytes(bytes: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return toBase64Url(new Uint8Array(hash));
}
