export function envelopeVersion(): number {
  return 1;
}

export type EncryptedPayload = {
  v: number;
  alg: "AES-GCM-256";
  kdf: "PBKDF2-SHA256";
  iter: number;
  salt: string;
  iv: string;
  ct: string;
};

const PBKDF2_ITERATIONS = 120_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

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

async function deriveAesKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(encoder.encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: asArrayBuffer(salt),
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptText(plainText: string, passphrase: string): Promise<EncryptedPayload> {
  const encoder = new TextEncoder();
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveAesKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(iv),
    },
    key,
    asArrayBuffer(encoder.encode(plainText)),
  );

  return {
    v: envelopeVersion(),
    alg: "AES-GCM-256",
    kdf: "PBKDF2-SHA256",
    iter: PBKDF2_ITERATIONS,
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ct: toBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function decryptText(payload: EncryptedPayload, passphrase: string): Promise<string> {
  if (payload.v !== envelopeVersion()) {
    throw new Error("unsupported envelope version");
  }
  if (payload.alg !== "AES-GCM-256" || payload.kdf !== "PBKDF2-SHA256") {
    throw new Error("unsupported algorithm");
  }

  const key = await deriveAesKey(passphrase, fromBase64Url(payload.salt), payload.iter);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(fromBase64Url(payload.iv)),
    },
    key,
    asArrayBuffer(fromBase64Url(payload.ct)),
  );

  return new TextDecoder().decode(plaintext);
}

export function serializeEncryptedPayload(payload: EncryptedPayload): string {
  return `enc:v${payload.v}:${payload.kdf}:${payload.alg}:${payload.iter}:${payload.salt}:${payload.iv}:${payload.ct}`;
}

export function parseEncryptedPayload(text: string): EncryptedPayload | null {
  if (!text.startsWith("enc:v")) return null;
  const parts = text.split(":");
  if (parts.length !== 8) return null;

  const version = Number(parts[1].replace("v", ""));
  const iter = Number(parts[4]);
  if (!Number.isFinite(version) || !Number.isFinite(iter)) return null;
  // `iter` is attacker-controlled — it comes straight from sender-supplied
  // ciphertext. Reject values outside a sane PBKDF2 band so a hostile
  // envelope can neither weaken the KDF (iter=1) nor lock the tab with a
  // multi-minute derivation (iter=1e9). Our own writer uses
  // PBKDF2_ITERATIONS (120k), comfortably inside this range.
  if (iter < 100_000 || iter > 1_000_000) return null;

  const payload: EncryptedPayload = {
    v: version,
    kdf: parts[2] as EncryptedPayload["kdf"],
    alg: parts[3] as EncryptedPayload["alg"],
    iter,
    salt: parts[5],
    iv: parts[6],
    ct: parts[7],
  };
  return payload;
}
