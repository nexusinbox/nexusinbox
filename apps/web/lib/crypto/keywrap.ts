type WrapResult = {
  wrappedKey: string;
  ephemeralPublicKey: string;
  iv: string;
  salt: string;
  ciphertext: string;
};

const WRAP_PREFIX = "x25519v1:";
const IV_BYTES = 12;
const SALT_BYTES = 16;

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

export function isValidX25519PublicKeyB64Url(publicKeyB64Url: string): boolean {
  if (!publicKeyB64Url || typeof publicKeyB64Url !== "string") {
    return false;
  }
  try {
    return fromBase64Url(publicKeyB64Url).byteLength === 32;
  } catch {
    return false;
  }
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function deriveWrapKey(sharedSecret: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey("raw", asArrayBuffer(sharedSecret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asArrayBuffer(salt),
      info: asArrayBuffer(new TextEncoder().encode("nexusinbox/x25519-wrap/v1")),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function importX25519PublicKey(publicKeyB64Url: string): Promise<CryptoKey> {
  if (!isValidX25519PublicKeyB64Url(publicKeyB64Url)) {
    throw new Error("invalid x25519 public key format");
  }
  return crypto.subtle.importKey("raw", asArrayBuffer(fromBase64Url(publicKeyB64Url)), { name: "X25519" }, false, []);
}

export async function wrapContentKeyForRecipient(
  contentKey: string,
  recipientPublicKeyB64Url: string,
): Promise<WrapResult> {
  const recipientPublicKey = await importX25519PublicKey(recipientPublicKeyB64Url);
  const ephemeral = (await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: recipientPublicKey },
    ephemeral.privateKey,
    256,
  );
  const sharedSecret = new Uint8Array(sharedBits);
  const iv = randomBytes(IV_BYTES);
  const salt = randomBytes(SALT_BYTES);
  const wrapKey = await deriveWrapKey(sharedSecret, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    wrapKey,
    asArrayBuffer(new TextEncoder().encode(contentKey)),
  );
  const ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const wrappedKey = `${WRAP_PREFIX}${toBase64Url(ephemeralRaw)}:${toBase64Url(salt)}:${toBase64Url(iv)}:${toBase64Url(
    new Uint8Array(ciphertext),
  )}`;
  return {
    wrappedKey,
    ephemeralPublicKey: toBase64Url(ephemeralRaw),
    iv: toBase64Url(iv),
    salt: toBase64Url(salt),
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function unwrapContentKeyWithRecipientPrivateKey(
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

  const ephemeralPublicKey = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(fromBase64Url(ephemeralPublicKeyB64)),
    { name: "X25519" },
    false,
    [],
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: ephemeralPublicKey },
    recipientPrivateKey,
    256,
  );
  const sharedSecret = new Uint8Array(sharedBits);
  const salt = fromBase64Url(saltB64);
  const iv = fromBase64Url(ivB64);
  const ciphertext = fromBase64Url(ciphertextB64);
  const wrapKey = await deriveWrapKey(sharedSecret, salt);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    wrapKey,
    asArrayBuffer(ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}
