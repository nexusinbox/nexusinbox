type WrapResult = {
  wrappedKey: string;
  ephemeralPublicKey: string;
  iv: string;
  salt: string;
  ciphertext: string;
};

type WrapPurpose = { prefix: string; info: string };

// A message's content key.
const CONTENT_KEY_WRAP: WrapPurpose = { prefix: "x25519v1:", info: "nexusinbox/x25519-wrap/v1" };
// A person's contacts key (docs/28 P3-8). Its own HKDF info and prefix mean
// a message's wrapped content key can never be opened as a contacts key, or
// the other way round: a server that swaps one for the other gets a failed
// AES-GCM tag, not a key whose value it knows.
const CONTACTS_KEY_WRAP: WrapPurpose = {
  prefix: "ckx25519v1:",
  info: "nexusinbox/contacts-key-wrap/v1",
};

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

async function deriveWrapKey(sharedSecret: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey("raw", asArrayBuffer(sharedSecret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asArrayBuffer(salt),
      info: asArrayBuffer(new TextEncoder().encode(info)),
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

async function wrapForRecipient(
  secret: string,
  recipientPublicKeyB64Url: string,
  purpose: WrapPurpose,
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
  const wrapKey = await deriveWrapKey(sharedSecret, salt, purpose.info);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    wrapKey,
    asArrayBuffer(new TextEncoder().encode(secret)),
  );
  const ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const wrappedKey = `${purpose.prefix}${toBase64Url(ephemeralRaw)}:${toBase64Url(salt)}:${toBase64Url(iv)}:${toBase64Url(
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

async function unwrapWithPrivateKey(
  wrappedKey: string,
  recipientPrivateKey: CryptoKey,
  purpose: WrapPurpose,
): Promise<string> {
  if (!wrappedKey.startsWith(purpose.prefix)) {
    throw new Error("unsupported wrapped key format");
  }
  const raw = wrappedKey.slice(purpose.prefix.length);
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
  const wrapKey = await deriveWrapKey(sharedSecret, salt, purpose.info);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    wrapKey,
    asArrayBuffer(ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}

export async function wrapContentKeyForRecipient(
  contentKey: string,
  recipientPublicKeyB64Url: string,
): Promise<WrapResult> {
  return wrapForRecipient(contentKey, recipientPublicKeyB64Url, CONTENT_KEY_WRAP);
}

export async function unwrapContentKeyWithRecipientPrivateKey(
  wrappedKey: string,
  recipientPrivateKey: CryptoKey,
): Promise<string> {
  return unwrapWithPrivateKey(wrappedKey, recipientPrivateKey, CONTENT_KEY_WRAP);
}

/** Wraps the person's contacts key to one of their agents' X25519 keys. */
export async function wrapContactsKeyForAgent(
  contactsKey: string,
  agentPublicKeyB64Url: string,
): Promise<string> {
  return (await wrapForRecipient(contactsKey, agentPublicKeyB64Url, CONTACTS_KEY_WRAP)).wrappedKey;
}

export async function unwrapContactsKey(
  wrappedKey: string,
  agentPrivateKey: CryptoKey,
): Promise<string> {
  return unwrapWithPrivateKey(wrappedKey, agentPrivateKey, CONTACTS_KEY_WRAP);
}
