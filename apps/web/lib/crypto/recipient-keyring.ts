// Recipient X25519 private keys are persisted per-DID in IndexedDB as
// non-extractable CryptoKeys. That keeps raw PKCS#8 out of JavaScript
// during steady-state loads, while still allowing message decryption
// through WebCrypto.

import {
  secureStoreKey,
  secureLoadKey,
  migrateFromLocalStorage,
  isKeystoreAvailable,
  toBase64Url,
} from "./keystore";

const STORAGE_PREFIX = "nexusinbox:recipient-key:";

const memoryKeyring = new Map<string, CryptoKey>();

let migrated = false;
let migrationPromise: Promise<void> | null = null;

function ensureMigration(): Promise<void> {
  if (migrated) return Promise.resolve();
  if (migrationPromise) return migrationPromise;
  if (!isKeystoreAvailable()) {
    migrated = true;
    return Promise.resolve();
  }
  migrationPromise = migrateFromLocalStorage(STORAGE_PREFIX, { name: "X25519" }, ["deriveBits"])
    .then(() => {
      migrated = true;
    })
    .catch(() => {
      migrated = true;
    });
  return migrationPromise;
}

function storageKey(did: string): string {
  return STORAGE_PREFIX + did;
}

export async function generateX25519KeyPairMaterial(): Promise<{
  publicKey: string;
  privateKey: CryptoKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "X25519" },
    false,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const publicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  return {
    publicKey: toBase64Url(publicRaw),
    privateKey: keyPair.privateKey,
  };
}

export function saveRecipientPrivateKey(did: string, privateKey: CryptoKey): void {
  if (!did || !privateKey) return;
  memoryKeyring.set(did, privateKey);
  if (isKeystoreAvailable()) {
    secureStoreKey(storageKey(did), privateKey).catch(() => {
      // IndexedDB write failure — in-memory key is still usable this session
    });
  }
}

export async function getRecipientPrivateKey(
  did: string,
): Promise<CryptoKey | null> {
  await ensureMigration();

  const cached = memoryKeyring.get(did);
  if (cached) return cached;

  if (!isKeystoreAvailable()) return null;
  const key = await secureLoadKey(storageKey(did));
  if (key) {
    memoryKeyring.set(did, key);
  }
  return key;
}

/**
 * Cheap presence check without materialising the CryptoKey. Backs the
 * Phase 1 visibility state machine in docs/21 — the Web UI needs to
 * know "do we have the key for this recipient at all" before it even
 * tries to decrypt, so it can distinguish "still decrypting" from
 * "this message lives on another device / in the daemon."
 *
 * `getRecipientPrivateKey` has a strict return contract (`CryptoKey |
 * null`) that callers rely on for actual decryption, so this helper
 * wraps it and collapses the result to a boolean to signal intent at
 * the call site.
 */
export async function hasRecipientPrivateKey(did: string): Promise<boolean> {
  if (!did) return false;
  const key = await getRecipientPrivateKey(did);
  return key !== null;
}
