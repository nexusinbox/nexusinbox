// Signing private keys are persisted per-DID in IndexedDB as
// non-extractable CryptoKeys. Raw PKCS#8 never re-enters JavaScript
// during normal loads. This narrows exfiltration paths, but active
// same-origin script can still ask WebCrypto to sign, so CSP/XSS
// hardening remains mandatory.

import {
  secureStoreKey,
  secureLoadKey,
  migrateFromLocalStorage,
  isKeystoreAvailable,
  toBase64Url,
} from "./keystore";

const STORAGE_PREFIX = "nexusinbox:signing-key:";

const memorySigningKeyring = new Map<string, CryptoKey>();

let migrated = false;
let migrationPromise: Promise<void> | null = null;

function ensureMigration(): Promise<void> {
  if (migrated) return Promise.resolve();
  if (migrationPromise) return migrationPromise;
  if (!isKeystoreAvailable()) {
    migrated = true;
    return Promise.resolve();
  }
  migrationPromise = migrateFromLocalStorage(STORAGE_PREFIX, { name: "Ed25519" }, ["sign"])
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

export async function generateEd25519SigningKeyPairMaterial(): Promise<{
  publicKey: string;
  privateKey: CryptoKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    false,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  return {
    publicKey: toBase64Url(publicRaw),
    privateKey: keyPair.privateKey,
  };
}

export function saveSigningPrivateKey(did: string, privateKey: CryptoKey): void {
  if (!did || !privateKey) return;
  memorySigningKeyring.set(did, privateKey);
  if (isKeystoreAvailable()) {
    secureStoreKey(storageKey(did), privateKey).catch(() => {
      // IndexedDB write failure — in-memory key is still usable this session
    });
  }
}

export async function hasSigningPrivateKeyMaterial(did: string): Promise<boolean> {
  if (!did) return false;
  return (await getSigningPrivateKey(did)) !== null;
}

export async function getSigningPrivateKey(
  did: string,
): Promise<CryptoKey | null> {
  await ensureMigration();

  const cached = memorySigningKeyring.get(did);
  if (cached) return cached;

  if (!isKeystoreAvailable()) return null;
  const key = await secureLoadKey(storageKey(did));
  if (key) {
    memorySigningKeyring.set(did, key);
  }
  return key;
}
