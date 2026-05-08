// keystore.ts — IndexedDB-backed browser keystore
//
// Strategy:
// 1. Persist non-extractable private CryptoKeys directly in IndexedDB.
// 2. Persist a non-extractable AES-GCM wrap key for legacy migration.
// 3. Migrate any old localStorage PKCS#8 strings into non-extractable
//    CryptoKeys on first access, then remove the legacy entries.
//
// This reduces raw secret exposure: JavaScript no longer receives PKCS#8
// strings during normal loads. Same-origin script can still invoke key
// operations while the app is open, so CSP and XSS prevention remain
// mandatory defense layers.

const DB_NAME = "nexusinbox-keystore";
const DB_VERSION = 2;
const STORE_WRAP_KEYS = "wrap-keys";
const STORE_PRIVATE_KEYS = "private-keys";
const MASTER_KEY_ID = "master";

export type WebCryptoImportAlgorithm =
  | AlgorithmIdentifier
  | RsaHashedImportParams
  | EcKeyImportParams
  | HmacImportParams
  | AesKeyAlgorithm;

type LegacyWrappedKeyRecord = { id: string; wrapped: ArrayBuffer; iv: Uint8Array };
type KeyRecord = { id: string; key: CryptoKey };
type WrapKeyRecord = { id: string; key: CryptoKey };

// ---------------------------------------------------------------------------
// Base64url helpers — shared across the crypto layer
// ---------------------------------------------------------------------------

export function toBase64Url(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function asArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(
    view.byteOffset,
    view.byteOffset + view.byteLength,
  ) as ArrayBuffer;
}

// ---------------------------------------------------------------------------
// IndexedDB helpers
// ---------------------------------------------------------------------------

function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof indexedDB !== "undefined";
}

let dbPromise: Promise<IDBDatabase> | null = null;

function openDB(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    if (!isBrowser()) {
      reject(new Error("IndexedDB not available"));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_WRAP_KEYS)) {
        db.createObjectStore(STORE_WRAP_KEYS, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(STORE_PRIVATE_KEYS)) {
        db.createObjectStore(STORE_PRIVATE_KEYS, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => {
      dbPromise = null;
      reject(request.error);
    };
  });
  return dbPromise;
}

function idbGet<T>(storeName: string, key: string): Promise<T | undefined> {
  return openDB().then(
    (db) =>
      new Promise<T | undefined>((resolve, reject) => {
        const tx = db.transaction(storeName, "readonly");
        const store = tx.objectStore(storeName);
        const req = store.get(key);
        req.onsuccess = () => resolve(req.result as T | undefined);
        req.onerror = () => reject(req.error);
      }),
  );
}

function idbPut<T>(storeName: string, value: T): Promise<void> {
  return openDB().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(storeName, "readwrite");
        const store = tx.objectStore(storeName);
        const req = store.put(value);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      }),
  );
}

// ---------------------------------------------------------------------------
// Legacy wrap-key support for localStorage migration
// ---------------------------------------------------------------------------

let wrapKeyPromise: Promise<CryptoKey> | null = null;

function getOrCreateWrapKey(): Promise<CryptoKey> {
  if (wrapKeyPromise) return wrapKeyPromise;
  wrapKeyPromise = (async () => {
    const existing = await idbGet<WrapKeyRecord>(STORE_WRAP_KEYS, MASTER_KEY_ID);
    if (existing?.key) {
      return existing.key;
    }
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    await idbPut<WrapKeyRecord>(STORE_WRAP_KEYS, { id: MASTER_KEY_ID, key });
    return key;
  })().catch((err) => {
    wrapKeyPromise = null;
    throw err;
  });
  return wrapKeyPromise;
}

async function decryptLegacyRecord(
  record: LegacyWrappedKeyRecord,
): Promise<Uint8Array | null> {
  const wrapKey = await getOrCreateWrapKey();
  try {
    const iv = new Uint8Array(record.iv);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
      wrapKey,
      record.wrapped,
    );
    return new Uint8Array(decrypted);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function secureStoreKey(id: string, key: CryptoKey): Promise<void> {
  await idbPut<KeyRecord>(STORE_PRIVATE_KEYS, { id, key });
}

export async function secureLoadKey(id: string): Promise<CryptoKey | null> {
  const record = await idbGet<KeyRecord | LegacyWrappedKeyRecord>(STORE_PRIVATE_KEYS, id);
  if (!record) return null;

  if ("key" in record && record.key) {
    return record.key;
  }

  if ("wrapped" in record && record.wrapped) {
    return null;
  }

  return null;
}

export async function migrateFromLocalStorage(
  prefix: string,
  algorithm: WebCryptoImportAlgorithm,
  usages: KeyUsage[],
): Promise<void> {
  if (!isBrowser()) return;
  const keysToMigrate: Array<{ lsKey: string; value: string }> = [];
  try {
    for (let i = 0; i < window.localStorage.length; i += 1) {
      const lsKey = window.localStorage.key(i);
      if (lsKey && lsKey.startsWith(prefix)) {
        const value = window.localStorage.getItem(lsKey);
        if (value) {
          keysToMigrate.push({ lsKey, value });
        }
      }
    }
  } catch {
    return;
  }

  for (const { lsKey, value } of keysToMigrate) {
    const existing = await secureLoadKey(lsKey);
    if (!existing) {
      try {
        const imported = await crypto.subtle.importKey(
          "pkcs8",
          asArrayBuffer(fromBase64Url(value)),
          algorithm,
          false,
          usages,
        );
        await secureStoreKey(lsKey, imported);
      } catch {
        // Ignore invalid legacy entries and continue clearing them.
      }
    }
    try {
      window.localStorage.removeItem(lsKey);
    } catch {
      // Best effort removal
    }
  }

  const db = await openDB();
  const tx = db.transaction(STORE_PRIVATE_KEYS, "readonly");
  const store = tx.objectStore(STORE_PRIVATE_KEYS);
  const allRecords = await new Promise<Array<KeyRecord | LegacyWrappedKeyRecord>>(
    (resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () =>
        resolve((request.result as Array<KeyRecord | LegacyWrappedKeyRecord>) ?? []);
      request.onerror = () => reject(request.error);
    },
  );

  for (const record of allRecords) {
    if (!("wrapped" in record) || !record.wrapped) continue;
    const decrypted = await decryptLegacyRecord(record);
    if (!decrypted) continue;
    try {
      const imported = await crypto.subtle.importKey(
        "pkcs8",
        asArrayBuffer(decrypted),
        algorithm,
        false,
        usages,
      );
      await secureStoreKey(record.id, imported);
    } catch {
      // Drop unreadable legacy entries by leaving them inaccessible.
    }
  }
}

export function isKeystoreAvailable(): boolean {
  return isBrowser();
}
