// Phase 4.5 (docs/25f) — BYOK LLM credential storage.
//
// Mirrors apps/web/lib/calendar/gcalAuth.ts: IndexedDB-only, no
// server touch. The API key never enters localStorage, a URL, or
// a fetch to our API — it exists only in the user's browser until
// they choose to use it for a draft-generation call or revoke it.

const DB_NAME = "nexusinbox-llm";
const DB_VERSION = 1;
const STORE = "keys";
const RECORD_KEY = "primary";

export const DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5";

export type LLMProvider = "anthropic";

export type StoredLLMKey = {
  provider: LLMProvider;
  api_key: string;
  model: string;
  created_at: number;
};

// ---------------------------------------------------------------------------
// IndexedDB
// ---------------------------------------------------------------------------

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet(): Promise<StoredLLMKey | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(RECORD_KEY);
    req.onsuccess = () =>
      resolve((req.result as StoredLLMKey | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function dbPut(entry: StoredLLMKey): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(entry, RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function dbDelete(): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Persist a BYOK API key for future draft generation. Strips
 * whitespace to catch paste errors and rejects obviously empty
 * input — anything else goes to IndexedDB verbatim. We do NOT
 * validate the key with a pre-flight call to the provider; the
 * user learns about typos when the first draft generation fails
 * with a 401 so the Settings UX doesn't cost an API call per save.
 */
export async function saveLLMKey(input: {
  provider?: LLMProvider;
  apiKey: string;
  model?: string;
}): Promise<StoredLLMKey> {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    throw new Error("LLM key storage requires a browser");
  }
  const apiKey = input.apiKey.trim();
  if (!apiKey) throw new Error("API key is empty");
  const entry: StoredLLMKey = {
    provider: input.provider ?? "anthropic",
    api_key: apiKey,
    model: input.model?.trim() || DEFAULT_ANTHROPIC_MODEL,
    created_at: Date.now(),
  };
  await dbPut(entry);
  return entry;
}

export async function getLLMKey(): Promise<StoredLLMKey | null> {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return null;
  }
  try {
    return await dbGet();
  } catch {
    return null;
  }
}

export async function isLLMConnected(): Promise<boolean> {
  const entry = await getLLMKey();
  return !!entry && entry.api_key.length > 0;
}

export async function disconnectLLM(): Promise<void> {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return;
  }
  try {
    await dbDelete();
  } catch {
    // best-effort
  }
}

/**
 * Helper used by the Settings card to render a safe fingerprint of
 * the saved key without showing the key itself. Returns something
 * like "sk-ant-…dJk" — last four characters preceded by an ellipsis,
 * never more than that. Returns null when nothing is stored.
 */
export async function getLLMKeyFingerprint(): Promise<string | null> {
  const entry = await getLLMKey();
  if (!entry) return null;
  const tail = entry.api_key.slice(-4);
  return `•••${tail}`;
}
