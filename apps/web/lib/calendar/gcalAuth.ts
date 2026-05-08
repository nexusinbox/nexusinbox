// Phase 4.4d (docs/25d) — Google Calendar auth via Google Identity
// Services (GIS). Implicit-style token client → browser-only access
// token → IndexedDB storage. No refresh token, no server handoff —
// the server's only involvement is exposing the public client_id
// via NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID.
//
// The module is small and defensively-typed because GIS is an
// externally-injected script. It exposes four entry points the
// settings UI and the executor call:
//   - requestCalendarToken()   — opens Google's consent popup
//   - getCalendarToken()       — returns a live token or null
//   - isCalendarConnected()    — lightweight boolean helper
//   - disconnectCalendar()     — wipes the IndexedDB row

const DB_NAME = "nexusinbox-gcal";
const DB_VERSION = 1;
const STORE = "tokens";
const TOKEN_KEY = "primary";
// Google's OAuth scope for "read-only freebusy" is actually the
// broader calendar.readonly scope — Google doesn't ship a scope
// narrower than that for `freebusy.query`. We accept this breadth
// because `calendar.freebusy` is technically a sensitive-but-not-
// restricted scope, and the browser-only flow keeps the access
// local to the user's device (see ADR 25d §2.2).
export const CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.freebusy";
const REFRESH_MARGIN_MS = 60_000;

export type StoredCalendarToken = {
  access_token: string;
  expires_at: number;
  scope: string;
  user_email?: string;
};

export function calendarClientId(): string | null {
  const v = process.env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID;
  return v && v.length > 0 ? v : null;
}

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

async function dbGet(): Promise<StoredCalendarToken | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(TOKEN_KEY);
    req.onsuccess = () => resolve((req.result as StoredCalendarToken | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function dbPut(token: StoredCalendarToken): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(token, TOKEN_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function dbDelete(): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(TOKEN_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// GIS SDK loader (idempotent)
// ---------------------------------------------------------------------------

type TokenResponse = {
  access_token: string;
  expires_in: number;
  scope: string;
  error?: string;
};

type TokenClient = {
  requestAccessToken: (overrideConfig?: { prompt?: string }) => void;
};

type GoogleAccounts = {
  oauth2: {
    initTokenClient: (config: {
      client_id: string;
      scope: string;
      callback: (response: TokenResponse) => void;
      prompt?: string;
    }) => TokenClient;
    revoke: (token: string, done?: () => void) => void;
  };
};

declare global {
  interface Window {
    google?: { accounts?: GoogleAccounts };
  }
}

let sdkPromise: Promise<void> | null = null;

export function loadGisSdk(): Promise<void> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("GIS SDK requires a browser"));
  }
  if (window.google?.accounts?.oauth2) {
    return Promise.resolve();
  }
  if (sdkPromise) return sdkPromise;
  sdkPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => {
      sdkPromise = null;
      reject(new Error("failed to load Google Identity Services"));
    };
    document.head.appendChild(script);
  });
  return sdkPromise;
}

// ---------------------------------------------------------------------------
// Token lifecycle
// ---------------------------------------------------------------------------

function tokenIsLive(token: StoredCalendarToken | null): token is StoredCalendarToken {
  if (!token) return false;
  return token.expires_at - REFRESH_MARGIN_MS > Date.now();
}

/**
 * Open Google's consent popup and store the resulting token. Must
 * be called from a direct user gesture (click) so popup blockers
 * pass it through.
 */
export async function requestCalendarToken(): Promise<StoredCalendarToken> {
  const clientId = calendarClientId();
  if (!clientId) {
    throw new Error(
      "NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID is not configured; add it to .env.local to enable Calendar integration.",
    );
  }
  await loadGisSdk();
  const google = window.google?.accounts?.oauth2;
  if (!google) throw new Error("GIS SDK did not expose accounts.oauth2");

  return new Promise<StoredCalendarToken>((resolve, reject) => {
    const client = google.initTokenClient({
      client_id: clientId,
      scope: CALENDAR_SCOPE,
      callback: (response) => {
        if (response.error) {
          reject(new Error(`Calendar consent declined: ${response.error}`));
          return;
        }
        const token: StoredCalendarToken = {
          access_token: response.access_token,
          expires_at: Date.now() + response.expires_in * 1000,
          scope: response.scope,
        };
        dbPut(token).then(() => resolve(token)).catch(reject);
      },
    });
    client.requestAccessToken();
  });
}

/**
 * Return a valid Calendar token, refreshing silently if close to
 * expiry. Returns null if the user has not connected the
 * integration, the token is expired and refresh failed, or the
 * SDK isn't available (SSR).
 */
export async function getCalendarToken(): Promise<StoredCalendarToken | null> {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return null;
  }
  let token: StoredCalendarToken | null;
  try {
    token = await dbGet();
  } catch {
    return null;
  }
  if (!token) return null;
  if (tokenIsLive(token)) return token;
  const stale: StoredCalendarToken = token;

  // Silent renewal via hidden iframe prompt="none". If the user
  // previously consented we can get a fresh token without another
  // popup. Any failure leaves the stored (expired) record in place
  // so the UI can prompt the user to reconnect.
  const clientId = calendarClientId();
  if (!clientId) return null;
  try {
    await loadGisSdk();
  } catch {
    return null;
  }
  const google = window.google?.accounts?.oauth2;
  if (!google) return null;

  return new Promise<StoredCalendarToken | null>((resolve) => {
    const client = google.initTokenClient({
      client_id: clientId,
      scope: CALENDAR_SCOPE,
      callback: (response) => {
        if (response.error || !response.access_token) {
          resolve(null);
          return;
        }
        const fresh: StoredCalendarToken = {
          access_token: response.access_token,
          expires_at: Date.now() + response.expires_in * 1000,
          scope: response.scope,
          user_email: stale.user_email,
        };
        dbPut(fresh).then(() => resolve(fresh)).catch(() => resolve(null));
      },
    });
    client.requestAccessToken({ prompt: "none" });
  });
}

export async function isCalendarConnected(): Promise<boolean> {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return false;
  }
  try {
    const token = await dbGet();
    return tokenIsLive(token);
  } catch {
    return false;
  }
}

export async function disconnectCalendar(): Promise<void> {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return;
  }
  try {
    const existing = await dbGet();
    if (existing?.access_token) {
      await loadGisSdk().catch(() => undefined);
      window.google?.accounts?.oauth2.revoke(existing.access_token);
    }
  } catch {
    // best-effort revoke; local delete still happens below
  }
  await dbDelete();
}
