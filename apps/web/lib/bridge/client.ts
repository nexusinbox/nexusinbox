/**
 * BridgeClient — Web-side counterpart to services/signer-daemon's
 * bridge module (docs/22 Phase 3a).
 *
 * The browser talks to a loopback-bound daemon HTTP endpoint to ask
 * for a single content-key unwrap. The daemon never receives the
 * recipient's private key; we only receive the resulting
 * `content_key` plaintext, which we then use with the existing
 * AES-GCM decrypt path for subject + body.
 *
 * This module stays strict about failures: anything other than a
 * clean 200 with `{ content_key }` short-circuits to a typed error
 * the UI can branch on. The bridge endpoint is considered optional
 * infrastructure — detection (`BridgeClient.detect`) always resolves
 * to a status, never throws, so the UI can render "Daemon offline"
 * vs "Daemon available, paired" without try/catch.
 */

// Default port comes from services/signer-daemon/src/main.rs
// (--bridge-port default). A localhost-only fetch so no TLS.
const DEFAULT_PORT = 43417;

// AbortController-backed timeout for every request. The daemon is
// local; if it takes longer than this something's actually wrong.
const DEFAULT_TIMEOUT_MS = 4000;

/**
 * Status of the daemon's bridge listener as observed from the
 * browser. Never throws; always resolves to a discriminated union
 * the UI can render without defensive try/catch.
 */
export type BridgePairedSession = {
  /** sha256 hex of the bearer this session owns. `null` for the
   * legacy shared-secret synthetic row. */
  id: string | null;
  device_label: string;
  created_at: string;
  last_used_at: string;
  shared_secret: boolean;
};

export type BridgeRatePolicy = {
  bridged_decrypts_per_min_used: number;
  bridged_decrypts_per_min_max: number;
  bridged_decrypts_per_day_used: number;
  bridged_decrypts_per_day_max: number;
};

export type BridgeStatus =
  | {
      kind: "available";
      aid: string;
      did: string;
      encryption_public_key: string | null;
      version: string;
      paired_sessions: BridgePairedSession[];
      policy: BridgeRatePolicy | null;
    }
  | { kind: "offline" }
  | { kind: "unauthorized" } // token missing or wrong — user needs to (re)pair
  | { kind: "forbidden_origin" }; // Origin rejected — misconfigured daemon

export type BridgeUnwrapResult =
  | { kind: "ok"; content_key: string }
  | { kind: "offline" }
  | { kind: "unauthorized" }
  | { kind: "forbidden_origin" }
  | { kind: "bad_request"; message: string }
  | { kind: "rate_limited"; message: string }
  | { kind: "daemon_error"; message: string };

export type BridgePairResult =
  | { kind: "ok"; token: string; device_label: string; created_at: string }
  | { kind: "offline" }
  | { kind: "forbidden_origin" }
  | { kind: "rejected"; message: string }
  | { kind: "bad_request"; message: string }
  | { kind: "daemon_error"; message: string };

export type BridgeRevokeResult =
  | { kind: "ok"; revoked: number }
  | { kind: "offline" }
  | { kind: "unauthorized" }
  | { kind: "forbidden_origin" }
  | { kind: "daemon_error"; message: string };

export type BridgeClientOptions = {
  /** Override the base URL. Default: `http://127.0.0.1:43417`. */
  baseUrl?: string;
  /** Shared secret for `X-NexusInbox-Bridge`. Missing ⇒ requests
   * resolve to `kind: "unauthorized"` without hitting the network. */
  token?: string | null;
  /**
   * Phase 3c.2 session nonce for `X-NexusInbox-Bridge-Nonce`.
   * Required on privileged calls when the daemon-side token was
   * minted with a nonce binding. Missing → daemon returns 401 with
   * outcome `nonce_missing`, which the UI surfaces as
   * `session_missing` so the user knows to re-pair in this tab.
   */
  sessionNonce?: string | null;
  /** Fetch timeout in ms. Default 4000. */
  timeoutMs?: number;
  /** Injection point for tests. Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
};

function defaultBaseUrl(): string {
  return `http://127.0.0.1:${DEFAULT_PORT}`;
}

function abortIn(ms: number): AbortController {
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), ms);
  return ctrl;
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function isNetworkError(err: unknown): boolean {
  // The same failure class covers "daemon not running",
  // "port not bound", and AbortController-triggered timeouts — the UI
  // treats them identically (daemon offline / not reachable).
  if (err instanceof DOMException && err.name === "AbortError") return true;
  if (err instanceof TypeError) return true; // fetch failed to connect
  return false;
}

export class BridgeClient {
  private readonly baseUrl: string;
  private readonly token: string | null;
  private readonly sessionNonce: string | null;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: BridgeClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? defaultBaseUrl();
    this.token = options.token ?? null;
    this.sessionNonce = options.sessionNonce ?? null;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  /** Compose the privileged-call header set: bearer + optional
   * session nonce. Pair and detect flows use only a subset.  */
  private privilegedHeaders(): Record<string, string> {
    const h: Record<string, string> = {
      "X-NexusInbox-Bridge": this.token ?? "",
    };
    if (this.sessionNonce) {
      h["X-NexusInbox-Bridge-Nonce"] = this.sessionNonce;
    }
    return h;
  }

  /**
   * Probe the daemon. Never throws. Discriminated result lets the
   * UI skip rendering the "Restore" button when the daemon is off.
   */
  async detect(): Promise<BridgeStatus> {
    if (!this.token) return { kind: "unauthorized" };
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/v1/status`, {
        method: "GET",
        headers: this.privilegedHeaders(),
        // The daemon endpoint is loopback; no cookies / credentials.
        credentials: "omit",
        cache: "no-store",
        signal: abortIn(this.timeoutMs).signal,
      });
    } catch (err) {
      if (isNetworkError(err)) return { kind: "offline" };
      throw err;
    }
    if (response.status === 401) return { kind: "unauthorized" };
    if (response.status === 403) return { kind: "forbidden_origin" };
    if (!response.ok) return { kind: "offline" };
    const body = (await safeJson(response)) as
      | null
      | {
          ok?: boolean;
          version?: string;
          aid?: string;
          did?: string;
          encryption_public_key?: string | null;
          paired_sessions?: BridgePairedSession[];
          policy?: BridgeRatePolicy;
        };
    if (!body || body.ok !== true || !body.aid || !body.did) {
      return { kind: "offline" };
    }
    return {
      kind: "available",
      aid: body.aid,
      did: body.did,
      encryption_public_key: body.encryption_public_key ?? null,
      version: body.version ?? "",
      paired_sessions: Array.isArray(body.paired_sessions)
        ? body.paired_sessions
        : [],
      // Daemon pre-Phase-3c omits this field; pass `null` through
      // so older daemons don't break the UI.
      policy: body.policy ?? null,
    };
  }

  /**
   * Exchange a daemon-issued pairing code for a long-lived bearer.
   * The Web UI prompts the operator for the code out of band (it
   * was printed to daemon stderr at startup); we just forward it.
   * Does *not* require a token — that's the whole point of pairing.
   */
  async pair(args: {
    pairingCode: string;
    deviceLabel?: string;
    /**
     * Browser-generated random string stored in sessionStorage. The
     * daemon records its sha256 and will demand the raw value in
     * `X-NexusInbox-Bridge-Nonce` on every privileged call
     * afterwards. Omit for 3b-style pairing (backward compat).
     */
    sessionNonce?: string;
  }): Promise<BridgePairResult> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/v1/pair`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairing_code: args.pairingCode,
          device_label: args.deviceLabel ?? null,
          session_nonce: args.sessionNonce ?? null,
        }),
        credentials: "omit",
        cache: "no-store",
        signal: abortIn(this.timeoutMs).signal,
      });
    } catch (err) {
      if (isNetworkError(err)) return { kind: "offline" };
      throw err;
    }
    if (response.status === 403) return { kind: "forbidden_origin" };
    if (response.status === 401) {
      const text = await response.text().catch(() => "");
      return { kind: "rejected", message: text || "pairing code rejected" };
    }
    if (response.status === 400) {
      const text = await response.text().catch(() => "");
      return { kind: "bad_request", message: text || "bad request" };
    }
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      return {
        kind: "daemon_error",
        message: text || `daemon error ${response.status}`,
      };
    }
    const body = (await safeJson(response)) as {
      token?: string;
      device_label?: string;
      created_at?: string;
    } | null;
    if (!body?.token) {
      return { kind: "daemon_error", message: "daemon returned no token" };
    }
    return {
      kind: "ok",
      token: body.token,
      device_label: body.device_label ?? "",
      created_at: body.created_at ?? new Date().toISOString(),
    };
  }

  /**
   * Revoke the token this client is currently using (DELETE
   * /v1/session). Requires the caller to have supplied a token via
   * the constructor so the daemon can identify the session to drop.
   */
  async revokeSession(): Promise<BridgeRevokeResult> {
    return this.deleteRevoke("/v1/session");
  }

  /**
   * Revoke *every* paired browser in one shot (DELETE
   * /v1/sessions). The legacy shared-secret session survives since
   * that lives in daemon config, not in the inventory.
   */
  async revokeAllSessions(): Promise<BridgeRevokeResult> {
    return this.deleteRevoke("/v1/sessions");
  }

  private async deleteRevoke(path: string): Promise<BridgeRevokeResult> {
    if (!this.token) return { kind: "unauthorized" };
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "DELETE",
        headers: this.privilegedHeaders(),
        credentials: "omit",
        cache: "no-store",
        signal: abortIn(this.timeoutMs).signal,
      });
    } catch (err) {
      if (isNetworkError(err)) return { kind: "offline" };
      throw err;
    }
    if (response.status === 401) return { kind: "unauthorized" };
    if (response.status === 403) return { kind: "forbidden_origin" };
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      return {
        kind: "daemon_error",
        message: text || `daemon error ${response.status}`,
      };
    }
    const body = (await safeJson(response)) as { revoked?: number } | null;
    return { kind: "ok", revoked: body?.revoked ?? 0 };
  }

  /**
   * Ask the daemon to unwrap a single wrapped `content_key`. Never
   * throws for network / auth / malformed conditions — they resolve
   * to a `kind` the UI branches on.
   */
  async unwrap(encryptedKey: string): Promise<BridgeUnwrapResult> {
    if (!this.token) return { kind: "unauthorized" };
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/v1/unwrap`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.privilegedHeaders(),
        },
        body: JSON.stringify({ encrypted_key: encryptedKey }),
        credentials: "omit",
        cache: "no-store",
        signal: abortIn(this.timeoutMs).signal,
      });
    } catch (err) {
      if (isNetworkError(err)) return { kind: "offline" };
      throw err;
    }
    if (response.status === 401) return { kind: "unauthorized" };
    if (response.status === 403) return { kind: "forbidden_origin" };
    if (response.status === 400) {
      const text = await response.text().catch(() => "");
      return { kind: "bad_request", message: text || "bad request" };
    }
    if (response.status === 429) {
      const text = await response.text().catch(() => "");
      // Daemon's Policy L3 tripped — surface as its own kind so the
      // UI can tell "you're out of bridge-decrypt quota" apart from
      // "daemon blew up".
      return {
        kind: "rate_limited",
        message: text || "bridge-decrypt rate cap reached",
      };
    }
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      return {
        kind: "daemon_error",
        message: text || `daemon error ${response.status}`,
      };
    }
    const body = (await safeJson(response)) as { content_key?: string } | null;
    if (!body?.content_key) {
      return { kind: "daemon_error", message: "daemon returned no content_key" };
    }
    return { kind: "ok", content_key: body.content_key };
  }
}
