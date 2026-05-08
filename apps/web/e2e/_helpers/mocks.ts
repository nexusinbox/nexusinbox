/**
 * Shared route mocks for the deterministic-flow E2E specs
 * (mvp-flow, navigation-links, etc.).
 *
 * The signed-in shell talks to a handful of endpoints on every
 * boot — `/api/auth/session`, `/api/agents`, `/api/messages` (per
 * folder), `/api/contacts`, plus a few agent-settings extras —
 * and any of them hanging or 5xx-ing leaves the page in a
 * loading skeleton with no `.thread-item` rows or sidebar links.
 * That's the regression the OSS prep audit caught.
 *
 * The smoke specs don't need a real backend; they just need the
 * boot path to *resolve* deterministically. So this helper
 * registers route handlers that:
 *
 *   - return a single-agent / single-message seed so the inbox
 *     list, sidebar agent counters, and ConversationThread mount
 *     have something to render;
 *   - return empty defaults for everything else (contacts,
 *     credentials, audit log, etc.) so peripheral panels don't
 *     hang waiting on the network.
 *
 * Mutations (POST/PATCH/DELETE) fall through to `route.fallback()`
 * by default — the smoke specs are read-only, and any test that
 * needs to exercise a write path should layer a more specific
 * route AFTER calling this helper.
 */

import type { Page } from "@playwright/test";

export const SEED_AGENT = {
  id: "00000000-0000-0000-0000-000000000aa1",
  did: "did:key:zE2EAGENTSEED01",
  aid: "aid:ai:01E2ESEEDAGENT01",
  label: "Test agent",
  public_key: "pkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpk",
  encryption_key: "ekekekekekekekekekekekekekekekekekekekek",
  is_active: true,
  auto_reply: false,
  unread_count: 1,
  created_at: "2026-05-01T00:00:00Z",
} as const;

export const SEED_MESSAGE = {
  id: "00000000-0000-0000-0000-000000000bb1",
  sender_did: "did:key:zE2ESENDERSEED01",
  sender_label: "Test sender",
  recipient_did: SEED_AGENT.did,
  recipient_label: SEED_AGENT.label,
  thread_id: null,
  subject_encrypted: "U0VFRF9TVUJKRUNUX0VOQ1JZUFRFRA",
  storage_ref: "byos://localfs/seed-message.bin",
  status: "unread",
  priority: "normal",
  ai_category: null,
  created_at: "2026-05-08T00:00:00Z",
  trust_score: 0.5,
  folder: "inbox",
  starred: false,
} as const;

function jsonOk(body: unknown) {
  return {
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  };
}

/**
 * Wire up the deterministic backend for an authenticated, single-
 * agent, single-message smoke flow. Call this BEFORE `page.goto`
 * so the mocks are in place when the boot path fires its requests.
 */
export async function mockNexusInboxBackend(page: Page): Promise<void> {
  // Last-resort catchall registered FIRST so it loses to every
  // specific route below (Playwright matches routes in
  // most-recently-registered-wins order). Anything that isn't
  // explicitly handled returns a deterministic 404 here — without
  // this, the next.js dev server proxies the request to a backend
  // that isn't running on :8080 and each ECONNREFUSED takes ~5s to
  // fail. Under fullSuite parallel load that back-pressures the
  // dev server enough to slow real navigations to a crawl, which
  // is what previously made mvp-flow / navigation-links flake when
  // run alongside the rest of the suite.
  await page.route("**/api/**", async (route) => {
    await route.fulfill({
      status: 404,
      contentType: "application/json",
      body: JSON.stringify({ error: "not_mocked" }),
    });
  });

  // Session check fired by AuthSessionStatus in AppShell.
  await page.route("**/api/auth/session", async (route) => {
    await route.fulfill(
      jsonOk({
        authenticated: true,
        user: {
          id: "00000000-0000-0000-0000-000000000001",
          display_name: "E2E user",
        },
      }),
    );
  });

  // /agents — list returns the seed agent so byAgent / agentSettings
  // links + the sidebar agent counter resolve. Mutations fall through.
  await page.route("**/api/agents*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill(jsonOk({ agents: [SEED_AGENT] }));
      return;
    }
    await route.fallback();
  });

  // /messages — folder=inbox (and the empty default) gets the seed
  // message; every other folder returns an empty list. /messages/{id}
  // and /messages/{id}/content return content envelopes shaped just
  // enough for ConversationThread to mount its DOM nodes; the body
  // ciphertext is bogus by design (decryption will fail and the
  // component falls back to its visible "unavailable" / "decrypt
  // failed" card, which still includes the .reader-subject and
  // .conversation-message-body selectors the specs assert on).
  await page.route("**/api/messages**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();

    const contentMatch = url.pathname.match(
      /^\/api\/messages\/([^/]+)\/content$/,
    );
    if (contentMatch && method === "GET") {
      // MessageContentResponse is *flat*, not nested under
      // `envelope`. The fields are the ones consumed directly by
      // ConversationThread + decryptEnvelopeText. The encrypted_*
      // values are intentionally not real `enc:v1:…` payloads —
      // parseEncryptedPayload will return null and the decrypt
      // helper falls back to its `passthrough` branch, which still
      // counts as a readable state and lets the subject row mount.
      await route.fulfill(
        jsonOk({
          encrypted_content: "AAAAAAAAAAAAAAAAAAAAAAAA",
          encrypted_key: "x25519v1:AAAA:AAAA:AAAA:AAAA",
          nonce: "AAAAAAAAAAAAAAAAAAAAAAAA",
          sender_did: SEED_MESSAGE.sender_did,
          recipient_did: SEED_MESSAGE.recipient_did,
          subject_encrypted: SEED_MESSAGE.subject_encrypted,
          thread_id: null,
          content_type: "text/plain",
        }),
      );
      return;
    }

    if (method === "GET" && url.pathname === "/api/messages") {
      const folder = url.searchParams.get("folder");
      const showSeed = !folder || folder === "inbox" || folder === "all";
      const messages = showSeed ? [SEED_MESSAGE] : [];
      await route.fulfill(
        jsonOk({
          messages,
          total: messages.length,
          page: 1,
          per_page: Number(url.searchParams.get("per_page") ?? 50),
        }),
      );
      return;
    }

    await route.fallback();
  });

  // Empty defaults for the panels around the inbox so their boot
  // queries don't hang the page. We do not assert anything against
  // these in the smoke specs — they exist purely to keep the shell
  // out of perpetual loading state.
  await page.route("**/api/contacts*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill(jsonOk({ contacts: [] }));
      return;
    }
    await route.fallback();
  });

  await page.route("**/api/blocks*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill(jsonOk({ blocks: [] }));
      return;
    }
    await route.fallback();
  });

  await page.route("**/api/agent-credentials*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill(jsonOk({ credentials: [] }));
      return;
    }
    await route.fallback();
  });

  await page.route("**/api/agent-audit-log*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill(jsonOk({ events: [], total: 0 }));
      return;
    }
    await route.fallback();
  });

  await page.route("**/api/agents/*/auto-reply-policy*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill(jsonOk({ policy: null, revision: 0 }));
      return;
    }
    await route.fallback();
  });

  // Integrations status — used by /integrations; otherwise returns
  // a benign "all-green" payload so the page renders.
  await page.route("**/api/integrations/status*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill(
        jsonOk({
          api: { ok: true, version: "test" },
          world_id: { configured: false },
          postgres: { connected: false },
          websocket: { enabled: false },
          purge: { enabled: false },
          storage: { backend: "localfs", enabled: true },
          agents: { count: 1 },
        }),
      );
      return;
    }
    await route.fallback();
  });
}
