import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

test("realtime subscriber: new_message WS push triggers a messages refetch", async ({
  page,
  context,
  baseURL,
}) => {
  // Catchall + boot-path mocks first so AppShell's /api/agents,
  // /api/contacts, etc. don't proxy to the absent :8080 backend.
  // The /api/messages handler below is layered after so it wins
  // on Playwright's last-registered-first match order; we need it
  // to count fetches in this spec.
  await mockNexusInboxBackend(page);

  // Land on `/` directly (skip /login round-trip) by injecting a
  // future-`exp` session cookie before navigation. Without this,
  // middleware (`apps/web/middleware.ts:215`) would treat the cookie
  // as expired and redirect to /login — see the helper's docstring.
  await seedAuthSessionCookie(context, baseURL);

  // Intercept any messages list fetches (real or mocked) and track hit
  // count so we can assert that WS pushes trigger a re-fetch.
  let messagesFetchCount = 0;
  await page.route("**/api/messages*", async (route) => {
    messagesFetchCount += 1;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ messages: [], total: 0 }),
    });
  });

  // Mock the WebSocket upgrade so we don't need a running API server.
  await page.routeWebSocket("**/api/ws", (ws) => {
    // Immediately push a `new_message` event like the real server does.
    ws.send(
      JSON.stringify({
        event: "new_message",
        data: {
          message_id: "00000000-0000-0000-0000-000000000000",
          agent_did: "did:key:zTest",
          sender_did: "did:key:zSystem",
          subject_encrypted: "c3ViamVjdA==",
          priority: "normal",
          timestamp: new Date().toISOString(),
        },
      }),
    );
  });

  await page.goto("/");

  // The visible "Live" badge was intentionally removed — RealtimeSubscriber
  // is now a side-effect-only component (returns null, see
  // apps/web/app/_components/RealtimeSubscriber.tsx). Assert the *behaviour*
  // the user actually relies on: a `new_message` push invalidates the
  // `messages` query, react-query re-fetches, and our /api/messages mock
  // sees a second hit.
  //
  // Initial mount fetches once; the WS push triggers an invalidation that
  // schedules at least one more fetch. We assert >= 2 hits, which is
  // tolerant of react-query's exact replay timing.
  await expect.poll(() => messagesFetchCount, { timeout: 5_000 }).toBeGreaterThanOrEqual(2);
});
