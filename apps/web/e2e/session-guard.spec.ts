import { expect, test } from "@playwright/test";
import { mockNexusInboxBackend } from "./_helpers/mocks";

test("session guard: protected page redirects to login when session endpoint returns unauthenticated", async ({ page }) => {
  // Catchall + boot-path mocks first, then the spec-specific 401
  // session handler is layered after so it wins on Playwright's
  // last-registered-first match. Without the catchall the AppShell
  // boot queries proxy to the absent :8080 backend and the 5s
  // ECONNREFUSED timeouts can stall the redirect we're asserting on.
  await mockNexusInboxBackend(page);

  await page.goto("/login");
  const currentUrl = new URL(page.url());

  await page.context().addCookies([
    {
      name: "nexusinbox_session",
      value: "stale-session",
      url: `${currentUrl.protocol}//${currentUrl.host}`,
    },
  ]);

  await page.route("**/api/auth/session", async (route) => {
    await route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ authenticated: false, reason: "expired" }),
    });
  });

  await page.goto("/compose");
  // Client-side guard in AuthSessionStatus redirects to /login with next=/compose.
  await expect.poll(() => new URL(page.url()).pathname).toBe("/login");
  await expect.poll(() => new URL(page.url()).searchParams.get("next")).toBe("/compose");
});
