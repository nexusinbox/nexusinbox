import { expect, test } from "@playwright/test";
import { makeFutureSessionJwt } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

test("logout flow: authenticated user can sign out and is redirected to login", async ({ page }) => {
  // Force JA locale so the "ログアウト" button label matches; Playwright
  // contexts start with no localStorage so the i18n provider would
  // otherwise default to en.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  // Stand up the deterministic backend (seed agent / message + 404
  // catchall) so AppShell's boot queries don't hammer the absent
  // :8080 proxy. Without this the dev server gets back-pressured by
  // a flood of ECONNREFUSED errors and the logout button can take
  // long enough to mount that the test times out under parallel
  // load — even though it passes in isolation.
  await mockNexusInboxBackend(page);

  await page.goto("/login");

  const currentUrl = new URL(page.url());
  const appOrigin = `${currentUrl.protocol}//${currentUrl.host}`;

  // Future-`exp` JWT so middleware (`apps/web/middleware.ts:215`) lets
  // the request through; without this the goto("/") below would be
  // redirected to /login and the visible-logout-button assertion
  // would never fire.
  await page.context().addCookies([
    {
      name: "nexusinbox_session",
      value: makeFutureSessionJwt(),
      url: appOrigin,
    },
  ]);

  // Layered after mockNexusInboxBackend so this more-specific route
  // wins (Playwright matches in registration order, last-wins). The
  // helper already returns an authenticated session, but logout
  // needs a separate handler that emits the cookie-clearing
  // Set-Cookie header.
  await page.route("**/api/auth/logout", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: {
        "set-cookie": "nexusinbox_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
      },
      body: JSON.stringify({ success: true }),
    });
  });

  await page.goto("/");
  await expect(page).toHaveURL(/\/$/);

  const logoutButton = page.getByRole("button", { name: /ログアウト|Logout/ });
  await expect(logoutButton).toBeVisible();
  await logoutButton.click();

  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByTestId("login-root")).toBeVisible();

  await page.goto("/");
  await expect(page).toHaveURL(/\/login\?next=%2F$/);
});
