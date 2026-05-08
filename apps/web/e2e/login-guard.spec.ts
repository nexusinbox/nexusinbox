import { expect, test } from "@playwright/test";
import { makeFutureSessionJwt } from "./_helpers/auth";

test("login guard: authenticated user can still open /login for re-authentication", async ({ page }) => {
  await page.goto("/login");
  const currentUrl = new URL(page.url());

  await page.context().addCookies([
    {
      name: "nexusinbox_session",
      value: makeFutureSessionJwt(),
      url: `${currentUrl.protocol}//${currentUrl.host}`,
    },
  ]);

  await page.goto("/login?next=%2Fcompose");
  await expect(page).toHaveURL(/\/login\?next=%2Fcompose$/);
  await expect(page.getByTestId("login-root")).toBeVisible();
});

test("login page: shows error state when world config endpoint returns non-json", async ({ page }) => {
  await page.route("**/api/world/request-config", async (route) => {
    await route.fulfill({
      status: 500,
      contentType: "text/html",
      body: "<!DOCTYPE html><html><body>error</body></html>",
    });
  });

  await page.goto("/login");
  await page.getByTestId("login-cta").click();

  // The iframe at /login/idkit fetches /api/world/request-config, hits
  // the mocked 500+HTML response, and postMessages the error back to
  // the parent. The parent renders it into the `login-status` element.
  //
  // We assert via `data-kind="error"` rather than the rendered text so
  // the test stays locale-independent — the same flow is exercised in
  // both ja and en builds.
  const status = page.getByTestId("login-status");
  await expect(status).toHaveAttribute("data-kind", "error");
  // Sanity: the status element renders *some* non-empty message.
  await expect(status).not.toHaveText(/^\s*$/);
});

test("login page: CTA mounts the /login/idkit iframe (not a direct IDKit widget)", async ({ page }) => {
  await page.goto("/login");
  await page.getByTestId("login-cta").click();

  const iframe = page.getByTestId("login-iframe");
  await expect(iframe).toBeVisible();
  const src = await iframe.getAttribute("src");
  expect(src).toMatch(/^\/login\/idkit(\?.*)?$/);
});

// NOTE: CSP route-isolation (no `'unsafe-eval'` on /login, eval-allowed
// only on /login/idkit) is intentionally NOT asserted in this spec.
// Playwright runs against `next dev`, which broadens CSP to permit
// HMR — running the assertion here produced false negatives. The
// invariant is exercised by `apps/web/security-headers.test.ts`
// (vitest, calls `buildCsp(nonce, pathname)` directly with both
// pathnames) and by docs/18 §10.3 which documents the shipped
// middleware behaviour. Add a separate `*.prod.spec.ts` once a CI
// step builds and serves a production bundle.
