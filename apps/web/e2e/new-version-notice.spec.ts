import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

// A tab left open across a deploy keeps running the old code. The shell
// asks /app-version which build the server runs and offers a reload once
// it differs from the build the tab was loaded from (playwright.config.ts
// starts the dev server as build "e2e-build").

test.beforeEach(async ({ page, context, baseURL }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });
  await mockNexusInboxBackend(page);
  await seedAuthSessionCookie(context, baseURL);
});

test("new version notice: stays hidden while the server runs the same build", async ({ page }) => {
  const checked = page.waitForResponse((r) => r.url().endsWith("/app-version"));
  await page.goto("/");
  const response = await checked;
  expect(await response.json()).toEqual({ version: "e2e-build" });
  await expect(page.getByTestId("new-version-notice")).toHaveCount(0);
});

test("new version notice: offers a reload once the server runs a newer build", async ({ page }) => {
  await page.route("**/app-version", (route) =>
    route.fulfill({ json: { version: "next-build" }, headers: { "Cache-Control": "no-store" } }),
  );
  await page.goto("/");
  const notice = page.getByTestId("new-version-notice");
  await expect(notice).toContainText("新しい版があります");

  // Reloading picks up the new build; with the server on it, the notice goes.
  await page.unroute("**/app-version");
  await page.getByTestId("new-version-reload").click();
  await page.waitForLoadState("load");
  await expect(page.getByTestId("new-version-notice")).toHaveCount(0);
});
