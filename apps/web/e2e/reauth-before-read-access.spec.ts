// Handing out read access needs a recent World ID sign-in (audit run-6,
// mock docs/33_reauth_mock.html): an older session gets the notice and a
// way back to this page through World ID.
import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

test("consent: an old sign-in is asked to confirm with World ID and comes back here", async ({
  page,
  context,
  baseURL,
}) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
    window.localStorage.setItem("nexusinbox-theme", "light");
  });
  await mockNexusInboxBackend(page);
  await page.route("**/api/oauth/authorize/info**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        client_name: "Claude",
        client_id: "c1",
        client_kind: "registered",
        redirect_host: "claude.ai",
        agent_label: "秘書",
        device_label: "macOS",
        aid: "aid:ai:01E2ESEEDAGENT01",
        scope: ["inbox.read", "inbox.draft"],
      }),
    }),
  );
  let decided = 0;
  await page.route("**/api/oauth/authorize", (route) => {
    decided += 1;
    return route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ error: "reauthentication_required", message: "sign in again" }),
    });
  });
  await seedAuthSessionCookie(context, baseURL);
  const query = "response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb&state=xyz&code_challenge=abc&code_challenge_method=S256&resource=https%3A%2F%2Fx.mcp.agent-inbox.ai%2Fmcp";
  await page.goto(`/oauth/authorize?${query}`);
  await page.getByRole("button", { name: "許可する" }).click();

  const notice = page.getByTestId("reauth-notice");
  await expect(notice).toContainText("World ID で確かめてください");
  await expect(notice).toContainText("確かめたあと、この画面に戻ります");
  expect(decided).toBe(1);
  const href = await notice.getByRole("link", { name: "World ID で確かめる" }).getAttribute("href");
  // Back to this consent page, with its parameters, after signing in again.
  const next = new URL(href!, "https://x.invalid").searchParams.get("next");
  expect(next).toBe(`/oauth/authorize?${query}`);
  expect(href).toContain("reauth=1");
  if (process.env.SHOT) await page.screenshot({ path: process.env.SHOT, fullPage: true });
});
