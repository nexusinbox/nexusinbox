import { expect, test } from "@playwright/test";
import { mockNexusInboxBackend } from "./_helpers/mocks";

/**
 * The AI-draft and Calendar integrations call third-party APIs straight
 * from the browser with the user's own key (BYOK). CSP is enforced by the
 * browser, so no unit test can prove those calls are allowed — this spec
 * loads a real page under the served CSP and fetches each URL from inside
 * it (review 2026-09-07: both features were silently blocked in prod).
 *
 * A request CSP blocks never reaches the network, so the route handlers
 * below never fire for it and `fetch` rejects. "Handler fired + 200" is
 * therefore direct proof the policy admits the URL, and the example.com
 * control proves the policy is actually being enforced.
 *
 * `next dev` serves the same BYOK entries as production (only the
 * localhost / ws:// dev extras differ, see middleware.ts).
 */
test("CSP admits the BYOK endpoints by exact URL and still blocks everything else", async ({
  page,
}) => {
  await mockNexusInboxBackend(page);

  const fired: string[] = [];
  const answer = (label: string) => async (route: import("@playwright/test").Route) => {
    fired.push(label);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "access-control-allow-origin": "*" },
      body: "{}",
    });
  };
  await page.route("https://api.anthropic.com/**", answer("anthropic"));
  await page.route("https://www.googleapis.com/**", answer("googleapis"));
  await page.route("https://oauth2.googleapis.com/**", answer("revoke"));
  await page.route("https://example.com/**", answer("example"));

  // /help is public, so no session is needed; CSP is minted per request.
  const response = await page.goto("/help");
  const csp = response?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("https://api.anthropic.com/v1/messages");

  const results = await page.evaluate(async () => {
    // A plain-text POST is a "simple" CORS request (no preflight), so the
    // only thing between fetch and the mocked 200 is CSP.
    const probe = async (url: string) => {
      try {
        const res = await fetch(url, { method: "POST", body: "{}" });
        return `ok:${res.status}`;
      } catch (error) {
        return `blocked:${(error as Error).name}`;
      }
    };
    return {
      anthropic: await probe("https://api.anthropic.com/v1/messages"),
      freebusy: await probe("https://www.googleapis.com/calendar/v3/freebusy"),
      revoke: await probe("https://oauth2.googleapis.com/revoke"),
      // Same provider, different path: exact-URL sources must not open it.
      otherGooglePath: await probe("https://www.googleapis.com/drive/v3/files"),
      control: await probe("https://example.com/"),
    };
  });

  expect(results.anthropic).toBe("ok:200");
  expect(results.freebusy).toBe("ok:200");
  expect(results.revoke).toBe("ok:200");
  expect(results.otherGooglePath).toMatch(/^blocked:/);
  expect(results.control).toMatch(/^blocked:/);
  expect(fired).toEqual(expect.arrayContaining(["anthropic", "googleapis", "revoke"]));
  expect(fired).not.toContain("example");
});
