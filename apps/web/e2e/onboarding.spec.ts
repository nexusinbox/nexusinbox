// First-run guide (docs/41 stage B): only checked AI tools can be chosen,
// a phone stops before creating anything, and connecting waits for the
// AI's permission before moving on.
import { expect, test, type Page } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

const iso = (ms: number) => new Date(ms).toISOString();
const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });

const AGENT = {
  id: "00000000-0000-0000-0000-0000000000b1",
  did: "did:key:zOnboard",
  aid: "aid:ai:ONBOARD",
  label: "秘書",
  public_key: "pk",
  encryption_key: "ek",
  is_active: true,
  auto_reply: false,
  unread_count: 0,
  created_at: iso(Date.now()),
  devices: [{ did: "did:key:zOnboard", kind: "browser", activated_at: iso(Date.now()) }],
};

async function setup(page: Page, state: { granted: boolean }) {
  let created = false;
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
    window.localStorage.setItem("nexusinbox-theme", "light");
  });
  await mockNexusInboxBackend(page);
  await page.route("**/api/agents*", (r) => {
    if (r.request().method() === "POST") {
      created = true;
      return r.fulfill(json({ id: AGENT.id, did: AGENT.did, aid: AGENT.aid, label: AGENT.label }));
    }
    return r.fulfill(json({ agents: created ? [AGENT] : [] }));
  });
  await page.route("**/api/agents/*", (r) => r.fulfill(json(AGENT)));
  await page.route("**/api/agents/*/auto-reply-policy*", (r) => r.fulfill(json({ policy: {}, revision: 1 })));
  await page.route("**/api/agent-credentials*", (r) =>
    r.fulfill(
      json({
        credentials: [
          {
            credential_id: "c1",
            aid: AGENT.aid,
            label: "MacBook Air",
            status: "active",
            key_holder: "signer_daemon",
            activated_at: iso(Date.now() - 60_000),
            last_used_at: iso(Date.now() - 5_000),
            cloud_access: true,
            cloud_url: "https://k3x9q7.mcp.agent-inbox.ai/mcp",
            cloud_serving_at: iso(Date.now() - 5_000),
          },
        ],
      }),
    ),
  );
  await page.route("**/api/oauth/grants*", (r) =>
    r.fulfill(
      json({
        grants: state.granted
          ? [{ id: "g1", aid: AGENT.aid, resource: "https://k3x9q7.mcp.agent-inbox.ai/mcp", agent_label: "秘書", client_name: "Claude Code", scope: [], created_at: iso(Date.now()), last_used_at: iso(Date.now()) }]
          : [],
      }),
    ),
  );
}

test("first run: Claude Code is connected once the computer runs and the AI is allowed", async ({
  page,
  context,
  baseURL,
}) => {
  const state = { granted: false };
  await setup(page, state);
  await seedAuthSessionCookie(context, baseURL);

  // No agent yet: Home sends the person to the guide.
  await page.goto("/");
  await expect(page).toHaveURL(/\/onboarding$/);

  // AI tools still being checked cannot be chosen (docs/41 §5.2.1).
  await expect(page.getByTestId("first-run-ai-muse")).toBeDisabled();
  await expect(page.getByTestId("first-run-ai-desktop")).toBeDisabled();
  await expect(page.getByTestId("first-run-next")).toBeDisabled();
  await page.getByTestId("first-run-ai-claude-code").click();
  await page.getByTestId("first-run-next").click();

  await page.getByTestId("first-run-name").fill("秘書");
  await page.getByTestId("first-run-create").click();

  const connect = page.getByTestId("first-run-connect");
  await expect(connect).toContainText("接続しました（MacBook Air）");
  await expect(page.getByTestId("first-run-mcp-add")).toHaveText(
    "claude mcp add --transport http nexusinbox https://k3x9q7.mcp.agent-inbox.ai/mcp",
  );
  // Not allowed yet: no way forward but connecting later.
  await expect(page.getByTestId("first-run-connect-later")).toBeVisible();
  await expect(page.getByTestId("first-run-granted")).toHaveCount(0);

  state.granted = true;
  await expect(page.getByTestId("first-run-granted")).toContainText("Claude Code", { timeout: 15_000 });
  await page.getByTestId("first-run-next").click();
  await expect(page.getByText("どこまで任せますか？")).toBeVisible();
  await expect(page.getByTestId("preset-manual")).toHaveAttribute("aria-checked", "true");
});

test.describe("on a phone", () => {
  test.use({ viewport: { width: 320, height: 700 }, isMobile: true, hasTouch: true });

  test("first run: an AI that needs a computer stops before anything is created", async ({ page, context, baseURL }) => {
    await setup(page, { granted: false });
    await seedAuthSessionCookie(context, baseURL);
    await page.goto("/onboarding");
    await page.getByTestId("first-run-ai-claude-code").click();
    await page.getByTestId("first-run-next").click();
    await expect(page.getByTestId("first-run-mobile")).toContainText("パソコンでこのページを開いてください");
    await expect(page.getByTestId("first-run-name")).toHaveCount(0);
    await page.getByTestId("first-run-web-only").click();
    await expect(page.getByTestId("first-run-name")).toBeVisible();
    await expect(page.getByTestId("first-run-step")).toContainText("ステップ 2 / 5");
  });
});
