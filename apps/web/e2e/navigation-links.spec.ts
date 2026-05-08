import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend, SEED_AGENT } from "./_helpers/mocks";

test("global navigation: menu links open target pages without bouncing back to inbox", async ({
  page,
  context,
  baseURL,
}) => {
  // Force the JA locale so the navigation labels below
  // ("エージェント別", "エージェント設定", etc.) match what the
  // shell renders. The i18n provider defaults to `en` for a fresh
  // Playwright context.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  // Wire up the deterministic backend before navigation. Without the
  // /api/agents seed, the sidebar's "エージェント別" link falls back
  // to the placeholder /agent route and the count badge stays in a
  // loading-shaped state — both of which can throw off Playwright's
  // accessible-name lookup. With the seed in place, the link
  // resolves to /agent/<seed-did> and the rest of the shell mounts
  // cleanly.
  await mockNexusInboxBackend(page);

  await seedAuthSessionCookie(context, baseURL);

  await page.goto("/");
  await expect(page).toHaveURL(/\/$/);

  // Sidebar — "エージェント別" navigates to the byAgent page bound
  // to the first owned agent's did. Accept either the bare /agent
  // route (cold-cache, before the agents query resolves) or
  // /agent/<did> (warm-cache, after AppShell has rewritten the
  // href). With the mocked agents response above, the warm path is
  // the realistic one.
  await page.getByRole("link", { name: "エージェント別" }).click();
  await expect(page).toHaveURL(
    new RegExp(`/agent(/${encodeURIComponent(SEED_AGENT.did)})?$`),
  );

  // Sidebar — "エージェント設定" → /settings/agents.
  await page.getByRole("link", { name: "エージェント設定" }).click();
  await expect(page).toHaveURL(/\/settings\/agents$/);

  // Topbar icon — `aria-label="ヘルプ"` → /help. /help is public so
  // no extra mocking is needed for this hop.
  await page.getByLabel("ヘルプ").click();
  await expect(page).toHaveURL(/\/help$/);

  // Topbar icon — `aria-label="アプリ"` → /integrations.
  await page.getByLabel("アプリ").click();
  await expect(page).toHaveURL(/\/integrations$/);

  // Topbar avatar — `aria-label="プロフィール"` → /settings/profile.
  await page.getByLabel("プロフィール").click();
  await expect(page).toHaveURL(/\/settings\/profile$/);
});
