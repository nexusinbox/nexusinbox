import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

test("global navigation: menu links open target pages without bouncing back to inbox", async ({
  page,
  context,
  baseURL,
}) => {
  // Force the JA locale so the navigation labels below
  // ("確認が必要", "エージェント", etc.) match what the
  // shell renders. The i18n provider defaults to `en` for a fresh
  // Playwright context.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  // Wire up the deterministic backend before navigation, so the shell
  // mounts cleanly and count badges do not stay in a loading state.
  await mockNexusInboxBackend(page);

  await seedAuthSessionCookie(context, baseURL);

  await page.goto("/");
  await expect(page).toHaveURL(/\/$/);

  // Sidebar — the mail items (docs/34 §3 step 3).
  await page.getByRole("link", { name: "確認が必要", exact: true }).click();
  await expect(page).toHaveURL(/\/pending$/);
  await page.getByRole("link", { name: "アーカイブ", exact: true }).click();
  await expect(page).toHaveURL(/\/\?view=archive$/);

  // Sidebar — "エージェント" → /settings/agents.
  await page.getByRole("link", { name: "エージェント", exact: true }).click();
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
