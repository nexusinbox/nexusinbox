import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

test("global navigation: menu links open target pages without bouncing back to inbox", async ({
  page,
  context,
  baseURL,
}) => {
  // Force the JA locale so the navigation labels below
  // ("ホーム", "会話", "エージェント", etc.) match what the
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

  // Home first; the four main places, then the archive (docs/41 §3).
  await expect(page.getByTestId("home-attention")).toBeVisible();
  await page.getByRole("link", { name: /^会話/ }).first().click();
  await expect(page).toHaveURL(/\/conversations$/);
  await page.getByRole("link", { name: "アーカイブ", exact: true }).click();
  await expect(page).toHaveURL(/\/conversations\?view=archive$/);
  await page.getByRole("link", { name: /^ホーム/ }).first().click();
  await expect(page).toHaveURL(/\/$/);

  // Sidebar — "エージェント" → /settings/agents.
  await page.getByRole("link", { name: "エージェント", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/agents$/);

  // `aria-label="アプリ"` → /integrations.
  await page.getByLabel("アプリ").click();
  await expect(page).toHaveURL(/\/integrations$/);

  // The avatar, `aria-label="プロフィール"` → /settings/profile.
  await page.getByLabel("プロフィール").click();
  await expect(page).toHaveURL(/\/settings\/profile$/);

  // Sidebar — "ヘルプ" → /help, last: /help is public, with its own frame.
  await page.getByRole("link", { name: "ヘルプ", exact: true }).first().click();
  await expect(page).toHaveURL(/\/help$/);
});
