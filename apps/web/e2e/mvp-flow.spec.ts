import { expect, test } from "@playwright/test";
import { makeFutureSessionJwt } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

test("MVP flow: login screen shown, then direct route to inbox -> detail -> compose", async ({
  page,
}) => {
  // Force the JA locale so the assertions below ("作成", "新規メッセージ",
  // "送信") match the rendered labels. Without this the i18n provider
  // falls back to `en` for a fresh Playwright context (no
  // localStorage from a prior session) and the same selectors miss.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  // Wire up the deterministic backend BEFORE navigating: AppShell
  // hits `/agents`, `/messages`, `/contacts`, etc. on every boot,
  // and an unmocked endpoint will leave the page in a loading
  // skeleton (no `.thread-item` rows, no sidebar links). See
  // `e2e/_helpers/mocks.ts` for the seed shape.
  await mockNexusInboxBackend(page);

  await page.goto("/login");

  await expect(page.getByTestId("login-root")).toBeVisible();
  await expect(page.getByRole("link", { name: "Skip to Dashboard" })).toHaveCount(0);

  const currentUrl = new URL(page.url());
  await page.context().addCookies([
    {
      name: "nexusinbox_session",
      value: makeFutureSessionJwt(),
      url: `${currentUrl.protocol}//${currentUrl.host}`,
    },
  ]);

  // Current e2e scope intentionally shortcuts auth and navigates
  // directly with a session cookie.
  await page.goto("/");

  await expect(page).toHaveURL(/\/$/);

  // Inbox row from the seeded /api/messages response.
  const firstThread = page.locator(".thread-item").first();
  await expect(firstThread).toBeVisible();
  await firstThread.click();

  // Detail pane is rendered by ConversationThread. The seeded
  // envelope is intentionally undecryptable on this device so the
  // component falls back to its passthrough / unavailable branch —
  // which still mounts the `.conversation-thread` container and
  // at least one `.conversation-message-body` panel. We assert on
  // those two markers instead of `.reader-subject`, because the
  // subject `<h2>` legitimately renders empty when the encrypted
  // value can't decrypt and Playwright reports an empty heading
  // as `hidden`.
  await expect(page.locator(".conversation-thread")).toBeVisible();
  await expect(page.locator(".conversation-message-body").first()).toBeVisible();

  // Compose pill in the topbar / sidebar takes the user to /compose.
  await page.getByRole("link", { name: "作成" }).first().click();

  await expect(page).toHaveURL(/\/compose$/);
  await expect(page.getByText("新規メッセージ")).toBeVisible();
  // Send button label is plain "送信" (renamed from
  // "暗号化して送信" upstream); the smoke check only confirms the
  // submit button mounts so the user has a path forward.
  await expect(
    page.getByRole("button", { name: "送信" }).first(),
  ).toBeVisible();
});
