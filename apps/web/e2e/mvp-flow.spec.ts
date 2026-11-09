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
  // skeleton (no conversation rows, no sidebar links). See
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

  // Conversation row from the seeded /api/messages response.
  const firstThread = page.getByTestId("dm-row").first();
  await expect(firstThread).toBeVisible();
  await firstThread.click();

  // The conversation view. The seeded envelope is intentionally
  // undecryptable on this device, so the message shows its
  // unavailable branch — still one message in the conversation.
  await expect(page.locator(".dm-conv")).toBeVisible();
  await expect(page.getByTestId("dm-message").first()).toBeVisible();

  // Compose pill in the topbar / sidebar takes the user to /compose.
  await page.getByRole("link", { name: "新しい会話" }).first().click();

  await expect(page).toHaveURL(/\/compose$/);
  // A bare /compose is the 新しい会話 picker (docs/35 step 3); the full
  // form is one link away.
  await page.getByTestId("new-conversation-full-form").click();
  await expect(page).toHaveURL(/\/compose\?full=1/);
  await expect(page.getByText("新規メッセージ")).toBeVisible();
  // Send button label is plain "送信" (renamed from
  // "暗号化して送信" upstream); the smoke check only confirms the
  // submit button mounts so the user has a path forward.
  await expect(
    page.getByRole("button", { name: "送信" }).first(),
  ).toBeVisible();
});
