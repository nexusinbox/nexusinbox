import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

type BlockEntry = {
  id: string;
  level: "l1_did" | "l2_identity" | "l3_stealth";
  target_did: string | null;
  target_world_id: string | null;
  created_at: string;
};

function blockId(index: number): string {
  return `00000000-0000-0000-0000-${String(index).padStart(12, "b")}`;
}

test("blocks management: list, create L1/L2, delete", async ({ page, context, baseURL }) => {
  const blocks: BlockEntry[] = [];
  let seq = 1;

  // JA locale so the asserted labels ("ブロックはありません。", "ブロック追加",
  // etc.) match the rendered text. Playwright contexts have no
  // localStorage by default and the i18n provider falls back to en.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  // Stand up the deterministic backend (session + agents + 404
  // catchall) so AppShell's boot queries don't proxy to the absent
  // :8080 backend. The blocks-specific routes layered after this
  // call win because Playwright matches routes last-registered-first.
  await mockNexusInboxBackend(page);

  await page.route("**/api/blocks", async (route) => {
    const method = route.request().method();
    if (method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ blocks }),
      });
      return;
    }
    if (method === "POST") {
      const payload = route.request().postDataJSON() as {
        level: BlockEntry["level"];
        target_did?: string;
        target_world_id?: string;
      };
      const id = blockId(seq++);
      blocks.unshift({
        id,
        level: payload.level,
        target_did: payload.target_did ?? null,
        target_world_id: payload.target_world_id ?? null,
        created_at: new Date().toISOString(),
      });
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({ id }),
      });
      return;
    }
    await route.fallback();
  });

  await page.route("**/api/blocks/*", async (route) => {
    if (route.request().method() === "DELETE") {
      const url = new URL(route.request().url());
      const id = url.pathname.split("/").pop()!;
      const before = blocks.length;
      const idx = blocks.findIndex((b) => b.id === id);
      if (idx >= 0) blocks.splice(idx, 1);
      await route.fulfill({
        status: blocks.length < before ? 204 : 404,
        contentType: "application/json",
        body: blocks.length < before ? "" : JSON.stringify({ error: "not_found" }),
      });
      return;
    }
    await route.fallback();
  });

  await seedAuthSessionCookie(context, baseURL);

  await page.goto("/settings/blocks");
  await expect(page).toHaveURL(/\/settings\/blocks$/);
  await expect(page.getByText("ブロックはありません。")).toBeVisible();

  // Block list rows now render as `.card-item` (the older
  // `.thread-item` class went away when the page moved off the
  // shared inbox layout). Add-button label is the full
  // `t("blocks.addBtn")` string ("追加 (上級者向け手入力)") and the
  // delete button is `t("blocks.unblock")` ("ブロック解除"). The
  // displayed level title is the long localized label, not "L1" /
  // "L2" — we assert via the rendered targetDidBadge / world-id
  // badge and the identifier text instead.
  const addBtn = page.getByRole("button", { name: "追加 (上級者向け手入力)" });

  // Create an L1 block.
  const l1Did = "did:key:zE2EBlock00001";
  await page.locator("#block-target-did").fill(l1Did);
  await addBtn.click();
  await expect(page.getByText("ブロックを追加しました。")).toBeVisible();
  const firstCard = page.locator(".card-item").first();
  await expect(firstCard).toContainText("特定の送信者をブロック");
  await expect(firstCard).toContainText(l1Did);

  // Switch level to L2 and create.
  await page.locator(".select").first().selectOption("l2_identity");
  await page.locator("#block-target-world-id").fill("0xDEADBEEF");
  await addBtn.click();
  await expect(page.locator(".card-item")).toHaveCount(2);
  await expect(firstCard).toContainText("ID単位の完全ブロック");
  await expect(firstCard).toContainText("0xDEADBEEF");

  // Delete the first (L2) entry.
  await firstCard.getByRole("button", { name: "ブロック解除" }).click();
  await expect(page.getByText("ブロックを解除しました。")).toBeVisible();
  await expect(page.locator(".card-item")).toHaveCount(1);
  await expect(firstCard).toContainText("特定の送信者をブロック");
});
