// Contacts → "Blocked": list, block by technical ID, unblock (docs/05 §1.4).
// The API sends no World ID hash back, and the manual form takes a
// technical ID only.
import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

type BlockEntry = {
  id: string;
  level: "l1_did" | "l2_identity" | "l3_stealth";
  target_did: string | null;
  created_at: string;
};

function blockId(index: number): string {
  return `00000000-0000-0000-0000-${String(index).padStart(12, "b")}`;
}

test("blocks management: empty list, block by technical ID, unblock", async ({ page, context, baseURL }) => {
  const blocks: BlockEntry[] = [];
  const posted: unknown[] = [];
  let seq = 1;

  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });
  // Deterministic backend first; the blocks routes below win (last
  // registered is matched first).
  await mockNexusInboxBackend(page);

  await page.route("**/api/blocks", async (route) => {
    const method = route.request().method();
    if (method === "GET") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ blocks }) });
      return;
    }
    if (method === "POST") {
      const payload = route.request().postDataJSON() as { level: BlockEntry["level"]; target_did?: string };
      posted.push(payload);
      const id = blockId(seq++);
      blocks.unshift({
        id,
        level: payload.level,
        target_did: payload.target_did ?? null,
        created_at: new Date().toISOString(),
      });
      await route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ id }) });
      return;
    }
    await route.fallback();
  });

  await page.route("**/api/blocks/*", async (route) => {
    if (route.request().method() === "DELETE") {
      const id = new URL(route.request().url()).pathname.split("/").pop()!;
      const idx = blocks.findIndex((b) => b.id === id);
      if (idx >= 0) blocks.splice(idx, 1);
      await route.fulfill({ status: idx >= 0 ? 204 : 404, contentType: "application/json", body: "" });
      return;
    }
    await route.fallback();
  });

  await seedAuthSessionCookie(context, baseURL);
  await page.goto("/settings/blocks");
  await expect(page).toHaveURL(/\/settings\/blocks$/);
  await expect(page.getByText("ブロックしている相手はいません。")).toBeVisible();

  // The manual form: a technical ID only, no World ID hash field.
  await page.getByText("アドレスを指定してブロック（上級者向け）").click();
  await expect(page.getByText("ブロックの範囲：この相手だけ")).toBeVisible();
  await expect(page.locator("#block-target-world-id")).toHaveCount(0);

  const did = "did:key:zE2EBlock00001";
  await page.locator("#block-target-did").fill(did);
  await page.getByRole("button", { name: "ブロックする" }).click();
  await expect(page.getByText("ブロックを追加しました。")).toBeVisible();
  expect(posted).toEqual([{ level: "l1_did", target_did: did }]);
  const rows = page.locator(".bl-row");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("この相手だけ");

  // A person-wide block made from a message (the server names no one).
  blocks.unshift({ id: blockId(seq++), level: "l2_identity", target_did: null, created_at: new Date().toISOString() });
  await page.reload();
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("ある人のすべてのエージェント");

  // Unblock it.
  await rows.first().getByTestId("blocks-unblock").click();
  await expect(page.getByText("ブロックを解除しました。")).toBeVisible();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("この相手だけ");
});
