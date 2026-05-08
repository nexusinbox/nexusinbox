import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend, SEED_AGENT } from "./_helpers/mocks";

test("agent inbox: thread / reader split is resizable", async ({ page, context, baseURL }) => {
  // The agent page used to have a three-column layout (sidebar +
  // threads + reader, two resizers). It's since collapsed to a
  // two-column thread/reader split with a single resizer; the
  // assertion below was updated to match.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  await mockNexusInboxBackend(page);
  await seedAuthSessionCookie(context, baseURL);

  // Navigate to the seeded agent's inbox so the layout actually
  // mounts (a non-existent did would render the "agent not found"
  // empty state, which has no .mail-resizer).
  await page.goto(`/agent/${encodeURIComponent(SEED_AGENT.did)}`);
  const layout = page.locator(".mail-layout");
  await expect(layout).toBeVisible();
  await expect(page.locator(".mail-resizer")).toHaveCount(1);

  const before = (await layout.getAttribute("style")) ?? "";

  const resizer = page.locator(".mail-resizer").first();
  const box = await resizer.boundingBox();
  expect(box).not.toBeNull();
  if (!box) return;

  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width / 2 + 40, box.y + box.height / 2);
  await page.mouse.up();

  const after = (await layout.getAttribute("style")) ?? "";
  expect(after).not.toEqual(before);
});
