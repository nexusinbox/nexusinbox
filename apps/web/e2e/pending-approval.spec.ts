import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

type MessageRecord = {
  id: string;
  sender_did: string;
  sender_label: string | null;
  recipient_did: string;
  recipient_label: string | null;
  thread_id: null;
  subject_encrypted: string;
  status: "unread" | "read" | "archived";
  priority: "high" | "normal" | "low" | "background";
  ai_category: string | null;
  created_at: string;
  trust_score: number;
  // The pending view server-side filters on `folder=pending_approval`
  // (apps/web/app/pending/page.tsx:33). Approve/reject mutate the
  // folder via PATCH /messages/:id/flags, so this mock has to track
  // it too — once the folder leaves pending_approval, the row drops
  // out of the GET list.
  folder: "pending_approval" | "inbox" | "trash";
};

test("pending approval: approve and reject flagged messages", async ({ page, context, baseURL }) => {
  const messages: MessageRecord[] = [
    {
      id: "00000000-0000-0000-0000-0000000000a1",
      sender_did: "did:key:zE2EPendingA",
      sender_label: null,
      recipient_did: "did:key:zE2ERecip0001",
      recipient_label: "受信エージェント",
      thread_id: null,
      subject_encrypted: "怪しい件名A",
      status: "unread",
      priority: "background",
      ai_category: "spam_burst",
      created_at: new Date().toISOString(),
      trust_score: 0.1,
      folder: "pending_approval",
    },
    {
      id: "00000000-0000-0000-0000-0000000000a2",
      sender_did: "did:key:zE2EPendingB",
      sender_label: null,
      recipient_did: "did:key:zE2ERecip0001",
      recipient_label: "受信エージェント",
      thread_id: null,
      subject_encrypted: "怪しい件名B",
      status: "unread",
      priority: "background",
      ai_category: "spam_denylist",
      created_at: new Date().toISOString(),
      trust_score: 0.0,
      folder: "pending_approval",
    },
  ];

  // JA locale + deterministic backend (catchall + boot-path mocks)
  // before any spec-specific routes. The custom /api/agents and
  // /api/messages handlers below are registered after this call so
  // they win on Playwright's last-registered-first match order.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });
  await mockNexusInboxBackend(page);

  await page.route("**/api/agents*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          agents: [
            {
              id: "00000000-0000-0000-0000-0000000000f1",
              did: "did:key:zE2ERecip0001",
              label: "受信エージェント",
              public_key: "pk",
              encryption_key: "ek",
              is_active: true,
              auto_reply: false,
              unread_count: 2,
              created_at: new Date().toISOString(),
            },
          ],
        }),
      });
      return;
    }
    await route.fallback();
  });

  await page.route("**/api/messages**", async (route) => {
    const request = route.request();
    const method = request.method();
    const url = new URL(request.url());
    const pathname = url.pathname;

    if (pathname === "/api/messages" && method === "GET") {
      const folder = url.searchParams.get("folder");
      const filtered = folder
        ? messages.filter((m) => m.folder === folder)
        : messages;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          messages: filtered,
          total: filtered.length,
          page: 1,
          per_page: 100,
        }),
      });
      return;
    }

    // PATCH /messages/:id/flags — folder change (apps/web/app/pending/
    // page.tsx routes approve to folder=inbox, reject to folder=trash).
    // Test the more-specific /flags pattern BEFORE the bare
    // /messages/:id status path.
    const flagsMatch = pathname.match(/^\/api\/messages\/([^/]+)\/flags$/);
    if (flagsMatch && method === "PATCH") {
      const id = flagsMatch[1];
      const payload = request.postDataJSON() as {
        folder?: MessageRecord["folder"];
      };
      const target = messages.find((m) => m.id === id);
      if (!target || !payload.folder) {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ error: "not_found" }),
        });
        return;
      }
      target.folder = payload.folder;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ id, folder: target.folder }),
      });
      return;
    }

    const statusMatch = pathname.match(/^\/api\/messages\/([^/]+)$/);
    if (statusMatch && method === "PATCH") {
      const id = statusMatch[1];
      const payload = request.postDataJSON() as { status?: "read" | "archived" };
      const target = messages.find((m) => m.id === id);
      if (!target || !payload.status) {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ error: "not_found" }),
        });
        return;
      }
      target.status = payload.status;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ id, status: target.status }),
      });
      return;
    }

    await route.fallback();
  });

  await seedAuthSessionCookie(context, baseURL);

  await page.goto("/pending");
  await expect(page).toHaveURL(/\/pending$/);
  // Heading text follows the `pending.heading` template
  // "{count}件のメッセージが確認を待っています". The previous "承認待ち N 件"
  // copy was removed when the page was rewritten.
  await expect(page.locator(".reader-subject")).toContainText(
    "2件のメッセージが確認を待っています",
  );

  // Approve the first flagged message. Approve == folder=inbox via
  // PATCH /messages/:id/flags, so the row drops out of the
  // folder=pending_approval query result and the heading count
  // decreases. The approve button is `pending.approve` ("承認"); the
  // reject counterpart is `pending.reject` ("拒否", not "却下").
  await page
    .locator(".panel", { hasText: "怪しい件名A" })
    .getByRole("button", { name: "承認" })
    .click();
  await expect(
    page.getByText("メッセージを承認し、受信トレイに移動しました。"),
  ).toBeVisible();
  await expect(page.locator(".reader-subject")).toContainText(
    "1件のメッセージが確認を待っています",
  );

  // Reject the remaining message → folder=trash → empty state.
  await page
    .locator(".panel", { hasText: "怪しい件名B" })
    .getByRole("button", { name: "拒否" })
    .click();
  await expect(
    page.getByText("メッセージを拒否し、ゴミ箱に移動しました。"),
  ).toBeVisible();
  await expect(page.getByText("確認が必要なメッセージはありません。")).toBeVisible();
});
