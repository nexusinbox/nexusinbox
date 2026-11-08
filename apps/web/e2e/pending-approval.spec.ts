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
  // "届いたメッセージ（{count}）" (docs/34 §3 step 3).
  const heading = page.getByTestId("pending-messages").locator("h3");
  await expect(heading).toContainText("届いたメッセージ（2）");
  // The AI drafts section sits above it, empty here.
  await expect(page.getByTestId("agent-drafts")).toContainText("AI が作った下書き（0）");

  // Approve the first flagged message. Approve == folder=inbox via
  // PATCH /messages/:id/flags, so the row drops out of the
  // folder=pending_approval query result and the heading count
  // decreases. The approve button is `pending.approve` ("受信に入れる");
  // the reject counterpart is `pending.reject` ("捨てる").
  // The subject is ciphertext for the recipient agent and is never shown
  // as text; each row is told apart by why it was held.
  await expect(page.getByText("怪しい件名A")).toHaveCount(0);
  await expect(page.getByText("件名は暗号化されています").first()).toBeVisible();
  await page
    .getByTestId("pending-row")
    .filter({ hasText: "短時間に大量の送信" })
    .getByRole("button", { name: "受信に入れる" })
    .click();
  await expect(page.getByText("受信に入れました。")).toBeVisible();
  await expect(heading).toContainText("届いたメッセージ（1）");

  // Reject the remaining message → folder=trash → empty state.
  await page
    .getByTestId("pending-row")
    .filter({ hasText: "迷惑な送信者の一覧に一致" })
    .getByRole("button", { name: "捨てる" })
    .click();
  await expect(page.getByText("ゴミ箱に移しました。")).toBeVisible();
  await expect(page.getByText("確認が必要なメッセージはありません。")).toBeVisible();
});
