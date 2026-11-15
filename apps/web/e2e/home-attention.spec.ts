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
  // Home's 「あなたの判断が必要」 asks for `folder=pending_approval`
  // (lib/home/use-attention.ts). Approve/reject mutate the
  // folder via PATCH /messages/:id/flags, so this mock has to track
  // it too — once the folder leaves pending_approval, the row drops
  // out of the GET list.
  folder: "pending_approval" | "inbox" | "trash";
};

test("home: the old 確認が必要 lands on Home, and held messages are let in or thrown away there", async ({
  page,
  context,
  baseURL,
}) => {
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

  // The old page is Home's 「あなたの判断が必要」 (docs/41 §3.1).
  await page.goto("/pending");
  await expect(page).toHaveURL(/\/#attention$/);
  const section = page.getByTestId("home-attention");
  const count = page.getByTestId("home-attention-count");
  await expect(count).toHaveText("2 件");
  // The breakdown says what kind of work it is (docs/41 §6.1).
  await expect(section).toContainText("受信の許可 2");
  await expect(page.getByTestId("mailbox-count-attention").first()).toHaveText("2");

  // The subject is ciphertext for the recipient agent and is never shown
  // as text; each row is told apart by why it was held.
  await expect(page.getByText("怪しい件名A")).toHaveCount(0);
  const burst = page.getByTestId("home-attention-row").filter({ hasText: "短時間に大量の送信" });
  await burst.getByRole("button", { name: "決める" }).click();
  await expect(burst.getByText("件名は暗号化されています")).toBeVisible();
  await burst.getByRole("button", { name: "受け取る" }).click();
  await expect(page.getByText("受信に入れました。")).toBeVisible();
  await expect(count).toHaveText("1 件");

  // Throw the other away → nothing left.
  const denylist = page.getByTestId("home-attention-row").filter({ hasText: "迷惑な送信者の一覧に一致" });
  await denylist.getByRole("button", { name: "決める" }).click();
  await denylist.getByRole("button", { name: "捨てる" }).click();
  await expect(page.getByText("ゴミ箱に移しました。")).toBeVisible();
  await expect(page.getByTestId("home-attention-none")).toBeVisible();
  await expect(count).toHaveText("0 件");
});

test("home: a failed load is not shown as nothing to do", async ({ page, context, baseURL }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });
  await mockNexusInboxBackend(page);
  await page.route("**/api/agent-drafts*", async (route) => {
    await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "down" }) });
  });
  await seedAuthSessionCookie(context, baseURL);

  await page.goto("/");
  await expect(page.getByTestId("home-attention-error")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("home-attention-count")).toHaveText("—");
  await expect(page.getByTestId("home-attention-none")).toHaveCount(0);
  await expect(page.getByTestId("mailbox-count-attention")).toHaveCount(0);
});

test("home: old links that named a conversation open the conversations", async ({ page, context, baseURL }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });
  await mockNexusInboxBackend(page);
  await seedAuthSessionCookie(context, baseURL);

  await page.goto("/?view=archive");
  await expect(page).toHaveURL(/\/conversations\?view=archive$/);
  await page.goto("/?agent=did%3Akey%3AzE2E");
  await expect(page).toHaveURL(/\/conversations\?agent=did%3Akey%3AzE2E$/);
  await page.goto("/agent/did:key:zE2E");
  await expect(page).toHaveURL(/\/conversations\?agent=did(:|%3A)key(:|%3A)zE2E$/);
});

test("home: more than one page of held messages is counted, and the rest can be read", async ({
  page,
  context,
  baseURL,
}) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });
  await mockNexusInboxBackend(page);
  const held = Array.from({ length: 150 }, (_, i) => ({
    id: `00000000-0000-0000-0000-${String(i).padStart(12, "0")}`,
    sender_did: `did:key:zHeld${i}`,
    sender_label: null,
    recipient_did: "did:key:zE2EAGENTSEED01",
    recipient_label: null,
    thread_id: null,
    subject_encrypted: "x",
    status: "unread",
    priority: "background",
    ai_category: "spam_burst",
    created_at: new Date().toISOString(),
    trust_score: 0.1,
    folder: "pending_approval",
  }));
  await page.route("**/api/messages**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/messages" && url.searchParams.get("folder") === "pending_approval") {
      const perPage = Number(url.searchParams.get("per_page") ?? 100);
      const pageNo = Number(url.searchParams.get("page") ?? 1);
      const messages = held.slice((pageNo - 1) * perPage, pageNo * perPage);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ messages, total: held.length, page: pageNo, per_page: perPage }),
      });
      return;
    }
    await route.fallback();
  });
  await seedAuthSessionCookie(context, baseURL);

  await page.goto("/");
  await expect(page.getByTestId("home-attention-count")).toHaveText("150 件");
  await expect(page.getByTestId("home-attention")).toContainText("受信の許可 150");
  const more = page.getByTestId("home-attention-more");
  await expect(more).toContainText("ほかに 50 件");
  await expect(page.getByTestId("home-attention-row")).toHaveCount(100);
  await more.getByRole("button", { name: "続きを読み込む" }).click();
  await expect(page.getByTestId("home-attention-row")).toHaveCount(150);
  await expect(more).toHaveCount(0);
  await expect(page.getByTestId("home-attention-count")).toHaveText("150 件");
});
