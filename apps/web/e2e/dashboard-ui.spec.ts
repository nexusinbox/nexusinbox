import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend, SEED_AGENT } from "./_helpers/mocks";

// Two-message seed shaped to exercise the conversation list: free-text
// search on the counterpart name and the 未読 chip.
type SeedMessage = {
  id: string;
  sender_did: string;
  sender_label: string;
  recipient_did: string;
  recipient_label: string;
  thread_id: null;
  subject_encrypted: string;
  storage_ref: string;
  status: "unread" | "read" | "archived";
  priority: "high" | "normal" | "low" | "background";
  ai_category: null;
  created_at: string;
  trust_score: number;
  folder: "inbox" | "trash" | "spam" | "archive";
  starred: boolean;
};

test("dashboard UI: search and the unread chip", async ({
  page,
  context,
  baseURL,
}) => {
  // Force JA locale before any navigation so the chip labels
  // ("すべて", "未読") match.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  const messages: SeedMessage[] = [
    {
      id: "00000000-0000-0000-0000-0000000000c1",
      sender_did: "did:key:zE2EDashSenderA",
      sender_label: "社内エージェント",
      recipient_did: SEED_AGENT.did,
      recipient_label: SEED_AGENT.label,
      thread_id: null,
      // subject_encrypted is rendered verbatim because the inbox
      // passes through anything that isn't `enc:v1:...` formatted.
      subject_encrypted: "Q1社内レポート",
      storage_ref: "byos://localfs/dashboard-c1.bin",
      status: "read",
      priority: "normal",
      ai_category: null,
      created_at: "2026-05-08T01:00:00Z",
      trust_score: 0.9,
      folder: "inbox",
      starred: true,
    },
    {
      id: "00000000-0000-0000-0000-0000000000c2",
      sender_did: "did:key:zE2EDashSenderB",
      sender_label: "技術エージェント",
      recipient_did: SEED_AGENT.did,
      recipient_label: SEED_AGENT.label,
      thread_id: null,
      subject_encrypted: "OpenAPI仕様確認のお願い",
      storage_ref: "byos://localfs/dashboard-c2.bin",
      status: "unread",
      priority: "normal",
      ai_category: null,
      created_at: "2026-05-08T02:00:00Z",
      trust_score: 0.8,
      folder: "inbox",
      starred: false,
    },
  ];

  await mockNexusInboxBackend(page);
  await seedAuthSessionCookie(context, baseURL);

  // Layered after the helper so this more-specific /messages handler
  // wins. It returns our two-row dataset on GET.
  await page.route("**/api/messages**", async (route) => {
    const request = route.request();
    const method = request.method();
    const url = new URL(request.url());

    if (url.pathname === "/api/messages" && method === "GET") {
      const folder = url.searchParams.get("folder");
      const filtered = !folder || folder === "inbox" || folder === "all"
        ? messages
        : messages.filter((m) => m.folder === folder);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          messages: filtered,
          total: filtered.length,
          page: 1,
          per_page: Number(url.searchParams.get("per_page") ?? 50),
        }),
      });
      return;
    }

    await route.fallback();
  });

  await page.goto("/");
  const rows = page.getByTestId("dm-row");
  await expect(rows).toHaveCount(2);

  // The search box filters on the counterpart's name (and the decrypted
  // preview, which these passthrough rows don't have).
  const searchInput = page.getByLabel("メッセージを検索");
  await searchInput.fill("技術");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("技術エージェント");

  await searchInput.fill("");
  await expect(rows).toHaveCount(2);

  // Only the second message is unread.
  await page.getByRole("tab", { name: "未読" }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("技術エージェント");

  await page.getByRole("tab", { name: "すべて" }).click();
  await expect(rows).toHaveCount(2);
});
