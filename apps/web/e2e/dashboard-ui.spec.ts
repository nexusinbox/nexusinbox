import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend, SEED_AGENT } from "./_helpers/mocks";

// Two-message seed shaped to exercise: free-text search across
// sender_label + subject_encrypted (the inbox passes through the
// "encrypted" field as plaintext when parseEncryptedPayload returns
// null, see lib/crypto/envelope.ts), the starred filter tab, the
// bulk-star toolbar, and localStorage-backed search persistence.
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

test("dashboard UI: search, filter, bulk star and persisted query", async ({
  page,
  context,
  baseURL,
}) => {
  // Force JA locale before any navigation so the rendered tab /
  // toolbar labels ("スター付き", "すべて選択", "スター解除") match.
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
  // wins. We need it to (a) return our two-row dataset on GET and
  // (b) mutate `starred` on PATCH /:id/flags so the bulk
  // unstar-then-tab-switch flow works.
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

    const flagsMatch = url.pathname.match(
      /^\/api\/messages\/([^/]+)\/flags$/,
    );
    if (flagsMatch && method === "PATCH") {
      const id = flagsMatch[1];
      const payload = request.postDataJSON() as {
        starred?: boolean;
        folder?: SeedMessage["folder"];
      };
      const target = messages.find((m) => m.id === id);
      if (!target) {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ error: "not_found" }),
        });
        return;
      }
      if (typeof payload.starred === "boolean") {
        target.starred = payload.starred;
      }
      if (payload.folder) {
        target.folder = payload.folder;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ id, starred: target.starred, folder: target.folder }),
      });
      return;
    }

    await route.fallback();
  });

  await page.goto("/");
  await expect(page.locator(".thread-item")).toHaveCount(2);

  // searchLabel = "メッセージを検索" (the older "メッセージ検索" copy is gone).
  // We search on sender_label rather than subject because subject_encrypted
  // is rendered as a localized "decrypting…" placeholder until the row is
  // opened — so subject text doesn't enter the search haystack for closed
  // rows even when the cipher is passthrough. sender_label is rendered
  // verbatim from the API response, which is a stable surface for the
  // search filter test.
  const searchInput = page.getByLabel("メッセージを検索");
  await searchInput.fill("技術");
  await expect(page.locator(".thread-item")).toHaveCount(1);
  await expect(page.locator(".thread-item").first()).toContainText(
    "技術エージェント",
  );

  // filterStarred tab label is "スター付き" (renamed from the old
  // "スター"). The starred-only view + the lingering "技術" search
  // intersects to nothing — the OpenAPI message isn't starred and the
  // starred Q1 message's sender ("社内エージェント") doesn't contain
  // "技術". Assert via row count so we don't depend on a specific
  // empty-state copy.
  await page.getByRole("tab", { name: "スター付き" }).click();
  await expect(page.locator(".thread-item")).toHaveCount(0);

  await searchInput.fill("");
  await expect(page.locator(".thread-item")).toHaveCount(1);

  // selectAll checkbox aria-label is "すべて選択" (was "全選択").
  // Bulk unstar empties the starred-only view.
  await page.getByLabel("すべて選択").check();
  await page.getByRole("button", { name: "スター解除" }).click();
  await expect(page.locator(".thread-item")).toHaveCount(0);

  await page.getByRole("tab", { name: "すべて" }).click();
  await expect(page.locator(".thread-item")).toHaveCount(2);

  // Search query is persisted in localStorage; reload should restore it.
  await searchInput.fill("技術");
  await page.reload();
  await expect(searchInput).toHaveValue("技術");
  await expect(page.locator(".thread-item")).toHaveCount(1);
});
