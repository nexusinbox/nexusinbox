// The requests panel at the top of a conversation (docs/41 §7.3). The
// mocked bodies are plain A2A JSON (the reader shows them as is), so the
// person's own messages count and received ones stay unverified.
import { expect, test, type Page } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend, SEED_AGENT } from "./_helpers/mocks";

const A2A = "application/vnd.nexusinbox.a2a+json; v=1";
const THEM = "did:key:zE2ETANAKA";
const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
const iso = (offsetMin: number) => new Date(Date.now() + offsetMin * 60_000).toISOString();

type Row = { id: string; mine: boolean; at: string; protocol: Record<string, unknown>; body: string };

function entry(r: Row) {
  return {
    id: r.id,
    sender_did: r.mine ? SEED_AGENT.did : THEM,
    sender_label: r.mine ? SEED_AGENT.label : "田中さん",
    recipient_did: r.mine ? THEM : SEED_AGENT.did,
    recipient_label: r.mine ? "田中さん" : SEED_AGENT.label,
    thread_id: "11111111-1111-1111-1111-111111111111",
    subject_encrypted: "",
    status: "read",
    priority: "normal",
    ai_category: null,
    created_at: r.at,
    trust_score: 0.9,
    folder: r.mine ? "sent" : "inbox",
    starred: false,
  };
}

async function setup(page: Page, rows: Row[]) {
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
    window.localStorage.setItem("nexusinbox-theme", "light");
  });
  await mockNexusInboxBackend(page);
  await page.route("**/api/messages**", async (route) => {
    const url = new URL(route.request().url());
    const content = url.pathname.match(/^\/api\/messages\/([^/]+)\/content$/);
    if (content) {
      const r = rows.find((x) => x.id === content[1]);
      if (!r) return route.fallback();
      return route.fulfill(
        json({
          encrypted_content: JSON.stringify({ v: 1, body: r.body, protocol: r.protocol }),
          encrypted_key: "plain",
          nonce: "",
          sender_did: entry(r).sender_did,
          recipient_did: entry(r).recipient_did,
          thread_id: entry(r).thread_id,
          content_type: A2A,
        }),
      );
    }
    if (url.pathname === "/api/messages") {
      const folder = url.searchParams.get("folder");
      const list = rows.filter((r) => (folder === "sent" ? r.mine : !r.mine)).map(entry);
      return route.fulfill(json({ messages: list, total: list.length, page: 1, per_page: 100 }));
    }
    return route.fallback();
  });
}

test("conversation: our proposal waits for them, an unverified reply is left out", async ({ page, context, baseURL }) => {
  const deadline = iso(60 * 24);
  await setup(page, [
    {
      id: "00000000-0000-0000-0000-0000000000c1",
      mine: true,
      at: iso(-30),
      body: "来週の打ち合わせ、木曜 14:00 か金曜 10:00 はいかがですか。",
      protocol: {
        id: "P1",
        type: "schedule_negotiation",
        action: "propose",
        reply_to: null,
        payload: {
          event_title: "打ち合わせ",
          candidates: [{ start: iso(60 * 48), end: iso(60 * 49) }],
          required_participants: [],
          response_deadline: deadline,
        },
      },
    },
    {
      id: "00000000-0000-0000-0000-0000000000c2",
      mine: false,
      at: iso(-10),
      body: "木曜でお願いします。",
      protocol: { id: "P2", type: "schedule_negotiation", action: "accept", reply_to: "P1", payload: { selected_candidate: { start: iso(60 * 48), end: iso(60 * 49) } } },
    },
  ]);
  await seedAuthSessionCookie(context, baseURL);
  await page.goto("/conversations");
  await page.getByTestId("dm-row").first().click();

  const panel = page.getByTestId("request-panel");
  // The unverified accept does not finish it: still waiting for them.
  await expect(panel.locator('[data-state="waiting_for_them"]')).toContainText("打ち合わせ");
  await expect(panel.locator('[data-state="waiting_for_them"]')).toContainText("次は");
  await expect(panel.getByTestId("request-unverified")).toContainText("確かめられない依頼 1 件");
  await expect(panel.locator('[data-state="agreed"]')).toHaveCount(0);
  // The list: under way, and something to check, never mixed.
  const row = page.getByTestId("dm-row-requests").first();
  await expect(row).toContainText("進行中 1");
  await expect(row).toContainText("確かめが必要な依頼");
  if (process.env.SHOT) await page.screenshot({ path: process.env.SHOT, fullPage: true });
});
