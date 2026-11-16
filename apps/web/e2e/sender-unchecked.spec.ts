// A received request whose sender could not be looked up (docs/40 §14.5):
// no red warning, a quiet note, and answering asks first.
import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
import { mockNexusInboxBackend, SEED_AGENT } from "./_helpers/mocks";

const A2A = "application/vnd.nexusinbox.a2a+json; v=1";
const THEM = "did:key:zE2EUNCHECKED";
const ID = "00000000-0000-0000-0000-0000000000d1";
const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });

test("conversation: a sender not checked just now gets a note, and answering asks first", async ({
  page,
  context,
  baseURL,
}) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
    window.localStorage.setItem("nexusinbox-theme", "light");
  });
  await mockNexusInboxBackend(page);
  const at = new Date(Date.now() - 5 * 60_000).toISOString();
  const entry = {
    id: ID,
    sender_did: THEM,
    sender_label: "田中さん",
    recipient_did: SEED_AGENT.did,
    recipient_label: SEED_AGENT.label,
    thread_id: "22222222-2222-2222-2222-222222222222",
    subject_encrypted: "",
    status: "read",
    priority: "normal",
    ai_category: null,
    created_at: at,
    trust_score: 0.9,
    folder: "inbox",
    starred: false,
  };
  const protocol = {
    id: "T1",
    type: "task_delegation",
    action: "delegate",
    reply_to: null,
    payload: { task_title: "資料の確認", description: "明日までに確認してください。" },
  };
  // The sender lookup fails (an outage, or a server that will not say).
  await page.route("**/api/recipients/resolve**", (route) => route.fulfill({ status: 503, body: "{}" }));
  await page.route("**/api/messages**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === `/api/messages/${ID}/content`) {
      return route.fulfill(
        json({
          encrypted_content: JSON.stringify({ v: 1, body: "資料の確認をお願いします。", protocol }),
          encrypted_key: "plain",
          nonce: "",
          sender_did: THEM,
          recipient_did: SEED_AGENT.did,
          thread_id: entry.thread_id,
          content_type: A2A,
          signature_v2: { signature: "sig", sent_at: at, sender_aid: "aid:ai:01E2ETHEM", recipient_aid: SEED_AGENT.aid },
        }),
      );
    }
    if (url.pathname === "/api/messages") {
      const list = url.searchParams.get("folder") === "sent" ? [] : [entry];
      return route.fulfill(json({ messages: list, total: list.length, page: 1, per_page: 100 }));
    }
    return route.fallback();
  });
  await seedAuthSessionCookie(context, baseURL);
  await page.goto("/conversations");
  await page.getByTestId("dm-row").first().click();

  await expect(page.getByTestId("sender-unchecked")).toContainText("送り主をまだ確かめられていません");
  await expect(page.getByTestId("sender-unverified")).toHaveCount(0);

  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByTestId("task-accept-btn").click();
  const confirm = page.getByTestId("sender-unverified-confirm");
  await expect(confirm).toContainText("送り主をまだ確かめられていません");
  if (process.env.SHOT) await page.screenshot({ path: process.env.SHOT, fullPage: true });
  await confirm.getByRole("button", { name: "やめる" }).click();
  await expect(confirm).toHaveCount(0);
});
