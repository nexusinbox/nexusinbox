import { expect, test } from "@playwright/test";
import { makeFutureSessionJwt } from "./_helpers/auth";
import { mockNexusInboxBackend } from "./_helpers/mocks";

// Integrated smoke flow that exercises the in-browser key-generation
// + envelope-encryption pipeline end-to-end:
//   1. Create two agents from the /settings/agents/new page. Each
//      call generates a fresh Ed25519 + X25519 keypair in the
//      browser and stashes the private halves in localStorage.
//   2. POST /messages from /compose with a real envelope encrypted
//      against the recipient's X25519 public key (which was
//      registered via /agents on step 1).
//   3. GET /messages and GET /messages/:id/content to render the
//      received row, then decrypt the body using the recipient's
//      private key from the same browser's localStorage.
//
// Because both agents live in the same Playwright context, the
// recipient's private key is available locally for the final
// decrypt step — that's the test's whole point.

type AgentRecord = {
  id: string;
  did: string;
  aid: string;
  label: string;
  public_key: string;
  encryption_key: string;
  is_active: boolean;
  auto_reply: boolean;
  unread_count: number;
  created_at: string;
};

type MessageRecord = {
  id: string;
  sender_did: string;
  recipient_did: string;
  subject_encrypted: string;
  encrypted_content: string;
  encrypted_key: string;
  nonce: string;
  status: "unread" | "read" | "archived";
  priority: "high" | "normal" | "low" | "background";
  created_at: string;
  trust_score: number;
  thread_id: string | null;
};

function makeDid(index: number): string {
  return `did:key:zE2E${String(index).padStart(6, "0")}`;
}

function makeAid(index: number): string {
  return `aid:ai:01E2ESEED${String(index).padStart(7, "0")}`;
}

function makeMessageId(index: number): string {
  return `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`;
}

test("integrated flow: login -> compose -> send -> receive -> decrypt", async ({
  page,
}) => {
  // Force JA locale so the navigation/button labels we click below
  // ("作成", "送信", "受信トレイ") match the rendered UI.
  await page.addInitScript(() => {
    window.localStorage.setItem("nexusinbox-locale", "ja");
  });

  const agents: AgentRecord[] = [];
  const messages: MessageRecord[] = [];
  let agentSeq = 1;
  let messageSeq = 1;

  // Catchall + boot-path mocks (session, contacts, blocks, etc.).
  // The /agents and /messages handlers below are layered after this
  // call so they win on Playwright's last-registered-first match.
  await mockNexusInboxBackend(page);

  await page.route("**/api/agents*", async (route) => {
    const method = route.request().method();

    if (method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ agents }),
      });
      return;
    }

    if (method === "POST") {
      const payload = route.request().postDataJSON() as {
        label: string;
        public_key: string;
        encryption_key: string;
      };
      const id = makeMessageId(agentSeq);
      const did = makeDid(agentSeq);
      const aid = makeAid(agentSeq);
      agentSeq += 1;

      agents.push({
        id,
        did,
        aid,
        label: payload.label,
        public_key: payload.public_key,
        encryption_key: payload.encryption_key,
        is_active: true,
        auto_reply: false,
        unread_count: 0,
        created_at: new Date().toISOString(),
      });

      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({ id, did, aid }),
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

    if (pathname === "/api/messages" && method === "POST") {
      const payload = request.postDataJSON() as {
        sender_did: string;
        recipient_did: string;
        envelope: {
          encrypted_content: string;
          encrypted_key: string;
          nonce: string;
          metadata?: { subject_encrypted?: string };
        };
      };
      const id = makeMessageId(messageSeq);
      messageSeq += 1;

      messages.unshift({
        id,
        sender_did: payload.sender_did,
        recipient_did: payload.recipient_did,
        subject_encrypted: payload.envelope.metadata?.subject_encrypted ?? "",
        encrypted_content: payload.envelope.encrypted_content,
        encrypted_key: payload.envelope.encrypted_key,
        nonce: payload.envelope.nonce,
        status: "unread",
        priority: "normal",
        created_at: new Date().toISOString(),
        trust_score: 0.9,
        thread_id: null,
      });

      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({ message_id: id, status: "accepted" }),
      });
      return;
    }

    if (pathname === "/api/messages" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          messages: messages.map((m) => ({
            id: m.id,
            sender_did: m.sender_did,
            sender_label: null,
            recipient_did: m.recipient_did,
            recipient_label: null,
            thread_id: null,
            subject_encrypted: m.subject_encrypted,
            status: m.status,
            priority: m.priority,
            ai_category: null,
            created_at: m.created_at,
            trust_score: m.trust_score,
            folder: "inbox",
            starred: false,
          })),
          total: messages.length,
          page: 1,
          per_page: 50,
        }),
      });
      return;
    }

    const contentMatch = pathname.match(
      /^\/api\/messages\/([^/]+)\/content$/,
    );
    if (contentMatch && method === "GET") {
      const id = contentMatch[1];
      const target = messages.find((m) => m.id === id);
      if (!target) {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ error: "not_found" }),
        });
        return;
      }
      // MessageContentResponse is FLAT — fields sit directly at the
      // top level (lib/api/types.ts). Returning the same envelope
      // the sender POSTed is what makes round-trip decryption work
      // against the recipient's X25519 private key in localStorage.
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          encrypted_content: target.encrypted_content,
          encrypted_key: target.encrypted_key,
          nonce: target.nonce,
          sender_did: target.sender_did,
          recipient_did: target.recipient_did,
          subject_encrypted: target.subject_encrypted,
          thread_id: null,
          content_type: "text/plain",
        }),
      });
      return;
    }

    const flagsMatch = pathname.match(/^\/api\/messages\/([^/]+)\/flags$/);
    if (flagsMatch && method === "PATCH") {
      // Status / folder / starred toggles fired by the inbox row
      // when it auto-marks-as-read on open. Stub as a no-op success.
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({}),
      });
      return;
    }

    const statusMatch = pathname.match(/^\/api\/messages\/([^/]+)$/);
    if (statusMatch && method === "PATCH") {
      const id = statusMatch[1];
      const payload = request.postDataJSON() as { status?: "read" | "archived" };
      const target = messages.find((m) => m.id === id);
      if (target && payload.status) {
        target.status = payload.status;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ id, status: target?.status ?? "read" }),
      });
      return;
    }

    await route.fallback();
  });

  await page.goto("/login");
  await expect(page.getByTestId("login-root")).toBeVisible();

  const currentUrl = new URL(page.url());
  await page.context().addCookies([
    {
      name: "nexusinbox_session",
      value: makeFutureSessionJwt(),
      url: `${currentUrl.protocol}//${currentUrl.host}`,
    },
  ]);

  // Create the sender agent.
  await page.goto("/settings/agents/new");
  await expect(page).toHaveURL(/\/settings\/agents\/new$/);
  // The agent-create form has a single text input; pick it via the
  // panel + .input class rather than guessing an id.
  const newAgentInput = page.locator(".panel input.input").first();
  await newAgentInput.fill("送信元エージェント");
  await page.getByRole("button", { name: "作成" }).click();
  await expect(
    page.getByText("エージェントを作成しました。一覧に戻ります。"),
  ).toBeVisible();
  // The page auto-navigates back to /settings/agents after a brief
  // delay; wait for the URL change before we kick off agent #2.
  await expect(page).toHaveURL(/\/settings\/agents$/);

  // Create the recipient agent.
  await page.goto("/settings/agents/new");
  await expect(page).toHaveURL(/\/settings\/agents\/new$/);
  await page.locator(".panel input.input").first().fill("受信先エージェント");
  await page.getByRole("button", { name: "作成" }).click();
  await expect(
    page.getByText("エージェントを作成しました。一覧に戻ります。"),
  ).toBeVisible();
  await expect(page).toHaveURL(/\/settings\/agents$/);

  // Verify the route handler captured both creations before we
  // start composing — the recipient's encryption_key has to be on
  // the GET /agents response for the compose page to encrypt
  // against it.
  expect(agents).toHaveLength(2);
  const senderDid = agents[0].did;
  const recipientDid = agents[1].did;

  const plainSubject = "E2E統合テスト件名";
  const plainBody = "E2E統合テスト本文";

  await page.goto("/compose");
  await expect(page).toHaveURL(/\/compose$/);
  await page.locator("select.select").selectOption(senderDid);
  await page.locator("input.input").first().fill(recipientDid);
  await page.locator("input.input").nth(1).fill(plainSubject);
  await page.locator("textarea.textarea").fill(plainBody);
  // Send button label is "送信" (the older "暗号化して送信" copy
  // was renamed upstream).
  await page.getByRole("button", { name: "送信" }).first().click();
  await expect(
    page.getByText("メッセージを送信しました。"),
  ).toBeVisible();

  // Bounce back to /, click the inbox row, expect the decrypted
  // subject + body. Same browser context → recipient's private key
  // is in localStorage → decryption resolves the real plaintext.
  await page.goto("/");
  await expect(page).toHaveURL(/\/$/);
  await expect(page.locator(".thread-item").first()).toBeVisible();
  await page.locator(".thread-item").first().click();

  await expect(page.locator(".reader-subject")).toContainText(plainSubject);
  await expect(page.locator(".conversation-message-body").first()).toContainText(
    plainBody,
  );
});
