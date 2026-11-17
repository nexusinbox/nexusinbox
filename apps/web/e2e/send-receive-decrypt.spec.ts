import { expect, test } from "@playwright/test";
import { seedAuthSessionCookie } from "./_helpers/auth";
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
  /** The root browser only, until its signed list names more (docs/40). */
  devices: { did: string; encryption_public_key: string; kind: "browser"; activated_at: string }[];
  device_list: { version: number; jws: string } | null;
};

/** did:key of an Ed25519 public key (base64url), as the API derives it. */
function didFromPublicKey(publicKeyB64Url: string): string {
  const raw = Buffer.from(publicKeyB64Url, "base64url");
  const bytes = Buffer.concat([Buffer.from([0xed, 0x01]), raw]);
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = BigInt(`0x${bytes.toString("hex")}`);
  let out = "";
  while (n > 0n) {
    out = alphabet[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = `1${out}`;
  }
  return `did:key:z${out}`;
}

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

function makeAid(index: number): string {
  return `aid:ai:01E2ESEED${String(index).padStart(7, "0")}`;
}

function makeMessageId(index: number): string {
  return `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`;
}

test("integrated flow: login -> compose -> send -> receive -> decrypt", async ({
  page,
  context,
  baseURL,
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
      const did = didFromPublicKey(payload.public_key);
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
        devices: [
          {
            did,
            encryption_public_key: payload.encryption_key,
            kind: "browser",
            activated_at: new Date().toISOString(),
          },
        ],
        device_list: null,
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

  // The browser signs each agent's first device list (Home's upkeep).
  await page.route("**/api/agents/*/device-list", async (route) => {
    if (route.request().method() !== "PUT") return route.fallback();
    const id = new URL(route.request().url()).pathname.split("/")[3];
    const agent = agents.find((a) => a.id === id);
    const { jws } = route.request().postDataJSON() as { jws: string };
    const payload = JSON.parse(Buffer.from(jws.split(".")[1], "base64url").toString("utf8")) as { version: number };
    if (!agent) return route.fulfill({ status: 404, body: "{}" });
    agent.device_list = { version: payload.version, jws };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ version: payload.version }),
    });
  });

  // The compose page resolves every recipient on the server (an AID to
  // the agent's newest key, a did:key to that key).
  await page.route("**/api/recipients/resolve*", async (route) => {
    const identifier = new URL(route.request().url()).searchParams.get("identifier") ?? "";
    const agent = agents.find((a) => a.did === identifier || a.aid === identifier);
    if (!agent) {
      await route.fulfill({
        status: 404,
        contentType: "application/json",
        body: JSON.stringify({ error: "not_found", message: "recipient not found" }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        input: identifier,
        aid: agent.aid,
        did: agent.did,
        label: agent.label,
        signing_public_key: agent.public_key,
        encryption_public_key: agent.encryption_key,
        key_holder: "web_keystore",
        devices: agent.devices.map(({ did, encryption_public_key }) => ({ did, encryption_public_key })),
        device_list: agent.device_list,
      }),
    });
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

  // Signed in before the first page: opening /login with a session makes
  // it move to Home on its own, which aborted the next goto.
  await seedAuthSessionCookie(context, baseURL);

  // Create the sender agent.
  await page.goto("/settings/agents/new");
  await expect(page).toHaveURL(/\/settings\/agents\/new$/);
  // The agent-create form has a single text input; pick it via the
  // panel + .input class rather than guessing an id.
  const newAgentInput = page.locator(".panel input.input").first();
  await newAgentInput.fill("送信元エージェント");
  await page.getByRole("button", { name: "エージェントを作る" }).click();
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
  await page.getByRole("button", { name: "エージェントを作る" }).click();
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

  // Home signs each agent's first device list (this browser is the only
  // device); sending waits for the recipient to have one (docs/40 §15.2).
  await page.goto("/");
  await expect.poll(() => agents.every((a) => a.device_list !== null), { timeout: 15_000 }).toBe(true);

  const plainSubject = "E2E統合テスト件名";
  const plainBody = "E2E統合テスト本文";

  // The full form (a bare /compose is the 新しい会話 picker).
  await page.goto("/compose?full=1");
  await expect(page).toHaveURL(/\/compose\?full=1$/);
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

  // Bounce back to /, open the conversation, expect the decrypted
  // subject + body. Same browser context → recipient's private key
  // is in localStorage → decryption resolves the real plaintext.
  await page.goto("/conversations");
  await expect(page).toHaveURL(/\/conversations$/);
  await expect(page.getByTestId("dm-row").first()).toBeVisible();
  await page.getByTestId("dm-row").first().click();

  await expect(page.locator(".dm-subject").first()).toContainText(plainSubject);
  await expect(page.locator(".dm-bubble").first()).toContainText(plainBody);
});
