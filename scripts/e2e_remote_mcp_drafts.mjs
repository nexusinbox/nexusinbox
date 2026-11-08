#!/usr/bin/env node
// End-to-end check of drafts from a cloud AI (docs/33 §8, §9), against a
// local API, the signer daemon and the gateway's remote MCP endpoint:
//
//   1. connect agent A with a pairing code (as a person does)
//   2. start a gateway with --mcp-listen, and register a review key (this
//      script stands in for the browser)
//   3. B sends A a message; the official MCP client lists and reads it
//   4. the MCP client asks for a reply draft; nothing reaches B yet
//   5. the "browser" opens the draft with its review key
//   6. the person approves it; B receives it and can decrypt it
//   7. OAuth (docs/33 §10): an app with the official SDK's OAuth client
//      finds the API from the endpoint's 401, registers, gets the person's
//      consent and a token, and drafts; a read-only grant cannot draft
//
// Needs the same local API as scripts/e2e_isolated_auto_reply.mjs (dev
// bearer, CSRF on, migrations up to 0027) with
// AGENT_INBOX_MCP_ALLOW_LOCAL_RESOURCES=true, and a built gateway.
//
// Usage: API=http://localhost:8081 node scripts/e2e_remote_mcp_drafts.mjs
//   KEEP=1 leaves the stack and the MCP endpoint running.
//   BROWSER_REVIEW=1 USER_ID=<signed-in user> lets a real browser do steps 5
//   and 6: the script waits for the browser to set itself up for review,
//   then waits for the person to press "この内容で送る".

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync, spawn } from "node:child_process";

const API = process.env.API ?? "http://localhost:8080";
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = process.env.WORK ?? fs.mkdtempSync(path.join(os.tmpdir(), "nxe2e-work-"));
const MCP_PORT = Number(process.env.MCP_PORT ?? 8797);
const GATEWAY_BIN =
  process.env.GATEWAY_BIN ?? path.join(REPO, "services/agent-gateway/target/debug/nexusinbox-gateway");
const SDK = path.join(REPO, "packages/mcp-server/node_modules/@modelcontextprotocol/sdk/dist/esm");

if (!["localhost", "127.0.0.1", "[::1]"].includes(new URL(API).hostname)) {
  console.error(`refusing to run against ${API}: local API only`);
  process.exit(2);
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const step = (msg) => console.log(`\n== ${msg}`);
function fail(msg, extra) {
  console.error(`\nFAIL: ${msg}`);
  if (extra !== undefined) console.error(typeof extra === "string" ? extra : JSON.stringify(extra, null, 2));
  process.exitCode = 1;
  throw new Error(msg);
}

// --- keys --------------------------------------------------------------

function base58btc(buf) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt("0x" + Buffer.from(buf).toString("hex"));
  const chars = [];
  while (num > 0n) {
    chars.unshift(ALPHABET[Number(num % 58n)]);
    num /= 58n;
  }
  for (const b of buf) {
    if (b === 0) chars.unshift("1");
    else break;
  }
  return chars.join("");
}

function makeAgentKeys() {
  const sign = crypto.generateKeyPairSync("ed25519");
  const enc = crypto.generateKeyPairSync("x25519");
  const signPub = sign.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const encPub = enc.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    sign,
    enc,
    signSeed: sign.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32),
    encPriv: enc.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32),
    signPubB64: b64url(signPub),
    encPubB64: b64url(encPub),
    did: `did:key:z${base58btc(Buffer.concat([Buffer.from([0xed, 0x01]), signPub]))}`,
  };
}

// --- envelope crypto (mirrors packages/crypto and apps/web/lib/crypto) ---

function encryptText(plaintext, contentKey) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(Buffer.from(contentKey, "utf8"), salt, 120000, 32, "sha256");
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(plaintext, "utf8")), c.final(), c.getAuthTag()]);
  return {
    serialized: `enc:v1:PBKDF2-SHA256:AES-GCM-256:120000:${b64url(salt)}:${b64url(iv)}:${b64url(ct)}`,
    iv: b64url(iv),
  };
}

function decryptText(serialized, contentKey) {
  const parts = serialized.split(":");
  if (parts.length !== 8 || parts[0] !== "enc") throw new Error(`not enc:v1: ${serialized.slice(0, 30)}`);
  const [, , , , iter, salt, iv, ct] = parts;
  const key = crypto.pbkdf2Sync(Buffer.from(contentKey, "utf8"), Buffer.from(salt, "base64url"), Number(iter), 32, "sha256");
  const body = Buffer.from(ct, "base64url");
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  d.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]).toString("utf8");
}

const WRAP_INFO = Buffer.from("nexusinbox/x25519-wrap/v1");

function wrapContentKey(contentKey, recipientEncPubB64) {
  const recipient = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(recipientEncPubB64, "base64url")]),
    format: "der",
    type: "spki",
  });
  const eph = crypto.generateKeyPairSync("x25519");
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipient });
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const wrapKey = Buffer.from(crypto.hkdfSync("sha256", shared, salt, WRAP_INFO, 32));
  const c = crypto.createCipheriv("aes-256-gcm", wrapKey, iv);
  const ct = Buffer.concat([c.update(Buffer.from(contentKey, "utf8")), c.final(), c.getAuthTag()]);
  const ephPub = eph.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return `x25519v1:${b64url(ephPub)}:${b64url(salt)}:${b64url(iv)}:${b64url(ct)}`;
}

function unwrapContentKey(wrapped, encPrivateKey) {
  const [eph, salt, iv, ct] = wrapped.slice("x25519v1:".length).split(":");
  const ephPub = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(eph, "base64url")]),
    format: "der",
    type: "spki",
  });
  const shared = crypto.diffieHellman({ privateKey: encPrivateKey, publicKey: ephPub });
  const wrapKey = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(salt, "base64url"), WRAP_INFO, 32));
  const body = Buffer.from(ct, "base64url");
  const d = crypto.createDecipheriv("aes-256-gcm", wrapKey, Buffer.from(iv, "base64url"));
  d.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]).toString("utf8");
}

// --- API ------------------------------------------------------------------

async function api(method, p, { auth, body } = {}) {
  const headers = { "Content-Type": "application/json", Origin: "http://localhost:3100" };
  if (auth) headers.Authorization = auth;
  const res = await fetch(`${API}${p}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { status: res.status, data };
}

function expectStatus(resp, ok, what) {
  if (!ok.includes(resp.status)) fail(`${what}: HTTP ${resp.status}`, resp.data);
  return resp.data;
}

// --- main -------------------------------------------------------------------

const STACK = path.join(REPO, "scripts/run_noninteractive_stack.sh");
const PASSPHRASE = "e2e-passphrase";
let stackDir = null;
let stackEnv = null;
let gateway = null;
let oauthGateway = null;
function stack(command, input) {
  return execFileSync("sh", [STACK, command, stackDir], {
    cwd: REPO,
    env: stackEnv,
    input,
    stdio: ["pipe", "pipe", "pipe"],
  }).toString();
}

// Poll gently: the local API limits requests per IP.
async function poll(what, fn, seconds = 300) {
  for (let waited = 0; waited < seconds; waited += 3) {
    const resp = await fn();
    if (resp.status === 429) {
      await sleep(10_000);
      waited += 10;
      continue;
    }
    const value = expectStatus(resp, [200], what);
    if (value) return value;
    await sleep(3000);
  }
  return null;
}

function sendFrom(sender, recipient, subjectText, bodyText) {
  const contentKey = b64url(crypto.randomBytes(32));
  const body = encryptText(bodyText, contentKey);
  const subject = encryptText(subjectText, contentKey);
  const wrapped = wrapContentKey(contentKey, recipient.encPubB64);
  const signingPayload = [sender.did, recipient.did, subject.serialized, body.serialized, wrapped, body.iv].join("\n");
  const signature = b64url(crypto.sign(null, Buffer.from(signingPayload, "utf8"), sender.sign.privateKey));
  return {
    sender_did: sender.did,
    recipient_did: recipient.did,
    envelope: {
      encrypted_content: body.serialized,
      encrypted_key: wrapped,
      nonce: body.iv,
      signature,
      metadata: { subject_encrypted: subject.serialized, content_type: "text/plain", thread_id: null, has_attachments: false },
    },
  };
}

async function main() {
  const browser = !!process.env.BROWSER_REVIEW;
  const userId = process.env.USER_ID ?? crypto.randomUUID();
  const human = `Bearer dev-user-${userId}`;

  if (!process.env.USER_ID) {
    step("seed a human user (local DB)");
    execFileSync("docker", [
      "exec", "nexusinbox-postgres", "psql", "-U", "agent_inbox", "-d", "agent_inbox", "-q", "-c",
      `INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) VALUES ('${userId}', 'e2e-${userId}', 'e2e-${userId}', 'orb')`,
    ]);
  }

  step("register agents A (on this computer) and B (the other side)");
  const placeholder = makeAgentKeys();
  const B = makeAgentKeys();
  const agentA = expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-A-secretary", public_key: placeholder.signPubB64, encryption_key: placeholder.encPubB64 } }),
    [200, 201], "create agent A");
  expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-B-friend", public_key: B.signPubB64, encryption_key: B.encPubB64 } }),
    [200, 201], "create agent B");

  step("connect A with a pairing code");
  const cred = expectStatus(
    await api("POST", "/agent-credentials", { auth: human, body: { agent_id: agentA.id, label: "e2e-daemon", scopes: ["messages.read", "messages.send"], pairing: true } }),
    [201], "create pairing credential");
  const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), "nxe2e-"));
  stackEnv = {
    ...process.env,
    HOME: WORK,
    CARGO_HOME: process.env.CARGO_HOME ?? path.join(os.homedir(), ".cargo"),
    RUSTUP_HOME: process.env.RUSTUP_HOME ?? path.join(os.homedir(), ".rustup"),
    AGENT_INBOX_SIGNER_SOCKET: path.join(sockDir, "signer.sock"),
    AGENT_INBOX_GATEWAY_SOCKET: path.join(sockDir, "gateway.sock"),
  };
  const agentDir = path.join(WORK, ".nexusinbox", "e2e-a-secretary");
  try {
    const out = execFileSync("sh", [STACK, "connect", cred.pairing_code, API], {
      cwd: REPO,
      env: stackEnv,
      input: `${PASSPHRASE}\n${PASSPHRASE}\n`,
      stdio: ["pipe", "pipe", "pipe"],
    }).toString();
    stackDir = agentDir;
    if (!/Signer up:\s+yes/.test(out)) fail("signer did not come up", out);
  } catch (e) {
    if (fs.existsSync(path.join(agentDir, "agent.env"))) stackDir = agentDir;
    fail("connect failed", `${e.stdout ?? ""}${e.stderr ?? e}`);
  }
  const resolved = expectStatus(
    await api("GET", `/recipients/resolve?identifier=${encodeURIComponent(agentA.aid)}`, { auth: human }),
    [200], "resolve A");
  const A = { did: resolved.did, encPubB64: resolved.encryption_public_key };
  console.log(`  A ${A.did}`);

  step("start a gateway with the remote MCP endpoint");
  const tokenFile = path.join(WORK, "mcp-token");
  const gatewayLog = path.join(WORK, "mcp-gateway.log");
  gateway = spawn(GATEWAY_BIN, [
    "--llm-socket", path.join(sockDir, "mcp-gw.sock"),
    "--signer-socket", stackEnv.AGENT_INBOX_SIGNER_SOCKET,
    "--api-url", API,
    "--mcp-listen", `127.0.0.1:${MCP_PORT}`,
    "--mcp-token-file", tokenFile,
  ], { stdio: ["ignore", fs.openSync(gatewayLog, "a"), fs.openSync(gatewayLog, "a")] });
  for (let i = 0; i < 40 && !fs.readFileSync(gatewayLog, "utf8").includes("Remote MCP"); i++) await sleep(250);
  if (!fs.existsSync(tokenFile)) fail("no MCP token file", fs.readFileSync(gatewayLog, "utf8"));
  if ((fs.statSync(tokenFile).mode & 0o777) !== 0o600) fail("MCP token file is not 0600");

  const { Client } = await import(pathToFileURL(path.join(SDK, "client/index.js")).href);
  const { StreamableHTTPClientTransport } = await import(pathToFileURL(path.join(SDK, "client/streamableHttp.js")).href);
  const mcp = new Client({ name: "e2e-muse", version: "0" });
  await mcp.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${MCP_PORT}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${fs.readFileSync(tokenFile, "utf8").trim()}` } },
  }));
  const tools = (await mcp.listTools()).tools.map((t) => t.name);
  console.log(`  tools: ${tools.join(", ")}`);
  if (!tools.includes("create_draft") || tools.some((n) => n.includes("send"))) fail("unexpected tool list", tools);
  const call = async (name, args) => {
    const r = await mcp.callTool({ name, arguments: args });
    return { error: r.isError ? r.content?.[0]?.text : null, value: r.structuredContent };
  };

  step("without a review browser, drafting is refused");
  if ((expectStatus(await api("GET", "/review-keys", { auth: human }), [200], "review keys")).review_keys.length) {
    fail("this user already has review keys; use a fresh user");
  }
  const sent = expectStatus(await api("POST", "/messages", { auth: human, body: sendFrom(B, A, "Lunch on Friday?", "Are you free for lunch on Friday at noon?") }), [202], "B → A");
  const early = await call("create_draft", { reply_to_message_id: sent.message_id, body: "Yes" });
  if (!early.error?.includes("No browser is set up")) fail("expected a refusal without review keys", early);
  console.log(`  refused: ${early.error.slice(0, 60)}…`);

  let review = null;
  let reviewKey = null;
  if (browser) {
    step("waiting for the browser: 確認が必要 → このブラウザを確認に使う");
    reviewKey = await poll("review keys", async () => {
      const r = await api("GET", "/review-keys", { auth: human });
      return r.status === 200 ? { status: 200, data: r.data.review_keys[0] ?? null } : r;
    });
    if (!reviewKey) fail("the browser did not set itself up within 5 minutes");
    console.log(`  browser key: ${reviewKey.label}`);
  } else {
    step("the 'browser' registers a review key");
    review = crypto.generateKeyPairSync("x25519");
    const reviewPub = b64url(review.publicKey.export({ type: "spki", format: "der" }).subarray(-32));
    reviewKey = expectStatus(
      await api("POST", "/review-keys", { auth: human, body: { public_key: reviewPub, label: "e2e browser" } }),
      [201], "register review key");
  }

  step("the MCP client lists and reads the message");
  const inbox = await call("list_inbox", {});
  const row = inbox.value?.messages?.find((m) => m.message_id === sent.message_id);
  if (!row || row.sent_by_this_agent) fail("message not in the inbox", inbox);
  const read = await call("read_message", { message_id: sent.message_id });
  if (read.error || read.value.subject !== "Lunch on Friday?" || !read.value.body.includes("noon") || !read.value.notice) fail("read_message", read);
  console.log(`  read: "${read.value.subject}"`);

  step("the MCP client drafts a reply; nothing is sent");
  const replyText = "Friday at noon works. See you then.";
  const draft = await call("create_draft", { reply_to_message_id: sent.message_id, body: replyText });
  if (draft.error || draft.value.sent !== false) fail("create_draft", draft);
  console.log(`  draft ${draft.value.draft_id}: "${draft.value.subject}"`);
  const bInbox = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(B.did)}`, { auth: human }), [200], "list B");
  if (bInbox.messages.some((m) => m.sender_did === A.did)) fail("B already received something before approval");

  const drafts = expectStatus(await api("GET", "/agent-drafts", { auth: human }), [200], "list drafts");
  const d = drafts.drafts.find((x) => x.id === draft.value.draft_id);
  if (!d || d.via !== "e2e-muse" || d.recipient_label == null) fail("draft listing", d);
  let got = null;
  if (browser) {
    step("waiting for the person: 確認が必要 → 開いて確認 → この内容で送る");
    got = await poll("list B", async () => {
      const r = await api("GET", `/messages?agent_did=${encodeURIComponent(B.did)}`, { auth: human });
      return r.status === 200
        ? { status: 200, data: r.data.messages.find((m) => m.sender_did === A.did && m.folder !== "sent") ?? null }
        : r;
    });
    if (!got) fail("the draft was not approved within 5 minutes");
  } else {
    step("the 'browser' opens the draft with its review key");
    const wrap = d.review_wraps.find((w) => w.review_key_id === reviewKey.id);
    const reviewCk = unwrapContentKey(wrap.wrapped_key, review.privateKey);
    const draftSubject = decryptText(d.subject_encrypted, reviewCk);
    const draftBody = decryptText(d.encrypted_content, reviewCk);
    if (draftSubject !== "Re: Lunch on Friday?" || draftBody !== replyText) fail("draft contents", { draftSubject, draftBody });
    console.log(`  opened: "${draftSubject}" / "${draftBody}" (via ${d.via})`);

    step("the person approves; B receives and decrypts it");
    expectStatus(await api("POST", `/agent-drafts/${d.id}/send`, { auth: human }), [202], "approve");
    const after = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(B.did)}`, { auth: human }), [200], "list B");
    got = after.messages.find((m) => m.sender_did === A.did && m.folder !== "sent");
    if (!got) fail("B did not receive the approved draft");
  }
  const content = expectStatus(await api("GET", `/messages/${got.id}/content`, { auth: human }), [200], "content");
  const ck = unwrapContentKey(content.encrypted_key, B.enc.privateKey);
  const gotBody = decryptText(content.encrypted_content, ck);
  if (gotBody !== replyText || content.thread_id !== (row.thread_id ?? sent.message_id)) fail("received reply", { gotBody, content });
  console.log(`  B got "${gotBody}" in thread ${content.thread_id}`);
  const left = expectStatus(await api("GET", "/agent-drafts", { auth: human }), [200], "list drafts");
  if (left.drafts.length !== 0) fail("the draft is still listed");

  await mcp.close();

  step("OAuth: start a gateway that takes only OAuth tokens");
  const oauthPort = MCP_PORT + 1;
  const oauthUrl = `http://127.0.0.1:${oauthPort}/mcp`;
  const oauthLog = path.join(WORK, "mcp-oauth-gateway.log");
  oauthGateway = spawn(GATEWAY_BIN, [
    "--llm-socket", path.join(sockDir, "mcp-oauth.sock"),
    "--signer-socket", stackEnv.AGENT_INBOX_SIGNER_SOCKET,
    "--api-url", API,
    "--mcp-listen", `127.0.0.1:${oauthPort}`,
    "--mcp-public-url", oauthUrl,
  ], { stdio: ["ignore", fs.openSync(oauthLog, "a"), fs.openSync(oauthLog, "a")] });
  for (let i = 0; i < 40 && !fs.readFileSync(oauthLog, "utf8").includes("OAuth audience"); i++) await sleep(250);
  if (!fs.readFileSync(oauthLog, "utf8").includes("OAuth audience")) fail("OAuth gateway did not start", fs.readFileSync(oauthLog, "utf8"));
  const prm = await (await fetch(`http://127.0.0.1:${oauthPort}/.well-known/oauth-protected-resource/mcp`)).json();
  if (prm.resource !== oauthUrl || prm.authorization_servers?.[0] !== API) fail("protected resource metadata", prm);

  // The person's side of consent, as the web page does it.
  const consent = async (authUrl) => {
    const params = Object.fromEntries(new URL(authUrl).searchParams);
    const info = expectStatus(await api("GET", `/oauth/authorize/info?${new URLSearchParams(params)}`, { auth: human }), [200], "consent info");
    const out = expectStatus(await api("POST", "/oauth/authorize", { auth: human, body: { ...params, approve: true } }), [200], "consent");
    return { info, code: new URL(out.redirect_to).searchParams.get("code") };
  };
  const { UnauthorizedError } = await import(pathToFileURL(path.join(SDK, "client/auth.js")).href);
  const makeProvider = () => {
    const store = {};
    return {
      store,
      get redirectUrl() { return "http://127.0.0.1:9/callback"; },
      get clientMetadata() {
        return { client_name: "e2e-oauth-muse", redirect_uris: ["http://127.0.0.1:9/callback"], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
      },
      clientInformation: () => store.client,
      saveClientInformation: (c) => { store.client = c; },
      tokens: () => store.tokens,
      saveTokens: (t) => { store.tokens = t; },
      redirectToAuthorization: (u) => { store.authUrl = u.toString(); },
      saveCodeVerifier: (v) => { store.verifier = v; },
      codeVerifier: () => store.verifier,
    };
  };
  const oauthConnect = async (provider, scopeOverride) => {
    const transport = new StreamableHTTPClientTransport(new URL(oauthUrl), { authProvider: provider });
    const client = new Client({ name: "e2e-oauth-muse", version: "0" });
    try {
      await client.connect(transport);
      fail("connected without a token");
    } catch (e) {
      if (!(e instanceof UnauthorizedError)) throw e;
    }
    if (!provider.store.authUrl) fail("the SDK did not reach the authorization endpoint");
    let authUrl = provider.store.authUrl;
    if (scopeOverride) {
      const u = new URL(authUrl);
      u.searchParams.set("scope", scopeOverride);
      authUrl = u.toString();
    }
    const { info, code } = await consent(authUrl);
    await transport.finishAuth(code);
    const again = new Client({ name: "e2e-oauth-muse", version: "0" });
    await again.connect(new StreamableHTTPClientTransport(new URL(oauthUrl), { authProvider: provider }));
    return { client: again, info, authUrl };
  };
  const callOauth = async (client, name, args) => {
    const r = await client.callTool({ name, arguments: args });
    return { error: r.isError ? r.content?.[0]?.text : null, value: r.structuredContent };
  };

  step("OAuth: the SDK discovers, registers, gets consent and a token");
  const provider = makeProvider();
  const { client: oauthClient, info, authUrl } = await oauthConnect(provider);
  console.log(`  authorize at ${new URL(authUrl).origin}${new URL(authUrl).pathname}`);
  console.log(`  consent page: ${info.client_name} → ${info.agent_label} (${info.scope.join(" ")})`);
  if (!provider.store.client?.client_id?.startsWith("nxc_")) fail("no dynamic registration", provider.store.client);
  if (!provider.store.tokens?.access_token?.startsWith("nxa_")) fail("no access token", provider.store.tokens);
  const oread = await callOauth(oauthClient, "read_message", { message_id: sent.message_id });
  if (oread.error || oread.value.subject !== "Lunch on Friday?") fail("OAuth read", oread);
  const odraft = await callOauth(oauthClient, "create_draft", { reply_to_message_id: sent.message_id, body: "Drafted over OAuth." });
  if (odraft.error) fail("OAuth draft", odraft);
  const listed = expectStatus(await api("GET", "/agent-drafts", { auth: human }), [200], "drafts");
  const viaOauth = listed.drafts.find((x) => x.id === odraft.value.draft_id);
  if (viaOauth?.via !== "e2e-oauth-muse") fail("the draft is not named after the OAuth app", viaOauth);
  console.log(`  read and drafted as "${viaOauth.via}"`);
  const grants = expectStatus(await api("GET", "/oauth/grants", { auth: human }), [200], "grants");
  if (!grants.grants.some((g) => g.client_name === "e2e-oauth-muse")) fail("the connection is not listed", grants);
  await oauthClient.close();
  expectStatus(await api("DELETE", `/agent-drafts/${odraft.value.draft_id}`, { auth: human }), [204], "discard");

  step("OAuth: a read-only grant cannot draft");
  const { client: reader } = await oauthConnect(makeProvider(), "inbox.read");
  const denied = await callOauth(reader, "create_draft", { reply_to_message_id: sent.message_id, body: "no" });
  if (!denied.error?.includes("not allowed")) fail("a read-only grant drafted", denied);
  console.log("  refused");
  await reader.close();

  console.log("\nPASS: drafts from the remote MCP endpoint are sent only after approval");
  if (process.env.KEEP) {
    console.log(`  KEEP: MCP http://127.0.0.1:${MCP_PORT}/mcp, token ${tokenFile}, user ${userId}`);
    process.exit(0);
  }
}

function cleanup() {
  if (process.env.KEEP) return;
  try {
    gateway?.kill();
    oauthGateway?.kill();
  } catch {}
  if (stackDir) {
    try {
      stack("stop");
    } catch {}
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(cleanup);
