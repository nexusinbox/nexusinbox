#!/usr/bin/env node
// End-to-end check of drafts from a cloud AI (docs/33 §8, §9), against a
// local API, the signer daemon and the gateway's remote MCP endpoint:
//
//   1. connect agent A with a long connect code (as a person does, docs/40
//      §13.5); this script is A's browser: it made A's root key, checks the
//      computer's MAC, signs A's device list and MACs the root back
//   2. start a gateway with --mcp-listen
//   3. B sends A a message (signature v2, wrapped for A's listed devices);
//      the official MCP client lists and reads it
//   4. the MCP client asks for a reply draft; nothing reaches B yet
//   5. the "browser" opens the draft with A's root key: drafts are wrapped
//      for the agent's listed devices (docs/40 §16.3)
//   6. the person approves it; B receives it and can decrypt it
//   7. OAuth (docs/33 §10): an app with the official SDK's OAuth client
//      finds the API from the endpoint's 401, registers, gets the person's
//      consent and a token, and drafts; a read-only grant cannot draft
//   8. RELAY=1 (docs/33 §11): Pebble (Let's Encrypt's test CA), the relay,
//      and a gateway with --mcp-relay that gets its own certificate through
//      the relay once the person turns cloud access on; the OAuth client
//      reaches it at https://<id>.mcp.agent-inbox.ai, and turning it off
//      disconnects the app and takes the computer off the relay
//
// Needs the same local API as scripts/e2e_isolated_auto_reply.mjs (dev
// bearer, CSRF on, all migrations) with
// AGENT_INBOX_MCP_ALLOW_LOCAL_RESOURCES=true, a built gateway and signer,
// and packages/core built (pnpm --filter @nexusinbox/core build).
//
// Usage: API=http://localhost:8081 node scripts/e2e_remote_mcp_drafts.mjs
//   KEEP=1 leaves the stack and the MCP endpoint running.
//   RELAY=1 also needs AGENT_INBOX_RELAY_TICKET_KEY on the API, a built
//   relay, and pebble + pebble-challtestsrv v2.10.1 in ~/go/bin.

import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
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
const RELAY_BIN =
  process.env.RELAY_BIN ?? path.join(REPO, "services/mcp-relay/target/debug/nexusinbox-relay");
const RELAY_PORT = Number(process.env.RELAY_PORT ?? 8799);
const SDK = path.join(REPO, "packages/mcp-server/node_modules/@modelcontextprotocol/sdk/dist/esm");
const CORE = path.join(REPO, "packages/core/dist");
const core = await import(pathToFileURL(path.join(CORE, "index.js")).href);
const deviceList = await import(pathToFileURL(path.join(CORE, "device-list.js")).href);
const pairing = await import(pathToFileURL(path.join(CORE, "pairing.js")).href);

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
  let res;
  // The local API limits requests per IP: wait out the window.
  for (let attempt = 0; ; attempt++) {
    res = await fetch(`${API}${p}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status !== 429 || attempt === 6) break;
    await res.text();
    await sleep(10_000);
  }
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
const relayProcs = [];
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

/** An agent's Ed25519 key as WebCrypto wants it, for core's signing. */
function webSigningKey(keys) {
  return crypto.webcrypto.subtle.importKey(
    "pkcs8",
    keys.sign.privateKey.export({ type: "pkcs8", format: "der" }),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

/** Sign (with the root key) and store an agent's device list (docs/40 §4.2). */
async function putDeviceList(human, agent, root, version, devices) {
  const jws = await deviceList.signDeviceList(await webSigningKey(root), {
    v: 1,
    aid: agent.aid,
    root: root.did,
    version,
    issued_at: new Date().toISOString(),
    devices,
  });
  expectStatus(await api("PUT", `/agents/${agent.id}/device-list`, { auth: human, body: { jws } }), [200], "device list");
}

/**
 * A message from `sender` to `recipient`, signed with v2 and wrapped for
 * every listed device of both agents (docs/38, docs/40 §14).
 */
async function sendFrom(sender, recipient, subjectText, bodyText) {
  const envelope = await core.buildEncryptedTextEnvelope({
    senderAid: sender.aid,
    recipientAid: recipient.aid,
    senderDid: sender.did,
    recipientDid: recipient.did,
    recipientEncryptionPublicKey: recipient.encPubB64,
    senderSigningPrivateKey: await webSigningKey(sender),
    senderEncryptionPublicKey: sender.encPubB64,
    recipientDevices: recipient.devices,
    senderDevices: sender.devices,
    subject: subjectText,
    body: bodyText,
  });
  return { sender_did: sender.did, recipient_did: recipient.did, envelope };
}

async function main() {
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
  const agentB = expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-B-friend", public_key: B.signPubB64, encryption_key: B.encPubB64 } }),
    [200, 201], "create agent B");
  // Agents without a device list are not sent to (docs/40 §15.2). The
  // browser each was created in signs its own.
  B.aid = agentB.aid;
  B.devices = [{ did: B.did, encryption_public_key: B.encPubB64 }];
  await putDeviceList(human, agentB, B, 1, [{ did: B.did, enc: B.encPubB64, kind: "browser" }]);
  await putDeviceList(human, agentA, placeholder, 1, [{ did: placeholder.did, enc: placeholder.encPubB64, kind: "browser" }]);

  step("connect A with a long connect code (docs/40 §13.5)");
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
    // The relay phase runs its own gateway against the local relay.
    AGENT_INBOX_MCP_RELAY: "off",
  };
  const agentDir = path.join(WORK, ".nexusinbox", "e2e-a-secretary");
  const secret = pairing.generatePairingSecret();
  try {
    const out = execFileSync("sh", [STACK, "connect", pairing.longPairingCode(cred.pairing_code, secret), API], {
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
  step("A's browser checks the computer's MAC, signs it into the list, and MACs the root back");
  const listedA = expectStatus(await api("GET", "/agents", { auth: human }), [200], "list agents").agents.find(
    (a) => a.aid === agentA.aid,
  );
  const computer = listedA.devices.find((d) => d.kind === "computer");
  const mac = await pairing.pairingDeviceMac(secret, cred.credential_id, computer.did, computer.encryption_public_key);
  if (!computer.pairing_mac || !pairing.macEqual(mac, computer.pairing_mac)) fail("the computer's keys do not match the code", computer);
  await putDeviceList(human, agentA, placeholder, 2, [
    { did: placeholder.did, enc: placeholder.encPubB64, kind: "browser" },
    { did: computer.did, enc: computer.encryption_public_key, kind: "computer" },
  ]);
  const rootMac = await pairing.pairingRootMac(secret, cred.credential_id, agentA.aid, placeholder.did);
  expectStatus(
    await api("PUT", `/agent-credentials/${cred.credential_id}/pairing-root`, { auth: human, body: { mac: rootMac } }),
    [200, 204], "pairing root");
  const A = {
    aid: agentA.aid,
    did: computer.did,
    encPubB64: computer.encryption_public_key,
    devices: [
      { did: placeholder.did, encryption_public_key: placeholder.encPubB64 },
      { did: computer.did, encryption_public_key: computer.encryption_public_key },
    ],
  };
  console.log(`  A ${A.did} (root ${placeholder.did})`);

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

  const sent = expectStatus(
    await api("POST", "/messages", { auth: human, body: await sendFrom(B, A, "Lunch on Friday?", "Are you free for lunch on Friday at noon?") }),
    [202], "B → A");

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
  step("the 'browser' opens the draft with A's root key (a listed device)");
  if (!d.signed_v2) fail("the draft is not signed with v2", d);
  const wrap = d.sender_encrypted_keys.find((w) => w.did === placeholder.did);
  if (!wrap) fail("the draft is not wrapped for A's listed browser", d.sender_encrypted_keys);
  if ((d.review_wraps ?? []).length) fail("the draft still carries review wraps", d.review_wraps);
  const draftCk = unwrapContentKey(wrap.key, placeholder.enc.privateKey);
  const draftSubject = decryptText(d.subject_encrypted, draftCk);
  const draftBody = decryptText(d.encrypted_content, draftCk);
  if (draftSubject !== "Re: Lunch on Friday?" || draftBody !== replyText) fail("draft contents", { draftSubject, draftBody });
  console.log(`  opened: "${draftSubject}" / "${draftBody}" (via ${d.via})`);

  step("the person approves; B receives and decrypts it");
  expectStatus(await api("POST", `/agent-drafts/${d.id}/send`, { auth: human }), [202], "approve");
  const after = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(B.did)}`, { auth: human }), [200], "list B");
  const got = after.messages.find((m) => m.sender_did === A.did && m.folder !== "sent");
  if (!got) fail("B did not receive the approved draft");
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
  // The SDK's own requests (discovery, registration, tokens) wait out the
  // local API's per-IP limit too.
  const patientFetch = async (input, init) => {
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(input, init);
      if (res.status !== 429 || attempt === 6) return res;
      await sleep(10_000);
    }
  };
  const oauthConnect = async (provider, scopeOverride, url = oauthUrl, fetchFn = patientFetch) => {
    const transport = new StreamableHTTPClientTransport(new URL(url), { authProvider: provider, fetch: fetchFn });
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
    await again.connect(new StreamableHTTPClientTransport(new URL(url), { authProvider: provider, fetch: fetchFn }));
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

  if (process.env.RELAY) {
    await relayPhase({ sockDir, human, sent, makeProvider, oauthConnect, callOauth, credentialId: cred.credential_id });
  }

  console.log("\nPASS: drafts from the remote MCP endpoint are sent only after approval");
  if (process.env.KEEP) {
    console.log(`  KEEP: MCP http://127.0.0.1:${MCP_PORT}/mcp, token ${tokenFile}, user ${userId}`);
    process.exit(0);
  }
}

// --- relay (docs/33 §11) -------------------------------------------------

function logTo(file) {
  return { stdio: ["ignore", fs.openSync(file, "a"), fs.openSync(file, "a")] };
}

async function waitForLog(file, needle, seconds, what) {
  for (let i = 0; i < seconds * 4; i++) {
    if (fs.existsSync(file) && fs.readFileSync(file, "utf8").includes(needle)) return;
    await sleep(250);
  }
  fail(`${what} (no "${needle}" in ${file})`, fs.existsSync(file) ? fs.readFileSync(file, "utf8").slice(-3000) : "");
}

function httpsGet(url, ca) {
  return new Promise((resolve, reject) => {
    https.get(url, { ca }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString()));
    }).on("error", reject);
  });
}

// What a cloud AI does, except that DNS for *.mcp.agent-inbox.ai points at
// the local relay port. The URL, SNI and certificate checks are the real ones.
function fetchViaRelay(ca) {
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (!url.hostname.endsWith(".mcp.agent-inbox.ai")) {
      // The local API limits requests per IP; this run has made many.
      for (let tries = 0; ; tries++) {
        const r = await fetch(input, init);
        if (r.status !== 429 || tries >= 12) return r;
        await sleep(10_000);
      }
    }
    const headers = Object.fromEntries(new Headers(init.headers ?? {}));
    return new Promise((resolve, reject) => {
      const req = https.request({
        host: "127.0.0.1",
        port: RELAY_PORT,
        servername: url.hostname,
        ca,
        method: init.method ?? "GET",
        path: url.pathname + url.search,
        headers: { ...headers, host: url.hostname },
      }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const pairs = Object.entries(res.headers).flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => [k, x]) : [[k, String(v)]]));
          const empty = chunks.length === 0 || [204, 304].includes(res.statusCode);
          resolve(new Response(empty ? null : Buffer.concat(chunks), { status: res.statusCode, headers: pairs }));
        });
      });
      req.on("error", reject);
      if (init.body) req.write(typeof init.body === "string" ? init.body : Buffer.from(init.body));
      req.end();
    });
  };
}

async function relayPhase({ sockDir, human, sent, makeProvider, oauthConnect, callOauth, credentialId }) {
  step("relay: Pebble, the relay, and a gateway that gets its own certificate");
  const gobin = path.join(os.homedir(), "go/bin");
  const pebbleSrc = path.join(execFileSync("go", ["env", "GOMODCACHE"]).toString().trim(), "github.com/letsencrypt/pebble/v2@v2.10.1");
  const minica = fs.readFileSync(path.join(pebbleSrc, "test/certs/pebble.minica.pem"));

  // DNS for Pebble's validation: every name is 127.0.0.1.
  const dnsLog = path.join(WORK, "challtestsrv.log");
  relayProcs.push(spawn(path.join(gobin, "pebble-challtestsrv"), [
    "-defaultIPv4", "127.0.0.1", "-defaultIPv6", "", "-dnsserver", "127.0.0.1:8053",
    "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "", "-management", "127.0.0.1:8055",
  ], logTo(dnsLog)));
  const pebbleConfig = path.join(WORK, "pebble-config.json");
  fs.writeFileSync(pebbleConfig, JSON.stringify({
    pebble: {
      listenAddress: "127.0.0.1:14000",
      managementListenAddress: "127.0.0.1:15000",
      certificate: path.join(pebbleSrc, "test/certs/localhost/cert.pem"),
      privateKey: path.join(pebbleSrc, "test/certs/localhost/key.pem"),
      httpPort: 5002,
      tlsPort: RELAY_PORT, // TLS-ALPN-01 goes to the relay, which passes it to the computer
      ocspResponderURL: "",
      externalAccountBindingRequired: false,
    },
  }));
  const pebbleLog = path.join(WORK, "pebble.log");
  relayProcs.push(spawn(path.join(gobin, "pebble"), ["-config", pebbleConfig, "-dnsserver", "127.0.0.1:8053"], {
    ...logTo(pebbleLog),
    env: { ...process.env, PEBBLE_VA_NOSLEEP: "1", PEBBLE_WFE_NONCEREJECT: "0" },
  }));
  await waitForLog(pebbleLog, "ACME directory available", 20, "Pebble did not start");

  // The relay's own certificate (Let's Encrypt in production).
  const pki = path.join(WORK, "relay-pki");
  fs.mkdirSync(pki, { recursive: true });
  const ossl = (args) => execFileSync("openssl", args, { cwd: pki, stdio: ["ignore", "pipe", "pipe"] });
  ossl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=e2e relay CA"]);
  ossl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "relay.key", "-out", "relay.csr", "-subj", "/CN=relay.agent-inbox.ai"]);
  fs.writeFileSync(path.join(pki, "ext.cnf"), "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:relay.agent-inbox.ai\nextendedKeyUsage=serverAuth\n");
  ossl(["x509", "-req", "-in", "relay.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "relay.pem", "-days", "1", "-extfile", "ext.cnf"]);

  const key = expectStatus(await api("GET", "/mcp-relay/ticket-key"), [200], "ticket key (is AGENT_INBOX_RELAY_TICKET_KEY set on the API?)");
  const relayLog = path.join(WORK, "relay.log");
  relayProcs.push(spawn(RELAY_BIN, [], {
    ...logTo(relayLog),
    env: {
      PATH: process.env.PATH,
      RELAY_LISTEN: `127.0.0.1:${RELAY_PORT}`,
      RELAY_TICKET_PUBLIC_KEY: key.x,
      RELAY_TLS_CERT: path.join(pki, "relay.pem"),
      RELAY_TLS_KEY: path.join(pki, "relay.key"),
    },
  }));
  await waitForLog(relayLog, "listening", 20, "relay did not start");

  const gwLog = path.join(WORK, "mcp-relay-gateway.log");
  const acmeCache = path.join(WORK, "acme");
  relayProcs.push(spawn(GATEWAY_BIN, [
    "--llm-socket", path.join(sockDir, "mcp-relay.sock"),
    "--signer-socket", stackEnv.AGENT_INBOX_SIGNER_SOCKET,
    "--api-url", API,
    "--mcp-relay", `127.0.0.1:${RELAY_PORT}`,
    "--mcp-relay-ca", path.join(pki, "ca.pem"),
    "--mcp-acme-directory", "https://localhost:14000/dir",
    "--mcp-acme-ca", path.join(pebbleSrc, "test/certs/pebble.minica.pem"),
    "--mcp-acme-cache", acmeCache,
  ], logTo(gwLog)));
  // Off until the person turns it on (docs/33 §12): the gateway only asks.
  await waitForLog(gwLog, "Cloud access is off", 30, "the gateway did not ask about cloud access");
  if (fs.readFileSync(gwLog, "utf8").includes("Connected to the relay")) fail("connected to the relay while cloud access was off");
  const cloudAccess = `/agent-credentials/${credentialId}/cloud-access`;
  expectStatus(await api("PUT", cloudAccess, { auth: human, body: { enabled: true } }), [200], "turn cloud access on");
  console.log("  off by default; turned on from the person's session");
  await waitForLog(gwLog, "Connected to the relay as", 60, "the gateway did not connect to the relay");
  const host = fs.readFileSync(gwLog, "utf8").match(/Connected to the relay as (\S+)/)[1];
  if (!/^[a-km-np-z2-9]{10}\.mcp\.agent-inbox\.ai$/.test(host)) fail("unexpected MCP host", host);
  console.log(`  connected as ${host}`);
  await waitForLog(gwLog, "DeployedNewCert", 60, "no certificate");
  if ((fs.statSync(acmeCache).mode & 0o777) !== 0o700) fail("the ACME cache is not 0700");
  console.log("  certificate issued by Pebble through the relay (TLS-ALPN-01)");

  // Trust only Pebble's root for the MCP host: the chain must verify for
  // this name, which only the computer holds the key for.
  const root = await httpsGet("https://localhost:15000/roots/0", minica);
  const relayFetch = fetchViaRelay(root);
  const relayUrl = `https://${host}/mcp`;
  const prm = await (await relayFetch(`https://${host}/.well-known/oauth-protected-resource/mcp`)).json();
  if (prm.resource !== relayUrl || prm.authorization_servers?.[0] !== API) fail("protected resource metadata via the relay", prm);

  step("relay: the OAuth client reads and drafts at https://<id>.mcp.agent-inbox.ai");
  const { client } = await oauthConnect(makeProvider(), undefined, relayUrl, relayFetch);
  const read = await callOauth(client, "read_message", { message_id: sent.message_id });
  if (read.error || read.value.subject !== "Lunch on Friday?") fail("read via the relay", read);
  const draft = await callOauth(client, "create_draft", { reply_to_message_id: sent.message_id, body: "Drafted through the relay." });
  if (draft.error) fail("draft via the relay", draft);
  await client.close();
  expectStatus(await api("DELETE", `/agent-drafts/${draft.value.draft_id}`, { auth: human }), [204], "discard");
  console.log("  read and drafted");

  step("relay: the page sees it ready; turning it off disconnects and leaves");
  let ready = null;
  for (let i = 0; i < 20 && !ready; i++) {
    const list = expectStatus(await api("GET", "/agent-credentials", { auth: human }), [200], "list credentials");
    const mine = list.credentials.find((c) => c.credential_id === credentialId);
    if (mine?.cloud_access && mine.cloud_url === relayUrl && mine.cloud_serving_at) ready = mine;
    else await sleep(2000);
  }
  if (!ready) fail("the credential never showed the relay URL as ready");
  const off = expectStatus(await api("PUT", cloudAccess, { auth: human, body: { enabled: false } }), [200], "turn cloud access off");
  if (!(off.disconnected >= 1)) fail("turning it off disconnected no AI app", off);
  await waitForLog(gwLog, "left the relay", 45, "the gateway did not leave the relay");
  const gone = await relayFetch(`https://${host}/mcp`).then(() => false, () => true);
  if (!gone) fail("the relay still answered for the computer after it left");
  console.log(`  ready on the page; off disconnected ${off.disconnected} app(s), and the computer left the relay`);

  step("relay: names nobody holds go nowhere");
  const nobody = "abcdefghij.mcp.agent-inbox.ai";
  const refused = await relayFetch(`https://${nobody}/mcp`).then(() => false, () => true);
  if (!refused) fail("the relay answered for a name nobody holds");
  const counts = fs.readFileSync(relayLog, "utf8");
  // Only its own listen line may carry an address; no computer's name.
  const lines = counts.split("\n").filter((l) => l && !l.includes("listening on"));
  if (counts.includes(host) || lines.some((l) => /\d+\.\d+\.\d+\.\d+/.test(l))) fail("the relay logged a host or an address", counts);
  console.log("  refused; the relay log names no host and no address");
}

function cleanup() {
  if (process.env.KEEP) return;
  try {
    gateway?.kill();
    oauthGateway?.kill();
    for (const p of relayProcs) p.kill();
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
