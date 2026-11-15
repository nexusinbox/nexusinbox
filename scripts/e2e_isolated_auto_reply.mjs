#!/usr/bin/env node
// End-to-end check of the Isolated-mode auto-reply executor with the real
// API, signer daemon and agent gateway (docs/29, runbook 19 §7.3).
//
//   agent A: created the way the web UI does it, then connected the way a
//            person does it: the web shows a long connect code and
//            `run_noninteractive_stack.sh connect <code>` enrolls the daemon
//            and starts the daemon and gateway (docs/31, docs/40 §13.5);
//            this script is A's browser: it checks the computer's MAC,
//            signs it into A's device list and MACs the root back
//   agent B: plain keypairs held by this script (the sender), with a signed
//            device list; it signs with signature v2 (docs/40 §14)
//   agent C: enrolled with `nexusinbox-signer --enroll --dir`, the flow the
//            settings page still offers
//
// B sends A a schedule_negotiation propose, signed with v2 and wrapped for
// A's listed devices. The gateway checks the sender against B's list and
// only answers a verified, recent message. With A's policy set to
// auto_accept, the gateway executor must reply on its own: claim the row,
// unwrap and sign with the daemon, POST the accept, mark the row. The script
// then opens the reply with B's X25519 key and checks no second reply follows.
//
// Local only. Prerequisites:
//   - Postgres from `docker-compose up -d postgres` (container nexusinbox-postgres)
//   - an API on localhost started with
//       AGENT_INBOX_ALLOW_DEV_BEARER=true
//       AGENT_INBOX_CORS_ORIGINS=http://localhost:3100   (the Origin this script sends)
//       AGENT_INBOX_PUBLIC_API_URL=<the same URL as API below>
//       AGENT_INBOX_STORAGE_BACKEND=localfs
//     Keep the CSRF check on, as in production: the daemon calls the API
//     without an Origin, and only the cookie-less routes may let it through.
//   - `cargo build` in services/signer-daemon and services/agent-gateway
//   - packages/core built (pnpm --filter @nexusinbox/core build)
//
// Usage: API=http://localhost:8080 node scripts/e2e_isolated_auto_reply.mjs
//   Against an unpacked release instead of the checkout:
//   STACK=<dir>/nexusinbox SIGNER_BIN=<dir>/nexusinbox-signer API=... node scripts/e2e_isolated_auto_reply.mjs

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

const API = process.env.API ?? "http://localhost:8080";
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = process.env.WORK ?? fs.mkdtempSync(path.join(os.tmpdir(), "nxe2e-work-"));
const A2A_CONTENT_TYPE = "application/vnd.nexusinbox.a2a+json; v=1";
const CORE = path.join(REPO, "packages/core/dist");
const core = await import(pathToFileURL(path.join(CORE, "index.js")).href);
const deviceList = await import(pathToFileURL(path.join(CORE, "device-list.js")).href);
const pairing = await import(pathToFileURL(path.join(CORE, "pairing.js")).href);

// It seeds users straight into the database and relies on the dev bearer,
// so it must never point at a deployed API.
if (!["localhost", "127.0.0.1", "[::1]"].includes(new URL(API).hostname)) {
  console.error(`refusing to run against ${API}: local API only`);
  process.exit(2);
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const b64urlJson = (obj) => b64url(Buffer.from(JSON.stringify(obj), "utf8"));
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
  // The API allows 60 requests a minute from one address; the polling
  // below can reach that, so wait out the window instead of failing.
  for (let attempt = 0; ; attempt++) {
    res = await fetch(`${API}${p}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status !== 429 || attempt >= 12) break;
    await sleep(5000);
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

// --- main -------------------------------------------------------------------

// The stack script, as a person runs it from the repository root, or
// STACK / SIGNER_BIN pointing at an unpacked release (docs/32).
const STACK = process.env.STACK ?? path.join(REPO, "scripts/run_noninteractive_stack.sh");
const SIGNER_BIN =
  process.env.SIGNER_BIN ?? path.join(REPO, "services/signer-daemon/target/debug/nexusinbox-signer");
const PASSPHRASE = "e2e-passphrase";
let stackDir = null;
let stackEnv = null;
// The OS name the daemon reports as the device label.
const DEVICE_LABEL = { darwin: "macOS", linux: "Linux", win32: "Windows" }[process.platform] ?? process.platform;
function stack(command, input) {
  return execFileSync("sh", [STACK, command, stackDir], {
    cwd: REPO,
    env: stackEnv,
    input,
    stdio: ["pipe", "pipe", "pipe"],
  }).toString();
}

async function main() {
  const userId = crypto.randomUUID();
  const human = `Bearer dev-user-${userId}`;

  step("seed a human user (local DB)");
  execFileSync("docker", [
    "exec", "nexusinbox-postgres", "psql", "-U", "agent_inbox", "-d", "agent_inbox", "-q", "-c",
    `INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) VALUES ('${userId}', 'e2e-${userId}', 'e2e-${userId}', 'orb')`,
  ]);

  step("register agents A (Isolated), B (sender) and C (classic enroll)");
  // A is created the way the web UI does it; connecting below gives it the
  // keys it will actually use.
  const placeholder = makeAgentKeys();
  const B = makeAgentKeys();
  const agentA = expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-A-isolated", public_key: placeholder.signPubB64, encryption_key: placeholder.encPubB64 } }),
    [200, 201], "create agent A");
  const agentB = expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-B-sender", public_key: B.signPubB64, encryption_key: B.encPubB64 } }),
    [200, 201], "create agent B");
  const placeholderC = makeAgentKeys();
  const agentC = expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-C-enroll", public_key: placeholderC.signPubB64, encryption_key: placeholderC.encPubB64 } }),
    [200, 201], "create agent C");
  console.log(`  B ${agentB.did}`);
  // Agents without a device list are not sent to, and their messages are
  // not answered (docs/40 §15.2). The browser each was created in signs its own.
  B.aid = agentB.aid;
  B.devices = [{ did: B.did, encryption_public_key: B.encPubB64 }];
  await putDeviceList(human, agentB, B, 1, [{ did: B.did, enc: B.encPubB64, kind: "browser" }]);
  await putDeviceList(human, agentA, placeholder, 1, [{ did: placeholder.did, enc: placeholder.encPubB64, kind: "browser" }]);

  const mode = (f) => (fs.statSync(f).mode & 0o777).toString(8);
  const checkAgentDir = (dir, credentialId) => {
    if (mode(dir) !== "700") fail(`${dir} mode ${mode(dir)}, expected 700`);
    for (const f of ["signing.key.enc", "encryption.key.enc", "agent.env"]) {
      if (mode(path.join(dir, f)) !== "600") fail(`${f} mode ${mode(path.join(dir, f))}, expected 600`);
    }
    const agentEnv = fs.readFileSync(path.join(dir, "agent.env"), "utf8");
    for (const expected of [`AGENT_INBOX_CREDENTIAL_ID=${credentialId}`, `AGENT_INBOX_API_URL=${API}`]) {
      if (!agentEnv.includes(expected)) fail(`agent.env lacks ${expected}`, agentEnv);
    }
    return agentEnv;
  };

  step("connect A with a long connect code: run_noninteractive_stack.sh connect <code>");
  const cred = expectStatus(
    await api("POST", "/agent-credentials", { auth: human, body: { agent_id: agentA.id, label: "e2e-daemon", scopes: ["messages.read", "messages.send"], pairing: true } }),
    [201], "create pairing credential");
  if (cred.enrollment_secret || !/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/.test(cred.pairing_code ?? "")) {
    fail("expected a pairing code and no enrollment secret", cred);
  }
  // Unix socket paths must stay under SUN_LEN (104 bytes on macOS), which
  // the scratch directory may exceed; put the sockets in a short temp dir.
  // HOME points at the scratch directory, so ~/.nexusinbox lands there;
  // cargo and rustup keep their own homes.
  const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), "nxe2e-"));
  stackEnv = {
    ...process.env,
    HOME: WORK,
    CARGO_HOME: process.env.CARGO_HOME ?? path.join(os.homedir(), ".cargo"),
    RUSTUP_HOME: process.env.RUSTUP_HOME ?? path.join(os.homedir(), ".rustup"),
    AGENT_INBOX_SIGNER_SOCKET: path.join(sockDir, "signer.sock"),
    AGENT_INBOX_GATEWAY_SOCKET: path.join(sockDir, "gateway.sock"),
    AGENT_INBOX_MODE_A_EXECUTOR_INTERVAL_SECS: "5",
  };
  const agentDir = path.join(WORK, ".nexusinbox", "e2e-a-isolated");
  // The secret only this browser and the computer know (docs/40 §13.5).
  const secret = pairing.generatePairingSecret();
  try {
    // The new passphrase is asked twice; stdin is not a terminal here.
    const out = execFileSync("sh", [STACK, "connect", pairing.longPairingCode(cred.pairing_code, secret), API], {
      cwd: REPO,
      env: stackEnv,
      input: `${PASSPHRASE}\n${PASSPHRASE}\n`,
      stdio: ["pipe", "pipe", "pipe"],
    }).toString();
    stackDir = agentDir;
    if (!/Signer up:\s+yes/.test(out) || !/Gateway up:\s+yes/.test(out)) fail("stack did not come up", out);
  } catch (e) {
    if (fs.existsSync(path.join(agentDir, "agent.env"))) stackDir = agentDir;
    fail("connect failed", `${e.stdout ?? ""}${e.stderr ?? e}`);
  }
  const agentEnv = checkAgentDir(agentDir, cred.credential_id);
  if (!agentEnv.includes(`AGENT_INBOX_AID=${agentA.aid}`)) fail("agent.env names another agent", agentEnv);
  console.log(`  ${agentDir}: keys and agent.env (700 / 600)`);
  // The web sees the machine connected, under its OS name only.
  const creds = expectStatus(await api("GET", "/agent-credentials", { auth: human }), [200], "list credentials");
  const connected = creds.credentials.find((c) => c.credential_id === cred.credential_id);
  if (connected?.status !== "active" || connected?.label !== DEVICE_LABEL) fail(`expected an active credential labelled ${DEVICE_LABEL}`, connected);
  // The code is spent.
  const reused = await api("POST", "/agent-pairing/resolve", { body: { pairing_code: cred.pairing_code } });
  if (reused.status !== 404) fail(`a used pairing code resolved (${reused.status})`);
  // The agent now answers on the daemon's keys.
  const resolved = expectStatus(
    await api("GET", `/recipients/resolve?identifier=${encodeURIComponent(agentA.aid)}`, { auth: human }),
    [200], "resolve A");
  if (resolved.did === agentA.did) fail("A still answers on the placeholder keys after connecting");

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
  console.log(`  A ${A.did} (connected, labelled ${connected.label}; root ${placeholder.did})`);

  step("enroll C the classic way: nexusinbox-signer --enroll --dir");
  const credC = expectStatus(
    await api("POST", "/agent-credentials", { auth: human, body: { agent_id: agentC.id, label: "e2e-classic" } }),
    [201], "create credential for C");
  const agentDirC = path.join(WORK, "agent-c");
  try {
    execFileSync(SIGNER_BIN, [
      "--enroll",
      "--credential-id", credC.credential_id,
      "--dir", agentDirC,
      "--api-url", API,
    ], {
      env: { ...process.env, AGENT_INBOX_ENROLLMENT_SECRET: credC.enrollment_secret },
      input: `${PASSPHRASE}\n${PASSPHRASE}\n`,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (e) {
    fail("signer --enroll failed", `${e.stderr ?? e}`);
  }
  checkAgentDir(agentDirC, credC.credential_id);
  const credsAfter = expectStatus(await api("GET", "/agent-credentials", { auth: human }), [200], "list credentials");
  const classic = credsAfter.credentials.find((c) => c.credential_id === credC.credential_id);
  if (classic?.status !== "active" || classic?.label !== "e2e-classic") fail("C's credential should be active and keep its label", classic);
  console.log(`  ${agentDirC}: enrolled, label kept`);

  step("turn A's auto-reply on with an auto_accept policy");
  expectStatus(await api("PATCH", `/agents/${agentA.id}`, { auth: human, body: { auto_reply: true } }), [200], "enable auto-reply");
  expectStatus(
    await api("PUT", `/agents/${agentA.id}/auto-reply-policy`, { auth: human, body: { policy: { v: 1, default_action: "auto_accept" } } }),
    [200, 201], "put policy");

  step("B sends A a schedule_negotiation propose");
  const day = 86400_000;
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "+00:00");
  const candidate = { start: iso(Date.now() + 7 * day), end: iso(Date.now() + 7 * day + 3600_000) };
  const proposeId = crypto.randomUUID();
  // Signed with v2 and wrapped for every listed device of both agents
  // (docs/38, docs/40 §14), as a browser sends it.
  const envelope = await core.buildA2AEnvelope({
    senderAid: B.aid,
    recipientAid: A.aid,
    senderDid: B.did,
    recipientDid: A.did,
    recipientEncryptionPublicKey: A.encPubB64,
    senderSigningPrivateKey: await webSigningKey(B),
    senderEncryptionPublicKey: B.encPubB64,
    recipientDevices: A.devices,
    senderDevices: B.devices,
    subject: "E2E propose",
    body: "Can we meet next week?",
    protocol: {
      id: proposeId,
      type: "schedule_negotiation",
      action: "propose",
      reply_to: null,
      payload: {
        event_title: "E2E sync",
        candidates: [candidate],
        required_participants: [B.did, A.did],
        response_deadline: iso(Date.now() + 3 * day),
      },
    },
  });
  if (!envelope.signature_v2) fail("the propose is not signed with v2", envelope);
  const sent = expectStatus(
    await api("POST", "/messages", {
      auth: human,
      body: { sender_did: B.did, recipient_did: A.did, envelope, priority: "normal" },
    }),
    [202], "send propose");
  console.log(`  sent ${sent.message_id}`);

  // The evaluator stamps the recipient row asynchronously.
  let inboxRow;
  for (let i = 0; i < 20 && !inboxRow; i++) {
    const list = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(A.did)}`, { auth: human }), [200], "list A");
    inboxRow = list.messages.find((m) => m.sender_did === B.did && m.folder === "inbox" && m.auto_reply_decision);
    if (!inboxRow) await sleep(250);
  }
  if (!inboxRow) fail("the server never stamped A's inbox row");
  console.log(`  A's row ${inboxRow.id}: decision=${inboxRow.auto_reply_decision} (${inboxRow.auto_reply_reason})`);
  if (inboxRow.auto_reply_decision !== "auto_accept") fail("expected an auto_accept stamp", inboxRow);

  step("wait for A's auto-reply to reach B");
  let reply;
  for (let i = 0; i < 60 && !reply; i++) {
    await sleep(1000);
    const list = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(B.did)}`, { auth: human }), [200], "list B");
    reply = list.messages.find((m) => m.sender_did === A.did && m.folder !== "sent");
  }
  if (!reply) {
    fail("no reply within 60s", { gateway: fs.readFileSync(path.join(agentDir, "run", "gateway.log"), "utf8").slice(-3000) });
  }
  console.log(`  reply ${reply.id} from A`);

  step("open the reply with B's X25519 key");
  const content = expectStatus(await api("GET", `/messages/${reply.id}/content`, { auth: human }), [200], "reply content");
  if (content.content_type !== A2A_CONTENT_TYPE) fail("reply is not A2A", content);
  const replyKey = unwrapContentKey(content.encrypted_key, B.enc.privateKey);
  const replyA2a = JSON.parse(decryptText(content.encrypted_content, replyKey));
  console.log(`  protocol: ${replyA2a.protocol.type}/${replyA2a.protocol.action} reply_to=${replyA2a.protocol.reply_to}`);
  if (replyA2a.protocol.type !== "schedule_negotiation" || replyA2a.protocol.action !== "accept") fail("expected an accept", replyA2a);
  if (replyA2a.protocol.reply_to !== proposeId) fail("reply_to does not point at the propose", replyA2a);
  console.log(`  selected: ${JSON.stringify(replyA2a.protocol.payload.selected_candidate)}`);
  // docs/35 §5: the computer keeps a copy of the content key for itself, so
  // A can read its own reply later.
  if (!/^x25519v1:/.test(content.sender_encrypted_key ?? "") || content.sender_encrypted_key === content.encrypted_key) {
    fail("the auto-reply has no sender copy of its key", content.sender_encrypted_key);
  }
  console.log("  the reply keeps a sender copy of its key");
  // docs/38: every device gets its own wrap. A's other device is the key it
  // was created with (the browser's), so A can read the reply there too.
  const browserWrap = (content.sender_encrypted_keys ?? []).find((w) => w.did === agentA.did);
  if (!browserWrap) fail("the reply has no wrap for A's browser key", content.sender_encrypted_keys);
  if (unwrapContentKey(browserWrap.key, placeholder.enc.privateKey) !== replyKey) {
    fail("A's browser key does not open its wrap of the reply");
  }
  const bWrap = (content.encrypted_keys ?? []).find((w) => w.did === agentB.did);
  if (!bWrap || unwrapContentKey(bWrap.key, B.enc.privateKey) !== replyKey) {
    fail("B's device list wrap does not open the reply", content.encrypted_keys);
  }
  console.log(`  the reply is wrapped for ${content.encrypted_keys.length} recipient and ${content.sender_encrypted_keys.length} sender devices; A's browser opens its copy`);

  step("A's original row is marked sent and claimed");
  const listA = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(A.did)}`, { auth: human }), [200], "list A");
  const settled = listA.messages.find((m) => m.id === inboxRow.id);
  console.log(`  auto_reply_claimed_at=${settled?.auto_reply_claimed_at} auto_reply_sent_at=${settled?.auto_reply_sent_at}`);
  if (!settled?.auto_reply_sent_at || !settled?.auto_reply_claimed_at) fail("row not settled", settled);

  // A later tick must not reply again.
  await sleep(7000);
  const again = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(B.did)}`, { auth: human }), [200], "list B");
  const replies = again.messages.filter((m) => m.sender_did === A.did && m.folder !== "sent");
  console.log(`  replies after another tick: ${replies.length}`);
  if (replies.length !== 1) fail("expected exactly one reply", replies);

  console.log("\nPASS: the Isolated executor answered with the real daemon, gateway and API");
  console.log(`  logs: ${WORK}`);
}

main()
  .catch((e) => {
    if (!process.exitCode) {
      console.error(e);
      process.exitCode = 1;
    }
  })
  .finally(() => {
    if (stackDir) {
      try {
        stack("stop");
      } catch {
        // already stopped
      }
    }
  });
