#!/usr/bin/env node
// End-to-end check of the Isolated-mode auto-reply executor with the real
// API, signer daemon and agent gateway (docs/29, runbook 19 §7.3).
//
//   agent A: keys live in the signer daemon (Isolated mode)
//   agent B: plain keypairs held by this script (the sender)
//
// B sends A a schedule_negotiation propose. With A's policy set to
// auto_accept, the gateway executor must reply on its own: claim the row,
// unwrap and sign with the daemon, POST the accept, mark the row. The script
// then opens the reply with B's X25519 key and checks no second reply follows.
//
// Local only. Prerequisites:
//   - Postgres from `docker-compose up -d postgres` (container nexusinbox-postgres)
//   - an API on localhost started with
//       AGENT_INBOX_ALLOW_DEV_BEARER=true AGENT_INBOX_DISABLE_CSRF_CHECK=true
//       AGENT_INBOX_PUBLIC_API_URL=<the same URL as API below>
//       AGENT_INBOX_STORAGE_BACKEND=localfs
//   - `cargo build` in services/signer-daemon and services/agent-gateway
//
// Usage: API=http://localhost:8080 node scripts/e2e_isolated_auto_reply.mjs

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawn } from "node:child_process";

const API = process.env.API ?? "http://localhost:8080";
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = process.env.WORK ?? fs.mkdtempSync(path.join(os.tmpdir(), "nxe2e-work-"));
const A2A_CONTENT_TYPE = "application/vnd.nexusinbox.a2a+json; v=1";

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

const children = [];
function startProcess(name, cmd, args, env) {
  const log = fs.openSync(path.join(WORK, `${name}.log`), "w");
  const child = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ["ignore", log, log] });
  children.push(child);
  return child;
}

async function main() {
  const userId = crypto.randomUUID();
  const human = `Bearer dev-user-${userId}`;

  step("seed a human user (local DB)");
  execFileSync("docker", [
    "exec", "nexusinbox-postgres", "psql", "-U", "agent_inbox", "-d", "agent_inbox", "-q", "-c",
    `INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) VALUES ('${userId}', 'e2e-${userId}', 'e2e-${userId}', 'orb')`,
  ]);

  step("register agents A (Isolated) and B (sender)");
  const A = makeAgentKeys();
  const B = makeAgentKeys();
  const agentA = expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-A-isolated", public_key: A.signPubB64, encryption_key: A.encPubB64 } }),
    [200, 201], "create agent A");
  const agentB = expectStatus(
    await api("POST", "/agents", { auth: human, body: { label: "e2e-B-sender", public_key: B.signPubB64, encryption_key: B.encPubB64 } }),
    [200, 201], "create agent B");
  console.log(`  A ${agentA.did}\n  B ${agentB.did}`);
  if (agentA.did !== A.did) fail("API derived a different DID for A", { api: agentA.did, local: A.did });

  step("create and activate A's credential (keys to be held by the daemon)");
  const cred = expectStatus(
    await api("POST", "/agent-credentials", { auth: human, body: { agent_id: agentA.id, label: "e2e-daemon", scopes: ["messages.read", "messages.send"] } }),
    [200, 201], "create credential");
  const now = Math.floor(Date.now() / 1000);
  const proofSigned = `${b64urlJson({ alg: "EdDSA", typ: "JWT" })}.${b64urlJson({ credential_id: cred.credential_id, iat: now })}`;
  const proof = `${proofSigned}.${b64url(crypto.sign(null, Buffer.from(proofSigned), A.sign.privateKey))}`;
  expectStatus(
    await api("POST", `/agent-credentials/${cred.credential_id}/activate`, {
      body: {
        enrollment_secret: cred.enrollment_secret,
        signing_public_key: A.signPubB64,
        encryption_public_key: A.encPubB64,
        enrollment_proof: proof,
        key_holder: "signer_daemon",
      },
    }),
    [200], "activate credential");

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
  const a2a = {
    v: 1,
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
  };
  const contentKey = b64url(crypto.randomBytes(32));
  const body = encryptText(JSON.stringify(a2a), contentKey);
  const subject = encryptText("E2E propose", contentKey);
  const wrapped = wrapContentKey(contentKey, A.encPubB64);
  const signingPayload = [B.did, A.did, subject.serialized, body.serialized, wrapped, body.iv].join("\n");
  const signature = b64url(crypto.sign(null, Buffer.from(signingPayload, "utf8"), B.sign.privateKey));
  const sent = expectStatus(
    await api("POST", "/messages", {
      auth: human,
      body: {
        sender_did: B.did,
        recipient_did: A.did,
        envelope: {
          encrypted_content: body.serialized,
          encrypted_key: wrapped,
          nonce: body.iv,
          signature,
          metadata: { subject_encrypted: subject.serialized, content_type: A2A_CONTENT_TYPE, thread_id: null, has_attachments: false },
        },
        priority: "normal",
      },
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

  step("start the signer daemon (A's keys) and the gateway executor");
  const signKey = path.join(WORK, "a_signing.key");
  const encKey = path.join(WORK, "a_encryption.key");
  fs.writeFileSync(signKey, A.signSeed, { mode: 0o600 });
  fs.writeFileSync(encKey, A.encPriv, { mode: 0o600 });
  // Unix socket paths must stay under SUN_LEN (104 bytes on macOS), which
  // the scratch directory exceeds; use a short private temp dir for them.
  const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), "nxe2e-"));
  const signerSock = path.join(sockDir, "signer.sock");
  const gatewaySock = path.join(sockDir, "gateway.sock");
  for (const s of [signerSock, gatewaySock]) fs.rmSync(s, { force: true });
  startProcess("signer", path.join(REPO, "services/signer-daemon/target/debug/nexusinbox-signer"), [
    "--socket", signerSock,
    "--key-file", signKey,
    "--encryption-key-file", encKey,
    "--unsafe-plaintext-key",
    "--aid", agentA.aid,
    "--credential-id", cred.credential_id,
    "--api-url", API,
  ]);
  for (let i = 0; i < 40 && !fs.existsSync(signerSock); i++) await sleep(250);
  if (!fs.existsSync(signerSock)) fail("signer daemon did not open its socket", fs.readFileSync(path.join(WORK, "signer.log"), "utf8"));
  startProcess("gateway", path.join(REPO, "services/agent-gateway/target/debug/nexusinbox-gateway"), [
    "--llm-socket", gatewaySock,
    "--signer-socket", signerSock,
    "--api-url", API,
  ], { AGENT_INBOX_MODE_A_EXECUTOR: "on", AGENT_INBOX_MODE_A_EXECUTOR_INTERVAL_SECS: "5" });

  step("wait for A's auto-reply to reach B");
  let reply;
  for (let i = 0; i < 60 && !reply; i++) {
    await sleep(1000);
    const list = expectStatus(await api("GET", `/messages?agent_did=${encodeURIComponent(B.did)}`, { auth: human }), [200], "list B");
    reply = list.messages.find((m) => m.sender_did === A.did && m.folder !== "sent");
  }
  if (!reply) {
    fail("no reply within 60s", { gateway: fs.readFileSync(path.join(WORK, "gateway.log"), "utf8").slice(-3000) });
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
    for (const c of children) c.kill("SIGTERM");
  });
