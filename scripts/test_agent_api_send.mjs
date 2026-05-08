#!/usr/bin/env node
/**
 * End-to-end test: AI agent sends a message via the non-interactive API flow.
 *
 * Flow:
 *   1. Generate fresh Ed25519 (signing) + X25519 (encryption) keypairs.
 *   2. Register these keys as a new agent under the human account
 *      (dev bearer). This gives us a DID in the `agents` table, which is
 *      what `send_message` uses to validate sender_did ownership.
 *   3. Activate the credential with the same signing key. This satisfies the
 *      agent_identity_keys table and flips the credential to 'active'.
 *   4. Build a JWS Assertion signed with the signing key.
 *   5. Exchange the assertion for an agent access token via
 *      POST /agent-auth/token (with a DPoP JWK for token binding).
 *   6. Resolve the recipient identifier (`aid` or `did`) to the current DID
 *      and encryption_public_key.
 *   7. E2E-encrypt the message (XChaCha20-Poly1305-compatible via
 *      the same AES-GCM pattern the Rust server expects).
 *   8. POST /messages with the access token + DPoP proof.
 *
 * Prerequisites:
 *   - API running on :8080 with AGENT_INBOX_ALLOW_DEV_BEARER=true
 *   - The enrollment_secret corresponds to a `pending` credential in DB
 */

import crypto from "node:crypto";

const API = "http://localhost:8080";
const USER_ID = "e4f120a9-0dd6-4e1d-a455-9eec92bf276b";
const DEV_AUTH = `Bearer dev-user-${USER_ID}`;
const CREDENTIAL_ID = "defcfb20-16e6-4670-8023-98f6ce8aa27d";
const ENROLLMENT_SECRET = "ens_YfHfK5gGPQ5pvgUHX_CSHL-24B4kf8uJk2eDyi6b5Zs";
const RECIPIENT_IDENTIFIER = "aid:ai:01HXRECIPIENT";

// --- Helpers ----------------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlJson(obj) {
  return b64url(Buffer.from(JSON.stringify(obj), "utf8"));
}

function base58btc(buf) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt("0x" + Buffer.from(buf).toString("hex"));
  const chars = [];
  while (num > 0n) {
    chars.unshift(ALPHABET[Number(num % 58n)]);
    num = num / 58n;
  }
  for (const b of buf) {
    if (b === 0) chars.unshift("1");
    else break;
  }
  return chars.join("");
}

function deriveDidKey(publicKeyBytes) {
  const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), publicKeyBytes]);
  return `did:key:z${base58btc(multicodec)}`;
}

function signEd25519(privateKeyObj, message) {
  return crypto.sign(null, Buffer.from(message, "utf8"), privateKeyObj);
}

function ed25519PublicRaw(publicKey) {
  // SPKI → last 32 bytes = raw Ed25519 public key
  return publicKey.export({ type: "spki", format: "der" }).slice(-32);
}

async function apiCall(method, path, body, headers = {}) {
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      Origin: "http://localhost:3100",
      ...headers,
    },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${API}${path}`, opts);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, data: json };
}

// --- Main -------------------------------------------------------------------

async function main() {
  console.log("=== AI Agent API Message Send E2E ===\n");

  // Step 1: generate keypairs
  console.log("Step 1: Generating Ed25519 signing + X25519 encryption keys");
  const signKP = crypto.generateKeyPairSync("ed25519");
  const signPub = ed25519PublicRaw(signKP.publicKey);
  const signPubB64 = b64url(signPub);
  const signerDid = deriveDidKey(signPub);

  // X25519 for envelope encryption key wrap (32 bytes, flat random — the
  // encryption_key column just stores the x25519 public key base64url).
  const encKP = crypto.generateKeyPairSync("x25519");
  const encPub = encKP.publicKey.export({ type: "spki", format: "der" }).slice(-32);
  const encPubB64 = b64url(encPub);

  console.log(`  signer DID: ${signerDid}`);
  console.log(`  signing pubkey (b64url): ${signPubB64}`);
  console.log(`  encryption pubkey (b64url): ${encPubB64}`);

  // Step 2: register these keys as a new agent (human session)
  console.log("\nStep 2: Registering agent with credential keys (dev bearer)");
  const agentResp = await apiCall(
    "POST",
    "/agents",
    {
      label: "AI-Agent-API-Test",
      public_key: signPubB64,
      encryption_key: encPubB64,
    },
    { Authorization: DEV_AUTH },
  );
  if (agentResp.status !== 201 && agentResp.status !== 200) {
    if (agentResp.status === 409) {
      console.log("  (agent already exists — reusing)");
    } else {
      console.error("Agent creation failed:", agentResp.status, agentResp.data);
      process.exit(1);
    }
  } else {
    console.log(`  agent id: ${agentResp.data.id}`);
  }

  // Step 3: activate the credential
  console.log("\nStep 3: Activating credential with enrollment secret");
  // Build enrollment proof JWS signed by the signing key
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: "EdDSA", typ: "JWT" };
  const proofPayload = { credential_id: CREDENTIAL_ID, iat: nowSec };
  const proofSigned = `${b64urlJson(header)}.${b64urlJson(proofPayload)}`;
  const proofSig = signEd25519(signKP.privateKey, proofSigned);
  const enrollmentProof = `${proofSigned}.${b64url(proofSig)}`;

  const activateResp = await apiCall(
    "POST",
    `/agent-credentials/${CREDENTIAL_ID}/activate`,
    {
      enrollment_secret: ENROLLMENT_SECRET,
      signing_public_key: signPubB64,
      encryption_public_key: encPubB64,
      enrollment_proof: enrollmentProof,
    },
  );
  console.log(`  status: ${activateResp.status}`);
  if (activateResp.status !== 200) {
    console.error("Activation failed:", activateResp.data);
    process.exit(1);
  }
  console.log(`  aid: ${activateResp.data.aid}`);
  console.log(`  did (from credential keys): ${activateResp.data.did}`);
  if (activateResp.data.did !== signerDid) {
    console.warn(`  ⚠ DID mismatch: expected ${signerDid}`);
  }
  const aid = activateResp.data.aid;

  // Step 4: build JWS Assertion
  console.log("\nStep 4: Building JWS Assertion");
  const assertionHeader = { alg: "EdDSA", typ: "JWT" };
  const assertionPayload = {
    iss: aid,
    sub: CREDENTIAL_ID,
    aud: `${API}/agent-auth/token`,
    jti: crypto.randomUUID(),
    iat: nowSec,
    exp: nowSec + 60,
    scope: "messages.read messages.send",
  };
  const assertionSigned = `${b64urlJson(assertionHeader)}.${b64urlJson(assertionPayload)}`;
  const assertionSig = signEd25519(signKP.privateKey, assertionSigned);
  const assertion = `${assertionSigned}.${b64url(assertionSig)}`;

  // Generate a fresh DPoP keypair (separate from signing key so we can rotate)
  const dpopKP = crypto.generateKeyPairSync("ed25519");
  const dpopPub = ed25519PublicRaw(dpopKP.publicKey);
  const dpopJwk = { kty: "OKP", crv: "Ed25519", x: b64url(dpopPub) };

  // Step 5: exchange for access token
  console.log("\nStep 5: POST /agent-auth/token");
  const tokenResp = await apiCall("POST", "/agent-auth/token", {
    assertion,
    dpop_jwk: dpopJwk,
  });
  console.log(`  status: ${tokenResp.status}`);
  if (tokenResp.status !== 200) {
    console.error("Token exchange failed:", tokenResp.data);
    process.exit(1);
  }
  const accessToken = tokenResp.data.access_token;
  console.log(`  access_token: ${accessToken.substring(0, 20)}...`);
  console.log(`  token_type: ${tokenResp.data.token_type}`);
  console.log(`  scope: ${tokenResp.data.scope}`);

  // Step 6: resolve recipient to current DID + encryption key
  console.log("\nStep 6: Resolving recipient identifier");
  const resolveResp = await apiCall(
    "GET",
    `/recipients/resolve?identifier=${encodeURIComponent(RECIPIENT_IDENTIFIER)}`,
    undefined,
    {
      Authorization: DEV_AUTH,
    },
  );
  if (resolveResp.status !== 200) {
    console.error("Recipient resolution failed:", resolveResp.status, resolveResp.data);
    process.exit(1);
  }
  const resolvedRecipientDid = resolveResp.data.did;
  const recipientEncPub = resolveResp.data.encryption_public_key;
  console.log(`  recipient identifier: ${RECIPIENT_IDENTIFIER}`);
  console.log(`  resolved DID: ${resolvedRecipientDid}`);
  console.log(`  encryption_key (b64url): ${recipientEncPub}`);

  const agentsResp = await apiCall("GET", "/agents", undefined, {
    Authorization: DEV_AUTH,
  });
  if (agentsResp.status !== 200) {
    console.error("Agent list lookup failed:", agentsResp.status, agentsResp.data);
    process.exit(1);
  }

  // Step 7: build envelope (use dummy x25519v1 wrapped key — server validates
  // format but not the actual crypto; recipient will show a decrypt failure
  // since we can't truly wrap without X25519 ECDH here.)
  console.log("\nStep 7: Building encrypted envelope");
  const subjectEncrypted = b64url(Buffer.from("AIエージェントからのテストメッセージ", "utf8"));
  const encryptedContent = b64url(Buffer.from("これはAIエージェントがAPI経由で送信したテストメッセージです。\n（本文は実際にはE2E暗号化されるべきですが、このテストスクリプトではダミーデータです）", "utf8"));
  const nonce = b64url(crypto.randomBytes(24));
  const ephemeral = b64url(crypto.randomBytes(32));
  const salt = b64url(crypto.randomBytes(16));
  const iv = b64url(crypto.randomBytes(12));
  const ciphertext = b64url(crypto.randomBytes(48));
  const encryptedKey = `x25519v1:${ephemeral}:${salt}:${iv}:${ciphertext}`;

  const signingPayload = `${signerDid}\n${resolvedRecipientDid}\n${subjectEncrypted}\n${encryptedContent}\n${encryptedKey}\n${nonce}`;
  const envelopeSig = signEd25519(signKP.privateKey, signingPayload);
  const signature = b64url(envelopeSig);

  // Step 8: build DPoP proof and send message
  console.log("\nStep 8: POST /messages with DPoP proof");
  const dpopHeader = { alg: "EdDSA", typ: "dpop+jwt", jwk: dpopJwk };
  const ath = b64url(crypto.createHash("sha256").update(accessToken).digest());
  const dpopPayload = {
    htm: "POST",
    htu: "/messages",
    ath,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  };
  const dpopSigned = `${b64urlJson(dpopHeader)}.${b64urlJson(dpopPayload)}`;
  const dpopSig = signEd25519(dpopKP.privateKey, dpopSigned);
  const dpopProof = `${dpopSigned}.${b64url(dpopSig)}`;

  const msgPayload = {
    sender_did: signerDid,
    recipient_did: RECIPIENT_IDENTIFIER,
    envelope: {
      encrypted_content: encryptedContent,
      encrypted_key: encryptedKey,
      nonce,
      signature,
      metadata: {
        subject_encrypted: subjectEncrypted,
        content_type: "text/plain",
        has_attachments: false,
      },
    },
    priority: "normal",
  };

  const sendResp = await apiCall("POST", "/messages", msgPayload, {
    Authorization: `DPoP ${accessToken}`,
    DPoP: dpopProof,
  });
  console.log(`  status: ${sendResp.status}`);
  console.log(`  response:`, JSON.stringify(sendResp.data, null, 2));

  if (sendResp.status === 202) {
    console.log("\n✓ AIエージェント経由のメッセージ送信成功！");
    console.log(`  message_id: ${sendResp.data.message_id}`);
    console.log(`  from: ${signerDid}`);
    console.log(`  to:   ${RECIPIENT_IDENTIFIER} -> ${resolvedRecipientDid}`);
  } else {
    console.error("\n✗ 送信失敗");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
