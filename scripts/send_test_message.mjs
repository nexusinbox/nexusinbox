#!/usr/bin/env node
/**
 * Send a test message via the NexusInbox API.
 *
 * Usage:
 *   node scripts/send_test_message.mjs
 *
 * Prerequisites:
 *   - API running on localhost:8080 with AGENT_INBOX_ALLOW_DEV_BEARER=true
 *   - DATABASE_URL configured
 */

import crypto from "node:crypto";

const API = "http://localhost:8080";
const USER_ID = "e4f120a9-0dd6-4e1d-a455-9eec92bf276b";
const AUTH = `Bearer dev-user-${USER_ID}`;

// Recipient: メイン秘書2
const RECIPIENT_DID =
  "did:key:z6MkshJantcq9iiKaEVeyFLsvq8QS1rvLzT6yDyxeKcqSxMT";

// --- Helpers ----------------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function deriveDidKey(publicKeyBytes) {
  // did:key uses multicodec 0xed01 prefix for ed25519-pub
  const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), publicKeyBytes]);
  // base58btc encode (multibase prefix 'z')
  return `did:key:z${base58btc(multicodec)}`;
}

// Minimal base58btc encoder
function base58btc(buf) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt("0x" + Buffer.from(buf).toString("hex"));
  const chars = [];
  while (num > 0n) {
    const remainder = num % 58n;
    chars.unshift(ALPHABET[Number(remainder)]);
    num = num / 58n;
  }
  // leading zeros
  for (const byte of buf) {
    if (byte === 0) chars.unshift("1");
    else break;
  }
  return chars.join("");
}

async function api(method, path, body) {
  const opts = {
    method,
    headers: {
      Authorization: AUTH,
      "Content-Type": "application/json",
      Origin: "http://localhost:3100",
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${API}${path}`, opts);
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, data: json };
}

// --- Main -------------------------------------------------------------------

async function main() {
  console.log("=== NexusInbox Test Message Sender ===\n");

  // 1. Generate an Ed25519 keypair for a temporary test agent
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubKeyRaw = publicKey.export({ type: "spki", format: "der" }).slice(-32);
  const privKeyRaw = privateKey.export({ type: "pkcs8", format: "der" }).slice(-32);
  const pubKeyB64url = b64url(pubKeyRaw);
  const senderDid = deriveDidKey(pubKeyRaw);

  console.log(`Sender DID: ${senderDid}`);
  console.log(`Recipient DID: ${RECIPIENT_DID}`);
  console.log(`Public key (b64url): ${pubKeyB64url}`);

  // Generate a fake encryption key (32 bytes)
  const encKeyB64url = b64url(crypto.randomBytes(32));

  // 2. Register a temporary test agent
  console.log("\n--- Creating test agent ---");
  const createRes = await api("POST", "/agents", {
    label: "テスト送信者",
    public_key: pubKeyB64url,
    encryption_key: encKeyB64url,
  });
  console.log(`Create agent: ${createRes.status}`, JSON.stringify(createRes.data));

  if (createRes.status !== 200 && createRes.status !== 201) {
    console.error("Failed to create agent, aborting");
    process.exit(1);
  }

  // 3. Build the message envelope
  const subjectEncrypted = b64url(Buffer.from("テストメッセージの件名"));
  const encryptedContent = b64url(Buffer.from("これはAPI経由で送信されたテストメッセージです。"));
  const nonce = b64url(crypto.randomBytes(24));

  // Build a valid x25519v1 wrapped key format:
  // x25519v1:ephemeral(32B):salt(16B):iv(12B):ciphertext
  const ephemeral = b64url(crypto.randomBytes(32));
  const salt = b64url(crypto.randomBytes(16));
  const iv = b64url(crypto.randomBytes(12));
  const ciphertext = b64url(crypto.randomBytes(48));
  const encryptedKey = `x25519v1:${ephemeral}:${salt}:${iv}:${ciphertext}`;

  // 4. Sign the envelope
  const signingPayload = `${senderDid}\n${RECIPIENT_DID}\n${subjectEncrypted}\n${encryptedContent}\n${encryptedKey}\n${nonce}`;
  const signature = crypto.sign(null, Buffer.from(signingPayload), privateKey);
  const signatureB64url = b64url(signature);

  // 5. Send the message
  console.log("\n--- Sending message ---");
  const payload = {
    sender_did: senderDid,
    recipient_did: RECIPIENT_DID,
    envelope: {
      encrypted_content: encryptedContent,
      encrypted_key: encryptedKey,
      nonce: nonce,
      signature: signatureB64url,
      metadata: {
        subject_encrypted: subjectEncrypted,
        content_type: "text/plain",
        has_attachments: false,
      },
    },
    priority: "normal",
  };

  console.log("Payload:", JSON.stringify(payload, null, 2));

  const sendRes = await api("POST", "/messages", payload);
  console.log(`\nSend message: ${sendRes.status}`, JSON.stringify(sendRes.data, null, 2));

  if (sendRes.status === 200 || sendRes.status === 201 || sendRes.status === 202) {
    console.log("\n✓ テストメッセージ送信成功！");
  } else {
    console.error("\n✗ 送信失敗");
  }
}

main().catch(console.error);
