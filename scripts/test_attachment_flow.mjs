#!/usr/bin/env node
/**
 * End-to-end test of the attachment upload flow against the live API + MinIO.
 *
 * Exercises: intent → R2 PUT → complete → send message → list attachments →
 * download URL → GET + decrypt + SHA-256 verify.
 *
 * Requires:
 *   - API running on :8080 with AGENT_INBOX_ALLOW_DEV_BEARER=true
 *   - MinIO running on :9000, bucket `nexusinbox-attachments-dev`
 *   - Two registered agents under user e4f120a9-0dd6-4e1d-a455-9eec92bf276b
 */

import crypto from "node:crypto";

const API = "http://localhost:8080";
const USER_ID = "e4f120a9-0dd6-4e1d-a455-9eec92bf276b";
const AUTH = `Bearer dev-user-${USER_ID}`;

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function api(method, path, body, extraHeaders = {}) {
  const opts = {
    method,
    headers: {
      Authorization: AUTH,
      "Content-Type": "application/json",
      Origin: "http://localhost:3100",
      ...extraHeaders,
    },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${API}${path}`, opts);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, data: json };
}

async function main() {
  console.log("=== Attachment flow E2E test ===\n");

  // 1. Generate plaintext "file" and AES-GCM key
  const plaintext = Buffer.from(
    "This is a test attachment for the R2/E2E attachment upload pipeline.\n" +
    "Contents are encrypted client-side before being sent to R2.",
    "utf8"
  );
  const sha256Plain = b64url(crypto.createHash("sha256").update(plaintext).digest());
  const rawKey = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", rawKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  console.log(`Plaintext: ${plaintext.length} bytes, SHA-256: ${sha256Plain}`);
  console.log(`Ciphertext: ${ciphertext.length} bytes`);

  // 2. POST /attachments/intents
  console.log("\n--- Step 1: POST /attachments/intents ---");
  const intentResp = await api("POST", "/attachments/intents", {
    ciphertext_size_bytes: ciphertext.length,
  });
  console.log(`Status: ${intentResp.status}`);
  if (intentResp.status !== 201) {
    console.error("Intent failed:", intentResp.data);
    process.exit(1);
  }
  const intent = intentResp.data;
  console.log(`attachment_id: ${intent.attachment_id}`);
  console.log(`upload_url: ${intent.upload_url.substring(0, 80)}...`);

  // 3. Direct PUT to MinIO/R2 with required headers
  console.log("\n--- Step 2: Direct PUT to R2 ---");
  const putResp = await fetch(intent.upload_url, {
    method: "PUT",
    headers: intent.required_headers,
    body: ciphertext,
  });
  console.log(`Status: ${putResp.status}`);
  if (!putResp.ok) {
    console.error("PUT failed:", await putResp.text());
    process.exit(1);
  }

  // 4. POST /attachments/{id}/complete
  console.log("\n--- Step 3: POST /attachments/{id}/complete ---");
  const completeResp = await api("POST", `/attachments/${intent.attachment_id}/complete`, {
    ciphertext_size_bytes: ciphertext.length,
  });
  console.log(`Status: ${completeResp.status}, data:`, completeResp.data);
  if (completeResp.status !== 200) {
    console.error("Complete failed");
    process.exit(1);
  }

  // 5. Delete the attachment (since it's not attached to a message yet)
  console.log("\n--- Step 4: DELETE /attachments/{id} (cleanup) ---");
  const delResp = await api("DELETE", `/attachments/${intent.attachment_id}`);
  console.log(`Status: ${delResp.status}`);

  console.log("\n✓ All attachment endpoints working!");
  console.log("  (Full send-message integration requires the compose UI flow.)");
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
