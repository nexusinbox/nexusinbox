/**
 * Direct API flow WITH an attachment.
 *
 * Shows the full 4-step attachment path described in
 * docs/17_attachment_upload_r2_spec.md:
 *
 *   1. POST /attachments/intents     → presigned R2 PUT URL
 *   2. PUT  <upload_url>             → encrypted bytes
 *   3. POST /attachments/:id/complete → server verifies size, flips status
 *   4. POST /messages { attachments: [ref] } → the envelope links to the blob
 *
 * The ciphertext uses AES-GCM-256. The content key is wrapped for each
 * reader (recipient + sender for self-view) via X25519 ECDH. All of this
 * happens client-side — the server never sees the plaintext or the key.
 *
 * If AGENT_ATTACHMENT_PATH is set we encrypt that file; otherwise we
 * synthesize a small text file so the example is runnable out of the box.
 */

import { readFile } from "node:fs/promises";
import { createAuthenticatedApiClient } from "../../packages/core/dist/index.js";
import { loadOrActivateCredential } from "./_keystore.mjs";

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env: ${name}`);
  }
  return value;
}

async function loadAttachmentBytes() {
  const path = process.env.AGENT_ATTACHMENT_PATH;
  if (path) {
    const bytes = await readFile(path);
    return {
      filename: path.split("/").pop() ?? "attachment.bin",
      mime: guessMime(path),
      bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    };
  }
  // Synthesized sample so the script works without prep.
  const body = [
    "NexusInbox — synthesized test attachment",
    `generated_at: ${new Date().toISOString()}`,
    "",
    "If you can read this after decrypting, the attachment pipeline",
    "worked end-to-end: AES-GCM encrypt → R2 PUT → complete → message",
    "envelope references the attachment_id.",
    "",
  ].join("\n");
  return {
    filename: "nexusinbox-test-attachment.txt",
    mime: "text/plain",
    bytes: new TextEncoder().encode(body),
  };
}

function guessMime(path) {
  const ext = path.toLowerCase().split(".").pop();
  switch (ext) {
    case "txt":
    case "md":
      return "text/plain";
    case "json":
      return "application/json";
    case "pdf":
      return "application/pdf";
    case "png":
      return "image/png";
    case "jpg":
    case "jpeg":
      return "image/jpeg";
    default:
      return "application/octet-stream";
  }
}

async function main() {
  const baseUrl = required("AGENT_INBOX_BASE_URL");
  const aid = required("AGENT_AID");
  const credentialId = required("AGENT_CREDENTIAL_ID");
  const recipient = required("AGENT_RECIPIENT");

  console.log("=== Agent Runtime Direct API + Attachment ===");
  console.log("baseUrl:   ", baseUrl);
  console.log("aid:       ", aid);
  console.log("credential:", credentialId);

  // Step 0: load or activate the sender credential (ens_ only on first run).
  const { signing, source, keystorePath } = await loadOrActivateCredential({
    baseUrl,
    aid,
    credentialId,
    enrollmentSecret: process.env.AGENT_ENROLLMENT_SECRET,
    passphrase: process.env.AGENT_KEYSTORE_PASSPHRASE,
    keystoreDir: process.env.AGENT_KEYSTORE_DIR,
  });
  console.log(`keystore:   ${source} (${keystorePath})`);

  const { client, tokens } = await createAuthenticatedApiClient({
    baseUrl,
    aid,
    credentialId,
    signingPrivateKey: signing.privateKey,
  });
  console.log("token:     ", tokens.token_type, "(", tokens.scope, ")");

  // Resolve self + recipient so we have both encryption public keys — the
  // attachment content key gets wrapped for each reader so both can decrypt.
  const me = await client.resolveRecipient(aid);
  const to = await client.resolveRecipient(recipient);
  console.log("self:      ", me.did, `[${me.label}]`);
  console.log("recipient: ", to.did, `[${to.label}]`);

  // Step 1-3: encrypt + upload + complete.
  const attachment = await loadAttachmentBytes();
  console.log(
    `\nattachment: ${attachment.filename} (${attachment.mime}, ${attachment.bytes.byteLength} bytes plaintext)`,
  );

  console.log("\nStep 1-3: encrypt + PUT to R2 + complete");
  const uploaded = await client.encryptAndUploadAttachment({
    plaintext: attachment.bytes,
    filename: attachment.filename,
    mimeType: attachment.mime,
    senderDid: me.did,
    keyWrapTargets: [
      // Sender wrap first so the sender can view their own outgoing attachment.
      { did: me.did, encryptionPublicKeyB64Url: me.encryption_public_key ?? "" },
      { did: to.did, encryptionPublicKeyB64Url: to.encryption_public_key ?? "" },
    ],
  });
  console.log(
    `  attachment_id:         ${uploaded.attachmentId}`,
  );
  console.log(
    `  ciphertext_size_bytes: ${uploaded.ciphertext_size_bytes}`,
  );

  // Step 4: send a message that references the uploaded blob.
  console.log("\nStep 4: POST /messages with attachment reference");
  const sendResult = await client.sendTextMessage({
    senderDid: me.did,
    recipientDid: to.did,
    recipientEncryptionPublicKey: to.encryption_public_key ?? "",
    senderSigningPrivateKey: signing.privateKey,
    subject: "NexusInbox SDK example (with attachment)",
    body: `Sent from templates/agent-runtime-node/direct-api-with-attachment.mjs. Attachment: ${attachment.filename}`,
    attachments: [uploaded],
  });
  console.log("  send:", sendResult);

  console.log("\n✓ 送信完了 (message_id:", sendResult.message_id, ")");
  console.log("  受信側 UI で該当メッセージを開くと添付が表示されます。");
  console.log(
    "  復号は受信側の秘密鍵が必要なため、このスクリプトの実行ユーザーからは",
  );
  console.log("  送信トレイ (sent folder) 側で自分向け wrap を使って表示できます。");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
