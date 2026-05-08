/**
 * Direct API send example — persisted keystore edition.
 *
 * First run: pass AGENT_ENROLLMENT_SECRET. We activate the credential,
 * write private keys to ~/.nexusinbox/<credentialId>.json (0600, atomic),
 * and send a message.
 *
 * Later runs: omit AGENT_ENROLLMENT_SECRET. We read the keystore, skip
 * activation, and go straight to token exchange + send. The same
 * credential_id can be reused indefinitely this way.
 *
 * Env vars:
 *   AGENT_INBOX_BASE_URL       required
 *   AGENT_AID                  required
 *   AGENT_CREDENTIAL_ID        required
 *   AGENT_ENROLLMENT_SECRET    only on first run
 *   AGENT_RECIPIENT            required
 *   AGENT_KEYSTORE_PASSPHRASE  optional — encrypts the keystore at rest
 *   AGENT_KEYSTORE_DIR         optional (~/.nexusinbox)
 */

import { createAuthenticatedApiClient } from "../../packages/core/dist/index.js";
import { loadOrActivateCredential } from "./_keystore.mjs";

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env: ${name}`);
  }
  return value;
}

async function main() {
  const baseUrl = required("AGENT_INBOX_BASE_URL");
  const aid = required("AGENT_AID");
  const credentialId = required("AGENT_CREDENTIAL_ID");
  const recipient = required("AGENT_RECIPIENT");

  console.log("=== Agent Runtime Direct API Example ===");
  console.log("baseUrl:", baseUrl);
  console.log("aid:", aid);
  console.log("credentialId:", credentialId);

  const { signing, source, keystorePath } = await loadOrActivateCredential({
    baseUrl,
    aid,
    credentialId,
    enrollmentSecret: process.env.AGENT_ENROLLMENT_SECRET,
    passphrase: process.env.AGENT_KEYSTORE_PASSPHRASE,
    keystoreDir: process.env.AGENT_KEYSTORE_DIR,
  });
  console.log(`keystore: ${source} (${keystorePath})`);

  const { client, tokens } = await createAuthenticatedApiClient({
    baseUrl,
    aid,
    credentialId,
    signingPrivateKey: signing.privateKey,
  });
  console.log("token_type:", tokens.token_type);
  console.log("scope:", tokens.scope);

  const me = await client.resolveRecipient(aid);
  console.log("self:", me);
  const resolved = await client.resolveRecipient(recipient);
  console.log("recipient:", resolved);

  const sendResult = await client.sendTextMessage({
    senderDid: me.did,
    recipientDid: resolved.did,
    recipientEncryptionPublicKey: resolved.encryption_public_key ?? "",
    senderSigningPrivateKey: signing.privateKey,
    subject: "NexusInbox SDK example",
    body: "Hello from templates/agent-runtime-node/direct-api.mjs",
  });
  console.log("send:", sendResult);

  const inbox = await client.listMessages({ agentDid: aid, folder: "inbox", status: "all" });
  console.log("inbox total:", inbox.total);
  if (inbox.messages[0]) {
    const content = await client.readMessage(inbox.messages[0].id);
    console.log("latest message:", {
      id: inbox.messages[0].id,
      sender_did: content.sender_did,
      recipient_did: content.recipient_did,
      subject_encrypted: content.subject_encrypted,
    });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
