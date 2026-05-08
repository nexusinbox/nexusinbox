/**
 * Direct API reply flow — persisted keystore edition.
 *
 * Sibling to `direct-api.mjs`. Demonstrates the recipient side: pick up
 * an incoming message and reply through the same E2E path, reusing a
 * credential that was activated once and cached to disk.
 *
 * Env vars:
 *   AGENT_INBOX_BASE_URL       required
 *   AGENT_AID                  required — *this* agent's aid (replier)
 *   AGENT_CREDENTIAL_ID        required
 *   AGENT_ENROLLMENT_SECRET    only on first run
 *   AGENT_INCOMING_ID          optional — specific message to reply to
 *   AGENT_KEYSTORE_PASSPHRASE  optional
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
  const specificMessageId = process.env.AGENT_INCOMING_ID ?? null;

  console.log("=== Agent Runtime Direct API Reply Example ===");
  console.log("baseUrl:     ", baseUrl);
  console.log("replier aid: ", aid);
  console.log("credential:  ", credentialId);
  if (specificMessageId) {
    console.log("target msg:  ", specificMessageId);
  } else {
    console.log("target msg:  (newest inbox entry)");
  }

  // Step 1: load or activate the replier's credential.
  const { signing, source, keystorePath } = await loadOrActivateCredential({
    baseUrl,
    aid,
    credentialId,
    enrollmentSecret: process.env.AGENT_ENROLLMENT_SECRET,
    passphrase: process.env.AGENT_KEYSTORE_PASSPHRASE,
    keystoreDir: process.env.AGENT_KEYSTORE_DIR,
  });
  console.log(`keystore:    ${source} (${keystorePath})`);

  // Step 2: token.
  const { client, tokens } = await createAuthenticatedApiClient({
    baseUrl,
    aid,
    credentialId,
    signingPrivateKey: signing.privateKey,
  });
  console.log("token:       ", tokens.token_type, "(", tokens.scope, ")");

  // Step 3: list inbox.
  const inbox = await client.listMessages({
    agentDid: aid,
    folder: "inbox",
    status: "all",
  });
  console.log("\ninbox total:", inbox.total);
  if (inbox.total === 0) {
    console.error("Inbox is empty — nothing to reply to.");
    process.exit(1);
  }

  const target = specificMessageId
    ? inbox.messages.find((m) => m.id === specificMessageId)
    : inbox.messages[0];
  if (!target) {
    console.error(
      specificMessageId
        ? `message_id ${specificMessageId} not found in inbox`
        : "couldn't pick a message to reply to",
    );
    process.exit(1);
  }
  console.log("replying to: ", target.id);
  console.log("  from:", target.sender_did);

  // Step 4: fetch the encrypted body so we know the thread_id to keep
  // the reply in the same conversation.
  const content = await client.readMessage(target.id);
  const threadId = content.thread_id ?? target.thread_id ?? null;
  console.log("  thread_id:", threadId ?? "(none; starting new thread)");

  // Step 5: resolve the ORIGINAL sender by their stable aid if we have
  // it, falling back to the did we received. Resolving via aid survives
  // any key rotation the sender may have done since they sent us the
  // message.
  const senderReference = target.sender_did; // may be aid:ai:... or did:key:...
  const me = await client.resolveRecipient(aid);
  const sendBackTo = await client.resolveRecipient(senderReference);
  console.log(
    "  send back to:",
    sendBackTo.did,
    `[${sendBackTo.label ?? "unnamed"}]`,
  );

  // Step 6: send the reply in the same thread.
  const sendResult = await client.sendTextMessage({
    senderDid: me.did,
    recipientDid: sendBackTo.did,
    recipientEncryptionPublicKey: sendBackTo.encryption_public_key ?? "",
    senderSigningPrivateKey: signing.privateKey,
    subject: "Re: NexusInbox SDK example",
    body:
      "Reply sent from templates/agent-runtime-node/direct-api-reply.mjs. " +
      `In reply to message_id ${target.id}.`,
    threadId: threadId ?? undefined,
  });
  console.log("\nsend:", sendResult);
  console.log("\n✓ 返信送信完了 (message_id:", sendResult.message_id, ")");
  if (threadId) {
    console.log("  thread:", threadId, "(kept in same conversation)");
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
