#!/usr/bin/env node
import crypto from "node:crypto";
import net from "node:net";

const SOCKET_PATH = process.env.AGENT_INBOX_GATEWAY_SOCKET || "/tmp/nexusinbox-gateway.sock";

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function wrappedKey() {
  return `x25519v1:${b64url(crypto.randomBytes(32))}:${b64url(crypto.randomBytes(16))}:${b64url(crypto.randomBytes(12))}:${b64url(crypto.randomBytes(48))}`;
}

async function callGateway(method, params = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(SOCKET_PATH);
    let buffer = "";

    socket.on("connect", () => {
      socket.write(`${JSON.stringify({ id: 1, method, params })}\n`);
    });

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex === -1) return;
      const line = buffer.slice(0, newlineIndex).trim();
      socket.end();
      try {
        const response = JSON.parse(line);
        if (response.error) {
          reject(new Error(`${response.error.message}`));
          return;
        }
        resolve(response.result);
      } catch (error) {
        reject(error);
      }
    });

    socket.on("error", reject);
  });
}

function findMessageId(result, expectedDid) {
  const messages = Array.isArray(result?.messages) ? result.messages : [];
  const selfMessage = messages.find((message) =>
    message.sender_did === expectedDid && message.recipient_did === expectedDid,
  );
  return selfMessage?.id || messages[0]?.id || null;
}

async function main() {
  console.log("=== Agent Gateway Flow Smoke Test ===");
  console.log(`socket: ${SOCKET_PATH}`);

  const whoami = await callGateway("whoami");
  console.log("whoami:", whoami);

  const recipient = await callGateway("resolve_recipient", { identifier: whoami.aid });
  console.log("resolve_recipient:", {
    aid: recipient.aid,
    did: recipient.did,
    encryption_public_key: recipient.encryption_public_key ? "<present>" : "<missing>",
  });

  const subjectEncrypted = b64url("Gateway self-test subject");
  const encryptedContent = b64url("Gateway self-test body");
  const nonce = b64url(crypto.randomBytes(16));

  const sendResult = await callGateway("send_message", {
    recipient_did: whoami.aid,
    envelope: {
      encrypted_content: encryptedContent,
      encrypted_key: wrappedKey(),
      nonce,
      metadata: {
        subject_encrypted: subjectEncrypted,
        content_type: "text/plain",
        has_attachments: false,
      },
    },
  });
  console.log("send_message:", sendResult);

  const inbox = await callGateway("list_inbox", { folder: "inbox", status: "all" });
  console.log("list_inbox total:", inbox.total);

  const messageId = findMessageId(inbox, whoami.did);
  if (!messageId) {
    throw new Error("sent message was not found in inbox listing");
  }

  const content = await callGateway("read_message", { message_id: messageId });
  console.log("read_message:", {
    message_id: messageId,
    sender_did: content.sender_did,
    recipient_did: content.recipient_did,
    subject_encrypted: content.subject_encrypted,
    encrypted_content_present: Boolean(content.encrypted_content),
  });

  console.log("\n✓ Gateway flow succeeded");
}

main().catch((error) => {
  console.error("\n✗ Gateway flow failed");
  console.error(error);
  process.exit(1);
});
