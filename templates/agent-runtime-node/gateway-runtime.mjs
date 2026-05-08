import {
  NexusInboxGatewayClient,
  buildEncryptedTextEnvelope,
  createEd25519KeyPair,
} from "../../packages/core/dist/index.js";

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env: ${name}`);
  }
  return value;
}

async function main() {
  const socketPath = process.env.AGENT_INBOX_GATEWAY_SOCKET || "/tmp/nexusinbox-gateway.sock";

  console.log("=== Agent Runtime Gateway Example ===");
  console.log("socket:", socketPath);

  const gateway = new NexusInboxGatewayClient({ socketPath });
  const me = await gateway.whoami();
  console.log("whoami:", me);

  const inbox = await gateway.listInbox({ folder: "inbox", status: "all" });
  console.log("inbox total:", inbox.total);

  const selfRecipient = await gateway.resolveRecipient(me.aid);
  console.log("resolve self:", selfRecipient);

  const signing = await createEd25519KeyPair();
  const envelope = await buildEncryptedTextEnvelope({
    senderDid: me.did,
    recipientDid: selfRecipient.did,
    recipientEncryptionPublicKey: selfRecipient.encryption_public_key ?? "",
    senderSigningPrivateKey: signing.privateKey,
    subject: "Gateway example subject",
    body: "Hello from templates/agent-runtime-node/gateway-runtime.mjs",
  });
  delete envelope.signature;

  const send = await gateway.sendMessage({
    recipientDid: me.aid,
    envelope,
  });
  console.log("send:", send);

  const updatedInbox = await gateway.listInbox({ folder: "inbox", status: "all" });
  const latest = updatedInbox.messages[0];
  if (latest) {
    const content = await gateway.readMessage(latest.id);
    console.log("latest message:", {
      id: latest.id,
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
