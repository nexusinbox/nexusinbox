/**
 * The standard (SaaS) runtime passes its own X25519 public key when it
 * sends, so the envelope carries `sender_encrypted_key` (docs/35 §5).
 * Round-trip: the sender opens the message with its own private key via
 * the sender copy, and the recipient still opens it via `encrypted_key`.
 */

import { describe, expect, it } from "vitest";
import {
  buildA2AEnvelope,
  buildEncryptedTextEnvelope,
  createEd25519KeyPair,
  createX25519KeyPair,
  exportRawPublicKeyBase64Url,
} from "@nexusinbox/core";
import { decryptEnvelopeTextForRecipient } from "../src/decrypt.js";

describe("sender copy of the content key", () => {
  it("lets both the sender and the recipient open a text message", async () => {
    const signing = await createEd25519KeyPair();
    const sender = await createX25519KeyPair();
    const recipient = await createX25519KeyPair();

    const envelope = await buildEncryptedTextEnvelope({
      senderDid: "did:key:zSender",
      recipientDid: "did:key:zRecipient",
      recipientEncryptionPublicKey: await exportRawPublicKeyBase64Url(recipient.publicKey),
      senderEncryptionPublicKey: await exportRawPublicKeyBase64Url(sender.publicKey),
      senderSigningPrivateKey: signing.privateKey,
      subject: "hello",
      body: "world",
    });

    expect(envelope.sender_encrypted_key).toMatch(/^x25519v1:/);
    expect(envelope.sender_encrypted_key).not.toBe(envelope.encrypted_key);

    const common = {
      encrypted_content: envelope.encrypted_content,
      nonce: envelope.nonce,
      subject_encrypted: envelope.metadata.subject_encrypted,
    };
    const asSender = await decryptEnvelopeTextForRecipient({
      ...common,
      encrypted_key: envelope.sender_encrypted_key!,
      recipientPrivateKey: sender.privateKey,
    });
    const asRecipient = await decryptEnvelopeTextForRecipient({
      ...common,
      encrypted_key: envelope.encrypted_key,
      recipientPrivateKey: recipient.privateKey,
    });
    expect(asSender).toEqual({ subject: "hello", body: "world" });
    expect(asRecipient).toEqual({ subject: "hello", body: "world" });
  });

  it("adds no sender copy when the sender key is not given", async () => {
    const signing = await createEd25519KeyPair();
    const recipient = await createX25519KeyPair();
    const envelope = await buildA2AEnvelope({
      senderDid: "did:key:zSender",
      recipientDid: "did:key:zRecipient",
      recipientEncryptionPublicKey: await exportRawPublicKeyBase64Url(recipient.publicKey),
      senderSigningPrivateKey: signing.privateKey,
      subject: "hello",
      body: "world",
    });
    expect(envelope.sender_encrypted_key).toBeUndefined();
  });
});
