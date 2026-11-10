/**
 * Multi-device delivery (docs/38): the content key is wrapped for every
 * device of the recipient agent and of the sending agent, and each device
 * finds its own wrap with `contentKeyWrapsFor`.
 */

import { describe, expect, it } from "vitest";
import {
  buildEncryptedTextEnvelope,
  contentKeyWrapsFor,
  createEd25519KeyPair,
  createX25519KeyPair,
  exportRawPublicKeyBase64Url,
  type MessageContentResponse,
} from "@nexusinbox/core";
import { decryptEnvelopeTextForRecipient } from "../src/decrypt.js";

async function device(did: string) {
  const keys = await createX25519KeyPair();
  return { did, keys, encryption_public_key: await exportRawPublicKeyBase64Url(keys.publicKey) };
}

async function openAs(content: MessageContentResponse, did: string, privateKey: CryptoKey) {
  for (const encryptedKey of contentKeyWrapsFor(content, did)) {
    try {
      return await decryptEnvelopeTextForRecipient({
        encrypted_content: content.encrypted_content,
        encrypted_key: encryptedKey,
        nonce: content.nonce,
        subject_encrypted: content.subject_encrypted ?? "",
        recipientPrivateKey: privateKey,
      });
    } catch {
      // try the next wrap
    }
  }
  return null;
}

describe("content key wrapped for every device", () => {
  it("lets every device of both agents open the message", async () => {
    const signing = await createEd25519KeyPair();
    const bobPc = await device("did:key:zBobPc");
    const bobBrowser = await device("did:key:zBobBrowser");
    const aliceBrowser = await device("did:key:zAliceBrowser");
    const alicePc = await device("did:key:zAlicePc");

    const envelope = await buildEncryptedTextEnvelope({
      senderDid: alicePc.did,
      recipientDid: bobPc.did,
      recipientEncryptionPublicKey: bobPc.encryption_public_key,
      senderEncryptionPublicKey: alicePc.encryption_public_key,
      recipientDevices: [bobPc, bobBrowser],
      senderDevices: [alicePc, aliceBrowser],
      senderSigningPrivateKey: signing.privateKey,
      subject: "hello",
      body: "world",
    });

    expect(envelope.encrypted_keys?.map((w) => w.did)).toEqual([bobPc.did, bobBrowser.did]);
    expect(envelope.sender_encrypted_keys?.map((w) => w.did)).toEqual([alicePc.did, aliceBrowser.did]);

    const content: MessageContentResponse = {
      ...envelope,
      sender_did: alicePc.did,
      recipient_did: bobPc.did,
      subject_encrypted: envelope.metadata.subject_encrypted,
    };
    for (const d of [bobPc, bobBrowser, alicePc, aliceBrowser]) {
      expect(await openAs(content, d.did, d.keys.privateKey)).toEqual({ subject: "hello", body: "world" });
    }

    // A device not on either list cannot open it.
    const stranger = await device("did:key:zStranger");
    expect(await openAs(content, stranger.did, stranger.keys.privateKey)).toBeNull();
  });

  it("falls back to the single wraps of older messages", () => {
    const content: MessageContentResponse = {
      encrypted_content: "c",
      encrypted_key: "x25519v1:recipient",
      sender_encrypted_key: "x25519v1:sender",
      nonce: "n",
      sender_did: "did:key:zMe",
      recipient_did: "did:key:zThem",
    };
    expect(contentKeyWrapsFor(content, "did:key:zMe")).toEqual(["x25519v1:sender", "x25519v1:recipient"]);
    expect(contentKeyWrapsFor(content, "did:key:zThem")).toEqual(["x25519v1:recipient"]);
  });
});
