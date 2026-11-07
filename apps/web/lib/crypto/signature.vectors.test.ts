import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { signEnvelopePayload } from "./signature";

// Shared vector (tests/vectors/envelope_signing.json): the web signs exactly
// the bytes the signer daemon signs and the API verifies (docs/29 §2.4).
type Vector = {
  signing_seed_hex: string;
  fields: {
    sender_did: string;
    recipient_did: string;
    subject_encrypted: string;
    encrypted_content: string;
    encrypted_key: string;
    nonce: string;
  };
  signature_b64url: string;
};

const vector = JSON.parse(
  readFileSync(new URL("../../../../tests/vectors/envelope_signing.json", import.meta.url), "utf8"),
) as Vector;

function hexToBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

describe("envelope signing vector", () => {
  it("produces the same signature as the signer daemon and the API", async () => {
    // PKCS#8 wrapper for a raw 32-byte Ed25519 seed.
    const pkcs8 = new Uint8Array([
      ...hexToBytes("302e020100300506032b657004220420"),
      ...hexToBytes(vector.signing_seed_hex),
    ]);
    const signingPrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    const signature = await signEnvelopePayload({
      signingPrivateKey,
      senderDid: vector.fields.sender_did,
      recipientDid: vector.fields.recipient_did,
      subjectEncrypted: vector.fields.subject_encrypted,
      encryptedContent: vector.fields.encrypted_content,
      encryptedKey: vector.fields.encrypted_key,
      nonce: vector.fields.nonce,
    });
    expect(signature).toBe(vector.signature_b64url);
  });
});
