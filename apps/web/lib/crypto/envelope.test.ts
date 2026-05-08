import { describe, expect, it } from "vitest";
import { decryptEnvelopeText, encryptEnvelopeText, generateContentKey, ENCRYPTED_PLACEHOLDER } from "./envelope";
import { generateX25519KeyPairMaterial, saveRecipientPrivateKey } from "./recipient-keyring";
import { wrapContentKeyForRecipient } from "./keywrap";

describe("envelope crypto", () => {
  it("produces different ciphertext for the same plaintext", async () => {
    const plain = "same message";
    const first = await encryptEnvelopeText(plain);
    const second = await encryptEnvelopeText(plain);

    expect(first.serialized).not.toBe(second.serialized);
  });

  it("does not rely on fixed dev passphrase marker or legacy key markers", async () => {
    const encrypted = await encryptEnvelopeText("payload");
    expect(encrypted.serialized.includes("nexusinbox-dev-passphrase")).toBe(false);
    expect(encrypted.serialized.includes(":ekb64:")).toBe(false);
    expect(encrypted.encryptedKey).toBe("");
  });

  it("returns placeholder when encrypted key is not provided", async () => {
    const encrypted = await encryptEnvelopeText("hidden");
    const decrypted = await decryptEnvelopeText(encrypted.serialized);
    expect(decrypted).toBe(ENCRYPTED_PLACEHOLDER);
  });

  it("can reuse one content key for subject and body", async () => {
    const contentKey = generateContentKey();
    const encryptedSubject = await encryptEnvelopeText("subject", { contentKey });
    const encryptedBody = await encryptEnvelopeText("body", { contentKey });
    const did = "did:key:recipient-2";
    const pair = await generateX25519KeyPairMaterial();
    saveRecipientPrivateKey(did, pair.privateKey);
    const wrapped = await wrapContentKeyForRecipient(contentKey, pair.publicKey);

    await expect(
      decryptEnvelopeText(encryptedSubject.serialized, wrapped.wrappedKey, did),
    ).resolves.toBe("subject");
    await expect(
      decryptEnvelopeText(encryptedBody.serialized, wrapped.wrappedKey, did),
    ).resolves.toBe("body");
  });

  it("rejects decrypt when recipient DID does not match wrapped key", async () => {
    const encrypted = await encryptEnvelopeText("for recipient-a", {
      contentKey: generateContentKey(),
    });
    const pair = await generateX25519KeyPairMaterial();
    const wrapped = await wrapContentKeyForRecipient(generateContentKey(), pair.publicKey);
    const decrypted = await decryptEnvelopeText(encrypted.serialized, wrapped.wrappedKey, "did:key:recipient-b");
    expect(decrypted).toBe(ENCRYPTED_PLACEHOLDER);
  });

  it("decrypts x25519 wrapped encrypted_key when private key is available", async () => {
    const did = "did:key:x25519-recipient";
    const pair = await generateX25519KeyPairMaterial();
    saveRecipientPrivateKey(did, pair.privateKey);

    const contentKey = generateContentKey();
    const encrypted = await encryptEnvelopeText("wrapped-body", { contentKey });
    const wrapped = await wrapContentKeyForRecipient(contentKey, pair.publicKey);

    await expect(decryptEnvelopeText(encrypted.serialized, wrapped.wrappedKey, did)).resolves.toBe("wrapped-body");
  });
});
