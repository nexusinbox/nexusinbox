import { describe, expect, it } from "vitest";
import {
  isValidX25519PublicKeyB64Url,
  unwrapContentKeyWithRecipientPrivateKey,
  wrapContentKeyForRecipient,
} from "./keywrap";

function toBase64Url(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

describe("x25519 keywrap", () => {
  it("validates x25519 public key format", async () => {
    const recipient = (await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const recipientPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey));
    const recipientPublicB64 = toBase64Url(recipientPublicRaw);

    expect(isValidX25519PublicKeyB64Url(recipientPublicB64)).toBe(true);
    expect(isValidX25519PublicKeyB64Url("not-base64url")).toBe(false);
    expect(isValidX25519PublicKeyB64Url("")).toBe(false);
  });

  it("wraps and unwraps content key with recipient keypair", async () => {
    const recipient = (await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const recipientPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey));
    const recipientPublicB64 = toBase64Url(recipientPublicRaw);
    const contentKey = "test-content-key-b64url";

    const wrapped = await wrapContentKeyForRecipient(contentKey, recipientPublicB64);
    const unwrapped = await unwrapContentKeyWithRecipientPrivateKey(wrapped.wrappedKey, recipient.privateKey);

    expect(wrapped.wrappedKey.startsWith("x25519v1:")).toBe(true);
    expect(unwrapped).toBe(contentKey);
  });

  it("fails to unwrap with a different private key", async () => {
    const recipient = (await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const otherRecipient = (await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const recipientPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey));
    const recipientPublicB64 = toBase64Url(recipientPublicRaw);

    const wrapped = await wrapContentKeyForRecipient("secret-content-key", recipientPublicB64);

    await expect(
      unwrapContentKeyWithRecipientPrivateKey(wrapped.wrappedKey, otherRecipient.privateKey),
    ).rejects.toBeTruthy();
  });
});
