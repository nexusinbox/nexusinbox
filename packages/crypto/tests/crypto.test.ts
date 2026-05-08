import { describe, expect, it } from "vitest";
import {
  decryptText,
  encryptText,
  envelopeVersion,
  parseEncryptedPayload,
  serializeEncryptedPayload,
} from "../src/index";

describe("crypto", () => {
  it("returns current envelope version", () => {
    expect(envelopeVersion()).toBe(1);
  });

  it("encrypts and decrypts text round-trip", async () => {
    const plaintext = "hello agent inbox";
    const passphrase = "dev-passphrase";
    const encrypted = await encryptText(plaintext, passphrase);
    const decrypted = await decryptText(encrypted, passphrase);

    expect(decrypted).toBe(plaintext);
  });

  it("serializes and parses encrypted payload", async () => {
    const encrypted = await encryptText("payload", "dev-passphrase");
    const text = serializeEncryptedPayload(encrypted);
    const parsed = parseEncryptedPayload(text);

    expect(parsed).not.toBeNull();
    expect(parsed?.v).toBe(1);
    expect(parsed?.ct.length).toBeGreaterThan(0);
  });
});
