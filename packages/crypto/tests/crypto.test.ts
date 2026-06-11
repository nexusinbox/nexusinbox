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

  it("rejects out-of-band PBKDF2 iteration counts in attacker-supplied ciphertext", async () => {
    const encrypted = await encryptText("payload", "dev-passphrase");
    // Serialized form is enc:v1:kdf:alg:iter:salt:iv:ct — iter is index 4.
    const parts = serializeEncryptedPayload(encrypted).split(":");
    const withIter = (iter: string) => {
      const p = [...parts];
      p[4] = iter;
      return p.join(":");
    };

    // The honest writer's value (120k) parses fine.
    expect(parseEncryptedPayload(withIter("120000"))).not.toBeNull();
    // KDF-weakening (iter=1) and tab-locking DoS (iter=1e9) are rejected.
    expect(parseEncryptedPayload(withIter("1"))).toBeNull();
    expect(parseEncryptedPayload(withIter("1000000000"))).toBeNull();
    expect(parseEncryptedPayload(withIter("99999"))).toBeNull();
  });
});
