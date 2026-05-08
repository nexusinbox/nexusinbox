// KDF round-trip tests for the MCP keystore. These exercise the
// Argon2id write path that P2 #10 introduces plus the legacy
// PBKDF2-SHA256 read path kept for backwards compatibility.
//
// We test at the primitive layer (derive -> AES-GCM encrypt ->
// AES-GCM decrypt) rather than through `loadOrActivateCredential`
// because the higher-level flow hits the activation API, which
// would force the tests to stub HTTP. The KDF + AES-GCM round-trip
// is the only thing this fix actually changes.

import { describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import {
  _deriveKekArgon2id_testOnly,
  _deriveKekPbkdf2_testOnly,
} from "../src/keystore.js";

const subtle = webcrypto.subtle;

function randomSalt(): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(16));
}

function randomIv(): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(12));
}

async function roundTrip(kek: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = randomIv();
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, kek, plaintext));
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, kek, ct));
}

describe("keystore KDF round-trip", () => {
  const passphrase = "correct-horse-battery-staple";
  const plaintext = new TextEncoder().encode("signing-privkey-bytes");

  it("Argon2id: derived KEK round-trips AES-GCM encrypt/decrypt", async () => {
    // Faster params so tests finish quickly — production uses
    // 64 MiB / 3 iterations; this uses 1 MiB / 1 iteration, which
    // is still a valid Argon2id instance exercising the same code
    // path.
    const params = { memory_cost_kib: 1024, time_cost: 1, parallelism: 1 };
    const salt = randomSalt();
    const kek = await _deriveKekArgon2id_testOnly(passphrase, salt, params);
    const decrypted = await roundTrip(kek, plaintext);
    expect(new TextDecoder().decode(decrypted)).toBe("signing-privkey-bytes");
  });

  it("Argon2id: wrong passphrase yields a different KEK (decrypt fails)", async () => {
    const params = { memory_cost_kib: 1024, time_cost: 1, parallelism: 1 };
    const salt = randomSalt();
    const goodKek = await _deriveKekArgon2id_testOnly(passphrase, salt, params);
    const badKek = await _deriveKekArgon2id_testOnly("wrong-passphrase", salt, params);

    const iv = randomIv();
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, goodKek, plaintext);
    await expect(
      subtle.decrypt({ name: "AES-GCM", iv }, badKek, ct),
    ).rejects.toThrow();
  });

  it("PBKDF2 legacy path still decrypts records written by the pre-P2-#10 server", async () => {
    // Represent a keystore file that was produced by the old
    // PBKDF2-SHA256 path (what the MCP server used to write).
    // The new server must still open it — users shouldn't have to
    // re-activate just because the server upgraded its KDF.
    const salt = randomSalt();
    const iterations = 10_000; // fast for tests; the real default is 600_000
    const kek = await _deriveKekPbkdf2_testOnly(passphrase, salt, iterations);
    const decrypted = await roundTrip(kek, plaintext);
    expect(new TextDecoder().decode(decrypted)).toBe("signing-privkey-bytes");
  });

  it("PBKDF2 legacy path with wrong passphrase fails cleanly", async () => {
    const salt = randomSalt();
    const goodKek = await _deriveKekPbkdf2_testOnly(passphrase, salt, 10_000);
    const badKek = await _deriveKekPbkdf2_testOnly("wrong-passphrase", salt, 10_000);

    const iv = randomIv();
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, goodKek, plaintext);
    await expect(
      subtle.decrypt({ name: "AES-GCM", iv }, badKek, ct),
    ).rejects.toThrow();
  });

  it("Argon2id and PBKDF2 produce distinct KEKs for the same passphrase + salt", async () => {
    // Sanity check — makes sure the legacy read path doesn't
    // accidentally treat an argon2id record as pbkdf2 or vice
    // versa. The ciphertext written with one KDF must not decrypt
    // with the other.
    const salt = randomSalt();
    const argonKek = await _deriveKekArgon2id_testOnly(passphrase, salt, {
      memory_cost_kib: 1024,
      time_cost: 1,
      parallelism: 1,
    });
    const pbkdfKek = await _deriveKekPbkdf2_testOnly(passphrase, salt, 10_000);

    const iv = randomIv();
    const ctViaArgon = await subtle.encrypt({ name: "AES-GCM", iv }, argonKek, plaintext);
    await expect(
      subtle.decrypt({ name: "AES-GCM", iv }, pbkdfKek, ctViaArgon),
    ).rejects.toThrow();
  });
});
