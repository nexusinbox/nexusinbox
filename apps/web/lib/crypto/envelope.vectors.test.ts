import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decryptEnvelopeTextWithContentKey } from "./envelope";

// Shared vector (tests/vectors/content_encryption.json): enc:v1 text made
// by the web and by the Agent Gateway both decrypts here, so an auto-reply
// the gateway sends is readable in the browser (docs/29 §4).
type Vector = {
  content_key: string;
  plaintext: string;
  ciphertexts: Record<string, string>;
};

const vector = JSON.parse(
  readFileSync(new URL("../../../../tests/vectors/content_encryption.json", import.meta.url), "utf8"),
) as Vector;

describe("enc:v1 content vector", () => {
  it.each(Object.entries(vector.ciphertexts))("decrypts the text encrypted by %s", async (_, serialized) => {
    await expect(decryptEnvelopeTextWithContentKey(serialized, vector.content_key)).resolves.toEqual({
      state: "readable",
      text: vector.plaintext,
    });
  });
});
