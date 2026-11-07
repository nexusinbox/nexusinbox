import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { unwrapContentKeyWithRecipientPrivateKey } from "./keywrap";

// Shared vector (tests/vectors/x25519_wrap.json): keys wrapped by the web
// and by the signer daemon both unwrap here, so a reply the Agent Gateway
// sends is readable in the browser (docs/29 §4).
type Vector = {
  recipient_private_key_b64url: string;
  content_key: string;
  wrapped_keys: Record<string, string>;
};

const vector = JSON.parse(
  readFileSync(new URL("../../../../tests/vectors/x25519_wrap.json", import.meta.url), "utf8"),
) as Vector;

function fromBase64Url(text: string): number[] {
  return Array.from(Buffer.from(text, "base64url"));
}

describe("x25519 wrap vector", () => {
  it.each(Object.entries(vector.wrapped_keys))("unwraps the key wrapped by %s", async (_, wrapped) => {
    // PKCS#8 wrapper for a raw 32-byte X25519 private key.
    const pkcs8 = new Uint8Array([
      ...Buffer.from("302e020100300506032b656e04220420", "hex"),
      ...fromBase64Url(vector.recipient_private_key_b64url),
    ]);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, false, [
      "deriveBits",
    ]);
    await expect(unwrapContentKeyWithRecipientPrivateKey(wrapped, privateKey)).resolves.toBe(
      vector.content_key,
    );
  });
});
