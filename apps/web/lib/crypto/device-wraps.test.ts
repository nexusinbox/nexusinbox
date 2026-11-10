// Multi-device delivery (docs/38): wrap the content key for every device,
// and each device finds its own wrap.

import { describe, expect, it, vi } from "vitest";

vi.mock("../api/client", () => ({ defaultApiClient: {} }));
vi.mock("./recipient-keyring", () => ({ hasRecipientPrivateKey: async () => false }));

import { wrapContentKeyForDevices } from "./device-wraps";
import { unwrapContentKeyWithRecipientPrivateKey } from "./keywrap";
import { wrapsForDid } from "./wrap-select";
import { candidateDids } from "../inbox/decrypt-message";
import type { MessageIndexEntry } from "../api/types";

function toBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function device(did: string) {
  const keys = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  return { did, keys, encryption_public_key: toBase64Url(raw) };
}

describe("content key wrapped for every device", () => {
  it("gives each device a wrap only its own key opens", async () => {
    const pc = await device("did:key:zPc");
    const browser = await device("did:key:zBrowser");
    const contentKey = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));

    const wraps = await wrapContentKeyForDevices(contentKey, [
      pc,
      browser,
      pc, // listed twice: wrapped once
      { did: "did:key:zBad", encryption_public_key: "not-a-key" }, // skipped
    ]);
    expect(wraps.map((w) => w.did)).toEqual([pc.did, browser.did]);

    for (const d of [pc, browser]) {
      const [mine] = wrapsForDid({ encrypted_keys: wraps }, d.did);
      expect(await unwrapContentKeyWithRecipientPrivateKey(mine, d.keys.privateKey)).toBe(contentKey);
    }
    await expect(
      unwrapContentKeyWithRecipientPrivateKey(wrapsForDid({ encrypted_keys: wraps }, pc.did)[0], browser.keys.privateKey),
    ).rejects.toThrow();
  });

  it("finds a device's wraps in either list", () => {
    const content = {
      encrypted_keys: [{ did: "did:key:zA", key: "x25519v1:a" }],
      sender_encrypted_keys: [{ did: "did:key:zB", key: "x25519v1:b" }],
    };
    expect(wrapsForDid(content, "did:key:zA")).toEqual(["x25519v1:a"]);
    expect(wrapsForDid(content, "did:key:zB")).toEqual(["x25519v1:b"]);
    expect(wrapsForDid({}, "did:key:zA")).toEqual([]);
  });

  it("lets a received message be tried with any of the agent's own devices", () => {
    const entry = { sender_did: "did:key:zThem", recipient_did: "did:key:zMyPc" } as MessageIndexEntry;
    expect(candidateDids(entry, false, ["did:key:zMyBrowser", "did:key:zMyPc"])).toEqual([
      "did:key:zMyPc",
      "did:key:zMyBrowser",
    ]);
  });
});
