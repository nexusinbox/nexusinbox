// Pairing MACs and connect-code splitting against the shared vectors
// (docs/40 §13.5), which the Rust daemon and gateway also pass.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  browserPairDeviceMac,
  browserPairFragment,
  browserPairRootMac,
  generatePairingSecret,
  importPairingKey,
  longPairingCode,
  macEqual,
  pairingDeviceMac,
  pairingRootMac,
  parseBrowserPairFragment,
  splitPairingCode,
} from "../src/pairing";

type Vectors = {
  macs: { secret: string; credential_id: string; did: string; enc: string; aid: string; root: string; device_mac: string; root_mac: string }[];
  codes: { input: string; code: string | null; secret: string | null }[];
};
const vectors = JSON.parse(
  readFileSync(join(__dirname, "../../../tests/vectors/pairing_mac.json"), "utf8"),
) as Vectors;

describe("pairing (docs/40 §13.5)", () => {
  it.each(vectors.macs)("MACs for $credential_id / $secret", async (c) => {
    expect(await pairingDeviceMac(c.secret, c.credential_id, c.did, c.enc)).toBe(c.device_mac);
    expect(await pairingRootMac(c.secret, c.credential_id, c.aid, c.root)).toBe(c.root_mac);
    // A stored, non-extractable key gives the same MACs.
    const key = await importPairingKey(c.secret);
    expect(key.extractable).toBe(false);
    expect(await pairingDeviceMac(key, c.credential_id, c.did, c.enc)).toBe(c.device_mac);
  });

  it.each(vectors.codes)("splits $input", (c) => {
    expect(splitPairingCode(c.input)).toEqual(c.code ? { code: c.code, secret: c.secret } : null);
  });

  it("builds a code that splits back", () => {
    const secret = generatePairingSecret();
    expect(secret).toMatch(/^[0-9A-HJKMNP-TV-Z]{16}$/);
    const typed = longPairingCode("7kq4p-zx9m2", secret);
    expect(typed).toMatch(/^7KQ4P-ZX9M2-\w{4}-\w{4}-\w{4}-\w{4}$/);
    expect(splitPairingCode(typed)).toEqual({ code: "7KQ4P-ZX9M2", secret });
  });

  it("compares MACs", () => {
    expect(macEqual("abc", "abc")).toBe(true);
    expect(macEqual("abc", "abd")).toBe(false);
    expect(macEqual("abc", "ab")).toBe(false);
  });
});

describe("a second browser (docs/40 §17.4)", () => {
  it("puts the code and the secret after # and reads them back", () => {
    const fragment = browserPairFragment("k7q2m-9xh4t", "8f3jv6wn2rcpzd4e");
    expect(fragment).toBe("K7Q2M9XH4T.8F3JV6WN2RCPZD4E");
    expect(parseBrowserPairFragment(`#${fragment}`)).toEqual({ code: "K7Q2M-9XH4T", secret: "8F3JV6WN2RCPZD4E" });
    // The 26-character code typed by hand reads the same.
    expect(parseBrowserPairFragment("K7Q2M-9XH4T-8F3J-V6WN-2RCP-ZD4E")).toEqual({
      code: "K7Q2M-9XH4T",
      secret: "8F3JV6WN2RCPZD4E",
    });
    // Without the secret there is nothing to check the keys with.
    expect(parseBrowserPairFragment("K7Q2M9XH4T")).toBeNull();
  });

  it("MACs bind the pairing, the agent and the key, apart from the computer's", async () => {
    const secret = "8F3JV6WN2RCPZD4E";
    const mac = await browserPairDeviceMac(secret, "p1", "aid:ai:a", "did:key:z1", "ENC");
    expect(await browserPairDeviceMac(secret, "p1", "aid:ai:a", "did:key:z1", "ENC")).toBe(mac);
    expect(await browserPairDeviceMac(secret, "p1", "aid:ai:b", "did:key:z1", "ENC")).not.toBe(mac);
    expect(await browserPairDeviceMac(secret, "p2", "aid:ai:a", "did:key:z1", "ENC")).not.toBe(mac);
    expect(await pairingDeviceMac(secret, "p1", "did:key:z1", "ENC")).not.toBe(mac);
    const root = await browserPairRootMac(secret, "p1", "aid:ai:a", "did:key:zRoot");
    expect(await pairingRootMac(secret, "p1", "aid:ai:a", "did:key:zRoot")).not.toBe(root);
  });
});
