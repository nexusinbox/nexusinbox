// The own root behind the confirmation number (docs/40 §16.2) comes from
// this browser, never from the server alone.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { keys } = vi.hoisted(() => ({ keys: new Set<string>() }));
vi.mock("../crypto/signing-keyring", () => ({
  getSigningPrivateKey: async (did: string) => (keys.has(did) ? ({} as CryptoKey) : null),
}));

import { savePin } from "./peer-pins";
import { ownRootHere } from "./device-list";

const AID = "aid:ai:own";

beforeEach(() => {
  keys.clear();
  const items = new Map<string, string>();
  vi.stubGlobal("window", {
    localStorage: {
      getItem: (k: string) => items.get(k) ?? null,
      setItem: (k: string, v: string) => void items.set(k, v),
      removeItem: (k: string) => void items.delete(k),
    },
  });
});
afterEach(() => vi.unstubAllGlobals());

describe("ownRootHere", () => {
  it("uses the pin this browser keeps, whatever the server names", async () => {
    savePin(AID, { root: "did:key:zPinned", version: 3 });
    expect(await ownRootHere({ aid: AID, did: "did:key:zServerSays" })).toBe("did:key:zPinned");
  });

  it("takes the server's DID only when this browser holds that key", async () => {
    keys.add("did:key:zMine");
    expect(await ownRootHere({ aid: AID, did: "did:key:zMine" })).toBe("did:key:zMine");
    expect(await ownRootHere({ aid: AID, did: "did:key:zSomeoneElse" })).toBeNull();
  });
});
