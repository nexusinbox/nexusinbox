// The own root behind confirmation numbers (docs/40 §16.2) comes from this
// browser, never from the server alone.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { keys } = vi.hoisted(() => ({ keys: new Set<string>() }));
vi.mock("../crypto/signing-keyring", () => ({
  getSigningPrivateKey: async (did: string) => (keys.has(did) ? ({} as CryptoKey) : null),
  hasSigningPrivateKeyMaterial: async (did: string) => keys.has(did),
}));

import { rememberOwnRoot, savePin } from "./peer-pins";
import { ownRootHere } from "./device-list";

const AID = "aid:ai:own";
const agent = (did: string, dids: string[] = []) => ({ aid: AID, did, dids, devices: [] });

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
  it("takes the server's DID only when this browser holds that key", async () => {
    keys.add("did:key:zMine");
    expect(await ownRootHere(agent("did:key:zMine"))).toBe("did:key:zMine");
    expect(await ownRootHere(agent("did:key:zSomeoneElse"))).toBeNull();
  });

  it("uses the root recorded when this browser joined, whatever the server names", async () => {
    rememberOwnRoot(AID, "did:key:zJoinedRoot");
    expect(await ownRootHere(agent("did:key:zServerSays"))).toBe("did:key:zJoinedRoot");
  });

  it("never takes another agent's pin as the own root", async () => {
    // The server names another person's aid as ours; this browser has a pin
    // for that aid but no key of the agent.
    savePin(AID, { root: "did:key:zTheirRoot", version: 3 });
    expect(await ownRootHere(agent("did:key:zServerSays", ["did:key:zServerSays"]))).toBeNull();
  });

  it("never takes a pin as the own root, even while holding a device key the server lists", async () => {
    // The server lists this browser's device under another aid it has a pin for.
    keys.add("did:key:zThisBrowser");
    savePin(AID, { root: "did:key:zTheirRoot", version: 2 });
    expect(await ownRootHere(agent("did:key:zServerSays", ["did:key:zThisBrowser"]))).toBeNull();
  });
});
