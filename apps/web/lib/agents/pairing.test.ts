// Connect code secrets (docs/40 §13.5): the browser approves a computer
// only when its keys match the code made here, and warns when they do not.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { keys, putPairingRoot, storeDeviceList } = vi.hoisted(() => ({
  keys: new Map<string, CryptoKey>(),
  putPairingRoot: vi.fn(),
  storeDeviceList: vi.fn(),
}));
vi.mock("../crypto/keystore", () => ({
  secureStoreKey: async (id: string, key: CryptoKey) => void keys.set(id, key),
  secureLoadKey: async (id: string) => keys.get(id) ?? null,
  secureDeleteKey: async (id: string) => void keys.delete(id),
}));
vi.mock("../api/client", () => ({ defaultApiClient: { putPairingRoot } }));
vi.mock("./device-list", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./device-list")>()),
  holdsRootKey: async () => true,
  checkDeviceList: async () => ({ kind: "none" }),
  storeDeviceList,
}));

import { pairingDeviceMac, pairingRootMac, splitPairingCode } from "@nexusinbox/core/pairing";
import type { Agent, AgentDevice } from "../api/types";
import { checkPairedDevices, pairedHere, pairingCodeWithSecret, pairingMismatch, settlePairing } from "./pairing";

function memoryStorage() {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
    get length() {
      return data.size;
    },
    key: (i: number) => [...data.keys()][i] ?? null,
    keys: () => [...data.keys()],
  };
}

const AID = "aid:ai:01PAIR";
const ROOT = "did:key:z6MkRoot";
const PC = "did:key:z6MkComputer";

function agentWith(device: Partial<AgentDevice>): Agent {
  return {
    id: "a1",
    aid: AID,
    did: ROOT,
    label: "秘書",
    devices: [
      { did: ROOT, encryption_public_key: "ENC_ROOT", kind: "browser", activated_at: "" },
      { did: PC, encryption_public_key: "ENC_PC", kind: "computer", activated_at: "", credential_id: "c1", ...device },
    ],
  } as Agent;
}

/** What the computer does with the code the browser showed. */
async function computerMac(code: string, enc = "ENC_PC"): Promise<string> {
  const { secret } = splitPairingCode(code)!;
  return pairingDeviceMac(secret!, "c1", PC, enc);
}

beforeEach(() => {
  const storage = memoryStorage();
  // Object.keys(localStorage) lists the stored keys in browsers.
  const proxy = new Proxy(storage, { ownKeys: () => storage.keys(), getOwnPropertyDescriptor: () => ({ enumerable: true, configurable: true }) });
  vi.stubGlobal("window", { localStorage: proxy });
  keys.clear();
  putPairingRoot.mockReset();
  storeDeviceList.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

describe("pairing (docs/40 §13.5)", () => {
  it("approves a computer whose keys match the code, and gives it the root", async () => {
    const code = (await pairingCodeWithSecret("c1", AID, "7KQ4P-ZX9M2"))!;
    expect(code).toMatch(/^7KQ4P-ZX9M2-\w{4}-\w{4}-\w{4}-\w{4}$/);
    const agent = agentWith({ pairing_mac: await computerMac(code) });
    expect(pairedHere(agent.devices![1])).toBe(true);

    const result = await settlePairing(agent);
    expect(result.matched.map((d) => d.did)).toEqual([PC]);
    expect(result.changed).toBe(true);
    expect([...storeDeviceList.mock.calls[0][1]]).toEqual([ROOT, PC]);
    const { secret } = splitPairingCode(code)!;
    expect(putPairingRoot).toHaveBeenCalledWith("c1", await pairingRootMac(secret!, "c1", AID, ROOT));
    // Done: the secret is gone.
    expect(keys.size).toBe(0);
    expect(pairedHere(agent.devices![1])).toBe(false);
  });

  it("keeps the secret when the root cannot be given yet", async () => {
    const code = (await pairingCodeWithSecret("c1", AID, "7KQ4P-ZX9M2"))!;
    putPairingRoot.mockRejectedValue(new Error("offline"));
    await settlePairing(agentWith({ pairing_mac: await computerMac(code) }));
    expect(keys.size).toBe(1);
  });

  it("warns, and never approves, when the server shows other keys", async () => {
    const code = (await pairingCodeWithSecret("c1", AID, "7KQ4P-ZX9M2"))!;
    const agent = agentWith({ encryption_public_key: "ENC_SWAPPED", pairing_mac: await computerMac(code) });
    const result = await settlePairing(agent);
    expect(result.mismatched.map((d) => d.did)).toEqual([PC]);
    expect(storeDeviceList).not.toHaveBeenCalled();
    expect(putPairingRoot).not.toHaveBeenCalled();
    expect(pairingMismatch(agent.devices![1])).toBe(true);
    // Still warned on the next look, with the secret dropped.
    expect(keys.size).toBe(0);
    expect((await checkPairedDevices(agent)).mismatched).toHaveLength(1);
  });

  it("treats a missing MAC as a mismatch", async () => {
    await pairingCodeWithSecret("c1", AID, "7KQ4P-ZX9M2");
    const result = await checkPairedDevices(agentWith({}));
    expect(result.mismatched).toHaveLength(1);
  });

  it("forgets the warning once the computer is removed", async () => {
    await pairingCodeWithSecret("c1", AID, "7KQ4P-ZX9M2");
    await checkPairedDevices(agentWith({}));
    const removed = { ...agentWith({}), devices: [agentWith({}).devices![0]] } as Agent;
    await checkPairedDevices(removed);
    expect(pairingMismatch(agentWith({}).devices![1])).toBe(false);
  });

  it("leaves computers connected with codes made elsewhere alone", async () => {
    const result = await settlePairing(agentWith({ pairing_mac: "x" }));
    expect(result).toMatchObject({ matched: [], mismatched: [], changed: false });
  });
});
