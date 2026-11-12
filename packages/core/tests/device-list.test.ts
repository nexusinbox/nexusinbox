import { describe, expect, it } from "vitest";
import { createEd25519KeyPair, deriveDidKeyFromPublicKey } from "../src/index";
import {
  deviceListVersion,
  ed25519KeyFromDidKey,
  signDeviceList,
  verifyDeviceList,
  type DeviceListPayload,
} from "../src/device-list";

async function root() {
  const pair = await createEd25519KeyPair();
  return { pair, did: await deriveDidKeyFromPublicKey(pair.publicKey) };
}

function payload(aid: string, rootDid: string, version = 1): DeviceListPayload {
  return {
    v: 1,
    aid,
    root: rootDid,
    version,
    issued_at: "2026-11-12T10:00:00Z",
    devices: [
      { did: rootDid, enc: "ROOT_ENC", kind: "browser" },
      { did: "did:key:z6MkComputer", enc: "PC_ENC", kind: "computer" },
    ],
  };
}

const b64 = (text: string) =>
  btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

describe("device lists (docs/40 §4.2)", () => {
  it("reads the Ed25519 key back out of a did:key", async () => {
    const { pair, did } = await root();
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    expect(ed25519KeyFromDidKey(did)).toEqual(raw);
    expect(ed25519KeyFromDidKey("did:key:zNotBase58!")).toBeNull();
    expect(ed25519KeyFromDidKey("did:web:example.com")).toBeNull();
  });

  it("verifies a list the root signed", async () => {
    const { pair, did } = await root();
    const list = payload("aid:ai:one", did, 3);
    const jws = await signDeviceList(pair.privateKey, list);
    expect(await verifyDeviceList(jws, { aid: "aid:ai:one", root: did })).toEqual(list);
    expect(deviceListVersion(jws)).toBe(3);
  });

  it("refuses a list signed by another key, for another agent, or altered", async () => {
    const real = await root();
    const other = await root();
    const list = payload("aid:ai:one", real.did);

    // Signed by a different key while naming the real root.
    const forged = await signDeviceList(other.pair.privateKey, list);
    expect(await verifyDeviceList(forged, { aid: "aid:ai:one", root: real.did })).toBeNull();

    const jws = await signDeviceList(real.pair.privateKey, list);
    // Checked against another root or agent.
    expect(await verifyDeviceList(jws, { aid: "aid:ai:one", root: other.did })).toBeNull();
    expect(await verifyDeviceList(jws, { aid: "aid:ai:two", root: real.did })).toBeNull();

    // A device added after signing.
    const [h, , s] = jws.split(".");
    const added = {
      ...list,
      devices: [...list.devices, { did: "did:key:z6MkAttacker", enc: "X", kind: "computer" }],
    };
    expect(
      await verifyDeviceList(`${h}.${b64(JSON.stringify(added))}.${s}`, { aid: "aid:ai:one", root: real.did }),
    ).toBeNull();
  });

  it("refuses lists that are not well formed even when signed", async () => {
    const { pair, did } = await root();
    const expected = { aid: "aid:ai:one", root: did };
    const twice = payload("aid:ai:one", did);
    twice.devices.push({ ...twice.devices[0] });
    expect(await verifyDeviceList(await signDeviceList(pair.privateKey, twice), expected)).toBeNull();

    const empty = { ...payload("aid:ai:one", did), devices: [] };
    expect(await verifyDeviceList(await signDeviceList(pair.privateKey, empty), expected)).toBeNull();

    const extra = { ...payload("aid:ai:one", did), note: "x" } as unknown as DeviceListPayload;
    expect(await verifyDeviceList(await signDeviceList(pair.privateKey, extra), expected)).toBeNull();
  });
});
