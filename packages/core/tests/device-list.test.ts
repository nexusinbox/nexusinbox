import { describe, expect, it } from "vitest";
import { createEd25519KeyPair, deriveDidKeyFromPublicKey } from "../src/index";
import {
  deviceListVersion,
  didKeyFromEd25519,
  ed25519KeyFromDidKey,
  listSigners,
  readDeviceList,
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
    // And makes the same did:key from the raw key, without the Node-only index.
    expect(didKeyFromEd25519(raw)).toBe(did);
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

describe("lists with a second signer (docs/40 §17.3)", () => {
  async function v2(signers: (root: string, phone: string) => string[], kind: "browser" | "computer" = "browser") {
    const r = await root();
    const phone = await root();
    const list: DeviceListPayload = {
      v: 2,
      aid: "aid:ai:one",
      root: r.did,
      version: 2,
      issued_at: "2026-11-14T10:00:00Z",
      devices: [
        { did: r.did, enc: "ROOT_ENC", kind: "browser" },
        { did: phone.did, enc: "PHONE_ENC", kind },
      ],
      signers: signers(r.did, phone.did),
    };
    return { r, phone, list };
  }

  it("reads a v2 list signed by a signer it names, and who may sign the next one", async () => {
    const { r, phone, list } = await v2((root, p) => [root, p]);
    const jws = await signDeviceList(phone.pair.privateKey, list, phone.did);
    const read = await readDeviceList(jws, "aid:ai:one");
    expect(read).toEqual({ list, signer: phone.did });
    expect(listSigners(read!.list)).toEqual([r.did, phone.did]);
    // Signed by the phone: not the root alone, but a signer the caller trusts.
    expect(await verifyDeviceList(jws, { aid: "aid:ai:one", root: r.did })).toBeNull();
    expect(await verifyDeviceList(jws, { aid: "aid:ai:one", root: r.did, signers: [phone.did] })).toEqual(list);
  });

  it("refuses signers that are not browsers on the list, or named twice, or none", async () => {
    for (const bad of [
      await v2((_r, p) => [p], "computer"),
      await v2(() => ["did:key:z6MkNotOnTheList"]),
      await v2((root) => [root, root]),
      await v2(() => []),
    ]) {
      const jws = await signDeviceList(bad.r.pair.privateKey, bad.list);
      expect(await readDeviceList(jws, "aid:ai:one")).toBeNull();
    }
  });

  it("refuses a v1 list signed by anyone but its root, and signers on a v1 list", async () => {
    const r = await root();
    const other = await root();
    const list = payload("aid:ai:one", r.did);
    expect(await readDeviceList(await signDeviceList(other.pair.privateKey, list, other.did), "aid:ai:one")).toBeNull();
    const withSigners = { ...list, signers: [r.did] };
    expect(await readDeviceList(await signDeviceList(r.pair.privateKey, withSigners), "aid:ai:one")).toBeNull();
  });
});

describe("whom senders wrap for (docs/40 §12.3)", () => {
  it("matches the shared vectors", async () => {
    const { readFileSync } = await import("node:fs");
    const { decideWrapTargets, pinAfter } = await import("../src/device-list");
    const vectors = JSON.parse(
      readFileSync(new URL("../../../tests/vectors/device_list_decisions.json", import.meta.url), "utf8"),
    );
    expect(vectors.cases.length).toBeGreaterThan(10);
    for (const c of vectors.cases) {
      const decision = await decideWrapTargets({
        served: c.served,
        requested: c.requested,
        knownAid: c.knownAid,
        pin: c.pin,
        acceptRoot: c.acceptRoot,
        history:
          c.history === undefined
            ? undefined
            : async (_aid: string, after: number) =>
                c.history ? c.history.filter((h: { version: number }) => h.version > after) : null,
      });
      const got =
        decision.kind === "stop"
          ? { kind: "stop", reason: decision.reason, ...(decision.root ? { root: decision.root } : {}) }
          : {
              kind: decision.kind,
              targets: decision.targets,
              single: decision.single,
              ...(decision.kind === "listed" ? { pin: pinAfter(c.pin, decision) } : {}),
            };
      expect(got, c.name).toEqual(c.expect);
    }
  });
});
