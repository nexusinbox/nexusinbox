// Senders check the recipient's device list (docs/40 §12): the root this
// browser or the person's contact remembers, and the sender's own list.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { resolveRecipient, updateContact, sealForSave, deviceListHistory } = vi.hoisted(() => ({
  resolveRecipient: vi.fn(),
  updateContact: vi.fn(),
  sealForSave: vi.fn(),
  deviceListHistory: vi.fn(),
}));
vi.mock("../api/client", () => ({ defaultApiClient: { resolveRecipient, updateContact }, deviceListHistory }));
vi.mock("../contacts/address-book", () => ({ loadAddressBook: async () => undefined, sealForSave }));
vi.mock("./recipient-keyring", () => ({ hasRecipientPrivateKey: async () => false }));

import { createEd25519KeyPair, deriveDidKeyFromPublicKey } from "@nexusinbox/core";
import { signDeviceList } from "@nexusinbox/core/device-list";
import { forgetContactRoots, loadPin, rememberContactRoots, savePin } from "../agents/peer-pins";
import type { ContactEntry, RecipientResolutionResponse } from "../api/types";
import { planSend, SendStop } from "./device-wraps";

function memoryStorage() {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
  };
}

async function agent(aid: string, version = 1, extra: string[] = []) {
  const pair = await createEd25519KeyPair();
  const did = await deriveDidKeyFromPublicKey(pair.publicKey);
  const jws = await signDeviceList(pair.privateKey, {
    v: 1,
    aid,
    root: did,
    version,
    issued_at: "2026-11-13T00:00:00Z",
    devices: [{ did, enc: `ENC_${aid}`, kind: "browser" }],
  });
  const served: RecipientResolutionResponse = {
    input: aid,
    aid,
    did,
    label: null,
    signing_public_key: "",
    encryption_public_key: `ENC_${aid}`,
    devices: [
      ...extra.map((d) => ({ did: d, encryption_public_key: "ENC_EXTRA" })),
      { did, encryption_public_key: `ENC_${aid}` },
    ],
    device_list: { version, jws },
  };
  return { did, served };
}

const PEER = "aid:ai:01PEER";
const ME = "aid:ai:01ME";

beforeEach(() => {
  vi.stubGlobal("window", { localStorage: memoryStorage(), addEventListener() {}, dispatchEvent() {} });
  forgetContactRoots();
  resolveRecipient.mockReset();
  updateContact.mockReset();
  sealForSave.mockReset();
  deviceListHistory.mockReset();
  deviceListHistory.mockResolvedValue(null);
});
afterEach(() => vi.unstubAllGlobals());

describe("planSend (docs/40 §12)", () => {
  it("wraps only for listed devices, remembers the root, and stops when it changes", async () => {
    const peer = await agent(PEER, 1, ["did:key:zAddedByServer"]);
    const me = await agent(ME);
    resolveRecipient.mockResolvedValue(me.served);

    const plan = await planSend(peer.served, PEER, me.did);
    expect(plan.recipientDevices.map((d) => d.did)).toEqual([peer.did]);
    expect(plan.recipient.did).toBe(peer.did);
    expect(plan.senderDevices.map((d) => d.did)).toEqual([me.did]);
    expect(plan.senderKey).toBe(`ENC_${ME}`);
    expect(loadPin(PEER)).toEqual({ root: peer.did, version: 1 });

    const swapped = await agent(PEER);
    const stop = await planSend(swapped.served, PEER, me.did).catch((e) => e);
    expect(stop).toBeInstanceOf(SendStop);
    expect(stop).toMatchObject({ reason: "root_changed", root: swapped.did });

    await planSend(swapped.served, PEER, me.did, { acceptRoot: swapped.did });
    expect(loadPin(PEER)).toEqual({ root: swapped.did, version: 1 });
  });

  it("stops on a root other than the one sealed in the contact", async () => {
    const peer = await agent(PEER);
    const contact: ContactEntry = {
      id: "c1",
      did: peer.did,
      person_name: "Alex",
      agent_label: null,
      note: null,
      aid: PEER,
      root: "did:key:z6MkSomeOtherRoot",
      readable: true,
      created_at: "",
      updated_at: "",
    };
    rememberContactRoots([contact]);
    resolveRecipient.mockRejectedValue(new Error("no sender"));
    await expect(planSend(peer.served, PEER, null)).rejects.toMatchObject({ reason: "root_changed" });
    expect(updateContact).not.toHaveBeenCalled();
  });

  it("stops on a root whose confirmation number did not match, and accepting clears it (docs/40 §16.2)", async () => {
    const peer = await agent(PEER);
    const contact: ContactEntry = {
      id: "c1",
      did: peer.did,
      person_name: "Alex",
      agent_label: null,
      note: null,
      aid: PEER,
      root: peer.did,
      verified: { root: "did:key:z6MkOlderRoot", at: "2026-11-01T00:00:00.000Z" },
      distrusted_root: peer.did,
      readable: true,
      created_at: "",
      updated_at: "",
    };
    rememberContactRoots([contact]);
    resolveRecipient.mockRejectedValue(new Error("no sender"));
    await expect(planSend(peer.served, PEER, null)).rejects.toMatchObject({ reason: "root_changed", root: peer.did });
    sealForSave.mockResolvedValue("cs1:sealed");
    await planSend(peer.served, PEER, null, { acceptRoot: peer.did });
    await vi.waitFor(() => expect(updateContact).toHaveBeenCalled());
    const saved = sealForSave.mock.calls.at(-1)![2];
    expect(saved.distrusted_root).toBeNull();
    // Checked before, and the person compared the new number: checked now.
    expect(saved.verified).toMatchObject({ root: peer.did });
  });

  it("seals a first-seen root into the contact", async () => {
    const peer = await agent(PEER);
    rememberContactRoots([
      {
        id: "c1",
        did: peer.did,
        person_name: "Alex",
        agent_label: null,
        note: null,
        aid: PEER,
        root: null,
        readable: true,
        created_at: "",
        updated_at: "",
      },
    ]);
    sealForSave.mockResolvedValue("cs1:sealed");
    await planSend(peer.served, PEER, null);
    await vi.waitFor(() => expect(updateContact).toHaveBeenCalledWith("c1", { sealed: "cs1:sealed" }));
    expect(sealForSave.mock.calls[0][2]).toMatchObject({ aid: PEER, root: peer.did });
  });

  it("keeps sending when the sender's own list is wrong, without its other devices", async () => {
    const peer = await agent(PEER);
    const me = await agent(ME);
    const other = await agent(ME);
    resolveRecipient.mockResolvedValue({ ...me.served, device_list: other.served.device_list });
    const plan = await planSend(peer.served, PEER, me.did);
    expect(plan.senderDevices).toEqual([]);
    expect(plan.senderKey).toBeUndefined();
  });

  it("stops when the server moves a DID to another agent, and allows a removed one", async () => {
    const peer = await agent(PEER, 1, ["did:key:zOldComputer"]);
    // First seen: the old computer's DID belongs to PEER.
    await planSend(peer.served, "did:key:zOldComputer", null);
    // Later the server answers that DID with another agent.
    const other = await agent("aid:ai:01OTHER");
    await expect(planSend(other.served, "did:key:zOldComputer", null)).rejects.toMatchObject({
      reason: "signature",
    });
    // The computer is gone from PEER: still PEER, sent to what is left.
    const plan = await planSend({ ...peer.served, devices: [peer.served.devices![1]] }, "did:key:zOldComputer", null);
    expect(plan.recipientDevices.map((d) => d.did)).toEqual([peer.did]);
  });

  it("follows a list a second signer signed from the version remembered (docs/40 §17.3)", async () => {
    const root = await createEd25519KeyPair();
    const rootDid = await deriveDidKeyFromPublicKey(root.publicKey);
    const phone = await createEd25519KeyPair();
    const phoneDid = await deriveDidKeyFromPublicKey(phone.publicKey);
    const rootDevice = { did: rootDid, enc: "ENC_ROOT", kind: "browser" as const };
    const phoneDevice = { did: phoneDid, enc: "ENC_PHONE", kind: "browser" as const };
    const at = "2026-11-14T00:00:00Z";
    const v1 = await signDeviceList(root.privateKey, {
      v: 1,
      aid: PEER,
      root: rootDid,
      version: 1,
      issued_at: at,
      devices: [rootDevice],
    });
    const v2 = await signDeviceList(root.privateKey, {
      v: 2,
      aid: PEER,
      root: rootDid,
      version: 2,
      issued_at: at,
      devices: [rootDevice, phoneDevice],
      signers: [rootDid, phoneDid],
    });
    // The phone removes the root browser.
    const v3 = await signDeviceList(
      phone.privateKey,
      { v: 2, aid: PEER, root: rootDid, version: 3, issued_at: at, devices: [phoneDevice], signers: [phoneDid] },
      phoneDid,
    );
    const served: RecipientResolutionResponse = {
      input: PEER,
      aid: PEER,
      did: phoneDid,
      label: null,
      signing_public_key: "",
      encryption_public_key: "ENC_PHONE",
      devices: [{ did: phoneDid, encryption_public_key: "ENC_PHONE" }],
      device_list: { version: 3, jws: v3 },
    };
    resolveRecipient.mockRejectedValue(new Error("no sender"));
    savePin(PEER, { root: rootDid, version: 1 });

    // Without the versions between, the send stops.
    await expect(planSend(served, PEER, null)).rejects.toMatchObject({ reason: "signature" });

    const versions = [
      { version: 1, jws: v1 },
      { version: 2, jws: v2 },
      { version: 3, jws: v3 },
    ];
    deviceListHistory.mockImplementation(async (_aid: string, after: number) =>
      versions.filter((r) => r.version > after),
    );
    const plan = await planSend(served, PEER, null);
    expect(plan.recipientDevices.map((d) => d.did)).toEqual([phoneDid]);
    expect(deviceListHistory).toHaveBeenLastCalledWith(PEER, 1);
    expect(loadPin(PEER)).toEqual({ root: rootDid, version: 3, signers: [phoneDid] });
  });

  it("stops for an agent with no list yet (docs/40 §15.2)", async () => {
    const peer = await agent(PEER);
    await expect(planSend({ ...peer.served, device_list: null }, PEER, null)).rejects.toMatchObject({
      reason: "no_list",
    });
  });
});
