import { describe, expect, it } from "vitest";
import { createEd25519KeyPair, deriveDidKeyFromPublicKey } from "@nexusinbox/core";
import { signDeviceList } from "@nexusinbox/core/device-list";
import type { Agent, AgentDevice } from "../api/types";
import { approvalOf, approvedWith, checkDeviceList, mismatchedDevices, nextDeviceList } from "./device-list";

const browser = (did: string): AgentDevice => ({
  did,
  encryption_public_key: "ROOT_ENC",
  kind: "browser",
  activated_at: "2026-11-08T00:00:00Z",
});
const computer = (did: string, enc = "PC_ENC"): AgentDevice => ({
  did,
  encryption_public_key: enc,
  kind: "computer",
  activated_at: "2026-11-10T00:00:00Z",
  credential_id: "cred-1",
});

async function agentWithList(devicesInList: AgentDevice[], devices: AgentDevice[], version = 1) {
  const pair = await createEd25519KeyPair();
  const did = await deriveDidKeyFromPublicKey(pair.publicKey);
  const list = devicesInList.map((d) => ({ ...d, did: d.did === "ROOT" ? did : d.did }));
  const agent: Agent = {
    id: "agent-1",
    aid: "aid:ai:one",
    did,
    label: "secretary",
    is_active: true,
    auto_reply: false,
    unread_count: 0,
    created_at: "2026-11-08T00:00:00Z",
    devices: devices.map((d) => ({ ...d, did: d.did === "ROOT" ? did : d.did })),
  };
  if (list.length > 0) {
    const jws = await signDeviceList(pair.privateKey, {
      v: 1,
      aid: agent.aid,
      root: did,
      version,
      issued_at: "2026-11-12T10:00:00Z",
      devices: list.map((d) => ({ did: d.did, enc: d.encryption_public_key as string, kind: d.kind })),
    });
    agent.device_list = { version, jws };
  }
  return { agent, pair };
}

describe("device list approval (docs/40 stage 1)", () => {
  it("reads approved, pending and changed keys off a signed list", async () => {
    const { agent } = await agentWithList(
      [browser("ROOT"), computer("did:key:zPC1")],
      [browser("ROOT"), computer("did:key:zPC1"), computer("did:key:zPC2")],
    );
    const status = await checkDeviceList(agent);
    expect(status.kind).toBe("ok");
    const [root, pc1, pc2] = agent.devices!;
    expect(approvalOf(root, status)).toBe("approved");
    expect(approvalOf(pc1, status)).toBe("approved");
    expect(approvalOf(pc2, status)).toBe("pending");

    // The server now returns another key for an approved computer.
    agent.devices![1] = { ...pc1, encryption_public_key: "SWAPPED" };
    expect(mismatchedDevices(agent, status).map((d) => d.did)).toEqual(["did:key:zPC1"]);
  });

  it("flags a list the root did not sign", async () => {
    const { agent } = await agentWithList([browser("ROOT")], [browser("ROOT")]);
    const other = await agentWithList([browser("ROOT")], [browser("ROOT")]);
    agent.device_list = other.agent.device_list;
    expect(await checkDeviceList(agent)).toEqual({ kind: "broken", reason: "signature" });
  });

  it("has nothing to check before the first list", async () => {
    const { agent } = await agentWithList([], [browser("ROOT")]);
    expect(await checkDeviceList(agent)).toEqual({ kind: "none" });
  });

  it("carries over only approved devices, or just the root before any list", async () => {
    const { agent } = await agentWithList(
      [browser("ROOT")],
      [browser("ROOT"), computer("did:key:zPC1"), computer("did:key:zPC2")],
      4,
    );
    const status = await checkDeviceList(agent);
    expect([...approvedWith(agent, status, ["did:key:zPC2"])].sort()).toEqual(
      [agent.did, "did:key:zPC2"].sort(),
    );
    expect([...approvedWith(agent, { kind: "none" }, ["did:key:zPC1"])].sort()).toEqual(
      [agent.did, "did:key:zPC1"].sort(),
    );

    const next = nextDeviceList(agent, new Set([agent.did, "did:key:zPC2"]), new Date("2026-11-12T00:00:00Z"));
    expect(next).toEqual({
      v: 1,
      aid: "aid:ai:one",
      root: agent.did,
      version: 5,
      issued_at: "2026-11-12T00:00:00.000Z",
      devices: [
        { did: agent.did, enc: "ROOT_ENC", kind: "browser" },
        { did: "did:key:zPC2", enc: "PC_ENC", kind: "computer" },
      ],
    });
    // Devices the server no longer lists are dropped.
    expect(nextDeviceList(agent, new Set(["did:key:zGone"]))).toBeNull();
  });
});
