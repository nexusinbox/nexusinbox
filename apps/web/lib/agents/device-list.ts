// Approving the devices that may read an agent (docs/40 stage 1). The
// agent's root key (the browser key it was created with) signs the list,
// or, once there is more than one, any browser the latest list names as a
// signer (docs/40 §17.3); the server stores it but cannot sign one. This
// browser remembers the highest version it has checked, so a server that
// serves an older list is noticed.

import {
  checkDeviceList as checkList,
  listSigners,
  pinFor,
  readDeviceList,
  signDeviceList,
  type DeviceListPayload,
} from "@nexusinbox/core/device-list";
import { defaultApiClient, deviceListHistory } from "../api/client";
import type { Agent, AgentDevice } from "../api/types";
import { getSigningPrivateKey } from "../crypto/signing-keyring";
import { localDeviceDid } from "./local-device";
import { loadPin, savePin } from "./peer-pins";

export type ListStatus =
  /** No list signed yet. */
  | { kind: "none" }
  | { kind: "ok"; list: DeviceListPayload }
  /** The list does not verify, or is older than one seen here. */
  | { kind: "broken"; reason: "signature" | "rollback" };

/** approved: in the list with the same key; pending: not in it; mismatch: in it with another key. */
export type Approval = "approved" | "pending" | "mismatch";

/** The newest version of the agent's list this browser has seen (0: none). */
export function loadSeenVersion(agent: Pick<Agent, "aid" | "did">): number {
  const pin = loadPin(agent.aid, agent.did);
  return pin && pin.root === agent.did ? pin.version : 0;
}

function saveSeen(agent: Pick<Agent, "aid" | "did">, list: DeviceListPayload): void {
  const pin = loadPin(agent.aid, agent.did);
  savePin(agent.aid, pinFor(pin && pin.root === agent.did ? pin : null, list));
}

/**
 * Check the agent's latest list against its root (`agents.did`) and what
 * this browser saw: signed by a signer it trusts, or followed from there
 * (docs/40 §17.3).
 */
export async function checkDeviceList(agent: Agent): Promise<ListStatus> {
  const pin = loadPin(agent.aid, agent.did);
  const seen = loadSeenVersion(agent);
  const ref = agent.device_list;
  if (!ref) return seen > 0 ? { kind: "broken", reason: "rollback" } : { kind: "none" };
  // The server now names another root for this agent than the one seen here.
  if (pin && pin.root !== agent.did) return { kind: "broken", reason: "signature" };
  const checked = await checkList({ aid: agent.aid, ref, pin, history: deviceListHistory });
  if (!checked.ok) return { kind: "broken", reason: checked.reason === "rollback" ? "rollback" : "signature" };
  if (checked.list.root !== agent.did) return { kind: "broken", reason: "signature" };
  saveSeen(agent, checked.list);
  return { kind: "ok", list: checked.list };
}

export function approvalOf(device: AgentDevice, status: ListStatus): Approval {
  if (status.kind !== "ok") return "pending";
  const entry = status.list.devices.find((d) => d.did === device.did);
  if (!entry) return "pending";
  return entry.enc === device.encryption_public_key ? "approved" : "mismatch";
}

/** The agent's devices whose key the list names differently. */
export function mismatchedDevices(agent: Agent, status: ListStatus): AgentDevice[] {
  return (agent.devices ?? []).filter((d) => approvalOf(d, status) === "mismatch");
}

/**
 * The next list: the agent's active devices in `dids`, one version above
 * both the server's latest and the highest this browser has seen (so a
 * list re-approved after a rollback is not itself older than one seen).
 * Every browser on it may sign the next one (docs/40 §17.4); with only the
 * root browser it stays v1, which computers before v0.8.0 read.
 */
export function nextDeviceList(
  agent: Agent,
  dids: Set<string>,
  now = new Date(),
  extra: AgentDevice[] = [],
): DeviceListPayload | null {
  const devices = [...(agent.devices ?? []), ...extra]
    .filter((d) => dids.has(d.did) && d.encryption_public_key)
    .map((d) => ({ did: d.did, enc: d.encryption_public_key as string, kind: d.kind }));
  if (devices.length === 0) return null;
  const signers = devices.filter((d) => d.kind === "browser").map((d) => d.did);
  const base = {
    aid: agent.aid,
    root: agent.did,
    version: Math.max(agent.device_list?.version ?? 0, loadSeenVersion(agent)) + 1,
    issued_at: now.toISOString(),
    devices,
  };
  if (signers.length === 1 && signers[0] === agent.did) return { v: 1, ...base };
  if (signers.length === 0) return null;
  return { v: 2, ...base, signers };
}

/**
 * Which devices stay approved when the person approves `add`: the ones
 * already approved, or, before any list exists, only the root browser.
 * Devices nobody approved are never carried over.
 */
export function approvedWith(agent: Agent, status: ListStatus, add: string[]): Set<string> {
  const base =
    status.kind === "ok"
      ? (agent.devices ?? []).filter((d) => approvalOf(d, status) === "approved").map((d) => d.did)
      : [agent.did];
  return new Set([...base, ...add]);
}

/**
 * This browser's device of the agent when it may sign the next list: a
 * signer of the latest list, or, before any, the root browser. Null when
 * it may not (docs/40 §17.3).
 */
export async function listSignerHere(agent: Pick<Agent, "aid" | "did" | "dids" | "device_list">): Promise<string | null> {
  const local = await localDeviceDid(agent);
  if (!local) return null;
  const ref = agent.device_list;
  const read = ref ? await readDeviceList(ref.jws, agent.aid) : null;
  const signers = read ? listSigners(read.list) : ref ? [] : [agent.did];
  return signers.includes(local) ? local : null;
}

/** All browsers that may sign the agent's latest list (the root alone before any). */
export async function listSignerDids(agent: Pick<Agent, "aid" | "did" | "device_list">): Promise<string[]> {
  const ref = agent.device_list;
  if (!ref) return [agent.did];
  const read = await readDeviceList(ref.jws, agent.aid);
  return read ? listSigners(read.list) : [];
}

/**
 * Sign, as this browser's device, and store a list of the agent's active
 * devices in `dids`, and of `extra` (a browser being added, which the
 * server makes active once the list names it). Changing who may sign
 * needs a recent World ID sign-in: the server then answers 403
 * `reauthentication_required`.
 */
export async function storeDeviceList(agent: Agent, dids: Set<string>, extra: AgentDevice[] = []): Promise<void> {
  const signer = await listSignerHere(agent);
  const key = signer ? await getSigningPrivateKey(signer) : null;
  if (!signer || !key) throw new Error("this browser cannot sign the agent's device list");
  const payload = nextDeviceList(agent, dids, new Date(), extra);
  if (!payload) throw new Error("no device to list");
  const jws = await signDeviceList(key, payload, signer);
  await defaultApiClient.putDeviceList(agent.id, jws);
  saveSeen(agent, payload);
}

/** Only the root browser itself: nothing to ask, so approve it quietly. */
export function onlyRootDevice(agent: Agent): boolean {
  const devices = agent.devices ?? [];
  return devices.length === 1 && devices[0].did === agent.did;
}
