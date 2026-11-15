// The device checks the inbox notices made (DeviceListNotice,
// NewDeviceNotice, StoppedComputerNotice), as Home items. Read only: what
// writes (settling a pairing, approving a lone browser, remembering the
// devices seen the first time) is in keepDevicesUpToDate.

import { approvedWith, checkDeviceList, listSignerHere, mismatchedDevices, onlyRootDevice, storeDeviceList } from "../agents/device-list";
import { checkPairedDevices, pairedHere, settlePairing } from "../agents/pairing";
import { loadSeenDevices, saveSeenDevices, stoppedComputers, unseenDevices } from "../agents/devices";
import type { QueryClient } from "@tanstack/react-query";
import { defaultApiClient } from "../api/client";
import { queryKeys } from "../api/hooks";
import type { Agent } from "../api/types";
import type { AttentionItem } from "./attention";

export async function collectDeviceAttention(agents: Agent[]): Promise<AttentionItem[]> {
  const out: AttentionItem[] = [];
  for (const agent of agents) {
    const devices = agent.devices ?? [];
    if (devices.length === 0) continue;
    const pairing = await checkPairedDevices(agent).catch(() => null);
    if (pairing && pairing.mismatched.length > 0) {
      out.push({ kind: "pairing_mismatch", agent, devices: pairing.mismatched });
    }
    const status = await checkDeviceList(agent);
    if (status.kind === "broken") {
      out.push({ kind: "list_wrong", agent, changed: [] });
    } else {
      const changed = mismatchedDevices(agent, status);
      if (changed.length > 0) {
        out.push({ kind: "list_wrong", agent, changed });
      } else if (status.kind === "none" && !onlyRootDevice(agent) && (await listSignerHere(agent)) !== null) {
        out.push({ kind: "list_undecided", agent });
      }
    }
    // A computer connected with a code made here is checked against the
    // code instead (above); a first look only remembers what is there.
    const seen = loadSeenDevices(agent.aid);
    if (seen !== null) {
      const added = unseenDevices(devices, seen).filter((d) => !pairedHere(d));
      if (added.length > 0) {
        out.push({ kind: "new_device", agent, devices: added, rootHere: (await listSignerHere(agent)) !== null });
      }
    }
  }
  return out;
}

/** Computers that stopped, most recently stopped first. */
export function stoppedAttention(agents: Agent[], now: number): AttentionItem[] {
  return [...stoppedComputers(agents, now)]
    .sort((a, b) => b.since - a.since)
    .map((s) => ({ kind: "computer_stopped" as const, ...s }));
}

/**
 * What the inbox notices did on their own: settle computers connected with
 * a code made here, approve this browser when it is the agent's only device,
 * and remember the devices of an agent seen here for the first time.
 * Returns whether the agents changed on the server.
 */
export async function keepDevicesUpToDate(agents: Agent[]): Promise<boolean> {
  let changed = false;
  for (const agent of agents) {
    const devices = agent.devices ?? [];
    if (devices.length === 0) continue;
    if (loadSeenDevices(agent.aid) === null) saveSeenDevices(agent.aid, devices);
    const paired = await settlePairing(agent).catch(() => null);
    if (paired?.changed) changed = true;
    if (!onlyRootDevice(agent)) continue;
    const status = await checkDeviceList(agent).catch(() => null);
    if (status?.kind !== "none" || (await listSignerHere(agent)) === null) continue;
    await storeDeviceList(agent, new Set([agent.did]))
      .then(() => {
        changed = true;
      })
      .catch(() => undefined);
  }
  return changed;
}

/** 「わたしがつないだ」: stop asking, and in the root browser approve them too. */
export async function acceptNewDevices(item: Extract<AttentionItem, { kind: "new_device" }>): Promise<boolean> {
  saveSeenDevices(item.agent.aid, item.agent.devices ?? []);
  if (!item.rootHere) return false;
  const status = await checkDeviceList(item.agent);
  if (status.kind === "broken") return false;
  await storeDeviceList(item.agent, approvedWith(item.agent, status, item.devices.map((d) => d.did)));
  return true;
}

/**
 * After the person connects a computer in this browser, record the agent's
 * device list as seen, so the computer they just added raises no notice,
 * and, in the browser the agent was created in, approve that computer
 * (the one whose credential was just activated) into the signed list.
 */
export async function acknowledgeDevicesAfterConnect(
  queryClient: QueryClient,
  aid: string,
  credentialId?: string,
): Promise<"verified" | "mismatch" | null> {
  try {
    await queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
    const data = await queryClient.fetchQuery({
      queryKey: queryKeys.agents(),
      queryFn: () => defaultApiClient.listAgents(),
    });
    const agent = data.agents.find((a) => a.aid === aid);
    if (agent?.devices) saveSeenDevices(aid, agent.devices);
    const connected = agent?.devices?.find((d) => credentialId && d.credential_id === credentialId);
    // Connected with a code made here: approve only if its keys match.
    if (agent && connected && pairedHere(connected)) {
      const result = await settlePairing(agent);
      if (result.changed) await queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
      if (result.mismatched.some((d) => d.did === connected.did)) return "mismatch";
      if (result.matched.some((d) => d.did === connected.did)) return "verified";
    } else if (agent && connected && (await listSignerHere(agent)) !== null) {
      const status = await checkDeviceList(agent);
      if (status.kind !== "broken") {
        await storeDeviceList(agent, approvedWith(agent, status, [connected.did]));
        await queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
      }
    }
  } catch {
    // The notice may show once; the person can approve from there.
  }
  return null;
}
