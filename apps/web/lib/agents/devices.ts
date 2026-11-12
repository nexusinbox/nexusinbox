// The devices that can read an agent's messages (docs/38 stage 4), and the
// notice when one appears that this browser has not seen. Which devices a
// browser has seen is kept in that browser only; the server stores nothing.

import type { AgentDevice } from "../api/types";
import { CONNECTED_WITHIN_MS, parseServerTime } from "./agent-status";

export type DeviceState = "this" | "connected" | "silent" | "other";

/**
 * How to show a device: the browser key when this browser holds it, a
 * computer by whether it was heard from in the last two minutes.
 */
export function deviceState(device: AgentDevice, now: number, heldHere: boolean): DeviceState {
  if (heldHere) return "this";
  if (device.kind !== "computer") return "other";
  const seen = parseServerTime(device.last_used_at) ?? parseServerTime(device.activated_at);
  return seen !== null && now - seen <= CONNECTED_WITHIN_MS ? "connected" : "silent";
}

const seenKey = (aid: string) => `nexusinbox.devices.seen.${aid}`;

/** The device DIDs this browser was last told about, or null the first time. */
export function loadSeenDevices(aid: string): string[] | null {
  try {
    const raw = window.localStorage.getItem(seenKey(aid));
    if (raw === null) return null;
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((d): d is string => typeof d === "string") : null;
  } catch {
    return null;
  }
}

export function saveSeenDevices(aid: string, devices: AgentDevice[]): void {
  try {
    window.localStorage.setItem(seenKey(aid), JSON.stringify(devices.map((d) => d.did)));
  } catch {
    // Storage blocked: the notice may show again, which is the safe side.
  }
}

/**
 * Devices that joined since this browser last looked. The first look only
 * records the list: an agent seen for the first time has nothing "new".
 */
export function unseenDevices(devices: AgentDevice[], seen: string[] | null): AgentDevice[] {
  if (seen === null) return [];
  return devices.filter((d) => !seen.includes(d.did));
}
