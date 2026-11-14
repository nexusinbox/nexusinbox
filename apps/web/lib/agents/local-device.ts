// Which of an agent's devices this browser is (docs/40 §17.4). The browser
// that created an agent holds the keys of `agent.did`; a browser added with
// a pairing link holds keys of its own DID, one of `agent.dids`. Sending,
// signing the device list and the automatic replies use this DID.

import type { Agent } from "../api/types";
import { hasSigningPrivateKeyMaterial } from "../crypto/signing-keyring";

/**
 * The DID of the agent's device whose signing key this browser holds, if
 * any. Only active devices count: a browser removed from the agent (its
 * key retired, docs/40 §17.5) still holds its key but is no longer one.
 */
export async function localDeviceDid(
  agent: Pick<Agent, "did" | "dids" | "devices"> | undefined,
): Promise<string | null> {
  if (!agent) return null;
  const active = agent.devices && agent.devices.length > 0 ? new Set(agent.devices.map((d) => d.did)) : null;
  for (const did of [agent.did, ...(agent.dids ?? []).filter((d) => d !== agent.did)]) {
    if (active && !active.has(did)) continue;
    try {
      if (await hasSigningPrivateKeyMaterial(did)) return did;
    } catch {
      // Keystore unavailable: this browser holds nothing.
    }
  }
  return null;
}

/**
 * Where a message this browser cannot open can be read: the agent's other
 * active devices. Null when no other browser is among them, so the old
 * "on the computer" text still fits.
 */
export function readableElsewhere(
  agent: Pick<Agent, "devices"> | undefined,
  local: string | null,
): { browsers: NonNullable<Agent["devices"]>; computer: boolean } | null {
  const others = (agent?.devices ?? []).filter((d) => d.did !== local);
  const browsers = others.filter((d) => d.kind === "browser");
  if (browsers.length === 0) return null;
  return { browsers, computer: others.some((d) => d.kind === "computer") };
}

/**
 * The browser that runs the agent's automatic replies (docs/40 §17.6): the
 * one chosen, else the one the agent was created with, else another of its
 * active browsers (the first was removed). Null when it has none.
 */
export function autoReplyBrowser(
  agent: Pick<Agent, "did" | "devices" | "auto_reply_device">,
): NonNullable<Agent["devices"]>[number] | null {
  const browsers = (agent.devices ?? []).filter((d) => d.kind === "browser");
  return (
    browsers.find((d) => d.did === agent.auto_reply_device) ??
    browsers.find((d) => d.did === agent.did) ??
    browsers[0] ??
    null
  );
}
