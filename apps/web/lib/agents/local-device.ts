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
