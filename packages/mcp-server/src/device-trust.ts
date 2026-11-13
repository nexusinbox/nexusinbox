/**
 * Checking a recipient's signed device list before wrapping (docs/40
 * §12.3, §13.2), for the Standard mode runtime, which talks to the API
 * without the gateway. The rules are core `decideWrapTargets`; what is
 * remembered of each agent lives in a file next to the keystore, in the
 * gateway's `peers.json` shape.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import type { RecipientResolution } from "@nexusinbox/core";
import { decideWrapTargets, pinAfter, type DevicePin, type StopReason } from "@nexusinbox/core/device-list";

export type Peers = {
  pins: Record<string, DevicePin>;
  dids: Record<string, string>;
  changed: Record<string, string>;
};

export class SendStoppedError extends Error {
  constructor(
    readonly reason: StopReason,
    readonly aid: string,
    readonly root?: string,
  ) {
    super(
      reason === "root_changed"
        ? `Not sent: the device list of ${aid} is now signed by another key (${root}). Their key may have been replaced; ask the person to confirm with them. [stopped: root_changed]`
        : `Not sent: the device list of ${aid} does not check out. Ask the person to look at it in the NexusInbox app. [stopped: ${reason}]`,
    );
    this.name = "SendStoppedError";
  }
}

async function load(file: string): Promise<Peers> {
  try {
    const value = JSON.parse(await fs.readFile(file, "utf8")) as Partial<Peers>;
    return { pins: value.pins ?? {}, dids: value.dids ?? {}, changed: value.changed ?? {} };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { pins: {}, dids: {}, changed: {} };
    throw error;
  }
}

async function save(file: string, peers: Peers): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.tmp`;
  await fs.rm(tmp, { force: true });
  await fs.writeFile(tmp, JSON.stringify(peers, null, 2), { mode: 0o600, flag: "wx" });
  await fs.rename(tmp, file);
}

/**
 * Check `served` (what the API resolved `requested` to) and return it with
 * only what may be wrapped for: `devices` the listed devices the server
 * still returns, with the listed keys, and `did` / `encryption_public_key`
 * the one `encrypted_key` goes to. Throws SendStoppedError.
 */
export async function checkRecipient(
  served: RecipientResolution,
  requested: string,
  peersFile: string,
): Promise<RecipientResolution> {
  const peers = await load(peersFile);
  const pin = peers.pins[served.aid] ?? null;
  const decision = await decideWrapTargets({
    served: { ...served, encryption_public_key: served.encryption_public_key ?? "" },
    requested,
    knownAid: requested.startsWith("did:") ? peers.dids[requested] : null,
    pin,
  });
  if (decision.kind === "stop") {
    if (decision.root) {
      peers.changed[served.aid] = decision.root;
      await save(peersFile, peers).catch(() => undefined);
    }
    throw new SendStoppedError(decision.reason, served.aid, decision.root);
  }
  if (requested.startsWith("did:")) peers.dids[requested] = served.aid;
  const next = pinAfter(pin, decision);
  if (next) {
    peers.pins[served.aid] = next;
    delete peers.changed[served.aid];
  }
  await save(peersFile, peers);
  return {
    ...served,
    did: decision.single.did,
    encryption_public_key: decision.single.encryption_public_key,
    devices: decision.targets,
  };
}
