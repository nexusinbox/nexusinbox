// Multi-device delivery (docs/38): a message's content key is wrapped for
// every device of the recipient agent and of the sending agent, so the
// browser and any connected computer can all read it.
//
// Which devices (docs/40 §12): only those the agent's signed device list
// names and the server still returns, checked against the root this
// browser remembers. A list that does not hold stops the send.

import {
  decideWrapTargets,
  pinAfter,
  type DevicePin,
  type StopReason,
  type WrapDecision,
  type WrapTarget,
} from "@nexusinbox/core/device-list";
import {
  contactForAid,
  contactsOpened,
  knownAidFor,
  loadPin,
  rememberDidAid,
  savePin,
} from "../agents/peer-pins";
import { defaultApiClient } from "../api/client";
import type { DeviceKey, KeyWrap, MessageContentResponse, RecipientResolutionResponse } from "../api/types";
import { loadAddressBook, sealForSave } from "../contacts/address-book";
import { isValidX25519PublicKeyB64Url, wrapContentKeyForRecipient } from "./keywrap";
import { hasRecipientPrivateKey } from "./recipient-keyring";
import { wrapsForDid } from "./wrap-select";

export { wrapsForDid };
export type { StopReason };

/** The content key wrapped for each device; devices without a usable key are skipped. */
export async function wrapContentKeyForDevices(
  contentKey: string,
  devices: DeviceKey[] | null | undefined,
): Promise<KeyWrap[]> {
  const out: KeyWrap[] = [];
  const seen = new Set<string>();
  for (const device of devices ?? []) {
    if (seen.has(device.did) || !isValidX25519PublicKeyB64Url(device.encryption_public_key)) continue;
    seen.add(device.did);
    out.push({
      did: device.did,
      key: (await wrapContentKeyForRecipient(contentKey, device.encryption_public_key)).wrappedKey,
    });
  }
  return out;
}

/** A send that must not go out: the recipient's device list does not hold (docs/40 §12.3). */
export class SendStop extends Error {
  constructor(
    readonly reason: StopReason,
    readonly aid: string,
    /** For root_changed: the root the list is now signed by. */
    readonly root?: string,
  ) {
    super(`send stopped: ${reason}`);
    this.name = "SendStop";
  }
}

export function isSendStop(error: unknown): error is SendStop {
  return error instanceof SendStop;
}

export type SendPlan = {
  /** The device `encrypted_key` (and `recipient_did`) goes to. */
  recipient: WrapTarget;
  recipientDevices: DeviceKey[];
  senderDevices: DeviceKey[];
  /** The sender's own key from its checked list, for `sender_encrypted_key`. */
  senderKey?: string;
  /** The recipient has no device list yet: wrapped as the server says. */
  unlisted: boolean;
};

async function openContacts(): Promise<void> {
  if (contactsOpened()) return;
  await loadAddressBook(defaultApiClient).catch(() => undefined);
}

/** Seal the root into the person's contact for this agent (best effort). */
async function sealRootIntoContact(aid: string, root: string): Promise<void> {
  const contact = contactForAid(aid);
  if (!contact || contact.root === root) return;
  try {
    const sealed = await sealForSave(defaultApiClient, contact.did, {
      person_name: contact.person_name,
      agent_label: contact.agent_label,
      note: contact.note,
      aid,
      root,
    });
    await defaultApiClient.updateContact(contact.id, { sealed });
    contact.root = root;
  } catch {
    // The next send or save tries again.
  }
}

async function decide(
  served: RecipientResolutionResponse,
  requested: string,
  acceptRoot?: string,
): Promise<WrapDecision> {
  await openContacts();
  const local = loadPin(served.aid);
  const contactRoot = contactForAid(served.aid)?.root ?? null;
  const pin: DevicePin | null = local ?? (contactRoot ? { root: contactRoot, version: 0 } : null);
  const knownAid = requested.startsWith("did:") ? knownAidFor(requested) : null;
  const decision = await decideWrapTargets({ served, requested, knownAid, pin, acceptRoot });
  if (decision.kind === "stop") return decision;
  if (requested.startsWith("did:")) rememberDidAid(requested, served.aid);
  if (decision.kind !== "listed") return decision;
  const root = decision.list.root;
  // The contact remembers another root than this browser does.
  if (contactRoot && contactRoot !== root && acceptRoot !== root) {
    return { kind: "stop", reason: "root_changed", root };
  }
  const next = pinAfter(pin, decision);
  if (next) savePin(served.aid, next);
  void sealRootIntoContact(served.aid, root);
  return decision;
}

async function ownSide(senderIdentifier: string | null | undefined): Promise<Pick<SendPlan, "senderDevices" | "senderKey">> {
  if (!senderIdentifier) return { senderDevices: [] };
  let served: RecipientResolutionResponse;
  try {
    served = await defaultApiClient.resolveRecipient(senderIdentifier);
  } catch {
    return { senderDevices: [] };
  }
  const decision = await decideWrapTargets({
    served,
    requested: senderIdentifier,
    knownAid: knownAidFor(senderIdentifier),
    pin: loadPin(served.aid),
  });
  if (decision.kind === "stop") {
    // The agent page and Messages already warn about the person's own
    // list; the copy goes only to the one key the caller holds.
    return { senderDevices: [] };
  }
  if (decision.kind === "listed") {
    const next = pinAfter(loadPin(served.aid), decision);
    if (next) savePin(served.aid, next);
  }
  return {
    senderDevices: decision.targets,
    senderKey:
      decision.kind === "listed"
        ? decision.targets.find((d) => d.did === senderIdentifier)?.encryption_public_key
        : undefined,
  };
}

/**
 * Check the recipient's list and pick the devices of both agents to wrap
 * for. Throws SendStop when the recipient's list does not hold;
 * `acceptRoot` is a new root the person has just accepted.
 */
export async function planSend(
  served: RecipientResolutionResponse,
  requested: string,
  senderIdentifier: string | null | undefined,
  options: { acceptRoot?: string } = {},
): Promise<SendPlan> {
  const decision = await decide(served, requested, options.acceptRoot);
  if (decision.kind === "stop") throw new SendStop(decision.reason, served.aid, decision.root);
  return {
    recipient: decision.single,
    recipientDevices: decision.targets,
    unlisted: decision.kind === "unlisted",
    ...(await ownSide(senderIdentifier)),
  };
}

/**
 * The agent has no device list and none was ever seen for it: senders
 * wrap as the server says (docs/40 Q8). A list seen before and now gone
 * stops the send instead.
 */
export function isUnlisted(served: Pick<RecipientResolutionResponse, "aid" | "device_list">): boolean {
  return !served.device_list && !loadPin(served.aid) && !contactForAid(served.aid)?.root;
}

/** Both per-device lists for a planned send. */
export async function deviceWraps(
  contentKey: string,
  plan: Pick<SendPlan, "recipientDevices" | "senderDevices">,
): Promise<{ encryptedKeys: KeyWrap[]; senderEncryptedKeys: KeyWrap[] }> {
  return {
    encryptedKeys: await wrapContentKeyForDevices(contentKey, plan.recipientDevices),
    senderEncryptedKeys: await wrapContentKeyForDevices(contentKey, plan.senderDevices),
  };
}

/**
 * The wrap this browser can open a received message with, and the DID
 * whose key opens it: a per-device wrap for one of `ownDids` it holds a
 * key for, else the single wrap of older messages (for `recipient_did`).
 */
export async function receivedWrap(
  content: Pick<MessageContentResponse, "encrypted_key" | "encrypted_keys" | "sender_encrypted_keys" | "recipient_did">,
  ownDids: string[],
): Promise<{ encryptedKey: string; did: string | undefined }> {
  for (const did of ownDids) {
    const wraps = wrapsForDid(content, did);
    if (wraps.length > 0 && (await hasRecipientPrivateKey(did))) {
      return { encryptedKey: wraps[0], did };
    }
  }
  return { encryptedKey: content.encrypted_key, did: content.recipient_did };
}
