// Who sent a received message (docs/40 §14.5). The sender signs the whole
// envelope (signature v2); this browser checks the signature, then that
// the signing device is on the sender's device list signed by the root it
// remembers (the same pins senders use, §12.4). The rules are core
// `checkSender`; the gateway makes the same decisions.

import {
  checkSender,
  pinAfterCheck,
  type DeliveredContent,
  type SenderCheckState,
} from "@nexusinbox/core/envelope-v2";
import type { DevicePin } from "@nexusinbox/core/device-list";
import { ApiError, defaultApiClient } from "../api/client";
import type { Agent, MessageContentResponse, RecipientResolutionResponse } from "../api/types";
import { loadAddressBook } from "../contacts/address-book";
import { contactForAid, contactsOpened, loadPin, savePin } from "./peer-pins";

/** `unchecked`: the sender's agent could not be looked up just now. */
export type ReceivedCheck = SenderCheckState | "unchecked";

const RESOLVE_TTL_MS = 5 * 60 * 1000;
const resolved = new Map<string, { at: number; value: Promise<RecipientResolutionResponse | null> }>();

/** The sender's agent, shared by the messages of one page for a few minutes. */
function resolveAgent(aid: string): Promise<RecipientResolutionResponse | null> {
  const hit = resolved.get(aid);
  if (hit && Date.now() - hit.at < RESOLVE_TTL_MS) return hit.value;
  const value = defaultApiClient.resolveRecipient(aid).catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 404) return null;
    resolved.delete(aid);
    throw error;
  });
  resolved.set(aid, { at: Date.now(), value });
  return value;
}

/**
 * Check a received (or own) message. `ownAgents` are the person's agents:
 * the reader is any of them, and an own agent's root is its created-with
 * DID.
 */
export async function checkReceived(
  content: MessageContentResponse,
  ownAgents: Pick<Agent, "aid" | "did">[],
): Promise<ReceivedCheck> {
  const sig = content.signature_v2;
  const readerAids = ownAgents.map((a) => a.aid);
  if (!sig) return "unsigned";
  let sender: RecipientResolutionResponse | null;
  try {
    sender = await resolveAgent(sig.sender_aid);
  } catch {
    return "unchecked";
  }
  if (!contactsOpened()) await loadAddressBook(defaultApiClient).catch(() => undefined);
  const own = ownAgents.find((a) => a.aid === sig.sender_aid);
  const local = loadPin(sig.sender_aid, own?.did);
  const contactRoot = contactForAid(sig.sender_aid)?.root ?? null;
  const pin: DevicePin | null = local ?? (contactRoot ? { root: contactRoot, version: 0 } : null);
  const check = await checkSender({
    content: content as DeliveredContent,
    readerAids,
    sender: sender ? { ...sender, encryption_public_key: sender.encryption_public_key ?? "" } : null,
    pin,
  });
  const next = pinAfterCheck(pin, check);
  if (next && check.state !== "root_changed" && (next.root !== local?.root || next.version !== local?.version)) {
    savePin(sig.sender_aid, next);
  }
  return check.state;
}

/**
 * Whether a check warns (as opposed to a quiet note, or nothing). A check
 * that could not run just now shows nothing; it runs again next time.
 */
export function receivedWarns(check: ReceivedCheck | undefined): boolean {
  return (
    check !== undefined && check !== "verified" && check !== "unsigned" && check !== "no_list" && check !== "unchecked"
  );
}

/** Signed in the old format: a quiet note only. */
export function receivedOldFormat(check: ReceivedCheck | undefined): boolean {
  return check === "unsigned" || check === "no_list";
}
