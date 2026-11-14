// review-key.ts — opening and sending AI drafts (docs/33 §9, docs/40 §16.3).
//
// A cloud-hosted AI cannot send; the person's computer stores its drafts
// encrypted for the recipient, with the same content key also wrapped to
// every device on the agent's signed list. A browser on the list opens
// drafts with its own key. The separate review keys that computers before
// v0.7.0 wrapped to are gone; forgetOldReviewKey() removes this browser's.

import { defaultApiClient } from "../api/client";
import type { Agent, AgentDraft, KeyWrap } from "../api/types";
import { decryptEnvelopeTextWithContentKey } from "./envelope";
import { isKeystoreAvailable, secureDeleteKey } from "./keystore";
import { unwrapContentKeyWithRecipientPrivateKey, wrapContentKeyForSender } from "./keywrap";
import { getRecipientPrivateKey } from "./recipient-keyring";
import { deviceWraps, planSend, SendStop } from "./device-wraps";

const PRIVATE_KEY_ID = "nexusinbox.review-key.v1";
const PUBLIC_KEY_STORAGE = "nexusinbox.review-key.pub.v1";

/**
 * Remove the review key an older version kept in this browser (docs/40
 * §16.3): nothing wraps to it any more, and keys no longer used should not
 * be kept.
 */
export async function forgetOldReviewKey(): Promise<void> {
  try {
    if (window.localStorage.getItem(PUBLIC_KEY_STORAGE) === null) return;
    window.localStorage.removeItem(PUBLIC_KEY_STORAGE);
  } catch {
    return;
  }
  if (isKeystoreAvailable()) await secureDeleteKey(PRIVATE_KEY_ID).catch(() => undefined);
}

export type OpenedDraft = {
  subject: string;
  body: string;
  /** Kept so the sender's copy can be made when the draft is sent. */
  contentKey: string;
};

async function openWithContentKey(draft: AgentDraft, contentKey: string): Promise<OpenedDraft | null> {
  const [subject, body] = await Promise.all([
    decryptEnvelopeTextWithContentKey(draft.subject_encrypted, contentKey),
    decryptEnvelopeTextWithContentKey(draft.encrypted_content, contentKey),
  ]);
  if (subject.state === "error" || body.state === "error") return null;
  return { subject: subject.text, body: body.text, contentKey };
}

/**
 * Open a draft here, or null when this browser cannot. Drafts are wrapped
 * for the devices on the agent's signed list (docs/40 §16.3): this browser
 * opens one when it holds the key of a listed device.
 */
export async function openDraftHere(draft: AgentDraft): Promise<OpenedDraft | null> {
  for (const wrap of draft.sender_encrypted_keys ?? []) {
    const privateKey = await getRecipientPrivateKey(wrap.did).catch(() => null);
    if (!privateKey) continue;
    try {
      const opened = await openWithContentKey(
        draft,
        await unwrapContentKeyWithRecipientPrivateKey(wrap.key, privateKey),
      );
      if (opened) return opened;
    } catch {
      // Another listed device's wrap may still open it.
    }
  }
  return null;
}

/**
 * The draft's content key wrapped for the agent that sends it, so the
 * person can read the sent message later (docs/35 §5). Undefined when the
 * draft is not open here or the agent has no encryption key.
 */
/**
 * The approved draft's content key for every device of the recipient
 * agent and of the sending agent (docs/38), checked against the
 * recipient's device list first: throws SendStop when it does not hold
 * (docs/40 §12). Empty lists when the draft is not open here.
 */
export async function draftDeviceWraps(
  draft: AgentDraft,
  opened: OpenedDraft | null | undefined,
  acceptRoot?: string,
): Promise<{ encryptedKeys: KeyWrap[]; senderEncryptedKeys: KeyWrap[] }> {
  const served = await defaultApiClient.resolveRecipient(draft.recipient_did);
  const plan = await planSend(served, draft.recipient_did, draft.sender_did, { acceptRoot });
  // The draft's own wrap went to `recipient_did`: it must be one of the
  // devices the recipient's list names (docs/40 §13.6).
  if (!plan.recipientDevices.some((d) => d.did === draft.recipient_did)) {
    throw new SendStop("signature", served.aid);
  }
  // A v2 draft was wrapped for every device and signed by the computer
  // (docs/40 §14.4): approving only sends it.
  if (!opened || draft.signed_v2) return { encryptedKeys: [], senderEncryptedKeys: [] };
  return deviceWraps(opened.contentKey, plan);
}

export async function senderCopyForDraft(
  draft: AgentDraft,
  opened: OpenedDraft | null | undefined,
  agents: Agent[],
): Promise<string | undefined> {
  if (!opened || draft.signed_v2) return undefined;
  // The key of the DID the draft is sent from: for an agent on a computer
  // that is the signer's key, not the agent's browser-era `encryption_key`.
  const senderKey = await defaultApiClient
    .resolveRecipient(draft.sender_did)
    .then((r) => (r.did === draft.sender_did ? r.encryption_public_key : undefined))
    .catch(() => undefined);
  if (senderKey) {
    const wrapped = await wrapContentKeyForSender(opened.contentKey, senderKey);
    if (wrapped) return wrapped;
  }
  const agent = agents.find(
    (a) =>
      a.aid === draft.aid || a.did === draft.sender_did || a.dids?.includes(draft.sender_did),
  );
  return wrapContentKeyForSender(opened.contentKey, agent?.encryption_key);
}
