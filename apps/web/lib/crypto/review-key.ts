// review-key.ts — this browser's key for reading AI drafts (docs/33 §9).
//
// A cloud-hosted AI cannot send; the person's computer stores its drafts
// encrypted for the recipient, with the same content key also wrapped to
// every browser the person set up for review. This module keeps that
// browser's X25519 private key (non-extractable, IndexedDB) and opens
// drafts with it. The public half is remembered in localStorage so the page
// can tell which server-side review key is this browser's.

import { defaultApiClient } from "../api/client";
import type { Agent, AgentDraft, ReviewKey } from "../api/types";
import { decryptEnvelopeTextWithContentKey } from "./envelope";
import { isKeystoreAvailable, secureLoadKey, secureStoreKey } from "./keystore";
import { unwrapContentKeyWithRecipientPrivateKey, wrapContentKeyForSender } from "./keywrap";
import { generateX25519KeyPairMaterial } from "./recipient-keyring";

const PRIVATE_KEY_ID = "nexusinbox.review-key.v1";
const PUBLIC_KEY_STORAGE = "nexusinbox.review-key.pub.v1";

function readPublicKey(): string | null {
  try {
    return window.localStorage.getItem(PUBLIC_KEY_STORAGE);
  } catch {
    return null;
  }
}

/** The server-side review key that belongs to this browser, if any. */
export async function findThisBrowsersReviewKey(
  keys: ReviewKey[],
): Promise<ReviewKey | null> {
  const publicKey = readPublicKey();
  if (!publicKey || !isKeystoreAvailable()) return null;
  const match = keys.find((k) => k.public_key === publicKey);
  if (!match) return null;
  const privateKey = await secureLoadKey(PRIVATE_KEY_ID);
  return privateKey ? match : null;
}

/** Make a new key pair for this browser. The caller registers the public half. */
export async function createReviewKeyMaterial(): Promise<string> {
  if (!isKeystoreAvailable()) {
    throw new Error("this browser cannot keep keys");
  }
  const { publicKey, privateKey } = await generateX25519KeyPairMaterial();
  await secureStoreKey(PRIVATE_KEY_ID, privateKey);
  window.localStorage.setItem(PUBLIC_KEY_STORAGE, publicKey);
  return publicKey;
}

/** Forget which key is this browser's (after it was removed on the server). */
export function forgetReviewKey(): void {
  try {
    window.localStorage.removeItem(PUBLIC_KEY_STORAGE);
  } catch {
    // nothing to forget
  }
}

/** A short name for this browser, shown in the list of review browsers. */
export function describeThisBrowser(): string {
  const ua = typeof navigator === "undefined" ? "" : navigator.userAgent;
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : "Browser";
  const os = /iPhone|iPad/.test(ua)
    ? "iPhone/iPad"
    : /Android/.test(ua)
      ? "Android"
      : /Mac OS X/.test(ua)
        ? "Mac"
        : /Windows/.test(ua)
          ? "Windows"
          : /Linux/.test(ua)
            ? "Linux"
            : "";
  return os ? `${browser} (${os})` : browser;
}

export type OpenedDraft = {
  subject: string;
  body: string;
  /** Kept so the sender's copy can be made when the draft is sent. */
  contentKey: string;
};

/** Decrypt a draft with this browser's review key, or null if it cannot. */
export async function openDraft(
  draft: AgentDraft,
  reviewKeyId: string,
): Promise<OpenedDraft | null> {
  const wrap = draft.review_wraps.find((w) => w.review_key_id === reviewKeyId);
  if (!wrap) return null;
  const privateKey = await secureLoadKey(PRIVATE_KEY_ID);
  if (!privateKey) return null;
  try {
    const contentKey = await unwrapContentKeyWithRecipientPrivateKey(
      wrap.wrapped_key,
      privateKey,
    );
    const [subject, body] = await Promise.all([
      decryptEnvelopeTextWithContentKey(draft.subject_encrypted, contentKey),
      decryptEnvelopeTextWithContentKey(draft.encrypted_content, contentKey),
    ]);
    if (subject.state === "error" || body.state === "error") return null;
    return { subject: subject.text, body: body.text, contentKey };
  } catch {
    return null;
  }
}

/**
 * The draft's content key wrapped for the agent that sends it, so the
 * person can read the sent message later (docs/35 §5). Undefined when the
 * draft is not open here or the agent has no encryption key.
 */
export async function senderCopyForDraft(
  draft: AgentDraft,
  opened: OpenedDraft | null | undefined,
  agents: Agent[],
): Promise<string | undefined> {
  if (!opened) return undefined;
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
