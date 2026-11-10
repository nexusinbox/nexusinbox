// Decrypt a message for whoever is looking at it: the recipient with the
// recipient's wrapped key, the sender with the sender's own copy
// (docs/35 §5). Used by the conversation list and the conversation view.

import type { MessageContentResponse, MessageIndexEntry } from "../api/types";
import { decryptEnvelopeTextWithState, ENCRYPTED_PLACEHOLDER } from "../crypto/envelope";
import { hasRecipientPrivateKey } from "../crypto/recipient-keyring";
import { wrapsForDid } from "../crypto/wrap-select";

/** A wrapped content key and the DID whose private key opens it. */
export type ViewerKey = { encryptedKey: string; did: string };

/**
 * The DIDs whose private keys could open this message for the viewer: the
 * addressed device, and any device of the viewer's own agent, since each
 * may have its own wrap (docs/38).
 */
export function candidateDids(entry: MessageIndexEntry, mine: boolean, ownDids: string[]): string[] {
  const dids = mine
    ? [entry.sender_did, ...ownDids, entry.recipient_did]
    : [entry.recipient_did, ...ownDids];
  return Array.from(new Set(dids.filter(Boolean)));
}

function viewerKeys(
  content: MessageContentResponse,
  entry: MessageIndexEntry,
  mine: boolean,
  ownDids: string[],
): ViewerKey[] {
  const keys: ViewerKey[] = [];
  // A wrap made for one of this agent's devices (docs/38), best first.
  for (const did of candidateDids(entry, mine, ownDids)) {
    for (const encryptedKey of wrapsForDid(content, did)) keys.push({ encryptedKey, did });
  }
  if (mine && content.sender_encrypted_key) {
    for (const did of Array.from(new Set([entry.sender_did, ...ownDids]))) {
      keys.push({ encryptedKey: content.sender_encrypted_key, did });
    }
  }
  // The recipient copy: the viewer is the recipient, or sent it to
  // another of their own agents.
  keys.push({ encryptedKey: content.encrypted_key, did: entry.recipient_did });
  return keys;
}

export type DecryptedMessage = {
  state: "readable" | "no_key" | "error";
  text: string;
  /** The key that opened the body; subject and attachments use it too. */
  key: ViewerKey | null;
};

/** True when this browser holds a private key for any of the DIDs. */
export async function hasAnyPrivateKey(dids: string[]): Promise<boolean> {
  for (const did of dids) {
    if (await hasRecipientPrivateKey(did)) return true;
  }
  return false;
}

export async function decryptMessageBody(
  content: MessageContentResponse,
  entry: MessageIndexEntry,
  mine: boolean,
  ownDids: string[],
): Promise<DecryptedMessage> {
  let sawError = false;
  for (const key of viewerKeys(content, entry, mine, ownDids)) {
    const result = await decryptEnvelopeTextWithState(
      content.encrypted_content,
      key.encryptedKey,
      key.did,
    );
    if (result.state === "readable" || result.state === "passthrough") {
      return { state: "readable", text: result.text, key };
    }
    if (result.state === "error") sawError = true;
  }
  return { state: sawError ? "error" : "no_key", text: ENCRYPTED_PLACEHOLDER, key: null };
}
