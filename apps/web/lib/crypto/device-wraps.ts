// Multi-device delivery (docs/38): a message's content key is wrapped for
// every device of the recipient agent and of the sending agent, so the
// browser and any connected computer can all read it.

import { defaultApiClient } from "../api/client";
import type { DeviceKey, KeyWrap, MessageContentResponse } from "../api/types";
import { isValidX25519PublicKeyB64Url, wrapContentKeyForRecipient } from "./keywrap";
import { hasRecipientPrivateKey } from "./recipient-keyring";
import { wrapsForDid } from "./wrap-select";

export { wrapsForDid };

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

/**
 * The devices of the agent that `identifier` (an AID or one of its DIDs)
 * belongs to. Best effort: on failure the message still goes out with the
 * single wraps.
 */
export async function agentDevices(identifier: string | null | undefined): Promise<DeviceKey[] | undefined> {
  if (!identifier) return undefined;
  try {
    return (await defaultApiClient.resolveRecipient(identifier)).devices;
  } catch {
    return undefined;
  }
}

/** Both lists for a message from `senderIdentifier` to a resolved recipient. */
export async function deviceWraps(
  contentKey: string,
  recipientDevices: DeviceKey[] | null | undefined,
  senderIdentifier: string | null | undefined,
): Promise<{ encryptedKeys: KeyWrap[]; senderEncryptedKeys: KeyWrap[] }> {
  return {
    encryptedKeys: await wrapContentKeyForDevices(contentKey, recipientDevices),
    senderEncryptedKeys: await wrapContentKeyForDevices(contentKey, await agentDevices(senderIdentifier)),
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
