// Picking a message's content-key wrap for a device (docs/38). Kept free
// of browser storage and the API client so pure code (the auto-reply
// executor, tests) can use it.

import type { MessageContentResponse } from "../api/types";

/** The per-device wraps addressed to `did` in a message, from both lists. */
export function wrapsForDid(
  content: Pick<MessageContentResponse, "encrypted_keys" | "sender_encrypted_keys">,
  did: string,
): string[] {
  return [...(content.encrypted_keys ?? []), ...(content.sender_encrypted_keys ?? [])]
    .filter((w) => w.did === did)
    .map((w) => w.key);
}
