// Thin wrapper around @nexusinbox/core's parseA2APayload. The Web
// UI gets a decrypted string + the envelope's content_type, and
// wants a typed `{ body, protocol }` pair it can hand to the
// ProtocolMessageRouter. Keeping the adapter in `_components/protocol`
// means ConversationThread doesn't import from `@nexusinbox/core`
// directly for this concern, and future routing logic (content_type
// fallback strategies, parse-error telemetry) has a natural home.
//
// We import from the `@nexusinbox/core/a2a` subpath (not the main
// entry) because the main entry transitively pulls in `node:crypto`
// and `node:net` via the Node API client. Webpack can't bundle those
// for the browser build. The `a2a` module is hand-audited to stay on
// Web Crypto + globalThis only.

import {
  parseA2APayload,
  type A2AProtocolBlock,
  type ParsedMessageBody,
} from "@nexusinbox/core/a2a";

export function parseProtocolBody(
  decryptedBody: string,
  contentType: string | null | undefined,
): ParsedMessageBody {
  return parseA2APayload(decryptedBody, contentType);
}

export type { A2AProtocolBlock };
