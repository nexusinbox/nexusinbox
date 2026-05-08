// Helper that takes a Card's `onRespond` payload and turns it into
// an A2A reply envelope sent through the existing messaging path.
// Pulled out of ConversationThread so the thread view stays focused
// on rendering and the reply pipeline is reusable (tests, future
// protocol types beyond schedule_negotiation).
//
// Design invariants (see docs/24 §2.7):
// - `thread_id` is inherited from the original envelope so the
//   inbox UI keeps the conversation grouped.
// - `protocol.reply_to` points at the original protocol.id for the
//   protocol-level correlation.
// - `sender` is the user's agent (i.e. the recipient of the original
//   message), `recipient` is the original sender.
// - The JSON body is assembled manually here instead of going
//   through `buildA2AEnvelope` in @nexusinbox/core. The main entry
//   of @nexusinbox/core pulls in `node:crypto` / `node:net` which
//   can't be bundled for the Next.js browser build; the browser-
//   safe subpath `@nexusinbox/core/a2a` ships the types + the
//   parse side but not the build side. We keep send-side crypto in
//   `apps/web/lib/crypto/*` (Web Crypto only), same pattern the
//   compose page already uses.

import {
  A2A_CONTENT_TYPE,
  uuidv7,
  type A2AMessagePayload,
  type A2AProtocolBlock,
  type A2AProtocolType,
} from "@nexusinbox/core/a2a";
import { defaultApiClient } from "../../../lib/api/client";
import {
  encryptEnvelopeText,
  generateContentKey,
} from "../../../lib/crypto/envelope";
import { wrapContentKeyForRecipient } from "../../../lib/crypto/keywrap";
import { signEnvelopePayload } from "../../../lib/crypto/signature";
import { getSigningPrivateKey } from "../../../lib/crypto/signing-keyring";
import {
  buildReplyPayload,
  type A2ARespondPayload,
} from "../../../lib/protocol/a2aReply";

type SendMessageFn = (payload: {
  senderDid: string;
  recipientDid: string;
  subjectEncrypted: string;
  encryptedContent: string;
  encryptedKey: string;
  nonce: string;
  signature: string;
  threadId?: string | null;
  contentType?: string;
  autoReplyOrigin?: string;
}) => Promise<unknown>;

export type SendProtocolReplyInput = {
  /**
   * Which A2A protocol this reply belongs to. Threaded through
   * `buildReplyPayload` so each type's own reply-shape logic runs.
   * Must match the `type` of the propose / delegate being replied to.
   */
  protocolType: A2AProtocolType;
  reply: A2ARespondPayload;
  /**
   * The envelope `thread_id` from the message the user is replying
   * to. New replies inherit this so the inbox UI keeps the
   * conversation grouped. When the original had no thread_id, pass
   * the original message_id so it becomes the thread root.
   */
  threadId: string | null;
  /** The protocol.id of the `propose` / `delegate` being responded to. */
  originalProtocolId: string;
  /** Subject to copy into the reply — usually "Re: " + original. */
  subject: string;
  /**
   * Short human-readable body put alongside the protocol block so
   * legacy viewers and notification previews have something to
   * show. May be empty; docs/24 recommends always filling it in.
   */
  bodySummary: string;
  /**
   * Viewer's agent DID — the "recipient" field of the original
   * envelope. Becomes this reply's sender_did.
   */
  viewerAgentDid: string;
  /**
   * Original sender of the propose / delegate — becomes this
   * reply's recipient_did. Will be re-resolved through
   * resolveRecipient in case the DID has rotated since the message
   * was first sent.
   */
  proposerDid: string;
  /**
   * Injected so unit tests can pass an in-memory stub. Defaults to
   * the useSendMessageMutation-driven client path.
   */
  sendMessage: SendMessageFn;
  /**
   * Phase 4.4c executor-origin tag. When set, threaded into the
   * envelope metadata so the recipient-side server evaluator skips
   * this delivery (no second auto-reply). See docs/25c §3.1.
   */
  autoReplyOrigin?: string;
};

export async function sendProtocolReply(input: SendProtocolReplyInput): Promise<void> {
  const resolved = await defaultApiClient.resolveRecipient(input.proposerDid);
  const recipientDid = resolved?.did ?? input.proposerDid;
  const recipientEncryptionKey = resolved?.encryption_public_key;
  if (!recipientEncryptionKey) {
    throw new Error(
      "Unable to resolve recipient encryption key for this protocol reply.",
    );
  }

  const signingPrivateKey = await getSigningPrivateKey(input.viewerAgentDid);
  if (!signingPrivateKey) {
    throw new Error(
      "Local signing key for this agent is not available on this device.",
    );
  }

  const protocolBlock: A2AProtocolBlock = {
    id: uuidv7(),
    type: input.protocolType,
    action: input.reply.action,
    reply_to: input.originalProtocolId,
    payload: buildReplyPayload(input.protocolType, input.reply),
  };
  const a2aPayload: A2AMessagePayload = {
    v: 1,
    body: input.bodySummary,
    protocol: protocolBlock,
  };
  const serialised = JSON.stringify(a2aPayload);

  const contentKey = generateContentKey();
  const encryptedSubject = await encryptEnvelopeText(input.subject, { contentKey });
  const encryptedBody = await encryptEnvelopeText(serialised, { contentKey });
  const wrapped = await wrapContentKeyForRecipient(contentKey, recipientEncryptionKey);
  const signature = await signEnvelopePayload({
    signingPrivateKey,
    senderDid: input.viewerAgentDid,
    recipientDid,
    subjectEncrypted: encryptedSubject.serialized,
    encryptedContent: encryptedBody.serialized,
    encryptedKey: wrapped.wrappedKey,
    nonce: encryptedBody.nonce,
  });

  await input.sendMessage({
    senderDid: input.viewerAgentDid,
    recipientDid,
    subjectEncrypted: encryptedSubject.serialized,
    encryptedContent: encryptedBody.serialized,
    encryptedKey: wrapped.wrappedKey,
    nonce: encryptedBody.nonce,
    signature,
    threadId: input.threadId,
    contentType: A2A_CONTENT_TYPE,
    autoReplyOrigin: input.autoReplyOrigin,
  });
}

