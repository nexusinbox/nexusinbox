// Build, encrypt, sign and send a schedule_negotiation propose (docs/24).
// The propose page and the first-run guide's self-test both send one. The
// A2A envelope is built here rather than through @nexusinbox/core's main
// entry, which is not browser-safe.

import {
  A2A_CONTENT_TYPE,
  uuidv7,
  type A2AMessagePayload,
  type A2AProtocolBlock,
  type ScheduleProposePayload,
} from "@nexusinbox/core/a2a";
import { encryptEnvelopeText, generateContentKey } from "../crypto/envelope";
import { wrapContentKeyForRecipient } from "../crypto/keywrap";
import { signEnvelopePayload } from "../crypto/signature";

export type SendEncryptedMessage = (payload: {
  senderDid: string;
  recipientDid: string;
  subjectEncrypted: string;
  encryptedContent: string;
  encryptedKey: string;
  nonce: string;
  signature: string;
  threadId: string | null;
  contentType: string;
}) => Promise<{ message_id: string }>;

export async function sendScheduleProposal(
  input: {
    senderDid: string;
    signingPrivateKey: CryptoKey;
    /** The recipient as resolved by the server, and its receiving key. */
    recipientDid: string;
    recipientEncryptionKey: string;
    subject: string;
    body: string;
    payload: ScheduleProposePayload;
    /** Called once the message is encrypted and signed, before sending. */
    onSending?: () => void;
  },
  send: SendEncryptedMessage,
): Promise<{ messageId: string; proposeId: string }> {
  const protocolBlock: A2AProtocolBlock = {
    id: uuidv7(),
    type: "schedule_negotiation",
    action: "propose",
    reply_to: null,
    payload: input.payload,
  };
  const a2aPayload: A2AMessagePayload = {
    v: 1,
    body: input.body,
    protocol: protocolBlock,
  };

  const contentKey = generateContentKey();
  const encSubject = await encryptEnvelopeText(input.subject, { contentKey });
  const encBody = await encryptEnvelopeText(JSON.stringify(a2aPayload), { contentKey });
  const wrapped = await wrapContentKeyForRecipient(contentKey, input.recipientEncryptionKey);
  const signature = await signEnvelopePayload({
    signingPrivateKey: input.signingPrivateKey,
    senderDid: input.senderDid,
    recipientDid: input.recipientDid,
    subjectEncrypted: encSubject.serialized,
    encryptedContent: encBody.serialized,
    encryptedKey: wrapped.wrappedKey,
    nonce: encBody.nonce,
  });

  input.onSending?.();
  const sent = await send({
    senderDid: input.senderDid,
    recipientDid: input.recipientDid,
    subjectEncrypted: encSubject.serialized,
    encryptedContent: encBody.serialized,
    encryptedKey: wrapped.wrappedKey,
    nonce: encBody.nonce,
    signature,
    // New thread — the server assigns the id.
    threadId: null,
    contentType: A2A_CONTENT_TYPE,
  });
  return { messageId: sent.message_id, proposeId: protocolBlock.id };
}
