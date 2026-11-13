"use client";

// Runs the browser-side auto-reply executor for one agent whose keys live
// in this browser (docs/25c, docs/34 §3). Mounted by the inbox for each
// such agent, so automatic replies go out while the inbox is open, not
// only on the per-agent page. Renders nothing.

import { useEffect, useMemo, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useAutoReplyPolicyQuery,
  useContactsQuery,
  useMessagesQuery,
} from "../../lib/api/hooks";
import type { Agent } from "../../lib/api/types";
import { defaultApiClient } from "../../lib/api/client";
import { decryptEnvelopeText } from "../../lib/crypto/envelope";
import { getSigningPrivateKey } from "../../lib/crypto/signing-keyring";
import { runAutoReplyExecutor } from "../../lib/protocol/autoReplyExecutor";
import { sendProtocolReply as realSendProtocolReply } from "./protocol/sendProtocolReply";
import { getCalendarToken } from "../../lib/calendar/gcalAuth";
import { findFirstFreeCandidate } from "../../lib/calendar/gcalFreebusy";
import { checkReceived } from "../../lib/agents/sender-check";
import { answeredReplies } from "../../lib/protocol/answered";

export function BrowserAutoReply({ agent }: { agent: Agent }) {
  const currentAgent = agent;
  const messagesQuery = useMessagesQuery({
    agentDid: agent.did,
    status: "all",
    folder: "inbox",
    page: 1,
    perPage: 50,
  });
  const contactsQuery = useContactsQuery();
  const knownContactDids = useMemo(() => {
    const dids = contactsQuery.data?.contacts?.map((contact) => contact.did) ?? [];
    return new Set(dids);
  }, [contactsQuery.data]);
  const policyQuery = useAutoReplyPolicyQuery(currentAgent.id);
  const queryClient = useQueryClient();
  // Guards against overlapping executor runs. Without this the
  // StrictMode double-invocation and every messagesQuery refetch
  // would kick off a concurrent executor pass — the server column
  // would still gate double sends, but we'd burn API + crypto work.
  const executorRunningRef = useRef(false);

  useEffect(() => {
    const agent = currentAgent;
    if (!agent) return;
    if (executorRunningRef.current) return;
    const messages = messagesQuery.data?.messages ?? [];
    const hasEligible = messages.some((m) => {
      if (m.auto_reply_sent_at) return false;
      if (m.auto_reply_claimed_at) return false;
      if (
        m.auto_reply_decision === "auto_accept" ||
        m.auto_reply_decision === "auto_decline"
      ) {
        return true;
      }
      // Phase 4.4d: the server stamped queue_for_human because the
      // server evaluator can't see protocols.*, but the client
      // evaluator + Calendar check may still resolve it to accept.
      if (
        m.auto_reply_decision === "queue_for_human" &&
        m.auto_reply_reason === "calendar_unavailable"
      ) {
        return true;
      }
      return false;
    });
    if (!hasEligible) return;

    let cancelled = false;
    executorRunningRef.current = true;
    (async () => {
      try {
        const signingKey = await getSigningPrivateKey(agent.did);
        if (cancelled) return;
        const gcalEntry = await getCalendarToken();
        const gcalToken = gcalEntry?.access_token ?? null;
        await runAutoReplyExecutor({
          viewerAgentDid: agent.did,
          viewerHasSigningKey: !!signingKey,
          messages,
          policy: (policyQuery.data?.policy as Record<string, unknown>) ?? null,
          masterAutoReplyEnabled: agent.auto_reply,
          isContact: (senderDid) => knownContactDids.has(senderDid),
          api: {
            getMessageContent: (id) => defaultApiClient.getMessageContent(id),
            markAutoReplySent: (id, params) =>
              defaultApiClient.markAutoReplySent(id, params),
            claimAutoReply: (id) => defaultApiClient.claimAutoReply(id),
            releaseAutoReplyClaim: (id) =>
              defaultApiClient.releaseAutoReplyClaim(id),
            skipAutoReply: (id, reason) => defaultApiClient.skipAutoReply(id, reason),
          },
          checkSender: (content) => checkReceived(content, [agent]),
          answered: answeredReplies,
          sendProtocolReply: (input) =>
            realSendProtocolReply({
              protocolType: input.protocolType,
              reply: input.reply,
              threadId: input.threadId,
              originalProtocolId: input.originalProtocolId,
              subject: input.subject,
              bodySummary: input.bodySummary,
              viewerAgentDid: input.viewerAgentDid,
              proposerDid: input.proposerDid,
              autoReplyOrigin: input.autoReplyOrigin,
              senderEncryptionKey: agent.encryption_key,
              sendMessage: (payload) =>
                defaultApiClient.seedMessage({
                  senderDid: payload.senderDid,
                  recipientDid: payload.recipientDid,
                  subjectEncrypted: payload.subjectEncrypted,
                  encryptedContent: payload.encryptedContent,
                  encryptedKey: payload.encryptedKey,
                  nonce: payload.nonce,
                  signing: payload.signing,
                  threadId: payload.threadId,
                  contentType: payload.contentType,
                  autoReplyOrigin: payload.autoReplyOrigin,
                  senderEncryptedKey: payload.senderEncryptedKey,
                  encryptedKeys: payload.encryptedKeys,
                  senderEncryptedKeys: payload.senderEncryptedKeys,
                }),
            }),
          decrypt: (ciphertext, encryptedKey, recipientDid) =>
            decryptEnvelopeText(ciphertext, encryptedKey, recipientDid),
          // Phase 4.4d: wire Google Calendar freebusy when the user
          // has connected their account. Callback omitted → executor
          // treats auto_accept_if_free as calendar_unavailable and
          // escalates to the human queue. Callback present + throws
          // → treated as transient API error and left for retry.
          calendarFreebusy: gcalToken
            ? async (candidates) =>
                findFirstFreeCandidate(candidates, gcalToken)
            : undefined,
        });
        if (!cancelled) {
          queryClient.invalidateQueries({ queryKey: ["messages"] });
        }
      } finally {
        executorRunningRef.current = false;
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    currentAgent,
    knownContactDids,
    messagesQuery.data,
    policyQuery.data,
    queryClient,
  ]);

  return null;
}
