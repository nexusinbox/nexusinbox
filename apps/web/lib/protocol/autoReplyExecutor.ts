// Phase 4.4c (docs/25c) — browser-side auto-reply executor.
//
// The inbox page launches this on every render. It walks the current
// messagesQuery data, picks out rows the 4.4b server evaluator already
// tagged with an actionable decision, decrypts them, re-evaluates
// client-side (so protocol overrides can fire), then builds + sends
// the A2A reply via the existing sendProtocolReply pipeline and flips
// `auto_reply_sent_at` via `markAutoReplySent` so a refresh or second
// tab won't send a duplicate.
//
// The module is intentionally side-effect-heavy and talks to the API;
// all external collaborators are passed in so the `.test.ts` can
// replace them with in-memory stubs.

import {
  A2A_CONTENT_TYPE,
  parseA2APayload,
  type A2AProtocolBlock,
  type ScheduleProposePayload,
  type ScheduleCandidate,
} from "@nexusinbox/core/a2a";
import type { MessageContentResponse, MessageIndexEntry } from "../api/types";
import {
  evaluateAutoReplyPolicyClient,
  mergeDecisions,
  type EvaluationContext,
  type ProtocolKey,
  type AutoReplyAction,
} from "./autoReplyClientEvaluator";
import type { A2ARespondPayload } from "./a2aReply";
import type { IsoInterval } from "../calendar/gcalFreebusy";

export const AUTO_REPLY_ORIGIN_CLIENT = "client_protocol_v1";

/** Abstraction over the two API client methods the executor needs. */
export type AutoReplyExecutorApi = {
  getMessageContent: (id: string) => Promise<MessageContentResponse>;
  markAutoReplySent: (
    id: string,
    params: { replyMessageId?: string },
  ) => Promise<{ auto_reply_sent_at: string }>;
};

/**
 * Callback the inbox provides so the executor can reuse the same
 * encrypt-sign-send pipeline the UI buttons use. This is typed as a
 * function rather than `typeof sendProtocolReply` to keep the
 * executor decoupled from the real helper's imports (easier mocking).
 */
export type SendProtocolReplyFn = (input: {
  protocolType: A2AProtocolBlock["type"];
  reply: A2ARespondPayload;
  threadId: string | null;
  originalProtocolId: string;
  subject: string;
  bodySummary: string;
  viewerAgentDid: string;
  proposerDid: string;
  autoReplyOrigin?: string;
  replyMessageIdSink?: (id: string) => void;
}) => Promise<void>;

/**
 * Helper fetched once at executor start: decrypt a ciphertext envelope
 * field to its plaintext. The inbox already has this wired up — we
 * just accept it as a callback so unit tests don't need Web Crypto.
 */
export type DecryptFn = (
  ciphertext: string,
  encryptedKey: string | undefined,
  recipientDid: string,
) => Promise<string>;

export type RunAutoReplyExecutorInput = {
  viewerAgentDid: string;
  viewerHasSigningKey: boolean;
  messages: MessageIndexEntry[];
  policy: Record<string, unknown> | null;
  masterAutoReplyEnabled: boolean;
  isContact: (senderDid: string) => boolean;
  api: AutoReplyExecutorApi;
  sendProtocolReply: SendProtocolReplyFn;
  decrypt: DecryptFn;
  /**
   * Phase 4.4d (docs/25d) — resolves `auto_accept_if_free` against
   * Google Calendar. Takes the original propose's candidates +
   * returns either the first free one or `null` if every slot
   * overlaps a busy interval. Throws when the check itself fails
   * (network, auth, quota) so the executor can tag the audit
   * reason accordingly. When the user hasn't connected Calendar
   * the callback is omitted entirely and the executor falls back
   * to queue_for_human (calendar_unavailable).
   */
  calendarFreebusy?: (candidates: readonly IsoInterval[]) => Promise<IsoInterval | null>;
  onProgress?: (event: AutoReplyExecutorEvent) => void;
};

export type AutoReplyExecutorEvent =
  | { kind: "skipped"; messageId: string; reason: string }
  | { kind: "sent"; messageId: string; action: "auto_accept" | "auto_decline" }
  | { kind: "error"; messageId: string; error: unknown };

const DEFAULT_DECLINE_REASON = "ポリシーに基づき自動で辞退しました";

/** Rows the executor should inspect — the server evaluator ran
 *  (decision != null) and we haven't dispatched a reply yet. Phase
 *  4.4d widens this to include `queue_for_human` entries whose
 *  cached reason says Calendar was the blocker: the client now
 *  knows how to resolve those. */
function eligibleMessages(messages: MessageIndexEntry[]): MessageIndexEntry[] {
  return messages.filter((m) => {
    if (m.auto_reply_decision == null || m.auto_reply_sent_at) return false;
    if (m.auto_reply_decision === "auto_accept") return true;
    if (m.auto_reply_decision === "auto_decline") return true;
    if (
      m.auto_reply_decision === "queue_for_human" &&
      m.auto_reply_reason === "calendar_unavailable"
    ) {
      return true;
    }
    return false;
  });
}

/**
 * Pick the first candidate the executor can safely commit to. Phase
 * 4.4c isn't aware of the user's calendar (that's 4.4d), so we accept
 * the first candidate verbatim. A future change can replace this with
 * a freebusy-aware picker.
 */
function pickScheduleCandidate(
  payload: ScheduleProposePayload,
): ScheduleCandidate | null {
  return payload.candidates[0] ?? null;
}

function scheduleReplyPayload(
  action: "auto_accept" | "auto_decline",
  protocol: A2AProtocolBlock,
  explicitCandidate: ScheduleCandidate | null = null,
): A2ARespondPayload | null {
  if (action === "auto_decline") {
    return { action: "decline", reason: DEFAULT_DECLINE_REASON };
  }
  const candidate = explicitCandidate
    ?? (() => {
      const proposePayload = protocol.payload as ScheduleProposePayload | undefined;
      return proposePayload ? pickScheduleCandidate(proposePayload) : null;
    })();
  if (!candidate) return null;
  return { action: "accept", selected_candidate: candidate };
}

function taskReplyPayload(
  action: "auto_accept" | "auto_decline",
): A2ARespondPayload {
  return action === "auto_accept"
    ? { action: "accept" }
    : { action: "decline", reason: DEFAULT_DECLINE_REASON };
}

/**
 * Main entrypoint. Processes entries in series to keep the outgoing
 * send rate predictable — 4.4c intentionally does not parallelise
 * because duplicate sends are the exact failure mode the column
 * guardrails are protecting against.
 */
export async function runAutoReplyExecutor(
  input: RunAutoReplyExecutorInput,
): Promise<void> {
  const progress = input.onProgress ?? (() => {});

  if (!input.viewerHasSigningKey) {
    // Agent's signing key lives only in the Signer Daemon (docs/22)
    // or hasn't been provisioned on this device; Standard mode can't do
    // anything here. Isolated mode (future) will pick these up.
    return;
  }

  const queue = eligibleMessages(input.messages);
  if (queue.length === 0) return;

  for (const entry of queue) {
    try {
      const content = await input.api.getMessageContent(entry.id);
      if (content.content_type !== A2A_CONTENT_TYPE) {
        progress({ kind: "skipped", messageId: entry.id, reason: "not_a2a" });
        continue;
      }
      const plaintext = await input.decrypt(
        content.encrypted_content,
        content.encrypted_key,
        input.viewerAgentDid,
      );
      const parsed = parseA2APayload(plaintext, A2A_CONTENT_TYPE);
      if (!parsed.protocol) {
        progress({ kind: "skipped", messageId: entry.id, reason: "not_a2a" });
        continue;
      }
      const protocolKey: ProtocolKey = {
        type: parsed.protocol.type,
        action: parsed.protocol.action,
      };

      const evalCtx: EvaluationContext = {
        masterAutoReplyEnabled: input.masterAutoReplyEnabled,
        priority: entry.priority,
        trustScore: entry.trust_score,
        senderDid: entry.sender_did,
        isContact: input.isContact(entry.sender_did),
        protocol: protocolKey,
      };

      const clientDecision = evaluateAutoReplyPolicyClient(input.policy, evalCtx);
      const finalDecision = mergeDecisions(
        entry.auto_reply_decision && entry.auto_reply_reason
          ? { action: entry.auto_reply_decision, reason: entry.auto_reply_reason }
          : null,
        clientDecision,
      );

      // Phase 4.4d — resolve auto_accept_if_free against the user's
      // Google Calendar before dispatching. The evaluator returns
      // the action raw; whether we actually send depends on freebusy.
      let resolvedAction: AutoReplyAction = finalDecision.action;
      let chosenScheduleCandidate: ScheduleCandidate | null = null;
      if (finalDecision.action === "auto_accept_if_free") {
        if (parsed.protocol.type !== "schedule_negotiation") {
          // auto_accept_if_free only makes sense for scheduling.
          // Anything else falls back to the human queue.
          progress({
            kind: "skipped",
            messageId: entry.id,
            reason: "calendar_wrong_protocol",
          });
          await input.api
            .markAutoReplySent(entry.id, {})
            .catch(() => undefined);
          continue;
        }
        if (!input.calendarFreebusy) {
          progress({
            kind: "skipped",
            messageId: entry.id,
            reason: "calendar_unavailable",
          });
          await input.api
            .markAutoReplySent(entry.id, {})
            .catch(() => undefined);
          continue;
        }
        const proposePayload = parsed.protocol.payload as
          | ScheduleProposePayload
          | undefined;
        const candidates = proposePayload?.candidates ?? [];
        try {
          const free = await input.calendarFreebusy(candidates);
          if (!free) {
            progress({
              kind: "skipped",
              messageId: entry.id,
              reason: "calendar_all_busy",
            });
            await input.api
              .markAutoReplySent(entry.id, {})
              .catch(() => undefined);
            continue;
          }
          resolvedAction = "auto_accept";
          chosenScheduleCandidate = { start: free.start, end: free.end };
        } catch {
          progress({
            kind: "skipped",
            messageId: entry.id,
            reason: "calendar_api_error",
          });
          // Don't mark sent — freebusy failures are usually
          // transient (network, 429). Leave the row for the next
          // render to retry.
          continue;
        }
      }

      if (resolvedAction !== "auto_accept" && resolvedAction !== "auto_decline") {
        progress({
          kind: "skipped",
          messageId: entry.id,
          reason: `decision_${resolvedAction}_${finalDecision.reason}`,
        });
        continue;
      }

      const replyPayload =
        parsed.protocol.type === "schedule_negotiation"
          ? scheduleReplyPayload(
              resolvedAction,
              parsed.protocol,
              chosenScheduleCandidate,
            )
          : taskReplyPayload(resolvedAction);
      if (!replyPayload) {
        progress({
          kind: "skipped",
          messageId: entry.id,
          reason: "reply_payload_unavailable",
        });
        continue;
      }

      let replyMessageId: string | undefined;
      await input.sendProtocolReply({
        protocolType: parsed.protocol.type,
        reply: replyPayload,
        threadId: entry.thread_id ?? entry.id,
        originalProtocolId: parsed.protocol.id,
        subject: "Re: (auto-reply)",
        bodySummary: "",
        viewerAgentDid: input.viewerAgentDid,
        proposerDid: entry.sender_did,
        autoReplyOrigin: AUTO_REPLY_ORIGIN_CLIENT,
        replyMessageIdSink: (id) => {
          replyMessageId = id;
        },
      });
      await input.api.markAutoReplySent(entry.id, { replyMessageId });
      progress({ kind: "sent", messageId: entry.id, action: resolvedAction });
    } catch (error) {
      progress({ kind: "error", messageId: entry.id, error });
      // Leave `auto_reply_sent_at` NULL so the next render retries
      // naturally. The executor is idempotent: a second run that
      // succeeds will flip the column.
    }
  }
}
