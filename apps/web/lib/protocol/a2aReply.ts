// Pure helpers shared between the A2A card UI and the protocol
// reply pipeline. Kept out of the React layer so they can be unit-
// tested without jsdom or @testing-library. The invariants these
// helpers encode (canRespond gating, reply payload shape) are the
// security-critical parts of docs/24 §2.6–2.7 — regressions here
// would produce wrong affordances (sender seeing Accept) or bad
// replies (wrong selected_candidate echo), both hard to catch in
// end-to-end tests.

import {
  isProposeExpired,
  type A2AProtocolBlock,
  type A2AProtocolType,
  type ScheduleAcceptPayload,
  type ScheduleCandidate,
  type ScheduleCounterPayload,
  type ScheduleProposePayload,
  type TaskAcceptPayload,
  type TaskCompletePayload,
  type TaskDeclinePayload,
} from "@nexusinbox/core/a2a";
import type { MessageFolder } from "../api/types";

/**
 * Schedule reply actions — the shape the ScheduleNegotiationCard
 * hands to its `onRespond` callback.
 */
export type ScheduleActionPayload =
  | { action: "accept"; selected_candidate: ScheduleCandidate }
  | { action: "decline"; reason?: string }
  | { action: "counter"; candidates: ScheduleCandidate[]; reason?: string };

/**
 * Task delegation reply actions — what TaskDelegationCard emits.
 * Keeps the discriminant on `action` so the Router can stay
 * type-agnostic when it forwards the reply.
 */
export type TaskActionPayload =
  | { action: "accept"; note?: string }
  | { action: "decline"; reason?: string }
  | { action: "complete"; result?: string };

/** Union of every recipient-side reply shape. */
export type A2ARespondPayload = ScheduleActionPayload | TaskActionPayload;

export type CanRespondContext = {
  folder: MessageFolder;
  protocol: A2AProtocolBlock;
};

/**
 * Centralised "should Accept/Decline be interactive?" predicate.
 * Keep per-type rules here so the Card and the Router can't drift.
 *
 * - schedule_negotiation: only `propose` (with live deadline)
 * - task_delegation: only `delegate`
 * - sender's own sent-view: never
 * - every other action (accept/decline/counter/complete) is a
 *   recorded outcome, never interactive again
 */
export function canRespondToProtocol(ctx: CanRespondContext): boolean {
  if (ctx.folder === "sent") return false;
  if (ctx.protocol.type === "schedule_negotiation") {
    if (ctx.protocol.action !== "propose") return false;
    return !isProposeExpired(ctx.protocol.payload as ScheduleProposePayload);
  }
  if (ctx.protocol.type === "task_delegation") {
    return ctx.protocol.action === "delegate";
  }
  return false;
}

/**
 * Per-type dispatcher: pick the right payload builder. Keeps the
 * Router / ConversationThread agnostic of which specific shape
 * each reply produces.
 */
export function buildReplyPayload(
  protocolType: A2AProtocolType,
  reply: A2ARespondPayload,
):
  | ScheduleAcceptPayload
  | ScheduleCounterPayload
  | TaskAcceptPayload
  | TaskCompletePayload
  | TaskDeclinePayload
  | { reason?: string } {
  if (protocolType === "schedule_negotiation") {
    return buildScheduleReplyPayload(reply);
  }
  return buildTaskReplyPayload(reply);
}

function buildScheduleReplyPayload(
  reply: A2ARespondPayload,
):
  | ScheduleAcceptPayload
  | ScheduleCounterPayload
  | { reason?: string } {
  switch (reply.action) {
    case "accept":
      if (!("selected_candidate" in reply)) {
        throw new Error(
          "schedule_negotiation accept reply requires selected_candidate",
        );
      }
      return {
        selected_candidate: {
          start: reply.selected_candidate.start,
          end: reply.selected_candidate.end,
        },
      };
    case "decline":
      return reply.reason !== undefined ? { reason: reply.reason } : {};
    case "counter":
      if (!("candidates" in reply)) {
        throw new Error(
          "schedule_negotiation counter reply requires candidates",
        );
      }
      return {
        candidates: reply.candidates.map((c) => ({ start: c.start, end: c.end })),
        ...(reply.reason !== undefined ? { reason: reply.reason } : {}),
      };
    case "complete":
      throw new Error(
        "schedule_negotiation has no `complete` action — use task_delegation",
      );
  }
}

function buildTaskReplyPayload(
  reply: A2ARespondPayload,
): TaskAcceptPayload | TaskCompletePayload | TaskDeclinePayload {
  switch (reply.action) {
    case "accept":
      return "note" in reply && reply.note !== undefined
        ? { note: reply.note }
        : {};
    case "decline":
      return reply.reason !== undefined ? { reason: reply.reason } : {};
    case "complete":
      return "result" in reply && reply.result !== undefined
        ? { result: reply.result }
        : {};
    case "counter":
      throw new Error("task_delegation has no `counter` action");
  }
}
