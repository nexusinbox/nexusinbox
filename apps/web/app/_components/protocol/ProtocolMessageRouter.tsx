"use client";

// Dispatches an A2A message to the right specialised card based on
// `protocol.type`. Today only `schedule_negotiation` is implemented;
// additional types land as sibling cards (see docs/24 §10).
//
// This is the one place that computes `canRespond`. Card components
// take a plain `readOnly` prop and never inspect message.folder,
// action, or expiry on their own — that keeps the UI invariant
// ("recipient on a propose with a live deadline") in a single
// location so unit tests can drive it without standing up a whole
// thread fixture.

import type { A2AProtocolBlock } from "./parseProtocolBody";
import { ScheduleNegotiationCard } from "./ScheduleNegotiationCard";
import { TaskDelegationCard } from "./TaskDelegationCard";
import type { MessageFolder } from "../../../lib/api/types";
import {
  canRespondToProtocol,
  type A2ARespondPayload,
  type ScheduleActionPayload,
  type TaskActionPayload,
} from "../../../lib/protocol/a2aReply";

export type ProtocolMessageContext = {
  // Inbox-level grouping. Same MessageFolder the server returned
  // for the MessageIndexEntry. "sent" means the viewer is the
  // sender — Accept/Decline are hidden because acting on a message
  // you sent yourself makes no sense. Every other folder is treated
  // as recipient-side.
  folder: MessageFolder;
  /**
   * Original envelope's `thread_id`, which reply messages inherit so
   * the inbox UI keeps the conversation grouped. Passed through to
   * the Card so its `onRespond` can attach it to outbound replies.
   */
  threadId: string | null;
  /**
   * Original protocol.id — reply messages set this as their
   * `reply_to`. Pre-computed here so Card doesn't have to know
   * which field of the protocol block to look at.
   */
  originalProtocolId: string;
};

export type ProtocolMessageRouterProps = {
  protocol: A2AProtocolBlock;
  /**
   * Plain-text body extracted from the A2A payload. Shown as the
   * human-readable summary above the structured UI so legacy-
   * language readers and screen readers still get context.
   */
  bodyText: string;
  context: ProtocolMessageContext;
  /**
   * Called when the recipient acts on a propose / delegate. The
   * specific reply shape is a union across every A2A type; the
   * Card only emits the variant that matches its protocol.type so
   * downstream `buildReplyPayload` can narrow it via the type
   * argument ConversationThread passes in.
   */
  onRespond?: (reply: A2ARespondPayload) => void | Promise<void>;
};

export function ProtocolMessageRouter({
  protocol,
  bodyText,
  context,
  onRespond,
}: ProtocolMessageRouterProps) {
  const canRespond = canRespondToProtocol({ folder: context.folder, protocol });

  if (protocol.type === "schedule_negotiation") {
    return (
      <ScheduleNegotiationCard
        protocol={protocol}
        bodyText={bodyText}
        readOnly={!canRespond}
        onRespond={onRespond as ((reply: ScheduleActionPayload) => void | Promise<void>) | undefined}
      />
    );
  }

  if (protocol.type === "task_delegation") {
    return (
      <TaskDelegationCard
        protocol={protocol}
        bodyText={bodyText}
        readOnly={!canRespond}
        onRespond={onRespond as ((reply: TaskActionPayload) => void | Promise<void>) | undefined}
      />
    );
  }

  // Unknown type — render a minimal placeholder so the user at
  // least sees something sensible. Forward-compat for future
  // protocol.type additions arriving on older clients.
  return (
    <div className="ai-protocol-card ai-protocol-card--unknown" data-testid="protocol-unknown">
      <p className="ai-protocol-body">{bodyText}</p>
      <p className="ai-protocol-footer">{`(Unrecognised protocol: ${protocol.type})`}</p>
    </div>
  );
}
