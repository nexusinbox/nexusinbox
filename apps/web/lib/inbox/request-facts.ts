// What the conversation list needs to say where each conversation's
// requests stand (docs/41 §7.3): each message read and its sender checked,
// once, then kept for the page's life. The state itself comes from
// @nexusinbox/core/request-state, as on the conversation and in the gateway.

import type { QueryClient } from "@tanstack/react-query";
import {
  conversationRequests,
  isFinished,
  type RequestMessage,
  type RequestState,
} from "@nexusinbox/core/request-state";
import { checkReceived } from "../agents/sender-check";
import { defaultApiClient } from "../api/client";
import { queryKeys } from "../api/hooks";
import type { Agent, MessageContentResponse } from "../api/types";
import { parseA2APayload } from "@nexusinbox/core/a2a";
import type { Conversation, ConversationMessage } from "./conversations";
import { decryptMessageBody } from "./decrypt-message";

type Fact = Pick<RequestMessage, "protocol" | "verified"> | "unreadable";

const facts = new Map<string, Promise<Fact>>();

async function readFact(
  m: ConversationMessage,
  ownDids: string[],
  agents: Agent[],
  queryClient: QueryClient,
): Promise<Fact> {
  try {
    const content = await queryClient.fetchQuery<MessageContentResponse>({
      queryKey: queryKeys.messageContent(m.entry.id),
      queryFn: () => defaultApiClient.getMessageContent(m.entry.id),
      staleTime: 30_000,
    });
    const body = await decryptMessageBody(content, m.entry, m.mine, ownDids);
    if (body.state !== "readable") return "unreadable";
    const parsed = parseA2APayload(body.text, content.content_type ?? null);
    const p = parsed.protocol;
    if (!p) return { protocol: null, verified: true };
    const check = m.mine ? "verified" : await checkReceived(content, agents).catch(() => "unchecked" as const);
    // Not checked just now: try again next time rather than call it unverified.
    if (check === "unchecked") {
      facts.delete(m.entry.id);
      return "unreadable";
    }
    return {
      protocol: {
        id: p.id,
        type: p.type,
        action: p.action,
        reply_to: p.reply_to,
        payload: p.payload as NonNullable<RequestMessage["protocol"]>["payload"],
      },
      verified: check === "verified",
    };
  } catch {
    facts.delete(m.entry.id);
    return "unreadable";
  }
}

export type ConversationChips = {
  /** A request waits for the person. */
  waiting: boolean;
  /** Other requests still under way (not finished, not needing a check). */
  inProgress: number;
  /** Requests that need checking: contradictions, missing originals, unknown since the AI started, unverified senders. */
  unresolved: boolean;
};

const UNRESOLVED: RequestState[] = ["conflict", "missing_original", "ai_unknown"];

/** Where one conversation's requests stand, for its row in the list. */
export async function conversationChips(
  conversation: Conversation,
  agents: Agent[],
  queryClient: QueryClient,
  now: number,
): Promise<ConversationChips | null> {
  const messages: RequestMessage[] = [];
  for (const m of conversation.messages) {
    let fact = facts.get(m.entry.id);
    if (!fact) {
      fact = readFact(m, conversation.ownDids, agents, queryClient);
      facts.set(m.entry.id, fact);
    }
    const f = await fact;
    // A message not read: the list says nothing rather than guess.
    if (f === "unreadable") return null;
    messages.push({
      id: m.entry.id,
      at: m.entry.created_at,
      mine: m.mine,
      verified: f.verified,
      protocol: f.protocol,
      auto_reply: m.mine
        ? null
        : { claimed_at: m.entry.auto_reply_claimed_at ?? null, sent_at: m.entry.auto_reply_sent_at ?? null },
    });
  }
  const out = conversationRequests(messages, new Date(now).toISOString());
  const waiting = out.requests.some((r) => r.state === "waiting_for_you");
  const unresolved = out.unverified.length > 0 || out.requests.some((r) => UNRESOLVED.includes(r.state));
  const inProgress = out.requests.filter(
    (r) => !isFinished(r.state) && !UNRESOLVED.includes(r.state) && r.state !== "waiting_for_you",
  ).length;
  return { waiting, inProgress, unresolved };
}
