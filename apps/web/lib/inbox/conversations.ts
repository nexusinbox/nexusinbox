// Group messages into conversations: one per (own agent, counterpart)
// pair, as in a DM list (docs/35 §2 "メッセージ"). Pure, so it is unit
// tested without React.

import type { Agent, MessageIndexEntry } from "../api/types";

export type ConversationMessage = {
  entry: MessageIndexEntry;
  /** True when one of the person's own agents sent it. */
  mine: boolean;
};

export type Conversation = {
  /** Stable id: own agent + counterpart. */
  key: string;
  /** The own DID used by the latest message (sender of mine, recipient of theirs). */
  ownDid: string;
  /** Every DID of the own agent (one, or two when a computer is connected). */
  ownDids: string[];
  ownAgent: Agent | undefined;
  counterpartDid: string;
  /** Oldest first. */
  messages: ConversationMessage[];
  latest: ConversationMessage;
  /** Newest message the counterpart sent, if any. */
  latestReceived: MessageIndexEntry | null;
  /** Received messages still unread. */
  unread: number;
  /** An automatic reply went out for one of the received messages. */
  autoReplied: boolean;
  /** thread_id of the latest message that has one. */
  threadId: string | null;
};

/** The agent a DID belongs to: its created-with DID or a computer's. */
function ownerOf(agents: Agent[], did: string): Agent | undefined {
  return agents.find((a) => a.did === did || a.dids?.includes(did));
}

function agentDids(agent: Agent): string[] {
  return Array.from(new Set([agent.did, ...(agent.dids ?? [])]));
}

/**
 * Group message rows into conversations, newest conversation first.
 *
 * A received row (recipient is one of the person's agents) belongs to
 * (recipient, sender); a sent row (sender is theirs) to (sender, recipient).
 * A message between two of the person's own agents shows up from both
 * sides, except an agent writing to itself, which is shown once as received.
 * Rows are de-duplicated by id, so the inbox and sent lists can be merged
 * as they are.
 */
export function groupConversations(
  entries: MessageIndexEntry[],
  agents: Agent[],
): Conversation[] {
  type Draft = {
    ownAgent: Agent | undefined;
    ownDids: string[];
    counterpartDid: string;
    byId: Map<string, ConversationMessage>;
  };
  const groups = new Map<string, Draft>();
  const seen = new Set<string>();

  const add = (ownDid: string, counterpartDid: string, entry: MessageIndexEntry, mine: boolean) => {
    const ownAgent = ownerOf(agents, ownDid);
    const ownKey = ownAgent ? ownAgent.did : ownDid;
    // The counterpart may be another of the person's agents: fold its DIDs too.
    const counterpartAgent = ownerOf(agents, counterpartDid);
    const counterpartKey = counterpartAgent ? counterpartAgent.did : counterpartDid;
    const key = ownKey + "|" + counterpartKey;
    let group = groups.get(key);
    if (!group) {
      group = {
        ownAgent,
        ownDids: ownAgent ? agentDids(ownAgent) : [ownDid],
        counterpartDid: counterpartKey,
        byId: new Map(),
      };
      groups.set(key, group);
    }
    // Received wins over sent for the same row (an agent writing to itself).
    if (!group.byId.has(entry.id) || !mine) {
      group.byId.set(entry.id, { entry, mine });
    }
  };

  for (const entry of entries) {
    if (seen.has(entry.id)) continue;
    seen.add(entry.id);
    const recipientOwn = Boolean(ownerOf(agents, entry.recipient_did));
    const senderOwn = Boolean(ownerOf(agents, entry.sender_did));
    // A sender-side bookkeeping copy is in the "sent" folder.
    if (recipientOwn && entry.folder !== "sent") {
      add(entry.recipient_did, entry.sender_did, entry, false);
    }
    if (senderOwn) {
      add(entry.sender_did, entry.recipient_did, entry, true);
    }
    if (!recipientOwn && !senderOwn) {
      // Agents not loaded yet: fall back to the folder.
      if (entry.folder === "sent") add(entry.sender_did, entry.recipient_did, entry, true);
      else add(entry.recipient_did, entry.sender_did, entry, false);
    }
  }

  const conversations: Conversation[] = [];
  for (const [key, group] of groups) {
    const messages = Array.from(group.byId.values()).sort((a, b) =>
      a.entry.created_at.localeCompare(b.entry.created_at),
    );
    const latest = messages[messages.length - 1];
    const received = messages.filter((m) => !m.mine);
    const withThread = [...messages].reverse().find((m) => m.entry.thread_id);
    conversations.push({
      key,
      ownDid: latest.mine ? latest.entry.sender_did : latest.entry.recipient_did,
      ownDids: group.ownDids,
      ownAgent: group.ownAgent,
      counterpartDid: group.counterpartDid,
      messages,
      latest,
      latestReceived: received.length > 0 ? received[received.length - 1].entry : null,
      unread: received.filter((m) => m.entry.status === "unread").length,
      autoReplied: received.some((m) => Boolean(m.entry.auto_reply_message_id)),
      threadId: withThread?.entry.thread_id ?? null,
    });
  }
  return conversations.sort((a, b) =>
    b.latest.entry.created_at.localeCompare(a.latest.entry.created_at),
  );
}

/**
 * Pick the rows a view shows from the received list (fetched by folder) and
 * the sent list (the server returns every row an own agent sent, whatever
 * its folder). Archiving keeps a sent copy in "sent" with status "archived".
 */
export function rowsForView(
  received: MessageIndexEntry[],
  sent: MessageIndexEntry[],
  view: "main" | "archive",
): MessageIndexEntry[] {
  const hidden = new Set(["spam", "trash"]);
  const sentRows = sent.filter((m) => {
    if (hidden.has(m.folder)) return false;
    const archived = m.status === "archived" || m.folder === "archive";
    return view === "archive" ? archived : !archived;
  });
  return [...received, ...sentRows];
}

/** A stable avatar colour (0–5) per DID. */
export function avatarColorIndex(did: string): number {
  let hash = 0;
  for (let i = 0; i < did.length; i += 1) {
    hash = (hash * 31 + did.charCodeAt(i)) >>> 0;
  }
  return hash % 6;
}

/** The first character of a name, for the round avatar. */
export function avatarInitial(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return "?";
  return Array.from(trimmed)[0].toUpperCase();
}

/**
 * One line of a decrypted body for the list: first non-empty line,
 * whitespace collapsed, clipped to `maxChars`.
 */
export function previewSnippet(body: string, maxChars = 140): string {
  const firstLine =
    body
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line.length > 0) ?? "";
  const collapsed = firstLine.replace(/\s+/g, " ").trim();
  if (collapsed.length === 0) return "";
  return collapsed.length > maxChars ? collapsed.slice(0, maxChars).trimEnd() + "…" : collapsed;
}

export type RelativeAge =
  | { kind: "now" }
  | { kind: "minutes"; n: number }
  | { kind: "hours"; n: number }
  | { kind: "yesterday" }
  | { kind: "date" };

/** How long ago, in the units the list shows (2分, 1時間, 昨日, then a date). */
export function relativeAge(isoText: string, now: Date = new Date()): RelativeAge {
  const date = new Date(isoText);
  if (Number.isNaN(date.getTime())) return { kind: "date" };
  const minutes = Math.floor((now.getTime() - date.getTime()) / 60_000);
  if (minutes < 1) return { kind: "now" };
  if (minutes < 60) return { kind: "minutes", n: minutes };
  if (date.toDateString() === now.toDateString()) {
    return { kind: "hours", n: Math.floor(minutes / 60) };
  }
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) return { kind: "yesterday" };
  return { kind: "date" };
}
