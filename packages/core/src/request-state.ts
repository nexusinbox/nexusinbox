// Where each request in a conversation stands (docs/41 §7, stage C). One
// request is the message that opened it (schedule `propose`, task
// `delegate`) and every reply linked to it by `reply_to`. Only messages
// whose sender was verified count; the Web and the gateway feed this the
// same facts and must get the same answer (tests/vectors/request_state.json).
//
// What it never does: call a request finished because a message was sent,
// guess from free text, or read a whole conversation into one message.

/** How long after an executor took a message "the AI started" stays shown. */
export const AI_STARTED_WINDOW_MS = 3 * 60 * 1000;

export type RequestType = "schedule_negotiation" | "task_delegation";
export type RequestAction = "propose" | "counter" | "accept" | "decline" | "delegate" | "complete";

export type RequestMessage = {
  /** The message's id on the server. */
  id: string;
  /** When it was sent (RFC 3339). */
  at: string;
  /** Sent by the person's own agent. */
  mine: boolean;
  /** Its sender was verified (signature v2 and device list). */
  verified: boolean;
  /** The decrypted protocol block, or null for free text. */
  protocol: {
    id: string;
    type: RequestType;
    action: RequestAction;
    reply_to: string | null;
    payload?: {
      candidates?: { start: string; end: string }[];
      response_deadline?: string;
      selected_candidate?: { start: string; end: string };
      result?: string;
    };
  } | null;
  /** The automatic-reply record of a received message. */
  auto_reply?: { claimed_at?: string | null; sent_at?: string | null } | null;
};

export type RequestState =
  | "waiting_for_you"
  | "waiting_for_them"
  /** An executor took the message within the last few minutes: the AI started. */
  | "ai_started"
  /** An executor took it earlier and no reply is known: what happened since is unknown. */
  | "ai_unknown"
  /** The automatic reply went out but is not among these messages. */
  | "ai_replied"
  /** Task taken on; the completion report is still to come. */
  | "accepted"
  /** Schedule: a candidate was agreed on (not put in a calendar). */
  | "agreed"
  /** Task: the completion report came. */
  | "completed"
  | "declined"
  | "expired"
  /** Replies that cannot all be true (accept and decline, two candidates, …). */
  | "conflict"
  /** Replies whose request is not among these messages. */
  | "missing_original";

export type Actor = "you" | "them" | "ai" | "none";

export type RequestSummary = {
  /** The protocol id of the message that opened it (or the missing one replies point to). */
  request_id: string;
  type: RequestType;
  state: RequestState;
  next: Actor;
  /** The latest event that counted. */
  last: { message_id: string; action: RequestAction; at: string; mine: boolean };
  /** Every message the state rests on, oldest first. */
  evidence: string[];
  deadline: string | null;
  selected: { start: string; end: string } | null;
  result: string | null;
  /** When the executor took the message, for ai_started / ai_unknown. */
  ai_started_at: string | null;
  /** The request's first message is not among these messages. */
  history_incomplete: boolean;
};

export type ConversationRequests = {
  requests: RequestSummary[];
  /** Protocol messages left out because their sender was not verified. */
  unverified: string[];
};

const TERMINAL: Record<RequestType, RequestAction[]> = {
  schedule_negotiation: ["accept", "decline"],
  task_delegation: ["decline", "complete"],
};

const FINISHED: RequestState[] = ["agreed", "completed", "declined", "expired"];
const UNRESOLVED: RequestState[] = ["conflict", "missing_original"];

/** Finished requests are folded away; unresolved ones never are. */
export function isFinished(state: RequestState): boolean {
  return FINISHED.includes(state);
}
export function isUnresolved(state: RequestState): boolean {
  return UNRESOLVED.includes(state);
}

const ORDER: RequestState[] = [
  "conflict",
  "missing_original",
  "waiting_for_you",
  "ai_unknown",
  "ai_started",
  "ai_replied",
  "accepted",
  "waiting_for_them",
  "expired",
  "agreed",
  "completed",
  "declined",
];

type Event = { message: RequestMessage; protocol: NonNullable<RequestMessage["protocol"]>; ms: number };

/**
 * Read a time as the API prints it: RFC 3339, or Postgres text such as
 * `2026-11-16 11:57:00.123456+00` (the message index), which not every
 * JavaScript engine reads as is.
 */
export function parseTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const iso = value
    .trim()
    .replace(" ", "T")
    .replace(/(\.\d{3})\d+/, "$1")
    .replace(/([+-]\d{2})$/, "$1:00");
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}
const time = parseTime;

export function conversationRequests(messages: RequestMessage[], now: string): ConversationRequests {
  const nowMs = time(now) ?? 0;
  const unverified: string[] = [];
  // One event per protocol id: a message delivered again counts once.
  const byProtocol = new Map<string, Event>();
  const sorted = [...messages].sort((a, b) => (time(a.at) ?? 0) - (time(b.at) ?? 0) || a.id.localeCompare(b.id));
  for (const message of sorted) {
    const protocol = message.protocol;
    if (!protocol) continue;
    if (!message.verified) {
      unverified.push(message.id);
      continue;
    }
    if (!byProtocol.has(protocol.id)) byProtocol.set(protocol.id, { message, protocol, ms: time(message.at) ?? 0 });
  }

  // Follow reply_to back to the opening message (or to the missing one).
  const rootOf = (event: Event): { root: string; found: boolean } => {
    const seen = new Set<string>();
    let current = event;
    for (;;) {
      seen.add(current.protocol.id);
      const parent = current.protocol.reply_to;
      if (parent === null) return { root: current.protocol.id, found: true };
      const next = byProtocol.get(parent);
      if (!next) return { root: parent, found: false };
      if (seen.has(next.protocol.id)) return { root: next.protocol.id, found: false };
      current = next;
    }
  };

  const groups = new Map<string, { found: boolean; events: Event[] }>();
  for (const event of [...byProtocol.values()].sort((a, b) => a.ms - b.ms)) {
    const { root, found } = rootOf(event);
    const group = groups.get(root) ?? { found, events: [] };
    group.found = group.found && found;
    group.events.push(event);
    groups.set(root, group);
  }

  const requests: RequestSummary[] = [];
  for (const [root, group] of groups) {
    requests.push(summarise(root, group.found, group.events, nowMs));
  }
  requests.sort(
    (a, b) =>
      ORDER.indexOf(a.state) - ORDER.indexOf(b.state) || (time(b.last.at) ?? 0) - (time(a.last.at) ?? 0),
  );
  return { requests, unverified };
}

/**
 * A reply no valid exchange makes (review 2026-11-17): answering (or
 * countering) one's own offer or something that is not an offer, accepting
 * a slot the offer its reply_to names did not name, or a task taken
 * on, declined or reported done by the side that asked for it. A good
 * signature does not make such a step valid.
 */
function outOfTurn(type: RequestType, events: Event[]): boolean {
  if (type === "task_delegation") {
    const opener = events[0].message.mine;
    return events
      .slice(1)
      .some((e) => ["accept", "decline", "complete"].includes(e.protocol.action) && e.message.mine === opener);
  }
  const same = (a: { start: string; end: string }, b: { start: string; end: string }) => {
    const [as, ae, bs, be] = [time(a.start), time(a.end), time(b.start), time(b.end)];
    return as !== null && ae !== null && as === bs && ae === be;
  };
  // Each answer is checked against the offer its reply_to names, not the
  // latest one (review 2026-11-17).
  const byId = new Map(events.map((e) => [e.protocol.id, e]));
  for (const e of events) {
    const action = e.protocol.action;
    if (action !== "counter" && action !== "accept" && action !== "decline") continue;
    const offer = e.protocol.reply_to === null ? undefined : byId.get(e.protocol.reply_to);
    if (!offer || (offer.protocol.action !== "propose" && offer.protocol.action !== "counter")) return true;
    if (offer.message.mine === e.message.mine) return true;
    if (action === "accept") {
      const pick = e.protocol.payload?.selected_candidate;
      const offered = offer.protocol.payload?.candidates ?? [];
      if (!pick || !offered.some((c) => same(c, pick))) return true;
    }
  }
  return false;
}

function summarise(root: string, found: boolean, events: Event[], nowMs: number): RequestSummary {
  const type = events[0].protocol.type;
  const last = events[events.length - 1];
  const base: RequestSummary = {
    request_id: root,
    type,
    state: "waiting_for_them",
    next: "none",
    last: { message_id: last.message.id, action: last.protocol.action, at: last.message.at, mine: last.message.mine },
    evidence: events.map((e) => e.message.id),
    deadline: null,
    selected: null,
    result: null,
    ai_started_at: null,
    history_incomplete: !found,
  };
  const done = (state: RequestState, next: Actor = "none"): RequestSummary => ({ ...base, state, next });

  if (!found) return done("missing_original", "you");
  if (events.some((e) => e.protocol.type !== type)) return done("conflict", "you");
  if (outOfTurn(type, events)) return done("conflict", "you");

  const terminal = TERMINAL[type];
  const firstTerminal = events.findIndex((e) => terminal.includes(e.protocol.action));
  if (firstTerminal >= 0) {
    const after = events.slice(firstTerminal);
    const actions = new Set(after.map((e) => e.protocol.action));
    // After an ending, only the same ending may come again.
    if (actions.size > 1) return done("conflict", "you");
    const ending = after[0].protocol;
    if (type === "schedule_negotiation" && ending.action === "accept") {
      const picks = new Set(after.map((e) => JSON.stringify(e.protocol.payload?.selected_candidate ?? null)));
      if (picks.size > 1) return done("conflict", "you");
      return { ...done("agreed"), selected: ending.payload?.selected_candidate ?? null };
    }
    if (type === "task_delegation" && ending.action === "complete") {
      const declined = events.slice(0, firstTerminal).some((e) => e.protocol.action === "decline");
      if (declined) return done("conflict", "you");
      return { ...done("completed"), result: ending.payload?.result ?? null };
    }
    if (type === "task_delegation" && ending.action === "decline" && events.slice(0, firstTerminal).some((e) => e.protocol.action === "accept")) {
      return done("conflict", "you");
    }
    return done("declined");
  }

  // Still open.
  if (type === "task_delegation") {
    const accept = [...events].reverse().find((e) => e.protocol.action === "accept");
    if (accept) {
      // Whoever took it on reports completion.
      return done("accepted", accept.message.mine ? "you" : "them");
    }
  }

  const deadline = last.protocol.payload?.response_deadline ?? null;
  const deadlineMs = time(deadline);
  if (deadlineMs !== null && deadlineMs < nowMs) return { ...done("expired"), deadline };

  if (last.message.mine) return { ...done("waiting_for_them", "them"), deadline };

  // Theirs: the person's turn, unless an executor took it.
  const record = last.message.auto_reply;
  const claimed = time(record?.claimed_at);
  if (record?.sent_at) return { ...done("ai_replied"), deadline };
  if (claimed !== null) {
    const started = { deadline, ai_started_at: record?.claimed_at ?? null };
    return nowMs - claimed <= AI_STARTED_WINDOW_MS
      ? { ...done("ai_started", "ai"), ...started }
      : { ...done("ai_unknown", "you"), ...started };
  }
  return { ...done("waiting_for_you", "you"), deadline };
}
