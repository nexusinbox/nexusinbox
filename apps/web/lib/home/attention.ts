// What needs the person on Home (docs/41 §6.1–§6.2): one list built from
// the existing notices and the old 「確認が必要」 page. Pure ordering and
// counting here; gathering the device checks is in collectDeviceAttention.

import type { Agent, AgentDevice, AgentDraft, MessageIndexEntry } from "../api/types";

export type AttentionItem =
  /** A device list that does not verify, or names a device with another key. */
  | { kind: "list_wrong"; agent: Agent; changed: AgentDevice[] }
  /** Computers whose keys are not the ones the connect code was typed on. */
  | { kind: "pairing_mismatch"; agent: Agent; devices: AgentDevice[] }
  | { kind: "new_device"; agent: Agent; devices: AgentDevice[]; rootHere: boolean }
  /** No device chosen to receive yet: messages cannot reach the agent. */
  | { kind: "list_undecided"; agent: Agent }
  | { kind: "draft"; draft: AgentDraft }
  /** A message held for the person to let in (the old 「確認が必要」). */
  | { kind: "held"; message: MessageIndexEntry }
  | { kind: "computer_stopped"; agent: Agent; device: AgentDevice; since: number };

export type AttentionKind = AttentionItem["kind"];

/** How the breakdown under the count names each kind (i18n key suffix). */
export type AttentionGroup = "device_check" | "new_device" | "undelivered" | "send" | "receive" | "stopped";

export function groupOf(kind: AttentionKind): AttentionGroup {
  switch (kind) {
    case "list_wrong":
    case "pairing_mismatch":
      return "device_check";
    case "new_device":
      return "new_device";
    case "list_undecided":
      return "undelivered";
    case "draft":
      return "send";
    case "held":
      return "receive";
    case "computer_stopped":
      return "stopped";
  }
}

// Trust warnings first, then what keeps messages from arriving, then the
// person's own decisions, then the computer (docs/41 §6.2).
const RANK: Record<AttentionKind, number> = {
  list_wrong: 0,
  pairing_mismatch: 0,
  new_device: 1,
  list_undecided: 2,
  draft: 3,
  held: 4,
  computer_stopped: 5,
};

/** Only these can be put off with 「あとで」 (docs/41 §6.1.1). */
export function canPutOff(kind: AttentionKind): boolean {
  return kind === "list_undecided" || kind === "computer_stopped";
}

/** The same problem has the same key, however often it is looked up. */
export function attentionKey(item: AttentionItem): string {
  switch (item.kind) {
    case "draft":
      return `draft:${item.draft.id}`;
    case "held":
      return `held:${item.message.id}`;
    case "computer_stopped":
      return `computer_stopped:${item.device.did}`;
    default:
      return `${item.kind}:${item.agent.aid}`;
  }
}

export type Arranged = {
  /** Counted and shown first, in order. */
  now: AttentionItem[];
  /** Put off: not counted, still listed at the end. */
  later: AttentionItem[];
  /** How many of `now` in each group, in the order they first appear. */
  breakdown: Array<{ group: AttentionGroup; n: number }>;
  /** What needs the person, counted: `now`, plus what is counted but not read yet. */
  count: number;
  /** Narrowed to one agent: what is not read yet cannot be told apart. */
  narrowed?: boolean;
};

export function arrangeAttention(
  items: AttentionItem[],
  putOff: (item: AttentionItem) => boolean,
): Arranged {
  const seen = new Set<string>();
  const unique: AttentionItem[] = [];
  for (const item of items) {
    const key = attentionKey(item);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(item);
  }
  // Stable: items of one kind keep the order they came in.
  const sorted = unique.map((item, i) => ({ item, i })).sort((a, b) => RANK[a.item.kind] - RANK[b.item.kind] || a.i - b.i).map((x) => x.item);
  const now: AttentionItem[] = [];
  const later: AttentionItem[] = [];
  for (const item of sorted) {
    if (canPutOff(item.kind) && putOff(item)) later.push(item);
    else now.push(item);
  }
  return { now, later, breakdown: breakdownOf(now), count: now.length };
}

function breakdownOf(now: AttentionItem[]): Arranged["breakdown"] {
  const breakdown: Arranged["breakdown"] = [];
  for (const item of now) {
    const group = groupOf(item.kind);
    const entry = breakdown.find((b) => b.group === group);
    if (entry) entry.n += 1;
    else breakdown.push({ group, n: 1 });
  }
  return breakdown;
}

/** Only the items `keep` says, counted again (Home's agent picker). */
export function narrowAttention(arranged: Arranged, keep: (item: AttentionItem) => boolean): Arranged {
  const now = arranged.now.filter(keep);
  return { now, later: arranged.later.filter(keep), breakdown: breakdownOf(now), count: now.length, narrowed: true };
}

/** The person's agent an item is about, if it can be told. */
export function agentOfItem(item: AttentionItem, agents: Agent[]): Agent | null {
  if ("agent" in item) return item.agent;
  const did = item.kind === "draft" ? item.draft.sender_did : item.message.recipient_did;
  return agents.find((a) => a.did === did || (a.dids ?? []).includes(did)) ?? null;
}

/** Unread pages still count: in the total and in the 受信の許可 part of the breakdown. */
export function withUnloaded(arranged: Arranged, unloaded: number): Arranged {
  if (unloaded === 0) return arranged;
  const breakdown = arranged.breakdown.some((b) => b.group === "receive")
    ? arranged.breakdown.map((b) => (b.group === "receive" ? { ...b, n: b.n + unloaded } : b))
    : [...arranged.breakdown, { group: "receive" as const, n: unloaded }];
  return { ...arranged, count: arranged.count + unloaded, breakdown };
}
