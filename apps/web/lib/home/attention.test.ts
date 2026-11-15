import { describe, expect, it } from "vitest";
import type { Agent, AgentDevice, AgentDraft, MessageIndexEntry } from "../api/types";
import { arrangeAttention, attentionKey, narrowAttention, withUnloaded, type AttentionItem } from "./attention";

const agent = (aid: string) => ({ aid, did: `did:key:${aid}`, label: aid }) as unknown as Agent;
const device = (did: string) => ({ did, kind: "computer" }) as unknown as AgentDevice;
const draft = (id: string) => ({ id }) as unknown as AgentDraft;
const message = (id: string) => ({ id }) as unknown as MessageIndexEntry;

const a = agent("a");
const b = agent("b");
const items: AttentionItem[] = [
  { kind: "computer_stopped", agent: a, device: device("pc1"), since: 1 },
  { kind: "held", message: message("m1") },
  { kind: "draft", draft: draft("d1") },
  { kind: "list_undecided", agent: b },
  { kind: "new_device", agent: a, devices: [device("p2")], rootHere: true },
  { kind: "draft", draft: draft("d2") },
  { kind: "list_wrong", agent: b, changed: [] },
];

describe("arrangeAttention", () => {
  it("puts trust warnings first and keeps the order within a kind", () => {
    const { now, later } = arrangeAttention(items, () => false);
    expect(now.map(attentionKey)).toEqual([
      "list_wrong:b",
      "new_device:a",
      "list_undecided:b",
      "draft:d1",
      "draft:d2",
      "held:m1",
      "computer_stopped:pc1",
    ]);
    expect(later).toEqual([]);
  });

  it("counts the same problem once", () => {
    const { now } = arrangeAttention([...items, { kind: "draft", draft: draft("d1") }], () => false);
    expect(now.filter((i) => i.kind === "draft")).toHaveLength(2);
  });

  it("moves what was put off to the end, uncounted, but only the kinds that allow it", () => {
    const { now, later, breakdown } = arrangeAttention(items, () => true);
    expect(later.map(attentionKey)).toEqual(["list_undecided:b", "computer_stopped:pc1"]);
    expect(now.map((i) => i.kind)).toEqual(["list_wrong", "new_device", "draft", "draft", "held"]);
    expect(breakdown).toEqual([
      { group: "device_check", n: 1 },
      { group: "new_device", n: 1 },
      { group: "send", n: 2 },
      { group: "receive", n: 1 },
    ]);
  });
});

describe("withUnloaded", () => {
  it("counts held messages the server has but the page has not read", () => {
    const arranged = withUnloaded(arrangeAttention(items, () => false), 120);
    expect(arranged.count).toBe(items.length + 120);
    expect(arranged.breakdown.find((b) => b.group === "receive")).toEqual({ group: "receive", n: 121 });
  });

  it("adds 受信の許可 to the breakdown when none of it was read", () => {
    const arranged = withUnloaded(arrangeAttention([], () => false), 3);
    expect(arranged).toMatchObject({ count: 3, breakdown: [{ group: "receive", n: 3 }] });
  });

  it("leaves what was not read out of one agent's count", () => {
    const all = withUnloaded(arrangeAttention(items, () => false), 5);
    const one = narrowAttention(all, (i) => "agent" in i && i.agent.aid === "b");
    expect(one).toMatchObject({ count: 2, narrowed: true });
  });
});
