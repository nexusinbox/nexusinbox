import { describe, expect, it } from "vitest";
import type { MessageIndexEntry } from "../api/types";
import { groupMessagesByThread } from "./group-by-thread";

function msg(overrides: Partial<MessageIndexEntry>): MessageIndexEntry {
  return {
    id: overrides.id ?? "m-1",
    sender_did: overrides.sender_did ?? "did:key:zSender",
    sender_label: overrides.sender_label ?? null,
    recipient_did: overrides.recipient_did ?? "did:key:zRecipient",
    recipient_label: overrides.recipient_label ?? null,
    thread_id: overrides.thread_id ?? null,
    subject_encrypted: overrides.subject_encrypted ?? "ENC",
    status: overrides.status ?? "read",
    priority: overrides.priority ?? "normal",
    ai_category: overrides.ai_category ?? null,
    created_at: overrides.created_at ?? "2026-05-01T00:00:00Z",
    trust_score: overrides.trust_score ?? 0.5,
    folder: overrides.folder ?? "inbox",
    starred: overrides.starred ?? false,
    auto_reply_decision: overrides.auto_reply_decision,
    auto_reply_reason: overrides.auto_reply_reason,
    auto_reply_sent_at: overrides.auto_reply_sent_at,
  };
}

describe("groupMessagesByThread", () => {
  it("returns an empty array for an empty input", () => {
    expect(groupMessagesByThread([])).toEqual([]);
  });

  it("treats each thread_id-less message as its own group", () => {
    const groups = groupMessagesByThread([
      msg({ id: "m-1", thread_id: null, created_at: "2026-05-01T00:00:00Z" }),
      msg({ id: "m-2", thread_id: null, created_at: "2026-05-02T00:00:00Z" }),
    ]);
    expect(groups).toHaveLength(2);
    expect(groups.map((g) => g.count)).toEqual([1, 1]);
    expect(groups.map((g) => g.representative.id)).toEqual(["m-2", "m-1"]);
  });

  it("collapses messages sharing a thread_id into one group", () => {
    const groups = groupMessagesByThread([
      msg({ id: "m-1", thread_id: "t-A", created_at: "2026-05-01T10:00:00Z" }),
      msg({ id: "m-2", thread_id: "t-A", created_at: "2026-05-02T10:00:00Z" }),
      msg({ id: "m-3", thread_id: "t-A", created_at: "2026-05-03T10:00:00Z" }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.count).toBe(3);
    // Representative is the newest message in the group.
    expect(groups[0]?.representative.id).toBe("m-3");
    // Inner messages are newest-first.
    expect(groups[0]?.messages.map((m) => m.id)).toEqual([
      "m-3",
      "m-2",
      "m-1",
    ]);
  });

  it("sorts groups by representative's created_at, newest first", () => {
    const groups = groupMessagesByThread([
      msg({ id: "old", thread_id: "t-old", created_at: "2026-05-01T00:00:00Z" }),
      msg({ id: "new", thread_id: "t-new", created_at: "2026-05-05T00:00:00Z" }),
      msg({ id: "mid", thread_id: "t-mid", created_at: "2026-05-03T00:00:00Z" }),
    ]);
    expect(groups.map((g) => g.representative.id)).toEqual([
      "new",
      "mid",
      "old",
    ]);
  });

  it("flags hasUnread when ANY message in the group is unread", () => {
    const groups = groupMessagesByThread([
      msg({
        id: "m-1",
        thread_id: "t-A",
        created_at: "2026-05-01T00:00:00Z",
        status: "unread",
      }),
      msg({
        id: "m-2",
        thread_id: "t-A",
        created_at: "2026-05-02T00:00:00Z",
        status: "read",
      }),
    ]);
    expect(groups[0]?.hasUnread).toBe(true);
  });

  it("clears hasUnread only when every message is read", () => {
    const groups = groupMessagesByThread([
      msg({
        id: "m-1",
        thread_id: "t-A",
        created_at: "2026-05-01T00:00:00Z",
        status: "read",
      }),
      msg({
        id: "m-2",
        thread_id: "t-A",
        created_at: "2026-05-02T00:00:00Z",
        status: "read",
      }),
    ]);
    expect(groups[0]?.hasUnread).toBe(false);
  });

  it("does not merge two singleton messages that share an id with a thread", () => {
    // Pure singletons (no thread_id) must not coalesce just because
    // their ids happen to be similar — the synthetic key per-id keeps
    // them distinct.
    const groups = groupMessagesByThread([
      msg({ id: "m-1", thread_id: null, created_at: "2026-05-01T00:00:00Z" }),
      msg({ id: "m-2", thread_id: null, created_at: "2026-05-02T00:00:00Z" }),
      // A real thread alongside the singletons:
      msg({ id: "m-3", thread_id: "t-X", created_at: "2026-05-03T00:00:00Z" }),
      msg({ id: "m-4", thread_id: "t-X", created_at: "2026-05-04T00:00:00Z" }),
    ]);
    expect(groups).toHaveLength(3);
    const counts = groups.map((g) => g.count).sort();
    expect(counts).toEqual([1, 1, 2]);
  });
});
