import { describe, expect, it } from "vitest";
import type { Agent, MessageIndexEntry } from "../api/types";
import {
  avatarColorIndex,
  avatarInitial,
  groupConversations,
  previewSnippet,
  relativeAge,
  rowsForView,
} from "./conversations";

function agent(did: string, label: string, dids?: string[]): Agent {
  return {
    id: "id-" + did,
    aid: "aid:" + did,
    did,
    label,
    is_active: true,
    auto_reply: false,
    unread_count: 0,
    created_at: "2026-11-01T00:00:00Z",
    dids,
  };
}

function msg(overrides: Partial<MessageIndexEntry> & { id: string }): MessageIndexEntry {
  return {
    sender_did: "did:them",
    sender_label: null,
    recipient_did: "did:me",
    recipient_label: null,
    thread_id: null,
    subject_encrypted: "",
    status: "read",
    priority: "normal",
    ai_category: null,
    created_at: "2026-11-09T10:00:00Z",
    trust_score: 0,
    folder: "inbox",
    starred: false,
    ...overrides,
  };
}

const me = agent("did:me", "秘書", ["did:me", "did:me-pc"]);
const other = agent("did:me2", "経理");

describe("groupConversations", () => {
  it("puts received and sent messages with the same counterpart together", () => {
    const list = groupConversations(
      [
        msg({ id: "r1", created_at: "2026-11-09T10:00:00Z", thread_id: "t1" }),
        msg({
          id: "s1",
          sender_did: "did:me",
          recipient_did: "did:them",
          folder: "sent",
          created_at: "2026-11-09T11:00:00Z",
          thread_id: "t1",
        }),
      ],
      [me],
    );
    expect(list).toHaveLength(1);
    const c = list[0];
    expect(c.counterpartDid).toBe("did:them");
    expect(c.ownAgent?.label).toBe("秘書");
    expect(c.messages.map((m) => [m.entry.id, m.mine])).toEqual([
      ["r1", false],
      ["s1", true],
    ]);
    expect(c.latest.entry.id).toBe("s1");
    expect(c.latestReceived?.id).toBe("r1");
    expect(c.threadId).toBe("t1");
  });

  it("maps every DID of an own agent to the same conversation", () => {
    const list = groupConversations(
      [
        msg({ id: "a", recipient_did: "did:me" }),
        msg({ id: "b", recipient_did: "did:me-pc", created_at: "2026-11-09T12:00:00Z" }),
      ],
      [me],
    );
    expect(list).toHaveLength(1);
    expect(list[0].ownDids).toEqual(["did:me", "did:me-pc"]);
    expect(list[0].ownDid).toBe("did:me-pc");
  });

  it("keeps different own agents apart", () => {
    const list = groupConversations(
      [msg({ id: "a" }), msg({ id: "b", recipient_did: "did:me2" })],
      [me, other],
    );
    expect(list).toHaveLength(2);
  });

  it("counts unread received messages and the auto-reply flag", () => {
    const [c] = groupConversations(
      [
        msg({ id: "a", status: "unread" }),
        msg({ id: "b", status: "unread", auto_reply_message_id: "x" }),
        msg({ id: "c", status: "read" }),
      ],
      [me],
    );
    expect(c.unread).toBe(2);
    expect(c.autoReplied).toBe(true);
  });

  it("sorts conversations by their latest message, newest first", () => {
    const list = groupConversations(
      [
        msg({ id: "old", sender_did: "did:a", created_at: "2026-11-01T00:00:00Z" }),
        msg({ id: "new", sender_did: "did:b", created_at: "2026-11-08T00:00:00Z" }),
      ],
      [me],
    );
    expect(list.map((c) => c.counterpartDid)).toEqual(["did:b", "did:a"]);
  });

  it("de-duplicates a row present in both the inbox and sent lists", () => {
    const row = msg({ id: "x", sender_did: "did:me2", recipient_did: "did:me" });
    const list = groupConversations([row, row], [me, other]);
    // Seen from both own agents, once each.
    expect(list).toHaveLength(2);
    const received = list.find((c) => c.ownAgent?.did === "did:me");
    const sent = list.find((c) => c.ownAgent?.did === "did:me2");
    expect(received?.messages).toEqual([{ entry: row, mine: false }]);
    expect(sent?.messages).toEqual([{ entry: row, mine: true }]);
  });

  it("shows an agent writing to itself once, as received", () => {
    const row = msg({ id: "self", sender_did: "did:me", recipient_did: "did:me", status: "unread" });
    const list = groupConversations([row], [me]);
    expect(list).toHaveLength(1);
    expect(list[0].messages).toEqual([{ entry: row, mine: false }]);
    expect(list[0].unread).toBe(1);
  });
});

describe("rowsForView", () => {
  const sentActive = msg({ id: "s1", sender_did: "did:me", folder: "sent" });
  const sentArchived = msg({ id: "s2", sender_did: "did:me", folder: "sent", status: "archived" });
  const sentTrash = msg({ id: "s3", sender_did: "did:me", folder: "trash" });

  it("keeps archived and binned sent copies out of the main list", () => {
    const rows = rowsForView([msg({ id: "r" })], [sentActive, sentArchived, sentTrash], "main");
    expect(rows.map((m) => m.id)).toEqual(["r", "s1"]);
  });

  it("shows only archived sent copies in the archive", () => {
    const rows = rowsForView([], [sentActive, sentArchived, sentTrash], "archive");
    expect(rows.map((m) => m.id)).toEqual(["s2"]);
  });
});

describe("helpers", () => {
  it("gives a stable avatar colour in range", () => {
    expect(avatarColorIndex("did:key:abc")).toBe(avatarColorIndex("did:key:abc"));
    for (const did of ["a", "did:key:z6Mk", "did:them", ""]) {
      const i = avatarColorIndex(did);
      expect(i).toBeGreaterThanOrEqual(0);
      expect(i).toBeLessThan(6);
    }
  });

  it("matches the API's avatar_color for public pages", () => {
    // Same vectors as avatar_color_index in services/api/src/lib.rs.
    expect(avatarColorIndex("did:key:a")).toBe(3);
    expect(avatarColorIndex("did:key:b")).toBe(4);
    expect(avatarColorIndex("did:key:c")).toBe(5);
    expect(
      avatarColorIndex("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
    ).toBe(5);
  });

  it("takes the first character for the avatar", () => {
    expect(avatarInitial("山田さんの秘書")).toBe("山");
    expect(avatarInitial(" bob")).toBe("B");
    expect(avatarInitial("")).toBe("?");
  });

  it("clips the preview to the first line", () => {
    expect(previewSnippet("\n  hello   world \nsecond")).toBe("hello world");
    expect(previewSnippet("abcdef", 3)).toBe("abc…");
    expect(previewSnippet("   ")).toBe("");
  });

  it("describes how long ago", () => {
    const now = new Date("2026-11-09T12:00:00");
    expect(relativeAge("2026-11-09T11:59:40", now)).toEqual({ kind: "now" });
    expect(relativeAge("2026-11-09T11:58:00", now)).toEqual({ kind: "minutes", n: 2 });
    expect(relativeAge("2026-11-09T09:00:00", now)).toEqual({ kind: "hours", n: 3 });
    expect(relativeAge("2026-11-08T09:00:00", now)).toEqual({ kind: "yesterday" });
    expect(relativeAge("2026-11-01T09:00:00", now)).toEqual({ kind: "date" });
  });
});
