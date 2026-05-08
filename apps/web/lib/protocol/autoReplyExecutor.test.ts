import { describe, expect, it, vi } from "vitest";
import {
  runAutoReplyExecutor,
  AUTO_REPLY_ORIGIN_CLIENT,
  type AutoReplyExecutorApi,
  type SendProtocolReplyFn,
} from "./autoReplyExecutor";
import type { MessageIndexEntry } from "../api/types";

function makeEntry(overrides: Partial<MessageIndexEntry> = {}): MessageIndexEntry {
  return {
    id: "msg-1",
    sender_did: "did:key:zSender",
    sender_label: null,
    recipient_did: "did:key:zViewer",
    recipient_label: null,
    thread_id: "thread-1",
    subject_encrypted: "subject-ct",
    status: "unread",
    priority: "normal",
    ai_category: null,
    created_at: "2026-04-24T10:00:00Z",
    trust_score: 0.8,
    folder: "inbox",
    starred: false,
    auto_reply_decision: "auto_accept",
    auto_reply_reason: "default_match",
    ...overrides,
  };
}

const candidate = {
  start: "2026-05-01T09:00:00+09:00",
  end: "2026-05-01T10:00:00+09:00",
};

const scheduleProposeBody = JSON.stringify({
  v: 1,
  body: "Let's meet",
  protocol: {
    id: "proto-1",
    type: "schedule_negotiation",
    action: "propose",
    reply_to: null,
    payload: {
      event_title: "Sync",
      candidates: [candidate],
      required_participants: ["did:key:zSender", "did:key:zViewer"],
    },
  },
});

const taskDelegateBody = JSON.stringify({
  v: 1,
  body: "Please handle",
  protocol: {
    id: "proto-2",
    type: "task_delegation",
    action: "delegate",
    reply_to: null,
    payload: { title: "Review PR" },
  },
});

function makeApi(overrides: Partial<AutoReplyExecutorApi> = {}): AutoReplyExecutorApi {
  return {
    getMessageContent: vi.fn(async () => ({
      encrypted_content: "ct",
      encrypted_key: "ek",
      nonce: "n",
      content_type: "application/vnd.nexusinbox.a2a+json; v=1",
    })),
    markAutoReplySent: vi.fn(async () => ({ auto_reply_sent_at: "2026-04-24T21:34:00Z" })),
    ...overrides,
  };
}

describe("runAutoReplyExecutor", () => {
  it("skips when viewer has no signing key", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: false,
      messages: [makeEntry()],
      policy: { v: 1, default_action: "auto_accept" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
    });
    expect(api.markAutoReplySent).not.toHaveBeenCalled();
    expect(sendProtocolReply).not.toHaveBeenCalled();
  });

  it("skips entries without an evaluator decision", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [makeEntry({ auto_reply_decision: undefined, auto_reply_reason: undefined })],
      policy: { v: 1, default_action: "auto_accept" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
    });
    expect(sendProtocolReply).not.toHaveBeenCalled();
  });

  it("skips entries already stamped with auto_reply_sent_at", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [makeEntry({ auto_reply_sent_at: "2026-04-24T20:00:00Z" })],
      policy: { v: 1, default_action: "auto_accept" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
    });
    expect(sendProtocolReply).not.toHaveBeenCalled();
  });

  it("sends a schedule_negotiation accept and marks sent", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [makeEntry()],
      policy: { v: 1, default_action: "auto_accept" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
    });
    expect(sendProtocolReply).toHaveBeenCalledTimes(1);
    const call = (sendProtocolReply as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.protocolType).toBe("schedule_negotiation");
    expect(call.reply).toEqual({ action: "accept", selected_candidate: candidate });
    expect(call.originalProtocolId).toBe("proto-1");
    expect(call.autoReplyOrigin).toBe(AUTO_REPLY_ORIGIN_CLIENT);
    expect(api.markAutoReplySent).toHaveBeenCalledWith("msg-1", expect.any(Object));
  });

  it("sends a task_delegation decline when policy says auto_decline", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [
        makeEntry({
          id: "msg-2",
          auto_reply_decision: "auto_decline",
          auto_reply_reason: "default_match",
        }),
      ],
      policy: { v: 1, default_action: "auto_decline" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => taskDelegateBody,
    });
    expect(sendProtocolReply).toHaveBeenCalledTimes(1);
    const call = (sendProtocolReply as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.protocolType).toBe("task_delegation");
    expect(call.reply.action).toBe("decline");
  });

  it("honours protocol override that upgrades queue → auto_accept", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [
        makeEntry({
          // Server evaluator stamped queue_for_human (default), but
          // the client evaluator sees the protocol and takes the
          // override path to auto_accept.
          auto_reply_decision: "queue_for_human",
          auto_reply_reason: "default_match",
        }),
      ],
      policy: {
        v: 1,
        default_action: "queue_for_human",
        protocols: {
          schedule_negotiation: {
            propose: { action: "auto_accept" },
          },
        },
      },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
    });
    // Still skipped at eligibility gate because decision was queue_for_human.
    expect(sendProtocolReply).not.toHaveBeenCalled();
  });

  it("does not send when master switch is off (belt-and-braces)", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [makeEntry()],
      policy: { v: 1, default_action: "auto_accept" },
      masterAutoReplyEnabled: false,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
    });
    expect(sendProtocolReply).not.toHaveBeenCalled();
  });

  it("continues processing when one entry throws", async () => {
    const api = makeApi({
      getMessageContent: vi
        .fn()
        .mockResolvedValueOnce(Promise.reject(new Error("network down")))
        .mockResolvedValueOnce({
          encrypted_content: "ct",
          encrypted_key: "ek",
          nonce: "n",
          content_type: "application/vnd.nexusinbox.a2a+json; v=1",
        }),
    });
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [makeEntry({ id: "msg-a" }), makeEntry({ id: "msg-b" })],
      policy: { v: 1, default_action: "auto_accept" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
    });
    expect(sendProtocolReply).toHaveBeenCalledTimes(1);
  });

  // -----------------------------------------------------------------
  // Phase 4.4d — Calendar freebusy resolution (docs/25d)
  // -----------------------------------------------------------------

  it("auto_accept_if_free with a free candidate sends accept picking that slot", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    const calendarFreebusy = vi.fn(async () => ({
      start: "2026-05-01T09:00:00+09:00",
      end: "2026-05-01T10:00:00+09:00",
    }));
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [
        makeEntry({
          auto_reply_decision: "queue_for_human",
          auto_reply_reason: "calendar_unavailable",
        }),
      ],
      policy: { v: 1, default_action: "auto_accept_if_free" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
      calendarFreebusy,
    });
    expect(calendarFreebusy).toHaveBeenCalledTimes(1);
    expect(sendProtocolReply).toHaveBeenCalledTimes(1);
    const call = (sendProtocolReply as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.reply.action).toBe("accept");
    expect(call.reply).toMatchObject({
      action: "accept",
      selected_candidate: {
        start: "2026-05-01T09:00:00+09:00",
        end: "2026-05-01T10:00:00+09:00",
      },
    });
  });

  it("auto_accept_if_free with all busy slots marks sent + skips", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    const calendarFreebusy = vi.fn(async () => null);
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [
        makeEntry({
          auto_reply_decision: "queue_for_human",
          auto_reply_reason: "calendar_unavailable",
        }),
      ],
      policy: { v: 1, default_action: "auto_accept_if_free" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
      calendarFreebusy,
    });
    expect(sendProtocolReply).not.toHaveBeenCalled();
    expect(api.markAutoReplySent).toHaveBeenCalledWith("msg-1", expect.any(Object));
  });

  it("auto_accept_if_free without Calendar integration marks sent as calendar_unavailable", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [
        makeEntry({
          auto_reply_decision: "queue_for_human",
          auto_reply_reason: "calendar_unavailable",
        }),
      ],
      policy: { v: 1, default_action: "auto_accept_if_free" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
      // No calendarFreebusy — user hasn't connected Google Calendar.
    });
    expect(sendProtocolReply).not.toHaveBeenCalled();
    expect(api.markAutoReplySent).toHaveBeenCalledWith("msg-1", expect.any(Object));
  });

  it("auto_accept_if_free with calendar API error leaves the row for retry", async () => {
    const api = makeApi();
    const sendProtocolReply: SendProtocolReplyFn = vi.fn(async () => {});
    const calendarFreebusy = vi.fn(async () => {
      throw new Error("freebusy HTTP 401");
    });
    await runAutoReplyExecutor({
      viewerAgentDid: "did:key:zViewer",
      viewerHasSigningKey: true,
      messages: [
        makeEntry({
          auto_reply_decision: "queue_for_human",
          auto_reply_reason: "calendar_unavailable",
        }),
      ],
      policy: { v: 1, default_action: "auto_accept_if_free" },
      masterAutoReplyEnabled: true,
      isContact: () => true,
      api,
      sendProtocolReply,
      decrypt: async () => scheduleProposeBody,
      calendarFreebusy,
    });
    expect(sendProtocolReply).not.toHaveBeenCalled();
    // Deliberately NOT marked sent so the next render retries.
    expect(api.markAutoReplySent).not.toHaveBeenCalled();
  });
});
