import { describe, expect, it } from "vitest";
import { buildReplyPayload, canRespondToProtocol } from "./a2aReply";
import type {
  A2AProtocolBlock,
  ScheduleCandidate,
  ScheduleProposePayload,
} from "@nexusinbox/core/a2a";

const candidate: ScheduleCandidate = {
  start: "2026-06-01T15:00:00+09:00",
  end: "2026-06-01T16:00:00+09:00",
};

function makePropose(overrides: Partial<ScheduleProposePayload> = {}): A2AProtocolBlock {
  return {
    id: "01932f7c-a8d4-7e01-b3f5-2c9a1b6d4e80",
    type: "schedule_negotiation",
    action: "propose",
    reply_to: null,
    payload: {
      event_title: "Sync",
      candidates: [candidate],
      required_participants: [],
      ...overrides,
    },
  };
}

// ---------------------------------------------------------------------------
// canRespondToProtocol — docs/24 §2.6 invariant
// ---------------------------------------------------------------------------

describe("canRespondToProtocol", () => {
  it("lets a recipient act on a fresh propose", () => {
    expect(
      canRespondToProtocol({
        folder: "inbox",
        protocol: makePropose(),
      }),
    ).toBe(true);
  });

  it("hides Accept/Decline on the sender's sent view", () => {
    expect(
      canRespondToProtocol({
        folder: "sent",
        protocol: makePropose(),
      }),
    ).toBe(false);
  });

  it("hides Accept/Decline on accept / decline / counter action records", () => {
    for (const action of ["accept", "decline", "counter"] as const) {
      const protocol: A2AProtocolBlock = {
        id: "01932f7c-a8d4-7e01-b3f5-2c9a1b6d4e80",
        type: "schedule_negotiation",
        action,
        reply_to: null,
        payload:
          action === "accept"
            ? { selected_candidate: candidate }
            : action === "decline"
              ? {}
              : { candidates: [candidate] },
      };
      expect(canRespondToProtocol({ folder: "inbox", protocol })).toBe(false);
    }
  });

  it("hides Accept/Decline past response_deadline", () => {
    const protocol = makePropose({ response_deadline: "2000-01-01T00:00:00Z" });
    expect(canRespondToProtocol({ folder: "inbox", protocol })).toBe(false);
  });

  it("allows Accept/Decline when response_deadline is still ahead", () => {
    const protocol = makePropose({ response_deadline: "2099-12-31T23:59:59+09:00" });
    expect(canRespondToProtocol({ folder: "inbox", protocol })).toBe(true);
  });

  it("treats non-inbox recipient folders (archive/drafts/spam) as interactive", () => {
    // The security invariant is "not sender", not "exactly inbox".
    // Archived conversations can still have pending proposals the
    // user hasn't acted on — hiding the buttons there would be
    // surprising. `spam` gets protected by the block/trust layer
    // before it ever reaches render; we don't add a second gate.
    for (const folder of ["archive", "drafts", "spam"] as const) {
      expect(
        canRespondToProtocol({
          folder,
          protocol: makePropose(),
        }),
      ).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// buildReplyPayload — docs/24 §2.4 + §7.1 context binding
// ---------------------------------------------------------------------------

describe("buildReplyPayload", () => {
  it("echoes back the selected candidate on accept", () => {
    const payload = buildReplyPayload("schedule_negotiation", {
      action: "accept",
      selected_candidate: candidate,
    });
    expect(payload).toEqual({ selected_candidate: candidate });
  });

  it("strips extra keys from the candidate so forward-compat fields don't leak", () => {
    // Future versions may add candidate_id etc. The reply should
    // only echo the authoritative { start, end } pair until the
    // protocol version explicitly includes extra fields in the
    // accept shape.
    const enriched = {
      start: candidate.start,
      end: candidate.end,
      unexpected_field: "should not leak",
    } as unknown as ScheduleCandidate;
    const payload = buildReplyPayload("schedule_negotiation", {
      action: "accept",
      selected_candidate: enriched,
    });
    expect(payload).toEqual({
      selected_candidate: { start: candidate.start, end: candidate.end },
    });
    expect((payload as { selected_candidate: Record<string, unknown> }).selected_candidate.unexpected_field).toBeUndefined();
  });

  it("omits reason on schedule decline when not provided", () => {
    const payload = buildReplyPayload("schedule_negotiation", { action: "decline" });
    expect(payload).toEqual({});
  });

  it("passes through schedule decline reason when given", () => {
    const payload = buildReplyPayload("schedule_negotiation", {
      action: "decline",
      reason: "I'm travelling that week.",
    });
    expect(payload).toEqual({ reason: "I'm travelling that week." });
  });

  it("strips candidate fields on counter and omits reason when blank", () => {
    const enriched = {
      start: candidate.start,
      end: candidate.end,
      unexpected_field: "nope",
    } as unknown as ScheduleCandidate;
    const payload = buildReplyPayload("schedule_negotiation", {
      action: "counter",
      candidates: [enriched, candidate],
    });
    expect(payload).toEqual({
      candidates: [
        { start: candidate.start, end: candidate.end },
        { start: candidate.start, end: candidate.end },
      ],
    });
    expect((payload as { reason?: string }).reason).toBeUndefined();
  });

  it("passes counter reason through when given", () => {
    const payload = buildReplyPayload("schedule_negotiation", {
      action: "counter",
      candidates: [candidate],
      reason: "How about the following week?",
    });
    expect(payload).toEqual({
      candidates: [{ start: candidate.start, end: candidate.end }],
      reason: "How about the following week?",
    });
  });

  // task_delegation replies --------------------------------------------------

  it("emits empty object for task accept with no note", () => {
    const payload = buildReplyPayload("task_delegation", { action: "accept" });
    expect(payload).toEqual({});
  });

  it("passes through task accept note when given", () => {
    const payload = buildReplyPayload("task_delegation", {
      action: "accept",
      note: "Starting tomorrow.",
    });
    expect(payload).toEqual({ note: "Starting tomorrow." });
  });

  it("emits empty object for task decline without reason", () => {
    const payload = buildReplyPayload("task_delegation", { action: "decline" });
    expect(payload).toEqual({});
  });

  it("passes through task complete result when given", () => {
    const payload = buildReplyPayload("task_delegation", {
      action: "complete",
      result: "Deck at /docs/roadmap-v1.pdf",
    });
    expect(payload).toEqual({ result: "Deck at /docs/roadmap-v1.pdf" });
  });

  it("throws when asking schedule_negotiation to build a complete reply", () => {
    expect(() =>
      buildReplyPayload("schedule_negotiation", {
        action: "complete",
        result: "nope",
      }),
    ).toThrow(/has no `complete` action/);
  });

  it("throws when asking task_delegation to build a counter reply", () => {
    expect(() =>
      buildReplyPayload("task_delegation", {
        action: "counter",
        candidates: [candidate],
      } as never),
    ).toThrow(/has no `counter` action/);
  });
});

// ---------------------------------------------------------------------------
// canRespondToProtocol — task_delegation cases
// ---------------------------------------------------------------------------

describe("canRespondToProtocol — task_delegation", () => {
  function makeDelegate(action: "delegate" | "accept" | "decline" | "complete"): A2AProtocolBlock {
    return {
      id: "01932f7c-a8d4-7e01-b3f5-2c9a1b6d4e80",
      type: "task_delegation",
      action,
      reply_to: null,
      payload: { title: "Write the report" },
    };
  }

  it("lets a recipient act on a delegate", () => {
    expect(
      canRespondToProtocol({ folder: "inbox", protocol: makeDelegate("delegate") }),
    ).toBe(true);
  });

  it("hides actions on accept / decline / complete records", () => {
    for (const action of ["accept", "decline", "complete"] as const) {
      expect(
        canRespondToProtocol({ folder: "inbox", protocol: makeDelegate(action) }),
      ).toBe(false);
    }
  });

  it("hides actions on the sender's sent-view", () => {
    expect(
      canRespondToProtocol({ folder: "sent", protocol: makeDelegate("delegate") }),
    ).toBe(false);
  });
});
