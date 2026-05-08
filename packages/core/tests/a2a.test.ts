import { describe, expect, it } from "vitest";
import {
  A2A_CONTENT_TYPE,
  A2AValidationError,
  assertValidA2APayload,
  assertValidScheduleNegotiationPayload,
  assertValidTaskDelegationPayload,
  buildA2AEnvelope,
  createEd25519KeyPair,
  createX25519KeyPair,
  exportRawPublicKeyBase64Url,
  isA2AContentType,
  isProposeExpired,
  isValidIso8601WithTimezone,
  parseA2APayload,
  serializeA2APayload,
  uuidv7,
  type A2AProtocolBlock,
  type ScheduleCandidate,
  type ScheduleProposePayload,
  type TaskDelegatePayload,
} from "../src/index";

// ---------------------------------------------------------------------------
// Time validation
// ---------------------------------------------------------------------------

describe("isValidIso8601WithTimezone", () => {
  it("accepts +09:00 offset", () => {
    expect(isValidIso8601WithTimezone("2026-06-01T15:00:00+09:00")).toBe(true);
  });
  it("accepts Z (UTC)", () => {
    expect(isValidIso8601WithTimezone("2026-06-01T06:00:00Z")).toBe(true);
  });
  it("accepts fractional seconds", () => {
    expect(isValidIso8601WithTimezone("2026-06-01T15:00:00.123+09:00")).toBe(true);
  });
  it("rejects naive strings (no timezone)", () => {
    expect(isValidIso8601WithTimezone("2026-06-01T15:00:00")).toBe(false);
  });
  it("rejects date-only", () => {
    expect(isValidIso8601WithTimezone("2026-06-01")).toBe(false);
  });
  it("rejects garbage", () => {
    expect(isValidIso8601WithTimezone("not a date")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// UUIDv7
// ---------------------------------------------------------------------------

describe("uuidv7", () => {
  it("produces a well-formed UUID string", () => {
    const id = uuidv7();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
  it("is monotonically-ish ordered over subsequent calls", () => {
    // UUIDv7 timestamps can collide inside the same millisecond, but
    // across a short sequence we expect non-decreasing prefixes.
    const ids = Array.from({ length: 5 }, () => uuidv7());
    const prefixes = ids.map((id) => id.slice(0, 8));
    const sorted = [...prefixes].sort();
    expect(prefixes).toEqual(sorted);
  });
});

// ---------------------------------------------------------------------------
// content_type predicate
// ---------------------------------------------------------------------------

describe("isA2AContentType", () => {
  it("matches canonical MIME", () => {
    expect(isA2AContentType(A2A_CONTENT_TYPE)).toBe(true);
  });
  it("matches without params (future-proofing)", () => {
    expect(isA2AContentType("application/vnd.nexusinbox.a2a+json")).toBe(true);
  });
  it("is case-insensitive on MIME name", () => {
    expect(isA2AContentType("APPLICATION/VND.NEXUSINBOX.A2A+JSON; v=1")).toBe(true);
  });
  it("rejects text/plain", () => {
    expect(isA2AContentType("text/plain")).toBe(false);
  });
  it("rejects undefined/null/empty", () => {
    expect(isA2AContentType(undefined)).toBe(false);
    expect(isA2AContentType(null)).toBe(false);
    expect(isA2AContentType("")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// parseA2APayload
// ---------------------------------------------------------------------------

describe("parseA2APayload", () => {
  it("parses a propose payload", () => {
    const payload = {
      v: 1,
      body: "Proposing two slots",
      protocol: {
        id: uuidv7(),
        type: "schedule_negotiation",
        action: "propose",
        reply_to: null,
        payload: {
          event_title: "Q2 kickoff",
          candidates: [
            { start: "2026-06-01T15:00:00+09:00", end: "2026-06-01T16:00:00+09:00" },
          ],
          required_participants: [],
        },
      },
    };
    const parsed = parseA2APayload(JSON.stringify(payload), A2A_CONTENT_TYPE);
    expect(parsed.body).toBe("Proposing two slots");
    expect(parsed.protocol?.action).toBe("propose");
    expect(parsed.protocol?.type).toBe("schedule_negotiation");
    expect(parsed.parse_error).toBeUndefined();
  });

  it("falls back to legacy plain text (no content_type)", () => {
    const parsed = parseA2APayload("hello there", undefined);
    expect(parsed.body).toBe("hello there");
    expect(parsed.protocol).toBe(null);
    expect(parsed.parse_error).toBeUndefined();
  });

  it("falls back to legacy on text/plain even if body looks like JSON", () => {
    const parsed = parseA2APayload('{"v":1,"body":"x"}', "text/plain");
    expect(parsed.body).toBe('{"v":1,"body":"x"}');
    expect(parsed.protocol).toBe(null);
  });

  it("marks parse_error when content_type claims A2A but body isn't JSON", () => {
    const parsed = parseA2APayload("not json", A2A_CONTENT_TYPE);
    expect(parsed.protocol).toBe(null);
    expect(parsed.parse_error).toBe(true);
  });

  it("marks parse_error when JSON is valid but shape is wrong", () => {
    const parsed = parseA2APayload('{"foo":"bar"}', A2A_CONTENT_TYPE);
    expect(parsed.protocol).toBe(null);
    expect(parsed.parse_error).toBe(true);
  });

  it("treats protocol with unknown action as parse_error", () => {
    const bad = {
      v: 1,
      body: "",
      protocol: {
        id: uuidv7(),
        type: "schedule_negotiation",
        action: "no-such-action",
        reply_to: null,
        payload: {},
      },
    };
    const parsed = parseA2APayload(JSON.stringify(bad), A2A_CONTENT_TYPE);
    expect(parsed.parse_error).toBe(true);
  });

  it("accepts body-only A2A payloads (no protocol field)", () => {
    const payload = { v: 1, body: "hello" };
    const parsed = parseA2APayload(JSON.stringify(payload), A2A_CONTENT_TYPE);
    expect(parsed.body).toBe("hello");
    expect(parsed.protocol).toBe(null);
    expect(parsed.parse_error).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

describe("assertValidScheduleNegotiationPayload", () => {
  const validCandidate: ScheduleCandidate = {
    start: "2026-06-01T15:00:00+09:00",
    end: "2026-06-01T16:00:00+09:00",
  };

  it("accepts a well-formed propose", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("propose", {
        event_title: "Sync",
        candidates: [validCandidate],
        required_participants: [],
      }),
    ).not.toThrow();
  });

  it("rejects propose with empty event_title", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("propose", {
        event_title: "",
        candidates: [validCandidate],
        required_participants: [],
      }),
    ).toThrow(A2AValidationError);
  });

  it("rejects propose with zero candidates", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("propose", {
        event_title: "Sync",
        candidates: [],
        required_participants: [],
      }),
    ).toThrow(/at least one candidate/);
  });

  it("rejects propose with 21 candidates", () => {
    const candidates = Array.from({ length: 21 }, () => validCandidate);
    expect(() =>
      assertValidScheduleNegotiationPayload("propose", {
        event_title: "Sync",
        candidates,
        required_participants: [],
      }),
    ).toThrow(/at most 20 candidates/);
  });

  it("rejects candidate with end <= start", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("propose", {
        event_title: "Sync",
        candidates: [
          { start: "2026-06-01T15:00:00+09:00", end: "2026-06-01T15:00:00+09:00" },
        ],
        required_participants: [],
      }),
    ).toThrow(/strictly after start/);
  });

  it("rejects candidate longer than 24h", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("propose", {
        event_title: "Sync",
        candidates: [
          { start: "2026-06-01T00:00:00+09:00", end: "2026-06-02T00:00:01+09:00" },
        ],
        required_participants: [],
      }),
    ).toThrow(/duration limit/);
  });

  it("rejects candidate with naive timestamp (no timezone)", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("propose", {
        event_title: "Sync",
        candidates: [
          { start: "2026-06-01T15:00:00", end: "2026-06-01T16:00:00" },
        ],
        required_participants: [],
      }),
    ).toThrow(/ISO 8601 with timezone/);
  });

  it("accepts accept with selected_candidate", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("accept", {
        selected_candidate: validCandidate,
      }),
    ).not.toThrow();
  });

  it("rejects accept missing selected_candidate", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("accept", {} as never),
    ).toThrow();
  });

  it("accepts decline with and without reason", () => {
    expect(() => assertValidScheduleNegotiationPayload("decline", {})).not.toThrow();
    expect(() =>
      assertValidScheduleNegotiationPayload("decline", { reason: "busy" }),
    ).not.toThrow();
  });

  it("accepts counter with multiple candidates", () => {
    expect(() =>
      assertValidScheduleNegotiationPayload("counter", {
        candidates: [validCandidate, validCandidate],
      }),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// isProposeExpired
// ---------------------------------------------------------------------------

describe("isProposeExpired", () => {
  const base: ScheduleProposePayload = {
    event_title: "Sync",
    candidates: [{ start: "2026-06-01T15:00:00+09:00", end: "2026-06-01T16:00:00+09:00" }],
    required_participants: [],
  };

  it("returns false when there's no deadline", () => {
    expect(isProposeExpired(base)).toBe(false);
  });

  it("returns false before the deadline", () => {
    const payload = { ...base, response_deadline: "2099-12-31T23:59:59+09:00" };
    expect(isProposeExpired(payload)).toBe(false);
  });

  it("returns true after the deadline", () => {
    const payload = { ...base, response_deadline: "2000-01-01T00:00:00Z" };
    expect(isProposeExpired(payload)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildA2AEnvelope — end-to-end with real crypto
// ---------------------------------------------------------------------------

async function makeCryptoFixture() {
  const sender = await createEd25519KeyPair();
  const recipient = await createX25519KeyPair();
  const senderPublic = await exportRawPublicKeyBase64Url(sender.publicKey);
  const recipientPublic = await exportRawPublicKeyBase64Url(recipient.publicKey);
  return {
    senderDid: `did:key:z-sender-${senderPublic.slice(0, 8)}`,
    recipientDid: `did:key:z-recipient-${recipientPublic.slice(0, 8)}`,
    senderSigningPrivateKey: sender.privateKey,
    recipientEncryptionPublicKey: recipientPublic,
  };
}

describe("buildA2AEnvelope", () => {
  it("tags envelope with the A2A content_type when protocol is present", async () => {
    const fx = await makeCryptoFixture();
    const proposeBlock: A2AProtocolBlock = {
      id: uuidv7(),
      type: "schedule_negotiation",
      action: "propose",
      reply_to: null,
      payload: {
        event_title: "Sync",
        candidates: [{ start: "2026-06-01T15:00:00+09:00", end: "2026-06-01T16:00:00+09:00" }],
        required_participants: [],
      },
    };
    const env = await buildA2AEnvelope({
      ...fx,
      subject: "Scheduling",
      body: "Two slots proposed",
      threadId: "thread-abc",
      protocol: proposeBlock,
    });
    expect(env.metadata.content_type).toBe(A2A_CONTENT_TYPE);
    expect(env.metadata.thread_id).toBe("thread-abc");
    expect(typeof env.encrypted_content).toBe("string");
    expect(typeof env.signature).toBe("string");
  });

  it("tags envelope with text/plain when protocol is omitted", async () => {
    const fx = await makeCryptoFixture();
    const env = await buildA2AEnvelope({
      ...fx,
      subject: "Hi",
      body: "no protocol",
    });
    expect(env.metadata.content_type).toBe("text/plain");
  });

  it("validates protocol payload and rejects bad input", async () => {
    const fx = await makeCryptoFixture();
    const badBlock: A2AProtocolBlock = {
      id: uuidv7(),
      type: "schedule_negotiation",
      action: "propose",
      reply_to: null,
      payload: {
        event_title: "",
        candidates: [],
        required_participants: [],
      },
    };
    await expect(
      buildA2AEnvelope({
        ...fx,
        subject: "S",
        body: "b",
        protocol: badBlock,
      }),
    ).rejects.toThrow(A2AValidationError);
  });
});

// ---------------------------------------------------------------------------
// serializeA2APayload — round-trip integrity
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// task_delegation validation
// ---------------------------------------------------------------------------

describe("assertValidTaskDelegationPayload", () => {
  const baseDelegate: TaskDelegatePayload = { title: "Write the report" };

  it("accepts a minimal delegate payload (title only)", () => {
    expect(() =>
      assertValidTaskDelegationPayload("delegate", baseDelegate),
    ).not.toThrow();
  });

  it("accepts a fully-specified delegate payload", () => {
    expect(() =>
      assertValidTaskDelegationPayload("delegate", {
        title: "Write the report",
        description: "Summary + three supporting charts.",
        due_date: "2026-06-30T23:59:59+09:00",
        priority: "high",
      }),
    ).not.toThrow();
  });

  it("rejects an empty title", () => {
    expect(() =>
      assertValidTaskDelegationPayload("delegate", { title: "   " }),
    ).toThrow(/title is required/);
  });

  it("rejects title longer than 200 chars", () => {
    expect(() =>
      assertValidTaskDelegationPayload("delegate", { title: "a".repeat(201) }),
    ).toThrow(/title must be ≤ 200/);
  });

  it("rejects an unknown priority", () => {
    expect(() =>
      assertValidTaskDelegationPayload("delegate", {
        ...baseDelegate,
        priority: "urgent" as never,
      }),
    ).toThrow(/priority must be one of/);
  });

  it("rejects a due_date without timezone", () => {
    expect(() =>
      assertValidTaskDelegationPayload("delegate", {
        ...baseDelegate,
        due_date: "2026-06-30T23:59:59",
      }),
    ).toThrow(/due_date must be ISO 8601/);
  });

  it("accepts accept with and without note", () => {
    expect(() => assertValidTaskDelegationPayload("accept", {})).not.toThrow();
    expect(() =>
      assertValidTaskDelegationPayload("accept", { note: "Starting tomorrow." }),
    ).not.toThrow();
  });

  it("rejects accept with overlong note", () => {
    expect(() =>
      assertValidTaskDelegationPayload("accept", { note: "n".repeat(2001) }),
    ).toThrow(/note must be ≤ 2000/);
  });

  it("accepts decline with and without reason", () => {
    expect(() => assertValidTaskDelegationPayload("decline", {})).not.toThrow();
    expect(() =>
      assertValidTaskDelegationPayload("decline", { reason: "At capacity." }),
    ).not.toThrow();
  });

  it("accepts complete with and without result", () => {
    expect(() => assertValidTaskDelegationPayload("complete", {})).not.toThrow();
    expect(() =>
      assertValidTaskDelegationPayload("complete", {
        result: "Report at https://…/summary.pdf",
      }),
    ).not.toThrow();
  });

  it("rejects a schedule-only action (propose / counter) for task_delegation", () => {
    expect(() =>
      assertValidTaskDelegationPayload("propose", {} as never),
    ).toThrow(/not valid for task_delegation/);
    expect(() =>
      assertValidTaskDelegationPayload("counter", {} as never),
    ).toThrow(/not valid for task_delegation/);
  });
});

// ---------------------------------------------------------------------------
// Cross-type dispatcher
// ---------------------------------------------------------------------------

describe("assertValidA2APayload dispatcher", () => {
  it("routes schedule_negotiation blocks to the schedule validator", () => {
    const block: A2AProtocolBlock = {
      id: uuidv7(),
      type: "schedule_negotiation",
      action: "propose",
      reply_to: null,
      payload: {
        event_title: "Sync",
        candidates: [
          { start: "2026-06-01T15:00:00+09:00", end: "2026-06-01T16:00:00+09:00" },
        ],
        required_participants: [],
      },
    };
    expect(() => assertValidA2APayload(block)).not.toThrow();
  });

  it("routes task_delegation blocks to the task validator", () => {
    const block: A2AProtocolBlock = {
      id: uuidv7(),
      type: "task_delegation",
      action: "delegate",
      reply_to: null,
      payload: { title: "Draft the roadmap" },
    };
    expect(() => assertValidA2APayload(block)).not.toThrow();
  });

  it("rejects a mismatched action on the wrong type", () => {
    const block: A2AProtocolBlock = {
      id: uuidv7(),
      type: "schedule_negotiation",
      action: "delegate",
      reply_to: null,
      payload: { title: "Draft the roadmap" } as never,
    };
    expect(() => assertValidA2APayload(block)).toThrow(
      /not valid for schedule_negotiation/,
    );
  });
});

// ---------------------------------------------------------------------------
// parseA2APayload accepts task_delegation
// ---------------------------------------------------------------------------

describe("parseA2APayload + task_delegation", () => {
  it("round-trips a delegate payload through JSON", () => {
    const block: A2AProtocolBlock = {
      id: uuidv7(),
      type: "task_delegation",
      action: "delegate",
      reply_to: null,
      payload: {
        title: "Draft the roadmap",
        description: "Aim for v0 by end of week.",
        priority: "normal",
      } satisfies TaskDelegatePayload,
    };
    const raw = serializeA2APayload({ v: 1, body: "task", protocol: block });
    const parsed = parseA2APayload(raw, A2A_CONTENT_TYPE);
    expect(parsed.protocol).toEqual(block);
    expect(parsed.parse_error).toBeUndefined();
  });

  it("rejects a task_delegation block carrying a schedule action", () => {
    const raw = JSON.stringify({
      v: 1,
      body: "",
      protocol: {
        id: uuidv7(),
        type: "task_delegation",
        action: "propose",
        reply_to: null,
        payload: { title: "won't pass" },
      },
    });
    const parsed = parseA2APayload(raw, A2A_CONTENT_TYPE);
    expect(parsed.protocol).toBe(null);
    expect(parsed.parse_error).toBe(true);
  });
});

describe("serializeA2APayload + parseA2APayload roundtrip", () => {
  it("round-trips a propose payload verbatim", () => {
    const protocol: A2AProtocolBlock = {
      id: uuidv7(),
      type: "schedule_negotiation",
      action: "propose",
      reply_to: null,
      payload: {
        event_title: "Sync",
        candidates: [
          { start: "2026-06-01T15:00:00+09:00", end: "2026-06-01T16:00:00+09:00" },
          { start: "2026-06-02T10:00:00+09:00", end: "2026-06-02T11:00:00+09:00" },
        ],
        required_participants: ["did:key:z-alice"],
        response_deadline: "2026-05-30T00:00:00Z",
      },
    };
    const raw = serializeA2APayload({ v: 1, body: "summary", protocol });
    const parsed = parseA2APayload(raw, A2A_CONTENT_TYPE);
    expect(parsed.body).toBe("summary");
    expect(parsed.protocol).toEqual(protocol);
    expect(parsed.parse_error).toBeUndefined();
  });

  it("round-trips an accept with echoed-back candidate", () => {
    const accept: A2AProtocolBlock = {
      id: uuidv7(),
      type: "schedule_negotiation",
      action: "accept",
      reply_to: uuidv7(),
      payload: {
        selected_candidate: {
          start: "2026-06-01T15:00:00+09:00",
          end: "2026-06-01T16:00:00+09:00",
        },
      },
    };
    const raw = serializeA2APayload({ v: 1, body: "Confirmed", protocol: accept });
    const parsed = parseA2APayload(raw, A2A_CONTENT_TYPE);
    expect(parsed.protocol).toEqual(accept);
  });
});
