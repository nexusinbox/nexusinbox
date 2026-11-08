import { describe, expect, it } from "vitest";
import type { MessageIndexEntry } from "../api/types";
import { selfTestCandidates, selfTestSettled, selfTestState } from "./self-test";

const row = (fields: Partial<MessageIndexEntry>) => ({ id: "m1", ...fields }) as MessageIndexEntry;

describe("self-test", () => {
  it("proposes 10:00 on the next two days, across a month end", () => {
    const candidates = selfTestCandidates(new Date(2026, 10, 30, 15, 0));
    expect(candidates.map((c) => c.start.slice(0, 16))).toEqual([
      "2026-12-01T10:00",
      "2026-12-02T10:00",
    ]);
    expect(candidates[0].end.slice(0, 16)).toBe("2026-12-01T10:30");
    expect(candidates[0].start).toMatch(/[+-]\d{2}:\d{2}$/);
  });

  it("follows the message from arrival to the decision", () => {
    expect(selfTestState(null, "browser")).toBe("waiting");
    expect(selfTestState(row({}), "browser")).toBe("arrived");
    expect(
      selfTestState(row({ auto_reply_decision: "queue_for_human", auto_reply_reason: "master_off" }), "pc"),
    ).toBe("queued");
    expect(
      selfTestState(row({ auto_reply_decision: "queue_for_human", auto_reply_reason: "not_a_contact" }), "browser"),
    ).toBe("queued_not_contact");
  });

  it("waits for the computer to answer, but not for the browser", () => {
    const accepted = row({ auto_reply_decision: "auto_accept" });
    expect(selfTestState(accepted, "browser")).toBe("accept_in_browser");
    expect(selfTestState(accepted, "pc")).toBe("accept_pending_pc");
    expect(selfTestState(row({ auto_reply_decision: "auto_accept", auto_reply_sent_at: "2026-11-08T01:00:00Z" }), "pc")).toBe(
      "accepted_pc",
    );
    expect(selfTestSettled("accept_pending_pc")).toBe(false);
    expect(selfTestSettled("arrived")).toBe(false);
    expect(selfTestSettled("accept_in_browser")).toBe(true);
    expect(selfTestSettled("queued")).toBe(true);
  });
});
