import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AI_STARTED_WINDOW_MS, conversationRequests, type RequestMessage } from "../src/request-state";

// Shared with the gateway (services/agent-gateway/src/request_state.rs):
// both must give the same answer for the same messages (docs/41 §7.3).
const vectors = JSON.parse(
  readFileSync(new URL("../../../tests/vectors/request_state.json", import.meta.url), "utf8"),
) as {
  now: string;
  ai_started_window_seconds: number;
  cases: {
    name: string;
    messages: RequestMessage[];
    expect: {
      requests: Array<Record<string, unknown> & { request_id: string; state: string; next: string; last_message_id: string; evidence: string[] }>;
      unverified: string[];
    };
  }[];
};

describe("conversationRequests (tests/vectors/request_state.json)", () => {
  it("uses the shared window", () => {
    expect(AI_STARTED_WINDOW_MS).toBe(vectors.ai_started_window_seconds * 1000);
  });

  for (const c of vectors.cases) {
    it(c.name, () => {
      const out = conversationRequests(c.messages, vectors.now);
      expect(out.unverified).toEqual(c.expect.unverified);
      expect(out.requests.map((r) => r.request_id)).toEqual(c.expect.requests.map((r) => r.request_id));
      c.expect.requests.forEach((want, i) => {
        const got = out.requests[i];
        expect(got.state).toBe(want.state);
        expect(got.next).toBe(want.next);
        expect(got.last.message_id).toBe(want.last_message_id);
        expect(got.evidence).toEqual(want.evidence);
        for (const key of ["deadline", "selected", "result", "ai_started_at", "history_incomplete"] as const) {
          if (key in want) expect(got[key]).toEqual(want[key]);
        }
      });
    });
  }
});
