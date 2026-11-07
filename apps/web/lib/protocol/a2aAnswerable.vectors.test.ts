import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  A2A_CONTENT_TYPE,
  assertValidA2APayload,
  parseA2APayload,
} from "@nexusinbox/core/a2a";
import type { MessageFolder } from "../api/types";
import { canRespondToProtocol } from "./a2aReply";

// Shared vectors (tests/vectors/a2a_answerable.json): the Agent Gateway
// runs the same cases through a2a_rust::check_answerable, so the browser
// and Isolated mode executors answer the same requests (docs/29 §2.6).
type AnswerableVector = {
  name: string;
  folder: MessageFolder;
  now: string;
  answerable: boolean;
  plaintext: unknown;
};

const vectors = JSON.parse(
  readFileSync(new URL("../../../../tests/vectors/a2a_answerable.json", import.meta.url), "utf8"),
) as { cases: AnswerableVector[] };

/** The executor's parse step followed by its `isAnswerableRequest` gate. */
function isAnswerable(vector: AnswerableVector): boolean {
  const raw =
    typeof vector.plaintext === "string" ? vector.plaintext : JSON.stringify(vector.plaintext);
  const parsed = parseA2APayload(raw, A2A_CONTENT_TYPE);
  if (!parsed.protocol) return false;
  if (!canRespondToProtocol({ folder: vector.folder, protocol: parsed.protocol })) return false;
  try {
    assertValidA2APayload(parsed.protocol);
  } catch {
    return false;
  }
  return true;
}

describe("A2A answerability vectors", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("has cases on both sides of the gate", () => {
    expect(vectors.cases.some((c) => c.answerable)).toBe(true);
    expect(vectors.cases.some((c) => !c.answerable)).toBe(true);
  });

  it.each(vectors.cases.map((c) => [c.name, c] as const))("%s", (_name, vector) => {
    // isProposeExpired reads the clock through `new Date()`.
    vi.useFakeTimers();
    vi.setSystemTime(new Date(vector.now));
    expect(isAnswerable(vector)).toBe(vector.answerable);
  });
});
