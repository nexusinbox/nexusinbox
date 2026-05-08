import { describe, expect, it } from "vitest";
import {
  CANDIDATE_MAX_COUNT,
  toIsoWithLocalOffset,
  validateCandidateRows,
  type CandidateRow,
} from "./candidateInput";

// Match the real i18n at runtime: a stub that echoes the key +
// params so assertions can match on the key rather than on
// specific English / Japanese strings.
const stubT = (key: string, params?: Record<string, string | number>) =>
  params ? `${key}:${JSON.stringify(params)}` : key;

describe("toIsoWithLocalOffset", () => {
  it("returns '' for empty input", () => {
    expect(toIsoWithLocalOffset("")).toBe("");
  });

  it("returns '' for an unparseable datetime", () => {
    expect(toIsoWithLocalOffset("not-a-date")).toBe("");
  });

  it("pads to seconds and appends the local TZ offset", () => {
    const iso = toIsoWithLocalOffset("2026-06-01T15:00");
    // We can't predict the test runner's local TZ, so match the
    // envelope shape: `YYYY-MM-DDTHH:MM:SS[+|-]HH:MM` or `…Z`.
    expect(iso).toMatch(/^2026-06-01T15:00:00(?:Z|[+-]\d{2}:\d{2})$/);
  });

  it("accepts inputs that already include seconds", () => {
    const iso = toIsoWithLocalOffset("2026-06-01T15:00:30");
    expect(iso).toMatch(/^2026-06-01T15:00:30(?:Z|[+-]\d{2}:\d{2})$/);
  });
});

describe("validateCandidateRows", () => {
  const goodRow: CandidateRow = {
    start: "2026-06-01T15:00",
    end: "2026-06-01T16:00",
  };

  it("accepts a minimal well-formed single row", () => {
    const result = validateCandidateRows([goodRow], stubT);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.candidates).toHaveLength(1);
      expect(result.candidates[0].start).toMatch(/^2026-06-01T15:00:00/);
      expect(result.candidates[0].end).toMatch(/^2026-06-01T16:00:00/);
    }
  });

  it("rejects zero rows with a localisable key", () => {
    const result = validateCandidateRows([], stubT);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("a2a.counterValidationNoCandidates");
    }
  });

  it("rejects a row with empty start / end", () => {
    const result = validateCandidateRows(
      [{ start: "", end: "" }],
      stubT,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("a2a.counterValidationEmpty");
      expect(result.error).toContain('"index":1');
    }
  });

  it("rejects a row where end is not strictly after start", () => {
    const result = validateCandidateRows(
      [{ start: "2026-06-01T15:00", end: "2026-06-01T15:00" }],
      stubT,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("a2a.counterValidationOrder");
    }
  });

  it("honours CANDIDATE_MAX_COUNT as the upper bound", () => {
    expect(CANDIDATE_MAX_COUNT).toBe(20);
    const tooMany: CandidateRow[] = Array.from({ length: 21 }, () => goodRow);
    const result = validateCandidateRows(tooMany, stubT);
    expect(result.ok).toBe(false);
  });

  it("preserves row order in the output", () => {
    const rows: CandidateRow[] = [
      { start: "2026-06-02T10:00", end: "2026-06-02T11:00" },
      { start: "2026-06-01T15:00", end: "2026-06-01T16:00" },
    ];
    const result = validateCandidateRows(rows, stubT);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.candidates[0].start).toMatch(/^2026-06-02T10:00:00/);
      expect(result.candidates[1].start).toMatch(/^2026-06-01T15:00:00/);
    }
  });
});
