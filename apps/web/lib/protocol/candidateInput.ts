// Shared helpers for the two A2A candidate-list forms: the
// CounterForm inside ScheduleNegotiationCard (reply) and the
// /compose/propose page (new proposal). Both collect a list of
// `{ start, end }` datetime-local inputs plus an optional reason /
// body, and must produce ISO 8601 strings with a real timezone
// offset so they round-trip through the docs/24 §2.5 validator.
//
// Kept as pure functions (no React) so both callers and unit
// tests can drive the logic without rendering.

import type {
  ScheduleCandidate,
} from "@nexusinbox/core/a2a";

/**
 * Attach the user's local TZ offset to a `datetime-local` value.
 *
 * `<input type="datetime-local">` hands back `"YYYY-MM-DDTHH:MM"` —
 * no timezone. Returning UTC here would lose the proposer's
 * wall-clock intent ("15:00 in Tokyo"), which is the whole reason
 * we rejected UTC-only in the ADR. Pad to seconds first so the
 * output matches the regex used by
 * `isValidIso8601WithTimezone` in `@nexusinbox/core/a2a`.
 */
export function toIsoWithLocalOffset(datetimeLocal: string): string {
  if (!datetimeLocal) return "";
  const padded = datetimeLocal.length === 16 ? `${datetimeLocal}:00` : datetimeLocal;
  const d = new Date(padded);
  if (Number.isNaN(d.getTime())) return "";
  const offsetMin = -d.getTimezoneOffset();
  const sign = offsetMin >= 0 ? "+" : "-";
  const abs = Math.abs(offsetMin);
  const hh = String(Math.floor(abs / 60)).padStart(2, "0");
  const mm = String(abs % 60).padStart(2, "0");
  return `${padded}${sign}${hh}:${mm}`;
}

/**
 * Translate a single i18n key with `{index}` substitution. Small
 * helper so the caller's React layer can inject its own `t()`.
 */
export type CandidateValidationTranslator = (
  key: string,
  params?: Record<string, string | number>,
) => string;

export type CandidateRow = { start: string; end: string };

export type CandidatesValidationResult =
  | { ok: true; candidates: ScheduleCandidate[] }
  | { ok: false; error: string };

export const CANDIDATE_MAX_COUNT = 20;

/**
 * Validate a list of datetime-local input rows. Returns the
 * parsed ScheduleCandidate[] or the first human-readable error.
 * Keeps the order of rows, matching the UI expectation.
 */
export function validateCandidateRows(
  rows: CandidateRow[],
  t: CandidateValidationTranslator,
): CandidatesValidationResult {
  if (rows.length === 0) {
    return { ok: false, error: t("a2a.counterValidationNoCandidates") };
  }
  if (rows.length > CANDIDATE_MAX_COUNT) {
    return {
      ok: false,
      error: t("a2a.counterValidationNoCandidates"),
    };
  }
  const candidates: ScheduleCandidate[] = [];
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const index = i + 1;
    if (!r.start || !r.end) {
      return { ok: false, error: t("a2a.counterValidationEmpty", { index }) };
    }
    const start = toIsoWithLocalOffset(r.start);
    const end = toIsoWithLocalOffset(r.end);
    if (!start || !end) {
      return { ok: false, error: t("a2a.counterValidationInvalid", { index }) };
    }
    if (Date.parse(end) <= Date.parse(start)) {
      return { ok: false, error: t("a2a.counterValidationOrder", { index }) };
    }
    candidates.push({ start, end });
  }
  return { ok: true, candidates };
}
