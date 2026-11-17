// Phase 4.4d (docs/25d) — Calendar freebusy helper used by the auto-
// reply executor to decide whether any candidate in a
// schedule_negotiation.propose is actually free. The overlap math is
// a pure function so it's trivially unit-testable; the API call is
// thin wrapper around `fetch`.

export type IsoInterval = {
  start: string;
  end: string;
};

const FREEBUSY_URL = "https://www.googleapis.com/calendar/v3/freebusy";

/**
 * Return `true` iff `candidate` does not overlap any of `busy`.
 * Uses half-open intervals — a candidate ending exactly when a
 * busy slot starts is treated as free. Callers pass ISO 8601
 * strings with explicit timezone (RFC 3339); Date.parse normalises
 * them to a numeric timestamp before comparison.
 */
export function isCandidateFree(
  candidate: IsoInterval,
  busy: readonly IsoInterval[],
): boolean {
  const candidateStart = Date.parse(candidate.start);
  const candidateEnd = Date.parse(candidate.end);
  if (!Number.isFinite(candidateStart) || !Number.isFinite(candidateEnd)) {
    return false;
  }
  if (candidateEnd <= candidateStart) return false;
  return busy.every((b) => {
    const bStart = Date.parse(b.start);
    const bEnd = Date.parse(b.end);
    if (!Number.isFinite(bStart) || !Number.isFinite(bEnd)) return true;
    return !(candidateStart < bEnd && bStart < candidateEnd);
  });
}

/** Pick the first free candidate. Returns `null` if every option overlaps a busy interval. */
export function pickFirstFreeCandidate(
  candidates: readonly IsoInterval[],
  busy: readonly IsoInterval[],
): IsoInterval | null {
  for (const c of candidates) {
    if (isCandidateFree(c, busy)) return c;
  }
  return null;
}

export type FreebusyFetcher = (
  url: string,
  init: { headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number; body: string }>;

const defaultFetcher: FreebusyFetcher = async (url, init) => {
  const resp = await fetch(url, {
    method: "POST",
    headers: init.headers,
    body: init.body,
  });
  const body = await resp.text();
  return { ok: resp.ok, status: resp.status, body };
};

/**
 * Query Calendar's freebusy endpoint over the envelope of all
 * candidates (timeMin = earliest start, timeMax = latest end) and
 * return the first candidate whose slot doesn't overlap any busy
 * interval. Returns:
 *
 *   - `candidate` when there's a free slot
 *   - `null` when all candidates overlap busy intervals
 *
 * Throws on network / auth / quota errors so the executor can
 * distinguish "all busy" from "couldn't check" in its audit reason.
 */
const DAY_MS = 24 * 60 * 60 * 1000;
/** How far ahead a slot may be: two years. */
const MAX_AHEAD_MS = 2 * 365 * DAY_MS;
/** How long one slot may be: a day. */
const MAX_SLOT_MS = DAY_MS;

export async function findFirstFreeCandidate(
  candidates: readonly IsoInterval[],
  accessToken: string,
  fetcher: FreebusyFetcher = defaultFetcher,
  now: number = Date.now(),
): Promise<IsoInterval | null> {
  // Only slots in the window a meeting can sensibly be in: the sender
  // chooses these, and far-off or reversed times are never accepted
  // automatically (nor sent to Google).
  candidates = candidates.filter((c) => {
    const start = Date.parse(c.start);
    const end = Date.parse(c.end);
    return (
      Number.isFinite(start) &&
      Number.isFinite(end) &&
      end > start &&
      end - start <= MAX_SLOT_MS &&
      start >= now - DAY_MS &&
      start <= now + MAX_AHEAD_MS
    );
  });
  if (candidates.length === 0) return null;

  const times = candidates
    .flatMap((c) => [Date.parse(c.start), Date.parse(c.end)])
    .filter((t) => Number.isFinite(t));
  if (times.length === 0) {
    throw new Error("all candidate timestamps unparseable");
  }
  const timeMin = new Date(Math.min(...times)).toISOString();
  const timeMax = new Date(Math.max(...times)).toISOString();

  const result = await fetcher(FREEBUSY_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      timeMin,
      timeMax,
      items: [{ id: "primary" }],
    }),
  });

  if (!result.ok) {
    throw new Error(`freebusy HTTP ${result.status}: ${result.body.slice(0, 200)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.body);
  } catch {
    throw new Error("freebusy response was not JSON");
  }
  const busy = extractPrimaryBusy(parsed);
  return pickFirstFreeCandidate(candidates, busy);
}

/**
 * The primary calendar's busy times. Anything else than a clean answer
 * throws: an unread calendar is never taken as free, since a free slot is
 * accepted automatically. Google reports a calendar it could not read in
 * `errors` with no `busy` (still HTTP 200).
 */
function extractPrimaryBusy(parsed: unknown): IsoInterval[] {
  const calendars = (parsed as { calendars?: unknown } | null)?.calendars;
  const primary = (calendars as Record<string, unknown> | null | undefined)?.primary as
    | { busy?: unknown; errors?: unknown }
    | null
    | undefined;
  if (!primary || typeof primary !== "object") throw new Error("freebusy: no primary calendar");
  if (Array.isArray(primary.errors) && primary.errors.length > 0) {
    throw new Error("freebusy: the primary calendar could not be read");
  }
  if (!Array.isArray(primary.busy)) throw new Error("freebusy: no busy list");
  return primary.busy.map((entry) => {
    const start = (entry as { start?: unknown } | null)?.start;
    const end = (entry as { end?: unknown } | null)?.end;
    if (typeof start !== "string" || typeof end !== "string") throw new Error("freebusy: malformed busy entry");
    return { start, end };
  });
}
