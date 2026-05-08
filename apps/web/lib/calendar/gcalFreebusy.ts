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
export async function findFirstFreeCandidate(
  candidates: readonly IsoInterval[],
  accessToken: string,
  fetcher: FreebusyFetcher = defaultFetcher,
): Promise<IsoInterval | null> {
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

function extractPrimaryBusy(parsed: unknown): IsoInterval[] {
  if (!parsed || typeof parsed !== "object") return [];
  const calendars = (parsed as { calendars?: Record<string, unknown> }).calendars;
  if (!calendars || typeof calendars !== "object") return [];
  const primary = (calendars as Record<string, { busy?: unknown }>).primary;
  if (!primary || typeof primary !== "object") return [];
  const busy = primary.busy;
  if (!Array.isArray(busy)) return [];
  return busy.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const start = (entry as { start?: unknown }).start;
    const end = (entry as { end?: unknown }).end;
    if (typeof start !== "string" || typeof end !== "string") return [];
    return [{ start, end }];
  });
}
