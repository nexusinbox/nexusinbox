import { describe, expect, it, vi } from "vitest";
import {
  findFirstFreeCandidate,
  isCandidateFree,
  pickFirstFreeCandidate,
  type FreebusyFetcher,
  type IsoInterval,
} from "./gcalFreebusy";

const c = (start: string, end: string): IsoInterval => ({ start, end });

describe("isCandidateFree — overlap math", () => {
  it("returns true when busy list is empty", () => {
    expect(isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"), [])).toBe(true);
  });

  it("returns false when candidate fully inside a busy slot", () => {
    const busy = [c("2026-05-01T08:00:00Z", "2026-05-01T11:00:00Z")];
    expect(isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"), busy)).toBe(false);
  });

  it("returns false when busy fully inside candidate", () => {
    const busy = [c("2026-05-01T09:15:00Z", "2026-05-01T09:45:00Z")];
    expect(isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"), busy)).toBe(false);
  });

  it("returns false on partial left overlap", () => {
    const busy = [c("2026-05-01T08:30:00Z", "2026-05-01T09:30:00Z")];
    expect(isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"), busy)).toBe(false);
  });

  it("returns false on partial right overlap", () => {
    const busy = [c("2026-05-01T09:30:00Z", "2026-05-01T10:30:00Z")];
    expect(isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"), busy)).toBe(false);
  });

  it("returns true when busy ends exactly at candidate start (half-open)", () => {
    const busy = [c("2026-05-01T08:00:00Z", "2026-05-01T09:00:00Z")];
    expect(isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"), busy)).toBe(true);
  });

  it("returns true when busy starts exactly at candidate end (half-open)", () => {
    const busy = [c("2026-05-01T10:00:00Z", "2026-05-01T11:00:00Z")];
    expect(isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"), busy)).toBe(true);
  });

  it("handles mixed timezones by normalising to epoch", () => {
    // 09:00 Tokyo == 00:00 UTC; busy 00:30-01:00 UTC overlaps.
    const busy = [c("2026-05-01T00:30:00Z", "2026-05-01T01:00:00Z")];
    expect(
      isCandidateFree(c("2026-05-01T09:00:00+09:00", "2026-05-01T10:00:00+09:00"), busy),
    ).toBe(false);
  });

  it("returns false on malformed candidate (defensive)", () => {
    expect(isCandidateFree(c("not-a-date", "also-not"), [])).toBe(false);
  });

  it("returns false when candidate end equals start", () => {
    expect(
      isCandidateFree(c("2026-05-01T09:00:00Z", "2026-05-01T09:00:00Z"), []),
    ).toBe(false);
  });
});

describe("pickFirstFreeCandidate", () => {
  it("picks the earliest free candidate, skipping busy ones", () => {
    const candidates = [
      c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"),
      c("2026-05-01T11:00:00Z", "2026-05-01T12:00:00Z"),
      c("2026-05-01T13:00:00Z", "2026-05-01T14:00:00Z"),
    ];
    const busy = [c("2026-05-01T08:30:00Z", "2026-05-01T11:30:00Z")];
    const result = pickFirstFreeCandidate(candidates, busy);
    expect(result?.start).toBe("2026-05-01T13:00:00Z");
  });

  it("returns null when every candidate overlaps", () => {
    const candidates = [
      c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"),
      c("2026-05-01T10:00:00Z", "2026-05-01T11:00:00Z"),
    ];
    const busy = [c("2026-05-01T08:00:00Z", "2026-05-01T12:00:00Z")];
    expect(pickFirstFreeCandidate(candidates, busy)).toBeNull();
  });
});

// The slots below are in May 2026; "now" is just before them.
const NOW = Date.parse("2026-04-30T00:00:00Z");

describe("findFirstFreeCandidate — API shape", () => {
  it("sends freebusy POST and picks free candidate on 200", async () => {
    const fetcher: FreebusyFetcher = vi.fn(async () => ({
      ok: true,
      status: 200,
      body: JSON.stringify({
        calendars: {
          primary: {
            busy: [{ start: "2026-05-01T08:30:00Z", end: "2026-05-01T09:30:00Z" }],
          },
        },
      }),
    }));
    const candidates = [
      c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z"),
      c("2026-05-01T11:00:00Z", "2026-05-01T12:00:00Z"),
    ];
    const free = await findFirstFreeCandidate(candidates, "tok-abc", fetcher, NOW);
    expect(free?.start).toBe("2026-05-01T11:00:00Z");
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("https://www.googleapis.com/calendar/v3/freebusy");
    expect(init.headers.Authorization).toBe("Bearer tok-abc");
    const body = JSON.parse(init.body);
    expect(body.items).toEqual([{ id: "primary" }]);
    expect(Date.parse(body.timeMin)).toBe(Date.parse("2026-05-01T09:00:00Z"));
    expect(Date.parse(body.timeMax)).toBe(Date.parse("2026-05-01T12:00:00Z"));
  });

  it("returns null when every candidate overlaps", async () => {
    const fetcher: FreebusyFetcher = async () => ({
      ok: true,
      status: 200,
      body: JSON.stringify({
        calendars: {
          primary: {
            busy: [{ start: "2026-05-01T08:00:00Z", end: "2026-05-01T14:00:00Z" }],
          },
        },
      }),
    });
    const free = await findFirstFreeCandidate(
      [c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z")],
      "tok",
      fetcher,
        NOW,
    );
    expect(free).toBeNull();
  });

  it("throws on non-2xx so the executor can mark calendar_api_error", async () => {
    const fetcher: FreebusyFetcher = async () => ({
      ok: false,
      status: 401,
      body: "unauthorized",
    });
    await expect(
      findFirstFreeCandidate(
        [c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z")],
        "bad-tok",
        fetcher,
        NOW,
      ),
    ).rejects.toThrow(/401/);
  });

  it.each([
    ["the calendar could not be read", { calendars: { primary: { errors: [{ domain: "global", reason: "notFound" }] } } }],
    ["no busy list", { calendars: { primary: {} } }],
    ["no primary calendar", { calendars: {} }],
    ["a malformed busy entry", { calendars: { primary: { busy: [{ start: "2026-05-01T09:00:00Z" }] } } }],
  ])("throws rather than call a slot free when %s", async (_, body) => {
    const fetcher: FreebusyFetcher = async () => ({ ok: true, status: 200, body: JSON.stringify(body) });
    await expect(
      findFirstFreeCandidate([c("2026-05-01T09:00:00Z", "2026-05-01T10:00:00Z")], "tok", fetcher, NOW),
    ).rejects.toThrow(/freebusy/);
  });

  it("sends no slot the sender put far off, reversed or too long", async () => {
    const fetcher: FreebusyFetcher = vi.fn();
    const odd = [
      c("9999-12-31T09:00:00-12:00", "9999-12-31T10:00:00-12:00"),
      c("2026-05-01T10:00:00Z", "2026-05-01T09:00:00Z"),
      c("2026-05-01T09:00:00Z", "2026-05-03T09:00:00Z"),
      c("2026-01-01T09:00:00Z", "2026-01-01T10:00:00Z"),
    ];
    expect(await findFirstFreeCandidate(odd, "tok", fetcher, NOW)).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("returns null for empty candidate list without calling API", async () => {
    const fetcher: FreebusyFetcher = vi.fn();
    expect(await findFirstFreeCandidate([], "tok", fetcher)).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });
});
