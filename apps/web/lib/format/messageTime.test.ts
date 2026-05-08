import { describe, expect, it } from "vitest";
import { formatListTimestamp } from "./messageTime";

// Anchor `now` to a fixed local instant so the day/year comparisons
// behave the same on every machine running the suite. We pick noon
// so an "earlier today" sample at 02:00 doesn't accidentally cross
// midnight boundaries due to timezone math.
const NOW = new Date("2026-05-02T12:00:00");

describe("formatListTimestamp — Gmail-style", () => {
  describe("today (same y/m/d as now)", () => {
    it("ja shows HH:mm", () => {
      const out = formatListTimestamp("2026-05-02T02:30:00", {
        locale: "ja",
        now: NOW,
      });
      expect(out).toBe("02:30");
    });

    it("en shows HH:mm (24-hour, en-GB)", () => {
      const out = formatListTimestamp("2026-05-02T14:30:00", {
        locale: "en",
        now: NOW,
      });
      expect(out).toBe("14:30");
    });

    it("HH:mm at exactly midnight", () => {
      const out = formatListTimestamp("2026-05-02T00:00:00", {
        locale: "ja",
        now: NOW,
      });
      expect(out).toBe("00:00");
    });
  });

  describe("same year, not today", () => {
    it("ja uses '<m>月<d>日' (no zero-pad)", () => {
      const out = formatListTimestamp("2026-04-30T12:00:00", {
        locale: "ja",
        now: NOW,
      });
      expect(out).toBe("4月30日");
    });

    it("ja yesterday is m/d, not time", () => {
      const out = formatListTimestamp("2026-05-01T23:59:59", {
        locale: "ja",
        now: NOW,
      });
      expect(out).toBe("5月1日");
    });

    it("en uses 'MMM d'", () => {
      const out = formatListTimestamp("2026-04-30T12:00:00", {
        locale: "en",
        now: NOW,
      });
      // Intl.DateTimeFormat normalises with NBSP between month & day
      // on some Node ICU builds; compare loosely so the test is
      // resilient to that.
      expect(out.replace(/\s+/g, " ")).toBe("Apr 30");
    });
  });

  describe("earlier year", () => {
    it("ja uses zero-padded YYYY/MM/DD", () => {
      const out = formatListTimestamp("2025-03-09T08:15:00", {
        locale: "ja",
        now: NOW,
      });
      expect(out).toBe("2025/03/09");
    });

    it("en uses M/D/YYYY (en-US locale-numeric)", () => {
      const out = formatListTimestamp("2025-03-09T08:15:00", {
        locale: "en",
        now: NOW,
      });
      expect(out).toBe("3/9/2025");
    });

    it("Dec 31 of last year still rolls into earlier-year branch", () => {
      const out = formatListTimestamp("2025-12-31T23:59:59", {
        locale: "ja",
        now: NOW,
      });
      expect(out).toBe("2025/12/31");
    });
  });

  describe("invalid input", () => {
    it("returns the --:-- placeholder for an unparseable string", () => {
      const out = formatListTimestamp("not-a-date", {
        locale: "ja",
        now: NOW,
      });
      expect(out).toBe("--:--");
    });
  });
});
