import type { Locale } from "../i18n";

/**
 * Gmail-style relative timestamp for message lists.
 *
 *   today           → time, locale-formatted (e.g. "14:30")
 *   same year       → month + day  (ja: "5月2日"  / en: "May 2")
 *   earlier years   → full y/m/d   (ja: "2025/05/02" / en: "5/2/2025")
 *
 * Why this shape: a list scan reads top-to-bottom and the eye lands
 * first on the most-recent rows, where time-of-day is what the user
 * cares about. Older rows just need a date stamp to anchor when
 * something happened; falling back to the year only when it's
 * actually a different year keeps the column narrow.
 *
 * `now` is injectable for deterministic tests. In the browser, omit
 * it and the helper reads `new Date()`.
 */
export function formatListTimestamp(
  isoText: string,
  options: { locale: Locale; now?: Date },
): string {
  const { locale } = options;
  const now = options.now ?? new Date();
  const date = new Date(isoText);
  if (Number.isNaN(date.getTime())) {
    return "--:--";
  }

  // Compare in the user's local timezone so "today" matches what the
  // user would call today, not UTC's notion. `toDateString()` returns
  // a local-timezone date with no time, which is exactly the
  // granularity we need.
  const sameDay = date.toDateString() === now.toDateString();
  if (sameDay) {
    return formatTime(date, locale);
  }

  const sameYear = date.getFullYear() === now.getFullYear();
  if (sameYear) {
    return formatMonthDay(date, locale);
  }

  return formatFullDate(date, locale);
}

function formatTime(date: Date, locale: Locale): string {
  // 24-hour time everywhere — matches the previous implementation
  // and stays compact in narrow list columns. en-GB happens to give
  // 24-hour by default; we use ja-JP / en-GB explicitly so a user
  // running the browser in 12-hour locale settings still sees the
  // same column width as everyone else.
  const tag = locale === "ja" ? "ja-JP" : "en-GB";
  return date.toLocaleTimeString(tag, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatMonthDay(date: Date, locale: Locale): string {
  if (locale === "ja") {
    // "5月2日" — Intl.DateTimeFormat with ja-JP + month: "numeric" +
    // day: "numeric" returns "5/2"; we hand-format here so the
    // ja list reads natively rather than locale-numeric.
    return `${date.getMonth() + 1}月${date.getDate()}日`;
  }
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

function formatFullDate(date: Date, locale: Locale): string {
  if (locale === "ja") {
    // "2025/05/02" — zero-pad m/d so the column doesn't jump width
    // when the month/day rolls over a digit boundary.
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, "0");
    const d = String(date.getDate()).padStart(2, "0");
    return `${y}/${m}/${d}`;
  }
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "numeric",
    day: "numeric",
  });
}
