/**
 * Validate a post-login redirect target coming from the `?next=`
 * query parameter.
 *
 * Accepts exactly one shape: an absolute site-relative path starting
 * with a single `/` and NOT a protocol-relative `//foo` (which
 * browsers would treat as scheme-relative to the current origin's
 * protocol and hop off-site). Anything else — absolute URLs,
 * `javascript:` URIs, backslash-prefixed variants — falls back to
 * the homepage.
 *
 * Without this guard, an attacker who gets the victim to click
 * `/login?next=https://evil.example/` could land them on an
 * arbitrary domain after World ID auth completes. That's a cheap
 * phishing primitive: the victim is "on NexusInbox" right up to
 * the moment of auth, then suddenly isn't.
 */
export function sanitiseNextPath(raw: string | null | undefined): string {
  if (!raw) return "/";
  // Control characters and whitespace first. The URL parser strips
  // ASCII TAB / LF / CR before it interprets a URL, so "/\t/evil.test"
  // passes a leading-characters check yet navigates to the
  // protocol-relative "//evil.test" (review 2026-11-07). Backslashes
  // are dropped for the same reason: parsers normalise `\` to `/`.
  if (/[\u0000-\u001f\u007f\s\\]/.test(raw)) return "/";
  // A single leading slash followed by something other than `/`. This
  // rejects "" / "https://evil.test" / "//evil.test" /
  // "javascript:alert(1)".
  if (!/^\/[^/]/.test(raw)) return "/";
  // Finally let the same parser that will perform the navigation decide
  // where it goes, and keep only the same-origin path it resolved to.
  const base = "https://nexusinbox.invalid";
  let parsed: URL;
  try {
    parsed = new URL(raw, base);
  } catch {
    return "/";
  }
  if (parsed.origin !== base) return "/";
  return parsed.pathname + parsed.search + parsed.hash;
}
