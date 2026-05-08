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
  // Reject anything that isn't a single leading slash followed by
  // something other than `/` or `\`. This rejects:
  //   - ""                    (no leading slash)
  //   - "https://evil.test"   (scheme)
  //   - "//evil.test"         (protocol-relative)
  //   - "/\evil.test"         (backslash-sneak past naive regex)
  //   - "javascript:alert(1)" (scheme, no slash)
  if (!/^\/[^/\\]/.test(raw)) return "/";
  return raw;
}
