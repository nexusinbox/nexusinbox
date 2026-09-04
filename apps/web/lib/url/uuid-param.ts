/**
 * Validate an identifier read from the query string before it is used
 * as an API path segment (`/messages/<id>/content` etc).
 *
 * Message and agent ids are server-generated UUIDs. Anything else
 * arriving via `?reply=` / `?forward=` is a crafted link rather than a
 * real id, so we drop it instead of forwarding it: a shared URL must
 * never be able to steer the page into fetching an unexpected path on
 * our own origin.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function sanitiseUuidParam(raw: string | null | undefined): string | null {
  if (!raw) return null;
  return UUID_RE.test(raw) ? raw : null;
}
