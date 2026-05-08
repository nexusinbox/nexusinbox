/**
 * Shared E2E helpers for surviving the auth gate in
 * `apps/web/middleware.ts`.
 *
 * The middleware (line 215) rejects any cookie whose decoded JWT
 * payload doesn't have a future `exp` — and `isTokenExpired` (line
 * 32) treats anything that isn't 3 dot-separated parts as already
 * expired. A literal placeholder like `"e2e-session"` therefore
 * fails the gate, the request is redirected to `/login?next=...`,
 * and the spec never mounts the protected route it's trying to
 * exercise.
 *
 * Use `makeFutureSessionJwt()` to mint a syntactically valid token
 * with a 1-hour future `exp`. Middleware does no signature check
 * (the API server does), and specs typically mock
 * `/api/auth/session` so no signed call ever flies — that's why
 * the signature segment is the literal string `"sig"`. This keeps
 * E2E tests independent of `JWT_SECRET`.
 */

import type { BrowserContext } from "@playwright/test";

const SESSION_COOKIE_NAME = "nexusinbox_session";

/**
 * Build a 3-segment JWT with `exp = now + 1 hour`. Unsigned (sig
 * segment is the literal "sig"); see file-level docstring.
 */
export function makeFutureSessionJwt(): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "none", typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      sub: "e2e-user",
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    }),
  ).toString("base64url");
  return `${header}.${payload}.sig`;
}

/**
 * Inject a future-`exp` session cookie into the browser context so
 * the next navigation to a protected route survives middleware.
 *
 * `baseURL` is Playwright's `baseURL` from the test fixture (or any
 * absolute URL); pass through verbatim.
 */
export async function seedAuthSessionCookie(
  context: BrowserContext,
  baseURL: string | undefined,
): Promise<void> {
  const url = baseURL ?? "http://127.0.0.1:3210";
  await context.addCookies([
    {
      name: SESSION_COOKIE_NAME,
      value: makeFutureSessionJwt(),
      url,
    },
  ]);
}
