import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

const AUTH_COOKIE_NAME = "nexusinbox_session";
const IS_DEV = process.env.NODE_ENV !== "production";

function isPublicPath(pathname: string): boolean {
  if (pathname === "/login") return true;
  // IDKit isolation sub-route — embedded as an iframe by /login.
  // Must be reachable without a session cookie, otherwise the
  // unauth'd redirect below rewrites it to /login and the iframe
  // ends up with /login's headers instead of its own (SAMEORIGIN +
  // 'unsafe-eval'). See docs/18_production_bootstrap_runbook.md §10.3.
  if (pathname === "/login/idkit") return true;
  if (pathname === "/concept") return true;
  if (pathname === "/privacy") return true;
  if (pathname === "/terms") return true;
  // /help is public-readable: the page renders Basics for everyone and
  // gates Advanced (MCP setup, API reference, daemon detail) behind the
  // session check inside the React tree. See apps/web/app/help/page.tsx.
  if (pathname === "/help") return true;
  if (pathname.startsWith("/api/")) return true;
  if (pathname.startsWith("/_next/")) return true;
  if (pathname === "/favicon.ico") return true;
  // Next 15 file-convention metadata routes. SNS crawlers
  // (Twitter, Slack, Facebook, Discord) hit these anonymously when
  // unfurling a shared link — gating them behind /login means the
  // crawler follows a 307, never reaches the image, and the social
  // card renders without artwork. Anything we drop into `app/` that
  // emits a public asset (opengraph-image.tsx, twitter-image.tsx,
  // icon.*, apple-icon.*, manifest.* …) needs to be allow-listed
  // here for the same reason.
  if (pathname === "/opengraph-image") return true;
  if (pathname === "/twitter-image") return true;
  if (pathname === "/icon" || pathname === "/icon.svg") return true;
  if (pathname === "/apple-icon") return true;
  if (pathname === "/manifest.webmanifest") return true;
  if (pathname === "/robots.txt") return true;
  if (pathname === "/sitemap.xml") return true;
  return false;
}

/**
 * Quick JWT expiry check without signature verification.
 * Decodes the payload (base64url) and checks the `exp` claim.
 * Signature verification is performed by the API server.
 */
function isTokenExpired(token: string): boolean {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return true;
    // base64url → base64 → decode
    const payload = parts[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const decoded = JSON.parse(atob(payload));
    if (typeof decoded.exp !== "number") return true;
    // Allow 30s clock skew
    return decoded.exp < Date.now() / 1000 - 30;
  } catch {
    return true;
  }
}

/**
 * Paths that need `'unsafe-eval'` in script-src. Keep this list
 * tight — every entry here is a page where a successful XSS
 * payload gets `eval()` / `new Function()` access and can therefore
 * bypass the nonce + strict-dynamic protection. Today the only
 * genuine need is the IDKit-isolated sub-route `/login/idkit`; its
 * transitive WalletConnect dependency calls `Function()` internally
 * and refuses to load under a eval-free CSP. The parent /login
 * embeds /login/idkit via iframe so the eval blast radius stays
 * inside that sub-route.
 *
 * When IDKit appears on a new route (e.g. a future re-auth modal),
 * route it through an iframe pointing at /login/idkit instead of
 * adding new entries here. The invariant "eval is allowed on
 * exactly one route" is what keeps the XSS surface bounded.
 */
const UNSAFE_EVAL_PATHS = new Set<string>(["/login/idkit"]);

/**
 * Paths that are allowed to be embedded in a same-origin iframe.
 * Everything else declares `frame-ancestors 'none'` + sends
 * `X-Frame-Options: DENY` (defense in depth for older browsers
 * that predate CSP 2).
 *
 * Currently only the IDKit isolation sub-route qualifies: it has
 * to be embedded by the parent /login to keep the iframe pattern
 * working. Nothing else in the app needs to be iframed.
 */
const SAME_ORIGIN_FRAME_PATHS = new Set<string>(["/login/idkit"]);

/**
 * Build a per-request Content-Security-Policy header with a fresh nonce.
 *
 * Next.js App Router injects inline scripts for hydration. Previously we
 * allowed those via `'unsafe-inline'`, which defeats most of CSP's XSS
 * mitigations. For an E2E-encrypted app, XSS is catastrophic — a successful
 * injection could exfiltrate plaintext at decryption time. We now mint a
 * nonce per request and allow only scripts that carry it; paired with
 * `'strict-dynamic'` so Next's own loader can load further chunks without
 * needing a static allowlist.
 *
 * `pathname` controls whether `'unsafe-eval'` is granted — see
 * {@link UNSAFE_EVAL_PATHS}. Keeping the relaxation scoped to the
 * IDKit route means an XSS on `/inbox`, `/settings/agents`,
 * `/compose`, etc. cannot use `eval()` to sidestep the nonce.
 *
 * Inline styles (styled-jsx, Next.js internal) still require `'unsafe-inline'`
 * because Next.js does not yet emit nonces on `<style>` tags. CSS injection is
 * strictly less dangerous than JS injection, so we scope the relaxation to
 * `style-src` only.
 */
export function buildCsp(
  nonce: string,
  pathname: string,
  opts: { isDev?: boolean } = {},
): string {
  // `'unsafe-eval'` is granted on two classes of page:
  //   1. Routes in UNSAFE_EVAL_PATHS — currently just /login/idkit,
  //      which embeds IDKit and cannot run under a eval-free CSP.
  //   2. Every route when we're in dev — Next.js's default webpack
  //      devtool (`eval-source-map`) emits bundles that call `eval()`
  //      at runtime. Without `unsafe-eval` in dev the scripts load
  //      but never execute, and React never hydrates. In production
  //      builds there is no eval in the bundles so this relaxation
  //      disappears.
  //
  // Keep the branches explicit so reviewers can see why dev runs
  // looser than prod. See docs/18_production_bootstrap_runbook.md
  // §10.3 for the original IDKit / WalletConnect rationale.
  //
  // `opts.isDev` defaults to the module-level `IS_DEV` so the live
  // middleware automatically picks the right branch. Tests pass it
  // explicitly to assert the production shape regardless of the
  // vitest NODE_ENV (which is "test", not "production").
  const isDev = opts.isDev ?? IS_DEV;
  const allowUnsafeEval = isDev || UNSAFE_EVAL_PATHS.has(pathname);
  const scriptSrc = allowUnsafeEval
    ? `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`
    : `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`;

  // `frame-ancestors 'self'` only on the IDKit isolation sub-route
  // — the parent /login is same-origin and needs to embed it. Every
  // other route stays 'none' so no page can be framed (clickjacking
  // + phishing protection).
  const allowSameOriginFrame = SAME_ORIGIN_FRAME_PATHS.has(pathname);
  const frameAncestors = allowSameOriginFrame
    ? "frame-ancestors 'self'"
    : "frame-ancestors 'none'";

  // Loopback Signer Daemon bridge (docs/22 Phase 3a). Listed in both
  // dev and prod `connect-src` so the Web UI can reach a user-run
  // daemon at http://127.0.0.1:<port> without CSP blocking the
  // fetch. Safe because the browser still honours Private Network
  // Access preflights and the daemon itself enforces Origin + bearer
  // token; CSP is the belt, PNA + bearer is the braces.
  const bridgeConnect =
    "http://127.0.0.1:* http://[::1]:* http://localhost:*";

  // Attachment downloads are fetched from a Cloudflare R2 presigned URL
  // (AGENT_INBOX_S3_ENDPOINT, shaped `<account>.r2.cloudflarestorage.com`).
  // Without this entry the production CSP blocks the ConversationThread
  // attachment fetch. Scoped to the R2 S3-endpoint wildcard, not `*`.
  const r2Connect = "https://*.r2.cloudflarestorage.com";

  const connectSrc = IS_DEV
    ? `connect-src 'self' http://localhost:* ws://localhost:* ${bridgeConnect} ${r2Connect} https://bridge.worldcoin.org https://*.worldcoin.org https://*.world.org`
    : `connect-src 'self' ${process.env.NEXT_PUBLIC_WS_URL ?? "wss://app.nexusinbox.ai/ws"} ${bridgeConnect} ${r2Connect} https://bridge.worldcoin.org https://*.worldcoin.org https://*.world.org`;

  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    frameAncestors,
    "frame-src 'self' https://bridge.worldcoin.org https://*.worldcoin.org https://*.world.org",
    "form-action 'self'",
    // IDKit v4 fetches TWK Lausanne fonts (5 weights) from
    // `world-id-assets.com` and may pull occasional brand assets /
    // QR icons from the same origin. Both are governed by Worldcoin
    // and are not in `*.worldcoin.org` / `*.world.org`, so we list
    // them explicitly. Without this, the IDKit widget renders in
    // fallback fonts and iOS Safari can show a "content blocked"
    // interstitial when CSP violations pile up.
    "img-src 'self' data: blob: https://world-id-assets.com",
    "font-src 'self' data: https://world-id-assets.com",
    scriptSrc,
    // style-src stays 'unsafe-inline' — Next.js / styled-jsx emit inline styles
    // without nonces and CSS injection is significantly less dangerous than JS.
    "style-src 'self' 'unsafe-inline'",
    connectSrc,
  ].join("; ");
}

/**
 * Generate a 128-bit cryptographically random nonce and base64-encode it.
 * Uses the Web Crypto API available in the Edge Runtime.
 */
function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // base64 encode without importing Buffer (not available in Edge)
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const sessionValue = request.cookies.get(AUTH_COOKIE_NAME)?.value;

  // Mint a fresh nonce for every request and thread it through request
  // headers so server components / root layout can stamp it on script tags.
  const nonce = generateNonce();
  // `pathname` controls whether `'unsafe-eval'` is granted — only IDKit
  // routes (`/login`) need it. Everywhere else runs under a strict
  // nonce + strict-dynamic CSP so an XSS on e.g. /inbox cannot
  // escape via eval().
  const csp = buildCsp(nonce, pathname);

  // `X-Frame-Options` is legacy cousin of `frame-ancestors`; modern
  // browsers let CSP win, but older ones (IE11 / early Edge) only
  // look at XFO. We keep both in sync: DENY everywhere except the
  // IDKit isolation sub-route, which needs SAMEORIGIN so the
  // parent /login can embed it. Setting this here (not via
  // next.config.ts static headers) so the pathname-specific
  // value is authoritative with no conflicting static header.
  const xFrameOptions = SAME_ORIGIN_FRAME_PATHS.has(pathname) ? "SAMEORIGIN" : "DENY";

  const buildResponse = () => {
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set("x-nonce", nonce);
    // Make the CSP visible to any SSR code that needs it.
    requestHeaders.set("content-security-policy", csp);
    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set("Content-Security-Policy", csp);
    response.headers.set("X-Frame-Options", xFrameOptions);
    return response;
  };

  if (isPublicPath(pathname)) {
    return buildResponse();
  }

  if (!sessionValue || isTokenExpired(sessionValue)) {
    const loginUrl = new URL("/login", request.url);
    const nextPath = pathname + search;
    loginUrl.searchParams.set("next", nextPath);
    const response = NextResponse.redirect(loginUrl);
    response.headers.set("Content-Security-Policy", csp);
    response.headers.set("X-Frame-Options", xFrameOptions);
    // Clear stale cookie to avoid redirect loops
    if (sessionValue) {
      response.cookies.delete(AUTH_COOKIE_NAME);
    }
    return response;
  }

  return buildResponse();
}

export const config = {
  // Run middleware on every page navigation AND every static asset request,
  // except for Next internals that must never be rewritten.
  matcher: [
    {
      source:
        "/((?!api|_next/static|_next/image|favicon.ico|icon.svg).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
