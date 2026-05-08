import { NextRequest, NextResponse } from "next/server";

// Session state is per-user and per-request. A cached copy would leak
// one user's auth state to anyone who hits the same edge cache key, and
// would also miss cookie expirations from upstream. Force-dynamic keeps
// Next.js server-side fresh; the headers below keep the browser, the
// Vercel edge, and any intermediate proxy from retaining the response.
export const dynamic = "force-dynamic";

const NO_CACHE_HEADERS = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  Pragma: "no-cache",
  Expires: "0",
} as const;

function applyNoCache(response: NextResponse): NextResponse {
  for (const [k, v] of Object.entries(NO_CACHE_HEADERS)) {
    response.headers.set(k, v);
  }
  return response;
}

const apiOrigin = process.env.API_ORIGIN ?? (process.env.NODE_ENV === "production" ? "" : "http://localhost:8080");
if (!apiOrigin) {
  throw new Error("API_ORIGIN environment variable is required in production");
}
const AUTH_COOKIE_NAME = "nexusinbox_session";

function shouldUseSecureCookie(request: NextRequest): boolean {
  const configured = process.env.AGENT_INBOX_COOKIE_SECURE;
  if (configured && (configured === "1" || configured.toLowerCase() === "true")) {
    return true;
  }
  return request.nextUrl.protocol === "https:";
}

// Must mirror the Domain attribute the Rust API uses when it originally
// issued the cookie. Otherwise the browser sees our "clear" directive as
// a different cookie (host-scoped) and leaves the domain-scoped session
// alive — the user stays logged-in despite a 401 from upstream.
function cookieDomainAttr(): string {
  const domain = process.env.AGENT_INBOX_COOKIE_DOMAIN?.trim();
  return domain ? `; Domain=${domain}` : "";
}

function clearSessionCookie(request: NextRequest): string {
  const secureAttr = shouldUseSecureCookie(request) ? "; Secure" : "";
  const domainAttr = cookieDomainAttr();
  return `${AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secureAttr}${domainAttr}`;
}

export async function GET(request: NextRequest) {
  const forwardedCookie = request.headers.get("cookie") ?? "";

  let upstream: Response;
  try {
    upstream = await fetch(`${apiOrigin}/auth/session`, {
      method: "GET",
      headers: {
        cookie: forwardedCookie,
      },
      cache: "no-store",
    });
  } catch {
    const response = NextResponse.json(
      { authenticated: false, reason: "upstream_unavailable" },
      { status: 503 },
    );
    response.headers.append("set-cookie", clearSessionCookie(request));
    return applyNoCache(response);
  }

  let payload: Record<string, unknown>;
  try {
    payload = (await upstream.json()) as Record<string, unknown>;
  } catch {
    payload = { authenticated: upstream.ok };
  }

  const response = NextResponse.json(payload, { status: upstream.status });

  const upstreamHeaders = upstream.headers as Headers & { getSetCookie?: () => string[] };
  const setCookies =
    typeof upstreamHeaders.getSetCookie === "function"
      ? upstreamHeaders.getSetCookie()
      : (() => {
          const single = upstream.headers.get("set-cookie");
          return single ? [single] : [];
        })();

  for (const cookie of setCookies) {
    if (cookie) {
      response.headers.append("set-cookie", cookie);
    }
  }

  if (upstream.status === 401) {
    response.headers.append("set-cookie", clearSessionCookie(request));
  }

  return applyNoCache(response);
}

export async function PATCH(request: NextRequest) {
  const forwardedCookie = request.headers.get("cookie") ?? "";
  const body = await request.text();

  // Forward the browser's Origin/Referer so the API CSRF middleware
  // can match against its allowlist. Without these, the backend
  // rejects state-changing requests with 403 "request origin is not allowed".
  const forwardHeaders: Record<string, string> = {
    "content-type": "application/json",
    cookie: forwardedCookie,
  };
  const originHeader = request.headers.get("origin");
  if (originHeader) forwardHeaders["origin"] = originHeader;
  const refererHeader = request.headers.get("referer");
  if (refererHeader) forwardHeaders["referer"] = refererHeader;

  let upstream: Response;
  try {
    upstream = await fetch(`${apiOrigin}/auth/session`, {
      method: "PATCH",
      headers: forwardHeaders,
      body,
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { error: "upstream_unavailable", message: "プロフィールサーバに接続できませんでした。" },
      { status: 503 },
    );
  }

  let payload: unknown;
  try {
    payload = await upstream.json();
  } catch {
    payload = { error: "upstream_invalid", message: "サーバ応答を解釈できませんでした。" };
  }

  const response = NextResponse.json(payload, { status: upstream.status });

  const upstreamHeaders = upstream.headers as Headers & { getSetCookie?: () => string[] };
  const setCookies =
    typeof upstreamHeaders.getSetCookie === "function"
      ? upstreamHeaders.getSetCookie()
      : (() => {
          const single = upstream.headers.get("set-cookie");
          return single ? [single] : [];
        })();

  for (const cookie of setCookies) {
    if (cookie) {
      response.headers.append("set-cookie", cookie);
    }
  }

  return response;
}
