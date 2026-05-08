import { NextRequest, NextResponse } from "next/server";

const apiOrigin = process.env.API_ORIGIN ?? (process.env.NODE_ENV === "production" ? "" : "http://localhost:8080");
if (!apiOrigin) {
  throw new Error("API_ORIGIN environment variable is required in production");
}

export async function POST(request: NextRequest) {
  const rawBody = await request.text();

  // Forward the browser's Origin/Referer so the API can perform CSRF check.
  const forwardHeaders: Record<string, string> = {
    "content-type": "application/json",
  };
  const originHeader = request.headers.get("origin");
  if (originHeader) forwardHeaders["origin"] = originHeader;
  const refererHeader = request.headers.get("referer");
  if (refererHeader) forwardHeaders["referer"] = refererHeader;

  const upstream = await fetch(`${apiOrigin}/auth/verify`, {
    method: "POST",
    headers: forwardHeaders,
    body: rawBody,
    cache: "no-store",
  });

  const contentType = upstream.headers.get("content-type") ?? "application/json";
  const responseText = await upstream.text();

  let response: NextResponse;
  if (contentType.includes("application/json")) {
    try {
      response = NextResponse.json(JSON.parse(responseText), {
        status: upstream.status,
      });
    } catch {
      response = new NextResponse(responseText, {
        status: upstream.status,
        headers: { "content-type": "application/json" },
      });
    }
  } else {
    response = new NextResponse(responseText, {
      status: upstream.status,
      headers: { "content-type": contentType || "text/plain; charset=utf-8" },
    });
  }

  const upstreamHeaders = upstream.headers as Headers & {
    getSetCookie?: () => string[];
  };
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
