import type { NextConfig } from "next";
import { CONVERSATION_PARAMS } from "./lib/url/conversations";

const isDev = process.env.NODE_ENV !== "production";

// NOTE: Content-Security-Policy is set per-request in middleware.ts with a
// fresh nonce each time. Keeping CSP out of next.config's static headers
// lets us use 'nonce-<random>' 'strict-dynamic' instead of 'unsafe-inline'
// for the script-src directive (required for an E2E-encrypted app where
// XSS could exfiltrate plaintext at decryption time).

// Which build this is. Open tabs compare theirs with the server's to tell
// the person a new version is out (app/_components/NewVersionNotice.tsx).
// It must be the same in every build worker, so it comes from the
// environment: the deployed commit on Vercel; empty, and the notice off,
// elsewhere unless set.
const appVersion =
  process.env.NEXT_PUBLIC_APP_VERSION || process.env.VERCEL_GIT_COMMIT_SHA || "";

const nextConfig: NextConfig = {
  env: { NEXT_PUBLIC_APP_VERSION: appVersion },
  allowedDevOrigins: ["https://app.nexusinbox.ai"],
  async rewrites() {
    const apiOrigin = process.env.API_ORIGIN ?? (isDev ? "http://localhost:8080" : "");
    if (!apiOrigin) {
      throw new Error("API_ORIGIN environment variable is required in production");
    }
    return [
      {
        source: "/api/:path*",
        destination: `${apiOrigin}/:path*`,
      },
    ];
  },
  // The old per-agent inbox (/agent, /agent/<DID>) is gone; bookmarks land
  // on the conversations, filtered to that agent. Home took `/` (docs/41
  // §3.1): a link to `/` naming a conversation, an agent or a view still
  // opens the conversations (the query is passed on), and 「確認が必要」
  // (/pending) is Home's 「あなたの判断が必要」.
  async redirects() {
    return [
      { source: "/agent", destination: "/conversations", permanent: false },
      { source: "/agent/:did", destination: "/conversations?agent=:did", permanent: false },
      ...CONVERSATION_PARAMS.map((key) => ({
        source: "/",
        has: [{ type: "query" as const, key }],
        destination: "/conversations",
        permanent: false,
      })),
      { source: "/pending", destination: "/#attention", permanent: false },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          // X-Frame-Options is set per-request in middleware.ts so the
          // /login/idkit isolation sub-route can be SAMEORIGIN while
          // every other path stays DENY. Defining it as a static
          // header here would conflict with the middleware value and
          // make iframe embedding behaviour browser-dependent.
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          // Enforce HTTPS for 1 year, include subdomains, allow HSTS preload
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" },
        ],
      },
    ];
  },
};

export default nextConfig;
