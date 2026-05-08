import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV !== "production";

// NOTE: Content-Security-Policy is set per-request in middleware.ts with a
// fresh nonce each time. Keeping CSP out of next.config's static headers
// lets us use 'nonce-<random>' 'strict-dynamic' instead of 'unsafe-inline'
// for the script-src directive (required for an E2E-encrypted app where
// XSS could exfiltrate plaintext at decryption time).

const nextConfig: NextConfig = {
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
