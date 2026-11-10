import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import nextConfig from "./next.config";
import { buildCsp, middleware } from "./middleware";

describe("web security headers", () => {
  it("sets static security headers for all paths", async () => {
    const rules = await nextConfig.headers?.();
    expect(rules).toBeDefined();
    expect(rules?.length).toBeGreaterThan(0);

    const allPathRule = rules?.find((rule) => rule.source === "/:path*");
    expect(allPathRule).toBeDefined();
    const headers = allPathRule?.headers ?? [];
    const keys = headers.map((h) => h.key);

    expect(keys).toContain("X-Content-Type-Options");
    expect(keys).toContain("Referrer-Policy");
    expect(keys).toContain("Permissions-Policy");
    expect(keys).toContain("Strict-Transport-Security");
  });

  it("does NOT set X-Frame-Options as a static header (moved to middleware)", async () => {
    // Static XFO would conflict with the pathname-specific value
    // middleware sets for /login/idkit (SAMEORIGIN vs DENY). Keeping
    // it solely in middleware guarantees browsers see one coherent
    // value per route.
    const rules = await nextConfig.headers?.();
    const allPathRule = rules?.find((rule) => rule.source === "/:path*");
    const keys = (allPathRule?.headers ?? []).map((h) => h.key);
    expect(keys).not.toContain("X-Frame-Options");
  });

  it("builds production CSP without script unsafe-inline", () => {
    const csp = buildCsp("test-nonce", "/inbox", { isDev: false });
    expect(csp).toContain("script-src 'self' 'nonce-test-nonce' 'strict-dynamic'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
  });

  it("lists only loopback sources browsers accept for the daemon bridge", () => {
    for (const isDev of [false, true]) {
      const csp = buildCsp("test-nonce", "/", { isDev });
      const connect = csp.split("; ").find((d) => d.startsWith("connect-src "))!;
      const sources = connect.split(" ").slice(1);
      expect(sources).toContain("http://127.0.0.1:*");
      // An IP-literal host source is invalid CSP; browsers drop it noisily.
      expect(sources.some((s) => s.includes("["))).toBe(false);
    }
  });

  it("lets the browser reach the BYOK endpoints (AI draft, Calendar) by exact URL", () => {
    // These are called straight from the browser with the user's own key.
    // If they are missing from connect-src the features fail only in a
    // real browser, so pin every one of them here — in prod and dev.
    const directCalls = [
      "https://api.anthropic.com/v1/messages", // lib/llm/anthropicDraft.ts
      "https://www.googleapis.com/calendar/v3/freebusy", // lib/calendar/gcalFreebusy.ts
      "https://oauth2.googleapis.com/revoke", // google.accounts.oauth2.revoke
    ];
    for (const isDev of [false, true]) {
      const csp = buildCsp("test-nonce", "/compose", { isDev });
      const connect = csp.split("; ").find((d) => d.startsWith("connect-src "));
      expect(connect, `connect-src missing (isDev=${isDev})`).toBeDefined();
      const sources = connect!.split(" ").slice(1);
      for (const url of directCalls) {
        expect(sources, `${url} (isDev=${isDev})`).toContain(url);
      }
      // Exact URLs only: no bare provider origins and no scheme-wide escape hatch.
      expect(sources).not.toContain("https://api.anthropic.com");
      expect(sources).not.toContain("https://www.googleapis.com");
      expect(sources).not.toContain("https:");
      expect(sources).not.toContain("*");
    }
  });

  it("allows the Google sign-in frame used for silent Calendar token renewal", () => {
    const csp = buildCsp("test-nonce", "/integrations", { isDev: false });
    const frame = csp.split("; ").find((d) => d.startsWith("frame-src "));
    expect(frame).toContain("https://accounts.google.com");
  });

  it("uses the production WebSocket origin in prod connect-src, not the dev localhost one", () => {
    const prod = buildCsp("test-nonce", "/inbox", { isDev: false });
    expect(prod).toContain("wss://");
    expect(prod).not.toContain("ws://localhost:*");
    const dev = buildCsp("test-nonce", "/inbox", { isDev: true });
    expect(dev).toContain("ws://localhost:*");
  });

  it("omits 'unsafe-eval' on non-IDKit routes in production so XSS cannot bootstrap via eval", () => {
    // /login is now in the eval-free set — IDKit lives behind the
    // iframe at /login/idkit instead. Dev mode necessarily keeps
    // eval enabled (Next.js webpack eval-source-map devtool), which
    // is why this assertion pins `isDev: false` explicitly.
    for (const pathname of ["/inbox", "/settings/agents", "/compose", "/help", "/login"]) {
      const csp = buildCsp("test-nonce", pathname, { isDev: false });
      expect(csp, `unsafe-eval leaked into prod CSP for ${pathname}`).not.toContain("'unsafe-eval'");
    }
  });

  it("keeps 'unsafe-eval' on /login/idkit in production (IDKit isolation sub-route)", () => {
    const csp = buildCsp("test-nonce", "/login/idkit", { isDev: false });
    expect(csp).toContain("'unsafe-eval'");
  });

  it("grants 'unsafe-eval' everywhere in dev mode (webpack eval-source-map needs it)", () => {
    // Fresh installs / test harness default NODE_ENV=test, which the
    // middleware treats as "not production". Confirm that the dev
    // fallback unlocks eval on normal routes so `pnpm dev` works.
    for (const pathname of ["/inbox", "/login", "/login/idkit", "/settings/agents"]) {
      const csp = buildCsp("test-nonce", pathname, { isDev: true });
      expect(csp, `dev CSP must allow eval for ${pathname}`).toContain("'unsafe-eval'");
    }
  });

  it("locks frame-ancestors to 'none' on every route except /login/idkit", () => {
    for (const pathname of ["/inbox", "/settings/agents", "/compose", "/help", "/login"]) {
      const csp = buildCsp("test-nonce", pathname, { isDev: false });
      expect(csp, `frame-ancestors weakened on ${pathname}`).toContain("frame-ancestors 'none'");
    }
  });

  it("allows same-origin framing on /login/idkit (and drops the blanket 'none')", () => {
    const csp = buildCsp("test-nonce", "/login/idkit", { isDev: false });
    expect(csp).toContain("frame-ancestors 'self'");
    expect(csp).not.toContain("frame-ancestors 'none'");
  });

  it("sets dynamic CSP + X-Frame-Options on /login (parent of the iframe)", () => {
    // middleware uses the module-level IS_DEV (NODE_ENV !== "production"),
    // so the exact `'unsafe-eval'` presence depends on how tests are run.
    // Eval vs. no-eval is exhaustively covered by the buildCsp unit
    // tests above — here we only pin the route-invariant shape.
    const request = new NextRequest("https://app.nexusinbox.ai/login");
    const response = middleware(request);
    const csp = response.headers.get("Content-Security-Policy");
    const xfo = response.headers.get("X-Frame-Options");

    expect(csp).toBeTruthy();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("script-src 'self' 'nonce-");
    expect(csp).toContain("'strict-dynamic'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(xfo).toBe("DENY");
  });

  it("allows World ID hosts only on the login pages", () => {
    for (const isDev of [false, true]) {
      for (const pathname of ["/login", "/login/idkit"]) {
        const csp = buildCsp("test-nonce", pathname, { isDev });
        expect(csp, `${pathname} needs World ID`).toContain("https://bridge.worldcoin.org");
        expect(csp).toContain("https://world-id-assets.com");
      }
      for (const pathname of ["/inbox", "/settings/agents", "/compose", "/help", "/"]) {
        const csp = buildCsp("test-nonce", pathname, { isDev });
        for (const host of ["worldcoin.org", "world.org", "world-id-assets.com"]) {
          expect(csp, `${host} leaked into ${pathname} (isDev=${isDev})`).not.toContain(host);
        }
      }
    }
  });

  it("pins attachment fetches to ATTACHMENT_STORAGE_ORIGIN when it is a plain https source", () => {
    const saved = process.env.ATTACHMENT_STORAGE_ORIGIN;
    try {
      delete process.env.ATTACHMENT_STORAGE_ORIGIN;
      expect(buildCsp("n", "/inbox", { isDev: false })).toContain("https://*.r2.cloudflarestorage.com");

      process.env.ATTACHMENT_STORAGE_ORIGIN = "https://abc123.r2.cloudflarestorage.com/agent-inbox-prod/";
      const pinned = buildCsp("n", "/inbox", { isDev: false });
      expect(pinned).toContain("https://abc123.r2.cloudflarestorage.com/agent-inbox-prod/");
      expect(pinned).not.toContain("https://*.r2.cloudflarestorage.com");

      // A value that would smuggle extra sources or directives is ignored.
      process.env.ATTACHMENT_STORAGE_ORIGIN = "https://evil.example; script-src *";
      const rejected = buildCsp("n", "/inbox", { isDev: false });
      expect(rejected).toContain("https://*.r2.cloudflarestorage.com");
      expect(rejected).not.toContain("evil.example");
    } finally {
      if (saved === undefined) delete process.env.ATTACHMENT_STORAGE_ORIGIN;
      else process.env.ATTACHMENT_STORAGE_ORIGIN = saved;
    }
  });

  it("serves an agent's intro page (/to/<aid>) without a session, and nothing else under /to", () => {
    const open = middleware(new NextRequest("https://app.nexusinbox.ai/to/aid%3Aai%3A01ABC"));
    expect(open.headers.get("location")).toBeNull();
    for (const path of ["/to", "/to/", "/to/aid%3Aai%3A01ABC/more", "/topics"]) {
      const gated = middleware(new NextRequest("https://app.nexusinbox.ai" + path));
      expect(gated.headers.get("location"), path).toContain("/login?next=");
    }
  });

  it("sets X-Frame-Options: SAMEORIGIN on /login/idkit", () => {
    const request = new NextRequest("https://app.nexusinbox.ai/login/idkit");
    const response = middleware(request);
    const csp = response.headers.get("Content-Security-Policy");
    const xfo = response.headers.get("X-Frame-Options");

    expect(csp).toContain("frame-ancestors 'self'");
    expect(csp).toContain("'unsafe-eval'");
    expect(xfo).toBe("SAMEORIGIN");
  });
});
