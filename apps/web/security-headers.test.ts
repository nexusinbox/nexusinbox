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
