import { describe, expect, it } from "vitest";
import { sanitiseNextPath } from "./next-path";

describe("sanitiseNextPath", () => {
  it("accepts a simple site-relative path", () => {
    expect(sanitiseNextPath("/inbox")).toBe("/inbox");
    expect(sanitiseNextPath("/settings/agents")).toBe("/settings/agents");
    expect(sanitiseNextPath("/compose?to=aid:ai:x")).toBe("/compose?to=aid:ai:x");
  });

  it("falls back to '/' on null / undefined / empty input", () => {
    expect(sanitiseNextPath(null)).toBe("/");
    expect(sanitiseNextPath(undefined)).toBe("/");
    expect(sanitiseNextPath("")).toBe("/");
  });

  it("rejects absolute URLs (open redirect primitive)", () => {
    expect(sanitiseNextPath("https://evil.example")).toBe("/");
    expect(sanitiseNextPath("http://evil.example/inbox")).toBe("/");
  });

  it("rejects protocol-relative URLs (//evil.example hops off-site)", () => {
    expect(sanitiseNextPath("//evil.example")).toBe("/");
    expect(sanitiseNextPath("//evil.example/inbox")).toBe("/");
  });

  it("rejects backslash-prefixed sneaks past naive regex", () => {
    // Some older browsers and servers normalise \\ to // before
    // navigation; reject to stay safe under every combination.
    expect(sanitiseNextPath("/\\evil.example")).toBe("/");
  });

  it("rejects scheme-only inputs without a leading slash", () => {
    expect(sanitiseNextPath("javascript:alert(1)")).toBe("/");
    expect(sanitiseNextPath("data:text/html,<script>")).toBe("/");
  });

  it("rejects paths that don't start with a slash", () => {
    expect(sanitiseNextPath("inbox")).toBe("/");
    expect(sanitiseNextPath("settings/agents")).toBe("/");
  });
});
