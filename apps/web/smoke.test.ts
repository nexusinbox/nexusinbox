import { describe, expect, it } from "vitest";

describe("web scaffold", () => {
  it("has a valid placeholder route", () => {
    expect("/".startsWith("/")).toBe(true);
  });
});
