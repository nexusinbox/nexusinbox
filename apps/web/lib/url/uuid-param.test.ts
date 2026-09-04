import { describe, expect, it } from "vitest";
import { sanitiseUuidParam } from "./uuid-param";

describe("sanitiseUuidParam", () => {
  it("passes a well-formed UUID through unchanged", () => {
    const id = "2b6d8a1e-0c4f-4b7e-9a1d-3c5e7f9b1d2e";
    expect(sanitiseUuidParam(id)).toBe(id);
    expect(sanitiseUuidParam(id.toUpperCase())).toBe(id.toUpperCase());
  });

  it("returns null for empty input", () => {
    expect(sanitiseUuidParam(null)).toBeNull();
    expect(sanitiseUuidParam(undefined)).toBeNull();
    expect(sanitiseUuidParam("")).toBeNull();
  });

  it("rejects anything that is not exactly one UUID", () => {
    expect(sanitiseUuidParam("../auth/session")).toBeNull();
    expect(sanitiseUuidParam("2b6d8a1e-0c4f-4b7e-9a1d-3c5e7f9b1d2e/content")).toBeNull();
    expect(sanitiseUuidParam("2b6d8a1e-0c4f-4b7e-9a1d-3c5e7f9b1d2e?x=1")).toBeNull();
    expect(sanitiseUuidParam("not-a-uuid")).toBeNull();
  });
});
