import { describe, expect, it } from "vitest";
import type { LayoutMode } from "../src/index";

describe("ui", () => {
  it("supports layout modes", () => {
    const mode: LayoutMode = "desktop";
    expect(mode).toBe("desktop");
  });
});
