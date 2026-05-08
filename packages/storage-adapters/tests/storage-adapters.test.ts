import { describe, expect, it } from "vitest";
import type { StorageBackend } from "../src/index";

describe("storage-adapters", () => {
  it("supports local backend", () => {
    const backend: StorageBackend = "local";
    expect(backend).toBe("local");
  });
});
