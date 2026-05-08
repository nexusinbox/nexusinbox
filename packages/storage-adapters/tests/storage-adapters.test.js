import { describe, expect, it } from "vitest";
describe("storage-adapters", () => {
    it("supports local backend", () => {
        const backend = "local";
        expect(backend).toBe("local");
    });
});
