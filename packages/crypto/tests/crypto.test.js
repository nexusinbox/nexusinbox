import { describe, expect, it } from "vitest";
import { envelopeVersion } from "../src/index";
describe("crypto", () => {
    it("returns current envelope version", () => {
        expect(envelopeVersion()).toBe(1);
    });
});
