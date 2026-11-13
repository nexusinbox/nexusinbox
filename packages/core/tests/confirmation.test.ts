import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { confirmationNumber } from "../src/confirmation";

const vectors = JSON.parse(
  readFileSync(new URL("../../../tests/vectors/confirmation_number.json", import.meta.url), "utf8"),
) as { cases: { a: string; b: string; number: string }[] };

describe("confirmation numbers (docs/40 §16.2)", () => {
  it("match the shared vectors, either way round", async () => {
    for (const c of vectors.cases) {
      expect(await confirmationNumber(c.a, c.b)).toBe(c.number);
      expect(await confirmationNumber(c.b, c.a)).toBe(c.number);
      expect(c.number).toMatch(/^\d{5} \d{5} \d{5} \d{5}$/);
    }
  });

  it("change when either root changes", async () => {
    const [c] = vectors.cases;
    expect(await confirmationNumber(c.a, `${c.b}x`)).not.toBe(c.number);
  });
});
