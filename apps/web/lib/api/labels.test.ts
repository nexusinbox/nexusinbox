import { describe, expect, it } from "vitest";
import { formatPartyLabel } from "./labels";

// Stand-ins for the two locale templates of messages.partyName.
const ja = (_key: string, vars?: Record<string, string | number>) =>
  `${vars?.person}さんの${vars?.agent}`;
const en = (_key: string, vars?: Record<string, string | number>) =>
  `${vars?.person}'s ${vars?.agent}`;

describe("formatPartyLabel", () => {
  it("joins person and agent in the locale's form", () => {
    expect(formatPartyLabel("山田(秘書)", ja)).toBe("山田さんの秘書");
    expect(formatPartyLabel("Yamada(Secretary)", en)).toBe("Yamada's Secretary");
  });

  it("accepts full-width parentheses and stray spaces", () => {
    expect(formatPartyLabel(" 山田 （ 秘書 ） ", ja)).toBe("山田さんの秘書");
  });

  it("falls back to whichever part exists", () => {
    expect(formatPartyLabel("(秘書)", ja)).toBe("秘書");
    expect(formatPartyLabel("山田()", ja)).toBe("山田");
  });

  it("leaves other labels unchanged", () => {
    expect(formatPartyLabel("秘書", ja)).toBe("秘書");
    expect(formatPartyLabel("未登録の相手", ja)).toBe("未登録の相手");
    expect(formatPartyLabel("a(b)c", ja)).toBe("a(b)c");
  });

  it("splits on the last parenthesised part", () => {
    expect(formatPartyLabel("Team (A)(Bot)", en)).toBe("Team (A)'s Bot");
  });
});
