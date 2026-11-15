import { describe, expect, it } from "vitest";
import { onboardingHref, parseAi, resumeStep, stepsFor } from "./flow";

describe("first-run order", () => {
  it("skips connecting for the web", () => {
    expect(stepsFor("web")).toEqual(["ai", "name", "replies", "test", "done"]);
    expect(stepsFor("claude_code")).toContain("connect");
  });

  it("only takes the AI tools that can be chosen", () => {
    expect(parseAi("claude_code")).toBe("claude_code");
    expect(parseAi("muse")).toBeNull();
    expect(parseAi(null)).toBeNull();
  });
});

describe("resumeStep", () => {
  it("does not carry on where the key is not", () => {
    expect(resumeStep({ ai: "claude_code", keyHere: false, allowed: true })).toBe("elsewhere");
  });

  it("asks which AI when that was not kept", () => {
    expect(resumeStep({ ai: null, keyHere: true, allowed: false })).toBe("ai");
  });

  it("stays at connecting until the AI is allowed", () => {
    expect(resumeStep({ ai: "claude_code", keyHere: true, allowed: false })).toBe("connect");
    expect(resumeStep({ ai: "claude_code", keyHere: true, allowed: true })).toBe("replies");
    expect(resumeStep({ ai: "web", keyHere: true, allowed: false })).toBe("replies");
  });
});

describe("onboardingHref", () => {
  it("keeps the agent, the AI and an invitation's address", () => {
    expect(onboardingHref({ agent: "a1", ai: "claude_code", with: "aid:ai:X" })).toBe(
      "/onboarding?agent=a1&ai=claude_code&with=aid%3Aai%3AX",
    );
    expect(onboardingHref({})).toBe("/onboarding");
  });
});
