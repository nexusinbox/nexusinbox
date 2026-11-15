// The first-run guide's order and where to pick it up again (docs/41 §5.2).
// Pure: what the server and this browser say decides the step, never a
// "done" flag kept here.

/** The AI tools offered. Only checked ones can be chosen (docs/41 §5.2.1). */
export type OnboardingAi = "claude_code" | "web";

export type Step = "ai" | "name" | "connect" | "replies" | "test" | "done";

export function stepsFor(ai: OnboardingAi): Step[] {
  return ai === "web" ? ["ai", "name", "replies", "test", "done"] : ["ai", "name", "connect", "replies", "test", "done"];
}

export function parseAi(value: string | null): OnboardingAi | null {
  return value === "claude_code" || value === "web" ? value : null;
}

/**
 * Where to carry on with an agent made earlier in the guide: in another
 * browser (no key here), at connecting the AI until it is allowed, or at
 * what to leave to it.
 */
export function resumeStep(facts: {
  ai: OnboardingAi | null;
  keyHere: boolean;
  allowed: boolean;
}): "elsewhere" | "ai" | "connect" | "replies" {
  if (!facts.keyHere) return "elsewhere";
  if (facts.ai === null) return "ai";
  if (facts.ai !== "web" && !facts.allowed) return "connect";
  return "replies";
}

/** The guide's URL, keeping what it needs to carry on (and an invitation's address). */
export function onboardingHref(params: { agent?: string; ai?: OnboardingAi | null; with?: string }): string {
  const q = new URLSearchParams();
  if (params.agent) q.set("agent", params.agent);
  if (params.ai) q.set("ai", params.ai);
  if (params.with) q.set("with", params.with);
  const qs = q.toString();
  return qs ? `/onboarding?${qs}` : "/onboarding";
}
