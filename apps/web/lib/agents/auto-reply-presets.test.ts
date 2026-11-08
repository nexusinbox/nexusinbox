import { describe, expect, it } from "vitest";
import { evaluateAutoReplyPolicyClient } from "../protocol/autoReplyClientEvaluator";
import { presetSettings, type AutoReplyPreset } from "./auto-reply-presets";

// What the executors decide for a message under each preset, with the
// protocol known (as it is once the message is opened).
function decide(
  preset: AutoReplyPreset,
  protocol: { type: "schedule_negotiation" | "task_delegation"; action: string },
  isContact: boolean,
) {
  const { autoReply, policy } = presetSettings(preset);
  return evaluateAutoReplyPolicyClient(policy, {
    masterAutoReplyEnabled: autoReply,
    priority: "normal",
    trustScore: 0.5,
    senderDid: "did:key:zSender",
    isContact,
    protocol,
  }).action;
}

const PROPOSE = { type: "schedule_negotiation", action: "propose" } as const;
const DELEGATE = { type: "task_delegation", action: "delegate" } as const;

describe("auto-reply presets", () => {
  it("manual leaves every request to the person", () => {
    expect(presetSettings("manual")).toEqual({ autoReply: false, policy: null });
    expect(decide("manual", PROPOSE, true)).toBe("queue_for_human");
  });

  it("contacts accepts scheduling proposals from contacts only", () => {
    expect(decide("contacts", PROPOSE, true)).toBe("auto_accept");
    expect(decide("contacts", PROPOSE, false)).toBe("queue_for_human");
    expect(decide("contacts", DELEGATE, true)).toBe("queue_for_human");
  });

  it("all accepts scheduling proposals from anyone, and nothing else", () => {
    expect(decide("all", PROPOSE, false)).toBe("auto_accept");
    expect(decide("all", DELEGATE, false)).toBe("queue_for_human");
  });

  it("lets the server hold back strangers under contacts", () => {
    // The server sees only the default branch; its conditions must carry
    // the contact rule, or every sender would be tagged auto_accept.
    expect(presetSettings("contacts").policy?.default_conditions).toEqual({
      require_contact: true,
    });
  });
});
