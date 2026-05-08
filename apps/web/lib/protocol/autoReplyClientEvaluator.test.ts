import { describe, expect, it } from "vitest";
import {
  evaluateAutoReplyPolicyClient,
  mergeDecisions,
  type EvaluationContext,
} from "./autoReplyClientEvaluator";

function ctx(overrides: Partial<EvaluationContext> = {}): EvaluationContext {
  return {
    masterAutoReplyEnabled: true,
    priority: "normal",
    trustScore: 0.8,
    senderDid: "did:key:zAlice",
    isContact: true,
    ...overrides,
  };
}

const minimalPolicy = (defaultAction: string) => ({
  v: 1,
  default_action: defaultAction,
});

// ---------------------------------------------------------------------------
// Base equivalence with the Rust evaluator (docs/25c §9 matrix)
// ---------------------------------------------------------------------------

describe("client evaluator — Rust equivalence", () => {
  it("master_off always queues", () => {
    const d = evaluateAutoReplyPolicyClient(
      minimalPolicy("auto_accept"),
      ctx({ masterAutoReplyEnabled: false }),
    );
    expect(d.action).toBe("queue_for_human");
    expect(d.reason).toBe("master_off");
  });

  it("empty policy returns no_policy", () => {
    const d = evaluateAutoReplyPolicyClient({}, ctx());
    expect(d.action).toBe("queue_for_human");
    expect(d.reason).toBe("no_policy");
  });

  it("unsupported schema version falls back safely", () => {
    const d = evaluateAutoReplyPolicyClient(
      { v: 99, default_action: "auto_accept" },
      ctx(),
    );
    expect(d.action).toBe("queue_for_human");
    expect(d.reason).toBe("unsupported_schema");
  });

  it("default auto_accept passes through", () => {
    const d = evaluateAutoReplyPolicyClient(minimalPolicy("auto_accept"), ctx());
    expect(d.action).toBe("auto_accept");
    expect(d.reason).toBe("default_match");
    expect(d.matchedRulePath).toBe("default");
  });

  it("default auto_decline passes through", () => {
    const d = evaluateAutoReplyPolicyClient(minimalPolicy("auto_decline"), ctx());
    expect(d.action).toBe("auto_decline");
  });

  it("auto_accept_if_free is returned raw for the executor to resolve (Phase 4.4d)", () => {
    const d = evaluateAutoReplyPolicyClient(
      minimalPolicy("auto_accept_if_free"),
      ctx(),
    );
    expect(d.action).toBe("auto_accept_if_free");
    expect(d.reason).toBe("default_match");
    expect(d.fallbackReason).toBeUndefined();
  });

  it("delegate_to_llm falls back to queue / llm_unavailable", () => {
    const d = evaluateAutoReplyPolicyClient(
      minimalPolicy("delegate_to_llm"),
      ctx(),
    );
    expect(d.action).toBe("queue_for_human");
    expect(d.reason).toBe("llm_unavailable");
    expect(d.fallbackReason).toBe("llm_unavailable");
  });

  it("priority_at_most rejects higher-priority messages", () => {
    const d = evaluateAutoReplyPolicyClient(
      {
        v: 1,
        default_action: "auto_accept",
        default_conditions: { priority_at_most: "normal" },
      },
      ctx({ priority: "high" }),
    );
    expect(d.action).toBe("queue_for_human");
    expect(d.reason).toBe("priority_exceeds_policy");
  });

  it("min_trust_score rejects low-trust senders", () => {
    const d = evaluateAutoReplyPolicyClient(
      {
        v: 1,
        default_action: "auto_accept",
        default_conditions: { min_trust_score: 0.5 },
      },
      ctx({ trustScore: 0.3 }),
    );
    expect(d.reason).toBe("trust_below_threshold");
  });

  it("require_contact rejects strangers", () => {
    const d = evaluateAutoReplyPolicyClient(
      {
        v: 1,
        default_action: "auto_accept",
        default_conditions: { require_contact: true },
      },
      ctx({ isContact: false }),
    );
    expect(d.reason).toBe("not_a_contact");
  });

  it("sender_in_allowlist admits match", () => {
    const d = evaluateAutoReplyPolicyClient(
      {
        v: 1,
        default_action: "auto_accept",
        default_conditions: { sender_in_allowlist: ["did:key:zAlice"] },
      },
      ctx(),
    );
    expect(d.action).toBe("auto_accept");
  });

  it("sender_in_allowlist rejects non-members", () => {
    const d = evaluateAutoReplyPolicyClient(
      {
        v: 1,
        default_action: "auto_accept",
        default_conditions: { sender_in_allowlist: ["did:key:zOther"] },
      },
      ctx(),
    );
    expect(d.reason).toBe("sender_not_in_allowlist");
  });

  it("defensive queue on malformed priority context", () => {
    const d = evaluateAutoReplyPolicyClient(
      {
        v: 1,
        default_action: "auto_accept",
        default_conditions: { priority_at_most: "normal" },
      },
      ctx({ priority: "weird_value" }),
    );
    expect(d.action).toBe("queue_for_human");
    expect(d.reason).toBe("invalid_policy");
  });

  it("evaluator reports client_protocol_v1 mode", () => {
    const d = evaluateAutoReplyPolicyClient(minimalPolicy("auto_accept"), ctx());
    expect(d.evaluatorMode).toBe("client_protocol_v1");
  });
});

// ---------------------------------------------------------------------------
// Protocol-specific override (TS only — the server mode is blind to this)
// ---------------------------------------------------------------------------

describe("client evaluator — protocol overrides", () => {
  const policyWithOverride = {
    v: 1,
    default_action: "queue_for_human",
    protocols: {
      schedule_negotiation: {
        propose: { action: "auto_accept" },
      },
      task_delegation: {
        delegate: {
          action: "auto_decline",
          conditions: { min_trust_score: 0.9 },
        },
      },
    },
  };

  it("schedule_negotiation.propose override wins over default", () => {
    const d = evaluateAutoReplyPolicyClient(
      policyWithOverride,
      ctx({ protocol: { type: "schedule_negotiation", action: "propose" } }),
    );
    expect(d.action).toBe("auto_accept");
    expect(d.matchedRulePath).toBe("protocols.schedule_negotiation.propose");
    expect(d.reason).toBe("protocol_override_match");
  });

  it("override conditions replace default conditions (not AND)", () => {
    // Default conditions would *require* contact, but the override
    // should apply without inheriting them.
    const policy = {
      v: 1,
      default_action: "queue_for_human",
      default_conditions: { require_contact: true },
      protocols: {
        schedule_negotiation: {
          propose: { action: "auto_accept" },
        },
      },
    };
    const d = evaluateAutoReplyPolicyClient(
      policy,
      ctx({
        protocol: { type: "schedule_negotiation", action: "propose" },
        isContact: false,
      }),
    );
    expect(d.action).toBe("auto_accept");
  });

  it("override conditions are still enforced when the override has its own", () => {
    const d = evaluateAutoReplyPolicyClient(
      policyWithOverride,
      ctx({
        protocol: { type: "task_delegation", action: "delegate" },
        trustScore: 0.3,
      }),
    );
    expect(d.action).toBe("queue_for_human");
    expect(d.reason).toBe("trust_below_threshold");
    expect(d.matchedRulePath).toBe("protocols.task_delegation.delegate");
  });

  it("absent protocol falls back to default branch", () => {
    const d = evaluateAutoReplyPolicyClient(policyWithOverride, ctx());
    expect(d.action).toBe("queue_for_human");
    expect(d.matchedRulePath).toBe("default");
  });

  it("unknown protocol.action falls back to default branch", () => {
    const d = evaluateAutoReplyPolicyClient(
      policyWithOverride,
      ctx({ protocol: { type: "schedule_negotiation", action: "unknown_verb" } }),
    );
    expect(d.matchedRulePath).toBe("default");
  });
});

// ---------------------------------------------------------------------------
// Merge rule
// ---------------------------------------------------------------------------

describe("mergeDecisions", () => {
  it("master_off from server always wins", () => {
    const merged = mergeDecisions(
      { action: "queue_for_human", reason: "master_off" },
      {
        action: "auto_accept",
        reason: "default_match",
        matchedRulePath: "default",
        evaluatorMode: "client_protocol_v1",
      },
    );
    expect(merged.action).toBe("queue_for_human");
    expect(merged.reason).toBe("master_off");
  });

  it("client decision wins when server isn't master_off", () => {
    const merged = mergeDecisions(
      { action: "queue_for_human", reason: "default_match" },
      {
        action: "auto_accept",
        reason: "protocol_override_match",
        matchedRulePath: "protocols.schedule_negotiation.propose",
        evaluatorMode: "client_protocol_v1",
      },
    );
    expect(merged.action).toBe("auto_accept");
    expect(merged.reason).toBe("protocol_override_match");
  });

  it("client decision applies even when server is absent", () => {
    const merged = mergeDecisions(null, {
      action: "auto_decline",
      reason: "default_match",
      matchedRulePath: "default",
      evaluatorMode: "client_protocol_v1",
    });
    expect(merged.action).toBe("auto_decline");
  });
});
