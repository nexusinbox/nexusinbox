// Phase 4.4c (docs/25c) — client-side auto-reply evaluator.
//
// Mirrors the server-side Rust evaluator in services/api/src/lib.rs so
// the two stages produce identical decisions for any input they both
// see. The client additionally honours protocol-specific overrides
// (`policy.protocols.<type>.<action>`) because the browser has the
// decrypted A2A payload and can tell which (type, action) pair arrived
// — the server can't. See docs/25c §4 for the contract.
//
// The evaluator is pure: no DB, no network, no clock. Side effects
// live entirely in the caller (the executor module). This file is
// covered by `autoReplyClientEvaluator.test.ts`.

import type { AutoReplyDecision } from "../api/types";
import type { AutoReplyPolicy } from "../api/types";

// Re-export so callers can share the enum without pulling from
// api/types. Kept as a string union to match the wire protocol.
export type AutoReplyAction = AutoReplyDecision;

export type A2AProtocolType = "schedule_negotiation" | "task_delegation";

/** Minimal key the evaluator cares about — just type + action. */
export type ProtocolKey = {
  type: A2AProtocolType;
  action: string;
};

export type EvaluationContext = {
  masterAutoReplyEnabled: boolean;
  priority: "high" | "normal" | "low" | "background" | string;
  trustScore: number;
  senderDid: string;
  isContact: boolean;
  /**
   * Present when the browser has already decrypted and parsed the A2A
   * envelope; absent when the evaluator is being called as a pure
   * unit test fixture. The server-mode evaluator always leaves this
   * None.
   */
  protocol?: ProtocolKey;
};

export type Decision = {
  action: AutoReplyAction;
  reason: string;
  matchedRulePath: string;
  fallbackReason?: string;
  evaluatorMode: "server_metadata_v1" | "client_protocol_v1";
};

const PRIORITY_RANK: Record<string, number> = {
  background: 0,
  low: 1,
  normal: 2,
  high: 3,
};

function priorityRank(priority: string): number | undefined {
  return PRIORITY_RANK[priority];
}

const VALID_ACTIONS: ReadonlySet<string> = new Set<AutoReplyAction>([
  "queue_for_human",
  "auto_accept",
  "auto_decline",
  "auto_accept_if_free",
  "delegate_to_llm",
]);

function isValidAction(s: unknown): s is AutoReplyAction {
  return typeof s === "string" && VALID_ACTIONS.has(s as AutoReplyAction);
}

function queue(
  reason: string,
  matchedRulePath: string,
  fallbackReason?: string,
): Decision {
  return {
    action: "queue_for_human",
    reason,
    matchedRulePath,
    fallbackReason,
    evaluatorMode: "client_protocol_v1",
  };
}

function resolveConditionViolation(
  conditions: unknown,
  ctx: EvaluationContext,
): string | null {
  if (!conditions || typeof conditions !== "object") return null;
  const obj = conditions as Record<string, unknown>;

  const pam = obj.priority_at_most;
  if (typeof pam === "string") {
    const msgRank = priorityRank(ctx.priority);
    const capRank = priorityRank(pam);
    if (msgRank === undefined || capRank === undefined) {
      return "invalid_policy";
    }
    if (msgRank > capRank) return "priority_exceeds_policy";
  }

  const mts = obj.min_trust_score;
  if (typeof mts === "number") {
    if (ctx.trustScore < mts) return "trust_below_threshold";
  }

  if (obj.require_contact === true && !ctx.isContact) {
    return "not_a_contact";
  }

  const sia = obj.sender_in_allowlist;
  if (Array.isArray(sia)) {
    const allowed = sia.some((v) => typeof v === "string" && v === ctx.senderDid);
    if (!allowed) return "sender_not_in_allowlist";
  }

  return null;
}

function finaliseActionOrFallback(
  action: AutoReplyAction,
  matchedRulePath: string,
): Decision {
  // Phase 4.4d (docs/25d): auto_accept_if_free is no longer a
  // fallback case — the executor calls into gcalFreebusy.ts to
  // resolve it against the user's Google Calendar. We still
  // keep delegate_to_llm as a permanent fallback because Phase 4.4e
  // is cancelled (docs/25e).
  if (action === "delegate_to_llm") {
    return queue("llm_unavailable", matchedRulePath, "llm_unavailable");
  }
  return {
    action,
    reason:
      matchedRulePath === "default" ? "default_match" : "protocol_override_match",
    matchedRulePath,
    evaluatorMode: "client_protocol_v1",
  };
}

/**
 * Evaluate `policy` against `ctx` and return a decision. Safe to call
 * with policies that failed server-side validation — this function
 * defensively falls back to queue_for_human on anything it can't
 * interpret.
 */
export function evaluateAutoReplyPolicyClient(
  policy: AutoReplyPolicy | Record<string, unknown> | null | undefined,
  ctx: EvaluationContext,
): Decision {
  if (!ctx.masterAutoReplyEnabled) {
    return {
      action: "queue_for_human",
      reason: "master_off",
      matchedRulePath: "master",
      evaluatorMode: "client_protocol_v1",
    };
  }

  if (!policy || typeof policy !== "object" || Object.keys(policy).length === 0) {
    return queue("no_policy", "default");
  }

  const policyObj = policy as Record<string, unknown>;
  if (policyObj.v !== 1) {
    return queue("unsupported_schema", "default");
  }

  // Start with the default branch so we can fall back to it when
  // there's no protocol-specific override.
  const defaultActionRaw = policyObj.default_action;
  if (!isValidAction(defaultActionRaw)) {
    return queue("no_policy", "default");
  }

  let chosenAction: AutoReplyAction = defaultActionRaw;
  let matchedRulePath = "default";
  let conditions = policyObj.default_conditions;
  let isProtocolOverride = false;

  // Protocol-specific override kicks in when we know the protocol
  // (Standard mode always, Mode C never). It entirely replaces the default
  // conditions — the AND-on-both model was rejected in docs/25c §4
  // because it made "override this for schedule_negotiation only"
  // unreachable when strict default_conditions were set.
  if (ctx.protocol) {
    const protocols = policyObj.protocols;
    if (protocols && typeof protocols === "object") {
      const typeBlock = (protocols as Record<string, unknown>)[ctx.protocol.type];
      if (typeBlock && typeof typeBlock === "object") {
        const actionBlock = (typeBlock as Record<string, unknown>)[
          ctx.protocol.action
        ];
        if (actionBlock && typeof actionBlock === "object") {
          const ab = actionBlock as Record<string, unknown>;
          if (isValidAction(ab.action)) {
            chosenAction = ab.action;
            matchedRulePath = `protocols.${ctx.protocol.type}.${ctx.protocol.action}`;
            conditions = ab.conditions;
            isProtocolOverride = true;
          }
        }
      }
    }
  }

  const violation = resolveConditionViolation(conditions, ctx);
  if (violation) {
    return queue(violation, matchedRulePath);
  }

  const decision = finaliseActionOrFallback(chosenAction, matchedRulePath);
  // Rename reason for protocol override hits so audit filters can
  // distinguish the two paths cleanly.
  if (
    isProtocolOverride &&
    decision.action !== "queue_for_human" &&
    decision.reason === "default_match"
  ) {
    decision.reason = "protocol_override_match";
  }
  return decision;
}

/**
 * Combine a cached server decision with the freshly-computed client
 * decision. The most specific evaluator wins, *except* that
 * `master_off` from the server is always final: a disabled agent
 * never sends auto-replies, regardless of what the client concluded.
 */
export function mergeDecisions(
  server: Pick<Decision, "action" | "reason"> | null | undefined,
  client: Decision,
): Decision {
  if (server && server.reason === "master_off") {
    return {
      action: "queue_for_human",
      reason: "master_off",
      matchedRulePath: "master",
      evaluatorMode: client.evaluatorMode,
    };
  }
  return client;
}
