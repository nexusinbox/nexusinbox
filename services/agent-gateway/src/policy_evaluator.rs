// Phase 4.4c+B — Rust protocol-aware client evaluator for Isolated mode.
//
// Ports `apps/web/lib/protocol/autoReplyClientEvaluator.ts` so the
// Gateway can see the decrypted A2A protocol block and honour
// `policy.protocols.<type>.<action>` overrides the same way the
// browser (Standard mode) already does. docs/25c-a §2.3 identified this as
// deferred work in 4.4c+A; this module lands the deferred piece.
//
// The TS and Rust versions must agree on every case in the ADR 25c §9
// equivalence matrix — the test module below mirrors that table
// 1:1 so drift produces a failing test, not a silent divergence.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    QueueForHuman,
    AutoAccept,
    AutoDecline,
    AutoAcceptIfFree,
    DelegateToLlm,
}

impl Action {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Action::QueueForHuman => "queue_for_human",
            Action::AutoAccept => "auto_accept",
            Action::AutoDecline => "auto_decline",
            Action::AutoAcceptIfFree => "auto_accept_if_free",
            Action::DelegateToLlm => "delegate_to_llm",
        }
    }

    fn parse(s: &str) -> Option<Action> {
        match s {
            "queue_for_human" => Some(Action::QueueForHuman),
            "auto_accept" => Some(Action::AutoAccept),
            "auto_decline" => Some(Action::AutoDecline),
            "auto_accept_if_free" => Some(Action::AutoAcceptIfFree),
            "delegate_to_llm" => Some(Action::DelegateToLlm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolKey {
    pub protocol_type: &'static str,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub master_auto_reply_enabled: bool,
    pub priority: String,
    pub trust_score: f64,
    pub sender_did: String,
    pub is_contact: bool,
    pub protocol: Option<ProtocolKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: &'static str,
    pub matched_rule_path: String,
    pub fallback_reason: Option<&'static str>,
    pub evaluator_mode: &'static str,
}

pub const EVALUATOR_MODE: &str = "client_protocol_v1";

fn priority_rank(priority: &str) -> Option<i32> {
    match priority {
        "background" => Some(0),
        "low" => Some(1),
        "normal" => Some(2),
        "high" => Some(3),
        _ => None,
    }
}

fn queue(
    reason: &'static str,
    matched_rule_path: impl Into<String>,
    fallback: Option<&'static str>,
) -> Decision {
    Decision {
        action: Action::QueueForHuman,
        reason,
        matched_rule_path: matched_rule_path.into(),
        fallback_reason: fallback,
        evaluator_mode: EVALUATOR_MODE,
    }
}

fn evaluate_conditions(
    conditions: Option<&Value>,
    ctx: &EvaluationContext,
) -> Option<&'static str> {
    let obj = conditions?.as_object()?;

    if let Some(pam) = obj.get("priority_at_most").and_then(|v| v.as_str()) {
        match (priority_rank(&ctx.priority), priority_rank(pam)) {
            (Some(msg), Some(cap)) if msg > cap => return Some("priority_exceeds_policy"),
            (None, _) | (_, None) => return Some("invalid_policy"),
            _ => {}
        }
    }

    if let Some(mts) = obj.get("min_trust_score").and_then(|v| v.as_f64()) {
        if ctx.trust_score < mts {
            return Some("trust_below_threshold");
        }
    }

    if obj.get("require_contact").and_then(|v| v.as_bool()) == Some(true) && !ctx.is_contact {
        return Some("not_a_contact");
    }

    if let Some(arr) = obj.get("sender_in_allowlist").and_then(|v| v.as_array()) {
        let allowed = arr
            .iter()
            .any(|v| v.as_str() == Some(ctx.sender_did.as_str()));
        if !allowed {
            return Some("sender_not_in_allowlist");
        }
    }

    None
}

fn finalise_action(
    action: Action,
    matched_rule_path: String,
    is_protocol_override: bool,
) -> Decision {
    match action {
        Action::AutoAcceptIfFree => Decision {
            action: Action::QueueForHuman,
            reason: "calendar_unavailable",
            matched_rule_path,
            fallback_reason: Some("calendar_unavailable"),
            evaluator_mode: EVALUATOR_MODE,
        },
        Action::DelegateToLlm => Decision {
            action: Action::QueueForHuman,
            reason: "llm_unavailable",
            matched_rule_path,
            fallback_reason: Some("llm_unavailable"),
            evaluator_mode: EVALUATOR_MODE,
        },
        _ => Decision {
            action,
            reason: if is_protocol_override {
                "protocol_override_match"
            } else {
                "default_match"
            },
            matched_rule_path,
            fallback_reason: None,
            evaluator_mode: EVALUATOR_MODE,
        },
    }
}

/// Evaluate a policy against a context. Mirrors
/// `evaluateAutoReplyPolicyClient` in apps/web/lib/protocol —
/// corresponding cases are covered by identical tests on both sides
/// so drift shows up in CI rather than at runtime.
pub fn evaluate(policy: Option<&Value>, ctx: &EvaluationContext) -> Decision {
    if !ctx.master_auto_reply_enabled {
        return Decision {
            action: Action::QueueForHuman,
            reason: "master_off",
            matched_rule_path: "master".into(),
            fallback_reason: None,
            evaluator_mode: EVALUATOR_MODE,
        };
    }

    let Some(policy) = policy else {
        return queue("no_policy", "default", None);
    };
    let Some(obj) = policy.as_object() else {
        return queue("no_policy", "default", None);
    };
    if obj.is_empty() {
        return queue("no_policy", "default", None);
    }
    if obj.get("v").and_then(|v| v.as_u64()) != Some(1) {
        return queue("unsupported_schema", "default", None);
    }

    let Some(default_action_str) = obj.get("default_action").and_then(|v| v.as_str()) else {
        return queue("no_policy", "default", None);
    };
    let Some(default_action) = Action::parse(default_action_str) else {
        return queue("invalid_policy", "default", None);
    };

    let mut chosen_action = default_action;
    let mut matched_rule_path = String::from("default");
    let mut conditions_value = obj.get("default_conditions").cloned();
    let mut is_protocol_override = false;

    if let Some(protocol) = ctx.protocol.as_ref() {
        if let Some(protocols) = obj.get("protocols").and_then(|v| v.as_object()) {
            if let Some(type_block) = protocols
                .get(protocol.protocol_type)
                .and_then(|v| v.as_object())
            {
                if let Some(action_block) =
                    type_block.get(&protocol.action).and_then(|v| v.as_object())
                {
                    if let Some(action_str) = action_block.get("action").and_then(|v| v.as_str()) {
                        if let Some(action) = Action::parse(action_str) {
                            chosen_action = action;
                            matched_rule_path =
                                format!("protocols.{}.{}", protocol.protocol_type, protocol.action);
                            conditions_value = action_block.get("conditions").cloned();
                            is_protocol_override = true;
                        }
                    }
                }
            }
        }
    }

    if let Some(violation) = evaluate_conditions(conditions_value.as_ref(), ctx) {
        return queue(violation, matched_rule_path, None);
    }

    finalise_action(chosen_action, matched_rule_path, is_protocol_override)
}

/// Combine a server-side cached decision with the freshly computed
/// client decision. Mirrors `mergeDecisions` in the TS side — a
/// `master_off` from the server is sticky, otherwise the more
/// specific (client) evaluator wins.
pub fn merge(server_reason: Option<&str>, client: Decision) -> Decision {
    if server_reason == Some("master_off") {
        return Decision {
            action: Action::QueueForHuman,
            reason: "master_off",
            matched_rule_path: "master".into(),
            fallback_reason: None,
            evaluator_mode: client.evaluator_mode,
        };
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(master: bool) -> EvaluationContext {
        EvaluationContext {
            master_auto_reply_enabled: master,
            priority: "normal".into(),
            trust_score: 0.8,
            sender_did: "did:key:zAlice".into(),
            is_contact: true,
            protocol: None,
        }
    }

    fn minimal(default_action: &str) -> Value {
        json!({ "v": 1, "default_action": default_action })
    }

    #[test]
    fn master_off_always_queues() {
        let d = evaluate(Some(&minimal("auto_accept")), &ctx(false));
        assert_eq!(d.action, Action::QueueForHuman);
        assert_eq!(d.reason, "master_off");
    }

    #[test]
    fn empty_policy_returns_no_policy() {
        let d = evaluate(Some(&json!({})), &ctx(true));
        assert_eq!(d.action, Action::QueueForHuman);
        assert_eq!(d.reason, "no_policy");
    }

    #[test]
    fn unknown_schema_version_rejected_safely() {
        let mut p = minimal("auto_accept");
        p["v"] = json!(99);
        let d = evaluate(Some(&p), &ctx(true));
        assert_eq!(d.reason, "unsupported_schema");
    }

    #[test]
    fn default_auto_accept_passes_through() {
        let d = evaluate(Some(&minimal("auto_accept")), &ctx(true));
        assert_eq!(d.action, Action::AutoAccept);
        assert_eq!(d.reason, "default_match");
        assert_eq!(d.matched_rule_path, "default");
    }

    #[test]
    fn auto_accept_if_free_falls_back_to_queue() {
        let d = evaluate(Some(&minimal("auto_accept_if_free")), &ctx(true));
        assert_eq!(d.action, Action::QueueForHuman);
        assert_eq!(d.fallback_reason, Some("calendar_unavailable"));
    }

    #[test]
    fn delegate_to_llm_falls_back_to_queue() {
        let d = evaluate(Some(&minimal("delegate_to_llm")), &ctx(true));
        assert_eq!(d.action, Action::QueueForHuman);
        assert_eq!(d.fallback_reason, Some("llm_unavailable"));
    }

    #[test]
    fn priority_at_most_rejects_higher_priority() {
        let p = json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "priority_at_most": "normal" }
        });
        let mut c = ctx(true);
        c.priority = "high".into();
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.reason, "priority_exceeds_policy");
    }

    #[test]
    fn min_trust_score_rejects_low_trust() {
        let p = json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "min_trust_score": 0.5 }
        });
        let mut c = ctx(true);
        c.trust_score = 0.3;
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.reason, "trust_below_threshold");
    }

    #[test]
    fn require_contact_rejects_stranger() {
        let p = json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "require_contact": true }
        });
        let mut c = ctx(true);
        c.is_contact = false;
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.reason, "not_a_contact");
    }

    #[test]
    fn sender_in_allowlist_admits_match() {
        let p = json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "sender_in_allowlist": ["did:key:zAlice"] }
        });
        let d = evaluate(Some(&p), &ctx(true));
        assert_eq!(d.action, Action::AutoAccept);
    }

    #[test]
    fn sender_in_allowlist_rejects_non_member() {
        let p = json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "sender_in_allowlist": ["did:key:zOther"] }
        });
        let d = evaluate(Some(&p), &ctx(true));
        assert_eq!(d.reason, "sender_not_in_allowlist");
    }

    #[test]
    fn defensive_queue_on_malformed_priority() {
        let p = json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "priority_at_most": "normal" }
        });
        let mut c = ctx(true);
        c.priority = "unknown_value".into();
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.reason, "invalid_policy");
    }

    #[test]
    fn protocol_override_wins_over_default() {
        let p = json!({
            "v": 1,
            "default_action": "queue_for_human",
            "protocols": {
                "schedule_negotiation": {
                    "propose": { "action": "auto_accept" }
                }
            }
        });
        let mut c = ctx(true);
        c.protocol = Some(ProtocolKey {
            protocol_type: "schedule_negotiation",
            action: "propose".into(),
        });
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.action, Action::AutoAccept);
        assert_eq!(
            d.matched_rule_path,
            "protocols.schedule_negotiation.propose"
        );
        assert_eq!(d.reason, "protocol_override_match");
    }

    #[test]
    fn protocol_override_conditions_replace_default_conditions() {
        // Default would block via require_contact=true, but the
        // override doesn't inherit those conditions.
        let p = json!({
            "v": 1,
            "default_action": "queue_for_human",
            "default_conditions": { "require_contact": true },
            "protocols": {
                "schedule_negotiation": {
                    "propose": { "action": "auto_accept" }
                }
            }
        });
        let mut c = ctx(true);
        c.is_contact = false;
        c.protocol = Some(ProtocolKey {
            protocol_type: "schedule_negotiation",
            action: "propose".into(),
        });
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.action, Action::AutoAccept);
    }

    #[test]
    fn protocol_override_enforces_its_own_conditions() {
        let p = json!({
            "v": 1,
            "default_action": "queue_for_human",
            "protocols": {
                "task_delegation": {
                    "delegate": {
                        "action": "auto_accept",
                        "conditions": { "min_trust_score": 0.9 }
                    }
                }
            }
        });
        let mut c = ctx(true);
        c.trust_score = 0.3;
        c.protocol = Some(ProtocolKey {
            protocol_type: "task_delegation",
            action: "delegate".into(),
        });
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.action, Action::QueueForHuman);
        assert_eq!(d.reason, "trust_below_threshold");
    }

    #[test]
    fn unknown_protocol_action_falls_back_to_default() {
        let p = json!({
            "v": 1,
            "default_action": "queue_for_human",
            "protocols": { "schedule_negotiation": { "propose": { "action": "auto_accept" } } }
        });
        let mut c = ctx(true);
        c.protocol = Some(ProtocolKey {
            protocol_type: "schedule_negotiation",
            action: "unknown_verb".into(),
        });
        let d = evaluate(Some(&p), &c);
        assert_eq!(d.matched_rule_path, "default");
    }

    #[test]
    fn merge_preserves_master_off_from_server() {
        let client = evaluate(Some(&minimal("auto_accept")), &ctx(true));
        let merged = merge(Some("master_off"), client);
        assert_eq!(merged.action, Action::QueueForHuman);
        assert_eq!(merged.reason, "master_off");
    }

    #[test]
    fn merge_returns_client_when_server_is_not_master_off() {
        let client = evaluate(Some(&minimal("auto_accept")), &ctx(true));
        let merged = merge(Some("default_match"), client.clone());
        assert_eq!(merged, client);
    }

    #[test]
    fn merge_accepts_no_server_decision() {
        let client = evaluate(Some(&minimal("auto_decline")), &ctx(true));
        let merged = merge(None, client.clone());
        assert_eq!(merged, client);
    }
}
