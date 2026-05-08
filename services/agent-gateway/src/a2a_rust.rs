// Phase 4.4c+ (docs/25c-a §2.3) — minimal Rust A2A parser + reply
// payload builder. Mirrors packages/core/src/a2a.ts just enough for
// the Isolated mode executor to read an incoming propose/delegate and build
// the matching accept/decline. Full schema validation stays on the
// TS side for now; the gateway only needs shape-level agreement.

use serde::Serialize;
use serde_json::Value;

pub const A2A_CONTENT_TYPE: &str = "application/vnd.nexusinbox.a2a+json; v=1";
pub const A2A_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2AProtocolType {
    ScheduleNegotiation,
    TaskDelegation,
}

impl A2AProtocolType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "schedule_negotiation" => Some(A2AProtocolType::ScheduleNegotiation),
            "task_delegation" => Some(A2AProtocolType::TaskDelegation),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            A2AProtocolType::ScheduleNegotiation => "schedule_negotiation",
            A2AProtocolType::TaskDelegation => "task_delegation",
        }
    }
}

#[derive(Debug, Clone)]
pub struct A2AProtocolBlock {
    pub id: String,
    pub protocol_type: A2AProtocolType,
    pub action: String,
    // Kept for completeness; the executor doesn't currently branch
    // on it but future code (e.g. counter-of-counter) will need it.
    #[allow(dead_code)]
    pub reply_to: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct A2APayload {
    // Plain-text body summary. Not used by the executor today, but
    // the parser keeps it so logs / audit paths have something
    // human-readable to display.
    #[allow(dead_code)]
    pub body: String,
    pub protocol: Option<A2AProtocolBlock>,
}

/// Parse a decrypted A2A body. Returns `None` for malformed input or
/// content types that aren't A2A — callers pass plaintext verbatim
/// and treat `None` as "not an auto-reply candidate".
pub fn parse_a2a_payload(raw: &str, content_type: Option<&str>) -> Option<A2APayload> {
    if !is_a2a_content_type(content_type) {
        return None;
    }
    let parsed: Value = serde_json::from_str(raw).ok()?;
    let obj = parsed.as_object()?;
    if obj.get("v").and_then(|v| v.as_u64()) != Some(A2A_SCHEMA_VERSION) {
        return None;
    }
    let body = obj
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let protocol = obj.get("protocol").and_then(parse_protocol_block);
    Some(A2APayload { body, protocol })
}

fn parse_protocol_block(raw: &Value) -> Option<A2AProtocolBlock> {
    let obj = raw.as_object()?;
    let id = obj.get("id").and_then(|v| v.as_str())?.to_string();
    if id.is_empty() {
        return None;
    }
    let protocol_type = A2AProtocolType::from_str(obj.get("type").and_then(|v| v.as_str())?)?;
    let action = obj.get("action").and_then(|v| v.as_str())?.to_string();
    let reply_to = match obj.get("reply_to") {
        Some(Value::Null) | None => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return None,
    };
    let payload = obj.get("payload")?.clone();
    if !payload.is_object() {
        return None;
    }
    Some(A2AProtocolBlock {
        id,
        protocol_type,
        action,
        reply_to,
        payload,
    })
}

pub fn is_a2a_content_type(ct: Option<&str>) -> bool {
    match ct {
        Some(s) => s
            .to_ascii_lowercase()
            .starts_with("application/vnd.nexusinbox.a2a+json"),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Reply payload builders
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ScheduleCandidate {
    pub start: String,
    pub end: String,
}

/// Pick the first candidate from a propose payload. Isolated mode doesn't
/// consult a calendar (that's Phase 4.4d) so the simplest policy is
/// to accept the earliest option. Returns `None` when the payload
/// has no candidates at all.
pub fn first_candidate_from_propose(payload: &Value) -> Option<ScheduleCandidate> {
    let arr = payload.get("candidates")?.as_array()?;
    let first = arr.first()?.as_object()?;
    let start = first.get("start")?.as_str()?.to_string();
    let end = first.get("end")?.as_str()?.to_string();
    Some(ScheduleCandidate { start, end })
}

/// Build the payload that sits inside a `schedule_negotiation` reply
/// block. `action` determines which shape we produce — `accept`
/// requires a candidate to echo back (context binding per docs/24
/// §7.1), `decline` carries just the reason.
pub fn build_schedule_reply_payload(
    action: &str,
    accept_candidate: Option<ScheduleCandidate>,
    decline_reason: Option<&str>,
) -> Option<Value> {
    match action {
        "accept" => {
            let candidate = accept_candidate?;
            Some(serde_json::json!({
                "selected_candidate": { "start": candidate.start, "end": candidate.end },
            }))
        }
        "decline" => {
            let mut obj = serde_json::Map::new();
            if let Some(r) = decline_reason {
                obj.insert("reason".into(), Value::String(r.to_string()));
            }
            Some(Value::Object(obj))
        }
        _ => None,
    }
}

/// Build a `task_delegation` reply payload. `action` is either
/// `accept` or `decline`; task delegation replies are small so we
/// pack both into one helper.
pub fn build_task_reply_payload(action: &str, reason_or_note: Option<&str>) -> Option<Value> {
    match action {
        "accept" => {
            let mut obj = serde_json::Map::new();
            if let Some(n) = reason_or_note {
                obj.insert("note".into(), Value::String(n.to_string()));
            }
            Some(Value::Object(obj))
        }
        "decline" => {
            let mut obj = serde_json::Map::new();
            if let Some(r) = reason_or_note {
                obj.insert("reason".into(), Value::String(r.to_string()));
            }
            Some(Value::Object(obj))
        }
        _ => None,
    }
}

/// Serialise a full outgoing A2A envelope body. `protocol_block_json`
/// must already contain the `id` / `type` / `action` / `reply_to` /
/// `payload` fields the receiver expects — this helper just stamps
/// the v=1 outer frame around it.
pub fn serialize_outgoing_body(body_summary: &str, protocol_block_json: Value) -> String {
    serde_json::json!({
        "v": A2A_SCHEMA_VERSION,
        "body": body_summary,
        "protocol": protocol_block_json,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn propose_body() -> String {
        serde_json::json!({
            "v": 1,
            "body": "Let's meet",
            "protocol": {
                "id": "proto-1",
                "type": "schedule_negotiation",
                "action": "propose",
                "reply_to": null,
                "payload": {
                    "event_title": "Sync",
                    "candidates": [
                        {"start": "2026-05-01T09:00:00+09:00", "end": "2026-05-01T10:00:00+09:00"}
                    ],
                    "required_participants": ["did:key:A", "did:key:B"]
                }
            }
        })
        .to_string()
    }

    #[test]
    fn parse_valid_propose() {
        let parsed = parse_a2a_payload(&propose_body(), Some(A2A_CONTENT_TYPE)).expect("parse");
        let protocol = parsed.protocol.expect("protocol present");
        assert_eq!(protocol.id, "proto-1");
        assert_eq!(protocol.protocol_type, A2AProtocolType::ScheduleNegotiation);
        assert_eq!(protocol.action, "propose");
        assert!(protocol.reply_to.is_none());
    }

    #[test]
    fn parse_rejects_non_a2a_content_type() {
        assert!(parse_a2a_payload(&propose_body(), Some("text/plain")).is_none());
        assert!(parse_a2a_payload(&propose_body(), None).is_none());
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let body = serde_json::json!({"v": 2, "body": "", "protocol": null}).to_string();
        assert!(parse_a2a_payload(&body, Some(A2A_CONTENT_TYPE)).is_none());
    }

    #[test]
    fn parse_rejects_missing_protocol_fields() {
        let body = serde_json::json!({
            "v": 1,
            "body": "",
            "protocol": {"id": "p", "type": "schedule_negotiation"}
        })
        .to_string();
        let parsed = parse_a2a_payload(&body, Some(A2A_CONTENT_TYPE)).expect("parse frame");
        // Frame parses but the malformed protocol block is dropped.
        assert!(parsed.protocol.is_none());
    }

    #[test]
    fn parse_rejects_unknown_protocol_type() {
        let body = serde_json::json!({
            "v": 1,
            "body": "",
            "protocol": {
                "id": "p",
                "type": "nonsense",
                "action": "x",
                "reply_to": null,
                "payload": {}
            }
        })
        .to_string();
        let parsed = parse_a2a_payload(&body, Some(A2A_CONTENT_TYPE)).expect("frame");
        assert!(parsed.protocol.is_none());
    }

    #[test]
    fn first_candidate_from_propose_picks_first() {
        let parsed = parse_a2a_payload(&propose_body(), Some(A2A_CONTENT_TYPE)).unwrap();
        let protocol = parsed.protocol.unwrap();
        let candidate = first_candidate_from_propose(&protocol.payload).expect("candidate");
        assert_eq!(candidate.start, "2026-05-01T09:00:00+09:00");
    }

    #[test]
    fn build_schedule_accept_includes_selected_candidate() {
        let candidate = ScheduleCandidate {
            start: "2026-05-01T09:00:00+09:00".into(),
            end: "2026-05-01T10:00:00+09:00".into(),
        };
        let payload = build_schedule_reply_payload("accept", Some(candidate), None).unwrap();
        assert_eq!(
            payload
                .get("selected_candidate")
                .and_then(|v| v.get("start"))
                .and_then(|v| v.as_str()),
            Some("2026-05-01T09:00:00+09:00")
        );
    }

    #[test]
    fn build_schedule_decline_includes_reason() {
        let payload = build_schedule_reply_payload("decline", None, Some("busy")).unwrap();
        assert_eq!(payload.get("reason").and_then(|v| v.as_str()), Some("busy"));
    }

    #[test]
    fn build_task_accept_with_note() {
        let payload = build_task_reply_payload("accept", Some("ok")).unwrap();
        assert_eq!(payload.get("note").and_then(|v| v.as_str()), Some("ok"));
    }

    #[test]
    fn build_task_accept_without_note_is_empty_object() {
        let payload = build_task_reply_payload("accept", None).unwrap();
        assert!(payload.as_object().unwrap().is_empty());
    }

    #[test]
    fn build_unknown_action_returns_none() {
        assert!(build_schedule_reply_payload("counter", None, None).is_none());
        assert!(build_task_reply_payload("complete", None).is_none());
    }

    #[test]
    fn serialize_outgoing_body_frames_correctly() {
        let payload = build_task_reply_payload("accept", None).unwrap();
        let block = serde_json::json!({
            "id": "proto-2",
            "type": "task_delegation",
            "action": "accept",
            "reply_to": "proto-1",
            "payload": payload,
        });
        let serialised = serialize_outgoing_body("", block);
        let round_trip: Value = serde_json::from_str(&serialised).unwrap();
        assert_eq!(round_trip["v"].as_u64(), Some(1));
        assert_eq!(round_trip["protocol"]["action"].as_str(), Some("accept"));
    }
}
