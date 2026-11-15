//! Where each request in a conversation stands (docs/41 §7, stage C), for
//! the AI tools. The same rules as `packages/core/src/request-state.ts`;
//! both pass tests/vectors/request_state.json. A request is the message
//! that opened it and every reply linked to it by `reply_to`; only messages
//! whose sender was verified count. Sent is not finished, free text says
//! nothing, and one message is never read as the whole conversation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// How long after an executor took a message "the AI started" stays shown.
pub const AI_STARTED_WINDOW_SECS: i64 = 180;

#[derive(Debug, Clone, Deserialize)]
pub struct RequestMessage {
    pub id: String,
    pub at: String,
    pub mine: bool,
    pub verified: bool,
    pub protocol: Option<ProtocolFacts>,
    #[serde(default)]
    pub auto_reply: Option<AutoReplyRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolFacts {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub action: String,
    pub reply_to: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AutoReplyRecord {
    #[serde(default)]
    pub claimed_at: Option<String>,
    #[serde(default)]
    pub sent_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LastEvent {
    pub message_id: String,
    pub action: String,
    pub at: String,
    pub mine: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RequestSummary {
    pub request_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub state: &'static str,
    pub next: &'static str,
    pub last: LastEvent,
    pub evidence: Vec<String>,
    pub deadline: Option<String>,
    pub selected: Option<Value>,
    pub result: Option<String>,
    pub ai_started_at: Option<String>,
    pub history_incomplete: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ConversationRequests {
    pub requests: Vec<RequestSummary>,
    pub unverified: Vec<String>,
}

const ORDER: [&str; 12] = [
    "conflict",
    "missing_original",
    "waiting_for_you",
    "ai_unknown",
    "ai_started",
    "ai_replied",
    "accepted",
    "waiting_for_them",
    "expired",
    "agreed",
    "completed",
    "declined",
];

fn time(value: Option<&str>) -> Option<i64> {
    value
        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|t| t.with_timezone(&Utc).timestamp_millis())
}

fn terminal(kind: &str) -> &'static [&'static str] {
    if kind == "task_delegation" {
        &["decline", "complete"]
    } else {
        &["accept", "decline"]
    }
}

struct Event<'a> {
    message: &'a RequestMessage,
    protocol: &'a ProtocolFacts,
    ms: i64,
}

pub fn conversation_requests(messages: &[RequestMessage], now: &str) -> ConversationRequests {
    let now_ms = time(Some(now)).unwrap_or(0);
    let mut unverified = Vec::new();
    let mut sorted: Vec<&RequestMessage> = messages.iter().collect();
    sorted.sort_by(|a, b| {
        time(Some(&a.at))
            .unwrap_or(0)
            .cmp(&time(Some(&b.at)).unwrap_or(0))
            .then_with(|| a.id.cmp(&b.id))
    });
    // One event per protocol id: a message delivered again counts once.
    let mut by_protocol: HashMap<&str, Event> = HashMap::new();
    let mut order: Vec<&str> = Vec::new();
    for message in sorted {
        let Some(protocol) = message.protocol.as_ref() else {
            continue;
        };
        if !message.verified {
            unverified.push(message.id.clone());
            continue;
        }
        if !by_protocol.contains_key(protocol.id.as_str()) {
            order.push(protocol.id.as_str());
            by_protocol.insert(
                protocol.id.as_str(),
                Event {
                    message,
                    protocol,
                    ms: time(Some(&message.at)).unwrap_or(0),
                },
            );
        }
    }

    // Follow reply_to back to the opening message (or to the missing one).
    let root_of = |start: &str| -> (String, bool) {
        let mut seen = HashSet::new();
        let mut current = start;
        loop {
            seen.insert(current);
            let event = &by_protocol[current];
            match event.protocol.reply_to.as_deref() {
                None => return (current.to_string(), true),
                Some(parent) => match by_protocol.get(parent) {
                    None => return (parent.to_string(), false),
                    Some(next) if seen.contains(next.protocol.id.as_str()) => {
                        return (next.protocol.id.clone(), false)
                    }
                    Some(next) => current = next.protocol.id.as_str(),
                },
            }
        }
    };

    let mut events: Vec<&Event> = order.iter().map(|id| &by_protocol[id]).collect();
    events.sort_by_key(|e| e.ms);
    let mut groups: Vec<(String, bool, Vec<&Event>)> = Vec::new();
    for event in events {
        let (root, found) = root_of(event.protocol.id.as_str());
        if let Some(group) = groups.iter_mut().find(|g| g.0 == root) {
            group.1 = group.1 && found;
            group.2.push(event);
        } else {
            groups.push((root, found, vec![event]));
        }
    }

    let mut requests: Vec<RequestSummary> = groups
        .into_iter()
        .map(|(root, found, events)| summarise(root, found, &events, now_ms))
        .collect();
    requests.sort_by(|a, b| {
        let rank = |s: &str| ORDER.iter().position(|o| *o == s).unwrap_or(ORDER.len());
        rank(a.state).cmp(&rank(b.state)).then_with(|| {
            time(Some(&b.last.at))
                .unwrap_or(0)
                .cmp(&time(Some(&a.last.at)).unwrap_or(0))
        })
    });
    ConversationRequests {
        requests,
        unverified,
    }
}

fn payload_str(protocol: &ProtocolFacts, key: &str) -> Option<String> {
    protocol
        .payload
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn summarise(root: String, found: bool, events: &[&Event], now_ms: i64) -> RequestSummary {
    let kind = events[0].protocol.kind.clone();
    let last = events[events.len() - 1];
    let base = RequestSummary {
        request_id: root,
        kind: kind.clone(),
        state: "waiting_for_them",
        next: "none",
        last: LastEvent {
            message_id: last.message.id.clone(),
            action: last.protocol.action.clone(),
            at: last.message.at.clone(),
            mine: last.message.mine,
        },
        evidence: events.iter().map(|e| e.message.id.clone()).collect(),
        deadline: None,
        selected: None,
        result: None,
        ai_started_at: None,
        history_incomplete: !found,
    };
    let done = |state: &'static str, next: &'static str| RequestSummary {
        state,
        next,
        ..base.clone()
    };

    if !found {
        return done("missing_original", "you");
    }
    if events.iter().any(|e| e.protocol.kind != kind) {
        return done("conflict", "you");
    }

    let ending_actions = terminal(&kind);
    if let Some(first) = events
        .iter()
        .position(|e| ending_actions.contains(&e.protocol.action.as_str()))
    {
        let after = &events[first..];
        let actions: HashSet<&str> = after.iter().map(|e| e.protocol.action.as_str()).collect();
        // After an ending, only the same ending may come again.
        if actions.len() > 1 {
            return done("conflict", "you");
        }
        let ending = after[0].protocol;
        let before = &events[..first];
        if kind == "schedule_negotiation" && ending.action == "accept" {
            let picks: HashSet<String> = after
                .iter()
                .map(|e| {
                    e.protocol
                        .payload
                        .get("selected_candidate")
                        .cloned()
                        .unwrap_or(Value::Null)
                        .to_string()
                })
                .collect();
            if picks.len() > 1 {
                return done("conflict", "you");
            }
            let mut out = done("agreed", "none");
            out.selected = ending.payload.get("selected_candidate").cloned();
            return out;
        }
        if kind == "task_delegation" && ending.action == "complete" {
            if before.iter().any(|e| e.protocol.action == "decline") {
                return done("conflict", "you");
            }
            let mut out = done("completed", "none");
            out.result = payload_str(ending, "result");
            return out;
        }
        if kind == "task_delegation"
            && ending.action == "decline"
            && before.iter().any(|e| e.protocol.action == "accept")
        {
            return done("conflict", "you");
        }
        return done("declined", "none");
    }

    // Still open.
    if kind == "task_delegation" {
        if let Some(accept) = events.iter().rev().find(|e| e.protocol.action == "accept") {
            // Whoever took it on reports completion.
            return done("accepted", if accept.message.mine { "you" } else { "them" });
        }
    }

    let deadline = payload_str(last.protocol, "response_deadline");
    if let Some(deadline_ms) = time(deadline.as_deref()) {
        if deadline_ms < now_ms {
            let mut out = done("expired", "none");
            out.deadline = deadline;
            return out;
        }
    }
    let with_deadline = |mut out: RequestSummary| {
        out.deadline = deadline.clone();
        out
    };
    if last.message.mine {
        return with_deadline(done("waiting_for_them", "them"));
    }

    // Theirs: the person's turn, unless an executor took it.
    let record = last.message.auto_reply.clone().unwrap_or_default();
    if record.sent_at.is_some() {
        return with_deadline(done("ai_replied", "none"));
    }
    if let Some(claimed_ms) = time(record.claimed_at.as_deref()) {
        let mut out = if now_ms - claimed_ms <= AI_STARTED_WINDOW_SECS * 1000 {
            done("ai_started", "ai")
        } else {
            done("ai_unknown", "you")
        };
        out.ai_started_at = record.claimed_at.clone();
        return with_deadline(out);
    }
    with_deadline(done("waiting_for_you", "you"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vectors {
        now: String,
        ai_started_window_seconds: i64,
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        messages: Vec<RequestMessage>,
        expect: Expect,
    }
    #[derive(Deserialize)]
    struct Expect {
        requests: Vec<Value>,
        unverified: Vec<String>,
    }

    #[test]
    fn decisions_match_the_shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/request_state.json"
        );
        let vectors: Vectors = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(vectors.ai_started_window_seconds, AI_STARTED_WINDOW_SECS);
        assert_eq!(vectors.cases.len(), 30);
        for case in &vectors.cases {
            let out = conversation_requests(&case.messages, &vectors.now);
            assert_eq!(out.unverified, case.expect.unverified, "{}", case.name);
            let got_ids: Vec<&str> = out.requests.iter().map(|r| r.request_id.as_str()).collect();
            let want_ids: Vec<&str> = case
                .expect
                .requests
                .iter()
                .map(|r| r["request_id"].as_str().unwrap())
                .collect();
            assert_eq!(got_ids, want_ids, "{}", case.name);
            for (got, want) in out.requests.iter().zip(&case.expect.requests) {
                assert_eq!(got.state, want["state"], "{}", case.name);
                assert_eq!(got.next, want["next"], "{}", case.name);
                assert_eq!(
                    got.last.message_id, want["last_message_id"],
                    "{}",
                    case.name
                );
                assert_eq!(
                    serde_json::json!(got.evidence),
                    want["evidence"],
                    "{}",
                    case.name
                );
                let got = serde_json::to_value(got).unwrap();
                for key in [
                    "deadline",
                    "selected",
                    "result",
                    "ai_started_at",
                    "history_incomplete",
                ] {
                    if let Some(w) = want.get(key) {
                        assert_eq!(&got[key], w, "{}: {}", case.name, key);
                    }
                }
            }
        }
    }
}
