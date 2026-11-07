// Phase 4.4c+ (docs/25c-a §2.3) — minimal Rust A2A parser + reply
// payload builder. Mirrors packages/core/src/a2a.ts just enough for
// the Isolated mode executor to read an incoming propose/delegate and build
// the matching accept/decline. `check_answerable` ports the browser
// executor's request gate (docs/29 §2.6); tests/vectors/a2a_answerable.json
// keeps it in step with the TS side.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

pub const A2A_CONTENT_TYPE: &str = "application/vnd.nexusinbox.a2a+json; v=1";
pub const A2A_SCHEMA_VERSION: u64 = 1;

// Limits from packages/core/src/a2a.ts.
const SCHEDULE_MAX_CANDIDATES: usize = 20;
const SCHEDULE_MAX_CANDIDATE_DURATION_MS: i64 = 24 * 3600 * 1000;
const MAX_TASK_TITLE_LEN: usize = 200;
const MAX_TASK_DESCRIPTION_LEN: usize = 4000;
const VALID_TASK_PRIORITIES: [&str; 3] = ["high", "normal", "low"];

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
    // Required like in the TS `isA2AMessagePayload`, which rejects the
    // whole payload (protocol included) without a string body.
    let body = obj.get("body").and_then(|v| v.as_str())?.to_string();
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
    // Must be present, `null` or a string, as in the TS `isA2AProtocolBlock`.
    let reply_to = match obj.get("reply_to") {
        Some(Value::Null) => None,
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
// Answerability gate (docs/29 §2.6)
// ---------------------------------------------------------------------------

/// Port of the browser executor's `isAnswerableRequest`
/// (apps/web/lib/protocol/autoReplyExecutor.ts): `canRespondToProtocol`
/// (a2aReply.ts) plus `assertValidA2APayload` (packages/core/src/a2a.ts).
/// `Err` carries the reason the executor must not answer. `now` is the
/// clock for `response_deadline`, injected so expiry is testable.
pub fn check_answerable(
    folder: &str,
    protocol: &A2AProtocolBlock,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if folder == "sent" {
        return Err("sent_folder");
    }
    match protocol.protocol_type {
        A2AProtocolType::ScheduleNegotiation => {
            if protocol.action != "propose" {
                return Err("not_a_request");
            }
            validate_propose(&protocol.payload)?;
            if is_propose_expired(&protocol.payload, now) {
                return Err("expired");
            }
        }
        A2AProtocolType::TaskDelegation => {
            if protocol.action != "delegate" {
                return Err("not_a_request");
            }
            validate_delegate(&protocol.payload)?;
        }
    }
    Ok(())
}

/// `isProposeExpired`: the deadline has passed (strictly). Only called on a
/// validated payload, where a present deadline is a valid timestamp.
fn is_propose_expired(payload: &Value, now: DateTime<Utc>) -> bool {
    payload
        .get("response_deadline")
        .and_then(Value::as_str)
        .and_then(parse_js_timestamp_ms)
        .is_some_and(|deadline| now.timestamp_millis() > deadline)
}

/// `assertValidProposePayload`. A key that is present (even as `null`) is
/// checked, like `!== undefined` on the TS side.
fn validate_propose(payload: &Value) -> Result<(), &'static str> {
    const INVALID: &str = "invalid_payload";
    let p = payload.as_object().ok_or(INVALID)?;
    match p.get("event_title") {
        Some(Value::String(title)) if !is_js_blank(title) => {}
        _ => return Err(INVALID),
    }
    let candidates = p
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or(INVALID)?;
    if candidates.is_empty() || candidates.len() > SCHEDULE_MAX_CANDIDATES {
        return Err(INVALID);
    }
    for candidate in candidates {
        let start = candidate
            .get("start")
            .and_then(Value::as_str)
            .and_then(parse_js_timestamp_ms);
        let end = candidate
            .get("end")
            .and_then(Value::as_str)
            .and_then(parse_js_timestamp_ms);
        let (Some(start), Some(end)) = (start, end) else {
            return Err(INVALID);
        };
        if start >= end || end - start > SCHEDULE_MAX_CANDIDATE_DURATION_MS {
            return Err(INVALID);
        }
    }
    if !p.get("required_participants").is_some_and(Value::is_array) {
        return Err(INVALID);
    }
    if let Some(deadline) = p.get("response_deadline") {
        if deadline.as_str().and_then(parse_js_timestamp_ms).is_none() {
            return Err(INVALID);
        }
    }
    Ok(())
}

/// `assertValidDelegatePayload`. Lengths are JS `.length` (UTF-16 units).
fn validate_delegate(payload: &Value) -> Result<(), &'static str> {
    const INVALID: &str = "invalid_payload";
    let p = payload.as_object().ok_or(INVALID)?;
    match p.get("title") {
        Some(Value::String(title))
            if !is_js_blank(title) && js_length(title) <= MAX_TASK_TITLE_LEN => {}
        _ => return Err(INVALID),
    }
    if let Some(description) = p.get("description") {
        match description {
            Value::String(d) if js_length(d) <= MAX_TASK_DESCRIPTION_LEN => {}
            _ => return Err(INVALID),
        }
    }
    if let Some(due_date) = p.get("due_date") {
        if due_date.as_str().and_then(parse_js_timestamp_ms).is_none() {
            return Err(INVALID);
        }
    }
    if let Some(priority) = p.get("priority") {
        if !priority
            .as_str()
            .is_some_and(|value| VALID_TASK_PRIORITIES.contains(&value))
        {
            return Err(INVALID);
        }
    }
    Ok(())
}

/// JS `String.prototype.length`: UTF-16 code units, so an emoji counts 2.
fn js_length(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `s.trim().length === 0` with JavaScript's whitespace (WhiteSpace and
/// LineTerminator). Not `char::is_whitespace`: JS trims U+FEFF but keeps
/// U+0085.
fn is_js_blank(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(
            c,
            '\u{9}'..='\u{d}'
                | ' '
                | '\u{a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
        )
    })
}

/// `isValidIso8601WithTimezone` followed by `Date.parse`, as epoch
/// milliseconds. The shape is the TS regex
/// `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$`.
/// The value follows V8's `Date.parse`, which the TS vector test runs on:
/// day 1-31 whatever the month (February 30 rolls into March), 24:00:00
/// only with zero minutes, seconds and fraction, offsets up to ±23:59, and
/// the fraction read as V8 reads it (`v8_fraction_ms`).
pub fn parse_js_timestamp_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let digits = |at: usize, len: usize| -> Option<i64> {
        b.get(at..at + len)?.iter().try_fold(0_i64, |acc, d| {
            d.is_ascii_digit().then(|| acc * 10 + i64::from(d - b'0'))
        })
    };
    let byte_is = |at: usize, expected: u8| b.get(at) == Some(&expected);

    if !(byte_is(4, b'-')
        && byte_is(7, b'-')
        && byte_is(10, b'T')
        && byte_is(13, b':')
        && byte_is(16, b':'))
    {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);

    let mut i = 19;
    let mut fraction: &[u8] = &[];
    if byte_is(i, b'.') {
        let start = i + 1;
        let mut end = start;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return None;
        }
        fraction = &b[start..end];
        i = end;
    }

    let offset_ms = match b.get(i).copied() {
        Some(b'Z') => {
            i += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            if !byte_is(i + 3, b':') {
                return None;
            }
            let (offset_hour, offset_minute) = (digits(i + 1, 2)?, digits(i + 4, 2)?);
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            i += 6;
            let magnitude = (offset_hour * 60 + offset_minute) * 60_000;
            if sign == b'+' {
                magnitude
            } else {
                -magnitude
            }
        }
        _ => return None,
    };
    if i != b.len() {
        return None;
    }

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 24 || minute > 59 || second > 59 {
        return None;
    }
    if hour == 24 && (minute != 0 || second != 0 || fraction.iter().any(|&d| d != b'0')) {
        return None;
    }

    let days = days_to_first_of_month(year, month) + day - 1;
    Some(
        days * 86_400_000 + ((hour * 60 + minute) * 60 + second) * 1000 + v8_fraction_ms(fraction)
            - offset_ms,
    )
}

/// Milliseconds from fraction-of-second digits, read the way V8 does
/// (`DateParser::ReadMilliseconds`): leading zeros are skipped, at most 9
/// significant digits are kept, and the digit count is capped at 9 before
/// scaling to 3 places. Up to 9 digits that is plain truncation; past 9
/// with leading zeros V8 keeps too much (".0012345678" reads as 12 ms).
fn v8_fraction_ms(digits: &[u8]) -> i64 {
    let value = digits
        .iter()
        .skip_while(|&&d| d == b'0')
        .take(9)
        .fold(0_i64, |acc, &d| acc * 10 + i64::from(d - b'0'));
    match digits.len().min(9) {
        0 => 0,
        1 => value * 100,
        2 => value * 10,
        n => value / 10_i64.pow((n - 3) as u32),
    }
}

/// Days from 1970-01-01 to the first of `month` (proleptic Gregorian, year
/// 0 is a leap year, as in JS dates). Day overflow is added by the caller.
fn days_to_first_of_month(year: i64, month: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y.rem_euclid(400);
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
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

    #[test]
    fn parse_rejects_missing_body_and_missing_reply_to() {
        // The TS parser drops the whole payload in both cases, so the
        // browser never answers them; the gateway must not either.
        let mut no_body: Value = serde_json::from_str(&propose_body()).unwrap();
        no_body.as_object_mut().unwrap().remove("body");
        assert!(parse_a2a_payload(&no_body.to_string(), Some(A2A_CONTENT_TYPE)).is_none());

        let mut no_reply_to: Value = serde_json::from_str(&propose_body()).unwrap();
        no_reply_to["protocol"]
            .as_object_mut()
            .unwrap()
            .remove("reply_to");
        let parsed = parse_a2a_payload(&no_reply_to.to_string(), Some(A2A_CONTENT_TYPE)).unwrap();
        assert!(parsed.protocol.is_none());
    }

    #[test]
    fn js_timestamps_match_v8_date_parse() {
        // Values printed by `Date.parse` in Node (V8).
        let cases: &[(&str, Option<i64>)] = &[
            ("2026-01-01T10:00:00Z", Some(1_767_261_600_000)),
            ("2026-01-01T10:00:00+23:59", Some(1_767_175_260_000)),
            ("2026-01-01T23:59:59-23:59", Some(1_767_398_339_000)),
            ("2026-01-01T24:00:00Z", Some(1_767_312_000_000)),
            ("2026-01-01T24:00:00+09:00", Some(1_767_279_600_000)),
            ("2026-01-01T24:00:00.0Z", Some(1_767_312_000_000)),
            ("2026-02-30T10:00:00Z", Some(1_772_445_600_000)),
            ("2026-04-31T10:00:00Z", Some(1_777_629_600_000)),
            ("0000-01-01T00:00:00Z", Some(-62_167_219_200_000)),
            ("0000-02-29T00:00:00Z", Some(-62_162_121_600_000)),
            ("2026-01-01T10:00:00.1Z", Some(1_767_261_600_100)),
            ("2026-01-01T10:00:00.12Z", Some(1_767_261_600_120)),
            ("2026-01-01T10:00:00.9999Z", Some(1_767_261_600_999)),
            ("2026-01-01T10:00:00.0005Z", Some(1_767_261_600_000)),
            ("2026-01-01T10:00:00.0012345678Z", Some(1_767_261_600_012)),
            (
                "2026-01-01T10:00:00.0001234567891Z",
                Some(1_767_261_600_123),
            ),
            ("2026-12-31T23:59:59.999-23:59", Some(1_798_847_939_999)),
            ("2026-02-32T10:00:00Z", None),
            ("2026-13-01T10:00:00Z", None),
            ("2026-00-01T10:00:00Z", None),
            ("2026-01-00T10:00:00Z", None),
            ("2026-01-01T24:00:01Z", None),
            ("2026-01-01T24:00:00.0005Z", None),
            ("2026-01-01T25:00:00Z", None),
            ("2026-01-01T10:60:00Z", None),
            ("2026-01-01T10:00:60Z", None),
            ("2026-01-01T10:00:00+24:00", None),
            ("2026-01-01T10:00:00+10:60", None),
            // Shapes the TS regex rejects even where Date.parse would not.
            ("2026-01-01t10:00:00Z", None),
            ("2026-01-01T10:00:00z", None),
            ("2026-01-01T10:00:00+0900", None),
            ("2026-01-01T10:00:00", None),
            ("2026-01-01T10:00:00.Z", None),
            (" 2026-01-01T10:00:00Z", None),
            ("2026-01-01T10:00:00Z\n", None),
            ("2026-1-01T10:00:00Z", None),
            ("２026-01-01T10:00:00Z", None),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_js_timestamp_ms(input), *expected, "{input:?}");
        }
    }

    #[test]
    fn js_blank_uses_the_javascript_whitespace_set() {
        assert!(is_js_blank(""));
        assert!(is_js_blank(
            " \t\n\r\u{b}\u{c}\u{a0}\u{2028}\u{3000}\u{feff}"
        ));
        assert!(!is_js_blank("\u{85}"));
        assert!(!is_js_blank("\u{200b}"));
        assert!(!is_js_blank(" x "));
    }

    /// tests/vectors/a2a_answerable.json — the same cases run through the
    /// web's canRespondToProtocol + assertValidA2APayload
    /// (apps/web/lib/protocol/a2aAnswerable.vectors.test.ts).
    #[test]
    fn answerable_vectors_match_the_web() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vectors/a2a_answerable.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let doc: Value = serde_json::from_str(&raw).expect("vector file is JSON");
        let cases = doc["cases"].as_array().expect("cases array");
        assert!(cases.iter().any(|c| c["answerable"] == Value::Bool(true)));
        assert!(cases.iter().any(|c| c["answerable"] == Value::Bool(false)));

        let mut mismatches = Vec::new();
        for case in cases {
            let name = case["name"].as_str().expect("name");
            let folder = case["folder"].as_str().expect("folder");
            let now: DateTime<Utc> = case["now"].as_str().expect("now").parse().expect("now");
            let expected = case["answerable"].as_bool().expect("answerable");
            let plaintext = match &case["plaintext"] {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let verdict = match parse_a2a_payload(&plaintext, Some(A2A_CONTENT_TYPE))
                .and_then(|p| p.protocol)
            {
                Some(protocol) => check_answerable(folder, &protocol, now),
                None => Err("not_a2a"),
            };
            if verdict.is_ok() != expected {
                mismatches.push(format!("{name}: expected {expected}, got {verdict:?}"));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }
}
