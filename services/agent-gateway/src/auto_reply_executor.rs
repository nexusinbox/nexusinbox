// Phase 4.4c+ (docs/25c-a) — Isolated mode auto-reply executor.
//
// Long-lived tokio task that polls the API for messages the server
// evaluator stamped as `auto_accept` / `auto_decline` and dispatches
// the corresponding A2A reply. The daemon owns the signing and
// content-key wrap operations; the gateway only holds the cleartext
// content key for the duration of a single AES-GCM encrypt call.
//
// The executor stays intentionally small — it reuses the existing
// HTTP helpers and daemon IPC (`call_signer`) from main.rs rather than
// growing its own stack. docs/29 is the recovery ADR for the shape below:
// agent-scoped config, the same answerability gate as the web, a claim
// before every send, and a handled mark on every row it will not answer.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::a2a_rust::{
    build_schedule_reply_payload, build_task_reply_payload, check_answerable,
    first_candidate_from_propose, parse_a2a_payload, serialize_outgoing_body, A2AProtocolBlock,
    A2AProtocolType, A2A_CONTENT_TYPE,
};
use crate::envelope_crypto::{decrypt_envelope_text, encrypt_envelope_text, generate_content_key};
use crate::policy_evaluator::{self, Action as EvalAction, EvaluationContext, ProtocolKey};

pub const DEFAULT_INTERVAL_SECS: u64 = 30;
pub const MAX_PER_TICK: usize = 10;
pub const AUTO_REPLY_ORIGIN_DAEMON: &str = "daemon_protocol_v1";

/// A row that fails this many times (fetch, unwrap, decrypt, resolve, a
/// refused send...) is marked handled and left to the human (docs/29 §2.7).
const MAX_ATTEMPTS_PER_ROW: u32 = 3;

const DEFAULT_DECLINE_REASON: &str = "ポリシーに基づき自動で辞退しました";
const AUTO_REPLY_SUBJECT: &str = "Re: (auto-reply)";

/// Read the feature flag once. Values other than `on` / `1` / `true`
/// (case-insensitive) keep the executor dormant.
pub fn executor_enabled() -> bool {
    match std::env::var("AGENT_INBOX_MODE_A_EXECUTOR") {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "on" | "1" | "true"),
        Err(_) => false,
    }
}

pub fn executor_interval() -> Duration {
    let secs = std::env::var("AGENT_INBOX_MODE_A_EXECUTOR_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs.clamp(5, 3600))
}

// ---------------------------------------------------------------------------
// HTTP abstraction — kept narrow so the 1-tick driver is unit-testable.
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait ExecutorBackend: Send + Sync {
    /// `GET /agent-auto-reply/config`: this agent's own master switch and
    /// policy, readable with the agent token (docs/29 §2.1).
    async fn fetch_config(&self) -> Result<AutoReplyConfig, String>;
    async fn fetch_pending_messages(&self) -> Result<Vec<PendingMessage>, String>;
    async fn fetch_message_content(&self, message_id: &str) -> Result<MessageContent, String>;
    async fn resolve_recipient(&self, did: &str) -> Result<RecipientPubkey, String>;
    /// The signer daemon's DID (`get_public_key`), which replies are sent from.
    async fn fetch_our_did(&self) -> Result<String, String>;
    /// The daemon's own X25519 public key (`get_public_key`), if it has one.
    /// Replies carry a copy of the content key wrapped for it so this agent
    /// can read what it sent (docs/35 §5).
    async fn fetch_our_encryption_key(&self) -> Result<Option<String>, String>;
    async fn daemon_unwrap_content_key(&self, encrypted_key: &str) -> Result<String, String>;
    async fn daemon_wrap_content_key(
        &self,
        recipient_pub_b64: &str,
        content_key: &str,
    ) -> Result<String, String>;
    /// The daemon's `sign_envelope`; returns the signature.
    async fn daemon_sign_envelope(&self, params: &EnvelopeSigningParams) -> Result<String, String>;
    /// `POST /messages/{id}/auto-reply-claim`. `Ok(false)` on 409: another
    /// executor holds the row, or its reply already went out.
    async fn claim_auto_reply(&self, message_id: &str) -> Result<bool, String>;
    /// `DELETE /messages/{id}/auto-reply-claim`, for a send that certainly
    /// did not happen.
    async fn release_auto_reply_claim(&self, message_id: &str) -> Result<(), String>;
    async fn post_reply(&self, body: &Value) -> Result<Value, PostReplyError>;
    /// `PATCH /messages/{id}/auto-reply-sent`. Without `reply_message_id` it
    /// marks a row handled without a reply.
    async fn mark_auto_reply_sent(
        &self,
        message_id: &str,
        reply_message_id: Option<&str>,
    ) -> Result<(), String>;
}

/// The agent's own auto-reply settings (docs/29 §2.1).
#[derive(Debug, Clone)]
pub struct AutoReplyConfig {
    /// The owner's per-agent master switch (`agents.auto_reply`). Rows the
    /// server stamped while it was on stay pending after it is turned off,
    /// so it is read every tick.
    pub auto_reply_enabled: bool,
    pub policy: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub id: String,
    pub sender_did: String,
    // The executor doesn't read this today (the daemon's own DID is
    // the one we send from), but keeping it on the struct makes
    // cross-checking audit records easier.
    #[allow(dead_code)]
    pub recipient_did: String,
    pub thread_id: Option<String>,
    /// The row's folder. A row in `sent` is never answered.
    pub folder: String,
    // Kept for observability — the server's cached decision is
    // still useful when logging "why did we try / skip this entry".
    // The final send/skip choice now goes through the client
    // evaluator + merge rule (Phase 4.4c+B), so the raw field
    // doesn't gate dispatch any more.
    #[allow(dead_code)]
    pub decision: String,
    /// Phase 4.4c+B — extra context the protocol-aware evaluator
    /// needs. Set by the backend when it lists pending messages.
    pub priority: String,
    pub trust_score: f64,
    pub auto_reply_reason: Option<String>,
    /// Whether the sender is in the owner's contacts: one bit per pending
    /// row instead of the owner's contact list (docs/29 §2.2).
    pub sender_is_contact: bool,
}

#[derive(Debug, Clone)]
pub struct MessageContent {
    pub encrypted_content: String,
    pub encrypted_key: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecipientPubkey {
    pub did: String,
    pub encryption_public_key: String,
}

/// The six fields the daemon signs (its `SignEnvelopeParams`). They must be
/// the values `POST /messages` carries: the API rebuilds the signed bytes
/// from the request and verifies against them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvelopeSigningParams {
    pub sender_did: String,
    pub recipient_did: String,
    pub subject_encrypted: String,
    pub encrypted_content: String,
    pub encrypted_key: String,
    pub nonce: String,
}

/// Why `POST /messages` failed, split by whether the reply may have gone out.
#[derive(Debug, Clone)]
pub enum PostReplyError {
    /// Failed before the request left the gateway (no token). Nothing sent.
    NotSent(String),
    /// The API refused the request (4xx). Nothing sent.
    Rejected { status: u16, message: String },
    /// 5xx, timeout or a dropped connection: the reply may have been stored.
    Unknown(String),
}

/// What the executor carries from one tick to the next. Memory only:
/// nothing new is stored server-side (docs/29 §2.7).
#[derive(Debug, Default)]
pub struct ExecutorState {
    /// Failed attempts per message id, dropped once the row is settled.
    failures: HashMap<String, u32>,
    /// The daemon's DID once it has answered. Asked again while unknown, so
    /// a daemon that was down at startup cannot leave it empty for good.
    our_did: Option<String>,
}

// ---------------------------------------------------------------------------
// Single-tick driver — loops over eligible messages and dispatches.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct TickReport {
    pub sent: usize,
    pub skipped: usize,
    pub errors: usize,
}

pub async fn run_one_tick<B: ExecutorBackend>(
    backend: &B,
    state: &mut ExecutorState,
    now: DateTime<Utc>,
) -> TickReport {
    let mut report = TickReport::default();
    let pending = match backend.fetch_pending_messages().await {
        Ok(list) => list,
        Err(e) => {
            eprintln!("[auto-reply] fetch pending failed: {e}");
            report.errors += 1;
            return report;
        }
    };
    // Rows that left the list were settled elsewhere (or pushed out of the
    // window); forgetting them keeps the map bounded by MAX_PER_TICK.
    state
        .failures
        .retain(|id, _| pending.iter().any(|m| &m.id == id));
    if pending.is_empty() {
        return report;
    }
    // docs/29 §2.3: no config, no evaluation. Evaluating as "no policy"
    // would mark answerable rows handled during a transient outage.
    let config = match backend.fetch_config().await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("[auto-reply] fetch config failed, skipping this tick: {e}");
            report.errors += 1;
            return report;
        }
    };

    for entry in pending.iter().take(MAX_PER_TICK) {
        match dispatch_one(backend, state, entry, &config, now).await {
            DispatchOutcome::Sent => {
                report.sent += 1;
                state.failures.remove(&entry.id);
            }
            DispatchOutcome::Skipped => {
                report.skipped += 1;
                state.failures.remove(&entry.id);
            }
            DispatchOutcome::Abandoned => {
                report.errors += 1;
                state.failures.remove(&entry.id);
            }
            DispatchOutcome::Failed => {
                report.errors += 1;
                record_failure(backend, state, &entry.id).await;
            }
            DispatchOutcome::RateLimited => {
                // Not the row's fault, so it does not count towards its
                // attempts; the next tick tries again.
                report.errors += 1;
                break;
            }
        }
    }
    report
}

pub async fn run_loop<B: ExecutorBackend>(backend: Arc<B>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut state = ExecutorState::default();
    loop {
        ticker.tick().await;
        let report = run_one_tick(backend.as_ref(), &mut state, Utc::now()).await;
        if report.sent + report.skipped + report.errors > 0 {
            eprintln!(
                "[auto-reply] tick: sent={} skipped={} errors={}",
                report.sent, report.skipped, report.errors
            );
        }
    }
}

enum DispatchOutcome {
    /// Reply sent and the row marked with its id.
    Sent,
    /// Settled without sending: marked handled, or another executor holds it.
    Skipped,
    /// Transient failure, retried next tick. Any claim was given back.
    Failed,
    /// The reply may have gone out (5xx, timeout), or went out but could
    /// not be marked. The claim stays, so the row is left to the human.
    Abandoned,
    /// `POST /messages` answered 429: claim given back, stop this tick.
    RateLimited,
}

async fn dispatch_one<B: ExecutorBackend>(
    backend: &B,
    state: &mut ExecutorState,
    entry: &PendingMessage,
    config: &AutoReplyConfig,
    now: DateTime<Utc>,
) -> DispatchOutcome {
    let id = entry.id.as_str();

    // 1. Read the request. Failures here are transient: retried next tick.
    let content = match backend.fetch_message_content(id).await {
        Ok(c) => c,
        Err(e) => return failed(id, "fetch content", &e),
    };
    // Exact match, as in the web executor.
    if content.content_type.as_deref() != Some(A2A_CONTENT_TYPE) {
        return mark_handled(backend, id, "not_a2a").await;
    }
    let content_key = match backend
        .daemon_unwrap_content_key(&content.encrypted_key)
        .await
    {
        Ok(k) => k,
        Err(e) => return failed(id, "unwrap_content_key", &e),
    };
    let plaintext = match decrypt_envelope_text(&content.encrypted_content, &content_key) {
        Ok(p) => p,
        Err(e) => return failed(id, "decrypt", &e),
    };

    // 2. Decide. Every "no" marks the row handled so it leaves the list.
    let Some(protocol) =
        parse_a2a_payload(&plaintext, Some(A2A_CONTENT_TYPE)).and_then(|p| p.protocol)
    else {
        return mark_handled(backend, id, "not_a2a").await;
    };
    // The web's `isAnswerableRequest`: a live, well-formed propose or
    // delegate only (docs/29 §2.6).
    if let Err(reason) = check_answerable(&entry.folder, &protocol, now) {
        return mark_handled(backend, id, reason).await;
    }

    // Phase 4.4c+B — re-evaluate with the protocol-aware client
    // evaluator. Mirrors Standard mode's merge so a `protocols.*` override
    // can upgrade a queued decision or downgrade an auto-accept one.
    let eval_ctx = EvaluationContext {
        master_auto_reply_enabled: config.auto_reply_enabled,
        priority: entry.priority.clone(),
        trust_score: entry.trust_score,
        sender_did: entry.sender_did.clone(),
        is_contact: entry.sender_is_contact,
        protocol: Some(ProtocolKey {
            protocol_type: protocol.protocol_type.as_str(),
            action: protocol.action.clone(),
        }),
    };
    let client_decision = policy_evaluator::evaluate(config.policy.as_ref(), &eval_ctx);
    let final_decision =
        policy_evaluator::merge(entry.auto_reply_reason.as_deref(), client_decision);
    let action = match final_decision.action {
        EvalAction::AutoAccept => "accept",
        EvalAction::AutoDecline => "decline",
        _ => return mark_handled(backend, id, final_decision.reason).await,
    };
    let Some(reply_block) = build_reply_block(&protocol, action) else {
        return mark_handled(backend, id, "reply_payload_unavailable").await;
    };

    // 3. Take the row so no other executor sends the same reply (docs/29 §2.5).
    match backend.claim_auto_reply(id).await {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("[auto-reply] {id}: claimed by another executor; leaving it");
            return DispatchOutcome::Skipped;
        }
        Err(e) => return failed(id, "claim", &e),
    }

    // 4. Seal and sign. Nothing has been sent, so a failure gives the claim back.
    let body = match seal_reply(backend, state, entry, reply_block).await {
        Ok(body) => body,
        Err(e) => {
            release_claim(backend, id).await;
            return failed(id, "prepare reply", &e);
        }
    };

    // 5. Send. Only a certain non-delivery gives the claim back: no reply is
    //    better than a duplicate one.
    match backend.post_reply(&body).await {
        Ok(resp) => {
            let reply_message_id = resp.get("message_id").and_then(Value::as_str);
            match backend.mark_auto_reply_sent(id, reply_message_id).await {
                Ok(()) => DispatchOutcome::Sent,
                Err(e) => {
                    // The row stays claimed, so it does not come back.
                    eprintln!("[auto-reply] {id}: reply sent but marking it failed: {e}");
                    DispatchOutcome::Abandoned
                }
            }
        }
        Err(PostReplyError::Rejected { status, message }) => {
            release_claim(backend, id).await;
            if status == 429 {
                eprintln!("[auto-reply] {id}: POST /messages rate-limited ({message}); stopping this tick");
                DispatchOutcome::RateLimited
            } else {
                failed(id, "POST /messages", &format!("{status}: {message}"))
            }
        }
        Err(PostReplyError::NotSent(e)) => {
            release_claim(backend, id).await;
            failed(id, "POST /messages", &e)
        }
        Err(PostReplyError::Unknown(e)) => {
            eprintln!(
                "[auto-reply] {id}: POST /messages may have been delivered ({e}); keeping the claim, the row is left to the human"
            );
            DispatchOutcome::Abandoned
        }
    }
}

fn failed(message_id: &str, step: &str, error: &str) -> DispatchOutcome {
    eprintln!("[auto-reply] {message_id}: {step} failed: {error}");
    DispatchOutcome::Failed
}

/// Mark a row the executor will not answer as handled, without a reply id,
/// so it leaves the pending list (the web executor does the same).
async fn mark_handled<B: ExecutorBackend>(
    backend: &B,
    message_id: &str,
    reason: &str,
) -> DispatchOutcome {
    eprintln!("[auto-reply] {message_id}: not answering ({reason}); marking it handled");
    match backend.mark_auto_reply_sent(message_id, None).await {
        Ok(()) => DispatchOutcome::Skipped,
        Err(e) => failed(message_id, "mark handled", &e),
    }
}

async fn release_claim<B: ExecutorBackend>(backend: &B, message_id: &str) {
    if let Err(e) = backend.release_auto_reply_claim(message_id).await {
        // The row stays claimed and off the pending list: a human takes it.
        eprintln!("[auto-reply] {message_id}: releasing the claim failed: {e}");
    }
}

/// Count a failed attempt. On the MAX_ATTEMPTS_PER_ROW-th, mark the row
/// handled so it stops coming back, and forget it.
async fn record_failure<B: ExecutorBackend>(
    backend: &B,
    state: &mut ExecutorState,
    message_id: &str,
) {
    let attempts = state.failures.entry(message_id.to_string()).or_insert(0);
    *attempts += 1;
    if *attempts < MAX_ATTEMPTS_PER_ROW {
        return;
    }
    state.failures.remove(message_id);
    eprintln!(
        "[auto-reply] {message_id}: failed {MAX_ATTEMPTS_PER_ROW} times; marking it handled for the human"
    );
    if let Err(e) = backend.mark_auto_reply_sent(message_id, None).await {
        eprintln!("[auto-reply] {message_id}: marking it handled failed: {e}");
    }
}

/// The DID replies are sent from: asked from the daemon until it answers,
/// then reused.
async fn our_did<B: ExecutorBackend>(
    backend: &B,
    state: &mut ExecutorState,
) -> Result<String, String> {
    if let Some(did) = &state.our_did {
        return Ok(did.clone());
    }
    let did = backend
        .fetch_our_did()
        .await
        .map_err(|e| format!("get_public_key: {e}"))?;
    if did.is_empty() {
        return Err("get_public_key returned an empty DID".into());
    }
    state.our_did = Some(did.clone());
    Ok(did)
}

/// Encrypt the reply for the original sender, have the daemon wrap the key
/// and sign, and build the `POST /messages` body (matches
/// SendMessageRequest). The body carries exactly the signed fields.
async fn seal_reply<B: ExecutorBackend>(
    backend: &B,
    state: &mut ExecutorState,
    entry: &PendingMessage,
    reply_block: Value,
) -> Result<Value, String> {
    // The sender of the original is the recipient of the reply.
    let recipient = backend
        .resolve_recipient(&entry.sender_did)
        .await
        .map_err(|e| format!("resolve_recipient: {e}"))?;
    let sender_did = our_did(backend, state).await?;
    let content_key = generate_content_key();
    let subject = encrypt_envelope_text(AUTO_REPLY_SUBJECT, &content_key)?;
    let body = encrypt_envelope_text(&serialize_outgoing_body("", reply_block), &content_key)?;
    let wrapped_key = backend
        .daemon_wrap_content_key(&recipient.encryption_public_key, &content_key)
        .await
        .map_err(|e| format!("wrap_content_key: {e}"))?;
    let sender_wrapped_key = sender_copy(backend, &content_key).await;
    let signing = EnvelopeSigningParams {
        sender_did,
        recipient_did: recipient.did,
        subject_encrypted: subject.serialized,
        encrypted_content: body.serialized,
        encrypted_key: wrapped_key,
        nonce: body.nonce_b64url,
    };
    let signature = backend
        .daemon_sign_envelope(&signing)
        .await
        .map_err(|e| format!("sign_envelope: {e}"))?;
    // Same fallback as the web: a thread is named after its first message.
    let thread_id = entry.thread_id.as_deref().unwrap_or(entry.id.as_str());
    let mut body = serde_json::json!({
        "sender_did": signing.sender_did,
        "recipient_did": signing.recipient_did,
        "envelope": {
            "encrypted_content": signing.encrypted_content,
            "encrypted_key": signing.encrypted_key,
            "nonce": signing.nonce,
            "signature": signature,
            "metadata": {
                "subject_encrypted": signing.subject_encrypted,
                "content_type": A2A_CONTENT_TYPE,
                "thread_id": thread_id,
                "auto_reply_origin": AUTO_REPLY_ORIGIN_DAEMON,
            }
        }
    });
    // Not covered by the signature (docs/35 §5).
    if let Some(key) = sender_wrapped_key {
        body["envelope"]["sender_encrypted_key"] = Value::String(key);
    }
    Ok(body)
}

/// The content key wrapped for the daemon's own X25519 key. Best effort: a
/// reply without it still reaches the recipient, only this agent cannot
/// reread it later.
async fn sender_copy<B: ExecutorBackend>(backend: &B, content_key: &str) -> Option<String> {
    let own_pub = match backend.fetch_our_encryption_key().await {
        Ok(Some(key)) if !key.is_empty() => key,
        Ok(_) => return None,
        Err(e) => {
            eprintln!("[auto-reply] get_public_key for the sender copy failed: {e}");
            return None;
        }
    };
    match backend.daemon_wrap_content_key(&own_pub, content_key).await {
        Ok(wrapped) => Some(wrapped),
        Err(e) => {
            eprintln!("[auto-reply] wrapping the sender copy failed: {e}");
            None
        }
    }
}

/// Build the `protocol` block that goes into the outgoing A2A envelope body.
fn build_reply_block(protocol: &A2AProtocolBlock, action: &str) -> Option<Value> {
    // Schedule: the only `action` we actually send from here is
    // `propose → accept/decline`. Task delegation goes from
    // `delegate → accept/decline`. Anything else (counter, complete)
    // is out of scope for 4.4c+.
    let expected_source_action = match protocol.protocol_type {
        A2AProtocolType::ScheduleNegotiation => "propose",
        A2AProtocolType::TaskDelegation => "delegate",
    };
    if protocol.action != expected_source_action {
        return None;
    }

    let payload_value = match protocol.protocol_type {
        A2AProtocolType::ScheduleNegotiation => {
            let candidate = if action == "accept" {
                first_candidate_from_propose(&protocol.payload)
            } else {
                None
            };
            let decline_reason = (action == "decline").then_some(DEFAULT_DECLINE_REASON);
            build_schedule_reply_payload(action, candidate, decline_reason)?
        }
        A2AProtocolType::TaskDelegation => {
            let note = (action == "decline").then_some(DEFAULT_DECLINE_REASON);
            build_task_reply_payload(action, note)?
        }
    };

    Some(serde_json::json!({
        "id": new_uuid_like_id(),
        "type": protocol.protocol_type.as_str(),
        "action": action,
        "reply_to": protocol.id,
        "payload": payload_value,
    }))
}

/// Best-effort UUID-ish string for the outgoing `protocol.id`. The
/// spec (docs/24) asks for an opaque stable identifier — the browser
/// uses UUIDv7; we use base64url randomness which is equally opaque
/// and does not require an extra crate.
fn new_uuid_like_id() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        "2026-11-07T00:00:00Z".parse().unwrap()
    }

    struct MockBackend {
        pending: Vec<PendingMessage>,
        content_by_id: HashMap<String, MessageContent>,
        pubkey: RecipientPubkey,
        // Seed: the inner content_key used by the fixture body —
        // matches what `daemon_unwrap_content_key` will return.
        content_key: String,
        policy: Option<Value>,
        master: bool,
        config_error: Option<String>,
        // Answers to `fetch_our_did` in order; the last one repeats.
        our_did_answers: Mutex<VecDeque<Result<String, String>>>,
        our_encryption_key: Option<String>,
        resolve_error: Option<String>,
        claim: Result<bool, String>,
        post_error: Option<PostReplyError>,
        // Every call in order, e.g. "content:msg-1", "claim:msg-1", "post".
        calls: Mutex<Vec<String>>,
        sent: Mutex<Vec<Value>>,
        signed: Mutex<Vec<EnvelopeSigningParams>>,
        // Content keys handed to wrap_content_key, to open the sent reply.
        wrapped: Mutex<Vec<String>>,
        marked: Mutex<Vec<(String, Option<String>)>>,
    }

    impl MockBackend {
        fn log(&self, call: impl Into<String>) {
            self.calls.lock().unwrap().push(call.into());
        }

        fn count(&self, prefix: &str) -> usize {
            let calls = self.calls.lock().unwrap();
            calls.iter().filter(|c| c.starts_with(prefix)).count()
        }

        fn position(&self, call: &str) -> usize {
            let calls = self.calls.lock().unwrap();
            calls
                .iter()
                .position(|c| c == call)
                .unwrap_or_else(|| panic!("{call} not called: {calls:?}"))
        }

        fn marked(&self) -> Vec<(String, Option<String>)> {
            self.marked.lock().unwrap().clone()
        }

        fn sent_count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl ExecutorBackend for MockBackend {
        async fn fetch_config(&self) -> Result<AutoReplyConfig, String> {
            self.log("config");
            match &self.config_error {
                Some(e) => Err(e.clone()),
                None => Ok(AutoReplyConfig {
                    auto_reply_enabled: self.master,
                    policy: self.policy.clone(),
                }),
            }
        }

        async fn fetch_pending_messages(&self) -> Result<Vec<PendingMessage>, String> {
            self.log("pending");
            Ok(self.pending.clone())
        }

        async fn fetch_message_content(&self, id: &str) -> Result<MessageContent, String> {
            self.log(format!("content:{id}"));
            self.content_by_id
                .get(id)
                .cloned()
                .ok_or_else(|| "missing content".into())
        }

        async fn resolve_recipient(&self, _did: &str) -> Result<RecipientPubkey, String> {
            self.log("resolve");
            match &self.resolve_error {
                Some(e) => Err(e.clone()),
                None => Ok(self.pubkey.clone()),
            }
        }

        async fn fetch_our_did(&self) -> Result<String, String> {
            self.log("our_did");
            let mut answers = self.our_did_answers.lock().unwrap();
            if answers.len() > 1 {
                answers.pop_front().unwrap()
            } else {
                answers.front().cloned().unwrap()
            }
        }

        async fn fetch_our_encryption_key(&self) -> Result<Option<String>, String> {
            Ok(self.our_encryption_key.clone())
        }

        async fn daemon_unwrap_content_key(&self, _ek: &str) -> Result<String, String> {
            self.log("unwrap");
            Ok(self.content_key.clone())
        }

        async fn daemon_wrap_content_key(
            &self,
            recipient_pub: &str,
            content_key: &str,
        ) -> Result<String, String> {
            self.log("wrap");
            self.wrapped.lock().unwrap().push(content_key.into());
            Ok(format!("x25519v1:fake:wrapped-for:{recipient_pub}"))
        }

        async fn daemon_sign_envelope(
            &self,
            params: &EnvelopeSigningParams,
        ) -> Result<String, String> {
            self.log("sign");
            self.signed.lock().unwrap().push(params.clone());
            Ok("FAKE_SIGNATURE".into())
        }

        async fn claim_auto_reply(&self, id: &str) -> Result<bool, String> {
            self.log(format!("claim:{id}"));
            self.claim.clone()
        }

        async fn release_auto_reply_claim(&self, id: &str) -> Result<(), String> {
            self.log(format!("release:{id}"));
            Ok(())
        }

        async fn post_reply(&self, body: &Value) -> Result<Value, PostReplyError> {
            self.log("post");
            self.sent.lock().unwrap().push(body.clone());
            match &self.post_error {
                Some(e) => Err(e.clone()),
                None => Ok(json!({ "message_id": "reply-1" })),
            }
        }

        async fn mark_auto_reply_sent(
            &self,
            message_id: &str,
            reply_id: Option<&str>,
        ) -> Result<(), String> {
            self.log(format!("mark:{message_id}"));
            self.marked
                .lock()
                .unwrap()
                .push((message_id.into(), reply_id.map(str::to_string)));
            Ok(())
        }
    }

    fn propose_plaintext() -> Value {
        json!({
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
    }

    fn pending_row(id: &str) -> PendingMessage {
        PendingMessage {
            id: id.into(),
            sender_did: "did:key:zSender".into(),
            recipient_did: "did:key:zViewer".into(),
            thread_id: Some("thread-1".into()),
            folder: "inbox".into(),
            decision: "auto_accept".into(),
            priority: "normal".into(),
            trust_score: 0.8,
            auto_reply_reason: Some("default_match".into()),
            sender_is_contact: false,
        }
    }

    /// One pending row, `msg-1`, whose decrypted body is `plaintext`.
    fn backend_with_plaintext(plaintext: &str) -> MockBackend {
        let content_key = generate_content_key();
        let encrypted = encrypt_envelope_text(plaintext, &content_key)
            .expect("encrypt")
            .serialized;
        let mut map = HashMap::new();
        map.insert(
            "msg-1".into(),
            MessageContent {
                encrypted_content: encrypted,
                encrypted_key: "x25519v1:incoming:wrapped:key:data".into(),
                content_type: Some(A2A_CONTENT_TYPE.into()),
            },
        );
        MockBackend {
            pending: vec![pending_row("msg-1")],
            content_by_id: map,
            pubkey: RecipientPubkey {
                did: "did:key:zSender".into(),
                encryption_public_key: "fake-pub-key".into(),
            },
            content_key,
            policy: Some(json!({
                "v": 1,
                "default_action": "auto_accept",
            })),
            master: true,
            config_error: None,
            our_did_answers: Mutex::new(VecDeque::from([Ok("did:key:zViewer".to_string())])),
            our_encryption_key: Some("daemon-pub-key".into()),
            resolve_error: None,
            claim: Ok(true),
            post_error: None,
            calls: Mutex::new(Vec::new()),
            sent: Mutex::new(Vec::new()),
            signed: Mutex::new(Vec::new()),
            wrapped: Mutex::new(Vec::new()),
            marked: Mutex::new(Vec::new()),
        }
    }

    fn make_backend() -> MockBackend {
        backend_with_plaintext(&propose_plaintext().to_string())
    }

    async fn tick(backend: &MockBackend) -> TickReport {
        run_one_tick(backend, &mut ExecutorState::default(), now()).await
    }

    /// The row was settled without a reply: marked handled, never claimed.
    fn assert_marked_handled(backend: &MockBackend, report: &TickReport, case: &str) {
        assert_eq!(report.sent, 0, "{case}");
        assert_eq!(report.skipped, 1, "{case}");
        assert_eq!(
            backend.marked(),
            vec![("msg-1".to_string(), None)],
            "{case}"
        );
        assert_eq!(backend.count("claim:"), 0, "{case}");
        assert_eq!(backend.sent_count(), 0, "{case}");
    }

    #[tokio::test]
    async fn run_one_tick_dispatches_schedule_accept() {
        let backend = make_backend();
        let report = tick(&backend).await;
        assert_eq!(report.sent, 1);
        assert_eq!(report.errors, 0);
        // Claim, then send, then mark with the reply id.
        assert!(backend.position("claim:msg-1") < backend.position("post"));
        assert!(backend.position("post") < backend.position("mark:msg-1"));
        assert_eq!(
            backend.marked(),
            vec![("msg-1".to_string(), Some("reply-1".to_string()))]
        );
        assert_eq!(backend.count("release:"), 0);

        let sent = backend.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let envelope = &sent[0]["envelope"];
        assert_eq!(
            envelope["metadata"]["auto_reply_origin"].as_str(),
            Some(AUTO_REPLY_ORIGIN_DAEMON)
        );
        assert_eq!(
            envelope["metadata"]["content_type"].as_str(),
            Some(A2A_CONTENT_TYPE)
        );
        assert_eq!(envelope["metadata"]["thread_id"].as_str(), Some("thread-1"));

        // The reply opens with the content key that was wrapped for the
        // recipient, and accepts the first candidate of proto-1.
        let content_key = backend.wrapped.lock().unwrap()[0].clone();
        let reply: Value = serde_json::from_str(
            &decrypt_envelope_text(
                envelope["encrypted_content"].as_str().unwrap(),
                &content_key,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(reply["protocol"]["type"], "schedule_negotiation");
        assert_eq!(reply["protocol"]["action"], "accept");
        assert_eq!(reply["protocol"]["reply_to"], "proto-1");
        assert_eq!(
            reply["protocol"]["payload"]["selected_candidate"]["start"],
            "2026-05-01T09:00:00+09:00"
        );
        let subject = decrypt_envelope_text(
            envelope["metadata"]["subject_encrypted"].as_str().unwrap(),
            &content_key,
        )
        .unwrap();
        assert_eq!(subject, AUTO_REPLY_SUBJECT);

        // The same content key is also wrapped for the daemon itself, so the
        // agent can reread its reply; the signature covers only the
        // recipient's wrap.
        assert_eq!(
            envelope["encrypted_key"].as_str(),
            Some("x25519v1:fake:wrapped-for:fake-pub-key")
        );
        assert_eq!(
            envelope["sender_encrypted_key"].as_str(),
            Some("x25519v1:fake:wrapped-for:daemon-pub-key")
        );
        let wrapped = backend.wrapped.lock().unwrap();
        assert_eq!(wrapped.len(), 2);
        assert_eq!(wrapped[0], wrapped[1]);
        assert_eq!(
            backend.signed.lock().unwrap()[0].encrypted_key,
            "x25519v1:fake:wrapped-for:fake-pub-key"
        );
    }

    #[tokio::test]
    async fn reply_without_a_daemon_encryption_key_has_no_sender_copy() {
        let mut backend = make_backend();
        backend.our_encryption_key = None;
        let report = tick(&backend).await;
        assert_eq!(report.sent, 1);
        let sent = backend.sent.lock().unwrap();
        assert!(sent[0]["envelope"].get("sender_encrypted_key").is_none());
    }

    #[tokio::test]
    async fn run_one_tick_sends_nothing_once_the_master_switch_is_off() {
        // Regression (review 2026-11-07): the switch was hard-coded on, so a
        // row stamped `auto_accept` while auto-reply was enabled was still
        // answered after the owner turned it off. Now the row is settled.
        let mut backend = make_backend();
        backend.master = false;
        let report = tick(&backend).await;
        assert_marked_handled(&backend, &report, "master off");
    }

    #[tokio::test]
    async fn run_one_tick_skips_non_a2a_content_type() {
        let mut backend = make_backend();
        if let Some(c) = backend.content_by_id.get_mut("msg-1") {
            c.content_type = Some("text/plain".into());
        }
        let report = tick(&backend).await;
        assert_marked_handled(&backend, &report, "text/plain");
        // Not even unwrapped.
        assert_eq!(backend.count("unwrap"), 0);
    }

    #[tokio::test]
    async fn run_one_tick_skips_when_client_evaluator_returns_queue() {
        // Policy has no default_action → client evaluator returns
        // no_policy → final action is queue_for_human → executor
        // skips even though the server's cached decision was
        // "auto_accept". This exercises the protocol-aware merge
        // (Phase 4.4c+B) — the client evaluator has final say.
        let mut backend = make_backend();
        backend.policy = Some(json!({}));
        let report = tick(&backend).await;
        assert_marked_handled(&backend, &report, "no policy");
    }

    #[tokio::test]
    async fn protocol_override_upgrades_queued_server_decision() {
        // Server cached queue_for_human (default), but policy has a
        // schedule_negotiation.propose override that says
        // auto_accept. The client evaluator sees the protocol and
        // upgrades the decision; the executor dispatches an accept.
        let mut backend = make_backend();
        backend.pending[0].decision = "auto_accept".into();
        backend.pending[0].auto_reply_reason = Some("default_match".into());
        backend.policy = Some(json!({
            "v": 1,
            "default_action": "queue_for_human",
            "protocols": {
                "schedule_negotiation": {
                    "propose": { "action": "auto_accept" }
                }
            }
        }));
        let report = tick(&backend).await;
        assert_eq!(report.sent, 1);
    }

    #[tokio::test]
    async fn master_off_from_server_blocks_send_even_with_policy() {
        // Cached reason=master_off — the merge rule keeps that sticky
        // even if the client-evaluated policy would auto_accept.
        let mut backend = make_backend();
        backend.pending[0].auto_reply_reason = Some("master_off".into());
        let report = tick(&backend).await;
        assert_marked_handled(&backend, &report, "server master_off");
    }

    #[tokio::test]
    async fn contact_requirement_blocks_non_contact() {
        let mut backend = make_backend();
        backend.policy = Some(json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "require_contact": true }
        }));
        // The row says the sender is not a contact.
        let report = tick(&backend).await;
        assert_marked_handled(&backend, &report, "not a contact");
    }

    #[tokio::test]
    async fn contact_requirement_passes_when_sender_is_in_contacts() {
        let mut backend = make_backend();
        backend.policy = Some(json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "require_contact": true }
        }));
        backend.pending[0].sender_is_contact = true;
        let report = tick(&backend).await;
        assert_eq!(report.sent, 1);
    }

    #[tokio::test]
    async fn run_one_tick_caps_at_max_per_tick() {
        let mut backend = make_backend();
        backend.pending = (0..(MAX_PER_TICK + 5))
            .map(|i| pending_row(&format!("msg-{i}")))
            .collect();
        // Re-use the single fixture content for every id so fetch
        // doesn't 404. Plain text keeps each row on the cheap skip path
        // (no PBKDF2 round, which is slow in debug builds).
        let mut template = backend.content_by_id.get("msg-1").cloned().unwrap();
        template.content_type = Some("text/plain".into());
        for i in 0..(MAX_PER_TICK + 5) {
            backend
                .content_by_id
                .insert(format!("msg-{i}"), template.clone());
        }
        let report = tick(&backend).await;
        assert_eq!(report.sent + report.skipped + report.errors, MAX_PER_TICK);
        assert_eq!(backend.count("content:"), MAX_PER_TICK);
        assert_eq!(backend.marked().len(), MAX_PER_TICK);
    }

    #[tokio::test]
    async fn config_fetch_failure_processes_nothing() {
        // docs/29 §2.3: evaluating without the config would treat every
        // row as "no policy" and mark it handled on a transient outage.
        let mut backend = make_backend();
        backend.config_error = Some("API returned 503".into());
        let report = tick(&backend).await;
        assert_eq!((report.sent, report.skipped, report.errors), (0, 0, 1));
        assert_eq!(
            *backend.calls.lock().unwrap(),
            vec!["pending".to_string(), "config".to_string()]
        );
        assert!(backend.marked().is_empty());
    }

    #[tokio::test]
    async fn claim_conflict_sends_nothing_and_marks_nothing() {
        let mut backend = make_backend();
        backend.claim = Ok(false);
        let report = tick(&backend).await;
        assert_eq!((report.sent, report.skipped, report.errors), (0, 1, 0));
        assert_eq!(backend.count("claim:msg-1"), 1);
        assert_eq!(backend.sent_count(), 0);
        assert!(backend.marked().is_empty());
        assert_eq!(backend.count("release:"), 0);
        assert_eq!(backend.count("sign"), 0);
    }

    #[tokio::test]
    async fn claim_error_counts_an_error_and_sends_nothing() {
        let mut backend = make_backend();
        backend.claim = Err("API returned 500".into());
        let mut state = ExecutorState::default();
        let report = run_one_tick(&backend, &mut state, now()).await;
        assert_eq!((report.sent, report.errors), (0, 1));
        assert_eq!(backend.sent_count(), 0);
        assert!(backend.marked().is_empty());
        assert_eq!(backend.count("release:"), 0);
        assert_eq!(state.failures.get("msg-1"), Some(&1));
    }

    #[tokio::test]
    async fn refused_send_releases_the_claim() {
        for error in [
            PostReplyError::Rejected {
                status: 400,
                message: "bad envelope".into(),
            },
            PostReplyError::NotSent("token endpoint unreachable".into()),
        ] {
            let mut backend = make_backend();
            backend.post_error = Some(error.clone());
            let mut state = ExecutorState::default();
            let report = run_one_tick(&backend, &mut state, now()).await;
            assert_eq!((report.sent, report.errors), (0, 1), "{error:?}");
            assert!(
                backend.position("post") < backend.position("release:msg-1"),
                "{error:?}"
            );
            assert!(backend.marked().is_empty(), "{error:?}");
            // Retried next tick, and counted towards the row's attempts.
            assert_eq!(state.failures.get("msg-1"), Some(&1), "{error:?}");
        }
    }

    #[tokio::test]
    async fn rate_limited_send_releases_and_stops_the_tick() {
        let mut backend = make_backend();
        backend.pending.push(pending_row("msg-2"));
        let template = backend.content_by_id["msg-1"].clone();
        backend.content_by_id.insert("msg-2".into(), template);
        backend.post_error = Some(PostReplyError::Rejected {
            status: 429,
            message: "slow down".into(),
        });
        let mut state = ExecutorState::default();
        let report = run_one_tick(&backend, &mut state, now()).await;
        assert_eq!((report.sent, report.skipped, report.errors), (0, 0, 1));
        assert_eq!(backend.count("release:msg-1"), 1);
        // The tick stopped before the second row.
        assert_eq!(backend.count("content:msg-2"), 0);
        assert!(backend.marked().is_empty());
        // Rate limiting is not the row's fault.
        assert!(state.failures.is_empty());
    }

    #[tokio::test]
    async fn send_with_unknown_outcome_keeps_the_claim() {
        // A 5xx or a timeout may come after the API stored the reply.
        // Releasing would let the next tick send a duplicate.
        let mut backend = make_backend();
        backend.post_error = Some(PostReplyError::Unknown("API returned 502".into()));
        let mut state = ExecutorState::default();
        let report = run_one_tick(&backend, &mut state, now()).await;
        assert_eq!((report.sent, report.errors), (0, 1));
        assert_eq!(backend.count("post"), 1);
        assert_eq!(backend.count("release:"), 0);
        assert!(backend.marked().is_empty());
        assert!(state.failures.is_empty());
    }

    #[tokio::test]
    async fn failure_after_the_claim_releases_it() {
        let mut backend = make_backend();
        backend.resolve_error = Some("API returned 404".into());
        let report = tick(&backend).await;
        assert_eq!((report.sent, report.errors), (0, 1));
        assert!(backend.position("claim:msg-1") < backend.position("release:msg-1"));
        assert_eq!(backend.count("post"), 0);
        assert!(backend.marked().is_empty());
    }

    #[tokio::test]
    async fn skip_cases_mark_the_row_handled() {
        let mut cases: Vec<(&str, MockBackend)> = vec![
            (
                "plaintext is not JSON",
                backend_with_plaintext("Let's meet at 9"),
            ),
            (
                "no protocol block",
                backend_with_plaintext(r#"{"v":1,"body":"hi"}"#),
            ),
        ];

        let mut accept = propose_plaintext();
        accept["protocol"]["action"] = json!("accept");
        accept["protocol"]["reply_to"] = json!("proto-0");
        accept["protocol"]["payload"] = json!({
            "selected_candidate": {"start": "2026-05-01T09:00:00Z", "end": "2026-05-01T10:00:00Z"}
        });
        cases.push(("not a request", backend_with_plaintext(&accept.to_string())));

        let mut invalid = propose_plaintext();
        invalid["protocol"]["payload"]["candidates"] = json!([]);
        cases.push((
            "invalid payload",
            backend_with_plaintext(&invalid.to_string()),
        ));

        let mut sent_folder = make_backend();
        sent_folder.pending[0].folder = "sent".into();
        cases.push(("sent folder", sent_folder));

        let mut needs_calendar = make_backend();
        needs_calendar.policy = Some(json!({ "v": 1, "default_action": "auto_accept_if_free" }));
        cases.push(("evaluator queues for the human", needs_calendar));

        for (case, backend) in cases {
            let report = tick(&backend).await;
            assert_marked_handled(&backend, &report, case);
        }
    }

    #[tokio::test]
    async fn expired_proposal_is_marked_handled_and_not_sent() {
        let mut plaintext = propose_plaintext();
        plaintext["protocol"]["payload"]["response_deadline"] = json!("2026-11-06T23:59:59Z");
        let backend = backend_with_plaintext(&plaintext.to_string());
        let report = tick(&backend).await;
        assert_marked_handled(&backend, &report, "expired");

        // The same request before its deadline is answered.
        let backend = backend_with_plaintext(&plaintext.to_string());
        let earlier: DateTime<Utc> = "2026-11-06T12:00:00Z".parse().unwrap();
        let report = run_one_tick(&backend, &mut ExecutorState::default(), earlier).await;
        assert_eq!(report.sent, 1);
    }

    #[tokio::test]
    async fn sign_envelope_receives_the_values_the_post_body_carries() {
        let mut backend = make_backend();
        // `/recipients/resolve` canonicalises the DID; the resolved one is
        // what gets signed and sent.
        backend.pubkey.did = "did:key:zResolvedSender".into();
        let report = tick(&backend).await;
        assert_eq!(report.sent, 1);

        let signed = backend.signed.lock().unwrap();
        let sent = backend.sent.lock().unwrap();
        assert_eq!((signed.len(), sent.len()), (1, 1));
        let (params, body) = (&signed[0], &sent[0]);
        let envelope = &body["envelope"];
        assert_eq!(params.sender_did, "did:key:zViewer");
        assert_eq!(params.recipient_did, "did:key:zResolvedSender");
        assert_eq!(
            body["sender_did"].as_str(),
            Some(params.sender_did.as_str())
        );
        assert_eq!(
            body["recipient_did"].as_str(),
            Some(params.recipient_did.as_str())
        );
        assert_eq!(
            envelope["metadata"]["subject_encrypted"].as_str(),
            Some(params.subject_encrypted.as_str())
        );
        assert_eq!(
            envelope["encrypted_content"].as_str(),
            Some(params.encrypted_content.as_str())
        );
        assert_eq!(
            envelope["encrypted_key"].as_str(),
            Some(params.encrypted_key.as_str())
        );
        assert_eq!(envelope["nonce"].as_str(), Some(params.nonce.as_str()));
        assert_eq!(envelope["signature"].as_str(), Some("FAKE_SIGNATURE"));
        // The daemon gets exactly its six fields.
        let mut keys: Vec<String> = serde_json::to_value(params)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "encrypted_content",
                "encrypted_key",
                "nonce",
                "recipient_did",
                "sender_did",
                "subject_encrypted"
            ]
        );
    }

    #[tokio::test]
    async fn row_failing_three_times_is_marked_handled() {
        let mut backend = make_backend();
        backend.content_by_id.clear();
        let mut state = ExecutorState::default();
        for attempt in 1..MAX_ATTEMPTS_PER_ROW {
            let report = run_one_tick(&backend, &mut state, now()).await;
            assert_eq!(report.errors, 1);
            assert!(backend.marked().is_empty(), "attempt {attempt}");
            assert_eq!(state.failures.get("msg-1"), Some(&attempt));
        }
        let report = run_one_tick(&backend, &mut state, now()).await;
        assert_eq!(report.errors, 1);
        assert_eq!(backend.marked(), vec![("msg-1".to_string(), None)]);
        assert!(state.failures.is_empty());
        assert_eq!(backend.count("claim:"), 0);
    }

    #[tokio::test]
    async fn empty_our_did_is_resolved_again() {
        // The daemon is down, then answers with an empty DID, then works.
        // The DID used to be read once at startup and kept empty for good.
        let backend = make_backend();
        *backend.our_did_answers.lock().unwrap() = VecDeque::from([
            Err("cannot connect to signer daemon".to_string()),
            Ok(String::new()),
            Ok("did:key:zViewer".to_string()),
        ]);
        let mut state = ExecutorState::default();
        for attempt in 1..=2 {
            let report = run_one_tick(&backend, &mut state, now()).await;
            assert_eq!((report.sent, report.errors), (0, 1), "attempt {attempt}");
            assert_eq!(backend.count("release:msg-1"), attempt);
            assert_eq!(backend.count("post"), 0);
        }
        let report = run_one_tick(&backend, &mut state, now()).await;
        assert_eq!(report.sent, 1);
        assert_eq!(
            backend.sent.lock().unwrap()[0]["sender_did"].as_str(),
            Some("did:key:zViewer")
        );
        // Once known, the DID is reused.
        run_one_tick(&backend, &mut state, now()).await;
        assert_eq!(backend.count("our_did"), 3);
        assert_eq!(backend.sent_count(), 2);
    }

    #[tokio::test]
    async fn thread_id_falls_back_to_the_message_id() {
        let mut backend = make_backend();
        backend.pending[0].thread_id = None;
        let report = tick(&backend).await;
        assert_eq!(report.sent, 1);
        assert_eq!(
            backend.sent.lock().unwrap()[0]["envelope"]["metadata"]["thread_id"].as_str(),
            Some("msg-1")
        );
    }

    #[test]
    fn executor_enabled_respects_env() {
        std::env::remove_var("AGENT_INBOX_MODE_A_EXECUTOR");
        assert!(!executor_enabled());
        std::env::set_var("AGENT_INBOX_MODE_A_EXECUTOR", "on");
        assert!(executor_enabled());
        std::env::set_var("AGENT_INBOX_MODE_A_EXECUTOR", "off");
        assert!(!executor_enabled());
        std::env::remove_var("AGENT_INBOX_MODE_A_EXECUTOR");
    }
}
