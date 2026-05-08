// Phase 4.4c+ (docs/25c-a) — Isolated mode auto-reply executor.
//
// Long-lived tokio task that polls the API for messages the server
// evaluator stamped as `auto_accept` / `auto_decline` and dispatches
// the corresponding A2A reply. The daemon owns the signing and
// content-key wrap operations; the gateway only holds the cleartext
// content key for the duration of a single AES-GCM encrypt call.
//
// The executor stays intentionally small — it reuses the existing
// HTTP helpers (`api_get` / `api_post` / `api_patch`) and daemon IPC
// (`call_signer`) from main.rs rather than growing its own stack.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::a2a_rust::{
    build_schedule_reply_payload, build_task_reply_payload, first_candidate_from_propose,
    is_a2a_content_type, parse_a2a_payload, serialize_outgoing_body, A2APayload, A2AProtocolBlock,
    A2AProtocolType, A2A_CONTENT_TYPE,
};
use crate::envelope_crypto::{decrypt_envelope_text, encrypt_envelope_text, generate_content_key};
use crate::policy_evaluator::{self, Action as EvalAction, EvaluationContext, ProtocolKey};

pub const DEFAULT_INTERVAL_SECS: u64 = 30;
pub const MAX_PER_TICK: usize = 10;
pub const AUTO_REPLY_ORIGIN_DAEMON: &str = "daemon_protocol_v1";

const DEFAULT_DECLINE_REASON: &str = "ポリシーに基づき自動で辞退しました";

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
    async fn fetch_pending_messages(&self) -> Result<Vec<PendingMessage>, String>;
    async fn fetch_message_content(&self, message_id: &str) -> Result<MessageContent, String>;
    async fn resolve_recipient(&self, did: &str) -> Result<RecipientPubkey, String>;
    async fn daemon_unwrap_content_key(&self, encrypted_key: &str) -> Result<String, String>;
    async fn daemon_wrap_content_key(
        &self,
        recipient_pub_b64: &str,
        content_key: &str,
    ) -> Result<String, String>;
    async fn daemon_sign_envelope(
        &self,
        sender_did: &str,
        recipient_did: &str,
        payload_b64: &str,
    ) -> Result<String, String>;
    async fn post_reply(&self, body: &Value) -> Result<Value, String>;
    async fn mark_auto_reply_sent(
        &self,
        message_id: &str,
        reply_message_id: Option<&str>,
    ) -> Result<(), String>;
    fn our_did(&self) -> &str;

    /// Phase 4.4c+B (docs/25c-a §2.3, ADR follow-up). Returns the
    /// agent's stored policy JSON so the Rust protocol-aware
    /// evaluator can honour `protocols.<type>.<action>` overrides.
    /// Default impl returns None (empty-policy semantics) so
    /// backends that haven't plumbed the endpoint through stay
    /// functional — they simply act on the server's cached decision
    /// without re-evaluating.
    async fn fetch_policy(&self) -> Result<Option<Value>, String> {
        Ok(None)
    }

    /// Phase 4.4c+B — set of DIDs the owner has saved as contacts.
    /// Used by the `require_contact` / `sender_in_allowlist` branches
    /// of the evaluator. Default impl returns empty so policies that
    /// hinge on contact status never auto-accept when the backend
    /// declines to plumb it through.
    async fn fetch_contact_dids(&self) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
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

// ---------------------------------------------------------------------------
// Single-tick driver — loops over eligible messages and dispatches.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct TickReport {
    pub sent: usize,
    pub skipped: usize,
    pub errors: usize,
}

pub async fn run_one_tick<B: ExecutorBackend>(backend: &B) -> TickReport {
    let mut report = TickReport::default();
    let pending = match backend.fetch_pending_messages().await {
        Ok(list) => list,
        Err(e) => {
            eprintln!("[auto-reply] fetch pending failed: {e}");
            return report;
        }
    };
    if pending.is_empty() {
        return report;
    }
    // Phase 4.4c+B: fetch policy + contacts once per tick. The
    // protocol-aware evaluator re-runs for every message but the
    // inputs that don't vary per-message are cached here.
    let policy = match backend.fetch_policy().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[auto-reply] fetch policy failed: {e}");
            None
        }
    };
    let contacts: std::collections::HashSet<String> = match backend.fetch_contact_dids().await {
        Ok(dids) => dids.into_iter().collect(),
        Err(e) => {
            eprintln!("[auto-reply] fetch contacts failed: {e}");
            std::collections::HashSet::new()
        }
    };

    let take = pending.len().min(MAX_PER_TICK);
    for entry in pending.into_iter().take(take) {
        match dispatch_one(backend, &entry, policy.as_ref(), &contacts).await {
            DispatchOutcome::Sent => report.sent += 1,
            DispatchOutcome::Skipped => report.skipped += 1,
            DispatchOutcome::Error => report.errors += 1,
        }
    }
    report
}

pub async fn run_loop<B: ExecutorBackend>(backend: Arc<B>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        run_one_tick(backend.as_ref()).await;
    }
}

enum DispatchOutcome {
    Sent,
    Skipped,
    Error,
}

async fn dispatch_one<B: ExecutorBackend>(
    backend: &B,
    entry: &PendingMessage,
    policy: Option<&Value>,
    contacts: &std::collections::HashSet<String>,
) -> DispatchOutcome {
    // 1. Fetch encrypted body + unwrap content key.
    let content = match backend.fetch_message_content(&entry.id).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[auto-reply] fetch content failed for {}: {e}", entry.id);
            return DispatchOutcome::Error;
        }
    };
    if !is_a2a_content_type(content.content_type.as_deref()) {
        return DispatchOutcome::Skipped;
    }
    let content_key = match backend
        .daemon_unwrap_content_key(&content.encrypted_key)
        .await
    {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[auto-reply] unwrap failed for {}: {e}", entry.id);
            return DispatchOutcome::Error;
        }
    };
    let plaintext = match decrypt_envelope_text(&content.encrypted_content, &content_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[auto-reply] decrypt failed for {}: {e}", entry.id);
            return DispatchOutcome::Error;
        }
    };

    // 2. Parse the A2A block and decide the reply payload shape.
    let parsed = match parse_a2a_payload(&plaintext, Some(A2A_CONTENT_TYPE)) {
        Some(p) => p,
        None => return DispatchOutcome::Skipped,
    };
    let Some(protocol) = parsed.protocol.clone() else {
        return DispatchOutcome::Skipped;
    };

    // Phase 4.4c+B — re-evaluate with the protocol-aware client
    // evaluator. Mirrors Standard mode's merge so a `protocols.*` override
    // can upgrade a queued decision or downgrade an auto-accept one.
    let eval_ctx = EvaluationContext {
        master_auto_reply_enabled: true,
        priority: entry.priority.clone(),
        trust_score: entry.trust_score,
        sender_did: entry.sender_did.clone(),
        is_contact: contacts.contains(&entry.sender_did),
        protocol: Some(ProtocolKey {
            protocol_type: protocol.protocol_type.as_str(),
            action: protocol.action.clone(),
        }),
    };
    let client_decision = policy_evaluator::evaluate(policy, &eval_ctx);
    let final_decision =
        policy_evaluator::merge(entry.auto_reply_reason.as_deref(), client_decision);

    let action = match final_decision.action {
        EvalAction::AutoAccept => "accept",
        EvalAction::AutoDecline => "decline",
        _ => return DispatchOutcome::Skipped,
    };
    let Some((reply_block, _thread_hint)) = build_reply_block(&parsed, &protocol, action) else {
        return DispatchOutcome::Skipped;
    };

    // 3. Resolve recipient pubkey (sender of the original = recipient
    //    of our reply) and seal the outgoing envelope.
    let recipient = match backend.resolve_recipient(&entry.sender_did).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[auto-reply] resolve_recipient failed for {}: {e}",
                entry.id
            );
            return DispatchOutcome::Error;
        }
    };
    let out_body = serialize_outgoing_body("", reply_block);
    let out_content_key = generate_content_key();
    let encrypted_subject = match encrypt_envelope_text("Re: (auto-reply)", &out_content_key) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[auto-reply] encrypt subject failed: {e}");
            return DispatchOutcome::Error;
        }
    };
    let encrypted_body = match encrypt_envelope_text(&out_body, &out_content_key) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[auto-reply] encrypt body failed: {e}");
            return DispatchOutcome::Error;
        }
    };
    let wrapped_key = match backend
        .daemon_wrap_content_key(&recipient.encryption_public_key, &out_content_key)
        .await
    {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[auto-reply] wrap_content_key failed: {e}");
            return DispatchOutcome::Error;
        }
    };
    let payload_b64 = envelope_payload_b64(
        backend.our_did(),
        &recipient.did,
        &encrypted_subject.serialized,
        &encrypted_body.serialized,
        &wrapped_key,
        &encrypted_body.nonce_b64url,
    );
    let signature = match backend
        .daemon_sign_envelope(backend.our_did(), &recipient.did, &payload_b64)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[auto-reply] sign_envelope failed: {e}");
            return DispatchOutcome::Error;
        }
    };

    // 4. Build the `POST /messages` body (matches SendMessageRequest).
    let post_body = serde_json::json!({
        "sender_did": backend.our_did(),
        "recipient_did": recipient.did,
        "envelope": {
            "encrypted_content": encrypted_body.serialized,
            "encrypted_key": wrapped_key,
            "nonce": encrypted_body.nonce_b64url,
            "signature": signature,
            "metadata": {
                "subject_encrypted": encrypted_subject.serialized,
                "content_type": A2A_CONTENT_TYPE,
                "thread_id": entry.thread_id,
                "auto_reply_origin": AUTO_REPLY_ORIGIN_DAEMON,
            }
        }
    });
    let send_resp = match backend.post_reply(&post_body).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[auto-reply] POST /messages failed for {}: {e}", entry.id);
            return DispatchOutcome::Error;
        }
    };
    let reply_message_id = send_resp
        .get("message_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // 5. Flip the idempotency column so neither Standard mode nor a retry
    //    re-sends this reply.
    if let Err(e) = backend
        .mark_auto_reply_sent(&entry.id, reply_message_id.as_deref())
        .await
    {
        eprintln!(
            "[auto-reply] mark_auto_reply_sent failed for {}: {e}",
            entry.id
        );
        return DispatchOutcome::Error;
    }
    DispatchOutcome::Sent
}

/// Build the `protocol` block that goes into the outgoing A2A
/// envelope body. Returns the JSON plus the `thread_id` hint for
/// callers that want to carry it on the envelope metadata.
fn build_reply_block(
    _payload: &A2APayload,
    protocol: &A2AProtocolBlock,
    action: &str,
) -> Option<(Value, Option<String>)> {
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

    let reply_block = serde_json::json!({
        "id": new_uuid_like_id(),
        "type": protocol.protocol_type.as_str(),
        "action": action,
        "reply_to": protocol.id,
        "payload": payload_value,
    });
    Some((reply_block, None))
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

/// Envelope payload string the signer daemon signs over. Must match
/// `apps/web/lib/crypto/signature.ts#signEnvelopePayload` — sender,
/// recipient, subject, content, key, nonce concatenated with `|`.
fn envelope_payload_b64(
    sender_did: &str,
    recipient_did: &str,
    subject_encrypted: &str,
    encrypted_content: &str,
    encrypted_key: &str,
    nonce: &str,
) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let raw = format!(
        "{sender_did}|{recipient_did}|{subject_encrypted}|{encrypted_content}|{encrypted_key}|{nonce}"
    );
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockBackend {
        pending: Vec<PendingMessage>,
        content_by_id: std::collections::HashMap<String, MessageContent>,
        pubkey: RecipientPubkey,
        our_did: String,
        sent: Mutex<Vec<Value>>,
        marked: Mutex<Vec<String>>,
        // Seed: the inner content_key used by the fixture body —
        // matches what `daemon_unwrap_content_key` will return.
        content_key: String,
        policy: Option<Value>,
        contacts: Vec<String>,
    }

    #[async_trait::async_trait]
    impl ExecutorBackend for MockBackend {
        async fn fetch_pending_messages(&self) -> Result<Vec<PendingMessage>, String> {
            Ok(self.pending.clone())
        }

        async fn fetch_message_content(&self, id: &str) -> Result<MessageContent, String> {
            self.content_by_id
                .get(id)
                .cloned()
                .ok_or_else(|| "missing content".into())
        }

        async fn resolve_recipient(&self, _did: &str) -> Result<RecipientPubkey, String> {
            Ok(self.pubkey.clone())
        }

        async fn daemon_unwrap_content_key(&self, _ek: &str) -> Result<String, String> {
            Ok(self.content_key.clone())
        }

        async fn daemon_wrap_content_key(
            &self,
            _recipient_pub: &str,
            _content_key: &str,
        ) -> Result<String, String> {
            Ok("x25519v1:fake:wrapped:key:data".into())
        }

        async fn daemon_sign_envelope(
            &self,
            _sender: &str,
            _recipient: &str,
            _payload: &str,
        ) -> Result<String, String> {
            Ok("FAKE_SIGNATURE".into())
        }

        async fn post_reply(&self, body: &Value) -> Result<Value, String> {
            self.sent.lock().unwrap().push(body.clone());
            Ok(serde_json::json!({ "message_id": "reply-1" }))
        }

        async fn mark_auto_reply_sent(
            &self,
            message_id: &str,
            _reply_id: Option<&str>,
        ) -> Result<(), String> {
            self.marked.lock().unwrap().push(message_id.into());
            Ok(())
        }

        fn our_did(&self) -> &str {
            &self.our_did
        }

        async fn fetch_policy(&self) -> Result<Option<Value>, String> {
            Ok(self.policy.clone())
        }

        async fn fetch_contact_dids(&self) -> Result<Vec<String>, String> {
            Ok(self.contacts.clone())
        }
    }

    fn fixture_propose_body_encrypted(content_key: &str) -> String {
        let inner = serde_json::json!({
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
        .to_string();
        encrypt_envelope_text(&inner, content_key)
            .expect("encrypt")
            .serialized
    }

    fn make_backend() -> MockBackend {
        let content_key = generate_content_key();
        let encrypted = fixture_propose_body_encrypted(&content_key);
        let mut map = std::collections::HashMap::new();
        map.insert(
            "msg-1".into(),
            MessageContent {
                encrypted_content: encrypted,
                encrypted_key: "x25519v1:incoming:wrapped:key:data".into(),
                content_type: Some(A2A_CONTENT_TYPE.into()),
            },
        );
        MockBackend {
            pending: vec![PendingMessage {
                id: "msg-1".into(),
                sender_did: "did:key:zSender".into(),
                recipient_did: "did:key:zViewer".into(),
                thread_id: Some("thread-1".into()),
                decision: "auto_accept".into(),
                priority: "normal".into(),
                trust_score: 0.8,
                auto_reply_reason: Some("default_match".into()),
            }],
            content_by_id: map,
            pubkey: RecipientPubkey {
                did: "did:key:zSender".into(),
                encryption_public_key: "fake-pub-key".into(),
            },
            our_did: "did:key:zViewer".into(),
            sent: Mutex::new(Vec::new()),
            marked: Mutex::new(Vec::new()),
            content_key,
            policy: Some(serde_json::json!({
                "v": 1,
                "default_action": "auto_accept",
            })),
            contacts: Vec::new(),
        }
    }

    #[tokio::test]
    async fn run_one_tick_dispatches_schedule_accept() {
        let backend = make_backend();
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent, 1);
        assert_eq!(report.errors, 0);
        let sent = backend.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let envelope = &sent[0];
        assert_eq!(
            envelope["envelope"]["metadata"]["auto_reply_origin"].as_str(),
            Some(AUTO_REPLY_ORIGIN_DAEMON)
        );
        assert_eq!(
            envelope["envelope"]["metadata"]["content_type"].as_str(),
            Some(A2A_CONTENT_TYPE)
        );
        let marked = backend.marked.lock().unwrap();
        assert_eq!(marked.as_slice(), &["msg-1".to_string()]);
    }

    #[tokio::test]
    async fn run_one_tick_skips_non_a2a_content_type() {
        let mut backend = make_backend();
        if let Some(c) = backend.content_by_id.get_mut("msg-1") {
            c.content_type = Some("text/plain".into());
        }
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent, 0);
        assert_eq!(report.skipped, 1);
        assert!(backend.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_one_tick_skips_when_client_evaluator_returns_queue() {
        // Policy has no default_action → client evaluator returns
        // no_policy → final action is queue_for_human → executor
        // skips even though the server's cached decision was
        // "auto_accept". This exercises the protocol-aware merge
        // (Phase 4.4c+B) — the client evaluator has final say.
        let mut backend = make_backend();
        backend.policy = Some(serde_json::json!({}));
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent, 0);
        assert_eq!(report.skipped, 1);
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
        backend.policy = Some(serde_json::json!({
            "v": 1,
            "default_action": "queue_for_human",
            "protocols": {
                "schedule_negotiation": {
                    "propose": { "action": "auto_accept" }
                }
            }
        }));
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent, 1);
    }

    #[tokio::test]
    async fn master_off_from_server_blocks_send_even_with_policy() {
        // Cached reason=master_off — the merge rule keeps that sticky
        // even if the client-evaluated policy would auto_accept.
        let mut backend = make_backend();
        backend.pending[0].auto_reply_reason = Some("master_off".into());
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent, 0);
        assert_eq!(report.skipped, 1);
    }

    #[tokio::test]
    async fn contact_requirement_blocks_non_contact() {
        let mut backend = make_backend();
        backend.policy = Some(serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "require_contact": true }
        }));
        // Default contacts are empty, so require_contact blocks.
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent, 0);
        assert_eq!(report.skipped, 1);
    }

    #[tokio::test]
    async fn contact_requirement_passes_when_sender_is_in_contacts() {
        let mut backend = make_backend();
        backend.policy = Some(serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "require_contact": true }
        }));
        backend.contacts = vec!["did:key:zSender".into()];
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent, 1);
    }

    #[tokio::test]
    async fn run_one_tick_caps_at_max_per_tick() {
        let mut backend = make_backend();
        backend.pending = (0..(MAX_PER_TICK + 5))
            .map(|i| PendingMessage {
                id: format!("msg-{i}"),
                sender_did: "did:key:zSender".into(),
                recipient_did: "did:key:zViewer".into(),
                thread_id: None,
                decision: "auto_accept".into(),
                priority: "normal".into(),
                trust_score: 0.8,
                auto_reply_reason: Some("default_match".into()),
            })
            .collect();
        // Re-use the single fixture content for every id so fetch
        // doesn't 404.
        let template = backend.content_by_id.get("msg-1").cloned().unwrap();
        for i in 0..(MAX_PER_TICK + 5) {
            backend
                .content_by_id
                .insert(format!("msg-{i}"), template.clone());
        }
        let report = run_one_tick(&backend).await;
        assert_eq!(report.sent + report.skipped + report.errors, MAX_PER_TICK);
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
