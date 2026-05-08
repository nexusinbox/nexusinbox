//! Phase 3c.3 audit forwarder — ships bridge lifecycle events from
//! the daemon's stderr sink to the API's `/agent-audit-log/bridge`
//! endpoint so `/settings/audit` (Phase 3c.4) has central
//! observability instead of only local log files.
//!
//! Wire format (docs/22 §8 Phase 3c):
//!
//!   * Each event is wrapped in a fresh JWS signed by the daemon's
//!     Ed25519 signing key — the same key registered at
//!     `/agent-credentials/:id/activate`. No access-token cache, no
//!     DPoP: the JWS is itself the auth, scoped via `aud` to the
//!     ingest endpoint and kept fresh via a ±60 s `iat` window.
//!
//!   * Delivery is fire-and-forget: on failure we log to stderr and
//!     move on. The daemon's default stderr audit sink is always
//!     installed too, so data loss here means "central dashboard
//!     missed one row" — never "audit trail disappears".
//!
//! The module is self-contained: a bounded mpsc channel absorbs
//! events from the sync audit hook, and a spawned Tokio task drains
//! the channel with `reqwest`. Back-pressure: if the channel is
//! full the sender drops the event and logs a warning rather than
//! blocking the handler — the hot path (`handle_unwrap`) must never
//! stall behind network.
//!
//! Forwarding is opt-in via `--bridge-forward-audit`; the existing
//! stderr path keeps working unchanged when disabled.
//!
//! See also:
//!   * `src/bridge.rs` — emits the events
//!   * `services/api/src/lib.rs` `ingest_bridge_audit_event` — server side

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc;

use crate::bridge::BridgeAuditEvent;

/// Spawned background worker configuration.
pub struct ForwarderConfig {
    /// Full `https://api.nexusinbox.ai` (no trailing slash). The
    /// worker appends the endpoint path before POSTing.
    pub api_base_url: String,
    pub aid: String,
    pub credential_id: String,
    pub signing_key: SigningKey,
}

/// Start the forwarder task and return a sender the audit sink can
/// stuff events into. The channel is bounded so a runaway audit
/// storm can't grow memory unbounded; when it's full we drop
/// events and log a stderr warning.
pub fn spawn(config: ForwarderConfig) -> mpsc::Sender<BridgeAuditEvent> {
    // 256 slots is comfortable for bursty request patterns while
    // staying tiny in RAM. If the endpoint is down for more than
    // that many events we accept data loss — stderr stream is the
    // source of truth.
    let (tx, mut rx) = mpsc::channel::<BridgeAuditEvent>(256);
    tokio::spawn(async move {
        // One client for the lifetime of the worker — reqwest
        // reuses its connection pool across requests. 2 s per-call
        // timeout so a hung API can't stall the queue indefinitely.
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[WARN] bridge-audit forwarder: cannot build HTTP client: {e}");
                return;
            }
        };
        let endpoint = format!(
            "{}/agent-audit-log/bridge",
            config.api_base_url.trim_end_matches('/')
        );

        while let Some(event) = rx.recv().await {
            let jws = sign_bridge_audit_jws(&config, &endpoint, &event);
            let body = serde_json::json!({ "jws": jws });
            match client.post(&endpoint).json(&body).send().await {
                Ok(response) if response.status().is_success() => {
                    // Happy path is silent — stderr already carries
                    // the event line via the default sink, no need
                    // for double-logging here.
                }
                Ok(response) => {
                    let status = response.status();
                    let body_text = response.text().await.unwrap_or_default();
                    eprintln!(
                        "[WARN] bridge-audit forwarder: API returned {status}: {}",
                        body_text.chars().take(240).collect::<String>()
                    );
                }
                Err(e) => {
                    eprintln!("[WARN] bridge-audit forwarder: POST failed: {e}");
                }
            }
        }
    });
    tx
}

/// Build the `{header}.{payload}.{sig}` JWS that wraps one audit
/// event. Payload layout matches the verifier in
/// `ingest_bridge_audit_event`:
///
/// ```text
/// {
///   "iss": "<aid>",
///   "sub": "<credential_id>",
///   "aud": "<endpoint url>",
///   "iat": <unix seconds>,
///   "jti": "<uuid>",
///   "bridge_event": { ...event fields... }
/// }
/// ```
fn sign_bridge_audit_jws(
    config: &ForwarderConfig,
    endpoint: &str,
    event: &BridgeAuditEvent,
) -> String {
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT" });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

    // Serialize-then-parse so the nested JSON round-trips through
    // the same shape the server will see. `serde_json::to_value`
    // would work too but this is a closer match to the ingest
    // endpoint's `claims.get("bridge_event")` read.
    let event_json: JsonValue = serde_json::to_value(event).unwrap_or(JsonValue::Null);

    let now = Utc::now().timestamp();
    let payload = serde_json::json!({
        "iss": config.aid,
        "sub": config.credential_id,
        "aud": endpoint,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
        "bridge_event": event_json,
    });
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = config.signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::OsRng;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn make_event() -> BridgeAuditEvent {
        BridgeAuditEvent {
            timestamp: "2026-04-22T00:00:00.000Z".into(),
            source: "signer-daemon-bridge",
            event: "bridged_decrypt",
            outcome: "ok",
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            did: "did:key:zTest".into(),
            origin: "https://app.nexusinbox.ai".into(),
            encrypted_key_hash: Some("deadbeef".into()),
            error_message: None,
        }
    }

    #[test]
    fn jws_is_three_parts_with_ed25519_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let config = ForwarderConfig {
            api_base_url: "https://api.example.test".into(),
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            signing_key,
        };
        let event = make_event();
        let jws = sign_bridge_audit_jws(
            &config,
            "https://api.example.test/agent-audit-log/bridge",
            &event,
        );
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Signature verifies against the signing input.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[test]
    fn jws_payload_carries_expected_claims() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let config = ForwarderConfig {
            api_base_url: "https://api.example.test".into(),
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            signing_key,
        };
        let event = make_event();
        let jws = sign_bridge_audit_jws(
            &config,
            "https://api.example.test/agent-audit-log/bridge",
            &event,
        );
        let parts: Vec<&str> = jws.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: JsonValue = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(claims["iss"], "aid:ai:01TEST");
        assert_eq!(claims["sub"], "cred-test");
        assert_eq!(
            claims["aud"],
            "https://api.example.test/agent-audit-log/bridge"
        );
        assert!(claims["iat"].is_i64());
        assert!(claims["jti"].as_str().unwrap().len() > 8);
        assert_eq!(claims["bridge_event"]["event"], "bridged_decrypt");
        assert_eq!(claims["bridge_event"]["outcome"], "ok");
    }
}
