use std::sync::Once;

static INIT: Once = Once::new();

fn ensure_test_env() {
    INIT.call_once(|| {
        // SAFETY: integration tests initialize this once at startup and set a fixed value.
        unsafe {
            std::env::set_var("JWT_SECRET", "nexusinbox-test-jwt-secret-0123456789abcdef");
            // Disable CSRF Origin check in integration tests (tests drive the router
            // directly without a browser). This env var is refused in production by
            // validate_runtime_config.
            std::env::set_var("AGENT_INBOX_DISABLE_CSRF_CHECK", "true");
        }
    });
}

pub fn test_app() -> axum::Router {
    ensure_test_env();
    nexusinbox_api::app()
}

#[allow(dead_code)]
pub fn test_app_with_mock_world_verify() -> axum::Router {
    ensure_test_env();
    // SAFETY: integration tests require explicit mock-mode opt-in when World verify is disabled.
    unsafe {
        std::env::set_var("AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK", "true");
    }
    nexusinbox_api::app()
}

#[allow(dead_code)]
pub fn issue_test_jwt(sub: &str, wid: &str, verification_level: &str, ttl_seconds: i64) -> String {
    ensure_test_env();
    nexusinbox_api::issue_dev_jwt(sub, wid, verification_level, ttl_seconds)
}

/// Sign a `POST /messages` body with envelope signature v2 (docs/40 §14.2),
/// replacing a v1 `signature` if it has one: the API takes v2 only since
/// stage 5 (§15.2). The agents are looked up with `GET /recipients/resolve`
/// as `auth`; a recipient that cannot be resolved (blocked, unknown) is
/// signed as given, and the send is refused before the signature matters.
#[allow(dead_code)]
pub async fn sign_body_v2(
    app: &axum::Router,
    auth: &str,
    key: &ed25519_dalek::SigningKey,
    body: &mut serde_json::Value,
) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Signer as _;
    use nexusinbox_api::envelope_v2;
    use serde_json::{json, Value};

    async fn resolve(app: &axum::Router, auth: &str, identifier: &str) -> Option<(String, String)> {
        use http_body_util::BodyExt as _;
        use tower::util::ServiceExt as _;
        let uri = format!(
            "/recipients/resolve?identifier={}",
            identifier.replace(':', "%3A")
        );
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(uri)
                    .header("authorization", auth)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let bytes = response.into_body().collect().await.ok()?.to_bytes();
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        Some((
            v["aid"].as_str()?.to_string(),
            v["did"].as_str()?.to_string(),
        ))
    }

    let sender_did = body["sender_did"].as_str().unwrap_or_default().to_string();
    let recipient_ref = body["recipient_did"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let sender_aid = resolve(app, auth, &sender_did)
        .await
        .map(|(aid, _)| aid)
        .unwrap_or_else(|| "aid:ai:unknown".into());
    let (recipient_aid, recipient_did) = resolve(app, auth, &recipient_ref)
        .await
        .unwrap_or_else(|| ("aid:ai:unknown".into(), recipient_ref.clone()));

    let envelope = body["envelope"].as_object_mut().expect("envelope");
    envelope.remove("signature");
    if envelope
        .get("metadata")
        .and_then(|m| m.get("content_type"))
        .and_then(Value::as_str)
        .is_none()
    {
        envelope
            .entry("metadata")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .unwrap()
            .insert("content_type".into(), json!("text/plain"));
    }
    let envelope = Value::Object(envelope.clone());
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let wraps = |v: &Value| -> Vec<(String, String)> {
        v.as_array()
            .into_iter()
            .flatten()
            .map(|w| (s(&w["did"]), s(&w["key"])))
            .collect()
    };
    let encrypted_keys = wraps(&envelope["encrypted_keys"]);
    let sender_encrypted_keys = wraps(&envelope["sender_encrypted_keys"]);
    let attachments: Vec<(String, String, String)> = body["attachments"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            (
                s(&a["attachment_id"]),
                s(&a["metadata_encrypted"]),
                s(&a["metadata_nonce"]),
            )
        })
        .collect();
    let sent_at = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let metadata = &envelope["metadata"];
    let thread_id = metadata["thread_id"].as_str().map(str::to_string);
    let fields = envelope_v2::Fields {
        sender_aid: &sender_aid,
        sender_did: &sender_did,
        recipient_aid: &recipient_aid,
        recipient_did: &recipient_did,
        sent_at: &sent_at,
        content_type: metadata["content_type"].as_str().unwrap_or("text/plain"),
        thread_id: thread_id.as_deref(),
        subject_encrypted: metadata["subject_encrypted"].as_str().unwrap_or_default(),
        encrypted_content: envelope["encrypted_content"].as_str().unwrap_or_default(),
        encrypted_key: envelope["encrypted_key"].as_str().unwrap_or_default(),
        nonce: envelope["nonce"].as_str().unwrap_or_default(),
        sender_encrypted_key: envelope["sender_encrypted_key"].as_str(),
        encrypted_keys: encrypted_keys
            .iter()
            .map(|(did, key)| envelope_v2::Wrap { did, key })
            .collect(),
        sender_encrypted_keys: sender_encrypted_keys
            .iter()
            .map(|(did, key)| envelope_v2::Wrap { did, key })
            .collect(),
        attachments: attachments
            .iter()
            .map(
                |(id, metadata_encrypted, metadata_nonce)| envelope_v2::Attachment {
                    id,
                    metadata_encrypted,
                    metadata_nonce,
                },
            )
            .collect(),
    };
    let signature = URL_SAFE_NO_PAD.encode(
        key.sign(envelope_v2::signing_input(&fields).as_bytes())
            .to_bytes(),
    );
    let mut envelope = envelope;
    envelope["signature_v2"] = json!({
        "signature": signature,
        "sent_at": sent_at,
        "sender_aid": sender_aid,
        "recipient_aid": recipient_aid,
    });
    body["envelope"] = envelope;
}
