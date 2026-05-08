//! Hermetic tests for `POST /agent-audit-log/bridge` — the Phase
//! 3c.3 endpoint that accepts signer-daemon bridge-lifecycle audit
//! events. No DB required: every assertion here hits 400 / 422
//! before the handler even looks at the credential table, so the
//! tests verify the shape-level guards alone. Full positive-path
//! verification (credential lookup + signature verify + row
//! inserted) lives in the DB integration suite behind
//! `AGENT_INBOX_DB_TESTS=1`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::util::ServiceExt;

mod common;

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

async fn post_bridge_audit(body: Value) -> axum::response::Response {
    let app = common::test_app();
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/agent-audit-log/bridge")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn bridge_audit_rejects_non_json_body() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-audit-log/bridge")
                .header("Content-Type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        !response.status().is_success(),
        "expected error, got {}",
        response.status()
    );
}

#[tokio::test]
async fn bridge_audit_rejects_missing_jws_field() {
    let response = post_bridge_audit(json!({ "foo": "bar" })).await;
    assert!(!response.status().is_success());
}

#[tokio::test]
async fn bridge_audit_rejects_non_three_part_jws() {
    let response = post_bridge_audit(json!({ "jws": "not-a-valid-jws" })).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn bridge_audit_rejects_malformed_payload_base64() {
    // Three parts separated by dots, but the payload segment won't
    // decode as base64url.
    let response = post_bridge_audit(json!({
        "jws": "aGVhZGVy.@@@BADBASE@@@.c2ln",
    }))
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert!(
        body.get("error").is_some(),
        "expected error envelope, got {body:?}"
    );
}

#[tokio::test]
async fn bridge_audit_rejects_payload_without_sub() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let header = URL_SAFE_NO_PAD.encode(json!({"alg": "EdDSA", "typ": "JWT"}).to_string());
    let payload = URL_SAFE_NO_PAD.encode(json!({"iss": "aid:ai:x"}).to_string());
    let sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let jws = format!("{header}.{payload}.{sig}");

    let response = post_bridge_audit(json!({ "jws": jws })).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("sub"),
        "expected message to mention missing sub, got {message:?}"
    );
}

#[tokio::test]
async fn bridge_audit_rejects_payload_with_non_uuid_sub() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let header = URL_SAFE_NO_PAD.encode(json!({"alg": "EdDSA", "typ": "JWT"}).to_string());
    let payload = URL_SAFE_NO_PAD.encode(json!({"iss": "aid:ai:x", "sub": "not-uuid"}).to_string());
    let sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let jws = format!("{header}.{payload}.{sig}");

    let response = post_bridge_audit(json!({ "jws": jws })).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
