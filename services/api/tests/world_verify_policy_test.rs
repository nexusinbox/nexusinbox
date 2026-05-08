use axum::body::Body;
use axum::http::{Request, StatusCode};
use serial_test::serial;
use tower::util::ServiceExt;

mod common;

#[tokio::test]
#[serial]
async fn auth_verify_rejects_mock_mode_in_production() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "production");
        std::env::set_var("AGENT_INBOX_WORLD_VERIFY_ENABLED", "false");
        std::env::remove_var("AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK");
    }

    let app = common::test_app();
    let payload = serde_json::json!({
      "proof": "0xproof-prod",
      "merkle_root": "0xroot-prod",
      "nullifier_hash": "0xnullifier-prod",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .header("origin", "https://app.nexusinbox.ai")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
#[serial]
async fn auth_verify_rejects_mock_mode_by_default_in_non_production() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("AGENT_INBOX_WORLD_VERIFY_ENABLED", "false");
        std::env::remove_var("AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK");
    }

    let app = common::test_app();
    let payload = serde_json::json!({
      "proof": "0xproof-dev-default",
      "merkle_root": "0xroot-dev-default",
      "nullifier_hash": "0xnullifier-dev-default",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
