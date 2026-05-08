use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

mod common;

#[tokio::test]
async fn auth_verify_requires_world_id_app_id_when_world_verify_enabled() {
    let world_verify_enabled = std::env::var("AGENT_INBOX_WORLD_VERIFY_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !world_verify_enabled {
        return;
    }

    let app = common::test_app();
    let payload = serde_json::json!({
      "proof": "0xproof-world-ci",
      "merkle_root": "0xroot-world-ci",
      "nullifier_hash": "0xnullifier-world-ci",
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
