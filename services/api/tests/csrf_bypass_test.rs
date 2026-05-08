use axum::body::Body;
use axum::http::{Request, StatusCode};
use serial_test::serial;
use tower::util::ServiceExt;

mod common;

/// Build the app then enable CSRF enforcement.
fn setup_app_with_csrf_enabled() -> axum::Router {
    let app = common::test_app();
    unsafe {
        std::env::set_var("AGENT_INBOX_DISABLE_CSRF_CHECK", "false");
    }
    app
}

fn restore_csrf_bypass() {
    unsafe {
        std::env::set_var("AGENT_INBOX_DISABLE_CSRF_CHECK", "true");
    }
}

#[tokio::test]
#[serial]
async fn csrf_bypass_agent_auth_token_endpoint() {
    let app = setup_app_with_csrf_enabled();
    // POST to /agent-auth/token without Origin should NOT be blocked by CSRF
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/token")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"credential_id":"test","assertion":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should NOT be 403 (CSRF). Will fail with 401/422 for bad assertion, which is fine.
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_bypass_agent_auth_refresh_endpoint() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"refresh_token":"agr_test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_bypass_agent_auth_revoke_endpoint() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/revoke")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_bypass_bearer_agt_token() {
    let app = setup_app_with_csrf_enabled();
    // POST to a Cookie-auth endpoint with Bearer agt_ should bypass CSRF
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("content-type", "application/json")
                .header("authorization", "Bearer agt_test_token_value")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should NOT be 403 (CSRF). Will fail with 401 for invalid token.
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_bypass_dpop_agt_token() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("content-type", "application/json")
                .header("authorization", "DPoP agt_test_token_value")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_still_blocks_cookie_post_without_origin() {
    let app = setup_app_with_csrf_enabled();
    // POST to a Cookie-auth endpoint WITHOUT Bearer agt_ and WITHOUT Origin
    // should still be blocked by CSRF
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}
