use axum::body::Body;
use axum::http::{Request, StatusCode};
use serial_test::serial;
use tower::util::ServiceExt;

mod common;

/// Build the app first (so ensure_test_env runs), then disable the bypass.
/// SAFETY: serialized via #[serial] to avoid concurrent env mutation.
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
async fn csrf_rejects_post_without_origin_or_referer() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_rejects_post_with_foreign_origin() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .header("origin", "https://evil.example.com")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_rejects_post_with_foreign_referer() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .header("referer", "https://evil.example.com/page")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_allows_post_with_trusted_origin() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .header("origin", "http://localhost:3100")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // The request passes CSRF check (not 403); it will fail with 422 for empty payload.
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    restore_csrf_bypass();
}

#[tokio::test]
#[serial]
async fn csrf_allows_post_with_trusted_referer() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .header("referer", "http://localhost:3100/login")
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
async fn csrf_allows_get_without_origin() {
    let app = setup_app_with_csrf_enabled();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    restore_csrf_bypass();
}
