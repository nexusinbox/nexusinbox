//! HTTP integration tests for POST /admin/purge/run.
//!
//! These run fully in-memory (no Postgres) and verify the admin-token guard
//! plus the 503 responses when the engine is disabled. The in-memory message
//! store is always empty in a freshly built app so we only assert the summary
//! shape for the success case; the purge decision logic is covered by unit
//! tests in lib.rs.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use serial_test::serial;
use tower::util::ServiceExt;

mod common;

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn clear_purge_env() {
    // SAFETY: integration tests reset this env between cases.
    unsafe {
        std::env::remove_var("AGENT_INBOX_ADMIN_TOKEN");
        std::env::remove_var("AGENT_INBOX_AUTO_PURGE_ENABLED");
    }
}

fn set_admin_token(value: &str) {
    unsafe {
        std::env::set_var("AGENT_INBOX_ADMIN_TOKEN", value);
    }
}

fn set_purge_enabled(value: &str) {
    unsafe {
        std::env::set_var("AGENT_INBOX_AUTO_PURGE_ENABLED", value);
    }
}

#[tokio::test]
#[serial]
async fn admin_purge_run_returns_503_when_token_unset() {
    clear_purge_env();
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/purge/run")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["error"], "admin_disabled");
}

#[tokio::test]
#[serial]
async fn admin_purge_run_returns_401_on_wrong_token() {
    clear_purge_env();
    set_admin_token("correct-secret");
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/purge/run")
                .header("x-admin-token", "wrong-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["error"], "unauthorized");
}

#[tokio::test]
#[serial]
async fn admin_purge_run_returns_503_when_engine_disabled_even_with_valid_token() {
    clear_purge_env();
    set_admin_token("correct-secret");
    // AGENT_INBOX_AUTO_PURGE_ENABLED intentionally unset
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/purge/run")
                .header("x-admin-token", "correct-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["error"], "auto_purge_disabled");
}

#[tokio::test]
#[serial]
async fn admin_purge_run_returns_summary_when_enabled() {
    clear_purge_env();
    set_admin_token("correct-secret");
    set_purge_enabled("true");
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/purge/run")
                .header("x-admin-token", "correct-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let summary = &body["summary"];
    // Fresh app: no messages to scan.
    assert_eq!(summary["scanned"].as_u64().unwrap(), 0);
    assert_eq!(summary["deleted"].as_u64().unwrap(), 0);
    assert_eq!(summary["tombstoned"].as_u64().unwrap(), 0);
    assert_eq!(summary["errors"].as_u64().unwrap(), 0);

    clear_purge_env();
}
