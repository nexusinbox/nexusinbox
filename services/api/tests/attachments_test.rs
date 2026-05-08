//! Hermetic tests for the attachment API surface.
//!
//! These cover authentication, input validation, scope, and the "database
//! required" error path so the integration failure modes don't regress. Tests
//! that need an actual S3/R2 backend (full intent → PUT → complete flow) live
//! in `scripts/test_attachment_flow.mjs` because they require MinIO/R2 to be
//! reachable.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::util::ServiceExt;

mod common;

const TEST_USER_ID: &str = "00000000-0000-0000-0000-000000000001";
const TEST_MESSAGE_ID: &str = "11111111-1111-4111-8111-111111111111";
const TEST_ATTACHMENT_ID: &str = "22222222-2222-4222-8222-222222222222";

fn auth_header() -> String {
    let token = common::issue_test_jwt(TEST_USER_ID, "0xattach-test", "orb", 60 * 60);
    format!("Bearer {token}")
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// POST /attachments/intents
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_attachment_intent_requires_authorization() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attachments/intents")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "ciphertext_size_bytes": 1024 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_attachment_intent_rejects_missing_size() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attachments/intents")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    // Without DB configured the API short-circuits with 500
    // ("database required but unavailable"); with DB the validation runs.
    // Either way it must NOT be 200/201.
    assert!(
        response.status().is_client_error()
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "expected non-success status, got {}",
        response.status()
    );
}

#[tokio::test]
async fn post_attachment_intent_rejects_zero_size() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attachments/intents")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "ciphertext_size_bytes": 0 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert_eq!(body["error"].as_str().unwrap_or(""), "validation_error");
}

#[tokio::test]
async fn post_attachment_intent_rejects_oversize_request() {
    let app = common::test_app();
    // 100 MiB — well above the 5 MiB per-file cap.
    let too_big = 100 * 1024 * 1024;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/attachments/intents")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "ciphertext_size_bytes": too_big }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert_eq!(body["error"].as_str().unwrap_or(""), "validation_error");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or("")
            .contains("ciphertext_size_bytes"),
        "validation message should name the offending field"
    );
}

// ---------------------------------------------------------------------------
// POST /attachments/{id}/complete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_attachment_complete_requires_authorization() {
    let app = common::test_app();
    let uri = format!("/attachments/{TEST_ATTACHMENT_ID}/complete");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "ciphertext_size_bytes": 1024 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_attachment_complete_rejects_missing_size() {
    let app = common::test_app();
    let uri = format!("/attachments/{TEST_ATTACHMENT_ID}/complete");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    // With DB required this returns 422 from the validation_error branch;
    // without DB it falls through to the database_required 500.
    assert!(
        response.status() == StatusCode::UNPROCESSABLE_ENTITY
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "got unexpected status {}",
        response.status()
    );
}

// ---------------------------------------------------------------------------
// GET /messages/{id}/attachments
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_message_attachments_requires_authorization() {
    let app = common::test_app();
    let uri = format!("/messages/{TEST_MESSAGE_ID}/attachments");
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// POST /messages/{id}/attachments/{attachmentId}/download
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attachment_download_url_requires_authorization() {
    let app = common::test_app();
    let uri = format!("/messages/{TEST_MESSAGE_ID}/attachments/{TEST_ATTACHMENT_ID}/download");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn attachment_download_url_404_for_unknown_message() {
    let app = common::test_app();
    let uri = format!("/messages/{TEST_MESSAGE_ID}/attachments/{TEST_ATTACHMENT_ID}/download");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    // The authenticated user owns no messages, so message lookup must fail.
    // With DB: 404. Without DB: 500 (database_required).
    assert!(
        response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "got unexpected status {}",
        response.status()
    );
}

// ---------------------------------------------------------------------------
// DELETE /attachments/{id}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_attachment_requires_authorization() {
    let app = common::test_app();
    let uri = format!("/attachments/{TEST_ATTACHMENT_ID}");
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_attachment_404_for_unknown_id() {
    let app = common::test_app();
    let uri = format!("/attachments/{TEST_ATTACHMENT_ID}");
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // With DB: 404 (row not found). Without DB: 500 (database_required).
    assert!(
        response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "got unexpected status {}",
        response.status()
    );
}

// ---------------------------------------------------------------------------
// Authorization: ensure the endpoints don't leak to other users.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attachment_endpoints_reject_bad_jwt() {
    let app = common::test_app();
    let bad_token = "Bearer not-a-real-jwt";

    let endpoints: &[(&str, &str, Option<&str>)] = &[
        ("POST", "/attachments/intents", Some(r#"{"ciphertext_size_bytes":1024}"#)),
        (
            "POST",
            "/attachments/22222222-2222-4222-8222-222222222222/complete",
            Some(r#"{"ciphertext_size_bytes":1024}"#),
        ),
        ("DELETE", "/attachments/22222222-2222-4222-8222-222222222222", None),
        (
            "GET",
            "/messages/11111111-1111-4111-8111-111111111111/attachments",
            None,
        ),
        (
            "POST",
            "/messages/11111111-1111-4111-8111-111111111111/attachments/22222222-2222-4222-8222-222222222222/download",
            Some("{}"),
        ),
    ];

    for (method, uri, body) in endpoints {
        let mut builder = Request::builder()
            .method(*method)
            .uri(*uri)
            .header("authorization", bad_token);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let response = app
            .clone()
            .oneshot(
                builder
                    .body(
                        body.map(|b| Body::from(b.to_string()))
                            .unwrap_or_else(Body::empty),
                    )
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "endpoint {} {} accepted a malformed JWT",
            method,
            uri
        );
    }
}
