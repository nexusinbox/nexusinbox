use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use serial_test::serial;
use tower::util::ServiceExt;
use uuid::Uuid;

mod common;

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
#[serial]
async fn auth_verify_returns_500_when_database_required_but_url_missing() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
        std::env::remove_var("DATABASE_URL");
        std::env::set_var("AGENT_INBOX_WORLD_VERIFY_ENABLED", "false");
        std::env::set_var("AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK", "true");
    }

    let app = common::test_app();
    let payload = serde_json::json!({
      "proof": "0xproof-db-required",
      "merkle_root": "0xroot-db-required",
      "nullifier_hash": "0xnullifier-db-required",
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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "server_error");
    assert_eq!(payload["message"], "database is required but unavailable");
}

#[tokio::test]
#[serial]
async fn list_agents_returns_500_when_database_required_but_url_missing() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
        std::env::remove_var("DATABASE_URL");
        std::env::set_var("AGENT_INBOX_ALLOW_DEV_BEARER", "true");
    }

    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header(
                    "authorization",
                    "Bearer dev-user-00000000-0000-0000-0000-000000000001",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "server_error");
    assert_eq!(payload["message"], "database is required but unavailable");
}

#[tokio::test]
#[serial]
async fn list_messages_returns_500_when_database_required_but_url_missing() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
        std::env::remove_var("DATABASE_URL");
        std::env::set_var("AGENT_INBOX_ALLOW_DEV_BEARER", "true");
    }

    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/messages?agent_did=all")
                .header(
                    "authorization",
                    "Bearer dev-user-00000000-0000-0000-0000-000000000001",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "server_error");
    assert_eq!(payload["message"], "database is required but unavailable");
}

#[tokio::test]
#[serial]
async fn send_message_returns_500_when_database_required_but_url_missing() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
        std::env::remove_var("DATABASE_URL");
        std::env::set_var("AGENT_INBOX_ALLOW_DEV_BEARER", "true");
    }

    let app = common::test_app();
    let payload = serde_json::json!({
      "sender_did": "did:key:z6MkhqDemo001",
      "recipient_did": "did:key:z6MkhqDemo002",
      "envelope": {
        "encrypted_content": "ZW5jcnlwdGVk",
        "encrypted_key": "x25519:ZmFrZWtleQ",
        "nonce": "nonce-demo",
        "signature": "c2lnbmF0dXJl",
        "metadata": {
          "subject_encrypted": "c3ViamVjdA",
          "content_type": "text/plain",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    "Bearer dev-user-00000000-0000-0000-0000-000000000001",
                )
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "server_error");
    assert_eq!(payload["message"], "database is required but unavailable");
}

#[tokio::test]
#[serial]
async fn message_content_returns_500_when_database_required_but_url_missing() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
        std::env::remove_var("DATABASE_URL");
        std::env::set_var("AGENT_INBOX_ALLOW_DEV_BEARER", "true");
    }

    let app = common::test_app();
    let message_id = Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/messages/{message_id}/content"))
                .header(
                    "authorization",
                    "Bearer dev-user-00000000-0000-0000-0000-000000000001",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "server_error");
    assert_eq!(payload["message"], "database is required but unavailable");
}

#[tokio::test]
#[serial]
async fn update_message_status_returns_500_when_database_required_but_url_missing() {
    // SAFETY: this test is serialized to avoid concurrent env mutations.
    unsafe {
        std::env::set_var("NODE_ENV", "development");
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
        std::env::remove_var("DATABASE_URL");
        std::env::set_var("AGENT_INBOX_ALLOW_DEV_BEARER", "true");
    }

    let app = common::test_app();
    let message_id = Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/messages/{message_id}"))
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    "Bearer dev-user-00000000-0000-0000-0000-000000000001",
                )
                .body(Body::from(
                    serde_json::json!({ "status": "read" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "server_error");
    assert_eq!(payload["message"], "database is required but unavailable");
}
