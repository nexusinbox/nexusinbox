use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::fs;
use tower::util::ServiceExt;

mod common;

const VALID_SIGNING_PRIVATE_KEY_B64URL: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
const RECIPIENT_SIGNING_PRIVATE_KEY_B64URL: &str = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA";
const VALID_ENCRYPTION_KEY_B64URL: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU";
const VALID_WRAPPED_KEY: &str = "x25519v1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE:AgICAgICAgICAgICAgICAg:AwMDAwMDAwMDAwMD:Y2lwaGVydGV4dC12YWxpZC1wYXlsb2Fk";
const TEST_USER_ID: &str = "00000000-0000-0000-0000-000000000001";

fn auth_header() -> String {
    let token = common::issue_test_jwt(
        "00000000-0000-0000-0000-000000000001",
        "0xnullifier",
        "orb",
        60 * 60,
    );
    format!("Bearer {token}")
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn sign_envelope(
    signing_private_key: &str,
    sender_did: &str,
    recipient_did: &str,
    subject_encrypted: &str,
    encrypted_content: &str,
    encrypted_key: &str,
    nonce: &str,
) -> String {
    let payload = format!(
        "{sender_did}\n{recipient_did}\n{subject_encrypted}\n{encrypted_content}\n{encrypted_key}\n{nonce}"
    );
    let private_key_bytes = URL_SAFE_NO_PAD.decode(signing_private_key).unwrap();
    let private_key_array: [u8; 32] = private_key_bytes.as_slice().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&private_key_array);
    let signature = signing_key.sign(payload.as_bytes());
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

fn public_key_b64url_from_private(signing_private_key: &str) -> String {
    let private_key_bytes = URL_SAFE_NO_PAD.decode(signing_private_key).unwrap();
    let private_key_array: [u8; 32] = private_key_bytes.as_slice().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&private_key_array);
    URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())
}

async fn create_test_agent(app: &axum::Router) -> (String, String) {
    let sender_did =
        create_agent_with_key(app, "sender-agent", VALID_SIGNING_PRIVATE_KEY_B64URL).await;
    (sender_did, VALID_SIGNING_PRIVATE_KEY_B64URL.to_string())
}

async fn create_agent_with_identity(
    app: &axum::Router,
    label: &str,
    signing_private_key: &str,
) -> (String, String) {
    let public_key = public_key_b64url_from_private(signing_private_key);
    let create_payload = json!({
      "label": label,
      "public_key": public_key,
      "encryption_key": VALID_ENCRYPTION_KEY_B64URL
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response_json(response).await;
    (
        created["aid"].as_str().unwrap().to_string(),
        created["did"].as_str().unwrap().to_string(),
    )
}

async fn create_recipient_agent(app: &axum::Router) -> String {
    create_agent_with_key(app, "recipient-agent", RECIPIENT_SIGNING_PRIVATE_KEY_B64URL).await
}

async fn create_agent_with_key(
    app: &axum::Router,
    label: &str,
    signing_private_key: &str,
) -> String {
    let public_key = public_key_b64url_from_private(signing_private_key);
    let create_payload = json!({
      "label": label,
      "public_key": public_key,
      "encryption_key": VALID_ENCRYPTION_KEY_B64URL
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response_json(response).await;
    created["did"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn post_message_accepts_aid_recipient_and_resolves_to_current_did() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let (recipient_aid, recipient_did) = create_agent_with_identity(
        &app,
        "recipient-agent",
        RECIPIENT_SIGNING_PRIVATE_KEY_B64URL,
    )
    .await;
    let subject_encrypted = "base64-subject-aid";
    let encrypted_content = "base64-content-aid";
    let encrypted_key = VALID_WRAPPED_KEY;
    let nonce = "base64-nonce-aid";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_aid,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_aid}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);

    let list_json = response_json(list_response).await;
    let messages = list_json["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["recipient_did"], recipient_did);
}

#[tokio::test]
async fn resolve_recipient_returns_current_identity_for_aid_and_did() {
    let app = common::test_app();
    let (recipient_aid, recipient_did) = create_agent_with_identity(
        &app,
        "recipient-agent",
        RECIPIENT_SIGNING_PRIVATE_KEY_B64URL,
    )
    .await;

    let aid_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/recipients/resolve?identifier={recipient_aid}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(aid_response.status(), StatusCode::OK);
    let aid_json = response_json(aid_response).await;
    assert_eq!(aid_json["aid"], recipient_aid);
    assert_eq!(aid_json["did"], recipient_did);

    let did_response = app
        .oneshot(
            Request::builder()
                .uri(format!("/recipients/resolve?identifier={recipient_did}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(did_response.status(), StatusCode::OK);
    let did_json = response_json(did_response).await;
    assert_eq!(did_json["aid"], recipient_aid);
    assert_eq!(did_json["did"], recipient_did);
    assert_eq!(did_json["label"], "recipient-agent");
}

fn wrapped_key_for(seed: &str) -> String {
    let ephemeral = URL_SAFE_NO_PAD.encode(vec![1_u8; 32]);
    let salt = URL_SAFE_NO_PAD.encode(vec![2_u8; 16]);
    let iv = URL_SAFE_NO_PAD.encode(vec![3_u8; 12]);
    let ciphertext = URL_SAFE_NO_PAD.encode(format!("ciphertext-{seed}-payload").as_bytes());
    format!("x25519v1:{ephemeral}:{salt}:{iv}:{ciphertext}")
}

#[tokio::test]
async fn messages_requires_authorization() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/messages?agent_did=all")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_rate_limit_returns_too_many_requests() {
    let app = common::test_app();
    let mut limited = false;

    for _ in 0..320 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }

    assert!(limited, "expected to hit rate limit within 320 requests");
}

#[tokio::test]
async fn post_message_then_get_and_patch_status() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "base64-subject";
    let encrypted_content = "base64-content";
    let encrypted_key = VALID_WRAPPED_KEY;
    let nonce = "base64-nonce";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);

    let send_json = response_json(send_response).await;
    let message_id = send_json["message_id"].as_str().unwrap().to_string();
    assert_eq!(send_json["status"], "delivered");

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);

    let list_json = response_json(list_response).await;
    let messages = list_json["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["id"], message_id);
    assert_eq!(messages[0]["status"], "unread");
    assert!(messages[0].get("encrypted_content").is_none());
    assert!(messages[0].get("encrypted_key").is_none());
    assert!(messages[0].get("nonce").is_none());
    // SECURITY: storage_ref must never be exposed in API responses — it leaks
    // backend type (localfs/gdrive) and internal locator. Clients fetch content
    // via GET /messages/{id}/content using only the public message id.
    assert!(messages[0].get("storage_ref").is_none());
    let _ = message_id;

    let patch_payload = json!({ "status": "read" });
    let patch_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/messages/{message_id}"))
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(patch_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patch_response.status(), StatusCode::OK);
    let patch_json = response_json(patch_response).await;
    assert_eq!(patch_json["status"], "read");

    let content_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages/{message_id}/content"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content_response.status(), StatusCode::OK);

    let content_json = response_json(content_response).await;
    assert_eq!(content_json["encrypted_content"], "base64-content");
    assert_eq!(content_json["encrypted_key"], VALID_WRAPPED_KEY);
    assert_eq!(content_json["nonce"], "base64-nonce");
}

#[tokio::test]
async fn message_content_returns_error_without_fallback_when_storage_file_missing() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "base64-subject";
    let encrypted_content = "base64-content";
    let encrypted_key = VALID_WRAPPED_KEY;
    let nonce = "base64-nonce";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let send_json = response_json(send_response).await;
    let message_id = send_json["message_id"].as_str().unwrap().to_string();

    let storage_path = std::env::temp_dir()
        .join("nexusinbox-localfs")
        .join("localfs")
        .join(TEST_USER_ID)
        .join(format!("{message_id}.json"));
    let _ = fs::remove_file(storage_path);

    let content_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages/{message_id}/content"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content_response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let error_json = response_json(content_response).await;
    assert_eq!(error_json["error"], "storage_error");
    assert!(error_json.get("encrypted_content").is_none());
    assert!(error_json.get("encrypted_key").is_none());
    assert!(error_json.get("nonce").is_none());
}

#[tokio::test]
async fn messages_rejects_oversized_payload() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "base64-subject";
    let big_content = "a".repeat(70 * 1024);
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        &big_content,
        VALID_WRAPPED_KEY,
        "base64-nonce",
    );
    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": big_content,
        "encrypted_key": VALID_WRAPPED_KEY,
        "nonce": "base64-nonce",
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn send_message_rejects_replayed_nonce() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "subject-replay";
    let encrypted_content = "content-replay";
    let encrypted_key = wrapped_key_for("replay");
    let nonce = "nonce-replay";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    let second = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error_json = response_json(second).await;
    assert_eq!(error_json["error"], "validation_error");
}

#[tokio::test]
async fn messages_validation_and_not_found() {
    let app = common::test_app();

    let invalid_send = json!({
      "sender_did": "did:key:sender123"
    });
    let invalid_send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(invalid_send.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        invalid_send_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let invalid_patch = json!({ "status": "invalid_status" });
    let invalid_patch_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/messages/00000000-0000-0000-0000-000000000000")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(invalid_patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        invalid_patch_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let missing_patch = json!({ "status": "read" });
    let missing_patch_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/messages/00000000-0000-0000-0000-000000000000")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(missing_patch.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_patch_response.status(), StatusCode::NOT_FOUND);

    let missing_content_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/messages/00000000-0000-0000-0000-000000000000/content")
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_content_response.status(), StatusCode::NOT_FOUND);

    let unauthorized_content_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/messages/00000000-0000-0000-0000-000000000000/content")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        unauthorized_content_response.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn messages_list_supports_filters_and_pagination() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;

    for i in 0..3 {
        let subject_encrypted = format!("subject-{i}");
        let encrypted_content = format!("content-{i}");
        let encrypted_key = wrapped_key_for(&format!("list-{i}"));
        let nonce = format!("nonce-{i}");
        let signature = sign_envelope(
            &signing_key,
            &sender_did,
            &recipient_did,
            &subject_encrypted,
            &encrypted_content,
            &encrypted_key,
            &nonce,
        );
        let send_payload = json!({
          "sender_did": sender_did,
          "recipient_did": recipient_did,
          "envelope": {
            "encrypted_content": encrypted_content,
            "encrypted_key": encrypted_key,
            "nonce": nonce,
            "signature": signature,
            "metadata": {
              "subject_encrypted": subject_encrypted,
              "thread_id": null,
              "content_type": "text/markdown",
              "has_attachments": false
            }
          }
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/messages")
                    .header("authorization", auth_header())
                    .header("content-type", "application/json")
                    .body(Body::from(send_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/messages?agent_did={recipient_did}&per_page=2&page=1&status=unread&priority=normal"
                ))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_json = response_json(list_response).await;
    assert_eq!(list_json["messages"].as_array().unwrap().len(), 2);
    assert_eq!(list_json["total"], 3);
    assert_eq!(list_json["page"], 1);
    assert_eq!(list_json["per_page"], 2);

    let page2_response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/messages?agent_did={recipient_did}&per_page=2&page=2"
                ))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page2_response.status(), StatusCode::OK);
    let page2_json = response_json(page2_response).await;
    assert_eq!(page2_json["messages"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn google_drive_mock_backend_persists_and_reads_content() {
    let app = nexusinbox_api::app_with_storage_backend("gdrive_mock");
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "gdrive-subject";
    let encrypted_content = "gdrive-content";
    let encrypted_key = wrapped_key_for("gdrive");
    let nonce = "gdrive-nonce";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let send_json = response_json(send_response).await;
    let message_id = send_json["message_id"].as_str().unwrap().to_string();

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_json = response_json(list_response).await;
    // SECURITY: storage_ref must not be exposed in the API response.
    assert!(list_json["messages"][0].get("storage_ref").is_none());

    let content_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages/{message_id}/content"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content_response.status(), StatusCode::OK);
    let content_json = response_json(content_response).await;
    assert_eq!(content_json["encrypted_content"], "gdrive-content");
}

#[tokio::test]
async fn gdrive_backend_requires_oauth_configuration() {
    let app = nexusinbox_api::app_with_storage_backend("gdrive");
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "alias-subject";
    let encrypted_content = "alias-content";
    let encrypted_key = wrapped_key_for("alias");
    let nonce = "alias-nonce";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let error_json = response_json(send_response).await;
    assert_eq!(error_json["error"], "storage_error");
    assert!(error_json["message"]
        .as_str()
        .unwrap_or_default()
        .contains("Google Drive"));
}

#[tokio::test]
async fn send_message_returns_not_found_when_recipient_missing() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    let subject_encrypted = "subject";
    let encrypted_content = "content";
    let encrypted_key = wrapped_key_for("missing");
    let nonce = "nonce-missing";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );
    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn send_message_returns_not_found_when_recipient_blocked_by_policy() {
    let setup_app = common::test_app();
    let recipient_did = create_recipient_agent(&setup_app).await;
    let app = nexusinbox_api::app_with_policy_dids(&[&recipient_did], &[]);
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;

    let subject_encrypted = "subject";
    let encrypted_content = "content";
    let encrypted_key = wrapped_key_for("blocked");
    let nonce = "nonce-blocked";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );
    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn send_message_marks_low_trust_sender_as_pending_approval() {
    let setup_app = common::test_app();
    let (sender_did, _signing_key) = create_test_agent(&setup_app).await;
    let app = nexusinbox_api::app_with_policy_dids(&[], &[&sender_did]);
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;

    let subject_encrypted = "subject";
    let encrypted_content = "content";
    let encrypted_key = wrapped_key_for("low-trust");
    let nonce = "nonce-low-trust";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );
    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = response_json(response).await;
    assert_eq!(json["status"], "pending_approval");
}

#[tokio::test]
async fn send_message_rejects_unowned_sender_did() {
    let app = common::test_app();
    let recipient_did = create_recipient_agent(&app).await;
    let send_payload = json!({
      "sender_did": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": "content",
        "encrypted_key": VALID_WRAPPED_KEY,
        "nonce": "nonce",
        "signature": "sig",
        "metadata": {
          "subject_encrypted": "subject",
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn send_message_rejects_invalid_signature() {
    let app = common::test_app();
    let (sender_did, _signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": "content",
        "encrypted_key": VALID_WRAPPED_KEY,
        "nonce": "nonce",
        "signature": "invalid-signature",
        "metadata": {
          "subject_encrypted": "subject",
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn send_message_rejects_non_x25519_wrapped_key_format() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "subject";
    let encrypted_content = "content";
    let encrypted_key = "ckb64:legacy";
    let nonce = "nonce";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn delete_message_removes_index_and_content() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "base64-subject";
    let encrypted_content = "base64-content";
    let encrypted_key = VALID_WRAPPED_KEY;
    let nonce = "base64-nonce";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        &encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let send_json = response_json(send_response).await;
    let message_id = send_json["message_id"].as_str().unwrap().to_string();

    let storage_path = std::env::temp_dir()
        .join("nexusinbox-localfs")
        .join("localfs")
        .join(TEST_USER_ID)
        .join(format!("{message_id}.json"));
    assert!(
        storage_path.exists(),
        "storage file should exist before delete"
    );

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/messages/{message_id}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    assert!(
        !storage_path.exists(),
        "storage file should be removed after delete"
    );

    let content_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages/{message_id}/content"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content_response.status(), StatusCode::NOT_FOUND);

    let second_delete = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/messages/{message_id}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_delete.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn send_message_rejects_malformed_x25519_wrapped_key_format() {
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;
    let subject_encrypted = "subject";
    let encrypted_content = "content";
    // iv part is intentionally too short (11 bytes decoded) to trigger strict format rejection.
    let encrypted_key = "x25519v1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE:AgICAgICAgICAgICAgICAg:AwMDAwMDAwMDAw:Y2lwaGVydGV4dC12YWxpZC1wYXlsb2Fk";
    let nonce = "nonce";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": "text/markdown",
          "has_attachments": false
        }
      }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// A2A protocol (docs/24) — content_type round-trip through BYOS
// ---------------------------------------------------------------------------
//
// The A2A dispatch in the Web UI relies on `GET /messages/:id/content`
// echoing back the sender's `envelope.metadata.content_type`. Before
// the A2A work the server was discarding that field; regressing to
// the old behaviour would silently turn every A2A message into a
// plain-text render on the recipient side (dangerous: the structured
// UI goes away, and legacy JSON starts showing up as raw body).

#[tokio::test]
async fn post_message_roundtrips_a2a_content_type_through_byos() {
    const A2A_MIME: &str = "application/vnd.nexusinbox.a2a+json; v=1";

    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;

    let subject_encrypted = "base64-subject-a2a";
    let encrypted_content = "base64-content-a2a";
    let encrypted_key = VALID_WRAPPED_KEY;
    let nonce = "base64-nonce-a2a";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "content_type": A2A_MIME,
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let send_json = response_json(send_response).await;
    let message_id = send_json["message_id"].as_str().unwrap().to_string();

    let content_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages/{message_id}/content"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content_response.status(), StatusCode::OK);
    let content_json = response_json(content_response).await;
    assert_eq!(
        content_json["content_type"], A2A_MIME,
        "A2A MIME must round-trip verbatim so the Web UI can dispatch on it",
    );
    assert_eq!(content_json["encrypted_content"], encrypted_content);
    assert_eq!(content_json["encrypted_key"], encrypted_key);
}

#[tokio::test]
async fn post_message_omits_content_type_from_response_when_sender_omitted_it() {
    // Backward-compat guard: BYOS blobs written before the A2A work
    // won't carry content_type. StoredMessageContent uses
    // #[serde(default)] so those deserialise with None; the response
    // must then omit the field entirely (skip_serializing_if) so
    // older web clients that don't read it still see a clean shape.
    let app = common::test_app();
    let (sender_did, signing_key) = create_test_agent(&app).await;
    let recipient_did = create_recipient_agent(&app).await;

    let subject_encrypted = "base64-subject-plain";
    let encrypted_content = "base64-content-plain";
    let encrypted_key = VALID_WRAPPED_KEY;
    let nonce = "base64-nonce-plain";
    let signature = sign_envelope(
        &signing_key,
        &sender_did,
        &recipient_did,
        subject_encrypted,
        encrypted_content,
        encrypted_key,
        nonce,
    );

    let send_payload = json!({
      "sender_did": sender_did,
      "recipient_did": recipient_did,
      "envelope": {
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature": signature,
        "metadata": {
          "subject_encrypted": subject_encrypted,
          "thread_id": null,
          "has_attachments": false
        }
      }
    });

    let send_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth_header())
                .header("content-type", "application/json")
                .body(Body::from(send_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let send_json = response_json(send_response).await;
    let message_id = send_json["message_id"].as_str().unwrap().to_string();

    let content_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages/{message_id}/content"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content_response.status(), StatusCode::OK);
    let content_json = response_json(content_response).await;
    assert!(
        content_json.get("content_type").is_none(),
        "response must omit content_type when sender didn't set it (backward-compat)",
    );
}
