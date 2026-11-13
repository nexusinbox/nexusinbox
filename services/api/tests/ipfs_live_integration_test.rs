//! Live IPFS integration test against a local Kubo node.
//!
//! Gated behind `AGENT_INBOX_IPFS_LIVE_TESTS=1`. Exercises the IPFS adapter by
//! sending a message (→ /api/v0/add), reading its content (→ /api/v0/cat), and
//! deleting it (→ /api/v0/pin/rm).
//!
//! Usage:
//!   docker-compose up -d ipfs
//!   AGENT_INBOX_IPFS_LIVE_TESTS=1 \
//!     AGENT_INBOX_IPFS_API_URL=http://127.0.0.1:5001 \
//!     cargo test --test ipfs_live_integration_test

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http_body_util::BodyExt;
use serde_json::json;
use tower::util::ServiceExt;

mod common;

fn live_tests_enabled() -> bool {
    std::env::var("AGENT_INBOX_IPFS_LIVE_TESTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "missing required env var `{name}` for IPFS live test. Example:\n\
             AGENT_INBOX_IPFS_LIVE_TESTS=1 \\\n\
             AGENT_INBOX_IPFS_API_URL=http://127.0.0.1:5001 \\\n\
             cargo test --manifest-path services/api/Cargo.toml --test ipfs_live_integration_test -- --nocapture"
        )
    })
}

#[tokio::test]
async fn ipfs_send_receive_delete_roundtrip_against_kubo() {
    if !live_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_IPFS_LIVE_TESTS=1 to run IPFS live tests");
        return;
    }

    let ipfs_api_url = required_env("AGENT_INBOX_IPFS_API_URL");
    let _ = common::test_app(); // initializes JWT_SECRET
    let app = nexusinbox_api::app_with_storage_backend("ipfs");

    let user_id = uuid::Uuid::new_v4();
    let token = common::issue_test_jwt(&user_id.to_string(), "0xlive-ipfs", "orb", 60 * 60);
    let auth = format!("Bearer {token}");
    // The agent's signing key: sends carry envelope signature v2 (docs/40 §15.2).
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);

    // Register an agent.
    let create_agent = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "label": "ipfs-live",
                        "public_key": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                        "encryption_key": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_agent.status(), StatusCode::CREATED);
    let created: serde_json::Value =
        serde_json::from_slice(&create_agent.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let agent_did = created["did"].as_str().unwrap().to_string();

    // Send a message; the adapter PUTs to /api/v0/add and stores the CID.
    let mut envelope = json!({
        "sender_did": agent_did,
        "recipient_did": agent_did,
        "envelope": {
            "encrypted_content": "aXBmcy1jaXBoZXI=",
            "encrypted_key": "x25519v1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE:AgICAgICAgICAgICAgICAg:AwMDAwMDAwMDAwMD:Y2lwaGVydGV4dC12YWxpZC1wYXlsb2Fk",
            "nonce": "aXBmcy1ub25jZQ==",
            "metadata": {
                "subject_encrypted": "aXBmcy1zdWJq",
                "content_type": "text/plain",
                "has_attachments": false
            }
        }
    });
    common::sign_body_v2(&app, &auth, &signing_key, &mut envelope).await;
    let send = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(envelope.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        send.status(),
        StatusCode::ACCEPTED,
        "expected 202 ACCEPTED; if this fails, confirm the local Kubo node is \
         running and AGENT_INBOX_IPFS_API_URL=`{ipfs_api_url}` points to it \
         (for example `docker-compose up -d ipfs`)."
    );
    let send_body: serde_json::Value =
        serde_json::from_slice(&send.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let message_id = send_body["message_id"].as_str().unwrap().to_string();

    // Read it back.
    let read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages/{message_id}/content"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    let read_body: serde_json::Value =
        serde_json::from_slice(&read.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(read_body["encrypted_content"], "aXBmcy1jaXBoZXI=");

    // Delete (unpin).
    let del = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/messages/{message_id}"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::NO_CONTENT);
}
