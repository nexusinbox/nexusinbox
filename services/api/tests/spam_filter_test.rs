use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
use tower::util::ServiceExt;

mod common;

const SENDER_PRIV: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
const RECIPIENT_PRIV: &str = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA";
const ENC_KEY: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU";
const WRAPPED_KEY: &str = "x25519v1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE:AgICAgICAgICAgICAgICAg:AwMDAwMDAwMDAwMD:Y2lwaGVydGV4dC12YWxpZC1wYXlsb2Fk";

const USER: &str = "00000000-0000-0000-0000-0000000000aa";
const WID: &str = "0xspam-test";

fn auth() -> String {
    let token = common::issue_test_jwt(USER, WID, "orb", 60 * 60);
    format!("Bearer {token}")
}

fn pubkey_of(priv_b64url: &str) -> String {
    let bytes = URL_SAFE_NO_PAD.decode(priv_b64url).unwrap();
    let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
    URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&arr).verifying_key().to_bytes())
}

fn sign_envelope(priv_b64url: &str, payload: &str) -> String {
    let bytes = URL_SAFE_NO_PAD.decode(priv_b64url).unwrap();
    let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
    URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&arr)
            .sign(payload.as_bytes())
            .to_bytes(),
    )
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn create_agent(app: &axum::Router, label: &str, priv_b64url: &str) -> String {
    let payload = json!({
        "label": label,
        "public_key": pubkey_of(priv_b64url),
        "encryption_key": ENC_KEY,
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("authorization", auth())
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    body_json(response).await["did"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn send(app: &axum::Router, sender_did: &str, recipient_did: &str, nonce: &str) -> Value {
    let subject = "subj";
    let content = "body";
    let signing_payload =
        format!("{sender_did}\n{recipient_did}\n{subject}\n{content}\n{WRAPPED_KEY}\n{nonce}");
    let signature = sign_envelope(SENDER_PRIV, &signing_payload);
    let payload = json!({
        "sender_did": sender_did,
        "recipient_did": recipient_did,
        "envelope": {
            "encrypted_content": content,
            "encrypted_key": WRAPPED_KEY,
            "nonce": nonce,
            "signature": signature,
            "metadata": {
                "subject_encrypted": subject,
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
                .header("authorization", auth())
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    body_json(response).await
}

async fn list(app: &axum::Router, recipient_did: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

#[tokio::test]
#[serial]
async fn spam_denylist_routes_to_pending_approval() {
    // Derive what the sender's DID will be so we can install it in the env
    // deny-list before the app reads the env at construction time.
    let sender_pub = pubkey_of(SENDER_PRIV);
    let probe_app = common::test_app();
    // Create the agent on a throwaway app to discover its did:key string.
    let sender_did = {
        let payload = json!({
            "label": "probe",
            "public_key": sender_pub,
            "encryption_key": ENC_KEY,
        });
        let response = probe_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/agents")
                    .header("authorization", auth())
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        body_json(response).await["did"]
            .as_str()
            .unwrap()
            .to_string()
    };

    // SAFETY: integration tests mutate process env; serial guards against races.
    unsafe {
        std::env::set_var("AGENT_INBOX_SPAM_SENDER_DIDS", &sender_did);
    }
    let app = common::test_app();
    let _ = create_agent(&app, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(&app, "recipient", RECIPIENT_PRIV).await;

    let body = send(&app, &sender_did, &recipient_did, "n-spam-deny").await;
    assert_eq!(body["status"], "pending_approval");

    let listed = list(&app, &recipient_did).await;
    let messages = listed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["priority"], "background");
    assert_eq!(messages[0]["ai_category"], "spam_denylist");

    unsafe {
        std::env::remove_var("AGENT_INBOX_SPAM_SENDER_DIDS");
    }
}

#[tokio::test]
#[serial]
async fn burst_threshold_flags_subsequent_sends_as_spam() {
    unsafe {
        std::env::remove_var("AGENT_INBOX_SPAM_SENDER_DIDS");
    }
    let app = common::test_app();
    let sender_did = create_agent(&app, "burst-sender", SENDER_PRIV).await;
    let recipient_did = create_agent(&app, "burst-recipient", RECIPIENT_PRIV).await;

    // Threshold = 10. The first 10 sends are clean; the 11th gets flagged.
    for i in 0..10_u32 {
        let body = send(&app, &sender_did, &recipient_did, &format!("burst-{i}")).await;
        assert_eq!(body["status"], "delivered", "send {i} should be delivered");
    }
    let flagged = send(&app, &sender_did, &recipient_did, "burst-overflow").await;
    assert_eq!(flagged["status"], "pending_approval");

    let listed = list(&app, &recipient_did).await;
    let messages = listed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 11);
    let last = &messages[10];
    assert_eq!(last["priority"], "background");
    assert_eq!(last["ai_category"], "spam_burst");
}

#[tokio::test]
#[serial]
async fn clean_send_carries_no_ai_category() {
    unsafe {
        std::env::remove_var("AGENT_INBOX_SPAM_SENDER_DIDS");
    }
    let app = common::test_app();
    let sender_did = create_agent(&app, "clean-sender", SENDER_PRIV).await;
    let recipient_did = create_agent(&app, "clean-recipient", RECIPIENT_PRIV).await;

    let body = send(&app, &sender_did, &recipient_did, "clean-1").await;
    assert_eq!(body["status"], "delivered");

    let listed = list(&app, &recipient_did).await;
    let messages = listed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert!(messages[0]["ai_category"].is_null());
}
