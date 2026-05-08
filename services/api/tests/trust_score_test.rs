use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::util::ServiceExt;

mod common;

const SENDER_PRIV: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
const RECIPIENT_PRIV: &str = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA";
const ENC_KEY: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU";
const WRAPPED_KEY: &str = "x25519v1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE:AgICAgICAgICAgICAgICAg:AwMDAwMDAwMDAwMD:Y2lwaGVydGV4dC12YWxpZC1wYXlsb2Fk";

const SENDER_USER: &str = "00000000-0000-0000-0000-0000000000aa";
const SENDER_WID: &str = "0xsender-trust";
fn auth(sub: &str, wid: &str, level: &str) -> String {
    let token = common::issue_test_jwt(sub, wid, level, 60 * 60);
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

async fn create_agent(
    app: &axum::Router,
    sub: &str,
    wid: &str,
    level: &str,
    label: &str,
    priv_b64url: &str,
) -> String {
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
                .header("authorization", auth(sub, wid, level))
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

async fn send(
    app: &axum::Router,
    sub: &str,
    wid: &str,
    level: &str,
    sender_did: &str,
    recipient_did: &str,
    nonce: &str,
) -> Value {
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
                .header("authorization", auth(sub, wid, level))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    body_json(response).await
}

async fn list_messages(
    app: &axum::Router,
    sub: &str,
    wid: &str,
    level: &str,
    recipient_did: &str,
) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth(sub, wid, level))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

#[tokio::test]
async fn orb_sender_receives_normal_priority_at_baseline() {
    // Same user owns both endpoints (in-memory store is keyed by sender's user_id).
    let app = common::test_app();
    let sender_did =
        create_agent(&app, SENDER_USER, SENDER_WID, "orb", "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        SENDER_USER,
        SENDER_WID,
        "orb",
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    let send_body = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        "orb",
        &sender_did,
        &recipient_did,
        "n-orb",
    )
    .await;
    assert_eq!(send_body["status"], "delivered");

    let listed = list_messages(&app, SENDER_USER, SENDER_WID, "orb", &recipient_did).await;
    let messages = listed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["priority"], "normal");
    let score = messages[0]["trust_score"].as_f64().unwrap();
    assert!(
        (score - 0.80).abs() < 1e-3,
        "expected baseline orb score 0.80, got {score}"
    );
}

#[tokio::test]
async fn non_orb_sender_receives_no_level_bonus() {
    // The service only accepts Orb verification at login, but the trust
    // scorer still has to be well-defined for legacy / unexpected values.
    // Confirm that any non-orb level contributes no verification bonus,
    // so the score falls back to the 0.40 baseline (delivered).
    let app = common::test_app();
    let sender_did = create_agent(
        &app,
        SENDER_USER,
        SENDER_WID,
        "device",
        "sender",
        SENDER_PRIV,
    )
    .await;
    let recipient_did = create_agent(
        &app,
        SENDER_USER,
        SENDER_WID,
        "device",
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    let _ = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        "device",
        &sender_did,
        &recipient_did,
        "n-device",
    )
    .await;
    let listed = list_messages(&app, SENDER_USER, SENDER_WID, "device", &recipient_did).await;
    let messages = listed["messages"].as_array().unwrap();
    let score = messages[0]["trust_score"].as_f64().unwrap();
    assert!(
        (score - 0.40).abs() < 1e-3,
        "expected non-orb baseline score 0.40, got {score}"
    );
    assert_eq!(messages[0]["priority"], "normal");
}

#[tokio::test]
async fn blocks_against_sender_lower_trust_score() {
    let app = common::test_app();
    let sender_did =
        create_agent(&app, SENDER_USER, SENDER_WID, "orb", "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        SENDER_USER,
        SENDER_WID,
        "orb",
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    // Two independent third-party owners install L2 identity bans against the sender's wid.
    // Each block subtracts 0.15 → expected score = 0.80 - 0.30 = 0.50.
    for i in 0..2_u8 {
        let owner_sub = format!("00000000-0000-0000-0000-0000000000{:02x}", 0xc0 + i);
        let owner_wid = format!("0xowner-{i}");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/blocks")
                    .header("authorization", auth(&owner_sub, &owner_wid, "orb"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "level": "l2_identity", "target_world_id": SENDER_WID })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let _ = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        "orb",
        &sender_did,
        &recipient_did,
        "n-blocked",
    )
    .await;
    let listed = list_messages(&app, SENDER_USER, SENDER_WID, "orb", &recipient_did).await;
    let messages = listed["messages"].as_array().unwrap();
    let score = messages[0]["trust_score"].as_f64().unwrap();
    assert!(
        (score - 0.50).abs() < 1e-3,
        "expected score 0.50 after 2 blocks, got {score}"
    );
    assert_eq!(messages[0]["priority"], "normal");
}

#[tokio::test]
async fn unverified_sender_routes_to_pending_approval() {
    // A non-orb verification_level yields no level bonus (the service only
    // accepts Orb at login, so any other value here is legacy/unexpected)
    // and therefore starts at baseline 0.40. Walk the send threshold:
    //   - 1 L2 block against the sender: 0.40 - 0.15 = 0.25 → still delivered
    //   - 2 L2 blocks:                   0.40 - 0.30 = 0.10 → pending_approval
    let app = common::test_app();
    let sender_did =
        create_agent(&app, SENDER_USER, SENDER_WID, "orb", "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        SENDER_USER,
        SENDER_WID,
        "orb",
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    let add_block = |suffix: u8| {
        let app = app.clone();
        async move {
            let owner_sub = format!("00000000-0000-0000-0000-0000000000{:02x}", 0xd0 + suffix);
            let owner_wid = format!("0xowner-low-{suffix}");
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/blocks")
                        .header("authorization", auth(&owner_sub, &owner_wid, "orb"))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({ "level": "l2_identity", "target_world_id": SENDER_WID })
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }
    };

    add_block(0).await;

    // 0.40 - 0.15 = 0.25, above the 0.20 pending threshold → delivered.
    let body = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        "device",
        &sender_did,
        &recipient_did,
        "n-low",
    )
    .await;
    assert_eq!(body["status"], "delivered");

    add_block(1).await;

    // 0.40 - 0.30 = 0.10, below threshold → routed to pending_approval.
    let body2 = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        "device",
        &sender_did,
        &recipient_did,
        "n-low2",
    )
    .await;
    assert_eq!(body2["status"], "pending_approval");

    let listed = list_messages(&app, SENDER_USER, SENDER_WID, "orb", &recipient_did).await;
    let messages = listed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    // In-memory list returns insertion order, so the second send is at index 1.
    let last = &messages[1];
    assert_eq!(last["priority"], "background");
    let score = last["trust_score"].as_f64().unwrap();
    assert!(score < 0.20, "expected score < 0.20, got {score}");
}
