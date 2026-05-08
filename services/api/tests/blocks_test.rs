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
const SENDER_WID: &str = "0xsender-wid";
const RECIPIENT_USER: &str = "00000000-0000-0000-0000-0000000000bb";
const RECIPIENT_WID: &str = "0xrecipient-wid";

fn auth(sub: &str, wid: &str) -> String {
    let token = common::issue_test_jwt(sub, wid, "orb", 60 * 60);
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
                .header("authorization", auth(sub, wid))
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
    sender_did: &str,
    recipient_did: &str,
    sender_priv: &str,
    nonce: &str,
) -> axum::response::Response {
    let subject = "subj";
    let content = "body";
    let signing_payload =
        format!("{sender_did}\n{recipient_did}\n{subject}\n{content}\n{WRAPPED_KEY}\n{nonce}");
    let signature = sign_envelope(sender_priv, &signing_payload);
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
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", auth(sub, wid))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn create_block(
    app: &axum::Router,
    sub: &str,
    wid: &str,
    body: Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/blocks")
                .header("authorization", auth(sub, wid))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn create_block_validates_level_and_target() {
    let app = common::test_app();
    let bad_level =
        create_block(&app, RECIPIENT_USER, RECIPIENT_WID, json!({ "level": "x" })).await;
    assert_eq!(bad_level.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let l1_missing = create_block(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        json!({ "level": "l1_did" }),
    )
    .await;
    assert_eq!(l1_missing.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let l2_missing = create_block(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        json!({ "level": "l2_identity" }),
    )
    .await;
    assert_eq!(l2_missing.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn l1_block_silently_drops_message() {
    let app = common::test_app();
    let sender_did = create_agent(&app, SENDER_USER, SENDER_WID, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    // Recipient owner installs an L1 block against the sender DID.
    let block_response = create_block(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        json!({ "level": "l1_did", "target_did": sender_did }),
    )
    .await;
    assert_eq!(block_response.status(), StatusCode::CREATED);

    // Sender attempts to deliver — must look like success but never persist.
    let send_response = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-l1",
    )
    .await;
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let body = body_json(send_response).await;
    assert_eq!(body["status"], "delivered");

    // Recipient inbox must be empty (silent drop).
    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth(RECIPIENT_USER, RECIPIENT_WID))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let listed = body_json(list_response).await;
    assert_eq!(listed["messages"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn l2_identity_ban_returns_not_found() {
    let app = common::test_app();
    let sender_did = create_agent(&app, SENDER_USER, SENDER_WID, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    let block_response = create_block(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        json!({ "level": "l2_identity", "target_world_id": SENDER_WID }),
    )
    .await;
    assert_eq!(block_response.status(), StatusCode::CREATED);

    let send_response = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-l2",
    )
    .await;
    assert_eq!(send_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn l3_stealth_returns_not_found_and_persists_nothing() {
    let app = common::test_app();
    let sender_did = create_agent(&app, SENDER_USER, SENDER_WID, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    let block_response = create_block(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        json!({ "level": "l3_stealth", "target_world_id": SENDER_WID }),
    )
    .await;
    assert_eq!(block_response.status(), StatusCode::CREATED);

    let send_response = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-l3",
    )
    .await;
    assert_eq!(send_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_block_unblocks_sender() {
    let app = common::test_app();
    let sender_did = create_agent(&app, SENDER_USER, SENDER_WID, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    let create_response = create_block(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        json!({ "level": "l2_identity", "target_world_id": SENDER_WID }),
    )
    .await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let block_id = body_json(create_response).await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let blocked = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-d1",
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::NOT_FOUND);

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/blocks/{block_id}"))
                .header("authorization", auth(RECIPIENT_USER, RECIPIENT_WID))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let allowed = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-d2",
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn list_blocks_is_scoped_per_user() {
    let app = common::test_app();
    let _ = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;
    let other_user = "00000000-0000-0000-0000-0000000000cc";
    let other_wid = "0xother";

    let _ = create_block(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        json!({ "level": "l2_identity", "target_world_id": SENDER_WID }),
    )
    .await;

    let list_other = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/blocks")
                .header("authorization", auth(other_user, other_wid))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_other.status(), StatusCode::OK);
    let other_body = body_json(list_other).await;
    assert_eq!(other_body["blocks"].as_array().unwrap().len(), 0);

    let list_owner = app
        .oneshot(
            Request::builder()
                .uri("/blocks")
                .header("authorization", auth(RECIPIENT_USER, RECIPIENT_WID))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_owner.status(), StatusCode::OK);
    let owner_body = body_json(list_owner).await;
    assert_eq!(owner_body["blocks"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------
// /blocks/from-message/:message_id — UI-driven "Block sender" flow.
// The hermetic suite runs in-memory mode, so only the validation
// and L1 happy-path branches are reachable here. The L2/L3
// world_id_hash-resolution happy path needs DB and lives in
// blocks_db_integration_test.rs.
// ---------------------------------------------------------------

async fn post_block_from_message(
    app: &axum::Router,
    sub: &str,
    wid: &str,
    message_id: &str,
    body: Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/blocks/from-message/{message_id}"))
                .header("authorization", auth(sub, wid))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn block_from_message_rejects_unknown_level() {
    let app = common::test_app();
    // Use any uuid — level validation runs before message lookup.
    let resp = post_block_from_message(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "00000000-0000-0000-0000-000000000001",
        json!({ "level": "bogus" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn block_from_message_returns_404_for_unknown_message() {
    let app = common::test_app();
    let resp = post_block_from_message(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "00000000-0000-0000-0000-000000000001",
        json!({ "level": "l1_did" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn block_from_message_requires_authentication() {
    let app = common::test_app();
    // No Authorization header — must 401 before touching the
    // message store.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/blocks/from-message/00000000-0000-0000-0000-000000000001")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "level": "l1_did" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn block_from_message_l1_blocks_sender_without_ui_typing_the_did() {
    // The whole point of this endpoint: the UI calls it with only
    // a message_id, and the server pulls sender_did off the
    // recipient-owned row. No DID / World ID typing required.
    let app = common::test_app();
    let sender_did = create_agent(&app, SENDER_USER, SENDER_WID, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;

    // Deliver one message so the recipient actually has a row to
    // block-from.
    let send_response = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-bfm-1",
    )
    .await;
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);

    // Fetch the recipient's inbox to discover the message_id. The
    // UI does this same lookup implicitly — the "Block sender"
    // button is attached to a rendered row.
    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth(RECIPIENT_USER, RECIPIENT_WID))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = body_json(list_response).await;
    let message_id = listed["messages"][0]["id"].as_str().unwrap().to_string();

    let resp = post_block_from_message(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        &message_id,
        json!({ "level": "l1_did" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["level"], "l1_did");
    assert_eq!(body["target_did"].as_str().unwrap(), sender_did);
    assert!(body["target_world_id"].is_null());
}

#[tokio::test]
async fn block_from_message_rejects_cross_user_message_id() {
    // Another user's message_id must be rejected as 404, not
    // 500/403 — this endpoint must not confirm existence of a
    // message the caller didn't receive.
    let app = common::test_app();
    let sender_did = create_agent(&app, SENDER_USER, SENDER_WID, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;
    let send_response = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-bfm-x",
    )
    .await;
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth(RECIPIENT_USER, RECIPIENT_WID))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = body_json(list_response).await;
    let message_id = listed["messages"][0]["id"].as_str().unwrap().to_string();

    // Attacker (different user) tries to block a correspondent
    // they never heard from.
    let other_user = "00000000-0000-0000-0000-0000000000cc";
    let other_wid = "0xother";
    let resp = post_block_from_message(
        &app,
        other_user,
        other_wid,
        &message_id,
        json!({ "level": "l1_did" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn block_from_message_l2_requires_db_for_world_id_resolution() {
    // In hermetic (no-DB) mode we can't resolve sender_did →
    // world_id_hash, so the endpoint must explicitly refuse L2/L3
    // rather than inserting a block with a null target.
    let app = common::test_app();
    let sender_did = create_agent(&app, SENDER_USER, SENDER_WID, "sender", SENDER_PRIV).await;
    let recipient_did = create_agent(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        "recipient",
        RECIPIENT_PRIV,
    )
    .await;
    let send_response = send(
        &app,
        SENDER_USER,
        SENDER_WID,
        &sender_did,
        &recipient_did,
        SENDER_PRIV,
        "n-bfm-l2",
    )
    .await;
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={recipient_did}"))
                .header("authorization", auth(RECIPIENT_USER, RECIPIENT_WID))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = body_json(list_response).await;
    let message_id = listed["messages"][0]["id"].as_str().unwrap().to_string();

    let resp = post_block_from_message(
        &app,
        RECIPIENT_USER,
        RECIPIENT_WID,
        &message_id,
        json!({ "level": "l2_identity" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "sender_not_registered");
}
