//! DB-mode integration tests for AI drafts that wait for the person's
//! approval (docs/33 §8, §9): review keys, creating a draft with an agent
//! token, listing, approving (sending) and discarding with the session.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test agent_drafts_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use tower::util::ServiceExt;
use uuid::Uuid;

mod common;

fn db_tests_enabled() -> bool {
    std::env::var("AGENT_INBOX_DB_TESTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

async fn db_pool() -> PgPool {
    let url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB integration tests");
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("failed to connect to Postgres")
}

async fn reset_schema(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE TABLE agent_audit_log, agent_tokens, agent_credentials, message_attachments, \
         attachment_uploads, blocks, message_index, sessions, replay_nonces, \
         agent_identity_keys, agent_identities, agents, users RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .expect("failed to truncate schema");
}

async fn seed_user(pool: &PgPool, user_id: Uuid, world_id: &str, level: &str) {
    sqlx::query(
        "INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(world_id)
    .bind(world_id)
    .bind(level)
    .execute(pool)
    .await
    .expect("failed to seed user");
}

async fn seed_session(pool: &PgPool, user_id: Uuid, wid: &str, level: &str) -> String {
    let (token, jwt_id, exp) =
        nexusinbox_api::issue_dev_session(&user_id.to_string(), wid, level, 60 * 60);
    sqlx::query(
        "INSERT INTO sessions (user_id, jwt_id, expires_at) VALUES ($1, $2, to_timestamp($3))",
    )
    .bind(user_id)
    .bind(&jwt_id)
    .bind(exp)
    .execute(pool)
    .await
    .expect("failed to seed session");
    format!("Bearer {token}")
}

fn ensure_db_env() {
    // SAFETY: test-local env setup.
    unsafe {
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
    }
}

fn derive_did_key(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    let mut multicodec = Vec::with_capacity(34);
    multicodec.push(0xed);
    multicodec.push(0x01);
    multicodec.extend_from_slice(&verifying_key.to_bytes());
    format!("did:key:z{}", bs58::encode(&multicodec).into_string())
}

struct UserAgent {
    user_id: Uuid,
    auth: String,
    did: String,
    aid: String,
    signing_key: SigningKey,
}

async fn seed_user_with_agent(
    pool: &PgPool,
    wid: &str,
    label: &str,
    signing_seed_byte: u8,
) -> UserAgent {
    let user_id = Uuid::new_v4();
    seed_user(pool, user_id, wid, "orb").await;
    let auth = seed_session(pool, user_id, wid, "orb").await;

    let signing_seed: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[0] = signing_seed_byte;
        bytes
    };
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let did = derive_did_key(&signing_key.verifying_key());
    let public_key_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:xuser{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, $4, $5, $6, true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(&did)
    .bind(label)
    .bind(&public_key_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(agent_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed agent_identity");
    sqlx::query(
        "INSERT INTO agent_identity_keys (aid, did, signing_public_key, encryption_public_key, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(&aid)
    .bind(&did)
    .bind(&public_key_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed identity_key");

    UserAgent {
        user_id,
        auth,
        did,
        aid,
        signing_key,
    }
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Plain-bearer agent token for `agent` with `messages.read` + `messages.send`.
async fn seed_agent_token(pool: &PgPool, agent: &UserAgent) -> String {
    let credential_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'test', 'active', 'unused', NOW())",
    )
    .bind(credential_id)
    .bind(&agent.aid)
    .bind(agent.user_id)
    .execute(pool)
    .await
    .expect("seed credential");
    let access = format!("agt_test{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agent_tokens \
           (credential_id, access_hash, refresh_hash, dpop_jkt, scopes, \
            access_expires_at, refresh_expires_at) \
         VALUES ($1, $2, $3, 'none', $4, NOW() + interval '1 hour', NOW() + interval '1 day')",
    )
    .bind(credential_id)
    .bind(sha256_hex(&access))
    .bind(sha256_hex(&format!("agr_{access}")))
    .bind(vec![
        "messages.read".to_string(),
        "messages.send".to_string(),
    ])
    .execute(pool)
    .await
    .expect("seed token");
    format!("Bearer {access}")
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn wrapped_key(marker: u8) -> String {
    format!(
        "x25519v1:{}:{}:{}:{}",
        URL_SAFE_NO_PAD.encode([marker; 32]),
        URL_SAFE_NO_PAD.encode([0u8; 16]),
        URL_SAFE_NO_PAD.encode([0u8; 12]),
        URL_SAFE_NO_PAD.encode([0u8; 48]),
    )
}

/// A signed draft body from `sender` to `recipient_did`, wrapped to `review_key_id`.
/// Signed with envelope signature v2 (docs/40 §15.2): the same fields as a
/// `POST /messages` body, with `signature_v2` at the top level.
async fn draft_body(
    app: &axum::Router,
    sender: &UserAgent,
    recipient_did: &str,
    review_key_id: &str,
) -> Value {
    let subject_encrypted = URL_SAFE_NO_PAD.encode(b"subject-ct-draft");
    let encrypted_content = URL_SAFE_NO_PAD.encode(b"body-ct-draft");
    let encrypted_key = wrapped_key(1);
    let nonce = URL_SAFE_NO_PAD.encode([7u8; 24]);
    let mut message = json!({
        "sender_did": sender.did,
        "recipient_did": recipient_did,
        "envelope": {
            "encrypted_content": encrypted_content,
            "encrypted_key": encrypted_key,
            "nonce": nonce,
            "encrypted_keys": [],
            "sender_encrypted_keys": [],
            "metadata": { "subject_encrypted": subject_encrypted, "content_type": "text/plain" }
        }
    });
    common::sign_body_v2(app, &sender.auth, &sender.signing_key, &mut message).await;
    json!({
        "sender_did": sender.did,
        "recipient_did": recipient_did,
        "subject_encrypted": subject_encrypted,
        "encrypted_content": encrypted_content,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "signature_v2": message["envelope"]["signature_v2"],
        "encrypted_keys": [],
        "sender_encrypted_keys": [],
        "content_type": "text/plain",
        "review_wraps": [{ "review_key_id": review_key_id, "wrapped_key": wrapped_key(2) }],
        "via": "Muse",
    })
}

async fn register_review_key(app: &axum::Router, auth: &str) -> String {
    let (status, body) = call(
        app,
        "POST",
        "/review-keys",
        auth,
        Some(json!({ "public_key": URL_SAFE_NO_PAD.encode([9u8; 32]), "label": "Safari" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_string()
}

async fn audit_events(pool: &PgPool, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT event FROM agent_audit_log WHERE user_id = $1 ORDER BY event")
        .bind(user_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

macro_rules! setup {
    () => {{
        if !db_tests_enabled() {
            eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
            return;
        }
        ensure_db_env();
        let pool = db_pool().await;
        reset_schema(&pool).await;
        (common::test_app(), pool)
    }};
}

#[tokio::test]
#[serial]
async fn approved_draft_is_sent_and_removed() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xdraft-owner", "secretary", 0x51).await;
    let friend = seed_user_with_agent(&pool, "0xdraft-friend", "friend", 0x52).await;
    let agent = seed_agent_token(&pool, &me).await;
    let key_id = register_review_key(&app, &me.auth).await;
    // Connecting a computer gives an agent new keys; agents.did keeps the
    // DID it was created with. Names must still be found.
    for ua in [&me, &friend] {
        sqlx::query("UPDATE agents SET did = 'did:key:zcreated' || md5(did) WHERE did = $1")
            .bind(&ua.did)
            .execute(&pool)
            .await
            .unwrap();
    }

    // The agent list names every DID, so the web can match message rows.
    let (_, agents) = call(&app, "GET", "/agents", &me.auth, None).await;
    let dids = agents["agents"][0]["dids"].as_array().unwrap();
    assert!(dids.iter().any(|d| d == me.did.as_str()), "{agents}");

    // The computer sees the review keys it must wrap to.
    let (status, keys) = call(&app, "GET", "/review-keys", &agent, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys["review_keys"][0]["id"], key_id.as_str());

    let (status, created) = call(
        &app,
        "POST",
        "/agent-drafts",
        &agent,
        Some(draft_body(&app, &me, &friend.did, &key_id).await),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let draft_id = created["id"].as_str().unwrap().to_string();

    let (status, list) = call(&app, "GET", "/agent-drafts", &me.auth, None).await;
    assert_eq!(status, StatusCode::OK);
    let draft = &list["drafts"][0];
    assert_eq!(draft["id"], draft_id.as_str());
    assert_eq!(draft["recipient_label"], "friend");
    assert_eq!(draft["sender_label"], "secretary");
    assert_eq!(draft["via"], "Muse");
    assert_eq!(draft["review_wraps"][0]["review_key_id"], key_id.as_str());
    assert!(
        draft.get("encrypted_key").is_none(),
        "the recipient's wrap is not needed to review"
    );

    let (status, sent) = call(
        &app,
        "POST",
        &format!("/agent-drafts/{draft_id}/send"),
        &me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{sent}");

    let recipient_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1 AND sender_did = $2",
    )
    .bind(friend.user_id)
    .bind(&me.did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recipient_rows, 1, "the friend received it");
    let (_, friend_inbox) = call(
        &app,
        "GET",
        &format!("/messages?agent_did={}", friend.did),
        &friend.auth,
        None,
    )
    .await;
    assert_eq!(friend_inbox["messages"][0]["sender_label"], "secretary");
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_drafts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);

    // A second approval finds nothing.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/agent-drafts/{draft_id}/send"),
        &me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = audit_events(&pool, me.user_id).await;
    assert!(
        events.contains(&"agent_draft_created".to_string()),
        "{events:?}"
    );
    assert!(
        events.contains(&"agent_draft_sent".to_string()),
        "{events:?}"
    );
}

#[tokio::test]
#[serial]
async fn only_the_computer_creates_and_only_the_person_approves() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xdraft-owner2", "secretary", 0x53).await;
    let friend = seed_user_with_agent(&pool, "0xdraft-friend2", "friend", 0x54).await;
    let agent = seed_agent_token(&pool, &me).await;
    let key_id = register_review_key(&app, &me.auth).await;

    // A session cannot create a draft.
    let (status, _) = call(
        &app,
        "POST",
        "/agent-drafts",
        &me.auth,
        Some(draft_body(&app, &me, &friend.did, &key_id).await),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (_, created) = call(
        &app,
        "POST",
        "/agent-drafts",
        &agent,
        Some(draft_body(&app, &me, &friend.did, &key_id).await),
    )
    .await;
    let draft_id = created["id"].as_str().unwrap().to_string();

    // The agent token can neither list nor approve nor register a key.
    let (status, _) = call(&app, "GET", "/agent-drafts", &agent, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &app,
        "POST",
        &format!("/agent-drafts/{draft_id}/send"),
        &agent,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &app,
        "POST",
        "/review-keys",
        &agent,
        Some(json!({ "public_key": URL_SAFE_NO_PAD.encode([3u8; 32]) })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Another person cannot see or approve it.
    let (_, other_list) = call(&app, "GET", "/agent-drafts", &friend.auth, None).await;
    assert_eq!(other_list["drafts"].as_array().unwrap().len(), 0);
    let (status, _) = call(
        &app,
        "POST",
        &format!("/agent-drafts/{draft_id}/send"),
        &friend.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/agent-drafts/{draft_id}"),
        &friend.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The owner discards it.
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/agent-drafts/{draft_id}"),
        &me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = call(&app, "GET", "/agent-drafts", &me.auth, None).await;
    assert_eq!(list["drafts"].as_array().unwrap().len(), 0);
}

#[tokio::test]
#[serial]
async fn drafts_are_checked_when_they_are_made() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xdraft-owner3", "secretary", 0x55).await;
    let friend = seed_user_with_agent(&pool, "0xdraft-friend3", "friend", 0x56).await;
    let agent = seed_agent_token(&pool, &me).await;
    let key_id = register_review_key(&app, &me.auth).await;
    let friends_key = register_review_key(&app, &friend.auth).await;

    // A tampered body no longer matches the signature.
    let mut bad = draft_body(&app, &me, &friend.did, &key_id).await;
    bad["encrypted_content"] = json!(URL_SAFE_NO_PAD.encode(b"something-else"));
    let (status, _) = call(&app, "POST", "/agent-drafts", &agent, Some(bad)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Someone else's review key, or none, is refused: nobody could review it.
    let (status, _) = call(
        &app,
        "POST",
        "/agent-drafts",
        &agent,
        Some(draft_body(&app, &me, &friend.did, &friends_key).await),
    )
    .await;
    assert!(status.is_client_error(), "{status}");
    let mut none = draft_body(&app, &me, &friend.did, &key_id).await;
    none["review_wraps"] = json!([]);
    let (status, _) = call(&app, "POST", "/agent-drafts", &agent, Some(none)).await;
    assert!(status.is_client_error(), "{status}");

    // The sender must be this credential's agent.
    let (status, _) = call(
        &app,
        "POST",
        "/agent-drafts",
        &agent,
        Some(draft_body(&app, &friend, &me.did, &key_id).await),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn expired_drafts_cannot_be_sent_and_are_cleaned_up() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xdraft-owner4", "secretary", 0x57).await;
    let friend = seed_user_with_agent(&pool, "0xdraft-friend4", "friend", 0x58).await;
    let agent = seed_agent_token(&pool, &me).await;
    let key_id = register_review_key(&app, &me.auth).await;
    let (_, created) = call(
        &app,
        "POST",
        "/agent-drafts",
        &agent,
        Some(draft_body(&app, &me, &friend.did, &key_id).await),
    )
    .await;
    let draft_id = created["id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE agent_drafts SET expires_at = NOW() - interval '1 minute'")
        .execute(&pool)
        .await
        .unwrap();

    let (_, list) = call(&app, "GET", "/agent-drafts", &me.auth, None).await;
    assert_eq!(list["drafts"].as_array().unwrap().len(), 0);
    let (status, _) = call(
        &app,
        "POST",
        &format!("/agent-drafts/{draft_id}/send"),
        &me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let summary = nexusinbox_api::run_retention_pass(nexusinbox_api::RetentionConfig {
        mode: nexusinbox_api::RetentionMode::Enforce,
        retention_days: 90,
    })
    .await;
    assert_eq!(summary.agent_drafts, 1);
}

#[tokio::test]
#[serial]
async fn review_keys_can_be_removed() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xdraft-owner5", "secretary", 0x59).await;
    let friend = seed_user_with_agent(&pool, "0xdraft-friend5", "friend", 0x5a).await;
    let key_id = register_review_key(&app, &me.auth).await;

    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/review-keys/{key_id}"),
        &friend.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/review-keys/{key_id}"),
        &me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, keys) = call(&app, "GET", "/review-keys", &me.auth, None).await;
    assert_eq!(keys["review_keys"].as_array().unwrap().len(), 0);
}
