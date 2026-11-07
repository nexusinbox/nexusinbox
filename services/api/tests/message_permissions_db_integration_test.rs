//! DB-mode integration tests for which agent token may change a message
//! row (audit 2026-11-07): a write scope is needed to change status or
//! folder, and a sender agent may not change the inbox row of a sibling
//! agent of the same person.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test message_permissions_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
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
        "TRUNCATE TABLE agent_audit_log, agent_tokens, agent_credentials, contacts, \
         message_attachments, attachment_uploads, blocks, message_index, sessions, \
         replay_nonces, agent_identity_keys, agent_identities, agents, users \
         RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .expect("failed to truncate schema");
}

fn ensure_db_env() {
    // SAFETY: test-local env setup.
    unsafe {
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
    }
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Owner {
    user_id: Uuid,
}

async fn seed_owner(pool: &PgPool, wid: &str) -> Owner {
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) \
         VALUES ($1, $2, $2, 'orb')",
    )
    .bind(user_id)
    .bind(wid)
    .execute(pool)
    .await
    .expect("seed user");
    Owner { user_id }
}

struct Agent {
    did: String,
    aid: String,
}

async fn seed_agent(pool: &PgPool, owner: &Owner, label: &str, auto_reply: bool) -> Agent {
    let id = Uuid::new_v4();
    let did = format!("did:key:z{label}{}", Uuid::new_v4().simple());
    let aid = format!("aid:ai:claim{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active, \
           auto_reply) \
         VALUES ($1, $2, $3, $4, 'pk', 'ek', true, $5)",
    )
    .bind(id)
    .bind(owner.user_id)
    .bind(&did)
    .bind(label)
    .bind(auto_reply)
    .execute(pool)
    .await
    .expect("seed agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(id)
        .bind(owner.user_id)
        .execute(pool)
        .await
        .expect("seed agent identity");
    sqlx::query(
        "INSERT INTO agent_identity_keys \
           (aid, did, signing_public_key, encryption_public_key, status) \
         VALUES ($1, $2, 'pk', 'ek', 'active')",
    )
    .bind(&aid)
    .bind(&did)
    .execute(pool)
    .await
    .expect("seed identity key");
    Agent { did, aid }
}

/// Plain-bearer agent token (`dpop_jkt = 'none'`) for `agent`.
async fn seed_agent_token(pool: &PgPool, owner: &Owner, agent: &Agent, scopes: &[&str]) -> String {
    let credential_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'test', 'active', 'unused', NOW())",
    )
    .bind(credential_id)
    .bind(&agent.aid)
    .bind(owner.user_id)
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
    .bind(scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed token");
    format!("Bearer {access}")
}

/// An inbox row addressed to `recipient` that the evaluator stamped
/// `auto_accept`, so it is on the pending list.
/// A message row from `sender_did` to `recipient_did`, owned by `owner`.
async fn seed_row(
    pool: &PgPool,
    owner: &Owner,
    sender_did: &str,
    recipient_did: &str,
    folder: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_index \
           (id, owner_user_id, sender_did, recipient_did, subject_encrypted, storage_ref, \
            status, priority, folder, starred) \
         VALUES ($1, $2, $3, $4, 'subject-ct', $5, 'unread', 'normal', $6, FALSE)",
    )
    .bind(id)
    .bind(owner.user_id)
    .bind(sender_did)
    .bind(recipient_did)
    .bind(format!("localfs:v1://{id}"))
    .bind(folder)
    .execute(pool)
    .await
    .expect("seed row");
    id
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
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

macro_rules! skip_without_db {
    () => {
        if !db_tests_enabled() {
            eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
            return;
        }
        ensure_db_env();
    };
}

#[tokio::test]
#[serial]
async fn read_only_agent_token_cannot_change_status_or_folder() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xperm-scope").await;
    let agent = seed_agent(&pool, &owner, "a", false).await;
    let row = seed_row(&pool, &owner, "did:key:zsender", &agent.did, "inbox").await;
    let read_only = seed_agent_token(&pool, &owner, &agent, &["messages.read"]).await;
    let writer = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;

    for (path, body) in [
        (format!("/messages/{row}"), json!({"status": "read"})),
        (format!("/messages/{row}/flags"), json!({"starred": true})),
    ] {
        let (status, _) = call(&app, "PATCH", &path, &read_only, Some(body.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "read-only token on {path}");
        let (status, resp) = call(&app, "PATCH", &path, &writer, Some(body)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "send-scoped token on {path}: {resp}"
        );
    }
}

#[tokio::test]
#[serial]
async fn sender_agent_cannot_change_a_siblings_inbox_row() {
    // A send between two agents of one person is a single row: the
    // receiving sibling's inbox entry. The sender may read it but not
    // archive, flag or delete it.
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xperm-sibling").await;
    let sender = seed_agent(&pool, &owner, "s", false).await;
    let recipient = seed_agent(&pool, &owner, "r", false).await;
    let row = seed_row(&pool, &owner, &sender.did, &recipient.did, "inbox").await;
    let scopes = ["messages.read", "messages.send", "messages.delete"];
    let sender_token = seed_agent_token(&pool, &owner, &sender, &scopes).await;
    let recipient_token = seed_agent_token(&pool, &owner, &recipient, &scopes).await;

    for (method, path, body) in [
        (
            "PATCH",
            format!("/messages/{row}"),
            Some(json!({"status": "archived"})),
        ),
        (
            "PATCH",
            format!("/messages/{row}/flags"),
            Some(json!({"folder": "trash"})),
        ),
        ("DELETE", format!("/messages/{row}"), None),
    ] {
        let (status, _) = call(&app, method, &path, &sender_token, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "sender {method} {path}");
    }
    let (folder, status): (String, String) =
        sqlx::query_as("SELECT folder, status FROM message_index WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (folder.as_str(), status.as_str()),
        ("inbox", "unread"),
        "the row is untouched"
    );

    // The sender can still read it, and the recipient can change it.
    let (status, _) = call(
        &app,
        "GET",
        &format!("/messages/{row}/content"),
        &sender_token,
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "reading stays allowed for the sender"
    );
    let (status, resp) = call(
        &app,
        "PATCH",
        &format!("/messages/{row}"),
        &recipient_token,
        Some(json!({"status": "read"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
}

#[tokio::test]
#[serial]
async fn sender_agent_can_still_file_its_cross_person_sent_copy() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_owner(&pool, "0xperm-alice").await;
    let bob = seed_owner(&pool, "0xperm-bob").await;
    let alice_agent = seed_agent(&pool, &alice, "a", false).await;
    let bob_agent = seed_agent(&pool, &bob, "b", false).await;
    // Alice's sender-side copy of a message to Bob's agent.
    let sent_copy = seed_row(&pool, &alice, &alice_agent.did, &bob_agent.did, "sent").await;
    let token = seed_agent_token(
        &pool,
        &alice,
        &alice_agent,
        &["messages.read", "messages.send"],
    )
    .await;

    let (status, resp) = call(
        &app,
        "PATCH",
        &format!("/messages/{sent_copy}/flags"),
        &token,
        Some(json!({"starred": true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
}
