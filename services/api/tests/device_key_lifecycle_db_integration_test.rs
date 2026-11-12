//! DB-mode integration tests for which device keys stay in an agent's
//! recipient set (docs/38 §3):
//!   - revoking a computer's credential retires its key, so the agent's
//!     address resolves to the browser's key again;
//!   - an emergency shutdown retires every computer key and keeps the
//!     browser's;
//!   - rotating a computer's credential marks only that computer's key.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 DATABASE_URL=postgres://... \
//!     cargo test --test device_key_lifecycle_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
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
        "TRUNCATE TABLE agent_audit_log, agent_tokens, agent_credentials, \
         agent_identity_keys, agent_identities, blocks, message_index, \
         sessions, replay_nonces, agents, users RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .expect("failed to truncate schema");
}

fn ensure_db_env() {
    unsafe {
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
    }
}

struct Fixture {
    auth: String,
    agent_id: Uuid,
    aid: String,
    browser_did: String,
    user_id: Uuid,
}

/// A user with one agent whose browser key was created an hour ago.
async fn seed(pool: &PgPool, tag: &str) -> Fixture {
    let user_id = Uuid::new_v4();
    let wid = format!("0xdevice-{tag}");
    sqlx::query(
        "INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) \
         VALUES ($1, $2, $2, 'orb')",
    )
    .bind(user_id)
    .bind(&wid)
    .execute(pool)
    .await
    .expect("seed user");
    let (token, jwt_id, exp) =
        nexusinbox_api::issue_dev_session(&user_id.to_string(), &wid, "orb", 60 * 60);
    sqlx::query(
        "INSERT INTO sessions (user_id, jwt_id, expires_at) VALUES ($1, $2, to_timestamp($3))",
    )
    .bind(user_id)
    .bind(&jwt_id)
    .bind(exp)
    .execute(pool)
    .await
    .expect("seed session");

    let agent_id = Uuid::new_v4();
    let browser_did = format!("did:key:zbrowser{}", Uuid::new_v4().simple());
    let aid = format!("aid:ai:dev{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'secretary', 'BROWSER_SPK', 'BROWSER_ENC', true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(&browser_did)
    .execute(pool)
    .await
    .expect("seed agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(agent_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed identity");
    sqlx::query(
        "INSERT INTO agent_identity_keys \
           (aid, did, signing_public_key, encryption_public_key, status, activated_at) \
         VALUES ($1, $2, 'BROWSER_SPK', 'BROWSER_ENC', 'active', NOW() - INTERVAL '1 hour')",
    )
    .bind(&aid)
    .bind(&browser_did)
    .execute(pool)
    .await
    .expect("seed browser key");

    Fixture {
        auth: format!("Bearer {token}"),
        agent_id,
        aid,
        browser_did,
        user_id,
    }
}

/// A connected computer: an active credential and its active key.
async fn seed_computer(pool: &PgPool, f: &Fixture, n: u32) -> (Uuid, String) {
    let credential_id = Uuid::new_v4();
    let spk = format!("PC{n}_SPK");
    sqlx::query(
        "INSERT INTO agent_credentials (id, aid, user_id, label, status, allowed_scopes, \
           signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'macOS', 'active', ARRAY['messages.send']::text[], $4, NOW())",
    )
    .bind(credential_id)
    .bind(&f.aid)
    .bind(f.user_id)
    .bind(&spk)
    .execute(pool)
    .await
    .expect("seed credential");
    let did = format!("did:key:zpc{n}{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agent_identity_keys \
           (aid, did, signing_public_key, encryption_public_key, status, activated_at) \
         VALUES ($1, $2, $3, $4, 'active', NOW() - ($5::int * INTERVAL '1 minute'))",
    )
    .bind(&f.aid)
    .bind(&did)
    .bind(&spk)
    .bind(format!("PC{n}_ENC"))
    .bind(10 - n as i32)
    .execute(pool)
    .await
    .expect("seed computer key");
    (credential_id, did)
}

async fn call(app: &axum::Router, method: &str, uri: &str, auth: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
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

async fn resolved_did(app: &axum::Router, f: &Fixture) -> String {
    let (status, body) = call(
        app,
        "GET",
        &format!("/recipients/resolve?identifier={}", f.aid),
        &f.auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resolve failed: {body}");
    body["did"].as_str().expect("did in resolve").to_string()
}

/// (did, kind, label) of each device the agent list shows for the agent.
async fn device_summary(app: &axum::Router, f: &Fixture) -> Vec<(String, String, Option<String>)> {
    let (status, body) = call(app, "GET", "/agents", &f.auth).await;
    assert_eq!(status, StatusCode::OK, "list agents failed: {body}");
    let agent = body["agents"]
        .as_array()
        .and_then(|a| a.iter().find(|a| a["aid"] == f.aid.as_str()))
        .expect("agent in list")
        .clone();
    agent["devices"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|d| {
            (
                d["did"].as_str().unwrap_or_default().to_string(),
                d["kind"].as_str().unwrap_or_default().to_string(),
                d["label"].as_str().map(str::to_string),
            )
        })
        .collect()
}

async fn key_status(pool: &PgPool, did: &str) -> String {
    sqlx::query_scalar("SELECT status FROM agent_identity_keys WHERE did = $1")
        .bind(did)
        .fetch_one(pool)
        .await
        .expect("key row")
}

#[tokio::test]
#[serial]
async fn revoking_a_computer_takes_its_key_out_of_the_recipient_set() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed(&pool, "revoke").await;
    let (credential_id, pc_did) = seed_computer(&pool, &f, 1).await;

    assert_eq!(resolved_did(&app, &f).await, pc_did);
    // The agent list shows both devices, the computer by its name (docs/38 stage 4).
    assert_eq!(
        device_summary(&app, &f).await,
        vec![
            (f.browser_did.clone(), "browser".to_string(), None),
            (
                pc_did.clone(),
                "computer".to_string(),
                Some("macOS".to_string())
            ),
        ]
    );

    let (status, body) = call(
        &app,
        "DELETE",
        &format!("/agent-credentials/{credential_id}"),
        &f.auth,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revoke failed: {body}");

    assert_eq!(key_status(&pool, &pc_did).await, "retired");
    assert_eq!(key_status(&pool, &f.browser_did).await, "active");
    assert_eq!(resolved_did(&app, &f).await, f.browser_did);
    assert_eq!(
        device_summary(&app, &f).await,
        vec![(f.browser_did.clone(), "browser".to_string(), None)]
    );
}

#[tokio::test]
#[serial]
async fn emergency_shutdown_retires_every_computer_key_and_keeps_the_browser() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed(&pool, "shutdown").await;
    let (_, pc1) = seed_computer(&pool, &f, 1).await;
    let (_, pc2) = seed_computer(&pool, &f, 2).await;

    let (status, body) = call(
        &app,
        "POST",
        &format!("/agents/{}/emergency-shutdown", f.agent_id),
        &f.auth,
    )
    .await;
    assert!(status.is_success(), "shutdown failed: {status} {body}");

    assert_eq!(key_status(&pool, &pc1).await, "retired");
    assert_eq!(key_status(&pool, &pc2).await, "retired");
    assert_eq!(key_status(&pool, &f.browser_did).await, "active");
    assert_eq!(resolved_did(&app, &f).await, f.browser_did);
}

#[tokio::test]
#[serial]
async fn rotating_a_computer_marks_only_its_own_key() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed(&pool, "rotate").await;
    let (cred1, pc1) = seed_computer(&pool, &f, 1).await;
    let (_, pc2) = seed_computer(&pool, &f, 2).await;

    let (status, body) = call(
        &app,
        "POST",
        &format!("/agent-credentials/{cred1}/rotate"),
        &f.auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate failed: {body}");

    assert_eq!(key_status(&pool, &pc1).await, "rotating");
    assert_eq!(key_status(&pool, &pc2).await, "active");
    assert_eq!(key_status(&pool, &f.browser_did).await, "active");
}
