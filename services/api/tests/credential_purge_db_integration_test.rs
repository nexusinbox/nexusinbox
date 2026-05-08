//! DB-mode integration tests for POST /agent-credentials/:id/purge.
//!
//! Covers:
//!   - 204 on eligible (revoked >= 7 days ago): row deleted, audit
//!     carries the denormalised snapshot so the event remains
//!     interpretable after the FK goes NULL.
//!   - 409 purge_grace_period when revoked_at is within the grace
//!     window.
//!   - 409 purge_ineligible when status is not 'revoked'.
//!   - 404 for a credential that does not exist / belongs to a different
//!     user (prevents cross-tenant purge leakage).
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test credential_purge_db_integration_test -- --test-threads=1

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

async fn seed_user(pool: &PgPool, user_id: Uuid, world_id: &str) {
    sqlx::query(
        "INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) \
         VALUES ($1, $2, $3, 'orb')",
    )
    .bind(user_id)
    .bind(world_id)
    .bind(world_id)
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_session(pool: &PgPool, user_id: Uuid, wid: &str) -> String {
    let (token, jwt_id, exp) =
        nexusinbox_api::issue_dev_session(&user_id.to_string(), wid, "orb", 60 * 60);
    sqlx::query(
        "INSERT INTO sessions (user_id, jwt_id, expires_at) VALUES ($1, $2, to_timestamp($3))",
    )
    .bind(user_id)
    .bind(&jwt_id)
    .bind(exp)
    .execute(pool)
    .await
    .expect("seed session");
    format!("Bearer {token}")
}

async fn seed_agent_and_identity(pool: &PgPool, user_id: Uuid) -> String {
    let agent_id = Uuid::new_v4();
    let did = format!("did:key:z{}", Uuid::new_v4().simple());
    let aid = format!("aid:ai:purge{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'purge-target', 'PUB', 'ENC', true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(&did)
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
    aid
}

async fn seed_credential(
    pool: &PgPool,
    user_id: Uuid,
    aid: &str,
    status: &str,
    revoked_at_sql: Option<&str>,
    label: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    // Intentionally interpolate the SQL fragment for revoked_at so we can
    // pass things like `NOW() - INTERVAL '10 days'`. The `$3` parameter
    // keeps the rest type-safe.
    let revoked_sql = revoked_at_sql.unwrap_or("NULL");
    let q = format!(
        "INSERT INTO agent_credentials (id, aid, user_id, label, status, \
          allowed_scopes, created_at, revoked_at) \
         VALUES ($1, $2, $3, $4, $5::text, ARRAY['messages.send']::text[], \
                 NOW() - INTERVAL '30 days', {revoked_sql})"
    );
    sqlx::query(&q)
        .bind(id)
        .bind(aid)
        .bind(user_id)
        .bind(label)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed credential");
    id
}

fn ensure_db_env() {
    unsafe {
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::Null)
}

async fn purge(app: &axum::Router, credential_id: Uuid, auth: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/agent-credentials/{credential_id}/purge"))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn purge_eligible_deletes_row_and_writes_snapshot_audit() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpurge-eligible").await;
    let auth = seed_session(&pool, user_id, "0xpurge-eligible").await;
    let aid = seed_agent_and_identity(&pool, user_id).await;
    let cred_id = seed_credential(
        &pool,
        user_id,
        &aid,
        "revoked",
        Some("NOW() - INTERVAL '10 days'"),
        "eligible-revoked-cred",
    )
    .await;

    let response = purge(&app, cred_id, &auth).await;
    let status = response.status();
    if status != StatusCode::NO_CONTENT {
        let body = body_json(response).await;
        panic!("expected 204, got {status}, body={body}");
    }

    // Row is physically gone.
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "credential row must be deleted after purge");

    // Poll briefly for the fire-and-forget audit spawn to land.
    let mut audit_row: Option<serde_json::Value> = None;
    for _ in 0..10 {
        audit_row = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT detail FROM agent_audit_log \
             WHERE event = 'credential_purged' AND user_id = $1 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        if audit_row.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let audit_detail = audit_row.expect("credential_purged audit row missing");
    assert_eq!(
        audit_detail["credential_id_text"].as_str(),
        Some(cred_id.to_string().as_str()),
        "audit detail must carry the credential_id as text so it survives FK set-null"
    );
    assert_eq!(audit_detail["aid_snapshot"].as_str(), Some(aid.as_str()));
    assert_eq!(
        audit_detail["label_snapshot"].as_str(),
        Some("eligible-revoked-cred")
    );
    assert!(
        audit_detail["revoked_at_snapshot"].is_string(),
        "revoked_at_snapshot must be present"
    );

    // Since the credential row is gone, the FK on the audit row must have
    // been SET NULL. The snapshot is now the only way to identify the
    // credential — exactly what C was meant to protect against.
    let fk_credential_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT credential_id FROM agent_audit_log \
         WHERE event = 'credential_purged' AND user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        fk_credential_id.is_none(),
        "FK credential_id should be NULL after purge due to ON DELETE SET NULL"
    );
}

#[tokio::test]
#[serial]
async fn purge_within_grace_period_returns_conflict() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpurge-toofresh").await;
    let auth = seed_session(&pool, user_id, "0xpurge-toofresh").await;
    let aid = seed_agent_and_identity(&pool, user_id).await;
    let cred_id = seed_credential(
        &pool,
        user_id,
        &aid,
        "revoked",
        Some("NOW() - INTERVAL '1 day'"), // inside 7-day grace
        "fresh-revoked",
    )
    .await;

    let response = purge(&app, cred_id, &auth).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = body_json(response).await;
    assert_eq!(
        body["error"].as_str(),
        Some("purge_grace_period"),
        "expected purge_grace_period error, got {body:?}"
    );

    // Row must still exist.
    let still_there: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_credentials WHERE id = $1")
            .bind(cred_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(still_there, 1);
}

#[tokio::test]
#[serial]
async fn purge_active_credential_returns_conflict() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpurge-active").await;
    let auth = seed_session(&pool, user_id, "0xpurge-active").await;
    let aid = seed_agent_and_identity(&pool, user_id).await;
    let cred_id = seed_credential(&pool, user_id, &aid, "active", None, "active-cred").await;

    let response = purge(&app, cred_id, &auth).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = body_json(response).await;
    assert_eq!(
        body["error"].as_str(),
        Some("purge_ineligible"),
        "expected purge_ineligible for status=active, got {body:?}"
    );
}

#[tokio::test]
#[serial]
async fn purge_nonexistent_returns_not_found() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpurge-missing").await;
    let auth = seed_session(&pool, user_id, "0xpurge-missing").await;

    let response = purge(&app, Uuid::new_v4(), &auth).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn purge_cross_user_returns_not_found() {
    // If Alice tries to purge a credential owned by Bob, we must return
    // 404 (matching the revoke semantics — never leak existence across
    // users).
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();
    seed_user(&pool, alice, "0xalice-purge").await;
    seed_user(&pool, bob, "0xbob-purge").await;
    let alice_auth = seed_session(&pool, alice, "0xalice-purge").await;
    let bob_aid = seed_agent_and_identity(&pool, bob).await;
    let bob_cred = seed_credential(
        &pool,
        bob,
        &bob_aid,
        "revoked",
        Some("NOW() - INTERVAL '10 days'"),
        "bob-eligible",
    )
    .await;

    let response = purge(&app, bob_cred, &alice_auth).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Bob's credential must still be there.
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_credentials WHERE id = $1")
        .bind(bob_cred)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
}
