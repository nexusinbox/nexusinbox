//! DB-mode integration tests for `/agents/:id/auto-reply-policy`.
//!
//! Covers the round-trip that hermetic tests can't reach — row
//! creation, optimistic locking via revision, audit log emission,
//! and cascade deletes when the parent agent goes away.
//!
//! Usage:
//!   docker compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test auto_reply_policy_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
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
        "TRUNCATE TABLE agent_audit_log, agent_auto_reply_policies, agent_tokens, \
         agent_credentials, agent_identity_keys, agent_identities, blocks, \
         message_index, sessions, replay_nonces, agents, users RESTART IDENTITY CASCADE",
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

async fn seed_agent(pool: &PgPool, user_id: Uuid) -> Uuid {
    let agent_id = Uuid::new_v4();
    let did = format!("did:key:z{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'policy-target', 'PUB', 'ENC', true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(&did)
    .execute(pool)
    .await
    .expect("seed agent");
    agent_id
}

fn default_policy() -> Value {
    json!({
        "v": 1,
        "default_action": "queue_for_human",
        "protocols": {
            "schedule_negotiation": {
                "propose": {
                    "action": "auto_accept",
                    "conditions": {
                        "min_trust_score": 0.5,
                        "require_contact": true
                    },
                    "note_template": "OK from my agent."
                }
            }
        }
    })
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn put_policy(
    app: &axum::Router,
    agent_id: Uuid,
    auth: &str,
    body: Value,
    if_match: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(format!("/agents/{agent_id}/auto-reply-policy"))
        .header("authorization", auth)
        .header("content-type", "application/json");
    if let Some(im) = if_match {
        builder = builder.header("if-match", im);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn get_policy(app: &axum::Router, agent_id: Uuid, auth: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/agents/{agent_id}/auto-reply-policy"))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn delete_policy(app: &axum::Router, agent_id: Uuid, auth: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/agents/{agent_id}/auto-reply-policy"))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

// -----------------------------------------------------------------
// GET behaviour on empty + existing rows
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_returns_default_when_no_row_exists() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-get-default").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-get-default").await;
    let agent_id = seed_agent(&pool, user_id).await;

    let resp = get_policy(&app, agent_id, &auth).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = response_json(resp).await;
    assert_eq!(body["revision"], 0);
    assert_eq!(body["policy"], json!({}));
    assert_eq!(body["updated_at"], Value::Null);
    assert_eq!(etag.as_deref(), Some("\"0\""));
}

// -----------------------------------------------------------------
// PUT create → GET round-trip + audit event
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn put_create_round_trips_and_emits_audit_event() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-create").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-create").await;
    let agent_id = seed_agent(&pool, user_id).await;

    // First PUT — creating. revision: 0 indicates "no prior row".
    let resp = put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = response_json(resp).await;
    assert_eq!(body["revision"], 1);
    assert_eq!(etag.as_deref(), Some("\"1\""));

    // GET sees the same shape + revision.
    let get_resp = get_policy(&app, agent_id, &auth).await;
    let get_body = response_json(get_resp).await;
    assert_eq!(get_body["revision"], 1);
    assert_eq!(get_body["policy"]["default_action"], "queue_for_human");

    // Audit event landed (fire-and-forget — poll briefly).
    let mut found = false;
    for _ in 0..10 {
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_log \
             WHERE event = 'auto_reply_policy_created' AND user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if cnt >= 1 {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(found, "auto_reply_policy_created audit event expected");
}

// -----------------------------------------------------------------
// PUT update with correct If-Match bumps revision + emits updated event
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn put_update_increments_revision_and_logs_prev_next() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-update").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-update").await;
    let agent_id = seed_agent(&pool, user_id).await;

    // Create
    let create = put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);

    // Update with correct If-Match.
    let mut updated = default_policy();
    updated["default_action"] = json!("auto_decline");
    let update = put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": updated, "revision": 1 }),
        Some("\"1\""),
    )
    .await;
    assert_eq!(update.status(), StatusCode::OK);
    let body = response_json(update).await;
    assert_eq!(body["revision"], 2);
    assert_eq!(body["policy"]["default_action"], "auto_decline");

    // Audit: both created + updated rows exist, and the latest
    // `updated` carries prev + next policy in detail.
    let row = sqlx::query(
        "SELECT detail FROM agent_audit_log \
         WHERE event = 'auto_reply_policy_updated' AND user_id = $1 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .expect("audit fetch");
    // fire-and-forget → brief poll to avoid flake
    let detail: Option<Value> = match row {
        Some(r) => Some(r.get("detail")),
        None => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            sqlx::query_scalar::<_, Value>(
                "SELECT detail FROM agent_audit_log \
                 WHERE event = 'auto_reply_policy_updated' AND user_id = $1 \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(user_id)
            .fetch_optional(&pool)
            .await
            .unwrap()
        }
    };
    let detail = detail.expect("audit event expected");
    assert_eq!(detail["revision_before"], 1);
    assert_eq!(detail["revision_after"], 2);
    assert_eq!(detail["prev"]["default_action"], "queue_for_human");
    assert_eq!(detail["next"]["default_action"], "auto_decline");
}

// -----------------------------------------------------------------
// PUT with stale If-Match → 409
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn put_update_with_stale_if_match_returns_409() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-stale").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-stale").await;
    let agent_id = seed_agent(&pool, user_id).await;

    let create = put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);

    let stale = put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let body = response_json(stale).await;
    assert_eq!(body["error"], "revision_conflict");
}

// -----------------------------------------------------------------
// PUT without revision when row exists → 409 (prevents silent overwrite)
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn put_without_revision_but_row_exists_returns_409() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-norev").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-norev").await;
    let agent_id = seed_agent(&pool, user_id).await;

    // Seed a row first.
    let create = put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);

    // Attempt unconditional overwrite — no If-Match, no body revision.
    let overwrite = put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy() }),
        None,
    )
    .await;
    assert_eq!(overwrite.status(), StatusCode::CONFLICT);
}

// -----------------------------------------------------------------
// Ownership gate: another user's agent → 404
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn put_on_other_users_agent_returns_404() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();
    seed_user(&pool, alice, "0xalice-policy").await;
    seed_user(&pool, bob, "0xbob-policy").await;
    let alice_auth = seed_session(&pool, alice, "0xalice-policy").await;
    let bob_agent = seed_agent(&pool, bob).await;

    let resp = put_policy(
        &app,
        bob_agent,
        &alice_auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// -----------------------------------------------------------------
// DELETE removes the row + emits audit (and is idempotent afterwards)
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn delete_removes_row_and_emits_audit() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-delete").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-delete").await;
    let agent_id = seed_agent(&pool, user_id).await;

    // Create a row first.
    put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;

    // First DELETE — hits an existing row.
    let resp = delete_policy(&app, agent_id, &auth).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_auto_reply_policies WHERE agent_id = $1")
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);

    // Audit event present.
    let mut found_delete = false;
    for _ in 0..10 {
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_log \
             WHERE event = 'auto_reply_policy_deleted' AND user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if cnt >= 1 {
            found_delete = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(found_delete);

    // Second DELETE — idempotent, still 204, no second audit row.
    let resp2 = delete_policy(&app, agent_id, &auth).await;
    assert_eq!(resp2.status(), StatusCode::NO_CONTENT);
    let delete_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_audit_log \
         WHERE event = 'auto_reply_policy_deleted' AND user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        delete_count, 1,
        "second DELETE must not emit another audit event"
    );
}

// -----------------------------------------------------------------
// Dropping the parent agent cascades the policy row
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn policy_row_is_removed_when_parent_agent_is_deleted() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-cascade").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-cascade").await;
    let agent_id = seed_agent(&pool, user_id).await;

    put_policy(
        &app,
        agent_id,
        &auth,
        json!({ "policy": default_policy(), "revision": 0 }),
        Some("\"0\""),
    )
    .await;

    // Drop the agent via direct SQL to simulate ON DELETE CASCADE
    // without having to carry over the full DELETE /agents/{id}
    // response path. The cascade is what we're testing, not the
    // REST surface.
    sqlx::query("DELETE FROM agents WHERE id = $1")
        .bind(agent_id)
        .execute(&pool)
        .await
        .unwrap();

    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_auto_reply_policies WHERE agent_id = $1")
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "policy row must cascade on agent delete");
}

// -----------------------------------------------------------------
// Schema validation fails on bad policy JSON even with valid auth
// -----------------------------------------------------------------

#[tokio::test]
#[serial]
async fn put_rejects_policy_failing_schema_validation() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xpolicy-badjson").await;
    let auth = seed_session(&pool, user_id, "0xpolicy-badjson").await;
    let agent_id = seed_agent(&pool, user_id).await;

    // `v: 2` is not yet supported.
    let resp = put_policy(
        &app,
        agent_id,
        &auth,
        json!({
            "policy": { "v": 2, "default_action": "queue_for_human" },
            "revision": 0
        }),
        Some("\"0\""),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_auto_reply_policies WHERE agent_id = $1")
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "failed validation must not create a row");
}
