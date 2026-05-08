//! DB-mode integration tests for the hierarchical block list.
//!
//! These run against a real PostgreSQL and exercise the SQL paths added in
//! Step B (blocks table CRUD + `evaluate_block_decision_db` +
//! `SELECT COUNT(*) FROM blocks` inside `send_message`). They are gated
//! behind the `AGENT_INBOX_DB_TESTS=1` env var so the default `cargo test`
//! suite stays hermetic.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   psql ... < migrations/0001_init.sql
//!   psql ... < migrations/0002_blocks.sql
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test blocks_db_integration_test

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
    // Truncate all relevant tables between tests. `RESTART IDENTITY CASCADE`
    // flushes replay_nonces' BIGSERIAL too.
    sqlx::query(
        "TRUNCATE TABLE blocks, message_index, sessions, replay_nonces, agents, users \
         RESTART IDENTITY CASCADE",
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

/// Issue a JWT for `user_id` and insert a matching active session row so
/// `authenticated_claims` passes the `session_is_active_in_db` check.
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

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[serial]
async fn blocks_crud_roundtrip_against_postgres() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    // Initialize the router first so common::ensure_test_env sets JWT_SECRET
    // before we mint any tokens.
    let app = common::test_app();

    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xowner-db", "orb").await;
    let auth = seed_session(&pool, user_id, "0xowner-db", "orb").await;

    // Empty initially.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/blocks")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["blocks"].as_array().unwrap().len(), 0);

    // Create an L1 block.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/blocks")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "level": "l1_did",
                        "target_did": "did:key:z6MkhqDbTargetAA"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let l1_id: String = body_json(response).await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Create an L2 block.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/blocks")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "level": "l2_identity",
                        "target_world_id": "0xSPAMMER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify persistence directly in Postgres.
    let db_count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM blocks WHERE owner_user_id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(db_count, 2);

    // List returns both entries.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/blocks")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let blocks = body["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 2);
    let levels: Vec<&str> = blocks
        .iter()
        .map(|b| b["level"].as_str().unwrap())
        .collect();
    assert!(levels.contains(&"l1_did"));
    assert!(levels.contains(&"l2_identity"));

    // Delete the L1 block and verify 404 on re-delete.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/blocks/{l1_id}"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/blocks/{l1_id}"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify the remaining DB row.
    let remaining: i64 = sqlx::query("SELECT COUNT(*) AS c FROM blocks WHERE owner_user_id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(remaining, 1);
}

#[tokio::test]
#[serial]
async fn evaluate_block_decision_db_check_constraint_shape() {
    // Validates that the CHECK constraint in migration 0002 rejects malformed
    // rows (L1 requires target_did, L2/L3 require target_world_id).
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    let pool = db_pool().await;
    reset_schema(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xcheck", "orb").await;

    // L1 without target_did should fail.
    let err = sqlx::query(
        "INSERT INTO blocks (owner_user_id, level, target_world_id) VALUES ($1, 'l1_did', '0xbad')",
    )
    .bind(user_id)
    .execute(&pool)
    .await;
    assert!(
        err.is_err(),
        "L1 block without target_did should be rejected"
    );

    // L2 with both target_did and target_world_id should fail.
    let err = sqlx::query(
        "INSERT INTO blocks (owner_user_id, level, target_did, target_world_id) \
         VALUES ($1, 'l2_identity', 'did:key:zBad', '0xbad')",
    )
    .bind(user_id)
    .execute(&pool)
    .await;
    assert!(
        err.is_err(),
        "L2 block with both targets should be rejected"
    );

    // Valid L3 row is accepted.
    sqlx::query(
        "INSERT INTO blocks (owner_user_id, level, target_world_id) \
         VALUES ($1, 'l3_stealth', '0xgood')",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("valid L3 row should be accepted");
}
