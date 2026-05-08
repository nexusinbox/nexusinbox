//! DB-mode integration tests for POST /agent-audit-log/bridge.
//!
//! Covers the full positive path plus the four hardening rejections that
//! the hermetic `bridge_audit_ingest_test.rs` cannot reach (they all run
//! *after* the DB lookup):
//!
//!   - full positive: signature verify → iss / aud / iat / jti / event
//!     allow-list all pass → audit row inserted with the bridge_event
//!     payload preserved verbatim.
//!   - aud mismatch: JWS signed with a different `aud` string is
//!     rejected 401 even if everything else is correct.
//!   - stale iat: `iat` more than 60s in the past is rejected 422.
//!   - jti replay: same `(credential_id, jti)` POSTed twice — first
//!     succeeds, second returns 409 `replay_rejected`.
//!   - unknown event type: `bridge_event.event` outside the allow-list
//!     is rejected 422 even with a valid signature.
//!
//! These tests all require the `bridge_audit_replay` scope to use the DB
//! `replay_nonces` table, and the credential lookup to see the seeded
//! `signing_public_key` — hence the DB-integration gate.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test bridge_audit_ingest_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::time::Duration;
use tower::util::ServiceExt;
use uuid::Uuid;

mod common;

// The aud claim must byte-match what the server derives via
// `expected_api_url`. We drive that via AGENT_INBOX_PUBLIC_API_URL so the
// expected aud is fixed regardless of which Host header axum happens to
// surface — otherwise the test is implicitly coupled to tower's default
// request shape.
const TEST_API_URL: &str = "http://bridge-audit.test";
const BRIDGE_AUDIT_PATH: &str = "/agent-audit-log/bridge";

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

fn ensure_env() {
    unsafe {
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
        // Force the expected aud to a fixed string so test vectors don't
        // depend on request-level headers.
        std::env::set_var("AGENT_INBOX_PUBLIC_API_URL", TEST_API_URL);
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

/// Seeds a fully-active credential with the given signing key and returns
/// the generated aid. The credential's signing_public_key matches the key,
/// so any JWS signed with it will verify.
async fn seed_active_credential(
    pool: &PgPool,
    user_id: Uuid,
    credential_id: Uuid,
    signing_key: &SigningKey,
    label: &str,
) -> String {
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:bridge{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(format!("did:key:z{}", Uuid::new_v4().simple()))
    .bind("bridge-audit-test")
    .bind("legacy-public-key")
    .bind("legacy-encryption-key")
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

    let spk = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

    // Dummy enrollment_hash so the CHECK constraint is happy. The column is
    // meaningless once the credential is active.
    let dummy_hash = hex::encode(Sha256::digest(b"seed-dummy"));

    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, enrollment_hash, signing_public_key, \
            activated_at, allowed_scopes) \
         VALUES ($1, $2, $3, $4, 'active', $5, $6, NOW(), \
                 ARRAY['messages.send']::text[])",
    )
    .bind(credential_id)
    .bind(&aid)
    .bind(user_id)
    .bind(label)
    .bind(&dummy_hash)
    .bind(&spk)
    .execute(pool)
    .await
    .expect("seed active credential");

    aid
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build a compact JWS (EdDSA) whose payload carries the fields the bridge
/// audit endpoint checks: iss / sub / aud / iat / jti / bridge_event.
fn sign_bridge_jws(
    signing_key: &SigningKey,
    credential_id: Uuid,
    iss: &str,
    aud: &str,
    iat: i64,
    jti: &str,
    bridge_event: Value,
) -> String {
    let header = b64url(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = b64url(
        json!({
            "iss": iss,
            "sub": credential_id.to_string(),
            "aud": aud,
            "iat": iat,
            "jti": jti,
            "bridge_event": bridge_event,
        })
        .to_string()
        .as_bytes(),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = signing_key.sign(signing_input.as_bytes());
    format!("{}.{}.{}", header, payload, b64url(&signature.to_bytes()))
}

async fn post_bridge(app: &axum::Router, jws: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(BRIDGE_AUDIT_PATH)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "jws": jws }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

fn expected_aud() -> String {
    format!("{}{}", TEST_API_URL, BRIDGE_AUDIT_PATH)
}

#[tokio::test]
#[serial]
async fn bridge_audit_ingest_full_positive_path() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xbridge-audit-happy").await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let credential_id = Uuid::new_v4();
    let aid = seed_active_credential(
        &pool,
        user_id,
        credential_id,
        &signing_key,
        "bridge-happy-path",
    )
    .await;

    let event = json!({
        "event": "bridged_decrypt",
        "envelope_id": "env-abc",
        "outcome": "ok",
    });
    let jws = sign_bridge_jws(
        &signing_key,
        credential_id,
        &aid,
        &expected_aud(),
        chrono::Utc::now().timestamp(),
        "jti-happy-1",
        event.clone(),
    );

    let response = post_bridge(&app, &jws).await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response_json(response).await;
    assert_eq!(payload["accepted"], true);

    // audit_log row should land with the event_type and preserved detail.
    let mut saw_row = false;
    for _ in 0..10 {
        let row = sqlx::query(
            "SELECT event, detail FROM agent_audit_log \
             WHERE credential_id = $1 AND event = 'bridged_decrypt' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(credential_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        if let Some(r) = row {
            let detail: Value = r.get("detail");
            assert_eq!(detail, event, "detail must match the bridge_event verbatim");
            saw_row = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(saw_row, "expected bridged_decrypt audit row to be inserted");
}

#[tokio::test]
#[serial]
async fn bridge_audit_rejects_aud_mismatch() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xbridge-audit-aud").await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let credential_id = Uuid::new_v4();
    let aid = seed_active_credential(
        &pool,
        user_id,
        credential_id,
        &signing_key,
        "bridge-aud-mismatch",
    )
    .await;

    // aud points at a legitimate-looking URL but not the one the server
    // expects. Everything else is correct. This used to pass under the
    // earlier suffix-matching rule; must be 401 now.
    let jws = sign_bridge_jws(
        &signing_key,
        credential_id,
        &aid,
        "http://evil-mirror.test/agent-audit-log/bridge",
        chrono::Utc::now().timestamp(),
        "jti-aud-1",
        json!({ "event": "bridged_decrypt" }),
    );

    let response = post_bridge(&app, &jws).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "unauthorized");
}

#[tokio::test]
#[serial]
async fn bridge_audit_rejects_stale_iat() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xbridge-audit-iat").await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let credential_id = Uuid::new_v4();
    let aid = seed_active_credential(
        &pool,
        user_id,
        credential_id,
        &signing_key,
        "bridge-stale-iat",
    )
    .await;

    // 120s in the past — outside the ±60s freshness window.
    let jws = sign_bridge_jws(
        &signing_key,
        credential_id,
        &aid,
        &expected_aud(),
        chrono::Utc::now().timestamp() - 120,
        "jti-iat-1",
        json!({ "event": "bridged_decrypt" }),
    );

    let response = post_bridge(&app, &jws).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "validation_error");
}

#[tokio::test]
#[serial]
async fn bridge_audit_rejects_jti_replay() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xbridge-audit-replay").await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let credential_id = Uuid::new_v4();
    let aid =
        seed_active_credential(&pool, user_id, credential_id, &signing_key, "bridge-replay").await;

    let jws = sign_bridge_jws(
        &signing_key,
        credential_id,
        &aid,
        &expected_aud(),
        chrono::Utc::now().timestamp(),
        "jti-replay-1",
        json!({ "event": "bridged_decrypt" }),
    );

    // First POST: 200 accepted.
    let first = post_bridge(&app, &jws).await;
    assert_eq!(first.status(), StatusCode::OK);

    // Same JWS replayed: must be 409 replay_rejected, NOT a silent
    // duplicate insert.
    let second = post_bridge(&app, &jws).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let payload = response_json(second).await;
    assert_eq!(payload["error"], "replay_rejected");

    // Only one audit row should exist.
    let cnt: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_audit_log \
         WHERE credential_id = $1 AND event = 'bridged_decrypt'",
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cnt, 1, "replay must not insert a second audit row");
}

#[tokio::test]
#[serial]
async fn bridge_audit_rejects_unknown_event_type() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xbridge-audit-unknown-event").await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let credential_id = Uuid::new_v4();
    let aid = seed_active_credential(
        &pool,
        user_id,
        credential_id,
        &signing_key,
        "bridge-unknown-event",
    )
    .await;

    // Signature / aud / iat / jti are all valid — only the event name is
    // outside the allow-list. Must be rejected 422 so unknown events don't
    // leak into the audit table.
    let jws = sign_bridge_jws(
        &signing_key,
        credential_id,
        &aid,
        &expected_aud(),
        chrono::Utc::now().timestamp(),
        "jti-unknown-1",
        json!({ "event": "totally_made_up_event" }),
    );

    let response = post_bridge(&app, &jws).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "validation_error");

    // Nothing landed in the audit log.
    let cnt: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_audit_log WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cnt, 0, "unknown event_type must not produce an audit row");
}
