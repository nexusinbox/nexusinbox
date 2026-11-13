//! DB-mode integration tests for the daily data-retention pass (docs/28 §4).
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test retention_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use nexusinbox_api::{run_retention_pass, RetentionConfig, RetentionMode, RetentionSummary};
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::path::{Path, PathBuf};
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

/// Points localfs storage at a fresh directory for one test and restores
/// the previous value on drop.
struct StorageRoot {
    path: PathBuf,
    saved: Option<String>,
}

impl StorageRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nexusinbox-retention-test-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&path).unwrap();
        let saved = std::env::var("AGENT_INBOX_STORAGE_ROOT").ok();
        // SAFETY: test-local env mutation under #[serial]; restored on drop.
        unsafe {
            std::env::set_var("AGENT_INBOX_STORAGE_ROOT", &path);
        }
        Self { path, saved }
    }
}

impl Drop for StorageRoot {
    fn drop(&mut self) {
        // SAFETY: restore env.
        unsafe {
            match &self.saved {
                Some(value) => std::env::set_var("AGENT_INBOX_STORAGE_ROOT", value),
                None => std::env::remove_var("AGENT_INBOX_STORAGE_ROOT"),
            }
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn count_json_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                count_json_files(&path)
            } else if path.extension().is_some_and(|ext| ext == "json") {
                1
            } else {
                0
            }
        })
        .sum()
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("count query failed ({sql}): {e}"))
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

async fn seed_user_with_agent(pool: &PgPool, wid: &str, seed_byte: u8) -> UserAgent {
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

    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    let signing_key = SigningKey::from_bytes(&seed);
    let did = derive_did_key(&signing_key.verifying_key());
    let public_key_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:ret{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'agent', $4, $5, true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(&did)
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
        "INSERT INTO agent_identity_keys \
           (aid, did, signing_public_key, encryption_public_key, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(&aid)
    .bind(&did)
    .bind(&public_key_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed identity key");

    UserAgent {
        user_id,
        auth: format!("Bearer {token}"),
        did,
        aid,
        signing_key,
    }
}

async fn build_send_body(
    app: &axum::Router,
    auth: &str,
    sender: &UserAgent,
    recipient_did: &str,
    nonce_marker: u8,
) -> Value {
    let subject_encrypted = URL_SAFE_NO_PAD.encode(b"subject-ct-retention");
    let encrypted_content = URL_SAFE_NO_PAD.encode(b"body-ct-retention");
    let encrypted_key = format!(
        "x25519v1:{}:{}:{}:{}",
        URL_SAFE_NO_PAD.encode([0u8; 32]),
        URL_SAFE_NO_PAD.encode([0u8; 16]),
        URL_SAFE_NO_PAD.encode([0u8; 12]),
        URL_SAFE_NO_PAD.encode([0u8; 48]),
    );
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[0] = nonce_marker;
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let mut body = json!({
        "sender_did": sender.did,
        "recipient_did": recipient_did,
        "envelope": {
            "encrypted_content": encrypted_content,
            "encrypted_key": encrypted_key,
            "nonce": nonce,
            "metadata": {
                "subject_encrypted": subject_encrypted,
                "thread_id": null,
                "content_type": "text/plain",
                "has_attachments": false,
            }
        },
        "priority": "normal",
    });
    common::sign_body_v2(app, auth, &sender.signing_key, &mut body).await;
    body
}

/// Sends one cross-user message (two index rows, one blob) and returns the
/// sender-side row id.
async fn send(app: &axum::Router, from: &UserAgent, to: &UserAgent, nonce_marker: u8) -> Uuid {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &from.auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    build_send_body(app, &from.auth, from, &to.did, nonce_marker)
                        .await
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    Uuid::parse_str(body["message_id"].as_str().unwrap()).unwrap()
}

/// Moves both copies of a cross-user message (they share one blob, so one
/// storage_ref) into the past.
async fn age_message(pool: &PgPool, sender_row: Uuid, days: i64) {
    sqlx::query(
        "UPDATE message_index SET created_at = NOW() - ($2::bigint * INTERVAL '1 day') \
         WHERE storage_ref = (SELECT storage_ref FROM message_index WHERE id = $1)",
    )
    .bind(sender_row)
    .bind(days)
    .execute(pool)
    .await
    .expect("age message");
}

async fn seed_credential(
    pool: &PgPool,
    owner: &UserAgent,
    status: &str,
    revoked_days_ago: Option<i64>,
    enrollment_expired_days_ago: Option<i64>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, signing_public_key, revoked_at, enrollment_expires) \
         VALUES ($1, $2, $3, 'test', $4, 'unused', \
           NOW() - ($5::bigint * INTERVAL '1 day'), NOW() - ($6::bigint * INTERVAL '1 day'))",
    )
    .bind(id)
    .bind(&owner.aid)
    .bind(owner.user_id)
    .bind(status)
    .bind(revoked_days_ago)
    .bind(enrollment_expired_days_ago)
    .execute(pool)
    .await
    .expect("seed credential");
    id
}

async fn seed_token(
    pool: &PgPool,
    credential_id: Uuid,
    expired_days_ago: i64,
    revoked_days_ago: Option<i64>,
) {
    sqlx::query(
        "INSERT INTO agent_tokens \
           (credential_id, access_hash, refresh_hash, dpop_jkt, scopes, \
            access_expires_at, refresh_expires_at, revoked_at) \
         VALUES ($1, $2, $3, 'none', ARRAY['messages.read'], \
           NOW() - ($4::bigint * INTERVAL '1 day'), NOW() - ($4::bigint * INTERVAL '1 day'), \
           NOW() - ($5::bigint * INTERVAL '1 day'))",
    )
    .bind(credential_id)
    .bind(Uuid::new_v4().simple().to_string())
    .bind(Uuid::new_v4().simple().to_string())
    .bind(expired_days_ago)
    .bind(revoked_days_ago)
    .execute(pool)
    .await
    .expect("seed token");
}

async fn seed_audit_row(pool: &PgPool, owner: &UserAgent, days_ago: i64) {
    sqlx::query(
        "INSERT INTO agent_audit_log (user_id, aid, event, created_at) \
         VALUES ($1, $2, 'test_event', NOW() - ($3::bigint * INTERVAL '1 day'))",
    )
    .bind(owner.user_id)
    .bind(&owner.aid)
    .bind(days_ago)
    .execute(pool)
    .await
    .expect("seed audit row");
}

async fn seed_purged_upload(pool: &PgPool, owner: &UserAgent, purged_days_ago: i64) {
    sqlx::query(
        "INSERT INTO attachment_uploads \
           (owner_user_id, sender_did, r2_bucket, object_key, ciphertext_size_limit, status, \
            upload_expires_at, deleted_at, purged_at) \
         VALUES ($1, $2, 'bucket', $3, 1024, 'deleted', NOW(), \
           NOW() - ($4::bigint * INTERVAL '1 day'), NOW() - ($4::bigint * INTERVAL '1 day'))",
    )
    .bind(owner.user_id)
    .bind(&owner.did)
    .bind(format!("attachments/{}", Uuid::new_v4()))
    .bind(purged_days_ago)
    .execute(pool)
    .await
    .expect("seed purged upload");
}

/// One expired and one recent row (or row set) for every retention step.
struct Fixture {
    alice: UserAgent,
    bob: UserAgent,
    old_message: Uuid,
    recent_message: Uuid,
    old_revoked_credential: Uuid,
    recent_revoked_credential: Uuid,
    active_credential: Uuid,
    stale_pending_credential: Uuid,
}

async fn seed_fixture(app: &axum::Router, pool: &PgPool) -> Fixture {
    let alice = seed_user_with_agent(pool, "0xalice-retention", 0x91).await;
    let bob = seed_user_with_agent(pool, "0xbob-retention", 0x92).await;

    let old_message = send(app, &alice, &bob, 0x93).await;
    let recent_message = send(app, &alice, &bob, 0x94).await;
    age_message(pool, old_message, 100).await;

    // Sessions: expired 3 days ago (goes). A session revoked 3 days ago
    // but valid for 10 more days stays: its row keeps the JWT rejected.
    sqlx::query(
        "INSERT INTO sessions (user_id, jwt_id, expires_at) \
         VALUES ($1, 'expired-jti', NOW() - INTERVAL '3 days')",
    )
    .bind(alice.user_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sessions (user_id, jwt_id, expires_at, revoked_at) \
         VALUES ($1, 'revoked-jti', NOW() + INTERVAL '10 days', NOW() - INTERVAL '3 days')",
    )
    .bind(alice.user_id)
    .execute(pool)
    .await
    .unwrap();

    // Credentials and tokens.
    let old_revoked_credential = seed_credential(pool, &alice, "revoked", Some(40), None).await;
    seed_token(pool, old_revoked_credential, 40, Some(40)).await;
    let recent_revoked_credential = seed_credential(pool, &alice, "revoked", Some(5), None).await;
    let active_credential = seed_credential(pool, &alice, "active", None, None).await;
    seed_token(pool, active_credential, 10, None).await; // expired 10 days ago: goes
    seed_token(pool, active_credential, -1, None).await; // valid for a day: stays
    let stale_pending_credential = seed_credential(pool, &alice, "pending", None, Some(10)).await;

    seed_audit_row(pool, &alice, 100).await;
    seed_audit_row(pool, &alice, 10).await;
    seed_purged_upload(pool, &alice, 10).await;
    seed_purged_upload(pool, &alice, 1).await;

    Fixture {
        alice,
        bob,
        old_message,
        recent_message,
        old_revoked_credential,
        recent_revoked_credential,
        active_credential,
        stale_pending_credential,
    }
}

/// The auto-reply evaluator writes its own audit rows asynchronously on
/// every send, so tests count only the rows they seeded.
const AUDIT_SEEDED: &str = "SELECT COUNT(*) FROM agent_audit_log WHERE event = 'test_event'";

fn expected_summary() -> RetentionSummary {
    RetentionSummary {
        messages: 2,      // both copies of the old message
        message_blobs: 1, // the blob they shared
        attachment_uploads: 1,
        // The expired token of the active credential, plus the revoked
        // credential's token (revoked 40 days ago).
        agent_tokens: 2,
        agent_credentials: 2, // revoked 40 days ago, and the stale pending one
        sessions: 1,
        audit_log: 1,
        // The fixture's sends only touch today's counter.
        send_counters: 0,
        agent_drafts: 0,
        oauth: 0,
        errors: 0,
    }
}

fn config(mode: RetentionMode) -> RetentionConfig {
    RetentionConfig {
        mode,
        retention_days: 90,
    }
}

#[tokio::test]
#[serial]
async fn dry_run_counts_expired_rows_and_deletes_nothing() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let storage = StorageRoot::new();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let _fixture = seed_fixture(&app, &pool).await;

    let before = (
        count(&pool, "SELECT COUNT(*) FROM message_index").await,
        count(&pool, "SELECT COUNT(*) FROM sessions").await,
        count(&pool, "SELECT COUNT(*) FROM agent_tokens").await,
        count(&pool, "SELECT COUNT(*) FROM agent_credentials").await,
        count(&pool, AUDIT_SEEDED).await,
        count(&pool, "SELECT COUNT(*) FROM attachment_uploads").await,
    );
    assert_eq!(count_json_files(&storage.path), 2);

    let summary = run_retention_pass(config(RetentionMode::DryRun)).await;
    assert_eq!(summary, expected_summary());

    let after = (
        count(&pool, "SELECT COUNT(*) FROM message_index").await,
        count(&pool, "SELECT COUNT(*) FROM sessions").await,
        count(&pool, "SELECT COUNT(*) FROM agent_tokens").await,
        count(&pool, "SELECT COUNT(*) FROM agent_credentials").await,
        count(&pool, AUDIT_SEEDED).await,
        count(&pool, "SELECT COUNT(*) FROM attachment_uploads").await,
    );
    assert_eq!(before, after, "dry run must not delete any row");
    assert_eq!(
        count_json_files(&storage.path),
        2,
        "dry run keeps every blob"
    );
}

#[tokio::test]
#[serial]
async fn enforce_deletes_only_rows_past_their_retention() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let storage = StorageRoot::new();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed_fixture(&app, &pool).await;

    let summary = run_retention_pass(config(RetentionMode::Enforce)).await;
    assert_eq!(summary, expected_summary());

    // Messages: the old thread is gone on both sides, with its blob.
    let recent_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM message_index WHERE storage_ref = \
           (SELECT storage_ref FROM message_index WHERE id = $1)",
    )
    .bind(f.recent_message)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recent_rows, 2, "the recent message keeps both copies");
    let gone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE id = $1")
        .bind(f.old_message)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(gone, 0, "the old message is deleted");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM message_index").await, 2);
    assert_eq!(
        count_json_files(&storage.path),
        1,
        "only the recent message's blob is left"
    );

    // Sessions: the expired one goes; the revoked-but-unexpired one and
    // each user's live session stay.
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM sessions WHERE jwt_id = 'expired-jti'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM sessions WHERE jwt_id = 'revoked-jti'"
        )
        .await,
        1
    );
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sessions").await, 3);

    // Credentials and tokens.
    for (id, expected, what) in [
        (f.old_revoked_credential, 0, "revoked 40 days ago"),
        (
            f.stale_pending_credential,
            0,
            "pending, enrollment long expired",
        ),
        (f.recent_revoked_credential, 1, "revoked 5 days ago"),
        (f.active_credential, 1, "active"),
    ] {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_credentials WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, expected, "credential {what}");
    }
    let tokens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tokens, 1, "only the still-valid token is left");

    assert_eq!(count(&pool, AUDIT_SEEDED).await, 1);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM attachment_uploads").await,
        1
    );

    // Users and agents are not touched by retention.
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM users").await, 2);
    let _ = (&f.alice, &f.bob);

    // A second pass finds nothing left to delete.
    let again = run_retention_pass(config(RetentionMode::Enforce)).await;
    assert_eq!(again, RetentionSummary::default());
}

#[tokio::test]
#[serial]
async fn enforce_keeps_a_blob_a_recent_row_still_references() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let storage = StorageRoot::new();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_user_with_agent(&pool, "0xalice-retention-ref", 0xa1).await;
    let bob = seed_user_with_agent(&pool, "0xbob-retention-ref", 0xa2).await;
    let sender_row = send(&app, &alice, &bob, 0xa3).await;

    // Only the sender's copy is past the cutoff.
    sqlx::query("UPDATE message_index SET created_at = NOW() - INTERVAL '100 days' WHERE id = $1")
        .bind(sender_row)
        .execute(&pool)
        .await
        .unwrap();

    let summary = run_retention_pass(config(RetentionMode::Enforce)).await;
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.message_blobs, 0);
    let bob_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(bob.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bob_rows, 1, "the recipient's copy stays");
    assert_eq!(
        count_json_files(&storage.path),
        1,
        "the blob the recipient still references must survive"
    );
}

#[test]
#[serial]
fn config_from_env_fails_safe() {
    // SAFETY: test-local env mutation under #[serial]; restored below.
    let saved_mode = std::env::var("AGENT_INBOX_RETENTION_MODE").ok();
    let saved_days = std::env::var("AGENT_INBOX_RETENTION_DAYS").ok();
    unsafe {
        std::env::remove_var("AGENT_INBOX_RETENTION_MODE");
        std::env::set_var("AGENT_INBOX_RETENTION_DAYS", "0");
    }
    let unset = RetentionConfig::from_env();
    assert_eq!(
        unset.mode,
        RetentionMode::DryRun,
        "unset mode never deletes"
    );
    assert_eq!(unset.retention_days, 7, "days are floored at 7");
    unsafe {
        std::env::set_var("AGENT_INBOX_RETENTION_MODE", "Enforce ");
        std::env::set_var("AGENT_INBOX_RETENTION_DAYS", "abc");
    }
    let enforce = RetentionConfig::from_env();
    assert_eq!(enforce.mode, RetentionMode::Enforce);
    assert_eq!(
        enforce.retention_days, 90,
        "unparsable days fall back to 90"
    );
    unsafe {
        std::env::set_var("AGENT_INBOX_RETENTION_MODE", "enforced");
    }
    assert_eq!(
        RetentionConfig::from_env().mode,
        RetentionMode::DryRun,
        "a misspelt mode never deletes"
    );
    unsafe {
        match saved_mode {
            Some(v) => std::env::set_var("AGENT_INBOX_RETENTION_MODE", v),
            None => std::env::remove_var("AGENT_INBOX_RETENTION_MODE"),
        }
        match saved_days {
            Some(v) => std::env::set_var("AGENT_INBOX_RETENTION_DAYS", v),
            None => std::env::remove_var("AGENT_INBOX_RETENTION_DAYS"),
        }
    }
}
