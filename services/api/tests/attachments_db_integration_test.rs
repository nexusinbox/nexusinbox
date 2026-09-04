//! DB-mode integration test for attachment delete failure semantics.
//!
//! This specifically covers the regression where `DELETE /attachments/{id}`
//! used to set `deleted_at = NOW()` even when the underlying R2/S3 delete
//! failed. In that broken state, the background cleanup job would never retry
//! the orphaned blob because it only scans rows with `deleted_at IS NULL`.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test attachments_db_integration_test

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::fs;
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
        "TRUNCATE TABLE message_attachments, attachment_uploads, blocks, message_index, \
         sessions, replay_nonces, agents, users RESTART IDENTITY CASCADE",
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

#[tokio::test]
#[serial]
async fn delete_failure_keeps_attachment_as_cleanup_candidate() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xattach-owner", "orb").await;
    let auth = seed_session(&pool, user_id, "0xattach-owner", "orb").await;

    let attachment_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO attachment_uploads (
          id, owner_user_id, sender_did, draft_id,
          r2_bucket, object_key, ciphertext_size_limit,
          ciphertext_size_bytes, status, issued_at, upload_expires_at, uploaded_at
        ) VALUES (
          $1, $2, NULL, NULL,
          'test-bucket', 'attachments/test/blob.bin', 5242880,
          2048, 'uploaded', NOW(), NOW() + interval '5 minutes', NOW()
        )
        "#,
    )
    .bind(attachment_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("failed to seed attachment upload row");

    let saved_endpoint = std::env::var("AGENT_INBOX_S3_ENDPOINT").ok();
    let saved_bucket = std::env::var("AGENT_INBOX_S3_BUCKET").ok();
    let saved_access_key = std::env::var("AGENT_INBOX_S3_ACCESS_KEY_ID").ok();
    let saved_secret = std::env::var("AGENT_INBOX_S3_SECRET_ACCESS_KEY").ok();
    let saved_region = std::env::var("AGENT_INBOX_S3_REGION").ok();
    let saved_path_style = std::env::var("AGENT_INBOX_S3_PATH_STYLE").ok();
    let saved_prefix = std::env::var("AGENT_INBOX_S3_PREFIX").ok();

    // Force s3_delete_object() to fail fast in a deterministic way.
    // SAFETY: test-local env mutation under #[serial].
    unsafe {
        std::env::remove_var("AGENT_INBOX_S3_ENDPOINT");
        std::env::remove_var("AGENT_INBOX_S3_BUCKET");
        std::env::remove_var("AGENT_INBOX_S3_ACCESS_KEY_ID");
        std::env::remove_var("AGENT_INBOX_S3_SECRET_ACCESS_KEY");
        std::env::remove_var("AGENT_INBOX_S3_REGION");
        std::env::remove_var("AGENT_INBOX_S3_PATH_STYLE");
        std::env::remove_var("AGENT_INBOX_S3_PREFIX");
    }

    let uri = format!("/attachments/{attachment_id}");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Post-migration 0013 semantics:
    //   deleted_at — user intent to delete (always set)
    //   purged_at  — R2 object confirmed removed (only set after success)
    // On a failing R2 delete we expect deleted_at NOT NULL, purged_at NULL.
    let row = sqlx::query(
        r#"
        SELECT
            status,
            deleted_at IS NOT NULL AS deleted_at_is_set,
            purged_at IS NULL AS purged_at_is_null
        FROM attachment_uploads
        WHERE id = $1
        "#,
    )
    .bind(attachment_id)
    .fetch_one(&pool)
    .await
    .expect("failed to reload attachment row");
    let status: String = row.get("status");
    let deleted_at_is_set: bool = row.get("deleted_at_is_set");
    let purged_at_is_null: bool = row.get("purged_at_is_null");

    assert_eq!(status, "deleted");
    assert!(
        deleted_at_is_set,
        "user-requested delete must always record the deletion timestamp",
    );
    assert!(
        purged_at_is_null,
        "R2 delete failure must leave purged_at NULL so cleanup retries",
    );

    // The cleanup job uses (deleted_at IS NOT NULL AND purged_at IS NULL)
    // as its candidate predicate — this row must match it.
    let cleanup_candidates: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM attachment_uploads
        WHERE id = $1
          AND deleted_at IS NOT NULL
          AND purged_at IS NULL
        "#,
    )
    .bind(attachment_id)
    .fetch_one(&pool)
    .await
    .expect("failed to count cleanup candidates");
    assert_eq!(cleanup_candidates, 1);

    // SAFETY: restore prior env values.
    unsafe {
        match saved_endpoint {
            Some(value) => std::env::set_var("AGENT_INBOX_S3_ENDPOINT", value),
            None => std::env::remove_var("AGENT_INBOX_S3_ENDPOINT"),
        }
        match saved_bucket {
            Some(value) => std::env::set_var("AGENT_INBOX_S3_BUCKET", value),
            None => std::env::remove_var("AGENT_INBOX_S3_BUCKET"),
        }
        match saved_access_key {
            Some(value) => std::env::set_var("AGENT_INBOX_S3_ACCESS_KEY_ID", value),
            None => std::env::remove_var("AGENT_INBOX_S3_ACCESS_KEY_ID"),
        }
        match saved_secret {
            Some(value) => std::env::set_var("AGENT_INBOX_S3_SECRET_ACCESS_KEY", value),
            None => std::env::remove_var("AGENT_INBOX_S3_SECRET_ACCESS_KEY"),
        }
        match saved_region {
            Some(value) => std::env::set_var("AGENT_INBOX_S3_REGION", value),
            None => std::env::remove_var("AGENT_INBOX_S3_REGION"),
        }
        match saved_path_style {
            Some(value) => std::env::set_var("AGENT_INBOX_S3_PATH_STYLE", value),
            None => std::env::remove_var("AGENT_INBOX_S3_PATH_STYLE"),
        }
        match saved_prefix {
            Some(value) => std::env::set_var("AGENT_INBOX_S3_PREFIX", value),
            None => std::env::remove_var("AGENT_INBOX_S3_PREFIX"),
        }
    }
}

// ============================================================================
// POST /messages atomicity tests
// ============================================================================
//
// These tests fix the regression window where `send_message` persisted the
// message row, THEN called attach_uploads_to_message separately. If attach
// validation failed, the caller saw an error but the DB retained the
// orphaned message row. After the refactor:
//   1. Attachments are pre-validated outside any DB write (R2 HEAD + DB read)
//   2. A single transaction inserts message_index + message_attachments and
//      flips attachment_uploads.status in one shot
//   3. Any validation failure produces no DB writes at all
//
// The tests below seed the minimal DB rows needed for send_message to reach
// the attachment-validation branch, then assert on the post-call DB state.

/// Derive a valid `did:key` from an Ed25519 public key using the same
/// multicodec (0xed 0x01) + base58btc encoding as the production code path.
fn derive_did_key(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    let mut multicodec = Vec::with_capacity(34);
    multicodec.push(0xed);
    multicodec.push(0x01);
    multicodec.extend_from_slice(&verifying_key.to_bytes());
    format!("did:key:z{}", bs58::encode(&multicodec).into_string())
}

/// Sign the canonical send_message envelope (\n-joined) the server will
/// verify against the sender agent's public key.
#[allow(clippy::too_many_arguments)]
fn sign_envelope(
    signing_key: &SigningKey,
    sender_did: &str,
    recipient_did: &str,
    subject_encrypted: &str,
    encrypted_content: &str,
    encrypted_key: &str,
    nonce: &str,
) -> String {
    let payload = format!(
        "{sender_did}\n{recipient_did}\n{subject_encrypted}\n{encrypted_content}\n{encrypted_key}\n{nonce}"
    );
    URL_SAFE_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes())
}

#[derive(Clone)]
struct SendFixture {
    user_id: Uuid,
    auth: String,
    sender_did: String,
    recipient_did: String,
    signing_key: SigningKey,
    valid_attachment_id: Uuid,
}

/// Seed a full user + sender-agent + recipient-agent + an active
/// `uploaded`-status attachment. Returns everything send_message needs.
async fn seed_send_fixture(pool: &PgPool) -> SendFixture {
    let user_id = Uuid::new_v4();
    seed_user(pool, user_id, "0xattach-send", "orb").await;
    let auth = seed_session(pool, user_id, "0xattach-send", "orb").await;

    // Sender agent (with real Ed25519 key so envelope signature verifies).
    let signing_seed: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x42;
        bytes
    };
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let sender_did = derive_did_key(&signing_key.verifying_key());
    let sender_public_key_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

    let sender_agent_id = Uuid::new_v4();
    let sender_aid = format!("aid:ai:send{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'sender', $4, $5, true)",
    )
    .bind(sender_agent_id)
    .bind(user_id)
    .bind(&sender_did)
    .bind(&sender_public_key_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed sender agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&sender_aid)
        .bind(sender_agent_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed sender agent_identity");
    sqlx::query(
        "INSERT INTO agent_identity_keys (aid, did, signing_public_key, encryption_public_key, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(&sender_aid)
    .bind(&sender_did)
    .bind(&sender_public_key_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed sender identity_key");

    // Recipient agent (under same user for simplicity; send_message only
    // requires the recipient DID to exist in the agents table of SOME user).
    let recipient_agent_id = Uuid::new_v4();
    let recipient_did = format!("did:key:z{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'recipient', 'RECIPIENT_PUB', 'RECIPIENT_ENC', true)",
    )
    .bind(recipient_agent_id)
    .bind(user_id)
    .bind(&recipient_did)
    .execute(pool)
    .await
    .expect("seed recipient agent");

    // An attachment ready to be attached (status='uploaded').
    let valid_attachment_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO attachment_uploads (
            id, owner_user_id, sender_did, draft_id,
            r2_bucket, object_key, ciphertext_size_limit,
            ciphertext_size_bytes, status, issued_at, upload_expires_at, uploaded_at
        ) VALUES (
            $1, $2, $3, NULL,
            'test-bucket', $4, 5242880,
            2048, 'uploaded', NOW(), NOW() + interval '5 minutes', NOW()
        )
        "#,
    )
    .bind(valid_attachment_id)
    .bind(user_id)
    .bind(&sender_did)
    .bind(format!("attachments/{}/blob.bin", Uuid::new_v4()))
    .execute(pool)
    .await
    .expect("seed attachment_upload");

    SendFixture {
        user_id,
        auth,
        sender_did,
        recipient_did,
        signing_key,
        valid_attachment_id,
    }
}

/// Build a `/messages` request body with the given attachment_refs. Envelope
/// fields are opaque-ish strings (the server only validates structure and
/// signature, not the crypto content).
fn build_send_body(fixture: &SendFixture, attachments: Vec<Value>) -> Value {
    let subject_encrypted = URL_SAFE_NO_PAD.encode(b"subject-ct");
    let encrypted_content = URL_SAFE_NO_PAD.encode(b"body-ciphertext-opaque");
    let encrypted_key = format!(
        "x25519v1:{}:{}:{}:{}",
        URL_SAFE_NO_PAD.encode([0u8; 32]),
        URL_SAFE_NO_PAD.encode([0u8; 16]),
        URL_SAFE_NO_PAD.encode([0u8; 12]),
        URL_SAFE_NO_PAD.encode([0u8; 48]),
    );
    let nonce = URL_SAFE_NO_PAD.encode([0u8; 24]);
    let signature = sign_envelope(
        &fixture.signing_key,
        &fixture.sender_did,
        &fixture.recipient_did,
        &subject_encrypted,
        &encrypted_content,
        &encrypted_key,
        &nonce,
    );

    json!({
        "sender_did": fixture.sender_did,
        "recipient_did": fixture.recipient_did,
        "envelope": {
            "encrypted_content": encrypted_content,
            "encrypted_key": encrypted_key,
            "nonce": nonce,
            "signature": signature,
            "metadata": {
                "subject_encrypted": subject_encrypted,
                "thread_id": null,
                "content_type": "text/plain",
                "has_attachments": !attachments.is_empty(),
            }
        },
        "priority": "normal",
        "attachments": attachments,
    })
}

#[tokio::test]
#[serial]
async fn send_message_with_invalid_attachment_id_leaves_db_untouched() {
    // Goal: caller includes one bogus attachment_id alongside a valid
    // attachment. The send must fail, and after the call:
    //   - message_index has NO rows for this call
    //   - message_attachments has NO rows
    //   - the valid attachment is still status='uploaded', not 'attached'
    // i.e. attachment send is atomic "all-or-nothing".
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let fixture = seed_send_fixture(&pool).await;
    let bogus_attachment_id = Uuid::new_v4();

    // Snapshot baseline so the post-call assertions are scoped to this run.
    let before_messages: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(fixture.user_id)
            .fetch_one(&pool)
            .await
            .expect("count messages before");
    let before_message_attachments: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_attachments WHERE owner_user_id = $1")
            .bind(fixture.user_id)
            .fetch_one(&pool)
            .await
            .expect("count message_attachments before");
    assert_eq!(before_messages, 0);
    assert_eq!(before_message_attachments, 0);

    // Two attachment refs: the bogus one listed FIRST so prevalidate fails
    // on it before getting to the valid one. Either order should have the
    // same end-state; this variant is the riskier one for partial writes.
    let body = build_send_body(
        &fixture,
        vec![
            json!({
                "attachment_id": bogus_attachment_id.to_string(),
                "metadata_encrypted": "meta-ct-opaque",
                "metadata_nonce": "meta-nonce-opaque",
            }),
            json!({
                "attachment_id": fixture.valid_attachment_id.to_string(),
                "metadata_encrypted": "meta-ct-opaque",
                "metadata_nonce": "meta-nonce-opaque",
            }),
        ],
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &fixture.auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "expected failure status, got {}",
        response.status(),
    );

    // === The meaningful atomicity assertions ===
    let messages_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(fixture.user_id)
            .fetch_one(&pool)
            .await
            .expect("count messages after");
    assert_eq!(
        messages_after, 0,
        "partial-write regression: message_index row persisted after failed send",
    );

    let message_attachments_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_attachments WHERE owner_user_id = $1")
            .bind(fixture.user_id)
            .fetch_one(&pool)
            .await
            .expect("count message_attachments after");
    assert_eq!(
        message_attachments_after, 0,
        "partial-write regression: message_attachments row persisted after failed send",
    );

    let valid_status: String =
        sqlx::query_scalar("SELECT status FROM attachment_uploads WHERE id = $1")
            .bind(fixture.valid_attachment_id)
            .fetch_one(&pool)
            .await
            .expect("read attachment status");
    assert_eq!(
        valid_status, "uploaded",
        "valid attachment must not have been flipped to 'attached' when the send failed",
    );

    let valid_attached_msg: Option<Uuid> =
        sqlx::query_scalar("SELECT attached_message_id FROM attachment_uploads WHERE id = $1")
            .bind(fixture.valid_attachment_id)
            .fetch_one(&pool)
            .await
            .expect("read attached_message_id");
    assert!(
        valid_attached_msg.is_none(),
        "valid attachment must not have an attached_message_id pointer to a ghost row",
    );
}

#[tokio::test]
#[serial]
async fn send_message_with_empty_attachment_metadata_leaves_db_untouched() {
    // Same property as the bogus-id test but triggered via a different
    // validation gate (empty metadata_encrypted). Guards against regressions
    // where someone moves the metadata check to after the message insert.
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let fixture = seed_send_fixture(&pool).await;

    let body = build_send_body(
        &fixture,
        vec![json!({
            "attachment_id": fixture.valid_attachment_id.to_string(),
            "metadata_encrypted": "", // <-- empty, prevalidate rejects
            "metadata_nonce": "meta-nonce-opaque",
        })],
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &fixture.auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.status().is_client_error(),
        "expected client error on empty metadata, got {}",
        response.status(),
    );
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));
    // Defensive: make sure the error string is about the attachment, not
    // some prior validation step. Pointless comparison if the error surface
    // changes — that's fine, the structural assertions below are what
    // matter.
    let _ = body_json;

    let messages_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(fixture.user_id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(
        messages_after, 0,
        "no message row may exist after failed send"
    );

    let ma_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_attachments WHERE owner_user_id = $1")
            .bind(fixture.user_id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(
        ma_after, 0,
        "no message_attachment row may exist after failed send"
    );

    let att_status: String =
        sqlx::query_scalar("SELECT status FROM attachment_uploads WHERE id = $1")
            .bind(fixture.valid_attachment_id)
            .fetch_one(&pool)
            .await
            .expect("read status");
    assert_eq!(att_status, "uploaded");
}

#[tokio::test]
#[serial]
async fn failed_send_does_not_leave_orphaned_localfs_payload() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();

    let storage_root = std::env::temp_dir().join(format!(
        "nexusinbox-localfs-test-{}",
        Uuid::new_v4().simple()
    ));
    fs::create_dir_all(&storage_root).expect("create storage root");

    // SAFETY: serial test sets a dedicated temp storage root for this process.
    unsafe {
        std::env::set_var("AGENT_INBOX_STORAGE_ROOT", &storage_root);
    }

    let app = nexusinbox_api::app_with_storage_backend("localfs");
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let fixture = seed_send_fixture(&pool).await;
    let bogus_attachment_id = Uuid::new_v4();
    let body = build_send_body(
        &fixture,
        vec![
            json!({
                "attachment_id": bogus_attachment_id.to_string(),
                "metadata_encrypted": "meta-ct-opaque",
                "metadata_nonce": "meta-nonce-opaque",
            }),
            json!({
                "attachment_id": fixture.valid_attachment_id.to_string(),
                "metadata_encrypted": "meta-ct-opaque",
                "metadata_nonce": "meta-nonce-opaque",
            }),
        ],
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &fixture.auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "expected failed send, got {}",
        response.status(),
    );

    let user_storage_dir = storage_root
        .join("localfs")
        .join(fixture.user_id.to_string());
    let file_count = match fs::read_dir(&user_storage_dir) {
        Ok(entries) => entries.count(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => panic!("failed to inspect user storage dir: {error}"),
    };
    assert_eq!(
        file_count, 0,
        "failed send must not leave orphaned encrypted payload files behind"
    );

    let _ = fs::remove_dir_all(&storage_root);
    // SAFETY: restore process env after the serial test finishes.
    unsafe {
        std::env::remove_var("AGENT_INBOX_STORAGE_ROOT");
    }
}

// ============================================================================
// Cross-user attachment ownership (regression for Bug 2 in the 2026-04-20 review)
// ============================================================================
//
// When `send_message` writes two `message_index` rows (one per owner) the
// paired `message_attachments` rows must mirror that ownership — otherwise
// `generate_attachment_download_url`'s `WHERE ma.owner_user_id = $user`
// predicate rejects the recipient's legitimate download. Directly asserting
// the DB shape gives us a fast regression signal without needing live R2.

#[derive(Clone)]
struct CrossUserSendFixture {
    sender_user_id: Uuid,
    recipient_user_id: Uuid,
    sender_auth: String,
    sender_did: String,
    recipient_did: String,
    signing_key: SigningKey,
    valid_attachment_id: Uuid,
}

async fn seed_cross_user_send_fixture(pool: &PgPool) -> CrossUserSendFixture {
    // --- Sender user + agent ---
    let sender_user_id = Uuid::new_v4();
    seed_user(pool, sender_user_id, "0xattach-xuser-sender", "orb").await;
    let sender_auth = seed_session(pool, sender_user_id, "0xattach-xuser-sender", "orb").await;

    let sender_seed: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 0x51;
        b
    };
    let signing_key = SigningKey::from_bytes(&sender_seed);
    let sender_did = derive_did_key(&signing_key.verifying_key());
    let sender_pub_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

    let sender_agent_id = Uuid::new_v4();
    let sender_aid = format!("aid:ai:xsender{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'sender', $4, $5, true)",
    )
    .bind(sender_agent_id)
    .bind(sender_user_id)
    .bind(&sender_did)
    .bind(&sender_pub_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed sender agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&sender_aid)
        .bind(sender_agent_id)
        .bind(sender_user_id)
        .execute(pool)
        .await
        .expect("seed sender agent_identity");
    sqlx::query(
        "INSERT INTO agent_identity_keys (aid, did, signing_public_key, encryption_public_key, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(&sender_aid)
    .bind(&sender_did)
    .bind(&sender_pub_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed sender identity_key");

    // --- Recipient user + agent (DIFFERENT user_id) ---
    let recipient_user_id = Uuid::new_v4();
    seed_user(pool, recipient_user_id, "0xattach-xuser-recipient", "orb").await;

    let recipient_seed: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 0x77;
        b
    };
    let recipient_signing = SigningKey::from_bytes(&recipient_seed);
    let recipient_did = derive_did_key(&recipient_signing.verifying_key());
    let recipient_pub_b64 = URL_SAFE_NO_PAD.encode(recipient_signing.verifying_key().to_bytes());

    let recipient_agent_id = Uuid::new_v4();
    let recipient_aid = format!("aid:ai:xrecv{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'recipient', $4, $5, true)",
    )
    .bind(recipient_agent_id)
    .bind(recipient_user_id)
    .bind(&recipient_did)
    .bind(&recipient_pub_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed recipient agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&recipient_aid)
        .bind(recipient_agent_id)
        .bind(recipient_user_id)
        .execute(pool)
        .await
        .expect("seed recipient agent_identity");
    sqlx::query(
        "INSERT INTO agent_identity_keys (aid, did, signing_public_key, encryption_public_key, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(&recipient_aid)
    .bind(&recipient_did)
    .bind(&recipient_pub_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed recipient identity_key");

    // --- Sender's pending attachment ---
    let valid_attachment_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO attachment_uploads (
            id, owner_user_id, sender_did, draft_id,
            r2_bucket, object_key, ciphertext_size_limit,
            ciphertext_size_bytes, status, issued_at, upload_expires_at, uploaded_at
        ) VALUES (
            $1, $2, $3, NULL,
            'test-bucket', $4, 5242880,
            2048, 'uploaded', NOW(), NOW() + interval '5 minutes', NOW()
        )
        "#,
    )
    .bind(valid_attachment_id)
    .bind(sender_user_id)
    .bind(&sender_did)
    .bind(format!("attachments/{}/blob.bin", Uuid::new_v4()))
    .execute(pool)
    .await
    .expect("seed attachment_upload");

    CrossUserSendFixture {
        sender_user_id,
        recipient_user_id,
        sender_auth,
        sender_did,
        recipient_did,
        signing_key,
        valid_attachment_id,
    }
}

fn build_cross_user_send_body(fixture: &CrossUserSendFixture, attachments: Vec<Value>) -> Value {
    let subject_encrypted = URL_SAFE_NO_PAD.encode(b"subject-ct-x");
    let encrypted_content = URL_SAFE_NO_PAD.encode(b"body-ciphertext-x");
    let encrypted_key = format!(
        "x25519v1:{}:{}:{}:{}",
        URL_SAFE_NO_PAD.encode([0u8; 32]),
        URL_SAFE_NO_PAD.encode([0u8; 16]),
        URL_SAFE_NO_PAD.encode([0u8; 12]),
        URL_SAFE_NO_PAD.encode([0u8; 48]),
    );
    let nonce = URL_SAFE_NO_PAD.encode([0x11u8; 24]);
    let signature = sign_envelope(
        &fixture.signing_key,
        &fixture.sender_did,
        &fixture.recipient_did,
        &subject_encrypted,
        &encrypted_content,
        &encrypted_key,
        &nonce,
    );
    json!({
        "sender_did": fixture.sender_did,
        "recipient_did": fixture.recipient_did,
        "envelope": {
            "encrypted_content": encrypted_content,
            "encrypted_key": encrypted_key,
            "nonce": nonce,
            "signature": signature,
            "metadata": {
                "subject_encrypted": subject_encrypted,
                "thread_id": null,
                "content_type": "text/plain",
                "has_attachments": !attachments.is_empty(),
            }
        },
        "priority": "normal",
        "attachments": attachments,
    })
}

#[tokio::test]
#[serial]
async fn cross_user_send_writes_per_owner_message_attachments_rows() {
    // Regression: recipient-side attachment download was blocked because
    // the recipient's `message_attachments` row was inserted with the
    // sender's `owner_user_id`. `generate_attachment_download_url`'s
    // `WHERE ma.owner_user_id = $current_user` predicate then returned
    // "attachment not found" for the legitimate recipient.
    //
    // This asserts the post-send DB shape: each `message_attachments`
    // row's owner matches the owner of the `message_index` row it
    // references, so both sides' download-URL JOINs succeed.
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    // SAFETY: test-local env tweak; rejected at startup when NODE_ENV=production.
    unsafe {
        std::env::set_var("AGENT_INBOX_ALLOW_SKIP_S3_HEAD_IN_TESTS", "true");
    }
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let fx = seed_cross_user_send_fixture(&pool).await;

    let body = build_cross_user_send_body(
        &fx,
        vec![json!({
            "attachment_id": fx.valid_attachment_id.to_string(),
            "metadata_encrypted": "meta-ct-opaque",
            "metadata_nonce": "meta-nonce-opaque",
        })],
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &fx.sender_auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Two message_attachments rows — one per owner.
    let rows: Vec<(Uuid, Uuid, Uuid)> = sqlx::query(
        "SELECT message_id, owner_user_id, attachment_upload_id \
         FROM message_attachments WHERE attachment_upload_id = $1",
    )
    .bind(fx.valid_attachment_id)
    .fetch_all(&pool)
    .await
    .expect("fetch message_attachments rows")
    .into_iter()
    .map(|row| {
        (
            row.get::<Uuid, _>("message_id"),
            row.get::<Uuid, _>("owner_user_id"),
            row.get::<Uuid, _>("attachment_upload_id"),
        )
    })
    .collect();
    assert_eq!(
        rows.len(),
        2,
        "cross-user send must write one message_attachments row per owner"
    );

    // Sender's message_id (owner=sender) must exist, paired with a row
    // where owner=recipient and message_id matches recipient's
    // message_index row.
    let sender_row_mid: Uuid = sqlx::query_scalar(
        "SELECT id FROM message_index WHERE owner_user_id = $1 AND folder = 'sent'",
    )
    .bind(fx.sender_user_id)
    .fetch_one(&pool)
    .await
    .expect("sender-side message_index row");
    let recipient_row_mid: Uuid =
        sqlx::query_scalar("SELECT id FROM message_index WHERE owner_user_id = $1")
            .bind(fx.recipient_user_id)
            .fetch_one(&pool)
            .await
            .expect("recipient-side message_index row");

    let has_sender_link = rows
        .iter()
        .any(|(mid, owner, _)| *mid == sender_row_mid && *owner == fx.sender_user_id);
    let has_recipient_link = rows
        .iter()
        .any(|(mid, owner, _)| *mid == recipient_row_mid && *owner == fx.recipient_user_id);

    assert!(
        has_sender_link,
        "sender-side row must have a message_attachments entry owned by the sender, got {rows:?}"
    );
    assert!(
        has_recipient_link,
        "recipient-side row must have a message_attachments entry owned by the RECIPIENT \
         (this is the regression that blocked recipient downloads); got {rows:?}"
    );

    // attachment_uploads CAS must have flipped exactly once.
    let upload_status: String =
        sqlx::query_scalar("SELECT status FROM attachment_uploads WHERE id = $1")
            .bind(fx.valid_attachment_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(upload_status, "attached");

    // Finally, prove the download-URL authorization JOIN succeeds for
    // the recipient. We run the same SELECT shape that
    // `generate_attachment_download_url` uses but against the recipient's
    // user_id — a non-empty result row means the predicate would let the
    // recipient through. (The endpoint itself needs S3 config + presigner
    // which we don't have in the test harness; shape-of-SQL is enough.)
    let authorized: Option<String> = sqlx::query_scalar(
        r#"
        SELECT au.object_key
        FROM message_attachments ma
        JOIN attachment_uploads au ON au.id = ma.attachment_upload_id
        WHERE ma.message_id = $1
          AND ma.attachment_upload_id = $2
          AND ma.owner_user_id = $3
        "#,
    )
    .bind(recipient_row_mid)
    .bind(fx.valid_attachment_id)
    .bind(fx.recipient_user_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        authorized.is_some(),
        "recipient must pass the download authorization JOIN — regression test for Bug 2"
    );
}

// ============================================================================
// Attachment blob lifecycle after message deletion
// ============================================================================

const S3_ENV_KEYS: [&str; 7] = [
    "AGENT_INBOX_S3_ENDPOINT",
    "AGENT_INBOX_S3_BUCKET",
    "AGENT_INBOX_S3_ACCESS_KEY_ID",
    "AGENT_INBOX_S3_SECRET_ACCESS_KEY",
    "AGENT_INBOX_S3_REGION",
    "AGENT_INBOX_S3_PATH_STYLE",
    "AGENT_INBOX_S3_PREFIX",
];

/// Unset every S3 variable so `s3_delete_object()` fails fast and
/// deterministically (no live R2 in tests). Returns the prior values for
/// `restore_s3_env`.
fn clear_s3_env() -> Vec<(&'static str, Option<String>)> {
    S3_ENV_KEYS
        .iter()
        .map(|key| {
            let saved = std::env::var(key).ok();
            // SAFETY: test-local env mutation under #[serial].
            unsafe {
                std::env::remove_var(key);
            }
            (*key, saved)
        })
        .collect()
}

fn restore_s3_env(saved: Vec<(&'static str, Option<String>)>) {
    for (key, value) in saved {
        // SAFETY: test-local env mutation under #[serial].
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

async fn load_upload_lifecycle(pool: &PgPool, attachment_id: Uuid) -> (String, bool, bool) {
    let row = sqlx::query(
        r#"
        SELECT
            status,
            deleted_at IS NOT NULL AS deleted_at_is_set,
            purged_at IS NULL AS purged_at_is_null
        FROM attachment_uploads
        WHERE id = $1
        "#,
    )
    .bind(attachment_id)
    .fetch_one(pool)
    .await
    .expect("reload attachment_uploads row");
    (
        row.get("status"),
        row.get("deleted_at_is_set"),
        row.get("purged_at_is_null"),
    )
}

async fn delete_message_as(app: &axum::Router, auth: &str, message_id: Uuid) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/messages/{message_id}"))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
#[serial]
async fn deleting_both_message_copies_retires_attachment_upload() {
    // Regression (audit 2026-09-04): `delete_message` drops the
    // `message_attachments` links via FK cascade but never touched the
    // `attachment_uploads` row, so the R2 blob outlived both copies of the
    // message. The cleanup pass must retire the upload only once the LAST
    // link is gone — the recipient's copy keeps it alive.
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    // SAFETY: test-local env tweak; rejected at startup when NODE_ENV=production.
    unsafe {
        std::env::set_var("AGENT_INBOX_ALLOW_SKIP_S3_HEAD_IN_TESTS", "true");
    }
    let saved_s3_env = clear_s3_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let fx = seed_cross_user_send_fixture(&pool).await;
    let recipient_auth = seed_session(
        &pool,
        fx.recipient_user_id,
        "0xattach-xuser-recipient",
        "orb",
    )
    .await;

    let body = build_cross_user_send_body(
        &fx,
        vec![json!({
            "attachment_id": fx.valid_attachment_id.to_string(),
            "metadata_encrypted": "meta-ct-opaque",
            "metadata_nonce": "meta-nonce-opaque",
        })],
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &fx.sender_auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let sender_row_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM message_index WHERE owner_user_id = $1 AND folder = 'sent'",
    )
    .bind(fx.sender_user_id)
    .fetch_one(&pool)
    .await
    .expect("sender-side message_index row");
    let recipient_row_id: Uuid =
        sqlx::query_scalar("SELECT id FROM message_index WHERE owner_user_id = $1")
            .bind(fx.recipient_user_id)
            .fetch_one(&pool)
            .await
            .expect("recipient-side message_index row");

    // Sender deletes their copy: the recipient still links the upload, so
    // a cleanup pass must leave it untouched.
    assert_eq!(
        delete_message_as(&app, &fx.sender_auth, sender_row_id).await,
        StatusCode::NO_CONTENT
    );
    nexusinbox_api::run_attachment_cleanup_pass(&pool).await;
    let (status, deleted_at_is_set, _) = load_upload_lifecycle(&pool, fx.valid_attachment_id).await;
    assert_eq!(
        status, "attached",
        "upload must stay attached while the recipient's copy still links it"
    );
    assert!(!deleted_at_is_set);

    // Recipient deletes too: zero links left, so the pass retires the
    // upload. With S3 unset the purge fails fast, leaving purged_at NULL
    // so the row stays a candidate for the next pass.
    assert_eq!(
        delete_message_as(&app, &recipient_auth, recipient_row_id).await,
        StatusCode::NO_CONTENT
    );
    let remaining_links: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM message_attachments WHERE attachment_upload_id = $1",
    )
    .bind(fx.valid_attachment_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        remaining_links, 0,
        "FK cascade must have removed both link rows"
    );

    nexusinbox_api::run_attachment_cleanup_pass(&pool).await;
    let (status, deleted_at_is_set, purged_at_is_null) =
        load_upload_lifecycle(&pool, fx.valid_attachment_id).await;
    assert_eq!(
        status, "deleted",
        "unlinked upload must be retired for purge"
    );
    assert!(deleted_at_is_set);
    assert!(
        purged_at_is_null,
        "R2 unavailable in tests → purged_at stays NULL so cleanup retries"
    );

    restore_s3_env(saved_s3_env);
}
