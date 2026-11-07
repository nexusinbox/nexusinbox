//! DB-mode integration tests for self-service account deletion
//! (DELETE /auth/account, docs/28 §5 P2).
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test account_deletion_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
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
    let aid = format!("aid:ai:del{}", Uuid::new_v4().simple());
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

fn build_send_body(sender: &UserAgent, recipient_did: &str, nonce_marker: u8) -> Value {
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
    let payload = format!(
        "{}\n{recipient_did}\n{subject_encrypted}\n{encrypted_content}\n{encrypted_key}\n{nonce}",
        sender.did
    );
    let signature = URL_SAFE_NO_PAD.encode(sender.signing_key.sign(payload.as_bytes()).to_bytes());
    json!({
        "sender_did": sender.did,
        "recipient_did": recipient_did,
        "envelope": {
            "encrypted_content": encrypted_content,
            "encrypted_key": encrypted_key,
            "nonce": nonce,
            "signature": signature,
            "metadata": {
                "subject_encrypted": subject_encrypted,
                "thread_id": null,
                "content_type": "text/plain",
                "has_attachments": false,
            }
        },
        "priority": "normal",
    })
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
                    build_send_body(from, &to.did, nonce_marker).to_string(),
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

/// A second agent for an existing person (for a same-person send).
async fn seed_extra_agent(pool: &PgPool, owner: &UserAgent, seed_byte: u8) -> UserAgent {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    let signing_key = SigningKey::from_bytes(&seed);
    let did = derive_did_key(&signing_key.verifying_key());
    let public_key_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:del{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'agent', $4, $5, true)",
    )
    .bind(agent_id)
    .bind(owner.user_id)
    .bind(&did)
    .bind(&public_key_b64)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(agent_id)
        .bind(owner.user_id)
        .execute(pool)
        .await
        .expect("seed agent identity");
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
        user_id: owner.user_id,
        auth: owner.auth.clone(),
        did,
        aid,
        signing_key,
    }
}

async fn seed_upload(pool: &PgPool, owner: Uuid, sender_did: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO attachment_uploads \
           (id, owner_user_id, sender_did, r2_bucket, object_key, ciphertext_size_limit, \
            ciphertext_size_bytes, status, upload_expires_at, uploaded_at) \
         VALUES ($1, $2, $3, 'bucket', $4, 1024, 10, 'attached', NOW(), NOW())",
    )
    .bind(id)
    .bind(owner)
    .bind(sender_did)
    .bind(format!("attachments/{owner}/none/{id}/blob.bin"))
    .execute(pool)
    .await
    .expect("seed upload");
    id
}

async fn link_upload(
    pool: &PgPool,
    message_id: Uuid,
    upload: Uuid,
    owner: Uuid,
    from: &str,
    to: &str,
) {
    sqlx::query(
        "INSERT INTO message_attachments \
           (message_id, attachment_upload_id, owner_user_id, sender_did, recipient_did, \
            metadata_encrypted, metadata_nonce, ciphertext_size_bytes) \
         VALUES ($1, $2, $3, $4, $5, 'meta-ct', 'meta-nonce', 10)",
    )
    .bind(message_id)
    .bind(upload)
    .bind(owner)
    .bind(from)
    .bind(to)
    .execute(pool)
    .await
    .expect("link upload");
}

async fn delete_account(app: &axum::Router, auth: &str) -> (StatusCode, Value, Option<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth/account")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookie,
    )
}

async fn users_with_id(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn recent_sign_in_deletes_the_account_and_keeps_the_other_persons_copy() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let storage = StorageRoot::new();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_user_with_agent(&pool, "0xalice-delete", 0x61).await;
    let bob = seed_user_with_agent(&pool, "0xbob-delete", 0x62).await;
    let alice2 = seed_extra_agent(&pool, &alice, 0x63).await;

    // Alice -> Bob: two rows, one shared blob. Alice -> Alice: one row, her blob.
    let to_bob = send(&app, &alice, &bob, 0x64).await;
    let own = send(&app, &alice, &alice2, 0x65).await;
    assert_eq!(count_json_files(&storage.path), 2);
    let bob_row: Uuid = sqlx::query_scalar("SELECT id FROM message_index WHERE owner_user_id = $1")
        .bind(bob.user_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // An attachment Alice shared with Bob, and one only she references.
    let shared = seed_upload(&pool, alice.user_id, &alice.did).await;
    link_upload(&pool, to_bob, shared, alice.user_id, &alice.did, &bob.did).await;
    link_upload(&pool, bob_row, shared, bob.user_id, &alice.did, &bob.did).await;
    let private = seed_upload(&pool, alice.user_id, &alice.did).await;
    link_upload(&pool, own, private, alice.user_id, &alice.did, &alice2.did).await;

    // Things that must go with the account.
    sqlx::query(
        "INSERT INTO user_identities (user_id, provider, subject_hash, assurance) \
         VALUES ($1, 'world_id', 'alice-subject', 'high')",
    )
    .bind(alice.user_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO contacts (owner_user_id, did, sealed) VALUES ($1, $2, 'cs1:aXY:Y3Q')")
        .bind(alice.user_id)
        .bind(&bob.did)
        .execute(&pool)
        .await
        .unwrap();

    let (status, body, cookie) = delete_account(&app, &alice.auth).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(
        cookie.unwrap_or_default().contains("Max-Age=0"),
        "the session cookie is cleared"
    );

    assert_eq!(users_with_id(&pool, alice.user_id).await, 0);
    for (table, column) in [
        ("agents", "user_id"),
        ("agent_identities", "user_id"),
        ("sessions", "user_id"),
        ("user_identities", "user_id"),
        ("contacts", "owner_user_id"),
        ("message_index", "owner_user_id"),
        ("message_attachments", "owner_user_id"),
        ("attachment_uploads", "owner_user_id"),
    ] {
        let n: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column} = $1"))
                .bind(alice.user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 0, "{table} still holds rows of the deleted person");
    }

    // Bob keeps his copy: the row, the shared blob, and the attachment.
    assert_eq!(users_with_id(&pool, bob.user_id).await, 1);
    let bob_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(bob.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bob_rows, 1);
    assert_eq!(
        count_json_files(&storage.path),
        1,
        "only Alice's own blob is removed"
    );
    let shared_owner: Uuid =
        sqlx::query_scalar("SELECT owner_user_id FROM attachment_uploads WHERE id = $1")
            .bind(shared)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        shared_owner, bob.user_id,
        "the shared attachment is handed to Bob"
    );
    let private_left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM attachment_uploads WHERE id = $1")
            .bind(private)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(private_left, 0);
}

#[tokio::test]
#[serial]
async fn stale_sign_in_must_prove_the_person_again() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_user_with_agent(&pool, "0xalice-stale", 0x71).await;
    sqlx::query("UPDATE sessions SET issued_at = NOW() - INTERVAL '1 hour' WHERE user_id = $1")
        .bind(alice.user_id)
        .execute(&pool)
        .await
        .unwrap();

    let (status, body, _) = delete_account(&app, &alice.auth).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], json!("reauthentication_required"));
    assert_eq!(
        users_with_id(&pool, alice.user_id).await,
        1,
        "nothing is deleted"
    );
}

#[tokio::test]
#[serial]
async fn agent_token_cannot_delete_the_account() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_user_with_agent(&pool, "0xalice-agent", 0x81).await;
    let credential_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'test', 'active', 'unused', NOW())",
    )
    .bind(credential_id)
    .bind(&alice.aid)
    .bind(alice.user_id)
    .execute(&pool)
    .await
    .unwrap();
    let access = format!("agt_test{}", Uuid::new_v4().simple());
    let access_hash: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(access.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    sqlx::query(
        "INSERT INTO agent_tokens \
           (credential_id, access_hash, refresh_hash, dpop_jkt, scopes, \
            access_expires_at, refresh_expires_at) \
         VALUES ($1, $2, $3, 'none', ARRAY['messages.read','messages.send','messages.delete'], \
           NOW() + interval '1 hour', NOW() + interval '1 day')",
    )
    .bind(credential_id)
    .bind(access_hash)
    .bind(Uuid::new_v4().simple().to_string())
    .execute(&pool)
    .await
    .unwrap();

    let (status, _, _) = delete_account(&app, &format!("Bearer {access}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(users_with_id(&pool, alice.user_id).await, 1);
}
