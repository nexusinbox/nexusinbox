//! DB-mode integration tests for multi-device delivery, stage 1 (docs/38):
//!   - resolving an agent lists every active device, newest first;
//!   - a message can carry the content key for each recipient device and
//!     each sender device, and reading it returns both lists;
//!   - a wrap for a device of some other agent is refused.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 DATABASE_URL=postgres://... \
//!     cargo test --test multi_device_delivery_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
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
        "TRUNCATE TABLE message_attachments, attachment_uploads, blocks, message_index, \
         sessions, replay_nonces, agent_identity_keys, agent_identities, agents, users \
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

struct UserAgent {
    auth: String,
    did: String,
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
        auth,
        did,
        signing_key,
    }
}

fn build_send_body(sender: &UserAgent, recipient_did: &str, nonce_marker: u8) -> Value {
    let subject_encrypted = URL_SAFE_NO_PAD.encode(b"subject-ct-xuser");
    let encrypted_content = URL_SAFE_NO_PAD.encode(b"body-ct-xuser");
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
    let signature = sign_envelope(
        &sender.signing_key,
        &sender.did,
        recipient_did,
        &subject_encrypted,
        &encrypted_content,
        &encrypted_key,
        &nonce,
    );
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

fn wrap(marker: u8) -> String {
    format!(
        "x25519v1:{}:{}:{}:{}",
        URL_SAFE_NO_PAD.encode([marker; 32]),
        URL_SAFE_NO_PAD.encode([0u8; 16]),
        URL_SAFE_NO_PAD.encode([0u8; 12]),
        URL_SAFE_NO_PAD.encode([0u8; 48]),
    )
}

/// A computer joins the agent that `did` belongs to, a minute later than
/// the browser key. Returns the computer's DID.
async fn add_device(pool: &PgPool, did: &str, seed: u8) -> String {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let device_did = derive_did_key(&key.verifying_key());
    sqlx::query(
        "INSERT INTO agent_identity_keys \
           (aid, did, signing_public_key, encryption_public_key, status, activated_at) \
         SELECT aid, $2, $3, 'UENfRU5D', 'active', NOW() + INTERVAL '1 minute' \
         FROM agent_identity_keys WHERE did = $1",
    )
    .bind(did)
    .bind(&device_did)
    .bind(URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()))
    .execute(pool)
    .await
    .expect("add device");
    device_did
}

async fn aid_of(pool: &PgPool, did: &str) -> String {
    sqlx::query_scalar("SELECT aid FROM agent_identity_keys WHERE did = $1")
        .bind(did)
        .fetch_one(pool)
        .await
        .expect("aid")
}

async fn request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
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

#[tokio::test]
#[serial]
async fn resolving_an_agent_lists_every_device_newest_first() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_user_with_agent(&pool, "0xmd-alice-1", "alice", 11).await;
    let bob = seed_user_with_agent(&pool, "0xmd-bob-1", "bob", 12).await;
    let bob_pc = add_device(&pool, &bob.did, 13).await;
    let bob_aid = aid_of(&pool, &bob.did).await;

    let (status, body) = request(
        &app,
        "GET",
        &format!("/recipients/resolve?identifier={bob_aid}"),
        &alice.auth,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["did"],
        json!(bob_pc),
        "the newest device stays the single key"
    );
    let devices: Vec<&str> = body["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .map(|d| d["did"].as_str().unwrap())
        .collect();
    assert_eq!(devices, vec![bob_pc.as_str(), bob.did.as_str()]);

    // Resolving by one device's DID lists the whole agent too.
    let (_, by_did) = request(
        &app,
        "GET",
        &format!("/recipients/resolve?identifier={}", bob.did),
        &alice.auth,
        Value::Null,
    )
    .await;
    assert_eq!(by_did["devices"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
#[serial]
async fn a_message_carries_a_wrap_per_device_and_returns_them() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_user_with_agent(&pool, "0xmd-alice-2", "alice", 21).await;
    let alice_pc = add_device(&pool, &alice.did, 22).await;
    let bob = seed_user_with_agent(&pool, "0xmd-bob-2", "bob", 23).await;
    let bob_pc = add_device(&pool, &bob.did, 24).await;

    let mut body = build_send_body(&alice, &bob_pc, 1);
    body["envelope"]["encrypted_keys"] = json!([
        { "did": bob_pc, "key": wrap(1) },
        { "did": bob.did, "key": wrap(2) },
    ]);
    body["envelope"]["sender_encrypted_keys"] = json!([
        { "did": alice.did, "key": wrap(3) },
        { "did": alice_pc, "key": wrap(4) },
    ]);
    let (status, sent) = request(&app, "POST", "/messages", &alice.auth, body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{sent}");
    let id = sent["message_id"].as_str().unwrap();

    let (status, content) = request(
        &app,
        "GET",
        &format!("/messages/{id}/content"),
        &alice.auth,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{content}");
    assert_eq!(content["encrypted_keys"][1]["did"], json!(bob.did));
    assert_eq!(content["encrypted_keys"][1]["key"], json!(wrap(2)));
    assert_eq!(content["sender_encrypted_keys"][1]["did"], json!(alice_pc));
}

#[tokio::test]
#[serial]
async fn a_wrap_for_another_agents_device_is_refused() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let alice = seed_user_with_agent(&pool, "0xmd-alice-3", "alice", 31).await;
    let bob = seed_user_with_agent(&pool, "0xmd-bob-3", "bob", 32).await;
    let carol = seed_user_with_agent(&pool, "0xmd-carol-3", "carol", 33).await;

    let mut body = build_send_body(&alice, &bob.did, 2);
    body["envelope"]["encrypted_keys"] = json!([
        { "did": bob.did, "key": wrap(1) },
        { "did": carol.did, "key": wrap(2) },
    ]);
    let (status, _) = request(&app, "POST", "/messages", &alice.auth, body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let mut body = build_send_body(&alice, &bob.did, 3);
    body["envelope"]["sender_encrypted_keys"] = json!([{ "did": bob.did, "key": wrap(1) }]);
    let (status, _) = request(&app, "POST", "/messages", &alice.auth, body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
