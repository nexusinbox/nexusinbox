//! DB-mode integration tests for provider-agnostic identities and
//! per-person limits (docs/30).
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test identity_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
use sha2::{Digest, Sha256};
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
        "TRUNCATE TABLE user_send_counters, user_identities, agent_audit_log, agent_tokens, \
         agent_credentials, message_attachments, attachment_uploads, blocks, message_index, \
         sessions, replay_nonces, agent_identity_keys, agent_identities, agents, users \
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

/// Sets an env var for one test and restores the previous value on drop.
struct EnvGuard {
    name: &'static str,
    saved: Option<String>,
}

impl EnvGuard {
    fn set(name: &'static str, value: &str) -> Self {
        let saved = std::env::var(name).ok();
        // SAFETY: test-local env mutation under #[serial]; restored on drop.
        unsafe {
            std::env::set_var(name, value);
        }
        Self { name, saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: restore env.
        unsafe {
            match &self.saved {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }
}

fn hash_b64(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

fn derive_did_key(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    let mut multicodec = Vec::with_capacity(34);
    multicodec.push(0xed);
    multicodec.push(0x01);
    multicodec.extend_from_slice(&verifying_key.to_bytes());
    format!("did:key:z{}", bs58::encode(&multicodec).into_string())
}

struct Person {
    user_id: Uuid,
    session: String,
}

/// A person with a World ID hash and a browser session whose JWT carries
/// `session_wid`, the value old sessions carried (the raw nullifier).
async fn seed_person(pool: &PgPool, world_id_hash: &str, session_wid: &str) -> Person {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, world_id_hash, verification_level) VALUES ($1, $2, 'orb')")
        .bind(user_id)
        .bind(world_id_hash)
        .execute(pool)
        .await
        .expect("seed user");
    let (token, jwt_id, exp) =
        nexusinbox_api::issue_dev_session(&user_id.to_string(), session_wid, "orb", 60 * 60);
    sqlx::query(
        "INSERT INTO sessions (user_id, jwt_id, expires_at) VALUES ($1, $2, to_timestamp($3))",
    )
    .bind(user_id)
    .bind(&jwt_id)
    .bind(exp)
    .execute(pool)
    .await
    .expect("seed session");
    Person {
        user_id,
        session: format!("Bearer {token}"),
    }
}

struct Agent {
    did: String,
    signing_key: SigningKey,
}

async fn seed_agent(pool: &PgPool, owner: &Person, seed_byte: u8) -> Agent {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    let signing_key = SigningKey::from_bytes(&seed);
    let did = derive_did_key(&signing_key.verifying_key());
    let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:idt{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'agent', $4, $5, true)",
    )
    .bind(agent_id)
    .bind(owner.user_id)
    .bind(&did)
    .bind(&public_key)
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
    .bind(&public_key)
    .bind("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
    .execute(pool)
    .await
    .expect("seed identity key");
    Agent { did, signing_key }
}

fn send_body(sender: &Agent, recipient_did: &str, nonce_marker: u8) -> Value {
    let subject_encrypted = URL_SAFE_NO_PAD.encode(b"subject-ct-identity");
    let encrypted_content = URL_SAFE_NO_PAD.encode(b"body-ct-identity");
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

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(auth) = auth {
        builder = builder.header("authorization", auth);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
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
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body, cookie)
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
async fn login_twice_keeps_one_account_and_stores_no_raw_nullifier() {
    skip_without_db!();
    let app = common::test_app_with_mock_world_verify();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let nullifier = format!("0xnullifier-{}", Uuid::new_v4().simple());
    let proof = json!({
        "proof": "0xproof",
        "merkle_root": "0xroot",
        "nullifier_hash": nullifier,
        "verification_level": "orb",
        "action": "login",
        "signal": ""
    });

    let (status, first, cookie) =
        call(&app, "POST", "/auth/verify", None, Some(proof.clone())).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    // A World ID nullifier is the same on every login, so clear the replay
    // window instead of waiting it out.
    sqlx::query("DELETE FROM replay_nonces")
        .execute(&pool)
        .await
        .unwrap();
    let (status, second, _) = call(&app, "POST", "/auth/verify", None, Some(proof)).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        first["user"]["id"], second["user"]["id"],
        "the same person gets the same account"
    );

    let subject = hash_b64(&nullifier);
    let identities: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_identities \
         WHERE provider = 'world_id' AND subject_hash = $1 AND assurance = 'high'",
    )
    .bind(&subject)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(identities, 1);
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1);
    let raw_kept: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE nullifier_hash IS NOT NULL OR world_id_hash <> $1",
    )
    .bind(&subject)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(raw_kept, 0, "only the hash is stored");
    let replay_raw: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM replay_nonces WHERE replay_key LIKE $1")
            .bind(format!("%{nullifier}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(replay_raw, 0, "the replay key uses the hash too");

    // The session cookie carries the hash, not the raw nullifier.
    let cookie = cookie.expect("session cookie");
    let jwt = cookie
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("nexusinbox_session=");
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["wid"], json!(subject));
}

#[tokio::test]
#[serial]
async fn blocked_person_cannot_send_from_a_browser_session() {
    // Regression (docs/30 §2): the session JWT carried the raw nullifier and
    // send_message matched blocks against it, so a person blocked at the
    // human level still got through from the browser.
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let recipient = seed_person(&pool, "hash-recipient", "raw-recipient").await;
    let blocked = seed_person(&pool, "hash-blocked", "raw-nullifier-of-blocked").await;
    let recipient_agent = seed_agent(&pool, &recipient, 0x31).await;
    let blocked_agent = seed_agent(&pool, &blocked, 0x32).await;
    sqlx::query(
        "INSERT INTO blocks (owner_user_id, level, target_world_id) \
         VALUES ($1, 'l2_identity', 'hash-blocked')",
    )
    .bind(recipient.user_id)
    .execute(&pool)
    .await
    .unwrap();

    let (status, body, _) = call(
        &app,
        "POST",
        "/messages",
        Some(&blocked.session),
        Some(send_body(&blocked_agent, &recipient_agent.did, 0x33)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let delivered: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(recipient.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(delivered, 0, "nothing reaches the person who blocked");
}

#[tokio::test]
#[serial]
async fn daily_send_limit_is_shared_across_a_persons_agents() {
    skip_without_db!();
    let _limit = EnvGuard::set("AGENT_INBOX_SEND_LIMIT_PER_HUMAN_PER_DAY", "2");
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let recipient = seed_person(&pool, "hash-r", "raw-r").await;
    let sender = seed_person(&pool, "hash-s", "raw-s").await;
    let recipient_agent = seed_agent(&pool, &recipient, 0x41).await;
    let first_agent = seed_agent(&pool, &sender, 0x42).await;
    let second_agent = seed_agent(&pool, &sender, 0x43).await;

    for (agent, nonce, expected) in [
        (&first_agent, 0x44, StatusCode::ACCEPTED),
        (&second_agent, 0x45, StatusCode::ACCEPTED),
        // A third send is refused, whichever agent it comes from.
        (&first_agent, 0x46, StatusCode::TOO_MANY_REQUESTS),
    ] {
        let (status, body, _) = call(
            &app,
            "POST",
            "/messages",
            Some(&sender.session),
            Some(send_body(agent, &recipient_agent.did, nonce)),
        )
        .await;
        assert_eq!(status, expected, "{body}");
    }
    // The other person's budget is untouched.
    let (status, body, _) = call(
        &app,
        "POST",
        "/messages",
        Some(&recipient.session),
        Some(send_body(&recipient_agent, &first_agent.did, 0x47)),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

#[tokio::test]
#[serial]
async fn agent_count_is_capped_per_person() {
    skip_without_db!();
    let _cap = EnvGuard::set("AGENT_INBOX_MAX_AGENTS_PER_HUMAN", "2");
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let person = seed_person(&pool, "hash-cap", "raw-cap").await;

    for (i, expected) in [
        (1u8, StatusCode::CREATED),
        (2, StatusCode::CREATED),
        (3, StatusCode::CONFLICT),
    ] {
        let mut seed = [0u8; 32];
        seed[0] = 0x50 + i;
        let public_key =
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let (status, body, _) = call(
            &app,
            "POST",
            "/agents",
            Some(&person.session),
            Some(json!({
                "label": format!("agent-{i}"),
                "public_key": public_key,
                "encryption_key": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU",
            })),
        )
        .await;
        assert_eq!(status, expected, "agent {i}: {body}");
    }
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE user_id = $1")
        .bind(person.user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(agents, 2);
    let identities: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_identities WHERE user_id = $1")
            .bind(person.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(identities, 2, "each created agent got its identity row");
}
