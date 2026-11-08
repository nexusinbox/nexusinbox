//! DB-mode integration tests for pairing codes (docs/31): the web creates a
//! credential with `pairing: true` and shows a short code; the person's
//! machine resolves the code to its credential and activates it with the
//! code as the enrollment secret.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test agent_pairing_db_integration_test -- --test-threads=1

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
        "TRUNCATE TABLE agent_audit_log, agent_tokens, agent_credentials, agent_identity_keys, \
         agent_identities, sessions, agents, users RESTART IDENTITY CASCADE",
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

struct Person {
    user_id: Uuid,
    auth: String,
}

async fn seed_person(pool: &PgPool, wid: &str) -> Person {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, world_id_hash, verification_level) VALUES ($1, $2, 'orb')")
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
    Person {
        user_id,
        auth: format!("Bearer {token}"),
    }
}

/// An agent with an AID, which is what credential creation looks up.
async fn seed_agent(pool: &PgPool, owner: &Person, label: &str) -> (Uuid, String) {
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:test{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, $4, 'pk', 'ek', true)",
    )
    .bind(agent_id)
    .bind(owner.user_id)
    .bind(format!("did:key:z{}", Uuid::new_v4().simple()))
    .bind(label)
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
    (agent_id, aid)
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn resolve(app: &axum::Router, ip: &str, code: &str) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        "/agent-pairing/resolve",
        &[("x-forwarded-for", ip)],
        Some(json!({ "pairing_code": code })),
    )
    .await
}

async fn create_credential(
    app: &axum::Router,
    owner: &Person,
    agent_id: Uuid,
    pairing: bool,
) -> Value {
    let (status, body) = call(
        app,
        "POST",
        "/agent-credentials",
        &[("authorization", &owner.auth)],
        Some(json!({ "agent_id": agent_id, "label": "このパソコン", "pairing": pairing })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

/// What the daemon sends: fresh keys and a proof bound to the credential.
fn activation_body(credential_id: &str, secret: &str, device_label: Option<&str>) -> Value {
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    let header = b64(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = b64(json!({
        "credential_id": credential_id,
        "iat": chrono::Utc::now().timestamp(),
    })
    .to_string()
    .as_bytes());
    let signature = key.sign(format!("{header}.{claims}").as_bytes());
    let mut body = json!({
        "enrollment_secret": secret,
        "signing_public_key": b64(&key.verifying_key().to_bytes()),
        "encryption_public_key": b64(&[7u8; 32]),
        "enrollment_proof": format!("{header}.{claims}.{}", b64(&signature.to_bytes())),
        "key_holder": "signer_daemon",
    });
    if let Some(label) = device_label {
        body["device_label"] = json!(label);
    }
    body
}

async fn activate(app: &axum::Router, credential_id: &str, body: Value) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        &format!("/agent-credentials/{credential_id}/activate"),
        &[],
        Some(body),
    )
    .await
}

async fn credential_row(pool: &PgPool, credential_id: &str) -> (String, String, Option<String>) {
    let row = sqlx::query(
        "SELECT status, label, enrollment_hash FROM agent_credentials WHERE id = $1::uuid",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    (
        row.get("status"),
        row.get("label"),
        row.get("enrollment_hash"),
    )
}

fn is_pairing_code(code: &str) -> bool {
    let symbols = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    code.len() == 11
        && code.char_indices().all(|(i, c)| {
            if i == 5 {
                c == '-'
            } else {
                symbols.contains(c)
            }
        })
}

macro_rules! db_test_prelude {
    () => {{
        if !db_tests_enabled() {
            eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
            return;
        }
        ensure_db_env();
        let app = common::test_app();
        let pool = db_pool().await;
        reset_schema(&pool).await;
        (app, pool)
    }};
}

#[tokio::test]
#[serial]
async fn a_pairing_code_connects_one_machine_once() {
    let (app, pool) = db_test_prelude!();
    let owner = seed_person(&pool, "0xpairing-owner").await;
    let (agent_id, aid) = seed_agent(&pool, &owner, "秘書").await;

    let created = create_credential(&app, &owner, agent_id, true).await;
    let code = created["pairing_code"]
        .as_str()
        .expect("pairing code")
        .to_string();
    assert!(is_pairing_code(&code), "{code}");
    assert!(created["enrollment_secret"].is_null(), "{created}");
    let credential_id = created["credential_id"].as_str().unwrap().to_string();

    // Valid for 10 minutes, and stored only as the hash of the code.
    let expires =
        chrono::DateTime::parse_from_rfc3339(created["enrollment_expires_at"].as_str().unwrap())
            .unwrap();
    let left = expires.signed_duration_since(chrono::Utc::now());
    assert!(
        left > chrono::Duration::minutes(9) && left <= chrono::Duration::minutes(10),
        "{left}"
    );
    let normalized = code.replace('-', "");
    let (_, _, stored) = credential_row(&pool, &credential_id).await;
    assert_eq!(
        stored.as_deref(),
        Some(hex::encode(Sha256::digest(normalized.as_bytes())).as_str())
    );

    // The machine looks the code up as the person typed it.
    let typed = format!(" {} ", code.to_lowercase());
    let (status, found) = resolve(&app, "203.0.113.10", &typed).await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["credential_id"], credential_id.as_str());
    assert_eq!(found["aid"], aid.as_str());
    assert_eq!(found["agent_label"], "秘書");

    // ...and activates with it, naming itself.
    let (status, body) = activate(
        &app,
        &credential_id,
        activation_body(&credential_id, &code.to_lowercase(), Some("MacBook-Air")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status_now, label, hash) = credential_row(&pool, &credential_id).await;
    assert_eq!(status_now, "active");
    assert_eq!(label, "MacBook-Air");
    assert_eq!(hash, None);

    // The code is spent: it resolves to nothing and activates nothing.
    let (status, _) = resolve(&app, "203.0.113.10", &code).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = activate(
        &app,
        &credential_id,
        activation_body(&credential_id, &code, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn an_expired_pairing_code_resolves_to_nothing() {
    let (app, pool) = db_test_prelude!();
    let owner = seed_person(&pool, "0xpairing-expired").await;
    let (agent_id, _) = seed_agent(&pool, &owner, "agent").await;
    let created = create_credential(&app, &owner, agent_id, true).await;
    let code = created["pairing_code"].as_str().unwrap();
    let credential_id = created["credential_id"].as_str().unwrap();

    sqlx::query(
        "UPDATE agent_credentials SET enrollment_expires = NOW() - INTERVAL '1 second' \
         WHERE id = $1::uuid",
    )
    .bind(credential_id)
    .execute(&pool)
    .await
    .unwrap();

    let (status, _) = resolve(&app, "203.0.113.11", code).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = activate(
        &app,
        credential_id,
        activation_body(credential_id, code, None),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(credential_row(&pool, credential_id).await.0, "pending");
}

#[tokio::test]
#[serial]
async fn malformed_codes_are_refused_and_unknown_ones_are_not_found() {
    let (app, _pool) = db_test_prelude!();
    for bad in ["", "ABC", "7KQ4P-ZX9M", "7KQ4P-ZX9MU", "ens_abcdefghij"] {
        let (status, _) = resolve(&app, "203.0.113.12", bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}");
    }
    let (status, _) = resolve(&app, "203.0.113.13", "00000-00000").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn lookups_are_limited_per_ip() {
    let (app, _pool) = db_test_prelude!();
    for attempt in 0..10 {
        let (status, _) = resolve(&app, "203.0.113.20", "00000-00000").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "attempt {attempt}");
    }
    let (status, body) = resolve(&app, "203.0.113.20", "00000-00000").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    // Malformed codes count too, so they cannot be used to probe for free.
    let (status, _) = resolve(&app, "203.0.113.20", "x").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // Another address has its own budget.
    let (status, _) = resolve(&app, "203.0.113.21", "00000-00000").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn enrollment_secrets_work_as_before_and_never_resolve() {
    let (app, pool) = db_test_prelude!();
    let owner = seed_person(&pool, "0xpairing-classic").await;
    let (agent_id, _) = seed_agent(&pool, &owner, "agent").await;
    let created = create_credential(&app, &owner, agent_id, false).await;
    let secret = created["enrollment_secret"].as_str().unwrap();
    assert!(secret.starts_with("ens_"));
    assert!(created.get("pairing_code").is_none(), "{created}");
    let credential_id = created["credential_id"].as_str().unwrap();

    let (status, _) = resolve(&app, "203.0.113.30", secret).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // No device label: the label set on the web stays.
    let (status, body) = activate(
        &app,
        credential_id,
        activation_body(credential_id, secret, Some(" \t ")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status_now, label, _) = credential_row(&pool, credential_id).await;
    assert_eq!(status_now, "active");
    assert_eq!(label, "このパソコン");
}
