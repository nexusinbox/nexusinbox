//! DB-mode integration tests for how agent tokens follow their credential:
//!   - a self-revoked token is not mistaken for refresh-token reuse;
//!   - rotating a credential ends its existing tokens and can be completed
//!     with the new enrollment secret;
//!   - a credential without its own key never borrows another device's key;
//!   - a token carries the scopes its assertion asked for, not the
//!     credential's whole allowance.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 DATABASE_URL=postgres://... \
//!     cargo test --test agent_token_lifecycle_db_integration_test -- --test-threads=1

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

const HOST: &str = "api.lifecycle.test";

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

fn ensure_db_env() {
    unsafe {
        std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn public_key(key: &SigningKey) -> String {
    b64(&key.verifying_key().to_bytes())
}

fn new_key() -> SigningKey {
    SigningKey::from_bytes(&rand::random::<[u8; 32]>())
}

fn sign_jws(key: &SigningKey, payload: Value) -> String {
    let header = b64(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = b64(payload.to_string().as_bytes());
    let input = format!("{header}.{payload}");
    format!("{input}.{}", b64(&key.sign(input.as_bytes()).to_bytes()))
}

struct Fixture {
    auth: String,
    aid: String,
    credential_id: Uuid,
    computer_key: SigningKey,
    browser_key: SigningKey,
}

/// A user with one agent: a browser key and one connected computer, each
/// with a real Ed25519 key. The computer's credential allows `scopes`.
async fn seed(pool: &PgPool, tag: &str, scopes: &[&str]) -> Fixture {
    let user_id = Uuid::new_v4();
    let wid = format!("0xlifecycle-{tag}");
    sqlx::query(
        "INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) \
         VALUES ($1, $2, $2, 'orb')",
    )
    .bind(user_id)
    .bind(&wid)
    .execute(pool)
    .await
    .expect("seed user");
    let (token, jwt_id, exp) =
        nexusinbox_api::issue_dev_session(&user_id.to_string(), &wid, "orb", 60 * 60);
    sqlx::query(
        "INSERT INTO sessions (user_id, jwt_id, expires_at) VALUES ($1, $2, to_timestamp($3))",
    )
    .bind(user_id)
    .bind(&jwt_id)
    .bind(exp)
    .execute(pool)
    .await
    .expect("seed session");

    let browser_key = new_key();
    let computer_key = new_key();
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:life{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'secretary', $4, 'BROWSER_ENC', true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(format!("did:key:zbrowser{}", Uuid::new_v4().simple()))
    .bind(public_key(&browser_key))
    .execute(pool)
    .await
    .expect("seed agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(agent_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed identity");
    for (key, enc, name) in [
        (&browser_key, "BROWSER_ENC", "browser"),
        (&computer_key, "PC_ENC", "pc"),
    ] {
        sqlx::query(
            "INSERT INTO agent_identity_keys \
               (aid, did, signing_public_key, encryption_public_key, status, activated_at) \
             VALUES ($1, $2, $3, $4, 'active', NOW() - INTERVAL '1 hour')",
        )
        .bind(&aid)
        .bind(format!("did:key:z{name}{}", Uuid::new_v4().simple()))
        .bind(public_key(key))
        .bind(enc)
        .execute(pool)
        .await
        .expect("seed key");
    }

    let credential_id = Uuid::new_v4();
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO agent_credentials (id, aid, user_id, label, status, allowed_scopes, \
           signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'macOS', 'active', $4, $5, NOW())",
    )
    .bind(credential_id)
    .bind(&aid)
    .bind(user_id)
    .bind(&scopes)
    .bind(public_key(&computer_key))
    .execute(pool)
    .await
    .expect("seed credential");

    Fixture {
        auth: format!("Bearer {token}"),
        aid,
        credential_id,
        computer_key,
        browser_key,
    }
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST)
        .header("content-type", "application/json");
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// POST /agent-auth/token with an assertion for the fixture's credential.
async fn issue(
    app: &axum::Router,
    f: &Fixture,
    key: &SigningKey,
    scope: &str,
) -> (StatusCode, Value) {
    let now = chrono::Utc::now().timestamp();
    let assertion = sign_jws(
        key,
        json!({
            "iss": f.aid,
            "sub": f.credential_id.to_string(),
            "aud": format!("https://{HOST}/agent-auth/token"),
            "jti": Uuid::new_v4().to_string(),
            "iat": now,
            "exp": now + 60,
            "scope": scope,
        }),
    );
    send(
        app,
        "POST",
        "/agent-auth/token",
        None,
        json!({ "assertion": assertion }),
    )
    .await
}

async fn refresh(app: &axum::Router, refresh_token: &str) -> (StatusCode, Value) {
    send(
        app,
        "POST",
        "/agent-auth/refresh",
        None,
        json!({ "refresh_token": refresh_token }),
    )
    .await
}

async fn list_messages(app: &axum::Router, f: &Fixture, access_token: &str) -> StatusCode {
    let uri = format!("/messages?agent_did={}&folder=inbox&status=all", f.aid);
    let auth = format!("Bearer {access_token}");
    send(app, "GET", &uri, Some(&auth), Value::Null).await.0
}

async fn credential_status(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM agent_credentials WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("credential row")
}

fn token_of(body: &Value, field: &str) -> String {
    body[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} in {body}"))
        .to_string()
}

macro_rules! db_test_setup {
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
async fn revoking_an_access_token_is_not_taken_for_refresh_reuse() {
    let (app, pool) = db_test_setup!();
    let f = seed(&pool, "self-revoke", &["messages.read", "messages.send"]).await;
    let (status, body) = issue(&app, &f, &f.computer_key, "messages.read messages.send").await;
    assert_eq!(status, StatusCode::OK, "issue failed: {body}");
    let access = token_of(&body, "access_token");
    let refresh_token = token_of(&body, "refresh_token");

    // Someone holding only the access token revokes it.
    let (status, _) = send(
        &app,
        "POST",
        "/agent-auth/revoke",
        None,
        json!({ "token": access }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The gateway's next refresh is refused, but plainly: no reuse alarm.
    let (status, body) = refresh(&app, &refresh_token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_ne!(
        body["error"], "token_reuse_detected",
        "self-revoke must not look like reuse: {body}"
    );
    assert_eq!(credential_status(&pool, f.credential_id).await, "active");

    // And it can start again from a new assertion.
    let (status, body) = issue(&app, &f, &f.computer_key, "messages.read messages.send").await;
    assert_eq!(status, StatusCode::OK, "re-issue failed: {body}");
}

#[tokio::test]
#[serial]
async fn reusing_a_rotated_refresh_token_still_compromises_the_credential() {
    let (app, pool) = db_test_setup!();
    let f = seed(&pool, "reuse", &["messages.read", "messages.send"]).await;
    let (status, body) = issue(&app, &f, &f.computer_key, "messages.read messages.send").await;
    assert_eq!(status, StatusCode::OK, "issue failed: {body}");
    let first = token_of(&body, "refresh_token");

    let (status, body) = refresh(&app, &first).await;
    assert_eq!(status, StatusCode::OK, "refresh failed: {body}");
    let (status, body) = refresh(&app, &first).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "token_reuse_detected");
    assert_eq!(
        credential_status(&pool, f.credential_id).await,
        "compromised"
    );
}

#[tokio::test]
#[serial]
async fn rotation_ends_existing_tokens_and_completes_with_the_new_secret() {
    let (app, pool) = db_test_setup!();
    let f = seed(&pool, "rotate", &["messages.read", "messages.send"]).await;
    let (status, body) = issue(&app, &f, &f.computer_key, "messages.read messages.send").await;
    assert_eq!(status, StatusCode::OK, "issue failed: {body}");
    let access = token_of(&body, "access_token");
    let refresh_token = token_of(&body, "refresh_token");
    assert_eq!(list_messages(&app, &f, &access).await, StatusCode::OK);

    let uri = format!("/agent-credentials/{}/rotate", f.credential_id);
    let (status, body) = send(&app, "POST", &uri, Some(&f.auth), json!({})).await;
    assert_eq!(status, StatusCode::OK, "rotate failed: {body}");
    let secret = token_of(&body, "enrollment_secret");

    // The tokens from before the rotation stop working at once.
    assert_eq!(
        list_messages(&app, &f, &access).await,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = refresh(&app, &refresh_token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // No device's key can mint tokens for it until it is re-activated.
    for key in [&f.computer_key, &f.browser_key] {
        let (status, body) = issue(&app, &f, key, "messages.read").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "issued mid-rotation: {body}"
        );
    }

    // The new secret re-activates it with a new key.
    let new = new_key();
    let iat = chrono::Utc::now().timestamp();
    let proof = sign_jws(
        &new,
        json!({ "credential_id": f.credential_id.to_string(), "iat": iat }),
    );
    let uri = format!("/agent-credentials/{}/activate", f.credential_id);
    let (status, body) = send(
        &app,
        "POST",
        &uri,
        None,
        json!({
            "enrollment_secret": secret,
            "signing_public_key": public_key(&new),
            "encryption_public_key": "PC_ENC_2",
            "enrollment_proof": proof,
            "key_holder": "signer_daemon",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-activation failed: {body}");

    let (status, _) = issue(&app, &f, &f.computer_key, "messages.read").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the old key must not work after rotation"
    );
    let (status, body) = issue(&app, &f, &new, "messages.read").await;
    assert_eq!(status, StatusCode::OK, "the new key must work: {body}");
}

#[tokio::test]
#[serial]
async fn a_credential_without_its_own_key_never_borrows_another_devices_key() {
    let (app, pool) = db_test_setup!();
    let f = seed(&pool, "no-key", &["messages.read", "messages.send"]).await;
    sqlx::query("UPDATE agent_credentials SET signing_public_key = NULL WHERE id = $1")
        .bind(f.credential_id)
        .execute(&pool)
        .await
        .expect("clear key");
    for key in [&f.browser_key, &f.computer_key] {
        let (status, body) = issue(&app, &f, key, "messages.read").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "issued without the credential's key: {body}"
        );
    }
}

#[tokio::test]
#[serial]
async fn a_token_carries_the_scopes_its_assertion_asked_for() {
    let (app, pool) = db_test_setup!();
    let f = seed(
        &pool,
        "scope",
        &["messages.read", "messages.send", "messages.delete"],
    )
    .await;

    let (status, body) = issue(&app, &f, &f.computer_key, "messages.read").await;
    assert_eq!(status, StatusCode::OK, "issue failed: {body}");
    let access = token_of(&body, "access_token");
    let stored: Vec<String> =
        sqlx::query_scalar("SELECT scopes FROM agent_tokens WHERE access_hash = $1")
            .bind(hex::encode(Sha256::digest(access.as_bytes())))
            .fetch_one(&pool)
            .await
            .expect("token row");
    assert_eq!(stored, vec!["messages.read".to_string()]);

    // A refresh keeps the narrower set.
    let (status, body) = refresh(&app, &token_of(&body, "refresh_token")).await;
    assert_eq!(status, StatusCode::OK, "refresh failed: {body}");
    assert_eq!(body["scope"], "messages.read");

    // An assertion that asks for nothing gets nothing.
    let (status, _) = issue(&app, &f, &f.computer_key, "").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
