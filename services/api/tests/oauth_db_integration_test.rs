//! DB-mode integration tests for OAuth 2.1 for cloud AIs (docs/33 §10):
//! the computer's MCP URL, app registration, consent, tokens with PKCE,
//! introspection by the computer, refresh rotation, and disconnecting.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test oauth_db_integration_test -- --test-threads=1

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
        "TRUNCATE TABLE agent_audit_log, agent_tokens, agent_credentials, message_attachments, \
         attachment_uploads, blocks, message_index, sessions, replay_nonces, \
         agent_identity_keys, agent_identities, agents, users RESTART IDENTITY CASCADE",
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

#[allow(clippy::too_many_arguments, dead_code)]
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
    user_id: Uuid,
    auth: String,
    did: String,
    aid: String,
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
        user_id,
        auth,
        did,
        aid,
        signing_key,
    }
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Plain-bearer agent token for `agent` with `messages.read` + `messages.send`.
async fn seed_agent_token(pool: &PgPool, agent: &UserAgent) -> String {
    let credential_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, signing_public_key, activated_at, key_holder) \
         VALUES ($1, $2, $3, 'test', 'active', 'unused', NOW(), 'signer_daemon')",
    )
    .bind(credential_id)
    .bind(&agent.aid)
    .bind(agent.user_id)
    .execute(pool)
    .await
    .expect("seed credential");
    let access = format!("agt_test{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agent_tokens \
           (credential_id, access_hash, refresh_hash, dpop_jkt, scopes, \
            access_expires_at, refresh_expires_at) \
         VALUES ($1, $2, $3, 'none', $4, NOW() + interval '1 hour', NOW() + interval '1 day')",
    )
    .bind(credential_id)
    .bind(sha256_hex(&access))
    .bind(sha256_hex(&format!("agr_{access}")))
    .bind(vec![
        "messages.read".to_string(),
        "messages.send".to_string(),
    ])
    .execute(pool)
    .await
    .expect("seed token");
    format!("Bearer {access}")
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
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

async fn form(app: &axum::Router, uri: &str, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
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

fn urlencode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn query(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

const REDIRECT: &str = "https://ai.example/oauth/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

struct Setup {
    app: axum::Router,
    pool: PgPool,
    me: UserAgent,
    agent: String,
    resource: String,
    client_id: String,
}

async fn setup(pool: PgPool, wid: &str, seed: u8) -> Setup {
    let app = common::test_app();
    let me = seed_user_with_agent(&pool, wid, "secretary", seed).await;
    let agent = seed_agent_token(&pool, &me).await;
    let (status, res) = call(&app, "POST", "/mcp-resources", &agent, Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{res}");
    let resource = res["resource"].as_str().unwrap().to_string();
    let (status, client) = call(
        &app,
        "POST",
        "/oauth/register",
        "",
        Some(json!({ "client_name": "Muse", "redirect_uris": [REDIRECT] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    Setup {
        app,
        pool,
        me,
        agent,
        resource,
        client_id: client["client_id"].as_str().unwrap().to_string(),
    }
}

fn authorize_params<'a>(s: &'a Setup, chal: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("response_type", "code"),
        ("client_id", s.client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("state", "xyz"),
        ("code_challenge", chal),
        ("code_challenge_method", "S256"),
        ("resource", s.resource.as_str()),
    ]
}

/// Consent as the owner and return the code.
async fn consent(s: &Setup) -> String {
    let chal = challenge(VERIFIER);
    let params = authorize_params(s, &chal);
    let mut body: serde_json::Map<String, Value> = params
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    body.insert("approve".into(), json!(true));
    let (status, out) = call(
        &s.app,
        "POST",
        "/oauth/authorize",
        &s.me.auth,
        Some(Value::Object(body)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let to = out["redirect_to"].as_str().unwrap();
    assert!(to.starts_with(REDIRECT), "{to}");
    assert!(to.contains("state=xyz") && to.contains("iss="), "{to}");
    let url = reqwest_free_code(to);
    url
}

fn reqwest_free_code(url: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .find_map(|kv| kv.strip_prefix("code="))
        .unwrap()
        .to_string()
}

async fn exchange(s: &Setup, code: &str, verifier: &str) -> (StatusCode, Value) {
    form(
        &s.app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", &s.client_id),
            ("code_verifier", verifier),
            ("resource", &s.resource),
        ],
    )
    .await
}

async fn introspect(s: &Setup, token: &str) -> Value {
    let (status, out) = call(
        &s.app,
        "POST",
        "/oauth/introspect",
        &s.agent,
        Some(json!({ "token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    out
}

macro_rules! db {
    () => {{
        if !db_tests_enabled() {
            eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
            return;
        }
        ensure_db_env();
        let pool = db_pool().await;
        reset_schema(&pool).await;
        pool
    }};
}

#[tokio::test]
#[serial]
async fn metadata_advertises_pkce_and_registration() {
    let _pool = db!();
    let app = common::test_app();
    let (status, meta) = call(
        &app,
        "GET",
        "/.well-known/oauth-authorization-server",
        "",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        meta["scopes_supported"],
        json!(["inbox.read", "inbox.draft"])
    );
    assert!(meta["registration_endpoint"]
        .as_str()
        .unwrap()
        .ends_with("/oauth/register"));
    assert!(meta["authorization_endpoint"]
        .as_str()
        .unwrap()
        .ends_with("/oauth/authorize"));
    assert_eq!(meta["client_id_metadata_document_supported"], true);
}

#[tokio::test]
#[serial]
async fn a_computer_gets_one_stable_mcp_url() {
    let pool = db!();
    let s = setup(pool, "0xoauth-1", 0x61).await;
    assert!(
        s.resource.starts_with("https://") && s.resource.ends_with(".mcp.agent-inbox.ai/mcp"),
        "{}",
        s.resource
    );
    let (_, again) = call(&s.app, "POST", "/mcp-resources", &s.agent, Some(json!({}))).await;
    assert_eq!(again["resource"], s.resource.as_str());
    // Naming a local URL is for local tests only.
    let (status, _) = call(
        &s.app,
        "POST",
        "/mcp-resources",
        &s.agent,
        Some(json!({ "resource": "http://127.0.0.1:8787/mcp" })),
    )
    .await;
    assert!(status.is_client_error());
    // A person's session cannot register one.
    let (status, _) = call(
        &s.app,
        "POST",
        "/mcp-resources",
        &s.me.auth,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn consent_tokens_and_introspection() {
    let pool = db!();
    let s = setup(pool, "0xoauth-2", 0x62).await;

    let chal = challenge(VERIFIER);
    let (status, info) = call(
        &s.app,
        "GET",
        &format!(
            "/oauth/authorize/info?{}",
            query(&authorize_params(&s, &chal))
        ),
        &s.me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{info}");
    assert_eq!(info["client_name"], "Muse");
    assert_eq!(info["agent_label"], "secretary");
    assert_eq!(info["scope"], json!(["inbox.read", "inbox.draft"]));

    let code = consent(&s).await;
    // A wrong verifier fails, and the code is then spent.
    let (status, err) = exchange(&s, &code, &"x".repeat(43)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_grant");

    let code = consent(&s).await;
    let (status, tokens) = exchange(&s, &code, VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let access = tokens["access_token"].as_str().unwrap().to_string();
    assert!(access.starts_with("nxa_"));
    assert_eq!(tokens["scope"], "inbox.read inbox.draft");
    let info = introspect(&s, &access).await;
    assert_eq!(info["active"], true);
    assert_eq!(info["client_name"], "Muse");
    assert_eq!(info["aud"], s.resource.as_str());

    // The same code again: refused, and the grant is stopped.
    let (status, _) = exchange(&s, &code, VERIFIER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(introspect(&s, &access).await["active"], false);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events: Vec<String> =
        sqlx::query_scalar("SELECT event FROM agent_audit_log WHERE user_id = $1")
            .bind(s.me.user_id)
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert!(
        events.contains(&"oauth_grant_created".to_string()),
        "{events:?}"
    );
}

#[tokio::test]
#[serial]
async fn refresh_rotates_and_a_replayed_refresh_stops_the_grant() {
    let pool = db!();
    let s = setup(pool, "0xoauth-3", 0x63).await;
    let code = consent(&s).await;
    let (_, first) = exchange(&s, &code, VERIFIER).await;
    let refresh = first["refresh_token"].as_str().unwrap().to_string();
    let (status, second) = form(
        &s.app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &s.client_id),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let new_access = second["access_token"].as_str().unwrap().to_string();
    assert_eq!(introspect(&s, &new_access).await["active"], true);

    let (status, _) = form(
        &s.app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &s.client_id),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(introspect(&s, &new_access).await["active"], false);
}

#[tokio::test]
#[serial]
async fn only_the_owner_consents_and_disconnects() {
    let pool = db!();
    let s = setup(pool, "0xoauth-4", 0x64).await;
    let other = seed_user_with_agent(&s.pool, "0xoauth-4-other", "other", 0x65).await;
    let other_agent = seed_agent_token(&s.pool, &other).await;
    let chal = challenge(VERIFIER);
    let q = query(&authorize_params(&s, &chal));

    let (status, _) = call(
        &s.app,
        "GET",
        &format!("/oauth/authorize/info?{q}"),
        &other.auth,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "someone else's computer"
    );
    let (status, _) = call(
        &s.app,
        "GET",
        &format!("/oauth/authorize/info?{q}"),
        &s.agent,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an agent token cannot consent"
    );

    // Unknown redirect, sending scope, plain PKCE: refused.
    for (k, v) in [
        ("redirect_uri", "https://evil.example/cb"),
        ("scope", "inbox.send"),
        ("code_challenge_method", "plain"),
    ] {
        let mut p = authorize_params(&s, &chal);
        p.retain(|(key, _)| *key != k);
        p.push((k, v));
        let (status, _) = call(
            &s.app,
            "GET",
            &format!("/oauth/authorize/info?{}", query(&p)),
            &s.me.auth,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{k}={v}");
    }

    // Declining sends the app an access_denied.
    let mut body: serde_json::Map<String, Value> = authorize_params(&s, &chal)
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    body.insert("approve".into(), json!(false));
    let (_, out) = call(
        &s.app,
        "POST",
        "/oauth/authorize",
        &s.me.auth,
        Some(Value::Object(body)),
    )
    .await;
    assert!(out["redirect_to"]
        .as_str()
        .unwrap()
        .contains("error=access_denied"));

    let code = consent(&s).await;
    let (_, tokens) = exchange(&s, &code, VERIFIER).await;
    let access = tokens["access_token"].as_str().unwrap().to_string();

    // Another person's computer learns nothing about this token.
    let (_, other_view) = call(
        &s.app,
        "POST",
        "/oauth/introspect",
        &other_agent,
        Some(json!({ "token": access })),
    )
    .await;
    assert_eq!(other_view["active"], false);

    let (_, grants) = call(&s.app, "GET", "/oauth/grants", &s.me.auth, None).await;
    let list = grants["grants"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["client_name"], "Muse");
    let id = list[0]["id"].as_str().unwrap();
    let (status, _) = call(
        &s.app,
        "DELETE",
        &format!("/oauth/grants/{id}"),
        &other.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &s.app,
        "DELETE",
        &format!("/oauth/grants/{id}"),
        &s.me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(introspect(&s, &access).await["active"], false);
}

#[tokio::test]
#[serial]
async fn idle_grants_stop_working_and_are_cleaned_up() {
    let pool = db!();
    let s = setup(pool, "0xoauth-5", 0x66).await;
    let code = consent(&s).await;
    let (_, tokens) = exchange(&s, &code, VERIFIER).await;
    let access = tokens["access_token"].as_str().unwrap().to_string();
    sqlx::query("UPDATE oauth_grants SET last_used_at = NOW() - interval '31 days'")
        .execute(&s.pool)
        .await
        .unwrap();
    assert_eq!(introspect(&s, &access).await["active"], false);
    sqlx::query("UPDATE oauth_grants SET last_used_at = NOW() - interval '61 days'")
        .execute(&s.pool)
        .await
        .unwrap();
    let summary = nexusinbox_api::run_retention_pass(nexusinbox_api::RetentionConfig {
        mode: nexusinbox_api::RetentionMode::Enforce,
        retention_days: 90,
    })
    .await;
    assert!(summary.oauth >= 1, "{}", summary.oauth);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_grants")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

// ---------------------------------------------------------------------------
// Relay tickets (docs/33 §11.3)
// ---------------------------------------------------------------------------

fn jkt_of(key: &SigningKey) -> String {
    let x = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn dpop_proof(key: &SigningKey, method: &str, path: &str, access: &str) -> String {
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519",
                 "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()) },
    });
    let claims = json!({
        "htm": method,
        "htu": path,
        "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access.as_bytes())),
        "iat": chrono::Utc::now().timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

async fn dpop_call(
    app: &axum::Router,
    key: &SigningKey,
    access: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("DPoP {access}"))
                .header("dpop", dpop_proof(key, method, path, access))
                .header("content-type", "application/json")
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
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

const RELAY_KEY_SEED: [u8; 32] = [0x42; 32];

#[tokio::test]
#[serial]
async fn relay_tickets_are_bound_to_the_computers_dpop_key() {
    let pool = db!();
    std::env::set_var(
        "AGENT_INBOX_RELAY_TICKET_KEY",
        URL_SAFE_NO_PAD.encode(RELAY_KEY_SEED),
    );
    let s = setup(pool, "0xoauth-relay", 0x71).await;
    let credential_id: Uuid =
        sqlx::query_scalar("SELECT credential_id FROM mcp_resources WHERE resource = $1")
            .bind(&s.resource)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    // An AI app the person let in through this computer (docs/33 §12 checks
    // that turning cloud access off disconnects it).
    let code = consent(&s).await;
    let (status, tokens) = exchange(&s, &code, VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let app_token = tokens["access_token"].as_str().unwrap().to_string();
    assert_eq!(introspect(&s, &app_token).await["active"], true);

    // A plain bearer token is not enough: the relay needs a key to check.
    let (status, body) = call(
        &s.app,
        "POST",
        "/mcp-resources/relay-ticket",
        &s.agent,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Bind the same token to a DPoP key.
    let dpop_key = SigningKey::from_bytes(&[0x37; 32]);
    let access = s.agent.trim_start_matches("Bearer ").to_string();
    sqlx::query("UPDATE agent_tokens SET dpop_jkt = $1 WHERE access_hash = $2")
        .bind(jkt_of(&dpop_key))
        .bind(sha256_hex(&access))
        .execute(&s.pool)
        .await
        .unwrap();
    let ticket_call = || {
        dpop_call(
            &s.app,
            &dpop_key,
            &access,
            "POST",
            "/mcp-resources/relay-ticket",
            None,
        )
    };
    let status_call = |serving: bool| {
        dpop_call(
            &s.app,
            &dpop_key,
            &access,
            "POST",
            "/mcp-resources/relay-status",
            Some(json!({ "serving": serving })),
        )
    };

    // Off until the person turns it on: no ticket, and the computer is told.
    let (status, body) = ticket_call().await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = status_call(true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], false);
    let cloud_access = format!("/agent-credentials/{credential_id}/cloud-access");
    // Only the person turns it on, not the computer.
    let (status, _) = dpop_call(
        &s.app,
        &dpop_key,
        &access,
        "PUT",
        &cloud_access,
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    let (status, body) = call(
        &s.app,
        "PUT",
        &cloud_access,
        &s.me.auth,
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = status_call(true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], true);
    let (_, list) = call(&s.app, "GET", "/agent-credentials", &s.me.auth, None).await;
    let mine = list["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["credential_id"] == credential_id.to_string())
        .unwrap()
        .clone();
    assert_eq!(mine["cloud_access"], true, "{mine}");
    assert_eq!(mine["cloud_url"], s.resource.as_str());
    assert!(mine["cloud_serving_at"].is_string(), "{mine}");

    let (status, body) = ticket_call().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let host = s
        .resource
        .trim_start_matches("https://")
        .trim_end_matches("/mcp");
    assert_eq!(body["host"], host);
    assert_eq!(body["relay"], "relay.agent-inbox.ai");

    // The ticket verifies with the published key and carries the binding.
    let (status, jwk) = call(&s.app, "GET", "/mcp-relay/ticket-key", "", None).await;
    assert_eq!(status, StatusCode::OK);
    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(jwk["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&x).unwrap();
    let ticket = body["ticket"].as_str().unwrap();
    let (input, sig) = ticket.rsplit_once('.').unwrap();
    let sig: [u8; 64] = URL_SAFE_NO_PAD.decode(sig).unwrap().try_into().unwrap();
    vk.verify_strict(
        input.as_bytes(),
        &ed25519_dalek::Signature::from_bytes(&sig),
    )
    .unwrap();
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(input.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["sub"], host);
    assert_eq!(claims["aud"], "relay.agent-inbox.ai");
    assert_eq!(claims["cnf"]["jkt"], jkt_of(&dpop_key));
    assert!(claims["exp"].as_u64().unwrap() <= claims["iat"].as_u64().unwrap() + 120);

    // A person's session gets none, and without a key there are none at all.
    let human = seed_session(&s.pool, s.me.user_id, "0xoauth-relay", "orb").await;
    let (status, _) = call(&s.app, "POST", "/mcp-resources/relay-ticket", &human, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Turning it off closes the door and disconnects the AI apps let in
    // through this computer.
    let (status, body) = call(
        &s.app,
        "PUT",
        &cloud_access,
        &s.me.auth,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["disconnected"], 1);
    let revoked: bool = sqlx::query_scalar(
        "SELECT bool_and(revoked_at IS NOT NULL) FROM oauth_grants WHERE resource = $1",
    )
    .bind(&s.resource)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert!(revoked);
    let (status, _) = ticket_call().await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, body) = status_call(true).await;
    assert_eq!(body["enabled"], false);
    let serving: Option<String> =
        sqlx::query_scalar("SELECT cloud_serving_at::text FROM agent_credentials WHERE id = $1")
            .bind(credential_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(serving, None);

    // Someone else's computer cannot be switched.
    let other = seed_user_with_agent(&s.pool, "0xoauth-relay-other", "other", 0x72).await;
    let (status, _) = call(
        &s.app,
        "PUT",
        &cloud_access,
        &other.auth,
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(
        &s.app,
        "PUT",
        &cloud_access,
        &s.me.auth,
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    std::env::remove_var("AGENT_INBOX_RELAY_TICKET_KEY");
    // Without the relay key it cannot be turned on.
    let (status, _) = call(
        &s.app,
        "PUT",
        &cloud_access,
        &s.me.auth,
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = dpop_call(
        &s.app,
        &dpop_key,
        &access,
        "POST",
        "/mcp-resources/relay-ticket",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
#[serial]
async fn emergency_shutdown_disconnects_ai_apps_and_cloud_access() {
    let pool = db!();
    let s = setup(pool, "0xoauth-panic", 0x73).await;
    let code = consent(&s).await;
    let (status, tokens) = exchange(&s, &code, VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    sqlx::query(
        "UPDATE agent_credentials SET cloud_access_enabled_at = NOW(), cloud_serving_at = NOW() \
         WHERE aid = $1",
    )
    .bind(&s.me.aid)
    .execute(&s.pool)
    .await
    .unwrap();
    let agent_id: Uuid = sqlx::query_scalar("SELECT agent_id FROM agent_identities WHERE aid = $1")
        .bind(&s.me.aid)
        .fetch_one(&s.pool)
        .await
        .unwrap();

    let (status, body) = call(
        &s.app,
        "POST",
        &format!("/agents/{agent_id}/emergency-shutdown"),
        &s.me.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ai_apps_disconnected"], 1, "{body}");
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_grants WHERE aid = $1 AND revoked_at IS NULL",
    )
    .bind(&s.me.aid)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(live, 0);
    let cloud_on: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_credentials WHERE aid = $1 \
           AND (cloud_access_enabled_at IS NOT NULL OR cloud_serving_at IS NOT NULL)",
    )
    .bind(&s.me.aid)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(cloud_on, 0);
}

#[tokio::test]
#[serial]
async fn public_agent_pages_show_only_shared_agents() {
    let pool = db!();
    let app = common::test_app();
    let me = seed_user_with_agent(&pool, "0xpublic-agent", "秘書", 0x74).await;
    sqlx::query("UPDATE users SET display_name = '水本' WHERE id = $1")
        .bind(me.user_id)
        .execute(&pool)
        .await
        .unwrap();
    let agent_id: Uuid = sqlx::query_scalar("SELECT agent_id FROM agent_identities WHERE aid = $1")
        .bind(&me.aid)
        .fetch_one(&pool)
        .await
        .unwrap();
    let page = format!("/public/agents/{}", me.aid);

    // Not shared: indistinguishable from an address that does not exist.
    let (status, _) = call(&app, "GET", &page, "", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&app, "GET", "/public/agents/aid:ai:nobody", "", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = call(
        &app,
        "PATCH",
        &format!("/agents/{agent_id}"),
        &me.auth,
        Some(json!({ "share_enabled": true, "bio": "日程調整をします" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["share_enabled"], true);

    let (status, body) = call(&app, "GET", &page, "", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["label"], "秘書");
    assert_eq!(body["bio"], "日程調整をします");
    assert_eq!(body["owner_display_name"], "水本");
    // Only these fields: no DIDs, keys or ids.
    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 4, "{body}");

    let (status, _) = call(
        &app,
        "PATCH",
        &format!("/agents/{agent_id}"),
        &me.auth,
        Some(json!({ "share_enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&app, "GET", &page, "", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
