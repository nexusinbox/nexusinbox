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

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

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
         agent_identities, blocks, message_index, sessions, replay_nonces, agents, users \
         RESTART IDENTITY CASCADE",
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

async fn seed_pending_credential(
    pool: &PgPool,
    user_id: Uuid,
    credential_id: Uuid,
    enrollment_secret: &str,
) -> String {
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:test{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(format!("did:key:z{}", Uuid::new_v4().simple()))
    .bind("Test Agent")
    .bind("legacy-public-key")
    .bind("legacy-encryption-key")
    .execute(pool)
    .await
    .expect("failed to seed agent");

    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(agent_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("failed to seed agent identity");

    let enrollment_hash = hex::encode(Sha256::digest(enrollment_secret.as_bytes()));
    sqlx::query(
        "INSERT INTO agent_credentials (id, aid, user_id, label, status, enrollment_hash, enrollment_expires) \
         VALUES ($1, $2, $3, $4, 'pending', $5, NOW() + INTERVAL '10 minutes')",
    )
    .bind(credential_id)
    .bind(&aid)
    .bind(user_id)
    .bind("DB Test Credential")
    .bind(enrollment_hash)
    .execute(pool)
    .await
    .expect("failed to seed pending credential");

    aid
}

fn to_b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sign_enrollment_proof(signing_key: &SigningKey, credential_id: Uuid, iat: i64) -> String {
    let header = to_b64url(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = to_b64url(
        json!({
            "credential_id": credential_id.to_string(),
            "iat": iat,
        })
        .to_string()
        .as_bytes(),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = signing_key.sign(signing_input.as_bytes());
    format!(
        "{}.{}.{}",
        header,
        payload,
        to_b64url(&signature.to_bytes())
    )
}

// --- Helper: authenticate and get a session cookie ---

async fn authenticated_cookie(app: &axum::Router) -> String {
    let payload = json!({
      "proof": "0xproof",
      "merkle_root": "0xroot",
      "nullifier_hash": "0xnullifier_cred_test",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("missing set-cookie")
        .to_str()
        .unwrap()
        .to_string();
    // Extract just the cookie value
    set_cookie.split(';').next().unwrap().to_string()
}

// ============================================================================
// Agent credential endpoints — without DB, these should return 503 (DB required)
// or 401 (unauthorized). We test routing and auth guards.
// ============================================================================

#[tokio::test]
async fn credential_create_requires_authentication() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-credentials")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"agent_id":"test","label":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Without auth cookie, should get 401 or 422 (body parsed before auth check)
    let status = response.status().as_u16();
    assert!(
        status == 401 || status == 422,
        "expected 401 or 422, got {}",
        status
    );
}

#[tokio::test]
async fn credential_create_requires_db() {
    let app = common::test_app_with_mock_world_verify();
    let cookie = authenticated_cookie(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-credentials")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(Body::from(
                    json!({"agent_id": "00000000-0000-0000-0000-000000000001", "label": "test"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Without a DB, expect 500 or 503 (service unavailable / internal error)
    let status = response.status().as_u16();
    assert!(
        status == 500 || status == 503,
        "expected 500 or 503, got {}",
        status
    );
}

#[tokio::test]
async fn agent_auth_token_rejects_empty_body() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/token")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail with 422 (unprocessable) or 400 for missing fields
    let status = response.status().as_u16();
    assert!(
        status == 400 || status == 422,
        "expected 400 or 422, got {}",
        status
    );
}

#[tokio::test]
async fn agent_auth_refresh_rejects_invalid_token() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": "agr_invalid_token_value"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Without DB, expect 500/503; with DB, expect 401 for invalid token
    let status = response.status().as_u16();
    assert!(
        status == 401 || status == 500 || status == 503,
        "expected 401/500/503, got {}",
        status
    );
}

#[tokio::test]
async fn agent_auth_revoke_requires_agent_token() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/revoke")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Without an agt_ token, should get 401 or 422 (missing body fields)
    let status = response.status().as_u16();
    assert!(
        status == 401 || status == 422,
        "expected 401 or 422, got {}",
        status
    );
}

#[tokio::test]
async fn emergency_shutdown_requires_authentication() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/00000000-0000-0000-0000-000000000001/emergency-shutdown")
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn emergency_shutdown_requires_db() {
    let app = common::test_app_with_mock_world_verify();
    let cookie = authenticated_cookie(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/00000000-0000-0000-0000-000000000001/emergency-shutdown")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status().as_u16();
    assert!(
        status == 500 || status == 503,
        "expected 500 or 503 (no DB), got {}",
        status
    );
}

#[tokio::test]
async fn audit_log_requires_authentication() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/agent-audit-log")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Activate endpoint — enrollment_proof payload validation
// ============================================================================

#[tokio::test]
async fn activate_rejects_malformed_jws_proof() {
    let app = common::test_app();
    let cred_id = "00000000-0000-0000-0000-000000000001";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/agent-credentials/{cred_id}/activate"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enrollment_secret": "ens_test",
                        "signing_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "encryption_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "enrollment_proof": "not-a-jws"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Without DB → 500/503 (DB required check runs before proof validation).
    // With DB → 400/422 for malformed JWS.
    let status = response.status().as_u16();
    assert!(
        status == 400 || status == 422 || status == 500 || status == 503,
        "expected 400/422/500/503, got {}",
        status
    );
}

#[tokio::test]
async fn activate_requires_db() {
    let app = common::test_app();
    let cred_id = "00000000-0000-0000-0000-000000000001";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/agent-credentials/{cred_id}/activate"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enrollment_secret": "ens_test",
                        "signing_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "encryption_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "enrollment_proof": "eyJhbGciOiJFZERTQSJ9.eyJjcmVkZW50aWFsX2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAxIiwiaWF0IjoxNzEzMjcwMDAwfQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status().as_u16();
    assert!(
        status == 500 || status == 503,
        "expected 500 or 503 (no DB), got {}",
        status
    );
}

#[tokio::test]
#[serial]
async fn activate_rejects_proof_for_different_credential_id() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xagent-credential-owner", "orb").await;

    let credential_id = Uuid::new_v4();
    let enrollment_secret = "ens_db_test_mismatch";
    seed_pending_credential(&pool, user_id, credential_id, enrollment_secret).await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let proof = sign_enrollment_proof(&signing_key, Uuid::new_v4(), chrono::Utc::now().timestamp());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/agent-credentials/{credential_id}/activate"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enrollment_secret": enrollment_secret,
                        "signing_public_key": to_b64url(&signing_key.verifying_key().to_bytes()),
                        "encryption_public_key": "test-encryption-key",
                        "enrollment_proof": proof
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "validation_error");
    assert_eq!(
        payload["message"],
        "enrollment_proof credential_id does not match the target credential"
    );

    let status: String = sqlx::query("SELECT status FROM agent_credentials WHERE id = $1")
        .bind(credential_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("status");
    assert_eq!(status, "pending");
}

#[tokio::test]
#[serial]
async fn activate_rejects_stale_iat() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xagent-credential-owner-stale", "orb").await;

    let credential_id = Uuid::new_v4();
    let enrollment_secret = "ens_db_test_stale";
    seed_pending_credential(&pool, user_id, credential_id, enrollment_secret).await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let proof = sign_enrollment_proof(
        &signing_key,
        credential_id,
        chrono::Utc::now().timestamp() - 120,
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/agent-credentials/{credential_id}/activate"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enrollment_secret": enrollment_secret,
                        "signing_public_key": to_b64url(&signing_key.verifying_key().to_bytes()),
                        "encryption_public_key": "test-encryption-key",
                        "enrollment_proof": proof
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "validation_error");
    assert_eq!(
        payload["message"],
        "enrollment_proof iat is outside the 60-second window"
    );
}

#[tokio::test]
#[serial]
async fn activate_rejects_future_iat() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xagent-credential-owner-future", "orb").await;

    let credential_id = Uuid::new_v4();
    let enrollment_secret = "ens_db_test_future";
    seed_pending_credential(&pool, user_id, credential_id, enrollment_secret).await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let proof = sign_enrollment_proof(
        &signing_key,
        credential_id,
        chrono::Utc::now().timestamp() + 120,
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/agent-credentials/{credential_id}/activate"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enrollment_secret": enrollment_secret,
                        "signing_public_key": to_b64url(&signing_key.verifying_key().to_bytes()),
                        "encryption_public_key": "test-encryption-key",
                        "enrollment_proof": proof
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "validation_error");
    assert_eq!(
        payload["message"],
        "enrollment_proof iat is outside the 60-second window"
    );
}

// ============================================================================
// Activate — DB integration: success + lifecycle boundary cases
// ============================================================================
//
// These are the missing positive-path and counter-boundary tests that were
// called out in the 2026-04-24 coverage audit. Locking them down protects
// against silent regressions in:
//
//   - credential_activated audit emission
//   - signing_public_key persistence
//   - ACTIVATION_MAX_FAILED_ATTEMPTS auto-revoke threshold
//   - enrollment_expires enforcement
//   - wrong-secret handling (distinct from wrong-proof)

/// Helper: build a well-formed activate request body matching the seed.
fn activate_body(
    signing_key: &SigningKey,
    credential_id: Uuid,
    enrollment_secret: &str,
    iat_offset_secs: i64,
) -> Value {
    let iat = chrono::Utc::now().timestamp() + iat_offset_secs;
    json!({
        "enrollment_secret": enrollment_secret,
        "signing_public_key": to_b64url(&signing_key.verifying_key().to_bytes()),
        "encryption_public_key": "test-encryption-key",
        "enrollment_proof": sign_enrollment_proof(signing_key, credential_id, iat),
        "key_holder": "signer_daemon",
    })
}

async fn post_activate(
    app: &axum::Router,
    credential_id: Uuid,
    body: Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/agent-credentials/{credential_id}/activate"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn activate_succeeds_and_persists_public_key() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xagent-credential-activate-ok", "orb").await;

    let credential_id = Uuid::new_v4();
    let enrollment_secret = "ens_db_test_happy";
    seed_pending_credential(&pool, user_id, credential_id, enrollment_secret).await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let body = activate_body(&signing_key, credential_id, enrollment_secret, 0);

    let response = post_activate(&app, credential_id, body).await;
    assert_eq!(response.status(), StatusCode::OK);

    let resp = response_json(response).await;
    assert_eq!(resp["status"], "active");
    assert_eq!(resp["credential_id"], credential_id.to_string());
    assert!(resp["did"].as_str().unwrap().starts_with("did:key:z"));

    // Credential row is active, signing_public_key stored, failed counter reset.
    let row = sqlx::query(
        "SELECT status, signing_public_key, failed_activation_attempts, \
                (activated_at IS NOT NULL) AS has_activated_at, key_holder \
         FROM agent_credentials WHERE id = $1",
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let status: String = row.get("status");
    let spk: Option<String> = row.get("signing_public_key");
    let failed: i32 = row.get("failed_activation_attempts");
    let has_activated_at: bool = row.get("has_activated_at");
    let key_holder: String = row.get("key_holder");
    assert_eq!(status, "active");
    assert_eq!(
        spk.as_deref(),
        Some(to_b64url(&signing_key.verifying_key().to_bytes()).as_str())
    );
    assert_eq!(failed, 0);
    assert!(has_activated_at, "activated_at must be populated");
    assert_eq!(key_holder, "signer_daemon");

    // agent_identity_keys linkage is written.
    let key_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_identity_keys WHERE signing_public_key = $1",
    )
    .bind(to_b64url(&signing_key.verifying_key().to_bytes()))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(key_rows, 1, "agent_identity_keys row must be created");

    // Poll briefly for the fire-and-forget credential_activated audit.
    let mut saw_activated = false;
    for _ in 0..10 {
        let cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_log \
             WHERE event = 'credential_activated' AND credential_id = $1",
        )
        .bind(credential_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if cnt >= 1 {
            saw_activated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(saw_activated, "credential_activated audit must be recorded");
}

#[tokio::test]
#[serial]
async fn activate_rejects_wrong_enrollment_secret_and_bumps_counter() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xagent-credential-wrong-secret", "orb").await;

    let credential_id = Uuid::new_v4();
    seed_pending_credential(&pool, user_id, credential_id, "ens_real_secret").await;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    // Proof is perfectly valid (matching credential_id + fresh iat + correct
    // signing key) — the only thing wrong is the enrollment_secret. The
    // endpoint must distinguish this from a proof failure.
    let body = activate_body(&signing_key, credential_id, "ens_wrong_secret", 0);

    let response = post_activate(&app, credential_id, body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "unauthorized");
    assert_eq!(payload["message"], "invalid enrollment secret");

    // Counter went up by exactly 1, status still pending.
    let row = sqlx::query(
        "SELECT status, failed_activation_attempts FROM agent_credentials WHERE id = $1",
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let status: String = row.get("status");
    let failed: i32 = row.get("failed_activation_attempts");
    assert_eq!(status, "pending");
    assert_eq!(failed, 1);
}

#[tokio::test]
#[serial]
async fn activate_auto_revokes_at_max_failed_attempts() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xagent-credential-auto-revoke", "orb").await;

    let credential_id = Uuid::new_v4();
    seed_pending_credential(&pool, user_id, credential_id, "ens_real_secret").await;

    // ACTIVATION_MAX_FAILED_ATTEMPTS is 5. Hammer with wrong secrets and
    // verify the auto-revoke kicks in on exactly the 5th call.
    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    for attempt in 1..=5 {
        let body = activate_body(&signing_key, credential_id, "ens_wrong_secret", 0);
        let response = post_activate(&app, credential_id, body).await;

        if attempt < 5 {
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "attempt {attempt} should be unauthorized (wrong secret)"
            );
            let payload = response_json(response).await;
            assert_eq!(payload["message"], "invalid enrollment secret");
        } else {
            // 5th failure flips status to revoked — response message changes.
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let payload = response_json(response).await;
            assert_eq!(payload["error"], "credential_revoked");
            assert!(payload["message"]
                .as_str()
                .unwrap()
                .contains("auto-revoked"));
        }
    }

    // Verify post-state: status=revoked, enrollment_hash cleared.
    let row = sqlx::query(
        "SELECT status, failed_activation_attempts, enrollment_hash, \
                (revoked_at IS NOT NULL) AS has_revoked_at \
         FROM agent_credentials WHERE id = $1",
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let status: String = row.get("status");
    let failed: i32 = row.get("failed_activation_attempts");
    let enrollment_hash: Option<String> = row.get("enrollment_hash");
    let has_revoked_at: bool = row.get("has_revoked_at");
    assert_eq!(status, "revoked");
    assert_eq!(failed, 5);
    assert!(
        enrollment_hash.is_none(),
        "enrollment_hash must be cleared on auto-revoke"
    );
    assert!(
        has_revoked_at,
        "revoked_at must be populated on auto-revoke"
    );

    // One credential_auto_revoked audit must have been recorded (alongside
    // the 4 credential_activation_failed events).
    let mut saw_auto_revoked = false;
    let mut saw_failed_events = 0i64;
    for _ in 0..10 {
        saw_failed_events = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_log \
             WHERE event = 'credential_activation_failed' AND credential_id = $1",
        )
        .bind(credential_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let revoked_cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_audit_log \
             WHERE event = 'credential_auto_revoked' AND credential_id = $1",
        )
        .bind(credential_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if revoked_cnt >= 1 && saw_failed_events >= 4 {
            saw_auto_revoked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        saw_auto_revoked,
        "expected 4 credential_activation_failed + 1 credential_auto_revoked audit events \
         (got failed={saw_failed_events})"
    );
}

#[tokio::test]
#[serial]
async fn activate_rejects_expired_enrollment() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }

    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "0xagent-credential-expired", "orb").await;

    // Seed a fully-formed pending credential, then back-date the expiry.
    // We can't pass a custom expiry through seed_pending_credential, so do
    // the UPDATE after-the-fact. The enrollment_secret remains valid, so
    // any rejection here must come from the expiry check, not the secret
    // check — i.e. the expiry guard must run *before* secret comparison.
    let credential_id = Uuid::new_v4();
    let enrollment_secret = "ens_db_test_expired";
    seed_pending_credential(&pool, user_id, credential_id, enrollment_secret).await;
    sqlx::query(
        "UPDATE agent_credentials SET enrollment_expires = NOW() - INTERVAL '1 minute' \
         WHERE id = $1",
    )
    .bind(credential_id)
    .execute(&pool)
    .await
    .unwrap();

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let body = activate_body(&signing_key, credential_id, enrollment_secret, 0);

    let response = post_activate(&app, credential_id, body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let payload = response_json(response).await;
    assert_eq!(payload["error"], "validation_error");
    assert_eq!(payload["message"], "enrollment has expired");

    // Status must remain pending (expiry rejection does not bump counter
    // or auto-revoke — that's the wrong-secret/wrong-proof path).
    let row = sqlx::query(
        "SELECT status, failed_activation_attempts FROM agent_credentials WHERE id = $1",
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let status: String = row.get("status");
    let failed: i32 = row.get("failed_activation_attempts");
    assert_eq!(status, "pending");
    assert_eq!(
        failed, 0,
        "expired enrollment rejection must not bump the failed-attempts counter"
    );
}
