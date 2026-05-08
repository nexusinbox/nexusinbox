//! End-to-end revocation tests for agent token validation.
//!
//! These tests assert that DB-side revocation state changes (manual revoke,
//! refresh rotation, refresh-reuse detection, emergency shutdown,
//! credential revoke, agent deactivation) are *immediately* reflected in
//! the result of the next call to a DPoP/Bearer-authenticated endpoint.
//!
//! Every test goes through the HTTP router so we exercise the real
//! `validate_agent_token` path (DB JOIN + status checks + expiry + agent
//! is_active + DPoP chain), not a mocked in-memory variant.
//!
//! Tokens are issued with `dpop_jkt = "none"` so the tests don't have to
//! forge DPoP proofs; the replay-store and JKT plumbing is covered
//! separately in `internal_tests` (see `dpop_replay_in_db_*`).
//!
//! Gated behind AGENT_INBOX_DB_TESTS=1 so the default `cargo test` suite
//! stays hermetic; skipped automatically when DATABASE_URL isn't set.

use axum::body::Body;
use axum::http::{Request, StatusCode};
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

// --- DB test plumbing (mirrors agent_credential_test.rs conventions) ---

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

/// Seed a user + agent (active) + aid + active credential + one active
/// Bearer-mode token. Returns the plaintext access token + context needed
/// by test assertions.
#[derive(Debug, Clone)]
struct SeededAgent {
    user_id: Uuid,
    agent_id: Uuid,
    aid: String,
    credential_id: Uuid,
    access_token: String,
    token_id: Uuid,
    token_family_id: Uuid,
}

async fn seed_active_agent_with_token(pool: &PgPool) -> SeededAgent {
    let user_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:rev{}", Uuid::new_v4().simple());
    let credential_id = Uuid::new_v4();
    let token_id = Uuid::new_v4();
    let token_family_id = Uuid::new_v4();
    let access_token = format!("agt_{}", Uuid::new_v4().simple());
    let access_hash = hex::encode(Sha256::digest(access_token.as_bytes()));
    let nullifier = format!("0xnull_{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO users (id, world_id_hash, nullifier_hash, verification_level) \
         VALUES ($1, $2, $3, 'orb')",
    )
    .bind(user_id)
    .bind(&nullifier)
    .bind(&nullifier)
    .execute(pool)
    .await
    .expect("seed user");

    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, $4, $5, $6, true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(format!("did:key:z{}", Uuid::new_v4().simple()))
    .bind("revocation-test-agent")
    .bind("pub")
    .bind("enc")
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
        "INSERT INTO agent_credentials (id, aid, user_id, label, status, signing_public_key) \
         VALUES ($1, $2, $3, 'revocation-test', 'active', $4)",
    )
    .bind(credential_id)
    .bind(&aid)
    .bind(user_id)
    .bind("ed25519-public-key-stub")
    .execute(pool)
    .await
    .expect("seed credential");

    // Non-DPoP token so tests can call endpoints with plain Bearer auth.
    sqlx::query(
        "INSERT INTO agent_tokens ( \
             id, credential_id, access_hash, refresh_hash, dpop_jkt, \
             scopes, issued_at, access_expires_at, refresh_expires_at, token_family_id \
         ) VALUES ( \
             $1, $2, $3, $4, 'none', \
             ARRAY['messages.read', 'messages.send'], NOW(), NOW() + INTERVAL '1 hour', \
             NOW() + INTERVAL '30 days', $5 \
         )",
    )
    .bind(token_id)
    .bind(credential_id)
    .bind(&access_hash)
    .bind(Option::<String>::None)
    .bind(token_family_id)
    .execute(pool)
    .await
    .expect("seed agent_token");

    SeededAgent {
        user_id,
        agent_id,
        aid,
        credential_id,
        access_token,
        token_id,
        token_family_id,
    }
}

/// Call a token-authenticated endpoint; returns the HTTP status so tests
/// can assert on allow vs. reject. Uses `GET /messages` which goes through
/// `authenticated_context` → `validate_agent_token` for agent tokens.
async fn call_with_agent_token(app: &axum::Router, token: &str, aid: &str) -> StatusCode {
    let uri = format!("/messages?agent_did={}&folder=inbox&status=all", aid);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn active_token_is_accepted_baseline() {
    // Sanity: a freshly-seeded active token reaches the endpoint. If this
    // ever fails, every other test in this file is testing the wrong thing.
    if !db_tests_enabled() {
        eprintln!("skipping: AGENT_INBOX_DB_TESTS != 1");
        return;
    }
    ensure_db_env();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let seeded = seed_active_agent_with_token(&pool).await;
    let app = common::test_app();
    let status = call_with_agent_token(&app, &seeded.access_token, &seeded.aid).await;
    assert_eq!(status, StatusCode::OK, "baseline active token must be 200");
}

#[tokio::test]
#[serial]
async fn self_revoke_rejects_next_call_immediately() {
    if !db_tests_enabled() {
        eprintln!("skipping: AGENT_INBOX_DB_TESTS != 1");
        return;
    }
    ensure_db_env();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let seeded = seed_active_agent_with_token(&pool).await;
    let app = common::test_app();

    // Revoke via the agent-self-revoke endpoint (simulates the agent calling
    // POST /agent-auth/revoke with its own token).
    let revoke_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/revoke")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "token": seeded.access_token }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);

    // The same token must now fail on the next authenticated call.
    let status = call_with_agent_token(&app, &seeded.access_token, &seeded.aid).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revoked token must be 401 on next use",
    );
}

#[tokio::test]
#[serial]
async fn credential_revoke_rejects_all_tokens_under_it() {
    if !db_tests_enabled() {
        eprintln!("skipping: AGENT_INBOX_DB_TESTS != 1");
        return;
    }
    ensure_db_env();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let seeded = seed_active_agent_with_token(&pool).await;

    // Simulate the human revoking the credential directly at the DB level
    // (mirrors what DELETE /agent-credentials/:id does, minus the cookie
    // auth dance — already tested in agent_credential_test.rs).
    sqlx::query(
        "UPDATE agent_credentials SET status = 'revoked', revoked_at = NOW() WHERE id = $1",
    )
    .bind(seeded.credential_id)
    .execute(&pool)
    .await
    .expect("revoke credential");
    sqlx::query(
        "UPDATE agent_tokens SET revoked_at = NOW() WHERE credential_id = $1 AND revoked_at IS NULL",
    )
    .bind(seeded.credential_id)
    .execute(&pool)
    .await
    .expect("revoke tokens");

    let app = common::test_app();
    let status = call_with_agent_token(&app, &seeded.access_token, &seeded.aid).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "token under revoked credential must be 401",
    );
}

#[tokio::test]
#[serial]
async fn emergency_shutdown_rejects_all_existing_tokens() {
    if !db_tests_enabled() {
        eprintln!("skipping: AGENT_INBOX_DB_TESTS != 1");
        return;
    }
    ensure_db_env();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let seeded = seed_active_agent_with_token(&pool).await;

    // Emergency shutdown: flip every credential for this aid to revoked
    // and revoke every live token (mirrors agent_emergency_shutdown
    // handler's SQL directly — route-level behavior is covered by
    // agent_credential_test.rs auth/DB-required tests).
    sqlx::query(
        "UPDATE agent_credentials SET status = 'revoked', revoked_at = NOW() \
         WHERE aid = $1 AND status IN ('pending', 'active')",
    )
    .bind(&seeded.aid)
    .execute(&pool)
    .await
    .expect("revoke credentials via shutdown");
    sqlx::query(
        "UPDATE agent_tokens SET revoked_at = NOW() WHERE credential_id IN ( \
             SELECT id FROM agent_credentials WHERE aid = $1 \
         ) AND revoked_at IS NULL",
    )
    .bind(&seeded.aid)
    .execute(&pool)
    .await
    .expect("revoke tokens via shutdown");

    let app = common::test_app();
    let status = call_with_agent_token(&app, &seeded.access_token, &seeded.aid).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "token after emergency shutdown must be 401",
    );
}

#[tokio::test]
#[serial]
async fn agent_deactivation_rejects_existing_tokens() {
    if !db_tests_enabled() {
        eprintln!("skipping: AGENT_INBOX_DB_TESTS != 1");
        return;
    }
    ensure_db_env();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let seeded = seed_active_agent_with_token(&pool).await;

    // Soft stop: flip agents.is_active to false without touching the
    // credential. validate_agent_token must still reject the token.
    sqlx::query("UPDATE agents SET is_active = false WHERE id = $1")
        .bind(seeded.agent_id)
        .execute(&pool)
        .await
        .expect("deactivate agent");

    let app = common::test_app();
    let status = call_with_agent_token(&app, &seeded.access_token, &seeded.aid).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "token must be rejected when agents.is_active = false",
    );
}

#[tokio::test]
#[serial]
async fn refresh_reuse_revokes_entire_token_family() {
    // Two tokens share a token_family_id. Refresh-rotating one of them and
    // then replaying its old refresh_hash must:
    //   (a) leave every token in that family revoked,
    //   (b) leave the credential marked 'compromised'.
    if !db_tests_enabled() {
        eprintln!("skipping: AGENT_INBOX_DB_TESTS != 1");
        return;
    }
    ensure_db_env();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let seeded = seed_active_agent_with_token(&pool).await;

    // Give the seeded token a refresh_hash so we can exercise the refresh
    // endpoint against it.
    let old_refresh = format!("agr_{}", Uuid::new_v4().simple());
    let old_refresh_hash = hex::encode(Sha256::digest(old_refresh.as_bytes()));
    sqlx::query("UPDATE agent_tokens SET refresh_hash = $1 WHERE id = $2")
        .bind(&old_refresh_hash)
        .bind(seeded.token_id)
        .execute(&pool)
        .await
        .expect("attach refresh hash");

    // Add a SIBLING token in the same family — mimics a token issued via
    // an earlier rotation that's still live.
    let sibling_id = Uuid::new_v4();
    let sibling_access = format!("agt_{}", Uuid::new_v4().simple());
    let sibling_access_hash = hex::encode(Sha256::digest(sibling_access.as_bytes()));
    sqlx::query(
        "INSERT INTO agent_tokens ( \
             id, credential_id, access_hash, refresh_hash, dpop_jkt, \
             scopes, issued_at, access_expires_at, refresh_expires_at, token_family_id \
         ) VALUES ( \
             $1, $2, $3, NULL, 'none', \
             ARRAY['messages.read', 'messages.send'], NOW(), NOW() + INTERVAL '1 hour', \
             NOW() + INTERVAL '30 days', $4 \
         )",
    )
    .bind(sibling_id)
    .bind(seeded.credential_id)
    .bind(&sibling_access_hash)
    .bind(seeded.token_family_id)
    .execute(&pool)
    .await
    .expect("seed sibling token");

    let app = common::test_app();

    // First refresh rotation (legitimate): old_refresh → new pair.
    let rotation = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "refresh_token": old_refresh }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        rotation.status(),
        StatusCode::OK,
        "first rotation must succeed",
    );

    // Replay the ALREADY-rotated refresh_token → reuse detected.
    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agent-auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "refresh_token": old_refresh }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::UNAUTHORIZED,
        "reuse must produce 401",
    );
    let body: Value =
        serde_json::from_slice(&replay.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "token_reuse_detected");

    // Every token in the family must be revoked.
    let family_rows = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS total, \
                COUNT(*) FILTER (WHERE revoked_at IS NOT NULL)::BIGINT AS revoked \
         FROM agent_tokens WHERE token_family_id = $1",
    )
    .bind(seeded.token_family_id)
    .fetch_one(&pool)
    .await
    .expect("count family tokens");
    let total: i64 = family_rows.get("total");
    let revoked: i64 = family_rows.get("revoked");
    assert!(total >= 2, "family must contain parent + sibling");
    assert_eq!(
        revoked, total,
        "every token in the family must be revoked, got {revoked}/{total}",
    );

    // The sibling's access token must now be rejected by the validation
    // path too (closes the loop: revocation state → handler behavior).
    let sibling_status = call_with_agent_token(&app, &sibling_access, &seeded.aid).await;
    assert_eq!(
        sibling_status,
        StatusCode::UNAUTHORIZED,
        "sibling token in reused family must be rejected",
    );

    // Credential must be marked 'compromised'.
    let cred_status: (String,) =
        sqlx::query_as("SELECT status FROM agent_credentials WHERE id = $1")
            .bind(seeded.credential_id)
            .fetch_one(&pool)
            .await
            .expect("read credential status");
    assert_eq!(cred_status.0, "compromised");

    // Audit trail: refresh_reuse_detected + credential_compromised both
    // present, both carrying token_family_id in their detail JSONB.
    //
    // `record_audit_event` is fire-and-forget (`tokio::spawn`), so the
    // rows may not be visible the instant the refresh handler returns.
    // Poll up to 2s before failing — avoids a spurious flake when the
    // DB is under load from parallel integration suites.
    let audits: Vec<(String, Value)> = {
        let mut out: Vec<(String, Value)> = Vec::new();
        for _ in 0..40 {
            out = sqlx::query_as(
                "SELECT event, detail FROM agent_audit_log \
                 WHERE user_id = $1 AND event IN ('refresh_reuse_detected','credential_compromised') \
                 ORDER BY created_at ASC",
            )
            .bind(seeded.user_id)
            .fetch_all(&pool)
            .await
            .expect("load audit events");
            if out.len() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        out
    };
    assert_eq!(
        audits.len(),
        2,
        "expected both refresh_reuse_detected and credential_compromised within 2s",
    );
    for (event, detail) in &audits {
        assert_eq!(
            detail["token_family_id"],
            seeded.token_family_id.to_string(),
            "audit event {event} must carry token_family_id",
        );
    }
}

#[tokio::test]
#[serial]
async fn unauthenticated_requests_are_rejected_for_both_schemes() {
    // A request with no Authorization header and no session cookie must
    // be rejected on both cookie-auth and agent-token routes with 401.
    // This guards the "no token" path — agent token validation and human
    // session validation agree on unauthorized = 401.
    if !db_tests_enabled() {
        eprintln!("skipping: AGENT_INBOX_DB_TESTS != 1");
        return;
    }
    ensure_db_env();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let app = common::test_app();

    // Agent-token path: /messages accepts both Cookie (human) and DPoP
    // (agent) auth. With neither, it must be 401.
    let no_auth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/messages?agent_did=aid:ai:nobody&folder=inbox&status=all")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);

    // Garbage-token path: agt_ prefix but no matching row → 401
    // (exercises the "token present but lookup fails" branch).
    let fake_agent = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/messages?agent_did=aid:ai:nobody&folder=inbox&status=all")
                .header("authorization", "Bearer agt_not_in_db")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fake_agent.status(), StatusCode::UNAUTHORIZED);

    // Human-session path: POST /agents requires a valid JWT cookie; with
    // no cookie we expect 401.
    let fake_cookie = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("content-type", "application/json")
                .header("cookie", "nexusinbox_session=garbage")
                .body(Body::from(
                    json!({
                        "label": "x",
                        "public_key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
                        "encryption_key": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fake_cookie.status(), StatusCode::UNAUTHORIZED);

    // Keep the unused-warning happy.
    let _ = pool;
}
