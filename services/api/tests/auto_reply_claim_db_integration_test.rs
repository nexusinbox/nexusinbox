//! DB-mode integration tests for the Agent Gateway auto-reply routes
//! (docs/29): the agent-scoped config read, `sender_is_contact` on the
//! pending list, and the claim / release pair that keeps auto-replies
//! at-most-once.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test auto_reply_claim_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
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
        "TRUNCATE TABLE agent_audit_log, agent_tokens, agent_credentials, contacts, \
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

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Owner {
    user_id: Uuid,
    session: String,
}

async fn seed_owner(pool: &PgPool, wid: &str) -> Owner {
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
    Owner {
        user_id,
        session: format!("Bearer {token}"),
    }
}

struct Agent {
    id: Uuid,
    did: String,
    aid: String,
}

async fn seed_agent(pool: &PgPool, owner: &Owner, label: &str, auto_reply: bool) -> Agent {
    let id = Uuid::new_v4();
    let did = format!("did:key:z{label}{}", Uuid::new_v4().simple());
    let aid = format!("aid:ai:claim{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active, \
           auto_reply) \
         VALUES ($1, $2, $3, $4, 'pk', 'ek', true, $5)",
    )
    .bind(id)
    .bind(owner.user_id)
    .bind(&did)
    .bind(label)
    .bind(auto_reply)
    .execute(pool)
    .await
    .expect("seed agent");
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(id)
        .bind(owner.user_id)
        .execute(pool)
        .await
        .expect("seed agent identity");
    sqlx::query(
        "INSERT INTO agent_identity_keys \
           (aid, did, signing_public_key, encryption_public_key, status) \
         VALUES ($1, $2, 'pk', 'ek', 'active')",
    )
    .bind(&aid)
    .bind(&did)
    .execute(pool)
    .await
    .expect("seed identity key");
    Agent { id, did, aid }
}

/// Plain-bearer agent token (`dpop_jkt = 'none'`) for `agent`.
async fn seed_agent_token(pool: &PgPool, owner: &Owner, agent: &Agent, scopes: &[&str]) -> String {
    let credential_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'test', 'active', 'unused', NOW())",
    )
    .bind(credential_id)
    .bind(&agent.aid)
    .bind(owner.user_id)
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
    .bind(scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed token");
    format!("Bearer {access}")
}

/// An inbox row addressed to `recipient` that the evaluator stamped
/// `auto_accept`, so it is on the pending list.
async fn seed_pending_row(
    pool: &PgPool,
    owner: &Owner,
    sender_did: &str,
    recipient: &Agent,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_index \
           (id, owner_user_id, sender_did, recipient_did, subject_encrypted, storage_ref, \
            status, priority, folder, starred, auto_reply_decision, auto_reply_reason) \
         VALUES ($1, $2, $3, $4, 'subject-ct', $5, 'unread', 'normal', 'inbox', FALSE, \
           'auto_accept', 'default_match')",
    )
    .bind(id)
    .bind(owner.user_id)
    .bind(sender_did)
    .bind(&recipient.did)
    .bind(format!("localfs:v1://{id}"))
    .execute(pool)
    .await
    .expect("seed pending row");
    id
}

async fn call(app: &axum::Router, method: &str, uri: &str, auth: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
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
async fn config_returns_only_the_token_agents_switch_and_policy() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xclaim-config").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let sibling = seed_agent(&pool, &owner, "b", false).await;
    for (target, policy) in [
        (&agent, json!({"v": 1, "default": "auto_accept"})),
        (&sibling, json!({"v": 1, "default": "auto_decline"})),
    ] {
        sqlx::query(
            "INSERT INTO agent_auto_reply_policies (agent_id, revision, policy, updated_by_user_id) \
             VALUES ($1, 3, $2, $3)",
        )
        .bind(target.id)
        .bind(policy)
        .bind(owner.user_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;

    let (status, body) = call(&app, "GET", "/agent-auto-reply/config", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["auto_reply_enabled"], json!(true));
    assert_eq!(
        body["policy"]["default"],
        json!("auto_accept"),
        "its own policy, not the sibling's"
    );
    assert_eq!(body["revision"], json!(3));
    assert!(body.get("contacts").is_none());

    let (status, _) = call(&app, "GET", "/agent-auto-reply/config", &owner.session).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "human sessions use the /agents routes"
    );

    let read_only = seed_agent_token(&pool, &owner, &agent, &["messages.read"]).await;
    let (status, _) = call(&app, "GET", "/agent-auto-reply/config", &read_only).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "messages.send is required");

    // An agent without a policy row gets nulls, not an error.
    let sibling_token =
        seed_agent_token(&pool, &owner, &sibling, &["messages.read", "messages.send"]).await;
    sqlx::query("DELETE FROM agent_auto_reply_policies WHERE agent_id = $1")
        .bind(sibling.id)
        .execute(&pool)
        .await
        .unwrap();
    let (status, body) = call(&app, "GET", "/agent-auto-reply/config", &sibling_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["auto_reply_enabled"], json!(false));
    assert_eq!(body["policy"], Value::Null);
    assert_eq!(body["revision"], Value::Null);
}

#[tokio::test]
#[serial]
async fn pending_list_carries_sender_is_contact_and_hides_claimed_rows() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xclaim-pending").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;
    let friend = "did:key:zfriend";
    sqlx::query("INSERT INTO contacts (owner_user_id, did, person_name) VALUES ($1, $2, 'Friend')")
        .bind(owner.user_id)
        .bind(friend)
        .execute(&pool)
        .await
        .unwrap();
    let from_friend = seed_pending_row(&pool, &owner, friend, &agent).await;
    let from_stranger = seed_pending_row(&pool, &owner, "did:key:zstranger", &agent).await;

    let (status, body) = call(&app, "GET", "/messages?auto_reply_pending=1", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["messages"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let expected = row["id"] == json!(from_friend.to_string());
        assert_eq!(row["sender_is_contact"], json!(expected), "{row}");
    }

    let (_, body) = call(&app, "GET", "/messages", &token).await;
    for row in body["messages"].as_array().unwrap() {
        assert!(
            row.get("sender_is_contact").is_none(),
            "only the pending list carries the contact bit: {row}"
        );
    }

    let (status, _) = call(
        &app,
        "POST",
        &format!("/messages/{from_friend}/auto-reply-claim"),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = call(&app, "GET", "/messages?auto_reply_pending=1", &token).await;
    let ids: Vec<&str> = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![from_stranger.to_string().as_str()],
        "claimed rows leave the list"
    );

    // The inbox list shows the claim, so an unconfirmed attempt is visible
    // to the human (docs/29 §2.5).
    let (_, body) = call(&app, "GET", "/messages", &token).await;
    for row in body["messages"].as_array().unwrap() {
        let claimed = row["id"] == json!(from_friend.to_string());
        assert_eq!(
            row.get("auto_reply_claimed_at").is_some(),
            claimed,
            "auto_reply_claimed_at only on the claimed row: {row}"
        );
    }
}

#[tokio::test]
#[serial]
async fn claim_is_won_once_and_released_only_while_unsent() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xclaim-once").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;
    let row = seed_pending_row(&pool, &owner, "did:key:zsender", &agent).await;
    let claim = format!("/messages/{row}/auto-reply-claim");

    // Two executors race: exactly one wins.
    let (a, b) = tokio::join!(
        call(&app, "POST", &claim, &token),
        call(&app, "POST", &claim, &owner.session),
    );
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);

    assert_eq!(
        call(&app, "DELETE", &claim, &token).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "DELETE", &claim, &token).await.0,
        StatusCode::CONFLICT,
        "nothing left to release"
    );
    assert_eq!(call(&app, "POST", &claim, &token).await.0, StatusCode::OK);

    let (status, _) = call(
        &app,
        "PATCH",
        &format!("/messages/{row}/auto-reply-sent"),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call(&app, "DELETE", &claim, &token).await.0,
        StatusCode::CONFLICT,
        "a claim whose reply went out stays"
    );
    assert_eq!(
        call(&app, "POST", &claim, &token).await.0,
        StatusCode::CONFLICT,
        "a sent row cannot be claimed again"
    );
}

#[tokio::test]
#[serial]
async fn agent_token_cannot_claim_a_sibling_agents_row() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xclaim-sibling").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let sibling = seed_agent(&pool, &owner, "b", true).await;
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;
    let sibling_row = seed_pending_row(&pool, &owner, "did:key:zsender", &sibling).await;

    for method in ["POST", "DELETE"] {
        let (status, _) = call(
            &app,
            method,
            &format!("/messages/{sibling_row}/auto-reply-claim"),
            &token,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} on a sibling's row");
    }
    let claimed: Option<String> =
        sqlx::query_scalar("SELECT auto_reply_claimed_at::text FROM message_index WHERE id = $1")
            .bind(sibling_row)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claimed, None, "the sibling's row stays unclaimed");
}
