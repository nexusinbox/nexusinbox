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
    sqlx::query("INSERT INTO contacts (owner_user_id, did, sealed) VALUES ($1, $2, 'cs1:aXY:Y3Q')")
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

/// The agent page lists an agent's automatic replies from the audit log
/// filtered by AID (docs/31 §4 step 3), so a send must name the agent and
/// what was decided, and tell a real reply from a row handled silently.
#[tokio::test]
#[serial]
async fn sent_audit_names_the_agent_and_the_decision() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xsent-audit").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;
    let answered = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    let skipped = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    let reply_id = Uuid::new_v4();

    for (row, body) in [
        (answered, json!({ "reply_message_id": reply_id })),
        (skipped, json!({})),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/messages/{row}/auto-reply-sent"))
                    .header("authorization", &token)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // The audit write is fire-and-forget.
    let mut rows: Vec<(Option<String>, Value)> = Vec::new();
    for _ in 0..40 {
        rows = sqlx::query_as(
            "SELECT aid, detail FROM agent_audit_log WHERE event = 'auto_reply_sent' \
             ORDER BY detail->>'message_id'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        if rows.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rows.len(), 2);
    for (aid, detail) in &rows {
        assert_eq!(aid.as_deref(), Some(agent.aid.as_str()));
        assert_eq!(detail["decision"], "auto_accept");
        let message_id = detail["message_id"].as_str().unwrap();
        if message_id == answered.to_string() {
            assert_eq!(detail["reply_message_id"], reply_id.to_string());
        } else {
            assert_eq!(message_id, skipped.to_string());
            assert!(detail["reply_message_id"].is_null());
        }
    }
}

/// Migration 0024 fills in the AID of auto-reply rows written before the
/// API recorded it, and touches nothing else.
#[tokio::test]
#[serial]
async fn older_auto_reply_audit_rows_get_their_aid() {
    skip_without_db!();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xaudit-backfill").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;

    let insert = |event: &'static str, detail: Value| {
        let pool = pool.clone();
        let user_id = owner.user_id;
        async move {
            sqlx::query("INSERT INTO agent_audit_log (user_id, event, detail) VALUES ($1, $2, $3)")
                .bind(user_id)
                .bind(event)
                .bind(detail)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    insert(
        "auto_reply_evaluated",
        json!({ "agent_id": agent.id.to_string() }),
    )
    .await;
    insert("auto_reply_sent", json!({ "recipient_did": agent.did })).await;
    // Unknown agent, and another event naming the agent: both stay as they are.
    insert(
        "auto_reply_sent",
        json!({ "recipient_did": "did:key:zsomeone-else" }),
    )
    .await;
    insert(
        "auto_reply_policy_updated",
        json!({ "agent_id": agent.id.to_string() }),
    )
    .await;

    sqlx::raw_sql(include_str!("../migrations/0024_audit_auto_reply_aid.sql"))
        .execute(&pool)
        .await
        .expect("migration 0024");

    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT event, aid FROM agent_audit_log ORDER BY event, aid NULLS LAST")
            .fetch_all(&pool)
            .await
            .unwrap();
    let aids: Vec<(&str, Option<&str>)> = rows
        .iter()
        .map(|(event, aid)| (event.as_str(), aid.as_deref()))
        .collect();
    assert_eq!(
        aids,
        [
            ("auto_reply_evaluated", Some(agent.aid.as_str())),
            ("auto_reply_policy_updated", None),
            ("auto_reply_sent", Some(agent.aid.as_str())),
            ("auto_reply_sent", None),
        ]
    );
}

/// A well-formed Ed25519 did:key for a fresh random key.
fn real_did() -> String {
    let seed: [u8; 32] = rand::random();
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&verifying_key.to_bytes());
    format!("did:key:z{}", bs58::encode(&multicodec).into_string())
}

async fn mark_sent(app: &axum::Router, row: Uuid, auth: &str, body: Value) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/messages/{row}/auto-reply-sent"))
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The inbox labels a row "auto-replied" only when a reply went out: the
/// list carries the reply's id, and rows handled without one have none.
#[tokio::test]
#[serial]
async fn the_inbox_learns_which_rows_were_answered() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xanswered").await;
    let mut agent = seed_agent(&pool, &owner, "a", true).await;
    // The list endpoint checks the DID's format, so give this one a real did:key.
    let did = real_did();
    sqlx::query("UPDATE agent_identity_keys SET did = $1 WHERE aid = $2")
        .bind(&did)
        .bind(&agent.aid)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE agents SET did = $1 WHERE id = $2")
        .bind(&did)
        .bind(agent.id)
        .execute(&pool)
        .await
        .unwrap();
    agent.did = did;
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;
    let answered = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    let handled = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    let reply_id = Uuid::new_v4();

    assert_eq!(
        mark_sent(
            &app,
            answered,
            &token,
            json!({ "reply_message_id": reply_id })
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        mark_sent(&app, handled, &token, json!({})).await,
        StatusCode::OK
    );
    // A second mark changes nothing.
    assert_eq!(
        mark_sent(
            &app,
            answered,
            &token,
            json!({ "reply_message_id": Uuid::new_v4() })
        )
        .await,
        StatusCode::OK
    );

    let (status, list) = call(
        &app,
        "GET",
        &format!("/messages?agent_did={}&status=all", agent.did),
        &owner.session,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let rows = list["messages"].as_array().unwrap();
    let find = |id: Uuid| {
        rows.iter()
            .find(|m| m["id"] == id.to_string())
            .unwrap_or_else(|| panic!("row {id} missing from {list}"))
    };
    assert_eq!(
        find(answered)["auto_reply_message_id"],
        reply_id.to_string()
    );
    assert!(find(handled)["auto_reply_sent_at"].is_string());
    assert!(find(handled).get("auto_reply_message_id").is_none());
}

/// Migration 0025 takes older rows' reply ids from the audit log: only
/// for the row's owner, only real ids, never over an existing one.
#[tokio::test]
#[serial]
async fn older_rows_get_their_reply_id_from_the_audit_log() {
    skip_without_db!();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xreply-backfill").await;
    let stranger = seed_owner(&pool, "0xreply-stranger").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let answered = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    let handled = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    let spoofed = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    sqlx::query("UPDATE message_index SET auto_reply_sent_at = NOW()")
        .execute(&pool)
        .await
        .unwrap();
    let reply_id = Uuid::new_v4();
    for (user_id, message_id, reply) in [
        (owner.user_id, answered, json!(reply_id.to_string())),
        (owner.user_id, handled, Value::Null),
        // Another user's event naming this row is not believed.
        (stranger.user_id, spoofed, json!(Uuid::new_v4().to_string())),
    ] {
        sqlx::query(
            "INSERT INTO agent_audit_log (user_id, event, detail) VALUES ($1, 'auto_reply_sent', $2)",
        )
        .bind(user_id)
        .bind(json!({ "message_id": message_id.to_string(), "reply_message_id": reply }))
        .execute(&pool)
        .await
        .unwrap();
    }

    sqlx::raw_sql(include_str!(
        "../migrations/0025_message_index_auto_reply_message_id.sql"
    ))
    .execute(&pool)
    .await
    .expect("migration 0025");

    let reply_of = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT auto_reply_message_id FROM message_index WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(reply_of(answered).await, Some(reply_id));
    assert_eq!(reply_of(handled).await, None);
    assert_eq!(reply_of(spoofed).await, None);
}

async fn post_skip(app: &axum::Router, row: Uuid, auth: &str, reason: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/messages/{row}/auto-reply-skip"))
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "reason": reason }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// An executor that left an auto-reply to the person records why, with
/// the reason code only, so every device shows it (docs/40 §13.3).
#[tokio::test]
#[serial]
async fn a_sender_that_did_not_check_out_is_a_skip_reason() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xskip-v2").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;
    // docs/40 §14.5: the sender's signature or list did not check out.
    // docs/40 §15.2: the other agent has no device list yet.
    for reason in ["unsigned", "altered", "not_listed", "stale", "no_list"] {
        let row = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
        assert_eq!(
            post_skip(&app, row, &token, reason).await,
            StatusCode::OK,
            "{reason}"
        );
    }
}

#[tokio::test]
#[serial]
async fn a_skipped_auto_reply_is_recorded_with_its_reason() {
    skip_without_db!();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let owner = seed_owner(&pool, "0xskip").await;
    let agent = seed_agent(&pool, &owner, "a", true).await;
    let sibling = seed_agent(&pool, &owner, "b", true).await;
    let token = seed_agent_token(&pool, &owner, &agent, &["messages.read", "messages.send"]).await;
    let row = seed_pending_row(&pool, &owner, "did:key:zfriend", &agent).await;
    let sibling_row = seed_pending_row(&pool, &owner, "did:key:zfriend", &sibling).await;

    assert_eq!(
        post_skip(&app, row, &token, "root_changed").await,
        StatusCode::OK
    );
    assert_eq!(
        post_skip(&app, row, &owner.session, "no_device").await,
        StatusCode::OK
    );
    assert_eq!(
        post_skip(&app, row, &token, "because").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        post_skip(&app, sibling_row, &token, "signature").await,
        StatusCode::NOT_FOUND
    );

    let mut rows: Vec<(Option<String>, Option<Uuid>, Value)> = Vec::new();
    for _ in 0..40 {
        rows = sqlx::query_as(
            "SELECT aid, credential_id, detail FROM agent_audit_log \
             WHERE event = 'auto_reply_skipped' ORDER BY detail->>'by' DESC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        if rows.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rows.len(), 2, "{rows:?}");
    let (aid, credential, detail) = &rows[0];
    assert_eq!(aid.as_deref(), Some(agent.aid.as_str()));
    assert!(credential.is_some());
    assert_eq!(detail["by"], "computer");
    assert_eq!(detail["reason"], "root_changed");
    assert_eq!(detail["sender_did"], "did:key:zfriend");
    assert_eq!(detail["message_id"], row.to_string());
    let (aid, credential, detail) = &rows[1];
    assert_eq!(aid.as_deref(), Some(agent.aid.as_str()));
    assert!(credential.is_none());
    assert_eq!(detail["by"], "browser");
    assert_eq!(detail["reason"], "no_device");

    // The claim is untouched: the reply stays with the person.
    let claimed: Option<String> =
        sqlx::query_scalar("SELECT auto_reply_sent_at::text FROM message_index WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claimed, None);
}
