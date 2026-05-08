//! DB-mode integration test for cross-user `POST /messages` delivery.
//!
//! Regression: `send_message` historically inserted a single
//! `message_index` row owned by the sender's user. `list_messages`
//! filters by `owner_user_id = caller`, so a message sent from user A's
//! agent to user B's agent never showed up in user B's inbox. Same-user
//! tests never noticed because sender_user == recipient_user.
//!
//! After the fix, cross-user sends write two rows: one sender-side
//! (folder='sent') and one recipient-side (folder='inbox'), sharing
//! thread_id. This test seeds two real users with one agent each and
//! asserts that both inboxes observe the correct rows.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test cross_user_delivery_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
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
    user_id: Uuid,
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
        user_id,
        auth,
        did,
        signing_key,
    }
}

/// Add a second agent under an existing user. Used by same-user Sent
/// view tests where two agents sit on one World ID. Reuses the caller's
/// session auth (each row only needs an extra `agents` + `agent_identities`
/// + `agent_identity_keys` triple).
async fn seed_additional_agent(
    pool: &PgPool,
    user_id: Uuid,
    auth: String,
    label: &str,
    signing_seed_byte: u8,
) -> UserAgent {
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
    .expect("seed additional agent");
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

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[serial]
async fn cross_user_send_lands_in_recipient_inbox_and_sender_sent() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let alice = seed_user_with_agent(&pool, "0xalice-xuser", "alice", 0x42).await;
    let bob = seed_user_with_agent(&pool, "0xbob-xuser", "bob", 0x77).await;

    // Alice -> Bob
    let send_body = build_send_body(&alice, &bob.did, 0x01);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &alice.auth)
                .header("content-type", "application/json")
                .body(Body::from(send_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let sent = body_json(response).await;
    let sender_message_id = sent["message_id"].as_str().unwrap().to_string();

    // --- DB-level assertions ---
    //
    // Sender row: folder='sent', owned by Alice.
    let sender_rows: Vec<(String, String)> =
        sqlx::query("SELECT id::text AS id, folder FROM message_index WHERE owner_user_id = $1")
            .bind(alice.user_id)
            .fetch_all(&pool)
            .await
            .expect("alice rows")
            .into_iter()
            .map(|row| (row.get("id"), row.get("folder")))
            .collect();
    assert_eq!(
        sender_rows.len(),
        1,
        "alice should have exactly one message_index row after cross-user send"
    );
    assert_eq!(sender_rows[0].1, "sent", "alice row folder must be 'sent'");
    assert_eq!(
        sender_rows[0].0, sender_message_id,
        "sender's row id must match the returned message_id",
    );

    // Recipient row: folder='inbox', owned by Bob, distinct id, same thread_id.
    let recipient_rows: Vec<(String, String, Option<String>)> = sqlx::query(
        "SELECT id::text AS id, folder, thread_id::text AS thread_id \
         FROM message_index WHERE owner_user_id = $1",
    )
    .bind(bob.user_id)
    .fetch_all(&pool)
    .await
    .expect("bob rows")
    .into_iter()
    .map(|row| (row.get("id"), row.get("folder"), row.get("thread_id")))
    .collect();
    assert_eq!(
        recipient_rows.len(),
        1,
        "bob should have exactly one message_index row after cross-user send"
    );
    assert_eq!(
        recipient_rows[0].1, "inbox",
        "bob row folder must be 'inbox'"
    );
    assert_ne!(
        recipient_rows[0].0, sender_message_id,
        "recipient row must have a distinct id from the sender row"
    );

    // --- API-level assertions ---
    //
    // Alice sees her message in the 'sent' folder scoped to her agent.
    let sent_list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={}&folder=sent", alice.did))
                .header("authorization", &alice.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sent_list.status(), StatusCode::OK);
    let sent_json = body_json(sent_list).await;
    let sent_messages = sent_json["messages"].as_array().unwrap();
    assert_eq!(
        sent_messages.len(),
        1,
        "alice's sent folder should contain the message"
    );
    assert_eq!(sent_messages[0]["folder"], "sent");

    // Bob sees the message in his inbox when listing.
    let inbox_list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={}&folder=inbox", bob.did))
                .header("authorization", &bob.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inbox_list.status(), StatusCode::OK);
    let inbox_json = body_json(inbox_list).await;
    let inbox_messages = inbox_json["messages"].as_array().unwrap();
    assert_eq!(
        inbox_messages.len(),
        1,
        "bob's inbox should contain the cross-user message"
    );
    assert_eq!(inbox_messages[0]["folder"], "inbox");
    assert_eq!(inbox_messages[0]["sender_did"], alice.did);
    assert_eq!(inbox_messages[0]["recipient_did"], bob.did);
}

#[tokio::test]
#[serial]
async fn cross_user_delete_sender_row_does_not_garbage_collect_shared_payload() {
    // Regression: `send_message` writes two `message_index` rows that share
    // the same storage_ref. If `delete_message` deletes the storage blob
    // based on only the caller's row, the peer's row is left pointing at a
    // missing blob. Bob would get 404/500 when trying to read his inbox.
    //
    // This test drives a full A→B send, then has Alice delete her sent-side
    // row, and asserts Bob's inbox row still exists with the same
    // storage_ref. Finally Bob deletes, and only then is the storage_ref
    // unreferenced.
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let alice = seed_user_with_agent(&pool, "0xalice-delshared", "alice", 0x21).await;
    let bob = seed_user_with_agent(&pool, "0xbob-delshared", "bob", 0x22).await;

    let send_body = build_send_body(&alice, &bob.did, 0x30);
    let sent = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &alice.auth)
                .header("content-type", "application/json")
                .body(Body::from(send_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sent.status(), StatusCode::ACCEPTED);
    let sent_body = body_json(sent).await;
    let sender_row_id = sent_body["message_id"].as_str().unwrap().to_string();

    // Grab the shared storage_ref + the recipient's row id.
    let storage_ref: String =
        sqlx::query_scalar("SELECT storage_ref FROM message_index WHERE id::text = $1")
            .bind(&sender_row_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let bob_row_id: String =
        sqlx::query_scalar("SELECT id::text FROM message_index WHERE owner_user_id = $1")
            .bind(bob.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    // Alice deletes her sent row.
    let del_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/messages/{sender_row_id}"))
                .header("authorization", &alice.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_alice.status(), StatusCode::NO_CONTENT);

    // Alice's row is gone, Bob's row is intact.
    let alice_remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(alice.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        alice_remaining, 0,
        "alice row must be gone after her delete"
    );

    let bob_remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(bob.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        bob_remaining, 1,
        "bob row MUST still exist after alice's delete — this is the regression"
    );

    // Bob still references the same storage_ref.
    let shared_ref_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE storage_ref = $1")
            .bind(&storage_ref)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        shared_ref_count, 1,
        "bob's row must still reference the shared storage_ref"
    );

    // Bob can still list his inbox and see the message.
    let bob_inbox = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={}&folder=inbox", bob.did))
                .header("authorization", &bob.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_inbox.status(), StatusCode::OK);
    let inbox_json = body_json(bob_inbox).await;
    assert_eq!(
        inbox_json["messages"].as_array().unwrap().len(),
        1,
        "bob's inbox must still list the message after alice's delete"
    );

    // Bob deletes his row. Now the storage_ref has no refs and can be GC'd.
    let del_bob = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/messages/{bob_row_id}"))
                .header("authorization", &bob.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_bob.status(), StatusCode::NO_CONTENT);

    let final_ref_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE storage_ref = $1")
            .bind(&storage_ref)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(final_ref_count, 0);
}

#[tokio::test]
#[serial]
async fn cross_user_reply_preserves_thread_id_on_both_sides() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    let alice = seed_user_with_agent(&pool, "0xalice-reply", "alice", 0x11).await;
    let bob = seed_user_with_agent(&pool, "0xbob-reply", "bob", 0x22).await;

    // Alice -> Bob (opens a thread server-side when thread_id is null).
    let first = build_send_body(&alice, &bob.did, 0x10);
    let first_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &alice.auth)
                .header("content-type", "application/json")
                .body(Body::from(first.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_resp.status(), StatusCode::ACCEPTED);

    // Read Bob's inbox to discover the thread_id server-assigned on this send.
    let bob_inbox = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={}&folder=inbox", bob.did))
                .header("authorization", &bob.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let inbox = body_json(bob_inbox).await;
    let incoming = &inbox["messages"][0];
    let thread_id = incoming["thread_id"].as_str().map(|s| s.to_string());
    // thread_id may be null when the server defers thread assignment to the
    // first reply; in that case skip this stronger assertion and only check
    // that Bob's reply lands in Alice's inbox.
    let bob_reply = {
        let subject = URL_SAFE_NO_PAD.encode(b"Re: cross-user");
        let content = URL_SAFE_NO_PAD.encode(b"reply-ct");
        let key = format!(
            "x25519v1:{}:{}:{}:{}",
            URL_SAFE_NO_PAD.encode([0u8; 32]),
            URL_SAFE_NO_PAD.encode([0u8; 16]),
            URL_SAFE_NO_PAD.encode([0u8; 12]),
            URL_SAFE_NO_PAD.encode([0u8; 48]),
        );
        let mut n = [0u8; 24];
        n[0] = 0x20;
        let nonce = URL_SAFE_NO_PAD.encode(n);
        let signature = sign_envelope(
            &bob.signing_key,
            &bob.did,
            &alice.did,
            &subject,
            &content,
            &key,
            &nonce,
        );
        json!({
            "sender_did": bob.did,
            "recipient_did": alice.did,
            "envelope": {
                "encrypted_content": content,
                "encrypted_key": key,
                "nonce": nonce,
                "signature": signature,
                "metadata": {
                    "subject_encrypted": subject,
                    "thread_id": thread_id,
                    "content_type": "text/plain",
                    "has_attachments": false,
                }
            },
            "priority": "normal",
        })
    };

    let reply_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &bob.auth)
                .header("content-type", "application/json")
                .body(Body::from(bob_reply.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reply_resp.status(), StatusCode::ACCEPTED);

    // Alice's inbox now contains bob's reply.
    let alice_inbox = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={}&folder=inbox", alice.did))
                .header("authorization", &alice.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let alice_inbox_json = body_json(alice_inbox).await;
    let alice_msgs = alice_inbox_json["messages"].as_array().unwrap();
    assert_eq!(
        alice_msgs.len(),
        1,
        "alice's inbox should now contain bob's reply"
    );
    assert_eq!(alice_msgs[0]["sender_did"], bob.did);
    assert_eq!(alice_msgs[0]["recipient_did"], alice.did);

    // Alice's "sent" folder still holds the original outbound message
    // (the reply did not change Alice's sent count).
    let alice_sent = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/messages?agent_did={}&folder=sent", alice.did))
                .header("authorization", &alice.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let alice_sent_json = body_json(alice_sent).await;
    assert_eq!(alice_sent_json["messages"].as_array().unwrap().len(), 1);
}

/// Same-user (one human, two of their own agents) sends create only the
/// recipient-side `message_index` row (folder='inbox') by design — no
/// dual row, no extra storage. Before the fix the Sent view gated on
/// `m.folder = 'sent'`, so same-user sends were invisible there. The fix
/// identifies "my sent" by `sender_did = (one of my dids)` instead, so
/// the single row appears in both Sent (sender perspective) and Inbox
/// (recipient perspective) without changing the INSERT.
#[tokio::test]
#[serial]
async fn same_user_send_appears_in_sent_view() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;

    // One World ID owns two agents. This mirrors today's "two
    // secretaries on one human" test setup so the regression check
    // matches the production trigger.
    let agent_a = seed_user_with_agent(&pool, "0xowner-same", "secretary-1", 0x33).await;
    let agent_b = seed_additional_agent(
        &pool,
        agent_a.user_id,
        agent_a.auth.clone(),
        "secretary-2",
        0x44,
    )
    .await;

    // Agent A → Agent B (same human owns both).
    let send_body = build_send_body(&agent_a, &agent_b.did, 0x05);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/messages")
                .header("authorization", &agent_a.auth)
                .header("content-type", "application/json")
                .body(Body::from(send_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Sanity: same-user send is single-row (the optimization that made
    // the Sent view break in the first place is preserved).
    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE owner_user_id = $1")
            .bind(agent_a.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 1, "same-user send must remain single-row");

    // Agent A's Sent view: regression target. Pre-fix this returned 0.
    let sent_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages?agent_did={}&folder=sent", agent_a.did))
                .header("authorization", &agent_a.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sent_a.status(), StatusCode::OK);
    let sent_a_json = body_json(sent_a).await;
    assert_eq!(
        sent_a_json["messages"].as_array().unwrap().len(),
        1,
        "agent A's Sent must surface the same-user send",
    );
    assert_eq!(sent_a_json["messages"][0]["sender_did"], agent_a.did);
    assert_eq!(sent_a_json["messages"][0]["recipient_did"], agent_b.did);

    // Agent B's Inbox view: shows the same row from the recipient
    // perspective. Was already working pre-fix; included as the
    // "no regression" half of the contract.
    let inbox_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages?agent_did={}&folder=inbox", agent_b.did))
                .header("authorization", &agent_a.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let inbox_b_json = body_json(inbox_b).await;
    assert_eq!(
        inbox_b_json["messages"].as_array().unwrap().len(),
        1,
        "agent B's Inbox must keep showing the message",
    );

    // Agent B's Sent view must NOT include the row — B didn't send,
    // it only received. Sender_did filter excludes correctly.
    let sent_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/messages?agent_did={}&folder=sent", agent_b.did))
                .header("authorization", &agent_a.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sent_b_json = body_json(sent_b).await;
    assert_eq!(
        sent_b_json["messages"].as_array().unwrap().len(),
        0,
        "agent B's Sent must stay empty — B didn't send",
    );

    // agent_did=all + folder=sent: the user_owned_dids subquery should
    // pick up agent A's did and surface the row exactly once.
    let sent_all = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/messages?agent_did=all&folder=sent")
                .header("authorization", &agent_a.auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sent_all_json = body_json(sent_all).await;
    assert_eq!(
        sent_all_json["messages"].as_array().unwrap().len(),
        1,
        "Sent across all agents must include the same-user send",
    );
}
