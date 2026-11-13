//! DB-mode integration tests for envelope signature v2 (docs/40 §14):
//!   - a v2 signature over the whole envelope is checked when sending,
//!     kept with the ciphertext and returned with the content, with the
//!     sender's device list as it was when it was sent;
//!   - a signature over anything else than what arrived, or naming other
//!     agents, is refused;
//!   - v1 still works for older senders;
//!   - a v2 draft is sent with the wraps it was signed with.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test signature_v2_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use nexusinbox_api::envelope_v2;
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
        "TRUNCATE TABLE agent_device_lists, agent_drafts, agent_audit_log, agent_tokens, agent_credentials, message_attachments, \
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
           (id, aid, user_id, label, status, signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'test', 'active', 'unused', NOW())",
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

fn wrapped_key(marker: u8) -> String {
    format!(
        "x25519v1:{}:{}:{}:{}",
        URL_SAFE_NO_PAD.encode([marker; 32]),
        URL_SAFE_NO_PAD.encode([0u8; 16]),
        URL_SAFE_NO_PAD.encode([0u8; 12]),
        URL_SAFE_NO_PAD.encode([0u8; 48]),
    )
}

async fn register_review_key(app: &axum::Router, auth: &str) -> String {
    let (status, body) = call(
        app,
        "POST",
        "/review-keys",
        auth,
        Some(json!({ "public_key": URL_SAFE_NO_PAD.encode([9u8; 32]), "label": "Safari" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_string()
}

macro_rules! setup {
    () => {{
        if !db_tests_enabled() {
            eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
            return;
        }
        ensure_db_env();
        let pool = db_pool().await;
        reset_schema(&pool).await;
        (common::test_app(), pool)
    }};
}

const SENT_AT: &str = "2026-11-20T10:41:00.000Z";

struct V2 {
    content_type: &'static str,
    thread_id: Option<String>,
    subject_encrypted: String,
    encrypted_content: String,
    encrypted_key: String,
    nonce: String,
    sender_encrypted_key: Option<String>,
    encrypted_keys: Vec<(String, String)>,
    sender_encrypted_keys: Vec<(String, String)>,
}

fn v2_message(sender: &UserAgent, recipient_did: &str, marker: u8) -> V2 {
    V2 {
        content_type: "text/plain",
        thread_id: None,
        subject_encrypted: URL_SAFE_NO_PAD.encode(b"subject-ct-v2"),
        encrypted_content: URL_SAFE_NO_PAD.encode(b"body-ct-v2"),
        encrypted_key: wrapped_key(1),
        nonce: URL_SAFE_NO_PAD.encode([marker; 24]),
        sender_encrypted_key: Some(wrapped_key(3)),
        encrypted_keys: vec![(recipient_did.to_string(), wrapped_key(1))],
        sender_encrypted_keys: vec![(sender.did.clone(), wrapped_key(3))],
    }
}

/// The v2 signature by `signer` over `m` as sent from `sender` to the
/// recipient agent, naming `sender_aid` and `recipient_aid`.
fn sign_v2(
    signer: &SigningKey,
    sender: &UserAgent,
    recipient_did: &str,
    sender_aid: &str,
    recipient_aid: &str,
    m: &V2,
) -> Value {
    let wraps = |list: &[(String, String)]| -> Vec<(String, String)> { list.to_vec() };
    let ek = wraps(&m.encrypted_keys);
    let sek = wraps(&m.sender_encrypted_keys);
    let fields = envelope_v2::Fields {
        sender_aid,
        sender_did: &sender.did,
        recipient_aid,
        recipient_did,
        sent_at: SENT_AT,
        content_type: m.content_type,
        thread_id: m.thread_id.as_deref(),
        subject_encrypted: &m.subject_encrypted,
        encrypted_content: &m.encrypted_content,
        encrypted_key: &m.encrypted_key,
        nonce: &m.nonce,
        sender_encrypted_key: m.sender_encrypted_key.as_deref(),
        encrypted_keys: ek
            .iter()
            .map(|(did, key)| envelope_v2::Wrap { did, key })
            .collect(),
        sender_encrypted_keys: sek
            .iter()
            .map(|(did, key)| envelope_v2::Wrap { did, key })
            .collect(),
        attachments: vec![],
    };
    let signature = URL_SAFE_NO_PAD.encode(
        signer
            .sign(envelope_v2::signing_input(&fields).as_bytes())
            .to_bytes(),
    );
    json!({
        "signature": signature,
        "sent_at": SENT_AT,
        "sender_aid": sender_aid,
        "recipient_aid": recipient_aid,
    })
}

fn wraps_json(list: &[(String, String)]) -> Value {
    Value::Array(
        list.iter()
            .map(|(did, key)| json!({ "did": did, "key": key }))
            .collect(),
    )
}

fn send_body(sender: &UserAgent, recipient_did: &str, m: &V2, signature_v2: Value) -> Value {
    json!({
        "sender_did": sender.did,
        "recipient_did": recipient_did,
        "envelope": {
            "encrypted_content": m.encrypted_content,
            "encrypted_key": m.encrypted_key,
            "nonce": m.nonce,
            "sender_encrypted_key": m.sender_encrypted_key,
            "encrypted_keys": wraps_json(&m.encrypted_keys),
            "sender_encrypted_keys": wraps_json(&m.sender_encrypted_keys),
            "signature_v2": signature_v2,
            "metadata": {
                "subject_encrypted": m.subject_encrypted,
                "thread_id": m.thread_id,
                "content_type": m.content_type,
                "has_attachments": false,
            }
        }
    })
}

async fn seed_device_list(pool: &PgPool, aid: &str, version: i64, jws: &str) {
    sqlx::query("INSERT INTO agent_device_lists (aid, version, root_did, jws) VALUES ($1, $2, 'did:key:zroot', $3)")
        .bind(aid)
        .bind(version)
        .bind(jws)
        .execute(pool)
        .await
        .expect("seed device list");
}

async fn received_content(app: &axum::Router, pool: &PgPool, reader: &UserAgent) -> Value {
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM message_index WHERE owner_user_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(reader.user_id)
    .fetch_one(pool)
    .await
    .expect("a message");
    let (status, body) = call(
        app,
        "GET",
        &format!("/messages/{id}/content"),
        &reader.auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
#[serial]
async fn a_v2_signature_is_kept_and_returned_with_the_list_it_was_sent_under() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xv2-me", "secretary", 0x61).await;
    let friend = seed_user_with_agent(&pool, "0xv2-friend", "friend", 0x62).await;
    seed_device_list(&pool, &me.aid, 1, "list.v1.jws").await;
    seed_device_list(&pool, &me.aid, 2, "list.v2.jws").await;

    let m = v2_message(&me, &friend.did, 1);
    let sig = sign_v2(&me.signing_key, &me, &friend.did, &me.aid, &friend.aid, &m);
    let (status, body) = call(
        &app,
        "POST",
        "/messages",
        &me.auth,
        Some(send_body(&me, &friend.did, &m, sig.clone())),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    // A newer list after sending: the message keeps the one it went under.
    seed_device_list(&pool, &me.aid, 3, "list.v3.jws").await;

    // Local storage keeps the sender's copy readable here (production
    // storage serves both rows).
    for reader in [&me] {
        let content = received_content(&app, &pool, reader).await;
        assert_eq!(content["signature_v2"], sig, "{content}");
        assert_eq!(
            content["sender_device_list"],
            json!({ "version": 2, "jws": "list.v2.jws" })
        );
        assert_eq!(content["encrypted_keys"], wraps_json(&m.encrypted_keys));
        assert_eq!(
            content["sender_encrypted_key"],
            json!(m.sender_encrypted_key)
        );
        assert_eq!(content["content_type"], "text/plain");
    }
}

#[tokio::test]
#[serial]
async fn a_v2_signature_over_anything_else_is_refused() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xv2-me-2", "secretary", 0x63).await;
    let friend = seed_user_with_agent(&pool, "0xv2-friend-2", "friend", 0x64).await;
    let stranger = seed_user_with_agent(&pool, "0xv2-stranger", "stranger", 0x65).await;

    // Signed as text/plain, sent as a protocol message.
    let m = v2_message(&me, &friend.did, 2);
    let sig = sign_v2(&me.signing_key, &me, &friend.did, &me.aid, &friend.aid, &m);
    let mut body = send_body(&me, &friend.did, &m, sig);
    body["envelope"]["metadata"]["content_type"] = json!("application/vnd.nexusinbox.a2a+json");
    let (status, _) = call(&app, "POST", "/messages", &me.auth, Some(body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Signed without the sender's own wrap, sent with it.
    let mut unsigned_wrap = v2_message(&me, &friend.did, 3);
    unsigned_wrap.sender_encrypted_key = None;
    let sig = sign_v2(
        &me.signing_key,
        &me,
        &friend.did,
        &me.aid,
        &friend.aid,
        &unsigned_wrap,
    );
    let m = v2_message(&me, &friend.did, 3);
    let (status, _) = call(
        &app,
        "POST",
        "/messages",
        &me.auth,
        Some(send_body(&me, &friend.did, &m, sig)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Signed by another key.
    let m = v2_message(&me, &friend.did, 4);
    let sig = sign_v2(
        &stranger.signing_key,
        &me,
        &friend.did,
        &me.aid,
        &friend.aid,
        &m,
    );
    let (status, _) = call(
        &app,
        "POST",
        "/messages",
        &me.auth,
        Some(send_body(&me, &friend.did, &m, sig)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Naming another recipient agent, or another sending agent.
    let m = v2_message(&me, &friend.did, 5);
    let sig = sign_v2(
        &me.signing_key,
        &me,
        &friend.did,
        &me.aid,
        &stranger.aid,
        &m,
    );
    let (status, body) = call(
        &app,
        "POST",
        "/messages",
        &me.auth,
        Some(send_body(&me, &friend.did, &m, sig)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let sig = sign_v2(
        &me.signing_key,
        &me,
        &friend.did,
        &stranger.aid,
        &friend.aid,
        &m,
    );
    let (status, body) = call(
        &app,
        "POST",
        "/messages",
        &me.auth,
        Some(send_body(&me, &friend.did, &m, sig)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // A sent_at not in the form senders write.
    let mut sig = sign_v2(&me.signing_key, &me, &friend.did, &me.aid, &friend.aid, &m);
    sig["sent_at"] = json!("2026-11-20T10:41:00Z");
    let (status, _) = call(
        &app,
        "POST",
        "/messages",
        &me.auth,
        Some(send_body(&me, &friend.did, &m, sig)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let delivered: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_index")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(delivered, 0, "nothing was delivered");
}

#[tokio::test]
#[serial]
async fn v1_still_works_and_carries_no_v2_signature() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xv2-me-3", "secretary", 0x66).await;
    let friend = seed_user_with_agent(&pool, "0xv2-friend-3", "friend", 0x67).await;
    let m = v2_message(&me, &friend.did, 6);
    let signature = sign_envelope(
        &me.signing_key,
        &me.did,
        &friend.did,
        &m.subject_encrypted,
        &m.encrypted_content,
        &m.encrypted_key,
        &m.nonce,
    );
    let mut body = send_body(&me, &friend.did, &m, Value::Null);
    body["envelope"]["signature"] = json!(signature);
    let (status, body) = call(&app, "POST", "/messages", &me.auth, Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let content = received_content(&app, &pool, &me).await;
    assert!(content.get("signature_v2").is_none(), "{content}");
    assert!(content.get("sender_device_list").is_none(), "{content}");

    // Neither signature: refused.
    let (status, _) = call(
        &app,
        "POST",
        "/messages",
        &me.auth,
        Some(send_body(
            &me,
            &friend.did,
            &v2_message(&me, &friend.did, 7),
            Value::Null,
        )),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[serial]
async fn a_v2_draft_is_sent_with_the_wraps_it_was_signed_with() {
    let (app, pool) = setup!();
    let me = seed_user_with_agent(&pool, "0xv2-draft-me", "secretary", 0x68).await;
    let friend = seed_user_with_agent(&pool, "0xv2-draft-friend", "friend", 0x69).await;
    let agent = seed_agent_token(&pool, &me).await;
    let key_id = register_review_key(&app, &me.auth).await;

    let m = v2_message(&me, &friend.did, 8);
    let sig = sign_v2(&me.signing_key, &me, &friend.did, &me.aid, &friend.aid, &m);
    let draft = json!({
        "sender_did": me.did,
        "recipient_did": friend.did,
        "subject_encrypted": m.subject_encrypted,
        "encrypted_content": m.encrypted_content,
        "encrypted_key": m.encrypted_key,
        "nonce": m.nonce,
        "signature_v2": sig,
        "sender_encrypted_key": m.sender_encrypted_key,
        "encrypted_keys": wraps_json(&m.encrypted_keys),
        "sender_encrypted_keys": wraps_json(&m.sender_encrypted_keys),
        "content_type": "text/plain",
        "review_wraps": [{ "review_key_id": key_id, "wrapped_key": wrapped_key(2) }],
        "via": "Muse",
    });

    // A draft whose wraps differ from what was signed is refused when made.
    let mut tampered = draft.clone();
    tampered["encrypted_keys"] = json!([]);
    let (status, _) = call(&app, "POST", "/agent-drafts", &agent, Some(tampered)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, created) = call(&app, "POST", "/agent-drafts", &agent, Some(draft)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let draft_id = created["id"].as_str().unwrap().to_string();
    let (_, list) = call(&app, "GET", "/agent-drafts", &me.auth, None).await;
    assert_eq!(list["drafts"][0]["signed_v2"], true, "{list}");

    // The approving browser's wraps are ignored: the signed ones go out.
    let (status, sent) = call(
        &app,
        "POST",
        &format!("/agent-drafts/{draft_id}/send"),
        &me.auth,
        Some(json!({ "encrypted_keys": [{ "did": friend.did, "key": wrapped_key(9) }] })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{sent}");
    let content = received_content(&app, &pool, &me).await;
    assert_eq!(content["signature_v2"], sig);
    assert_eq!(content["encrypted_keys"], wraps_json(&m.encrypted_keys));
}
