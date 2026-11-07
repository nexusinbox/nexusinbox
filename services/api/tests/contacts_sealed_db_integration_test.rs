//! DB-mode integration tests for sealed contacts and contact keys
//! (docs/28 P3-8): the server keeps a contact's DID and an opaque sealed
//! blob, and stores the person's contacts key only as wraps for their own
//! agents.
//!
//! Usage:
//!   docker-compose up -d postgres
//!   AGENT_INBOX_DB_TESTS=1 \
//!     DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
//!     cargo test --test contacts_sealed_db_integration_test -- --test-threads=1

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
        "TRUNCATE TABLE contact_key_wraps, contacts, agent_tokens, agent_credentials, \
         sessions, agent_identity_keys, agent_identities, agents, users \
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

/// A well-formed Ed25519 did:key for a fresh random key.
fn random_did() -> String {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&verifying_key.to_bytes());
    format!("did:key:z{}", bs58::encode(&multicodec).into_string())
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

/// An agent row is all the contact-key endpoints look at.
async fn seed_agent(pool: &PgPool, owner: &Person) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let did = random_did();
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'agent', 'pk', 'ek', true)",
    )
    .bind(id)
    .bind(owner.user_id)
    .bind(&did)
    .execute(pool)
    .await
    .expect("seed agent");
    (id, did)
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", auth);
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

const SEALED_A: &str = "cs1:aXYtYWFhYWFhYWFhYWFh:Y2lwaGVydGV4dC1h";
const SEALED_B: &str = "cs1:aXYtYmJiYmJiYmJiYmJi:Y2lwaGVydGV4dC1i";
const WRAP_1: &str = "ckx25519v1:ZXBo:c2FsdA:aXY:Y3Qx";
const WRAP_2: &str = "ckx25519v1:ZXBo:c2FsdA:aXY:Y3Qy";

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
async fn contacts_keep_only_the_did_and_a_sealed_blob() {
    let (app, pool) = db_test_prelude!();
    let alice = seed_person(&pool, "0xalice-contacts").await;
    let did = random_did();

    // The old plaintext shape is no longer accepted.
    let (status, _) = call(
        &app,
        "POST",
        "/contacts",
        &alice.auth,
        Some(json!({ "did": did, "person_name": "Bob", "note": "met at a party" })),
    )
    .await;
    assert!(status.is_client_error(), "plaintext create got {status}");
    let (status, _) = call(
        &app,
        "POST",
        "/contacts",
        &alice.auth,
        Some(json!({ "did": did, "sealed": "Bob" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = call(
        &app,
        "POST",
        "/contacts",
        &alice.auth,
        Some(json!({ "did": did, "sealed": SEALED_A })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let sealed: String = sqlx::query_scalar("SELECT sealed FROM contacts WHERE did = $1")
        .bind(&did)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sealed, SEALED_A);
    // The table has no column a name or note could be written to.
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_name = 'contacts' ORDER BY column_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        columns,
        [
            "created_at",
            "did",
            "id",
            "owner_user_id",
            "sealed",
            "updated_at"
        ]
    );

    let (status, body) = call(&app, "GET", "/contacts", &alice.auth, None).await;
    assert_eq!(status, StatusCode::OK);
    let contact = body["contacts"][0].as_object().unwrap();
    assert_eq!(contact["did"], did);
    assert_eq!(contact["sealed"], SEALED_A);
    let mut keys: Vec<&str> = contact.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["created_at", "did", "id", "sealed", "updated_at"]);
}

#[tokio::test]
#[serial]
async fn updating_a_contact_replaces_its_sealed_fields() {
    let (app, pool) = db_test_prelude!();
    let alice = seed_person(&pool, "0xalice-update").await;
    let did = random_did();
    let (status, body) = call(
        &app,
        "POST",
        "/contacts",
        &alice.auth,
        Some(json!({ "did": did, "sealed": SEALED_A })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["id"].as_str().unwrap().to_string();

    let (status, body) = call(
        &app,
        "PATCH",
        &format!("/contacts/{id}"),
        &alice.auth,
        Some(json!({ "sealed": SEALED_B })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sealed"], SEALED_B);
    let sealed: String = sqlx::query_scalar("SELECT sealed FROM contacts WHERE did = $1")
        .bind(&did)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sealed, SEALED_B);

    // Another person cannot replace it.
    let mallory = seed_person(&pool, "0xmallory-update").await;
    let (status, _) = call(
        &app,
        "PATCH",
        &format!("/contacts/{id}"),
        &mallory.auth,
        Some(json!({ "sealed": SEALED_A })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

async fn wraps_of(pool: &PgPool, user_id: Uuid) -> Vec<(Uuid, String)> {
    sqlx::query_as(
        "SELECT agent_id, wrapped_key FROM contact_key_wraps WHERE user_id = $1 ORDER BY wrapped_key",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[serial]
async fn contact_key_wraps_are_added_but_never_replaced() {
    let (app, pool) = db_test_prelude!();
    let alice = seed_person(&pool, "0xalice-wraps").await;
    let (agent_1, did_1) = seed_agent(&pool, &alice).await;
    let (agent_2, did_2) = seed_agent(&pool, &alice).await;

    let (status, _) = call(
        &app,
        "POST",
        "/contact-keys",
        &alice.auth,
        Some(json!({ "initial": true, "wraps": [{ "agent_id": agent_1, "wrapped_key": WRAP_1 }] })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A second device starting its own key is told to open the existing one.
    let (status, body) = call(
        &app,
        "POST",
        "/contact-keys",
        &alice.auth,
        Some(json!({ "initial": true, "wraps": [{ "agent_id": agent_2, "wrapped_key": WRAP_2 }] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "contacts_key_exists");
    assert_eq!(wraps_of(&pool, alice.user_id).await.len(), 1);

    // Filling in a missing agent works; an existing wrap is left alone.
    let (status, _) = call(
        &app,
        "POST",
        "/contact-keys",
        &alice.auth,
        Some(json!({ "wraps": [
            { "agent_id": agent_1, "wrapped_key": WRAP_2 },
            { "agent_id": agent_2, "wrapped_key": WRAP_2 }
        ] })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        wraps_of(&pool, alice.user_id).await,
        vec![(agent_1, WRAP_1.to_string()), (agent_2, WRAP_2.to_string())]
    );

    let (status, body) = call(&app, "GET", "/contact-keys", &alice.auth, None).await;
    assert_eq!(status, StatusCode::OK);
    let wraps = body["wraps"].as_array().unwrap();
    assert_eq!(wraps.len(), 2);
    let dids: Vec<&str> = wraps
        .iter()
        .map(|w| w["agent_did"].as_str().unwrap())
        .collect();
    assert!(dids.contains(&did_1.as_str()) && dids.contains(&did_2.as_str()));
}

#[tokio::test]
#[serial]
async fn wraps_are_only_for_your_own_agents() {
    let (app, pool) = db_test_prelude!();
    let alice = seed_person(&pool, "0xalice-own").await;
    let bob = seed_person(&pool, "0xbob-own").await;
    let (alice_agent, _) = seed_agent(&pool, &alice).await;
    let (bob_agent, _) = seed_agent(&pool, &bob).await;

    let (status, _) = call(
        &app,
        "POST",
        "/contact-keys",
        &alice.auth,
        Some(json!({ "wraps": [
            { "agent_id": alice_agent, "wrapped_key": WRAP_1 },
            { "agent_id": bob_agent, "wrapped_key": WRAP_1 }
        ] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(
        &app,
        "POST",
        "/contact-keys",
        &alice.auth,
        Some(json!({ "wraps": [
            { "agent_id": alice_agent, "wrapped_key": WRAP_1 },
            { "agent_id": alice_agent, "wrapped_key": WRAP_2 }
        ] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = call(
        &app,
        "POST",
        "/contact-keys",
        &alice.auth,
        Some(json!({ "wraps": [{ "agent_id": alice_agent, "wrapped_key": "x25519v1:ZXBo:c2FsdA:aXY:Y3Q" }] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    assert!(wraps_of(&pool, alice.user_id).await.is_empty());
    assert!(wraps_of(&pool, bob.user_id).await.is_empty());
}

#[tokio::test]
#[serial]
async fn deleting_an_agent_drops_its_wrap_and_reset_drops_the_rest() {
    let (app, pool) = db_test_prelude!();
    let alice = seed_person(&pool, "0xalice-reset").await;
    let (agent_1, _) = seed_agent(&pool, &alice).await;
    let (agent_2, _) = seed_agent(&pool, &alice).await;
    let (status, _) = call(
        &app,
        "POST",
        "/contact-keys",
        &alice.auth,
        Some(json!({ "initial": true, "wraps": [
            { "agent_id": agent_1, "wrapped_key": WRAP_1 },
            { "agent_id": agent_2, "wrapped_key": WRAP_2 }
        ] })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let did = random_did();
    let (status, _) = call(
        &app,
        "POST",
        "/contacts",
        &alice.auth,
        Some(json!({ "did": did, "sealed": SEALED_A })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    sqlx::query("DELETE FROM agents WHERE id = $1")
        .bind(agent_1)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        wraps_of(&pool, alice.user_id).await,
        vec![(agent_2, WRAP_2.to_string())]
    );

    let (status, _) = call(&app, "DELETE", "/contact-keys", &alice.auth, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(wraps_of(&pool, alice.user_id).await.is_empty());
    // The sealed contacts stay; the person decides what to do with them.
    let (_, body) = call(&app, "GET", "/contacts", &alice.auth, None).await;
    assert_eq!(body["contacts"].as_array().unwrap().len(), 1);
}

#[tokio::test]
#[serial]
async fn agent_tokens_cannot_reach_contacts_or_contact_keys() {
    let (app, pool) = db_test_prelude!();
    let alice = seed_person(&pool, "0xalice-agent-token").await;
    let (agent_id, _) = seed_agent(&pool, &alice).await;
    let aid = format!("aid:ai:ct{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO agent_identities (aid, agent_id, user_id) VALUES ($1, $2, $3)")
        .bind(&aid)
        .bind(agent_id)
        .bind(alice.user_id)
        .execute(&pool)
        .await
        .unwrap();
    let credential_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_credentials \
           (id, aid, user_id, label, status, signing_public_key, activated_at) \
         VALUES ($1, $2, $3, 'test', 'active', 'unused', NOW())",
    )
    .bind(credential_id)
    .bind(&aid)
    .bind(alice.user_id)
    .execute(&pool)
    .await
    .unwrap();
    let access = format!("agt_test{}", Uuid::new_v4().simple());
    let access_hash: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(access.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    sqlx::query(
        "INSERT INTO agent_tokens \
           (credential_id, access_hash, refresh_hash, dpop_jkt, scopes, \
            access_expires_at, refresh_expires_at) \
         VALUES ($1, $2, $3, 'none', ARRAY['messages.read','messages.send'], \
           NOW() + interval '1 hour', NOW() + interval '1 day')",
    )
    .bind(credential_id)
    .bind(access_hash)
    .bind(Uuid::new_v4().simple().to_string())
    .execute(&pool)
    .await
    .unwrap();

    let agent_auth = format!("Bearer {access}");
    for (method, uri) in [
        ("GET", "/contacts"),
        ("GET", "/contact-keys"),
        ("DELETE", "/contact-keys"),
    ] {
        let (status, _) = call(&app, method, uri, &agent_auth, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}
