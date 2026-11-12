//! DB-mode integration tests for signed device lists (docs/40 stage 1):
//!   - the agent's root key signs a list of its active devices; the list
//!     comes back on the agent list and on recipient resolution;
//!   - a list signed by another key, naming a device with a different
//!     encryption key or a device of another agent, or altered after
//!     signing, is refused;
//!   - versions only go up;
//!   - someone else cannot store a list for the agent.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 DATABASE_URL=postgres://... \
//!     cargo test --test device_list_db_integration_test -- --test-threads=1

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
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
        "TRUNCATE TABLE agent_device_lists, agent_audit_log, agent_tokens, agent_credentials, \
         agent_identity_keys, agent_identities, sessions, replay_nonces, agents, users \
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

fn key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[1] = 0x5a;
    SigningKey::from_bytes(&bytes)
}

fn did_of(key: &SigningKey) -> String {
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&key.verifying_key().to_bytes());
    format!("did:key:z{}", bs58::encode(&multicodec).into_string())
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

struct Fixture {
    auth: String,
    agent_id: Uuid,
    aid: String,
    root: SigningKey,
    root_did: String,
    pc_did: String,
}

/// A user whose agent has its root browser key and one connected computer.
async fn seed(pool: &PgPool, tag: &str, seed: u8) -> Fixture {
    let user_id = Uuid::new_v4();
    let wid = format!("0xlist-{tag}");
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

    let root = key(seed);
    let root_did = did_of(&root);
    let root_spk = b64(&root.verifying_key().to_bytes());
    let pc = key(seed + 1);
    let pc_did = did_of(&pc);
    let agent_id = Uuid::new_v4();
    let aid = format!("aid:ai:list{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agents (id, user_id, did, label, public_key, encryption_key, is_active) \
         VALUES ($1, $2, $3, 'secretary', $4, $5, true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(&root_did)
    .bind(&root_spk)
    .bind(format!("ROOT_ENC_{tag}"))
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
    for (did, spk, enc, minutes) in [
        (&root_did, root_spk.clone(), format!("ROOT_ENC_{tag}"), 60),
        (
            &pc_did,
            b64(&pc.verifying_key().to_bytes()),
            format!("PC_ENC_{tag}"),
            5,
        ),
    ] {
        sqlx::query(
            "INSERT INTO agent_identity_keys \
               (aid, did, signing_public_key, encryption_public_key, status, activated_at) \
             VALUES ($1, $2, $3, $4, 'active', NOW() - ($5::int * INTERVAL '1 minute'))",
        )
        .bind(&aid)
        .bind(did)
        .bind(spk)
        .bind(enc)
        .bind(minutes)
        .execute(pool)
        .await
        .expect("seed key");
    }

    Fixture {
        auth: format!("Bearer {token}"),
        agent_id,
        aid,
        root,
        root_did,
        pc_did,
    }
}

fn sign_list(signer: &SigningKey, kid: &str, payload: &Value) -> String {
    let header = json!({ "alg": "EdDSA", "typ": "nexusinbox-device-list", "kid": kid });
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    );
    let signature = signer.sign(input.as_bytes());
    format!("{input}.{}", b64(&signature.to_bytes()))
}

fn list_payload(f: &Fixture, tag: &str, version: i64, with_pc: bool) -> Value {
    let mut devices = vec![json!({
        "did": f.root_did, "enc": format!("ROOT_ENC_{tag}"), "kind": "browser"
    })];
    if with_pc {
        devices.push(json!({
            "did": f.pc_did, "enc": format!("PC_ENC_{tag}"), "kind": "computer"
        }));
    }
    json!({
        "v": 1,
        "aid": f.aid,
        "root": f.root_did,
        "version": version,
        "issued_at": "2026-11-12T10:00:00Z",
        "devices": devices,
    })
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
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

async fn put_list(app: &axum::Router, f: &Fixture, auth: &str, jws: &str) -> (StatusCode, Value) {
    call(
        app,
        "PUT",
        &format!("/agents/{}/device-list", f.agent_id),
        auth,
        json!({ "jws": jws }),
    )
    .await
}

#[tokio::test]
#[serial]
async fn the_root_key_signs_the_device_list_and_it_comes_back() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed(&pool, "ok", 1).await;

    let jws = sign_list(&f.root, &f.root_did, &list_payload(&f, "ok", 1, true));
    let (status, body) = put_list(&app, &f, &f.auth, &jws).await;
    assert_eq!(status, StatusCode::OK, "store failed: {body}");
    assert_eq!(body["version"], 1);

    // The agent list carries it, and each device its encryption key.
    let (status, body) = call(&app, "GET", "/agents", &f.auth, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let agent = &body["agents"][0];
    assert_eq!(agent["device_list"]["version"], 1);
    assert_eq!(agent["device_list"]["jws"], jws.as_str());
    assert!(agent["devices"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["encryption_public_key"] == "PC_ENC_ok"));

    // So does resolution, by AID and by a device's DID.
    for identifier in [f.aid.as_str(), f.pc_did.as_str()] {
        let (status, body) = call(
            &app,
            "GET",
            &format!("/recipients/resolve?identifier={identifier}"),
            &f.auth,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["device_list"]["jws"], jws.as_str());
    }

    // A later version without the computer replaces it.
    let jws2 = sign_list(&f.root, &f.root_did, &list_payload(&f, "ok", 2, false));
    let (status, body) = put_list(&app, &f, &f.auth, &jws2).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = call(&app, "GET", "/agents", &f.auth, Value::Null).await;
    assert_eq!(body["agents"][0]["device_list"]["version"], 2);

    // Every version is kept (docs/40 §4.4).
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_device_lists WHERE aid = $1")
        .bind(&f.aid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, 2);
}

#[tokio::test]
#[serial]
async fn versions_only_go_up() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed(&pool, "ver", 11).await;

    let jws = sign_list(&f.root, &f.root_did, &list_payload(&f, "ver", 3, true));
    assert_eq!(put_list(&app, &f, &f.auth, &jws).await.0, StatusCode::OK);
    for version in [3, 2] {
        let jws = sign_list(
            &f.root,
            &f.root_did,
            &list_payload(&f, "ver", version, false),
        );
        let (status, body) = put_list(&app, &f, &f.auth, &jws).await;
        assert_eq!(status, StatusCode::CONFLICT, "version {version}: {body}");
    }
}

#[tokio::test]
#[serial]
async fn lists_the_root_did_not_sign_or_that_name_other_keys_are_refused() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed(&pool, "bad", 21).await;
    let other = seed(&pool, "other", 31).await;

    // Signed by the computer's key, claiming to be the root.
    let computer = key(22);
    let forged = sign_list(&computer, &f.root_did, &list_payload(&f, "bad", 1, true));
    let (status, body) = put_list(&app, &f, &f.auth, &forged).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Signed by the computer and naming it as the signer.
    let by_pc = sign_list(&computer, &f.pc_did, &list_payload(&f, "bad", 1, true));
    let (status, body) = put_list(&app, &f, &f.auth, &by_pc).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // A device with an encryption key the server does not hold for it.
    let mut swapped = list_payload(&f, "bad", 1, true);
    swapped["devices"][1]["enc"] = json!("ATTACKER_ENC");
    let jws = sign_list(&f.root, &f.root_did, &swapped);
    let (status, body) = put_list(&app, &f, &f.auth, &jws).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // A device of another agent.
    let mut foreign = list_payload(&f, "bad", 1, false);
    foreign["devices"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "did": other.pc_did, "enc": "PC_ENC_other", "kind": "computer" }));
    let jws = sign_list(&f.root, &f.root_did, &foreign);
    let (status, body) = put_list(&app, &f, &f.auth, &jws).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Altered after signing: the payload part swapped for another.
    let good = sign_list(&f.root, &f.root_did, &list_payload(&f, "bad", 1, false));
    let mut parts: Vec<&str> = good.split('.').collect();
    let altered_payload = b64(list_payload(&f, "bad", 1, true).to_string().as_bytes());
    parts[1] = &altered_payload;
    let (status, body) = put_list(&app, &f, &f.auth, &parts.join(".")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Naming another agent.
    let mut wrong_aid = list_payload(&f, "bad", 1, false);
    wrong_aid["aid"] = json!(other.aid);
    let jws = sign_list(&f.root, &f.root_did, &wrong_aid);
    let (status, body) = put_list(&app, &f, &f.auth, &jws).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Nothing was stored.
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_device_lists")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);

    // Someone else cannot store even a valid list for this agent.
    let (status, body) = put_list(&app, &f, &other.auth, &good).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
