//! DB-mode integration tests for a second browser that can sign an
//! agent's device list (docs/40 §17.4, §17.5):
//!   - a pairing for the person's agents; the new browser claims it with
//!     one key per agent, each with proof of the key and a MAC;
//!   - a list a signer puts makes the claimed key an active browser, and
//!     changing who may sign needs a recent World ID sign-in;
//!   - the new browser, once a signer, removes the root browser: its key
//!     stops, and its signature no longer counts;
//!   - the contacts key for the new browser, and the auto-reply browser.
//!
//! Usage:
//!   AGENT_INBOX_DB_TESTS=1 DATABASE_URL=postgres://... \
//!     cargo test --test second_browser_db_integration_test -- --test-threads=1

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
        "TRUNCATE TABLE browser_pairings, contact_key_device_wraps, contact_key_wraps, \
         agent_device_lists, agent_audit_log, agent_tokens, agent_credentials, \
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

fn v2_payload(f: &Fixture, version: i64, devices: Value, signers: Value) -> Value {
    json!({
        "v": 2,
        "aid": f.aid,
        "root": f.root_did,
        "version": version,
        "issued_at": "2026-11-14T10:00:00Z",
        "devices": devices,
        "signers": signers,
    })
}

async fn make_session_old(pool: &PgPool) {
    sqlx::query("UPDATE sessions SET issued_at = NOW() - INTERVAL '20 minutes'")
        .execute(pool)
        .await
        .unwrap();
}

async fn make_session_new(pool: &PgPool) {
    sqlx::query("UPDATE sessions SET issued_at = NOW()")
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[serial]
async fn a_second_browser_is_added_signs_and_removes_the_root() {
    if !db_tests_enabled() {
        eprintln!("skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests");
        return;
    }
    ensure_db_env();
    let app = common::test_app();
    let pool = db_pool().await;
    reset_schema(&pool).await;
    let f = seed(&pool, "two", 61).await;
    let other = seed(&pool, "stranger", 71).await;

    let v1 = sign_list(&f.root, &f.root_did, &list_payload(&f, "two", 1, true));
    let (status, body) = put_list(&app, &f, &f.auth, &v1).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The root browser starts a pairing for the agent.
    let (status, body) = call(
        &app,
        "POST",
        "/browser-pairings",
        &f.auth,
        json!({ "aids": [f.aid] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["id"].as_str().unwrap().to_string();
    let code = body["code"].as_str().unwrap().to_string();
    // Not for someone else's agents.
    let (status, _) = call(
        &app,
        "POST",
        "/browser-pairings",
        &other.auth,
        json!({ "aids": [f.aid] }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The new browser, signed in as the same person, finds it by the code.
    let (status, body) = call(
        &app,
        "POST",
        "/browser-pairings/resolve",
        &f.auth,
        json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], json!(id));
    assert_eq!(body["aids"], json!([f.aid]));
    let (status, _) = call(
        &app,
        "POST",
        "/browser-pairings/resolve",
        &other.auth,
        json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Its key for the agent, with proof it holds it.
    let phone = key(65);
    let phone_did = did_of(&phone);
    let phone_spk = b64(&phone.verifying_key().to_bytes());
    let phone_enc = b64(&[7u8; 32]);
    let mac = b64(&[9u8; 32]);
    let proof_input = format!(
        "nexusinbox-browser-pair-v1\n{id}\n{}\n{phone_did}\n{phone_enc}",
        f.aid
    );
    let proof = b64(&phone.sign(proof_input.as_bytes()).to_bytes());
    let device = |proof: &str, did: &str| {
        json!({
            "label": "Safari (iPhone)",
            "devices": [{
                "aid": f.aid, "did": did, "signing_public_key": phone_spk,
                "encryption_public_key": phone_enc, "mac": mac, "proof": proof
            }]
        })
    };
    let claim_uri = format!("/browser-pairings/{id}/claim");
    let (status, body) = call(
        &app,
        "POST",
        &claim_uri,
        &f.auth,
        device(&b64(&[0u8; 64]), &phone_did),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad proof: {body}"
    );
    let (status, body) = call(&app, "POST", &claim_uri, &f.auth, device(&proof, &f.pc_did)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "did of another key: {body}"
    );
    let (status, body) = call(
        &app,
        "POST",
        &claim_uri,
        &f.auth,
        device(&proof, &phone_did),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["claimed"][0]["did"], json!(phone_did));
    // Once only.
    let (status, _) = call(
        &app,
        "POST",
        &claim_uri,
        &f.auth,
        device(&proof, &phone_did),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Not yet a device of the agent.
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_identity_keys WHERE did = $1")
        .bind(&phone_did)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(active, 0);

    // The root signs it in as a signer: needs a recent World ID sign-in.
    let devices = json!([
        { "did": f.root_did, "enc": "ROOT_ENC_two", "kind": "browser" },
        { "did": f.pc_did, "enc": "PC_ENC_two", "kind": "computer" },
        { "did": phone_did, "enc": phone_enc, "kind": "browser" },
    ]);
    let v2 = sign_list(
        &f.root,
        &f.root_did,
        &v2_payload(&f, 2, devices, json!([f.root_did, phone_did])),
    );
    make_session_old(&pool).await;
    let (status, body) = put_list(&app, &f, &f.auth, &v2).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], json!("reauthentication_required"));
    make_session_new(&pool).await;
    let (status, body) = put_list(&app, &f, &f.auth, &v2).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let kind: Option<String> = sqlx::query_scalar(
        "SELECT device_kind FROM agent_identity_keys WHERE did = $1 AND status = 'active'",
    )
    .bind(&phone_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kind.as_deref(), Some("browser"));

    // The root MACs itself back for the new browser.
    let root_uri = format!("/browser-pairings/{id}/root");
    let (status, body) = call(
        &app,
        "PUT",
        &root_uri,
        &f.auth,
        json!({ "agents": [{ "aid": f.aid, "mac": mac }] }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = call(
        &app,
        "GET",
        &format!("/browser-pairings/{id}"),
        &f.auth,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["root_macs"], json!([{ "aid": f.aid, "mac": mac }]));

    // The agent list shows it as a browser with its name.
    let (_, body) = call(&app, "GET", "/agents", &f.auth, Value::Null).await;
    let listed = body["agents"][0]["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["did"] == json!(phone_did))
        .cloned()
        .unwrap();
    assert_eq!(listed["kind"], json!("browser"));
    assert_eq!(listed["label"], json!("Safari (iPhone)"));

    // The contacts key for the new browser comes back by its DID.
    let wrap = "ckx25519v1:ZXBo:c2FsdA:aXY:a2V5";
    let (status, body) = call(
        &app,
        "POST",
        "/contact-keys/devices",
        &f.auth,
        json!({ "did": phone_did, "wrapped_key": wrap }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = call(
        &app,
        "POST",
        "/contact-keys/devices",
        &f.auth,
        json!({ "did": f.pc_did, "wrapped_key": wrap }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a computer gets no contacts key"
    );
    let (_, body) = call(&app, "GET", "/contact-keys", &f.auth, Value::Null).await;
    assert!(
        body["wraps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["agent_did"] == json!(phone_did) && w["wrapped_key"] == json!(wrap)),
        "{body}"
    );

    // The new browser runs the automatic replies.
    let ar_uri = format!("/agents/{}/auto-reply-device", f.agent_id);
    let (status, _) = call(&app, "PUT", &ar_uri, &f.auth, json!({ "did": f.pc_did })).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a computer is not a browser"
    );
    let (status, _) = call(&app, "PUT", &ar_uri, &f.auth, json!({ "did": phone_did })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The new browser removes the root browser (lost): signed by the phone.
    let devices = json!([
        { "did": f.pc_did, "enc": "PC_ENC_two", "kind": "computer" },
        { "did": phone_did, "enc": phone_enc, "kind": "browser" },
    ]);
    let v3 = sign_list(
        &phone,
        &phone_did,
        &v2_payload(&f, 3, devices.clone(), json!([phone_did])),
    );
    let (status, body) = put_list(&app, &f, &f.auth, &v3).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let root_status: String =
        sqlx::query_scalar("SELECT status FROM agent_identity_keys WHERE did = $1")
            .bind(&f.root_did)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(root_status, "retired");

    // The removed root no longer signs.
    let v4 = sign_list(&f.root, &f.root_did, &list_payload(&f, "two", 4, true));
    let (status, body) = put_list(&app, &f, &f.auth, &v4).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Readers follow the versions.
    let uri = format!(
        "/recipients/device-lists?aid={}&after=0",
        f.aid.replace(':', "%3A")
    );
    let (_, body) = call(&app, "GET", &uri, &f.auth, Value::Null).await;
    assert_eq!(body["lists"].as_array().unwrap().len(), 3);
}
