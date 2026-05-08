use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::util::ServiceExt;

mod common;

const VALID_SIGNING_KEY_B64URL: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
const VALID_ENCRYPTION_KEY_B64URL: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU";

fn auth_header() -> String {
    let token = common::issue_test_jwt(
        "00000000-0000-0000-0000-000000000001",
        "0xnullifier",
        "orb",
        60 * 60,
    );
    format!("Bearer {token}")
}

#[tokio::test]
async fn agents_requires_authorization() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_agent_then_list_agents() {
    let app = common::test_app();

    let create_payload = serde_json::json!({
        "label": "秘書",
        "public_key": VALID_SIGNING_KEY_B64URL,
        "encryption_key": VALID_ENCRYPTION_KEY_B64URL
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("content-type", "application/json")
                .header("authorization", auth_header())
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_response.status(), StatusCode::CREATED);

    let list_response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_response.status(), StatusCode::OK);

    let body = list_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let agents = json.get("agents").and_then(Value::as_array).unwrap();

    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["label"], "秘書");
    assert!(agents[0]["did"].as_str().unwrap().starts_with("did:key:z"));
}

#[tokio::test]
async fn create_agent_rejects_invalid_public_key() {
    let app = common::test_app();

    let create_payload = serde_json::json!({
        "label": "invalid-agent",
        "public_key": "dev-public-key",
        "encryption_key": VALID_ENCRYPTION_KEY_B64URL
    });

    let create_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("content-type", "application/json")
                .header("authorization", auth_header())
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn create_agent_rejects_non_32byte_public_key() {
    let app = common::test_app();
    // 31-byte payload in base64url
    let short_public_key = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNk";

    let create_payload = serde_json::json!({
        "label": "invalid-agent",
        "public_key": short_public_key,
        "encryption_key": VALID_ENCRYPTION_KEY_B64URL
    });

    let create_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("content-type", "application/json")
                .header("authorization", auth_header())
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn create_agent_rejects_invalid_encryption_key() {
    let app = common::test_app();

    let create_payload = serde_json::json!({
        "label": "invalid-agent",
        "public_key": VALID_SIGNING_KEY_B64URL,
        "encryption_key": "dev-encryption-key"
    });

    let create_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents")
                .header("content-type", "application/json")
                .header("authorization", auth_header())
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(create_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
