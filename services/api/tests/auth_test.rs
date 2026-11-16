use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::util::ServiceExt;

mod common;

async fn response_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn auth_verify_issues_token_and_allows_access() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof",
      "merkle_root": "0xroot",
      "nullifier_hash": "0xnullifier",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let verify_response = app
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
    assert_eq!(verify_response.status(), StatusCode::OK);
    let set_cookie = verify_response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(set_cookie.contains("nexusinbox_session="));
    assert!(set_cookie.contains("HttpOnly"));

    let verify_json = response_json(verify_response).await;
    assert_eq!(verify_json["user"]["verification_level"], "orb");
    assert!(verify_json.get("token").is_none());
    let cookie_pair = set_cookie.split(';').next().unwrap_or("").to_string();

    let list_agents_response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header("cookie", cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_agents_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn dev_user_bearer_is_rejected_by_default() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header(
                    "authorization",
                    "Bearer dev-user-00000000-0000-0000-0000-000000000001",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_cookie_allows_access_without_authorization_header() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof-cookie",
      "merkle_root": "0xroot-cookie",
      "nullifier_hash": "0xnullifier-cookie",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let verify_response = app
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
    assert_eq!(verify_response.status(), StatusCode::OK);

    let set_cookie = verify_response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let cookie_pair = set_cookie.split(';').next().unwrap_or("").to_string();
    assert!(cookie_pair.starts_with("nexusinbox_session="));

    let list_agents_response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header("cookie", cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_agents_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_verify_rejects_invalid_payload() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof"
    });

    let verify_response = app
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
    assert_eq!(verify_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn auth_verify_rejects_replayed_payload() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof-replay",
      "merkle_root": "0xroot-replay",
      "nullifier_hash": "0xnullifier-replay",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let first = app
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
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
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
    assert_eq!(second.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn auth_verify_rejects_non_orb_verification_level() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof-device",
      "merkle_root": "0xroot-device",
      "nullifier_hash": "0xnullifier-device",
      "verification_level": "device",
      "action": "login",
      "signal": ""
    });

    let response = app
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
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn auth_verify_rejects_unexpected_action() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof-action",
      "merkle_root": "0xroot-action",
      "nullifier_hash": "0xnullifier-action",
      "verification_level": "orb",
      "action": "sign_in",
      "signal": ""
    });

    let response = app
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
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn auth_verify_rejects_unexpected_signal() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof-signal",
      "merkle_root": "0xroot-signal",
      "nullifier_hash": "0xnullifier-signal",
      "verification_level": "orb",
      "action": "login",
      "signal": "unexpected-signal"
    });

    let response = app
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
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn tampered_token_is_rejected() {
    let app = common::test_app();
    let token = common::issue_test_jwt(
        "00000000-0000-0000-0000-000000000001",
        "0xnullifier",
        "orb",
        60,
    );
    let tampered = format!("{token}x");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header("authorization", format!("Bearer {tampered}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let app = common::test_app();
    let token = common::issue_test_jwt(
        "00000000-0000-0000-0000-000000000001",
        "0xnullifier",
        "orb",
        -60,
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_logout_revokes_cookie_session() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof-logout",
      "merkle_root": "0xroot-logout",
      "nullifier_hash": "0xnullifier-logout",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let verify_response = app
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
    assert_eq!(verify_response.status(), StatusCode::OK);
    let cookie_pair = verify_response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_string();
    assert!(cookie_pair.starts_with("nexusinbox_session="));

    let logout_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("cookie", cookie_pair.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_response.status(), StatusCode::OK);
    let clear_cookie = logout_response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(clear_cookie.contains("nexusinbox_session="));
    assert!(clear_cookie.contains("Max-Age=0"));

    let post_logout_response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header("cookie", cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_logout_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_session_returns_authenticated_for_valid_cookie() {
    let app = common::test_app_with_mock_world_verify();
    let payload = json!({
      "proof": "0xproof-session-ok",
      "merkle_root": "0xroot-session-ok",
      "nullifier_hash": "0xnullifier-session-ok",
      "verification_level": "orb",
      "action": "login",
      "signal": ""
    });

    let verify_response = app
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
    assert_eq!(verify_response.status(), StatusCode::OK);
    let cookie_pair = verify_response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_string();

    let session_response = app
        .oneshot(
            Request::builder()
                .uri("/auth/session")
                .header("cookie", cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);
    let payload = response_json(session_response).await;
    assert_eq!(payload["authenticated"], true);
}

#[tokio::test]
async fn auth_session_rejects_invalid_cookie_and_clears_session_cookie() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/session")
                .header("cookie", "nexusinbox_session=invalid-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let clear_cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(clear_cookie.contains("nexusinbox_session="));
    assert!(clear_cookie.contains("Max-Age=0"));
}

async fn verify_status(payload: Value) -> StatusCode {
    let app = common::test_app_with_mock_world_verify();
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/auth/verify")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

fn idkit(responses: Value, extra: Value) -> Value {
    let mut result = json!({ "protocol_version": "3.0", "responses": responses });
    for (k, v) in extra.as_object().unwrap() {
        result[k] = v.clone();
    }
    json!({ "action": "login", "idkit_result": result })
}

fn orb(nullifier: &str) -> Value {
    json!({ "identifier": "orb", "nullifier": nullifier, "proof": "0xproof", "merkle_root": "0xroot" })
}

#[tokio::test]
async fn auth_verify_takes_an_idkit_result_with_one_response() {
    let status = verify_status(idkit(json!([orb("0xnullifier-idkit-one")]), json!({}))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn auth_verify_rejects_extra_idkit_responses() {
    // A fabricated first entry in front of a valid one must not choose the account.
    let both = json!([orb("0xnullifier-forged"), orb("0xnullifier-real")]);
    assert_eq!(
        verify_status(idkit(both, json!({}))).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        verify_status(idkit(json!([]), json!({}))).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn auth_verify_rejects_another_action_or_signal_inside_the_idkit_result() {
    let one = json!([orb("0xnullifier-idkit-action")]);
    assert_eq!(
        verify_status(idkit(one.clone(), json!({ "action": "other-action" }))).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut with_signal = idkit(one, json!({ "signal": "other-signal" }));
    with_signal["signal"] = json!("");
    assert_eq!(
        verify_status(with_signal).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
