use axum::http::StatusCode;
use futures_util::StreamExt;
use serde_json::Value;
use std::io::ErrorKind;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Error as WsError},
};

mod common;

#[tokio::test]
async fn ws_requires_authorization() {
    let app = common::test_app();
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind test listener: {error}"),
    };
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("ws://{addr}/ws");
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Authorization", "Bearer invalid-token".parse().unwrap());

    let err = connect_async(request).await.err().unwrap();
    match err {
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        other => panic!("expected HTTP error, got: {other}"),
    }
}

#[tokio::test]
async fn ws_rejects_sixth_connection_from_same_user() {
    // WS_MAX_CONNECTIONS_PER_USER = 5
    let app = common::test_app();
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind test listener: {error}"),
    };
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let token = common::issue_test_jwt(
        "00000000-0000-0000-0000-000000000007",
        "0xnullifier-limit",
        "orb",
        60,
    );

    // Open 5 connections and keep them alive
    let mut keepalive = Vec::new();
    for _ in 0..5 {
        let url = format!("ws://{addr}/ws");
        let mut request = url.into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let (stream, _response) = connect_async(request).await.unwrap();
        keepalive.push(stream);
    }

    // 6th connection must be rejected with 429
    let url = format!("ws://{addr}/ws");
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let err = connect_async(request).await.err().unwrap();
    match err {
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        other => panic!("expected HTTP error, got: {other}"),
    }
}

#[tokio::test]
async fn ws_sends_new_message_event_after_connect() {
    let app = common::test_app();
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind test listener: {error}"),
    };
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let token = common::issue_test_jwt(
        "00000000-0000-0000-0000-000000000001",
        "0xnullifier",
        "orb",
        60,
    );

    let url = format!("ws://{addr}/ws");
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());

    let (mut ws_stream, _response) = connect_async(request).await.unwrap();
    let first = ws_stream.next().await.unwrap().unwrap();
    let text = first.into_text().unwrap();

    let json: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["event"], "new_message");
    assert!(json["data"]["message_id"].as_str().unwrap().len() > 0);
}
