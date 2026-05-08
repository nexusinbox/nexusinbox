use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

mod common;

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
