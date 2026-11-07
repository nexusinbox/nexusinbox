//! The per-IP limiter must run before the process-wide budget.
//!
//! Regression (review 2026-11-07): the middleware charged the global bucket
//! (300 per window) first and the per-IP bucket (60 per window) second, so
//! a single client sending faster than its own cap still drained the shared
//! budget with requests that were then rejected per-IP — and every other
//! caller on the machine got 429 until the window rolled over.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;

mod common;

async fn status_from(app: &axum::Router, ip: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/status")
                .header("x-forwarded-for", ip)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn one_client_over_its_cap_cannot_exhaust_the_global_budget() {
    let app = common::test_app();

    // A full global window's worth of requests from one client: only its
    // own first 60 should count against the shared budget.
    let mut rejected = 0;
    for _ in 0..300 {
        if status_from(&app, "203.0.113.10").await == StatusCode::TOO_MANY_REQUESTS {
            rejected += 1;
        }
    }
    assert!(
        rejected > 0,
        "the per-IP cap must engage for the noisy client"
    );

    assert_ne!(
        status_from(&app, "198.51.100.20").await,
        StatusCode::TOO_MANY_REQUESTS,
        "another client must still be served"
    );
}
