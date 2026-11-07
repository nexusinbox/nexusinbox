//! Rate limiting: each caller is counted on its own before the
//! process-wide circuit breaker, and signed-in people are counted per person.
//!
//! Regressions (review 2026-11-07):
//! - The middleware charged the global bucket (then 300 per window) before
//!   the per-IP bucket (60 per window), so one client sending faster than
//!   its own cap drained the shared budget and every other caller got 429.
//! - With the per-IP order fixed, five IPs at their own cap still used up
//!   the 300, and web traffic, which reaches the API from Vercel's few IPs,
//!   shared one 60-per-window budget among everyone using the web app.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::util::ServiceExt;
use uuid::Uuid;

mod common;

async fn status_with(app: &axum::Router, ip: &str, session: Option<&str>) -> StatusCode {
    let mut builder = Request::builder()
        .uri("/status")
        .header("x-forwarded-for", ip);
    if let Some(token) = session {
        builder = builder.header("cookie", format!("nexusinbox_session={token}"));
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

fn session_for_new_person() -> String {
    let id = Uuid::new_v4().to_string();
    common::issue_test_jwt(&id, &format!("0xrl-{id}"), "orb", 600)
}

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

#[tokio::test]
async fn people_behind_one_ip_are_counted_per_person() {
    let app = common::test_app();
    // Everyone using the web app reaches the API from the same few IPs.
    let proxy_ip = "192.0.2.50";
    let alice = session_for_new_person();
    let bob = session_for_new_person();

    // Alice alone goes well past the per-IP cap of 60 ...
    for _ in 0..120 {
        assert_ne!(
            status_with(&app, proxy_ip, Some(&alice)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    // ... without touching Bob's budget or the IP's own.
    assert_ne!(
        status_with(&app, proxy_ip, Some(&bob)).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_ne!(
        status_with(&app, proxy_ip, None).await,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Alice's own budget still runs out.
    let mut limited = false;
    for _ in 0..300 {
        if status_with(&app, proxy_ip, Some(&alice)).await == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "a person's own budget must end");
}

#[tokio::test]
async fn forged_sessions_are_counted_per_ip() {
    let app = common::test_app();
    let ip = "192.0.2.60";
    let mut limited = false;
    for _ in 0..120 {
        // A session for a new person each time, with a broken signature:
        // it must not buy a fresh budget.
        let mut forged = session_for_new_person();
        let last = forged.pop().unwrap();
        forged.push(if last == 'A' { 'B' } else { 'A' });
        if status_with(&app, ip, Some(&forged)).await == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "forged sessions must share the IP's budget");
}

#[tokio::test]
async fn a_handful_of_ips_cannot_exhaust_the_shared_budget() {
    let app = common::test_app();
    // Six callers, each at its own cap: 360 requests, more than the old
    // shared budget of 300.
    for n in 0..6 {
        let ip = format!("198.51.100.{n}");
        for _ in 0..60 {
            assert_ne!(
                status_with(&app, &ip, None).await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
    }
    assert_ne!(
        status_with(&app, "203.0.113.99", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "another caller must still be served"
    );
}
