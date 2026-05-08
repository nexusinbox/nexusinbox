use std::sync::Once;

static INIT: Once = Once::new();

fn ensure_test_env() {
    INIT.call_once(|| {
        // SAFETY: integration tests initialize this once at startup and set a fixed value.
        unsafe {
            std::env::set_var("JWT_SECRET", "nexusinbox-test-jwt-secret-0123456789abcdef");
            // Disable CSRF Origin check in integration tests (tests drive the router
            // directly without a browser). This env var is refused in production by
            // validate_runtime_config.
            std::env::set_var("AGENT_INBOX_DISABLE_CSRF_CHECK", "true");
        }
    });
}

pub fn test_app() -> axum::Router {
    ensure_test_env();
    nexusinbox_api::app()
}

#[allow(dead_code)]
pub fn test_app_with_mock_world_verify() -> axum::Router {
    ensure_test_env();
    // SAFETY: integration tests require explicit mock-mode opt-in when World verify is disabled.
    unsafe {
        std::env::set_var("AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK", "true");
    }
    nexusinbox_api::app()
}

#[allow(dead_code)]
pub fn issue_test_jwt(sub: &str, wid: &str, verification_level: &str, ttl_seconds: i64) -> String {
    ensure_test_env();
    nexusinbox_api::issue_dev_jwt(sub, wid, verification_level, ttl_seconds)
}
