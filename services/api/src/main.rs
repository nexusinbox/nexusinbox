use std::net::SocketAddr;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() {
    // Prefer local overrides, then fallback to shared defaults.
    let _ = dotenvy::from_filename("services/api/.env.local");
    let _ = dotenvy::from_filename(".env.local");
    let _ = dotenvy::from_filename("services/api/.env");
    let _ = dotenvy::dotenv();

    // Initialize structured logging.
    // - Production: JSON format (RUST_LOG=info, LOG_FORMAT=json)
    // - Development: human-readable (RUST_LOG=debug, default)
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let use_json = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if use_json {
        fmt().with_env_filter(filter).json().init();
    } else {
        fmt().with_env_filter(filter).init();
    }

    nexusinbox_api::validate_runtime_config()
        .unwrap_or_else(|message| panic!("invalid API runtime configuration: {message}"));

    match nexusinbox_api::initialize_database_if_configured().await {
        Ok(true) => tracing::info!("database migrations applied successfully"),
        Ok(false) => tracing::warn!("DATABASE_URL not set: running in in-memory mode"),
        Err(message) => panic!("database initialization failed: {message}"),
    }

    // Kick off the attachment orphan cleanup job. No-op when DB isn't
    // configured (in-memory mode).
    if nexusinbox_api::spawn_attachment_cleanup_if_configured().await {
        tracing::info!("attachment cleanup job started");
    }

    // Kick off the replay-nonce table cleanup job. Deletes expired rows on a
    // 60s cadence so the hot path stays at one INSERT per DPoP proof. No-op
    // in in-memory mode.
    if nexusinbox_api::spawn_replay_nonce_cleanup_if_configured().await {
        tracing::info!("replay_nonces cleanup job started");
    }

    let app = nexusinbox_api::app();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!(%addr, "NexusInbox API listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    // Graceful shutdown: wait for SIGTERM (containers) or Ctrl+C (dev)
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("axum server exited unexpectedly");

    tracing::info!("shutdown complete");
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("received SIGINT, shutting down gracefully"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down gracefully"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("received SIGINT, shutting down gracefully");
    }
}
