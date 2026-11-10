//! Serving the remote MCP endpoint through the relay (docs/33 §11).
//!
//! The gateway connects out to the relay, presents an API-signed ticket and
//! a proof made with its DPoP key over this TLS connection, and then accepts
//! one yamux stream per cloud-AI connection. Each stream is the cloud AI's
//! own TLS, which is ended here with this computer's certificate for
//! `<id>.mcp.agent-inbox.ai` (obtained with TLS-ALPN-01 through the same
//! relay). The relay never sees the plaintext.

use crate::GatewayState;
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signer;
use futures::future::poll_fn;
use futures::StreamExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

const ALPN_CONTROL: &[u8] = b"nexusinbox-relay/1";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-nexusinbox-relay";
const PROOF_TYP: &str = "nexusinbox-relay-proof+jwt";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// After a session is replaced, how long it may keep carrying its streams.
const DRAIN: Duration = Duration::from_secs(600);

#[derive(Clone)]
pub struct Options {
    /// Where to connect, `host[:port]`. The TLS name is the relay host the
    /// API names in the ticket.
    pub relay: String,
    /// Extra root for the relay's certificate (local tests).
    pub relay_ca: Option<PathBuf>,
    pub acme_directory: String,
    pub acme_cache: PathBuf,
    /// Extra root for the ACME server's own TLS (local tests with Pebble).
    pub acme_ca: Option<PathBuf>,
    pub acme_contact: Option<String>,
}

/// Whether cloud AIs can reach this computer right now: a relay session is
/// up and the certificate is in place.
#[derive(Default)]
pub struct Status {
    connected: AtomicBool,
    cert_ready: AtomicBool,
}

impl Status {
    pub fn serving(&self) -> bool {
        self.connected.load(Ordering::Relaxed) && self.cert_ready.load(Ordering::Relaxed)
    }
    pub fn reset(&self) {
        self.connected.store(false, Ordering::Relaxed);
        self.cert_ready.store(false, Ordering::Relaxed);
    }
}

/// Serves through the relay until dropped. Everything it starts lives in
/// its own task sets, so aborting it closes the relay connection too.
pub async fn run(
    gateway: Arc<GatewayState>,
    app: Router,
    resource: String,
    opts: Options,
    status: Arc<Status>,
) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let host = reqwest::Url::parse(&resource)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .ok_or("the MCP URL has no host")?;
    create_private_dir(&opts.acme_cache)?;

    let acme_client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots(opts.acme_ca.as_ref())?)
            .with_no_client_auth(),
    );
    let acme = rustls_acme::AcmeConfig::new_with_client_config([host.clone()], acme_client)
        .contact(opts.acme_contact.iter().map(|c| format!("mailto:{c}")))
        .cache(rustls_acme::caches::DirCache::new(opts.acme_cache.clone()))
        .directory(&opts.acme_directory)
        .state();
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(acme.resolver());
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server = Arc::new(server);
    let challenge = acme.challenge_rustls_config();

    let relay_client = Arc::new({
        let mut c = rustls::ClientConfig::builder()
            .with_root_certificates(roots(opts.relay_ca.as_ref())?)
            .with_no_client_auth();
        c.alpn_protocols = vec![ALPN_CONTROL.to_vec()];
        c
    });

    eprintln!("[INFO] Remote MCP through the relay: {resource}");
    let mut acme = Some(acme);
    let mut background = JoinSet::new();
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect(&gateway, &opts.relay, relay_client.clone()).await {
            Ok((session, ttl)) => {
                backoff = Duration::from_secs(1);
                status.connected.store(true, Ordering::Relaxed);
                eprintln!("[INFO] Connected to the relay as {host}");
                // Order the certificate only once validation can reach us.
                if let Some(mut state) = acme.take() {
                    let status = status.clone();
                    background.spawn(async move {
                        while let Some(event) = state.next().await {
                            match event {
                                Ok(ok) => {
                                    if matches!(
                                        ok,
                                        rustls_acme::EventOk::DeployedCachedCert
                                            | rustls_acme::EventOk::DeployedNewCert
                                    ) {
                                        status.cert_ready.store(true, Ordering::Relaxed);
                                    }
                                    eprintln!("[INFO] certificate: {ok:?}");
                                }
                                Err(err) => eprintln!("[WARN] certificate: {err:?}"),
                            }
                        }
                    });
                }
                while background.try_join_next().is_some() {}
                let renew_at = ttl.saturating_sub(Duration::from_secs(120));
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                let streams = StreamCtx {
                    app: app.clone(),
                    server: server.clone(),
                    challenge: challenge.clone(),
                };
                let mut task = Box::pin(accept_streams(session, streams, stop_rx));
                tokio::select! {
                    _ = &mut task => {
                        status.connected.store(false, Ordering::Relaxed);
                        eprintln!("[WARN] The relay connection closed; reconnecting");
                    }
                    _ = tokio::time::sleep(renew_at) => {
                        // Make before break: the next session takes over new
                        // streams; this one drains in the background.
                        let _ = stop_tx.send(());
                        background.spawn(async move {
                            let _ = tokio::time::timeout(DRAIN, task).await;
                        });
                        continue;
                    }
                }
            }
            Err(e) => {
                status.connected.store(false, Ordering::Relaxed);
                eprintln!("[WARN] Could not connect to the relay: {e}");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

type Session = yamux::Connection<
    tokio_util::compat::Compat<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
>;

async fn connect(
    gateway: &GatewayState,
    relay: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(Session, Duration), String> {
    let token = crate::ensure_token(gateway).await?;
    let url = format!("{}/mcp-resources/relay-ticket", gateway.api_url);
    let ticket = crate::api_post(gateway, &url, &token, &serde_json::json!({})).await?;
    let ticket_value = ticket["ticket"].as_str().ok_or("no ticket in the reply")?;
    let relay_host = ticket["relay"].as_str().ok_or("no relay in the reply")?;
    let addr = if relay.contains(':') {
        relay.to_string()
    } else {
        format!("{relay}:443")
    };

    let tcp = tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("timed out connecting to {addr}"))?
        .map_err(|e| format!("{addr}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let name = rustls::pki_types::ServerName::try_from(relay_host.to_string())
        .map_err(|_| "bad relay host")?;
    let mut stream = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsConnector::from(tls).connect(name, tcp),
    )
    .await
    .map_err(|_| "timed out in the TLS handshake")?
    .map_err(|e| format!("TLS with the relay: {e}"))?;

    let mut exporter = [0u8; 32];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter, EXPORTER_LABEL, None)
        .map_err(|e| format!("TLS exporter: {e}"))?;
    let hello = serde_json::json!({
        "ticket": ticket_value,
        "proof": proof(gateway, relay_host, &exporter),
    });
    stream
        .write_all(format!("{hello}\n").as_bytes())
        .await
        .map_err(|e| format!("relay hello: {e}"))?;
    let line = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_line(&mut stream))
        .await
        .map_err(|_| "the relay did not answer")??;
    let reply: serde_json::Value =
        serde_json::from_slice(&line).map_err(|_| "the relay sent a bad reply")?;
    if reply["ok"] != true {
        return Err(format!(
            "the relay refused: {}",
            reply["error"].as_str().unwrap_or("unknown")
        ));
    }
    let ttl = Duration::from_secs(reply["ttl"].as_u64().unwrap_or(3600).max(300));
    let mut config = yamux::Config::default();
    config.set_max_num_streams(64);
    Ok((
        yamux::Connection::new(stream.compat(), config, yamux::Mode::Server),
        ttl,
    ))
}

/// A proof, signed with the DPoP key the ticket is bound to, over this
/// connection's TLS exporter value.
fn proof(gateway: &GatewayState, relay_host: &str, exporter: &[u8]) -> String {
    let header = serde_json::json!({
        "typ": PROOF_TYP,
        "alg": "EdDSA",
        "jwk": gateway.dpop_public_jwk,
    });
    let claims = serde_json::json!({
        "aud": relay_host,
        "tls": URL_SAFE_NO_PAD.encode(exporter),
        "iat": chrono::Utc::now().timestamp(),
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let sig = gateway.dpop_signing_key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

async fn read_line<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    loop {
        let b = r.read_u8().await.map_err(|e| format!("relay reply: {e}"))?;
        if b == b'\n' {
            return Ok(line);
        }
        if line.len() > 4096 {
            return Err("relay reply too long".into());
        }
        line.push(b);
    }
}

#[derive(Clone)]
struct StreamCtx {
    app: Router,
    server: Arc<rustls::ServerConfig>,
    challenge: Arc<rustls::ServerConfig>,
}

/// Accepts streams until the relay closes the session. After `stop`, keeps
/// driving the connection (the open streams need it) but the relay sends
/// no new ones here.
async fn accept_streams(
    mut session: Session,
    ctx: StreamCtx,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let mut stopped = false;
    // Dropped with this future, which ends every stream it started.
    let mut served = JoinSet::new();
    loop {
        while served.try_join_next().is_some() {}
        let next = poll_fn(|cx| session.poll_next_inbound(cx));
        let stream = if stopped {
            next.await
        } else {
            tokio::select! {
                s = next => s,
                _ = &mut stop => { stopped = true; continue; }
            }
        };
        match stream {
            Some(Ok(stream)) => {
                let ctx = ctx.clone();
                served.spawn(serve_stream(stream, ctx));
            }
            _ => return,
        }
    }
}

async fn serve_stream(stream: yamux::Stream, ctx: StreamCtx) {
    let io = stream.compat();
    let Ok(Ok(start)) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io),
    )
    .await
    else {
        return;
    };
    if rustls_acme::is_tls_alpn_challenge(&start.client_hello()) {
        if let Ok(mut tls) = start.into_stream(ctx.challenge).await {
            let _ = tls.shutdown().await;
        }
        return;
    }
    let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, start.into_stream(ctx.server)).await
    else {
        return;
    };
    let service = hyper_util::service::TowerToHyperService::new(ctx.app);
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
        .await;
}

fn roots(extra: Option<&PathBuf>) -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(path) = extra {
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        let certs =
            CertificateDer::pem_file_iter(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for cert in certs {
            let cert = cert.map_err(|e| format!("{}: {e}", path.display()))?;
            roots
                .add(cert)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    Ok(roots)
}

fn create_private_dir(dir: &PathBuf) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway self-signed CA (P-256, no key kept), for --mcp-acme-ca /
    // --mcp-relay-ca style files.
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUXaJB56JhELI/uEaJN29IKGPLW4swCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSbmV4dXNpbmJveC10ZXN0LWNhMCAXDTI2MTExMDA4MzE0OVoY
DzIxMjYxMDE3MDgzMTQ5WjAdMRswGQYDVQQDDBJuZXh1c2luYm94LXRlc3QtY2Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCIDMlkp7gAgzR6kv0ceSbCfaIKtli
540rYwJYbtYJ1vLhUTWn5onYid38I1ohV6dxnwJ5VVVFI8VJ80HlFWYoo1MwUTAd
BgNVHQ4EFgQU4kaE5qRdQCOkvZx65JO+EfapLHUwHwYDVR0jBBgwFoAU4kaE5qRd
QCOkvZx65JO+EfapLHUwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF
AiEA/fXTe7z8GgzOYv5ul3jkuXPm4Tm1mOgjpZy1aTagw60CIDQDcNqTu18We/Eb
ccDhmz3ihCx/BXa/InYnmq7vuzUo
-----END CERTIFICATE-----
";

    #[test]
    fn roots_add_an_extra_ca_from_a_pem_file() {
        let base = webpki_roots::TLS_SERVER_ROOTS.len();
        assert_eq!(roots(None).unwrap().len(), base);

        let path = std::env::temp_dir().join(format!("nexusinbox-ca-{}.pem", std::process::id()));
        std::fs::write(&path, TEST_CA_PEM).unwrap();
        let with_extra = roots(Some(&path));
        std::fs::remove_file(&path).ok();
        assert_eq!(with_extra.unwrap().len(), base + 1);

        let missing = std::env::temp_dir().join("nexusinbox-ca-missing.pem");
        assert!(roots(Some(&missing)).is_err());
    }
}
