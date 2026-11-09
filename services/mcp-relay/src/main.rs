//! NexusInbox MCP relay (docs/33 §11).
//!
//! One TCP port. The relay reads only the SNI of each TLS ClientHello:
//! - `<id>.<mcp domain>`: a cloud AI reaching a person's computer. The bytes
//!   go through untouched to that computer's control connection; TLS is
//!   ended on the computer, never here.
//! - `<relay host>`: a computer connecting out. The relay ends this TLS
//!   itself, checks the API-signed ticket and the key proof bound to this
//!   connection, then multiplexes streams over it.
//!
//! The relay keeps no database and writes no per-connection logs; it logs
//! counts only.

mod io;
mod session;
mod sni;
mod ticket;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Parser;
use futures::StreamExt;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::LazyConfigAcceptor;
use tokio_util::compat::TokioAsyncReadCompatExt;

const ALPN_CONTROL: &[u8] = b"nexusinbox-relay/1";
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_secs(3600);
const SESSION_GRACE: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 4096;
const MAX_PER_IP: usize = 64;

#[derive(Parser, Debug)]
#[command(
    name = "nexusinbox-relay",
    about = "SNI relay for cloud AIs (docs/33 §11)"
)]
struct Args {
    #[arg(long, env = "RELAY_LISTEN", default_value = "[::]:8443")]
    listen: SocketAddr,
    /// The host computers connect to; the relay ends TLS for it.
    #[arg(long, env = "RELAY_HOST", default_value = "relay.agent-inbox.ai")]
    relay_host: String,
    /// The domain under which each computer has `<id>.<domain>`.
    #[arg(long, env = "RELAY_MCP_DOMAIN", default_value = "mcp.agent-inbox.ai")]
    mcp_domain: String,
    /// The API's ticket key (`x` from GET /mcp-relay/ticket-key).
    #[arg(long, env = "RELAY_TICKET_PUBLIC_KEY")]
    ticket_public_key: String,
    /// A fixed certificate for the relay host (PEM). Otherwise ACME.
    #[arg(long, env = "RELAY_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, env = "RELAY_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Where the relay keeps its own ACME account and certificate.
    #[arg(long, env = "RELAY_ACME_CACHE")]
    acme_cache: Option<PathBuf>,
    #[arg(
        long,
        env = "RELAY_ACME_DIRECTORY",
        default_value = "https://acme-v02.api.letsencrypt.org/directory"
    )]
    acme_directory: String,
    #[arg(long, env = "RELAY_ACME_CONTACT")]
    acme_contact: Option<String>,
    /// Expect a PROXY protocol v1 header first (Fly's `proxy_proto`).
    #[arg(long, env = "RELAY_PROXY_PROTOCOL")]
    proxy_protocol: bool,
}

#[derive(Default)]
struct Counters {
    forwarded: AtomicU64,
    no_computer: AtomicU64,
    rejected: AtomicU64,
    control_ok: AtomicU64,
    control_failed: AtomicU64,
    bytes: AtomicU64,
}

struct Relay {
    relay_host: String,
    mcp_domain: String,
    api_key: ed25519_dalek::VerifyingKey,
    control_tls: Arc<rustls::ServerConfig>,
    challenge_tls: Option<Arc<rustls::ServerConfig>>,
    proxy_protocol: bool,
    registry: session::Registry,
    connections: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    counters: Counters,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("[relay] {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(args.ticket_public_key.trim())
        .map_err(|_| "RELAY_TICKET_PUBLIC_KEY is not base64url")?
        .try_into()
        .map_err(|_| "RELAY_TICKET_PUBLIC_KEY must be 32 bytes")?;
    let api_key = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| "RELAY_TICKET_PUBLIC_KEY is not an Ed25519 key")?;
    let relay_host = args.relay_host.to_ascii_lowercase();
    let mcp_domain = args.mcp_domain.to_ascii_lowercase();

    let (control_tls, challenge_tls) = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => (fixed_tls(cert, key)?, None),
        _ => {
            let cache = args
                .acme_cache
                .clone()
                .ok_or("set RELAY_ACME_CACHE, or RELAY_TLS_CERT and RELAY_TLS_KEY")?;
            let mut state = rustls_acme::AcmeConfig::new([relay_host.clone()])
                .contact(args.acme_contact.iter().map(|c| format!("mailto:{c}")))
                .cache(rustls_acme::caches::DirCache::new(cache))
                .directory(&args.acme_directory)
                .state();
            let mut control = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(state.resolver());
            control.alpn_protocols = vec![ALPN_CONTROL.to_vec()];
            let challenge = state.challenge_rustls_config();
            tokio::spawn(async move {
                while let Some(event) = state.next().await {
                    match event {
                        Ok(ok) => eprintln!("[relay] acme: {ok:?}"),
                        Err(err) => eprintln!("[relay] acme error: {err:?}"),
                    }
                }
            });
            (Arc::new(control), Some(challenge))
        }
    };

    let relay = Arc::new(Relay {
        relay_host,
        mcp_domain,
        api_key,
        control_tls,
        challenge_tls,
        proxy_protocol: args.proxy_protocol,
        registry: session::Registry::default(),
        connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        per_ip: Mutex::new(HashMap::new()),
        counters: Counters::default(),
    });

    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", args.listen))?;
    eprintln!(
        "[relay] listening on {} for {} and *.{}",
        args.listen, relay.relay_host, relay.mcp_domain
    );
    tokio::spawn(report(relay.clone()));

    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = relay.connections.clone().try_acquire_owned() else {
            continue;
        };
        let relay = relay.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle(relay, tcp, peer.ip()).await;
        });
    }
}

fn fixed_tls(cert: &PathBuf, key: &PathBuf) -> Result<Arc<rustls::ServerConfig>, String> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert).map_err(|e| format!("{}: {e}", cert.display()))?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key).map_err(|e| format!("{}: {e}", key.display()))?,
    ))
    .map_err(|e| format!("{}: {e}", key.display()))?
    .ok_or("no private key in RELAY_TLS_KEY")?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("relay certificate: {e}"))?;
    config.alpn_protocols = vec![ALPN_CONTROL.to_vec()];
    Ok(Arc::new(config))
}

/// Counts only: never which host, never which address.
async fn report(relay: Arc<Relay>) {
    let mut tick = tokio::time::interval(Duration::from_secs(600));
    tick.tick().await;
    loop {
        tick.tick().await;
        let c = &relay.counters;
        eprintln!(
            "[relay] computers={} forwarded={} no_computer={} rejected={} control_ok={} control_failed={} bytes={}",
            relay.registry.len(),
            c.forwarded.swap(0, Ordering::Relaxed),
            c.no_computer.swap(0, Ordering::Relaxed),
            c.rejected.swap(0, Ordering::Relaxed),
            c.control_ok.swap(0, Ordering::Relaxed),
            c.control_failed.swap(0, Ordering::Relaxed),
            c.bytes.swap(0, Ordering::Relaxed),
        );
    }
}

struct IpSlot<'a> {
    relay: &'a Relay,
    ip: IpAddr,
}

impl Drop for IpSlot<'_> {
    fn drop(&mut self) {
        let mut map = self.relay.per_ip.lock().unwrap();
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

fn take_ip_slot(relay: &Relay, ip: IpAddr) -> Option<IpSlot<'_>> {
    let mut map = relay.per_ip.lock().unwrap();
    let n = map.entry(ip).or_insert(0);
    if *n >= MAX_PER_IP {
        return None;
    }
    *n += 1;
    Some(IpSlot { relay, ip })
}

async fn handle(relay: Arc<Relay>, mut tcp: TcpStream, peer: IpAddr) {
    let _ = tcp.set_nodelay(true);
    let ip = if relay.proxy_protocol {
        match tokio::time::timeout(HELLO_TIMEOUT, io::read_proxy_v1(&mut tcp)).await {
            Ok(Ok(ip)) => ip,
            _ => return,
        }
    } else {
        peer
    };
    let Some(_slot) = take_ip_slot(&relay, ip) else {
        relay.counters.rejected.fetch_add(1, Ordering::Relaxed);
        return;
    };

    // Read just enough to see the server name.
    let mut buf = Vec::with_capacity(2048);
    let name = match tokio::time::timeout(HELLO_TIMEOUT, async {
        let mut chunk = [0u8; 4096];
        loop {
            match sni::parse(&buf) {
                sni::Hello::NeedMore => {}
                sni::Hello::Done(name) => return name,
                sni::Hello::Invalid => return None,
            }
            if buf.len() >= sni::MAX_HELLO + 5 * 8 {
                return None;
            }
            match tcp.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await
    {
        Ok(Some(name)) => name,
        _ => {
            relay.counters.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if name == relay.relay_host {
        control(&relay, io::Prefixed::new(buf, tcp)).await;
    } else if ticket::is_mcp_host(&name, &relay.mcp_domain) {
        forward(&relay, &name, buf, tcp).await;
    } else {
        relay.counters.rejected.fetch_add(1, Ordering::Relaxed);
    }
}

async fn forward(relay: &Relay, host: &str, hello: Vec<u8>, tcp: TcpStream) {
    let opened = tokio::time::timeout(CONTROL_TIMEOUT, relay.registry.open(host)).await;
    let Ok(Some(opened)) = opened else {
        relay.counters.no_computer.fetch_add(1, Ordering::Relaxed);
        return;
    };
    relay.counters.forwarded.fetch_add(1, Ordering::Relaxed);
    let session::Opened { stream, _permit } = opened;
    let stream = tokio_util::compat::FuturesAsyncReadCompatExt::compat(stream);
    let moved = io::pipe(io::Prefixed::new(hello, tcp), stream, IDLE).await;
    relay.counters.bytes.fetch_add(moved, Ordering::Relaxed);
}

#[derive(serde::Deserialize)]
struct ControlHello {
    ticket: String,
    proof: String,
}

async fn control(relay: &Relay, io: io::Prefixed<TcpStream>) {
    let result = tokio::time::timeout(CONTROL_TIMEOUT, async {
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io)
            .await
            .map_err(|_| "handshake")?;
        if let Some(challenge) = &relay.challenge_tls {
            if rustls_acme::is_tls_alpn_challenge(&start.client_hello()) {
                if let Ok(mut tls) = start.into_stream(challenge.clone()).await {
                    let _ = tls.shutdown().await;
                }
                return Err("acme challenge");
            }
        }
        let mut tls = start
            .into_stream(relay.control_tls.clone())
            .await
            .map_err(|_| "handshake")?;
        let mut exporter = [0u8; 32];
        tls.get_ref()
            .1
            .export_keying_material(&mut exporter, ticket::EXPORTER_LABEL, None)
            .map_err(|_| "exporter")?;
        let line = io::read_line(&mut tls, 8 * 1024)
            .await
            .map_err(|_| "hello")?;
        let hello: ControlHello = serde_json::from_slice(&line).map_err(|_| "hello")?;
        let rules = ticket::Rules {
            api_key: &relay.api_key,
            relay_host: &relay.relay_host,
            mcp_domain: &relay.mcp_domain,
        };
        match ticket::check(&rules, &hello.ticket, &hello.proof, &exporter, now()) {
            Ok(host) => Ok((tls, host)),
            Err(reason) => {
                let reply = serde_json::json!({ "ok": false, "error": reason });
                let _ = tls.write_all(format!("{reply}\n").as_bytes()).await;
                let _ = tls.shutdown().await;
                Err("ticket")
            }
        }
    })
    .await;

    let (mut tls, host) = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err("acme challenge")) => return,
        _ => {
            relay
                .counters
                .control_failed
                .fetch_add(1, Ordering::Relaxed);
            // Slow down guessing a little.
            tokio::time::sleep(Duration::from_secs(1)).await;
            return;
        }
    };
    let reply = serde_json::json!({
        "ok": true,
        "host": host,
        "ttl": SESSION_TTL.as_secs(),
    });
    if tls
        .write_all(format!("{reply}\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }
    relay.counters.control_ok.fetch_add(1, Ordering::Relaxed);
    let mut config = yamux::Config::default();
    config.set_max_num_streams(session::STREAMS_PER_HOST * 2);
    let conn = yamux::Connection::new(tls.compat(), config, yamux::Mode::Client);
    relay
        .registry
        .serve(host, conn, SESSION_TTL + SESSION_GRACE)
        .await;
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
