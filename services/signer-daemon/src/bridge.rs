//! Bridged-restore HTTP listener (docs/22 Phase 3a + 3b).
//!
//! Exposes a minimal loopback-only HTTP surface so the Web UI can ask
//! the daemon to unwrap a single message's content key on user
//! command. The key material never leaves this process — only the
//! short-lived `content_key` plaintext does, over a 127.0.0.1 hop the
//! same daemon already owns.
//!
//! Unbreakable invariants (docs/22 §2):
//!   * bind `127.0.0.1` / `::1` only — `0.0.0.0` is rejected at the
//!     CLI layer, so even a future typo can't expose the port to LAN.
//!   * every request must carry `Origin:` matching the configured
//!     allowed origin (default `https://app.nexusinbox.ai`).
//!   * privileged requests (/v1/unwrap, /v1/session*) must carry a
//!     bearer `X-NexusInbox-Bridge:` token. In 3a that was a single
//!     env-configured shared secret; in 3b we still accept that token
//!     (backward compat) AND any token issued via the pairing flow
//!     below. Tokens live in `daemon memory` only — daemon restart
//!     invalidates everything, which is the intended security
//!     property.
//!   * token comparison is constant-time for the shared-secret path;
//!     paired tokens are identified by sha256 hex lookup in an
//!     in-memory inventory that a hostile timing attacker can't
//!     accelerate past the hash step.
//!   * `/v1/pair` is the *only* unauthenticated endpoint. It is
//!     bound by three independent checks before issuing a token:
//!       1. loopback bind (daemon won't start otherwise),
//!       2. Origin exact-match (same CORS layer + middleware the
//!          other endpoints use),
//!       3. a short-lived pairing code the operator read out of the
//!          daemon's stderr.
//!   * responses forbid caching and cross-origin embedding.
//!
//! Phase 3b adds the pairing flow. Three new endpoints — `POST
//! /v1/pair`, `DELETE /v1/session`, `DELETE /v1/sessions` — plus
//! four new audit event kinds (`bridged_pair_requested`,
//! `bridged_pair_succeeded`, `bridged_pair_failed`,
//! `bridged_pair_revoked`) so pair lifecycle is as auditable as
//! decrypt itself. The shared-secret path (`--bridge-token` /
//! `AGENT_INBOX_BRIDGE_TOKEN`) stays fully working for migration.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::{derive_did_from_verifying_key, unwrap_content_key, DaemonState};

// -----------------------------------------------------------------------------
// Audit (docs/22 §2 invariant 6, §4.1)
// -----------------------------------------------------------------------------
//
// Every bridge request — success, client failure, or denial — emits
// a single JSON line to stderr so an operator can pipe the daemon's
// stderr to their log aggregation (`| tee -a /var/log/nexusinbox
// -signer.log`, journald, Loki, etc.) and reconstruct a full audit
// trail locally. The centralised `agent_audit_log` integration in
// the API is explicitly Phase 3c work — §8 of docs/22 was updated in
// parallel to call that out rather than claim the invariant is
// satisfied end-to-end.
//
// The format deliberately mirrors `@nexusinbox/mcp-server`'s audit
// schema (timestamp + source + event + aid + ...) so both sources
// can feed the same downstream pipeline without per-source parsing.

// Fields are `pub` because `bridge_audit_forwarder` constructs
// these in tests and serialises them for the API payload. At
// runtime the only construction site is `audit_base()` below, so
// the public surface is still narrow.
#[derive(Serialize, Clone, Debug)]
pub struct BridgeAuditEvent {
    /// ISO-8601, UTC, ms precision — matches
    /// `@nexusinbox/mcp-server`'s audit format.
    pub timestamp: String,
    /// Constant `"signer-daemon-bridge"` so downstream aggregators
    /// can separate bridge events from the UDS-side token-issuance
    /// traffic without guessing.
    pub source: &'static str,
    /// One of: `"bridged_decrypt"`, `"bridged_status"`,
    /// `"bridged_pair_requested"`, `"bridged_pair_succeeded"`,
    /// `"bridged_pair_failed"`, `"bridged_pair_revoked"`.
    pub event: &'static str,
    /// One of: `"ok"`, `"unauthorized"`, `"forbidden_origin"`,
    ///         `"bad_request"`, `"daemon_error"`, `"disabled"`,
    ///         `"rate_limited"`, `"nonce_missing"`,
    ///         `"nonce_mismatch"`, `"no_match"`.
    pub outcome: &'static str,
    pub aid: String,
    pub credential_id: String,
    pub did: String,
    /// Origin header as presented by the caller (or `"(missing)"`).
    /// Present on *every* outcome so denied requests expose where
    /// they came from — the whole point of logging rejects.
    pub origin: String,
    /// sha256(encrypted_key) hex. `None` when the request never
    /// carried a body (e.g. the status probe or an Origin reject
    /// before body parsing). Serialises the wrapped-key identity
    /// without leaking the ciphertext itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key_hash: Option<String>,
    /// Human-readable error message, if any. Mirrored verbatim from
    /// the outgoing HTTP response so stderr and client stay in sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// Sink for audit events. Default writes one JSON line to stderr;
/// tests swap in a Mutex-backed collector so they can assert
/// specific shapes without capturing real stderr. `Box<dyn Fn>` over
/// a plain function pointer gives us the flexibility to carry state
/// in the collector without macros.
pub type AuditSink = dyn Fn(&BridgeAuditEvent) + Send + Sync + 'static;

fn default_audit_sink() -> Arc<AuditSink> {
    Arc::new(|event: &BridgeAuditEvent| {
        // `serde_json::to_string` never fails for this shape (no
        // trailing floats etc.), so a `.unwrap_or` branch is safer
        // than `.expect` — the worst case is a structured line going
        // missing, not a daemon crash during audit.
        let line =
            serde_json::to_string(event).unwrap_or_else(|_| String::from("{\"audit\":\"failed\"}"));
        eprintln!("{line}");
    })
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(*b >> 4) as usize] as char);
        out.push(HEX[(*b & 0x0f) as usize] as char);
    }
    out
}

/// Runtime config threaded through the router state.
pub struct BridgeConfig {
    /// Optional shared-secret token kept for backward compatibility
    /// with Phase 3a deployments. When `Some`, it is accepted
    /// alongside any paired tokens and surfaces as a synthetic
    /// `shared-secret` session. Phase 3b operators who switch to the
    /// pair flow can leave this at `None` — daemon will still issue
    /// fresh tokens on pairing.
    pub shared_secret_token: Option<String>,
    /// Origin to accept. Exact-match string compare.
    pub allowed_origin: String,
    /// Pairing codes the daemon hands out at startup. 5-minute TTL,
    /// single-use. Operator reads one of these off stderr, types it
    /// into the Web UI, and `/v1/pair` consumes it to mint a real
    /// bearer token. Regenerated on daemon restart (docs/22 §4.3,
    /// §11 decision: memory-only, no disk persistence).
    pub pairing_code_ttl: Duration,
    /// Policy L3 (docs/22 §4.1 + §8 Phase 3c): cap on how many
    /// bridged decrypts the daemon will service inside a given
    /// window. The two-window shape (per-minute + per-day) matches
    /// docs/15 Policy L1/L2 style — per-minute swallows burst
    /// abuse, per-day bounds the blast radius of a long-term token
    /// leak.
    pub decrypts_per_day_max: u32,
    pub decrypts_per_min_max: u32,
}

impl BridgeConfig {
    /// Reasonable defaults — 5-minute pairing window matches docs/22
    /// §4.3. Rate-cap defaults mirror docs/22 §4.1 (50 per day,
    /// 3 per minute): a legit user restoring ~3 individual messages
    /// over coffee is fine, a leaked token burning through an inbox
    /// trips the cap inside a minute.
    pub fn with_shared_secret(token: Option<String>, allowed_origin: String) -> Self {
        Self {
            shared_secret_token: token,
            allowed_origin,
            pairing_code_ttl: Duration::from_secs(5 * 60),
            decrypts_per_day_max: 50,
            decrypts_per_min_max: 3,
        }
    }
}

/// A single pairing code advertised on stderr. One slot at a time;
/// issuing a new one revokes the previous. Consumed (set via
/// `Option::take`) by the first successful `/v1/pair` that presents
/// it.
#[derive(Clone)]
struct PairingCode {
    code: String,
    expires_at: Instant,
}

/// A long-lived token representing one paired browser. Lives in
/// `daemon memory` only (inventory is a `Mutex<HashMap>`), so daemon
/// restart wipes every pairing — the docs/22 §11 choice we locked in
/// for Phase 3b.
#[derive(Clone)]
pub(crate) struct PairingToken {
    /// Opaque bearer string prefixed `bt_`. Hashed on storage so a
    /// hostile memory dump of the inventory yields hashes, not
    /// replayable bearers. Never logged in full.
    #[allow(dead_code)] // held for future introspection / rotation hooks
    token_hash_hex: String,
    /// Human-readable hint ("Safari on MacBook Air", or whatever the
    /// pair flow passed). Surfaces in `/v1/status` so the user can
    /// identify which row to revoke.
    device_label: String,
    created_at: DateTime<Utc>,
    last_used_at: DateTime<Utc>,
    /// Phase 3c.2 — sha256 hex of the browser-generated session
    /// nonce captured at pair time. The browser must present the
    /// matching raw nonce in `X-NexusInbox-Bridge-Nonce` on every
    /// privileged call. Stored hashed so a memory dump yields the
    /// hash, not a replayable value.
    ///
    /// `None` means the pair predates Phase 3c.2 and the daemon
    /// won't ask for a nonce — kept for strict backward compat with
    /// sessions minted in 3b. New pairs always set this.
    session_nonce_hash: Option<String>,
}

/// Sliding-window rate limiter for bridged decrypts (Policy L3).
///
/// Two independent buckets:
///   * `per_min_timestamps`  — pruned on the 60-second window,
///   * `per_day_timestamps`  — pruned on the 86_400-second window.
///
/// Timestamps are `Instant`s so monotonic-clock drift / system-time
/// changes can't let a caller bypass the cap by rewinding the
/// system clock. `check_and_record()` is a one-shot "am I allowed,
/// and count me in if yes" with no reset-on-fail semantics; a
/// rejected attempt does *not* consume quota, but we still emit an
/// audit event so pattern detection can see it.
struct RateBuckets {
    per_min: Vec<Instant>,
    per_day: Vec<Instant>,
}

impl RateBuckets {
    fn new() -> Self {
        Self {
            per_min: Vec::new(),
            per_day: Vec::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        let minute = Duration::from_secs(60);
        let day = Duration::from_secs(86_400);
        self.per_min.retain(|t| now.duration_since(*t) < minute);
        self.per_day.retain(|t| now.duration_since(*t) < day);
    }

    fn check_and_record(
        &mut self,
        per_min_max: u32,
        per_day_max: u32,
    ) -> Result<RateSnapshot, RateLimitBreach> {
        let now = Instant::now();
        self.prune(now);
        if self.per_min.len() as u32 >= per_min_max {
            return Err(RateLimitBreach::Minute {
                used: self.per_min.len() as u32,
                max: per_min_max,
            });
        }
        if self.per_day.len() as u32 >= per_day_max {
            return Err(RateLimitBreach::Day {
                used: self.per_day.len() as u32,
                max: per_day_max,
            });
        }
        self.per_min.push(now);
        self.per_day.push(now);
        Ok(RateSnapshot {
            per_min_used: self.per_min.len() as u32,
            per_day_used: self.per_day.len() as u32,
        })
    }

    fn snapshot(&mut self) -> RateSnapshot {
        let now = Instant::now();
        self.prune(now);
        RateSnapshot {
            per_min_used: self.per_min.len() as u32,
            per_day_used: self.per_day.len() as u32,
        }
    }
}

/// Outcome of a successful rate check — callers may need the
/// counters for audit / status reporting.
#[derive(Clone)]
struct RateSnapshot {
    per_min_used: u32,
    per_day_used: u32,
}

/// Which bucket tripped the cap. Surfaces in the 429 error message
/// and the audit event so operators can tell "burst abuse" (minute)
/// from "long-term exfiltration" (day) apart.
#[derive(Clone)]
enum RateLimitBreach {
    Minute { used: u32, max: u32 },
    Day { used: u32, max: u32 },
}

impl RateLimitBreach {
    fn human(&self) -> String {
        match self {
            RateLimitBreach::Minute { used, max } => {
                format!("per-minute bridge-decrypt cap hit ({used}/{max})")
            }
            RateLimitBreach::Day { used, max } => {
                format!("per-day bridge-decrypt cap hit ({used}/{max})")
            }
        }
    }
}

struct BridgeAppState {
    daemon: Arc<DaemonState>,
    config: BridgeConfig,
    /// Precomputed DID so every audit entry can include it without
    /// re-running the Ed25519 → `did:key` base58 encode on the hot
    /// path.
    cached_did: String,
    /// Callback invoked for every bridge request. Default sink
    /// writes one JSON line to stderr; tests inject a collector.
    audit_sink: Arc<AuditSink>,
    /// At most one active pairing code. Guarded by a Mutex because
    /// the axum router spawns per-request tasks that can race on
    /// consumption.
    pairing_code: Mutex<Option<PairingCode>>,
    /// Inventory of paired tokens keyed by sha256 hex of the bearer
    /// so the validator does a constant-time hash + HashMap get
    /// rather than a linear scan of raw strings.
    tokens: Mutex<HashMap<String, PairingToken>>,
    /// Policy L3 sliding-window buckets. Single shared instance —
    /// rate caps are per-daemon, not per-paired-browser, so a
    /// compromised single token can't escape the cap by opening
    /// multiple sessions.
    rate_buckets: Mutex<RateBuckets>,
}

impl BridgeAppState {
    fn emit_audit(&self, event: BridgeAuditEvent) {
        (self.audit_sink)(&event);
    }

    fn audit_base(&self, origin: &str) -> BridgeAuditEvent {
        BridgeAuditEvent {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            source: "signer-daemon-bridge",
            event: "bridged_decrypt",
            outcome: "ok",
            aid: self.daemon.aid.clone(),
            credential_id: self.daemon.credential_id.clone(),
            did: self.cached_did.clone(),
            origin: origin.to_string(),
            encrypted_key_hash: None,
            error_message: None,
        }
    }

    /// Generate + stash a fresh pairing code. Invalidates any
    /// previous code — only one outstanding at a time so a lost /
    /// leaked code expires automatically when a new one gets issued.
    fn issue_pairing_code(&self) -> String {
        let code = generate_pairing_code();
        let expires_at = Instant::now() + self.config.pairing_code_ttl;
        let mut slot = self.pairing_code.lock().unwrap();
        *slot = Some(PairingCode {
            code: code.clone(),
            expires_at,
        });
        code
    }

    /// Consume the active pairing code iff the caller-supplied value
    /// matches and the window hasn't expired. `true` → the caller
    /// may mint a token. `false` → token request must be rejected.
    /// Constant-time compare defangs timing side-channels on the
    /// short code.
    fn consume_pairing_code(&self, presented: &str) -> bool {
        let mut slot = self.pairing_code.lock().unwrap();
        let Some(entry) = slot.as_ref() else {
            return false;
        };
        if Instant::now() >= entry.expires_at {
            *slot = None;
            return false;
        }
        if !constant_time_str_eq(&entry.code, presented) {
            // Intentionally *don't* drop the code on a wrong guess —
            // that would let an observer learn "code exists" from the
            // behaviour change. TTL still reaps it.
            return false;
        }
        *slot = None; // single-use
        true
    }

    /// Install a newly-minted bearer into the token inventory.
    /// `session_nonce` is the raw (not-yet-hashed) browser nonce —
    /// daemon stores its sha256 hex so a memory dump never yields
    /// a replayable nonce. `None` = 3b-era session with no binding.
    fn register_token(&self, raw_token: &str, device_label: String, session_nonce: Option<&str>) {
        let now = Utc::now();
        let record = PairingToken {
            token_hash_hex: sha256_hex(raw_token),
            device_label,
            created_at: now,
            last_used_at: now,
            session_nonce_hash: session_nonce.map(sha256_hex),
        };
        self.tokens
            .lock()
            .unwrap()
            .insert(record.token_hash_hex.clone(), record);
    }

    /// Identify the session owning a presented bearer AND, if the
    /// paired record demands one, verify the browser's session
    /// nonce. Returns a discriminant so callers can distinguish
    /// shared-secret / paired / invalid / nonce-mismatch in audit.
    ///
    /// Nonce binding (Phase 3c.2) — the browser generated `nonce`
    /// at pair time, stashed it in `sessionStorage` (dies with the
    /// tab), and presents it on every privileged call via the
    /// `X-NexusInbox-Bridge-Nonce` header. A token lifted from
    /// `localStorage` (XSS, rogue extension) by itself is useless
    /// without the matching nonce.
    fn resolve_token(&self, presented: &str, presented_nonce: Option<&str>) -> ResolvedSession {
        if let Some(expected) = self.config.shared_secret_token.as_deref() {
            if constant_time_str_eq(presented, expected) {
                return ResolvedSession::SharedSecret;
            }
        }
        let hash = sha256_hex(presented);
        let mut tokens = self.tokens.lock().unwrap();
        if let Some(record) = tokens.get_mut(&hash) {
            if let Some(expected_hash) = record.session_nonce_hash.clone() {
                let Some(nonce_raw) = presented_nonce else {
                    return ResolvedSession::NonceMissing;
                };
                let presented_hash = sha256_hex(nonce_raw);
                if !constant_time_str_eq(&presented_hash, &expected_hash) {
                    return ResolvedSession::NonceMismatch;
                }
            }
            record.last_used_at = Utc::now();
            return ResolvedSession::Paired {
                device_label: record.device_label.clone(),
            };
        }
        ResolvedSession::Invalid
    }

    /// Revoke the inventory record matching the presented bearer.
    /// Returns `Some(device_label)` if something was forgotten, else
    /// `None`. Used by DELETE /v1/session.
    fn revoke_token(&self, presented: &str) -> Option<String> {
        let hash = sha256_hex(presented);
        self.tokens
            .lock()
            .unwrap()
            .remove(&hash)
            .map(|record| record.device_label)
    }

    /// Drop every paired session in one shot. Used by DELETE
    /// /v1/sessions. Shared-secret token is *not* affected because
    /// it lives in the static config, not the inventory.
    fn revoke_all_tokens(&self) -> usize {
        let mut tokens = self.tokens.lock().unwrap();
        let count = tokens.len();
        tokens.clear();
        count
    }
}

/// Which authentication slot a presented bearer matched. The label
/// rides along so successful-decrypt audit entries can name the
/// browser that asked — operators trace "which session ran this
/// bridged_decrypt" without cross-referencing the token hash.
///
/// `NonceMissing` / `NonceMismatch` exist so the guard can emit
/// distinct audit outcomes (Phase 3c.2) — "someone presented a
/// real token but no / wrong session nonce" is a much higher-
/// urgency signal than "presented garbage", and operators should
/// be able to alert on it specifically.
#[derive(Clone)]
enum ResolvedSession {
    SharedSecret,
    Paired { device_label: String },
    NonceMissing,
    NonceMismatch,
    Invalid,
}

impl ResolvedSession {
    fn audit_label(&self) -> Option<String> {
        match self {
            ResolvedSession::SharedSecret => Some("(shared secret)".into()),
            ResolvedSession::Paired { device_label } => Some(device_label.clone()),
            ResolvedSession::NonceMissing
            | ResolvedSession::NonceMismatch
            | ResolvedSession::Invalid => None,
        }
    }
}

// -----------------------------------------------------------------------------
// Pairing code generator.
//
// Crockford alphabet (no ambiguous chars — 0/O, 1/I/L excluded) so the
// operator can read the code off a terminal in low light and the user
// can re-type it without mistakes. 12 chars grouped in 4+4+4 with a
// fixed `AIBX-` prefix, matching the format docs/22 §4.3 locked in.
// Output length is generous enough (~5e17 possibilities) for a 5-min
// TTL + single-use lifetime.
// -----------------------------------------------------------------------------

/// Crockford-base32 minus the visually-ambiguous digits (no 0/O/1/I).
/// 32 distinct glyphs → 5 bits per character → 60 bits of entropy in
/// the 12-char body, comfortably more than the 5-minute single-use
/// window needs.
const PAIRING_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTVWXYZ_";

/// Generate a fresh pairing code. `AIBX-XXXX-XXXX-XXXX`, readable
/// low-light, safe to re-type.
fn generate_pairing_code() -> String {
    let mut bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let mut out = String::from("AIBX-");
    for (i, b) in bytes.iter().enumerate() {
        out.push(PAIRING_ALPHABET[(*b % 32) as usize] as char);
        if (i + 1) % 4 == 0 && i != bytes.len() - 1 {
            out.push('-');
        }
    }
    out
}

// -----------------------------------------------------------------------------
// Entry point — spawned from main().
// -----------------------------------------------------------------------------

/// Launch the bridge listener on the given loopback address. Returns
/// only on fatal error; intended to be spawned into the Tokio runtime
/// as its own task alongside the UDS listener.
pub async fn run_bridge(
    daemon: Arc<DaemonState>,
    config: BridgeConfig,
    bind_addr: std::net::SocketAddr,
    audit_tee: Option<tokio::sync::mpsc::Sender<BridgeAuditEvent>>,
) -> Result<(), String> {
    // Defense-in-depth: refuse to bind to anything other than loopback
    // even if the CLI validator somehow let a non-loopback address
    // through. The daemon's whole security posture assumes the HTTP
    // surface is same-host only.
    match bind_addr.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => {}
        IpAddr::V6(ip) if ip.is_loopback() => {}
        other => {
            return Err(format!(
                "bridge bind refused: {other} is not a loopback address"
            ));
        }
    }

    let cached_did = derive_did_from_verifying_key(&daemon.verifying_key);
    // Audit sink composition (docs/22 §8 Phase 3c.3): stderr stays
    // as the always-on local source of truth; when the caller wired
    // a forwarder channel, we also tee into it so the API side
    // gets a chance to persist the event centrally. `try_send` so
    // a slow / full channel can't stall the hot path — dropped
    // events still live in the stderr line.
    let audit_sink: Arc<AuditSink> = if let Some(tee) = audit_tee {
        let stderr_sink = default_audit_sink();
        Arc::new(move |event: &BridgeAuditEvent| {
            (stderr_sink)(event);
            if let Err(err) = tee.try_send(event.clone()) {
                eprintln!("[WARN] bridge-audit tee dropped event: {err}");
            }
        })
    } else {
        default_audit_sink()
    };
    let state = Arc::new(BridgeAppState {
        daemon,
        config,
        cached_did,
        audit_sink,
        pairing_code: Mutex::new(None),
        tokens: Mutex::new(HashMap::new()),
        rate_buckets: Mutex::new(RateBuckets::new()),
    });

    // Issue one pairing code up front and print it to stderr. Users
    // who rely on the old `--bridge-token` env path can ignore the
    // line; users on the Phase 3b flow copy the `AIBX-…` string into
    // the Web UI. New codes also regenerate automatically when the
    // operator re-runs `--bridge-regenerate-pair-code` (a future
    // hook; for now a daemon restart does the same thing).
    let initial_code = state.issue_pairing_code();
    eprintln!(
        "[INFO]   Pairing code:  {}   (valid {} min, single-use)",
        initial_code,
        state.config.pairing_code_ttl.as_secs() / 60
    );

    // CORS policy: exact-match allowed-origin echo, no wildcard.
    let allowed_origin_header = HeaderValue::from_str(&state.config.allowed_origin)
        .map_err(|e| format!("invalid allowed-origin: {e}"))?;
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(allowed_origin_header)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-nexusinbox-bridge"),
            axum::http::HeaderName::from_static("x-nexusinbox-bridge-nonce"),
        ])
        .allow_private_network(true)
        .max_age(Duration::from_secs(60));

    // Two routers so `/v1/pair` can keep Origin enforcement but skip
    // the token guard (a caller who already had a token wouldn't be
    // pairing). Every other privileged path still runs
    // `enforce_bridge_guards` for Origin + token verification.
    let pair_router =
        Router::new()
            .route("/v1/pair", post(handle_pair))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                enforce_origin_only,
            ));
    let secure_router = Router::new()
        .route("/v1/status", get(handle_status))
        .route("/v1/unwrap", post(handle_unwrap))
        .route("/v1/session", delete(handle_revoke_session))
        .route("/v1/sessions", delete(handle_revoke_all_sessions))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_bridge_guards,
        ));

    let router = secure_router
        .merge(pair_router)
        .layer(cors)
        .with_state(state);

    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("failed to bind bridge listener on {bind_addr}: {e}"))?;
    eprintln!("[INFO] Bridge listener: http://{bind_addr}");
    axum::serve(listener, router)
        .await
        .map_err(|e| format!("bridge listener failed: {e}"))
}

// -----------------------------------------------------------------------------
// Middleware — the three unbreakable invariants in one layer.
// -----------------------------------------------------------------------------

/// Derive which audit `event` string to emit for a given request
/// path. Kept as a standalone mapping so the deny branches in both
/// `enforce_bridge_guards` and `enforce_origin_only` stay consistent.
fn audit_event_kind_for_path(path: &str) -> &'static str {
    match path {
        "/v1/status" => "bridged_status",
        "/v1/pair" => "bridged_pair_requested",
        "/v1/session" | "/v1/sessions" => "bridged_pair_revoked",
        _ => "bridged_decrypt",
    }
}

/// Full Origin + bearer-token middleware for the privileged routes
/// (`/v1/unwrap`, `/v1/status`, `/v1/session`, `/v1/sessions`).
async fn enforce_bridge_guards(
    State(state): State<Arc<BridgeAppState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // Preflight passes through; CorsLayer handles the actual
    // Access-Control-* response before we see the method.
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let origin_header = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(missing)")
        .to_string();
    let event_kind = audit_event_kind_for_path(request.uri().path());

    // 1. Origin must match exactly. Missing Origin → reject.
    let origin_ok = origin_header == state.config.allowed_origin;
    if !origin_ok {
        let mut event = state.audit_base(&origin_header);
        event.event = event_kind;
        event.outcome = "forbidden_origin";
        event.error_message = Some("origin not allowed".into());
        state.emit_audit(event);
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    // 2. Bearer token must match something the daemon knows about —
    // either the legacy shared secret (backward compat with Phase
    // 3a), or a token we minted via /v1/pair and still have in the
    // inventory. Tokens bound to a session nonce (Phase 3c.2) must
    // also come with a matching `X-NexusInbox-Bridge-Nonce`.
    let presented = headers
        .get("x-nexusinbox-bridge")
        .and_then(|v| v.to_str().ok());
    let presented_nonce = headers
        .get("x-nexusinbox-bridge-nonce")
        .and_then(|v| v.to_str().ok());
    let resolved = match presented {
        Some(v) => state.resolve_token(v, presented_nonce),
        None => ResolvedSession::Invalid,
    };
    // Three distinct deny outcomes let alerting tell "someone's
    // brute-forcing tokens" apart from "someone has a valid token
    // but the wrong session nonce", which is the higher-urgency
    // signal (token likely exfiltrated).
    let (deny_outcome, deny_message): (Option<&'static str>, Option<&'static str>) = match &resolved
    {
        ResolvedSession::Invalid => (Some("unauthorized"), Some("invalid bridge token")),
        ResolvedSession::NonceMissing => {
            (Some("nonce_missing"), Some("session nonce header missing"))
        }
        ResolvedSession::NonceMismatch => {
            (Some("nonce_mismatch"), Some("session nonce did not match"))
        }
        ResolvedSession::SharedSecret | ResolvedSession::Paired { .. } => (None, None),
    };
    if let (Some(outcome), Some(message)) = (deny_outcome, deny_message) {
        let mut event = state.audit_base(&origin_header);
        event.event = event_kind;
        event.outcome = outcome;
        event.error_message = Some(message.to_string());
        state.emit_audit(event);
        // Return 401 for both "wrong token" and "nonce mismatch" so
        // clients can't timing-discriminate between the two at the
        // status-code layer. The distinction lives in the audit
        // stream only.
        return (StatusCode::UNAUTHORIZED, message).into_response();
    }

    // Stash the resolved session into request extensions so handlers
    // can include the device_label in their audit emits without
    // running the lookup a second time.
    let mut request = request;
    request.extensions_mut().insert(resolved);

    let mut response = next.run(request).await;
    // 3. Never cache, never embed cross-origin.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Slim middleware for `/v1/pair` — Origin must still match and the
/// same hardening headers stick to the response, but the caller is
/// establishing a token in the first place so there's no bearer to
/// check. The pairing *code* is the credential here; it's consumed
/// inside `handle_pair`.
async fn enforce_origin_only(
    State(state): State<Arc<BridgeAppState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let origin_header = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(missing)")
        .to_string();
    let event_kind = audit_event_kind_for_path(request.uri().path());

    if origin_header != state.config.allowed_origin {
        let mut event = state.audit_base(&origin_header);
        event.event = event_kind;
        event.outcome = "forbidden_origin";
        event.error_message = Some("origin not allowed".into());
        state.emit_audit(event);
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Constant-time string comparison for secrets. Both sides coerce to
/// bytes; length mismatch short-circuits to false but still runs the
/// full loop on the longer side to avoid a timing side-channel on
/// secret length.
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let len = ab.len().max(bb.len());
    let mut diff: u8 = (ab.len() ^ bb.len()) as u8;
    for i in 0..len {
        let x = if i < ab.len() { ab[i] } else { 0 };
        let y = if i < bb.len() { bb[i] } else { 0 };
        diff |= x ^ y;
    }
    diff == 0
}

// -----------------------------------------------------------------------------
// GET /v1/status — liveness + identity echo.
// -----------------------------------------------------------------------------

#[derive(Serialize)]
struct PairedSessionSummary {
    /// sha256(token) hex — stable identifier the Web UI can match
    /// against its locally-stored token without leaking the token
    /// itself. `None` for the legacy shared-secret path.
    id: Option<String>,
    device_label: String,
    created_at: String,
    last_used_at: String,
    /// Synthetic row for the env-configured shared secret. UI shows
    /// it muted because it can only be revoked by restarting daemon
    /// without `--bridge-token`.
    shared_secret: bool,
}

#[derive(Serialize)]
struct PolicySnapshot {
    /// Current window usage — daemon-wide (not per-session). Lets
    /// the UI render "N / M decrypts remaining today" without
    /// having to track events itself.
    bridged_decrypts_per_min_used: u32,
    bridged_decrypts_per_min_max: u32,
    bridged_decrypts_per_day_used: u32,
    bridged_decrypts_per_day_max: u32,
}

#[derive(Serialize)]
struct StatusResponse {
    ok: bool,
    version: &'static str,
    paired: bool,
    aid: String,
    did: String,
    encryption_public_key: Option<String>,
    /// Phase 3b: every paired browser the inventory currently knows
    /// about. Lets /settings/agents render a list with revoke
    /// buttons, and lets the caller recognise its own session via
    /// the sha256 of its stored token.
    paired_sessions: Vec<PairedSessionSummary>,
    /// Phase 3c: rate-cap counters so the Web UI can surface the
    /// remaining quota before the user wastes a decrypt on a
    /// pre-empted 429.
    policy: PolicySnapshot,
}

async fn handle_status(
    State(state): State<Arc<BridgeAppState>>,
    headers: HeaderMap,
) -> Json<StatusResponse> {
    let daemon = &state.daemon;
    let did = derive_did_from_verifying_key(&daemon.verifying_key);
    let encryption_public_key = daemon.encryption_secret.as_ref().map(|secret| {
        let pk = X25519PublicKey::from(secret);
        URL_SAFE_NO_PAD.encode(pk.as_bytes())
    });

    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(missing)")
        .to_string();
    let mut event = state.audit_base(&origin);
    event.event = "bridged_status";
    event.outcome = "ok";
    state.emit_audit(event);

    let mut paired_sessions: Vec<PairedSessionSummary> = {
        let tokens = state.tokens.lock().unwrap();
        tokens
            .values()
            .map(|record| PairedSessionSummary {
                id: Some(record.token_hash_hex.clone()),
                device_label: record.device_label.clone(),
                created_at: record
                    .created_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                last_used_at: record
                    .last_used_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                shared_secret: false,
            })
            .collect()
    };
    // Newest pairing first so the UI list reads stable.
    paired_sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    if state.config.shared_secret_token.is_some() {
        // Surface the legacy env-configured secret as its own row so
        // the user can see "this browser is using the shared secret,
        // not a paired token" — matters for the Phase 3a → 3b
        // migration when both can coexist.
        paired_sessions.push(PairedSessionSummary {
            id: None,
            device_label: "(shared secret · env)".into(),
            created_at: "(daemon start)".into(),
            last_used_at: "(varies)".into(),
            shared_secret: true,
        });
    }

    let snapshot = state.rate_buckets.lock().unwrap().snapshot();

    Json(StatusResponse {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
        paired: !paired_sessions.is_empty(),
        aid: daemon.aid.clone(),
        did,
        encryption_public_key,
        paired_sessions,
        policy: PolicySnapshot {
            bridged_decrypts_per_min_used: snapshot.per_min_used,
            bridged_decrypts_per_min_max: state.config.decrypts_per_min_max,
            bridged_decrypts_per_day_used: snapshot.per_day_used,
            bridged_decrypts_per_day_max: state.config.decrypts_per_day_max,
        },
    })
}

// -----------------------------------------------------------------------------
// POST /v1/pair — exchange a freshly-printed pairing code for a
// long-lived bearer token that the Web UI stores locally.
// -----------------------------------------------------------------------------

#[derive(Deserialize)]
struct PairRequest {
    pairing_code: String,
    /// Optional UX hint ("Safari on MacBook Air") — surfaces in the
    /// Paired Sessions list so the user can identify which row to
    /// revoke later. Daemon never uses it for authz; clamped to 120
    /// chars to stop hostile clients from bloating the inventory.
    #[serde(default)]
    device_label: Option<String>,
    /// Phase 3c.2 — raw browser-generated nonce. Daemon stores its
    /// sha256 hex against this token, and every subsequent
    /// privileged call must present the matching raw value via
    /// `X-NexusInbox-Bridge-Nonce`. Accepted `base64url(32 bytes)`
    /// or any ≤128-char printable string; daemon treats it as an
    /// opaque secret. Omitted → 3b-era pairing with no nonce
    /// binding (kept for backward compat with older Web clients).
    #[serde(default)]
    session_nonce: Option<String>,
}

#[derive(Serialize)]
struct PairResponse {
    token: String,
    device_label: String,
    created_at: String,
}

async fn handle_pair(
    State(state): State<Arc<BridgeAppState>>,
    headers: HeaderMap,
    Json(payload): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(missing)")
        .to_string();

    let emit_failure = |message: &str| {
        let mut event = state.audit_base(&origin);
        event.event = "bridged_pair_failed";
        event.outcome = "unauthorized";
        event.error_message = Some(message.to_string());
        state.emit_audit(event);
    };

    // Always emit the request-received event before the verdict so
    // operators can correlate "someone tried to pair" even when the
    // attempt eventually failed.
    {
        let mut event = state.audit_base(&origin);
        event.event = "bridged_pair_requested";
        event.outcome = "ok";
        state.emit_audit(event);
    }

    let presented = payload.pairing_code.trim().to_ascii_uppercase();
    if presented.is_empty() {
        emit_failure("empty pairing code");
        return Err((StatusCode::BAD_REQUEST, "pairing_code is required".into()));
    }
    if !state.consume_pairing_code(&presented) {
        emit_failure("pairing code rejected");
        return Err((
            StatusCode::UNAUTHORIZED,
            "pairing code rejected (wrong, expired, or already used)".into(),
        ));
    }

    // Mint a fresh bearer. 32 bytes of CSPRNG → base64url so the
    // token is URL-safe and 43 chars long, matching the `bt_…` shape
    // the Web UI already renders in the legacy path.
    let mut raw = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    let bearer = format!("bt_{}", URL_SAFE_NO_PAD.encode(raw));

    let mut label = payload.device_label.unwrap_or_default().trim().to_string();
    if label.is_empty() {
        label = "Paired browser".into();
    }
    if label.len() > 120 {
        label.truncate(120);
    }

    // Clamp nonce to a sane length so a hostile client can't feed
    // a multi-MB string into the inventory. 32-byte base64url is 43
    // chars; 256 gives comfortable headroom for alternative
    // encodings without opening a DoS vector.
    let nonce = payload.session_nonce.as_deref().and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.len() > 256 {
            None
        } else {
            Some(trimmed)
        }
    });
    let has_nonce = nonce.is_some();
    state.register_token(&bearer, label.clone(), nonce);

    let created_at = Utc::now();
    {
        let mut event = state.audit_base(&origin);
        event.event = "bridged_pair_succeeded";
        event.outcome = "ok";
        event.error_message = Some(format!("device_label={label}; nonce_bound={has_nonce}"));
        state.emit_audit(event);
    }

    Ok(Json(PairResponse {
        token: bearer,
        device_label: label,
        created_at: created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
}

// -----------------------------------------------------------------------------
// DELETE /v1/session — revoke the bearer the caller presented.
// DELETE /v1/sessions — revoke every paired token (legacy shared
// secret survives; it's not in the inventory).
// -----------------------------------------------------------------------------

#[derive(Serialize)]
struct RevokeResponse {
    revoked: usize,
}

async fn handle_revoke_session(
    State(state): State<Arc<BridgeAppState>>,
    headers: HeaderMap,
) -> Json<RevokeResponse> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(missing)")
        .to_string();
    let presented = headers
        .get("x-nexusinbox-bridge")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let revoked_label = state.revoke_token(&presented);
    let count = revoked_label.as_ref().map(|_| 1).unwrap_or(0);

    let mut event = state.audit_base(&origin);
    event.event = "bridged_pair_revoked";
    event.outcome = if count == 1 { "ok" } else { "no_match" };
    event.error_message = Some(match revoked_label {
        Some(label) => format!("single: {label}"),
        None => "single: no matching token".into(),
    });
    state.emit_audit(event);

    Json(RevokeResponse { revoked: count })
}

async fn handle_revoke_all_sessions(
    State(state): State<Arc<BridgeAppState>>,
    headers: HeaderMap,
) -> Json<RevokeResponse> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(missing)")
        .to_string();

    let count = state.revoke_all_tokens();
    let mut event = state.audit_base(&origin);
    event.event = "bridged_pair_revoked";
    event.outcome = "ok";
    event.error_message = Some(format!("all: {count}"));
    state.emit_audit(event);

    Json(RevokeResponse { revoked: count })
}

// -----------------------------------------------------------------------------
// POST /v1/unwrap — the main entrypoint.
// -----------------------------------------------------------------------------

#[derive(Deserialize)]
struct UnwrapRequest {
    encrypted_key: String,
}

#[derive(Serialize)]
struct UnwrapResponse {
    content_key: String,
}

async fn handle_unwrap(
    State(state): State<Arc<BridgeAppState>>,
    headers: HeaderMap,
    session: axum::extract::Extension<ResolvedSession>,
    Json(payload): Json<UnwrapRequest>,
) -> Result<Json<UnwrapResponse>, (StatusCode, String)> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(missing)")
        .to_string();
    let ek_hash = sha256_hex(&payload.encrypted_key);
    let session_label = session.audit_label();

    // Shared emit helper keeps the four outcomes (disabled / ok /
    // bad_request / daemon_error) consistent in shape. Rust closures
    // move captures, so we clone the string fields we need up front.
    let emit = |outcome: &'static str, error_message: Option<String>| {
        let mut event = state.audit_base(&origin);
        event.event = "bridged_decrypt";
        event.outcome = outcome;
        event.encrypted_key_hash = Some(ek_hash.clone());
        // Prefer an explicit per-call error_message; fall back to
        // the session label so an `ok` event still records which
        // paired browser did the decrypt.
        event.error_message =
            error_message.or_else(|| session_label.as_ref().map(|l| format!("session: {l}")));
        state.emit_audit(event);
    };

    let Some(secret) = state.daemon.encryption_secret.as_ref() else {
        let msg = "unwrap_content_key disabled: no --encryption-key-file configured";
        emit("disabled", Some(msg.into()));
        // Mirror the UDS-side error so clients get the same message
        // whether they came through the bridge or the JSON-RPC
        // socket; disabling the encryption key should disable both
        // paths.
        return Err((StatusCode::SERVICE_UNAVAILABLE, msg.into()));
    };

    // Policy L3 (docs/22 §4.1 + §8 Phase 3c) — cap runs *before* the
    // crypto so a hostile caller can't pay the unwrap cost and then
    // learn "I was rate-limited" from a timing side channel. Rate
    // check is atomic (lock-scope holds the check+record) so two
    // concurrent requests can't both squeak past the boundary.
    match state.rate_buckets.lock().unwrap().check_and_record(
        state.config.decrypts_per_min_max,
        state.config.decrypts_per_day_max,
    ) {
        Ok(_snapshot) => {
            // Quota consumed; fall through to the actual decrypt.
        }
        Err(breach) => {
            let msg = breach.human();
            emit("rate_limited", Some(msg.clone()));
            return Err((StatusCode::TOO_MANY_REQUESTS, msg));
        }
    }

    match unwrap_content_key(secret, &payload.encrypted_key) {
        Ok(content_key) => {
            emit("ok", None);
            Ok(Json(UnwrapResponse { content_key }))
        }
        Err(msg) => {
            // Distinguish malformed input (client bug) from internal
            // crypto failure so clients can act on it sensibly
            // without leaking which stage failed in the reason
            // string — the matcher keeps the caller-visible message
            // identical to the UDS path.
            let is_bad_request = msg.contains("unsupported wrapped key")
                || msg.contains("invalid wrapped key")
                || msg.contains("invalid base64url")
                || msg.contains("ephemeral public key")
                || msg.contains("salt must be")
                || msg.contains("iv must be");
            let (code, outcome): (StatusCode, &'static str) = if is_bad_request {
                (StatusCode::BAD_REQUEST, "bad_request")
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "daemon_error")
            };
            emit(outcome, Some(msg.clone()));
            Err((code, msg))
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DaemonState, RateLimiter};
    use axum::http::{Method as HMethod, Request, StatusCode as HStatus};
    use chacha20poly1305::aead::OsRng;
    use ed25519_dalek::SigningKey;
    use hkdf::Hkdf;
    use http_body_util::BodyExt;
    use std::sync::Mutex;
    use tower::ServiceExt;
    use x25519_dalek::StaticSecret;

    #[test]
    fn constant_time_eq_agrees_with_plain_eq() {
        assert!(constant_time_str_eq("hello", "hello"));
        assert!(!constant_time_str_eq("hello", "HELLO"));
        assert!(!constant_time_str_eq("hello", "hello!"));
        assert!(!constant_time_str_eq("", "x"));
        assert!(constant_time_str_eq("", ""));
        // 32-byte realistic token shape
        assert!(constant_time_str_eq(
            "bt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "bt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!constant_time_str_eq(
            "bt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "bt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
        ));
    }

    // -----------------------------------------------------------------
    // Helpers for the in-process router tests. `build_router` mirrors
    // `run_bridge` but skips the TCP bind so tower::ServiceExt::oneshot
    // can drive requests through the full middleware stack.
    // -----------------------------------------------------------------

    /// Mutex-backed audit collector. Tests inspect `events.lock()`
    /// after driving requests through the router to assert the
    /// expected shape — JSON serialization is tested separately via
    /// the shape of a single event.
    #[derive(Default)]
    struct CollectingSink {
        events: Mutex<Vec<BridgeAuditEvent>>,
    }

    impl CollectingSink {
        fn into_arc() -> (Arc<Self>, Arc<AuditSink>) {
            let collector = Arc::new(CollectingSink::default());
            let c2 = Arc::clone(&collector);
            let sink: Arc<AuditSink> = Arc::new(move |e: &BridgeAuditEvent| {
                c2.events.lock().unwrap().push(e.clone());
            });
            (collector, sink)
        }
    }

    fn make_state_with_sink(
        secret: StaticSecret,
        token: &str,
        sink: Arc<AuditSink>,
    ) -> Arc<BridgeAppState> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let cached_did = derive_did_from_verifying_key(&verifying_key);
        let daemon = Arc::new(DaemonState {
            signing_key,
            verifying_key,
            encryption_secret: Some(secret),
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: std::time::Instant::now(),
            allowed_uid: None,
        });
        Arc::new(BridgeAppState {
            daemon,
            config: BridgeConfig {
                shared_secret_token: Some(token.to_string()),
                allowed_origin: "https://app.nexusinbox.ai".into(),
                pairing_code_ttl: Duration::from_secs(300),
                // Default caps generous enough not to perturb
                // tests that aren't specifically about rate
                // limiting. Dedicated tests construct their own
                // state with tight caps via the method below.
                decrypts_per_day_max: 10_000,
                decrypts_per_min_max: 1_000,
            },
            cached_did,
            audit_sink: sink,
            pairing_code: Mutex::new(None),
            tokens: Mutex::new(HashMap::new()),
            rate_buckets: Mutex::new(RateBuckets::new()),
        })
    }

    fn make_state(secret: StaticSecret, token: &str) -> Arc<BridgeAppState> {
        make_state_with_sink(secret, token, default_audit_sink())
    }

    fn build_router(state: Arc<BridgeAppState>) -> axum::Router {
        let allowed_origin_header = HeaderValue::from_str(&state.config.allowed_origin).unwrap();
        let cors = tower_http::cors::CorsLayer::new()
            .allow_origin(allowed_origin_header)
            .allow_methods([
                HMethod::GET,
                HMethod::POST,
                HMethod::DELETE,
                HMethod::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderName::from_static("x-nexusinbox-bridge"),
            ]);
        // Mirror `run_bridge`'s split: /v1/pair only runs the
        // origin-only middleware (no bearer yet), every other route
        // goes through `enforce_bridge_guards`.
        let pair_router = Router::new().route("/v1/pair", post(handle_pair)).layer(
            middleware::from_fn_with_state(state.clone(), enforce_origin_only),
        );
        let secure_router = Router::new()
            .route("/v1/status", get(handle_status))
            .route("/v1/unwrap", post(handle_unwrap))
            .route("/v1/session", delete(handle_revoke_session))
            .route("/v1/sessions", delete(handle_revoke_all_sessions))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                enforce_bridge_guards,
            ));
        secure_router
            .merge(pair_router)
            .layer(cors)
            .with_state(state)
    }

    /// Emulate apps/web/lib/crypto/keywrap.ts to produce a real
    /// `x25519v1:` envelope for the test recipient — lets the unwrap
    /// endpoint prove the full round trip without mocking the crypto.
    fn wrap_for_recipient(content_key: &str, recipient_pub: &X25519PublicKey) -> String {
        const SALT_LEN: usize = 16;
        const IV_LEN: usize = 12;
        const HKDF_INFO: &[u8] = b"nexusinbox/x25519-wrap/v1";

        let ephemeral_raw: [u8; 32] = rand::random();
        let ephemeral = StaticSecret::from(ephemeral_raw);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(recipient_pub);

        let salt: [u8; SALT_LEN] = rand::random();
        let iv: [u8; IV_LEN] = rand::random();
        let hk = Hkdf::<sha2::Sha256>::new(Some(&salt), shared.as_bytes());
        let mut wrap_key = [0u8; 32];
        hk.expand(HKDF_INFO, &mut wrap_key).unwrap();

        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();
        let ct = cipher
            .encrypt(Nonce::from_slice(&iv), content_key.as_bytes())
            .unwrap();
        format!(
            "x25519v1:{}:{}:{}:{}",
            URL_SAFE_NO_PAD.encode(ephemeral_pub.as_bytes()),
            URL_SAFE_NO_PAD.encode(salt),
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(&ct),
        )
    }

    #[tokio::test]
    async fn status_endpoint_requires_origin_header() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_test_token");
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::FORBIDDEN);
    }

    #[tokio::test]
    async fn status_endpoint_requires_token() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_test_token");
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn status_endpoint_rejects_wrong_origin() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_test_token");
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://evil.example.com")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::FORBIDDEN);
    }

    #[tokio::test]
    async fn status_endpoint_allows_correct_origin_and_token() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_test_token");
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["aid"], "aid:ai:01TEST");
        assert!(body["did"].as_str().unwrap().starts_with("did:key:z"));
    }

    #[tokio::test]
    async fn unwrap_endpoint_round_trips_a_real_envelope() {
        let raw: [u8; 32] = rand::random();
        let secret = StaticSecret::from(raw);
        let public = X25519PublicKey::from(&secret);
        let wrapped = wrap_for_recipient("test-content-key-xyz", &public);
        let state = make_state(secret, "bt_test_token");
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": wrapped }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["content_key"], "test-content-key-xyz");
    }

    #[tokio::test]
    async fn unwrap_endpoint_rejects_wrong_recipient_as_bad_request_or_500() {
        // Wrap for A, hand the ciphertext to a daemon holding secret B.
        let secret_a = StaticSecret::from(rand::random::<[u8; 32]>());
        let pub_a = X25519PublicKey::from(&secret_a);
        let wrapped = wrap_for_recipient("for-a", &pub_a);

        let secret_b = StaticSecret::from(rand::random::<[u8; 32]>());
        let state = make_state(secret_b, "bt_test_token");
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": wrapped }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // AES-GCM failure surfaces as 500 per handle_unwrap's mapping.
        assert_eq!(response.status(), HStatus::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn unwrap_endpoint_rejects_malformed_envelope_as_bad_request() {
        let state = make_state(
            StaticSecret::from(rand::random::<[u8; 32]>()),
            "bt_test_token",
        );
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": "not-an-envelope" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::BAD_REQUEST);
    }

    #[tokio::test]
    async fn responses_set_no_store_and_corp() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_test_token");
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .unwrap(),
            "same-origin"
        );
    }

    // -----------------------------------------------------------------
    // Audit (docs/22 §2 invariant 6) — every outcome emits a well-
    // formed event the caller can parse offline. We swap in a
    // Mutex-backed collector so we can assert on shape without
    // capturing real stderr.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn audit_fires_on_successful_unwrap() {
        let raw: [u8; 32] = rand::random();
        let secret = StaticSecret::from(raw);
        let public = X25519PublicKey::from(&secret);
        let wrapped = wrap_for_recipient("ck-audit-ok", &public);
        let (collector, sink) = CollectingSink::into_arc();
        let state = make_state_with_sink(secret, "bt_test_token", sink);
        let app = build_router(state);

        let _ = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": wrapped.clone() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let events = collector.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event, "bridged_decrypt");
        assert_eq!(ev.outcome, "ok");
        assert_eq!(ev.aid, "aid:ai:01TEST");
        assert_eq!(ev.credential_id, "cred-test");
        assert!(ev.did.starts_with("did:key:z"));
        assert_eq!(ev.origin, "https://app.nexusinbox.ai");
        // sha256 hex is 64 chars and deterministic for the same input.
        let expected = {
            let mut h = Sha256::new();
            h.update(wrapped.as_bytes());
            hex_lower(&h.finalize())
        };
        assert_eq!(ev.encrypted_key_hash.as_deref(), Some(expected.as_str()));
        // Success path now stamps the session label into
        // error_message so operators can correlate a given decrypt
        // with "which browser asked". Shared-secret sessions surface
        // as "(shared secret)".
        assert_eq!(
            ev.error_message.as_deref(),
            Some("session: (shared secret)"),
            "expected shared-secret session label on ok event, got {:?}",
            ev.error_message,
        );
        assert!(!ev.timestamp.is_empty());
    }

    #[tokio::test]
    async fn audit_fires_on_invalid_token_before_reaching_handler() {
        let raw: [u8; 32] = rand::random();
        let (collector, sink) = CollectingSink::into_arc();
        let state = make_state_with_sink(StaticSecret::from(raw), "bt_correct", sink);
        let app = build_router(state);

        let _ = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_wrong")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": "x25519v1:a:b:c:d" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let events = collector.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "unauthorized");
        // Guard rejected before the handler ran → no ek_hash yet.
        assert!(events[0].encrypted_key_hash.is_none());
        assert_eq!(events[0].origin, "https://app.nexusinbox.ai");
    }

    #[tokio::test]
    async fn audit_fires_on_wrong_origin() {
        let raw: [u8; 32] = rand::random();
        let (collector, sink) = CollectingSink::into_arc();
        let state = make_state_with_sink(StaticSecret::from(raw), "bt_test_token", sink);
        let app = build_router(state);

        let _ = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://evil.example.com")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let events = collector.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        // Status path still emits the `bridged_status` event kind even
        // though the middleware rejected before the handler — lets
        // operators spot Origin fishing without inferring from
        // silence.
        assert_eq!(ev.event, "bridged_status");
        assert_eq!(ev.outcome, "forbidden_origin");
        assert_eq!(ev.origin, "https://evil.example.com");
    }

    #[tokio::test]
    async fn audit_fires_on_bad_request_envelope() {
        let raw: [u8; 32] = rand::random();
        let (collector, sink) = CollectingSink::into_arc();
        let state = make_state_with_sink(StaticSecret::from(raw), "bt_test_token", sink);
        let app = build_router(state);

        let _ = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_test_token")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": "not-an-envelope" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let events = collector.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "bad_request");
        assert!(events[0].error_message.is_some());
        assert!(events[0].encrypted_key_hash.is_some());
    }

    #[tokio::test]
    async fn audit_event_serialises_to_json_line() {
        // Single-event shape contract — catches accidental renames or
        // case flips in serde keys. Downstream log aggregators match
        // on these field names.
        let ev = BridgeAuditEvent {
            timestamp: "2026-04-22T00:00:00.000Z".into(),
            source: "signer-daemon-bridge",
            event: "bridged_decrypt",
            outcome: "ok",
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            did: "did:key:zTest".into(),
            origin: "https://app.nexusinbox.ai".into(),
            encrypted_key_hash: Some("deadbeef".repeat(8)),
            error_message: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"event\":\"bridged_decrypt\""));
        assert!(json.contains("\"outcome\":\"ok\""));
        assert!(json.contains("\"source\":\"signer-daemon-bridge\""));
        assert!(json.contains("\"aid\":\"aid:ai:01TEST\""));
        assert!(json.contains("\"encrypted_key_hash\""));
        // error_message elided via skip_serializing_if.
        assert!(!json.contains("\"error_message\""));
    }

    // -----------------------------------------------------------------
    // Phase 3b — pairing flow (docs/22 §4.3).
    // -----------------------------------------------------------------

    fn pair_json(code: &str, label: Option<&str>) -> axum::body::Body {
        let mut obj = serde_json::json!({ "pairing_code": code });
        if let Some(l) = label {
            obj["device_label"] = serde_json::Value::String(l.to_string());
        }
        axum::body::Body::from(obj.to_string())
    }

    #[tokio::test]
    async fn pair_flow_issues_token_and_mints_paired_session() {
        let raw: [u8; 32] = rand::random();
        let (collector, sink) = CollectingSink::into_arc();
        let state = make_state_with_sink(StaticSecret::from(raw), "bt_shared", sink);
        // Issue a code first, then consume it via the router so the
        // happy path is exercised end-to-end.
        let code = state.issue_pairing_code();
        let app = build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/pair")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("Content-Type", "application/json")
                    .body(pair_json(&code, Some("Chrome on MacBook")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let issued_token = body["token"].as_str().unwrap().to_string();
        assert!(issued_token.starts_with("bt_"));
        assert_eq!(body["device_label"], "Chrome on MacBook");

        // Inventory should now carry exactly one record.
        assert_eq!(state.tokens.lock().unwrap().len(), 1);

        // The new token works on a privileged endpoint.
        let probe = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", &issued_token)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(probe.status(), HStatus::OK);

        // Audit: we expect at least a pair_requested + pair_succeeded
        // for the pair call, plus the bridged_status for the probe.
        let events = collector.events.lock().unwrap();
        let kinds: Vec<&str> = events.iter().map(|e| e.event).collect();
        assert!(
            kinds.contains(&"bridged_pair_requested"),
            "expected pair_requested, got {kinds:?}"
        );
        assert!(
            kinds.contains(&"bridged_pair_succeeded"),
            "expected pair_succeeded, got {kinds:?}"
        );
    }

    #[tokio::test]
    async fn pair_flow_rejects_wrong_code_and_emits_failed() {
        let raw: [u8; 32] = rand::random();
        let (collector, sink) = CollectingSink::into_arc();
        let state = make_state_with_sink(StaticSecret::from(raw), "bt_shared", sink);
        let _code = state.issue_pairing_code();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/pair")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("Content-Type", "application/json")
                    .body(pair_json("AIBX-0000-0000-0000", None))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::UNAUTHORIZED);
        // Inventory untouched.
        assert_eq!(state.tokens.lock().unwrap().len(), 0);
        let events = collector.events.lock().unwrap();
        assert!(events.iter().any(|e| e.event == "bridged_pair_failed"));
    }

    #[tokio::test]
    async fn pair_code_is_single_use() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_shared");
        let code = state.issue_pairing_code();
        let app = build_router(state.clone());

        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/pair")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("Content-Type", "application/json")
                    .body(pair_json(&code, None))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), HStatus::OK);

        let replay = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/pair")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("Content-Type", "application/json")
                    .body(pair_json(&code, None))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), HStatus::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn pair_endpoint_still_enforces_origin() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_shared");
        let code = state.issue_pairing_code();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/pair")
                    .header("Origin", "https://evil.example.com")
                    .header("Content-Type", "application/json")
                    .body(pair_json(&code, None))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::FORBIDDEN);
        // Code should *not* be consumed — a hostile origin can't
        // burn the operator's pairing window.
        assert_eq!(state.tokens.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn revoke_session_drops_single_token() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_shared");
        // Register two tokens manually so we can prove only one of
        // them leaves.
        state.register_token("bt_session_a", "A".into(), None);
        state.register_token("bt_session_b", "B".into(), None);
        assert_eq!(state.tokens.lock().unwrap().len(), 2);
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::DELETE)
                    .uri("/v1/session")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_session_a")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);

        let tokens = state.tokens.lock().unwrap();
        assert_eq!(tokens.len(), 1);
        assert!(tokens.contains_key(&sha256_hex("bt_session_b")));
    }

    #[tokio::test]
    async fn revoke_all_sessions_empties_inventory_but_keeps_shared_secret() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_shared");
        state.register_token("bt_session_a", "A".into(), None);
        state.register_token("bt_session_b", "B".into(), None);
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::DELETE)
                    .uri("/v1/sessions")
                    .header("Origin", "https://app.nexusinbox.ai")
                    // Use shared secret — it's kept even after the
                    // inventory is cleared.
                    .header("X-NexusInbox-Bridge", "bt_shared")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        assert_eq!(state.tokens.lock().unwrap().len(), 0);
        // Shared secret still authenticates (config-backed, not
        // inventory-backed).
        match state.resolve_token("bt_shared", None) {
            ResolvedSession::SharedSecret => {}
            other => panic!(
                "expected SharedSecret, got {:?}",
                match other {
                    ResolvedSession::Paired { .. } => "Paired",
                    ResolvedSession::Invalid => "Invalid",
                    _ => "?",
                }
            ),
        }
    }

    #[tokio::test]
    async fn status_lists_paired_sessions() {
        let raw: [u8; 32] = rand::random();
        let state = make_state(StaticSecret::from(raw), "bt_shared");
        state.register_token("bt_session_a", "Chrome on MacBook".into(), None);
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_shared")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let sessions = body["paired_sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2); // 1 paired + 1 shared-secret synthetic
        let labels: Vec<&str> = sessions
            .iter()
            .map(|s| s["device_label"].as_str().unwrap())
            .collect();
        assert!(labels.iter().any(|l| *l == "Chrome on MacBook"));
        assert!(labels.iter().any(|l| l.contains("shared secret")));
    }

    #[test]
    fn generate_pairing_code_has_expected_shape() {
        let code = generate_pairing_code();
        // AIBX- + 4-4-4 with dashes = 5 + 4 + 1 + 4 + 1 + 4 = 19 chars
        assert_eq!(code.len(), 19, "code length mismatch: {code}");
        assert!(code.starts_with("AIBX-"));
        let rest = &code[5..];
        let parts: Vec<&str> = rest.split('-').collect();
        assert_eq!(parts.len(), 3);
        for p in parts {
            assert_eq!(p.len(), 4);
            for ch in p.chars() {
                assert!(
                    PAIRING_ALPHABET.contains(&(ch as u8)),
                    "char {ch} not in Crockford alphabet"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // Phase 3c — Policy L3 rate cap (docs/22 §4.1 + §8).
    // -----------------------------------------------------------------

    /// Clone the shared helper but let the caller override the two
    /// rate caps so tests can drive tight windows without slowing
    /// anything down with real sleeps.
    fn make_state_with_limits(
        secret: StaticSecret,
        token: &str,
        per_min: u32,
        per_day: u32,
    ) -> (Arc<CollectingSink>, Arc<BridgeAppState>) {
        let (collector, sink) = CollectingSink::into_arc();
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let cached_did = derive_did_from_verifying_key(&verifying_key);
        let daemon = Arc::new(DaemonState {
            signing_key,
            verifying_key,
            encryption_secret: Some(secret),
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: std::time::Instant::now(),
            allowed_uid: None,
        });
        let state = Arc::new(BridgeAppState {
            daemon,
            config: BridgeConfig {
                shared_secret_token: Some(token.to_string()),
                allowed_origin: "https://app.nexusinbox.ai".into(),
                pairing_code_ttl: Duration::from_secs(300),
                decrypts_per_day_max: per_day,
                decrypts_per_min_max: per_min,
            },
            cached_did,
            audit_sink: sink,
            pairing_code: Mutex::new(None),
            tokens: Mutex::new(HashMap::new()),
            rate_buckets: Mutex::new(RateBuckets::new()),
        });
        (collector, state)
    }

    #[tokio::test]
    async fn rate_cap_returns_429_after_per_minute_limit() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let public = X25519PublicKey::from(&secret);
        let wrapped = wrap_for_recipient("ck-rate", &public);
        let (collector, state) = make_state_with_limits(secret, "bt_shared", 2, 100);
        let app = build_router(state);

        // First two succeed.
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(HMethod::POST)
                        .uri("/v1/unwrap")
                        .header("Origin", "https://app.nexusinbox.ai")
                        .header("X-NexusInbox-Bridge", "bt_shared")
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::json!({ "encrypted_key": wrapped.clone() }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), HStatus::OK);
        }

        // Third gets 429 + rate_limited audit.
        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_shared")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": wrapped.clone() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::TOO_MANY_REQUESTS);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("per-minute"),
            "expected per-minute breach message, got {body:?}"
        );

        let events = collector.events.lock().unwrap();
        let rate_limited = events
            .iter()
            .filter(|e| e.outcome == "rate_limited")
            .count();
        assert_eq!(rate_limited, 1);
    }

    #[tokio::test]
    async fn rate_cap_returns_429_after_per_day_limit() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let public = X25519PublicKey::from(&secret);
        let wrapped = wrap_for_recipient("ck-rate", &public);
        // per_min enormous so it doesn't interfere; per_day is tight.
        let (_collector, state) = make_state_with_limits(secret, "bt_shared", 999, 2);
        let app = build_router(state);

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(HMethod::POST)
                        .uri("/v1/unwrap")
                        .header("Origin", "https://app.nexusinbox.ai")
                        .header("X-NexusInbox-Bridge", "bt_shared")
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::json!({ "encrypted_key": wrapped.clone() }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), HStatus::OK);
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_shared")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": wrapped.clone() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::TOO_MANY_REQUESTS);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("per-day"));
    }

    #[tokio::test]
    async fn rate_cap_does_not_consume_quota_when_rejected() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let public = X25519PublicKey::from(&secret);
        let wrapped = wrap_for_recipient("ck", &public);
        let (_collector, state) = make_state_with_limits(secret, "bt_shared", 1, 100);
        let app = build_router(state.clone());

        // First call: OK, uses the 1-per-minute quota.
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/unwrap")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_shared")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({ "encrypted_key": wrapped.clone() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), HStatus::OK);

        // Second & third: both rejected with 429. Critically, the
        // per-day bucket must only count *successful* ops so abuse
        // can't be used to drain the long window.
        for _ in 0..2 {
            let reject = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(HMethod::POST)
                        .uri("/v1/unwrap")
                        .header("Origin", "https://app.nexusinbox.ai")
                        .header("X-NexusInbox-Bridge", "bt_shared")
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(
                            serde_json::json!({ "encrypted_key": wrapped.clone() }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(reject.status(), HStatus::TOO_MANY_REQUESTS);
        }

        // Per-day shows 1 used (the successful one), not 3.
        let snap = state.rate_buckets.lock().unwrap().snapshot();
        assert_eq!(snap.per_day_used, 1);
    }

    #[tokio::test]
    async fn status_endpoint_exposes_rate_policy() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let (_collector, state) = make_state_with_limits(secret, "bt_shared", 3, 50);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_shared")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let policy = body["policy"].as_object().expect("policy present");
        assert_eq!(policy["bridged_decrypts_per_min_max"], 3);
        assert_eq!(policy["bridged_decrypts_per_day_max"], 50);
        assert_eq!(policy["bridged_decrypts_per_min_used"], 0);
        assert_eq!(policy["bridged_decrypts_per_day_used"], 0);
    }

    #[test]
    fn rate_buckets_prune_drops_old_timestamps() {
        let mut buckets = RateBuckets::new();
        // Simulate an old entry by poking raw Instants.
        let old = Instant::now() - Duration::from_secs(3600);
        let now = Instant::now();
        buckets.per_min.push(old);
        buckets.per_day.push(old);
        buckets.per_min.push(now);
        buckets.per_day.push(now);
        buckets.prune(Instant::now());
        // old was > 60s ago so per_min drops it; per_day keeps
        // entries up to 86_400s so old survives there.
        assert_eq!(buckets.per_min.len(), 1);
        assert_eq!(buckets.per_day.len(), 2);
    }

    // -----------------------------------------------------------------
    // Phase 3c.2 — Session nonce binding (docs/22 §2, §4.3).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn pair_flow_records_session_nonce_hash_on_token() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let state = make_state(secret, "bt_shared");
        let code = state.issue_pairing_code();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method(HMethod::POST)
                    .uri("/v1/pair")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({
                            "pairing_code": code,
                            "device_label": "Chrome on MacBook",
                            "session_nonce": "nonce-raw-abc123",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        let tokens = state.tokens.lock().unwrap();
        let record = tokens.values().next().expect("one token registered");
        assert_eq!(
            record.session_nonce_hash.as_deref(),
            Some(sha256_hex("nonce-raw-abc123").as_str()),
        );
    }

    #[tokio::test]
    async fn privileged_request_rejects_token_with_missing_nonce() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let (_collector, state) = make_state_with_limits(secret, "bt_shared", 999, 999);
        state.register_token("bt_nonced", "A".into(), Some("nonce-xyz"));
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_nonced")
                    // No X-NexusInbox-Bridge-Nonce on purpose.
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::UNAUTHORIZED);
        let body_text = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body_text.contains("nonce"),
            "expected nonce message, got {body_text:?}"
        );
    }

    #[tokio::test]
    async fn privileged_request_rejects_wrong_nonce_with_distinct_audit() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let (collector, state) = {
            let (collector, state) = make_state_with_limits(secret, "bt_shared", 999, 999);
            state.register_token("bt_nonced", "A".into(), Some("nonce-xyz"));
            (collector, state)
        };
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_nonced")
                    .header("X-NexusInbox-Bridge-Nonce", "wrong-nonce")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::UNAUTHORIZED);
        let events = collector.events.lock().unwrap();
        assert!(
            events.iter().any(|e| e.outcome == "nonce_mismatch"),
            "expected nonce_mismatch outcome, got {:?}",
            events.iter().map(|e| e.outcome).collect::<Vec<_>>()
        );
        // Crucially NOT `unauthorized` — distinct outcome is the
        // whole point.
        assert!(
            !events.iter().any(|e| e.outcome == "unauthorized"),
            "should not emit generic unauthorized for a nonce mismatch"
        );
    }

    #[tokio::test]
    async fn privileged_request_accepts_matching_nonce() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let (_collector, state) = make_state_with_limits(secret, "bt_shared", 999, 999);
        state.register_token("bt_nonced", "A".into(), Some("nonce-xyz"));
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_nonced")
                    .header("X-NexusInbox-Bridge-Nonce", "nonce-xyz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
    }

    #[tokio::test]
    async fn privileged_request_ignores_nonce_for_shared_secret_path() {
        // Shared-secret sessions are config-backed and predate nonce
        // binding; a nonce header (or lack thereof) mustn't change
        // their acceptance. Otherwise existing Phase 3a deployments
        // would break on upgrade.
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let (_c, state) = make_state_with_limits(secret, "bt_shared", 999, 999);
        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_shared")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
    }

    #[tokio::test]
    async fn legacy_paired_token_without_nonce_still_works() {
        // 3b-era pairing: session_nonce_hash is None. The guard
        // must accept these for backward compat.
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let (_c, state) = make_state_with_limits(secret, "bt_shared", 999, 999);
        state.register_token("bt_legacy", "A".into(), None);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Origin", "https://app.nexusinbox.ai")
                    .header("X-NexusInbox-Bridge", "bt_legacy")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
    }
}
