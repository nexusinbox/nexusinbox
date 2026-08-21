use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Json as JsonBody, Path, Query, Request, State,
    },
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE},
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{
    decode, encode, errors::ErrorKind as JwtErrorKind, Algorithm, DecodingKey, EncodingKey,
    Header as JwtHeader, Validation,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::OnceCell;
use tower_http::cors::CorsLayer;
use ulid::Ulid;
use uuid::Uuid;

// Re-export tracing macros for structured logging throughout the crate.
// Use these instead of eprintln! for production observability.
#[allow(unused_imports)]
use tracing::{debug, error, info, warn};

const AUTH_COOKIE_NAME: &str = "nexusinbox_session";
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const RATE_LIMIT_REQUESTS_PER_WINDOW: u64 = 300;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const REQUEST_TIMEOUT_SECS: u64 = 10;
const AUTH_REPLAY_WINDOW_SECS: i64 = 300;
const MESSAGE_REPLAY_WINDOW_SECS: i64 = 300;
/// DPoP proof replay window (RFC 9449 §4.3). Matches the original in-memory
/// expiry of `iat + 120` seconds so the shared-store migration is behavior-
/// preserving.
const DPOP_REPLAY_WINDOW_SECS: i64 = 120;
/// Interval between background cleanup passes that delete expired rows from
/// `replay_nonces`. Per-request DELETE is intentionally avoided — it would
/// add synchronous SQL work to every DPoP-bound API call for no security
/// benefit.
const REPLAY_NONCE_CLEANUP_INTERVAL_SECS: u64 = 60;
const WORLD_VERIFY_BASE_URL_DEFAULT: &str = "https://developer.world.org";
const WORLD_VERIFY_TIMEOUT_SECS: u64 = 8;
const JWT_ISSUER_DEFAULT: &str = "nexusinbox-api";
const JWT_AUDIENCE_DEFAULT: &str = "nexusinbox-web";
const DB_CONNECT_TIMEOUT_SECS: u64 = 5;
const DB_MAX_CONNECTIONS_DEFAULT: u32 = 10;

// --- Security constants ---
/// Maximum length for a DID string (did:key:z... with multicodec Ed25519 = ~56 chars, allow headroom)
const MAX_DID_LENGTH: usize = 128;
/// Minimum plausible DID length (did:key:z + 43-char base58)
const MIN_DID_LENGTH: usize = 12;
/// Maximum length for agent label
const MAX_AGENT_LABEL_LENGTH: usize = 200;
/// Maximum length for public key / encryption key fields (base64url encoded 32-byte key ≈ 44 chars)
const MAX_KEY_FIELD_LENGTH: usize = 128;
/// Per-IP rate limit: requests per window
const PER_IP_RATE_LIMIT_REQUESTS: u64 = 60;
/// Per-IP rate limit window (seconds)
const PER_IP_RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum number of tracked IPs in the rate limiter map
const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;

// --- Attachment constants (see docs/17_attachment_upload_r2_spec.md) ---
/// Maximum ciphertext size per attachment (5 MiB).
const ATTACHMENT_MAX_CIPHERTEXT_BYTES: i64 = 5 * 1024 * 1024;
/// Maximum attachments per message.
const ATTACHMENT_MAX_COUNT_PER_MESSAGE: usize = 5;
/// Maximum cumulative ciphertext size per message (25 MiB).
const ATTACHMENT_MAX_CUMULATIVE_BYTES: i64 = 25 * 1024 * 1024;
/// Human session JWT + cookie TTL (14 days, absolute).
///
/// World ID re-auth is forced once this expires. Chosen to balance UX
/// (Gmail/GitHub use 14d) against the "lost device" exposure window.
/// Cookie-theft blast radius is already limited because message
/// signing keys live as non-extractable CryptoKeys in IndexedDB
/// (per-domain, per-device); see docs/26 §4.2.
const SESSION_TTL_SECS: i64 = 14 * 24 * 60 * 60;

/// Presigned PUT URL TTL (5 minutes).
const ATTACHMENT_PUT_URL_TTL_SECS: u64 = 300;
/// Presigned GET URL TTL (1 minute).
const ATTACHMENT_GET_URL_TTL_SECS: u64 = 60;
/// Intent expiry when still in `issued` state (30 minutes). Used by the
/// orphan cleanup job (docs/17 §12.1); placeholder constant reserved for
/// when that job is wired.
#[allow(dead_code)]
const ATTACHMENT_INTENT_EXPIRY_SECS: i64 = 30 * 60;
/// Per-user intent rate limit (20 per minute).
const ATTACHMENT_INTENT_RATE_LIMIT_PER_USER: i64 = 20;
/// Per-IP attachment intent rate limit (60 per minute). Enforced separately
/// from the global per-IP budget so an attacker using one IP can't burn the
/// shared rate limit on cheap attachment intents while still leaving other
/// endpoints reachable for the same IP.
const ATTACHMENT_INTENT_RATE_LIMIT_PER_IP: u64 = 60;
/// Rate limit window (1 minute).
const ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS: i64 = 60;

// --- WebSocket security constants ---
/// Maximum concurrent WebSocket connections per authenticated user
const WS_MAX_CONNECTIONS_PER_USER: usize = 5;
/// Maximum frames/messages a client may send per WS_RATE_WINDOW_SECS
const WS_MAX_FRAMES_PER_WINDOW: u64 = 60;
/// Rate-limit window for WebSocket client frames
const WS_RATE_WINDOW_SECS: i64 = 60;
/// Maximum size in bytes of any single WebSocket frame from the client
const WS_MAX_FRAME_BYTES: usize = 16 * 1024;
/// Idle timeout: close connection if no frames exchanged for this long
const WS_IDLE_TIMEOUT_SECS: u64 = 600;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    service: &'static str,
    version: &'static str,
    storage_backend: &'static str,
    database_configured: bool,
    database_connected: bool,
    auto_purge_enabled: bool,
    websocket_enabled: bool,
    world_id_verify_enabled: bool,
}

// FUTURE: Add Redis connection pool for multi-instance state:
//   - DPoP jti replay prevention (I12)
//   - Token revocation set for fast invalidation (I13)
//   - Migrate seen_auth_proofs / seen_message_nonces / revoked_session_jtis
//   Crate: `redis` or `deadpool-redis`. See REDIS_URL in .env.example.
#[derive(Clone)]
struct AppState {
    agents_by_user: Arc<Mutex<HashMap<String, Vec<Agent>>>>,
    messages_by_user: Arc<Mutex<HashMap<String, Vec<MessageRecord>>>>,
    blocked_recipient_dids: Arc<HashSet<String>>,
    low_trust_sender_dids: Arc<HashSet<String>>,
    storage_backend: StorageBackend,
    storage_root: Arc<PathBuf>,
    database_url: Option<String>,
    database_pool: Arc<OnceCell<PgPool>>,
    seen_auth_proofs: Arc<Mutex<HashMap<String, i64>>>,
    seen_message_nonces: Arc<Mutex<HashMap<String, i64>>>,
    revoked_session_jtis: Arc<Mutex<HashMap<String, i64>>>,
    request_budget: Arc<Mutex<RequestBudget>>,
    per_ip_budgets: Arc<Mutex<HashMap<String, RequestBudget>>>,
    /// Dedicated per-IP budget for POST /attachments/intents. See
    /// ATTACHMENT_INTENT_RATE_LIMIT_PER_IP.
    attachment_intent_ip_budgets: Arc<Mutex<HashMap<String, RequestBudget>>>,
    ws_connections_per_user: Arc<Mutex<HashMap<String, usize>>>,
    // SECURITY: hierarchical block lists keyed by recipient owner user_id.
    // L1 (l1_did) drops messages silently; L2 (l2_identity) and L3 (l3_stealth)
    // ban a sender's World ID identity entirely, returning 404 to mask the
    // recipient's existence. L3 additionally hides the recipient from DID
    // resolution endpoints (see list_agents).
    blocks_by_user: Arc<Mutex<HashMap<String, Vec<BlockEntry>>>>,
    // SECURITY: Layer 1 spam filter — env-based deny-list of sender DIDs known
    // to be malicious / spammy. Cheap O(1) lookup on the hot path.
    spam_sender_dids: Arc<HashSet<String>>,
    // Burst tracker for Layer 1 — counts messages from a sender within a
    // rolling window. Exceeding the threshold flags the message as spam.
    sender_burst_counts: Arc<Mutex<HashMap<String, (i64, u32)>>>,
    // First-seen timestamp per World ID, used to compute account_age for the
    // trust-score Phase 2 signals. The DB-backed path queries `users.created_at`
    // directly; this map is the in-memory fallback for tests and for the
    // first-message warm-up window.
    first_seen_at: Arc<Mutex<HashMap<String, i64>>>,
    // In-memory profile store used when no database is attached. Keyed by
    // user_id (stringified UUID). Mirrors users.display_name in the DB path.
    display_names: Arc<Mutex<HashMap<String, String>>>,
    // In-memory address book used when no database is attached. Keyed by
    // user_id. Mirrors the contacts table in the DB path.
    contacts_by_user: Arc<Mutex<HashMap<String, Vec<ContactEntry>>>>,
    /// DPoP jti replay cache: maps jti → expiry timestamp.
    /// Entries are evicted periodically (every 64 validations).
    dpop_jti_cache: Arc<Mutex<HashMap<String, i64>>>,
}

#[derive(Clone, Serialize)]
struct BlockEntry {
    id: Uuid,
    level: String,
    target_did: Option<String>,
    target_world_id: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
struct CreateBlockRequest {
    level: Option<String>,
    target_did: Option<String>,
    target_world_id: Option<String>,
}

#[derive(Serialize)]
struct BlocksResponse {
    blocks: Vec<BlockEntry>,
}

#[derive(Serialize)]
struct CreateBlockResponse {
    id: Uuid,
}

/// Body for `POST /blocks/from-message/:message_id` — the UI-driven
/// "Block sender" flow. The client only supplies the policy level;
/// the server derives the target identifier from the message's
/// `sender_did` so the recipient never needs to handle a World ID
/// nullifier hash by hand.
#[derive(Deserialize)]
struct BlockFromMessageRequest {
    level: Option<String>,
}

/// Response mirrors {@link CreateBlockResponse} but carries the
/// resolved `target_*` so the UI can surface e.g. "blocked
/// did:key:..." in the confirmation toast without refetching.
#[derive(Serialize)]
struct BlockFromMessageResponse {
    id: Uuid,
    level: String,
    target_did: Option<String>,
    target_world_id: Option<String>,
}

#[derive(Clone, Copy)]
struct RequestBudget {
    window_started_at: i64,
    count: u64,
}

#[derive(Clone, Copy)]
enum StorageBackend {
    LocalFs,
    GoogleDrive,
    GoogleDriveMock,
    Ipfs,
    S3,
}

impl StorageBackend {
    fn from_env_or_default() -> Self {
        let raw =
            std::env::var("AGENT_INBOX_STORAGE_BACKEND").unwrap_or_else(|_| "localfs".to_string());
        Self::from_str(&raw).unwrap_or(Self::LocalFs)
    }

    fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "local" | "localfs" => Some(Self::LocalFs),
            "google_drive" | "gdrive" => Some(Self::GoogleDrive),
            "google_drive_mock" | "gdrive_mock" => Some(Self::GoogleDriveMock),
            "ipfs" => Some(Self::Ipfs),
            "s3" | "s3_compatible" | "minio" | "r2" => Some(Self::S3),
            _ => None,
        }
    }

    fn storage_subdir(self) -> &'static str {
        match self {
            Self::LocalFs => "localfs",
            Self::GoogleDrive => "gdrive",
            Self::GoogleDriveMock => "gdrive-mock",
            Self::Ipfs => "ipfs",
            Self::S3 => "s3",
        }
    }
}

impl StorageBackend {
    fn from_storage_ref_scheme(raw: &str) -> Option<Self> {
        match raw {
            "localfs" => Some(Self::LocalFs),
            "gdrive" => Some(Self::GoogleDrive),
            "gdrive_mock" => Some(Self::GoogleDriveMock),
            "ipfs" => Some(Self::Ipfs),
            "s3" => Some(Self::S3),
            _ => None,
        }
    }

    fn storage_ref_scheme(self) -> &'static str {
        match self {
            Self::LocalFs => "localfs",
            Self::GoogleDrive => "gdrive",
            Self::GoogleDriveMock => "gdrive_mock",
            Self::Ipfs => "ipfs",
            Self::S3 => "s3",
        }
    }
}

struct StorageRef {
    backend: StorageBackend,
    locator: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    fn new() -> Self {
        Self::new_with_backend(StorageBackend::from_env_or_default())
    }

    fn new_with_backend(storage_backend: StorageBackend) -> Self {
        let blocked_recipient_dids = parse_did_policy_env("AGENT_INBOX_BLOCKED_RECIPIENT_DIDS");
        let low_trust_sender_dids = parse_did_policy_env("AGENT_INBOX_LOW_TRUST_SENDER_DIDS");
        Self::new_with_backend_and_policies(
            storage_backend,
            blocked_recipient_dids,
            low_trust_sender_dids,
        )
    }

    fn new_with_backend_and_policies(
        storage_backend: StorageBackend,
        blocked_recipient_dids: HashSet<String>,
        low_trust_sender_dids: HashSet<String>,
    ) -> Self {
        let root = std::env::var("AGENT_INBOX_STORAGE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("nexusinbox-localfs"));

        let _ = fs::create_dir_all(&root);

        Self {
            agents_by_user: Arc::new(Mutex::new(HashMap::new())),
            messages_by_user: Arc::new(Mutex::new(HashMap::new())),
            blocked_recipient_dids: Arc::new(blocked_recipient_dids),
            low_trust_sender_dids: Arc::new(low_trust_sender_dids),
            storage_backend,
            storage_root: Arc::new(root),
            database_url: std::env::var("DATABASE_URL").ok(),
            database_pool: Arc::new(OnceCell::new()),
            seen_auth_proofs: Arc::new(Mutex::new(HashMap::new())),
            seen_message_nonces: Arc::new(Mutex::new(HashMap::new())),
            revoked_session_jtis: Arc::new(Mutex::new(HashMap::new())),
            request_budget: Arc::new(Mutex::new(RequestBudget {
                window_started_at: Utc::now().timestamp(),
                count: 0,
            })),
            per_ip_budgets: Arc::new(Mutex::new(HashMap::new())),
            attachment_intent_ip_budgets: Arc::new(Mutex::new(HashMap::new())),
            ws_connections_per_user: Arc::new(Mutex::new(HashMap::new())),
            blocks_by_user: Arc::new(Mutex::new(HashMap::new())),
            spam_sender_dids: Arc::new(parse_did_policy_env("AGENT_INBOX_SPAM_SENDER_DIDS")),
            sender_burst_counts: Arc::new(Mutex::new(HashMap::new())),
            first_seen_at: Arc::new(Mutex::new(HashMap::new())),
            display_names: Arc::new(Mutex::new(HashMap::new())),
            contacts_by_user: Arc::new(Mutex::new(HashMap::new())),
            dpop_jti_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn database_pool(&self) -> Result<Option<PgPool>, String> {
        let Some(database_url) = self.database_url.clone() else {
            return Ok(None);
        };

        let pool = self
            .database_pool
            .get_or_try_init(|| async move {
                PgPoolOptions::new()
                    .max_connections(database_max_connections())
                    .acquire_timeout(Duration::from_secs(DB_CONNECT_TIMEOUT_SECS))
                    .connect(&database_url)
                    .await
            })
            .await
            .map_err(|error| {
                // Log the sqlx connect error (may embed host/user/db details)
                // server-side only; callers surface this String verbatim in
                // HTTP 500 bodies, so keep it generic.
                error!("failed to initialize database pool: {error}");
                "failed to initialize database pool".to_string()
            })?;

        Ok(Some(pool.clone()))
    }
}

#[derive(Clone)]
struct UserRecord {
    id: Uuid,
    verification_level: String,
    created_at: String,
    display_name: Option<String>,
}

/// Frontend sends raw IDKit result + action.
#[derive(Deserialize)]
struct AuthVerifyRequest {
    /// Raw IDKit result (forwarded as-is to World ID v4 verify API)
    idkit_result: Option<serde_json::Value>,
    /// Action name for verification
    action: Option<String>,
    // Legacy fields (kept for backward compat)
    #[allow(dead_code)]
    proof: Option<String>,
    #[allow(dead_code)]
    merkle_root: Option<String>,
    nullifier_hash: Option<String>,
    verification_level: Option<String>,
    #[allow(dead_code)]
    signal: Option<String>,
}

#[derive(Deserialize)]
struct WorldVerifyResult {
    success: bool,
    #[allow(dead_code)]
    action: Option<String>,
    #[allow(dead_code)]
    nullifier_hash: Option<String>,
}

#[derive(Serialize)]
struct AuthVerifyResponse {
    user: UserSummary,
}

#[derive(Serialize)]
struct AuthLogoutResponse {
    success: bool,
}

#[derive(Serialize)]
struct AuthSessionResponse {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserSummary>,
}

#[derive(Serialize, Clone)]
struct UserSummary {
    id: Uuid,
    display_name: Option<String>,
    verification_level: String,
    created_at: String,
}

#[derive(Deserialize)]
struct UpdateProfileRequest {
    display_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TokenClaims {
    iss: String,
    aud: String,
    sub: String,
    wid: String,
    verification_level: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    jti: Option<String>,
}

struct IssuedSession {
    token: String,
    jwt_id: String,
    expires_at_unix: i64,
}

#[derive(Clone, Serialize)]
struct Agent {
    id: Uuid,
    aid: String,
    did: String,
    label: String,
    public_key: String,
    encryption_key: String,
    is_active: bool,
    auto_reply: bool,
    unread_count: i32,
    created_at: String,
}

#[derive(Deserialize)]
struct CreateAgentRequest {
    label: String,
    public_key: String,
    encryption_key: String,
}

#[derive(Serialize)]
struct CreateAgentResponse {
    id: Uuid,
    aid: String,
    did: String,
}

#[derive(Serialize)]
struct AgentsResponse {
    agents: Vec<Agent>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

#[derive(Clone, Serialize)]
struct ContactEntry {
    id: Uuid,
    did: String,
    person_name: String,
    agent_label: Option<String>,
    note: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct ContactsResponse {
    contacts: Vec<ContactEntry>,
}

#[derive(Clone, Serialize)]
struct RecipientResolutionResponse {
    input: String,
    aid: String,
    did: String,
    label: Option<String>,
    signing_public_key: String,
    encryption_public_key: String,
    /// Aggregate over the recipient agent's *active* credentials so
    /// the sender UI can surface a truthful compose-time hint without
    /// probing the recipient's keystore. Values:
    ///
    /// - `"web_keystore"` → at least one active credential stores its
    ///   key in a browser keystore. The recipient can read on the web
    ///   UI, so no special hint is needed.
    /// - `"signer_daemon"` → every active credential lives inside a
    ///   Signer Daemon process. The recipient will not be able to
    ///   read this message in the web UI; compose should warn.
    /// - `"unknown"` → there's at least one active credential with
    ///   no recorded holder (pre-migration or unset). The Web UI
    ///   treats this as "assume Standard mode" to avoid false warnings; the
    ///   caller just surfaces no hint at all.
    ///
    /// See docs/21_message_visibility_ux_for_mcp_modes.md §4.4 / §7.
    key_holder: String,
}

#[derive(Deserialize)]
struct ResolveRecipientQuery {
    identifier: Option<String>,
}

#[derive(Deserialize)]
struct CreateContactRequest {
    did: String,
    person_name: String,
    agent_label: Option<String>,
    note: Option<String>,
}

#[derive(Serialize)]
struct CreateContactResponse {
    id: Uuid,
}

#[derive(Deserialize)]
struct UpdateContactRequest {
    person_name: Option<String>,
    agent_label: Option<String>,
    note: Option<String>,
}

fn compose_party_label(
    user_display_name: Option<String>,
    agent_label: Option<String>,
) -> Option<String> {
    let user = user_display_name
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let agent = agent_label
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    match (user, agent) {
        (Some(u), Some(a)) => Some(format!("{u}({a})")),
        (Some(u), None) => Some(u),
        (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

#[derive(Clone)]
struct MessageRecord {
    id: Uuid,
    sender_did: String,
    sender_label: Option<String>,
    recipient_did: String,
    recipient_label: Option<String>,
    thread_id: Option<Uuid>,
    subject_encrypted: String,
    storage_ref: String,
    status: String,
    priority: String,
    ai_category: Option<String>,
    created_at: String,
    trust_score: f32,
    folder: String,
    starred: bool,
}

#[derive(Serialize, Deserialize)]
struct StoredMessageContent {
    encrypted_content: String,
    encrypted_key: String,
    nonce: String,
    // Kept alongside the ciphertext so clients that fetch the body
    // can dispatch on MIME without a second round trip. Required for
    // A2A messages (docs/24) — the client needs `content_type` to
    // decide whether to JSON-parse the decrypted body or treat it
    // as plain text. `#[serde(default)]` keeps old BYOS blobs
    // readable: they deserialise with `content_type = None` and the
    // client falls back to legacy plain-text behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

#[derive(Deserialize)]
struct SendMessageRequest {
    sender_did: Option<String>,
    recipient_did: Option<String>,
    envelope: Option<Envelope>,
    /// Attachment IDs created via POST /attachments/intents and confirmed via
    /// POST /attachments/{id}/complete. See docs/17_attachment_upload_r2_spec.md.
    /// NOTE: clients also populate `attachments[i].attachment_id`. `attachment_ids`
    /// is kept for spec compatibility but the per-message validation actually
    /// iterates `attachments`, which carries richer metadata.
    #[allow(dead_code)]
    #[serde(default)]
    attachment_ids: Option<Vec<Uuid>>,
    /// Client-side encrypted metadata per attachment (filename, mime, plaintext
    /// size, wrapped keys, etc.). Server stores as opaque blob in DB.
    #[serde(default)]
    attachments: Option<Vec<AttachmentRef>>,
}

#[derive(Deserialize)]
struct AttachmentRef {
    attachment_id: Uuid,
    metadata_encrypted: String,
    metadata_nonce: String,
}

#[derive(Deserialize)]
struct CreateAttachmentIntentRequest {
    sender_did: Option<String>,
    draft_id: Option<String>,
    ciphertext_size_bytes: Option<i64>,
}

#[derive(Serialize)]
struct CreateAttachmentIntentResponse {
    attachment_id: Uuid,
    upload_url: String,
    upload_method: String,
    upload_expires_at: String,
    required_headers: serde_json::Value,
    max_ciphertext_size_bytes: i64,
}

#[derive(Deserialize)]
struct CompleteAttachmentRequest {
    ciphertext_size_bytes: Option<i64>,
}

#[derive(Serialize)]
struct CompleteAttachmentResponse {
    attachment_id: Uuid,
    status: String,
}

#[derive(Serialize)]
struct MessageAttachmentSummary {
    attachment_id: Uuid,
    metadata_encrypted: String,
    metadata_nonce: String,
    ciphertext_size_bytes: i64,
}

#[derive(Serialize)]
struct ListMessageAttachmentsResponse {
    attachments: Vec<MessageAttachmentSummary>,
}

#[derive(Serialize)]
struct AttachmentDownloadUrlResponse {
    download_url: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct Envelope {
    encrypted_content: Option<String>,
    encrypted_key: Option<String>,
    nonce: Option<String>,
    signature: Option<String>,
    metadata: Option<EnvelopeMetadata>,
}

#[derive(Deserialize)]
struct EnvelopeMetadata {
    subject_encrypted: Option<String>,
    thread_id: Option<Uuid>,
    content_type: Option<String>,
    has_attachments: Option<bool>,
    /// Phase 4.4c executor-origin marker. When present, the server
    /// evaluator skips this delivery so that an auto-reply cannot
    /// trigger another auto-reply. Value is a free-form tag
    /// ("client_protocol_v1", "daemon_protocol_v1", ...); the server
    /// only checks for presence. See docs/25c §3.1.
    #[serde(default)]
    auto_reply_origin: Option<String>,
}

#[derive(Serialize)]
struct SendMessageResponse {
    message_id: Uuid,
    status: String,
}

#[derive(Serialize)]
struct MessageIndexEntryResponse {
    id: Uuid,
    sender_did: String,
    sender_label: Option<String>,
    recipient_did: String,
    recipient_label: Option<String>,
    thread_id: Option<Uuid>,
    subject_encrypted: String,
    // SECURITY: storage_ref is intentionally NOT exposed in API responses.
    // It contains backend-internal information (storage scheme, locator).
    // Clients fetch message content via GET /messages/{id}/content which only
    // requires the public message id.
    status: String,
    priority: String,
    ai_category: Option<String>,
    created_at: String,
    trust_score: f32,
    folder: String,
    starred: bool,
    /// Phase 4.4b cached evaluator action (see docs/25b). `None`
    /// when the evaluator has not run for this row (pre-4.4b or
    /// `AGENT_INBOX_AUTO_REPLY_EVALUATOR=off`).
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_reply_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_reply_reason: Option<String>,
    /// Phase 4.4c executor idempotency snapshot. `None` until the
    /// client (Standard mode) or daemon (Isolated mode) marks the reply as sent via
    /// PATCH /messages/:id/auto-reply-sent. See docs/25c §3.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_reply_sent_at: Option<String>,
}

#[derive(Serialize)]
struct MessageListResponse {
    messages: Vec<MessageIndexEntryResponse>,
    total: usize,
    page: u32,
    per_page: u32,
}

#[derive(Deserialize)]
struct MessageListQuery {
    agent_did: Option<String>,
    folder: Option<String>,
    status: Option<String>,
    priority: Option<String>,
    // When set, return only the messages that belong to this thread
    // (used by the conversation view in the reader pane).
    thread_id: Option<String>,
    page: Option<u32>,
    per_page: Option<u32>,
    // Phase 4.4c+ (docs/25c-a §4.1). Isolated mode executor sets this to
    // restrict the list to messages the server evaluator tagged
    // with an actionable decision that hasn't been dispatched yet.
    // Serialised as "1" / "true" / "0" by the gateway.
    auto_reply_pending: Option<String>,
}

#[derive(Deserialize)]
struct UpdateMessageStatusRequest {
    status: Option<String>,
}

#[derive(Serialize)]
struct UpdateMessageStatusResponse {
    id: Uuid,
    status: String,
}

#[derive(Deserialize)]
struct UpdateMessageFlagsRequest {
    folder: Option<String>,
    starred: Option<bool>,
}

#[derive(Serialize)]
struct UpdateMessageFlagsResponse {
    id: Uuid,
    folder: String,
    starred: bool,
}

/// Phase 4.4c auto-reply executor idempotency endpoint. Clients POST
/// the reply through the normal send path and then PATCH this to flip
/// the message_index row's `auto_reply_sent_at` column, preventing
/// duplicate sends on refresh / multi-tab. See docs/25c §5.2.
#[derive(Deserialize, Default)]
struct MarkAutoReplySentRequest {
    /// Optional ID of the reply message that was just sent. Not
    /// validated server-side (the sender can't tamper with themselves
    /// in any useful way) — it lands verbatim in the audit event so
    /// investigators can correlate the two rows.
    #[serde(default)]
    reply_message_id: Option<Uuid>,
    /// Which executor dispatched the reply — `"client_protocol_v1"`
    /// for Standard mode (browser, default when absent) or
    /// `"daemon_protocol_v1"` for Isolated mode (gateway). Echoed into the
    /// audit event so investigators can tell the two paths apart.
    /// See docs/25c-a §4.2.
    #[serde(default)]
    executor_mode: Option<String>,
}

#[derive(Serialize)]
struct MarkAutoReplySentResponse {
    id: Uuid,
    auto_reply_sent_at: String,
}

#[derive(Serialize)]
struct MessageContentResponse {
    encrypted_content: String,
    encrypted_key: String,
    nonce: String,
    // Sender/recipient DIDs and the encrypted subject are also
    // surfaced here so the compose page can prefill a reply's
    // recipient and subject from a single fetch.
    sender_did: String,
    recipient_did: String,
    subject_encrypted: String,
    // thread_id is exposed so replies can continue the original
    // conversation instead of starting a new thread each hop.
    thread_id: Option<Uuid>,
    // content_type round-trips through BYOS so A2A clients can
    // dispatch on MIME without re-parsing the envelope metadata.
    // Omitted from the wire when absent to keep the response
    // backward compatible for clients that don't know about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

#[derive(Serialize)]
struct WsEventData {
    message_id: String,
    agent_did: String,
    sender_did: String,
    subject_encrypted: String,
    priority: String,
    timestamp: String,
}

#[derive(Serialize)]
struct WsEvent {
    event: String,
    data: WsEventData,
}

fn jwt_secret() -> Result<String, &'static str> {
    let secret = std::env::var("JWT_SECRET").map_err(|_| "missing_jwt_secret")?;
    if secret.len() < 32 {
        return Err("jwt_secret_too_short");
    }
    Ok(secret)
}

fn jwt_issuer() -> String {
    std::env::var("JWT_ISSUER").unwrap_or_else(|_| JWT_ISSUER_DEFAULT.to_string())
}

fn jwt_audience() -> String {
    std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| JWT_AUDIENCE_DEFAULT.to_string())
}

fn is_production_env() -> bool {
    std::env::var("NODE_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

fn parse_bool_env(var_name: &str, default: bool) -> bool {
    std::env::var(var_name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn database_required() -> bool {
    is_production_env() || parse_bool_env("AGENT_INBOX_DATABASE_REQUIRED", false)
}

fn database_max_connections() -> u32 {
    std::env::var("DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DB_MAX_CONNECTIONS_DEFAULT)
}

pub fn validate_runtime_config() -> Result<(), String> {
    jwt_secret().map_err(|reason| match reason {
        "missing_jwt_secret" => "JWT_SECRET is required".to_string(),
        "jwt_secret_too_short" => "JWT_SECRET must be at least 32 characters".to_string(),
        _ => "JWT runtime configuration is invalid".to_string(),
    })?;
    if is_production_env() && !world_verify_enabled() {
        return Err(
            "AGENT_INBOX_WORLD_VERIFY_ENABLED must be true when NODE_ENV=production".to_string(),
        );
    }
    // SECURITY: Refuse to start if dev bearer bypass is configured in production
    if is_production_env()
        && std::env::var("AGENT_INBOX_ALLOW_DEV_BEARER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        return Err(
            "AGENT_INBOX_ALLOW_DEV_BEARER must not be enabled when NODE_ENV=production".to_string(),
        );
    }
    // SECURITY: Refuse to start if CSRF check is disabled in production
    if is_production_env()
        && std::env::var("AGENT_INBOX_DISABLE_CSRF_CHECK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        return Err(
            "AGENT_INBOX_DISABLE_CSRF_CHECK must not be enabled when NODE_ENV=production"
                .to_string(),
        );
    }
    // SECURITY: Refuse to start if mock verify is configured in production
    if is_production_env()
        && std::env::var("AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        return Err(
            "AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK must not be enabled when NODE_ENV=production"
                .to_string(),
        );
    }
    // SECURITY: Refuse to start if the S3 HEAD bypass is configured in
    // production. This flag lets DB integration tests exercise the
    // attachment-linking SQL without spinning up a real R2/MinIO.
    if is_production_env()
        && std::env::var("AGENT_INBOX_ALLOW_SKIP_S3_HEAD_IN_TESTS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        return Err(
            "AGENT_INBOX_ALLOW_SKIP_S3_HEAD_IN_TESTS must not be enabled when NODE_ENV=production"
                .to_string(),
        );
    }
    if database_required() && std::env::var("DATABASE_URL").is_err() {
        return Err("DATABASE_URL is required when AGENT_INBOX_DATABASE_REQUIRED=true".to_string());
    }
    // SECURITY: In production the JWS `aud` and DPoP `htu` bindings must be
    // derived from a fixed, operator-set URL — never from the request `Host`
    // / `X-Forwarded-Proto` headers, which a caller controls. Refuse to start
    // if it isn't set so we can't silently fall back to header-derived
    // expectations (see `expected_api_url`).
    if is_production_env() && std::env::var("AGENT_INBOX_PUBLIC_API_URL").is_err() {
        return Err("AGENT_INBOX_PUBLIC_API_URL is required when NODE_ENV=production".to_string());
    }
    Ok(())
}

pub async fn initialize_database_if_configured() -> Result<bool, String> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(value) => value,
        Err(_) => {
            if database_required() {
                return Err("DATABASE_URL is required in production or when AGENT_INBOX_DATABASE_REQUIRED=true".to_string());
            }
            return Ok(false);
        }
    };

    let pool = PgPoolOptions::new()
        .max_connections(database_max_connections())
        .acquire_timeout(Duration::from_secs(DB_CONNECT_TIMEOUT_SECS))
        .connect(&database_url)
        .await
        .map_err(|error| format!("failed to connect to DATABASE_URL: {error}"))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|error| format!("failed to run database migrations: {error}"))?;

    pool.close().await;
    Ok(true)
}

fn issue_session_jwt(
    sub: &str,
    wid: &str,
    verification_level: &str,
    ttl_seconds: i64,
) -> Result<IssuedSession, &'static str> {
    let now = Utc::now().timestamp();
    let jwt_id = Uuid::new_v4().to_string();
    let claims = TokenClaims {
        iss: jwt_issuer(),
        aud: jwt_audience(),
        sub: sub.to_string(),
        wid: wid.to_string(),
        verification_level: verification_level.to_string(),
        iat: now,
        exp: now + ttl_seconds,
        jti: Some(jwt_id.clone()),
    };

    let secret = jwt_secret()?;
    let token = encode(
        &JwtHeader::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| "invalid_token")?;

    Ok(IssuedSession {
        token,
        jwt_id,
        expires_at_unix: claims.exp,
    })
}

pub fn issue_dev_jwt(sub: &str, wid: &str, verification_level: &str, ttl_seconds: i64) -> String {
    issue_session_jwt(sub, wid, verification_level, ttl_seconds)
        .expect("JWT_SECRET must be configured before issuing tokens")
        .token
}

/// Test-only helper: issue a dev JWT and return both the token and its jti so
/// callers can insert a matching row into the `sessions` table when exercising
/// DB-backed code paths.
pub fn issue_dev_session(
    sub: &str,
    wid: &str,
    verification_level: &str,
    ttl_seconds: i64,
) -> (String, String, i64) {
    let session = issue_session_jwt(sub, wid, verification_level, ttl_seconds)
        .expect("JWT_SECRET must be configured before issuing tokens");
    (session.token, session.jwt_id, session.expires_at_unix)
}

fn verify_dev_jwt(token: &str) -> Result<TokenClaims, &'static str> {
    let secret = jwt_secret()?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[jwt_issuer()]);
    validation.set_audience(&[jwt_audience()]);
    validation.validate_exp = true;
    validation.leeway = 0;

    decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|error| match error.kind() {
        JwtErrorKind::ExpiredSignature => "expired_token",
        _ => "invalid_token",
    })
}

#[allow(dead_code)]
fn is_valid_verification_level(level: &str) -> bool {
    level == "orb"
}

fn mask_identifier(raw: &str) -> String {
    if raw.is_empty() {
        return "none".to_string();
    }
    if raw.len() <= 10 {
        return "***".to_string();
    }
    let start = &raw[..6];
    let end = &raw[raw.len() - 4..];
    format!("{start}...{end}")
}

fn audit_auth_verify_event(
    status: u16,
    outcome: &str,
    reason: &str,
    action: &str,
    verification_level: &str,
    nullifier_hash: &str,
) {
    let payload = serde_json::json!({
        "event": "auth_verify",
        "timestamp": Utc::now().to_rfc3339(),
        "status": status,
        "outcome": outcome,
        "reason": reason,
        "action": action,
        "verification_level": verification_level,
        "nullifier_hash_masked": mask_identifier(nullifier_hash),
    });
    println!("{payload}");
}

fn world_verify_enabled() -> bool {
    std::env::var("AGENT_INBOX_WORLD_VERIFY_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn allow_world_verify_mock() -> bool {
    if is_production_env() {
        return false;
    }
    std::env::var("AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn expected_world_action() -> String {
    std::env::var("WORLD_ID_ACTION").unwrap_or_else(|_| "login".to_string())
}

fn expected_world_signal() -> String {
    std::env::var("WORLD_ID_SIGNAL").unwrap_or_default()
}

fn world_verify_base_url() -> String {
    std::env::var("WORLD_ID_VERIFY_BASE_URL")
        .unwrap_or_else(|_| WORLD_VERIFY_BASE_URL_DEFAULT.to_string())
}

/// Forward raw IDKit result to World ID v4 verify endpoint.
async fn verify_world_id_proof(
    rp_id: &str,
    payload: &serde_json::Value,
) -> Result<WorldVerifyResult, (StatusCode, Json<ErrorResponse>)> {
    let endpoint = format!(
        "{}/api/v4/verify/{}",
        world_verify_base_url().trim_end_matches('/'),
        rp_id
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(WORLD_VERIFY_TIMEOUT_SECS))
        .user_agent("NexusInbox/0.1.0")
        .build()
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "world_verify_error".to_string(),
                    message: "failed to initialize world verification client".to_string(),
                }),
            )
        })?;

    let response = client
        .post(endpoint)
        .header("Accept", "application/json")
        .json(payload)
        .send()
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "world_verify_unavailable".to_string(),
                    message: "failed to reach World verification API".to_string(),
                }),
            )
        })?;

    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_else(|_| "".to_string());
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "world_verify_failed".to_string(),
                message: if detail.is_empty() {
                    format!("world verification failed with HTTP {}", status.as_u16())
                } else {
                    format!("world verification failed: {detail}")
                },
            }),
        ));
    }

    response.json::<WorldVerifyResult>().await.map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: "world_verify_error".to_string(),
                message: "failed to parse World verification response".to_string(),
            }),
        )
    })
}

fn validation_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(ErrorResponse {
            error: "validation_error".to_string(),
            message: message.to_string(),
        }),
    )
}

fn internal_server_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: "server_error".to_string(),
            message: message.to_string(),
        }),
    )
}

/// Internal-error helper that keeps failure detail OUT of the HTTP response.
///
/// `public_msg` is the only thing the client sees; `detail` (the underlying
/// sqlx / reqwest / serde error) goes to the server log alone. Raw sqlx
/// error strings embed query text, table and column names, and connection
/// context — echoing them in a 500 body hands schema recon to any caller
/// (audit 2026-06-11, finding M2). Prefer this over
/// `internal_error("...", e)` everywhere a source error
/// is attached.
fn internal_error(
    public_msg: &str,
    detail: impl std::fmt::Display,
) -> (StatusCode, Json<ErrorResponse>) {
    error!("{public_msg}: {detail}");
    internal_server_error(public_msg)
}

fn database_required_but_unavailable_error() -> (StatusCode, Json<ErrorResponse>) {
    internal_server_error("database is required but unavailable")
}

fn conflict_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::CONFLICT,
        Json(ErrorResponse {
            error: "conflict".to_string(),
            message: message.to_string(),
        }),
    )
}

fn world_id_hash_from_nullifier(nullifier_hash: &str) -> String {
    let digest = Sha256::digest(nullifier_hash.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn derive_user_id_from_nullifier(nullifier_hash: &str) -> Uuid {
    let digest = Sha256::digest(nullifier_hash.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn parse_user_uuid(user_id: &str) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    Uuid::parse_str(user_id).map_err(|_| unauthorized_error("invalid session subject"))
}

fn forbidden_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "forbidden".to_string(),
            message: message.to_string(),
        }),
    )
}

fn not_found_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "not_found".to_string(),
            message: message.to_string(),
        }),
    )
}

fn decode_base64url(raw: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(raw).ok()
}

fn is_valid_public_key_material(raw: &str) -> bool {
    decode_base64url(raw)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}

fn derive_did_from_public_key(public_key: &str) -> Option<String> {
    let key_bytes = decode_base64url(public_key)?;
    if key_bytes.len() != 32 {
        return None;
    }

    // did:key for Ed25519 public keys: multicodec 0xed01 + 32-byte public key, base58btc multibase.
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xed);
    prefixed.push(0x01);
    prefixed.extend_from_slice(&key_bytes);

    let fingerprint = bs58::encode(prefixed).into_string();
    Some(format!("did:key:z{fingerprint}"))
}

fn unauthorized_error(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "unauthorized".to_string(),
            message: message.to_string(),
        }),
    )
}

fn is_valid_wrapped_encrypted_key_format(encrypted_key: &str) -> bool {
    if let Some(raw) = encrypted_key.strip_prefix("x25519v1:") {
        let mut parts = raw.split(':');
        let ephemeral = parts.next().unwrap_or_default();
        let salt = parts.next().unwrap_or_default();
        let iv = parts.next().unwrap_or_default();
        let ciphertext = parts.next().unwrap_or_default();
        if parts.next().is_some() {
            return false;
        }
        let ephemeral_bytes = match decode_base64url(ephemeral) {
            Some(bytes) => bytes,
            None => return false,
        };
        let salt_bytes = match decode_base64url(salt) {
            Some(bytes) => bytes,
            None => return false,
        };
        let iv_bytes = match decode_base64url(iv) {
            Some(bytes) => bytes,
            None => return false,
        };
        let ciphertext_bytes = match decode_base64url(ciphertext) {
            Some(bytes) => bytes,
            None => return false,
        };
        return ephemeral_bytes.len() == 32
            && salt_bytes.len() == 16
            && iv_bytes.len() == 12
            && ciphertext_bytes.len() >= 16;
    }
    false
}

fn parse_did_policy_env(var_name: &str) -> HashSet<String> {
    std::env::var(var_name)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default()
}

fn is_valid_aid(value: &str) -> bool {
    value.starts_with("aid:ai:")
        && value.len() > "aid:ai:".len()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '-' || c == '_')
}

fn validate_recipient_reference(
    value: &str,
    field_name: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if value.starts_with("aid:ai:") {
        if is_valid_aid(value) {
            Ok(())
        } else {
            Err(validation_error(&format!(
                "{field_name} must be a valid aid:ai:... identifier",
            )))
        }
    } else {
        validate_did(value, field_name)
    }
}

fn resolve_recipient_in_memory(state: &AppState, recipient: &str) -> Option<String> {
    let lock = state
        .agents_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for agents in lock.values() {
        for agent in agents {
            if agent.did == recipient || agent.aid == recipient {
                return Some(agent.did.clone());
            }
        }
    }
    None
}

fn resolve_recipient_record_in_memory(
    state: &AppState,
    recipient: &str,
) -> Option<RecipientResolutionResponse> {
    let lock = state
        .agents_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for agents in lock.values() {
        for agent in agents {
            if agent.did == recipient || agent.aid == recipient {
                return Some(RecipientResolutionResponse {
                    input: recipient.to_string(),
                    aid: agent.aid.clone(),
                    did: agent.did.clone(),
                    label: Some(agent.label.clone()),
                    signing_public_key: agent.public_key.clone(),
                    encryption_public_key: agent.encryption_key.clone(),
                    // In-memory fallback path has no credential table
                    // to aggregate over — surface as 'unknown', which
                    // the Web UI treats as Standard mode for display.
                    key_holder: "unknown".to_string(),
                });
            }
        }
    }
    None
}

fn recipient_exists(state: &AppState, recipient_did: &str) -> bool {
    state
        .agents_by_user
        .lock()
        .unwrap()
        .values()
        .any(|agents| agents.iter().any(|agent| agent.did == recipient_did))
}

fn recipient_is_blocked_by_policy(state: &AppState, recipient_did: &str) -> bool {
    state.blocked_recipient_dids.contains(recipient_did)
}

fn recipient_owner_in_memory(state: &AppState, recipient_did: &str) -> Option<String> {
    let lock = state
        .agents_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for (user_id, agents) in lock.iter() {
        if agents.iter().any(|agent| agent.did == recipient_did) {
            return Some(user_id.clone());
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockDecision {
    Allow,
    SilentDrop,
    Stealth,
}

/// Apply hierarchical block rules from the recipient owner's block list.
/// L1 (l1_did)        — silent drop a specific sender DID (return 202, no persist)
/// L2 (l2_identity)   — ban a sender World ID entirely, return 404
/// L3 (l3_stealth)    — L2 + DID resolution stealth, return 404
fn evaluate_block_decision(
    state: &AppState,
    recipient_owner: &str,
    sender_did: &str,
    sender_world_id: &str,
) -> BlockDecision {
    let lock = state
        .blocks_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(entries) = lock.get(recipient_owner) else {
        return BlockDecision::Allow;
    };
    decide_from_entries(entries, sender_did, sender_world_id)
}

fn decide_from_entries(
    entries: &[BlockEntry],
    sender_did: &str,
    sender_world_id: &str,
) -> BlockDecision {
    for entry in entries {
        match entry.level.as_str() {
            "l2_identity" | "l3_stealth" => {
                if let Some(target) = entry.target_world_id.as_deref() {
                    if !target.is_empty() && target == sender_world_id {
                        return BlockDecision::Stealth;
                    }
                }
            }
            "l1_did" => {
                if let Some(target) = entry.target_did.as_deref() {
                    if !target.is_empty() && target == sender_did {
                        return BlockDecision::SilentDrop;
                    }
                }
            }
            _ => {}
        }
    }
    BlockDecision::Allow
}

/// DB-backed variant of [`evaluate_block_decision`]. Runs one SELECT against
/// the `blocks` table, restricted to the recipient owner, then applies the
/// same L1/L2/L3 priority as the in-memory path. L2/L3 take precedence over
/// L1 (so a Stealth return always wins).
async fn evaluate_block_decision_db(
    pool: &PgPool,
    recipient_owner: Uuid,
    sender_did: &str,
    sender_world_id: &str,
) -> Result<BlockDecision, String> {
    let rows = sqlx::query(
        r#"
        SELECT level, target_did, target_world_id
        FROM blocks
        WHERE owner_user_id = $1
          AND (
            (level = 'l1_did' AND target_did = $2)
            OR (level IN ('l2_identity', 'l3_stealth') AND target_world_id = $3)
          )
        "#,
    )
    .bind(recipient_owner)
    .bind(sender_did)
    .bind(sender_world_id)
    .fetch_all(pool)
    .await
    .map_err(|error| format!("failed to query blocks: {error}"))?;

    use sqlx::Row;
    let mut has_l1 = false;
    for row in rows {
        let level: String = row.get("level");
        match level.as_str() {
            "l2_identity" | "l3_stealth" => return Ok(BlockDecision::Stealth),
            "l1_did" => has_l1 = true,
            _ => {}
        }
    }
    Ok(if has_l1 {
        BlockDecision::SilentDrop
    } else {
        BlockDecision::Allow
    })
}

// NOTE: L3 stealth on listing endpoints is not needed yet — list_agents only
// returns the caller's own agents, so an L3 ban is enforced by send_message's
// 404 path. A public DID resolver would need a stealth filter here.

fn sender_is_low_trust(state: &AppState, sender_did: &str) -> bool {
    state.low_trust_sender_dids.contains(sender_did)
}

/// Count globally how many users have an L1/L2/L3 block targeting this sender.
/// L1 matches by `target_did`; L2/L3 match by `target_world_id`. Used as an
/// abuse-history signal in the trust score.
fn count_blocks_against_sender(state: &AppState, sender_did: &str, sender_world_id: &str) -> u32 {
    let lock = state
        .blocks_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut total: u32 = 0;
    for entries in lock.values() {
        for entry in entries {
            let hit = match entry.level.as_str() {
                "l1_did" => entry.target_did.as_deref() == Some(sender_did),
                "l2_identity" | "l3_stealth" => {
                    !sender_world_id.is_empty()
                        && entry.target_world_id.as_deref() == Some(sender_world_id)
                }
                _ => false,
            };
            if hit {
                total = total.saturating_add(1);
            }
        }
    }
    total
}

/// Record the first time we observe a given World ID, so the in-memory path can
/// estimate account_age for the trust-score Phase 2 signals. Idempotent: only
/// the earliest timestamp is kept. The DB-backed path uses `users.created_at`
/// directly and ignores this map.
fn record_first_seen(state: &AppState, sender_world_id: &str, now: i64) {
    let mut lock = state
        .first_seen_at
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    lock.entry(sender_world_id.to_string()).or_insert(now);
}

/// Days since we first observed `sender_world_id`. Returns 0 if unseen.
fn account_age_days_in_memory(state: &AppState, sender_world_id: &str, now: i64) -> u64 {
    let lock = state
        .first_seen_at
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match lock.get(sender_world_id) {
        Some(first) if now > *first => ((now - *first) / 86_400) as u64,
        _ => 0,
    }
}

/// Read/archived/total counts for messages this sender previously sent.
/// In-memory only. Used by the Phase 2 trust-score delivery-history signal.
fn delivery_history_in_memory(
    state: &AppState,
    sender_user_id: &str,
    sender_did: &str,
) -> (u32, u32, u32) {
    let lock = state
        .messages_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(records) = lock.get(sender_user_id) else {
        return (0, 0, 0);
    };
    let mut read = 0u32;
    let mut archived = 0u32;
    let mut total = 0u32;
    for r in records {
        if r.sender_did != sender_did {
            continue;
        }
        total += 1;
        match r.status.as_str() {
            "read" => read += 1,
            "archived" => archived += 1,
            _ => {}
        }
    }
    (read, archived, total)
}

/// Dynamic trust score in [0.0, 1.0]. Weighted sum of:
///   - base reputation (0.40)
///   - verification level: orb +0.40 (the service only accepts Orb;
///     any other level contributes 0.0 and represents legacy data)
///   - blocks against sender: -0.15 each (capped)
///   - account_age (Phase 2): >=30d +0.10, >=7d +0.05
///   - delivery history (Phase 2, sample >=5):
///     archived ratio >=0.5 -0.30, >=0.3 -0.15
///     read ratio >=0.7 +0.05
///   - explicit deny-list (env override): forced 0.0
fn compute_trust_score(
    state: &AppState,
    sender_user_id: &str,
    sender_did: &str,
    sender_world_id: &str,
    verification_level: &str,
) -> f32 {
    let blocks = count_blocks_against_sender(state, sender_did, sender_world_id);
    compute_trust_score_with_blocks(
        state,
        sender_user_id,
        sender_did,
        sender_world_id,
        verification_level,
        blocks,
    )
}

/// Variant that accepts a precomputed blocks count. Used by the DB-backed
/// send path, which performs one aggregated SQL count instead of locking the
/// in-memory map.
fn compute_trust_score_with_blocks(
    state: &AppState,
    sender_user_id: &str,
    sender_did: &str,
    sender_world_id: &str,
    verification_level: &str,
    blocks: u32,
) -> f32 {
    if sender_is_low_trust(state, sender_did) {
        return 0.0;
    }
    let mut score: f32 = 0.40;
    // Only Orb-level World ID verification is accepted at login, so any
    // non-orb value here reflects stale session data or a test fixture and
    // earns no bonus.
    score += if verification_level == "orb" {
        0.40
    } else {
        0.0
    };
    let penalty = (blocks as f32 * 0.15).min(0.60);
    score -= penalty;

    // Phase 2: account age bonus (in-memory fallback).
    let now = Utc::now().timestamp();
    let age_days = account_age_days_in_memory(state, sender_world_id, now);
    if age_days >= 30 {
        score += 0.10;
    } else if age_days >= 7 {
        score += 0.05;
    }

    // Phase 2: delivery history. Sample threshold of 5 keeps existing tests
    // (which send <=3 messages) unaffected.
    let (read, archived, total) = delivery_history_in_memory(state, sender_user_id, sender_did);
    if total >= 5 {
        let archived_ratio = archived as f32 / total as f32;
        let read_ratio = read as f32 / total as f32;
        if archived_ratio >= 0.5 {
            score -= 0.30;
        } else if archived_ratio >= 0.3 {
            score -= 0.15;
        }
        if read_ratio >= 0.7 {
            score += 0.05;
        }
    }

    score.clamp(0.0, 1.0)
}

/// Maximum messages a single sender DID may post in a rolling window before
/// Layer 1 flags subsequent traffic as a spam burst.
const SPAM_BURST_WINDOW_SECS: i64 = 60;
const SPAM_BURST_THRESHOLD: u32 = 10;

/// Layer 1 spam filter — fast, deterministic checks that run on every send.
/// Returns the AI category label when the message is flagged, or None when
/// the message looks clean. Designed to be cheap (env-set lookup + counter).
fn apply_layer1_spam_filter(state: &AppState, sender_did: &str) -> Option<&'static str> {
    if state.spam_sender_dids.contains(sender_did) {
        return Some("spam_denylist");
    }

    let now = Utc::now().timestamp();
    let mut lock = state
        .sender_burst_counts
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let entry = lock.entry(sender_did.to_string()).or_insert((now, 0));
    if now - entry.0 >= SPAM_BURST_WINDOW_SECS {
        entry.0 = now;
        entry.1 = 0;
    }
    entry.1 = entry.1.saturating_add(1);
    if entry.1 > SPAM_BURST_THRESHOLD {
        return Some("spam_burst");
    }
    None
}

// =============================================================================
// FUTURE IMPROVEMENT (post-release): Layer 2 LLM-based spam filter
// =============================================================================
// The current Layer 2 hook is intentionally a no-op stub. A full implementation
// would forward envelope METADATA (not plaintext — message bodies are E2E
// encrypted and unreadable to the server) to a separate Python (FastAPI) filter
// service in `services/filter/` for an LLM verdict.
//
// Decision deferred for Phase 1 because:
//   1. E2E encryption prevents real content inspection on the server side, so
//      Layer 2 can only score sender DID patterns, send frequency, envelope
//      size anomalies, and trust score signals — much of which Layer 1 already
//      handles.
//   2. The FastAPI filter service, LLM provider integration, prompt design,
//      timeout/fallback policy, and per-tenant rate limits all need design.
//
// When revisiting:
//   - Recommended provider: Groq Llama 3.1 8B (≈$0.00003 / verdict, sub-200ms
//     latency, 14.4k RPM free tier). At trust_score < 0.5 trigger rate, even
//     1M monthly messages cost roughly $1.50.
//   - Alternative (privacy-first): bundle a local llama.cpp model inside the
//     filter service so no metadata leaves the deployment.
//   - Wire the call here, behind AGENT_INBOX_FILTER_SERVICE_URL, with a hard
//     timeout (1–2s) and fail-open (return None on error so trust-score
//     routing still applies).
//   - For real plaintext-aware filtering, do it CLIENT-SIDE after decryption,
//     not here. That belongs in apps/web or apps/desktop.
//
// Issue tag: future/layer2-llm-filter
// =============================================================================

/// Layer 2 hook — currently a no-op stub. Returns None so the routing decision
/// falls back to the trust-score table. See the FUTURE IMPROVEMENT block above
/// for the full design notes.
fn apply_layer2_spam_filter(_sender_did: &str, _trust_score: f32) -> Option<&'static str> {
    if std::env::var("AGENT_INBOX_FILTER_SERVICE_URL").is_err() {
        return None;
    }
    // Stub: even when the env var is set, the hook returns None until the
    // filter service is implemented (see FUTURE IMPROVEMENT block above).
    None
}

/// Map a trust score to delivery routing. Mirrors the table in
/// docs/05_security_filtering.md.
fn route_for_trust_score(score: f32) -> (&'static str, &'static str) {
    if score < 0.20 {
        ("pending_approval", "background")
    } else if score > 0.80 {
        // Reserved for accounts with additional positive signals beyond
        // baseline orb verification (e.g. future account_age / mutual comms).
        ("delivered", "high")
    } else {
        ("delivered", "normal")
    }
}

async fn recipient_exists_in_db(pool: &PgPool, recipient_did: &str) -> Result<bool, String> {
    // agent_identity_keys is the canonical source of active dids (survives
    // key rotation via `activate_agent_credential`). agents.did is the
    // *creation-time* did and goes stale after the first rotation, so we
    // can't rely on it alone. Accept either: agent_identity_keys with an
    // active row, OR the agents table (covers creation-time-only rows and
    // any backcompat path where identity_keys wasn't populated).
    let row = sqlx::query(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM agent_identity_keys WHERE did = $1 AND status = 'active'
            UNION ALL
            SELECT 1 FROM agents WHERE did = $1
        ) AS exists
        "#,
    )
    .bind(recipient_did)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("failed to query recipient existence: {error}"))?;
    Ok(row.get::<bool, _>("exists"))
}

async fn resolve_recipient_in_db(pool: &PgPool, recipient: &str) -> Result<Option<String>, String> {
    if recipient.starts_with("aid:ai:") {
        let row = sqlx::query(
            r#"
            SELECT aik.did
            FROM agent_identities ai
            JOIN agent_identity_keys aik ON aik.aid = ai.aid
            WHERE ai.aid = $1
              AND aik.status = 'active'
            ORDER BY aik.activated_at DESC
            LIMIT 1
            "#,
        )
        .bind(recipient)
        .fetch_optional(pool)
        .await
        .map_err(|error| format!("failed to resolve recipient aid: {error}"))?;
        return Ok(row.map(|row| row.get("did")));
    }

    if recipient_exists_in_db(pool, recipient).await? {
        Ok(Some(recipient.to_string()))
    } else {
        Ok(None)
    }
}

async fn resolve_recipient_record_in_db(
    pool: &PgPool,
    recipient: &str,
) -> Result<Option<RecipientResolutionResponse>, String> {
    let row = if recipient.starts_with("aid:ai:") {
        sqlx::query(
            r#"
            SELECT
              ai.aid,
              aik.did,
              a.label,
              aik.signing_public_key,
              aik.encryption_public_key
            FROM agent_identities ai
            JOIN agent_identity_keys aik ON aik.aid = ai.aid
            JOIN agents a ON a.id = ai.agent_id
            WHERE ai.aid = $1
              AND aik.status = 'active'
            ORDER BY aik.activated_at DESC
            LIMIT 1
            "#,
        )
        .bind(recipient)
        .fetch_optional(pool)
        .await
        .map_err(|error| format!("failed to resolve recipient aid: {error}"))?
    } else {
        sqlx::query(
            r#"
            SELECT
              ai.aid,
              aik.did,
              a.label,
              aik.signing_public_key,
              aik.encryption_public_key
            FROM agent_identity_keys aik
            JOIN agent_identities ai ON ai.aid = aik.aid
            JOIN agents a ON a.id = ai.agent_id
            WHERE aik.did = $1
              AND aik.status = 'active'
            LIMIT 1
            "#,
        )
        .bind(recipient)
        .fetch_optional(pool)
        .await
        .map_err(|error| format!("failed to resolve recipient did: {error}"))?
    };

    let Some(row) = row else {
        return Ok(None);
    };

    let aid: String = row.get("aid");
    let key_holder = aggregate_recipient_key_holder_in_db(pool, &aid).await?;

    Ok(Some(RecipientResolutionResponse {
        input: recipient.to_string(),
        aid,
        did: row.get("did"),
        label: row.get("label"),
        signing_public_key: row.get("signing_public_key"),
        encryption_public_key: row.get("encryption_public_key"),
        key_holder,
    }))
}

/// Collapse the recipient agent's active credentials into a single
/// `key_holder` hint for the compose-time UI (docs/21 §4.4).
///
/// Priority order errs on the side of NOT warning falsely:
///
///   1. If any active credential is `web_keystore`, the recipient can
///      read on the web — return `web_keystore` and show no hint.
///   2. Else if at least one is `unknown`, we can't rule out a
///      web-readable path; fall back to `unknown` so the Web UI
///      treats it as Standard mode.
///   3. Else every active credential is `signer_daemon` — return
///      `signer_daemon`, the compose screen shows the Daemon-isolated
///      warning.
///
/// Executed as a single small query so resolve_recipient stays fast
/// on the hot path.
async fn aggregate_recipient_key_holder_in_db(pool: &PgPool, aid: &str) -> Result<String, String> {
    let row = sqlx::query(
        r#"
        SELECT
          COUNT(*) FILTER (WHERE key_holder = 'web_keystore')   AS web_count,
          COUNT(*) FILTER (WHERE key_holder = 'unknown')        AS unknown_count,
          COUNT(*) FILTER (WHERE key_holder = 'signer_daemon')  AS daemon_count
        FROM agent_credentials
        WHERE aid = $1 AND status = 'active'
        "#,
    )
    .bind(aid)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("failed to aggregate recipient key_holder: {error}"))?;

    let web: i64 = row.get("web_count");
    let unknown: i64 = row.get("unknown_count");
    let daemon: i64 = row.get("daemon_count");

    if web > 0 {
        Ok("web_keystore".to_string())
    } else if unknown > 0 || (web == 0 && daemon == 0) {
        // No credentials at all also lands here (recipient agent
        // exists but has never been activated). Treat as unknown so
        // we don't falsely warn about daemon-isolation.
        Ok("unknown".to_string())
    } else {
        Ok("signer_daemon".to_string())
    }
}

async fn agent_owned_by_user_in_db(
    pool: &PgPool,
    user_id: Uuid,
    sender_did: &str,
) -> Result<Option<Agent>, String> {
    let row = sqlx::query(
        r#"
        SELECT
          a.id::text AS id,
          ai.aid,
          aik.did,
          a.label,
          aik.signing_public_key AS public_key,
          aik.encryption_public_key AS encryption_key,
          a.is_active,
          a.auto_reply,
          a.unread_count,
          a.created_at::text AS created_at
        FROM agent_identities ai
        JOIN agent_identity_keys aik ON aik.aid = ai.aid
        JOIN agents a ON a.id = ai.agent_id
        WHERE ai.user_id = $1
          AND aik.did = $2
          AND aik.status = 'active'
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(sender_did)
    .fetch_optional(pool)
    .await
    .map_err(|error| format!("failed to query sender agent ownership: {error}"))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let id_text: String = row.get("id");
    let id = Uuid::parse_str(&id_text)
        .map_err(|error| format!("invalid agent id from database: {error}"))?;
    Ok(Some(Agent {
        id,
        aid: row.get("aid"),
        did: row.get("did"),
        label: row.get("label"),
        public_key: row.get("public_key"),
        encryption_key: row.get("encryption_key"),
        is_active: row.get("is_active"),
        auto_reply: row.get("auto_reply"),
        unread_count: row.get("unread_count"),
        created_at: row.get("created_at"),
    }))
}

fn storage_file_path(state: &AppState, user_id: &str, message_id: Uuid) -> PathBuf {
    state
        .storage_root
        .join(state.storage_backend.storage_subdir())
        .join(user_id)
        .join(format!("{message_id}.json"))
}

fn parse_storage_ref(storage_ref: &str) -> Option<StorageRef> {
    // New format: <scheme>:v1://<locator>
    if let Some((scheme_and_version, locator_raw)) = storage_ref.split_once("://") {
        if let Some((scheme, version)) = scheme_and_version.split_once(':') {
            if version != "v1" {
                return None;
            }
            let backend = StorageBackend::from_storage_ref_scheme(scheme)?;
            return Some(StorageRef {
                backend,
                locator: locator_raw.to_string(),
            });
        }
    }

    // Legacy format: <scheme>://<uuid>
    let (backend, message_id_raw) = storage_ref
        .strip_prefix("localfs://")
        .map(|rest| (StorageBackend::LocalFs, rest))
        .or_else(|| {
            storage_ref
                .strip_prefix("gdrive://")
                .map(|rest| (StorageBackend::GoogleDriveMock, rest))
        })?;
    Some(StorageRef {
        backend,
        locator: message_id_raw.to_string(),
    })
}

fn storage_ref_for_locator(storage_backend: StorageBackend, locator: &str) -> String {
    format!("{}:v1://{locator}", storage_backend.storage_ref_scheme())
}

fn path_from_storage_ref(state: &AppState, user_id: &str, storage_ref: &str) -> Option<PathBuf> {
    let parsed = parse_storage_ref(storage_ref)?;
    if matches!(
        parsed.backend,
        StorageBackend::GoogleDrive | StorageBackend::Ipfs | StorageBackend::S3
    ) {
        return None;
    }
    let message_id = Uuid::parse_str(&parsed.locator).ok()?;

    let base = state
        .storage_root
        .join(parsed.backend.storage_subdir())
        .join(user_id);
    let resolved = base.join(format!("{message_id}.json"));
    let canonical_base = base.canonicalize().ok()?;
    let canonical_resolved = resolved.canonicalize().ok()?;
    if !canonical_resolved.starts_with(&canonical_base) {
        return None;
    }
    Some(canonical_resolved)
}

fn audit_storage_event(
    event: &str,
    backend: StorageBackend,
    user_id: &str,
    message_id: Option<Uuid>,
    result: &str,
    reason: Option<&str>,
) {
    let payload = serde_json::json!({
        "event": event,
        "backend": match backend {
            StorageBackend::LocalFs => "localfs",
            StorageBackend::GoogleDrive => "gdrive",
            StorageBackend::GoogleDriveMock => "gdrive_mock",
            StorageBackend::Ipfs => "ipfs",
            StorageBackend::S3 => "s3",
        },
        "user_id": user_id,
        "message_id": message_id.map(|value| value.to_string()),
        "result": result,
        "reason": reason.unwrap_or(""),
        "timestamp": Utc::now().to_rfc3339(),
    });
    eprintln!("{payload}");
}

fn write_payload_atomically(storage_file: &PathBuf, encoded_payload: &str) -> Result<(), String> {
    let parent = storage_file
        .parent()
        .ok_or_else(|| "missing parent directory for storage file".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to prepare local storage directory: {error}"))?;

    let tmp_path =
        storage_file.with_extension(format!("tmp-{}-{}", std::process::id(), Uuid::new_v4()));

    {
        let mut tmp_file = fs::File::create(&tmp_path)
            .map_err(|error| format!("failed to create temp file: {error}"))?;
        tmp_file
            .write_all(encoded_payload.as_bytes())
            .map_err(|error| format!("failed to write temp file: {error}"))?;
        tmp_file
            .sync_all()
            .map_err(|error| format!("failed to sync temp file: {error}"))?;
    }

    fs::rename(&tmp_path, storage_file).map_err(|error| {
        let _ = fs::remove_file(&tmp_path);
        format!("failed to promote temp file: {error}")
    })?;

    Ok(())
}

fn gdrive_api_base_url() -> String {
    std::env::var("AGENT_INBOX_GDRIVE_API_BASE_URL")
        .unwrap_or_else(|_| "https://www.googleapis.com".to_string())
}

fn gdrive_oauth_base_url() -> String {
    std::env::var("AGENT_INBOX_GDRIVE_OAUTH_BASE_URL")
        .unwrap_or_else(|_| "https://oauth2.googleapis.com".to_string())
}

fn gdrive_access_token_from_env() -> Option<String> {
    std::env::var("AGENT_INBOX_GDRIVE_ACCESS_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Deserialize)]
struct GoogleDriveTokenResponse {
    access_token: Option<String>,
}

async fn refresh_gdrive_access_token(client: &Client) -> Result<Option<String>, String> {
    let client_id = std::env::var("AGENT_INBOX_GDRIVE_CLIENT_ID").ok();
    let client_secret = std::env::var("AGENT_INBOX_GDRIVE_CLIENT_SECRET").ok();
    let refresh_token = std::env::var("AGENT_INBOX_GDRIVE_REFRESH_TOKEN").ok();
    let (Some(client_id), Some(client_secret), Some(refresh_token)) =
        (client_id, client_secret, refresh_token)
    else {
        return Ok(None);
    };

    let token_url = format!("{}/token", gdrive_oauth_base_url().trim_end_matches('/'));
    let response = client
        .post(token_url)
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|error| format!("failed to refresh Google Drive token: {error}"))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let detail = response.text().await.unwrap_or_default();
        if detail.contains("invalid_grant") {
            return Err(
                "google drive token revoked or expired; re-authorization required".to_string(),
            );
        }
        return Err(format!(
            "google drive token refresh failed with HTTP {}",
            status
        ));
    }

    let payload: GoogleDriveTokenResponse = response
        .json()
        .await
        .map_err(|_| "failed to parse Google Drive token refresh response".to_string())?;
    Ok(payload
        .access_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

async fn gdrive_send_with_retry<F>(
    client: &Client,
    mut build_request: F,
) -> Result<reqwest::Response, String>
where
    F: FnMut(&str) -> reqwest::RequestBuilder,
{
    let mut token = gdrive_access_token_from_env().ok_or_else(|| {
        "google drive access token is missing; set AGENT_INBOX_GDRIVE_ACCESS_TOKEN".to_string()
    })?;

    let mut response = build_request(&token)
        .send()
        .await
        .map_err(|error| format!("google drive request failed: {error}"))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        if let Some(refreshed) = refresh_gdrive_access_token(client).await? {
            token = refreshed;
            response = build_request(&token)
                .send()
                .await
                .map_err(|error| format!("google drive request retry failed: {error}"))?;
        }
    }

    Ok(response)
}

async fn gdrive_create_file(
    client: &Client,
    message_id: Uuid,
    payload: &str,
) -> Result<String, String> {
    let create_url = format!(
        "{}/drive/v3/files?fields=id",
        gdrive_api_base_url().trim_end_matches('/')
    );
    let folder_id = std::env::var("AGENT_INBOX_GDRIVE_FOLDER_ID").ok();
    let metadata = if let Some(folder_id) = folder_id.filter(|value| !value.trim().is_empty()) {
        serde_json::json!({
            "name": format!("{message_id}.json"),
            "parents": [folder_id],
            "mimeType": "application/json"
        })
    } else {
        serde_json::json!({
            "name": format!("{message_id}.json"),
            "mimeType": "application/json"
        })
    };

    let create_response = gdrive_send_with_retry(client, |token| {
        client
            .post(&create_url)
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(metadata.to_string())
    })
    .await?;

    if !create_response.status().is_success() {
        let status = create_response.status().as_u16();
        let detail = create_response.text().await.unwrap_or_default();
        return Err(format!(
            "google drive file create failed with HTTP {}: {}",
            status, detail
        ));
    }

    let created: serde_json::Value = create_response
        .json()
        .await
        .map_err(|_| "failed to parse Google Drive create response".to_string())?;
    let file_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "google drive create response missing file id".to_string())?;

    let upload_url = format!(
        "{}/upload/drive/v3/files/{}?uploadType=media",
        gdrive_api_base_url().trim_end_matches('/'),
        file_id
    );
    let upload_response = gdrive_send_with_retry(client, |token| {
        client
            .patch(&upload_url)
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(payload.to_string())
    })
    .await?;

    if !upload_response.status().is_success() {
        let status = upload_response.status().as_u16();
        let detail = upload_response.text().await.unwrap_or_default();
        // Clean up the empty file we created above so we don't leak orphans.
        let _ = gdrive_delete_file(client, &file_id).await;
        return Err(format!(
            "google drive upload failed with HTTP {}: {}",
            status, detail
        ));
    }

    Ok(file_id)
}

async fn gdrive_delete_file(client: &Client, file_id: &str) -> Result<(), String> {
    if file_id.trim().is_empty() {
        return Err("google drive storage locator is empty".to_string());
    }
    let delete_url = format!(
        "{}/drive/v3/files/{}",
        gdrive_api_base_url().trim_end_matches('/'),
        file_id
    );
    let response = gdrive_send_with_retry(client, |token| {
        client.delete(&delete_url).bearer_auth(token)
    })
    .await?;

    // Google Drive returns 204 No Content on successful delete; 404 means already gone.
    let status = response.status();
    if status.is_success() || status == StatusCode::NOT_FOUND {
        return Ok(());
    }
    let detail = response.text().await.unwrap_or_default();
    Err(format!(
        "google drive delete failed with HTTP {}: {}",
        status.as_u16(),
        detail
    ))
}

async fn gdrive_read_file(client: &Client, file_id: &str) -> Result<String, String> {
    if file_id.trim().is_empty() {
        return Err("google drive storage locator is empty".to_string());
    }

    let download_url = format!(
        "{}/drive/v3/files/{}?alt=media",
        gdrive_api_base_url().trim_end_matches('/'),
        file_id
    );
    let response =
        gdrive_send_with_retry(client, |token| client.get(&download_url).bearer_auth(token))
            .await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!(
            "google drive download failed with HTTP {}: {}",
            status, detail
        ));
    }

    response
        .text()
        .await
        .map_err(|error| format!("failed to read Google Drive payload body: {error}"))
}

/// IPFS (Kubo) HTTP RPC API helpers. See https://docs.ipfs.tech/reference/kubo/rpc/ .
/// The API is single-endpoint and POST-only. We target `/api/v0/add`, `/api/v0/cat`,
/// and `/api/v0/pin/rm`. Auth is optional (basic auth via AGENT_INBOX_IPFS_BASIC_AUTH).
fn ipfs_api_base_url() -> String {
    std::env::var("AGENT_INBOX_IPFS_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5001".to_string())
}

fn ipfs_apply_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(basic) = std::env::var("AGENT_INBOX_IPFS_BASIC_AUTH") {
        if let Some((user, pass)) = basic.split_once(':') {
            return request.basic_auth(user, Some(pass));
        }
    }
    request
}

async fn ipfs_create_file(
    client: &Client,
    message_id: Uuid,
    payload: &str,
) -> Result<String, String> {
    // Use ?pin=true so the node retains the block. cid-version=1 yields base32 CIDs
    // which are URL-safe and case-insensitive.
    let url = format!(
        "{}/api/v0/add?pin=true&cid-version=1",
        ipfs_api_base_url().trim_end_matches('/')
    );
    let file_name = format!("{message_id}.json");
    let part = reqwest::multipart::Part::bytes(payload.as_bytes().to_vec())
        .file_name(file_name)
        .mime_str("application/json")
        .map_err(|error| format!("failed to build ipfs multipart part: {error}"))?;
    let form = reqwest::multipart::Form::new().part("file", part);

    let response = ipfs_apply_auth(client.post(&url).multipart(form))
        .send()
        .await
        .map_err(|error| format!("ipfs add request failed: {error}"))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!("ipfs add failed with HTTP {status}: {detail}"));
    }

    // Kubo streams NDJSON. Our single-file form yields one line whose `Hash` field
    // is the CID we want.
    let body = response
        .text()
        .await
        .map_err(|error| format!("failed to read ipfs add response body: {error}"))?;
    let last_line = body
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| "ipfs add response was empty".to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(last_line)
        .map_err(|error| format!("failed to parse ipfs add response: {error}"))?;
    let cid = parsed
        .get("Hash")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "ipfs add response missing Hash".to_string())?;
    Ok(cid)
}

async fn ipfs_read_file(client: &Client, cid: &str) -> Result<String, String> {
    if cid.trim().is_empty() {
        return Err("ipfs storage locator is empty".to_string());
    }
    let url = format!(
        "{}/api/v0/cat?arg={}",
        ipfs_api_base_url().trim_end_matches('/'),
        cid
    );
    let response = ipfs_apply_auth(client.post(&url))
        .send()
        .await
        .map_err(|error| format!("ipfs cat request failed: {error}"))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!("ipfs cat failed with HTTP {status}: {detail}"));
    }
    response
        .text()
        .await
        .map_err(|error| format!("failed to read ipfs cat body: {error}"))
}

async fn ipfs_delete_file(client: &Client, cid: &str) -> Result<(), String> {
    if cid.trim().is_empty() {
        return Err("ipfs storage locator is empty".to_string());
    }
    // IPFS is content-addressed: "delete" means unpin + best-effort GC. If the CID
    // isn't pinned (already purged), treat that as success.
    let url = format!(
        "{}/api/v0/pin/rm?arg={}",
        ipfs_api_base_url().trim_end_matches('/'),
        cid
    );
    let response = ipfs_apply_auth(client.post(&url))
        .send()
        .await
        .map_err(|error| format!("ipfs pin rm request failed: {error}"))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let detail = response.text().await.unwrap_or_default();
    // Kubo returns 500 with Message "not pinned or pinned indirectly" when the
    // CID was never pinned. Treat as idempotent success.
    if detail.contains("not pinned") {
        return Ok(());
    }
    Err(format!(
        "ipfs pin rm failed with HTTP {}: {detail}",
        status.as_u16()
    ))
}

/// S3-compatible storage (AWS S3, MinIO, Cloudflare R2, Backblaze B2, etc.).
/// We sign each request with AWS Signature v4 against a single bucket/prefix so
/// uploads stay auditable and server-side encrypted by the provider.
struct S3Config {
    endpoint: String, // e.g. "https://s3.us-east-1.amazonaws.com" or "http://127.0.0.1:9000"
    region: String,   // "us-east-1", "auto" for R2, etc.
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    path_style: bool, // true for MinIO / local dev; false for AWS virtual-hosted.
    prefix: String,   // key prefix, may be empty.
}

fn s3_config_from_env() -> Result<S3Config, String> {
    let endpoint = std::env::var("AGENT_INBOX_S3_ENDPOINT")
        .map_err(|_| "AGENT_INBOX_S3_ENDPOINT must be set".to_string())?;
    let region = std::env::var("AGENT_INBOX_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let bucket = std::env::var("AGENT_INBOX_S3_BUCKET")
        .map_err(|_| "AGENT_INBOX_S3_BUCKET must be set".to_string())?;
    let access_key_id = std::env::var("AGENT_INBOX_S3_ACCESS_KEY_ID")
        .map_err(|_| "AGENT_INBOX_S3_ACCESS_KEY_ID must be set".to_string())?;
    let secret_access_key = std::env::var("AGENT_INBOX_S3_SECRET_ACCESS_KEY")
        .map_err(|_| "AGENT_INBOX_S3_SECRET_ACCESS_KEY must be set".to_string())?;
    let path_style = std::env::var("AGENT_INBOX_S3_PATH_STYLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let prefix = std::env::var("AGENT_INBOX_S3_PREFIX").unwrap_or_default();
    Ok(S3Config {
        endpoint: endpoint.trim_end_matches('/').to_string(),
        region,
        bucket,
        access_key_id,
        secret_access_key,
        path_style,
        prefix,
    })
}

/// RFC 3986 unreserved set + `/` (S3 keys use slashes as path separators that
/// must NOT be percent-encoded on the canonical URI line per AWS rules).
fn s3_uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        let c = *b;
        let unreserved =
            c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.' || c == b'~';
        if unreserved {
            out.push(c as char);
        } else if c == b'/' && !encode_slash {
            out.push('/');
        } else {
            out.push_str(&format!("%{:02X}", c));
        }
    }
    out
}

fn s3_object_key_for(config: &S3Config, message_id: Uuid) -> String {
    if config.prefix.is_empty() {
        format!("{message_id}.json")
    } else {
        format!("{}/{message_id}.json", config.prefix.trim_matches('/'))
    }
}

/// Build the attachment object key per the spec:
/// `attachments/{user_id}/{draft_or_message_id}/{attachment_id}/blob.bin`
///
/// The key is intentionally opaque — it contains no filename or MIME info so
/// that no business context leaks to anyone who can see the R2 key listing.
fn s3_attachment_key_for(
    config: &S3Config,
    user_id: Uuid,
    draft_or_message_id: &str,
    attachment_id: Uuid,
) -> String {
    let safe_draft = draft_or_message_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect::<String>();
    let draft_segment = if safe_draft.is_empty() {
        "none".to_string()
    } else {
        safe_draft
    };
    let base = format!("attachments/{user_id}/{draft_segment}/{attachment_id}/blob.bin");
    if config.prefix.is_empty() {
        base
    } else {
        format!("{}/{base}", config.prefix.trim_matches('/'))
    }
}

fn s3_host_and_canonical_uri(config: &S3Config, object_key: &str) -> (String, String, String) {
    // Returns (host, canonical_uri, full_url).
    // canonical_uri never percent-encodes '/'.
    let endpoint_url = &config.endpoint;
    // Strip scheme to derive host.
    let (scheme, host_part) = match endpoint_url.split_once("://") {
        Some((s, rest)) => (s.to_string(), rest.to_string()),
        None => ("https".to_string(), endpoint_url.clone()),
    };
    let host_only = host_part.split('/').next().unwrap_or("").to_string();
    let key_encoded = s3_uri_encode(object_key, false);

    if config.path_style {
        let canonical_uri = format!("/{}/{}", config.bucket, key_encoded);
        let url = format!("{scheme}://{host_only}{canonical_uri}");
        (host_only, canonical_uri, url)
    } else {
        let virtual_host = format!("{}.{}", config.bucket, host_only);
        let canonical_uri = format!("/{}", key_encoded);
        let url = format!("{scheme}://{virtual_host}{canonical_uri}");
        (virtual_host, canonical_uri, url)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Compute JWK Thumbprint (RFC 7638) for a DPoP public key.
///
/// For OKP (Ed25519) keys: `{"crv":"Ed25519","kty":"OKP","x":"<base64url>"}`
/// For EC (P-256) keys:    `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`
/// Members are sorted alphabetically per RFC 7638 §3.2.
fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or("missing kty")?;

    let canonical = match kty {
        "OKP" => {
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or("missing crv")?;
            let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("missing x")?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        "EC" => {
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or("missing crv")?;
            let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("missing x")?;
            let y = jwk.get("y").and_then(|v| v.as_str()).ok_or("missing y")?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        other => return Err(format!("unsupported kty: {other}")),
    };

    use sha2::Digest;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Validate a DPoP proof JWS (RFC 9449) against the stored JWK Thumbprint.
///
/// Returns Ok(()) if the proof is valid for the given method, URL, and access
/// token. Includes htm/htu validation and jti replay detection per RFC 9449
/// §4.3.
///
/// Replay detection uses `check_and_record_dpop_replay`, which delegates to
/// the shared Postgres `replay_nonces` table when available and falls back to
/// the in-memory `state.dpop_jti_cache` only when a DB pool is not required.
/// Fail-closed on DB errors — the replay store IS the security boundary.
async fn validate_dpop_proof(
    dpop_header: &str,
    expected_jkt: &str,
    htm: &str,
    htu: &str,
    access_token: &str,
    state: &AppState,
) -> Result<(), String> {
    let parts: Vec<&str> = dpop_header.split('.').collect();
    if parts.len() != 3 {
        return Err("DPoP proof must be a compact JWS".into());
    }

    // Decode header and validate typ (RFC 9449 §4.2)
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| "invalid base64url in DPoP header")?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| "invalid DPoP header JSON")?;

    // RFC 9449 §4.2: the JOSE header MUST contain "typ": "dpop+jwt"
    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "dpop+jwt" {
        return Err("DPoP header must have typ \"dpop+jwt\"".into());
    }

    let jwk = header.get("jwk").ok_or("DPoP header missing jwk")?;
    let jkt = compute_jwk_thumbprint(jwk)?;
    if !constant_time_eq(jkt.as_bytes(), expected_jkt.as_bytes()) {
        return Err("DPoP JWK thumbprint does not match bound key".into());
    }

    // Verify signature
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or("missing kty in DPoP jwk")?;
    if kty != "OKP" {
        return Err("only OKP (Ed25519) DPoP keys are supported".into());
    }
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or("missing x in DPoP jwk")?;
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| "invalid base64url in DPoP jwk x")?;
    let vk = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "DPoP public key must be 32 bytes")?,
    )
    .map_err(|_| "invalid Ed25519 DPoP public key")?;

    let signed_data = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "invalid base64url in DPoP signature")?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "DPoP signature must be 64 bytes")?,
    );
    vk.verify(signed_data.as_bytes(), &sig)
        .map_err(|_| "DPoP signature verification failed")?;

    // Decode payload and validate claims
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| "invalid base64url in DPoP payload")?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| "invalid DPoP payload JSON")?;

    // htm / htu
    let claim_htm = claims
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or("missing htm")?;
    let claim_htu = claims
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or("missing htu")?;
    if claim_htm != htm {
        return Err(format!("htm mismatch: expected {htm}, got {claim_htm}"));
    }
    // `htu` is compared as PATH ONLY (no scheme/host). This is intentional —
    // the gateway's `dpop_htu_for_url` normalises both the direct and Next.js
    // proxy routes to the same canonical path, which the full-URI host binding
    // RFC 9449 describes cannot express across the proxy hop. The `ath` claim
    // below pins each proof to a specific access token, covering most of the
    // gap. See agent-gateway `dpop_htu_for_url` (audit 2026-06-11 finding #4).
    if claim_htu != htu {
        return Err(format!("htu mismatch: expected {htu}, got {claim_htu}"));
    }

    // ath = base64url(sha256(access_token))
    let claim_ath = claims
        .get("ath")
        .and_then(|v| v.as_str())
        .ok_or("missing ath")?;
    use sha2::Digest;
    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    if claim_ath != expected_ath {
        return Err("ath does not match access token hash".into());
    }

    // iat within 60 seconds
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or("missing iat")?;
    let now = Utc::now().timestamp();
    if (now - iat).abs() > 60 {
        return Err("DPoP iat outside 60-second window".into());
    }

    // jti replay detection (RFC 9449 §4.3). Scoped by (jkt, htm, htu, jti) via
    // the shared store so different keys or different endpoints that happen to
    // pick the same jti are NOT collectively treated as a replay.
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or("missing jti in DPoP proof")?;
    let accepted = check_and_record_dpop_replay(state, jti, expected_jkt, htm, htu, iat).await?;
    if !accepted {
        return Err("DPoP jti replay detected".into());
    }

    Ok(())
}

/// Constant-time comparison for hash strings (prevents timing attacks).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Sign a single S3 request (Auth v4) and return (url, headers).
/// Query string is empty (we only touch single-object endpoints).
fn s3_sign_request(
    config: &S3Config,
    method: &str,
    object_key: &str,
    payload: &[u8],
) -> (String, Vec<(String, String)>) {
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let payload_hash = sha256_hex(payload);

    let (host, canonical_uri, url) = s3_host_and_canonical_uri(config, object_key);

    // Canonical headers (lowercase name, trimmed value, sorted). For S3 sigv4
    // we include host, x-amz-content-sha256, x-amz-date at minimum.
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_query_string = "";
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let scope = format!("{date_stamp}/{}/s3/aws4_request", config.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(
        format!("AWS4{}", config.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, config.region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}",
        config.access_key_id
    );

    let headers = vec![
        ("host".to_string(), host),
        ("x-amz-content-sha256".to_string(), payload_hash),
        ("x-amz-date".to_string(), amz_date),
        ("authorization".to_string(), authorization),
    ];
    (url, headers)
}

async fn s3_put_object(client: &Client, message_id: Uuid, payload: &str) -> Result<String, String> {
    let config = s3_config_from_env()?;
    let key = s3_object_key_for(&config, message_id);
    let (url, headers) = s3_sign_request(&config, "PUT", &key, payload.as_bytes());

    let mut request = client
        .put(&url)
        .header("content-type", "application/json")
        .body(payload.as_bytes().to_vec());
    for (name, value) in headers {
        // reqwest sets host automatically; skipping avoids duplicate headers.
        if name == "host" {
            continue;
        }
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("s3 put request failed: {error}"))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!("s3 put failed with HTTP {status}: {detail}"));
    }
    Ok(key)
}

async fn s3_get_object(client: &Client, object_key: &str) -> Result<String, String> {
    if object_key.trim().is_empty() {
        return Err("s3 storage locator is empty".to_string());
    }
    let config = s3_config_from_env()?;
    let (url, headers) = s3_sign_request(&config, "GET", object_key, b"");
    let mut request = client.get(&url);
    for (name, value) in headers {
        if name == "host" {
            continue;
        }
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("s3 get request failed: {error}"))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let detail = response.text().await.unwrap_or_default();
        return Err(format!("s3 get failed with HTTP {status}: {detail}"));
    }
    response
        .text()
        .await
        .map_err(|error| format!("failed to read s3 body: {error}"))
}

async fn s3_delete_object(client: &Client, object_key: &str) -> Result<(), String> {
    if object_key.trim().is_empty() {
        return Err("s3 storage locator is empty".to_string());
    }
    let config = s3_config_from_env()?;
    let (url, headers) = s3_sign_request(&config, "DELETE", object_key, b"");
    let mut request = client.delete(&url);
    for (name, value) in headers {
        if name == "host" {
            continue;
        }
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("s3 delete request failed: {error}"))?;
    let status = response.status();
    // S3 returns 204 on success; 404 means already gone — treat as idempotent.
    if status.is_success() || status == StatusCode::NOT_FOUND {
        return Ok(());
    }
    let detail = response.text().await.unwrap_or_default();
    Err(format!(
        "s3 delete failed with HTTP {}: {detail}",
        status.as_u16()
    ))
}

/// HEAD object → returns (size, metadata map). Used for attachment complete-phase
/// verification: we confirm the object exists, its size matches, and its
/// `x-amz-meta-*` headers match the intent we issued.
async fn s3_head_object(
    client: &Client,
    object_key: &str,
) -> Result<(i64, std::collections::HashMap<String, String>), String> {
    if object_key.trim().is_empty() {
        return Err("s3 storage locator is empty".to_string());
    }
    let config = s3_config_from_env()?;
    let (url, headers) = s3_sign_request(&config, "HEAD", object_key, b"");
    let mut request = client.head(&url);
    for (name, value) in headers {
        if name == "host" {
            continue;
        }
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("s3 head request failed: {error}"))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(format!("s3 head failed with HTTP {status}"));
    }
    let size = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(-1);
    let mut metadata = std::collections::HashMap::new();
    for (name, value) in response.headers() {
        let name_str = name.as_str();
        if let Some(meta_key) = name_str.strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                metadata.insert(meta_key.to_string(), v.to_string());
            }
        }
    }
    Ok((size, metadata))
}

/// SigV4 presigned URL: credentials ride in query string instead of
/// Authorization header. This lets the browser PUT/GET directly to R2 without
/// our secret access key.
///
/// `method`: "PUT" or "GET"
/// `ttl_secs`: expiry in seconds (AWS max 604800)
/// `extra_signed_headers`: additional headers that MUST be included in the
///   request (e.g. `x-amz-meta-*` for uploads). Their names are added to
///   `X-Amz-SignedHeaders` and their values hashed into the canonical request,
///   so a client cannot change them after signing.
/// `extra_query_params`: extra query parameters to include in the signature
///   (e.g. `response-content-disposition=attachment` for GET).
fn s3_presign_url(
    config: &S3Config,
    method: &str,
    object_key: &str,
    ttl_secs: u64,
    extra_signed_headers: &[(String, String)],
    extra_query_params: &[(String, String)],
) -> String {
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let (host, canonical_uri, url_base) = s3_host_and_canonical_uri(config, object_key);

    // SignedHeaders must include `host` at minimum plus any extra headers we
    // bind to the signature. All names are lowercase, sorted.
    let mut signed_header_names: Vec<String> = vec!["host".to_string()];
    for (name, _value) in extra_signed_headers {
        signed_header_names.push(name.to_lowercase());
    }
    signed_header_names.sort();
    signed_header_names.dedup();
    let signed_headers = signed_header_names.join(";");

    let scope = format!("{date_stamp}/{}/s3/aws4_request", config.region);
    let credential = format!("{}/{scope}", config.access_key_id);

    // Presigned URLs use UNSIGNED-PAYLOAD — the body is not hashed into the
    // signature, since we don't know it at signing time.
    let payload_hash = "UNSIGNED-PAYLOAD";

    // Canonical query string: all AWS query params + caller extras, sorted by
    // key with URL-encoded values.
    let mut query_params: Vec<(String, String)> = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential.clone()),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), ttl_secs.to_string()),
        ("X-Amz-SignedHeaders".to_string(), signed_headers.clone()),
    ];
    for (name, value) in extra_query_params {
        query_params.push((name.clone(), value.clone()));
    }
    query_params.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_query_string: String = query_params
        .iter()
        .map(|(k, v)| format!("{}={}", s3_uri_encode(k, true), s3_uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");

    // Canonical headers: `host` + extras, lowercase name + trimmed value, sorted.
    let mut header_entries: Vec<(String, String)> = vec![("host".to_string(), host.clone())];
    for (name, value) in extra_signed_headers {
        header_entries.push((name.to_lowercase(), value.trim().to_string()));
    }
    header_entries.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers: String = header_entries
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(
        format!("AWS4{}", config.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, config.region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!("{url_base}?{canonical_query_string}&X-Amz-Signature={signature}")
}

fn check_and_record_auth_replay_in_memory(state: &AppState, replay_key: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut seen = state
        .seen_auth_proofs
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    seen.retain(|_, seen_at| now - *seen_at <= AUTH_REPLAY_WINDOW_SECS);
    if seen.contains_key(replay_key) {
        return false;
    }
    seen.insert(replay_key.to_string(), now);
    true
}

fn check_and_record_message_replay_in_memory(state: &AppState, replay_key: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut seen = state
        .seen_message_nonces
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    seen.retain(|_, seen_at| now - *seen_at <= MESSAGE_REPLAY_WINDOW_SECS);
    if seen.contains_key(replay_key) {
        return false;
    }
    seen.insert(replay_key.to_string(), now);
    true
}

/// Atomically record a replay nonce in Postgres and tell the caller whether
/// it was the first sighting.
///
/// Returns `Ok(true)` on first-seen (INSERT succeeded), `Ok(false)` on replay
/// (unique-constraint conflict), `Err` on infrastructure failure. Callers
/// **must** treat the `Err` case as fail-closed: the replay-store is the
/// security boundary itself.
///
/// Expired rows are **not** deleted in this path. A periodic background task
/// (see `spawn_replay_nonce_cleanup_if_configured`) handles cleanup so this
/// hot path stays at one INSERT per check.
async fn check_and_record_replay_in_db(
    pool: &PgPool,
    scope: &str,
    replay_key: &str,
    window_secs: i64,
) -> Result<bool, String> {
    let result = sqlx::query(
        r#"
        INSERT INTO replay_nonces (scope, replay_key, expires_at)
        VALUES ($1, $2, NOW() + ($3::bigint * INTERVAL '1 second'))
        ON CONFLICT (scope, replay_key) DO NOTHING
        "#,
    )
    .bind(scope)
    .bind(replay_key)
    .bind(window_secs)
    .execute(pool)
    .await
    .map_err(|error| format!("failed to insert replay record: {error}"))?;

    Ok(result.rows_affected() > 0)
}

/// Compose the scope string for a DPoP proof replay entry. Including the JWK
/// thumbprint and the target method/URL in the scope means two proofs whose
/// jtis happen to collide — but were produced by different keys or targeted
/// different endpoints — are treated as distinct and both are accepted.
fn dpop_replay_scope(jkt: &str, htm: &str, htu: &str) -> String {
    format!("dpop_proof|{jkt}|{htm}|{htu}")
}

/// In-memory DPoP replay check scoped by (jkt, htm, htu, jti). Used in the
/// in-memory fallback path (tests, local development without Postgres). Keeps
/// the existing `state.dpop_jti_cache` HashMap but stores the composite key
/// instead of bare jti, matching the DB scope semantics.
fn check_and_record_dpop_replay_in_memory(
    state: &AppState,
    jti: &str,
    jkt: &str,
    htm: &str,
    htu: &str,
    iat: i64,
) -> bool {
    let now = Utc::now().timestamp();
    let mut cache = state
        .dpop_jti_cache
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let key = format!("{}|{}", dpop_replay_scope(jkt, htm, htu), jti);
    if cache.contains_key(&key) {
        return false;
    }
    let expiry = iat + DPOP_REPLAY_WINDOW_SECS;
    cache.insert(key, expiry);

    // Periodic eviction to cap HashMap growth. Cheap because the check is
    // scoped by byte-equal key lookup above.
    if cache.len().is_multiple_of(64) {
        cache.retain(|_, exp| *exp > now);
    }
    true
}

/// Shared-store DPoP replay check. Prefers Postgres when a pool is
/// available, falls back to the in-memory HashMap only when
/// `database_required()` is false. Fail-closed on DB errors.
async fn check_and_record_dpop_replay(
    state: &AppState,
    jti: &str,
    jkt: &str,
    htm: &str,
    htu: &str,
    iat: i64,
) -> Result<bool, String> {
    let maybe_pool = state.database_pool().await?;
    if let Some(pool) = maybe_pool {
        let scope = dpop_replay_scope(jkt, htm, htu);
        return check_and_record_replay_in_db(&pool, &scope, jti, DPOP_REPLAY_WINDOW_SECS).await;
    }
    if database_required() {
        return Err("database is required but unavailable".to_string());
    }
    Ok(check_and_record_dpop_replay_in_memory(
        state, jti, jkt, htm, htu, iat,
    ))
}

/// Background task: every `REPLAY_NONCE_CLEANUP_INTERVAL_SECS`, delete rows
/// whose `expires_at` is in the past. Keeps the table from growing unboundedly
/// without adding hot-path SQL work. Startup mirrors
/// `spawn_attachment_cleanup_job` — one cleanup task per API instance; races
/// between instances are harmless because `DELETE` is idempotent.
pub fn spawn_replay_nonce_cleanup_job(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            REPLAY_NONCE_CLEANUP_INTERVAL_SECS,
        ));
        // Skip immediate first tick so startup doesn't thrash the DB.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let result = sqlx::query("DELETE FROM replay_nonces WHERE expires_at <= NOW()")
                .execute(&pool)
                .await;
            match result {
                Ok(r) if r.rows_affected() > 0 => {
                    info!(
                        rows_deleted = r.rows_affected(),
                        "replay_nonces cleanup pass completed"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "replay_nonces cleanup failed"),
            }
        }
    });
}

/// Convenience entrypoint for `main.rs`: dedicated tiny pool + spawn the job
/// if a DATABASE_URL is configured. Matches the shape of
/// `spawn_attachment_cleanup_if_configured`.
pub async fn spawn_replay_nonce_cleanup_if_configured() -> bool {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        return false;
    };
    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(DB_CONNECT_TIMEOUT_SECS))
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => {
            tracing::warn!(error = %err, "replay_nonces cleanup: failed to connect to DB; job disabled");
            return false;
        }
    };
    spawn_replay_nonce_cleanup_job(pool);
    true
}

async fn check_and_record_auth_replay(state: &AppState, replay_key: &str) -> Result<bool, String> {
    let maybe_pool = state.database_pool().await?;
    if let Some(pool) = maybe_pool {
        return check_and_record_replay_in_db(
            &pool,
            "auth_verify",
            replay_key,
            AUTH_REPLAY_WINDOW_SECS,
        )
        .await;
    }
    if database_required() {
        return Err("database is required but unavailable".to_string());
    }
    Ok(check_and_record_auth_replay_in_memory(state, replay_key))
}

async fn check_and_record_message_replay(
    state: &AppState,
    replay_key: &str,
) -> Result<bool, String> {
    let maybe_pool = state.database_pool().await?;
    if let Some(pool) = maybe_pool {
        return check_and_record_replay_in_db(
            &pool,
            "message_nonce",
            replay_key,
            MESSAGE_REPLAY_WINDOW_SECS,
        )
        .await;
    }
    if database_required() {
        return Err("database is required but unavailable".to_string());
    }
    Ok(check_and_record_message_replay_in_memory(state, replay_key))
}

fn is_session_jti_revoked_in_memory(state: &AppState, jwt_id: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut revoked = state
        .revoked_session_jtis
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Evict expired entries periodically (every 64 checks) to avoid O(n) scan per request
    if revoked.len() > 64 && now % 64 == 0 {
        revoked.retain(|_, exp| *exp > now);
    }
    revoked.get(jwt_id).is_some_and(|exp| *exp > now)
}

fn revoke_session_jti_in_memory(state: &AppState, jwt_id: &str, exp: i64) {
    let mut revoked = state
        .revoked_session_jtis
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    revoked.insert(jwt_id.to_string(), exp);
}

fn build_envelope_signing_payload(
    sender_did: &str,
    recipient_did: &str,
    subject_encrypted: &str,
    encrypted_content: &str,
    encrypted_key: &str,
    nonce: &str,
) -> String {
    format!(
        "{sender_did}\n{recipient_did}\n{subject_encrypted}\n{encrypted_content}\n{encrypted_key}\n{nonce}"
    )
}

fn verify_envelope_signature(signing_key: &str, signature: &str, signing_payload: &str) -> bool {
    let public_key_bytes = match URL_SAFE_NO_PAD.decode(signing_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let public_key_array: [u8; 32] = match public_key_bytes.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key_array) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let signature_bytes = match URL_SAFE_NO_PAD.decode(signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature_array: [u8; 64] = match signature_bytes.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&signature_array);

    verifying_key
        .verify(signing_payload.as_bytes(), &signature)
        .is_ok()
}

fn consume_request_rate_limit(state: &AppState) -> bool {
    let now = Utc::now().timestamp();
    let mut budget = state
        .request_budget
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    if now - budget.window_started_at >= RATE_LIMIT_WINDOW_SECS as i64 {
        budget.window_started_at = now;
        budget.count = 0;
    }

    if budget.count >= RATE_LIMIT_REQUESTS_PER_WINDOW {
        return false;
    }

    budget.count += 1;
    true
}

/// Extract client IP from X-Forwarded-For or X-Real-IP headers, falling back to peer addr.
fn extract_client_ip(headers: &HeaderMap) -> String {
    // Cloudflare stamps CF-Connecting-IP with the real client address; when
    // traffic actually transits the tunnel the client cannot forge it.
    // Prefer it over the client-supplied X-Forwarded-For, which a caller can
    // set to any value to rotate past the per-IP rate limit (the primary
    // brute-force defense on credential activation).
    if let Some(cf_ip) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = cf_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    // In production we trust ONLY CF-Connecting-IP. Falling through to the
    // client-controlled XFF / X-Real-IP would reopen the spoofing hole, so a
    // request that reached us without the Cloudflare header lands in a shared
    // "unknown" bucket rather than a forgeable per-IP one.
    if is_production_env() {
        return "unknown".to_string();
    }
    // Non-production (local / docker): accept proxy headers for convenience.
    // X-Forwarded-For: client, proxy1, proxy2 — take the first (leftmost)
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

fn consume_per_ip_rate_limit(state: &AppState, client_ip: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut budgets = state
        .per_ip_budgets
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // Evict stale entries to prevent unbounded memory growth
    if budgets.len() > MAX_RATE_LIMIT_ENTRIES {
        budgets.retain(|_, b| now - b.window_started_at < PER_IP_RATE_LIMIT_WINDOW_SECS as i64 * 2);
    }

    let budget = budgets
        .entry(client_ip.to_string())
        .or_insert(RequestBudget {
            window_started_at: now,
            count: 0,
        });

    if now - budget.window_started_at >= PER_IP_RATE_LIMIT_WINDOW_SECS as i64 {
        budget.window_started_at = now;
        budget.count = 0;
    }

    if budget.count >= PER_IP_RATE_LIMIT_REQUESTS {
        return false;
    }

    budget.count += 1;
    true
}

async fn enforce_request_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Global rate limit
    if !consume_request_rate_limit(&state) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limited".to_string(),
                message: "too many requests in current window".to_string(),
            }),
        )
            .into_response();
    }

    // Per-IP rate limit
    let client_ip = extract_client_ip(request.headers());
    if !consume_per_ip_rate_limit(&state, &client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limited".to_string(),
                message: "too many requests from this IP in current window".to_string(),
            }),
        )
            .into_response();
    }

    next.run(request).await
}

/// Return the list of allowed Origin values based on environment config.
/// Mirrors `build_cors_layer` but returns strings for runtime comparison.
fn allowed_origins() -> Vec<String> {
    let allowed_origins_raw =
        std::env::var("AGENT_INBOX_CORS_ORIGINS").unwrap_or_else(|_| String::new());

    if !allowed_origins_raw.is_empty() {
        return allowed_origins_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    if is_production_env() {
        warn!("AGENT_INBOX_CORS_ORIGINS not set — using default production origin for CSRF check");
        vec!["https://app.nexusinbox.ai".to_string()]
    } else {
        vec![
            "http://localhost:3000".to_string(),
            "http://localhost:3100".to_string(),
            "http://127.0.0.1:3000".to_string(),
            "http://127.0.0.1:3100".to_string(),
        ]
    }
}

/// Check whether a given Origin value matches the allowlist.
fn is_origin_allowed(origin: &str) -> bool {
    let allowed = allowed_origins();
    allowed.iter().any(|a| a == origin)
}

/// Extract the "origin" part (scheme://host[:port]) of a Referer URL.
/// Returns None if the URL is malformed.
fn referer_origin(referer: &str) -> Option<String> {
    // Simple parser: find scheme://
    let scheme_end = referer.find("://")?;
    let scheme = &referer[..scheme_end];
    let rest = &referer[scheme_end + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

/// Enforce Origin/Referer check on state-changing requests to mitigate CSRF.
///
/// Rationale: session cookies are HttpOnly+SameSite=Strict which already prevents
/// most CSRF, but defense-in-depth via explicit origin verification is strongly
/// recommended. We check Origin first, fall back to Referer, and reject if
/// neither matches the allowlist.
async fn enforce_csrf_protection(request: Request, next: Next) -> Response {
    // SECURITY: test-only bypass — production validate_runtime_config refuses to start
    // if AGENT_INBOX_DISABLE_CSRF_CHECK is set, so this can never be enabled in prod.
    if !is_production_env()
        && std::env::var("AGENT_INBOX_DISABLE_CSRF_CHECK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        return next.run(request).await;
    }

    let method = request.method().clone();
    // Only check state-changing methods
    let needs_check = matches!(
        method,
        Method::POST | Method::PATCH | Method::PUT | Method::DELETE
    );

    if !needs_check {
        return next.run(request).await;
    }

    // Skip for endpoints that don't use Cookie auth (no CSRF risk)
    let path = request.uri().path();
    if path == "/health"
        || path == "/status"
        || path.starts_with("/agent-auth/")
        || (path.starts_with("/agent-credentials/") && path.ends_with("/activate"))
    {
        return next.run(request).await;
    }

    // Skip for requests using Agent Token auth (Bearer agt_...) — these are
    // not vulnerable to CSRF because they don't rely on ambient credentials.
    let has_agent_token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("Bearer agt_") || v.starts_with("DPoP agt_"))
        .unwrap_or(false);
    if has_agent_token {
        return next.run(request).await;
    }

    let headers = request.headers();
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let referer_origin_value = headers
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .and_then(referer_origin);

    let candidate = origin.or(referer_origin_value);

    let ok = match candidate {
        Some(value) => is_origin_allowed(&value),
        None => false,
    };

    if !ok {
        warn!(%path, %method, "CSRF origin rejected");
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".to_string(),
                message: "request origin is not allowed".to_string(),
            }),
        )
            .into_response();
    }

    next.run(request).await
}

async fn enforce_request_timeout(request: Request, next: Next) -> Response {
    match tokio::time::timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(ErrorResponse {
                error: "request_timeout".to_string(),
                message: "request processing timed out".to_string(),
            }),
        )
            .into_response(),
    }
}

// --- Input validation helpers ---

/// Validate DID format: must start with "did:key:z" and contain only valid base58 characters.
fn is_valid_did_format(did: &str) -> bool {
    if did.len() < MIN_DID_LENGTH || did.len() > MAX_DID_LENGTH {
        return false;
    }
    if !did.starts_with("did:key:z") {
        return false;
    }
    let key_part = &did["did:key:z".len()..];
    // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    key_part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l')
}

/// Validate that a string doesn't contain control characters (except newline/tab)
fn is_clean_text(s: &str) -> bool {
    s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t')
}

/// Validate agent label: non-empty, within length limit, no control chars
fn validate_agent_label(label: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if label.trim().is_empty() {
        return Err(validation_error("agent label cannot be empty"));
    }
    if label.len() > MAX_AGENT_LABEL_LENGTH {
        return Err(validation_error(&format!(
            "agent label exceeds maximum length of {MAX_AGENT_LABEL_LENGTH}"
        )));
    }
    if !is_clean_text(label) {
        return Err(validation_error("agent label contains invalid characters"));
    }
    Ok(())
}

/// Validate a DID string
fn validate_did(did: &str, field_name: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if did.trim().is_empty() {
        return Err(validation_error(&format!("{field_name} cannot be empty")));
    }
    if !is_valid_did_format(did) {
        return Err(validation_error(&format!(
            "{field_name} is not a valid DID format"
        )));
    }
    Ok(())
}

/// Validate base64url-encoded key field
fn validate_key_field(
    key: &str,
    field_name: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if key.trim().is_empty() {
        return Err(validation_error(&format!("{field_name} cannot be empty")));
    }
    if key.len() > MAX_KEY_FIELD_LENGTH {
        return Err(validation_error(&format!(
            "{field_name} exceeds maximum length"
        )));
    }
    // Verify it's valid base64url
    if URL_SAFE_NO_PAD.decode(key).is_err() {
        return Err(validation_error(&format!(
            "{field_name} is not valid base64url encoding"
        )));
    }
    Ok(())
}

/// GET /health — lightweight liveness + readiness probe for container orchestration.
/// Returns 200 if the service is running and can reach the database (if configured).
/// Returns 503 if database is configured but unreachable.
async fn health(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, (StatusCode, Json<HealthResponse>)> {
    if state.database_url.is_some() {
        let pool = state.database_pool().await.ok().flatten();
        match pool {
            Some(p) => {
                if sqlx::query("SELECT 1").fetch_one(&p).await.is_err() {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(HealthResponse {
                            status: "unhealthy",
                            service: "nexusinbox-api",
                        }),
                    ));
                }
            }
            None => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(HealthResponse {
                        status: "unhealthy",
                        service: "nexusinbox-api",
                    }),
                ));
            }
        }
    }
    Ok(Json(HealthResponse {
        status: "ok",
        service: "nexusinbox-api",
    }))
}

async fn public_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let database_configured = state.database_url.is_some();
    let database_connected = if database_configured {
        state.database_pool().await.ok().flatten().is_some()
    } else {
        false
    };
    let auto_purge_enabled = std::env::var("AGENT_INBOX_AUTO_PURGE_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let world_id_verify_enabled = std::env::var("WORLD_ID_APP_ID")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    Json(StatusResponse {
        service: "nexusinbox-api",
        version: env!("CARGO_PKG_VERSION"),
        storage_backend: state.storage_backend.storage_subdir(),
        database_configured,
        database_connected,
        auto_purge_enabled,
        websocket_enabled: true,
        world_id_verify_enabled,
    })
}

async fn auth_verify(
    State(state): State<AppState>,
    JsonBody(payload): JsonBody<AuthVerifyRequest>,
) -> Result<(HeaderMap, Json<AuthVerifyResponse>), (StatusCode, Json<ErrorResponse>)> {
    let action = payload.action.unwrap_or_default();
    let signal = payload
        .signal
        .clone()
        .or_else(|| {
            payload
                .idkit_result
                .as_ref()
                .and_then(|idkit| idkit.get("signal"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();

    // Extract nullifier and verification_level from idkit_result or legacy fields
    let (nullifier_hash, verification_level) = if let Some(ref idkit) = payload.idkit_result {
        let responses = idkit.get("responses").and_then(|v| v.as_array());
        let first = responses.and_then(|r| r.first());
        let nullifier = first
            .and_then(|r| r.get("nullifier"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let vl = first
            .and_then(|r| r.get("identifier"))
            .and_then(|v| v.as_str())
            .unwrap_or("orb")
            .to_string();
        (nullifier, vl)
    } else {
        (
            payload.nullifier_hash.unwrap_or_default(),
            payload.verification_level.unwrap_or_default(),
        )
    };

    let audit_fail = |status: u16, reason: &str| {
        audit_auth_verify_event(
            status,
            "failure",
            reason,
            &action,
            &verification_level,
            &nullifier_hash,
        )
    };

    if action.trim().is_empty() || nullifier_hash.trim().is_empty() {
        audit_fail(422, "missing_required_fields");
        return Err(validation_error(
            "missing required auth verify fields (action, nullifier)",
        ));
    }

    let expected_action = expected_world_action();
    if action != expected_action {
        audit_fail(422, "invalid_action");
        return Err(validation_error("invalid action"));
    }
    let expected_signal = expected_world_signal();
    if signal != expected_signal {
        audit_fail(422, "invalid_signal");
        return Err(validation_error("invalid signal"));
    }

    if !is_valid_verification_level(&verification_level) {
        audit_fail(422, "invalid_verification_level");
        return Err(validation_error("verification_level must be 'orb'"));
    }

    if !world_verify_enabled() && !allow_world_verify_mock() {
        audit_fail(503, "world_verify_required");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "world_verify_required".to_string(),
                message: "World verification must be enabled in production".to_string(),
            }),
        ));
    }

    if world_verify_enabled() {
        let rp_id = std::env::var("WORLD_ID_RP_ID").map_err(|_| {
            audit_fail(503, "world_verify_not_configured");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "world_verify_not_configured".to_string(),
                    message: "WORLD_ID_RP_ID is required when World verification is enabled"
                        .to_string(),
                }),
            )
        })?;

        // Forward raw IDKit result to World ID v4 verify endpoint.
        // Ensure action field is present (IDKit may not include it).
        let mut idkit_result = payload.idkit_result.clone().ok_or_else(|| {
            audit_fail(422, "missing_idkit_result");
            validation_error("idkit_result is required when World verification is enabled")
        })?;
        if let Some(obj) = idkit_result.as_object_mut() {
            obj.entry("action")
                .or_insert_with(|| serde_json::Value::String(action.clone()));
            obj.entry("signal")
                .or_insert_with(|| serde_json::Value::String(signal.clone()));
        }

        let verify_response = match verify_world_id_proof(&rp_id, &idkit_result).await {
            Ok(response) => response,
            Err((status, body)) => {
                let reason = body.message.clone();
                audit_fail(
                    status.as_u16(),
                    &format!("world_verify_http_error:{reason}"),
                );
                return Err((status, body));
            }
        };
        if !verify_response.success {
            audit_fail(401, "world_verify_failed");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "world_verify_failed".to_string(),
                    message: "world verification was not successful".to_string(),
                }),
            ));
        }
    }

    let replay_key = format!("{}:{}", nullifier_hash, action);
    if !check_and_record_auth_replay(&state, &replay_key)
        .await
        .map_err(|message| internal_server_error(&message))?
    {
        audit_fail(422, "replayed_auth_proof");
        return Err(validation_error("replayed auth proof is not allowed"));
    }

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    let user = if let Some(pool) = maybe_pool.clone() {
        let world_id_hash = world_id_hash_from_nullifier(&nullifier_hash);
        let row = sqlx::query(
            r#"
            INSERT INTO users (world_id_hash, nullifier_hash, verification_level)
            VALUES ($1, $2, $3)
            ON CONFLICT (nullifier_hash)
            DO UPDATE SET verification_level = EXCLUDED.verification_level
            RETURNING id::text AS id, verification_level, created_at::text AS created_at, display_name
            "#,
        )
        .bind(world_id_hash)
        .bind(&nullifier_hash)
        .bind(&verification_level)
        .fetch_one(&pool)
        .await
        .map_err(|error| internal_error("failed to upsert user", error))?;

        let id_text: String = row.get("id");
        let id = Uuid::parse_str(&id_text)
            .map_err(|error| internal_error("invalid user id from database", error))?;
        UserRecord {
            id,
            verification_level: row.get("verification_level"),
            created_at: row.get("created_at"),
            display_name: row.try_get("display_name").ok(),
        }
    } else {
        let id = derive_user_id_from_nullifier(&nullifier_hash);
        let display_name = state
            .display_names
            .lock()
            .ok()
            .and_then(|map| map.get(&id.to_string()).cloned());
        UserRecord {
            id,
            verification_level: verification_level.clone(),
            created_at: Utc::now().to_rfc3339(),
            display_name,
        }
    };

    let issued_session = issue_session_jwt(
        &user.id.to_string(),
        &nullifier_hash,
        &verification_level,
        SESSION_TTL_SECS,
    )
    .map_err(|reason| {
        audit_fail(500, reason);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "server_error".to_string(),
                message: "failed to issue session token".to_string(),
            }),
        )
    })?;

    if let Some(pool) = maybe_pool {
        sqlx::query(
            r#"
            INSERT INTO sessions (user_id, jwt_id, expires_at)
            VALUES ($1, $2, to_timestamp($3))
            "#,
        )
        .bind(user.id)
        .bind(&issued_session.jwt_id)
        .bind(issued_session.expires_at_unix)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to persist session", error))?;
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&issue_session_cookie(&issued_session.token)).map_err(|_| {
            audit_fail(500, "issue_session_cookie_failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "auth_error".to_string(),
                    message: "failed to issue session cookie".to_string(),
                }),
            )
        })?,
    );
    audit_auth_verify_event(
        200,
        "success",
        "verified",
        &action,
        &verification_level,
        &nullifier_hash,
    );

    Ok((
        headers,
        Json(AuthVerifyResponse {
            user: UserSummary {
                id: user.id,
                display_name: user.display_name,
                verification_level: user.verification_level,
                created_at: user.created_at,
            },
        }),
    ))
}

async fn auth_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<AuthLogoutResponse>), (StatusCode, Json<ErrorResponse>)> {
    let claims = authenticated_claims(&state, &headers).await?;
    let jwt_id = claims
        .jti
        .as_deref()
        .ok_or_else(|| unauthorized_error("token is missing jti"))?;

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&claims.sub)?;
        sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = COALESCE(revoked_at, NOW())
            WHERE user_id = $1 AND jwt_id = $2
            "#,
        )
        .bind(user_uuid)
        .bind(jwt_id)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to revoke session in database", error))?;
    } else {
        revoke_session_jti_in_memory(&state, jwt_id, claims.exp);
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie())
            .map_err(|_| internal_server_error("failed to clear session cookie"))?,
    );

    Ok((response_headers, Json(AuthLogoutResponse { success: true })))
}

async fn auth_session(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match authenticated_claims(&state, &headers).await {
        Ok(claims) => {
            let user = load_user_summary(&state, &claims).await;
            (
                StatusCode::OK,
                Json(AuthSessionResponse {
                    authenticated: true,
                    user,
                }),
            )
                .into_response()
        }
        Err((status, body)) => {
            let mut response = (status, body).into_response();
            if status == StatusCode::UNAUTHORIZED {
                if let Ok(cookie) = HeaderValue::from_str(&clear_session_cookie()) {
                    response.headers_mut().insert(SET_COOKIE, cookie);
                }
            }
            response
        }
    }
}

/// Load the profile summary for an authenticated user. Falls back to a
/// minimal summary derived from the JWT claims when the DB is unavailable,
/// consulting the in-memory display_names store for the edited name.
async fn load_user_summary(state: &AppState, claims: &TokenClaims) -> Option<UserSummary> {
    let user_uuid = Uuid::parse_str(&claims.sub).ok()?;

    if let Ok(Some(pool)) = state.database_pool().await {
        let row_opt = sqlx::query(
            r#"
            SELECT id::text AS id,
                   verification_level,
                   created_at::text AS created_at,
                   display_name
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();
        if let Some(row) = row_opt {
            let id_text: String = row.get("id");
            let id = Uuid::parse_str(&id_text).unwrap_or(user_uuid);
            return Some(UserSummary {
                id,
                display_name: row.try_get("display_name").ok(),
                verification_level: row.get("verification_level"),
                created_at: row.get("created_at"),
            });
        }
    }

    // In-memory fallback: synthesize from claims + display_names store.
    let display_name = state
        .display_names
        .lock()
        .ok()
        .and_then(|map| map.get(&claims.sub).cloned());
    Some(UserSummary {
        id: user_uuid,
        display_name,
        verification_level: claims.verification_level.clone(),
        created_at: DateTime::<Utc>::from_timestamp(claims.iat, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
    })
}

async fn update_auth_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<AuthSessionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = authenticated_claims(&state, &headers).await?;
    let user_uuid = parse_user_uuid(&claims.sub)?;

    // Sanitize display_name: trim, enforce 1..=64 chars, disallow control chars.
    let new_display_name = match payload.display_name.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                if trimmed.chars().count() > 64 {
                    return Err(validation_error(
                        "display_name must be 64 characters or fewer",
                    ));
                }
                if trimmed.chars().any(|c| c.is_control()) {
                    return Err(validation_error(
                        "display_name must not contain control characters",
                    ));
                }
                Some(trimmed.to_string())
            }
        }
        None => None,
    };

    if let Ok(Some(pool)) = state.database_pool().await {
        sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
            .bind(new_display_name.as_deref())
            .bind(user_uuid)
            .execute(&pool)
            .await
            .map_err(|error| internal_error("failed to update profile", error))?;
    }

    if let Ok(mut map) = state.display_names.lock() {
        match &new_display_name {
            Some(value) => {
                map.insert(claims.sub.clone(), value.clone());
            }
            None => {
                map.remove(&claims.sub);
            }
        }
    }

    let user = load_user_summary(&state, &claims).await;
    Ok(Json(AuthSessionResponse {
        authenticated: true,
        user,
    }))
}

async fn session_is_active_in_db(
    pool: &PgPool,
    user_id: Uuid,
    jwt_id: &str,
) -> Result<bool, String> {
    let row = sqlx::query(
        r#"
        SELECT EXISTS(
          SELECT 1
          FROM sessions
          WHERE user_id = $1
            AND jwt_id = $2
            AND revoked_at IS NULL
            AND expires_at > NOW()
        ) AS is_active
        "#,
    )
    .bind(user_id)
    .bind(jwt_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("failed to validate session in database: {error}"))?;
    Ok(row.get::<bool, _>("is_active"))
}

fn token_from_headers(headers: &HeaderMap) -> String {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            // Accept both "Bearer <token>" and "DPoP <token>" schemes.
            // DPoP scheme is used by agent tokens with sender-constrained
            // binding (RFC 9449). Full DPoP proof validation is enforced in
            // validate_agent_token() when dpop_jkt != "none".
            raw.strip_prefix("Bearer ")
                .or_else(|| raw.strip_prefix("DPoP "))
        })
        .map(str::to_string)
        .or_else(|| token_from_cookie(headers))
        .unwrap_or_default()
}

async fn authenticated_claims(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<TokenClaims, (StatusCode, Json<ErrorResponse>)> {
    let token = token_from_headers(headers);
    if token.is_empty() {
        return Err(unauthorized_error("missing bearer token"));
    }

    if allow_dev_bearer_bypass() {
        if let Some(user_id) = token.strip_prefix("dev-user-") {
            if !user_id.is_empty() {
                return Ok(TokenClaims {
                    iss: jwt_issuer(),
                    aud: jwt_audience(),
                    sub: user_id.to_string(),
                    wid: "dev".to_string(),
                    verification_level: "orb".to_string(),
                    iat: Utc::now().timestamp(),
                    exp: Utc::now().timestamp() + 300,
                    jti: Some(format!("dev-{}", Uuid::new_v4())),
                });
            }
        }
    }

    let claims = verify_dev_jwt(&token).map_err(|reason| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: format!("invalid bearer token: {reason}"),
            }),
        )
    })?;

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    if let Some(pool) = maybe_pool {
        let jwt_id = claims
            .jti
            .as_deref()
            .ok_or_else(|| unauthorized_error("token is missing jti"))?;
        let user_uuid = parse_user_uuid(&claims.sub)?;
        let is_active = session_is_active_in_db(&pool, user_uuid, jwt_id)
            .await
            .map_err(|message| internal_server_error(&message))?;
        if !is_active {
            return Err(unauthorized_error("session is not active"));
        }
    } else if let Some(jwt_id) = claims.jti.as_deref() {
        if is_session_jti_revoked_in_memory(state, jwt_id) {
            return Err(unauthorized_error("session is not active"));
        }
    }

    Ok(claims)
}

async fn authenticated_user_id(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let claims = authenticated_claims(state, headers).await?;
    Ok(claims.sub)
}

// ---------------------------------------------------------------------------
// P2: Dual-auth context — human session OR agent token (agt_)
// ---------------------------------------------------------------------------

/// Represents the authenticated caller — either a human via JWT/cookie session
/// or an AI agent via `agt_` access token.
#[derive(Debug, Clone)]
enum AuthContext {
    /// Human user authenticated via World ID JWT session.
    Human { user_id: String },
    /// Non-interactive agent authenticated via `agt_` access token.
    Agent {
        user_id: String,
        credential_id: Uuid,
        aid: String,
        scopes: Vec<String>,
    },
}

impl AuthContext {
    fn user_id(&self) -> &str {
        match self {
            AuthContext::Human { user_id } => user_id,
            AuthContext::Agent { user_id, .. } => user_id,
        }
    }

    /// Check whether this context has the required scope.
    /// Human sessions implicitly have all scopes.
    fn has_scope(&self, scope: &str) -> bool {
        match self {
            AuthContext::Human { .. } => true,
            AuthContext::Agent { scopes, .. } => scopes.iter().any(|s| s == scope),
        }
    }

    fn require_scope(&self, scope: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "forbidden".into(),
                    message: format!("scope '{}' is required for this operation", scope),
                }),
            ))
        }
    }
}

fn enforce_agent_bound_aid(
    ctx: &AuthContext,
    actual_aid: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if let AuthContext::Agent { aid, .. } = ctx {
        if aid != actual_aid {
            return Err(forbidden_error(
                "requested agent is not bound to the authenticated credential",
            ));
        }
    }
    Ok(())
}

/// Enforce that a message belongs to the **agent** (not just the
/// human owner) when the caller is authenticated with an agent token.
///
/// `list_messages` already calls `enforce_agent_bound_aid` on the
/// requested `agent_did` query parameter, but the per-message
/// endpoints (`GET /messages/:id/content`, `PATCH /messages/:id`,
/// `PATCH /messages/:id/flags`) look up by `owner_user_id` + `id`
/// only. That lets a compromised agent-A token access the encrypted
/// blob + mutate the flags of messages addressed to agent-B living
/// under the same human user — a cross-agent privilege escalation
/// inside a single account.
///
/// This helper resolves every active DID owned by the calling
/// agent's aid and checks that the message's `sender_did` or
/// `recipient_did` is one of them. Human (cookie) contexts are
/// passed through unchanged — humans can read their own user's
/// full inbox as before.
///
/// Returns `404 not_found` on mismatch, not `403`, so the endpoint
/// does not confirm the presence of a message the caller shouldn't
/// see (same pattern as block L2 / L3 stealth).
async fn enforce_agent_bound_message(
    pool: &PgPool,
    ctx: &AuthContext,
    sender_did: &str,
    recipient_did: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let AuthContext::Agent { aid, .. } = ctx else {
        return Ok(());
    };
    let row = sqlx::query(
        r#"
        SELECT 1
        FROM agent_identity_keys
        WHERE aid = $1
          AND status = 'active'
          AND did IN ($2, $3)
        LIMIT 1
        "#,
    )
    .bind(aid)
    .bind(sender_did)
    .bind(recipient_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| internal_error("agent-bound message lookup failed", e))?;
    if row.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "message not found".into(),
            }),
        ));
    }
    Ok(())
}

/// In-memory twin of {@link enforce_agent_bound_message} for tests
/// and dev runs without a DB. Walks `state.agents_by_user` for all
/// agents whose `aid` matches the caller and whose `did` is one of
/// the message's endpoints.
fn enforce_agent_bound_message_in_memory(
    state: &AppState,
    ctx: &AuthContext,
    sender_did: &str,
    recipient_did: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let AuthContext::Agent { aid, .. } = ctx else {
        return Ok(());
    };
    let lock = state
        .agents_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let owns = lock.values().any(|agents| {
        agents
            .iter()
            .any(|a| a.aid == *aid && (a.did == sender_did || a.did == recipient_did))
    });
    drop(lock);
    if !owns {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "message not found".into(),
            }),
        ));
    }
    Ok(())
}

/// Authenticate a request using either:
/// 1. `agt_` prefixed Bearer token → agent token lookup
/// 2. JWT cookie / Bearer JWT → human session (existing path)
///
/// This enables AI agents to call `/messages*` endpoints with the same
/// routes used by the Web UI.
async fn authenticated_context(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    uri: &str,
) -> Result<AuthContext, (StatusCode, Json<ErrorResponse>)> {
    let raw_token = token_from_headers(headers);

    // Agent token path: agt_ prefix
    if raw_token.starts_with("agt_") {
        return validate_agent_token(state, &raw_token, headers, method, uri).await;
    }

    // Fall back to human JWT session
    let user_id = authenticated_user_id(state, headers).await?;
    Ok(AuthContext::Human { user_id })
}

/// Validate an `agt_` access token against the database.
///
/// Steps:
/// 1. Compute sha256 of the token
/// 2. Look up `agent_tokens` by access_hash
/// 3. Check expiry
/// 4. Check credential status (must be 'active')
/// 5. Return AuthContext::Agent with user_id, credential_id, aid, scopes
async fn validate_agent_token(
    state: &AppState,
    token: &str,
    headers: &HeaderMap,
    method: &str,
    uri: &str,
) -> Result<AuthContext, (StatusCode, Json<ErrorResponse>)> {
    let hash = sha256_hex(token.as_bytes());

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?;
    let pool = maybe_pool.ok_or_else(|| {
        internal_server_error("database is required for agent token authentication")
    })?;

    // Single-query validation: JOIN agent_credentials → agent_identities →
    // agents so we learn all four revocation signals (token.revoked_at,
    // token expiry, credential.status, agent.is_active) in one round-trip.
    // Postgres is the source of truth for all of them; every request pays
    // this one SELECT and that's intentional — the spec asks us to stay
    // DB-first until caching becomes necessary.
    //
    // Note: revoked_at and expires_at are TIMESTAMPTZ. We don't need their
    // values — only "is this NULL?" / "is this in the past?" — so the SQL
    // side projects them to booleans. Avoids needing to enable sqlx's
    // `chrono`/`time` decode features just for two field checks.
    let row = sqlx::query(
        r#"
        SELECT
            t.id            AS token_id,
            t.credential_id AS credential_id,
            t.scopes        AS scopes,
            t.dpop_jkt      AS dpop_jkt,
            (t.revoked_at IS NOT NULL) AS token_is_revoked,
            c.status        AS credential_status,
            c.aid           AS aid,
            c.user_id       AS user_id,
            a.is_active     AS agent_is_active,
            (t.access_expires_at <= NOW()) AS is_expired
        FROM agent_tokens t
        JOIN agent_credentials c ON c.id = t.credential_id
        JOIN agent_identities ai ON ai.aid = c.aid
        JOIN agents a ON a.id = ai.agent_id
        WHERE t.access_hash = $1
        "#,
    )
    .bind(&hash)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("agent token lookup failed", e))?;

    let row = row.ok_or_else(|| unauthorized_error("invalid agent token"))?;

    // Check if token has been revoked (projected to bool server-side).
    let token_is_revoked: bool = row.get("token_is_revoked");
    if token_is_revoked {
        return Err(unauthorized_error("agent token has been revoked"));
    }

    // Check token expiry (computed server-side in SQL)
    let is_expired: bool = row.get("is_expired");
    if is_expired {
        return Err(unauthorized_error("agent token has expired"));
    }

    // Check credential status
    let cred_status: String = row.get("credential_status");
    if cred_status != "active" {
        return Err(unauthorized_error(&format!(
            "agent credential is not active (status: {})",
            cred_status
        )));
    }

    // Check that the underlying agent hasn't been deactivated. An emergency
    // shutdown flips credential status to revoked; the agent-level toggle
    // here is the soft-stop path (deactivate but keep the credentials
    // around for possible re-enablement).
    let agent_is_active: bool = row.get("agent_is_active");
    if !agent_is_active {
        return Err(unauthorized_error(
            "agent is not active (owner has deactivated it)",
        ));
    }

    // DPoP validation: if the token is bound to a DPoP key, require a valid
    // DPoP proof header on the request (RFC 9449).
    let dpop_jkt: String = row.get("dpop_jkt");
    if dpop_jkt != "none" {
        let dpop_proof = headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "dpop_required".into(),
                        message: "This token is DPoP-bound. Include a DPoP proof header.".into(),
                    }),
                )
            })?;

        if let Err(e) = validate_dpop_proof(dpop_proof, &dpop_jkt, method, uri, token, state).await
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "dpop_invalid".into(),
                    message: format!("DPoP proof validation failed: {e}"),
                }),
            ));
        }
    }

    let credential_id: Uuid = row.get("credential_id");
    let aid: String = row.get("aid");
    let user_id: Uuid = row.get("user_id");
    let scopes: Vec<String> = row.get("scopes");

    // Update last_used_at on credential (fire-and-forget)
    let pool_clone = pool.clone();
    let cred_id_clone = credential_id;
    tokio::spawn(async move {
        let _ = sqlx::query("UPDATE agent_credentials SET last_used_at = NOW() WHERE id = $1")
            .bind(cred_id_clone)
            .execute(&pool_clone)
            .await;
    });

    Ok(AuthContext::Agent {
        user_id: user_id.to_string(),
        credential_id,
        aid,
        scopes,
    })
}

fn allow_dev_bearer_bypass() -> bool {
    // SECURITY: Never allow dev bearer bypass in production environment
    if is_production_env() {
        return false;
    }
    std::env::var("AGENT_INBOX_ALLOW_DEV_BEARER")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn token_from_cookie(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(COOKIE).iter() {
        let raw = value.to_str().ok()?;
        for chunk in raw.split(';') {
            let part = chunk.trim();
            if let Some(token) = part.strip_prefix(&format!("{AUTH_COOKIE_NAME}=")) {
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }
    None
}

/// Optional `Domain=` attribute for the session cookie.
///
/// In split-host production setups (e.g. `app.nexusinbox.ai` for the
/// Next.js frontend and `api.nexusinbox.ai` for this Axum API), we need
/// the session cookie to be sent from the browser to BOTH hosts —
/// otherwise the WebSocket upgrade at `api.nexusinbox.ai/ws` has no
/// cookie and `authenticated_user_id` fails with 401.
///
/// Setting `AGENT_INBOX_COOKIE_DOMAIN=.nexusinbox.ai` promotes the
/// cookie to the registrable-domain parent so all `*.nexusinbox.ai`
/// subdomains share it. Leave unset for single-host dev (localhost) or
/// same-origin deployments where the default host-only scope is correct.
fn session_cookie_domain_attr() -> String {
    match std::env::var("AGENT_INBOX_COOKIE_DOMAIN") {
        Ok(d) if !d.trim().is_empty() => format!("; Domain={}", d.trim()),
        _ => String::new(),
    }
}

fn issue_session_cookie(token: &str) -> String {
    let secure_from_env = std::env::var("AGENT_INBOX_COOKIE_SECURE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let secure = secure_from_env || is_production_env();
    let secure_attr = if secure { "; Secure" } else { "" };
    let domain_attr = session_cookie_domain_attr();
    format!(
        "{AUTH_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECS}{secure_attr}{domain_attr}"
    )
}

fn clear_session_cookie() -> String {
    let secure_from_env = std::env::var("AGENT_INBOX_COOKIE_SECURE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let secure = secure_from_env || is_production_env();
    let secure_attr = if secure { "; Secure" } else { "" };
    // Matching Domain on the clear directive is required; without it the
    // browser treats this as a *different* cookie (host-scoped vs
    // domain-scoped) and leaves the domain-scoped session intact.
    let domain_attr = session_cookie_domain_attr();
    format!(
        "{AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure_attr}{domain_attr}"
    )
}

async fn list_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BlocksResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let rows = sqlx::query(
            r#"
            SELECT id, level, target_did, target_world_id,
                   created_at::text AS created_at
            FROM blocks
            WHERE owner_user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_uuid)
        .fetch_all(&pool)
        .await
        .map_err(|error| internal_error("failed to list blocks", error))?;
        let blocks = rows
            .into_iter()
            .map(|row| {
                use sqlx::Row;
                BlockEntry {
                    id: row.get("id"),
                    level: row.get("level"),
                    target_did: row.get("target_did"),
                    target_world_id: row.get("target_world_id"),
                    created_at: row.get("created_at"),
                }
            })
            .collect();
        return Ok(Json(BlocksResponse { blocks }));
    }

    let blocks = state
        .blocks_by_user
        .lock()
        .unwrap()
        .get(&user_id)
        .cloned()
        .unwrap_or_default();
    Ok(Json(BlocksResponse { blocks }))
}

async fn create_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<CreateBlockRequest>,
) -> Result<(StatusCode, Json<CreateBlockResponse>), (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let level = payload.level.unwrap_or_default();
    if !matches!(level.as_str(), "l1_did" | "l2_identity" | "l3_stealth") {
        return Err(validation_error(
            "level must be one of: l1_did, l2_identity, l3_stealth",
        ));
    }

    let target_did = payload
        .target_did
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let target_world_id = payload
        .target_world_id
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match level.as_str() {
        "l1_did" => {
            let did = target_did
                .as_deref()
                .ok_or_else(|| validation_error("target_did is required for l1_did blocks"))?;
            validate_did(did, "target_did")?;
        }
        "l2_identity" | "l3_stealth" => {
            if target_world_id.is_none() {
                return Err(validation_error(
                    "target_world_id is required for l2_identity and l3_stealth blocks",
                ));
            }
        }
        _ => unreachable!(),
    }

    let entry = BlockEntry {
        id: Uuid::new_v4(),
        level,
        target_did,
        target_world_id,
        created_at: Utc::now().to_rfc3339(),
    };
    let id = entry.id;

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        sqlx::query(
            r#"
            INSERT INTO blocks (id, owner_user_id, level, target_did, target_world_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(id)
        .bind(user_uuid)
        .bind(&entry.level)
        .bind(&entry.target_did)
        .bind(&entry.target_world_id)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to persist block", error))?;
        return Ok((StatusCode::CREATED, Json(CreateBlockResponse { id })));
    }

    state
        .blocks_by_user
        .lock()
        .unwrap()
        .entry(user_id)
        .or_default()
        .push(entry);
    Ok((StatusCode::CREATED, Json(CreateBlockResponse { id })))
}

/// `POST /blocks/from-message/:message_id` — register a block
/// against the sender of a message the caller has received, without
/// forcing the UI to surface / collect the sender's raw
/// `world_id_hash` (which is never returned to the recipient via any
/// existing endpoint). The server does the sender_did → user_id →
/// world_id_hash join internally so the client only passes the
/// policy `level` and the `message_id`.
///
/// Human session only — matches {@link create_block}. Agent tokens
/// cannot silently block a correspondent through a prompt-injected
/// tool call; block management stays a human-in-the-loop setting.
async fn create_block_from_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(message_id): axum::extract::Path<Uuid>,
    JsonBody(payload): JsonBody<BlockFromMessageRequest>,
) -> Result<(StatusCode, Json<BlockFromMessageResponse>), (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let level = payload.level.unwrap_or_default();
    if !matches!(level.as_str(), "l1_did" | "l2_identity" | "l3_stealth") {
        return Err(validation_error(
            "level must be one of: l1_did, l2_identity, l3_stealth",
        ));
    }

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|m| internal_server_error(&m))?;

    // Look up the message row the recipient actually owns, then
    // resolve the sender's identifier set. The recipient can only
    // block messages addressed to them — `owner_user_id` filters
    // out everything else and also returns 404 (not 403) for
    // messages the caller doesn't own, matching the stealth
    // behaviour of the rest of the read path.
    let (sender_did, sender_world_id) = if let Some(pool) = maybe_pool.as_ref() {
        let user_uuid = parse_user_uuid(&user_id)?;
        let row = sqlx::query(
            r#"
            SELECT sender_did FROM message_index
            WHERE id = $1 AND owner_user_id = $2
            LIMIT 1
            "#,
        )
        .bind(message_id)
        .bind(user_uuid)
        .fetch_optional(pool)
        .await
        .map_err(|e| internal_error("failed to load message", e))?;
        let row = row.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".into(),
                    message: "message not found".into(),
                }),
            )
        })?;
        let sender_did: String = row.get("sender_did");

        // For L2/L3 we also need the sender's world_id_hash. Walk
        // did → aid → user_id → users.world_id_hash. If the sender
        // has no row in our users table (external DID, unregistered
        // agent) the hash-based ban is meaningless — surface that
        // clearly rather than inserting a block that will never
        // match.
        let sender_world_id = if level == "l2_identity" || level == "l3_stealth" {
            let row = sqlx::query(
                r#"
                SELECT u.world_id_hash
                FROM agent_identity_keys aik
                JOIN agent_identities ai ON ai.aid = aik.aid
                JOIN users u ON u.id = ai.user_id
                WHERE aik.did = $1
                LIMIT 1
                "#,
            )
            .bind(&sender_did)
            .fetch_optional(pool)
            .await
            .map_err(|e| internal_error("failed to resolve sender", e))?;
            let row = row.ok_or_else(|| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(ErrorResponse {
                        error: "sender_not_registered".into(),
                        message:
                            "sender is not a registered NexusInbox account; L2/L3 blocks cannot resolve a World ID. Use L1 (Agent Address) to block this specific DID instead.".into(),
                    }),
                )
            })?;
            Some(row.get::<String, _>("world_id_hash"))
        } else {
            None
        };
        (sender_did, sender_world_id)
    } else {
        // In-memory fallback: look up message + agent/user in the
        // local state maps. Kept for parity with other handlers'
        // hermetic test mode; production always has a pool.
        let messages_lock = state
            .messages_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let messages = messages_lock.get(&user_id).cloned().unwrap_or_default();
        drop(messages_lock);
        let sender_did = messages
            .into_iter()
            .find(|m| m.id == message_id)
            .map(|m| m.sender_did)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".into(),
                        message: "message not found".into(),
                    }),
                )
            })?;
        // In-memory mode has no users table to consult, so
        // world_id_hash resolution always fails here. That's fine
        // for hermetic tests — the DB path is the real one.
        let sender_world_id = if level == "l2_identity" || level == "l3_stealth" {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: "sender_not_registered".into(),
                    message: "sender world_id_hash lookup requires a configured database".into(),
                }),
            ));
        } else {
            None
        };
        (sender_did, sender_world_id)
    };

    // Build the block row. L1 uses sender_did; L2/L3 use the
    // resolved world_id_hash. shape matches `create_block` so the
    // list endpoint / existing evaluate_block_decision treat it
    // identically.
    let (target_did, target_world_id) = match level.as_str() {
        "l1_did" => (Some(sender_did.clone()), None),
        "l2_identity" | "l3_stealth" => (None, sender_world_id.clone()),
        _ => unreachable!(),
    };

    let entry = BlockEntry {
        id: Uuid::new_v4(),
        level: level.clone(),
        target_did: target_did.clone(),
        target_world_id: target_world_id.clone(),
        created_at: Utc::now().to_rfc3339(),
    };
    let id = entry.id;

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        sqlx::query(
            r#"
            INSERT INTO blocks (id, owner_user_id, level, target_did, target_world_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(id)
        .bind(user_uuid)
        .bind(&entry.level)
        .bind(&entry.target_did)
        .bind(&entry.target_world_id)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to persist block", error))?;
    } else {
        state
            .blocks_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(user_id)
            .or_default()
            .push(entry);
    }

    Ok((
        StatusCode::CREATED,
        Json(BlockFromMessageResponse {
            id,
            level,
            target_did,
            target_world_id,
        }),
    ))
}

async fn delete_block(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let result = sqlx::query("DELETE FROM blocks WHERE id = $1 AND owner_user_id = $2")
            .bind(id)
            .bind(user_uuid)
            .execute(&pool)
            .await
            .map_err(|error| internal_error("failed to delete block", error))?;
        if result.rows_affected() == 0 {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    message: "block not found".to_string(),
                }),
            ));
        }
        return Ok(StatusCode::NO_CONTENT);
    }

    let mut lock = state
        .blocks_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(entries) = lock.get_mut(&user_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "block not found".to_string(),
            }),
        ));
    };
    let before = entries.len();
    entries.retain(|entry| entry.id != id);
    if entries.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "block not found".to_string(),
            }),
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

fn sanitize_contact_field(
    value: Option<String>,
    field: &str,
    max_len: usize,
) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    let trimmed = value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Some(ref v) = trimmed {
        if v.chars().count() > max_len {
            return Err(validation_error(&format!(
                "{field} must be at most {max_len} characters"
            )));
        }
    }
    Ok(trimmed)
}

fn require_contact_field(
    value: String,
    field: &str,
    max_len: usize,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(validation_error(&format!("{field} is required")));
    }
    if trimmed.chars().count() > max_len {
        return Err(validation_error(&format!(
            "{field} must be at most {max_len} characters"
        )));
    }
    Ok(trimmed)
}

async fn list_contacts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ContactsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    let contacts = if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let rows = sqlx::query(
            r#"
            SELECT
              id,
              did,
              person_name,
              agent_label,
              note,
              created_at::text AS created_at,
              updated_at::text AS updated_at
            FROM contacts
            WHERE owner_user_id = $1
            ORDER BY person_name ASC, created_at ASC
            "#,
        )
        .bind(user_uuid)
        .fetch_all(&pool)
        .await
        .map_err(|error| internal_error("failed to list contacts", error))?;

        rows.into_iter()
            .map(|row| ContactEntry {
                id: row.get("id"),
                did: row.get("did"),
                person_name: row.get("person_name"),
                agent_label: row.get("agent_label"),
                note: row.get("note"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect()
    } else {
        state
            .contacts_by_user
            .lock()
            .unwrap()
            .get(&user_id)
            .cloned()
            .unwrap_or_default()
    };

    Ok(Json(ContactsResponse { contacts }))
}

async fn create_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<CreateContactRequest>,
) -> Result<(StatusCode, Json<CreateContactResponse>), (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    validate_did(&payload.did, "did")?;
    let did = payload.did.trim().to_string();
    let person_name = require_contact_field(payload.person_name, "person_name", 64)?;
    let agent_label = sanitize_contact_field(payload.agent_label, "agent_label", 64)?;
    let note = sanitize_contact_field(payload.note, "note", 500)?;

    let id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let result = sqlx::query(
            r#"
            INSERT INTO contacts (id, owner_user_id, did, person_name, agent_label, note)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (owner_user_id, did) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(user_uuid)
        .bind(&did)
        .bind(&person_name)
        .bind(&agent_label)
        .bind(&note)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to create contact", error))?;
        if result.rows_affected() == 0 {
            return Err(conflict_error(
                "a contact for this DID already exists in your address book",
            ));
        }
    } else {
        let mut lock = state
            .contacts_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entries = lock.entry(user_id).or_default();
        if entries.iter().any(|entry| entry.did == did) {
            return Err(conflict_error(
                "a contact for this DID already exists in your address book",
            ));
        }
        entries.push(ContactEntry {
            id,
            did,
            person_name,
            agent_label,
            note,
            created_at: now.clone(),
            updated_at: now,
        });
    }

    Ok((StatusCode::CREATED, Json(CreateContactResponse { id })))
}

async fn update_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    JsonBody(payload): JsonBody<UpdateContactRequest>,
) -> Result<Json<ContactEntry>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    let person_name = match payload.person_name {
        Some(v) => Some(require_contact_field(v, "person_name", 64)?),
        None => None,
    };
    let agent_label = sanitize_contact_field(payload.agent_label, "agent_label", 64)?;
    let note = sanitize_contact_field(payload.note, "note", 500)?;

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let row_opt = sqlx::query(
            r#"
            UPDATE contacts
            SET person_name = COALESCE($3, person_name),
                agent_label = CASE WHEN $4::text IS NOT NULL THEN $4 ELSE agent_label END,
                note        = CASE WHEN $5::text IS NOT NULL THEN $5 ELSE note        END,
                updated_at  = NOW()
            WHERE id = $1 AND owner_user_id = $2
            RETURNING id, did, person_name, agent_label, note,
                      created_at::text AS created_at,
                      updated_at::text AS updated_at
            "#,
        )
        .bind(id)
        .bind(user_uuid)
        .bind(&person_name)
        .bind(&agent_label)
        .bind(&note)
        .fetch_optional(&pool)
        .await
        .map_err(|error| internal_error("failed to update contact", error))?;

        let Some(row) = row_opt else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    message: "contact not found".to_string(),
                }),
            ));
        };
        return Ok(Json(ContactEntry {
            id: row.get("id"),
            did: row.get("did"),
            person_name: row.get("person_name"),
            agent_label: row.get("agent_label"),
            note: row.get("note"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }));
    }

    let mut lock = state
        .contacts_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(entries) = lock.get_mut(&user_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "contact not found".to_string(),
            }),
        ));
    };
    let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "contact not found".to_string(),
            }),
        ));
    };
    if let Some(v) = person_name {
        entry.person_name = v;
    }
    if let Some(v) = agent_label {
        entry.agent_label = Some(v);
    }
    if let Some(v) = note {
        entry.note = Some(v);
    }
    entry.updated_at = Utc::now().to_rfc3339();
    Ok(Json(entry.clone()))
}

async fn delete_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let result = sqlx::query("DELETE FROM contacts WHERE id = $1 AND owner_user_id = $2")
            .bind(id)
            .bind(user_uuid)
            .execute(&pool)
            .await
            .map_err(|error| internal_error("failed to delete contact", error))?;
        if result.rows_affected() == 0 {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    message: "contact not found".to_string(),
                }),
            ));
        }
        return Ok(StatusCode::NO_CONTENT);
    }

    let mut lock = state
        .contacts_by_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(entries) = lock.get_mut(&user_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "contact not found".to_string(),
            }),
        ));
    };
    let before = entries.len();
    entries.retain(|entry| entry.id != id);
    if entries.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "contact not found".to_string(),
            }),
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn resolve_recipient(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<ResolveRecipientQuery>,
) -> Result<Json<RecipientResolutionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    ctx.require_scope("messages.send")?;

    let identifier = query.identifier.unwrap_or_default();
    if identifier.trim().is_empty() {
        return Err(validation_error("identifier is required"));
    }
    validate_recipient_reference(&identifier, "identifier")?;

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    let resolved = if let Some(pool) = maybe_pool {
        resolve_recipient_record_in_db(&pool, &identifier)
            .await
            .map_err(|message| internal_server_error(&message))?
    } else {
        resolve_recipient_record_in_memory(&state, &identifier)
    };

    match resolved {
        Some(value) => Ok(Json(value)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "recipient not found".into(),
            }),
        )),
    }
}

async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AgentsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    let agents = if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let rows = sqlx::query(
            r#"
            SELECT
              a.id::text AS id,
              COALESCE(ai.aid, '') AS aid,
              a.did,
              a.label,
              a.public_key,
              a.encryption_key,
              a.is_active,
              a.auto_reply,
              a.unread_count,
              a.created_at::text AS created_at
            FROM agents a
            LEFT JOIN agent_identities ai ON ai.agent_id = a.id
            WHERE a.user_id = $1
            ORDER BY a.created_at ASC
            "#,
        )
        .bind(user_uuid)
        .fetch_all(&pool)
        .await
        .map_err(|error| internal_error("failed to list agents", error))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id_text: String = row.get("id");
            let id = Uuid::parse_str(&id_text)
                .map_err(|error| internal_error("invalid agent id from database", error))?;
            out.push(Agent {
                id,
                aid: row.get("aid"),
                did: row.get("did"),
                label: row.get("label"),
                public_key: row.get("public_key"),
                encryption_key: row.get("encryption_key"),
                is_active: row.get("is_active"),
                auto_reply: row.get("auto_reply"),
                unread_count: row.get("unread_count"),
                created_at: row.get("created_at"),
            });
        }
        out
    } else {
        state
            .agents_by_user
            .lock()
            .unwrap()
            .get(&user_id)
            .cloned()
            .unwrap_or_default()
    };

    Ok(Json(AgentsResponse { agents }))
}

async fn create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<CreateAgentRequest>,
) -> Result<(StatusCode, Json<CreateAgentResponse>), (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    // Input validation
    validate_agent_label(&payload.label)?;
    validate_key_field(&payload.public_key, "public_key")?;
    validate_key_field(&payload.encryption_key, "encryption_key")?;

    if !is_valid_public_key_material(&payload.public_key) {
        return Err(validation_error(
            "public_key must be base64url-encoded Ed25519 key material (exactly 32 bytes)",
        ));
    }
    if !is_valid_public_key_material(&payload.encryption_key) {
        return Err(validation_error(
            "encryption_key must be base64url-encoded X25519 key material (exactly 32 bytes)",
        ));
    }

    let did = derive_did_from_public_key(&payload.public_key)
        .ok_or_else(|| validation_error("failed to derive did:key from public_key"))?;
    let id = Uuid::new_v4();
    let aid = format!("aid:ai:{}", Ulid::new().to_string());

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let maybe_conflict = sqlx::query("SELECT 1 FROM agents WHERE did = $1 LIMIT 1")
            .bind(&did)
            .fetch_optional(&pool)
            .await
            .map_err(|error| internal_error("failed to check agent conflict", error))?;
        if maybe_conflict.is_some() {
            return Err(conflict_error(
                "an agent for this public_key already exists",
            ));
        }

        sqlx::query(
            r#"
            INSERT INTO agents (
              id, user_id, did, label, public_key, encryption_key, is_active, auto_reply, unread_count, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, true, false, 0, NOW())
            "#,
        )
        .bind(id)
        .bind(user_uuid)
        .bind(&did)
        .bind(&payload.label)
        .bind(&payload.public_key)
        .bind(&payload.encryption_key)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to create agent", error))?;

        // Insert into agent_identities + agent_identity_keys (stable aid layer).
        sqlx::query(
            r#"
            INSERT INTO agent_identities (aid, agent_id, user_id, created_at)
            VALUES ($1, $2, $3, NOW())
            "#,
        )
        .bind(&aid)
        .bind(id)
        .bind(user_uuid)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to create agent_identity", error))?;

        sqlx::query(
            r#"
            INSERT INTO agent_identity_keys (aid, did, signing_public_key, encryption_public_key, status, activated_at)
            VALUES ($1, $2, $3, $4, 'active', NOW())
            "#,
        )
        .bind(&aid)
        .bind(&did)
        .bind(&payload.public_key)
        .bind(&payload.encryption_key)
        .execute(&pool)
        .await
        .map_err(|error| {
            internal_error("failed to create agent_identity_key", error)
        })?;
    } else {
        let agent = Agent {
            id,
            aid: aid.clone(),
            did: did.clone(),
            label: payload.label,
            public_key: payload.public_key,
            encryption_key: payload.encryption_key,
            is_active: true,
            auto_reply: false,
            unread_count: 0,
            created_at: Utc::now().to_rfc3339(),
        };

        let mut lock = state
            .agents_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let user_agents = lock.entry(user_id).or_default();
        if user_agents.iter().any(|existing| existing.did == did) {
            return Err(conflict_error(
                "an agent for this public_key already exists",
            ));
        }
        user_agents.push(agent);
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateAgentResponse { id, aid, did }),
    ))
}

#[derive(Deserialize)]
struct UpdateAgentRequest {
    label: Option<String>,
    auto_reply: Option<bool>,
}

#[derive(Serialize)]
struct UpdateAgentResponse {
    id: Uuid,
    label: String,
    auto_reply: bool,
}

/// PATCH /agents/{id}
///
/// Rename an agent or toggle auto-reply. The did / key material is
/// immutable — renaming only affects the human-readable label shown in
/// the UI and in compose contacts.
async fn update_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    JsonBody(payload): JsonBody<UpdateAgentRequest>,
) -> Result<Json<UpdateAgentResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    if payload.label.is_none() && payload.auto_reply.is_none() {
        return Err(validation_error(
            "at least one of label or auto_reply must be provided",
        ));
    }
    if let Some(label) = payload.label.as_deref() {
        validate_agent_label(label)?;
    }

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let row = sqlx::query(
            r#"
            UPDATE agents
            SET
              label      = COALESCE($1, label),
              auto_reply = COALESCE($2, auto_reply)
            WHERE id = $3 AND user_id = $4
            RETURNING label, auto_reply
            "#,
        )
        .bind(payload.label.as_deref())
        .bind(payload.auto_reply)
        .bind(agent_id)
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|error| internal_error("failed to update agent", error))?;
        if let Some(row) = row {
            return Ok(Json(UpdateAgentResponse {
                id: agent_id,
                label: row.get("label"),
                auto_reply: row.get("auto_reply"),
            }));
        }
    } else {
        let mut lock = state
            .agents_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let agents = lock.entry(user_id).or_default();
        if let Some(agent) = agents.iter_mut().find(|a| a.id == agent_id) {
            if let Some(label) = payload.label {
                agent.label = label;
            }
            if let Some(auto_reply) = payload.auto_reply {
                agent.auto_reply = auto_reply;
            }
            return Ok(Json(UpdateAgentResponse {
                id: agent.id,
                label: agent.label.clone(),
                auto_reply: agent.auto_reply,
            }));
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "not_found".to_string(),
            message: "agent not found".to_string(),
        }),
    ))
}

/// DELETE /agents/{id}
///
/// Retire an agent owned by the authenticated user. Cascade deletes
/// agent_identities, agent_identity_keys, agent_credentials, and
/// agent_tokens via ON DELETE CASCADE. message_index rows are NOT
/// deleted — they belong to the user, not the agent, so past
/// conversations remain accessible. Note that the DID stays
/// technically resolvable by anyone who still has it cached — this
/// is a best-effort "forget" rather than a revoke.
async fn delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let result = sqlx::query("DELETE FROM agents WHERE id = $1 AND user_id = $2")
            .bind(agent_id)
            .bind(user_uuid)
            .execute(&pool)
            .await
            .map_err(|error| internal_error("failed to delete agent", error))?;
        if result.rows_affected() > 0 {
            return Ok(StatusCode::NO_CONTENT);
        }
    } else {
        let mut lock = state
            .agents_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let agents = lock.entry(user_id).or_default();
        let before = agents.len();
        agents.retain(|a| a.id != agent_id);
        if agents.len() < before {
            return Ok(StatusCode::NO_CONTENT);
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "not_found".to_string(),
            message: "agent not found".to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Auto-reply policy — Phase 4.4a (docs/25)
// ---------------------------------------------------------------------------
//
// Policy storage and CRUD. The evaluator (4.4b), executor (4.4c),
// Calendar integration (4.4d), and LLM integration (4.4e) land in
// later phases; for now, these endpoints only persist the user's
// declarative intent and never triggered any automated behaviour.
// `agents.auto_reply` (BOOLEAN, migrations/0001) stays the master
// on/off switch — policy rows are only evaluated when that flag is
// true (see docs/25 §2.3).

const VALID_AUTO_REPLY_ACTIONS: &[&str] = &[
    "queue_for_human",
    "auto_accept",
    "auto_decline",
    "auto_accept_if_free", // Phase 4.4d (Calendar) — accepted at 4.4a but evaluator is UNIMPLEMENTED
    "delegate_to_llm",     // Phase 4.4e (LLM) — accepted at 4.4a but evaluator is UNIMPLEMENTED
];

const VALID_POLICY_PRIORITY_VALUES: &[&str] = &["high", "normal", "low", "background"];

const MAX_NOTE_TEMPLATE_LEN: usize = 2000;
const MAX_SENDER_ALLOWLIST_LEN: usize = 100;

#[derive(Serialize)]
struct AutoReplyPolicyResponse {
    agent_id: Uuid,
    schema_version: i32,
    revision: i64,
    policy: serde_json::Value,
    /// `None` when no row exists yet (virtual "default" state).
    /// When present, ISO 8601 stringified timestamp.
    updated_at: Option<String>,
}

#[derive(Deserialize)]
struct PutAutoReplyPolicyRequest {
    policy: serde_json::Value,
    /// Optional revision for optimistic locking. Servers prefer
    /// the `If-Match` header but accept this field as a fallback
    /// for proxies / CDNs that strip conditional-request headers.
    /// See docs/25 §6.
    #[serde(default)]
    revision: Option<i64>,
}

/// Validate a policy JSON document against docs/25 §5. Returns a
/// human-readable error string on the first failure — the caller
/// wraps it in a 422 via `validation_error`. Unknown fields are
/// ignored per the forward-compat invariant in docs/25 §9.
fn validate_auto_reply_policy(policy: &serde_json::Value) -> Result<(), String> {
    let obj = policy
        .as_object()
        .ok_or_else(|| "policy must be a JSON object".to_string())?;
    match obj.get("v").and_then(|v| v.as_u64()) {
        Some(1) => {}
        _ => return Err("policy.v must be 1".to_string()),
    }
    let default_action = obj
        .get("default_action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "policy.default_action is required".to_string())?;
    if !VALID_AUTO_REPLY_ACTIONS.contains(&default_action) {
        return Err(format!(
            "policy.default_action must be one of {}",
            VALID_AUTO_REPLY_ACTIONS.join(", ")
        ));
    }
    if let Some(protocols) = obj.get("protocols") {
        let protocols = protocols
            .as_object()
            .ok_or_else(|| "policy.protocols must be an object when present".to_string())?;
        for (type_name, type_cfg) in protocols {
            let valid_actions: &[&str] = match type_name.as_str() {
                "schedule_negotiation" => &["propose"],
                "task_delegation" => &["delegate"],
                _ => {
                    return Err(format!(
                        "policy.protocols.{type_name} is not a recognised protocol type"
                    ));
                }
            };
            let type_cfg = type_cfg
                .as_object()
                .ok_or_else(|| format!("policy.protocols.{type_name} must be an object"))?;
            for (action_name, action_cfg) in type_cfg {
                if !valid_actions.contains(&action_name.as_str()) {
                    return Err(format!(
                        "policy.protocols.{type_name}.{action_name} is not allowed for {type_name}"
                    ));
                }
                validate_auto_reply_protocol_action(type_name, action_name, action_cfg)?;
            }
        }
    }
    Ok(())
}

fn validate_auto_reply_protocol_action(
    type_name: &str,
    action_name: &str,
    cfg: &serde_json::Value,
) -> Result<(), String> {
    let cfg = cfg
        .as_object()
        .ok_or_else(|| format!("policy.protocols.{type_name}.{action_name} must be an object"))?;
    let act = cfg
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("policy.protocols.{type_name}.{action_name}.action is required"))?;
    if !VALID_AUTO_REPLY_ACTIONS.contains(&act) {
        return Err(format!(
            "policy.protocols.{type_name}.{action_name}.action must be one of {}",
            VALID_AUTO_REPLY_ACTIONS.join(", ")
        ));
    }
    if let Some(conditions) = cfg.get("conditions") {
        validate_auto_reply_conditions(type_name, action_name, conditions)?;
    }
    if let Some(nt) = cfg.get("note_template") {
        let s = nt.as_str().ok_or_else(|| {
            format!("policy.protocols.{type_name}.{action_name}.note_template must be a string")
        })?;
        if s.len() > MAX_NOTE_TEMPLATE_LEN {
            return Err(format!(
                "policy.protocols.{type_name}.{action_name}.note_template exceeds {MAX_NOTE_TEMPLATE_LEN} chars"
            ));
        }
    }
    Ok(())
}

fn validate_auto_reply_conditions(
    type_name: &str,
    action_name: &str,
    conditions: &serde_json::Value,
) -> Result<(), String> {
    let obj = conditions.as_object().ok_or_else(|| {
        format!("policy.protocols.{type_name}.{action_name}.conditions must be an object")
    })?;
    if let Some(mts) = obj.get("min_trust_score") {
        let n = mts
            .as_f64()
            .ok_or_else(|| "conditions.min_trust_score must be a number".to_string())?;
        if !(0.0..=1.0).contains(&n) {
            return Err("conditions.min_trust_score must be in [0, 1]".to_string());
        }
    }
    if let Some(rc) = obj.get("require_contact") {
        rc.as_bool()
            .ok_or_else(|| "conditions.require_contact must be a boolean".to_string())?;
    }
    if let Some(pam) = obj.get("priority_at_most") {
        let s = pam
            .as_str()
            .ok_or_else(|| "conditions.priority_at_most must be a string".to_string())?;
        if !VALID_POLICY_PRIORITY_VALUES.contains(&s) {
            return Err(format!(
                "conditions.priority_at_most must be one of {}",
                VALID_POLICY_PRIORITY_VALUES.join(", ")
            ));
        }
    }
    if let Some(sia) = obj.get("sender_in_allowlist") {
        let arr = sia
            .as_array()
            .ok_or_else(|| "conditions.sender_in_allowlist must be an array".to_string())?;
        if arr.len() > MAX_SENDER_ALLOWLIST_LEN {
            return Err(format!(
                "conditions.sender_in_allowlist exceeds {MAX_SENDER_ALLOWLIST_LEN} entries"
            ));
        }
        for (i, v) in arr.iter().enumerate() {
            let did = v
                .as_str()
                .ok_or_else(|| format!("conditions.sender_in_allowlist[{i}] must be a string"))?;
            if !did.starts_with("did:") {
                return Err(format!(
                    "conditions.sender_in_allowlist[{i}] must start with 'did:'"
                ));
            }
        }
    }
    Ok(())
}

/// Phase 4.4b auto-reply evaluator. See docs/25b for the decision
/// model, invariants, and rollout story.
///
/// The evaluator is intentionally pure: given a policy document and
/// a context, it returns exactly the same decision every time. DB /
/// network / clock side effects live in the caller so the evaluator
/// is trivially unit-testable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AutoReplyAction {
    QueueForHuman,
    AutoAccept,
    AutoDecline,
    AutoAcceptIfFree,
    DelegateToLlm,
}

impl AutoReplyAction {
    fn as_str(self) -> &'static str {
        match self {
            AutoReplyAction::QueueForHuman => "queue_for_human",
            AutoReplyAction::AutoAccept => "auto_accept",
            AutoReplyAction::AutoDecline => "auto_decline",
            AutoReplyAction::AutoAcceptIfFree => "auto_accept_if_free",
            AutoReplyAction::DelegateToLlm => "delegate_to_llm",
        }
    }

    fn parse(s: &str) -> Option<AutoReplyAction> {
        match s {
            "queue_for_human" => Some(AutoReplyAction::QueueForHuman),
            "auto_accept" => Some(AutoReplyAction::AutoAccept),
            "auto_decline" => Some(AutoReplyAction::AutoDecline),
            "auto_accept_if_free" => Some(AutoReplyAction::AutoAcceptIfFree),
            "delegate_to_llm" => Some(AutoReplyAction::DelegateToLlm),
            _ => None,
        }
    }
}

/// Priority rank: higher = more urgent. The policy condition
/// `priority_at_most` is a ceiling, so messages with rank greater
/// than the ceiling fail the check.
fn priority_rank(priority: &str) -> Option<i32> {
    match priority {
        "background" => Some(0),
        "low" => Some(1),
        "normal" => Some(2),
        "high" => Some(3),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct AutoReplyEvaluationContext {
    master_auto_reply_enabled: bool,
    priority: String,
    trust_score: f64,
    sender_did: String,
    is_contact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AutoReplyDecision {
    action: AutoReplyAction,
    reason: &'static str,
    matched_rule_path: &'static str,
    fallback_reason: Option<&'static str>,
    evaluator_mode: &'static str,
}

const AUTO_REPLY_EVALUATOR_MODE_SERVER_V1: &str = "server_metadata_v1";

/// Evaluate a stored policy against a server-side metadata context.
///
/// Returns `queue_for_human` for any condition the caller cannot
/// safely auto-dispatch — see docs/25b §4.4 for the resolution order
/// and reason codes.
fn evaluate_auto_reply_policy(
    policy: &serde_json::Value,
    ctx: &AutoReplyEvaluationContext,
) -> AutoReplyDecision {
    // Master switch always wins. A disabled agent never auto-replies
    // even if a policy row exists.
    if !ctx.master_auto_reply_enabled {
        return AutoReplyDecision {
            action: AutoReplyAction::QueueForHuman,
            reason: "master_off",
            matched_rule_path: "master",
            fallback_reason: None,
            evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
        };
    }

    let obj = match policy.as_object() {
        Some(o) if !o.is_empty() => o,
        _ => {
            return AutoReplyDecision {
                action: AutoReplyAction::QueueForHuman,
                reason: "no_policy",
                matched_rule_path: "default",
                fallback_reason: None,
                evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
            };
        }
    };

    match obj.get("v").and_then(|v| v.as_u64()) {
        Some(1) => {}
        _ => {
            return AutoReplyDecision {
                action: AutoReplyAction::QueueForHuman,
                reason: "unsupported_schema",
                matched_rule_path: "default",
                fallback_reason: None,
                evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
            };
        }
    }

    let default_action_str = match obj.get("default_action").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return AutoReplyDecision {
                action: AutoReplyAction::QueueForHuman,
                reason: "no_policy",
                matched_rule_path: "default",
                fallback_reason: None,
                evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
            };
        }
    };
    let default_action = match AutoReplyAction::parse(default_action_str) {
        Some(a) => a,
        None => {
            return AutoReplyDecision {
                action: AutoReplyAction::QueueForHuman,
                reason: "invalid_policy",
                matched_rule_path: "default",
                fallback_reason: None,
                evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
            };
        }
    };

    // Evaluate `default_conditions` if present. Unknown / mistyped
    // fields are treated as violations (defensive) so a corrupted
    // policy can never silently loosen the safety check.
    if let Some(conditions) = obj.get("default_conditions") {
        if let Some(reason) = evaluate_auto_reply_conditions(conditions, ctx) {
            return AutoReplyDecision {
                action: AutoReplyAction::QueueForHuman,
                reason,
                matched_rule_path: "default",
                fallback_reason: None,
                evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
            };
        }
    }

    // Actions that require external I/O (Calendar, LLM) aren't wired
    // up yet. Fall back to human review until 4.4d/4.4e land.
    match default_action {
        AutoReplyAction::AutoAcceptIfFree => AutoReplyDecision {
            action: AutoReplyAction::QueueForHuman,
            reason: "calendar_unavailable",
            matched_rule_path: "default",
            fallback_reason: Some("calendar_unavailable"),
            evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
        },
        AutoReplyAction::DelegateToLlm => AutoReplyDecision {
            action: AutoReplyAction::QueueForHuman,
            reason: "llm_unavailable",
            matched_rule_path: "default",
            fallback_reason: Some("llm_unavailable"),
            evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
        },
        _ => AutoReplyDecision {
            action: default_action,
            reason: "default_match",
            matched_rule_path: "default",
            fallback_reason: None,
            evaluator_mode: AUTO_REPLY_EVALUATOR_MODE_SERVER_V1,
        },
    }
}

/// Returns `Some(reason)` on the first condition violation, `None`
/// when all conditions pass or are absent.
fn evaluate_auto_reply_conditions(
    conditions: &serde_json::Value,
    ctx: &AutoReplyEvaluationContext,
) -> Option<&'static str> {
    let obj = conditions.as_object()?;

    if let Some(pam) = obj.get("priority_at_most").and_then(|v| v.as_str()) {
        match (priority_rank(&ctx.priority), priority_rank(pam)) {
            (Some(msg), Some(cap)) if msg > cap => return Some("priority_exceeds_policy"),
            (None, _) => return Some("invalid_policy"),
            (_, None) => return Some("invalid_policy"),
            _ => {}
        }
    }

    if let Some(mts) = obj.get("min_trust_score").and_then(|v| v.as_f64()) {
        if ctx.trust_score < mts {
            return Some("trust_below_threshold");
        }
    }

    if let Some(true) = obj.get("require_contact").and_then(|v| v.as_bool()) {
        if !ctx.is_contact {
            return Some("not_a_contact");
        }
    }

    if let Some(sia) = obj.get("sender_in_allowlist").and_then(|v| v.as_array()) {
        let allowed = sia
            .iter()
            .any(|v| v.as_str() == Some(ctx.sender_did.as_str()));
        if !allowed {
            return Some("sender_not_in_allowlist");
        }
    }

    None
}

/// Read the 4.4b evaluator gate once per call. Values other than
/// "off" (case-insensitive) enable the evaluator; default is on.
/// See docs/25b §7 for the staging story.
fn auto_reply_evaluator_gate() -> &'static str {
    static GATE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    GATE.get_or_init(|| {
        std::env::var("AGENT_INBOX_AUTO_REPLY_EVALUATOR")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    })
}

fn auto_reply_evaluator_enabled() -> bool {
    !matches!(auto_reply_evaluator_gate(), "off")
}

/// Fire-and-forget evaluator for a freshly-inserted recipient-side
/// `message_index` row. Safe to call for every delivery; a no-op
/// when the recipient DID does not resolve to an agent we own, or
/// when the env gate is "off".
fn spawn_auto_reply_evaluation(
    pool: PgPool,
    recipient_user_id: Uuid,
    recipient_message_id: Uuid,
    recipient_did: String,
    sender_did: String,
    priority: String,
    trust_score: f64,
) {
    if !auto_reply_evaluator_enabled() {
        return;
    }
    tokio::spawn(async move {
        let row = match sqlx::query(
            r#"
            SELECT
              a.id               AS agent_id,
              a.auto_reply       AS master_auto_reply_enabled,
              p.policy           AS policy,
              p.revision         AS policy_revision,
              EXISTS (
                SELECT 1 FROM contacts c
                WHERE c.owner_user_id = $1 AND c.did = $3
              ) AS is_contact
            FROM agent_identity_keys aik
            JOIN agent_identities ai ON ai.aid = aik.aid
            JOIN agents a ON a.id = ai.agent_id
            LEFT JOIN agent_auto_reply_policies p ON p.agent_id = a.id
            WHERE aik.did = $2 AND a.user_id = $1
            LIMIT 1
            "#,
        )
        .bind(recipient_user_id)
        .bind(&recipient_did)
        .bind(&sender_did)
        .fetch_optional(&pool)
        .await
        {
            Ok(Some(row)) => row,
            Ok(None) => return, // recipient agent not owned here; nothing to evaluate
            Err(error) => {
                eprintln!("auto_reply_evaluator: context query failed: {error}");
                return;
            }
        };

        let agent_id: Uuid = row.get("agent_id");
        let master: bool = row.get("master_auto_reply_enabled");
        let policy: serde_json::Value = row
            .try_get::<serde_json::Value, _>("policy")
            .unwrap_or_else(|_| serde_json::json!({}));
        let policy_revision: Option<i64> = row.try_get("policy_revision").ok();
        let is_contact: bool = row.get("is_contact");

        let ctx = AutoReplyEvaluationContext {
            master_auto_reply_enabled: master,
            priority,
            trust_score,
            sender_did: sender_did.clone(),
            is_contact,
        };
        let decision = evaluate_auto_reply_policy(&policy, &ctx);

        let detail = serde_json::json!({
            "message_id": recipient_message_id.to_string(),
            "agent_id": agent_id.to_string(),
            "sender_did": sender_did,
            "decision": {
                "action": decision.action.as_str(),
                "reason": decision.reason,
                "matched_rule_path": decision.matched_rule_path,
                "fallback_reason": decision.fallback_reason,
            },
            "policy_revision": policy_revision,
            "evaluator_mode": decision.evaluator_mode,
        });
        record_audit_event(
            pool.clone(),
            recipient_user_id,
            None,
            None,
            "auto_reply_evaluated",
            detail,
        );

        // message_index column UPDATE is best-effort cache for the
        // inbox list; the audit event above is the source of truth.
        if let Err(error) = sqlx::query(
            r#"
            UPDATE message_index
               SET auto_reply_decision = $1,
                   auto_reply_reason   = $2
             WHERE id = $3 AND owner_user_id = $4
            "#,
        )
        .bind(decision.action.as_str())
        .bind(decision.reason)
        .bind(recipient_message_id)
        .bind(recipient_user_id)
        .execute(&pool)
        .await
        {
            eprintln!("auto_reply_evaluator: cache UPDATE failed: {error}");
        }
    });
}

/// Pull the expected row revision out of an `If-Match` header.
/// Accepts either the bare number ("42") or the RFC 7232 quoted
/// form ("\"42\""); clients in the wild send both. Returns `None`
/// when the header is absent or malformed — callers then look at
/// the body's `revision` field as a second source, and finally
/// treat a missing value as "skip the check" (rare, but needed
/// for initial create calls). See docs/25 §6.
fn extract_if_match_revision(headers: &HeaderMap) -> Option<i64> {
    let header_val = headers.get("if-match")?.to_str().ok()?;
    let trimmed = header_val.trim().trim_matches('"');
    trimmed.parse::<i64>().ok()
}

fn etag_from_revision(revision: i64) -> String {
    format!("\"{revision}\"")
}

async fn ensure_agent_owned_by_user(
    pool: &PgPool,
    agent_id: Uuid,
    user_uuid: Uuid,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let exists = sqlx::query("SELECT id FROM agents WHERE id = $1 AND user_id = $2")
        .bind(agent_id)
        .bind(user_uuid)
        .fetch_optional(pool)
        .await
        .map_err(|e| internal_error("agent lookup failed", e))?;
    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "agent not found".into(),
            }),
        ));
    }
    Ok(())
}

/// GET /agents/:id/auto-reply-policy — returns the current policy
/// row for the agent. When no row exists, returns an empty-policy
/// default with `revision: 0` so clients can unconditionally PUT
/// the first value without reading twice.
async fn get_auto_reply_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;
    ensure_agent_owned_by_user(&pool, agent_id, user_uuid).await?;

    let row = sqlx::query(
        r#"
        SELECT schema_version, revision, policy, updated_at::text AS updated_at
        FROM agent_auto_reply_policies
        WHERE agent_id = $1
        "#,
    )
    .bind(agent_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("policy fetch failed", e))?;

    let (body, etag) = match row {
        Some(r) => {
            let rev: i64 = r.get("revision");
            let resp = AutoReplyPolicyResponse {
                agent_id,
                schema_version: r.get("schema_version"),
                revision: rev,
                policy: r.get("policy"),
                updated_at: r.get("updated_at"),
            };
            (resp, etag_from_revision(rev))
        }
        None => {
            let resp = AutoReplyPolicyResponse {
                agent_id,
                schema_version: 1,
                revision: 0,
                policy: serde_json::json!({}),
                updated_at: None,
            };
            (resp, etag_from_revision(0))
        }
    };

    let mut response = Json(body).into_response();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    Ok(response)
}

/// PUT /agents/:id/auto-reply-policy — replace the stored policy.
/// Optimistic locking: when an `If-Match` header (or body
/// `revision` field) is provided, the value must equal the
/// current row's revision; otherwise 409. When neither is
/// provided we only succeed if the row doesn't exist yet
/// (effectively "create if absent") so a concurrent create+put
/// race can't silently overwrite.
async fn put_auto_reply_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    JsonBody(payload): JsonBody<PutAutoReplyPolicyRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;
    ensure_agent_owned_by_user(&pool, agent_id, user_uuid).await?;

    validate_auto_reply_policy(&payload.policy)
        .map_err(|e| validation_error(&format!("policy validation failed: {e}")))?;

    let expected_rev = extract_if_match_revision(&headers).or(payload.revision);

    let existing =
        sqlx::query("SELECT revision, policy FROM agent_auto_reply_policies WHERE agent_id = $1")
            .bind(agent_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| internal_error("policy fetch failed", e))?;
    let (prev_rev, prev_policy) = match existing {
        Some(r) => (
            r.get::<i64, _>("revision"),
            Some(r.get::<serde_json::Value, _>("policy")),
        ),
        None => (0_i64, None),
    };

    // If the caller supplied an expected revision, enforce it.
    // If they didn't and a row already exists, treat that as an
    // unconditional overwrite attempt and reject — otherwise we'd
    // silently clobber a value the caller never saw.
    let caller_expected = match expected_rev {
        Some(v) => v,
        None => prev_rev,
    };
    if caller_expected != prev_rev {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "revision_conflict".into(),
                message: format!(
                    "expected revision {caller_expected} but server state is at revision {prev_rev}. Refresh and reapply."
                ),
            }),
        ));
    }
    if expected_rev.is_none() && prev_policy.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "revision_conflict".into(),
                message: "policy already exists; retry with If-Match to confirm the overwrite."
                    .into(),
            }),
        ));
    }

    let new_rev = prev_rev + 1;
    let is_create = prev_policy.is_none();

    sqlx::query(
        r#"
        INSERT INTO agent_auto_reply_policies
            (agent_id, schema_version, revision, policy, updated_by_user_id, created_at, updated_at)
        VALUES ($1, 1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (agent_id) DO UPDATE
            SET revision = EXCLUDED.revision,
                policy = EXCLUDED.policy,
                updated_by_user_id = EXCLUDED.updated_by_user_id,
                updated_at = NOW()
        "#,
    )
    .bind(agent_id)
    .bind(new_rev)
    .bind(&payload.policy)
    .bind(user_uuid)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("policy upsert failed", e))?;

    let updated_at: Option<String> = sqlx::query_scalar(
        "SELECT updated_at::text FROM agent_auto_reply_policies WHERE agent_id = $1",
    )
    .bind(agent_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("policy post-read failed", e))?;

    let event = if is_create {
        "auto_reply_policy_created"
    } else {
        "auto_reply_policy_updated"
    };
    record_audit_event(
        pool.clone(),
        user_uuid,
        None,
        None,
        event,
        serde_json::json!({
            "agent_id": agent_id.to_string(),
            "prev": prev_policy,
            "next": payload.policy.clone(),
            "revision_before": prev_rev,
            "revision_after": new_rev,
        }),
    );

    let body = AutoReplyPolicyResponse {
        agent_id,
        schema_version: 1,
        revision: new_rev,
        policy: payload.policy,
        updated_at,
    };
    let etag = etag_from_revision(new_rev);
    let mut response = Json(body).into_response();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    Ok(response)
}

/// DELETE /agents/:id/auto-reply-policy — drop the stored row.
/// Idempotent: always returns 204, even if no row existed.
/// Audit event is only recorded when an actual row was deleted.
async fn delete_auto_reply_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;
    ensure_agent_owned_by_user(&pool, agent_id, user_uuid).await?;

    let row =
        sqlx::query("SELECT revision, policy FROM agent_auto_reply_policies WHERE agent_id = $1")
            .bind(agent_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| internal_error("policy fetch failed", e))?;

    if let Some(r) = row {
        let prev_rev: i64 = r.get("revision");
        let prev_policy: serde_json::Value = r.get("policy");
        sqlx::query("DELETE FROM agent_auto_reply_policies WHERE agent_id = $1")
            .bind(agent_id)
            .execute(&pool)
            .await
            .map_err(|e| internal_error("policy delete failed", e))?;
        record_audit_event(
            pool.clone(),
            user_uuid,
            None,
            None,
            "auto_reply_policy_deleted",
            serde_json::json!({
                "agent_id": agent_id.to_string(),
                "prev": prev_policy,
                "revision_before": prev_rev,
            }),
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Agent Credentials — non-interactive access (docs/15 v2)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateAgentCredentialRequest {
    agent_id: Uuid,
    label: String,
    scopes: Option<Vec<String>>,
}

#[derive(Serialize)]
struct AgentCredentialResponse {
    credential_id: Uuid,
    aid: String,
    label: String,
    status: String,
    allowed_scopes: Vec<String>,
    enrollment_secret: Option<String>,
    enrollment_expires_at: Option<String>,
    created_at: String,
    activated_at: Option<String>,
    last_used_at: Option<String>,
    // Present only for status='revoked'. Used client-side to show the
    // grace-period countdown on the purge button.
    revoked_at: Option<String>,
    /// Where the private-key material for this credential lives. One of
    /// `"web_keystore"` / `"signer_daemon"` / `"unknown"`. Pre-migration
    /// credentials surface as `"unknown"`; the Web UI treats that as
    /// Standard mode for display purposes. See
    /// docs/21_message_visibility_ux_for_mcp_modes.md §7.
    key_holder: String,
}

#[derive(Serialize)]
struct AgentCredentialsListResponse {
    credentials: Vec<AgentCredentialResponse>,
}

fn generate_enrollment_secret() -> String {
    let mut buf = [0u8; 32];
    rand::fill(&mut buf);
    format!("ens_{}", URL_SAFE_NO_PAD.encode(buf))
}

const VALID_SCOPES: &[&str] = &["messages.read", "messages.send", "messages.delete"];

/// POST /agent-credentials — create a new credential (enrollment secret).
/// Requires human Cookie session.
async fn create_agent_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<CreateAgentCredentialRequest>,
) -> Result<(StatusCode, Json<AgentCredentialResponse>), (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;

    // Validate label
    let label = payload.label.trim().to_string();
    if label.is_empty() || label.len() > 64 {
        return Err(validation_error("label must be 1-64 characters"));
    }

    // Validate scopes
    let scopes: Vec<String> = payload
        .scopes
        .unwrap_or_else(|| vec!["messages.read".into(), "messages.send".into()]);
    for scope in &scopes {
        if !VALID_SCOPES.contains(&scope.as_str()) {
            return Err(validation_error(&format!("invalid scope: {scope}")));
        }
    }

    // Verify agent belongs to user and has an aid
    let aid_row = sqlx::query(
        r#"
        SELECT ai.aid
        FROM agents a
        JOIN agent_identities ai ON ai.agent_id = a.id
        WHERE a.id = $1 AND a.user_id = $2
        LIMIT 1
        "#,
    )
    .bind(payload.agent_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("failed to look up agent", e))?;

    let aid: String = match aid_row {
        Some(row) => row.get("aid"),
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".into(),
                    message: "agent not found or missing identity".into(),
                }),
            ));
        }
    };

    let secret = generate_enrollment_secret();
    let enrollment_hash = sha256_hex(secret.as_bytes());
    let expires = (Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
    let cred_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO agent_credentials (
            id, aid, user_id, label, status,
            enrollment_hash, enrollment_expires, allowed_scopes, created_at
        ) VALUES ($1, $2, $3, $4, 'pending', $5, $6::timestamptz, $7, NOW())
        "#,
    )
    .bind(cred_id)
    .bind(&aid)
    .bind(user_uuid)
    .bind(&label)
    .bind(&enrollment_hash)
    .bind(&expires)
    .bind(&scopes as &[String])
    .execute(&pool)
    .await
    .map_err(|e| internal_error("failed to create credential", e))?;

    Ok((
        StatusCode::CREATED,
        Json(AgentCredentialResponse {
            credential_id: cred_id,
            aid,
            label,
            status: "pending".into(),
            allowed_scopes: scopes,
            enrollment_secret: Some(secret), // plaintext returned ONLY here
            enrollment_expires_at: Some(expires.clone()),
            created_at: Utc::now().to_rfc3339(),
            activated_at: None,
            last_used_at: None,
            revoked_at: None,
            // Pending credential has no key material yet — the
            // activation call records the real holder. `unknown` is
            // the natural "not set" state per the 0014 default.
            key_holder: "unknown".into(),
        }),
    ))
}

/// GET /agent-credentials — list credentials for the current user.
async fn list_agent_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AgentCredentialsListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;

    let rows = sqlx::query(
        r#"
        SELECT
            id::text, aid, label, status,
            allowed_scopes,
            key_holder,
            created_at::text AS created_at,
            activated_at::text AS activated_at,
            last_used_at::text AS last_used_at,
            enrollment_expires::text AS enrollment_expires,
            revoked_at::text AS revoked_at
        FROM agent_credentials
        WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_uuid)
    .fetch_all(&pool)
    .await
    .map_err(|e| internal_error("failed to list credentials", e))?;

    let mut credentials = Vec::with_capacity(rows.len());
    for row in rows {
        let id_str: String = row.get("id");
        let credential_id =
            Uuid::parse_str(&id_str).map_err(|e| internal_error("invalid credential id", e))?;
        // Only surface enrollment_expires while the credential is still
        // pending; once it's active or revoked, the field is historical
        // noise and we also cleared it during activation.
        let status: String = row.get("status");
        let enrollment_expires_at: Option<String> = if status == "pending" {
            row.get::<Option<String>, _>("enrollment_expires")
        } else {
            None
        };
        credentials.push(AgentCredentialResponse {
            credential_id,
            aid: row.get("aid"),
            label: row.get("label"),
            status,
            allowed_scopes: row.get("allowed_scopes"),
            enrollment_secret: None, // never returned after creation
            enrollment_expires_at,
            created_at: row
                .get::<Option<String>, _>("created_at")
                .unwrap_or_default(),
            activated_at: row.get("activated_at"),
            last_used_at: row.get("last_used_at"),
            revoked_at: row.get("revoked_at"),
            key_holder: row.get("key_holder"),
        });
    }

    Ok(Json(AgentCredentialsListResponse { credentials }))
}

/// DELETE /agent-credentials/:id — revoke a credential immediately.
async fn revoke_agent_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;

    let actor_ip = extract_client_ip(&headers);
    let actor_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Revoke credential
    let result = sqlx::query(
        r#"
        UPDATE agent_credentials
        SET status = 'revoked', revoked_at = NOW()
        WHERE id = $1 AND user_id = $2 AND status IN ('pending', 'active')
        "#,
    )
    .bind(credential_id)
    .bind(user_uuid)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("failed to revoke credential", e))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "credential not found or already revoked".into(),
            }),
        ));
    }

    // Also revoke all tokens for this credential
    let token_result = sqlx::query(
        "UPDATE agent_tokens SET revoked_at = NOW() WHERE credential_id = $1 AND revoked_at IS NULL",
    )
    .bind(credential_id)
    .execute(&pool)
    .await;
    let tokens_revoked = token_result.map(|r| r.rows_affected()).unwrap_or(0);

    // Audit: credential_revoked
    record_audit_event(
        pool.clone(),
        user_uuid,
        Some(credential_id),
        None,
        "credential_revoked",
        serde_json::json!({
            "method": "manual_revoke",
            "actor_type": "human",
            "actor_user_id": user_uuid.to_string(),
            "actor_ip": actor_ip,
            "actor_user_agent": actor_user_agent,
            "tokens_revoked": tokens_revoked,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Minimum time a credential must stay in `status='revoked'` before the
/// user is allowed to purge the row. Keeps a retention window where the
/// audit log still has a live FK so support can cross-reference a recent
/// revoke without inner-joining against snapshot fields in the detail.
const CREDENTIAL_PURGE_GRACE_DAYS: i64 = 7;

/// How many failed `POST /agent-credentials/:id/activate` attempts
/// the server tolerates before burning the credential. Each wrong
/// `enrollment_secret` or failed `enrollment_proof` bumps the
/// counter; reaching this threshold flips the credential to
/// `revoked` so the legitimate owner must issue a new one. Chosen
/// at 5 because (a) 43-char secrets make raw brute force infeasible
/// anyway — the counter defends against UUID leakage + focused
/// attempts — and (b) 5 gives honest clients headroom for
/// transient paste errors without cratering the pairing UX.
const ACTIVATION_MAX_FAILED_ATTEMPTS: i32 = 5;

/// POST /agent-credentials/:id/purge — physically delete a revoked
/// credential row.
///
/// This is intentionally separate from `DELETE /agent-credentials/:id`
/// (which is the *revoke* path). Overloading one endpoint with two
/// semantics is a support footgun.
///
/// Eligibility: the row must be `status='revoked'` AND `revoked_at` at
/// least `CREDENTIAL_PURGE_GRACE_DAYS` in the past. Active, pending, or
/// freshly-revoked rows return 409 Conflict with a clear reason.
///
/// Audit: before the DELETE we emit a `credential_purged` event whose
/// `detail` carries a denormalised snapshot (`credential_id_text`,
/// `aid_snapshot`, `label_snapshot`, `revoked_at_snapshot`). Because
/// `agent_audit_log.credential_id` is `ON DELETE SET NULL`, the
/// post-delete audit row would otherwise lose its FK link. The snapshot
/// preserves enough to tell "which credential was this" after the
/// physical row is gone.
async fn purge_agent_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;

    let actor_ip = extract_client_ip(&headers);
    let actor_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Ownership + eligibility check in one query. We read status,
    // revoked_at, aid, label together so the audit snapshot below is
    // built from a consistent read.
    let row = sqlx::query(
        r#"
        SELECT
            id::text AS id_text,
            aid,
            label,
            status,
            revoked_at::text AS revoked_at_text,
            revoked_at IS NOT NULL
              AND revoked_at <= NOW() - make_interval(days => $3::int) AS purge_eligible
        FROM agent_credentials
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(credential_id)
    .bind(user_uuid)
    .bind(CREDENTIAL_PURGE_GRACE_DAYS as i32)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("failed to look up credential", e))?;

    let row = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "credential not found".into(),
            }),
        )
    })?;

    let status: String = row.get("status");
    if status != "revoked" {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "purge_ineligible".into(),
                message: format!(
                    "credential must be revoked before purge (current status: {})",
                    status
                ),
            }),
        ));
    }
    let eligible: bool = row.get("purge_eligible");
    if !eligible {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "purge_grace_period".into(),
                message: format!(
                    "credential must remain revoked for at least {} days before purge",
                    CREDENTIAL_PURGE_GRACE_DAYS
                ),
            }),
        ));
    }

    let credential_id_text: String = row.get("id_text");
    let aid_snapshot: String = row.get("aid");
    let label_snapshot: String = row.get("label");
    let revoked_at_snapshot: Option<String> = row.get("revoked_at_text");

    // Audit the purge SYNCHRONOUSLY, before the DELETE. The audit table's
    // credential_id is ON DELETE SET NULL, so a fire-and-forget spawn
    // would race the DELETE — if the spawn's INSERT lands after the
    // DELETE, the FK check rejects it (credential no longer exists) and
    // the event vanishes. Awaiting here guarantees the audit row is
    // committed first; the `credential_id` FK is then nulled later by
    // the DELETE cascade, and the snapshot fields below preserve
    // identifiability.
    let audit_detail = serde_json::json!({
        "credential_id_text": credential_id_text,
        "aid_snapshot": aid_snapshot,
        "label_snapshot": label_snapshot,
        "revoked_at_snapshot": revoked_at_snapshot,
        "actor_type": "human",
        "actor_user_id": user_uuid.to_string(),
        "actor_ip": actor_ip,
        "actor_user_agent": actor_user_agent,
    });
    sqlx::query(
        r#"
        INSERT INTO agent_audit_log (user_id, credential_id, aid, event, detail)
        VALUES ($1, $2, $3, 'credential_purged', $4)
        "#,
    )
    .bind(user_uuid)
    .bind(credential_id)
    .bind(&aid_snapshot)
    .bind(&audit_detail)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("failed to record purge audit", e))?;

    // Physical delete. Tokens are already revoked by the preceding
    // revoke_agent_credential; the `agent_tokens` FK cascade will clean
    // up any rows we missed.
    let delete_result = sqlx::query(
        r#"
        DELETE FROM agent_credentials
        WHERE id = $1 AND user_id = $2 AND status = 'revoked'
          AND revoked_at IS NOT NULL
          AND revoked_at <= NOW() - make_interval(days => $3::int)
        "#,
    )
    .bind(credential_id)
    .bind(user_uuid)
    .bind(CREDENTIAL_PURGE_GRACE_DAYS as i32)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("failed to purge credential", e))?;

    if delete_result.rows_affected() == 0 {
        // Raced with another purge or a state change between our SELECT
        // and DELETE. Surface a retryable error instead of a cryptic 204.
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "purge_raced".into(),
                message: "credential state changed during purge — retry".into(),
            }),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// P8: Missing endpoints — activate, PATCH, rotate, self-revoke
// ---------------------------------------------------------------------------

/// POST /agent-credentials/:id/activate — Signer Daemon submits public keys
/// to activate a pending credential.
///
/// The caller proves ownership of the signing key by submitting a JWS proof
/// signed with the Ed25519 key that includes the credential_id.
#[derive(Deserialize)]
struct ActivateCredentialRequest {
    enrollment_secret: String,
    signing_public_key: String,
    encryption_public_key: String,
    /// JWS compact serialization proving ownership of signing_public_key.
    /// Payload must include: credential_id, iat.
    enrollment_proof: String,
    /// Optional hint from the activating client about where the
    /// private-key material will live. Mirrors the `AgentKeyHolder`
    /// enum in @nexusinbox/core. Accepted values: `"web_keystore"`,
    /// `"signer_daemon"`, `"unknown"`. Omitted / unrecognised values
    /// are stored as `"unknown"` and the Web UI falls back to Standard mode
    /// rendering, matching pre-migration behaviour. See
    /// docs/21_message_visibility_ux_for_mcp_modes.md §7.
    #[serde(default)]
    key_holder: Option<String>,
}

/// Clamp an incoming `key_holder` string to the allowed set. The DB
/// CHECK constraint already enforces this but the Rust side filters
/// first so a malformed value doesn't surface a 500 — it silently
/// downgrades to `unknown`, which is the safer UX.
fn normalise_key_holder(raw: Option<&str>) -> &'static str {
    match raw {
        Some("web_keystore") => "web_keystore",
        Some("signer_daemon") => "signer_daemon",
        _ => "unknown",
    }
}

async fn activate_agent_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<Uuid>,
    JsonBody(payload): JsonBody<ActivateCredentialRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;

    // Look up the credential
    let cred_row = sqlx::query(
        r#"
        SELECT
            id, aid, user_id, status, enrollment_hash,
            failed_activation_attempts,
            (enrollment_expires <= NOW()) AS is_expired
        FROM agent_credentials
        WHERE id = $1 AND status = 'pending'
        "#,
    )
    .bind(credential_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("credential lookup failed", e))?;

    let cred_row = cred_row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "credential not found or not in pending status".into(),
            }),
        )
    })?;

    let is_expired: bool = cred_row.get("is_expired");
    if is_expired {
        return Err(validation_error("enrollment has expired"));
    }

    let current_attempts: i32 = cred_row.try_get("failed_activation_attempts").unwrap_or(0);
    let user_id_for_audit: Uuid = cred_row.get("user_id");
    let aid_for_audit: String = cred_row.get("aid");

    // Shared failure path: bump the per-credential counter, and when
    // it crosses `ACTIVATION_MAX_FAILED_ATTEMPTS`, burn the
    // credential. Even if the caller knows the credential UUID they
    // get at most N guesses at the 43-char secret before the row is
    // revoked and they have to start over with a fresh enrollment.
    //
    // Returns the "real" error to hand back to the caller — the
    // auto-revoke path returns its own 401 to communicate the
    // stricter outcome. Using a helper closure keeps the error
    // payloads at the original callsites while centralising the
    // policy logic.
    async fn record_failed_attempt(
        pool: &PgPool,
        credential_id: Uuid,
        user_id: Uuid,
        aid: String,
        current_attempts: i32,
        origin_error: (StatusCode, Json<ErrorResponse>),
    ) -> (StatusCode, Json<ErrorResponse>) {
        // Atomic increment + optional auto-revoke. Branching inside
        // the CASE keeps the behaviour race-safe: two concurrent
        // failing requests both increment and both see the final
        // value via RETURNING.
        let updated = sqlx::query(
            r#"
            UPDATE agent_credentials
            SET failed_activation_attempts = failed_activation_attempts + 1,
                status = CASE
                    WHEN failed_activation_attempts + 1 >= $2 THEN 'revoked'
                    ELSE status
                END,
                revoked_at = CASE
                    WHEN failed_activation_attempts + 1 >= $2 AND revoked_at IS NULL THEN NOW()
                    ELSE revoked_at
                END,
                enrollment_hash = CASE
                    WHEN failed_activation_attempts + 1 >= $2 THEN NULL
                    ELSE enrollment_hash
                END,
                enrollment_expires = CASE
                    WHEN failed_activation_attempts + 1 >= $2 THEN NULL
                    ELSE enrollment_expires
                END
            WHERE id = $1
            RETURNING failed_activation_attempts, status
            "#,
        )
        .bind(credential_id)
        .bind(ACTIVATION_MAX_FAILED_ATTEMPTS)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

        let auto_revoked = updated
            .as_ref()
            .and_then(|row| row.try_get::<String, _>("status").ok())
            .map(|status| status == "revoked")
            .unwrap_or(false);

        // Every failure emits an audit event so operators can spot
        // brute-force attempts even before the auto-revoke trips.
        record_audit_event(
            pool.clone(),
            user_id,
            Some(credential_id),
            Some(aid),
            if auto_revoked {
                "credential_auto_revoked"
            } else {
                "credential_activation_failed"
            },
            serde_json::json!({
                "previous_attempts": current_attempts,
                "new_attempts": current_attempts + 1,
                "threshold": ACTIVATION_MAX_FAILED_ATTEMPTS,
                "auto_revoked": auto_revoked,
            }),
        );

        if auto_revoked {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "credential_revoked".into(),
                    message: format!(
                        "credential has been auto-revoked after {} failed activation attempts; issue a fresh credential",
                        ACTIVATION_MAX_FAILED_ATTEMPTS
                    ),
                }),
            )
        } else {
            origin_error
        }
    }

    // Verify enrollment secret (constant-time comparison via sha256)
    let stored_hash: Option<String> = cred_row.get("enrollment_hash");
    let stored_hash = stored_hash.ok_or_else(|| {
        validation_error("credential has no enrollment hash (already activated?)")
    })?;
    let provided_hash = sha256_hex(payload.enrollment_secret.as_bytes());
    if !constant_time_eq(stored_hash.as_bytes(), provided_hash.as_bytes()) {
        return Err(record_failed_attempt(
            &pool,
            credential_id,
            user_id_for_audit,
            aid_for_audit.clone(),
            current_attempts,
            unauthorized_error("invalid enrollment secret"),
        )
        .await);
    }

    // Verify the enrollment proof JWS — signature + payload claims
    let proof_parts: Vec<&str> = payload.enrollment_proof.split('.').collect();
    if proof_parts.len() != 3 {
        return Err(record_failed_attempt(
            &pool,
            credential_id,
            user_id_for_audit,
            aid_for_audit.clone(),
            current_attempts,
            validation_error("enrollment_proof must be a compact JWS"),
        )
        .await);
    }

    // ---- Decode and validate payload (credential_id binding + freshness) ----
    let proof_payload_bytes = URL_SAFE_NO_PAD
        .decode(proof_parts[1])
        .map_err(|_| validation_error("invalid base64url in enrollment_proof payload"))?;
    let proof_claims: serde_json::Value = serde_json::from_slice(&proof_payload_bytes)
        .map_err(|e| validation_error(&format!("invalid enrollment_proof payload JSON: {e}")))?;

    // credential_id must match the path parameter
    let proof_credential_id = proof_claims
        .get("credential_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| validation_error("enrollment_proof payload must include credential_id"))?;
    if proof_credential_id != credential_id.to_string() {
        return Err(record_failed_attempt(
            &pool,
            credential_id,
            user_id_for_audit,
            aid_for_audit.clone(),
            current_attempts,
            validation_error("enrollment_proof credential_id does not match the target credential"),
        )
        .await);
    }

    // iat must be present and within 60-second window
    let proof_iat = proof_claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| validation_error("enrollment_proof payload must include iat (integer)"))?;
    let now = Utc::now().timestamp();
    if (now - proof_iat).abs() > 60 {
        return Err(validation_error(
            "enrollment_proof iat is outside the 60-second window",
        ));
    }

    // ---- Verify Ed25519 signature ----
    let pub_key_bytes = URL_SAFE_NO_PAD
        .decode(&payload.signing_public_key)
        .map_err(|_| validation_error("invalid base64url in signing_public_key"))?;
    let verifying_key = VerifyingKey::from_bytes(
        pub_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| validation_error("signing_public_key must be 32 bytes"))?,
    )
    .map_err(|_| validation_error("invalid Ed25519 public key"))?;

    let proof_signed_data = format!("{}.{}", proof_parts[0], proof_parts[1]);
    let proof_sig_bytes = URL_SAFE_NO_PAD
        .decode(proof_parts[2])
        .map_err(|_| validation_error("invalid base64url in proof signature"))?;
    let proof_sig = Signature::from_bytes(
        proof_sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| validation_error("proof signature must be 64 bytes"))?,
    );

    if verifying_key
        .verify(proof_signed_data.as_bytes(), &proof_sig)
        .is_err()
    {
        return Err(record_failed_attempt(
            &pool,
            credential_id,
            user_id_for_audit,
            aid_for_audit.clone(),
            current_attempts,
            unauthorized_error("enrollment proof signature verification failed"),
        )
        .await);
    }

    // Derive did:key from the signing public key
    // did:key uses multicodec 0xed01 prefix for Ed25519
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&pub_key_bytes);
    let did = format!("did:key:z{}", bs58::encode(&multicodec).into_string());

    let aid = aid_for_audit.clone();
    let user_id = user_id_for_audit;

    // Insert into agent_identity_keys (if this DID doesn't already exist)
    let _ = sqlx::query(
        r#"
        INSERT INTO agent_identity_keys (aid, did, signing_public_key, encryption_public_key, status)
        VALUES ($1, $2, $3, $4, 'active')
        ON CONFLICT (did) DO NOTHING
        "#,
    )
    .bind(&aid)
    .bind(&did)
    .bind(&payload.signing_public_key)
    .bind(&payload.encryption_public_key)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("failed to insert identity key", e))?;

    // Activate the credential: store signing key, clear enrollment
    // hash, and record the caller's key_holder hint. Zero the
    // failed-attempt counter on success so an operator-issued
    // re-pair of a partially-attempted credential doesn't carry
    // stale pressure toward the auto-revoke threshold.
    // `normalise_key_holder` clamps unknown strings to `'unknown'`
    // so a malformed client can't bypass the DB CHECK and surface a
    // 500.
    let key_holder = normalise_key_holder(payload.key_holder.as_deref());
    sqlx::query(
        r#"
        UPDATE agent_credentials
        SET status = 'active',
            signing_public_key = $1,
            enrollment_hash = NULL,
            enrollment_expires = NULL,
            activated_at = NOW(),
            failed_activation_attempts = 0,
            key_holder = $3
        WHERE id = $2
        "#,
    )
    .bind(&payload.signing_public_key)
    .bind(credential_id)
    .bind(key_holder)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("failed to activate credential", e))?;

    // Audit: credential_activated
    record_audit_event(
        pool.clone(),
        user_id,
        Some(credential_id),
        Some(aid.clone()),
        "credential_activated",
        serde_json::json!({ "did": did }),
    );

    Ok(Json(serde_json::json!({
        "credential_id": credential_id.to_string(),
        "aid": aid,
        "did": did,
        "status": "active"
    })))
}

/// PATCH /agent-credentials/:id — update label or policy on a credential.
#[derive(Deserialize)]
struct PatchCredentialRequest {
    label: Option<String>,
    policy: Option<serde_json::Value>,
}

async fn patch_agent_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<Uuid>,
    JsonBody(payload): JsonBody<PatchCredentialRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;

    // Verify ownership
    let exists = sqlx::query("SELECT id FROM agent_credentials WHERE id = $1 AND user_id = $2")
        .bind(credential_id)
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|e| internal_error("lookup failed", e))?;

    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "credential not found".into(),
            }),
        ));
    }

    if let Some(ref label) = payload.label {
        let label = label.trim();
        if label.is_empty() || label.len() > 64 {
            return Err(validation_error("label must be 1-64 characters"));
        }
        sqlx::query("UPDATE agent_credentials SET label = $1 WHERE id = $2")
            .bind(label)
            .bind(credential_id)
            .execute(&pool)
            .await
            .map_err(|e| internal_error("update label failed", e))?;
    }

    if let Some(ref policy) = payload.policy {
        sqlx::query("UPDATE agent_credentials SET policy = $1 WHERE id = $2")
            .bind(policy)
            .bind(credential_id)
            .execute(&pool)
            .await
            .map_err(|e| internal_error("update policy failed", e))?;
    }

    Ok(Json(serde_json::json!({
        "credential_id": credential_id.to_string(),
        "updated": true
    })))
}

/// POST /agent-credentials/:id/rotate — initiate key rotation for a credential.
/// A new enrollment secret is issued so the Daemon can re-enroll with new keys.
async fn rotate_agent_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;

    // Verify ownership and get aid
    let cred_row = sqlx::query(
        r#"
        SELECT id, aid, status
        FROM agent_credentials
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(credential_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("lookup failed", e))?;

    let cred_row = cred_row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "credential not found".into(),
            }),
        )
    })?;

    let status: String = cred_row.get("status");
    if status != "active" {
        return Err(validation_error("only active credentials can be rotated"));
    }

    let aid: String = cred_row.get("aid");

    // Mark old identity keys as rotating
    let _ = sqlx::query(
        r#"
        UPDATE agent_identity_keys
        SET status = 'rotating'
        WHERE aid = $1 AND status = 'active'
        "#,
    )
    .bind(&aid)
    .execute(&pool)
    .await;

    // Issue new enrollment secret for re-activation
    let secret = generate_enrollment_secret();
    let enrollment_hash = sha256_hex(secret.as_bytes());
    let expires = (Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();

    sqlx::query(
        r#"
        UPDATE agent_credentials
        SET enrollment_hash = $1,
            enrollment_expires = $2::timestamptz,
            signing_public_key = NULL
        WHERE id = $3
        "#,
    )
    .bind(&enrollment_hash)
    .bind(&expires)
    .bind(credential_id)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("rotate update failed", e))?;

    // Audit: key_rotation_started
    record_audit_event(
        pool.clone(),
        user_uuid,
        Some(credential_id),
        Some(aid.clone()),
        "key_rotation_started",
        serde_json::json!({}),
    );

    Ok(Json(serde_json::json!({
        "credential_id": credential_id.to_string(),
        "aid": aid,
        "enrollment_secret": secret,
        "enrollment_expires_at": expires,
        "message": "Re-activate the credential with the new keys within 30 minutes."
    })))
}

/// POST /agent-auth/revoke — self-revoke a token (agent-initiated).
/// The agent submits its own access or refresh token to revoke it.
#[derive(Deserialize)]
struct AgentRevokeRequest {
    token: String,
}

async fn agent_auth_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<AgentRevokeRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;

    let token = payload.token.trim();
    let hash = sha256_hex(token.as_bytes());

    let actor_ip = extract_client_ip(&headers);
    let actor_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Try revoking by access_hash first, then by refresh_hash
    let result = sqlx::query(
        r#"
        UPDATE agent_tokens
        SET revoked_at = NOW()
        WHERE (access_hash = $1 OR refresh_hash = $1)
          AND revoked_at IS NULL
        "#,
    )
    .bind(&hash)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("revoke failed", e))?;

    if result.rows_affected() == 0 {
        // Token not found or already revoked — return 200 anyway (RFC 7009 §2.2)
        return Ok(StatusCode::OK);
    }

    // Look up for audit
    let maybe_row = sqlx::query(
        r#"
        SELECT t.id, t.credential_id, t.token_family_id, c.user_id, c.aid
        FROM agent_tokens t
        JOIN agent_credentials c ON c.id = t.credential_id
        WHERE t.access_hash = $1 OR t.refresh_hash = $1
        LIMIT 1
        "#,
    )
    .bind(&hash)
    .fetch_optional(&pool)
    .await;

    if let Ok(Some(row)) = maybe_row {
        let token_id: Uuid = row.get("id");
        let cred_id: Uuid = row.get("credential_id");
        let family_id: Uuid = row.get("token_family_id");
        let uid: Uuid = row.get("user_id");
        let aid: String = row.get("aid");
        record_audit_event(
            pool.clone(),
            uid,
            Some(cred_id),
            Some(aid),
            "token_revoked",
            serde_json::json!({
                "method": "self_revoke",
                "actor_type": "agent",
                "token_id": token_id.to_string(),
                "token_family_id": family_id.to_string(),
                "actor_ip": actor_ip,
                "actor_user_agent": actor_user_agent,
            }),
        );
    }

    Ok(StatusCode::OK)
}

/// POST /agents/{id}/emergency-shutdown — revoke ALL credentials for an agent.
///
/// This is the "panic button" for when an agent's security is compromised.
/// All credentials under the agent's aid are immediately revoked, and all
/// associated tokens are invalidated.
async fn agent_emergency_shutdown(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<EmergencyShutdownResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;
    let user_uuid = parse_user_uuid(&user_id)?;

    let actor_ip = extract_client_ip(&headers);
    let actor_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Verify the agent belongs to this user and get its aid
    let agent_row = sqlx::query(
        r#"
        SELECT ai.aid
        FROM agents a
        JOIN agent_identities ai ON ai.agent_id = a.id
        WHERE a.id = $1 AND a.user_id = $2
        "#,
    )
    .bind(agent_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("agent lookup failed", e))?;

    let agent_row = agent_row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "agent not found".into(),
            }),
        )
    })?;

    let aid: String = agent_row.get("aid");

    // Revoke all active credentials for this aid
    let cred_result = sqlx::query(
        r#"
        UPDATE agent_credentials
        SET status = 'revoked', revoked_at = NOW()
        WHERE aid = $1 AND user_id = $2 AND status IN ('pending', 'active')
        "#,
    )
    .bind(&aid)
    .bind(user_uuid)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("credential revocation failed", e))?;

    let credentials_revoked = cred_result.rows_affected();

    // Revoke all tokens under those credentials
    let token_result = sqlx::query(
        r#"
        UPDATE agent_tokens SET revoked_at = NOW()
        WHERE credential_id IN (
            SELECT id FROM agent_credentials WHERE aid = $1 AND user_id = $2
        ) AND revoked_at IS NULL
        "#,
    )
    .bind(&aid)
    .bind(user_uuid)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("token revocation failed", e))?;

    let tokens_revoked = token_result.rows_affected();

    // Audit: emergency_shutdown
    record_audit_event(
        pool.clone(),
        user_uuid,
        None,
        Some(aid.clone()),
        "emergency_shutdown",
        serde_json::json!({
            "agent_id": agent_id.to_string(),
            "credentials_revoked": credentials_revoked,
            "tokens_revoked": tokens_revoked,
            "actor_type": "human",
            "actor_user_id": user_uuid.to_string(),
            "actor_ip": actor_ip,
            "actor_user_agent": actor_user_agent,
        }),
    );

    warn!(
        %agent_id, %aid, credentials_revoked, tokens_revoked,
        "emergency shutdown executed"
    );

    Ok(Json(EmergencyShutdownResponse {
        agent_id: agent_id.to_string(),
        aid,
        credentials_revoked,
        tokens_revoked,
    }))
}

#[derive(Serialize)]
struct EmergencyShutdownResponse {
    agent_id: String,
    aid: String,
    credentials_revoked: u64,
    tokens_revoked: u64,
}

// ---------------------------------------------------------------------------
// Agent Auth Token — JWS Assertion → Access Token + Refresh Token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AgentAuthTokenRequest {
    /// Base64url-encoded JWS (compact serialization) signed by the agent's
    /// Ed25519 key. Payload must include: iss (aid), sub (credential_id),
    /// aud, jti, iat, exp, scope.
    assertion: String,
    /// DPoP public key (JWK format) for sender-constrained tokens (RFC 9449).
    /// If provided, the token is bound to this key via JWK Thumbprint (RFC 7638).
    dpop_jwk: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct AgentAuthTokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
}

/// Decoded (but not yet verified) JWS assertion payload.
#[derive(Deserialize)]
#[allow(dead_code)]
struct AssertionClaims {
    iss: String, // aid:ai:...
    sub: String, // credential_id
    aud: String,
    jti: String,
    iat: i64,
    exp: i64,
    scope: String,
}

const ACCESS_TOKEN_TTL_SECS: u64 = 900; // 15 min
const REFRESH_TOKEN_TTL_SECS: u64 = 86400; // 24 h

fn generate_token(prefix: &str) -> String {
    let mut buf = [0u8; 48];
    rand::fill(&mut buf);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(buf))
}

// ---------------------------------------------------------------------------
// P6: Audit log + Policy L3
// ---------------------------------------------------------------------------

/// Maximum sends per credential per day (Policy L3, configurable)
const POLICY_L3_MAX_SENDS_PER_CREDENTIAL_PER_DAY: i64 = 200;

/// Event types the bridge-audit ingest endpoint (Phase 3c.3 of
/// docs/22) is allowed to write. Keeping this strict stops a
/// compromised daemon from forging arbitrary events on behalf of
/// an agent — it can only stamp bridge lifecycle rows.
const BRIDGE_AUDIT_ALLOWED_EVENTS: &[&str] = &[
    "bridged_decrypt",
    "bridged_status",
    "bridged_pair_requested",
    "bridged_pair_succeeded",
    "bridged_pair_failed",
    "bridged_pair_revoked",
];

/// Max clock skew accepted on `iat` in the ingest JWS. Matches the
/// 60-second window used by `/agent-auth/token`'s enrollment_proof
/// check, so daemons don't need separate clock-sync tolerance.
const BRIDGE_AUDIT_IAT_SKEW_SECONDS: i64 = 60;

/// How long the server remembers a (credential_id, jti) to reject
/// replays of the same signed envelope. 2× the iat skew window so
/// any event that would still look "fresh" to the iat check is
/// still inside the replay window and must have a unique jti.
const BRIDGE_AUDIT_REPLAY_WINDOW_SECS: i64 = 120;

/// Scope string for bridge-audit replay rows. Including the
/// credential_id means two daemons whose jti generators happen to
/// collide (e.g. reused uuid after a process restart on one side)
/// are not mistaken for replays of each other.
fn bridge_audit_replay_scope(credential_id: Uuid) -> String {
    format!("bridge_audit|{credential_id}")
}

/// How long the server remembers a (credential_id, jti) pair to
/// reject replays of the same `/agent-auth/token` assertion. Must
/// be strictly larger than the iat acceptance window (60 s) so any
/// assertion still fresh enough to pass the iat check is guaranteed
/// to have a unique jti.
const AGENT_AUTH_REPLAY_WINDOW_SECS: i64 = 120;

fn agent_auth_replay_scope(credential_id: Uuid) -> String {
    format!("agent_auth|{credential_id}")
}

/// Mirror of {@link check_and_record_bridge_audit_replay} for the
/// interactive token-issuance endpoint. Separate scope so the two
/// replay windows don't interfere — a jti the daemon reused across
/// the two endpoints should fail both.
async fn check_and_record_agent_auth_replay(
    state: &AppState,
    credential_id: Uuid,
    jti: &str,
) -> Result<bool, String> {
    let maybe_pool = state.database_pool().await?;
    if let Some(pool) = maybe_pool {
        let scope = agent_auth_replay_scope(credential_id);
        return check_and_record_replay_in_db(&pool, &scope, jti, AGENT_AUTH_REPLAY_WINDOW_SECS)
            .await;
    }
    if database_required() {
        return Err("database is required but unavailable".to_string());
    }
    let composite = format!("{}|{}", agent_auth_replay_scope(credential_id), jti);
    Ok(check_and_record_auth_replay_in_memory(state, &composite))
}

/// Atomic "was this (credential_id, jti) pair seen in the last 120s?"
/// check. Prefers the shared Postgres `replay_nonces` table; falls
/// back to the in-memory `seen_auth_proofs` HashMap only when a DB
/// isn't configured (tests, local dev). Fail-closed on DB errors.
async fn check_and_record_bridge_audit_replay(
    state: &AppState,
    credential_id: Uuid,
    jti: &str,
) -> Result<bool, String> {
    let maybe_pool = state.database_pool().await?;
    if let Some(pool) = maybe_pool {
        let scope = bridge_audit_replay_scope(credential_id);
        return check_and_record_replay_in_db(&pool, &scope, jti, BRIDGE_AUDIT_REPLAY_WINDOW_SECS)
            .await;
    }
    if database_required() {
        return Err("database is required but unavailable".to_string());
    }
    // In-memory: include the scope in the map key so different
    // credentials' jti namespaces stay disjoint.
    let composite = format!("{}|{}", bridge_audit_replay_scope(credential_id), jti);
    Ok(check_and_record_auth_replay_in_memory(state, &composite))
}

/// Compose an absolute URL the server would claim as the canonical
/// location of `path` (which must include the leading `/`). Preference
/// order:
///
///   1. `AGENT_INBOX_PUBLIC_API_URL` env var, when set and non-empty.
///      Production deployments set this on the API process (e.g.
///      `https://api.nexusinbox.ai`) so the expected URL is fixed
///      and independent of request-level header manipulation.
///   2. Derive from the request's `Host` header + `X-Forwarded-Proto`
///      (or `https` when behind the default Cloudflare tunnel config).
///      Kept as a best-effort fallback for single-node / dev setups
///      that haven't wired the env var yet.
///
/// Used for byte-equal `aud` validation on any signed assertion the
/// server accepts (`/agent-auth/token`, `/agent-audit-log/bridge`,
/// …) — callers should NOT roll their own aud derivation.
fn expected_api_url(headers: &axum::http::HeaderMap, path: &str) -> Option<String> {
    debug_assert!(path.starts_with('/'), "path must start with '/'");
    if let Ok(raw) = std::env::var("AGENT_INBOX_PUBLIC_API_URL") {
        let trimmed = raw.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return Some(format!("{trimmed}{path}"));
        }
    }
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())?;
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_ascii_lowercase())
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| "https".to_string());
    Some(format!("{scheme}://{host}{path}"))
}

#[derive(Deserialize)]
struct BridgeAuditIngestRequest {
    /// JWS compact serialization. Payload must include `iss` (aid),
    /// `sub` (credential_id uuid), `iat`, `jti`, `aud`, and a
    /// `bridge_event` object carrying the event fields below.
    jws: String,
}

#[derive(Serialize)]
struct BridgeAuditIngestResponse {
    accepted: bool,
}

/// `POST /agent-audit-log/bridge` — accept a signer-daemon bridge
/// audit event and insert it into `agent_audit_log` without going
/// through the interactive agent-token dance (docs/22 §8 Phase 3c).
///
/// The caller is expected to be a Signer Daemon fire-and-forget
/// audit forwarder that doesn't hold an access token. Auth is a
/// single-use JWS signed by the agent's Ed25519 signing key — the
/// same key the `/agent-credentials/:id/activate` flow registered.
/// Per-event signing keeps the write endpoint independent of the
/// access-token lifecycle (no token cache, no DPoP, no refresh)
/// while still being cryptographically bound to the credential.
///
/// Verification chain:
///   1. JWS parse + EdDSA signature check against
///      `agent_credentials.signing_public_key`.
///   2. `iss` matches the credential's aid.
///   3. `aud` byte-equal match against the expected ingest URL
///      (derived from `AGENT_INBOX_PUBLIC_API_URL` if set, else the
///      `Host` / `X-Forwarded-Proto` headers). No suffix / prefix
///      matching — a JWS that was signed for any other endpoint is
///      rejected even if it happens to end with the same path.
///   4. `iat` inside ±60 s of server time.
///   5. `jti` present and not seen in the last
///      `BRIDGE_AUDIT_REPLAY_WINDOW_SECS` (per credential_id) —
///      keeps an attacker who sniffed one JWS from replaying it.
///   6. `bridge_event.event` is in the strict allow-list.
///
/// Everything after that is treated as opaque detail JSON.
async fn ingest_bridge_audit_event(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    JsonBody(payload): JsonBody<BridgeAuditIngestRequest>,
) -> Result<Json<BridgeAuditIngestResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Every shape-level guard runs *before* we touch the DB pool so
    // a malformed request doesn't masquerade as "database unavailable"
    // — the caller needs to know whether the problem is their payload
    // or our infra.
    let parts: Vec<&str> = payload.jws.split('.').collect();
    if parts.len() != 3 {
        return Err(validation_error("jws must be a compact three-part JWS"));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| validation_error("invalid base64url in JWS payload"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| validation_error(&format!("invalid JWS payload JSON: {e}")))?;

    let credential_id_str = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| validation_error("JWS payload missing sub"))?;
    let credential_id = Uuid::parse_str(credential_id_str)
        .map_err(|_| validation_error("JWS sub is not a valid credential UUID"))?;

    // DB is only needed from here down — credential lookup + insert.
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;

    let cred_row = sqlx::query(
        r#"
        SELECT aid, user_id, status, signing_public_key
        FROM agent_credentials
        WHERE id = $1
        "#,
    )
    .bind(credential_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("credential lookup failed", e))?
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".into(),
                message: "credential not found".into(),
            }),
        )
    })?;

    let status: String = cred_row.get("status");
    if status != "active" {
        return Err(unauthorized_error("credential is not active"));
    }
    let stored_aid: String = cred_row.get("aid");
    let stored_user_id: Uuid = cred_row.get("user_id");
    let stored_pubkey: Option<String> = cred_row.get("signing_public_key");
    let stored_pubkey = stored_pubkey
        .ok_or_else(|| unauthorized_error("credential has no signing_public_key on record"))?;

    // 1. Signature verify.
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(&stored_pubkey)
        .map_err(|_| internal_server_error("stored signing_public_key is not base64url"))?;
    let verifying_key = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| internal_server_error("stored signing_public_key must be 32 bytes"))?,
    )
    .map_err(|_| internal_server_error("stored signing_public_key is not a valid Ed25519 key"))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| validation_error("invalid base64url in JWS signature"))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| validation_error("JWS signature must be 64 bytes"))?,
    );
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| unauthorized_error("JWS signature verification failed"))?;

    // 2. iss must match the credential's aid.
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| validation_error("JWS payload missing iss"))?;
    if iss != stored_aid {
        return Err(unauthorized_error("JWS iss does not match credential aid"));
    }

    // 3. aud must BYTE-EQUAL the expected ingest URL. Suffix matching
    //    was the old rule — it let any signed envelope whose aud ended
    //    with `/agent-audit-log/bridge` through, even if the aud host
    //    was an attacker-controlled mirror. Exact match kills that
    //    whole class of cross-endpoint replay.
    let aud = claims
        .get("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| validation_error("JWS payload missing aud"))?;
    let expected_aud = expected_api_url(&headers, "/agent-audit-log/bridge").ok_or_else(|| {
        internal_server_error(
            "server cannot determine expected audit aud (set AGENT_INBOX_PUBLIC_API_URL)",
        )
    })?;
    if aud != expected_aud {
        return Err(unauthorized_error(
            "JWS aud does not match the bridge audit ingest URL",
        ));
    }

    // 4. iat freshness.
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| validation_error("JWS payload missing iat"))?;
    let now = Utc::now().timestamp();
    if (now - iat).abs() > BRIDGE_AUDIT_IAT_SKEW_SECONDS {
        return Err(validation_error("JWS iat outside ±60s freshness window"));
    }

    // 5. jti present + not-seen-recently. Bounded 120s window per
    //    (credential_id, jti) stops a passive capture of one envelope
    //    from being POST'd twice. Fail-closed on DB error.
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| validation_error("JWS payload missing jti"))?;
    if jti.is_empty() || jti.len() > 128 {
        return Err(validation_error(
            "JWS jti must be a non-empty ≤128 char string",
        ));
    }
    let accepted = check_and_record_bridge_audit_replay(&state, credential_id, jti)
        .await
        .map_err(|e| internal_error("bridge audit replay check failed", e))?;
    if !accepted {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "replay_rejected".into(),
                message: "bridge audit JWS jti was already seen; duplicate rejected".into(),
            }),
        ));
    }

    // 6. bridge_event object + event allow-list.
    let event_obj = claims
        .get("bridge_event")
        .ok_or_else(|| validation_error("JWS payload missing bridge_event"))?;
    let event_type = event_obj
        .get("event")
        .and_then(|v| v.as_str())
        .ok_or_else(|| validation_error("bridge_event.event is required"))?;
    if !BRIDGE_AUDIT_ALLOWED_EVENTS.contains(&event_type) {
        return Err(validation_error(
            "bridge_event.event is not in the allow-list",
        ));
    }

    // Strip any top-level JWS envelope fields that aren't part of
    // the event itself. The detail column stores *exactly* what the
    // daemon emitted, so log readers can correlate across stderr
    // and DB without translation.
    record_audit_event(
        pool,
        stored_user_id,
        Some(credential_id),
        Some(stored_aid.clone()),
        event_type,
        event_obj.clone(),
    );

    Ok(Json(BridgeAuditIngestResponse { accepted: true }))
}

/// Record an audit event to the database (fire-and-forget).
fn record_audit_event(
    pool: PgPool,
    user_id: Uuid,
    credential_id: Option<Uuid>,
    aid: Option<String>,
    event: &str,
    detail: serde_json::Value,
) {
    let event = event.to_string();
    tokio::spawn(async move {
        let _ = sqlx::query(
            r#"
            INSERT INTO agent_audit_log (user_id, credential_id, aid, event, detail)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(user_id)
        .bind(credential_id)
        .bind(aid.as_deref())
        .bind(&event)
        .bind(&detail)
        .execute(&pool)
        .await;
    });
}

/// Policy L3: check daily send limit for a credential.
///
/// NOTE (known limitation, audit 2026-06-11 finding #3): this COUNTs prior
/// `agent_message_sent` audit rows, so it is a check-then-act with a TOCTOU
/// window — N concurrent sends can each read a count below the cap and all
/// proceed, briefly exceeding POLICY_L3_MAX_SENDS_PER_CREDENTIAL_PER_DAY. This
/// is accepted: L3 is the outermost of three layers and the inner two bound
/// throughput well below the point where the race matters — L1 caps token
/// issuance at 6/hour/credential (≈144/day) in the Signer Daemon and L2 caps
/// 20 sends/token in the gateway. Making L3 strictly atomic would need either
/// a dedicated counter column (migration + a shift from this rolling-24h
/// window to a fixed window) or a per-credential advisory lock serialising
/// sends; neither is worth the cost while L1/L2 already gate the volume.
async fn check_policy_l3_send_limit(
    pool: &PgPool,
    credential_id: Uuid,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*) AS cnt
        FROM agent_audit_log
        WHERE credential_id = $1
          AND event = 'agent_message_sent'
          AND created_at > NOW() - INTERVAL '24 hours'
        "#,
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .map_err(|e| internal_error("policy L3 check failed", e))?;

    let count: i64 = row.get("cnt");
    if count >= POLICY_L3_MAX_SENDS_PER_CREDENTIAL_PER_DAY {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limit_exceeded".into(),
                message: format!(
                    "Policy L3: credential send limit reached ({}/{} per day)",
                    count, POLICY_L3_MAX_SENDS_PER_CREDENTIAL_PER_DAY
                ),
            }),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Audit log query
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AuditLogEntry {
    id: String,
    credential_id: Option<String>,
    aid: Option<String>,
    event: String,
    detail: serde_json::Value,
    created_at: String,
}

#[derive(Serialize)]
struct AuditLogResponse {
    events: Vec<AuditLogEntry>,
    total: i64,
}

/// GET /agent-audit-log — list audit events for the authenticated user.
async fn list_agent_audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;

    let user_uuid = parse_user_uuid(&user_id)?;
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);

    // Build WHERE clause
    let mut conditions = vec!["user_id = $1".to_string()];
    let mut param_idx = 2u32;

    let cred_filter = query.credential_id.clone();
    if cred_filter.is_some() {
        conditions.push(format!("credential_id = ${param_idx}"));
        param_idx += 1;
    }

    // `aid` is stored as plain TEXT, so a basic length cap is enough
    // to keep the query plan honest. The `aid:ai:<ULID>` form tops
    // out around 33 chars, anything wildly longer is junk and gets
    // silently dropped to spare an index scan.
    let aid_filter = query
        .aid
        .clone()
        .filter(|v| !v.is_empty() && v.len() <= 128);
    if aid_filter.is_some() {
        conditions.push(format!("aid = ${param_idx}"));
        param_idx += 1;
    }

    let event_filter = query.event.clone();
    if event_filter.is_some() {
        conditions.push(format!("event = ${param_idx}"));
        param_idx += 1;
    }

    // Sanitised prefix filter (letters / digits / underscore only,
    // length ≤ 64) so the LIKE expression can't smuggle `%` / `_`
    // wildcards from user input. Exact `event` match wins when both
    // are supplied — matches the struct doc comment's promise.
    let event_prefix_filter: Option<String> = if event_filter.is_some() {
        None
    } else {
        query.event_prefix.as_ref().and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.len() > 64 {
                return None;
            }
            if trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                Some(format!("{trimmed}%"))
            } else {
                None
            }
        })
    };
    if event_prefix_filter.is_some() {
        conditions.push(format!("event LIKE ${param_idx}"));
        param_idx += 1;
    }

    let where_clause = conditions.join(" AND ");
    let count_sql = format!("SELECT COUNT(*) AS total FROM agent_audit_log WHERE {where_clause}");
    let list_sql = format!(
        "SELECT id::text, credential_id::text, aid, event, detail, created_at::text \
         FROM agent_audit_log WHERE {where_clause} \
         ORDER BY created_at DESC LIMIT ${param_idx} OFFSET ${}",
        param_idx + 1
    );

    // Count query
    let mut count_q = sqlx::query(&count_sql).bind(user_uuid);
    if let Some(ref cid) = cred_filter {
        let cid_uuid =
            Uuid::parse_str(cid).map_err(|_| validation_error("invalid credential_id format"))?;
        count_q = count_q.bind(cid_uuid);
    }
    if let Some(ref aid) = aid_filter {
        count_q = count_q.bind(aid);
    }
    if let Some(ref evt) = event_filter {
        count_q = count_q.bind(evt);
    }
    if let Some(ref prefix) = event_prefix_filter {
        count_q = count_q.bind(prefix);
    }
    let count_row = count_q
        .fetch_one(&pool)
        .await
        .map_err(|e| internal_error("audit count failed", e))?;
    let total: i64 = count_row.get("total");

    // List query
    let mut list_q = sqlx::query(&list_sql).bind(user_uuid);
    if let Some(ref cid) = cred_filter {
        let cid_uuid =
            Uuid::parse_str(cid).map_err(|_| validation_error("invalid credential_id format"))?;
        list_q = list_q.bind(cid_uuid);
    }
    if let Some(ref aid) = aid_filter {
        list_q = list_q.bind(aid);
    }
    if let Some(ref evt) = event_filter {
        list_q = list_q.bind(evt);
    }
    if let Some(ref prefix) = event_prefix_filter {
        list_q = list_q.bind(prefix);
    }
    list_q = list_q.bind(limit as i64).bind(offset as i64);

    let rows = list_q
        .fetch_all(&pool)
        .await
        .map_err(|e| internal_error("audit list failed", e))?;

    let events: Vec<AuditLogEntry> = rows
        .iter()
        .map(|r| AuditLogEntry {
            id: r.get("id"),
            credential_id: r.get("credential_id"),
            aid: r.get("aid"),
            event: r.get("event"),
            detail: r.get("detail"),
            created_at: r.get("created_at"),
        })
        .collect();

    Ok(Json(AuditLogResponse { events, total }))
}

#[derive(Deserialize)]
struct AuditLogQuery {
    credential_id: Option<String>,
    /// Filter by agent identifier (`aid:ai:...`). Used by the
    /// per-agent visibility panels (e.g. auto-reply decision
    /// history) that need to scope events to a single agent
    /// without paying for client-side filtering of every event
    /// the user owns. Stored as TEXT in the DB so this is a
    /// straight equality match (no parsing).
    aid: Option<String>,
    event: Option<String>,
    /// Prefix match on `event`, e.g. `"bridged_"` to bucket the
    /// whole Phase 3c.3 bridge lifecycle. Mutually exclusive with
    /// `event` — if both are supplied, the exact match wins. Only
    /// user-safe characters (letters / underscores) are accepted;
    /// anything else is silently ignored to stop SQL LIKE wildcard
    /// injection via the query string.
    event_prefix: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

/// POST /agent-auth/token — exchange JWS assertion for access + refresh tokens.
///
/// No Cookie required. The caller proves ownership of the agent's signing key
/// by submitting a JWS signed with Ed25519.
async fn agent_auth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<AgentAuthTokenRequest>,
) -> Result<Json<AgentAuthTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let actor_ip = extract_client_ip(&headers);
    let actor_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;

    // ---- 1. Decode JWS (Ed25519 compact) ----
    // JWS format: base64url(header).base64url(payload).base64url(signature)
    let parts: Vec<&str> = payload.assertion.split('.').collect();
    if parts.len() != 3 {
        return Err(validation_error(
            "assertion must be a compact JWS (3 dot-separated parts)",
        ));
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| validation_error("invalid base64url in assertion payload"))?;
    let claims: AssertionClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| validation_error(&format!("invalid assertion payload JSON: {e}")))?;

    // ---- 2. Validate timing ----
    let now = Utc::now().timestamp();
    if (now - claims.iat).abs() > 60 {
        return Err(validation_error(
            "assertion iat is outside the 60-second window",
        ));
    }
    if claims.exp <= now {
        return Err(validation_error("assertion has expired"));
    }

    // ---- 2b. Validate `aud` byte-equal to the expected token URL.
    // Without this, an attacker who captures an assertion signed for
    // some OTHER endpoint (e.g. `/agent-audit-log/bridge`) could
    // replay it here to mint a fresh AT+RT pair — the Signer Daemon
    // uses the same Ed25519 key for every assertion it emits. Suffix
    // matching is deliberately NOT used: a JWS targeting any other
    // host with the same path tail is rejected.
    let expected_aud = expected_api_url(&headers, "/agent-auth/token").ok_or_else(|| {
        internal_server_error(
            "server cannot determine expected token aud (set AGENT_INBOX_PUBLIC_API_URL)",
        )
    })?;
    if claims.aud != expected_aud {
        return Err(unauthorized_error(
            "JWS aud does not match /agent-auth/token",
        ));
    }

    // ---- 2c. jti shape guard — the *replay* check runs after the
    // Ed25519 signature verify so unauthenticated junk can't pollute
    // the replay cache. Here we only validate the string is
    // well-formed so we don't DoS the replay INSERT path below with
    // multi-MB jtis, and so the error message is about the payload
    // rather than the DB.
    if claims.jti.is_empty() || claims.jti.len() > 128 {
        return Err(validation_error(
            "assertion jti must be a non-empty ≤128 char string",
        ));
    }

    // ---- 3. Look up credential + signing key ----
    let cred_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| validation_error("assertion sub must be a valid credential UUID"))?;

    let cred_row = sqlx::query(
        r#"
        SELECT
            c.id, c.aid, c.user_id, c.status, c.allowed_scopes, c.signing_public_key,
            aik.signing_public_key AS identity_key
        FROM agent_credentials c
        JOIN agent_identity_keys aik ON aik.aid = c.aid AND aik.status = 'active'
        WHERE c.id = $1 AND c.aid = $2 AND c.status = 'active'
        LIMIT 1
        "#,
    )
    .bind(cred_id)
    .bind(&claims.iss)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("credential lookup failed", e))?;

    let cred_row = cred_row.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".into(),
                message: "credential not found, inactive, or aid mismatch".into(),
            }),
        )
    })?;

    // Use credential's own signing key if set (post-activation), otherwise
    // fall back to the identity key from agent_identity_keys.
    let signing_key_b64: String = cred_row
        .get::<Option<String>, _>("signing_public_key")
        .unwrap_or_else(|| cred_row.get("identity_key"));

    // ---- 4. Verify Ed25519 signature ----
    let pub_key_bytes = URL_SAFE_NO_PAD
        .decode(&signing_key_b64)
        .map_err(|_| internal_server_error("invalid signing key encoding in database"))?;
    let verifying_key = VerifyingKey::from_bytes(
        pub_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| internal_server_error("signing key is not 32 bytes"))?,
    )
    .map_err(|_| internal_server_error("invalid Ed25519 public key"))?;

    let signed_data = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| validation_error("invalid base64url in assertion signature"))?;
    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| validation_error("signature must be exactly 64 bytes"))?,
    );

    verifying_key
        .verify(signed_data.as_bytes(), &signature)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".into(),
                    message: "JWS signature verification failed".into(),
                }),
            )
        })?;

    // ---- 4b. jti replay rejection (post-signature).
    // Runs only after signature verify so unauthenticated callers
    // can't burn entries in replay_nonces by spraying junk — the
    // insert side-effect is gated on "the caller actually holds the
    // credential's signing key". Scoped per credential_id so jti
    // collisions across different daemons do not interfere.
    // Fail-closed on DB error.
    let accepted = check_and_record_agent_auth_replay(&state, cred_id, &claims.jti)
        .await
        .map_err(|e| internal_error("agent-auth replay check failed", e))?;
    if !accepted {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "replay_rejected".into(),
                message: "agent-auth assertion jti was already seen; duplicate rejected".into(),
            }),
        ));
    }

    // ---- 5. Validate scopes ----
    let allowed: Vec<String> = cred_row.get("allowed_scopes");
    let requested: Vec<&str> = claims.scope.split_whitespace().collect();
    for scope in &requested {
        if !allowed.iter().any(|a| a == scope) {
            return Err(validation_error(&format!(
                "scope '{scope}' is not allowed for this credential"
            )));
        }
    }

    // ---- 6. Issue tokens ----
    let access_token = generate_token("agt_");
    let refresh_token = generate_token("agr_");
    let access_hash = sha256_hex(access_token.as_bytes());
    let refresh_hash = sha256_hex(refresh_token.as_bytes());
    let access_expires =
        (Utc::now() + chrono::Duration::seconds(ACCESS_TOKEN_TTL_SECS as i64)).to_rfc3339();
    let refresh_expires =
        (Utc::now() + chrono::Duration::seconds(REFRESH_TOKEN_TTL_SECS as i64)).to_rfc3339();

    // Compute DPoP JWK Thumbprint (RFC 7638) if dpop_jwk is provided.
    // When present, the token is sender-constrained: only the holder of the
    // corresponding private key can use it (RFC 9449).
    let dpop_jkt = if let Some(ref jwk) = payload.dpop_jwk {
        compute_jwk_thumbprint(jwk)
            .map_err(|e| validation_error(&format!("invalid dpop_jwk: {e}")))?
    } else {
        "none".to_string()
    };

    // Fresh issuance → a brand-new token family. DEFAULT gen_random_uuid()
    // on token_family_id fires here; RETURNING surfaces the value so we
    // can log it for audit/forensics.
    let inserted = sqlx::query(
        r#"
        INSERT INTO agent_tokens (
            credential_id, access_hash, refresh_hash, dpop_jkt,
            scopes, issued_at, access_expires_at, refresh_expires_at
        ) VALUES ($1, $2, $3, $4, $5, NOW(), $6::timestamptz, $7::timestamptz)
        RETURNING id, token_family_id
        "#,
    )
    .bind(cred_id)
    .bind(&access_hash)
    .bind(&refresh_hash)
    .bind(&dpop_jkt)
    .bind(&allowed as &[String])
    .bind(&access_expires)
    .bind(&refresh_expires)
    .fetch_one(&pool)
    .await
    .map_err(|e| internal_error("failed to insert token", e))?;
    let new_token_id: Uuid = inserted.get("id");
    let new_token_family_id: Uuid = inserted.get("token_family_id");

    // Update last_used_at on credential
    let _ = sqlx::query("UPDATE agent_credentials SET last_used_at = NOW() WHERE id = $1")
        .bind(cred_id)
        .execute(&pool)
        .await;

    // Audit: token_issued
    let user_id_for_audit: Uuid = cred_row.get("user_id");
    record_audit_event(
        pool.clone(),
        user_id_for_audit,
        Some(cred_id),
        Some(claims.iss.clone()),
        "token_issued",
        serde_json::json!({
            "scopes": claims.scope,
            "token_id": new_token_id.to_string(),
            "token_family_id": new_token_family_id.to_string(),
            "dpop_bound": dpop_jkt != "none",
            "actor_type": "agent",
            "actor_ip": actor_ip,
            "actor_user_agent": actor_user_agent,
        }),
    );

    let token_type = if dpop_jkt == "none" { "Bearer" } else { "DPoP" };

    Ok(Json(AgentAuthTokenResponse {
        access_token,
        refresh_token,
        token_type: token_type.into(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: claims.scope,
    }))
}

// ---------------------------------------------------------------------------
// P3: Refresh token rotation + reuse detection
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AgentRefreshRequest {
    refresh_token: String,
}

/// Shared response for a detected/raced refresh-token reuse: family-scoped
/// revoke + credential compromise + audit trail, returning the 401 the
/// caller should propagate. Invoked from two places in `agent_auth_refresh`:
///   1. when the initial SELECT already sees `revoked_at IS NOT NULL`, and
///   2. when the atomic rotation UPDATE affects zero rows — i.e. a concurrent
///      refresh already consumed this RT. Case (2) closes the double-spend
///      window where two refreshes both read the RT as live and each mint a
///      fresh token pair.
#[allow(clippy::too_many_arguments)]
async fn revoke_refresh_family_for_reuse(
    pool: &PgPool,
    credential_id: Uuid,
    token_family_id: Uuid,
    token_id: Uuid,
    refresh_user_id: Uuid,
    aid: &str,
    actor_ip: &str,
    actor_user_agent: &str,
) -> (StatusCode, Json<ErrorResponse>) {
    // First: family-scoped revoke (the "minimum" requirement).
    let family_revoke = sqlx::query(
        r#"
        UPDATE agent_tokens
        SET revoked_at = NOW(), flagged_at = NOW()
        WHERE token_family_id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(token_family_id)
    .execute(pool)
    .await;
    let family_tokens_revoked = family_revoke.map(|r| r.rows_affected()).unwrap_or(0);

    // Second: mark credential as compromised (escalation).
    let _ = sqlx::query(
        r#"
        UPDATE agent_credentials
        SET status = 'compromised', revoked_at = NOW()
        WHERE id = $1 AND status != 'compromised'
        "#,
    )
    .bind(credential_id)
    .execute(pool)
    .await;

    // Third: revoke any OTHER live tokens under the same credential
    // that happened to belong to different families.
    let _ = sqlx::query(
        r#"
        UPDATE agent_tokens
        SET revoked_at = NOW(), flagged_at = NOW()
        WHERE credential_id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(credential_id)
    .execute(pool)
    .await;

    warn!(
        %credential_id, %token_id, %token_family_id,
        family_tokens_revoked,
        actor_ip = %actor_ip,
        "refresh token reuse detected — family revoked, credential compromised"
    );

    // Audit: refresh_reuse_detected + credential_compromised
    record_audit_event(
        pool.clone(),
        refresh_user_id,
        Some(credential_id),
        Some(aid.to_string()),
        "refresh_reuse_detected",
        serde_json::json!({
            "token_id": token_id.to_string(),
            "token_family_id": token_family_id.to_string(),
            "family_tokens_revoked": family_tokens_revoked,
            "detected_ip": actor_ip,
            "detected_user_agent": actor_user_agent,
        }),
    );
    record_audit_event(
        pool.clone(),
        refresh_user_id,
        Some(credential_id),
        Some(aid.to_string()),
        "credential_compromised",
        serde_json::json!({
            "reason": "refresh_token_reuse",
            "token_family_id": token_family_id.to_string(),
            "actor_type": "system",
            "triggered_by_token_id": token_id.to_string(),
        }),
    );

    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "token_reuse_detected".into(),
            message: "Refresh token reuse detected. Credential has been revoked for security. \
                      Contact the account owner to re-issue credentials."
                .into(),
        }),
    )
}

/// POST /agent-auth/refresh — rotate a refresh token.
///
/// The caller submits the current `agr_` refresh token. If valid and unused:
///   1. Old token row gets `revoked_at = NOW()`
///   2. New AT + RT pair is issued and stored
///   3. Response returns the new tokens
///
/// **DPoP binding**: If the original token was DPoP-bound (`dpop_jkt != "none"`),
/// the caller MUST supply a DPoP proof header proving possession of the bound key.
/// The new token inherits the same `dpop_jkt`.
///
/// **Reuse detection**: If the submitted RT was already revoked (i.e. someone
/// already used it), this is a token theft signal. The entire credential is
/// marked `compromised` and ALL tokens under it are revoked.
async fn agent_auth_refresh(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<AgentRefreshRequest>,
) -> Result<Json<AgentAuthTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pool = state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
        .ok_or_else(database_required_but_unavailable_error)?;

    let rt = payload.refresh_token.trim();
    if !rt.starts_with("agr_") {
        return Err(validation_error(
            "refresh_token must start with 'agr_' prefix",
        ));
    }

    let hash = sha256_hex(rt.as_bytes());

    // Look up the token row by refresh_hash. Same boolean-projection trick
    // for revoked_at as in validate_agent_token — avoids pulling in the
    // sqlx `chrono` decode feature just for a NULL check.
    let row = sqlx::query(
        r#"
        SELECT
            t.id              AS token_id,
            t.credential_id   AS credential_id,
            t.scopes          AS scopes,
            (t.revoked_at IS NOT NULL) AS token_is_revoked,
            t.dpop_jkt        AS dpop_jkt,
            t.token_family_id AS token_family_id,
            c.status          AS credential_status,
            c.aid             AS aid,
            c.user_id         AS user_id,
            (t.refresh_expires_at <= NOW()) AS is_expired
        FROM agent_tokens t
        JOIN agent_credentials c ON c.id = t.credential_id
        WHERE t.refresh_hash = $1
        "#,
    )
    .bind(&hash)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("refresh token lookup failed", e))?;

    let row = row.ok_or_else(|| unauthorized_error("invalid refresh token"))?;

    let token_id: Uuid = row.get("token_id");
    let credential_id: Uuid = row.get("credential_id");
    let scopes: Vec<String> = row.get("scopes");
    let dpop_jkt: String = row.get("dpop_jkt");
    let token_family_id: Uuid = row.get("token_family_id");
    let cred_status: String = row.get("credential_status");
    let aid: String = row.get("aid");
    let refresh_user_id: Uuid = row.get("user_id");
    let token_is_revoked: bool = row.get("token_is_revoked");
    let is_expired: bool = row.get("is_expired");

    // Actor context for audit trails (IP / UA of the refresh caller). Present
    // for both the happy path and reuse detection so forensics has the same
    // fields regardless of outcome.
    let actor_ip = extract_client_ip(&headers);
    let actor_user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // ---- Reuse detection ----
    // If this RT was already revoked, it means someone already used it.
    // Minimum response per spec: revoke every live token in the same
    // token_family_id. Escalation: compromise the entire credential (which
    // also nukes tokens from any other families under it). We do both
    // because the credential-compromise case is the right answer for a
    // stolen signing key — the attacker can otherwise mint a fresh family.
    if token_is_revoked {
        return Err(revoke_refresh_family_for_reuse(
            &pool,
            credential_id,
            token_family_id,
            token_id,
            refresh_user_id,
            &aid,
            &actor_ip,
            &actor_user_agent,
        )
        .await);
    }

    // Check credential status
    if cred_status != "active" {
        return Err(unauthorized_error(&format!(
            "agent credential is not active (status: {})",
            cred_status
        )));
    }

    // Check RT expiry
    if is_expired {
        return Err(unauthorized_error("refresh token has expired"));
    }

    // ---- DPoP sender-constraint on refresh (RFC 9449 §6.1) ----
    // If the original token was DPoP-bound, the caller must prove possession
    // of the same key by supplying a valid DPoP proof header.
    if dpop_jkt != "none" {
        let dpop_proof = headers
            .get("DPoP")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "dpop_required".into(),
                        message: "DPoP proof header is required for DPoP-bound token refresh"
                            .into(),
                    }),
                )
            })?;
        // For refresh, we validate the proof against the refresh token itself
        // (the caller doesn't have the old AT anymore, so ath is based on the RT).
        validate_dpop_proof(
            dpop_proof,
            &dpop_jkt,
            method.as_str(),
            uri.path(),
            rt,
            &state,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "dpop_invalid".into(),
                    message: format!("DPoP proof validation failed on refresh: {e}"),
                }),
            )
        })?;
    }

    // ---- Rotate: atomically revoke the old token row ----
    // `AND revoked_at IS NULL` makes this UPDATE the serialization point.
    // Two refreshes presenting the same RT both read `revoked_at IS NULL` in
    // the SELECT above; only one can win this conditional revoke. If our
    // UPDATE affects zero rows (`RETURNING` yields no row), a concurrent
    // refresh already consumed this RT — treat it as reuse and revoke the
    // family instead of minting a second valid token pair from one RT.
    let revoked = sqlx::query(
        "UPDATE agent_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL RETURNING id",
    )
    .bind(token_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("failed to revoke old token", e))?;

    if revoked.is_none() {
        return Err(revoke_refresh_family_for_reuse(
            &pool,
            credential_id,
            token_family_id,
            token_id,
            refresh_user_id,
            &aid,
            &actor_ip,
            &actor_user_agent,
        )
        .await);
    }

    // ---- Issue new AT + RT ----
    let new_access = generate_token("agt_");
    let new_refresh = generate_token("agr_");
    let access_hash = sha256_hex(new_access.as_bytes());
    let refresh_hash = sha256_hex(new_refresh.as_bytes());
    let access_expires =
        (Utc::now() + chrono::Duration::seconds(ACCESS_TOKEN_TTL_SECS as i64)).to_rfc3339();
    let refresh_expires =
        (Utc::now() + chrono::Duration::seconds(REFRESH_TOKEN_TTL_SECS as i64)).to_rfc3339();

    let scope_str = scopes.join(" ");

    // Rotation: new token INHERITS the parent's token_family_id so the
    // whole rotation chain can be revoked as a unit on reuse detection.
    sqlx::query(
        r#"
        INSERT INTO agent_tokens (
            credential_id, access_hash, refresh_hash, dpop_jkt,
            scopes, issued_at, access_expires_at, refresh_expires_at,
            token_family_id
        ) VALUES ($1, $2, $3, $4, $5, NOW(), $6::timestamptz, $7::timestamptz, $8)
        "#,
    )
    .bind(credential_id)
    .bind(&access_hash)
    .bind(&refresh_hash)
    .bind(&dpop_jkt)
    .bind(&scopes as &[String])
    .bind(&access_expires)
    .bind(&refresh_expires)
    .bind(token_family_id)
    .execute(&pool)
    .await
    .map_err(|e| internal_error("failed to insert new token", e))?;

    // Update last_used_at on credential
    let _ = sqlx::query("UPDATE agent_credentials SET last_used_at = NOW() WHERE id = $1")
        .bind(credential_id)
        .execute(&pool)
        .await;

    // Audit: token_refreshed
    record_audit_event(
        pool.clone(),
        refresh_user_id,
        Some(credential_id),
        Some(aid),
        "token_refreshed",
        serde_json::json!({
            "scopes": scope_str,
            "token_family_id": token_family_id.to_string(),
            "rotated_from_token_id": token_id.to_string(),
            "actor_type": "agent",
            "actor_ip": actor_ip,
            "actor_user_agent": actor_user_agent,
        }),
    );

    let token_type = if dpop_jkt == "none" { "Bearer" } else { "DPoP" };

    Ok(Json(AgentAuthTokenResponse {
        access_token: new_access,
        refresh_token: new_refresh,
        token_type: token_type.into(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: scope_str,
    }))
}

async fn send_message(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<SendMessageRequest>,
) -> Result<(StatusCode, Json<SendMessageResponse>), (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    ctx.require_scope("messages.send")?;
    let user_id = ctx.user_id().to_string();
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    // Policy L3: daily send limit for agent credentials
    if let AuthContext::Agent { credential_id, .. } = &ctx {
        if let Some(pool) = &maybe_pool {
            check_policy_l3_send_limit(pool, *credential_id).await?;
        }
    }

    // For agent tokens, look up world_id + verification_level from users table.
    // Human sessions carry them in the JWT claims.
    let (sender_world_id, verification_level) = match &ctx {
        AuthContext::Human { .. } => {
            // Re-extract from JWT claims for wid + verification_level
            let claims = authenticated_claims(&state, &headers).await?;
            (claims.wid.clone(), claims.verification_level.clone())
        }
        AuthContext::Agent { user_id, .. } => {
            if let Some(pool) = &maybe_pool {
                let user_uuid = parse_user_uuid(user_id)?;
                let row = sqlx::query(
                    "SELECT world_id_hash, verification_level FROM users WHERE id = $1",
                )
                .bind(user_uuid)
                .fetch_optional(pool)
                .await
                .map_err(|e| internal_error("failed to lookup user", e))?;
                match row {
                    Some(r) => (
                        r.get::<String, _>("world_id_hash"),
                        r.get::<String, _>("verification_level"),
                    ),
                    None => (String::new(), "device".to_string()),
                }
            } else {
                (String::new(), "device".to_string())
            }
        }
    };

    let sender_did = payload.sender_did.unwrap_or_default();
    let recipient_ref = payload.recipient_did.unwrap_or_default();
    let envelope = payload.envelope;
    let metadata = envelope.as_ref().and_then(|e| e.metadata.as_ref());
    let signature = envelope
        .as_ref()
        .and_then(|e| e.signature.clone())
        .unwrap_or_default();

    let _ = envelope.as_ref().and_then(|e| e.encrypted_content.as_ref());
    let _ = envelope.as_ref().and_then(|e| e.encrypted_key.as_ref());
    let _ = envelope.as_ref().and_then(|e| e.nonce.as_ref());
    let _ = metadata.and_then(|m| m.has_attachments);
    // `content_type` rides with the ciphertext into BYOS (see
    // StoredMessageContent). We intentionally keep it out of the
    // server's normal validation path — anything the client sends
    // is preserved verbatim and returned on read.
    let content_type = metadata.and_then(|m| m.content_type.clone());

    let subject_encrypted = metadata
        .and_then(|m| m.subject_encrypted.clone())
        .unwrap_or_default();
    let encrypted_content = envelope
        .as_ref()
        .and_then(|e| e.encrypted_content.clone())
        .unwrap_or_default();
    let encrypted_key = envelope
        .as_ref()
        .and_then(|e| e.encrypted_key.clone())
        .unwrap_or_default();
    let nonce = envelope
        .as_ref()
        .and_then(|e| e.nonce.clone())
        .unwrap_or_default();

    if sender_did.trim().is_empty()
        || recipient_ref.trim().is_empty()
        || subject_encrypted.trim().is_empty()
        || encrypted_content.trim().is_empty()
        || encrypted_key.trim().is_empty()
        || nonce.trim().is_empty()
        || signature.trim().is_empty()
    {
        return Err(validation_error(
            "sender_did, recipient_did, envelope.{encrypted_content,encrypted_key,nonce,signature} and envelope.metadata.subject_encrypted are required",
        ));
    }
    // Validate DID format
    validate_did(&sender_did, "sender_did")?;
    validate_recipient_reference(&recipient_ref, "recipient_did")?;
    if !is_valid_wrapped_encrypted_key_format(&encrypted_key) {
        return Err(validation_error(
            "envelope.encrypted_key must use x25519v1 wrapped key format",
        ));
    }

    let recipient_did = if let Some(pool) = maybe_pool.clone() {
        match resolve_recipient_in_db(&pool, &recipient_ref)
            .await
            .map_err(|message| internal_server_error(&message))?
        {
            Some(did) => did,
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        message: "recipient not found or blocked by policy".to_string(),
                    }),
                ))
            }
        }
    } else {
        match resolve_recipient_in_memory(&state, &recipient_ref) {
            Some(did) => did,
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        message: "recipient not found or blocked by policy".to_string(),
                    }),
                ))
            }
        }
    };

    let signing_agent = if let Some(pool) = maybe_pool.clone() {
        let user_uuid = parse_user_uuid(&user_id)?;
        match agent_owned_by_user_in_db(&pool, user_uuid, &sender_did)
            .await
            .map_err(|message| internal_server_error(&message))?
        {
            Some(agent) => {
                enforce_agent_bound_aid(&ctx, &agent.aid)?;
                agent
            }
            None => {
                return Err(forbidden_error(
                    "sender_did is not owned by the authenticated user",
                ))
            }
        }
    } else {
        let lock = state
            .agents_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let maybe = lock
            .get(&user_id)
            .and_then(|agents| agents.iter().find(|agent| agent.did == sender_did));
        match maybe {
            Some(agent) => {
                enforce_agent_bound_aid(&ctx, &agent.aid)?;
                agent.clone()
            }
            None => {
                return Err(forbidden_error(
                    "sender_did is not owned by the authenticated user",
                ));
            }
        }
    };

    let expected_did = derive_did_from_public_key(&signing_agent.public_key)
        .ok_or_else(|| unauthorized_error("invalid sender signing key format"))?;
    if expected_did != signing_agent.did || expected_did != sender_did {
        return Err(unauthorized_error("sender_did does not match signing key"));
    }

    let signing_payload = build_envelope_signing_payload(
        &sender_did,
        &recipient_did,
        &subject_encrypted,
        &encrypted_content,
        &encrypted_key,
        &nonce,
    );
    if !verify_envelope_signature(&signing_agent.public_key, &signature, &signing_payload) {
        return Err(unauthorized_error("invalid envelope signature"));
    }

    let recipient_exists_result = recipient_exists(&state, &recipient_did)
        || if let Some(pool) = maybe_pool.clone() {
            recipient_exists_in_db(&pool, &recipient_did)
                .await
                .map_err(|message| internal_server_error(&message))?
        } else {
            false
        };

    if !recipient_exists_result || recipient_is_blocked_by_policy(&state, &recipient_did) {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "recipient not found or blocked by policy".to_string(),
            }),
        ));
    }

    // SECURITY: hierarchical block enforcement (L1/L2/L3). DB and in-memory
    // paths are both wired. L2/L3 must return 404 to mask the recipient's
    // existence; L1 silently accepts and discards.
    //
    // Also captures the recipient's owning user_id (DB path) / user_id string
    // (in-memory path) so we can mirror the message into the recipient's
    // inbox later without re-querying.
    let mut recipient_owner_uuid_db: Option<Uuid> = None;
    let mut recipient_owner_id_mem: Option<String> = None;
    let block_decision = if let Some(pool) = maybe_pool.clone() {
        // Prefer the post-rotation source (agent_identities via the active
        // identity key), fall back to the creation-time agents.did row.
        let owner_row = sqlx::query(
            r#"
            SELECT ai.user_id
            FROM agent_identities ai
            JOIN agent_identity_keys aik ON aik.aid = ai.aid
            WHERE aik.did = $1 AND aik.status = 'active'
            UNION
            SELECT user_id FROM agents WHERE did = $1
            LIMIT 1
            "#,
        )
        .bind(&recipient_did)
        .fetch_optional(&pool)
        .await
        .map_err(|error| internal_error("failed to resolve recipient owner", error))?;
        if let Some(row) = owner_row {
            use sqlx::Row;
            let owner_uuid: Uuid = row.get("user_id");
            recipient_owner_uuid_db = Some(owner_uuid);
            evaluate_block_decision_db(&pool, owner_uuid, &sender_did, &sender_world_id)
                .await
                .map_err(|message| internal_server_error(&message))?
        } else {
            BlockDecision::Allow
        }
    } else if let Some(recipient_owner) = recipient_owner_in_memory(&state, &recipient_did) {
        let decision =
            evaluate_block_decision(&state, &recipient_owner, &sender_did, &sender_world_id);
        recipient_owner_id_mem = Some(recipient_owner);
        decision
    } else {
        BlockDecision::Allow
    };
    {
        match block_decision {
            BlockDecision::Stealth => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        message: "recipient not found or blocked by policy".to_string(),
                    }),
                ));
            }
            BlockDecision::SilentDrop => {
                // L1: pretend acceptance, never persist or notify recipient.
                return Ok((
                    StatusCode::ACCEPTED,
                    Json(SendMessageResponse {
                        message_id: Uuid::new_v4(),
                        status: "delivered".to_string(),
                    }),
                ));
            }
            BlockDecision::Allow => {}
        }
    }

    let replay_key = format!("{sender_did}:{nonce}");
    if !check_and_record_message_replay(&state, &replay_key)
        .await
        .map_err(|message| internal_server_error(&message))?
    {
        return Err(validation_error("replayed message nonce is not allowed"));
    }

    record_first_seen(&state, &sender_world_id, Utc::now().timestamp());
    let trust_score = if let Some(pool) = maybe_pool.clone() {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS count FROM blocks
            WHERE (level = 'l1_did' AND target_did = $1)
               OR (level IN ('l2_identity', 'l3_stealth') AND target_world_id = $2)
            "#,
        )
        .bind(&sender_did)
        .bind(&sender_world_id)
        .fetch_one(&pool)
        .await
        .map_err(|error| internal_error("failed to count blocks", error))?;
        use sqlx::Row;
        let count: i64 = row.get("count");
        let blocks = count.clamp(0, u32::MAX as i64) as u32;
        compute_trust_score_with_blocks(
            &state,
            &user_id,
            &sender_did,
            &sender_world_id,
            &verification_level,
            blocks,
        )
    } else {
        compute_trust_score(
            &state,
            &user_id,
            &sender_did,
            &sender_world_id,
            &verification_level,
        )
    };
    let (mut delivery_status, mut priority) = route_for_trust_score(trust_score);

    // SECURITY: AI spam filter pipeline. Layer 1 always runs (cheap deny-list
    // + burst counter); Layer 2 runs only when an external filter service is
    // configured. A flag from either layer downgrades the message to the
    // pending_approval queue so the recipient can review before exposure.
    let mut ai_category: Option<String> =
        apply_layer1_spam_filter(&state, &sender_did).map(|c| c.to_string());
    if ai_category.is_none() && trust_score < 0.5 {
        ai_category = apply_layer2_spam_filter(&sender_did, trust_score).map(|c| c.to_string());
    }
    if ai_category.is_some() {
        delivery_status = "pending_approval";
        priority = "background";
    }

    let id = Uuid::new_v4();

    let db_send_context = if let Some(pool) = maybe_pool.as_ref() {
        let user_uuid = parse_user_uuid(&user_id)?;
        // Fail fast before touching BYOS storage. If attachment validation
        // rejects the request, we should not leave an orphaned encrypted
        // payload blob behind.
        let validated_attachments = if let Some(attachment_refs) = &payload.attachments {
            if attachment_refs.len() > ATTACHMENT_MAX_COUNT_PER_MESSAGE {
                return Err(validation_error(&format!(
                    "too many attachments (max {})",
                    ATTACHMENT_MAX_COUNT_PER_MESSAGE
                )));
            }
            let client = Client::new();
            prevalidate_attachments_for_message(pool, &client, user_uuid, attachment_refs).await?
        } else {
            Vec::new()
        };
        Some((user_uuid, validated_attachments))
    } else {
        None
    };

    let stored_payload = StoredMessageContent {
        encrypted_content: encrypted_content.clone(),
        encrypted_key: encrypted_key.clone(),
        nonce: nonce.clone(),
        content_type: content_type.clone(),
    };
    let encoded_payload = serde_json::to_string(&stored_payload).map_err(|_| {
        audit_storage_event(
            "storage_write",
            state.storage_backend,
            &user_id,
            Some(id),
            "error",
            Some("encode_failed"),
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "storage_error".to_string(),
                message: "failed to encode encrypted payload".to_string(),
            }),
        )
    })?;
    let storage_ref = match state.storage_backend {
        StorageBackend::LocalFs | StorageBackend::GoogleDriveMock => {
            let storage_file = storage_file_path(&state, &user_id, id);
            write_payload_atomically(&storage_file, &encoded_payload).map_err(|error| {
                audit_storage_event(
                    "storage_write",
                    state.storage_backend,
                    &user_id,
                    Some(id),
                    "error",
                    Some("persist_failed"),
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "storage_error".to_string(),
                        message: format!(
                            "failed to persist encrypted payload to local storage: {error}"
                        ),
                    }),
                )
            })?;
            storage_ref_for_locator(state.storage_backend, &id.to_string())
        }
        StorageBackend::GoogleDrive => {
            let client = Client::new();
            let file_id = gdrive_create_file(&client, id, &encoded_payload)
                .await
                .map_err(|error| {
                    audit_storage_event(
                        "storage_write",
                        state.storage_backend,
                        &user_id,
                        Some(id),
                        "error",
                        Some("persist_failed"),
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "storage_error".to_string(),
                            message: format!(
                                "failed to persist encrypted payload to Google Drive: {error}"
                            ),
                        }),
                    )
                })?;
            storage_ref_for_locator(state.storage_backend, &file_id)
        }
        StorageBackend::S3 => {
            let client = Client::new();
            let key = s3_put_object(&client, id, &encoded_payload)
                .await
                .map_err(|error| {
                    audit_storage_event(
                        "storage_write",
                        state.storage_backend,
                        &user_id,
                        Some(id),
                        "error",
                        Some("persist_failed"),
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "storage_error".to_string(),
                            message: format!("failed to persist encrypted payload to S3: {error}"),
                        }),
                    )
                })?;
            storage_ref_for_locator(state.storage_backend, &key)
        }
        StorageBackend::Ipfs => {
            let client = Client::new();
            let cid = ipfs_create_file(&client, id, &encoded_payload)
                .await
                .map_err(|error| {
                    audit_storage_event(
                        "storage_write",
                        state.storage_backend,
                        &user_id,
                        Some(id),
                        "error",
                        Some("persist_failed"),
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "storage_error".to_string(),
                            message: format!(
                                "failed to persist encrypted payload to IPFS: {error}"
                            ),
                        }),
                    )
                })?;
            storage_ref_for_locator(state.storage_backend, &cid)
        }
    };
    audit_storage_event(
        "storage_write",
        state.storage_backend,
        &user_id,
        Some(id),
        "ok",
        None,
    );

    // Messages flagged by the spam pipeline land in pending_approval; low-
    // trust messages caught by trust_score routing go to spam. Everything
    // else lands in the inbox. Folder is a presentation concern and does
    // not affect the delivery ACK we return to the sender.
    let initial_folder = if delivery_status == "pending_approval" {
        "pending_approval"
    } else if ai_category.as_deref() == Some("spam") {
        "spam"
    } else {
        "inbox"
    };

    let message = MessageRecord {
        id,
        sender_did,
        sender_label: None,
        recipient_did,
        recipient_label: None,
        thread_id: metadata.and_then(|m| m.thread_id),
        subject_encrypted,
        storage_ref,
        status: "unread".to_string(),
        priority: priority.to_string(),
        ai_category: ai_category.clone(),
        created_at: Utc::now().to_rfc3339(),
        trust_score,
        folder: initial_folder.to_string(),
        starred: false,
    };

    if let Some(pool) = maybe_pool {
        let (user_uuid, validated_attachments) =
            db_send_context.expect("db_send_context must exist when database pool exists");

        // Cross-user send splits into two message_index rows (one per
        // owner) so each side's inbox query, filtered by owner_user_id,
        // can see the message. Same-user send collapses to a single row
        // to preserve prior behaviour (no duplicate inbox listing).
        //
        // `message.id` here is the sender-side row id and is returned to
        // the caller as `message_id`. `recipient_row_id` is allocated on
        // the fly when the recipient differs.
        let sender_row_id = message.id;
        let recipient_user = recipient_owner_uuid_db.unwrap_or(user_uuid);
        let is_cross_user = recipient_user != user_uuid;
        let recipient_row_id = if is_cross_user {
            Uuid::new_v4()
        } else {
            sender_row_id
        };

        // ---- Phase 2: atomic DB writes. ----
        // message_index INSERT(s) and message_attachments + attachment_uploads
        // updates all happen inside one transaction. If anything fails mid-
        // flight, `tx` is dropped without commit and Postgres rolls back,
        // leaving no partial-write ghosts for the caller to discover.
        let mut tx = pool
            .begin()
            .await
            .map_err(|error| internal_error("failed to start send transaction", error))?;
        let tx_result: Result<(), (StatusCode, Json<ErrorResponse>)> = async {
            if is_cross_user {
                // Sender-side bookkeeping row ("sent" folder, status="sent").
                sqlx::query(
                    r#"
                    INSERT INTO message_index (
                      id,
                      owner_user_id,
                      sender_did,
                      recipient_did,
                      thread_id,
                      subject_encrypted,
                      storage_ref,
                      status,
                      priority,
                      ai_category,
                      trust_score,
                      folder,
                      starred,
                      created_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'sent', $8, $9, $10, 'sent', FALSE, NOW())
                    "#,
                )
                .bind(sender_row_id)
                .bind(user_uuid)
                .bind(&message.sender_did)
                .bind(&message.recipient_did)
                .bind(message.thread_id)
                .bind(&message.subject_encrypted)
                .bind(&message.storage_ref)
                .bind(&message.priority)
                .bind(&message.ai_category)
                .bind(message.trust_score)
                .execute(&mut *tx)
                .await
                .map_err(|error| {
                    internal_error("failed to persist sender-side message index", error)
                })?;

                // Recipient-side deliverable row (inbox / spam / pending_approval,
                // status="unread").
                sqlx::query(
                    r#"
                    INSERT INTO message_index (
                      id,
                      owner_user_id,
                      sender_did,
                      recipient_did,
                      thread_id,
                      subject_encrypted,
                      storage_ref,
                      status,
                      priority,
                      ai_category,
                      trust_score,
                      folder,
                      starred,
                      created_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'unread', $8, $9, $10, $11, FALSE, NOW())
                    "#,
                )
                .bind(recipient_row_id)
                .bind(recipient_user)
                .bind(&message.sender_did)
                .bind(&message.recipient_did)
                .bind(message.thread_id)
                .bind(&message.subject_encrypted)
                .bind(&message.storage_ref)
                .bind(&message.priority)
                .bind(&message.ai_category)
                .bind(message.trust_score)
                .bind(&message.folder)
                .execute(&mut *tx)
                .await
                .map_err(|error| {
                    internal_error("failed to persist recipient-side message index", error)
                })?;
            } else {
                // Same-user send: single row with folder="inbox"/"spam"/"pending_approval".
                sqlx::query(
                    r#"
                    INSERT INTO message_index (
                      id,
                      owner_user_id,
                      sender_did,
                      recipient_did,
                      thread_id,
                      subject_encrypted,
                      storage_ref,
                      status,
                      priority,
                      ai_category,
                      trust_score,
                      folder,
                      starred,
                      created_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'unread', $8, $9, $10, $11, FALSE, NOW())
                    "#,
                )
                .bind(sender_row_id)
                .bind(user_uuid)
                .bind(&message.sender_did)
                .bind(&message.recipient_did)
                .bind(message.thread_id)
                .bind(&message.subject_encrypted)
                .bind(&message.storage_ref)
                .bind(&message.priority)
                .bind(&message.ai_category)
                .bind(message.trust_score)
                .bind(&message.folder)
                .execute(&mut *tx)
                .await
                .map_err(|error| internal_error("failed to persist message index", error))?;
            }

            if !validated_attachments.is_empty() {
                // Per-row ownership for message_attachments: every link row
                // gets the same owner_user_id as the message_index row it
                // points at. This keeps the (owner, message_id) tuple
                // consistent across the two tables so the recipient — who
                // owns the recipient-side message_index row — also owns the
                // recipient-side message_attachments link and can pass
                // `owner_user_id = current_user` checks in
                // generate_attachment_download_url.
                for v in &validated_attachments {
                    insert_message_attachment_row_in_tx(
                        &mut tx,
                        recipient_user,
                        recipient_row_id,
                        &message.sender_did,
                        &message.recipient_did,
                        v,
                    )
                    .await?;
                    if is_cross_user {
                        insert_message_attachment_row_in_tx(
                            &mut tx,
                            user_uuid,
                            sender_row_id,
                            &message.sender_did,
                            &message.recipient_did,
                            v,
                        )
                        .await?;
                    }
                }

                // Flip the attachment_uploads CAS exactly once per send.
                // Ownership of the upload row stays with the sender — they
                // paid the intent and the PUT — regardless of how many
                // message_attachments rows we inserted above. `attached_message_id`
                // points at the sender-side row as a bookkeeping hint.
                mark_attachments_attached_in_tx(
                    &mut tx,
                    user_uuid,
                    sender_row_id,
                    &validated_attachments,
                )
                .await?;
            }

            tx.commit()
                .await
                .map_err(|error| internal_error("failed to commit send transaction", error))?;
            Ok(())
        }
        .await;

        if let Err(error) = tx_result {
            if let Err(cleanup_error) =
                delete_storage_object_by_ref(&state, &user_id, &message.storage_ref).await
            {
                audit_storage_event(
                    "storage_rollback_cleanup",
                    state.storage_backend,
                    &user_id,
                    Some(id),
                    "error",
                    Some("payload_cleanup_failed"),
                );
                eprintln!("failed to delete orphaned payload after send rollback: {cleanup_error}");
            } else {
                audit_storage_event(
                    "storage_rollback_cleanup",
                    state.storage_backend,
                    &user_id,
                    Some(id),
                    "ok",
                    None,
                );
            }
            return Err(error);
        }

        // ---- Phase 3: post-commit audit. ----
        // Emit one event per attached attachment AFTER the transaction
        // lands. If we emitted inside the tx, a rollback would leave dangling
        // audit spawns pointing at rows that never existed.
        for v in &validated_attachments {
            record_audit_event(
                pool.clone(),
                user_uuid,
                None,
                None,
                "attachment_attached_to_message",
                serde_json::json!({
                    "attachment_id": v.attachment_id.to_string(),
                    "object_key": v.object_key,
                    "message_id": sender_row_id.to_string(),
                    "recipient_message_id": recipient_row_id.to_string(),
                    "recipient_did": &message.recipient_did,
                    "ciphertext_size_bytes": v.size_bytes,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                }),
            );
        }

        // ---- Phase 4: auto-reply evaluator (docs/25b + 25c). ----
        // Fire-and-forget decision on the recipient-side row. Skips
        // the sender-only "sent" ghost for same-user sends — those
        // aren't deliveries the recipient needs an auto-reply for.
        // Also skips when the incoming envelope is itself an auto-reply
        // (docs/25c §3.1 — the `auto_reply_origin` metadata marker is
        // our loop-prevention guardrail).
        let eligible_for_evaluator = is_cross_user || message.folder != "sent";
        let auto_reply_origin = metadata.and_then(|m| m.auto_reply_origin.clone());
        if eligible_for_evaluator {
            if let Some(origin) = auto_reply_origin.as_deref() {
                record_audit_event(
                    pool.clone(),
                    recipient_user,
                    None,
                    None,
                    "auto_reply_skipped_incoming_is_auto_reply",
                    serde_json::json!({
                        "message_id": recipient_row_id.to_string(),
                        "sender_did": message.sender_did,
                        "recipient_did": message.recipient_did,
                        "origin": origin,
                    }),
                );
            } else {
                spawn_auto_reply_evaluation(
                    pool.clone(),
                    recipient_user,
                    recipient_row_id,
                    message.recipient_did.clone(),
                    message.sender_did.clone(),
                    message.priority.clone(),
                    message.trust_score.into(),
                );
            }
        }
    } else {
        // In-memory path mirrors the DB split: when the recipient is a
        // different in-memory user, push to both buckets with the right
        // folder on each side; same-user collapses to a single row.
        let recipient_owner_id = recipient_owner_id_mem.clone();
        let is_cross_user_mem = matches!(
            recipient_owner_id.as_deref(),
            Some(rid) if rid != user_id.as_str()
        );

        if is_cross_user_mem {
            let rid = recipient_owner_id.expect("recipient owner present");
            let mut sender_row = message.clone();
            sender_row.folder = "sent".to_string();
            sender_row.status = "sent".to_string();

            let mut recipient_row = message;
            recipient_row.id = Uuid::new_v4();

            let mut lock = state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            lock.entry(user_id).or_default().push(sender_row);
            lock.entry(rid).or_default().push(recipient_row);
        } else {
            state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(user_id)
                .or_default()
                .push(message);
        }
    }

    // Audit: agent_message_sent (for Policy L3 counting + audit trail)
    if let AuthContext::Agent {
        credential_id, aid, ..
    } = &ctx
    {
        let audit_pool = state.database_pool().await.ok().flatten();
        if let Some(pool) = audit_pool {
            let user_uuid = parse_user_uuid(ctx.user_id())?;
            record_audit_event(
                pool,
                user_uuid,
                Some(*credential_id),
                Some(aid.clone()),
                "agent_message_sent",
                serde_json::json!({
                    "message_id": id.to_string(),
                }),
            );
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(SendMessageResponse {
            message_id: id,
            status: delivery_status.to_string(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Attachment handlers (docs/17_attachment_upload_r2_spec.md)
// ---------------------------------------------------------------------------

/// Dedicated per-IP budget for POST /attachments/intents. Kept separate
/// from the global per-IP budget so cheap intent calls from one attacker
/// IP can't starve the shared bucket used by the rest of the API.
fn consume_attachment_intent_ip_budget(state: &AppState, client_ip: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut budgets = state
        .attachment_intent_ip_budgets
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Evict stale entries so the map stays bounded.
    if budgets.len() > MAX_RATE_LIMIT_ENTRIES {
        budgets.retain(|_, b| {
            now - b.window_started_at < ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS * 2
        });
    }
    let budget = budgets
        .entry(client_ip.to_string())
        .or_insert(RequestBudget {
            window_started_at: now,
            count: 0,
        });
    if now - budget.window_started_at >= ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS {
        budget.window_started_at = now;
        budget.count = 0;
    }
    if budget.count >= ATTACHMENT_INTENT_RATE_LIMIT_PER_IP {
        return false;
    }
    budget.count += 1;
    true
}

/// Per-user rate limit on `POST /attachments/intents`. Counts intents
/// `issued_at` within the sliding window.
async fn check_attachment_intent_rate_limit(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let row = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) FROM attachment_uploads
        WHERE owner_user_id = $1
          AND issued_at > NOW() - make_interval(secs => $2)
        "#,
    )
    .bind(user_id)
    .bind(ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS as f64)
    .fetch_one(pool)
    .await
    .map_err(|error| internal_error("rate limit check failed", error))?;
    if row >= ATTACHMENT_INTENT_RATE_LIMIT_PER_USER {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limited".to_string(),
                message: format!(
                    "too many attachment intents (limit: {} per {} seconds)",
                    ATTACHMENT_INTENT_RATE_LIMIT_PER_USER, ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS
                ),
            }),
        ));
    }
    Ok(())
}

async fn create_attachment_intent(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<CreateAttachmentIntentRequest>,
) -> Result<(StatusCode, Json<CreateAttachmentIntentResponse>), (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    // Both human and agent contexts may create intents; agent tokens need
    // messages.send scope (since attachment upload is a precursor to send).
    if matches!(&ctx, AuthContext::Agent { .. }) {
        ctx.require_scope("messages.send")?;
    }
    let user_id = ctx.user_id().to_string();
    let user_uuid = parse_user_uuid(&user_id)?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Per-IP rate limit — enforced before DB work so cheap intent spam from a
    // single IP fails fast without touching Postgres.
    if !consume_attachment_intent_ip_budget(&state, &client_ip) {
        // Audit the rejection so ops can see the IP + UA of the offender.
        // DB may be unavailable here too — fire-and-forget on a best-effort
        // pool, skipping if we can't get one.
        if let Ok(Some(pool)) = state.database_pool().await {
            record_audit_event(
                pool,
                user_uuid,
                None,
                None,
                "attachment_upload_rejected_rate_limit",
                serde_json::json!({
                    "scope": "per_ip",
                    "limit": ATTACHMENT_INTENT_RATE_LIMIT_PER_IP,
                    "window_secs": ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                }),
            );
        }
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limited".to_string(),
                message: format!(
                    "too many attachment intents from this IP (limit: {} per {} seconds)",
                    ATTACHMENT_INTENT_RATE_LIMIT_PER_IP, ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS
                ),
            }),
        ));
    }

    // Validate input
    let ciphertext_size = payload
        .ciphertext_size_bytes
        .ok_or_else(|| validation_error("ciphertext_size_bytes is required"))?;
    if ciphertext_size <= 0 {
        return Err(validation_error("ciphertext_size_bytes must be > 0"));
    }
    if ciphertext_size > ATTACHMENT_MAX_CIPHERTEXT_BYTES {
        return Err(validation_error(&format!(
            "ciphertext_size_bytes exceeds limit of {}",
            ATTACHMENT_MAX_CIPHERTEXT_BYTES
        )));
    }

    let sender_did = payload
        .sender_did
        .clone()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !sender_did.is_empty() {
        validate_did(&sender_did, "sender_did")?;
    }

    let draft_id = payload
        .draft_id
        .clone()
        .unwrap_or_default()
        .trim()
        .to_string();
    let draft_ref = if draft_id.is_empty() {
        "none".to_string()
    } else {
        draft_id.clone()
    };

    // DB required for attachments
    let pool = match state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
    {
        Some(p) => p,
        None => return Err(database_required_but_unavailable_error()),
    };

    // Verify sender_did ownership (if provided)
    if !sender_did.is_empty() {
        let owned = agent_owned_by_user_in_db(&pool, user_uuid, &sender_did)
            .await
            .map_err(|msg| internal_server_error(&msg))?;
        match owned {
            Some(agent) => enforce_agent_bound_aid(&ctx, &agent.aid)?,
            None => {
                return Err(forbidden_error(
                    "sender_did is not owned by the authenticated user",
                ))
            }
        }
    }

    // Per-user rate limit
    check_attachment_intent_rate_limit(&pool, user_uuid).await?;

    // Load R2 config
    let config = s3_config_from_env()
        .map_err(|msg| internal_error("attachment storage not configured", msg))?;

    // Generate identifiers
    let attachment_id = Uuid::new_v4();
    let object_key = s3_attachment_key_for(&config, user_uuid, &draft_ref, attachment_id);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(ATTACHMENT_PUT_URL_TTL_SECS as i64);
    let issued_at_str = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Metadata headers that MUST be sent by the client and are bound into the
    // presigned URL signature. If the client tries to change them, R2 will
    // reject the PUT.
    let extra_signed_headers: Vec<(String, String)> = vec![
        (
            "x-amz-meta-attachment-id".to_string(),
            attachment_id.to_string(),
        ),
        (
            "x-amz-meta-owner-user-id".to_string(),
            user_uuid.to_string(),
        ),
        ("x-amz-meta-issued-at".to_string(), issued_at_str.clone()),
        (
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        ),
    ];

    let upload_url = s3_presign_url(
        &config,
        "PUT",
        &object_key,
        ATTACHMENT_PUT_URL_TTL_SECS,
        &extra_signed_headers,
        &[],
    );

    // Persist the intent row. We let PostgreSQL materialize `issued_at`
    // and `upload_expires_at` to avoid binding chrono types (sqlx chrono
    // feature is not enabled).
    sqlx::query(
        r#"
        INSERT INTO attachment_uploads (
            id, owner_user_id, sender_did, draft_id,
            r2_bucket, object_key,
            ciphertext_size_limit,
            status, issued_at, upload_expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'issued', NOW(),
                  NOW() + make_interval(secs => $8))
        "#,
    )
    .bind(attachment_id)
    .bind(user_uuid)
    .bind(if sender_did.is_empty() {
        None
    } else {
        Some(sender_did)
    })
    .bind(if draft_id.is_empty() {
        None
    } else {
        Some(draft_id.clone())
    })
    .bind(&config.bucket)
    .bind(&object_key)
    .bind(ATTACHMENT_MAX_CIPHERTEXT_BYTES)
    .bind(ATTACHMENT_PUT_URL_TTL_SECS as f64)
    .execute(&pool)
    .await
    .map_err(|error| internal_error("failed to persist intent", error))?;

    // Audit — include client_ip + user_agent in detail so incident response
    // can correlate attachment upload attempts with other API traffic.
    // Emit under the spec's name (`attachment_upload_intent_created`); the
    // legacy `attachment_intent_issued` event is retired in this commit.
    record_audit_event(
        pool.clone(),
        user_uuid,
        None,
        None,
        "attachment_upload_intent_created",
        serde_json::json!({
            "attachment_id": attachment_id.to_string(),
            "object_key": object_key,
            "ciphertext_size_bytes": ciphertext_size,
            "draft_id": draft_id,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }),
    );

    let required_headers = serde_json::json!({
        "Content-Type": "application/octet-stream",
        "x-amz-meta-attachment-id": attachment_id.to_string(),
        "x-amz-meta-owner-user-id": user_uuid.to_string(),
        "x-amz-meta-issued-at": issued_at_str,
    });

    Ok((
        StatusCode::CREATED,
        Json(CreateAttachmentIntentResponse {
            attachment_id,
            upload_url,
            upload_method: "PUT".to_string(),
            upload_expires_at: expires_at.to_rfc3339(),
            required_headers,
            max_ciphertext_size_bytes: ATTACHMENT_MAX_CIPHERTEXT_BYTES,
        }),
    ))
}

async fn complete_attachment(
    State(state): State<AppState>,
    Path(attachment_id): Path<Uuid>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<CompleteAttachmentRequest>,
) -> Result<(StatusCode, Json<CompleteAttachmentResponse>), (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    if matches!(&ctx, AuthContext::Agent { .. }) {
        ctx.require_scope("messages.send")?;
    }
    let user_uuid = parse_user_uuid(ctx.user_id())?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Per-IP burst limit. Shares the attachment-operations budget with
    // /attachments/intents so the overall ceiling per IP (60/min) covers
    // the full upload flow rather than letting complete be abused to
    // enumerate R2 state cheaply.
    if !consume_attachment_intent_ip_budget(&state, &client_ip) {
        if let Ok(Some(audit_pool)) = state.database_pool().await {
            record_audit_event(
                audit_pool,
                user_uuid,
                None,
                None,
                "attachment_upload_rejected_rate_limit",
                serde_json::json!({
                    "scope": "per_ip",
                    "endpoint": "complete",
                    "limit": ATTACHMENT_INTENT_RATE_LIMIT_PER_IP,
                    "window_secs": ATTACHMENT_INTENT_RATE_LIMIT_WINDOW_SECS,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                }),
            );
        }
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limited".to_string(),
                message: "too many attachment operations from this IP".to_string(),
            }),
        ));
    }

    let expected_size = payload
        .ciphertext_size_bytes
        .ok_or_else(|| validation_error("ciphertext_size_bytes is required"))?;

    let pool = match state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
    {
        Some(p) => p,
        None => return Err(database_required_but_unavailable_error()),
    };

    // Load intent, verify ownership + status + TTL. Time comparison happens
    // in SQL (PostgreSQL) because sqlx chrono feature is not enabled and we
    // cannot materialize TIMESTAMPTZ into Rust types cleanly.
    let row = sqlx::query(
        r#"
        SELECT object_key, ciphertext_size_limit, status,
               (upload_expires_at < NOW()) AS is_expired
        FROM attachment_uploads
        WHERE id = $1 AND owner_user_id = $2
        "#,
    )
    .bind(attachment_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to load intent", error))?;

    let row = row.ok_or_else(|| not_found_error("attachment not found"))?;
    use sqlx::Row as SqlxRow;
    let object_key: String = row.get("object_key");
    let size_limit: i64 = row.get("ciphertext_size_limit");
    let status: String = row.get("status");
    let is_expired: bool = row.get("is_expired");

    if status != "issued" {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "invalid_state".to_string(),
                message: format!("attachment status is '{status}', expected 'issued'"),
            }),
        ));
    }
    if is_expired {
        // Mark as expired
        let _ = sqlx::query(
            "UPDATE attachment_uploads SET status = 'expired' WHERE id = $1 AND status = 'issued'",
        )
        .bind(attachment_id)
        .execute(&pool)
        .await;
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "expired".to_string(),
                message: "upload intent has expired".to_string(),
            }),
        ));
    }
    if expected_size > size_limit {
        return Err(validation_error(
            "ciphertext_size_bytes exceeds intent limit",
        ));
    }

    // HEAD R2 to verify actual size and metadata
    let client = Client::new();
    let (actual_size, metadata) = s3_head_object(&client, &object_key)
        .await
        .map_err(|error| {
            (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "object_not_found".to_string(),
                    message: format!("R2 object not found or inaccessible: {error}"),
                }),
            )
        })?;

    if actual_size != expected_size {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "size_mismatch".to_string(),
                message: format!("expected ciphertext_size {expected_size}, actual {actual_size}"),
            }),
        ));
    }

    // Verify R2 metadata matches intent (tamper detection).
    // The metadata was bound into the presigned URL signature, so if it was
    // changed the PUT would have failed — but we re-verify to defend against
    // R2 or middlebox bugs.
    if metadata.get("attachment-id").map(String::as_str) != Some(&attachment_id.to_string()) {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "metadata_mismatch".to_string(),
                message: "object attachment-id metadata mismatch".to_string(),
            }),
        ));
    }
    if metadata.get("owner-user-id").map(String::as_str) != Some(&user_uuid.to_string()) {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "metadata_mismatch".to_string(),
                message: "object owner-user-id metadata mismatch".to_string(),
            }),
        ));
    }

    // Flip status to uploaded
    sqlx::query(
        r#"
        UPDATE attachment_uploads
        SET status = 'uploaded',
            ciphertext_size_bytes = $1,
            uploaded_at = NOW(),
            last_verified_at = NOW()
        WHERE id = $2 AND owner_user_id = $3 AND status = 'issued'
        "#,
    )
    .bind(actual_size)
    .bind(attachment_id)
    .bind(user_uuid)
    .execute(&pool)
    .await
    .map_err(|error| internal_error("failed to mark uploaded", error))?;

    // Emit under the spec's name (`attachment_upload_completed`); retires the
    // legacy `attachment_uploaded_verified` event.
    record_audit_event(
        pool.clone(),
        user_uuid,
        None,
        None,
        "attachment_upload_completed",
        serde_json::json!({
            "attachment_id": attachment_id.to_string(),
            "object_key": object_key,
            "ciphertext_size_bytes": actual_size,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }),
    );

    Ok((
        StatusCode::OK,
        Json(CompleteAttachmentResponse {
            attachment_id,
            status: "uploaded".to_string(),
        }),
    ))
}

/// Associate previously-uploaded attachments with a message.
///
/// Called inside `send_message` after the message row is persisted. Every
/// attachment must pass these checks:
///   - owner_user_id matches the authenticated user
///   - status == 'uploaded' (complete phase done, not yet attached, not expired)
///   - the object still exists in R2 (HEAD re-verification)
///   - per-message count and cumulative size limits are respected
///
/// On success each attachment row's status flips to 'attached' and a row is
/// written to `message_attachments`.
// clippy::too_many_arguments: this helper spans the full send_message context
// (user, message, both DIDs, refs, and request-provenance fields for audit);
// bundling into a struct would obscure the flow without reducing complexity.
#[allow(clippy::too_many_arguments)]
/// A single attachment that passed `prevalidate_attachments_for_message` and
/// is ready to be linked to a message inside the send transaction.
#[derive(Debug, Clone)]
struct ValidatedAttachment {
    attachment_id: Uuid,
    object_key: String,
    size_bytes: i64,
    metadata_encrypted: String,
    metadata_nonce: String,
}

/// Read-only + external-I/O phase of attachment attachment. Runs BEFORE the
/// message-send transaction opens, so:
///   - the transaction stays short (no R2 HEAD blocking it)
///   - a bad attachment aborts the send before any DB write lands
///   - re-tries after a validation failure see clean DB state
///
/// Validates, for each incoming AttachmentRef:
///   - the attachment row exists and is owned by the caller
///   - its status is 'uploaded' (complete phase done, not yet attached)
///   - cumulative ciphertext size fits under the per-message cap
///   - the R2 object still exists (HEAD)
///   - the client-supplied encrypted-metadata fields are non-empty
///
/// On success returns a Vec<ValidatedAttachment> that
/// `link_attachments_in_tx` consumes inside the transaction.
async fn prevalidate_attachments_for_message(
    pool: &PgPool,
    client: &Client,
    user_uuid: Uuid,
    refs: &[AttachmentRef],
) -> Result<Vec<ValidatedAttachment>, (StatusCode, Json<ErrorResponse>)> {
    let mut validated: Vec<ValidatedAttachment> = Vec::with_capacity(refs.len());
    let mut cumulative: i64 = 0;
    for att_ref in refs {
        if att_ref.metadata_encrypted.trim().is_empty() || att_ref.metadata_nonce.trim().is_empty()
        {
            return Err(validation_error(&format!(
                "attachment {} metadata_encrypted/metadata_nonce are required",
                att_ref.attachment_id
            )));
        }

        let row = sqlx::query(
            r#"
            SELECT object_key, ciphertext_size_bytes, status, upload_expires_at
            FROM attachment_uploads
            WHERE id = $1 AND owner_user_id = $2
            "#,
        )
        .bind(att_ref.attachment_id)
        .bind(user_uuid)
        .fetch_optional(pool)
        .await
        .map_err(|error| internal_error("failed to load attachment", error))?;

        let row = row.ok_or_else(|| {
            validation_error(&format!(
                "attachment {} not found or not owned by user",
                att_ref.attachment_id
            ))
        })?;
        use sqlx::Row as SqlxRow;
        let object_key: String = row.get("object_key");
        let size_bytes: Option<i64> = row.get("ciphertext_size_bytes");
        let status: String = row.get("status");

        if status != "uploaded" {
            return Err(validation_error(&format!(
                "attachment {} has status '{}', expected 'uploaded'",
                att_ref.attachment_id, status
            )));
        }

        let size = size_bytes.unwrap_or(0);
        cumulative += size;
        if cumulative > ATTACHMENT_MAX_CUMULATIVE_BYTES {
            return Err(validation_error(&format!(
                "cumulative attachment size exceeds {} bytes",
                ATTACHMENT_MAX_CUMULATIVE_BYTES
            )));
        }

        // Re-verify object still exists on R2. Skipped only when running
        // under the explicit test escape-hatch env var (refused at startup
        // when NODE_ENV=production, so this can never be bypassed live).
        // DB integration tests use this to exercise the attachment-linking
        // SQL without spinning up MinIO.
        let skip_s3_head = std::env::var("AGENT_INBOX_ALLOW_SKIP_S3_HEAD_IN_TESTS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !skip_s3_head {
            s3_head_object(client, &object_key).await.map_err(|_| {
                (
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        error: "object_missing".to_string(),
                        message: format!(
                            "R2 object for attachment {} is missing",
                            att_ref.attachment_id
                        ),
                    }),
                )
            })?;
        }

        validated.push(ValidatedAttachment {
            attachment_id: att_ref.attachment_id,
            object_key,
            size_bytes: size,
            metadata_encrypted: att_ref.metadata_encrypted.clone(),
            metadata_nonce: att_ref.metadata_nonce.clone(),
        });
    }
    Ok(validated)
}

/// Insert one `message_attachments` row. Called INSIDE the message-send
/// transaction, so any error here rolls the whole send back. No external
/// I/O — prevalidation has already happened.
///
/// `row_owner_user_uuid` is whoever owns the message_index row that this
/// link attaches to. For same-user sends that's the sender; for
/// cross-user sends the helper is called once with the recipient's uuid
/// (for the recipient-side row) and again with the sender's uuid (for
/// the sender-side mirror). Keeping the `message_attachments.owner` in
/// sync with the `message_index.owner` for the same `message_id` is
/// what makes `generate_attachment_download_url`'s JOIN-with-owner
/// check succeed on both sides after cross-user delivery.
async fn insert_message_attachment_row_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row_owner_user_uuid: Uuid,
    message_id: Uuid,
    sender_did: &str,
    recipient_did: &str,
    v: &ValidatedAttachment,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    sqlx::query(
        r#"
        INSERT INTO message_attachments (
            id, message_id, attachment_upload_id, owner_user_id,
            sender_did, recipient_did,
            metadata_encrypted, metadata_nonce, ciphertext_size_bytes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(v.attachment_id)
    .bind(row_owner_user_uuid)
    .bind(sender_did)
    .bind(recipient_did)
    .bind(&v.metadata_encrypted)
    .bind(&v.metadata_nonce)
    .bind(v.size_bytes)
    .execute(&mut **tx)
    .await
    .map_err(|error| internal_error("failed to link attachment", error))?;
    Ok(())
}

/// Flip `attachment_uploads.status` from `uploaded` to `attached` for
/// every entry in `validated`. Called ONCE per send (even in cross-user
/// sends that link two `message_attachments` rows per attachment) — the
/// CAS `status = 'uploaded'` guard is what guarantees an attachment
/// cannot be double-spent across concurrent sends.
///
/// `attached_message_id` is only used for server-side bookkeeping /
/// cleanup heuristics; pointing it at the sender-side row id is fine
/// because the `message_attachments` table is the authoritative link.
async fn mark_attachments_attached_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    upload_owner_user_uuid: Uuid,
    attached_message_id: Uuid,
    validated: &[ValidatedAttachment],
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    for v in validated {
        let updated = sqlx::query(
            r#"
            UPDATE attachment_uploads
            SET status = 'attached',
                attached_message_id = $1,
                last_verified_at = NOW()
            WHERE id = $2 AND owner_user_id = $3 AND status = 'uploaded'
            "#,
        )
        .bind(attached_message_id)
        .bind(v.attachment_id)
        .bind(upload_owner_user_uuid)
        .execute(&mut **tx)
        .await
        .map_err(|error| internal_error("failed to mark attached", error))?;

        if updated.rows_affected() == 0 {
            // Prevalidation saw status='uploaded'; the UPDATE now sees
            // something else. Another send grabbed this attachment first,
            // or the user revoked/deleted it in flight. Roll back.
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "attachment_race".to_string(),
                    message: format!(
                        "attachment {} was consumed or revoked by a concurrent operation",
                        v.attachment_id
                    ),
                }),
            ));
        }
    }
    Ok(())
}

async fn list_message_attachments(
    State(state): State<AppState>,
    Path(message_id): Path<Uuid>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<ListMessageAttachmentsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    if matches!(&ctx, AuthContext::Agent { .. }) {
        ctx.require_scope("messages.read")?;
    }
    let user_uuid = parse_user_uuid(ctx.user_id())?;

    let pool = match state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
    {
        Some(p) => p,
        None => return Err(database_required_but_unavailable_error()),
    };

    // Ownership check: user must own the message.
    let owner_row = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM message_index WHERE id = $1 AND owner_user_id = $2",
    )
    .bind(message_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to load message", error))?;

    if owner_row.is_none() {
        return Err(not_found_error("message not found"));
    }

    let rows = sqlx::query(
        r#"
        SELECT attachment_upload_id, metadata_encrypted, metadata_nonce, ciphertext_size_bytes
        FROM message_attachments
        WHERE message_id = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(message_id)
    .fetch_all(&pool)
    .await
    .map_err(|error| internal_error("failed to load attachments", error))?;

    use sqlx::Row as SqlxRow;
    let attachments: Vec<MessageAttachmentSummary> = rows
        .into_iter()
        .map(|row| MessageAttachmentSummary {
            attachment_id: row.get("attachment_upload_id"),
            metadata_encrypted: row.get("metadata_encrypted"),
            metadata_nonce: row.get("metadata_nonce"),
            ciphertext_size_bytes: row.get("ciphertext_size_bytes"),
        })
        .collect();

    Ok(Json(ListMessageAttachmentsResponse { attachments }))
}

async fn generate_attachment_download_url(
    State(state): State<AppState>,
    Path((message_id, attachment_id)): Path<(Uuid, Uuid)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<AttachmentDownloadUrlResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    if matches!(&ctx, AuthContext::Agent { .. }) {
        ctx.require_scope("messages.read")?;
    }
    let user_uuid = parse_user_uuid(ctx.user_id())?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Per-IP scraping guard. An attacker with a stolen cookie could
    // otherwise try to iterate attachment_ids for bulk presigned-URL
    // harvesting. Shares the attachment-operations budget.
    if !consume_attachment_intent_ip_budget(&state, &client_ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate_limited".to_string(),
                message: "too many attachment operations from this IP".to_string(),
            }),
        ));
    }

    let pool = match state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
    {
        Some(p) => p,
        None => return Err(database_required_but_unavailable_error()),
    };

    // Step 1: verify user owns the message (same condition as message_content).
    let msg_owned = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM message_index WHERE id = $1 AND owner_user_id = $2",
    )
    .bind(message_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to load message", error))?;
    if msg_owned.is_none() {
        return Err(not_found_error("message not found"));
    }

    // Step 2: verify the attachment row exists for this message, and the
    // underlying intent row is status='attached'.
    let row = sqlx::query(
        r#"
        SELECT au.object_key, au.status
        FROM message_attachments ma
        JOIN attachment_uploads au ON au.id = ma.attachment_upload_id
        WHERE ma.message_id = $1
          AND ma.attachment_upload_id = $2
          AND ma.owner_user_id = $3
        "#,
    )
    .bind(message_id)
    .bind(attachment_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to load attachment", error))?;

    let row = row.ok_or_else(|| not_found_error("attachment not found"))?;
    use sqlx::Row as SqlxRow;
    let object_key: String = row.get("object_key");
    let status: String = row.get("status");

    if status != "attached" {
        return Err(not_found_error("attachment is not in a downloadable state"));
    }

    // Step 3: generate a short-lived presigned GET URL. The
    // response-content-disposition=attachment query param is signed so the
    // browser never gets an inline URL.
    let config = s3_config_from_env()
        .map_err(|msg| internal_error("attachment storage not configured", msg))?;
    let extra_query = vec![(
        "response-content-disposition".to_string(),
        "attachment".to_string(),
    )];
    let download_url = s3_presign_url(
        &config,
        "GET",
        &object_key,
        ATTACHMENT_GET_URL_TTL_SECS,
        &[],
        &extra_query,
    );
    let expires_at = Utc::now() + chrono::Duration::seconds(ATTACHMENT_GET_URL_TTL_SECS as i64);

    record_audit_event(
        pool.clone(),
        user_uuid,
        None,
        None,
        "attachment_download_url_issued",
        serde_json::json!({
            "attachment_id": attachment_id.to_string(),
            "message_id": message_id.to_string(),
            "client_ip": client_ip,
            "user_agent": user_agent,
        }),
    );

    Ok(Json(AttachmentDownloadUrlResponse {
        download_url,
        expires_at: expires_at.to_rfc3339(),
    }))
}

async fn delete_attachment(
    State(state): State<AppState>,
    Path(attachment_id): Path<Uuid>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    if matches!(&ctx, AuthContext::Agent { .. }) {
        ctx.require_scope("messages.send")?;
    }
    let user_uuid = parse_user_uuid(ctx.user_id())?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let pool = match state
        .database_pool()
        .await
        .map_err(|msg| internal_server_error(&msg))?
    {
        Some(p) => p,
        None => return Err(database_required_but_unavailable_error()),
    };

    // Load: only `issued` or `uploaded` intents may be deleted by the owner.
    // 'attached' rows are tied to a message and removed via message deletion.
    let row = sqlx::query(
        r#"
        SELECT object_key, status
        FROM attachment_uploads
        WHERE id = $1 AND owner_user_id = $2
        "#,
    )
    .bind(attachment_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to load intent", error))?;

    let row = row.ok_or_else(|| not_found_error("attachment not found"))?;
    use sqlx::Row as SqlxRow;
    let object_key: String = row.get("object_key");
    let status: String = row.get("status");

    if status == "attached" {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "already_attached".to_string(),
                message: "attachment is linked to a message; delete the message instead"
                    .to_string(),
            }),
        ));
    }
    if status == "deleted" {
        return Ok(StatusCode::NO_CONTENT);
    }

    // User intent = delete → always set deleted_at.
    // R2 purge is best-effort; if it fails we leave purged_at NULL so the
    // background orphan cleanup retries. This is the whole point of splitting
    // deleted_at and purged_at into two columns.
    let client = Client::new();
    let r2_purged = s3_delete_object(&client, &object_key).await.is_ok();

    sqlx::query(
        r#"
        UPDATE attachment_uploads
        SET status = 'deleted',
            deleted_at = NOW(),
            purged_at = CASE WHEN $3 THEN NOW() ELSE purged_at END
        WHERE id = $1 AND owner_user_id = $2
        "#,
    )
    .bind(attachment_id)
    .bind(user_uuid)
    .bind(r2_purged)
    .execute(&pool)
    .await
    .map_err(|error| internal_error("failed to mark deleted", error))?;

    record_audit_event(
        pool.clone(),
        user_uuid,
        None,
        None,
        "attachment_deleted",
        serde_json::json!({
            "attachment_id": attachment_id.to_string(),
            "object_key": object_key,
            "r2_purged": r2_purged,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }),
    );

    // If R2 purge succeeded we emit the purged audit immediately so the
    // timeline reflects the real lifecycle. The background job only covers
    // the retry case.
    if r2_purged {
        record_audit_event(
            pool.clone(),
            user_uuid,
            None,
            None,
            "attachment_purged",
            serde_json::json!({
                "attachment_id": attachment_id.to_string(),
                "object_key": object_key,
                "trigger": "user_delete",
            }),
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Attachment orphan cleanup (docs/17 §12.1).
//
// Three kinds of orphans exist in the attachment lifecycle:
//   1. `issued` intents past upload_expires_at  → never PUT to R2.
//   2. `uploaded` intents >24h old              → PUT succeeded but the
//      sender never called POST /messages to attach them.
//   3. Objects still in R2 after status flipped to `deleted`/`expired`   —
//      the DB marker exists but the blob may have leaked past a transient
//      S3 failure.
//
// We want to:
//   - flip (1)/(2) to `expired` so retry logic stops considering them usable,
//   - purge the underlying R2 object for (1)/(2)/(3) best-effort,
//   - record an audit event per purge so operators can reconcile costs.
//
// The job runs as a background tokio task started at boot. It sleeps
// between passes and silently retries on any error — a cleanup failure must
// never crash the API process.
// ---------------------------------------------------------------------------

/// How often the background cleanup pass runs. Picked so that a single
/// oversight (R2 outage, DB restart) doesn't leak more than ~10 minutes of
/// orphans before the next sweep.
const ATTACHMENT_CLEANUP_INTERVAL_SECS: u64 = 10 * 60;
/// Intents that reached `uploaded` but never got attached to a message are
/// expired after this long. Matches the spec §12.1 "24h" bound.
const ATTACHMENT_UPLOADED_ORPHAN_SECS: i64 = 24 * 60 * 60;

/// Run one pass of the attachment orphan cleanup.
///
/// Returns `(intents_expired, objects_deleted)` for logging. Errors during a
/// single row's cleanup are absorbed — the job must make progress across
/// partial failures.
async fn run_attachment_cleanup_pass(pool: &PgPool) -> (u64, u64) {
    // Step 1: intents that expired without ever being PUT. Flip them to
    // `expired` and set deleted_at (= "ready for R2 purge, if an object
    // accidentally exists"). RETURNING gives us the list so we can emit a
    // per-row `attachment_upload_abandoned` audit event.
    let abandoned_issued = sqlx::query(
        r#"
        UPDATE attachment_uploads
        SET status = 'expired', deleted_at = NOW()
        WHERE status = 'issued' AND upload_expires_at < NOW()
        RETURNING id, owner_user_id, object_key
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_else(|err| {
        warn!(error = %err, "attachment cleanup: failed to expire issued intents");
        Vec::new()
    });
    for row in &abandoned_issued {
        use sqlx::Row as SqlxRow;
        let row_id: Uuid = row.get("id");
        let owner_user_id: Uuid = row.get("owner_user_id");
        let object_key: String = row.get("object_key");
        record_audit_event(
            pool.clone(),
            owner_user_id,
            None,
            None,
            "attachment_upload_abandoned",
            serde_json::json!({
                "attachment_id": row_id.to_string(),
                "object_key": object_key,
                "reason": "intent_expired_before_upload",
            }),
        );
    }

    // Step 2: PUT succeeded but the sender never called /messages to attach.
    let abandoned_uploaded = sqlx::query(
        r#"
        UPDATE attachment_uploads
        SET status = 'expired', deleted_at = NOW()
        WHERE status = 'uploaded'
          AND uploaded_at < NOW() - make_interval(secs => $1)
        RETURNING id, owner_user_id, object_key
        "#,
    )
    .bind(ATTACHMENT_UPLOADED_ORPHAN_SECS as f64)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|err| {
        warn!(error = %err, "attachment cleanup: failed to expire uploaded orphans");
        Vec::new()
    });
    for row in &abandoned_uploaded {
        use sqlx::Row as SqlxRow;
        let row_id: Uuid = row.get("id");
        let owner_user_id: Uuid = row.get("owner_user_id");
        let object_key: String = row.get("object_key");
        record_audit_event(
            pool.clone(),
            owner_user_id,
            None,
            None,
            "attachment_upload_abandoned",
            serde_json::json!({
                "attachment_id": row_id.to_string(),
                "object_key": object_key,
                "reason": "uploaded_but_not_attached",
            }),
        );
    }

    // Step 3: everything that needs R2 purging — deleted_at set, purged_at
    // still NULL. This covers:
    //   - rows the user just marked `DELETE /attachments/:id` whose
    //     synchronous R2 delete hit a transient error
    //   - rows we just expired in Steps 1/2 above
    //   - rows inherited from legacy single-flag code (handled via
    //     migration 0013 backfill)
    let purge_candidates = sqlx::query(
        r#"
        SELECT id, owner_user_id, object_key
        FROM attachment_uploads
        WHERE deleted_at IS NOT NULL AND purged_at IS NULL
        LIMIT 200
        "#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let client = Client::new();
    let mut purged: u64 = 0;
    for row in &purge_candidates {
        use sqlx::Row as SqlxRow;
        let row_id: Uuid = row.get("id");
        let owner_user_id: Uuid = row.get("owner_user_id");
        let object_key: String = row.get("object_key");

        // Best-effort R2 delete. On failure we leave purged_at NULL so the
        // next pass retries; we log but don't advance row state.
        let r2_ok = s3_delete_object(&client, &object_key).await.is_ok();

        if r2_ok {
            let _ = sqlx::query("UPDATE attachment_uploads SET purged_at = NOW() WHERE id = $1")
                .bind(row_id)
                .execute(pool)
                .await;

            record_audit_event(
                pool.clone(),
                owner_user_id,
                None,
                None,
                "attachment_purged",
                serde_json::json!({
                    "attachment_id": row_id.to_string(),
                    "object_key": object_key,
                    "trigger": "cleanup_job",
                }),
            );
            purged += 1;
        }
    }

    (
        abandoned_issued.len() as u64 + abandoned_uploaded.len() as u64,
        purged,
    )
}

/// Spawn the attachment orphan cleanup job as a background tokio task.
///
/// Call once at server startup after DB pool is ready. Invocations are
/// idempotent — stale state gets rolled forward on each tick regardless of
/// which pod runs the pass.
pub fn spawn_attachment_cleanup_job(pool: PgPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            ATTACHMENT_CLEANUP_INTERVAL_SECS,
        ));
        // Skip the immediate first tick; startup races with migrations.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let (expired, purged) = run_attachment_cleanup_pass(&pool).await;
            if expired > 0 || purged > 0 {
                info!(
                    expired = expired,
                    purged_objects = purged,
                    "attachment cleanup pass completed"
                );
            }
        }
    });
}

/// Convenience entrypoint for `main.rs`: builds a dedicated small pool for
/// the cleanup job and spawns it if `DATABASE_URL` is configured. Returns
/// `false` when the job wasn't started (in-memory mode / no DB).
pub async fn spawn_attachment_cleanup_if_configured() -> bool {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        return false;
    };
    let pool = match PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(DB_CONNECT_TIMEOUT_SECS))
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => {
            tracing::warn!(error = %err, "attachment cleanup: failed to connect to DB; job disabled");
            return false;
        }
    };
    spawn_attachment_cleanup_job(pool);
    true
}

async fn list_messages(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<MessageListQuery>,
) -> Result<Json<MessageListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    ctx.require_scope("messages.read")?;
    let user_id = ctx.user_id().to_string();
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }
    let requested_agent = query.agent_did.clone().unwrap_or_default();
    let requested_agent = if requested_agent.trim().is_empty() {
        match &ctx {
            AuthContext::Agent { aid, .. } => aid.clone(),
            AuthContext::Human { .. } => {
                return Err(validation_error("agent_did is required"));
            }
        }
    } else {
        requested_agent
    };

    if let Some(folder) = query.folder.as_deref() {
        if !matches!(
            folder,
            "inbox"
                | "sent"
                | "drafts"
                | "archive"
                | "spam"
                | "trash"
                | "pending_approval"
                | "starred"
                | "all"
        ) {
            return Err(validation_error(
                "folder must be one of: inbox, sent, drafts, archive, spam, trash, pending_approval, starred, all",
            ));
        }
    }

    if let Some(status) = query.status.as_deref() {
        if !matches!(status, "unread" | "read" | "all") {
            return Err(validation_error("status must be one of: unread, read, all"));
        }
    }

    if let Some(priority) = query.priority.as_deref() {
        if !matches!(priority, "high" | "normal" | "low" | "background") {
            return Err(validation_error(
                "priority must be one of: high, normal, low, background",
            ));
        }
    }

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(50);
    if page == 0 || per_page == 0 {
        return Err(validation_error("page and per_page must be >= 1"));
    }
    if per_page > 100 {
        return Err(validation_error("per_page must be <= 100"));
    }

    // Resolve the requested agent to a set of dids that identify it.
    // An aid can rotate through many dids over its lifetime (each
    // `activate_agent_credential` issues a fresh one), and older messages
    // remain addressed to the did that was active at send-time. Collect the
    // full historical set so list filters match across rotation boundaries.
    let (resolved_agent_did, resolved_agent_dids): (String, Vec<String>) = if requested_agent
        == "all"
    {
        if matches!(ctx, AuthContext::Agent { .. }) {
            return Err(forbidden_error(
                "agent tokens may only access the inbox bound to their credential",
            ));
        }
        ("all".to_string(), Vec::new())
    } else {
        validate_recipient_reference(&requested_agent, "agent_did")?;
        let resolved = if let Some(pool) = maybe_pool.clone() {
            resolve_recipient_record_in_db(&pool, &requested_agent)
                .await
                .map_err(|message| internal_server_error(&message))?
        } else {
            resolve_recipient_record_in_memory(&state, &requested_agent)
        };
        match resolved {
            Some(record) => {
                enforce_agent_bound_aid(&ctx, &record.aid)?;
                let current_did = record.did.clone();
                let all_dids = if let Some(pool) = maybe_pool.clone() {
                    let rows = sqlx::query("SELECT did FROM agent_identity_keys WHERE aid = $1")
                        .bind(&record.aid)
                        .fetch_all(&pool)
                        .await
                        .map_err(|error| {
                            internal_error("failed to resolve agent did history", error)
                        })?;
                    let mut out: Vec<String> = rows
                        .into_iter()
                        .map(|row| row.get::<String, _>("did"))
                        .collect();
                    if !out.iter().any(|d| d == &current_did) {
                        out.push(current_did.clone());
                    }
                    out
                } else {
                    vec![current_did.clone()]
                };
                (current_did, all_dids)
            }
            None => {
                let fallback = requested_agent.clone();
                let dids = vec![fallback.clone()];
                (fallback, dids)
            }
        }
    };

    let folder_filter = query.folder.as_deref();
    // "sent" filters by sender_did rather than recipient_did; other folders
    // (inbox/spam/trash/…) filter by recipient as before so the "エージェント別"
    // view keeps working on the receiving side.
    let is_sent_view = matches!(folder_filter, Some("sent"));
    let agent_scope_all = resolved_agent_did == "all";

    let thread_filter = query
        .thread_id
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok());

    let status_filter = query.status.as_deref().filter(|s| *s != "all");
    let priority_filter = query.priority.as_deref();
    let auto_reply_pending = query
        .auto_reply_pending
        .as_deref()
        .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false);

    let limit = per_page as i64;
    let offset = ((page.saturating_sub(1)) as i64) * limit;

    let (messages_out, total_count): (Vec<MessageIndexEntryResponse>, usize) = if let Some(pool) =
        maybe_pool
    {
        let user_uuid = parse_user_uuid(&user_id)?;

        // For Sent + agent_scope_all we need the caller's full set of owned
        // dids (current + historical) so the WHERE clause can match
        // `sender_did` against "any of mine". Same-user sends only create the
        // recipient-side row (folder='inbox') — see send_message in this file
        // — so identifying "my sent" by `sender_did = mine` rather than by
        // the folder column is what makes Sent show same-user sends without
        // a dual-row insert. Kept as a separate pre-query so the DB doesn't
        // need a self-join on every other view.
        let user_owned_dids: Vec<String> = if is_sent_view && agent_scope_all {
            sqlx::query(
                r#"
                SELECT aik.did
                FROM agent_identity_keys aik
                JOIN agent_identities ai ON ai.aid = aik.aid
                WHERE ai.user_id = $1
                "#,
            )
            .bind(user_uuid)
            .fetch_all(&pool)
            .await
            .map_err(|error| internal_error("failed to resolve user-owned dids", error))?
            .into_iter()
            .map(|row| row.get::<String, _>("did"))
            .collect()
        } else {
            Vec::new()
        };

        // Every filter is pushed into the WHERE clause so the DB
        // returns only the page the caller asked for. Previously
        // the handler did `fetch_all` over every row owned by the
        // user, then filtered + paginated in Rust — a tens-of-
        // thousands-of-rows account (legit or weaponised) could
        // force the worker to allocate the full inbox on every
        // request, an easy OOM DoS. `COUNT(*) OVER ()` returns the
        // total-before-pagination in the same query so the caller
        // still sees the real page count without a second roundtrip.
        //
        // Optional filters are threaded as `Option<T>` bindings
        // with `COALESCE` / `IS NULL OR` patterns so one prepared
        // statement covers every combination.
        let rows = sqlx::query(
            r#"
            SELECT
              m.id::text AS id,
              m.sender_did,
              m.recipient_did,
              m.thread_id::text AS thread_id,
              m.subject_encrypted,
              m.storage_ref,
              m.status,
              m.priority,
              m.ai_category,
              m.created_at::text AS created_at,
              m.trust_score,
              m.folder,
              m.starred,
              m.auto_reply_decision,
              m.auto_reply_reason,
              m.auto_reply_sent_at::text AS auto_reply_sent_at,
              sa.label AS sender_agent_label,
              su.display_name AS sender_user_name,
              ra.label AS recipient_agent_label,
              ru.display_name AS recipient_user_name,
              COUNT(*) OVER () AS total_count
            FROM message_index m
            LEFT JOIN agents sa ON sa.did = m.sender_did
            LEFT JOIN users  su ON su.id  = sa.user_id
            LEFT JOIN agents ra ON ra.did = m.recipient_did
            LEFT JOIN users  ru ON ru.id  = ra.user_id
            WHERE m.owner_user_id = $1
              -- Agent scope.
              -- $2 (agent_scope_all):
              --   true  → any did the caller owns counts
              --   false → restrict to the specific dids in $4
              -- $3 (is_sent_view):
              --   true  → match sender_did (= "messages I sent")
              --   false → match recipient_did (= "messages I received")
              -- For scope_all + sent we need to restrict by *any* did the
              -- user owns ($12), otherwise we'd return everyone else's
              -- rows whose sender happens to be inside this account
              -- (impossible by owner_user_id, but the constraint also
              -- preserves the "this is mine" semantics for the same-user
              -- send case where the row's folder is 'inbox' but sender is
              -- still one of the caller's agents).
              AND (
                ($2::bool AND NOT $3::bool)
                OR ($2::bool AND $3::bool AND m.sender_did = ANY($12::text[]))
                OR (NOT $2::bool AND $3::bool AND m.sender_did    = ANY($4::text[]))
                OR (NOT $2::bool AND NOT $3::bool AND m.recipient_did = ANY($4::text[]))
              )
              -- Folder filter: 'all' excludes spam+trash,
              -- 'starred' is a cross-folder view, 'sent' is identified by
              -- sender_did (above) rather than the stored folder column —
              -- same-user sends only create the recipient-side row
              -- (folder='inbox') so we can't gate Sent on `folder='sent'`
              -- without losing them. Anything else pins `m.folder` exactly.
              AND (
                $5::text IS NULL
                OR ($5::text = 'all'     AND m.folder NOT IN ('spam', 'trash'))
                OR ($5::text = 'starred' AND m.starred AND m.folder NOT IN ('spam', 'trash'))
                OR ($5::text = 'sent')
                OR ($5::text NOT IN ('all', 'starred', 'sent') AND m.folder = $5::text)
              )
              AND ($6::text  IS NULL OR m.status    = $6::text)
              AND ($7::text  IS NULL OR m.priority  = $7::text)
              AND ($8::uuid  IS NULL OR m.thread_id = $8::uuid)
              -- Phase 4.4c+ (docs/25c-a §4.1): Isolated mode executor filter.
              -- When on, restrict to rows the evaluator stamped with an
              -- actionable decision the executor hasn't dispatched yet.
              -- Backed by the partial index from migration 0018.
              AND (
                NOT $11::bool
                OR (
                  m.auto_reply_decision IN ('auto_accept', 'auto_decline')
                  AND m.auto_reply_sent_at IS NULL
                )
              )
            ORDER BY m.created_at DESC
            LIMIT $9 OFFSET $10
            "#,
        )
        .bind(user_uuid)
        .bind(agent_scope_all)
        .bind(is_sent_view)
        .bind(&resolved_agent_dids as &[String])
        .bind(folder_filter)
        .bind(status_filter)
        .bind(priority_filter)
        .bind(thread_filter)
        .bind(limit)
        .bind(offset)
        .bind(auto_reply_pending)
        .bind(&user_owned_dids as &[String])
        .fetch_all(&pool)
        .await
        .map_err(|error| internal_error("failed to list messages", error))?;

        let total: i64 = rows
            .first()
            .and_then(|row| row.try_get("total_count").ok())
            .unwrap_or(0);
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id_text: String = row.get("id");
            let id = Uuid::parse_str(&id_text)
                .map_err(|error| internal_error("invalid message id from database", error))?;
            let thread_id = row
                .get::<Option<String>, _>("thread_id")
                .and_then(|value| Uuid::parse_str(&value).ok());
            let sender_agent_label: Option<String> = row.get("sender_agent_label");
            let sender_user_name: Option<String> = row.get("sender_user_name");
            let recipient_agent_label: Option<String> = row.get("recipient_agent_label");
            let recipient_user_name: Option<String> = row.get("recipient_user_name");
            out.push(MessageIndexEntryResponse {
                id,
                sender_did: row.get("sender_did"),
                sender_label: compose_party_label(sender_user_name, sender_agent_label),
                recipient_did: row.get("recipient_did"),
                recipient_label: compose_party_label(recipient_user_name, recipient_agent_label),
                thread_id,
                subject_encrypted: row.get("subject_encrypted"),
                status: row.get("status"),
                priority: row.get("priority"),
                ai_category: row.get("ai_category"),
                created_at: row.get("created_at"),
                trust_score: row.get("trust_score"),
                folder: row.get("folder"),
                starred: row.get("starred"),
                auto_reply_decision: row.try_get("auto_reply_decision").ok(),
                auto_reply_reason: row.try_get("auto_reply_reason").ok(),
                auto_reply_sent_at: row.try_get("auto_reply_sent_at").ok(),
            });
        }
        (out, total as usize)
    } else {
        // In-memory path: tiny test corpus, just do the filter + slice
        // in Rust like before. Memory pressure isn't a concern here.
        let all = state
            .messages_by_user
            .lock()
            .unwrap()
            .get(&user_id)
            .cloned()
            .unwrap_or_default();

        let filtered: Vec<_> = if agent_scope_all {
            all
        } else if is_sent_view {
            all.into_iter()
                .filter(|m| resolved_agent_dids.iter().any(|d| d == &m.sender_did))
                .collect()
        } else {
            all.into_iter()
                .filter(|m| resolved_agent_dids.iter().any(|d| d == &m.recipient_did))
                .collect()
        };

        let filtered: Vec<_> = filtered
            .into_iter()
            .filter(|m| match folder_filter {
                Some("all") => m.folder != "spam" && m.folder != "trash",
                Some("starred") => m.starred && m.folder != "spam" && m.folder != "trash",
                Some(f) => m.folder == f,
                None => true,
            })
            .filter(|m| match status_filter {
                Some(s) => m.status == s,
                None => true,
            })
            .filter(|m| match priority_filter {
                Some(p) => m.priority == p,
                None => true,
            })
            .filter(|m| match thread_filter {
                Some(tid) => m.thread_id == Some(tid),
                None => true,
            })
            .collect();

        let total = filtered.len();
        let start = offset as usize;
        let end = start.saturating_add(limit as usize);
        let messages = filtered
            .into_iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .map(|m| MessageIndexEntryResponse {
                id: m.id,
                sender_did: m.sender_did,
                sender_label: m.sender_label,
                recipient_did: m.recipient_did,
                recipient_label: m.recipient_label,
                thread_id: m.thread_id,
                subject_encrypted: m.subject_encrypted,
                status: m.status,
                priority: m.priority,
                ai_category: m.ai_category,
                created_at: m.created_at,
                trust_score: m.trust_score,
                folder: m.folder,
                starred: m.starred,
                auto_reply_decision: None,
                auto_reply_reason: None,
                auto_reply_sent_at: None,
            })
            .collect();
        (messages, total)
    };

    let messages = messages_out;
    let total = total_count;

    Ok(Json(MessageListResponse {
        messages,
        total,
        page,
        per_page,
    }))
}

async fn message_content(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
) -> Result<Json<MessageContentResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    ctx.require_scope("messages.read")?;
    let user_id = ctx.user_id().to_string();
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    let maybe = if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        let row = sqlx::query(
            r#"
            SELECT
              id::text AS id,
              sender_did,
              recipient_did,
              thread_id::text AS thread_id,
              subject_encrypted,
              storage_ref,
              status,
              priority,
              ai_category,
              created_at::text AS created_at,
              trust_score,
              folder,
              starred
            FROM message_index
            WHERE owner_user_id = $1 AND id = $2
            LIMIT 1
            "#,
        )
        .bind(user_uuid)
        .bind(message_id)
        .fetch_optional(&pool)
        .await
        .map_err(|error| internal_error("failed to load message content index", error))?;

        row.map(|row| {
            let thread_id = row
                .get::<Option<String>, _>("thread_id")
                .and_then(|value| Uuid::parse_str(&value).ok());
            MessageRecord {
                id: message_id,
                sender_did: row.get("sender_did"),
                sender_label: None,
                recipient_did: row.get("recipient_did"),
                recipient_label: None,
                thread_id,
                subject_encrypted: row.get("subject_encrypted"),
                storage_ref: row.get("storage_ref"),
                status: row.get("status"),
                priority: row.get("priority"),
                ai_category: row.get("ai_category"),
                created_at: row.get("created_at"),
                trust_score: row.get("trust_score"),
                folder: row.get("folder"),
                starred: row.get("starred"),
            }
        })
    } else {
        let lock = state
            .messages_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let messages = lock.get(&user_id).cloned().unwrap_or_default();
        messages
            .into_iter()
            .find(|message| message.id == message_id)
    };

    match maybe {
        Some(message) => {
            // Enforce the agent boundary AFTER the owner_user_id
            // lookup and BEFORE touching storage / returning the
            // encrypted blob. Matching a different agent's aid
            // within the same user is treated as 404 so the
            // endpoint doesn't confirm presence of an unrelated
            // message (same stealth pattern as L2/L3 block).
            if let Some(pool) = state
                .database_pool()
                .await
                .map_err(|m| internal_server_error(&m))?
            {
                enforce_agent_bound_message(
                    &pool,
                    &ctx,
                    &message.sender_did,
                    &message.recipient_did,
                )
                .await?;
            } else {
                enforce_agent_bound_message_in_memory(
                    &state,
                    &ctx,
                    &message.sender_did,
                    &message.recipient_did,
                )?;
            }
            if let Some(parsed) = parse_storage_ref(&message.storage_ref) {
                let raw = match parsed.backend {
                    StorageBackend::GoogleDrive => {
                        let client = Client::new();
                        gdrive_read_file(&client, &parsed.locator)
                            .await
                            .map_err(|_| {
                                audit_storage_event(
                                    "storage_read",
                                    state.storage_backend,
                                    &user_id,
                                    Some(message.id),
                                    "error",
                                    Some("read_failed"),
                                );
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: "storage_error".to_string(),
                                        message:
                                            "failed to read encrypted payload from google drive"
                                                .to_string(),
                                    }),
                                )
                            })?
                    }
                    StorageBackend::S3 => {
                        let client = Client::new();
                        s3_get_object(&client, &parsed.locator).await.map_err(|_| {
                            audit_storage_event(
                                "storage_read",
                                state.storage_backend,
                                &user_id,
                                Some(message.id),
                                "error",
                                Some("read_failed"),
                            );
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    error: "storage_error".to_string(),
                                    message: "failed to read encrypted payload from s3".to_string(),
                                }),
                            )
                        })?
                    }
                    StorageBackend::Ipfs => {
                        let client = Client::new();
                        ipfs_read_file(&client, &parsed.locator)
                            .await
                            .map_err(|_| {
                                audit_storage_event(
                                    "storage_read",
                                    state.storage_backend,
                                    &user_id,
                                    Some(message.id),
                                    "error",
                                    Some("read_failed"),
                                );
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: "storage_error".to_string(),
                                        message: "failed to read encrypted payload from ipfs"
                                            .to_string(),
                                    }),
                                )
                            })?
                    }
                    StorageBackend::LocalFs | StorageBackend::GoogleDriveMock => {
                        let path = path_from_storage_ref(&state, &user_id, &message.storage_ref)
                            .ok_or_else(|| {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(ErrorResponse {
                                        error: "storage_error".to_string(),
                                        message: "invalid storage reference for message content"
                                            .to_string(),
                                    }),
                                )
                            })?;

                        fs::read_to_string(path).map_err(|_| {
                            audit_storage_event(
                                "storage_read",
                                state.storage_backend,
                                &user_id,
                                Some(message.id),
                                "error",
                                Some("read_failed"),
                            );
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    error: "storage_error".to_string(),
                                    message: "failed to read encrypted payload from local storage"
                                        .to_string(),
                                }),
                            )
                        })?
                    }
                };

                let payload: StoredMessageContent = serde_json::from_str(&raw).map_err(|_| {
                    audit_storage_event(
                        "storage_read",
                        state.storage_backend,
                        &user_id,
                        Some(message.id),
                        "error",
                        Some("read_failed"),
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "storage_error".to_string(),
                            message: "failed to read encrypted payload from local storage"
                                .to_string(),
                        }),
                    )
                })?;
                audit_storage_event(
                    "storage_read",
                    state.storage_backend,
                    &user_id,
                    Some(message.id),
                    "ok",
                    None,
                );

                return Ok(Json(MessageContentResponse {
                    encrypted_content: payload.encrypted_content,
                    encrypted_key: payload.encrypted_key,
                    nonce: payload.nonce,
                    sender_did: message.sender_did.clone(),
                    recipient_did: message.recipient_did.clone(),
                    subject_encrypted: message.subject_encrypted.clone(),
                    thread_id: message.thread_id,
                    content_type: payload.content_type,
                }));
            }
            audit_storage_event(
                "storage_read",
                state.storage_backend,
                &user_id,
                Some(message.id),
                "error",
                Some("invalid_storage_ref"),
            );

            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "storage_error".to_string(),
                    message: "invalid storage reference for message content".to_string(),
                }),
            ))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "message not found".to_string(),
            }),
        )),
    }
}

async fn update_message_status(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
    JsonBody(payload): JsonBody<UpdateMessageStatusRequest>,
) -> Result<Json<UpdateMessageStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    // Status update (read/archived) requires messages.read scope
    ctx.require_scope("messages.read")?;
    let user_id = ctx.user_id().to_string();
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }
    let status = payload.status.unwrap_or_default();

    if status != "read" && status != "archived" {
        return Err(validation_error("status must be one of: read, archived"));
    }

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        // Pre-flight: fetch the message so we can enforce the agent
        // boundary. Without this, an agent-A token could mark
        // agent-B's messages as read or archive them (silent cross-
        // agent privilege escalation within a single user).
        let pre = sqlx::query(
            r#"
            SELECT sender_did, recipient_did
            FROM message_index
            WHERE id = $1 AND owner_user_id = $2
            LIMIT 1
            "#,
        )
        .bind(message_id)
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|e| internal_error("message lookup failed", e))?;
        if let Some(row) = pre {
            let sender_did: String = row.get("sender_did");
            let recipient_did: String = row.get("recipient_did");
            enforce_agent_bound_message(&pool, &ctx, &sender_did, &recipient_did).await?;
        }
        // Archiving a message also moves it out of the inbox folder so the
        // inbox view no longer shows it. This mirrors Gmail's archive
        // semantics where the message is still findable in All Mail.
        // "read" does not change folder.
        let result = if status == "archived" {
            sqlx::query(
                r#"
                UPDATE message_index
                SET status = $1,
                    folder = CASE WHEN folder = 'inbox' THEN 'archive' ELSE folder END
                WHERE id = $2 AND owner_user_id = $3
                "#,
            )
            .bind(&status)
            .bind(message_id)
            .bind(user_uuid)
            .execute(&pool)
            .await
        } else {
            sqlx::query(
                r#"
                UPDATE message_index
                SET status = $1
                WHERE id = $2 AND owner_user_id = $3
                "#,
            )
            .bind(&status)
            .bind(message_id)
            .bind(user_uuid)
            .execute(&pool)
            .await
        }
        .map_err(|error| internal_error("failed to update message status", error))?;
        if result.rows_affected() > 0 {
            return Ok(Json(UpdateMessageStatusResponse {
                id: message_id,
                status,
            }));
        }
    } else {
        // Snapshot the endpoints first so we can run the agent
        // boundary check without holding the messages lock while
        // also reading agents_by_user inside the helper.
        let endpoints = {
            let lock = state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            lock.get(&user_id).and_then(|messages| {
                messages
                    .iter()
                    .find(|m| m.id == message_id)
                    .map(|m| (m.sender_did.clone(), m.recipient_did.clone()))
            })
        };
        if let Some((sender_did, recipient_did)) = endpoints {
            enforce_agent_bound_message_in_memory(&state, &ctx, &sender_did, &recipient_did)?;
        }

        let mut lock = state
            .messages_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let messages = lock.entry(user_id).or_default();

        let maybe_message = messages.iter_mut().find(|message| message.id == message_id);
        if let Some(message) = maybe_message {
            message.status = status.clone();
            if status == "archived" && message.folder == "inbox" {
                message.folder = "archive".to_string();
            }
            return Ok(Json(UpdateMessageStatusResponse {
                id: message.id,
                status,
            }));
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "not_found".to_string(),
            message: "message not found".to_string(),
        }),
    ))
}

/// PATCH /messages/{id}/flags
///
/// Update the folder bucket and/or starred flag for a message owned by
/// the authenticated user. Used by the inbox UI to move messages into
/// spam/trash/archive, restore them, and toggle stars. The body may
/// set `folder`, `starred`, or both.
async fn update_message_flags(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
    JsonBody(payload): JsonBody<UpdateMessageFlagsRequest>,
) -> Result<Json<UpdateMessageFlagsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    ctx.require_scope("messages.read")?;
    let user_id = ctx.user_id().to_string();
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    if payload.folder.is_none() && payload.starred.is_none() {
        return Err(validation_error(
            "at least one of folder or starred must be provided",
        ));
    }

    if let Some(folder) = payload.folder.as_deref() {
        if !matches!(
            folder,
            "inbox" | "sent" | "drafts" | "archive" | "spam" | "trash" | "pending_approval"
        ) {
            return Err(validation_error(
                "folder must be one of: inbox, sent, drafts, archive, spam, trash, pending_approval",
            ));
        }
    }

    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        // Pre-flight agent-boundary check. See
        // `enforce_agent_bound_message` for the threat model — agent-A
        // tokens must not be able to move agent-B's messages around.
        let pre = sqlx::query(
            r#"
            SELECT sender_did, recipient_did
            FROM message_index
            WHERE id = $1 AND owner_user_id = $2
            LIMIT 1
            "#,
        )
        .bind(message_id)
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|e| internal_error("message lookup failed", e))?;
        if let Some(row) = pre {
            let sender_did: String = row.get("sender_did");
            let recipient_did: String = row.get("recipient_did");
            enforce_agent_bound_message(&pool, &ctx, &sender_did, &recipient_did).await?;
        }
        // Gmail-parity invariant: restoring a message to the inbox clears a
        // lingering 'archived' status. Without this, a message that was
        // archived-then-restored would keep status='archived' which is not a
        // valid inbox state. Non-inbox moves leave status untouched so spam
        // and trash views can still show the original read/unread signal.
        let row = sqlx::query(
            r#"
            UPDATE message_index
            SET
              folder  = COALESCE($1, folder),
              starred = COALESCE($2, starred),
              status  = CASE
                WHEN $1 = 'inbox' AND status = 'archived' THEN 'read'
                ELSE status
              END
            WHERE id = $3 AND owner_user_id = $4
            RETURNING folder, starred
            "#,
        )
        .bind(payload.folder.as_deref())
        .bind(payload.starred)
        .bind(message_id)
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|error| internal_error("failed to update message flags", error))?;
        if let Some(row) = row {
            use sqlx::Row;
            return Ok(Json(UpdateMessageFlagsResponse {
                id: message_id,
                folder: row.get("folder"),
                starred: row.get("starred"),
            }));
        }
    } else {
        // Same boundary check for the in-memory path — snapshot the
        // endpoints without holding the map lock so the helper can
        // read agents_by_user cleanly.
        let endpoints = {
            let lock = state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            lock.get(&user_id).and_then(|messages| {
                messages
                    .iter()
                    .find(|m| m.id == message_id)
                    .map(|m| (m.sender_did.clone(), m.recipient_did.clone()))
            })
        };
        if let Some((sender_did, recipient_did)) = endpoints {
            enforce_agent_bound_message_in_memory(&state, &ctx, &sender_did, &recipient_did)?;
        }
        let mut lock = state
            .messages_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let messages = lock.entry(user_id).or_default();
        if let Some(message) = messages.iter_mut().find(|m| m.id == message_id) {
            if let Some(folder) = payload.folder {
                // Same invariant as the DB path: inbox restore clears archived.
                if folder == "inbox" && message.status == "archived" {
                    message.status = "read".to_string();
                }
                message.folder = folder;
            }
            if let Some(starred) = payload.starred {
                message.starred = starred;
            }
            return Ok(Json(UpdateMessageFlagsResponse {
                id: message.id,
                folder: message.folder.clone(),
                starred: message.starred,
            }));
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "not_found".to_string(),
            message: "message not found".to_string(),
        }),
    ))
}

/// PATCH /messages/{id}/auto-reply-sent
///
/// Flips `message_index.auto_reply_sent_at` from NULL to NOW() for
/// the recipient-side row the caller owns. Predicated on
/// `auto_reply_sent_at IS NULL` so repeated calls from page refresh
/// or parallel tabs are idempotent — the first one wins and
/// subsequent PATCHes return the frozen timestamp unchanged.
/// See docs/25c §3.2 / §5.2.
async fn mark_auto_reply_sent(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
    body: Option<JsonBody<MarkAutoReplySentRequest>>,
) -> Result<Json<MarkAutoReplySentResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    ctx.require_scope("messages.send")?;
    let user_id = ctx.user_id().to_string();
    let payload = body.map(|JsonBody(p)| p).unwrap_or_default();

    let pool = match state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?
    {
        Some(pool) => pool,
        None => return Err(database_required_but_unavailable_error()),
    };

    let user_uuid = parse_user_uuid(&user_id)?;

    // Pre-flight agent-boundary check: agent tokens must not reach
    // across to a peer agent's inbox rows. Same pattern as
    // `update_message_flags`.
    let pre = sqlx::query(
        r#"
        SELECT sender_did, recipient_did
        FROM message_index
        WHERE id = $1 AND owner_user_id = $2
        LIMIT 1
        "#,
    )
    .bind(message_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("message lookup failed", e))?;

    let Some(row) = pre else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "message not found".to_string(),
            }),
        ));
    };
    let sender_did: String = row.get("sender_did");
    let recipient_did: String = row.get("recipient_did");
    enforce_agent_bound_message(&pool, &ctx, &sender_did, &recipient_did).await?;

    // Idempotent UPDATE: sets the column only when it's still NULL,
    // then returns the stamped value (either the NOW() we just wrote
    // or the pre-existing one a racing tab won).
    let updated = sqlx::query(
        r#"
        UPDATE message_index
        SET auto_reply_sent_at = COALESCE(auto_reply_sent_at, NOW())
        WHERE id = $1 AND owner_user_id = $2
        RETURNING auto_reply_sent_at::text AS auto_reply_sent_at,
                  (auto_reply_sent_at = NOW() OR auto_reply_sent_at IS NULL) AS newly_stamped
        "#,
    )
    .bind(message_id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|e| internal_error("failed to mark auto-reply sent", e))?;

    let Some(updated_row) = updated else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: "message not found".to_string(),
            }),
        ));
    };

    let auto_reply_sent_at: String = updated_row.get("auto_reply_sent_at");

    record_audit_event(
        pool,
        user_uuid,
        None,
        None,
        "auto_reply_sent",
        serde_json::json!({
            "message_id": message_id.to_string(),
            "sender_did": sender_did,
            "recipient_did": recipient_did,
            "reply_message_id": payload.reply_message_id.map(|id| id.to_string()),
            "auto_reply_sent_at": auto_reply_sent_at,
            "executor_mode": payload
                .executor_mode
                .clone()
                .unwrap_or_else(|| "client_protocol_v1".to_string()),
        }),
    );

    Ok(Json(MarkAutoReplySentResponse {
        id: message_id,
        auto_reply_sent_at,
    }))
}

/// DELETE /messages/{id}
///
/// Delete a message owned by the authenticated user:
///   1. Look up the message index row (ownership enforced via owner_user_id)
///   2. Delete the encrypted payload from storage (LocalFs / Google Drive)
///   3. Remove the message_index row
///
/// Auto-purge and user-initiated deletes both route through this handler.
async fn delete_message(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    // Deletion is an irreversible write — require the dedicated
    // `messages.delete` scope, not the read scope. A token granted only
    // `messages.read` must not be able to permanently destroy messages.
    ctx.require_scope("messages.delete")?;
    let user_id = ctx.user_id().to_string();
    let maybe_pool = state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?;
    if maybe_pool.is_none() && database_required() {
        return Err(database_required_but_unavailable_error());
    }

    // Cross-user messages write two `message_index` rows that share the
    // same `storage_ref` (one sender-side, one recipient-side — see
    // `send_message`). Deleting the caller's row must NOT remove the
    // underlying blob while the counterparty still has their row,
    // otherwise the peer's read path breaks from under them.
    //
    // Order is critical:
    //   1. DELETE this owner's row, RETURNING storage_ref.
    //   2. Count remaining rows that still reference that storage_ref.
    //   3. Only when the ref count hits zero, GC the blob.
    //
    // Fetching `storage_ref` up front and THEN deleting would technically
    // work for the common case, but the DELETE-RETURNING form keeps the
    // "this owner's row is gone before we look at peers" ordering
    // self-evident, and also yields the correct 404 when the row never
    // existed or was double-deleted.

    // --- DB path ---
    if let Some(pool) = maybe_pool {
        let user_uuid = parse_user_uuid(&user_id)?;
        // Pre-flight agent-boundary check — same pattern as
        // status / flags updates. Without this, agent-A's token
        // could delete agent-B's inbox row (leaving the blob
        // orphaned while the other peer still has theirs).
        let pre = sqlx::query(
            r#"
            SELECT sender_did, recipient_did
            FROM message_index
            WHERE id = $1 AND owner_user_id = $2
            LIMIT 1
            "#,
        )
        .bind(message_id)
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|e| internal_error("message lookup failed", e))?;
        if let Some(row) = pre {
            let sender_did: String = row.get("sender_did");
            let recipient_did: String = row.get("recipient_did");
            enforce_agent_bound_message(&pool, &ctx, &sender_did, &recipient_did).await?;
        }
        let deleted_storage_ref: Option<String> = sqlx::query_scalar(
            "DELETE FROM message_index WHERE id = $1 AND owner_user_id = $2 \
             RETURNING storage_ref",
        )
        .bind(message_id)
        .bind(user_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|error| internal_error("failed to delete message index row", error))?;

        let storage_ref = match deleted_storage_ref {
            Some(s) => s,
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "not_found".to_string(),
                        message: "message not found".to_string(),
                    }),
                ));
            }
        };

        // Are any other owners still pointing at this blob?
        let remaining_refs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM message_index WHERE storage_ref = $1")
                .bind(&storage_ref)
                .fetch_one(&pool)
                .await
                .map_err(|error| internal_error("failed to count storage_ref refs", error))?;

        if remaining_refs == 0 {
            gc_message_storage(&state, &user_id, message_id, &storage_ref).await?;
        } else {
            // Peer still references the blob; leave it alone. The owning
            // peer's later DELETE (or auto-purge) will collect it.
            audit_storage_event(
                "storage_delete",
                state.storage_backend,
                &user_id,
                Some(message_id),
                "skipped_shared_ref",
                None,
            );
        }
    } else {
        // --- In-memory path ---
        // Same shape as the DB: drop this user's row first, then sweep
        // every other user's bucket for a row that still holds the same
        // storage_ref before touching the file.
        let (storage_ref, sender_did, recipient_did) = {
            let lock = state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let messages = lock.get(&user_id).cloned().unwrap_or_default();
            match messages.into_iter().find(|m| m.id == message_id) {
                Some(m) => (m.storage_ref, m.sender_did, m.recipient_did),
                None => {
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "not_found".to_string(),
                            message: "message not found".to_string(),
                        }),
                    ));
                }
            }
        };
        // Agent-boundary check before we actually retain/remove the
        // row — same 404-on-mismatch behaviour as the other handlers.
        enforce_agent_bound_message_in_memory(&state, &ctx, &sender_did, &recipient_did)?;

        {
            let mut lock = state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(messages) = lock.get_mut(&user_id) {
                messages.retain(|m| m.id != message_id);
            }
        }

        let any_peer_holds_ref = {
            let lock = state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            lock.values()
                .any(|msgs| msgs.iter().any(|m| m.storage_ref == storage_ref))
        };

        if !any_peer_holds_ref {
            gc_message_storage(&state, &user_id, message_id, &storage_ref).await?;
        } else {
            audit_storage_event(
                "storage_delete",
                state.storage_backend,
                &user_id,
                Some(message_id),
                "skipped_shared_ref",
                None,
            );
        }
    }

    audit_storage_event(
        "storage_delete",
        state.storage_backend,
        &user_id,
        Some(message_id),
        "success",
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Delete the encrypted payload blob referenced by `storage_ref`. The
/// caller must have already verified no `message_index` row still
/// references it — this function does not re-check.
async fn gc_message_storage(
    state: &AppState,
    user_id: &str,
    message_id: Uuid,
    storage_ref: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let Some(parsed) = parse_storage_ref(storage_ref) else {
        return Ok(());
    };
    match parsed.backend {
        StorageBackend::GoogleDrive => {
            let client = Client::new();
            if let Err(error) = gdrive_delete_file(&client, &parsed.locator).await {
                audit_storage_event(
                    "storage_delete",
                    state.storage_backend,
                    user_id,
                    Some(message_id),
                    "error",
                    Some("gdrive_delete_failed"),
                );
                return Err(internal_error(
                    "failed to delete encrypted payload from google drive",
                    error,
                ));
            }
        }
        StorageBackend::S3 => {
            let client = Client::new();
            if let Err(error) = s3_delete_object(&client, &parsed.locator).await {
                audit_storage_event(
                    "storage_delete",
                    state.storage_backend,
                    user_id,
                    Some(message_id),
                    "error",
                    Some("s3_delete_failed"),
                );
                return Err(internal_error(
                    "failed to delete encrypted payload from s3",
                    error,
                ));
            }
        }
        StorageBackend::Ipfs => {
            let client = Client::new();
            if let Err(error) = ipfs_delete_file(&client, &parsed.locator).await {
                audit_storage_event(
                    "storage_delete",
                    state.storage_backend,
                    user_id,
                    Some(message_id),
                    "error",
                    Some("ipfs_delete_failed"),
                );
                return Err(internal_error(
                    "failed to unpin encrypted payload from ipfs",
                    error,
                ));
            }
        }
        StorageBackend::LocalFs | StorageBackend::GoogleDriveMock => {
            if let Some(path) = path_from_storage_ref(state, user_id, storage_ref) {
                // Ignore NotFound: the row may still exist even if the file vanished.
                match fs::remove_file(&path) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        audit_storage_event(
                            "storage_delete",
                            state.storage_backend,
                            user_id,
                            Some(message_id),
                            "error",
                            Some("localfs_delete_failed"),
                        );
                        return Err(internal_error(
                            "failed to delete encrypted payload from local storage",
                            error,
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

// =============================================================================
// Auto-Purge Policy Engine (Phase 3.3)
// =============================================================================
//
// The engine evaluates each message against a simple set of env-configurable
// rules and produces a PurgeDecision. A runner iterates over the user's
// messages (in-memory or DB), applies the decision, deletes the BYOS object,
// and either drops the index row or marks it `auto_purged`.
//
// The engine is invoked by POST /admin/purge/run (shared-secret header) so an
// external cron / k8s CronJob / systemd timer can drive the cadence without
// the API owning a scheduler.
//
// Rules (all read from env, all measured in days-since-created_at):
//   AGENT_INBOX_AUTO_PURGE_ENABLED             default false
//   AGENT_INBOX_PURGE_BACKGROUND_AFTER_DAYS    default 30
//   AGENT_INBOX_PURGE_LOW_PRIORITY_AFTER_DAYS  default 180
//   AGENT_INBOX_PURGE_ARCHIVED_AFTER_DAYS      default 90
//
// `protected_senders` is taken from AGENT_INBOX_PURGE_PROTECTED_SENDER_DIDS
// (comma-separated). Messages from those DIDs are never purged regardless of
// age.

#[derive(Clone, Debug, PartialEq, Eq)]
enum PurgeDecision {
    Keep,
    /// Purge the BYOS object and delete the index row outright.
    Delete,
    /// Purge the BYOS object but retain a tombstone row with status='auto_purged'.
    Tombstone,
}

#[derive(Clone, Debug)]
struct PurgeRules {
    enabled: bool,
    background_after_days: i64,
    low_priority_after_days: i64,
    archived_after_days: i64,
    protected_sender_dids: HashSet<String>,
}

impl PurgeRules {
    fn from_env() -> Self {
        fn parse_days(key: &str, default: i64) -> i64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(default)
        }
        let enabled = std::env::var("AGENT_INBOX_AUTO_PURGE_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let protected_sender_dids = std::env::var("AGENT_INBOX_PURGE_PROTECTED_SENDER_DIDS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<HashSet<String>>();
        Self {
            enabled,
            background_after_days: parse_days("AGENT_INBOX_PURGE_BACKGROUND_AFTER_DAYS", 30),
            low_priority_after_days: parse_days("AGENT_INBOX_PURGE_LOW_PRIORITY_AFTER_DAYS", 180),
            archived_after_days: parse_days("AGENT_INBOX_PURGE_ARCHIVED_AFTER_DAYS", 90),
            protected_sender_dids,
        }
    }
}

/// Pure decision function. `now_unix` is the evaluation instant so tests can
/// pin the clock. Messages with unparseable `created_at` are kept.
fn evaluate_purge_decision(
    message: &MessageRecord,
    now_unix: i64,
    rules: &PurgeRules,
) -> PurgeDecision {
    if rules.protected_sender_dids.contains(&message.sender_did) {
        return PurgeDecision::Keep;
    }
    if message.status == "auto_purged" {
        // Already tombstoned — don't re-purge.
        return PurgeDecision::Keep;
    }

    let created_at = match chrono::DateTime::parse_from_rfc3339(&message.created_at) {
        Ok(dt) => dt.timestamp(),
        Err(_) => return PurgeDecision::Keep,
    };
    let age_days = (now_unix - created_at).max(0) / 86_400;

    // Archived messages: once older than threshold, purge BYOS payload and
    // keep an auto_purged tombstone so the user still sees "archived (purged)"
    // history in their inbox.
    if message.status == "archived" && age_days >= rules.archived_after_days {
        return PurgeDecision::Tombstone;
    }

    // background-category messages older than threshold: full delete, no tombstone.
    if message.ai_category.as_deref() == Some("background")
        && age_days >= rules.background_after_days
    {
        return PurgeDecision::Delete;
    }

    // low_priority: full delete after longer window.
    if message.ai_category.as_deref() == Some("low_priority")
        && age_days >= rules.low_priority_after_days
    {
        return PurgeDecision::Delete;
    }

    PurgeDecision::Keep
}

#[derive(Serialize, Default, Debug)]
struct PurgeSummary {
    scanned: u64,
    deleted: u64,
    tombstoned: u64,
    errors: u64,
}

/// Delete the BYOS object referenced by `storage_ref` without touching the
/// index row. Used by the auto-purge runner. Returns Ok(()) on success and on
/// idempotent "already missing" cases.
async fn delete_storage_object_by_ref(
    state: &AppState,
    user_id: &str,
    storage_ref: &str,
) -> Result<(), String> {
    let Some(parsed) = parse_storage_ref(storage_ref) else {
        return Ok(());
    };
    match parsed.backend {
        StorageBackend::GoogleDrive => {
            let client = Client::new();
            gdrive_delete_file(&client, &parsed.locator).await
        }
        StorageBackend::S3 => {
            let client = Client::new();
            s3_delete_object(&client, &parsed.locator).await
        }
        StorageBackend::Ipfs => {
            let client = Client::new();
            ipfs_delete_file(&client, &parsed.locator).await
        }
        StorageBackend::LocalFs | StorageBackend::GoogleDriveMock => {
            if let Some(path) = path_from_storage_ref(state, user_id, storage_ref) {
                match fs::remove_file(&path) {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(format!("localfs delete failed: {error}")),
                }
            } else {
                Ok(())
            }
        }
    }
}

/// Run a single pass of auto-purge. Iterates over the active state (DB if
/// available, otherwise the in-memory store for every user) and applies the
/// rules. Returns a summary usable by the HTTP handler.
async fn run_auto_purge_once(state: &AppState, rules: &PurgeRules) -> PurgeSummary {
    let mut summary = PurgeSummary::default();
    if !rules.enabled {
        return summary;
    }
    let now_unix = Utc::now().timestamp();

    // DB path. When a pool is available we scan all non-tombstoned rows across
    // every owner, apply the same pure evaluator used in the in-memory path,
    // delete the BYOS object, and either DELETE or UPDATE the index row.
    let maybe_pool = match state.database_pool().await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("[audit] auto_purge_db_pool_unavailable error={}", error);
            None
        }
    };
    if let Some(pool) = maybe_pool {
        let rows = match sqlx::query(
            r#"
            SELECT
              id::text AS id,
              owner_user_id::text AS owner_user_id,
              sender_did,
              recipient_did,
              thread_id::text AS thread_id,
              subject_encrypted,
              storage_ref,
              status,
              priority,
              ai_category,
              created_at::text AS created_at,
              trust_score
            FROM message_index
            WHERE status <> 'auto_purged'
            "#,
        )
        .fetch_all(&pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                eprintln!("[audit] auto_purge_db_scan_failed error={}", error);
                summary.errors += 1;
                return summary;
            }
        };

        for row in rows {
            summary.scanned += 1;
            let id_text: String = row.get("id");
            let Ok(message_id) = Uuid::parse_str(&id_text) else {
                summary.errors += 1;
                continue;
            };
            let owner_user_id: String = row.get("owner_user_id");
            let thread_id = row
                .get::<Option<String>, _>("thread_id")
                .and_then(|value| Uuid::parse_str(&value).ok());
            let message = MessageRecord {
                id: message_id,
                sender_did: row.get("sender_did"),
                sender_label: None,
                recipient_did: row.get("recipient_did"),
                recipient_label: None,
                thread_id,
                subject_encrypted: row.get("subject_encrypted"),
                storage_ref: row.get("storage_ref"),
                status: row.get("status"),
                priority: row.get("priority"),
                ai_category: row.get("ai_category"),
                created_at: row.get("created_at"),
                trust_score: row.get("trust_score"),
                folder: "inbox".to_string(),
                starred: false,
            };
            let decision = evaluate_purge_decision(&message, now_unix, rules);
            if decision == PurgeDecision::Keep {
                continue;
            }
            if let Err(error) =
                delete_storage_object_by_ref(state, &owner_user_id, &message.storage_ref).await
            {
                eprintln!(
                    "[audit] auto_purge_delete_failed user_id={} message_id={} error={}",
                    owner_user_id, message.id, error
                );
                summary.errors += 1;
                continue;
            }
            let Ok(owner_uuid) = Uuid::parse_str(&owner_user_id) else {
                summary.errors += 1;
                continue;
            };
            let sql_result = match decision {
                PurgeDecision::Delete => {
                    sqlx::query("DELETE FROM message_index WHERE id = $1 AND owner_user_id = $2")
                        .bind(message.id)
                        .bind(owner_uuid)
                        .execute(&pool)
                        .await
                }
                PurgeDecision::Tombstone => {
                    sqlx::query(
                        "UPDATE message_index SET status = 'auto_purged', storage_ref = '' \
                         WHERE id = $1 AND owner_user_id = $2",
                    )
                    .bind(message.id)
                    .bind(owner_uuid)
                    .execute(&pool)
                    .await
                }
                PurgeDecision::Keep => unreachable!(),
            };
            match sql_result {
                Ok(_) => match decision {
                    PurgeDecision::Delete => summary.deleted += 1,
                    PurgeDecision::Tombstone => summary.tombstoned += 1,
                    PurgeDecision::Keep => {}
                },
                Err(error) => {
                    eprintln!(
                        "[audit] auto_purge_index_update_failed message_id={} error={}",
                        message.id, error
                    );
                    summary.errors += 1;
                    continue;
                }
            }
            audit_storage_event(
                "auto_purge",
                state.storage_backend,
                &owner_user_id,
                Some(message.id),
                "ok",
                None,
            );
        }
        return summary;
    }

    // In-memory path: snapshot the map so we can release the lock before
    // awaiting storage deletes.
    let snapshot: Vec<(String, Vec<MessageRecord>)> = {
        let lock = state
            .messages_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        lock.iter()
            .map(|(uid, msgs)| (uid.clone(), msgs.clone()))
            .collect()
    };

    for (user_id, messages) in snapshot {
        for message in messages {
            summary.scanned += 1;
            let decision = evaluate_purge_decision(&message, now_unix, rules);
            if decision == PurgeDecision::Keep {
                continue;
            }
            if let Err(error) =
                delete_storage_object_by_ref(state, &user_id, &message.storage_ref).await
            {
                eprintln!(
                    "[audit] auto_purge_delete_failed user_id={} message_id={} error={}",
                    user_id, message.id, error
                );
                summary.errors += 1;
                continue;
            }
            // Apply the index update.
            let mut lock = state
                .messages_by_user
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(bucket) = lock.get_mut(&user_id) {
                match decision {
                    PurgeDecision::Delete => {
                        bucket.retain(|m| m.id != message.id);
                        summary.deleted += 1;
                    }
                    PurgeDecision::Tombstone => {
                        if let Some(found) = bucket.iter_mut().find(|m| m.id == message.id) {
                            found.status = "auto_purged".to_string();
                            found.storage_ref = String::new();
                        }
                        summary.tombstoned += 1;
                    }
                    PurgeDecision::Keep => unreachable!(),
                }
            }
            audit_storage_event(
                "auto_purge",
                state.storage_backend,
                &user_id,
                Some(message.id),
                "ok",
                None,
            );
        }
    }
    summary
}

#[derive(Serialize)]
struct PurgeRunResponse {
    summary: PurgeSummary,
}

/// POST /admin/purge/run
///
/// Shared-secret authentication via `X-Admin-Token` header (set
/// `AGENT_INBOX_ADMIN_TOKEN`). Returns 503 if auto-purge is disabled, 401 if
/// the token is missing or wrong, 200 otherwise.
async fn admin_run_purge(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PurgeRunResponse>, (StatusCode, Json<ErrorResponse>)> {
    let expected = std::env::var("AGENT_INBOX_ADMIN_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "admin_disabled".to_string(),
                message: "AGENT_INBOX_ADMIN_TOKEN is not configured".to_string(),
            }),
        ));
    }
    let provided = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "invalid admin token".to_string(),
            }),
        ));
    }
    let rules = PurgeRules::from_env();
    if !rules.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "auto_purge_disabled".to_string(),
                message: "AGENT_INBOX_AUTO_PURGE_ENABLED is not set".to_string(),
            }),
        ));
    }
    let summary = run_auto_purge_once(&state, &rules).await;
    eprintln!(
        "[audit] auto_purge_run scanned={} deleted={} tombstoned={} errors={}",
        summary.scanned, summary.deleted, summary.tombstoned, summary.errors
    );
    Ok(Json(PurgeRunResponse { summary }))
}

async fn ws_handler(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;

    // SECURITY: enforce per-user concurrent connection limit before upgrade.
    {
        let mut conns = state
            .ws_connections_per_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let current = conns.get(&user_id).copied().unwrap_or(0);
        if current >= WS_MAX_CONNECTIONS_PER_USER {
            eprintln!(
                "[audit] ws_connection_limit status=429 user_id={} current={}",
                user_id, current
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "ws_connection_limit".to_string(),
                    message: "maximum concurrent WebSocket connections reached".to_string(),
                }),
            ));
        }
        conns.insert(user_id.clone(), current + 1);
    }

    let state_for_socket = state.clone();
    Ok(ws.on_upgrade(move |socket| handle_socket(state_for_socket, socket, user_id)))
}

/// Decrement the per-user WS connection counter on disconnect.
fn release_ws_connection(state: &AppState, user_id: &str) {
    let mut conns = state
        .ws_connections_per_user
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = conns.get_mut(user_id) {
        if *entry > 0 {
            *entry -= 1;
        }
        if *entry == 0 {
            conns.remove(user_id);
        }
    }
}

async fn handle_socket(state: AppState, mut socket: WebSocket, user_id: String) {
    // Send initial placeholder event so existing clients keep working.
    let event = WsEvent {
        event: "new_message".to_string(),
        data: WsEventData {
            message_id: Uuid::new_v4().to_string(),
            agent_did: format!("did:key:{user_id}"),
            sender_did: "did:key:system".to_string(),
            subject_encrypted: "base64-subject".to_string(),
            priority: "normal".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        },
    };

    if let Ok(payload) = serde_json::to_string(&event) {
        let _ = socket.send(Message::Text(payload.into())).await;
    }

    // SECURITY: receive loop with per-connection rate limiting, size enforcement, and idle timeout.
    let mut window_started_at = Utc::now().timestamp();
    let mut frame_count: u64 = 0;

    loop {
        let recv =
            tokio::time::timeout(Duration::from_secs(WS_IDLE_TIMEOUT_SECS), socket.recv()).await;

        let msg = match recv {
            Err(_) => {
                // Idle timeout
                eprintln!(
                    "[audit] ws_idle_timeout user_id={} after_secs={}",
                    user_id, WS_IDLE_TIMEOUT_SECS
                );
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            Ok(None) => break,         // connection closed
            Ok(Some(Err(_))) => break, // transport error
            Ok(Some(Ok(msg))) => msg,
        };

        // Rate limiting: check window and count
        let now = Utc::now().timestamp();
        if now - window_started_at >= WS_RATE_WINDOW_SECS {
            window_started_at = now;
            frame_count = 0;
        }
        frame_count += 1;
        if frame_count > WS_MAX_FRAMES_PER_WINDOW {
            eprintln!(
                "[audit] ws_frame_rate_limit user_id={} frames={}",
                user_id, frame_count
            );
            let _ = socket.send(Message::Close(None)).await;
            break;
        }

        // Size enforcement
        let frame_size = match &msg {
            Message::Text(t) => t.len(),
            Message::Binary(b) => b.len(),
            _ => 0,
        };
        if frame_size > WS_MAX_FRAME_BYTES {
            eprintln!(
                "[audit] ws_frame_too_large user_id={} size={}",
                user_id, frame_size
            );
            let _ = socket.send(Message::Close(None)).await;
            break;
        }

        // Handle message types
        match msg {
            Message::Close(_) => break,
            Message::Ping(data) => {
                let _ = socket.send(Message::Pong(data)).await;
            }
            // Text/Binary/Pong: currently no commands defined; ignore quietly.
            _ => {}
        }
    }

    release_ws_connection(&state, &user_id);
}

pub fn app() -> Router {
    let state = AppState::default();
    app_with_state(state)
}

pub fn app_with_storage_backend(backend: &str) -> Router {
    let storage_backend = StorageBackend::from_str(backend).unwrap_or(StorageBackend::LocalFs);
    let state = AppState::new_with_backend(storage_backend);
    app_with_state(state)
}

pub fn app_with_policy_dids(
    blocked_recipient_dids: &[&str],
    low_trust_sender_dids: &[&str],
) -> Router {
    let state = AppState::new_with_backend_and_policies(
        StorageBackend::LocalFs,
        blocked_recipient_dids
            .iter()
            .map(|did| did.to_string())
            .collect(),
        low_trust_sender_dids
            .iter()
            .map(|did| did.to_string())
            .collect(),
    );
    app_with_state(state)
}

/// Build CORS layer based on environment configuration.
fn build_cors_layer() -> CorsLayer {
    let allowed_origins_raw =
        std::env::var("AGENT_INBOX_CORS_ORIGINS").unwrap_or_else(|_| String::new());

    let cors = if is_production_env() {
        // In production, require explicit origin allowlist
        if allowed_origins_raw.is_empty() {
            warn!(
                "AGENT_INBOX_CORS_ORIGINS not set — using default production origin. \
                 Set AGENT_INBOX_CORS_ORIGINS to explicitly configure allowed origins."
            );
            CorsLayer::new()
                .allow_origin("https://app.nexusinbox.ai".parse::<HeaderValue>().unwrap())
        } else {
            let origins: Vec<HeaderValue> = allowed_origins_raw
                .split(',')
                .filter_map(|s| s.trim().parse::<HeaderValue>().ok())
                .collect();
            CorsLayer::new().allow_origin(origins)
        }
    } else {
        // In development, allow configured origins or localhost variants
        if allowed_origins_raw.is_empty() {
            CorsLayer::new().allow_origin([
                "http://localhost:3000".parse::<HeaderValue>().unwrap(),
                "http://localhost:3100".parse::<HeaderValue>().unwrap(),
                "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
                "http://127.0.0.1:3100".parse::<HeaderValue>().unwrap(),
            ])
        } else {
            let origins: Vec<HeaderValue> = allowed_origins_raw
                .split(',')
                .filter_map(|s| s.trim().parse::<HeaderValue>().ok())
                .collect();
            CorsLayer::new().allow_origin(origins)
        }
    };

    cors.allow_methods([
        Method::GET,
        Method::POST,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ])
    .allow_headers([AUTHORIZATION, CONTENT_TYPE, COOKIE])
    .allow_credentials(true)
    .max_age(Duration::from_secs(3600))
}

fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(public_status))
        .route("/auth/verify", post(auth_verify))
        .route(
            "/auth/session",
            get(auth_session).patch(update_auth_profile),
        )
        .route("/auth/logout", post(auth_logout))
        .route("/agents", get(list_agents).post(create_agent))
        .route(
            "/agents/{id}",
            axum::routing::patch(update_agent).delete(delete_agent),
        )
        .route(
            "/agent-credentials",
            get(list_agent_credentials).post(create_agent_credential),
        )
        .route(
            "/agent-credentials/{id}",
            axum::routing::patch(patch_agent_credential).delete(revoke_agent_credential),
        )
        .route(
            "/agent-credentials/{id}/activate",
            post(activate_agent_credential),
        )
        .route(
            "/agent-credentials/{id}/rotate",
            post(rotate_agent_credential),
        )
        .route(
            "/agent-credentials/{id}/purge",
            post(purge_agent_credential),
        )
        .route("/agent-auth/token", post(agent_auth_token))
        .route("/agent-auth/refresh", post(agent_auth_refresh))
        .route("/agent-auth/revoke", post(agent_auth_revoke))
        .route("/agent-audit-log", get(list_agent_audit_log))
        .route("/agent-audit-log/bridge", post(ingest_bridge_audit_event))
        .route(
            "/agents/{id}/emergency-shutdown",
            post(agent_emergency_shutdown),
        )
        .route(
            "/agents/{id}/auto-reply-policy",
            get(get_auto_reply_policy)
                .put(put_auto_reply_policy)
                .delete(delete_auto_reply_policy),
        )
        .route("/blocks", get(list_blocks).post(create_block))
        .route(
            "/blocks/from-message/{message_id}",
            post(create_block_from_message),
        )
        .route("/blocks/{id}", axum::routing::delete(delete_block))
        .route("/contacts", get(list_contacts).post(create_contact))
        .route(
            "/contacts/{id}",
            axum::routing::patch(update_contact).delete(delete_contact),
        )
        .route("/recipients/resolve", get(resolve_recipient))
        .route("/messages", get(list_messages).post(send_message))
        .route("/messages/{id}/content", get(message_content))
        .route(
            "/messages/{id}",
            axum::routing::patch(update_message_status).delete(delete_message),
        )
        .route(
            "/messages/{id}/auto-reply-sent",
            axum::routing::patch(mark_auto_reply_sent),
        )
        .route(
            "/messages/{id}/flags",
            axum::routing::patch(update_message_flags),
        )
        .route("/messages/{id}/attachments", get(list_message_attachments))
        .route(
            "/messages/{id}/attachments/{attachment_id}/download",
            post(generate_attachment_download_url),
        )
        .route("/attachments/intents", post(create_attachment_intent))
        .route("/attachments/{id}/complete", post(complete_attachment))
        .route(
            "/attachments/{id}",
            axum::routing::delete(delete_attachment),
        )
        .route("/ws", get(ws_handler))
        .route("/admin/purge/run", post(admin_run_purge))
        .layer(build_cors_layer())
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(axum::middleware::from_fn(enforce_csrf_protection))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_request_rate_limit,
        ))
        .layer(axum::middleware::from_fn(enforce_request_timeout))
        .with_state(state)
}

#[cfg(test)]
mod internal_tests {
    use super::*;
    use serial_test::serial;

    fn make_state() -> AppState {
        AppState::new_with_backend_and_policies(
            StorageBackend::LocalFs,
            HashSet::new(),
            HashSet::new(),
        )
    }

    fn push_record(state: &AppState, user_id: &str, sender_did: &str, status: &str) {
        let mut lock = state
            .messages_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        lock.entry(user_id.to_string())
            .or_default()
            .push(MessageRecord {
                id: Uuid::new_v4(),
                sender_did: sender_did.to_string(),
                sender_label: None,
                recipient_did: "did:key:zRecipient".to_string(),
                recipient_label: None,
                thread_id: None,
                subject_encrypted: "s".into(),
                storage_ref: "r".into(),
                status: status.into(),
                priority: "normal".into(),
                ai_category: None,
                created_at: Utc::now().to_rfc3339(),
                trust_score: 0.8,
                folder: "inbox".into(),
                starred: false,
            });
    }

    #[test]
    fn account_age_bonus_kicks_in_at_thresholds() {
        let state = make_state();
        let now = Utc::now().timestamp();
        // <7 days → no bonus → orb baseline 0.80.
        record_first_seen(&state, "0xage", now - 86_400 * 3);
        let s = compute_trust_score(&state, "user-age", "did:key:sender", "0xage", "orb");
        assert!((s - 0.80).abs() < 1e-3, "got {s}");

        // >=7 days → +0.05.
        let state = make_state();
        record_first_seen(&state, "0xage", now - 86_400 * 10);
        let s = compute_trust_score(&state, "user-age", "did:key:sender", "0xage", "orb");
        assert!((s - 0.85).abs() < 1e-3, "got {s}");

        // >=30 days → +0.10 (capped at 1.0 by clamp).
        let state = make_state();
        record_first_seen(&state, "0xage", now - 86_400 * 60);
        let s = compute_trust_score(&state, "user-age", "did:key:sender", "0xage", "orb");
        assert!((s - 0.90).abs() < 1e-3, "got {s}");
    }

    #[test]
    fn delivery_history_archived_ratio_lowers_score() {
        let state = make_state();
        // 5 messages, 3 archived (60%), 0 read → -0.30.
        for _ in 0..3 {
            push_record(&state, "user-h", "did:key:sender", "archived");
        }
        for _ in 0..2 {
            push_record(&state, "user-h", "did:key:sender", "delivered");
        }
        let s = compute_trust_score(&state, "user-h", "did:key:sender", "0xh", "orb");
        assert!((s - 0.50).abs() < 1e-3, "got {s}");
    }

    #[test]
    fn delivery_history_high_read_ratio_grants_small_bonus() {
        let state = make_state();
        // 5 messages, 4 read (80%), 1 delivered → +0.05.
        for _ in 0..4 {
            push_record(&state, "user-h2", "did:key:sender", "read");
        }
        push_record(&state, "user-h2", "did:key:sender", "delivered");
        let s = compute_trust_score(&state, "user-h2", "did:key:sender", "0xh2", "orb");
        assert!((s - 0.85).abs() < 1e-3, "got {s}");
    }

    #[test]
    fn delivery_history_below_sample_threshold_is_ignored() {
        let state = make_state();
        // 4 archived messages → still under sample threshold 5 → no penalty.
        for _ in 0..4 {
            push_record(&state, "user-h3", "did:key:sender", "archived");
        }
        let s = compute_trust_score(&state, "user-h3", "did:key:sender", "0xh3", "orb");
        assert!((s - 0.80).abs() < 1e-3, "got {s}");
    }

    #[test]
    #[serial]
    fn issue_session_cookie_enables_secure_when_env_is_true() {
        let previous = std::env::var("AGENT_INBOX_COOKIE_SECURE").ok();
        // SAFETY: test-local env mutation.
        unsafe {
            std::env::set_var("AGENT_INBOX_COOKIE_SECURE", "true");
        }
        let cookie = issue_session_cookie("token-value");
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));

        // SAFETY: restore prior env value.
        unsafe {
            match previous {
                Some(value) => std::env::set_var("AGENT_INBOX_COOKIE_SECURE", value),
                None => std::env::remove_var("AGENT_INBOX_COOKIE_SECURE"),
            }
        }
    }

    #[test]
    #[serial]
    fn issue_session_cookie_appends_domain_when_env_is_set() {
        // Regression for cross-subdomain WebSocket auth: without the
        // Domain attribute the cookie is host-scoped to the frontend
        // (app.nexusinbox.ai) and never reaches the API (api.nexusinbox.ai),
        // breaking the /ws handshake.
        let previous = std::env::var("AGENT_INBOX_COOKIE_DOMAIN").ok();
        // SAFETY: test-local env mutation under #[serial].
        unsafe {
            std::env::set_var("AGENT_INBOX_COOKIE_DOMAIN", ".nexusinbox.ai");
        }
        let issued = issue_session_cookie("token-value");
        let cleared = clear_session_cookie();
        assert!(
            issued.contains("Domain=.nexusinbox.ai"),
            "issue should include Domain attribute, got: {issued}"
        );
        assert!(
            cleared.contains("Domain=.nexusinbox.ai"),
            "clear must match issue's Domain or the browser keeps the session, got: {cleared}"
        );

        // SAFETY: restore prior env value.
        unsafe {
            match previous {
                Some(value) => std::env::set_var("AGENT_INBOX_COOKIE_DOMAIN", value),
                None => std::env::remove_var("AGENT_INBOX_COOKIE_DOMAIN"),
            }
        }
    }

    #[test]
    #[serial]
    fn issue_session_cookie_omits_domain_when_env_is_empty_or_unset() {
        // Dev / single-host deployments must stay host-scoped (Domain= is
        // illegal with a value of "localhost" on some browsers, and any
        // explicit Domain= fails when the serving host isn't a parent match).
        let previous = std::env::var("AGENT_INBOX_COOKIE_DOMAIN").ok();
        // SAFETY: test-local env mutation.
        unsafe {
            std::env::remove_var("AGENT_INBOX_COOKIE_DOMAIN");
        }
        let unset = issue_session_cookie("t");
        unsafe {
            std::env::set_var("AGENT_INBOX_COOKIE_DOMAIN", "   ");
        }
        let whitespace = issue_session_cookie("t");
        assert!(!unset.contains("Domain="), "unset → no Domain: {unset}");
        assert!(
            !whitespace.contains("Domain="),
            "whitespace → treated as unset: {whitespace}"
        );

        // SAFETY: restore prior env value.
        unsafe {
            match previous {
                Some(value) => std::env::set_var("AGENT_INBOX_COOKIE_DOMAIN", value),
                None => std::env::remove_var("AGENT_INBOX_COOKIE_DOMAIN"),
            }
        }
    }

    #[test]
    #[serial]
    fn validate_runtime_config_requires_database_url_when_database_is_required() {
        let previous_required = std::env::var("AGENT_INBOX_DATABASE_REQUIRED").ok();
        let previous_database_url = std::env::var("DATABASE_URL").ok();
        let previous_jwt_secret = std::env::var("JWT_SECRET").ok();
        let previous_node_env = std::env::var("NODE_ENV").ok();

        // SAFETY: test-local env mutation.
        unsafe {
            std::env::set_var("NODE_ENV", "development");
            std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", "true");
            std::env::remove_var("DATABASE_URL");
            std::env::set_var("JWT_SECRET", "01234567890123456789012345678901");
        }

        let result = validate_runtime_config();
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap_or_default()
            .contains("DATABASE_URL is required"));

        // SAFETY: restore prior env values.
        unsafe {
            match previous_required {
                Some(value) => std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", value),
                None => std::env::remove_var("AGENT_INBOX_DATABASE_REQUIRED"),
            }
            match previous_database_url {
                Some(value) => std::env::set_var("DATABASE_URL", value),
                None => std::env::remove_var("DATABASE_URL"),
            }
            match previous_jwt_secret {
                Some(value) => std::env::set_var("JWT_SECRET", value),
                None => std::env::remove_var("JWT_SECRET"),
            }
            match previous_node_env {
                Some(value) => std::env::set_var("NODE_ENV", value),
                None => std::env::remove_var("NODE_ENV"),
            }
        }
    }

    #[test]
    #[serial]
    fn validate_runtime_config_requires_database_url_in_production() {
        let previous_required = std::env::var("AGENT_INBOX_DATABASE_REQUIRED").ok();
        let previous_database_url = std::env::var("DATABASE_URL").ok();
        let previous_jwt_secret = std::env::var("JWT_SECRET").ok();
        let previous_node_env = std::env::var("NODE_ENV").ok();
        let previous_world_verify = std::env::var("AGENT_INBOX_WORLD_VERIFY_ENABLED").ok();

        // SAFETY: test-local env mutation.
        unsafe {
            std::env::set_var("NODE_ENV", "production");
            std::env::remove_var("AGENT_INBOX_DATABASE_REQUIRED");
            std::env::remove_var("DATABASE_URL");
            std::env::set_var("JWT_SECRET", "01234567890123456789012345678901");
            std::env::set_var("AGENT_INBOX_WORLD_VERIFY_ENABLED", "true");
        }

        let result = validate_runtime_config();
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap_or_default()
            .contains("DATABASE_URL is required"));

        // SAFETY: restore prior env values.
        unsafe {
            match previous_required {
                Some(value) => std::env::set_var("AGENT_INBOX_DATABASE_REQUIRED", value),
                None => std::env::remove_var("AGENT_INBOX_DATABASE_REQUIRED"),
            }
            match previous_database_url {
                Some(value) => std::env::set_var("DATABASE_URL", value),
                None => std::env::remove_var("DATABASE_URL"),
            }
            match previous_jwt_secret {
                Some(value) => std::env::set_var("JWT_SECRET", value),
                None => std::env::remove_var("JWT_SECRET"),
            }
            match previous_node_env {
                Some(value) => std::env::set_var("NODE_ENV", value),
                None => std::env::remove_var("NODE_ENV"),
            }
            match previous_world_verify {
                Some(value) => std::env::set_var("AGENT_INBOX_WORLD_VERIFY_ENABLED", value),
                None => std::env::remove_var("AGENT_INBOX_WORLD_VERIFY_ENABLED"),
            }
        }
    }

    #[test]
    #[serial]
    fn issue_dev_jwt_embeds_jti_claim() {
        let previous_jwt_secret = std::env::var("JWT_SECRET").ok();
        // SAFETY: test-local env mutation.
        unsafe {
            std::env::set_var("JWT_SECRET", "01234567890123456789012345678901");
        }

        let token = issue_dev_jwt("00000000-0000-0000-0000-000000000001", "wid", "orb", 60);
        let claims = verify_dev_jwt(&token).expect("token should decode");
        assert!(claims.jti.is_some());
        assert!(!claims.jti.unwrap_or_default().is_empty());

        // SAFETY: restore prior env values.
        unsafe {
            match previous_jwt_secret {
                Some(value) => std::env::set_var("JWT_SECRET", value),
                None => std::env::remove_var("JWT_SECRET"),
            }
        }
    }

    #[test]
    fn derive_did_from_public_key_matches_did_key_multicodec_format() {
        let public_key_b64url = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
        let did = derive_did_from_public_key(public_key_b64url).expect("did should derive");
        assert!(did.starts_with("did:key:z"));

        let encoded = did.trim_start_matches("did:key:z");
        let decoded = bs58::decode(encoded)
            .into_vec()
            .expect("did:key fingerprint should be valid base58btc");

        assert_eq!(decoded.len(), 34);
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);

        let original_key = decode_base64url(public_key_b64url).expect("base64url should decode");
        assert_eq!(decoded[2..], original_key[..]);
    }

    #[test]
    fn enforce_agent_bound_aid_allows_matching_credential_aid() {
        let ctx = AuthContext::Agent {
            user_id: "user-1".to_string(),
            credential_id: Uuid::new_v4(),
            aid: "aid:ai:test123".to_string(),
            scopes: vec!["messages.read".to_string()],
        };
        assert!(enforce_agent_bound_aid(&ctx, "aid:ai:test123").is_ok());
    }

    #[test]
    fn enforce_agent_bound_aid_rejects_other_agents() {
        let ctx = AuthContext::Agent {
            user_id: "user-1".to_string(),
            credential_id: Uuid::new_v4(),
            aid: "aid:ai:test123".to_string(),
            scopes: vec!["messages.read".to_string()],
        };
        let err = enforce_agent_bound_aid(&ctx, "aid:ai:other456").expect_err("must reject");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn parse_storage_ref_accepts_v1_and_legacy_formats() {
        let message_id = Uuid::new_v4();
        let v1 = format!("localfs:v1://{message_id}");
        let legacy = format!("localfs://{message_id}");

        let parsed_v1 = parse_storage_ref(&v1).expect("v1 storage_ref should parse");
        let parsed_legacy = parse_storage_ref(&legacy).expect("legacy storage_ref should parse");

        assert!(matches!(parsed_v1.backend, StorageBackend::LocalFs));
        assert!(matches!(parsed_legacy.backend, StorageBackend::LocalFs));
        assert_eq!(parsed_v1.locator, message_id.to_string());
        assert_eq!(parsed_legacy.locator, message_id.to_string());
    }

    #[test]
    fn s3_storage_backend_scheme_roundtrip() {
        assert!(matches!(
            StorageBackend::from_str("s3"),
            Some(StorageBackend::S3)
        ));
        assert!(matches!(
            StorageBackend::from_str("minio"),
            Some(StorageBackend::S3)
        ));
        assert_eq!(StorageBackend::S3.storage_ref_scheme(), "s3");
        assert_eq!(StorageBackend::S3.storage_subdir(), "s3");

        let key = "inbox/550e8400-e29b-41d4-a716-446655440000.json";
        let storage_ref = storage_ref_for_locator(StorageBackend::S3, key);
        assert_eq!(storage_ref, format!("s3:v1://{key}"));
        let parsed = parse_storage_ref(&storage_ref).expect("s3 storage ref parses");
        assert!(matches!(parsed.backend, StorageBackend::S3));
        assert_eq!(parsed.locator, key);
    }

    #[test]
    fn s3_sigv4_canonical_request_matches_aws_example() {
        // Known-answer test: AWS SigV4 "GetObject" example from AWS docs, using
        // Credential=AKIAIOSFODNN7EXAMPLE / SecretKey=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
        // Region=us-east-1 / Service=s3 / Date=20130524T000000Z.
        // We can't mock Utc::now, so we only verify the canonical URI encoder
        // and the HMAC helpers used by the signer.
        let encoded = s3_uri_encode("path/to/object name.json", false);
        assert_eq!(encoded, "path/to/object%20name.json");
        // Slashes get escaped when encode_slash=true (used for query strings).
        let encoded_all = s3_uri_encode("a/b c", true);
        assert_eq!(encoded_all, "a%2Fb%20c");

        // HMAC-SHA256 known answer (RFC 4231 Test Case 1).
        let mac = hmac_sha256(&[0x0bu8; 20], b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    fn purge_rules_for_tests() -> PurgeRules {
        PurgeRules {
            enabled: true,
            background_after_days: 30,
            low_priority_after_days: 180,
            archived_after_days: 90,
            protected_sender_dids: HashSet::new(),
        }
    }

    fn fake_message(status: &str, category: Option<&str>, days_ago: i64) -> MessageRecord {
        let created = Utc::now() - chrono::Duration::days(days_ago);
        MessageRecord {
            id: Uuid::new_v4(),
            sender_did: "did:key:zSender".to_string(),
            sender_label: None,
            recipient_did: "did:key:zRecipient".to_string(),
            recipient_label: None,
            thread_id: None,
            subject_encrypted: "c3Viag==".to_string(),
            storage_ref: "localfs:v1://abc".to_string(),
            status: status.to_string(),
            priority: "normal".to_string(),
            ai_category: category.map(str::to_string),
            created_at: created.to_rfc3339(),
            trust_score: 0.5,
            folder: "inbox".to_string(),
            starred: false,
        }
    }

    #[test]
    fn auto_purge_keeps_fresh_background_message() {
        let rules = purge_rules_for_tests();
        let msg = fake_message("unread", Some("background"), 5);
        let now = Utc::now().timestamp();
        assert_eq!(
            evaluate_purge_decision(&msg, now, &rules),
            PurgeDecision::Keep
        );
    }

    #[test]
    fn auto_purge_deletes_old_background_message() {
        let rules = purge_rules_for_tests();
        let msg = fake_message("unread", Some("background"), 45);
        let now = Utc::now().timestamp();
        assert_eq!(
            evaluate_purge_decision(&msg, now, &rules),
            PurgeDecision::Delete
        );
    }

    #[test]
    fn auto_purge_tombstones_old_archived_message() {
        let rules = purge_rules_for_tests();
        let msg = fake_message("archived", Some("normal"), 100);
        let now = Utc::now().timestamp();
        assert_eq!(
            evaluate_purge_decision(&msg, now, &rules),
            PurgeDecision::Tombstone
        );
    }

    #[test]
    fn auto_purge_respects_protected_sender_list() {
        let mut rules = purge_rules_for_tests();
        rules
            .protected_sender_dids
            .insert("did:key:zSender".to_string());
        let msg = fake_message("unread", Some("background"), 45);
        let now = Utc::now().timestamp();
        assert_eq!(
            evaluate_purge_decision(&msg, now, &rules),
            PurgeDecision::Keep
        );
    }

    #[test]
    fn auto_purge_skips_already_tombstoned_rows() {
        let rules = purge_rules_for_tests();
        let msg = fake_message("auto_purged", Some("background"), 400);
        let now = Utc::now().timestamp();
        assert_eq!(
            evaluate_purge_decision(&msg, now, &rules),
            PurgeDecision::Keep
        );
    }

    #[test]
    fn auto_purge_low_priority_requires_longer_window() {
        let rules = purge_rules_for_tests();
        let young = fake_message("unread", Some("low_priority"), 100);
        let old = fake_message("unread", Some("low_priority"), 200);
        let now = Utc::now().timestamp();
        assert_eq!(
            evaluate_purge_decision(&young, now, &rules),
            PurgeDecision::Keep
        );
        assert_eq!(
            evaluate_purge_decision(&old, now, &rules),
            PurgeDecision::Delete
        );
    }

    #[test]
    fn ipfs_storage_backend_scheme_roundtrip() {
        assert!(matches!(
            StorageBackend::from_str("ipfs"),
            Some(StorageBackend::Ipfs)
        ));
        assert_eq!(StorageBackend::Ipfs.storage_ref_scheme(), "ipfs");
        assert_eq!(StorageBackend::Ipfs.storage_subdir(), "ipfs");

        let cid = "bafybeigdyrztkwmrxgbeh5m6nw2qyqzvywg2fwm6fh6phq3mzg2umyzx2i";
        let storage_ref = storage_ref_for_locator(StorageBackend::Ipfs, cid);
        assert_eq!(storage_ref, format!("ipfs:v1://{cid}"));
        let parsed = parse_storage_ref(&storage_ref).expect("ipfs storage ref parses");
        assert!(matches!(parsed.backend, StorageBackend::Ipfs));
        assert_eq!(parsed.locator, cid);
    }

    // ---- DPoP replay-store tests (in-memory path) ----
    //
    // Exercises `check_and_record_dpop_replay_in_memory`, which is the
    // fallback path when DATABASE_URL is not configured (dev / tests). The
    // Postgres path shares identical accept/reject semantics via
    // `replay_nonces (scope, replay_key)`; the DB variant is covered by
    // `tests/dpop_replay_db_integration_test.rs` against a live Postgres.

    #[test]
    fn dpop_replay_in_memory_accepts_first_and_rejects_second() {
        let state = make_state();
        let iat = Utc::now().timestamp();
        assert!(
            check_and_record_dpop_replay_in_memory(&state, "jti-1", "jkt-A", "POST", "/m", iat),
            "first sighting must be accepted"
        );
        assert!(
            !check_and_record_dpop_replay_in_memory(&state, "jti-1", "jkt-A", "POST", "/m", iat),
            "replay of same scope+jti must be rejected"
        );
    }

    #[test]
    fn dpop_replay_in_memory_different_jkt_is_not_a_replay() {
        let state = make_state();
        let iat = Utc::now().timestamp();
        assert!(check_and_record_dpop_replay_in_memory(
            &state,
            "jti-shared",
            "jkt-A",
            "POST",
            "/m",
            iat,
        ));
        assert!(
            check_and_record_dpop_replay_in_memory(
                &state,
                "jti-shared",
                "jkt-B",
                "POST",
                "/m",
                iat,
            ),
            "jti collision across different DPoP keys must not false-positive",
        );
    }

    #[test]
    fn dpop_replay_in_memory_different_htm_is_not_a_replay() {
        let state = make_state();
        let iat = Utc::now().timestamp();
        assert!(check_and_record_dpop_replay_in_memory(
            &state,
            "jti-shared",
            "jkt-A",
            "POST",
            "/m",
            iat,
        ));
        assert!(
            check_and_record_dpop_replay_in_memory(&state, "jti-shared", "jkt-A", "GET", "/m", iat,),
            "same key + jti but different HTTP method must not be flagged",
        );
    }

    #[test]
    fn dpop_replay_in_memory_different_htu_is_not_a_replay() {
        let state = make_state();
        let iat = Utc::now().timestamp();
        assert!(check_and_record_dpop_replay_in_memory(
            &state,
            "jti-shared",
            "jkt-A",
            "POST",
            "/messages",
            iat,
        ));
        assert!(
            check_and_record_dpop_replay_in_memory(
                &state,
                "jti-shared",
                "jkt-A",
                "POST",
                "/attachments/intents",
                iat,
            ),
            "same key + jti but different endpoint must not be flagged",
        );
    }

    #[test]
    fn dpop_replay_scope_encodes_all_context_fields() {
        let s = dpop_replay_scope("jkt-A", "POST", "/m");
        assert!(s.contains("dpop_proof"));
        assert!(s.contains("jkt-A"));
        assert!(s.contains("POST"));
        assert!(s.contains("/m"));

        // Changing any component must change the scope string so the DB
        // unique constraint (scope, replay_key) cannot collapse them.
        assert_ne!(s, dpop_replay_scope("jkt-B", "POST", "/m"));
        assert_ne!(s, dpop_replay_scope("jkt-A", "GET", "/m"));
        assert_ne!(s, dpop_replay_scope("jkt-A", "POST", "/other"));
    }

    // ---- DPoP replay-store tests (Postgres path) ----
    //
    // These exercise the shared `replay_nonces` table directly. They only
    // run when DATABASE_URL points at a live Postgres (usual Docker compose
    // database); otherwise they're skipped so the default test suite stays
    // hermetic. Each test uses a Uuid-suffixed scope so parallel runs don't
    // collide on the unique index.

    async fn try_connect_replay_db() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(DB_CONNECT_TIMEOUT_SECS))
            .connect(&url)
            .await
            .ok()
    }

    #[tokio::test]
    async fn dpop_replay_in_db_accepts_first_rejects_second() {
        let Some(pool) = try_connect_replay_db().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let run_id = Uuid::new_v4().to_string();
        let scope = format!("{}|{}", dpop_replay_scope("jkt-A", "POST", "/m"), run_id);
        let jti = "jti-once";

        let first = check_and_record_replay_in_db(&pool, &scope, jti, 60)
            .await
            .expect("DB insert should succeed");
        assert!(first, "first sighting must be accepted");

        let second = check_and_record_replay_in_db(&pool, &scope, jti, 60)
            .await
            .expect("DB insert should succeed");
        assert!(!second, "replay of same (scope, jti) must be rejected");
    }

    #[tokio::test]
    async fn dpop_replay_in_db_different_scope_is_not_a_replay() {
        let Some(pool) = try_connect_replay_db().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let run_id = Uuid::new_v4().to_string();
        let scope_a = format!("{}|{}", dpop_replay_scope("jkt-A", "POST", "/m"), run_id);
        let scope_b = format!("{}|{}", dpop_replay_scope("jkt-B", "POST", "/m"), run_id);
        let jti = "jti-shared";

        assert!(check_and_record_replay_in_db(&pool, &scope_a, jti, 60)
            .await
            .expect("first insert ok"));
        assert!(
            check_and_record_replay_in_db(&pool, &scope_b, jti, 60)
                .await
                .expect("second insert (different scope) ok"),
            "same jti under a different DPoP key must not be flagged as replay",
        );
    }

    #[tokio::test]
    async fn dpop_replay_in_db_parallel_race_leaves_exactly_one_accepted() {
        // If N clients submit the same (scope, jti) concurrently, exactly
        // ONE INSERT must win and the rest must see Ok(false). This is
        // what the unique index buys us.
        let Some(pool) = try_connect_replay_db().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let run_id = Uuid::new_v4().to_string();
        let scope = format!("{}|{}", dpop_replay_scope("jkt-A", "POST", "/m"), run_id);
        let jti = "jti-parallel";

        let mut handles = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            let scope = scope.clone();
            let jti = jti.to_string();
            handles.push(tokio::spawn(async move {
                check_and_record_replay_in_db(&pool, &scope, &jti, 60)
                    .await
                    .expect("DB insert should return ok")
            }));
        }
        let mut accepted = 0;
        for h in handles {
            if h.await.expect("task should complete") {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, 1,
            "exactly one concurrent insert must win the unique-index race",
        );
    }

    #[tokio::test]
    async fn dpop_replay_in_db_cleanup_does_not_poison_future_inserts() {
        // After expiry-based cleanup deletes stale rows, a *different*
        // (scope, jti) pair must still be acceptable. Guards against a
        // buggy cleanup that drops unrelated rows.
        let Some(pool) = try_connect_replay_db().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let run_id = Uuid::new_v4().to_string();
        let scope = format!("{}|{}", dpop_replay_scope("jkt-A", "POST", "/m"), run_id);

        // Insert an entry that expires immediately (ttl=0 → expires_at = NOW()).
        assert!(check_and_record_replay_in_db(&pool, &scope, "jti-old", 0)
            .await
            .expect("first insert ok"));
        sqlx::query("DELETE FROM replay_nonces WHERE expires_at <= NOW()")
            .execute(&pool)
            .await
            .expect("cleanup should succeed");

        assert!(
            check_and_record_replay_in_db(&pool, &scope, "jti-new", 60)
                .await
                .expect("fresh jti insert ok"),
            "cleanup must not poison the index for unrelated keys",
        );
    }

    // -----------------------------------------------------------------
    // Bridge audit ingest — aud derivation + replay protection.
    // Pure-function unit tests; the full signature + DB path is
    // exercised by the hermetic suite in
    // `tests/bridge_audit_ingest_test.rs`.
    // -----------------------------------------------------------------

    #[test]
    #[serial]
    fn bridge_audit_aud_prefers_env_var_over_host_header() {
        // SAFETY: these tests are marked `#[serial]` so env var writes
        // don't race with other suites.
        let previous = std::env::var("AGENT_INBOX_PUBLIC_API_URL").ok();
        unsafe {
            std::env::set_var("AGENT_INBOX_PUBLIC_API_URL", "https://api.example.test/");
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "evil.attacker.example".parse().unwrap());
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        let aud =
            expected_api_url(&headers, "/agent-audit-log/bridge").expect("env branch must resolve");
        assert_eq!(aud, "https://api.example.test/agent-audit-log/bridge");
        unsafe {
            match previous {
                Some(v) => std::env::set_var("AGENT_INBOX_PUBLIC_API_URL", v),
                None => std::env::remove_var("AGENT_INBOX_PUBLIC_API_URL"),
            }
        }
    }

    #[test]
    #[serial]
    fn bridge_audit_aud_falls_back_to_host_header_when_env_unset() {
        let previous = std::env::var("AGENT_INBOX_PUBLIC_API_URL").ok();
        unsafe {
            std::env::remove_var("AGENT_INBOX_PUBLIC_API_URL");
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "api.nexusinbox.ai".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let aud = expected_api_url(&headers, "/agent-audit-log/bridge")
            .expect("host branch must resolve");
        assert_eq!(aud, "https://api.nexusinbox.ai/agent-audit-log/bridge");
        unsafe {
            if let Some(v) = previous {
                std::env::set_var("AGENT_INBOX_PUBLIC_API_URL", v);
            }
        }
    }

    #[test]
    #[serial]
    fn bridge_audit_aud_returns_none_when_no_env_and_no_host() {
        let previous = std::env::var("AGENT_INBOX_PUBLIC_API_URL").ok();
        unsafe {
            std::env::remove_var("AGENT_INBOX_PUBLIC_API_URL");
        }
        let headers = axum::http::HeaderMap::new();
        assert!(expected_api_url(&headers, "/agent-audit-log/bridge").is_none());
        unsafe {
            if let Some(v) = previous {
                std::env::set_var("AGENT_INBOX_PUBLIC_API_URL", v);
            }
        }
    }

    #[tokio::test]
    async fn bridge_audit_replay_accepts_first_rejects_second_in_memory() {
        let state = make_state();
        let cred = Uuid::new_v4();
        let first = check_and_record_bridge_audit_replay(&state, cred, "jti-abc")
            .await
            .expect("first sighting returns Ok");
        assert!(first, "first sighting must be accepted");
        let second = check_and_record_bridge_audit_replay(&state, cred, "jti-abc")
            .await
            .expect("second sighting returns Ok");
        assert!(!second, "replay of same (credential, jti) must be rejected");
    }

    #[tokio::test]
    async fn bridge_audit_replay_different_credentials_do_not_collide() {
        let state = make_state();
        let cred_a = Uuid::new_v4();
        let cred_b = Uuid::new_v4();
        assert!(
            check_and_record_bridge_audit_replay(&state, cred_a, "jti-shared")
                .await
                .expect("Ok"),
            "cred A first sighting must be accepted",
        );
        assert!(
            check_and_record_bridge_audit_replay(&state, cred_b, "jti-shared")
                .await
                .expect("Ok"),
            "cred B must see the same jti as first, not a replay",
        );
    }

    // -----------------------------------------------------------------
    // Agent-auth token ingest — aud derivation + replay protection.
    // Same structural guarantees as bridge audit above; the two
    // endpoints share the expected_api_url helper and mirror each
    // other's replay scope shape.
    // -----------------------------------------------------------------

    #[test]
    fn agent_auth_aud_composes_against_token_path() {
        let previous = std::env::var("AGENT_INBOX_PUBLIC_API_URL").ok();
        unsafe {
            std::env::set_var("AGENT_INBOX_PUBLIC_API_URL", "https://api.example.test");
        }
        let headers = axum::http::HeaderMap::new();
        let aud = expected_api_url(&headers, "/agent-auth/token").expect("env branch resolves");
        assert_eq!(aud, "https://api.example.test/agent-auth/token");
        unsafe {
            match previous {
                Some(v) => std::env::set_var("AGENT_INBOX_PUBLIC_API_URL", v),
                None => std::env::remove_var("AGENT_INBOX_PUBLIC_API_URL"),
            }
        }
    }

    #[tokio::test]
    async fn agent_auth_replay_accepts_first_rejects_second() {
        let state = make_state();
        let cred = Uuid::new_v4();
        assert!(
            check_and_record_agent_auth_replay(&state, cred, "jti-x")
                .await
                .expect("Ok"),
            "first sighting must be accepted",
        );
        assert!(
            !check_and_record_agent_auth_replay(&state, cred, "jti-x")
                .await
                .expect("Ok"),
            "replay of same (credential, jti) must be rejected",
        );
    }

    // -----------------------------------------------------------------
    // Cross-agent message boundary (P0 hardening).
    // In-memory helper only — the DB path is exercised by the
    // credential_purge / cross_user_delivery integration tests.
    // -----------------------------------------------------------------

    fn push_agent_for_user(state: &AppState, user_id: &str, aid: &str, did: &str) {
        let mut lock = state
            .agents_by_user
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        lock.entry(user_id.to_string()).or_default().push(Agent {
            id: Uuid::new_v4(),
            aid: aid.to_string(),
            did: did.to_string(),
            label: "test".into(),
            public_key: "pk".into(),
            encryption_key: "ek".into(),
            is_active: true,
            auto_reply: false,
            unread_count: 0,
            created_at: Utc::now().to_rfc3339(),
        });
    }

    #[test]
    fn agent_bound_message_passes_through_cookie_auth() {
        // Cookie (Human) callers must keep unfettered access to the
        // whole user's inbox — the helper is only meant to constrain
        // agent-token callers.
        let state = make_state();
        let ctx = AuthContext::Human {
            user_id: "user-1".into(),
        };
        assert!(
            enforce_agent_bound_message_in_memory(
                &state,
                &ctx,
                "did:key:zSender",
                "did:key:zRecipient",
            )
            .is_ok(),
            "cookie auth must not be blocked by the agent boundary",
        );
    }

    #[test]
    fn agent_bound_message_allows_own_did() {
        let state = make_state();
        push_agent_for_user(&state, "user-1", "aid:ai:alice", "did:key:zAlice");
        let ctx = AuthContext::Agent {
            user_id: "user-1".into(),
            credential_id: Uuid::new_v4(),
            aid: "aid:ai:alice".into(),
            scopes: vec!["messages.read".into()],
        };
        // alice is the recipient
        assert!(enforce_agent_bound_message_in_memory(
            &state,
            &ctx,
            "did:key:zOtherSender",
            "did:key:zAlice",
        )
        .is_ok());
        // alice is the sender (their own outbox row)
        assert!(enforce_agent_bound_message_in_memory(
            &state,
            &ctx,
            "did:key:zAlice",
            "did:key:zRecipient",
        )
        .is_ok());
    }

    #[test]
    fn agent_bound_message_rejects_sibling_agents_inside_same_user() {
        // This is the core privilege-escalation case: agent-A's
        // token tries to read a message that belongs to agent-B,
        // where both agents live under the same human user.
        // Without the guard, the owner_user_id-only lookup would
        // let the read through.
        let state = make_state();
        push_agent_for_user(&state, "user-1", "aid:ai:alice", "did:key:zAlice");
        push_agent_for_user(&state, "user-1", "aid:ai:bob", "did:key:zBob");
        let ctx = AuthContext::Agent {
            user_id: "user-1".into(),
            credential_id: Uuid::new_v4(),
            aid: "aid:ai:alice".into(),
            scopes: vec!["messages.read".into()],
        };
        let err = enforce_agent_bound_message_in_memory(
            &state,
            &ctx,
            "did:key:zExternalSender",
            "did:key:zBob",
        )
        .expect_err("alice must not see bob's row");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(
            err.1.error, "not_found",
            "mismatch must be masked as 404 not 403 (stealth)"
        );
    }

    #[tokio::test]
    async fn agent_auth_replay_scope_is_disjoint_from_bridge_audit() {
        // A jti issued for the bridge-audit endpoint must NOT shadow
        // a same-value jti issued for the token endpoint — the two
        // belong to different scope namespaces. Mixing them would
        // let a captured bridge-audit jti lock out a live daemon
        // trying to exchange a token (or vice versa).
        let state = make_state();
        let cred = Uuid::new_v4();
        assert!(
            check_and_record_bridge_audit_replay(&state, cred, "shared-jti")
                .await
                .expect("Ok"),
            "bridge-audit first sighting",
        );
        assert!(
            check_and_record_agent_auth_replay(&state, cred, "shared-jti")
                .await
                .expect("Ok"),
            "agent-auth sees this as first-seen (different scope)",
        );
    }

    // -----------------------------------------------------------------------
    // Auto-reply policy validator (docs/25 §5.3)
    // -----------------------------------------------------------------------

    fn valid_policy() -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "default_action": "queue_for_human",
            "protocols": {
                "schedule_negotiation": {
                    "propose": {
                        "action": "auto_accept",
                        "conditions": {
                            "min_trust_score": 0.5,
                            "require_contact": true,
                            "priority_at_most": "normal",
                            "sender_in_allowlist": ["did:key:zAlice"]
                        },
                        "note_template": "OK from my agent."
                    }
                },
                "task_delegation": {
                    "delegate": { "action": "queue_for_human" }
                }
            }
        })
    }

    #[test]
    fn validate_policy_accepts_a_well_formed_policy() {
        assert!(validate_auto_reply_policy(&valid_policy()).is_ok());
    }

    #[test]
    fn validate_policy_rejects_missing_v() {
        let mut p = valid_policy();
        p.as_object_mut().unwrap().remove("v");
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_wrong_v() {
        let mut p = valid_policy();
        p["v"] = serde_json::json!(2);
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_missing_default_action() {
        let mut p = valid_policy();
        p.as_object_mut().unwrap().remove("default_action");
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_unknown_default_action() {
        let mut p = valid_policy();
        p["default_action"] = serde_json::json!("explode_the_inbox");
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_unknown_protocol_type() {
        let mut p = valid_policy();
        p["protocols"]["phantom"] = serde_json::json!({ "act": {} });
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_wrong_action_for_type() {
        let mut p = valid_policy();
        // `propose` is valid for schedule_negotiation; `delegate` is not.
        p["protocols"]["schedule_negotiation"]["delegate"] =
            serde_json::json!({ "action": "queue_for_human" });
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_unknown_action_enum() {
        let mut p = valid_policy();
        p["protocols"]["schedule_negotiation"]["propose"]["action"] =
            serde_json::json!("maybe_accept");
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_oversized_note_template() {
        let mut p = valid_policy();
        p["protocols"]["schedule_negotiation"]["propose"]["note_template"] =
            serde_json::json!("a".repeat(MAX_NOTE_TEMPLATE_LEN + 1));
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_trust_score_out_of_range() {
        let mut p = valid_policy();
        p["protocols"]["schedule_negotiation"]["propose"]["conditions"]["min_trust_score"] =
            serde_json::json!(1.5);
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_bad_priority_value() {
        let mut p = valid_policy();
        p["protocols"]["schedule_negotiation"]["propose"]["conditions"]["priority_at_most"] =
            serde_json::json!("urgent");
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_non_did_allowlist_entry() {
        let mut p = valid_policy();
        p["protocols"]["schedule_negotiation"]["propose"]["conditions"]["sender_in_allowlist"] =
            serde_json::json!(["not-a-did"]);
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_rejects_oversized_allowlist() {
        let mut p = valid_policy();
        let big: Vec<String> = (0..MAX_SENDER_ALLOWLIST_LEN + 1)
            .map(|i| format!("did:key:z{i}"))
            .collect();
        p["protocols"]["schedule_negotiation"]["propose"]["conditions"]["sender_in_allowlist"] =
            serde_json::json!(big);
        assert!(validate_auto_reply_policy(&p).is_err());
    }

    #[test]
    fn validate_policy_ignores_unknown_fields_at_top_level() {
        let mut p = valid_policy();
        p["_future_field"] = serde_json::json!({"foo": "bar"});
        // forward-compat per docs/25 §9
        assert!(validate_auto_reply_policy(&p).is_ok());
    }

    #[test]
    fn extract_if_match_handles_plain_and_quoted_values() {
        use axum::http::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert("if-match", HeaderValue::from_static("42"));
        assert_eq!(extract_if_match_revision(&h), Some(42));

        let mut h2 = HeaderMap::new();
        h2.insert("if-match", HeaderValue::from_static("\"42\""));
        assert_eq!(extract_if_match_revision(&h2), Some(42));

        let empty = HeaderMap::new();
        assert_eq!(extract_if_match_revision(&empty), None);

        let mut bad = HeaderMap::new();
        bad.insert("if-match", HeaderValue::from_static("not-a-number"));
        assert_eq!(extract_if_match_revision(&bad), None);
    }

    #[test]
    fn etag_from_revision_wraps_in_quotes() {
        assert_eq!(etag_from_revision(0), "\"0\"");
        assert_eq!(etag_from_revision(42), "\"42\"");
    }

    // ------------------------------------------------------------
    // Phase 4.4b evaluator (docs/25b)
    // ------------------------------------------------------------

    fn eval_ctx(master: bool) -> AutoReplyEvaluationContext {
        AutoReplyEvaluationContext {
            master_auto_reply_enabled: master,
            priority: "normal".to_string(),
            trust_score: 0.8,
            sender_did: "did:key:zAlice".to_string(),
            is_contact: true,
        }
    }

    fn minimal_policy(default_action: &str) -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "default_action": default_action,
        })
    }

    #[test]
    fn evaluator_master_off_always_queues() {
        let ctx = eval_ctx(false);
        let decision = evaluate_auto_reply_policy(&minimal_policy("auto_accept"), &ctx);
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "master_off");
        assert_eq!(decision.matched_rule_path, "master");
    }

    #[test]
    fn evaluator_empty_policy_returns_no_policy() {
        let decision = evaluate_auto_reply_policy(&serde_json::json!({}), &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "no_policy");
    }

    #[test]
    fn evaluator_unknown_schema_version_is_rejected_safely() {
        let mut p = minimal_policy("auto_accept");
        p["v"] = serde_json::json!(99);
        let decision = evaluate_auto_reply_policy(&p, &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "unsupported_schema");
    }

    #[test]
    fn evaluator_missing_default_action_falls_back_to_no_policy() {
        let p = serde_json::json!({ "v": 1 });
        let decision = evaluate_auto_reply_policy(&p, &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "no_policy");
    }

    #[test]
    fn evaluator_default_action_auto_accept_passes_through() {
        let decision = evaluate_auto_reply_policy(&minimal_policy("auto_accept"), &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::AutoAccept);
        assert_eq!(decision.reason, "default_match");
        assert_eq!(decision.matched_rule_path, "default");
        assert!(decision.fallback_reason.is_none());
    }

    #[test]
    fn evaluator_default_action_auto_decline_passes_through() {
        let decision = evaluate_auto_reply_policy(&minimal_policy("auto_decline"), &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::AutoDecline);
        assert_eq!(decision.reason, "default_match");
    }

    #[test]
    fn evaluator_auto_accept_if_free_falls_back_until_calendar_is_wired() {
        let decision =
            evaluate_auto_reply_policy(&minimal_policy("auto_accept_if_free"), &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "calendar_unavailable");
        assert_eq!(decision.fallback_reason, Some("calendar_unavailable"));
    }

    #[test]
    fn evaluator_delegate_to_llm_falls_back_until_llm_is_wired() {
        let decision =
            evaluate_auto_reply_policy(&minimal_policy("delegate_to_llm"), &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "llm_unavailable");
        assert_eq!(decision.fallback_reason, Some("llm_unavailable"));
    }

    #[test]
    fn evaluator_priority_at_most_rejects_high_priority_messages() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "priority_at_most": "normal" },
        });
        let mut ctx = eval_ctx(true);
        ctx.priority = "high".to_string();
        let decision = evaluate_auto_reply_policy(&p, &ctx);
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "priority_exceeds_policy");
    }

    #[test]
    fn evaluator_priority_at_most_admits_lower_priority_messages() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "priority_at_most": "normal" },
        });
        let mut ctx = eval_ctx(true);
        ctx.priority = "low".to_string();
        let decision = evaluate_auto_reply_policy(&p, &ctx);
        assert_eq!(decision.action, AutoReplyAction::AutoAccept);
    }

    #[test]
    fn evaluator_min_trust_score_rejects_low_trust_senders() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "min_trust_score": 0.5 },
        });
        let mut ctx = eval_ctx(true);
        ctx.trust_score = 0.3;
        let decision = evaluate_auto_reply_policy(&p, &ctx);
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "trust_below_threshold");
    }

    #[test]
    fn evaluator_require_contact_rejects_strangers() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "require_contact": true },
        });
        let mut ctx = eval_ctx(true);
        ctx.is_contact = false;
        let decision = evaluate_auto_reply_policy(&p, &ctx);
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "not_a_contact");
    }

    #[test]
    fn evaluator_sender_in_allowlist_admits_match() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": {
                "sender_in_allowlist": ["did:key:zAlice", "did:key:zBob"]
            },
        });
        let decision = evaluate_auto_reply_policy(&p, &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::AutoAccept);
    }

    #[test]
    fn evaluator_sender_in_allowlist_rejects_non_member() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": {
                "sender_in_allowlist": ["did:key:zBob"]
            },
        });
        let decision = evaluate_auto_reply_policy(&p, &eval_ctx(true));
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "sender_not_in_allowlist");
    }

    #[test]
    fn evaluator_combines_conditions_with_and_semantics() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": {
                "min_trust_score": 0.5,
                "require_contact": true,
            },
        });
        let mut ctx = eval_ctx(true);
        // trust passes but contact fails → queued for first failing reason
        ctx.trust_score = 0.9;
        ctx.is_contact = false;
        let decision = evaluate_auto_reply_policy(&p, &ctx);
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "not_a_contact");
    }

    #[test]
    fn evaluator_ignores_protocols_block_in_server_mode() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "queue_for_human",
            "protocols": {
                "schedule_negotiation": {
                    "propose": { "action": "auto_accept" }
                }
            }
        });
        let decision = evaluate_auto_reply_policy(&p, &eval_ctx(true));
        // Server mode is blind to A2A content_type, so the default
        // action wins. The protocol override is deferred to the
        // client/daemon evaluator (Phase 4.4c).
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "default_match");
    }

    #[test]
    fn evaluator_defensive_against_malformed_priority_context() {
        let p = serde_json::json!({
            "v": 1,
            "default_action": "auto_accept",
            "default_conditions": { "priority_at_most": "normal" },
        });
        let mut ctx = eval_ctx(true);
        ctx.priority = "weird_value".to_string();
        let decision = evaluate_auto_reply_policy(&p, &ctx);
        assert_eq!(decision.action, AutoReplyAction::QueueForHuman);
        assert_eq!(decision.reason, "invalid_policy");
    }

    #[test]
    fn evaluator_reports_server_metadata_v1_mode() {
        let decision = evaluate_auto_reply_policy(&minimal_policy("auto_accept"), &eval_ctx(true));
        assert_eq!(decision.evaluator_mode, "server_metadata_v1");
    }
}
