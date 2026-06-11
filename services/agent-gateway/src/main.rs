//! NexusInbox — HTTP Gateway
//!
//! Bridges the LLM Runtime (Trust: LOW) to the NexusInbox API.
//! The LLM never touches Bearer tokens or HTTP directly — it calls
//! tool RPCs on a Unix Domain Socket, and this Gateway translates
//! them into authenticated API requests.
//!
//! Security properties:
//!   - Bearer token (`agt_`) lives only in Gateway memory
//!   - LLM sees sanitised JSON responses (no auth headers, no token patterns)
//!   - Tool allow-list: only inbox operations, no arbitrary HTTP
//!   - Output scan: blocks responses containing `agt_`, `agr_`, `ens_` patterns
//!   - Policy L2: per-token send rate limit, destination whitelist (future)
//!
//! See docs/15_non_interactive_agent_access_design.md §4, §7.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};

mod a2a_rust;
mod auto_reply_executor;
mod envelope_crypto;
mod policy_evaluator;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "nexusinbox-gateway", about = "NexusInbox HTTP Gateway")]
struct Cli {
    /// UDS path for LLM-facing tool RPC server
    #[arg(long, default_value = "/tmp/nexusinbox-gateway.sock")]
    llm_socket: String,

    /// UDS path to the Signer Daemon
    #[arg(long, default_value = "/tmp/nexusinbox-signer.sock")]
    signer_socket: String,

    /// NexusInbox API base URL
    #[arg(long, default_value = "http://localhost:3001/api")]
    api_url: String,

    /// Agent selector for inbox queries. Accepts `aid:ai:...` or `did:key:...`.
    /// If omitted, the gateway uses the current signer `aid`.
    #[arg(long, alias = "agent-did")]
    agent_ref: Option<String>,

    /// Maximum send_message calls per token lifetime (Policy L2)
    #[arg(long, default_value = "20")]
    max_sends_per_token: u32,

    /// Allowed peer UID for SO_PEERCRED check (§4.3 IPC security).
    /// If set, only connections from this UID (the LLM runtime) are accepted.
    #[arg(long)]
    allowed_uid: Option<u32>,
}

// ---------------------------------------------------------------------------
// Token management
// ---------------------------------------------------------------------------

struct TokenState {
    access_token: Option<String>,
    refresh_token: Option<String>,
    /// When the current access token expires
    expires_at: Option<chrono::DateTime<Utc>>,
}

impl TokenState {
    fn new() -> Self {
        Self {
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }

    fn is_valid(&self) -> bool {
        match (&self.access_token, self.expires_at) {
            (Some(_), Some(exp)) => Utc::now() < exp - chrono::Duration::seconds(30),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy L2: Send rate limiting
// ---------------------------------------------------------------------------

struct PolicyL2 {
    send_count: u32,
    max_sends_per_token: u32,
}

impl PolicyL2 {
    fn new(max_sends: u32) -> Self {
        Self {
            send_count: 0,
            max_sends_per_token: max_sends,
        }
    }

    fn check_send(&mut self) -> Result<(), String> {
        if self.send_count >= self.max_sends_per_token {
            return Err(format!(
                "Policy L2: send limit reached ({}/{}). Acquire a new token.",
                self.send_count, self.max_sends_per_token
            ));
        }
        self.send_count += 1;
        Ok(())
    }

    fn reset(&mut self) {
        self.send_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Output sanitiser (§7.2 defense-in-depth)
// ---------------------------------------------------------------------------

/// Scan a string for token patterns that must never reach the LLM.
/// Returns true if the content is safe (no leaks detected).
fn scan_output(content: &str) -> bool {
    let patterns = [
        "agt_",
        "agr_",
        "ens_",
        "Authorization:",
        "Bearer agt_",
        "DPoP agt_",
    ];
    for p in &patterns {
        if content.contains(p) {
            eprintln!(
                "[SECURITY] Output scan: blocked response containing '{}' pattern",
                p
            );
            return false;
        }
    }
    true
}

/// Sanitise a JSON value by redacting any string fields containing token patterns.
fn sanitise_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) if !scan_output(s) => {
            *s = "[REDACTED]".to_string();
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                sanitise_json(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                sanitise_json(v);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RpcRequest {
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct RpcResponse {
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcResponse {
    fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self {
            id,
            result: None,
            error: Some(RpcError { code, message }),
        }
    }
}

// ---------------------------------------------------------------------------
// Gateway state
// ---------------------------------------------------------------------------

struct GatewayState {
    api_url: String,
    agent_ref: Option<String>,
    signer_socket: String,
    token: Mutex<TokenState>,
    policy: Mutex<PolicyL2>,
    http_client: reqwest::Client,
    start_time: Instant,
    /// If set, only accept UDS connections from this UID (SO_PEERCRED, §4.3).
    allowed_uid: Option<u32>,
    dpop_signing_key: SigningKey,
    dpop_public_jwk: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct SignerIdentity {
    aid: String,
    did: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RecipientResolution {
    aid: String,
    did: String,
    signing_public_key: Option<String>,
    encryption_public_key: Option<String>,
}

// ---------------------------------------------------------------------------
// Signer Daemon IPC client
// ---------------------------------------------------------------------------

async fn call_signer(
    socket_path: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("cannot connect to signer daemon at {}: {}", socket_path, e))?;

    let (reader, mut writer) = stream.into_split();

    let req = serde_json::json!({
        "id": 1,
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write to signer failed: {}", e))?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| format!("read from signer failed: {}", e))?;

    let resp: serde_json::Value = serde_json::from_str(response_line.trim())
        .map_err(|e| format!("invalid signer response: {}", e))?;

    if let Some(err) = resp.get("error") {
        return Err(format!(
            "signer error: {}",
            err.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
        ));
    }

    resp.get("result")
        .cloned()
        .ok_or_else(|| "signer returned no result".into())
}

async fn get_signer_identity(state: &GatewayState) -> Result<SignerIdentity, String> {
    let result = call_signer(
        &state.signer_socket,
        "get_public_key",
        serde_json::json!({}),
    )
    .await?;
    serde_json::from_value::<SignerIdentity>(result)
        .map_err(|e| format!("invalid signer identity response: {}", e))
}

fn random_b64url(bytes: usize) -> String {
    let mut buf = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Build the DPoP `htu` claim for a request to `url`.
///
/// NOTE (known limitation, audit 2026-06-11 finding #4): `htu` is deliberately
/// the request PATH only, not the full target URI RFC 9449 §4.2 nominally asks
/// for. The gateway reaches the API by two routes — directly
/// (`http://host:8080/messages`) and via the Next.js proxy
/// (`http://host:3001/api/messages`) — and the API validates the proof against
/// the path it actually received. A full-URI `htu` would embed the
/// gateway-side host and the `/api` proxy prefix, which never match the
/// host/path the API server sees, breaking every proxied request. Stripping
/// `/api/` here makes both routes converge on the same canonical path.
///
/// Security trade-off: this drops the host binding RFC 9449 provides, so a
/// proof is not pinned to an origin. The `ath` (access-token-hash) claim still
/// binds each proof to one specific token, so a captured proof cannot be
/// replayed against a different token — the residual gap is only a same-token,
/// same-path relay to another host, which requires breaking TLS. If the proxy
/// hop is ever removed, switch both sides to a canonical
/// `AGENT_INBOX_PUBLIC_API_URL`-based full URI to restore host binding.
fn dpop_htu_for_url(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid DPoP URL: {}", e))?;
    let path = parsed.path();
    if path == "/api" {
        return Ok("/".into());
    }
    if let Some(stripped) = path.strip_prefix("/api/") {
        return Ok(format!("/{}", stripped));
    }
    Ok(path.to_string())
}

fn build_dpop_proof(
    state: &GatewayState,
    method: &str,
    url: &str,
    access_token: &str,
) -> Result<String, String> {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": state.dpop_public_jwk.clone(),
    });
    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    let payload = serde_json::json!({
        "htm": method,
        "htu": dpop_htu_for_url(url)?,
        "iat": Utc::now().timestamp(),
        "jti": random_b64url(24),
        "ath": ath,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|e| format!("DPoP header encode failed: {}", e))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload).map_err(|e| format!("DPoP payload encode failed: {}", e))?,
    );
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = state.dpop_signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

// ---------------------------------------------------------------------------
// Token lifecycle
// ---------------------------------------------------------------------------

/// Ensure we have a valid access token. If not, obtain one via the Signer Daemon.
async fn ensure_token(state: &GatewayState) -> Result<String, String> {
    // Check if current token is still valid
    {
        let ts = state.token.lock().unwrap();
        if ts.is_valid() {
            return Ok(ts.access_token.clone().unwrap());
        }
    }

    // Try refresh first
    let maybe_rt = {
        let ts = state.token.lock().unwrap();
        ts.refresh_token.clone()
    };
    if let Some(rt) = maybe_rt {
        match refresh_token(state, &rt).await {
            Ok(at) => return Ok(at),
            Err(e) => {
                eprintln!(
                    "[WARN] Refresh failed ({}), falling back to new assertion",
                    e
                );
            }
        }
    }

    // Get a fresh token via JWS assertion
    obtain_new_token(state).await
}

async fn obtain_new_token(state: &GatewayState) -> Result<String, String> {
    // 1. Ask Signer Daemon for a JWS assertion
    let result = call_signer(
        &state.signer_socket,
        "sign_assertion",
        serde_json::json!({}),
    )
    .await?;
    let assertion = result["assertion"]
        .as_str()
        .ok_or("signer did not return assertion")?
        .to_string();

    // 2. Exchange assertion for tokens at the API
    let resp = state
        .http_client
        .post(format!("{}/agent-auth/token", state.api_url))
        .json(&serde_json::json!({
            "assertion": assertion,
            "dpop_jwk": state.dpop_public_jwk.clone(),
        }))
        .send()
        .await
        .map_err(|e| format!("token request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("token endpoint returned {}: {}", status, body));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid token response: {}", e))?;

    let access_token = body["access_token"]
        .as_str()
        .ok_or("missing access_token")?
        .to_string();
    let refresh_token = body["refresh_token"].as_str().map(|s| s.to_string());
    let expires_in = body["expires_in"].as_u64().unwrap_or(900);

    // Store tokens
    {
        let mut ts = state.token.lock().unwrap();
        ts.access_token = Some(access_token.clone());
        ts.refresh_token = refresh_token;
        ts.expires_at = Some(Utc::now() + chrono::Duration::seconds(expires_in as i64));
    }

    // Reset send counter for new token
    {
        let mut policy = state.policy.lock().unwrap();
        policy.reset();
    }

    Ok(access_token)
}

async fn refresh_token(state: &GatewayState, rt: &str) -> Result<String, String> {
    let url = format!("{}/agent-auth/refresh", state.api_url);
    // DPoP proof on refresh: ath is computed over the refresh token (the caller
    // no longer holds the old access token). Server validates key binding to
    // prevent stolen-RT rotation (RFC 9449 §6.1).
    let dpop = build_dpop_proof(state, "POST", &url, rt)?;
    let resp = state
        .http_client
        .post(&url)
        .header("Authorization", format!("DPoP {}", rt))
        .header("DPoP", dpop)
        .json(&serde_json::json!({ "refresh_token": rt }))
        .send()
        .await
        .map_err(|e| format!("refresh request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("refresh returned {}: {}", status, body));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid refresh response: {}", e))?;

    let access_token = body["access_token"]
        .as_str()
        .ok_or("missing access_token")?
        .to_string();
    let refresh_token = body["refresh_token"].as_str().map(|s| s.to_string());
    let expires_in = body["expires_in"].as_u64().unwrap_or(900);

    {
        let mut ts = state.token.lock().unwrap();
        ts.access_token = Some(access_token.clone());
        ts.refresh_token = refresh_token;
        ts.expires_at = Some(Utc::now() + chrono::Duration::seconds(expires_in as i64));
    }

    Ok(access_token)
}

// ---------------------------------------------------------------------------
// Tool allow-list — the ONLY operations the LLM can invoke
// ---------------------------------------------------------------------------

const ALLOWED_METHODS: &[&str] = &[
    "whoami",
    "resolve_recipient",
    "list_inbox",
    "read_message",
    "send_message",
    "mark_read",
    "archive_message",
    // Phase 2.5: proxies to signer-daemon's `unwrap_content_key` so
    // Isolated mode callers (MCP / LLM runtime) can decrypt inbound envelopes
    // without ever holding the recipient's X25519 private key.
    "unwrap_content_key",
    "status",
];

// ---------------------------------------------------------------------------
// RPC handlers
// ---------------------------------------------------------------------------

async fn handle_rpc(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    // Tool allow-list enforcement
    if !ALLOWED_METHODS.contains(&req.method.as_str()) {
        return RpcResponse::error(
            req.id.clone(),
            -32601,
            format!(
                "method '{}' is not in the allow-list. Permitted: {:?}",
                req.method, ALLOWED_METHODS
            ),
        );
    }

    match req.method.as_str() {
        "whoami" => handle_whoami(state, req).await,
        "resolve_recipient" => handle_resolve_recipient(state, req).await,
        "list_inbox" => handle_list_inbox(state, req).await,
        "read_message" => handle_read_message(state, req).await,
        "send_message" => handle_send_message(state, req).await,
        "mark_read" => handle_mark_read(state, req).await,
        "archive_message" => handle_archive_message(state, req).await,
        "unwrap_content_key" => handle_unwrap_content_key(state, req).await,
        "status" => handle_status(state, req),
        _ => unreachable!(),
    }
}

/// Phase 2.5: proxy the wrapped content key to the signer daemon so it
/// can run the X25519 ECDH + HKDF + AES-GCM unwrap and hand back the
/// plaintext content key. The daemon keeps the private half; the
/// gateway only sees (encrypted_key in → content_key out). No API call.
async fn handle_unwrap_content_key(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    let encrypted_key = match req.params.get("encrypted_key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => {
            return RpcResponse::error(
                req.id.clone(),
                -32602,
                "missing param: encrypted_key".into(),
            )
        }
    };

    match call_signer(
        &state.signer_socket,
        "unwrap_content_key",
        serde_json::json!({ "encrypted_key": encrypted_key }),
    )
    .await
    {
        Ok(mut result) => {
            // Content_key itself is short-lived AES-GCM material, not a
            // token secret, so `sanitise_json` (which nukes agt_/agr_/
            // ens_ prefixed strings) is a no-op here. Still run it so
            // any future ath / refresh additions auto-filter.
            sanitise_json(&mut result);
            RpcResponse::success(req.id.clone(), result)
        }
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

async fn resolve_recipient_identifier(
    state: &GatewayState,
    token: &str,
    identifier: &str,
) -> Result<RecipientResolution, String> {
    let mut url = reqwest::Url::parse(&format!("{}/recipients/resolve", state.api_url))
        .map_err(|e| format!("invalid resolve_recipient URL: {}", e))?;
    url.query_pairs_mut().append_pair("identifier", identifier);
    let body = api_get(state, url.as_ref(), token).await?;
    serde_json::from_value::<RecipientResolution>(body)
        .map_err(|e| format!("invalid resolve_recipient response: {}", e))
}

async fn handle_whoami(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    match get_signer_identity(state).await {
        Ok(identity) => RpcResponse::success(
            req.id.clone(),
            serde_json::json!({
                "aid": identity.aid,
                "did": identity.did,
                "agent_ref": state.agent_ref,
            }),
        ),
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

async fn handle_resolve_recipient(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    let token = match ensure_token(state).await {
        Ok(t) => t,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };
    let identifier = match req.params.get("identifier").and_then(|v| v.as_str()) {
        Some(identifier) => identifier,
        None => {
            return RpcResponse::error(req.id.clone(), -32602, "missing param: identifier".into())
        }
    };

    match resolve_recipient_identifier(state, &token, identifier).await {
        Ok(body) => {
            let mut json = serde_json::to_value(&body).unwrap_or_else(|_| serde_json::json!({}));
            sanitise_json(&mut json);
            RpcResponse::success(req.id.clone(), json)
        }
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

async fn handle_list_inbox(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    let token = match ensure_token(state).await {
        Ok(t) => t,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };
    let signer_identity = match get_signer_identity(state).await {
        Ok(identity) => identity,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };

    let folder = req
        .params
        .get("folder")
        .and_then(|v| v.as_str())
        .unwrap_or("inbox");
    let status = req
        .params
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    // Build the URL via `query_pairs_mut` so every LLM-supplied
    // parameter is URL-encoded end-to-end. The previous `format!`
    // version interpolated `folder` / `status` / `agent_ref` raw,
    // which let a prompt-injected LLM smuggle extra query params
    // (e.g. `folder=inbox&owner=attacker`) into the outbound API
    // request. `resolve_recipient_identifier` above already follows
    // this pattern — matching it keeps the Gateway's URL-encoding
    // discipline uniform across tools.
    let mut url = match reqwest::Url::parse(&format!("{}/messages", state.api_url)) {
        Ok(u) => u,
        Err(e) => {
            return RpcResponse::error(
                req.id.clone(),
                -32603,
                format!("invalid API base URL: {e}"),
            );
        }
    };
    url.query_pairs_mut()
        .append_pair(
            "agent_did",
            state
                .agent_ref
                .as_deref()
                .unwrap_or(signer_identity.aid.as_str()),
        )
        .append_pair("folder", folder)
        .append_pair("status", status);

    match api_get(state, url.as_ref(), &token).await {
        Ok(mut body) => {
            sanitise_json(&mut body);
            RpcResponse::success(req.id.clone(), body)
        }
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

/// True when `s` is a canonical 8-4-4-4-12 hex UUID. Gateway RPC handlers
/// validate LLM-supplied `message_id` values against this before
/// interpolating them into an API path: a non-UUID like "../agents" would
/// otherwise let reqwest canonicalise the path and drive the gateway's
/// authenticated session to an unintended endpoint (path traversal).
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

async fn handle_read_message(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    let token = match ensure_token(state).await {
        Ok(t) => t,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };

    let message_id = match req.params.get("message_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return RpcResponse::error(req.id.clone(), -32602, "missing param: message_id".into())
        }
    };

    if !is_uuid(message_id) {
        return RpcResponse::error(
            req.id.clone(),
            -32602,
            "invalid param: message_id must be a UUID".into(),
        );
    }

    let url = format!("{}/messages/{}/content", state.api_url, message_id);

    match api_get(state, &url, &token).await {
        Ok(mut body) => {
            sanitise_json(&mut body);
            RpcResponse::success(req.id.clone(), body)
        }
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

async fn handle_send_message(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    // Policy L2: send rate check
    {
        let mut policy = state.policy.lock().unwrap();
        if let Err(e) = policy.check_send() {
            return RpcResponse::error(req.id.clone(), -32000, e);
        }
    }

    let token = match ensure_token(state).await {
        Ok(t) => t,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };
    let signer_identity = match get_signer_identity(state).await {
        Ok(identity) => identity,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };

    let recipient_did = match req.params.get("recipient_did").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => {
            return RpcResponse::error(
                req.id.clone(),
                -32602,
                "missing param: recipient_did".into(),
            )
        }
    };

    // The actual message content should already be encrypted by the caller.
    // Gateway passes through the envelope fields without inspecting content.
    let envelope = req
        .params
        .get("envelope")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let resolved_recipient = match resolve_recipient_identifier(state, &token, recipient_did).await
    {
        Ok(recipient) => recipient,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };

    let envelope = if envelope.get("signature").and_then(|v| v.as_str()).is_some() {
        envelope
    } else {
        let subject_encrypted = match envelope
            .get("metadata")
            .and_then(|metadata| metadata.get("subject_encrypted"))
            .and_then(|v| v.as_str())
        {
            Some(subject) => subject,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    -32602,
                    "envelope.metadata.subject_encrypted is required when signature is omitted"
                        .into(),
                )
            }
        };
        let encrypted_content = match envelope.get("encrypted_content").and_then(|v| v.as_str()) {
            Some(value) => value,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    -32602,
                    "missing envelope.encrypted_content".into(),
                )
            }
        };
        let encrypted_key = match envelope.get("encrypted_key").and_then(|v| v.as_str()) {
            Some(value) => value,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    -32602,
                    "missing envelope.encrypted_key".into(),
                )
            }
        };
        let nonce = match envelope.get("nonce").and_then(|v| v.as_str()) {
            Some(value) => value,
            None => {
                return RpcResponse::error(req.id.clone(), -32602, "missing envelope.nonce".into())
            }
        };

        let sign_result = match call_signer(
            &state.signer_socket,
            "sign_envelope",
            serde_json::json!({
                "sender_did": signer_identity.did,
                "recipient_did": resolved_recipient.did,
                "subject_encrypted": subject_encrypted,
                "encrypted_content": encrypted_content,
                "encrypted_key": encrypted_key,
                "nonce": nonce,
            }),
        )
        .await
        {
            Ok(result) => result,
            Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
        };

        let signature = match sign_result.get("signature").and_then(|v| v.as_str()) {
            Some(signature) => signature,
            None => {
                return RpcResponse::error(
                    req.id.clone(),
                    -32000,
                    "signer returned no envelope signature".into(),
                )
            }
        };

        let mut envelope_object = match envelope {
            serde_json::Value::Object(map) => map,
            _ => {
                return RpcResponse::error(
                    req.id.clone(),
                    -32602,
                    "envelope must be a JSON object".into(),
                )
            }
        };
        envelope_object.insert(
            "signature".into(),
            serde_json::Value::String(signature.into()),
        );
        serde_json::Value::Object(envelope_object)
    };

    let body = serde_json::json!({
        "sender_did": signer_identity.did,
        "recipient_did": recipient_did,
        "envelope": envelope,
    });

    let url = format!("{}/messages", state.api_url);

    match api_post(state, &url, &token, &body).await {
        Ok(mut resp) => {
            sanitise_json(&mut resp);
            RpcResponse::success(req.id.clone(), resp)
        }
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

async fn handle_mark_read(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    let token = match ensure_token(state).await {
        Ok(t) => t,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };

    let message_id = match req.params.get("message_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return RpcResponse::error(req.id.clone(), -32602, "missing param: message_id".into())
        }
    };

    if !is_uuid(message_id) {
        return RpcResponse::error(
            req.id.clone(),
            -32602,
            "invalid param: message_id must be a UUID".into(),
        );
    }

    let url = format!("{}/messages/{}", state.api_url, message_id);
    let body = serde_json::json!({ "status": "read" });

    match api_patch(state, &url, &token, &body).await {
        Ok(mut resp) => {
            sanitise_json(&mut resp);
            RpcResponse::success(req.id.clone(), resp)
        }
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

async fn handle_archive_message(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    let token = match ensure_token(state).await {
        Ok(t) => t,
        Err(e) => return RpcResponse::error(req.id.clone(), -32000, e),
    };

    let message_id = match req.params.get("message_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return RpcResponse::error(req.id.clone(), -32602, "missing param: message_id".into())
        }
    };

    if !is_uuid(message_id) {
        return RpcResponse::error(
            req.id.clone(),
            -32602,
            "invalid param: message_id must be a UUID".into(),
        );
    }

    let url = format!("{}/messages/{}", state.api_url, message_id);
    let body = serde_json::json!({ "status": "archived" });

    match api_patch(state, &url, &token, &body).await {
        Ok(mut resp) => {
            sanitise_json(&mut resp);
            RpcResponse::success(req.id.clone(), resp)
        }
        Err(e) => RpcResponse::error(req.id.clone(), -32000, e),
    }
}

fn handle_status(state: &GatewayState, req: &RpcRequest) -> RpcResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let has_token = state.token.lock().unwrap().is_valid();
    let policy = state.policy.lock().unwrap();

    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "gateway": "nexusinbox-gateway",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": uptime,
            "agent_ref": state.agent_ref,
            "has_valid_token": has_token,
            "sends_used": policy.send_count,
            "sends_max": policy.max_sends_per_token,
            "allowed_methods": ALLOWED_METHODS,
        }),
    )
}

// ---------------------------------------------------------------------------
// HTTP helpers — all API calls go through these
// ---------------------------------------------------------------------------

async fn api_get(
    state: &GatewayState,
    url: &str,
    token: &str,
) -> Result<serde_json::Value, String> {
    let dpop = build_dpop_proof(state, "GET", url, token)?;
    let resp = state
        .http_client
        .get(url)
        .header("Authorization", format!("DPoP {}", token))
        .header("DPoP", dpop)
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| format!("API GET failed: {}", e))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid API response: {}", e))?;

    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("request failed");
        return Err(format!("API returned {}: {}", status, msg));
    }

    Ok(body)
}

async fn api_post(
    state: &GatewayState,
    url: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let dpop = build_dpop_proof(state, "POST", url, token)?;
    let resp = state
        .http_client
        .post(url)
        .header("Authorization", format!("DPoP {}", token))
        .header("DPoP", dpop)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| format!("API POST failed: {}", e))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid API response: {}", e))?;

    if !status.is_success() {
        let msg = resp_body["message"].as_str().unwrap_or("request failed");
        return Err(format!("API returned {}: {}", status, msg));
    }

    Ok(resp_body)
}

async fn api_patch(
    state: &GatewayState,
    url: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let dpop = build_dpop_proof(state, "PATCH", url, token)?;
    let resp = state
        .http_client
        .patch(url)
        .header("Authorization", format!("DPoP {}", token))
        .header("DPoP", dpop)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| format!("API PATCH failed: {}", e))?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid API response: {}", e))?;

    if !status.is_success() {
        let msg = resp_body["message"].as_str().unwrap_or("request failed");
        return Err(format!("API returned {}: {}", status, msg));
    }

    Ok(resp_body)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let dpop_signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let dpop_public_jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(dpop_signing_key.verifying_key().to_bytes()),
    });

    eprintln!("[INFO] NexusInbox HTTP Gateway starting");
    eprintln!(
        "[INFO]   Agent ref:      {}",
        cli.agent_ref.as_deref().unwrap_or("<signer aid>")
    );
    eprintln!("[INFO]   API URL:        {}", cli.api_url);
    eprintln!("[INFO]   Signer socket:  {}", cli.signer_socket);
    eprintln!("[INFO]   LLM socket:     {}", cli.llm_socket);
    eprintln!("[INFO]   Max sends/token: {}", cli.max_sends_per_token);

    let state = Arc::new(GatewayState {
        api_url: cli.api_url,
        agent_ref: cli.agent_ref,
        signer_socket: cli.signer_socket,
        token: Mutex::new(TokenState::new()),
        policy: Mutex::new(PolicyL2::new(cli.max_sends_per_token)),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client"),
        start_time: Instant::now(),
        allowed_uid: cli.allowed_uid,
        dpop_signing_key,
        dpop_public_jwk,
    });

    // Remove stale socket
    let socket_path = std::path::PathBuf::from(&cli.llm_socket);
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = UnixListener::bind(&socket_path).unwrap_or_else(|e| {
        eprintln!(
            "[ERROR] Failed to bind UDS {}: {}",
            socket_path.display(),
            e
        );
        std::process::exit(1);
    });

    // Set socket permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&socket_path, perms).ok();
    }

    eprintln!("[INFO] Listening on {}", socket_path.display());

    // Phase 4.4c+ (docs/25c-a §5) — Isolated mode auto-reply executor.
    // Gated on AGENT_INBOX_MODE_A_EXECUTOR so the default gateway
    // behaviour (LLM runtime IPC only) is unchanged.
    if auto_reply_executor::executor_enabled() {
        let interval = auto_reply_executor::executor_interval();
        let exec_state = Arc::clone(&state);
        eprintln!(
            "[INFO] Isolated mode auto-reply executor: ENABLED (interval {:?})",
            interval
        );
        tokio::spawn(async move {
            let backend = Arc::new(GatewayExecutorBackend::new(exec_state).await);
            auto_reply_executor::run_loop(backend, interval).await;
        });
    } else {
        eprintln!("[INFO] Isolated mode auto-reply executor: disabled (set AGENT_INBOX_MODE_A_EXECUTOR=on to enable)");
    }

    // Graceful shutdown
    let cleanup_path = socket_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("\n[INFO] Shutting down...");
        std::fs::remove_file(&cleanup_path).ok();
        std::process::exit(0);
    });

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // SO_PEERCRED check (§4.3 IPC security). When --allowed-uid is
                // unset we default to this process's own uid, so an
                // unconfigured deployment still rejects other users on the host
                // instead of accepting everyone. We deliberately do NOT
                // special-case uid 0: a local root process must not be able to
                // bypass the configured peer restriction.
                #[cfg(unix)]
                {
                    let my_uid = unsafe { libc::getuid() };
                    let allowed_uid = state.allowed_uid.unwrap_or(my_uid);
                    match stream.peer_cred() {
                        Ok(cred) => {
                            let peer_uid = cred.uid();
                            if peer_uid != allowed_uid && peer_uid != my_uid {
                                eprintln!(
                                    "[SECURITY] Rejected connection from UID {} (allowed: {})",
                                    peer_uid, allowed_uid
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            eprintln!("[SECURITY] Failed to get peer credentials: {}", e);
                            continue;
                        }
                    }
                }

                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_connection(state, stream).await;
                });
            }
            Err(e) => {
                eprintln!("[ERROR] Accept failed: {}", e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4.4c+ Isolated mode auto-reply executor — ExecutorBackend impl wiring the
// in-process HTTP + daemon IPC helpers.
// ---------------------------------------------------------------------------

struct GatewayExecutorBackend {
    state: Arc<GatewayState>,
    our_did: String,
}

impl GatewayExecutorBackend {
    async fn new(state: Arc<GatewayState>) -> Self {
        let did = match get_signer_identity(state.as_ref()).await {
            Ok(id) => id.did,
            Err(e) => {
                eprintln!(
                    "[auto-reply] failed to resolve our DID from signer: {e}; executor will error until daemon is reachable"
                );
                String::new()
            }
        };
        GatewayExecutorBackend {
            state,
            our_did: did,
        }
    }
}

#[async_trait::async_trait]
impl auto_reply_executor::ExecutorBackend for GatewayExecutorBackend {
    async fn fetch_pending_messages(
        &self,
    ) -> Result<Vec<auto_reply_executor::PendingMessage>, String> {
        let token = ensure_token(&self.state).await?;
        let url = format!(
            "{}/messages?auto_reply_pending=1&per_page={}",
            self.state.api_url,
            auto_reply_executor::MAX_PER_TICK
        );
        let body = api_get(&self.state, &url, &token).await?;
        let messages = body
            .get("messages")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(messages.len());
        for m in messages {
            let (Some(id), Some(sender_did), Some(recipient_did), Some(decision)) = (
                m.get("id").and_then(|v| v.as_str()),
                m.get("sender_did").and_then(|v| v.as_str()),
                m.get("recipient_did").and_then(|v| v.as_str()),
                m.get("auto_reply_decision").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            out.push(auto_reply_executor::PendingMessage {
                id: id.into(),
                sender_did: sender_did.into(),
                recipient_did: recipient_did.into(),
                thread_id: m
                    .get("thread_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                decision: decision.into(),
                priority: m
                    .get("priority")
                    .and_then(|v| v.as_str())
                    .unwrap_or("normal")
                    .into(),
                trust_score: m.get("trust_score").and_then(|v| v.as_f64()).unwrap_or(0.0),
                auto_reply_reason: m
                    .get("auto_reply_reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
        Ok(out)
    }

    async fn fetch_message_content(
        &self,
        message_id: &str,
    ) -> Result<auto_reply_executor::MessageContent, String> {
        let token = ensure_token(&self.state).await?;
        let url = format!("{}/messages/{}/content", self.state.api_url, message_id);
        let body = api_get(&self.state, &url, &token).await?;
        Ok(auto_reply_executor::MessageContent {
            encrypted_content: body
                .get("encrypted_content")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .into(),
            encrypted_key: body
                .get("encrypted_key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .into(),
            content_type: body
                .get("content_type")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }

    async fn resolve_recipient(
        &self,
        did: &str,
    ) -> Result<auto_reply_executor::RecipientPubkey, String> {
        let token = ensure_token(&self.state).await?;
        let url = format!(
            "{}/recipients/resolve?identifier={}",
            self.state.api_url,
            urlencoding_encode(did)
        );
        let body = api_get(&self.state, &url, &token).await?;
        Ok(auto_reply_executor::RecipientPubkey {
            did: body
                .get("did")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .into(),
            encryption_public_key: body
                .get("encryption_public_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "recipient has no encryption_public_key".to_string())?
                .into(),
        })
    }

    async fn daemon_unwrap_content_key(&self, encrypted_key: &str) -> Result<String, String> {
        let result = call_signer(
            &self.state.signer_socket,
            "unwrap_content_key",
            serde_json::json!({ "encrypted_key": encrypted_key }),
        )
        .await?;
        result["content_key"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "daemon unwrap_content_key returned no content_key".into())
    }

    async fn daemon_wrap_content_key(
        &self,
        recipient_pub_b64: &str,
        content_key: &str,
    ) -> Result<String, String> {
        let result = call_signer(
            &self.state.signer_socket,
            "wrap_content_key",
            serde_json::json!({
                "recipient_encryption_pub": recipient_pub_b64,
                "content_key": content_key,
            }),
        )
        .await?;
        result["wrapped_key"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "daemon wrap_content_key returned no wrapped_key".into())
    }

    async fn daemon_sign_envelope(
        &self,
        sender_did: &str,
        recipient: &str,
        payload_b64: &str,
    ) -> Result<String, String> {
        let result = call_signer(
            &self.state.signer_socket,
            "sign_envelope",
            serde_json::json!({
                "sender_did": sender_did,
                "recipient": recipient,
                "payload_b64": payload_b64,
            }),
        )
        .await?;
        result["signature"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "daemon sign_envelope returned no signature".into())
    }

    async fn post_reply(&self, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let token = ensure_token(&self.state).await?;
        let url = format!("{}/messages", self.state.api_url);
        api_post(&self.state, &url, &token, body).await
    }

    async fn mark_auto_reply_sent(
        &self,
        message_id: &str,
        reply_message_id: Option<&str>,
    ) -> Result<(), String> {
        let token = ensure_token(&self.state).await?;
        let url = format!(
            "{}/messages/{}/auto-reply-sent",
            self.state.api_url, message_id
        );
        let mut body = serde_json::json!({
            "executor_mode": auto_reply_executor::AUTO_REPLY_ORIGIN_DAEMON,
        });
        if let Some(id) = reply_message_id {
            body["reply_message_id"] = serde_json::Value::String(id.into());
        }
        api_patch(&self.state, &url, &token, &body).await?;
        Ok(())
    }

    fn our_did(&self) -> &str {
        &self.our_did
    }

    async fn fetch_policy(&self) -> Result<Option<serde_json::Value>, String> {
        let token = ensure_token(&self.state).await?;
        // The /agents response narrows to the authenticated agent's
        // own record when the caller is an agent token (docs/07).
        // Pick the first row and use its id.
        let agents_url = format!("{}/agents", self.state.api_url);
        let agents_body = api_get(&self.state, &agents_url, &token).await?;
        let Some(agent_id) = agents_body
            .get("agents")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|a| a.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        else {
            return Ok(None);
        };
        let policy_url = format!(
            "{}/agents/{}/auto-reply-policy",
            self.state.api_url, agent_id
        );
        let policy_resp = api_get(&self.state, &policy_url, &token).await?;
        Ok(policy_resp.get("policy").cloned())
    }

    async fn fetch_contact_dids(&self) -> Result<Vec<String>, String> {
        let token = ensure_token(&self.state).await?;
        let url = format!("{}/contacts", self.state.api_url);
        let body = api_get(&self.state, &url, &token).await?;
        let contacts = body
            .get("contacts")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(contacts
            .into_iter()
            .filter_map(|c| c.get("did").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect())
    }
}

/// Minimal URL-encoder for DID values so we don't need to pull in
/// another crate just for one call site. DIDs are "did:key:zXYZ..."
/// — none of the characters need escaping in practice, but the
/// colon does, so encode defensively.
fn urlencoding_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

async fn handle_connection(state: Arc<GatewayState>, stream: tokio::net::UnixStream) {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let response = match serde_json::from_str::<RpcRequest>(trimmed) {
                    Ok(req) => handle_rpc(&state, &req).await,
                    Err(e) => RpcResponse::error(
                        serde_json::Value::Null,
                        -32700,
                        format!("parse error: {}", e),
                    ),
                };

                let mut out = serde_json::to_string(&response).unwrap();
                out.push('\n');
                if writer.write_all(out.as_bytes()).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("[ERROR] Read error: {}", e);
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_scan_output_clean() {
        assert!(scan_output("Hello, this is a normal message"));
        assert!(scan_output(r#"{"messages": [], "total": 0}"#));
    }

    #[test]
    fn test_scan_output_blocks_tokens() {
        assert!(!scan_output("here is agt_abc123 leaked"));
        assert!(!scan_output("agr_secret_token"));
        assert!(!scan_output("ens_enrollment_secret"));
        assert!(!scan_output("Authorization: Bearer agt_xyz"));
        assert!(!scan_output("DPoP agt_xyz"));
    }

    #[test]
    fn test_sanitise_json() {
        let mut val = serde_json::json!({
            "message": "hello",
            "leaked": "agt_secret123",
            "nested": {
                "token": "agr_refresh_here"
            }
        });
        sanitise_json(&mut val);
        assert_eq!(val["message"], "hello");
        assert_eq!(val["leaked"], "[REDACTED]");
        assert_eq!(val["nested"]["token"], "[REDACTED]");
    }

    #[test]
    fn test_is_uuid_accepts_canonical_and_rejects_traversal() {
        // Canonical UUIDs (both cases) pass.
        assert!(is_uuid("00000000-0000-0000-0000-000000000bb1"));
        assert!(is_uuid("A1B2C3D4-E5F6-7890-ABCD-EF1234567890"));
        // Path-traversal and other non-UUID message_id values are rejected
        // before they reach the format!-built API path.
        assert!(!is_uuid("../agents"));
        assert!(!is_uuid("../../agent-auth/revoke"));
        assert!(!is_uuid(""));
        assert!(!is_uuid("00000000-0000-0000-0000-000000000bb1/../agents"));
        assert!(!is_uuid("g0000000-0000-0000-0000-000000000bb1")); // non-hex
        assert!(!is_uuid("00000000_0000_0000_0000_000000000bb1")); // wrong sep
    }

    #[test]
    fn test_policy_l2_send_limit() {
        let mut policy = PolicyL2::new(3);
        assert!(policy.check_send().is_ok()); // 1
        assert!(policy.check_send().is_ok()); // 2
        assert!(policy.check_send().is_ok()); // 3
        assert!(policy.check_send().is_err()); // 4 -> blocked

        policy.reset();
        assert!(policy.check_send().is_ok()); // reset -> 1 again
    }

    #[test]
    fn test_token_state_validity() {
        let mut ts = TokenState::new();
        assert!(!ts.is_valid());

        ts.access_token = Some("agt_test".into());
        ts.expires_at = Some(Utc::now() + chrono::Duration::seconds(300));
        assert!(ts.is_valid());

        // Expired token
        ts.expires_at = Some(Utc::now() - chrono::Duration::seconds(60));
        assert!(!ts.is_valid());
    }

    #[test]
    fn test_allowed_methods() {
        assert!(ALLOWED_METHODS.contains(&"whoami"));
        assert!(ALLOWED_METHODS.contains(&"resolve_recipient"));
        assert!(ALLOWED_METHODS.contains(&"list_inbox"));
        assert!(ALLOWED_METHODS.contains(&"send_message"));
        assert!(ALLOWED_METHODS.contains(&"read_message"));
        assert!(ALLOWED_METHODS.contains(&"mark_read"));
        assert!(ALLOWED_METHODS.contains(&"archive_message"));
        assert!(ALLOWED_METHODS.contains(&"unwrap_content_key"));
        assert!(ALLOWED_METHODS.contains(&"status"));
        assert!(!ALLOWED_METHODS.contains(&"http_fetch"));
        assert!(!ALLOWED_METHODS.contains(&"exec_shell"));
    }

    #[tokio::test]
    async fn test_unwrap_content_key_rejects_missing_param() {
        // We don't stand up a real signer daemon here — this only checks
        // the param-validation path. A real end-to-end test lives in
        // signer-daemon::tests (roundtrip) + the Isolated mode runtime tests.
        let state = make_test_state();
        let req = RpcRequest {
            id: json!(1),
            method: "unwrap_content_key".into(),
            params: json!({}),
        };

        let resp = handle_unwrap_content_key(&state, &req).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("encrypted_key"));
    }

    #[test]
    fn test_dpop_htu_strips_next_proxy_prefix() {
        assert_eq!(
            dpop_htu_for_url("http://localhost:3001/api/messages/abc/content").unwrap(),
            "/messages/abc/content"
        );
        assert_eq!(
            dpop_htu_for_url("http://localhost:8080/messages").unwrap(),
            "/messages"
        );
    }

    fn make_test_state() -> GatewayState {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        GatewayState {
            api_url: "http://localhost:3001/api".into(),
            agent_ref: Some("aid:ai:test".into()),
            signer_socket: "/tmp/signer.sock".into(),
            token: Mutex::new(TokenState::new()),
            policy: Mutex::new(PolicyL2::new(20)),
            http_client: reqwest::Client::new(),
            start_time: Instant::now(),
            allowed_uid: None,
            dpop_public_jwk: json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            }),
            dpop_signing_key: signing_key,
        }
    }

    #[test]
    fn test_build_dpop_proof_shape() {
        let state = make_test_state();

        let proof = build_dpop_proof(
            &state,
            "GET",
            "http://localhost:3001/api/messages/123/content",
            "agt_test_token",
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert!(header.contains("\"typ\":\"dpop+jwt\""));
        assert!(header.contains("\"alg\":\"EdDSA\""));
        assert!(header.contains("\"jwk\""));

        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert!(payload.contains("\"htm\":\"GET\""));
        assert!(payload.contains("\"htu\":\"/messages/123/content\""));
        assert!(payload.contains("\"ath\""));
        assert!(payload.contains("\"jti\""));
    }

    #[test]
    fn test_build_dpop_proof_for_refresh() {
        let state = make_test_state();

        // Refresh uses POST method and refresh token for ath
        let proof = build_dpop_proof(
            &state,
            "POST",
            "http://localhost:3001/api/agent-auth/refresh",
            "agr_refresh_token_value",
        )
        .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert!(payload.contains("\"htm\":\"POST\""));
        assert!(payload.contains("\"htu\":\"/agent-auth/refresh\""));
        assert!(payload.contains("\"ath\""));

        // ath should be sha256 of the refresh token, not access token
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(b"agr_refresh_token_value"));
        assert!(payload.contains(&expected_ath));
    }

    #[test]
    fn test_build_dpop_proof_unique_jti() {
        let state = make_test_state();
        let url = "http://localhost:3001/api/messages";

        let proof1 = build_dpop_proof(&state, "GET", url, "agt_t1").unwrap();
        let proof2 = build_dpop_proof(&state, "GET", url, "agt_t1").unwrap();

        let jti1: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(proof1.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let jti2: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(proof2.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();

        assert_ne!(
            jti1["jti"], jti2["jti"],
            "each DPoP proof must have a unique jti"
        );
    }

    #[test]
    fn test_status_reports_agent_ref() {
        let state = make_test_state();
        let req = RpcRequest {
            id: json!(1),
            method: "status".into(),
            params: json!({}),
        };

        let resp = handle_status(&state, &req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["agent_ref"], "aid:ai:test");
    }

    #[test]
    fn test_allowed_methods_do_not_include_arbitrary_signer_access() {
        assert!(!ALLOWED_METHODS.contains(&"sign_assertion"));
        assert!(!ALLOWED_METHODS.contains(&"sign_envelope"));
    }
}
